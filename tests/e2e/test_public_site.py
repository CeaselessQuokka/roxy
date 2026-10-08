"""The public site in a real browser: strict CSP, highlighted Luau, contrast, accessibility, copy buttons.

What this is
    Browser tests for `/`, `/docs` and `/status` (plan 16.1) served by the real public router behind Roxy's real
    `SecurityHeadersMiddleware`, in headless Chromium, in the light and the dark theme.

Why it exists
    The unit tests read the HTML and the stylesheet as text; only a browser shows what a visitor gets. Here the
    strict CSP (plan 9.2) must report no violation with the server-side Luau highlighting in place, every
    highlight color as the browser computes it must keep 4.5:1 against the code block it sits on (WCAG 1.4.3),
    axe-core must find nothing serious, and the Copy button must copy the example exactly as it is in its .luau
    file, without the markup the highlighter adds.

How it works
    `public_server` runs a slim app (the public router, the real templates, hashed static files and security
    headers; no databases, so the status page shows "degraded", which is fine for these checks) with uvicorn on
    127.0.0.1 in a thread. The `browser`, `open_page`, `wait_js` and `axe` fixtures come from tests/e2e/conftest.py.
    Computed colors are read through the DevTools protocol (`page.evaluate`), outside the page's CSP.

What to read next
    `roxy/public/pages.py`, `roxy/public/luau_highlight.py`, `roxy/static/public/site.css` and `site.js`.
"""

from __future__ import annotations

import re
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import Response

PAGES = ("/", "/docs", "/status")
THEMES = ("light", "dark")
TEXT_MIN = 4.5  # WCAG 1.4.3


def build_public_app() -> FastAPI:
    from roxy.config.env import EnvSettings
    from roxy.core.security_headers import SecurityHeadersMiddleware
    from roxy.core.templating import STATIC_DIR, STATIC_URL_PREFIX, AssetHasher, HashedStaticFiles, Templates
    from roxy.public import pages

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(SecurityHeadersMiddleware)
    app.state.env = EnvSettings(
        env="development", state_dir=Path(tempfile.mkdtemp(prefix="roxy-e2e-public-")), site_origin="http://localhost"
    )
    hasher = AssetHasher(STATIC_DIR)
    app.state.templates = Templates(hasher=hasher)
    app.mount(STATIC_URL_PREFIX, HashedStaticFiles(directory=STATIC_DIR, hasher=hasher), name="static")
    app.include_router(pages.router)
    app.state.csp_reports = []

    @app.post("/csp-report")
    async def csp_report(request: Request) -> Response:
        app.state.csp_reports.append((await request.body())[:8192].decode("utf-8", "replace"))
        return Response(status_code=204)

    return app


@pytest.fixture(scope="module")
def public_server() -> Iterator[str]:
    import uvicorn

    app = build_public_app()
    config = uvicorn.Config(
        app, host="127.0.0.1", port=0, log_level="warning", lifespan="off", timeout_graceful_shutdown=1
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, name="e2e-public-uvicorn", daemon=True)
    thread.start()
    deadline = time.monotonic() + 20
    while not server.started:
        if time.monotonic() > deadline or not thread.is_alive():
            pytest.fail("the public e2e server did not start")
        time.sleep(0.05)
    port = server.servers[0].sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=10)


def luminance(rgb: tuple[float, float, float]) -> float:
    def channel(value: float) -> float:
        c = value / 255
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    red, green, blue = rgb
    return 0.2126 * channel(red) + 0.7152 * channel(green) + 0.0722 * channel(blue)


def contrast(first: tuple[float, float, float], second: tuple[float, float, float]) -> float:
    high, low = sorted((luminance(first), luminance(second)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def rgb(css_color: str) -> tuple[float, float, float]:
    match = re.fullmatch(r"rgba?\(\s*([\d.]+),\s*([\d.]+),\s*([\d.]+)(?:,\s*([\d.]+))?\s*\)", css_color.strip())
    assert match is not None, css_color
    assert match.group(4) in (None, "1"), f"a translucent color cannot be judged alone: {css_color}"
    return float(match.group(1)), float(match.group(2)), float(match.group(3))


HIGHLIGHT_COLORS = """() => {
  const found = {};
  for (const span of document.querySelectorAll("pre code.hl span")) {
    const pre = span.closest("pre");
    found[span.className] = {
      color: getComputedStyle(span).color,
      background: getComputedStyle(pre).backgroundColor,
      styled: span.hasAttribute("style"),
    };
  }
  return found;
}"""


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("path", PAGES)
def test_public_pages_have_no_csp_violations_or_errors(
    public_server: str, open_page: Callable[..., Any], wait_js: Callable[..., Any], path: str, theme: str
) -> None:
    record = open_page(color_scheme=theme)
    response = record.page.goto(public_server + path)
    assert response is not None
    assert response.status == 200
    assert "'nonce-" in response.headers["content-security-policy"]
    if path != "/status":
        wait_js(record.page, "document.querySelectorAll('.copy-button').length > 0")  # site.js ran under the CSP
    assert record.csp_violations() == []
    assert record.console_csp() == []
    assert [line for line in record.console if line.startswith("error")] == []
    assert record.errors == []


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("path", ["/", "/docs"])
def test_highlighted_luau_meets_text_contrast(
    public_server: str, open_page: Callable[..., Any], path: str, theme: str
) -> None:
    record = open_page(color_scheme=theme)
    record.page.goto(public_server + path)
    # The theme really applies (else the dark run would only repeat the light one).
    assert record.page.evaluate("matchMedia('(prefers-color-scheme: dark)').matches") is (theme == "dark")
    found: dict[str, dict[str, Any]] = record.page.evaluate(HIGHLIGHT_COLORS)
    expected = {"k", "s", "n", "c", "b", "t", "o"} | ({"i"} if path == "/" else set())
    assert expected <= set(found), sorted(found)
    for css_class, seen in found.items():
        assert seen["styled"] is False, css_class  # colors come from site.css classes only, never inline styles
        ratio = contrast(rgb(seen["color"]), rgb(seen["background"]))
        assert ratio >= TEXT_MIN, (theme, css_class, seen, round(ratio, 2))
    background = luminance(rgb(found["k"]["background"]))
    assert (background < 0.1) if theme == "dark" else (background > 0.8), found["k"]  # a dark or a light code block


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("path", PAGES)
def test_axe_finds_nothing_serious_on_public_pages(
    public_server: str,
    open_page: Callable[..., Any],
    axe: Callable[[Any], list[dict[str, Any]]],
    path: str,
    theme: str,
) -> None:
    record = open_page(color_scheme=theme)
    record.page.goto(public_server + path)
    assert axe(record.page) == []


def test_copy_button_copies_the_example_without_markup(
    public_server: str, open_page: Callable[..., Any], wait_js: Callable[..., Any]
) -> None:
    from roxy.public import pages

    record = open_page(color_scheme="light", permissions=["clipboard-read", "clipboard-write"])
    page = record.page
    page.goto(public_server + "/")
    blocks = page.locator("pre code.language-luau")
    assert blocks.count() == len(pages.HOME_EXAMPLE_NAMES)
    for index, name in enumerate(pages.HOME_EXAMPLE_NAMES):
        page.locator(".code").filter(has=page.locator("code.language-luau")).nth(index).locator(".copy-button").click()
        wait_js(page, "document.getElementById('announcer').textContent.includes('copied')")
        copied = page.evaluate("navigator.clipboard.readText()")
        assert copied == (pages.HOME_EXAMPLES_DIR / f"{name}.luau").read_text(encoding="utf-8"), name
        wait_js(page, "document.getElementById('announcer').textContent === ''", timeout=5.0)
    assert record.csp_violations() == []
