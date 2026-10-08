"""Browser test fixtures: a live loopback server for the dashboard design system and a headless Chromium.

What this is
    `ui_server` starts a small app on 127.0.0.1 (random port) in a background thread: Roxy's real
    `SecurityHeadersMiddleware` (so every page carries the exact plan 9.2 policy with a fresh nonce), the real
    `Templates` and hashed static files, the development component gallery (`roxy.admin.gallery`), the CSP spike
    page (tests/e2e/spike/), and a `/csp-report` collector. `browser` is one headless Chromium per session;
    `open_page(...)` makes a fresh context per test that records every CSP violation, console error and page error.

Why it exists
    The design system has to be proven in a real browser: the CSP spike (plan 9.2, a P0 gate item moved to P11),
    axe-core accessibility checks in both themes and at phone and desktop sizes (plan 14.9, 19.8), and the
    behaviors only a browser runs (htmx, Alpine, uPlot, the session heartbeat). The app is deliberately slim: it
    does not need databases, so these tests do not depend on the lifespan other phases are still building.

How it works
    uvicorn runs in a daemon thread with its own event loop; the fixture waits until it is serving, then reads the
    bound port. Chromium needs libraries unpacked without root (AGENT_BRIEF), so LD_LIBRARY_PATH is set for the
    browser process. Tests skip cleanly when Playwright or the browser is missing. Every request stays on loopback
    (plan 19.12); the socket guard in tests/conftest.py still applies to the test process itself.

What to read next
    tests/e2e/test_csp_spike.py, tests/e2e/test_design_system.py, src/roxy/admin/gallery.py.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, Response

HERE = Path(__file__).resolve().parent
SPIKE_DIR = HERE / "spike"
AXE_PATH = HERE / "vendor" / "axe-core-4.13.0" / "axe.min.js"
PW_LIBS = Path.home() / ".local" / "pwlibs" / "root" / "usr" / "lib" / "x86_64-linux-gnu"

# Records violations from the moment the document starts, before any page script runs. Playwright injects init
# scripts through the DevTools protocol, outside the page's CSP, so this recorder never causes a violation itself.
CSP_RECORDER = """
window.__csp = [];
document.addEventListener("securitypolicyviolation", (e) => {
  window.__csp.push({directive: e.violatedDirective, blocked: e.blockedURI, source: e.sourceFile,
                     line: e.lineNumber, sample: e.sample, disposition: e.disposition});
});
"""


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Everything in tests/e2e is a browser test (marker `e2e`)."""
    for item in items:
        if HERE in Path(str(item.fspath)).resolve().parents:
            item.add_marker(pytest.mark.e2e)


def _browser_env() -> dict[str, str]:
    env = dict(os.environ)
    extra = f"{PW_LIBS}:{PW_LIBS / 'nss'}"
    env["LD_LIBRARY_PATH"] = f"{extra}:{env['LD_LIBRARY_PATH']}" if env.get("LD_LIBRARY_PATH") else extra
    return env


def build_ui_app() -> FastAPI:
    """The slim app the browser tests talk to (see the module docstring)."""
    from roxy.admin.gallery import include_gallery
    from roxy.config.env import EnvSettings
    from roxy.core.security_headers import SecurityHeadersMiddleware
    from roxy.core.templating import STATIC_DIR, TEMPLATES_DIR, AssetHasher, HashedStaticFiles, Templates

    state_dir = Path(tempfile.mkdtemp(prefix="roxy-e2e-"))
    env = EnvSettings(env="development", state_dir=state_dir, site_origin="http://localhost")
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(SecurityHeadersMiddleware)
    app.state.env = env
    hasher = AssetHasher(STATIC_DIR)
    app.state.templates = Templates(directories=(TEMPLATES_DIR, SPIKE_DIR), hasher=hasher)
    app.state.csp_reports = []
    app.mount("/static", HashedStaticFiles(directory=STATIC_DIR, hasher=hasher), name="static")
    include_gallery(app, env)

    @app.get("/admin/_spike", response_class=HTMLResponse)
    async def spike_page(request: Request) -> HTMLResponse:
        bad_sri = request.query_params.get("sri") == "bad"
        return app.state.templates.render(request, "spike.html", {"bad_sri": bad_sri})  # type: ignore[no-any-return]

    @app.get("/admin/_spike/fragment", response_class=HTMLResponse)
    async def spike_fragment(request: Request) -> HTMLResponse:
        await asyncio.sleep(0.4)  # long enough for the htmx indicator to show
        raw = request.query_params.get("n", "1")
        n = int(raw) if raw.isdigit() and len(raw) < 4 else 1
        return HTMLResponse(
            f'<div id="swapped-{n}" class="swapped" data-n="{n}"><p>Swapped fragment {n}</p>'
            f'<button type="button" id="inner-{n}" hx-get="/admin/_spike/fragment?n={n + 1}" '
            f'hx-target="#swapped-{n}" hx-swap="outerHTML">Swap again</button></div>'
        )

    @app.post("/csp-report")
    async def csp_report(request: Request) -> Response:
        body = (await request.body())[:8192]
        app.state.csp_reports.append(body.decode("utf-8", "replace"))
        return Response(status_code=204)

    return app


@dataclass
class UIServer:
    base_url: str
    app: FastAPI


@pytest.fixture(scope="session")
def ui_server() -> Iterator[UIServer]:
    import uvicorn

    app = build_ui_app()
    config = uvicorn.Config(
        app, host="127.0.0.1", port=0, log_level="warning", lifespan="off", timeout_graceful_shutdown=1
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, name="e2e-uvicorn", daemon=True)
    thread.start()
    deadline = time.monotonic() + 20
    while not server.started:
        if time.monotonic() > deadline or not thread.is_alive():
            pytest.fail("the e2e server did not start")
        time.sleep(0.05)
    port = server.servers[0].sockets[0].getsockname()[1]
    yield UIServer(base_url=f"http://127.0.0.1:{port}", app=app)
    server.should_exit = True
    thread.join(timeout=10)


@pytest.fixture(scope="module")
def browser() -> Iterator[Any]:
    # Module scope, not session: Playwright's sync API keeps its own event loop marked as running in the main
    # thread until `stop()`, and every pytest-asyncio test collected after tests/e2e in the same run would then fail
    # with "Runner.run() cannot be called from a running event loop".
    sync_api = pytest.importorskip("playwright.sync_api")
    manager = sync_api.sync_playwright().start()
    try:
        instance = manager.chromium.launch(env=_browser_env())
    except Exception as error:  # the browser or its libraries are not installed here
        manager.stop()
        pytest.skip(f"Chromium cannot start: {error}")
    yield instance
    instance.close()
    manager.stop()


@dataclass
class PageRecord:
    """A page plus everything it reported: CSP violations, console errors and uncaught page errors."""

    page: Any
    console: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def csp_violations(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = self.page.evaluate("window.__csp || []")
        return result

    def console_csp(self) -> list[str]:
        return [line for line in self.console if "Content Security Policy" in line]


@pytest.fixture
def open_page(browser: Any) -> Iterator[Callable[..., PageRecord]]:
    contexts: list[Any] = []

    def factory(width: int = 1440, height: int = 900, color_scheme: str = "dark", **options: Any) -> PageRecord:
        context = browser.new_context(viewport={"width": width, "height": height}, color_scheme=color_scheme, **options)
        contexts.append(context)
        page = context.new_page()
        record = PageRecord(page)
        page.add_init_script(CSP_RECORDER)
        page.on("console", lambda message: record.console.append(f"{message.type}: {message.text}"))
        page.on("pageerror", lambda error: record.errors.append(str(error)))
        return record

    yield factory
    for context in contexts:
        context.close()


def wait_for_js(page: Any, expression: str, timeout: float = 10.0) -> Any:
    """Poll a JavaScript expression until it is truthy and return its value.

    Playwright's `wait_for_function` evaluates its predicate with eval inside the page, which the strict CSP
    refuses (and reports as a violation). `page.evaluate` runs through the DevTools protocol instead, outside the
    page's CSP, so polling with it leaves the violation log clean.
    """
    deadline = time.monotonic() + timeout
    while True:
        value = page.evaluate(expression)
        if value:
            return value
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out after {timeout} s waiting for: {expression}")
        page.wait_for_timeout(50)


def run_axe(page: Any) -> list[dict[str, Any]]:
    """Run the vendored axe-core in the page and return violations with impact serious or critical.

    axe is evaluated through the DevTools protocol (page.evaluate), not added as a <script>, so the page's CSP is not
    loosened for the test and cannot block it.
    """
    page.evaluate(AXE_PATH.read_text(encoding="utf-8") + "\n;0")
    result: dict[str, Any] = page.evaluate(
        """async () => await axe.run(document, {
             runOnly: {type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"]},
             resultTypes: ["violations"]})"""
    )
    return [
        {"id": v["id"], "impact": v["impact"], "help": v["help"], "nodes": [n["target"] for n in v["nodes"]][:8]}
        for v in result["violations"]
        if v.get("impact") in ("serious", "critical")
    ]


@pytest.fixture
def wait_js() -> Callable[..., Any]:
    """The wait_for_js helper as a fixture (test modules cannot import this conftest by name)."""
    return wait_for_js


@pytest.fixture
def axe() -> Callable[[Any], list[dict[str, Any]]]:
    """The run_axe helper as a fixture."""
    return run_axe
