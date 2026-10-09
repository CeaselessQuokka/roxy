"""Public pages read memory only while answering: frozen asset hashes, warmed templates, and the bare-app fallback.

What this is
    Unit tests for the startup work that keeps file system calls off the event loop (review findings public-1,
    public-2 and mp-5): `AssetHasher.freeze`, `Templates.warm` (`roxy/core/templating.py`), and the pages'
    fallbacks for an app whose lifespan did not run (`served_guide`, `_cached_value` in `roxy/public/pages.py`).

Why it exists
    One blocking `stat` or `open` on the loop thread stalls every request of a worker, the proxy's included, for as
    long as the disk does. The integration tests (`tests/integration/test_rr_public_loop_io.py`,
    `test_rr_mp_loop_blocking.py`) watch the wired app; these pin each building block on its own, including the
    parts a wired app never reaches (the bound on frozen hashes, a template that does not compile, an app without
    its lifespan).

How it works
    "No file system call" is proven by making `os.stat`, `io.open` and `open` raise after the startup work:
    anything that still touched the disk would fail. Temporary directories hold the templates and assets.

What to read next
    `roxy/core/templating.py`, `roxy/public/pages.py` (`load_public_content`), and the integration tests above.
"""

from __future__ import annotations

import asyncio
import builtins
import hashlib
import io
import logging
import os
from pathlib import Path
from typing import Any

import httpx
import jinja2
import pytest
from fastapi import FastAPI

from roxy.core import templating
from roxy.core.templating import AssetHasher, Templates
from roxy.public import pages


def make_static(tmp_path: Path) -> Path:
    static = tmp_path / "static"
    (static / "css").mkdir(parents=True)
    (static / "css" / "app.css").write_text("body { color: black; }\n", encoding="utf-8")
    (static / "app.js").write_text("export {};\n", encoding="utf-8")
    return static


def test_a_frozen_hasher_answers_from_memory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    static = make_static(tmp_path)
    live = AssetHasher(static)
    frozen = AssetHasher(static)
    assert not frozen.frozen
    assert frozen.freeze() == 2
    assert frozen.frozen
    digest = hashlib.sha256((static / "css" / "app.css").read_bytes()).hexdigest()[:10]
    (static / "late.css").write_text("added after the freeze\n", encoding="utf-8")

    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("the frozen hasher touched the disk")

    monkeypatch.setattr(os, "stat", refuse)
    monkeypatch.setattr(io, "open", refuse)
    monkeypatch.setattr(builtins, "open", refuse)
    assert frozen.url("css/app.css") == f"/static/css/app.{digest}.css"
    assert frozen.resolve(f"css/app.{digest}.css") == ("css/app.css", True)
    assert frozen.resolve("css/app.0123456789.css") == ("css/app.css", False)  # an old hash: same file, no-cache
    assert frozen.resolve("css/none.0123456789.css") == ("css/none.0123456789.css", False)
    assert frozen.url("late.css") == "/static/late.css"  # unseen until the next process, like any release file
    assert frozen.url("../etc/passwd") == "/static/../etc/passwd"  # never leaves the directory, never a lookup
    monkeypatch.undo()
    assert live.url("css/app.css") == frozen.url("css/app.css")  # the same names as the live hasher


def test_freeze_keeps_lookups_live_past_the_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Plan P9: a directory with more files than the bound is not held in memory; lookups stay live."""
    static = make_static(tmp_path)
    monkeypatch.setattr(templating, "_MAX_CACHED_ASSETS", 1)
    hasher = AssetHasher(static)
    with caplog.at_level(logging.WARNING, logger="roxy.core.templating"):
        assert hasher.freeze() == 0
    assert not hasher.frozen
    assert "static_assets_not_frozen" in caplog.text
    assert hasher.url("app.js").startswith("/static/app.")


def test_warm_compiles_templates_and_renders_never_touch_the_disk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "templates"
    root.mkdir()
    (root / "base.html").write_text("<link href=\"{{ static_url('site.css') }}\">{% block content %}{% endblock %}")
    (root / "page.html").write_text('{% extends "base.html" %}{% block content %}<p>{{ name }}</p>{% endblock %}')
    (root / "data.txt").write_text("not a page template")
    static = tmp_path / "static"
    static.mkdir()
    (static / "site.css").write_text("p {}\n")
    templates = Templates(directories=(root,), hasher=AssetHasher(static))
    assert templates.env.auto_reload is False
    assert templates.warm() == 2  # base.html and page.html; data.txt is not a page template
    assert templates.hasher.frozen

    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError(f"file system call while rendering: {args[:1]}")

    monkeypatch.setattr(os, "stat", refuse)
    monkeypatch.setattr(io, "open", refuse)
    monkeypatch.setattr(builtins, "open", refuse)
    for _ in range(2):  # the first render after warm() and every later one: memory only
        html = templates.env.get_template("page.html").render(name="<b>")
        assert html.startswith('<link href="/static/site.')
        assert html.endswith("<p>&lt;b&gt;</p>")
    monkeypatch.undo()
    # auto_reload is off: an edit is not seen by this process (a release never edits its files; a restart does).
    (root / "page.html").write_text("changed")
    assert templates.env.get_template("page.html").render(name="x").endswith("<p>x</p>")


def test_warm_logs_and_skips_a_template_that_does_not_compile(caplog: pytest.LogCaptureFixture) -> None:
    loader = jinja2.DictLoader({"good.html": "<p>ok</p>", "broken.html": "{% if %}", "notes.txt": "{% if %}"})
    templates = Templates(loader=loader, hasher=AssetHasher(Path("/nonexistent-static-dir")))
    with caplog.at_level(logging.WARNING, logger="roxy.core.templating"):
        assert templates.warm() == 1  # notes.txt is not listed for warming; broken.html is logged, not raised
    assert "template_warm_failed" in caplog.text
    assert templates.hasher.frozen  # an empty static directory freezes to an empty map
    assert templates.warm(["good.html"]) == 1


def test_the_lifespan_warms_the_templates_anonymous_visitors_reach() -> None:
    """Public and sign-in pages compile at startup; dashboard templates (behind the sign-in) on first use."""
    names = ("public/a.html", "auth/b.html", "admin/c.html", "public/robots.txt", "components/d.html")
    loader = jinja2.DictLoader(dict.fromkeys(names, "x"))
    templates = Templates(loader=loader, hasher=AssetHasher(Path("/nonexistent-static-dir")))
    assert templates.page_templates(pages.ANONYMOUS_TEMPLATE_PREFIXES) == ["auth/b.html", "public/a.html"]
    assert len(templates.page_templates()) == 4  # every .html template


async def test_an_app_without_its_lifespan_still_serves_from_a_thread(monkeypatch: pytest.MonkeyPatch) -> None:
    """The routes never read files on the loop, even when nothing warmed them: the guide, robots.txt and the build
    date are loaded once on a worker thread, and the guide is then kept on the app."""
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)  # /docs is the guide, not Swagger
    app.include_router(pages.router)  # no lifespan runs: ASGITransport does not send lifespan events
    assert getattr(app.state, pages.GUIDE_STATE_ATTRIBUTE, None) is None
    threads: list[Any] = []
    real_to_thread = asyncio.to_thread

    async def counting_to_thread(fn: Any, *args: Any) -> Any:
        threads.append(fn)
        return await real_to_thread(fn, *args)

    monkeypatch.setattr(asyncio, "to_thread", counting_to_thread)  # pages.py calls asyncio.to_thread
    pages.robots_bytes.cache_clear()
    pages.build_time.cache_clear()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        assert (await client.get("/docs")).status_code == 200
        assert (await client.get("/robots.txt")).status_code == 200
        assert (await client.get("/sitemap.xml")).status_code == 200
        assert (await client.get("/robots.txt")).status_code == 200  # cached now: no second thread hop
        assert (await client.get("/docs")).status_code == 200
    assert isinstance(getattr(app.state, pages.GUIDE_STATE_ATTRIBUTE), pages.RenderedGuide)
    assert threads == [pages.load_guide, pages.robots_bytes, pages.build_time]
