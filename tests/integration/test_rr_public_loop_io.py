"""Adversarial review (public site lens): file system calls the public pages make on the event loop thread.

What this is
    Tests that serve the public pages through the fully wired app (`create_app` with its lifespan) and record every
    `os.stat` and every `open` made on the event loop thread from Roxy's public page or templating code while a
    page is being answered. Each page is fetched once before the probes go live, so one-time work (the first
    template compile, the first asset hash, `functools.cache` fills) is excluded: what remains is what EVERY visit
    pays.

Why it exists
    AGENT_BRIEF "never block the event loop": one blocking call on the loop stalls every request of the worker,
    including the proxy's. Finding LOOP-2 (`/health` stat calls) was fixed for that reason, and the lead's notes
    leave the public pages open for this review ("public pages and core/templating open/stat templates on the
    loop"). A `stat` is microseconds on a healthy disk, but on a stalled one (the case LOOP-2 was about) every
    anonymous visit to `/`, `/docs` or `/status` freezes the whole worker.
    - Finding public-1 (fixed): `Templates.render` statted every template on every render (Jinja's `auto_reload`,
      also for the `extends` parent) and `static_url()` statted every asset it names (`AssetHasher.file_hash`),
      all on the loop. Now `auto_reload` is off and the lifespan compiles the templates and freezes the asset
      hashes on a thread (`Templates.warm`).
    - Finding public-2 (fixed): `/docs` statted `docs/USER_GUIDE.md` on every request (`pages.load_guide`), on
      the loop. Now the lifespan renders the guide on a thread and the route serves it from `app.state`.
    Since the lifespan does all the file work up front, even the FIRST visit after startup makes no file system
    call on the loop (`test_rr_public_first_visits_make_no_file_system_call_on_the_loop`).

How it works
    `os.stat`, `builtins.open` and `io.open` are wrapped. A call counts when it runs on the loop thread while the
    watch is active and its stack (walked in full) contains a frame from `roxy/public/pages.py` or
    `roxy/core/templating.py`, so background loops of the lifespan that happen to run meanwhile are not blamed.

What to read next
    `roxy/core/templating.py` (`Templates`, `AssetHasher`), `roxy/public/pages.py` (`load_guide`), and
    `tests/integration/test_review_loop_blocking.py` (the same probe idea for the proxy path and `/health`).
"""

from __future__ import annotations

import builtins
import io
import os
import re
import sys
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from types import FrameType
from typing import Any

import httpx
import pytest

_WATCHED_FILES = (
    f"{os.sep}roxy{os.sep}public{os.sep}pages.py",
    f"{os.sep}roxy{os.sep}core{os.sep}templating.py",
)
PAGES = ("/", "/docs", "/status", "/sitemap.xml", "/robots.txt")


@dataclass
class Watch:
    """Blocking file calls seen on the loop thread from the public page or templating code."""

    loop_thread: int
    active: bool = False
    page: str = ""
    hits: list[tuple[str, str, str, str]] = field(default_factory=list)  # (page, call, target, roxy frame)

    def roxy_frame(self) -> str:
        """`file:line` of the nearest frame in pages.py or templating.py, or "" when none is on the stack."""
        frame: FrameType | None = sys._getframe(2)
        while frame is not None:
            name = frame.f_code.co_filename
            if name.endswith(_WATCHED_FILES):
                return f"{name.rsplit(os.sep, 3)[-1]}:{frame.f_lineno}"
            frame = frame.f_back
        return ""

    def check(self, call: str, target: Any) -> None:
        if not self.active or threading.get_ident() != self.loop_thread:
            return
        where = self.roxy_frame()
        if where:
            self.hits.append((self.page, call, os.fspath(target) if isinstance(target, os.PathLike) else str(target),
                              where))  # fmt: skip


@pytest.fixture
def watch(monkeypatch: pytest.MonkeyPatch) -> Iterator[Watch]:
    found = Watch(loop_thread=threading.get_ident())
    real_stat, real_open, real_io_open = os.stat, builtins.open, io.open

    def wrap(call: str, real: Callable[..., Any]) -> Callable[..., Any]:
        def probe(target: Any, *args: Any, **kwargs: Any) -> Any:
            found.check(call, target)
            return real(target, *args, **kwargs)

        return probe

    monkeypatch.setattr(os, "stat", wrap("stat", real_stat))
    monkeypatch.setattr(builtins, "open", wrap("open", real_open))
    monkeypatch.setattr(io, "open", wrap("open", real_io_open))
    yield found
    found.active = False


async def _visit_every_page(client: httpx.AsyncClient, watch: Watch) -> None:
    headers = {"User-Agent": "Mozilla/5.0", "X-Forwarded-For": "203.0.113.40"}
    home = (await client.get("/", headers=headers)).text
    stylesheet = re.search(r'href="(/static/public/site\.[0-9a-f]{10}\.css)"', home)
    assert stylesheet is not None
    # The hashed stylesheet too: in production nginx serves it, but any name a release does not have (an old or a
    # made-up hash) falls back to the app (`@roxy_static_fallback`), whose `HashedStaticFiles` resolves it here.
    paths = (*PAGES, stylesheet.group(1))
    for path in paths:  # warm up: first compiles, first hashes and cached reads are not what this test is about
        assert (await client.get(path, headers=headers)).status_code == 200, path
    watch.active = True
    for path in paths:
        watch.page = path
        assert (await client.get(path, headers=headers)).status_code == 200, path
    watch.active = False


async def test_rr_public_page_renders_make_no_file_system_call_on_the_loop(
    client: httpx.AsyncClient, watch: Watch
) -> None:
    await _visit_every_page(client, watch)
    from_templating = [hit for hit in watch.hits if "templating.py" in hit[3]]
    print("\nfile system calls on the loop from core/templating.py:", from_templating)
    assert from_templating == []


async def test_rr_public_docs_makes_no_file_system_call_on_the_loop(client: httpx.AsyncClient, watch: Watch) -> None:
    await _visit_every_page(client, watch)
    from_pages = [hit for hit in watch.hits if "pages.py" in hit[3]]
    print("\nfile system calls on the loop from public/pages.py:", from_pages)
    assert from_pages == []


async def test_rr_public_first_visits_make_no_file_system_call_on_the_loop(
    app: Any, client: httpx.AsyncClient, watch: Watch
) -> None:
    """Stronger than the two above: no warm-up at all. The lifespan already compiled every template, hashed every
    asset, rendered the guide and read the crawler files on a thread, so even the first visit to each page (and
    to a hashed asset the app serves, with the current hash, an old one and one the release does not have) reads
    memory only."""
    hasher = app.state.templates.hasher
    assert hasher.frozen
    stylesheet = hasher.url("public/site.css")  # before the watch: the test's own call is not a page's
    headers = {"User-Agent": "Mozilla/5.0", "X-Forwarded-For": "203.0.113.41"}
    paths = (
        *PAGES,
        "/favicon.ico",
        stylesheet,
        "/static/public/site.0123456789.css",
        "/static/public/no.0123456789.css",
    )
    watch.active = True
    statuses = {}
    for path in paths:
        watch.page = path
        statuses[path] = (await client.get(path, headers=headers)).status_code
    watch.active = False
    assert statuses == {**dict.fromkeys(paths, 200), "/static/public/no.0123456789.css": 404}, statuses
    print("\nfile system calls on the loop on first visits:", watch.hits)
    assert watch.hits == []
