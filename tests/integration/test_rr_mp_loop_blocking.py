"""Review round, lens mp: file system calls on the event loop thread while serving public pages.

What this is
    The reproduction of finding mp-5 (fixed): the fully wired application (real lifespan) serves the public pages
    (`/`, `/docs`), and probes on `os.stat`, `builtins.open` and `io.open` record every call made on the event loop
    thread from Roxy's own code. After one warm-up request per page, a steady-state request must make no file
    system call on the loop at all.

Why it exists
    AGENT_BRIEF "never block the event loop" and plan 5.2: one blocking call on the loop stalls every request of
    the worker, and gunicorn kills a worker whose loop is frozen for its `timeout` (30 s). The fix pass removed the
    same class of call from `/health` (finding LOOP-2: a `stat` of each database file on a stalled disk froze the
    worker) and listed the public pages as open (fix1_integrate.md open issue 8, LEAD_NOTES "open for the review
    round"); no test asserted it. Three calls ran on every page render:
    - jinja2's `FileSystemLoader` with the default `auto_reload=True` checked every cached template (and each
      template it extends or includes) with `os.path.getmtime`, a `stat`, before using it;
    - `AssetHasher.file_hash` (`static_url()` in every template) ran `Path.stat()` for every asset reference, and
      read the whole file on the loop the first time or whenever the file changed;
    - `/docs` statted the guide (`pages.load_guide`).
    On a healthy disk each call takes microseconds; on a stalled disk (the LOOP-2 scenario) every page request
    froze the worker, the proxy traffic of that worker included. The fix (the same one closes public-1 and
    public-2): `auto_reload=False`, and the public pages' lifespan compiles the templates, freezes the asset hashes
    and renders the guide on a thread (`Templates.warm`, `pages.load_public_content`).

How it works
    `_install_probes` wraps the three calls before the app starts, and records a call only while the probe is
    active, on the loop thread, and with a frame of `src/roxy` on the stack (so pytest's and httpx's own work is
    ignored).

What to read next
    `roxy/core/templating.py` (`Templates`, `AssetHasher`), `roxy/public/pages.py`, and
    tests/integration/test_review_loop_blocking.py (the earlier review's probes for SQLite, argon2 and zstd).
"""

from __future__ import annotations

import builtins
import io
import os
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from types import FrameType
from typing import Any

import pytest

_SRC_MARKER = f"{os.sep}src{os.sep}roxy{os.sep}"
PAGES = ("/", "/docs")


def _roxy_frame(depth: int = 2, limit: int = 30) -> str:
    """`module:line` of the nearest caller frame inside src/roxy (empty when the call did not come from Roxy)."""
    frame: FrameType | None = sys._getframe(depth)
    for _ in range(limit):
        if frame is None:
            break
        name = frame.f_code.co_filename
        if _SRC_MARKER in name:
            return f"{name.split(_SRC_MARKER, 1)[1]}:{frame.f_lineno}"
        frame = frame.f_back
    return ""


@dataclass
class LoopWatch:
    loop_thread: int
    active: bool = False
    hits: list[tuple[str, str]] = field(default_factory=list)  # (call, where)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def on_loop(self) -> bool:
        return self.active and threading.get_ident() == self.loop_thread

    def record(self, call: str, where: str) -> None:
        with self.lock:
            if len(self.hits) < 2000:
                self.hits.append((call[:160], where))


def _install_probes(monkeypatch: pytest.MonkeyPatch, watch: LoopWatch) -> None:
    def probe(name: str, real: Callable[..., Any]) -> Callable[..., Any]:
        def wrapped(target: Any, *args: Any, **kwargs: Any) -> Any:
            if watch.on_loop():
                where = _roxy_frame()
                if where:
                    watch.record(f"{name} {target}", where)
            return real(target, *args, **kwargs)

        return wrapped

    monkeypatch.setattr(os, "stat", probe("stat", os.stat))
    monkeypatch.setattr(builtins, "open", probe("open", builtins.open))
    monkeypatch.setattr(io, "open", probe("open", io.open))  # pathlib's read_bytes and read_text use io.open


async def test_rr_mp_public_pages_make_no_file_system_call_on_the_loop(
    env: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Steady state, after one warm-up render of each page: `/` and `/docs` must not `stat` or `open` any file on
    the event loop thread (AGENT_BRIEF, plan 5.2; the same rule finding LOOP-2 enforced for `/health`)."""
    import httpx

    from roxy.main import create_app

    watch = LoopWatch(loop_thread=threading.get_ident())
    _install_probes(monkeypatch, watch)
    app = create_app(env)
    lifespan = app.router.lifespan_context(app)
    await lifespan.__aenter__()
    try:
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 50000))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
            headers = {"User-Agent": "Mozilla/5.0", "X-Forwarded-For": "203.0.113.51"}
            for path in PAGES:  # warm-up: templates compiled, assets hashed once
                assert (await http.get(path, headers=headers)).status_code == 200
            watch.active = True
            for path in PAGES:
                response = await http.get(path, headers=headers)
                assert response.status_code == 200, path
            watch.active = False
    finally:
        watch.active = False
        await lifespan.__aexit__(None, None, None)
    where = sorted({hit[1] for hit in watch.hits})
    print(f"\n{len(watch.hits)} file system calls on the loop thread in 2 steady-state page renders, from {where}")
    assert watch.hits == [], watch.hits[:8]
