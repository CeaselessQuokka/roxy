"""Review round, lens mp: a slow log reader (journald) must not freeze the event loop.

What this is
    The reproduction (now a regular test) of finding mp-11. The fully wired application (real lifespan, `respx` playing
    Roblox) logs to `sys.stderr`, which the test replaces with the write end of a pipe, as systemd connects a
    service's stderr to journald. A reader thread plays journald. After startup the reader pauses (journald busy
    flushing to a slow disk, or restarting) and the pipe is filled; then one request is served whose answer is a
    5xx (Roblox answers 503), which the request log writes at WARNING, while a ticker task measures how long the
    event loop stops ticking. The reader resumes after 3 s.

Why it exists
    AGENT_BRIEF "never block the event loop" and plan 5.2: one blocking call on the loop stalls every request of the
    worker, and gunicorn kills a worker whose loop is frozen for its `timeout` (30 s). `roxy.core.logging` installs
    a plain `logging.StreamHandler` on stderr, so every log line at INFO or above (the `http_request` line of every
    5xx answer and of every request slower than 10 s, upstream and degraded warnings, and the lines of every
    background loop of the worker) is a blocking `write()` on the event loop thread. When journald stops reading
    for a moment, the pipe buffer (64 KiB) fills and the next log call freezes the whole worker, proxy traffic
    included, until journald reads again. An incident is exactly when warnings are logged per request, and a stall
    of 30 s gets every worker killed, each new one blocking again on its first startup line. The fix pass removed
    `stat` calls (LOOP-2) and capture encoding (LOOP-1) from the loop; log writes are the same class (a queue
    handler with a bounded queue and a writer thread is the usual fix, dropping and counting lines when full).

How it works
    `_Journal` reads the pipe on a thread (polling with `select`, so a pause really stops reading). The pipe is
    filled with non-blocking writes until the kernel refuses more, then switched back to blocking, which is what
    the handler's stream uses. Fixed: the lifespan configures logging with `background=True`, so lines are
    formatted and scrubbed on the logging thread and written by `core.logging.BackgroundLogWriter`'s own thread
    through a bounded queue (dropped and counted when full); the shutdown flushes it within its budget.

What to read next
    `roxy/core/logging.py` (`configure_logging`), `roxy/core/middleware.py` (the `http_request` line and its
    levels), `roxy/lifespan.py` (where logging is configured), tests/integration/test_review_loop_blocking.py.
"""

from __future__ import annotations

import asyncio
import fcntl
import os
import select
import sys
import threading
import time
from typing import Any

import httpx
import pytest

pytestmark = [pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX pipes")]

STALL_S = 3.0
"""How long the log reader pauses (a short journald hiccup)."""


class _Journal:
    """Reads the pipe like journald, until told to pause; resumes when `reading` is set again."""

    def __init__(self, read_fd: int) -> None:
        self.read_fd = read_fd
        self.reading = threading.Event()
        self.reading.set()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, name="rr-mp-journal", daemon=True)

    def _run(self) -> None:
        while not self.stop.is_set():
            if not self.reading.wait(0.05):
                continue
            # Never park inside a blocking read: a paused journal must not drain the pipe a moment later.
            ready, _, _ = select.select([self.read_fd], [], [], 0.02)
            if not ready or not self.reading.is_set():
                continue
            try:
                chunk = os.read(self.read_fd, 65536)
            except OSError:
                return
            if not chunk:
                return


def _fill(write_fd: int) -> int:
    """Fill the pipe until the kernel would block; return the bytes written."""
    flags = fcntl.fcntl(write_fd, fcntl.F_GETFL)
    fcntl.fcntl(write_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
    written = 0
    try:
        while True:
            try:
                written += os.write(write_fd, b"x" * 4096)
            except BlockingIOError:
                break
    finally:
        fcntl.fcntl(write_fd, fcntl.F_SETFL, flags)
    return written


@pytest.mark.timeout(60)
async def test_rr_mp_a_paused_log_reader_never_freezes_the_event_loop(
    env: Any, respx_mock: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from roxy.main import create_app

    respx_mock.route(host="games.roblox.com").mock(return_value=httpx.Response(503, json={"errors": []}))
    read_fd, write_fd = os.pipe()
    journal = _Journal(read_fd)
    journal.thread.start()
    stream = os.fdopen(write_fd, "w", buffering=1, encoding="utf-8")
    monkeypatch.setattr(sys, "stderr", stream)  # what systemd does: stderr is journald's stream
    app = create_app(env)
    lifespan = app.router.lifespan_context(app)
    await lifespan.__aenter__()
    gaps: list[float] = []
    status = 0
    try:
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 50000))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver", timeout=60) as http:
            headers = {"User-Agent": "Roblox/Linux", "X-Forwarded-For": "203.0.113.71"}
            assert (await http.get("/health", headers=headers)).status_code == 200
            journal.reading.clear()  # journald stops reading for a moment
            await asyncio.sleep(0.2)
            assert _fill(write_fd) > 0
            threading.Timer(STALL_S, journal.reading.set).start()

            async def ticker() -> None:
                last = time.monotonic()
                while True:
                    await asyncio.sleep(0.02)
                    now = time.monotonic()
                    gaps.append(now - last)
                    last = now

            tick = asyncio.create_task(ticker())
            await asyncio.sleep(0.1)
            response = await http.get("/games.roblox.com/v1/games?universeIds=1", headers=headers)
            status = response.status_code
            await asyncio.sleep(0.1)
            tick.cancel()
    finally:
        journal.reading.set()
        await lifespan.__aexit__(None, None, None)
        journal.stop.set()
        monkeypatch.undo()
        stream.close()
        journal.thread.join(5)
        os.close(read_fd)
    stall = max(gaps, default=0.0)
    print(f"\nanswer {status}; longest event loop stall while journald paused {STALL_S} s: {stall:.2f} s")
    assert status >= 500, "Roblox's 503 reached the caller as a 5xx answer (a WARNING request log line)"
    assert stall < 1.0, f"the event loop froze for {stall:.2f} s waiting for the log reader"
