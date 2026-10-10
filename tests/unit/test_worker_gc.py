"""A started worker freezes its startup heap, so full garbage collections stay short (finding LOAD-3).

What this is
    Unit tests for `roxy/worker.py` `freeze_startup_heap` and the `RoxyServer.startup` hook that calls it.

Why it exists
    Every full collection walked the whole startup heap (about 900,000 blocks) with the event loop stopped: 115 to
    125 ms each, measured in the load harness, often enough at 200 requests a second to dominate the tail latency.
    `gc.freeze` after startup takes those objects out of every later collection. Only a real worker may do it: a
    test process that builds many apps must never freeze (frozen garbage cycles are never collected).

How it works
    `gc.freeze` and `gc.collect` are replaced with recorders; uvicorn's own `Server.startup` is replaced with a stub
    that marks the server started (or not), so no socket is opened.

What to read next
    `roxy/worker.py`, `tests/unit/test_worker_shutdown.py`, docs/PERFORMANCE.md (LOAD-3).
"""

from __future__ import annotations

import gc
from typing import Any

import pytest

from roxy import worker


def test_freeze_startup_heap_collects_first_then_freezes(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def collect(*_args: Any) -> int:
        calls.append("collect")
        return 0

    monkeypatch.setattr(gc, "collect", collect)
    monkeypatch.setattr(gc, "freeze", lambda: calls.append("freeze"))
    monkeypatch.setattr(gc, "get_freeze_count", lambda: 1234)
    assert worker.freeze_startup_heap() == 1234
    assert calls == ["collect", "freeze"]  # garbage first, so nothing dead is frozen


@pytest.mark.parametrize("started", [True, False])
async def test_the_server_freezes_only_after_a_successful_startup(
    monkeypatch: pytest.MonkeyPatch, started: bool
) -> None:
    from uvicorn.config import Config
    from uvicorn.server import Server

    frozen: list[int] = []

    async def uvicorn_startup(self: Server, sockets: Any = None) -> None:
        self.started = started

    monkeypatch.setattr(Server, "startup", uvicorn_startup)

    def freeze() -> int:
        frozen.append(1)
        return 7

    monkeypatch.setattr(worker, "freeze_startup_heap", freeze)
    server = worker.RoxyServer(Config(app="the-app"))
    await server.startup()
    assert frozen == ([1] if started else [])


async def test_an_app_lifespan_alone_never_freezes(app: Any) -> None:
    """The freeze lives in the gunicorn worker class only: `create_app` and its lifespan never call it, so a test
    process that runs many apps keeps collecting their garbage."""
    before = gc.get_freeze_count()
    lifespan = app.router.lifespan_context(app)
    await lifespan.__aenter__()
    try:
        assert gc.get_freeze_count() == before
    finally:
        await lifespan.__aexit__(None, None, None)
