"""A started worker freezes its startup heap, so full garbage collections stay short (finding LOAD-3).

What this is
    Unit tests for `roxy/worker.py` `freeze_startup_heap` and the `RoxyServer.startup` hook that calls it.

Why it exists
    Every full collection walked the whole startup heap (about 900,000 blocks) with the event loop stopped: 115 to
    125 ms each, measured in the load harness, often enough at 200 requests a second to dominate the tail latency.
    `gc.freeze` takes those objects out of every later collection: the app as built (its route tables already
    warmed by `create_asgi_app`) before its lifespan, the rest once it started, so the collection that runs while
    the listeners are open is short (docs/PERFORMANCE.md, "Startup warm-up (2026-10-14)"). Only a real worker may
    do it: a test process that builds many apps must never freeze (frozen garbage cycles are never collected).

How it works
    `gc.freeze` and `gc.collect` are replaced with recorders; uvicorn's own `Server.startup` is replaced with a stub
    that marks the server started (or not), so no socket is opened. One test serves the real `create_asgi_app` to
    check that its routes are warm before the first freeze and that the startup log line says so.

What to read next
    `roxy/worker.py`, `tests/unit/test_route_warmup.py`, `tests/unit/test_worker_shutdown.py`,
    docs/PERFORMANCE.md (LOAD-3).
"""

from __future__ import annotations

import gc
import logging
from typing import Any

import pytest

from roxy import worker


def _record_startup(monkeypatch: pytest.MonkeyPatch, calls: list[Any], *, started: bool = True) -> None:
    """uvicorn's startup (the lifespan, then the listeners) and the freeze replaced with recorders into `calls`."""
    from uvicorn.server import Server

    async def uvicorn_startup(self: Server, sockets: Any = None) -> None:
        calls.append("lifespan and listeners")
        self.started = started

    def freeze() -> int:
        calls.append("freeze")
        return 7

    monkeypatch.setattr(Server, "startup", uvicorn_startup)
    monkeypatch.setattr(worker, "freeze_startup_heap", freeze)


def _startup_fields(caplog: pytest.LogCaptureFixture) -> dict[str, Any]:
    records = [record for record in caplog.records if record.getMessage() == "startup_heap_frozen"]
    assert len(records) == 1
    fields: dict[str, Any] = getattr(records[0], "fields", {})
    return fields


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
async def test_the_server_freezes_the_app_before_its_lifespan_and_the_rest_only_after_a_successful_startup(
    monkeypatch: pytest.MonkeyPatch, started: bool
) -> None:
    """The app as built is frozen before the lifespan and the listeners, so the freeze once the app started walks
    only what the lifespan made; a failed start never gets the second freeze."""
    from uvicorn.config import Config

    calls: list[Any] = []
    _record_startup(monkeypatch, calls, started=started)
    server = worker.RoxyServer(Config(app="the-app"))
    await server.startup()
    expected: list[Any] = ["freeze", "lifespan and listeners"]
    assert calls == ([*expected, "freeze"] if started else expected)


async def test_the_served_app_is_warm_before_the_first_freeze_and_the_log_says_so(
    env: Any, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The one startup warm-up runs when the worker loads the app (`create_asgi_app`), before `RoxyServer.startup`:
    the first freeze takes the route tables with the app, and the startup line reports the warm-up."""
    from uvicorn.config import Config

    from roxy.main import create_asgi_app

    served: Any = create_asgi_app(env)  # what `roxy.asgi` builds in each gunicorn worker after the fork
    calls: list[Any] = []
    _record_startup(monkeypatch, calls)
    warm_at_freeze: list[Any] = []
    recorded_freeze = worker.freeze_startup_heap

    def freeze() -> int:
        warm_at_freeze.append(getattr(served.state, "route_warmup", None))
        return recorded_freeze()

    monkeypatch.setattr(worker, "freeze_startup_heap", freeze)
    server = worker.RoxyServer(Config(app=served))
    with caplog.at_level(logging.INFO, logger="roxy.worker"):
        await server.startup()
    assert calls == ["freeze", "lifespan and listeners", "freeze"]
    warmed = served.state.route_warmup.routes
    assert warmed is not None
    assert warmed >= 300
    # The warm-up had run when the app as built was frozen, so its route tables are frozen with it.
    assert warm_at_freeze[0] is served.state.route_warmup
    fields = _startup_fields(caplog)
    assert fields["objects"] == 7
    assert fields["frozen_before_lifespan"] == 7
    assert fields["freeze_before_lifespan_ms"] >= 0
    assert fields["routes_warmed"] == warmed
    assert fields["route_warmup_ms"] == served.state.route_warmup.ms


@pytest.mark.parametrize("kind", ["not an app", "no app", "failed walk"])
async def test_an_app_without_warm_routes_never_stops_the_worker(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, kind: str
) -> None:
    """An app that was not warmed (not built by `create_asgi_app`) or whose walk failed is served all the same; its
    routes are built on the first request, as before, and the startup line says `routes_warmed` None."""
    from types import SimpleNamespace

    from uvicorn.config import Config

    from roxy.main import RouteWarmup

    failed = SimpleNamespace(state=SimpleNamespace(route_warmup=RouteWarmup(routes=None, ms=0.4)))
    served: Any = {"not an app": "the-app", "no app": None, "failed walk": failed}[kind]
    calls: list[Any] = []
    _record_startup(monkeypatch, calls)
    server = worker.RoxyServer(Config(app=served))
    with caplog.at_level(logging.INFO, logger="roxy.worker"):
        await server.startup()
    assert calls == ["freeze", "lifespan and listeners", "freeze"]
    fields = _startup_fields(caplog)
    assert fields["routes_warmed"] is None
    assert fields["route_warmup_ms"] == (0.4 if kind == "failed walk" else None)


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
