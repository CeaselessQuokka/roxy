"""A stopping worker always runs its lifespan shutdown before gunicorn's kill (finding SHUTDOWN-HOLD).

What this is
    Unit tests for `roxy/worker.py` (uvicorn's `timeout_graceful_shutdown` derived from gunicorn's settings, the
    `RoxyServer` drain hook) and the shutdown path of `roxy/lifespan.py` (`begin_drain`, the shared shutdown
    budget). The real-gunicorn proof is tests/multiprocess/test_review_gunicorn_mp.py.

Why it exists
    gunicorn kills a worker `graceful_timeout` after asking it to stop. uvicorn waited without a limit for open
    requests, a tarpit hold lasts up to 55 s, and the lifespan shutdown (final metrics flush, leader lease release)
    then never ran. Each piece of the fix is pinned here so a refactor cannot quietly undo one.

How it works
    Plain function calls with fake contexts, one real gunicorn `Worker` object built from gunicorn's own config
    (no process is started), and one real app lifespan whose metrics loop ignores its stop signal.

What to read next
    `roxy/worker.py`, `roxy/lifespan.py` (`begin_drain`, `shutdown_time_left`), `deploy/gunicorn.conf.py`.
"""

from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace
from typing import Any

import pytest

from roxy import lifespan, worker


@pytest.mark.parametrize(
    ("graceful", "timeout", "expected"),
    [(30, 30, 20.0), (30, 0, 20.0), (30, 60, 20.0), (20, 60, 10.0), (60, 30, 20.0), (5, 30, 1.0)],
)
def test_graceful_shutdown_fits_inside_gunicorns_limits(graceful: int, timeout: int, expected: float) -> None:
    value = worker.graceful_shutdown_s(graceful, timeout)
    assert value == expected
    limit = min(graceful, timeout) if timeout else graceful
    if limit > lifespan.SHUTDOWN_BUDGET_S + worker.SHUTDOWN_MARGIN_S:
        assert value + lifespan.SHUTDOWN_BUDGET_S + worker.SHUTDOWN_MARGIN_S <= limit


def test_the_worker_class_caps_uvicorns_graceful_wait() -> None:
    from gunicorn.config import Config
    from gunicorn.glogging import Logger

    cfg = Config()
    cfg.set("graceful_timeout", 30)
    cfg.set("timeout", 30)
    built = worker.RoxyUvicornWorker(0, 1, [], None, 15.0, cfg, Logger(cfg))
    assert built.config.timeout_graceful_shutdown == 20.0
    assert built.config.timeout_keep_alive == 75  # the class options still apply


async def test_roxy_server_drains_before_uvicorn_waits(monkeypatch: pytest.MonkeyPatch) -> None:
    from uvicorn.config import Config
    from uvicorn.server import Server

    order: list[str] = []
    monkeypatch.setattr(lifespan, "begin_drain", lambda app: order.append(f"drain {app}"))

    async def uvicorn_shutdown(self: Server, sockets: Any = None) -> None:
        order.append("uvicorn waits for open requests")

    monkeypatch.setattr(Server, "shutdown", uvicorn_shutdown)
    server = worker.RoxyServer(Config(app="the-app"))
    await server.shutdown()
    assert order == ["drain the-app", "uvicorn waits for open requests"]


class FakeTarpit:
    def __init__(self) -> None:
        self.woken = 0

    def wake_all(self) -> None:
        self.woken += 1


def _app_with(ctx: Any) -> Any:
    return SimpleNamespace(state=SimpleNamespace(ctx=ctx))


def test_begin_drain_drops_readiness_and_wakes_the_tarpit() -> None:
    tarpit = FakeTarpit()
    ctx = SimpleNamespace(ready=True, worker_id="w1", abuse=SimpleNamespace(tarpit=tarpit))
    lifespan.begin_drain(_app_with(ctx))
    assert ctx.ready is False
    assert tarpit.woken == 1
    # roxy.asgi serves a ListenerDispatcher: the public app is behind `.public`.
    lifespan.begin_drain(SimpleNamespace(public=_app_with(ctx)))
    assert tarpit.woken == 2


@pytest.mark.parametrize(
    "app",
    [
        SimpleNamespace(),  # no state at all
        _app_with(None),  # startup did not finish
        _app_with(SimpleNamespace(ready=True, worker_id="w", abuse=None)),  # no abuse pipeline
        _app_with(SimpleNamespace(ready=True, worker_id="w", abuse=SimpleNamespace(tarpit=object()))),  # no hook
    ],
)
def test_begin_drain_never_raises(app: Any) -> None:
    lifespan.begin_drain(app)


def test_begin_drain_survives_a_failing_hook() -> None:
    class Broken:
        def wake_all(self) -> None:
            raise RuntimeError("boom")

    ctx = SimpleNamespace(ready=True, worker_id="w", abuse=SimpleNamespace(tarpit=Broken()))
    lifespan.begin_drain(_app_with(ctx))
    assert ctx.ready is False


async def test_shutdown_time_left_follows_the_budget() -> None:
    assert lifespan.shutdown_time_left(10.0) == 10.0  # not shutting down: the step's own cap

    async def in_shutdown() -> tuple[float, float]:
        lifespan._shutdown_deadline.set(time.monotonic() + 3.0)
        return lifespan.shutdown_time_left(10.0), lifespan.shutdown_time_left(1.0)

    first, second = await asyncio.create_task(in_shutdown())  # its own context, like the lifespan task
    assert 2.5 < first <= 3.0
    assert second == 1.0

    async def spent() -> float:
        lifespan._shutdown_deadline.set(time.monotonic() - 5.0)
        return lifespan.shutdown_time_left(10.0)

    assert await asyncio.create_task(spent()) == lifespan.SHUTDOWN_MIN_STEP_S
    assert lifespan.shutdown_time_left(10.0) == 10.0  # the other tasks' deadlines never leak into this one


async def test_a_stuck_loop_cannot_push_the_final_flush_past_the_budget(
    env: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A background loop that ignores its stop signal is cut off when the shutdown budget is spent, and the final
    metrics flush (and every later cleanup) still runs. Without the budget that loop alone would hold the shutdown
    for `LOOP_STOP_TIMEOUT_S` (10 s)."""
    from roxy.main import create_app
    from roxy.metrics.recorder import MetricsRecorder

    monkeypatch.setattr(lifespan, "SHUTDOWN_BUDGET_S", 1.5)

    async def stuck(self: MetricsRecorder, stop: asyncio.Event) -> None:
        await asyncio.sleep(3600)  # never looks at `stop`

    closed: list[bool] = []
    real_close = MetricsRecorder.close

    def close(self: MetricsRecorder) -> Any:
        closed.append(True)
        return real_close(self)

    monkeypatch.setattr(MetricsRecorder, "run", stuck)
    monkeypatch.setattr(MetricsRecorder, "close", close)
    app = create_app(env)
    context = app.router.lifespan_context(app)
    await context.__aenter__()
    ctx = app.state.ctx
    assert ctx.ready
    started = time.monotonic()
    await context.__aexit__(None, None, None)
    elapsed = time.monotonic() - started
    assert closed == [True], "the final flush ran"
    assert ctx.ready is False
    assert 1.0 <= elapsed < lifespan.LOOP_STOP_TIMEOUT_S - 3.0, elapsed  # waited, but only within the budget
