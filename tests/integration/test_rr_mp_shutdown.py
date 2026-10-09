"""Review round, lens mp: the lifespan shutdown budget while a shared database is locked by another process.

What this is
    The reproduction (now a regular test) of finding mp-6. The fully wired application (real lifespan, every
    background loop) serves a few requests so the metrics recorder holds unflushed numbers; then another process takes
    metrics.db's write lock (`BEGIN IMMEDIATE`), the way the leader's rollup or retention batch in the other color, a
    backup or a stalled worker would; then the lifespan shuts down. The test measures how long the shutdown takes and
    the longest stall of the event loop while it runs.

Why it exists
    DESIGN.md 11.9 "Shutdown": every cleanup step of the lifespan shutdown shares ONE 8 s budget
    (`lifespan.SHUTDOWN_BUDGET_S`), because `roxy.worker` gives uvicorn `graceful_timeout - 8 - 2` = 20 s for open
    requests and gunicorn kills the worker at `graceful_timeout` (30 s). A shutdown that overruns the budget can be
    killed half way (the alert drain, the egress and database closes never run). Metrics may degrade open (C7),
    so losing the final flush to a locked metrics.db is acceptable; overrunning the budget and freezing the loop
    for it is not. Today the final flush is `MetricsRecorder.close()` -> `BatchWriter.flush_now()` ->
    `Database.write_sync`, registered with `stack.callback` (synchronous): it waits SQLite's full 5 s
    `busy_timeout` ON THE EVENT LOOP THREAD, outside `shutdown_time_left`, after the flush loop's own last flush
    already spent 5 s on the same lock.

How it works
    `_lock` starts a child process that holds the write lock until released (after the shutdown finished). A
    ticker task on the loop records the longest gap between its 20 ms ticks during the shutdown. Fixed: the final
    flush is `MetricsRecorder.aclose` (awaited, every write's busy budget cut to what is left of the shutdown
    budget, at most `FINAL_FLUSH_MAX_S`), the flush loop no longer flushes once more on stop, and the database close
    is budgeted too.

What to read next
    `roxy/lifespan.py` (`_close_recorder`, `_close_databases`, `shutdown_time_left`, `SHUTDOWN_BUDGET_S`),
    `roxy/metrics/recorder.py` (`aclose`, `_ShutdownBudgetTarget`), `roxy/worker.py` (`graceful_shutdown_s`).
"""

from __future__ import annotations

import asyncio
import multiprocessing as mp
import sqlite3
import sys
import time
from typing import Any

import pytest

pytestmark = [pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX processes")]

CTX = mp.get_context("spawn")
SLACK_S = 1.0
"""Allowed over the budget: closing sockets and threads after the last step."""


def _hold_lock(path: str, ready: Any, release: Any, hold_s: float) -> None:
    conn = sqlite3.connect(path, isolation_level=None, timeout=30)
    conn.execute("BEGIN IMMEDIATE")
    ready.set()
    release.wait(hold_s)
    conn.execute("ROLLBACK")
    conn.close()


@pytest.mark.timeout(120)
async def test_rr_mp_shutdown_stays_in_its_budget_while_metrics_db_is_locked(env: Any) -> None:
    """With metrics.db write-locked by another process for the whole shutdown, the lifespan shutdown must still end
    within `SHUTDOWN_BUDGET_S` (plus 1 s for closing threads), and the event loop must never freeze for a second.
    Measured today: 10.2 s, with one 5.0 s freeze (the synchronous final flush). With hot.db locked instead the
    same shutdown takes 5.1 s and never freezes the loop (every hot.db step is bounded), so only this path fails."""
    import httpx

    from roxy.lifespan import SHUTDOWN_BUDGET_S
    from roxy.main import create_app

    app = create_app(env)
    lifespan = app.router.lifespan_context(app)
    await lifespan.__aenter__()
    entered = True
    ready, release = CTX.Event(), CTX.Event()
    holder = None
    try:
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 50000))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
            headers = {"User-Agent": "Roblox/Linux", "X-Forwarded-For": "203.0.113.61"}
            for n in range(5):  # answered locally (OPTIONS), recorded by the metrics recorder, nothing upstream
                response = await http.options(f"/games.roblox.com/v1/games?universeIds={n}", headers=headers)
                assert response.status_code == 204
        assert app.state.ctx.recorder.batch.queued() > 0, "the recorder holds numbers the final flush must write"
        holder = CTX.Process(target=_hold_lock, args=(str(env.metrics_db), ready, release, 90.0), daemon=True)
        holder.start()
        assert ready.wait(20), "the lock holder never took metrics.db's write lock"

        gaps: list[float] = []

        async def ticker() -> None:
            last = time.monotonic()
            while True:
                await asyncio.sleep(0.02)
                now = time.monotonic()
                gaps.append(now - last)
                last = now

        tick = asyncio.create_task(ticker())
        started = time.monotonic()
        entered = False
        await lifespan.__aexit__(None, None, None)
        took = time.monotonic() - started
        tick.cancel()
    finally:
        if entered:
            await lifespan.__aexit__(None, None, None)
        release.set()
        if holder is not None:
            holder.join(10)
    stall = max(gaps, default=0.0)
    print(f"\nshutdown took {took:.2f} s (budget {SHUTDOWN_BUDGET_S} s); longest event loop stall {stall:.2f} s")
    assert took <= SHUTDOWN_BUDGET_S + SLACK_S, f"the lifespan shutdown took {took:.2f} s"
    assert stall < 1.0, f"the event loop was frozen for {stall:.2f} s during the shutdown"
