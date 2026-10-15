"""The recorder's shutdown flush (`MetricsRecorder.aclose`) stays inside its budget (finding mp-6).

What this is
    Unit tests for the final metrics flush the lifespan runs at shutdown: it writes everything (the minute still
    open included) when metrics.db is free, and when another connection holds metrics.db's write lock it gives up
    after its budget instead of SQLite's 5 s per write, without ever freezing the event loop.

Why it exists
    DESIGN.md 11.9 gives the whole lifespan shutdown 8 s, so gunicorn's kill never cuts it short. The old final flush
    was synchronous `close()` on the event loop thread, waiting the full busy timeout on a locked file (5 s frozen)
    after the flush loop had already waited 5 s for the same lock. Metrics may degrade open (plan C7), so losing the
    last batch is acceptable; overrunning the budget is not.

How it works
    The `recorder` fixture (tests/unit/metrics/conftest.py) on temp databases. A plain `sqlite3` connection opened in
    the test plays "another process" holding `BEGIN IMMEDIATE`. A ticker task measures the longest event loop gap.

What to read next
    `roxy/metrics/recorder.py` (`aclose`, `_ShutdownBudgetTarget`), `roxy/lifespan.py` (`_close_recorder`),
    tests/integration/test_rr_mp_shutdown.py (the same question through the whole lifespan).
"""

from __future__ import annotations

import asyncio
import sqlite3
import time
from collections.abc import Callable
from typing import Any

from roxy.metrics.recorder import MetricsRecorder


async def _with_ticker(work: Callable[[], Any]) -> tuple[Any, float, float]:
    """Run `work()` while a 10 ms ticker runs; return (result, seconds taken, longest loop gap)."""
    gaps: list[float] = []

    async def ticker() -> None:
        last = time.monotonic()
        while True:
            await asyncio.sleep(0.01)
            now = time.monotonic()
            gaps.append(now - last)
            last = now

    tick = asyncio.create_task(ticker())
    started = time.monotonic()
    try:
        result = await work()
    finally:
        took = time.monotonic() - started
        tick.cancel()
    return result, took, max(gaps, default=0.0)


def _requests(recorder: MetricsRecorder) -> int:
    value = recorder.dbs.metrics.read_sync(lambda c: c.execute("SELECT sum(requests) FROM rollup_minute").fetchone()[0])
    return int(value or 0)


async def test_aclose_writes_everything_when_metrics_db_is_free(recorder: MetricsRecorder, make_event: Any) -> None:
    for _ in range(7):
        recorder.record_outcome(make_event())
    result, took, _gap = await _with_ticker(lambda: recorder.aclose(budget_s=4.0))
    assert result is not None
    assert not result.failed_dbs
    assert recorder.batch.queued() == 0
    assert _requests(recorder) == 7
    assert took < 2.0


async def test_aclose_gives_up_after_its_budget_on_a_locked_metrics_db(
    recorder: MetricsRecorder, make_event: Any
) -> None:
    for _ in range(5):
        recorder.record_outcome(make_event())
    holder = sqlite3.connect(recorder.dbs.metrics.path, isolation_level=None, timeout=30)
    holder.execute("BEGIN IMMEDIATE")  # another process holds the write lock for the whole shutdown
    try:
        _result, took, gap = await _with_ticker(lambda: recorder.aclose(budget_s=1.0))
    finally:
        holder.execute("ROLLBACK")
        holder.close()
    assert took < 1.0 + 0.9, f"the final flush took {took:.2f} s against a 1 s budget (busy timeout is 5 s)"
    assert gap < 0.5, f"the event loop froze for {gap:.2f} s"
    assert _requests(recorder) == 0  # lost, as metrics may be (C7), and the worker stopped on time


async def test_writes_outside_the_shutdown_flush_keep_the_normal_busy_timeout(recorder: MetricsRecorder) -> None:
    """The budget wrapper only acts while `aclose` runs: an ordinary flush passes no budget of its own."""
    seen: list[int | None] = []
    real_write = recorder.dbs.metrics.write

    async def spy(fn: Any, *, immediate: bool = True, busy_timeout_ms: int | None = None) -> Any:
        seen.append(busy_timeout_ms)
        return await real_write(fn, immediate=immediate, busy_timeout_ms=busy_timeout_ms)

    recorder.dbs.metrics.write = spy  # type: ignore[method-assign]
    recorder.record_event("probe", "info", "x", {"n": 1})
    await recorder.flush()
    recorder.record_event("probe", "info", "y", {"n": 2})
    await recorder.aclose(budget_s=3.0)
    assert len(seen) == 2
    assert seen[0] is None
    last = seen[1]
    assert last is not None
    assert 0 < last <= 3000
    await recorder.flush()  # after aclose the wrapper passes writes through unchanged again
    assert seen[2:] in ([], [None])


async def test_the_flush_loop_leaves_the_final_flush_to_aclose(recorder: MetricsRecorder, make_event: Any) -> None:
    """A stop request ends the loop without one more flush (the final one is budgeted, in `aclose`)."""
    stop = asyncio.Event()
    loop = asyncio.create_task(recorder.run(stop))
    await asyncio.sleep(0.05)
    recorder.record_outcome(make_event())
    stop.set()
    await asyncio.wait_for(loop, 2.0)
    assert _requests(recorder) == 0
    await recorder.aclose(budget_s=2.0)
    assert _requests(recorder) == 1
