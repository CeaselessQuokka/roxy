"""Unit tests for roxy.scheduler.heartbeat (worker rows, fleet view, reset counts, loop lag)."""

from __future__ import annotations

import asyncio
import os
import sqlite3
import time

from roxy.core.clock import FakeClock
from roxy.scheduler.heartbeat import (
    HEARTBEAT_STALE_S,
    REMOVE_BUSY_BUDGET_MS,
    HeartbeatReporter,
    LoopLagMonitor,
    WorkerCounters,
    WorkerInfo,
    fleet_view,
    fresh_counts,
    read_rss_bytes,
    reset_fleet_counters,
)


def _info(pid: int, color: str, started_at: float) -> WorkerInfo:
    return WorkerInfo(
        worker_id=f"host:{pid}:abcd1234",
        color=color,
        pid=pid,
        started_at=int(started_at),
        hostname="host",
        master_pid=1,
        max_requests=20000,
        version="2.0.0",
    )


async def test_beat_writes_the_parity_row_84_fields(dbs, fake_clock: FakeClock) -> None:
    counters = WorkerCounters(requests=7, proxied=5)
    lag = LoopLagMonitor()
    for value in (1.0, 2.0, 50.0):
        lag.record(value)
    reporter = HeartbeatReporter(
        dbs.metrics,
        _info(4242, "blue", fake_clock.now() - 100),
        fake_clock,
        counters=counters,
        lag=lag,
        open_conns=lambda: 12,
        inflight_upstream=lambda: 3,
        is_leader=lambda: True,
        cache_generation=lambda: 9,
        rss=lambda: 123_456,
    )
    await reporter.beat()
    row = dbs.metrics.read_sync(lambda c: dict(c.execute("SELECT * FROM worker_heartbeat").fetchone()))
    assert row["pid"] == 4242
    assert row["color"] == "blue"
    assert row["worker_id"] == "host:4242:abcd1234"
    assert row["requests"] == 7
    assert row["proxied"] == 5
    assert row["rss"] == 123_456
    assert row["open_conns"] == 12
    assert row["inflight_upstream"] == 3
    assert row["loop_lag_ms_p99"] == 50.0
    assert row["max_requests"] == 20000
    assert row["master_pid"] == 1
    assert row["is_leader"] == 1
    assert row["cache_generation"] == 9
    assert row["last_seen"] == int(fake_clock.now())
    assert reporter.beats == 1


async def test_fleet_view_marks_fresh_stale_and_this_worker(dbs, fake_clock: FakeClock) -> None:
    blue = HeartbeatReporter(dbs.metrics, _info(10, "blue", fake_clock.now()), fake_clock, rss=lambda: None)
    green = HeartbeatReporter(dbs.metrics, _info(11, "green", fake_clock.now()), fake_clock, rss=lambda: None)
    await blue.beat()
    await green.beat()
    fake_clock.advance(HEARTBEAT_STALE_S + 1)
    await green.beat()
    now = fake_clock.now()
    view = dbs.metrics.read_sync(lambda c: fleet_view(c, now, this_pid=11))
    by_pid = {row["pid"]: row for row in view}
    assert by_pid[10]["fresh"] is False
    assert by_pid[11]["fresh"] is True
    assert by_pid[11]["is_this_worker"]
    assert not by_pid[10]["is_this_worker"]
    assert by_pid[11]["uptime_s"] == int(HEARTBEAT_STALE_S + 1)
    assert dbs.metrics.read_sync(lambda c: fresh_counts(c, now)) == {"green": 1}


async def test_reset_counts_is_adopted_by_every_worker(dbs, fake_clock: FakeClock) -> None:
    counters = WorkerCounters(requests=100, proxied=80)
    reporter = HeartbeatReporter(
        dbs.metrics, _info(20, "blue", fake_clock.now()), fake_clock, counters=counters, rss=lambda: None
    )
    await reporter.beat()
    reset_at = int(fake_clock.now()) + 1
    assert dbs.metrics.write_sync(lambda c: reset_fleet_counters(c, reset_at)) == 1
    counters.requests += 5  # traffic between the reset and the next beat
    await reporter.beat()
    assert counters.requests == 0
    assert counters.proxied == 0
    assert counters.reset_at == reset_at
    row = dbs.metrics.read_sync(
        lambda c: tuple(
            c.execute("SELECT requests, proxied, counters_reset_at FROM worker_heartbeat WHERE pid = 20").fetchone()
        )
    )
    assert row == (0, 0, reset_at)
    counters.requests = 3
    await reporter.beat()
    assert dbs.metrics.read_sync(lambda c: c.execute("SELECT requests FROM worker_heartbeat").fetchone()[0]) == 3


async def test_run_beats_and_removes_its_row_on_stop(dbs) -> None:
    reporter = HeartbeatReporter(dbs.metrics, WorkerInfo.current("w", "dev", 0.0), rss=read_rss_bytes)
    stop = asyncio.Event()
    task = asyncio.create_task(reporter.run(stop, interval_s=0.02))
    for _ in range(200):
        if reporter.beats >= 2:
            break
        await asyncio.sleep(0.01)
    assert reporter.beats >= 2
    row = dbs.metrics.read_sync(lambda c: dict(c.execute("SELECT * FROM worker_heartbeat").fetchone()))
    assert row["pid"] == os.getpid()
    assert row["rss"] > 0
    stop.set()
    await asyncio.wait_for(task, 5)
    assert dbs.metrics.read_sync(lambda c: c.execute("SELECT count(*) FROM worker_heartbeat").fetchone()[0]) == 0


async def test_loop_lag_monitor_measures_a_blocked_loop() -> None:
    monitor = LoopLagMonitor(interval_s=0.01, window=50)
    assert monitor.p99() is None
    stop = asyncio.Event()
    task = asyncio.create_task(monitor.run(stop))
    await asyncio.sleep(0.05)
    time.sleep(0.15)  # noqa: ASYNC251 (blocks the event loop on purpose: that is what the monitor must see)
    await asyncio.sleep(0.05)
    stop.set()
    await asyncio.wait_for(task, 2)
    p99 = monitor.p99()
    assert p99 is not None
    assert p99 >= 100


def test_beat_sync_and_rss(dbs, fake_clock: FakeClock) -> None:
    reporter = HeartbeatReporter(dbs.metrics, _info(30, "dev", fake_clock.now()), fake_clock)
    reporter.beat_sync()
    assert dbs.metrics.read_sync(lambda c: c.execute("SELECT count(*) FROM worker_heartbeat").fetchone()[0]) == 1
    rss = read_rss_bytes()
    assert rss is None or rss > 0


async def test_remove_never_waits_out_a_locked_metrics_db(dbs, fake_clock: FakeClock) -> None:
    """Review finding mp-6 (request 5): the shutdown delete of this worker's row waits at most
    `REMOVE_BUSY_BUDGET_MS` for another process's lock, so it cannot spend the 8 s shutdown budget the final
    metrics flush needs. The row then goes stale by itself."""
    reporter = HeartbeatReporter(dbs.metrics, _info(31, "dev", fake_clock.now()), fake_clock, rss=lambda: None)
    reporter.beat_sync()
    holder = sqlite3.connect(dbs.metrics.path, isolation_level=None, timeout=30)
    holder.execute("BEGIN IMMEDIATE")
    try:
        started = time.monotonic()
        await reporter.remove()  # logs heartbeat_remove_failed, never raises
        waited = time.monotonic() - started
    finally:
        holder.execute("ROLLBACK")
        holder.close()
    assert waited < REMOVE_BUSY_BUDGET_MS / 1000 + 1.0, waited
    assert dbs.metrics.read_sync(lambda c: c.execute("SELECT count(*) FROM worker_heartbeat").fetchone()[0]) == 1
