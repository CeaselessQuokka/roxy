"""Metrics end to end: recorder flush loop, leader compaction, retention, read models, live tail across workers.

Two recorders on separate `Database` objects stand in for two workers sharing the same files. Time is driven by a
`FakeClock` (WSL's wall clock steps back now and then); only the flush loop uses real asyncio time.
"""

from __future__ import annotations

import asyncio
import random
from collections.abc import Iterator
from typing import Any

import pytest

from roxy.config import catalog
from roxy.core.clock import FakeClock
from roxy.core.reasons import AuthClass, CacheState, Egress, Outcome, ReasonCode, Source
from roxy.metrics import queries as q
from roxy.metrics.capture import CaptureInput
from roxy.metrics.jobs import register_metrics_jobs
from roxy.metrics.live import LIVE_EVENT, EventTail
from roxy.metrics.recorder import MetricsRecorder, OutcomeEvent
from roxy.scheduler.jobs import JobRegistry, JobRunner
from roxy.scheduler.leader import LeaderElector
from roxy.storage import retention
from roxy.storage.db import DB_NAMES, Database, Databases

TEMPLATE = "games.roblox.com/v1/games/{gameId}/votes"


class Settings:
    def __init__(self, **overrides: Any) -> None:
        self.values = catalog.defaults()
        self.values.update(overrides)
        self.version = 1

    def get(self, key: str) -> Any:
        return self.values[key]


def event(clock: FakeClock, **fields: Any) -> OutcomeEvent:
    base: dict[str, Any] = {
        "at_ms": clock.now_ms(),
        "request_id": "R",
        "endpoint_template": TEMPLATE,
        "host": "games.roblox.com",
        "method": "GET",
        "egress": Egress.DIRECT,
        "outcome": Outcome.SERVED_UPSTREAM,
        "reason": ReasonCode.UPSTREAM_OK,
        "status": 200,
        "source": Source.ROBLOX,
        "cache_state": CacheState.MISS,
        "auth_class": AuthClass.ANON,
        "caller_bytes_in": 100,
        "caller_bytes_out": 500,
        "upstream_calls": 1,
        "upstream_bytes_in": 900,
        "upstream_bytes_out": 300,
        "latency_ms": 40.0,
        "queue_wait_ms": 1.0,
        "upstream_ms": 30.0,
        "client_ip": "203.0.113.5",
        "place_id": "12345",
        "user_agent": "Roblox/WinInet",
        "bypass": False,
        "error": False,
    }
    base.update(fields)
    return OutcomeEvent(**base)


@pytest.fixture
def second_worker(dbs: Any) -> Iterator[Databases]:
    """Separate Database objects (own threads and connections) on the same files: a second worker."""
    other = Databases(**{name: Database(name, dbs.paths[name]) for name in DB_NAMES}, paths=dict(dbs.paths))
    yield other
    other.close_all_sync()


async def test_flush_loop_compaction_and_queries(dbs: Any, second_worker: Databases, fake_clock: FakeClock) -> None:
    settings = Settings(metrics_flush_interval_ms=250)
    worker_a = MetricsRecorder(dbs, settings, fake_clock, worker_id="a", rng=random.Random(1).random)
    worker_b = MetricsRecorder(second_worker, settings, fake_clock, worker_id="b", rng=random.Random(2).random)
    stop = asyncio.Event()
    loops = [asyncio.create_task(w.run(stop)) for w in (worker_a, worker_b)]
    sent = 0
    for minute in range(90):
        for worker in (worker_a, worker_b):
            worker.record_outcome(event(fake_clock, request_id=f"{worker.worker_id}{minute}"))
            worker.record_outcome(
                event(
                    fake_clock,
                    outcome=Outcome.SERVED_CACHE,
                    reason=ReasonCode.CACHE_HIT,
                    cache_state=CacheState.HIT,
                    source=Source.CACHE,
                    upstream_calls=0,
                )
            )
            sent += 2
        fake_clock.advance(60)
        if minute % 30 == 0:
            await asyncio.sleep(0.3)  # let the flush loops run with real time
    await asyncio.sleep(0.3)
    stop.set()
    await asyncio.gather(*loops)
    worker_a.close()
    worker_b.close()
    total = dbs.metrics.read_sync(lambda c: c.execute("SELECT sum(requests) FROM rollup_minute").fetchone()[0])
    assert total == sent

    registry = JobRegistry()
    register_metrics_jobs(registry, dbs, settings.get)
    fake_clock.advance(3 * 3600)  # every hour closed; then take the lease (it lasts 15 s of this clock)
    leader = LeaderElector(dbs.hot, "a", fake_clock)
    await leader.tick()
    runner = JobRunner(registry, leader, fake_clock, worker_id="a")
    status = await runner.run_job_now("metrics_compaction")
    assert status.last_ok, status.last_error
    hours = dbs.metrics.read_sync(lambda c: c.execute("SELECT sum(requests) FROM rollup_hour").fetchone()[0])
    assert hours == sent

    now = fake_clock.now()
    window = q.resolve_window("24h", now=now, granularity="hour")
    totals = await dbs.metrics.read(lambda c: q.totals_sync(c, window))
    assert totals["requests"] == sent
    assert totals["avoided"] == sent // 2  # half of the requests were cache hits with no upstream call
    kpis = await q.kpis(dbs.metrics, window, now=now, compare="previous")
    assert kpis["tiles"]["requests"]["value"] == sent
    series = await q.series(dbs.metrics, window, metrics=["requests"])
    assert sum(series["groups"]["all"]["requests"]) == sent
    clients = await q.client_table(dbs.metrics, window, "ip", now=now)
    assert clients["rows"][0]["requests"] == sent


async def test_live_tail_sees_every_worker(dbs: Any, second_worker: Databases, fake_clock: FakeClock) -> None:
    settings = Settings()
    worker_a = MetricsRecorder(dbs, settings, fake_clock, worker_id="a")
    worker_b = MetricsRecorder(second_worker, settings, fake_clock, worker_id="b")
    tail = EventTail(dbs.metrics)  # the dashboard is connected to worker A
    sub = tail.subscribe(types=[LIVE_EVENT])
    await tail.poll_once()
    worker_a.record_outcome(event(fake_clock, request_id="FROM-A"))
    worker_b.record_outcome(event(fake_clock, request_id="FROM-B"))
    await worker_a.flush()
    await worker_b.flush()
    await tail.poll_once()
    seen = {sub.queue.get_nowait().detail["request_id"] for _ in range(sub.queue.qsize())}
    assert seen == {"FROM-A", "FROM-B"}


async def test_retention_after_compaction_keeps_history(dbs: Any, fake_clock: FakeClock) -> None:
    settings = Settings()
    worker = MetricsRecorder(dbs, settings, fake_clock, rng=random.Random(3).random)
    start = fake_clock.now()
    for _ in range(120):
        worker.record_outcome(event(fake_clock))
        worker.record_capture(CaptureInput(request_id="C", at_ms=fake_clock.now_ms(), outcome="refused"))
        fake_clock.advance(60)
    worker.record_probe("198.51.100.1", "Invalid 2FA code")
    worker.close()

    async def write(fn: Any) -> Any:
        return await dbs.metrics.write(fn)

    from roxy.metrics.rollups import CompactionConfig, compact_all

    fake_clock.advance(3 * 3600)
    await compact_all(write, fake_clock.now(), CompactionConfig(tz_name="UTC", max_buckets=500))
    # Twenty days later the minutes, samples and captures are gone; hours keep the totals.
    fake_clock.advance(20 * 86_400)
    policy = retention.RetentionPolicy.from_settings(settings.get)
    await retention.run_retention(dbs, policy, fake_clock.now())
    counts = dbs.metrics.read_sync(
        lambda c: {
            table: c.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            for table in ("rollup_minute", "rollup_hour", "request_samples", "captures", "events", "client_minute")
        }
    )
    assert counts["rollup_minute"] == 0
    assert counts["rollup_hour"] > 0
    assert counts["request_samples"] == 0
    assert counts["captures"] == 0
    assert counts["client_minute"] == 0
    assert counts["events"] > 0  # probes and refusals are kept 90 days
    window = q.Window(int(start) - int(start) % 3600, int(start) + 4 * 3600, "hour")
    totals = dbs.metrics.read_sync(lambda c: q.totals_sync(c, window))
    assert totals["requests"] == 120
