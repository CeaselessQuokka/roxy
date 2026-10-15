"""Metrics across real worker processes (plan 19.3, C6): totals equal the requests sent, with 1, 2 and 4 workers.

Each child process is a worker: its own `Database` objects, its own `MetricsRecorder`, flushing on its own schedule
into the same shared files. Every child uses the same simulated clock, so they write the same minutes and the same
dimension combinations at the same time, and the `ON CONFLICT ... DO UPDATE` upserts (and the histogram merge
function) must add their counts up exactly. The parent then checks every total, compacts as the leader and checks
the hours, and tails the events table to see live rows from every worker.
"""

from __future__ import annotations

import asyncio
import multiprocessing as mp
import random
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from roxy.config import catalog
from roxy.core.clock import FakeClock
from roxy.core.reasons import AuthClass, CacheState, Egress, Outcome, ReasonCode, Source
from roxy.metrics import histograms
from roxy.metrics.recorder import MetricsRecorder, OutcomeEvent
from roxy.metrics.rollups import CompactionConfig, compact_all
from roxy.storage.db import DB_NAMES, Database, Databases
from roxy.storage.migrate import migrate_paths

pytestmark = [
    pytest.mark.multiprocess,
    pytest.mark.skipif(sys.platform == "win32", reason="POSIX multiprocessing semantics"),
]

CTX = mp.get_context("spawn")
EVENTS_PER_WORKER = 3000
START = 1_760_000_400.0
REFUSE_EVERY = 10


class _Settings:
    def __init__(self, **overrides: Any) -> None:
        self.values = catalog.defaults()
        self.values.update(overrides)
        self.version = 1

    def get(self, key: str) -> Any:
        return self.values[key]


def _event(clock: FakeClock, i: int, worker: str) -> OutcomeEvent:
    refused = i % REFUSE_EVERY == 0
    return OutcomeEvent(
        at_ms=clock.now_ms(),
        request_id=f"{worker}-{i}",
        endpoint_template=f"games.roblox.com/v1/e{i % 7}",
        host="games.roblox.com",
        method="GET",
        egress=Egress.NONE if refused else Egress.DIRECT,
        outcome=Outcome.REFUSED if refused else Outcome.SERVED_UPSTREAM,
        reason=ReasonCode.THROTTLE if refused else ReasonCode.UPSTREAM_OK,
        status=429 if refused else 200,
        source=Source.ROXY if refused else Source.ROBLOX,
        cache_state=CacheState.NA if refused else CacheState.MISS,
        auth_class=AuthClass.ANON,
        caller_bytes_in=100,
        caller_bytes_out=500,
        upstream_calls=0 if refused else 1,
        upstream_bytes_in=0 if refused else 900,
        upstream_bytes_out=0 if refused else 300,
        latency_ms=float(i % 400),
        queue_wait_ms=1.0,
        upstream_ms=10.0,
        client_ip=f"198.51.100.{i % 40}",
        place_id=str(1000 + i % 5),
        user_agent="Roblox/WinInet",
        bypass=False,
        error=False,
        message_source="default" if refused else "",
    )


def _child(paths: dict[str, str], worker: str, seed: int) -> None:
    asyncio.run(_record(paths, worker, seed))


async def _record(paths: dict[str, str], worker: str, seed: int) -> None:
    dbs = Databases(
        **{name: Database(name, paths[name]) for name in DB_NAMES}, paths={k: Path(v) for k, v in paths.items()}
    )
    clock = FakeClock(START)
    recorder = MetricsRecorder(dbs, _Settings(), clock, worker_id=worker, rng=random.Random(seed).random)
    flush_every = 300 + seed * 37  # workers flush at different moments
    for i in range(EVENTS_PER_WORKER):
        recorder.record_outcome(_event(clock, i, worker))
        if i % 3 == 0:
            clock.advance(1.0)  # 3000 events over about 17 minutes of simulated time
        if i % flush_every == 0:
            await recorder.flush()
    recorder.close()
    await dbs.close_all()


def _query(path: Path, sql: str) -> list[tuple[Any, ...]]:
    conn = sqlite3.connect(str(path), timeout=10)
    try:
        return [tuple(r) for r in conn.execute(sql).fetchall()]
    finally:
        conn.close()


@pytest.mark.parametrize("workers", [1, 2, 4])
async def test_metric_totals_equal_requests_sent(tmp_path: Path, workers: int) -> None:
    paths = {name: tmp_path / f"{name}.db" for name in DB_NAMES}
    migrate_paths(paths)
    procs = [
        CTX.Process(target=_child, args=({k: str(v) for k, v in paths.items()}, f"w{n}", n), daemon=True)
        for n in range(workers)
    ]
    started = time.monotonic()
    for proc in procs:
        proc.start()
    for proc in procs:
        proc.join(120)
    assert all(p.exitcode == 0 for p in procs), [p.exitcode for p in procs]
    sent = workers * EVENTS_PER_WORKER
    refused = workers * len(range(0, EVENTS_PER_WORKER, REFUSE_EVERY))
    metrics = paths["metrics"]

    (requests, calls, errors) = _query(
        metrics, "SELECT sum(requests), sum(upstream_calls), sum(errors) FROM rollup_minute"
    )[0]
    assert requests == sent
    assert calls == sent - refused
    assert errors == 0
    blobs = _query(metrics, "SELECT latency_hist FROM rollup_minute")
    assert sum(histograms.total(histograms.decode(b[0])) for b in blobs) == sent
    # Same minute and same dimensions from different workers merged into one row each.
    keys = _query(metrics, "SELECT count(*), count(DISTINCT bucket_start || ':' || dim_hash) FROM rollup_minute")[0]
    assert keys[0] == keys[1]
    dims = _query(metrics, "SELECT count(*) FROM dims")[0][0]
    assert dims == 7 * 2  # 7 templates x (served, refused), each stored once whatever the number of workers
    for ctype in ("ip", "place"):
        (total,) = _query(metrics, f"SELECT sum(requests) FROM client_minute WHERE client_type = '{ctype}'")[0]
        assert total == sent
    (refusal_events,) = _query(
        metrics,
        "SELECT sum(coalesce(json_extract(detail_json, '$.count'), 1)) FROM events WHERE type = 'refusal'",
    )[0]
    assert refusal_events == refused  # budgeted per worker, summed per minute, exact in total
    samples = _query(metrics, "SELECT count(*) FROM request_samples")[0][0]
    assert samples == sent - refused  # request_sample_pct is 100 and refusals are not proxied requests

    # The leader compacts what every worker wrote.
    dbs = Databases(**{name: Database(name, paths[name]) for name in DB_NAMES}, paths=paths)
    try:

        async def write(fn: Any) -> Any:
            return await dbs.metrics.write(fn)

        await compact_all(write, START + 4 * 3600, CompactionConfig(tz_name="UTC"))
        hours = dbs.metrics.read_sync(lambda c: c.execute("SELECT sum(requests) FROM rollup_hour").fetchone()[0])
        assert hours == sent
        client_hours = dbs.metrics.read_sync(
            lambda c: c.execute("SELECT sum(requests) FROM client_hour WHERE client_type = 'ip'").fetchone()[0]
        )
        assert client_hours == sent
    finally:
        await dbs.close_all()
    elapsed = time.monotonic() - started
    print(f"\nPERFORMANCE metrics mp: {workers} workers x {EVENTS_PER_WORKER} events in {elapsed:.1f} s")
