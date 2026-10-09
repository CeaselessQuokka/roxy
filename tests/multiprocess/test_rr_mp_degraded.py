"""Review round, lens mp (multi-process and failure modes): the C7 degraded limiter at its edges.

What this is
    Reproductions, now regression tests, of two findings about the per-worker limiter the abuse pipeline falls back
    to while hot.db cannot be written (plan C7, DESIGN.md 11.5 and 11.9 "Abuse"). Each test runs the real
    `AbusePipeline` over migrated temporary databases; a separate "lock holder" process keeps hot.db write-locked
    the way a stalled worker, a long prune batch or a backup would, and the pipelines that play worker processes
    either share the test's event loop or run as real child processes.

Why it exists
    Plan C6 says no per-worker memory may multiply a limit, with 1, 2 and 4 workers, and C7 says the fallback is a
    conservative `limit / workers` per worker. The fix pass closed DEGRADED-REFILL (entering degraded mode no longer
    hands a client a fresh allowance). These tests attack the two other edges of the same mechanism:
    - mp-1: LEAVING degraded mode. Memory rows used to be dropped on recovery and never merged into hot.db, so every
      request a client sent during the outage was forgotten and the client got its full allowance again inside the
      same window (and a strike earned during the outage disappeared). Fixed: the first successful transaction that
      touches a key merges its memory rows into hot.db before deciding, and a background task merges the rest.
    - mp-2: a limit smaller than the number of workers. `degraded_limit` rounded the share up to 1, so a limit of 1
      became 2 with 2 workers and 4 with 4 workers. Fixed: the share is `limit // workers`, and a share of 0 refuses
      (fail closed, no strike).

How it works
    `_lock_hot` starts a child process that holds `BEGIN IMMEDIATE` on hot.db until released. Requests come from one
    client address (TEST-NET-3). Clocks are real; every window is far longer than the test, so the WSL wall clock
    steps cannot change a verdict.

What to read next
    `roxy/abuse/pipeline.py` (`_degraded_walk`, `_claim`, `merge_pending`), `roxy/abuse/limiter.py`
    (`degraded_limit`, `merge_limiter_row`), tests/unit/abuse/test_abuse_degraded_merge.py (the same mechanism with a
    fake clock), and tests/multiprocess/test_review_failure_modes_mp.py (the earlier review's tests).
"""

from __future__ import annotations

import asyncio
import multiprocessing as mp
import os
import sqlite3
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from roxy.abuse.pipeline import AbusePipeline
from roxy.abuse.verdict import Allow
from roxy.config.catalog import CATALOG
from roxy.core.clock import SystemClock
from roxy.rules.store import RulesSnapshot
from roxy.storage.db import DB_NAMES, Database
from roxy.storage.migrate import migrate_paths

pytestmark = [
    pytest.mark.multiprocess,
    pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX processes"),
]

CTX = mp.get_context("spawn")
IP = "203.0.113.41"  # TEST-NET-3 documentation range: never a real client


def _hold_hot_lock(path: str, ready: Any, release: Any, hold_s: float) -> None:
    """Child process: hold hot.db's write lock until `release` is set (or `hold_s` passed)."""
    conn = sqlite3.connect(path, isolation_level=None, timeout=30)
    conn.execute("BEGIN IMMEDIATE")
    ready.set()
    release.wait(hold_s)
    conn.execute("ROLLBACK")
    conn.close()


@dataclass
class HotLock:
    release: Any
    proc: Any

    def stop(self) -> None:
        self.release.set()
        self.proc.join(10)


@pytest.fixture
def paths(tmp_path: Path) -> dict[str, str]:
    files = {name: tmp_path / f"{name}.db" for name in DB_NAMES}
    migrate_paths(files)
    return {name: str(path) for name, path in files.items()}


@pytest.fixture
def procs() -> Iterator[list[Any]]:
    started: list[Any] = []
    yield started
    for proc in started:
        if proc.is_alive():
            proc.kill()
        proc.join(5)


def _lock_hot(procs: list[Any], hot_path: str, hold_s: float = 60.0) -> HotLock:
    ready, release = CTX.Event(), CTX.Event()
    proc = CTX.Process(target=_hold_hot_lock, args=(hot_path, ready, release, hold_s), daemon=True)
    proc.start()
    procs.append(proc)
    assert ready.wait(20), "the lock holder never took hot.db's write lock"
    return HotLock(release, proc)


class _Settings:
    """Catalog defaults plus overrides (the read side of RuntimeSettings that the pipeline uses)."""

    def __init__(self, overrides: dict[str, Any]) -> None:
        self.values = {key: spec.default for key, spec in CATALOG.items()}
        self.values.update(overrides)

    def snapshot(self) -> dict[str, Any]:
        return dict(self.values)


class _Req:
    """The ProxyRequest fields the abuse pipeline reads."""

    def __init__(self, ip: str = IP) -> None:
        self.client_ip = ip
        self.limit_key = ip
        self.method = "GET"
        self.host = "games.roblox.com"
        self.path = "/v1/games"
        self.query: list[tuple[str, str]] = []
        self.body = b""
        self.headers = {"user-agent": "Roblox/Linux"}
        self.header_names_in_order = ["user-agent"]
        self.user_agent = "Roblox/Linux"
        self.place_id = None
        self.is_browser = False
        self.template = "games.roblox.com/v1/games"
        self.bypass = False
        self.deadline_at = time.monotonic() + 60.0
        self.target_problem = None
        self.fresh_cache_hit = False
        self.request_id = "rr-mp"


def _pipeline(hot: Database, workers: int, limit: int, window: int = 300, mode: str = "gcra") -> AbusePipeline:
    settings = _Settings(
        {
            "allowed_requests_per_minute": limit,
            "throttle_reset_duration": window,
            "throttle_window_mode": mode,
            "flood_limit_per_minute": 100_000,
            "spam_enabled": 0,
            "tarpit_enabled": 0,
        }
    )
    return AbusePipeline(
        settings=settings,
        rules=RulesSnapshot.empty(),
        hot_db=hot,
        control_db=None,
        clock=SystemClock(),
        worker_id=f"rr-mp-{os.getpid()}-{id(hot)}",
        workers=workers,
    )


async def _admitted(pipeline: AbusePipeline, count: int) -> int:
    return sum([isinstance(await pipeline.evaluate(_Req()), Allow) for _ in range(count)])


# ======================================================== mp-1: leaving degraded mode refills the allowance


async def test_rr_mp_leaving_degraded_mode_never_refills_the_allowance(paths: dict[str, str], procs: list[Any]) -> None:
    """Plan C6 and C7 (DESIGN.md 11.9 "C7 degraded mode starts from the shared rows"). Two workers (two pipelines,
    each with its own hot.db connections, ROXY_WORKERS=2), a limit of 10 per 300 s and one fresh client.

    hot.db is write-locked by another process for a moment: each worker admits its share, 5, from memory, so the
    fleet admits 10, exactly the limit. The lock ends a second later. Inside the same 300 s window the client must
    get nothing more: it has used its whole allowance. Before the fix the first successful write cleared both
    workers' memory rows without merging them into hot.db, whose row still said the client sent nothing, so the
    client was admitted 10 more times: twice the limit in one window. The strike and penalty the client earned
    while degraded must reach hot.db too."""
    hot_a, hot_b = Database("hot", paths["hot"]), Database("hot", paths["hot"])
    worker_a, worker_b = _pipeline(hot_a, workers=2, limit=10), _pipeline(hot_b, workers=2, limit=10)
    try:
        lock = _lock_hot(procs, paths["hot"])
        try:
            during = await _admitted(worker_a, 6) + await _admitted(worker_b, 6)
            assert worker_a.degraded
            assert worker_b.degraded
        finally:
            lock.stop()
        assert during == 10, "each worker admits its share (5 of 10) while hot.db is locked"
        # hot.db takes writes again; the window (300 s) is far from over.
        after = 0
        for _ in range(5):
            after += await _admitted(worker_a, 1) + await _admitted(worker_b, 1)
        assert not worker_a.degraded
        assert not worker_b.degraded
        for worker in (worker_a, worker_b):
            await worker.aclose()  # the background merges finish: every memory row is in hot.db
            assert len(worker._memory_rows) == 0
            assert len(worker._memory_strikes) == 0
        strikes = hot_a.read_sync(
            lambda conn: conn.execute("SELECT strikes, throttled_until FROM strikes WHERE ip = ?", (IP,)).fetchone()
        )
    finally:
        await hot_a.close()
        await hot_b.close()
    print(f"\nadmitted while degraded {during}, admitted after recovery {after} (limit 10 per 300 s)")
    assert during + after <= 10, f"one client got {during + after} requests through in one window of a limit of 10"
    assert strikes is not None, "the strike earned while hot.db was locked reached hot.db"
    assert int(strikes[0]) >= 1
    assert int(strikes[1]) > time.time(), "and so did the penalty"


async def _until_writes_work(pipelines: list[AbusePipeline], timeout_s: float = 20.0) -> None:
    """Send another client's requests until every pipeline has left degraded mode (a busy circuit may stay open
    for a moment after the lock ends)."""
    other = "203.0.113.42"
    deadline = time.monotonic() + timeout_s
    for pipeline in pipelines:
        while pipeline.degraded:
            assert time.monotonic() < deadline, "hot.db never took writes again"
            await pipeline.evaluate(_Req(other))
            await asyncio.sleep(0.05)


@pytest.mark.parametrize("mode", ["gcra", "fixed"])
@pytest.mark.parametrize("workers", [1, 2, 4])
async def test_rr_mp_leaving_degraded_mode_with_1_2_and_4_workers(
    workers: int, mode: str, paths: dict[str, str], procs: list[Any]
) -> None:
    """C6 at 1, 2 and 4 workers, both window modes: a limit of 12 per 300 s (shares 12, 6 and 3) is spent while
    hot.db is locked; once it takes writes again (and after every merge), the client gets nothing more in the
    window."""
    limit = 12
    dbs = [Database("hot", paths["hot"]) for _ in range(workers)]
    pipelines = [_pipeline(db, workers=workers, limit=limit, mode=mode) for db in dbs]
    try:
        lock = _lock_hot(procs, paths["hot"])
        try:
            during = 0
            for pipeline in pipelines:
                during += await _admitted(pipeline, limit // workers + 1)
                assert pipeline.degraded
        finally:
            lock.stop()
        assert during == limit, f"each of {workers} workers admits its share of {limit}"
        await _until_writes_work(pipelines)
        after = 0
        for _ in range(3):
            for pipeline in pipelines:
                after += await _admitted(pipeline, 1)
        for pipeline in pipelines:
            await pipeline.aclose()
            assert len(pipeline._memory_rows) == 0
    finally:
        for db in dbs:
            await db.close()
    print(f"\n{workers} workers ({mode}): admitted {during} while degraded and {after} after (limit {limit})")
    assert during + after <= limit


# ========================================== mp-2: a limit below the worker count multiplies in degraded mode


def _degraded_child(hot_path: str, workers: int, start: Any, out: Any) -> None:
    asyncio.run(_degraded_main(hot_path, workers, start, out))


async def _degraded_main(hot_path: str, workers: int, start: Any, out: Any) -> None:
    hot = Database("hot", hot_path)
    pipeline = _pipeline(hot, workers=workers, limit=1)  # an allowance of 1 request per 300 s per client
    await asyncio.get_running_loop().run_in_executor(None, start.wait, 60)
    try:
        admitted = await _admitted(pipeline, 3)
    finally:
        await hot.close()
        out.put((admitted, pipeline.degraded))


@pytest.mark.parametrize("workers", [1, 2, 4])
def test_rr_mp_degraded_share_never_multiplies_a_small_limit(
    workers: int, paths: dict[str, str], procs: list[Any]
) -> None:
    """Plan C6 (tested with 1, 2 and 4 workers) and C7 ("a conservative in-memory per-worker limit of limit /
    workers"). `allowed_requests_per_minute` may be as low as 1 (catalog minimum), and endpoint rate rules may say
    1 request per period, per IP or globally. With hot.db write-locked, `workers` real processes each send the
    client's requests; the fleet must still admit at most 1. Before the fix `degraded_limit(1, workers)` was
    `max(1, 1 // workers)` = 1 per worker, so the fleet admitted `workers` requests (2 or 4 times the limit); now
    the share is 0 with 2 or more workers (refused, fail closed) and 1 with a single worker."""
    lock = _lock_hot(procs, paths["hot"])
    start, out = CTX.Event(), CTX.Queue()
    children = [
        CTX.Process(target=_degraded_child, args=(paths["hot"], workers, start, out), daemon=True)
        for _ in range(workers)
    ]
    for proc in children:
        proc.start()
        procs.append(proc)
    start.set()
    try:
        results = [out.get(timeout=120) for _ in children]
    finally:
        lock.stop()
    assert all(degraded for _, degraded in results), "every worker ran on its degraded memory limiter"
    total = sum(admitted for admitted, _ in results)
    print(f"\n{workers} workers admitted {[admitted for admitted, _ in results]} with a limit of 1")
    assert total <= 1, f"{workers} workers admitted {total} requests of one client with a limit of 1"
    if workers == 1:
        assert total == 1, "a single worker's share is the whole limit: degraded mode still serves it"
