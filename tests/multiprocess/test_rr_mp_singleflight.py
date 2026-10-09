"""Review round, lens mp: single-flight when the owner's worker goes away between its store and its publish.

What this is
    The reproduction of finding mp-12 (fixed). Two `CacheService` objects play two workers over the same migrated
    cache.db and hot.db (each with its own connections), and a "lock holder" process keeps hot.db write-locked at
    the moment the owner answers, the way a stalled worker, a long prune batch or a backup would. The owner's
    worker then shuts down gracefully (`CacheService.close()`, what a `max_requests` recycle, a reload or a deploy
    stop runs); an OOM kill at the same moment leaves the same state.

Why it exists
    Plan 6.9 step 4: "Losers (other workers) poll cache.db for K ... They then read the stored outcome: fresh entry
    (serve COALESCED)". The wave 2 single-flight moved the owner's outcome into its hot.db lease row, and followers
    in other workers polled ONLY that row (`SingleFlight._follow`). Answer-first (fix pass, CACHE-WAIT and SF-ORPHAN)
    stores the answer in cache.db from the owner's tail and only then publishes the outcome into the lease row,
    retrying while hot.db refuses. When the owner's worker went away in between (graceful close cancels tails after
    2 s; a kill cancels everything), the answer sat fresh in cache.db, the lease row said "in progress" until the
    owner deadline (36 s with defaults), and every follower that was already waiting got 503 `coalesce_timeout`
    when its own wait ended, never the stored answer. Now a follower that has waited `STORE_CHECK_AFTER_S` on a live
    lease also looks in cache.db (the cache's `_stored_answer`, every `STORE_CHECK_EVERY_S` and once more before a
    timeout) and serves the owner's stored entry as `COALESCED`.

How it works
    Owner deadline 11 s (`queue_wait_interactive_ms` 500, `request_timeout` 10, one attempt, backoff cap 500), the
    followers' wait 5 s (`cache_coalesce_wait_ms`). The owner's fetch waits on a gate; the follower starts and
    follows the live lease; hot.db is locked; the gate opens; the owner answers 200 and its tail stores the entry in
    cache.db (cache.db is free) but cannot publish; the test waits for the cache.db row, closes the owner service,
    keeps the lock 1.5 s more (longer than the last shielded publish attempt's 1 s budget; a lock that ends sooner
    lets that attempt land), releases it, and awaits the follower. The follower must be answered `COALESCED` from
    cache.db within a few seconds of the store (before the lock ends), with no upstream call of its own.

What to read next
    `roxy/upstream/singleflight.py` (`_follow`, `_check_store`, `_tail`, `close`), `roxy/cache/service.py`
    (`_fetch`, `_stored_answer`, `_serve_flight`, `_finish`), tests/multiprocess/test_review_failure_modes_mp.py
    (SF-ORPHAN).
"""

from __future__ import annotations

import asyncio
import multiprocessing as mp
import sqlite3
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from roxy.cache.service import CacheService
from roxy.cache.testing import FakeSettings, FakeUpstream, StaticRules, make_request
from roxy.core.clock import SystemClock
from roxy.core.reasons import CacheState, ReasonCode
from roxy.storage.db import DB_NAMES, Database
from roxy.storage.migrate import migrate_paths

pytestmark = [
    pytest.mark.multiprocess,
    pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX processes"),
]

CTX = mp.get_context("spawn")
TARGET = "games.roblox.com/v1/games/votes?universeIds=8686"
SETTINGS = {
    "queue_wait_interactive_ms": 500,
    "request_timeout": 10,
    "upstream_max_attempts": 1,
    "backoff_cap_ms": 500,
    "cache_coalesce_wait_ms": 5000,
}


def _hold_lock(path: str, ready: Any, release: Any) -> None:
    conn = sqlite3.connect(path, isolation_level=None, timeout=30)
    conn.execute("BEGIN IMMEDIATE")
    ready.set()
    release.wait(60)
    conn.execute("ROLLBACK")
    conn.close()


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


def _stored_rows(cache_path: str) -> int:
    conn = sqlite3.connect(f"file:{cache_path}?mode=ro", uri=True, timeout=5)
    try:
        return int(conn.execute("SELECT count(*) FROM entries WHERE substr(key, -8) != ' !flight'").fetchone()[0])
    finally:
        conn.close()


@pytest.mark.timeout(120)
async def test_rr_mp_followers_get_the_stored_answer_when_the_owner_goes_before_publishing(
    paths: dict[str, str], procs: list[Any]
) -> None:
    def worker(name: str, upstream: FakeUpstream) -> tuple[CacheService, Any]:
        dbs = SimpleNamespace(cache=Database("cache", paths["cache"]), hot=Database("hot", paths["hot"]))
        service = CacheService(
            dbs=dbs,
            settings=FakeSettings(SETTINGS),
            rules=StaticRules(),
            clock=SystemClock(),
            upstream=upstream,
            worker_id=name,
        )
        return service, dbs

    async def call(service: CacheService) -> Any:
        req = make_request(TARGET)
        return await service.serve(req, await service.peek(req))

    gate = asyncio.Event()
    up_owner, up_other = FakeUpstream(gate=gate), FakeUpstream()
    owner, owner_dbs = worker("rr-mp-owner", up_owner)
    other, other_dbs = worker("rr-mp-other", up_other)
    await owner.start()
    await other.start()
    ready, release = CTX.Event(), CTX.Event()
    holder = CTX.Process(target=_hold_lock, args=(paths["hot"], ready, release), daemon=True)
    done_at: list[float] = []
    try:
        first = asyncio.ensure_future(call(owner))
        await asyncio.wait_for(up_owner.started.wait(), 10)  # the owner holds the lease and is fetching
        follower = asyncio.ensure_future(call(other))
        follower.add_done_callback(lambda _task: done_at.append(time.monotonic()))
        await asyncio.sleep(0.3)  # the other worker saw the live lease and follows it
        holder.start()
        procs.append(holder)
        assert await asyncio.to_thread(ready.wait, 20), "the lock holder never took hot.db's write lock"
        gate.set()
        answer = await asyncio.wait_for(first, 10)
        assert answer.status == 200
        for _ in range(100):  # the owner's tail stores the answer in cache.db (free) right after answering
            if await asyncio.to_thread(_stored_rows, paths["cache"]):
                break
            await asyncio.sleep(0.05)
        else:
            raise AssertionError("the owner never stored its answer in cache.db")
        stored_at = time.monotonic()
        await owner.close()  # the owner's worker recycles: tails get 2 s, then are canceled (publish still refused)
        await asyncio.sleep(1.5)  # the lock outlasts the last (shielded) publish attempt's 1 s budget
        released_at = time.monotonic()
        release.set()
        result = await asyncio.wait_for(follower, 30)
    finally:
        release.set()
        for dbs in (owner_dbs, other_dbs):
            await dbs.cache.close()
            await dbs.hot.close()
        await other.close()
    answered_s = done_at[0] - stored_at
    print(
        f"\nfollower got {result.status} {result.reason.value} {answered_s:.2f} s after the answer was in cache.db; "
        f"other worker's upstream calls {up_other.count}"
    )
    assert up_other.count == 0  # a follower never goes upstream itself
    assert result.reason is not ReasonCode.COALESCE_TIMEOUT, "the stored answer was never read by the follower"
    assert (result.status, result.cache_state, result.body) == (200, CacheState.COALESCED, answer.body)
    # Answered while hot.db was still locked, so from cache.db (no publish could land), and soon after the store:
    # the follower looks there every STORE_CHECK_EVERY_S once the flight has run STORE_CHECK_AFTER_S.
    assert done_at[0] < released_at
    assert answered_s < 3.0, f"the follower read the stored answer {answered_s:.2f} s after it landed"
