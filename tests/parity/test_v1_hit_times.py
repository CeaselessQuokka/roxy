"""v1 parity: a cache hit time flushed by several workers stays the newest hit (v1's blank dashboard of 2026-10-09).

What this is
    The v2 side of v1's last smoke section, "Timestamps never compound across workers, and NaN never reaches the
    dashboard" (added by the v1 fix 12616fd): four workers that flush their cache hits in turn leave the entry's
    last hit time at the newest hit, and its hit count still adds up across the workers.

Why it exists
    v1's cross-worker merge added the cache's LastHit and LastMiss like counters. With three or more gunicorn
    workers the value swung with a growing amplitude until it overflowed to infinity and then NaN, and the NaN in
    /admin/diagnostics blanked every dashboard tile. v2 has no merge of per-worker JSON: each worker writes its
    buffered hits to cache.db with `hits = hits + n` and `last_hit_at = max(last_hit_at, at)` (plan 6.9, C6). These
    tests pin that with four workers on the same database files, the way v1's check used four.

How it works
    Four `CacheService` instances, each with its own connections to the same cache.db and hot.db (four gunicorn
    workers, as in tests/integration/test_cache_workers.py), share one stored answer. In turn, each serves it as a
    hit on a fake clock that moves forward and flushes its hit buffer; after every flush another worker reads the
    row. The rest of that v1 section (a NaN in the shared file, the repair on load, strict JSON in
    /admin/diagnostics) is v1 machinery v2 does not have; tests/V1_PARITY.md says what covers each row instead.

What to read next
    `roxy/cache/store.py` (`HitBuffer`, `SharedTier.flush`), `tests/integration/test_cache_workers.py` (the cache
    across workers) and `tests/migration/test_migration_damaged_numbers.py` (v1's damaged numbers at the import).
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from roxy.cache.service import CacheService, ServeResult
from roxy.cache.testing import FakeSettings, FakeUpstream, StaticRules, make_request, rules_snapshot
from roxy.core.clock import FakeClock
from roxy.core.reasons import CacheState
from roxy.storage.db import open_databases

VOTES = "games.roblox.com/v1/games/votes?universeIds=1"
WORKERS = 4
ROUNDS = 50
"""Hits per worker: 200 flushes in all, each one by the next worker in turn."""


class Fleet:
    """Four cache workers over the same database files, and the fake clock they share."""

    def __init__(self, workers: list[CacheService], clock: FakeClock) -> None:
        self.workers = workers
        self.clock = clock


@pytest.fixture
def fleet(env: Any, dbs: Any) -> Iterator[Fleet]:
    clock = FakeClock()
    others = [open_databases(env) for _ in range(WORKERS - 1)]
    upstream = FakeUpstream()
    # A long lifetime and no default rules: every request after the first is a hit for the whole test.
    settings = {"cache_ttl_seconds": 3600, "cache_default_rules_enabled": 0}
    workers = [
        CacheService(
            dbs=databases,
            settings=FakeSettings(settings),
            rules=StaticRules(rules_snapshot()),
            clock=clock,
            upstream=upstream,
            worker_id=f"w{index}",
        )
        for index, databases in enumerate([dbs, *others])
    ]
    try:
        yield Fleet(workers, clock)
    finally:
        for databases in others:
            databases.close_all_sync()


async def call(service: CacheService) -> ServeResult:
    """One request, then wait for its background cache.db write (callers never wait for it)."""
    req = make_request(VOTES)
    result = await service.serve(req, await service.peek(req))
    await service.settle()
    return result


async def stored_entry(fleet: Fleet) -> str:
    first = await call(fleet.workers[0])
    assert first.cache_state is CacheState.MISS
    assert first.key_id, "the answer was stored under a key"
    return first.key_id


async def test_v1_four_workers_flushing_hits_in_turn_keep_the_newest_time_and_the_sum(fleet: Fleet) -> None:
    """v1 smoke lines 3576 to 3578: 4 workers flush the hit time in turn; it always reads as the newest hit (never a
    sum or a swing of two workers' times), and the hit count adds up across the workers."""
    entry_id = await stored_entry(fleet)
    for step in range(WORKERS * ROUNDS):
        fleet.clock.advance(1)
        worker = fleet.workers[step % WORKERS]
        assert (await call(worker)).cache_state is CacheState.HIT
        await worker.flush()
        row = await fleet.workers[(step + 1) % WORKERS].get_entry(entry_id)  # read by the next worker
        assert row is not None
        assert row["LastHit"] == int(fleet.clock.now()), (step, row["LastHit"])
        assert row["Hits"] == step + 1, (step, row["Hits"])


async def test_v1_an_older_hit_flushed_late_never_moves_the_time_back(fleet: Fleet) -> None:
    """The order v1's merge got wrong: a worker whose buffered hit is older flushes after one with a newer hit."""
    first, second = fleet.workers[0], fleet.workers[1]
    entry_id = await stored_entry(fleet)
    fleet.clock.advance(10)
    await call(first)  # a hit, buffered in the first worker
    fleet.clock.advance(10)
    await call(second)
    await second.flush()
    newest = int(fleet.clock.now())
    await first.flush()  # the older hit lands last
    row = await second.get_entry(entry_id)
    assert row is not None
    assert row["LastHit"] == newest
    assert row["Hits"] == 2
