"""Purges, eviction and admin views of the shared tier (plan 6.5, 6.8, parity rows 54, 62, 65, 66).

`test_purge_invalidates_memory_tier_in_another_process` starts a real second process that holds an entry in its
memory tier, purges from this process, and checks the other process stops serving it (v1 bug B6).
"""

from __future__ import annotations

import asyncio
import multiprocessing as mp
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from roxy.cache.service import CacheService, ServeResult
from roxy.cache.store import PurgeKind, PurgeScope
from roxy.cache.testing import FakeSettings, FakeUpstream, StaticRules, make_request, ok, rules_snapshot
from roxy.core.clock import FakeClock, SystemClock
from roxy.core.reasons import CacheState
from roxy.core.tasks import TaskSupervisor
from roxy.rules.match import PatternValidationError
from roxy.storage.db import DB_NAMES, Database
from roxy.storage.migrate import migrate_paths

CTX = mp.get_context("spawn")


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


def service_for(
    dbs: Any, clock: Any, upstream: FakeUpstream | None = None, rules: Any = None, **settings: Any
) -> CacheService:
    return CacheService(
        dbs=dbs,
        settings=FakeSettings(settings),
        rules=StaticRules(rules or rules_snapshot()),
        clock=clock,
        upstream=upstream or FakeUpstream(),
        worker_id="purger",
    )


async def call(service: CacheService, target: str) -> ServeResult:
    """One request, then wait for its background cache.db write (callers never wait for it)."""
    req = make_request(target)
    result = await service.serve(req, await service.peek(req))
    await service.settle()
    return result


async def populate(service: CacheService, clock: FakeClock) -> None:
    for n in range(8):
        await call(service, f"games.roblox.com/v1/games/browse/{n}")
    for n in range(3):
        await call(service, f"users.roblox.com/v1/users/{n}")
    await call(service, "thumbnails.roblox.com/v1/assets?assetIds=1&t=5")
    clock.advance(2)


def count(dbs: Any, where: str = "1") -> int:
    return int(
        dbs.cache.read_sync(lambda conn: conn.execute(f"SELECT count(*) FROM entries WHERE {where}").fetchone()[0])
    )


async def test_purge_scopes_report_true_counts(dbs: Any, clock: FakeClock) -> None:
    rules = rules_snapshot(cache_rules=[{"pattern": "users.roblox.com/v1/users", "ttl": 900}], ignored_params=["t"])
    service = service_for(dbs, clock, rules=rules)
    await populate(service, clock)
    assert count(dbs) == 12
    one = make_request("games.roblox.com/v1/games/browse/0")
    key = (await service.peek(one)).key
    assert key is not None
    assert (await service.purge(PurgeScope.entry(key.id))).removed == 1
    assert (await service.purge(PurgeScope.entry(key.id))).removed == 0  # v1 B7: absent ids report 0
    assert (await service.purge(PurgeScope.entry("../../etc/passwd"))).removed == 0
    assert (await service.purge(PurgeScope.pattern("games.roblox.com/v1/games/browse"))).removed == 7
    assert (await service.purge(PurgeScope.rule(1))).removed == 3
    assert (await service.purge(PurgeScope.param("t"))).removed == 1  # scoped to entries that carried `t`
    assert count(dbs) == 0
    with pytest.raises(PatternValidationError):
        await service.purge(PurgeScope.pattern("(oops", "regex"))
    with pytest.raises(ValueError, match="Nothing to purge"):
        await service.purge(PurgeScope(PurgeKind.HOST, ""))


async def test_purge_host_regex_expired_and_all(dbs: Any, clock: FakeClock) -> None:
    service = service_for(dbs, clock)
    await populate(service, clock)
    assert (await service.purge(PurgeScope.host("USERS.roblox.com"))).removed == 3
    assert (await service.purge(PurgeScope.pattern(r"^thumbnails\.roblox\.com/v1/assets$", "regex"))).removed == 1
    clock.advance(200)  # expired (120) but inside the stale window (720)
    assert (await service.purge(PurgeScope.expired())).removed == 0
    assert (await service.purge(PurgeScope.expired(include_stale=True))).removed == 8
    await populate(service, clock)
    report = await service.purge(PurgeScope.all(), actor=SimpleNamespace(name="owner"))
    assert report.removed == 12
    assert report.generation == 1
    assert report.actor == "owner"
    assert count(dbs) == 0
    assert (await call(service, "games.roblox.com/v1/games/browse/0")).cache_state is CacheState.MISS


async def test_maintenance_removes_dead_rows_first_then_evicts_cold_entries(dbs: Any, clock: FakeClock) -> None:
    service = service_for(dbs, clock, cache_max_entries=5, cache_eviction_policy="hybrid")
    for n in range(4):
        await call(service, f"games.roblox.com/v1/old/{n}")
    clock.advance(1000)  # the old ones are past their stale window: dead
    for n in range(6):
        await call(service, f"games.roblox.com/v1/new/{n}")
    clock.advance(1)
    for _ in range(5):  # make new/0 and new/1 popular
        await call(service, "games.roblox.com/v1/new/0")
        await call(service, "games.roblox.com/v1/new/1")
    await service.flush()
    clock.advance(1)
    report = await service.maintain()
    assert report is not None
    assert report.dead == 4
    assert report.entries_before == 6
    assert report.evicted == 2
    assert report.entries_after == 4
    survivors = {
        row[0] for row in dbs.cache.read_sync(lambda conn: conn.execute("SELECT path FROM entries").fetchall())
    }
    assert {"v1/new/0", "v1/new/1"} <= survivors  # the hot keys survive (v1 evicted oldest first)


async def test_zero_budgets_hold_nothing_v1_b23(dbs: Any, clock: FakeClock) -> None:
    service = service_for(dbs, clock)
    await populate(service, clock)
    zero = service_for(dbs, clock, cache_max_bytes=0)
    report = await zero.maintain()
    assert report is not None
    assert report.entries_after == 0
    assert count(dbs) == 0
    await call(zero, "games.roblox.com/v1/x")
    assert count(dbs) == 0  # nothing new is written either


async def test_byte_budget_counts_stored_size(dbs: Any, clock: FakeClock) -> None:
    upstream = FakeUpstream(lambda req, n: ok(b"z" * 5000))
    service = service_for(dbs, clock, upstream, cache_compress=0)
    for n in range(10):
        await call(service, f"games.roblox.com/v1/big/{n}")
    total = int(dbs.cache.read_sync(lambda conn: conn.execute("SELECT sum(bytes) FROM entries").fetchone()[0]))
    rows, measured = await service.store.shared.totals()
    assert rows == 10
    assert measured == total
    small = service_for(dbs, clock, cache_max_bytes=total // 2)
    report = await small.maintain()
    assert report is not None
    assert report.bytes_after <= total // 2


async def test_admin_views_and_key_spread(dbs: Any, clock: FakeClock) -> None:
    service = service_for(dbs, clock)
    for n in range(6):
        await call(service, f"games.roblox.com/v1/games/9583680112/votes?t={1000 + n}")
    page = await service.list_entries(query="votes", limit=4, sort="key", order="asc")
    assert page["Total"] == 6
    assert len(page["Entries"]) == 4
    assert "body" not in page["Entries"][0]
    entry = await service.get_entry(page["Entries"][0]["id"])
    assert entry is not None
    assert entry["Body"].startswith('{"call"')
    assert entry["Params"][0][0] == "t"
    [group] = await service.key_spread()
    assert group.suspect
    assert group.suspect_param == "t"
    assert group.entries == 6
    assert await service.get_entry("0" * 24) is None


# --------------------------------------------------------------------------- another process's memory tier


def _child_holds_entry(paths: dict[str, str], target: str, ready: Any, purged: Any, results: Any) -> None:
    asyncio.run(_hold_entry(paths, target, ready, purged, results))


async def _hold_entry(paths: dict[str, str], target: str, ready: Any, purged: Any, results: Any) -> None:
    dbs = SimpleNamespace(cache=Database("cache", paths["cache"]), hot=Database("hot", paths["hot"]))
    tasks = TaskSupervisor()
    upstream = FakeUpstream()
    service = CacheService(
        dbs=dbs,
        settings=FakeSettings(),
        rules=StaticRules(),
        clock=SystemClock(),
        upstream=upstream,
        worker_id="child",
        tasks=tasks,
    )
    await service.start()  # the generation watch loop runs every 250 ms
    try:
        before = await call(service, target)
        in_memory = (await service.peek(make_request(target))).fresh is not None and len(service.store.memory) == 1
        ready.set()
        await asyncio.get_running_loop().run_in_executor(None, purged.wait, 30)
        deadline = time.monotonic() + 3.0
        state = None
        while time.monotonic() < deadline:
            await asyncio.sleep(0.1)
            if len(service.store.memory) == 0:
                state = (await service.peek(make_request(target))).state
                break
        results.put((before.cache_state.value, in_memory, None if state is None else state.value, upstream.count))
    finally:
        await tasks.stop(drain_timeout_s=1)
        dbs.cache.close_sync()
        dbs.hot.close_sync()


@pytest.mark.multiprocess
@pytest.mark.skipif(sys.platform == "win32", reason="spawned workers share POSIX file locks")
async def test_purge_invalidates_memory_tier_in_another_process(tmp_path: Path) -> None:
    paths = {name: tmp_path / f"{name}.db" for name in DB_NAMES}
    migrate_paths(paths)
    ready, purged, results = CTX.Event(), CTX.Event(), CTX.Queue()
    target = "games.roblox.com/v1/games/votes?universeIds=42"
    proc = CTX.Process(
        target=_child_holds_entry,
        args=({k: str(v) for k, v in paths.items()}, target, ready, purged, results),
        daemon=True,
    )
    proc.start()
    try:
        assert await asyncio.get_running_loop().run_in_executor(None, ready.wait, 60)
        dbs = SimpleNamespace(cache=Database("cache", paths["cache"]), hot=Database("hot", paths["hot"]))
        try:
            purger = CacheService(
                dbs=dbs,
                settings=FakeSettings(),
                rules=StaticRules(),
                clock=SystemClock(),
                upstream=FakeUpstream(),
                worker_id="parent",
            )
            report = await purger.purge(PurgeScope.pattern("games.roblox.com/v1/games/votes"))
            assert report.removed == 1
        finally:
            dbs.cache.close_sync()
            dbs.hot.close_sync()
        purged.set()
        before, was_in_memory, after, calls = await asyncio.get_running_loop().run_in_executor(
            None, results.get, True, 30
        )
    finally:
        proc.join(10)
        if proc.is_alive():
            proc.kill()
    assert before == "MISS"
    assert was_in_memory
    assert calls == 1
    assert after == "MISS"  # the other process dropped its memory copy and found no row
