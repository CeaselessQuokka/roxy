"""The cache across workers: two CacheService instances with their own connections, memory tiers and flights
share the same cache.db and hot.db files, exactly like two gunicorn workers (plan C6, 6.9).

Includes `test_cred_response_never_served_to_other_auth_class` (plan 6.9): hits, coalescing, SWR and stale serves.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from typing import Any

import pytest

from roxy.cache.service import CacheService, ServeResult
from roxy.cache.store import PurgeScope
from roxy.cache.testing import (
    FakeSettings,
    FakeUpstream,
    StaticRules,
    failure,
    make_request,
    ok,
    rules_snapshot,
)
from roxy.core.clock import FakeClock
from roxy.core.reasons import AuthClass, CacheState, Egress, ReasonCode
from roxy.storage.db import open_databases

VOTES = "games.roblox.com/v1/games/votes?universeIds=1"
CURRENCY = "economy.roblox.com/v1/user/currency"


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def second_dbs(env: Any, dbs: Any) -> Iterator[Any]:
    """The same database files through another set of connections (a second worker)."""
    other = open_databases(env)
    yield other
    other.close_all_sync()


def worker(
    dbs: Any, clock: FakeClock, name: str, upstream: FakeUpstream, rules: Any = None, **settings: Any
) -> CacheService:
    return CacheService(
        dbs=dbs,
        settings=FakeSettings(settings),
        rules=StaticRules(rules or rules_snapshot()),
        clock=clock,
        upstream=upstream,
        worker_id=name,
    )


async def call(service: CacheService, target: str = VOTES, **kwargs: Any) -> ServeResult:
    req = make_request(target, **kwargs)
    return await service.serve(req, await service.peek(req))


async def test_a_store_in_one_worker_is_a_hit_in_another(dbs: Any, second_dbs: Any, clock: FakeClock) -> None:
    up_a, up_b = FakeUpstream(), FakeUpstream()
    a, b = worker(dbs, clock, "a", up_a), worker(second_dbs, clock, "b", up_b)
    stored = await call(a)
    clock.advance(3)
    shared = await call(b)
    assert shared.cache_state is CacheState.HIT
    assert shared.body == stored.body
    assert up_a.count == 1
    assert up_b.count == 0


async def test_one_upstream_call_for_concurrent_requests_in_two_workers(
    dbs: Any, second_dbs: Any, clock: FakeClock
) -> None:
    gate = asyncio.Event()
    up_a, up_b = FakeUpstream(gate=gate), FakeUpstream(gate=gate)
    a, b = worker(dbs, clock, "a", up_a), worker(second_dbs, clock, "b", up_b)
    tasks = [asyncio.create_task(call(a)) for _ in range(10)] + [asyncio.create_task(call(b)) for _ in range(10)]
    await asyncio.sleep(0.3)
    gate.set()
    results = await asyncio.gather(*tasks)
    assert up_a.count + up_b.count == 1
    states = [r.cache_state for r in results]
    assert states.count(CacheState.MISS) == 1
    assert states.count(CacheState.COALESCED) == 19
    assert len({r.body for r in results}) == 1


async def test_owner_failure_reaches_the_other_worker_without_calls(
    dbs: Any, second_dbs: Any, clock: FakeClock
) -> None:
    gate = asyncio.Event()
    fail = lambda req, n: failure(ReasonCode.UPSTREAM_5XX, 503, retry_after_s=7)  # noqa: E731
    up_a, up_b = FakeUpstream(fail, gate=gate), FakeUpstream(fail, gate=gate)
    a, b = worker(dbs, clock, "a", up_a), worker(second_dbs, clock, "b", up_b)
    owner = asyncio.create_task(call(a))
    await up_a.started.wait()
    followers = [asyncio.create_task(call(b)) for _ in range(5)]
    await asyncio.sleep(0.2)
    gate.set()
    results = await asyncio.gather(owner, *followers)
    assert up_a.count == 1
    assert up_b.count == 0
    for result in results:
        assert result.status == 503
        assert result.reason is ReasonCode.UPSTREAM_5XX
        assert result.retry_after_s == 7
    assert all(r.upstream_calls == 0 for r in results[1:])


async def test_purge_reaches_the_other_workers_memory_tier(dbs: Any, second_dbs: Any, clock: FakeClock) -> None:
    up_a, up_b = FakeUpstream(), FakeUpstream()
    a, b = worker(dbs, clock, "a", up_a), worker(second_dbs, clock, "b", up_b)
    await a.start()
    await b.start()
    await call(a)
    clock.advance(2)
    assert (await call(b)).cache_state is CacheState.HIT  # now also in b's memory tier
    key_id = make_request(VOTES)
    peek = await b.peek(key_id)
    assert peek.key is not None
    assert peek.key.id in b.store.memory
    report = await a.purge(PurgeScope.host("games.roblox.com"), actor="test")
    assert report.removed == 1
    assert report.fleet_invalidated
    assert await b.store.sync_generation()  # b's watch loop (every 250 ms) sees the stamp move
    assert len(b.store.memory) == 0
    clock.advance(2)
    again = await call(b)
    assert again.cache_state is CacheState.MISS
    assert up_b.count == 1


async def test_purge_all_makes_old_rows_misses_before_they_are_deleted(
    dbs: Any, second_dbs: Any, clock: FakeClock
) -> None:
    up_a, up_b = FakeUpstream(), FakeUpstream()
    a, b = worker(dbs, clock, "a", up_a), worker(second_dbs, clock, "b", up_b)
    await call(a)
    # Simulate "the batched deletes have not reached this row yet": move the purge-all generation only.
    floor, _stamp = await b.store.shared.bump_generation(purge_all=True, now_s=int(clock.now()))
    assert floor == 1
    clock.advance(2)
    result = await call(b)
    assert result.cache_state is CacheState.MISS
    assert up_b.count == 1


async def test_cred_response_never_served_to_other_auth_class(dbs: Any, second_dbs: Any, clock: FakeClock) -> None:
    """Plan 6.9: a credential answer and an anonymous answer of one URL never share an entry, a flight, an SWR
    refresh or a stale serve. Worker `cred` has the endpoint on its credential allowlist (cache_private 0);
    worker `anon` does not (as after the admin removed the allowlist row)."""
    cred_rules = rules_snapshot(
        credential_allowlist=[
            {"pattern": "economy.roblox.com/v1/user/currency", "methods": ["GET"], "cache_private": 0}
        ]
    )
    gate = asyncio.Event()
    gate.set()
    up_cred = FakeUpstream(
        lambda req, n: ok(f'{{"robux":"secret-{n}"}}', auth_class=AuthClass.CRED, egress=Egress.CREDENTIAL), gate=gate
    )
    up_anon = FakeUpstream(lambda req, n: ok(f'{{"robux":"anon-{n}"}}'), gate=gate)
    cred = worker(dbs, clock, "cred", up_cred, cred_rules)
    anon = worker(second_dbs, clock, "anon", up_anon)

    # Hits: each class gets only its own entry.
    first_cred = await call(cred, CURRENCY)
    first_anon = await call(anon, CURRENCY)
    assert first_cred.auth_class is AuthClass.CRED
    assert b"secret" in first_cred.body
    assert first_anon.cache_state is CacheState.MISS
    assert b"anon" in first_anon.body
    assert first_cred.key_id != first_anon.key_id
    clock.advance(2)
    assert b"secret" not in (await call(anon, CURRENCY)).body
    assert b"secret" in (await call(cred, CURRENCY)).body

    # Coalescing: concurrent fetches of both classes are separate flights.
    clock.advance(800)  # both entries are long gone (past their stale windows)
    gate.clear()
    tasks = [asyncio.create_task(call(cred, CURRENCY)) for _ in range(3)]
    tasks += [asyncio.create_task(call(anon, CURRENCY)) for _ in range(3)]
    await asyncio.sleep(0.2)
    gate.set()
    results = await asyncio.gather(*tasks)
    assert up_cred.count == 2
    assert up_anon.count == 2
    assert all(b"secret" in r.body for r in results[:3])
    assert all(b"secret" not in r.body for r in results[3:])

    # Stale-while-revalidate: each class revalidates its own entry with its own refresh.
    clock.advance(150)
    revalidating = await call(anon, CURRENCY)
    assert revalidating.cache_state is CacheState.REVALIDATING
    assert b"secret" not in revalidating.body
    await anon.swr.drain()
    assert up_anon.count == 3
    assert up_cred.count == 2
    cred_revalidating = await call(cred, CURRENCY)
    assert cred_revalidating.cache_state is CacheState.REVALIDATING
    assert b"secret" in cred_revalidating.body
    await cred.swr.drain()

    # Stale after failure: the anonymous caller gets its own stale copy, never the credential one.
    clock.advance(300)
    up_anon.responder = lambda req, n: failure(ReasonCode.UPSTREAM_5XX, 503)
    stale = await call(anon, CURRENCY)
    assert stale.cache_state is CacheState.STALE
    assert b"anon" in stale.body
    assert b"secret" not in stale.body


async def test_credential_answer_for_an_anonymous_key_is_neither_stored_nor_shared(
    dbs: Any, second_dbs: Any, clock: FakeClock
) -> None:
    """Defense in depth: if the upstream ever answered an anonymous key with the credential, nothing keeps it."""
    gate = asyncio.Event()
    leaky = lambda req, n: ok('{"robux":"secret"}', auth_class=AuthClass.CRED)  # noqa: E731
    up_a, up_b = FakeUpstream(leaky, gate=gate), FakeUpstream(lambda req, n: ok('{"robux":"anon"}'))
    a, b = worker(dbs, clock, "a", up_a), worker(second_dbs, clock, "b", up_b)
    owner = asyncio.create_task(call(a, CURRENCY))
    await up_a.started.wait()
    follower = asyncio.create_task(call(b, CURRENCY))
    await asyncio.sleep(0.2)
    gate.set()
    await owner
    other = await follower
    assert b"secret" not in other.body
    assert up_b.count == 1
    count = dbs.cache.read_sync(
        lambda conn: conn.execute("SELECT count(*) FROM entries WHERE body_len > 0").fetchone()[0]
    )
    assert count == 1  # only the anonymous answer was stored


async def test_maintenance_runs_once_per_period_fleet_wide(dbs: Any, second_dbs: Any, clock: FakeClock) -> None:
    a = worker(dbs, clock, "a", FakeUpstream(), cache_max_entries=3)
    b = worker(second_dbs, clock, "b", FakeUpstream(), cache_max_entries=3)
    for n in range(6):
        await call(a, f"games.roblox.com/v1/games/votes?universeIds={n}")
    report = await a.maintain()
    assert report is not None
    assert report.evicted >= 3
    assert await b.maintain() is None  # within the same minute: not b's turn
    clock.advance(61)
    assert await b.maintain() is not None
    count = dbs.cache.read_sync(lambda conn: conn.execute("SELECT count(*) FROM entries").fetchone()[0])
    assert count <= 3
