"""CacheService.peek and serve (DESIGN 11.2): every Roxy-Cache state, against real temp SQLite files.

States covered: HIT (and negative HIT), REVALIDATING, STALE (marker cooldown, upstream cooldown, after failure,
coalesce timeout), COALESCED, MISS, OFF. The clock is a FakeClock, so entry lifetimes and lease expiry move only
when a test says so (a finished flight's outcome lingers one fake second; tests advance past it).
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest

from roxy.cache.service import CacheService, ServeResult, _detached
from roxy.cache.testing import (
    FakeSettings,
    FakeUpstream,
    StaticRules,
    failure,
    make_request,
    ok,
    roblox_429,
    roblox_error,
    rules_snapshot,
)
from roxy.core.clock import FakeClock
from roxy.core.reasons import AuthClass, CacheState, Egress, Outcome, ReasonCode, Source
from roxy.storage.db import open_databases
from roxy.upstream.queue import Priority

VOTES = "games.roblox.com/v1/games/votes?universeIds=1"


def make_service(
    dbs: Any, clock: FakeClock, upstream: FakeUpstream | None = None, *, worker: str = "w1", **settings: Any
) -> CacheService:
    return CacheService(
        dbs=dbs,
        settings=FakeSettings(settings),
        rules=StaticRules(rules_snapshot()),
        clock=clock,
        upstream=upstream or FakeUpstream(),
        worker_id=worker,
    )


async def call(service: CacheService, target: str = VOTES, **kwargs: Any) -> ServeResult:
    req = make_request(target, **kwargs)
    peek = await service.peek(req)
    return await service.serve(req, peek)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


async def test_miss_then_hit(dbs: Any, clock: FakeClock) -> None:
    upstream = FakeUpstream()
    service = make_service(dbs, clock, upstream)
    first = await call(service)
    assert first.cache_state is CacheState.MISS
    assert first.status == 200
    assert first.outcome is Outcome.SERVED_UPSTREAM
    assert first.source is Source.ROBLOX
    assert first.reason is ReasonCode.UPSTREAM_OK
    assert first.upstream_calls == 1
    assert first.egress is Egress.DIRECT
    assert upstream.calls[0].priority == Priority.INTERACTIVE
    assert upstream.calls[0].purpose == "caller"
    clock.advance(5)
    req = make_request(VOTES)
    peek = await service.peek(req)
    assert req.fresh_cache_hit
    assert req.cache_key is peek.key
    second = await service.serve(req, peek)
    assert second.cache_state is CacheState.HIT
    assert second.reason is ReasonCode.CACHE_HIT
    assert second.body == first.body
    assert second.cache_age_s == 5
    assert second.cache_ttl_s == 120
    assert second.outcome is Outcome.SERVED_CACHE
    assert second.source is Source.CACHE
    assert second.upstream_calls == 0
    assert second.key_id == first.key_id == peek.key.id
    assert upstream.count == 1
    assert service.stats.hits == 1
    assert service.stats.misses == 1
    assert service.stats.stores == 1


async def test_hit_from_shared_tier_after_memory_loss(dbs: Any, clock: FakeClock) -> None:
    upstream = FakeUpstream()
    service = make_service(dbs, clock, upstream)
    await call(service)
    service.store.memory.clear()
    again = await call(service)
    assert again.cache_state is CacheState.HIT
    assert upstream.count == 1
    assert len(service.store.memory) == 1  # promoted back into memory


async def test_off_when_disabled_and_for_write_methods(dbs: Any, clock: FakeClock) -> None:
    upstream = FakeUpstream()
    disabled = make_service(dbs, clock, upstream, cache_enabled=0)
    result = await call(disabled)
    assert result.cache_state is CacheState.OFF
    assert result.key_id is None
    enabled = make_service(dbs, clock, upstream)
    put = await call(enabled, "games.roblox.com/v1/x", method="PUT", body=b"{}")
    assert put.cache_state is CacheState.OFF
    assert upstream.count == 2


async def test_negative_entries_replay_their_status(dbs: Any, clock: FakeClock) -> None:
    upstream = FakeUpstream(lambda req, n: roblox_error(404, b'{"errors":[{"code":0}]}'))
    service = make_service(dbs, clock, upstream)
    first = await call(service)
    assert first.status == 404
    assert first.cache_state is CacheState.MISS
    assert first.reason is ReasonCode.UPSTREAM_4XX
    clock.advance(2)
    second = await call(service)
    assert second.status == 404
    assert second.cache_state is CacheState.HIT
    assert second.reason is ReasonCode.CACHE_NEGATIVE
    assert upstream.count == 1
    clock.advance(61)  # past cache_error_ttl_seconds: a negative entry is never served stale
    third = await call(service)
    assert third.cache_state is CacheState.MISS
    assert upstream.count == 2


async def test_revalidating_serves_at_once_and_refreshes_once(dbs: Any, clock: FakeClock) -> None:
    gate = asyncio.Event()
    upstream = FakeUpstream()
    service = make_service(dbs, clock, upstream)
    original = await call(service)
    clock.advance(150)  # expired at 120, inside the 60 s SWR window
    upstream.gate = gate
    results = [await call(service) for _ in range(3)]
    assert all(r.cache_state is CacheState.REVALIDATING for r in results)
    assert all(r.reason is ReasonCode.CACHE_REVALIDATING and r.body == original.body for r in results)
    assert results[0].cache_age_s == 150
    await upstream.started.wait()
    gate.set()
    await service.swr.drain()
    assert upstream.count == 2  # one background refresh for three REVALIDATING serves
    refresh = upstream.calls[1]
    assert refresh.priority == Priority.BACKGROUND
    assert refresh.purpose == "swr_refresh"
    assert refresh.stale_available
    refreshed = await call(service)
    assert refreshed.cache_state is CacheState.HIT
    assert refreshed.body != original.body
    assert service.stats.refreshes == 1


async def test_swr_budget_zero_fetches_while_the_caller_waits(dbs: Any, clock: FakeClock) -> None:
    upstream = FakeUpstream()
    service = make_service(dbs, clock, upstream, swr_max_inflight=0)
    await call(service)
    clock.advance(150)
    result = await call(service)
    assert result.cache_state is CacheState.MISS
    assert upstream.count == 2
    assert upstream.calls[1].priority == Priority.INTERACTIVE_STALE
    assert upstream.calls[1].stale_available


async def test_stale_during_upstream_cooldown_without_contacting_roblox(dbs: Any, clock: FakeClock) -> None:
    upstream = FakeUpstream()
    service = make_service(dbs, clock, upstream)
    original = await call(service)
    clock.advance(300)  # beyond SWR (180), inside the stale window (720)
    upstream.cooldown_s = 25.0
    result = await call(service)
    assert result.cache_state is CacheState.STALE
    assert result.reason is ReasonCode.CACHE_STALE_COOLDOWN
    assert result.cooldown_s == 25
    assert result.body == original.body
    assert result.upstream_calls == 0
    assert upstream.count == 1


async def test_stale_after_failure(dbs: Any, clock: FakeClock) -> None:
    upstream = FakeUpstream()
    service = make_service(dbs, clock, upstream)
    original = await call(service)
    clock.advance(300)
    upstream.responder = lambda req, n: failure(ReasonCode.UPSTREAM_5XX, 503)
    result = await call(service)
    assert result.cache_state is CacheState.STALE
    assert result.reason is ReasonCode.CACHE_STALE_ERROR
    assert result.stale_after_failure
    assert result.status == 200
    assert result.body == original.body
    assert result.upstream_calls == 1
    assert result.upstream_status == 503


async def test_failure_without_stale_passes_through_as_miss(dbs: Any, clock: FakeClock) -> None:
    service = make_service(dbs, clock, FakeUpstream(lambda req, n: failure(ReasonCode.UPSTREAM_TIMEOUT, 504)))
    result = await call(service)
    assert result.cache_state is CacheState.MISS
    assert result.status == 504
    assert result.outcome is Outcome.FAILED
    assert result.reason is ReasonCode.UPSTREAM_TIMEOUT


async def test_definitive_404_does_not_get_a_stale_200_v1_b18(dbs: Any, clock: FakeClock) -> None:
    upstream = FakeUpstream()
    service = make_service(dbs, clock, upstream)
    await call(service)
    clock.advance(300)
    upstream.responder = lambda req, n: roblox_error(404)
    result = await call(service)
    assert result.status == 404
    assert result.cache_state is CacheState.MISS


async def test_429_marker_keeps_callers_away_from_roblox(dbs: Any, clock: FakeClock) -> None:
    upstream = FakeUpstream(lambda req, n: roblox_429(30))
    service = make_service(dbs, clock, upstream)
    first = await call(service)
    assert first.status == 429
    assert first.reason is ReasonCode.UPSTREAM_COOLDOWN
    assert first.cache_state is CacheState.MISS
    clock.advance(5)
    second = await call(service)
    assert upstream.count == 1  # answered from the marker
    assert second.status == 429
    assert second.reason is ReasonCode.UPSTREAM_COOLDOWN
    assert second.retry_after_s == 25
    assert second.cooldown_s == 25
    assert second.upstream_calls == 0
    clock.advance(30)  # marker expired
    upstream.responder = lambda req, n: ok("{}")
    third = await call(service)
    assert third.status == 200
    assert upstream.count == 2


async def test_429_with_stale_entry_serves_stale_then_marker_keeps_serving_stale(dbs: Any, clock: FakeClock) -> None:
    upstream = FakeUpstream()
    service = make_service(dbs, clock, upstream)
    original = await call(service)
    clock.advance(300)
    upstream.responder = lambda req, n: roblox_429(60)
    after = await call(service)
    assert after.cache_state is CacheState.STALE
    assert after.stale_after_failure
    assert after.upstream_status == 429
    assert after.cooldown_s == 60
    clock.advance(5)
    during = await call(service)
    assert during.cache_state is CacheState.STALE
    assert during.reason is ReasonCode.CACHE_STALE_COOLDOWN
    assert during.body == original.body
    assert during.cooldown_s == 55
    assert upstream.count == 2


async def test_coalesced_in_one_worker(dbs: Any, clock: FakeClock) -> None:
    gate = asyncio.Event()
    upstream = FakeUpstream(gate=gate)
    service = make_service(dbs, clock, upstream)
    tasks = [asyncio.create_task(call(service)) for _ in range(10)]
    await upstream.started.wait()
    await asyncio.sleep(0.05)
    gate.set()
    results = await asyncio.gather(*tasks)
    assert upstream.count == 1
    states = [r.cache_state for r in results]
    assert states.count(CacheState.MISS) == 1
    assert states.count(CacheState.COALESCED) == 9
    coalesced = next(r for r in results if r.cache_state is CacheState.COALESCED)
    assert coalesced.reason is ReasonCode.CACHE_COALESCED
    assert coalesced.upstream_calls == 0
    assert len({r.body for r in results}) == 1


async def test_coalesce_timeout_and_stale_fallback(dbs: Any, env: Any, clock: FakeClock) -> None:
    other_dbs = open_databases(env)
    try:
        gate = asyncio.Event()
        owner_upstream = FakeUpstream(gate=gate)
        owner = make_service(other_dbs, clock, owner_upstream, worker="w2")
        owner_task = asyncio.create_task(call(owner))
        await owner_upstream.started.wait()
        follower_upstream = FakeUpstream()
        follower = make_service(dbs, clock, follower_upstream, cache_coalesce_wait_ms=200)
        timed_out = await call(follower)
        assert timed_out.status == 503
        assert timed_out.reason is ReasonCode.COALESCE_TIMEOUT
        assert timed_out.cache_state is CacheState.MISS
        assert timed_out.retry_after_s == 36
        assert follower_upstream.count == 0  # followers never call upstream themselves
        gate.set()
        await owner_task
    finally:
        other_dbs.close_all_sync()


async def test_bypass_with_respected_no_cache(dbs: Any, clock: FakeClock) -> None:
    upstream = FakeUpstream()
    service = make_service(dbs, clock, upstream, cache_respect_no_cache=1)
    await call(service)
    clock.advance(2)
    bypass = await call(service, headers={"Cache-Control": "no-cache"})
    assert bypass.cache_state is CacheState.MISS
    assert upstream.count == 2
    assert service.stats.bypassed == 1


async def test_private_credential_endpoint_is_never_stored_or_coalesced(dbs: Any, clock: FakeClock) -> None:
    upstream = FakeUpstream(lambda req, n: ok("{}", auth_class=AuthClass.CRED, egress=Egress.CREDENTIAL))
    service = make_service(dbs, clock, upstream)
    service._rules = StaticRules(
        rules_snapshot(
            credential_allowlist=[
                {"pattern": "users.roblox.com/v1/users/authenticated", "methods": ["GET"], "cache_private": 1}
            ]
        )
    )
    results = [await call(service, "users.roblox.com/v1/users/authenticated") for _ in range(2)]
    assert all(r.cache_state is CacheState.OFF for r in results)
    assert upstream.count == 2
    count = dbs.cache.read_sync(lambda conn: conn.execute("SELECT count(*) FROM entries").fetchone()[0])
    leases = dbs.hot.read_sync(
        lambda conn: conn.execute("SELECT count(*) FROM lease WHERE name LIKE 'sf:%'").fetchone()[0]
    )
    assert count == 0
    assert leases == 0


async def test_rule_ttl_zero_is_miss_skipped_and_not_coalesced(dbs: Any, clock: FakeClock) -> None:
    upstream = FakeUpstream()
    service = make_service(dbs, clock, upstream)
    service._rules = StaticRules(rules_snapshot(cache_rules=[{"pattern": "games.roblox.com/v1/games", "ttl": 0}]))
    results = [await call(service) for _ in range(2)]
    assert all(r.cache_state is CacheState.MISS for r in results)
    assert upstream.count == 2
    assert service.stats.skipped == 2
    assert service.stats.stores == 0


async def test_post_batch_lookups_cached_by_body(dbs: Any, clock: FakeClock) -> None:
    upstream = FakeUpstream()
    service = make_service(dbs, clock, upstream)
    headers = {"content-type": "application/json"}
    body = b'{"userIds":[1,2]}'
    first = await call(service, "users.roblox.com/v1/users", method="POST", body=body, headers=headers)
    clock.advance(2)
    second = await call(service, "users.roblox.com/v1/users", method="POST", body=body, headers=headers)
    other = await call(service, "users.roblox.com/v1/users", method="POST", body=b'{"userIds":[3]}', headers=headers)
    assert first.cache_state is CacheState.MISS
    assert second.cache_state is CacheState.HIT
    assert other.cache_state is CacheState.MISS
    assert upstream.count == 2
    inspected = await service.get_entry(first.key_id)
    assert inspected is not None
    assert inspected["RequestBody"] == body.decode()


async def test_hits_and_change_observations_are_flushed(dbs: Any, clock: FakeClock) -> None:
    upstream = FakeUpstream(lambda req, n: ok('{"same":true}'))
    service = make_service(dbs, clock, upstream)
    first = await call(service)
    clock.advance(1)
    await call(service)
    await call(service)
    clock.advance(800)  # far past the stale window: a plain refetch of a key that had a body
    await call(service)
    assert await service.flush() >= 1
    hits = dbs.cache.read_sync(
        lambda conn: conn.execute("SELECT hits FROM entries WHERE id = ?", (first.key_id,)).fetchone()[0]
    )
    assert hits == 2
    row = dbs.cache.read_sync(
        lambda conn: conn.execute("SELECT refetches, identical_bodies FROM change_observations").fetchone()
    )
    assert tuple(row) == (1, 1)


async def test_disk_write_failure_keeps_serving_from_memory(
    dbs: Any, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    upstream = FakeUpstream()
    service = make_service(dbs, clock, upstream)
    shared = service.store.shared
    assert shared is not None

    async def broken(*_args: Any, **_kwargs: Any) -> int:
        from roxy.storage.db import SharedStateUnavailable

        raise SharedStateUnavailable("cache", "disk I/O error")

    monkeypatch.setattr(shared.db, "write", broken)
    await call(service)
    clock.advance(2)
    again = await call(service)
    assert again.cache_state is CacheState.HIT
    assert upstream.count == 1
    status = service.disk_status()
    assert not status["OK"]
    assert status["MemoryOnly"]
    assert status["Failures"] == 1


async def test_ignored_params_share_one_entry(dbs: Any, clock: FakeClock) -> None:
    upstream = FakeUpstream()
    service = make_service(dbs, clock, upstream)
    service._rules = StaticRules(rules_snapshot(ignored_params=["t"]))
    states = []
    for n in range(6):
        clock.advance(0.5)
        states.append((await call(service, f"games.roblox.com/v1/games/9583680112/votes?t={1000 + n}")).cache_state)
    assert states == [CacheState.MISS] + [CacheState.HIT] * 5  # v1 smoke 3428-3473 after ignoring `t`
    assert upstream.count == 1


async def test_contract_with_the_real_proxy_request(dbs: Any, clock: FakeClock) -> None:
    """The cache reads `proxy/context.py: ProxyRequest` exactly as the router builds it (decoded path with its
    leading slash, forwarded headers from `scrub.py`), and a background refresh copies it with a new deadline."""
    context = pytest.importorskip("roxy.proxy.context")

    def proxy_request() -> Any:
        body = b'{"userIds":[1]}'
        return context.ProxyRequest(
            request_id="r1",
            received_ms=0,
            deadline_at=time.monotonic() + 60,
            client_ip="127.0.0.1",
            limit_key="127.0.0.1",
            method="POST",
            host="users.roblox.com",
            path="/v1/users",
            query=[],
            prettyprint=False,
            body=body,
            content_type="application/json",
            headers={"content-type": "application/json", "accept": "Application/JSON", "accept-language": "fr"},
            header_names_in_order=["content-type", "accept", "accept-language"],
            user_agent="test",
            place_id=None,
            is_browser=False,
            template="users.roblox.com/v1/users",
            target="users.roblox.com/v1/users",
        )

    upstream = FakeUpstream()
    service = make_service(dbs, clock, upstream)
    req = proxy_request()
    peek = await service.peek(req)
    assert peek.key is not None
    assert req.cache_key is peek.key
    assert peek.key.text.startswith("POST users.roblox.com/v1/users #")
    assert peek.key.vary == (
        ("accept", "application/json"),
        ("content-length", "15"),
        ("content-type", "application/json"),
    )  # Accept-Language is never forwarded, so it is not in the key either (plan 9.13)
    assert (await service.serve(req, peek)).cache_state is CacheState.MISS
    clock.advance(2)
    again = proxy_request()
    assert (await service.serve(again, await service.peek(again))).cache_state is CacheState.HIT
    assert again.fresh_cache_hit
    copy = _detached(again, 30.0)
    assert type(copy) is type(again)
    assert copy.deadline_at > again.deadline_at - 31
    assert copy.request_id == "r1"
