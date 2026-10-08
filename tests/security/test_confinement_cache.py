"""A credential answer is never served to an anonymous request: probes for plan 6.9 and 19.5 item 10.

What this is
    Probes against `CacheService` (real temp SQLite files, a scripted upstream) for the case the defenses exist
    for: the upstream used the credential (`auth_class=cred`) for a request whose cache key is anonymous. That
    happens when the rules snapshot moves between the cache's `peek` (no allowlist row yet) and the upstream's
    routing (row present), or when an allowlist regex hits its time limit in one evaluation and not the other.
    Each probe checks one way the answer could reach anonymous requests: stored as an entry (later hits, stale
    and stale-while-revalidate serves), shared with followers in another worker, shared with followers in the
    same worker (finding F2, fixed), and a run of requests that all keep reaching the credential.

Why it exists
    Plan 6.9 and C2: a credential answer belongs to its own request. Before the F2 fix, followers in the owner's
    own process read the owner's result object directly (`_serve_flight`, the `value.result` branch) and were
    served it as `COALESCED`. Now the owner publishes `private` (`CacheService._absorb`): no store, and every
    follower, in this worker or another, competes again and makes its own call.

How it works
    `FakeUpstream` from `roxy.cache.testing` answers with a credential-class result after a gate opens; the
    requests are built with `make_request`, so their keys are anonymous (empty allowlist). Two `CacheService`
    objects over the same databases stand in for two workers.

What to read next
    `src/roxy/cache/service.py` (`_absorb`, `_serve_flight`), `src/roxy/cache/policy.py` (`store_decision`),
    `src/roxy/upstream/singleflight.py`, and `tests/integration/test_pipeline_e2e.py`
    (`test_cred_response_never_served_to_other_auth_class`).
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from roxy.cache.service import CacheService, ServeResult
from roxy.cache.testing import FakeSettings, FakeUpstream, StaticRules, make_request, ok, rules_snapshot
from roxy.core.clock import FakeClock
from roxy.core.reasons import AuthClass, CacheState, Egress
from roxy.storage.db import open_databases

TARGET = "economy.roblox.com/v1/user/currency"
SECRET_BODY = b'{"robux":"owner account"}'


def cred_answer(req: Any, number: int) -> Any:
    """What the upstream returns once it has routed the request to the credential (rules moved meanwhile)."""
    return ok(SECRET_BODY, auth_class=AuthClass.CRED, egress=Egress.CREDENTIAL)


def make_service(dbs: Any, clock: FakeClock, upstream: FakeUpstream, worker: str = "w1") -> CacheService:
    return CacheService(
        dbs=dbs,
        settings=FakeSettings(),
        rules=StaticRules(rules_snapshot()),  # empty allowlist: every key here is anonymous
        clock=clock,
        upstream=upstream,
        worker_id=worker,
    )


async def call(service: CacheService, target: str = TARGET) -> ServeResult:
    req = make_request(target)
    peek = await service.peek(req)
    assert peek.key is not None
    assert peek.key.auth_class is AuthClass.ANON
    return await service.serve(req, peek)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


async def test_credential_answer_is_never_stored_under_an_anonymous_key(dbs: Any, clock: FakeClock) -> None:
    """Not stored, so no later HIT, STALE or REVALIDATING serve can hand it out; the next request fetches again."""
    upstream = FakeUpstream(cred_answer)
    service = make_service(dbs, clock, upstream)
    first = await call(service)
    assert first.body == SECRET_BODY  # the request the upstream itself routed to the credential gets its answer
    for advance in (1, 330, 900):  # fresh, inside the SWR window, inside the stale window
        clock.advance(advance)
        again = await call(service)
        assert again.cache_state not in (CacheState.HIT, CacheState.REVALIDATING, CacheState.STALE)
    assert upstream.count == 4
    rows = dbs.cache.read_sync(lambda conn: conn.execute("SELECT count(*) FROM entries").fetchone()[0])
    assert rows == 0


async def test_follower_in_another_worker_never_gets_a_credential_answer(dbs: Any, clock: FakeClock, env: Any) -> None:
    """Cross-worker coalescing publishes `nostore` for a credential answer: the follower fetches for itself."""
    gate = asyncio.Event()
    owner_upstream = FakeUpstream(cred_answer, gate=gate)
    follower_upstream = FakeUpstream(lambda req, n: ok(b'{"robux":"anonymous"}'))
    other_dbs = open_databases(env)
    try:
        owner = make_service(dbs, clock, owner_upstream, worker="w1")
        follower = make_service(other_dbs, clock, follower_upstream, worker="w2")
        owner_task = asyncio.create_task(call(owner))
        await owner_upstream.started.wait()
        follower_task = asyncio.create_task(call(follower))
        await asyncio.sleep(0.1)  # the follower is polling the owner's lease
        gate.set()
        _, followed = await asyncio.gather(owner_task, follower_task)
        assert followed.body == b'{"robux":"anonymous"}'
        assert follower_upstream.count == 1  # it competed again and fetched for itself (`nostore`), never shared
    finally:
        other_dbs.close_all_sync()


async def test_follower_in_the_same_worker_never_gets_a_credential_answer(dbs: Any, clock: FakeClock) -> None:
    """Finding F2, same race with both requests in one worker: the follower joined the owner's in-process flight
    before the answer came back with the credential. It must not receive that answer; it competes again and makes
    its own call (here the rules have settled and its call is anonymous), and nothing is stored."""
    gate = asyncio.Event()

    def first_call_routed_to_the_credential(req: Any, number: int) -> Any:
        return cred_answer(req, number) if number == 1 else ok(b'{"robux":"anonymous"}')

    upstream = FakeUpstream(first_call_routed_to_the_credential, gate=gate)
    service = make_service(dbs, clock, upstream)
    owner_task = asyncio.create_task(call(service))
    await upstream.started.wait()
    follower_task = asyncio.create_task(call(service))
    await asyncio.sleep(0.05)  # the follower joined the in-process flight
    assert service.flights.inflight() == 1
    gate.set()
    owner, follower = await asyncio.gather(owner_task, follower_task)
    await service.settle()
    assert owner.body == SECRET_BODY  # the request the upstream itself routed to the credential gets its answer
    assert follower.body == b'{"robux":"anonymous"}'
    assert follower.cache_state is CacheState.MISS  # its own fetch, never COALESCED from the credential answer
    assert upstream.count == 2
    assert service.stats.private == 1
    rows = dbs.cache.read_sync(lambda conn: conn.execute("SELECT body_len FROM entries").fetchall())
    assert [row[0] for row in rows] == [len(b'{"robux":"anonymous"}')]  # only the anonymous answer was stored


async def test_every_same_worker_request_makes_its_own_credential_call(dbs: Any, clock: FakeClock) -> None:
    """While the upstream keeps routing an anonymous key to the credential, the answer is treated like a
    `cache_private` one (plan 6.9): each request that waited on the flight makes its own call, and none of them is
    ever served another request's answer (no COALESCED, no HIT, nothing stored)."""
    gate = asyncio.Event()
    upstream = FakeUpstream(
        lambda req, n: ok(f'{{"robux":"call {n}"}}', auth_class=AuthClass.CRED, egress=Egress.CREDENTIAL), gate=gate
    )
    service = make_service(dbs, clock, upstream)
    first = asyncio.create_task(call(service))
    await upstream.started.wait()
    others = [asyncio.create_task(call(service)) for _ in range(3)]
    await asyncio.sleep(0.05)
    gate.set()
    results = await asyncio.gather(first, *others)
    await service.settle()
    assert upstream.count == 4
    assert sorted(r.body for r in results) == [f'{{"robux":"call {n}"}}'.encode() for n in range(1, 5)]
    assert all(r.cache_state is CacheState.MISS for r in results)
    assert dbs.cache.read_sync(lambda conn: conn.execute("SELECT count(*) FROM entries").fetchone()[0]) == 0
