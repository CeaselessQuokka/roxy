"""A credential answer is never served to an anonymous request: probes for plan 6.9 and 19.5 item 10.

What this is
    Probes against `CacheService` (real temp SQLite files, a scripted upstream) for the case the defenses exist
    for: the upstream used the credential (`auth_class=cred`) for a request whose cache key is anonymous. That
    happens when the rules snapshot moves between the cache's `peek` (no allowlist row yet) and the upstream's
    routing (row present), or when an allowlist regex hits its time limit in one evaluation and not the other.
    Each probe checks one way the answer could reach anonymous requests: stored as an entry (later hits, stale
    and stale-while-revalidate serves), shared with followers in another worker, shared with followers in the
    same worker. The last one fails today (finding F2, strict xfail).

Why it exists
    `store_decision` refuses to store such an answer and `_outcome_for` publishes `nostore` to other workers, but
    followers in the owner's own process read the owner's result object directly (`_serve_flight`, the
    `value.result` branch) and are served it as `COALESCED`, so the cross-auth-class rule has a gap.

How it works
    `FakeUpstream` from `roxy.cache.testing` answers with a credential-class result after a gate opens; the
    requests are built with `make_request`, so their keys are anonymous (empty allowlist). Two `CacheService`
    objects over the same databases stand in for two workers.

What to read next
    `src/roxy/cache/service.py` (`_serve_flight`, `_outcome_for`), `src/roxy/cache/policy.py` (`store_decision`),
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


@pytest.mark.xfail(
    strict=True,
    reason=(
        "F2: a follower in the owner's own worker is served the owner's credential-class result under an "
        "anonymous key (cache/service.py _serve_flight, value.result branch skips the auth class check that "
        "_outcome_for applies across workers)"
    ),
)
async def test_follower_in_the_same_worker_never_gets_a_credential_answer(dbs: Any, clock: FakeClock) -> None:
    """Same race, both requests in one worker: the follower must not receive the credential answer."""
    gate = asyncio.Event()
    upstream = FakeUpstream(cred_answer, gate=gate)
    service = make_service(dbs, clock, upstream)
    owner_task = asyncio.create_task(call(service))
    await upstream.started.wait()
    follower_task = asyncio.create_task(call(service))
    await asyncio.sleep(0.05)  # the follower joined the in-process flight
    gate.set()
    owner, follower = await asyncio.gather(owner_task, follower_task)
    assert owner.body == SECRET_BODY
    assert (follower.cache_state, follower.body) != (CacheState.COALESCED, SECRET_BODY)
    assert follower.body != SECRET_BODY
