"""The cache's side of single-flight: answer first, store after, share big answers, keep credential answers private.

What this is
    Tests of `CacheService` (real temp SQLite files, the scripted `FakeUpstream`) for the wave 2 fix pass: the
    owner answers before its cache.db write (finding CACHE-WAIT), the writes waiting at once are bounded and their
    failures counted, an answer too big for the lease row reaches other workers through a handoff row (finding
    SF-NOSTORE), the upstream receives the single-flight lease hook and a lost lease makes the request a follower
    (plan 6.3 and 7.3), and the policy lookup in `peek` runs under one regex budget (plan 9.9). From the review
    round: followers in other workers read the owner's stored answer from cache.db when its outcome never arrives
    (finding mp-12), and a credential answer fetched under a `cache_private` row reaches nobody else (cred-4).

Why it exists
    Each behavior is a contract other packages rely on: the router never waits for a disposable cache, the
    upstream's reservation is the only hot.db write a miss needs for its lease, and the credential confinement
    (plan 6.9, C2) holds on every path an answer can take.

How it works
    Two `CacheService` objects over the same database files stand in for two workers. Slow or failing cache.db
    writes are simulated by replacing `SharedTier.write` on one service; the race between a look and a
    reservation is simulated by a fake upstream that inserts a competing lease row first.

What to read next
    `src/roxy/cache/service.py` (`_absorb`, `_finish`, `_share`, `_serve_flight`), `src/roxy/upstream/singleflight.py`,
    and `tests/multiprocess/test_review_failure_modes_mp.py` (the same findings with real processes).
"""

from __future__ import annotations

import asyncio
import itertools
import json
import time
from collections.abc import Iterator
from typing import Any

import pytest

from roxy.cache import service as service_module
from roxy.cache.keys import HANDOFF_SUFFIX
from roxy.cache.service import HANDOFF_TTL_S, CacheService, ServeResult
from roxy.cache.testing import FakeSettings, FakeUpstream, StaticRules, make_request, ok, rules_snapshot
from roxy.core.clock import FakeClock
from roxy.core.reasons import AuthClass, CacheState, Egress, ReasonCode
from roxy.rules.match import REGEX_REQUEST_BUDGET_S, regex_timeouts_total
from roxy.rules.models import CacheRuleRow
from roxy.rules.store import RulesSnapshot
from roxy.storage.db import SharedStateUnavailable, open_databases
from roxy.upstream.singleflight import LEASE_PREFIX, SHARE_BODY_MAX, FlightLease, FlightOutcome, OutcomeKind

VOTES = "games.roblox.com/v1/games/votes?universeIds=7"
BIG = b'{"data":"' + b"z" * (2 * SHARE_BODY_MAX) + b'"}'


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def second_dbs(env: Any, dbs: Any) -> Iterator[Any]:
    """The same database files through another set of connections (a second worker)."""
    other = open_databases(env)
    yield other
    other.close_all_sync()


def worker(dbs: Any, clock: FakeClock, upstream: FakeUpstream, name: str = "w1", **settings: Any) -> CacheService:
    return CacheService(
        dbs=dbs,
        settings=FakeSettings(settings),
        rules=StaticRules(rules_snapshot()),
        clock=clock,
        upstream=upstream,
        worker_id=name,
    )


async def call(service: CacheService, target: str = VOTES) -> ServeResult:
    req = make_request(target)
    return await service.serve(req, await service.peek(req))


def rows(dbs: Any) -> list[tuple[str, int]]:
    return [
        (str(r[0]), int(r[1]))
        for r in dbs.cache.read_sync(lambda conn: conn.execute("SELECT key, body_len FROM entries").fetchall())
    ]


class SlowDisk:
    """Replaces `SharedTier.write`: each write waits for `release`, then succeeds (or fails when `fail`)."""

    def __init__(self, service: CacheService, *, fail: bool = False) -> None:
        shared = service.store.shared
        assert shared is not None
        self.real = shared.write
        self.release = asyncio.Event()
        self.started = 0
        self.fail = fail
        shared.write = self.write  # type: ignore[method-assign]

    async def write(self, entry: Any, *, compress: bool, req_body: bytes | None = None) -> bool:
        self.started += 1
        await self.release.wait()
        if self.fail:
            return False
        return await self.real(entry, compress=compress, req_body=req_body)


# --- answer first, store after (finding CACHE-WAIT) ---------------------------------------------------------------


async def test_owner_answers_before_its_cache_db_write_lands(dbs: Any, second_dbs: Any, clock: FakeClock) -> None:
    upstream = FakeUpstream()
    owner = worker(dbs, clock, upstream)
    disk = SlowDisk(owner)
    result = await asyncio.wait_for(call(owner), 2)  # answered although the write is still waiting
    assert result.cache_state is CacheState.MISS
    assert result.status == 200
    assert disk.started == 1
    assert rows(dbs) == []
    clock.advance(1)
    assert (await call(owner)).cache_state is CacheState.HIT  # this worker already serves it from memory
    disk.release.set()
    await owner.settle()
    assert len(rows(dbs)) == 1
    other = worker(second_dbs, clock, FakeUpstream(), "w2")
    assert (await call(other)).cache_state is CacheState.HIT  # and every worker from cache.db
    assert upstream.count == 1


async def test_failed_cache_db_write_is_counted_and_the_answer_unaffected(dbs: Any, clock: FakeClock) -> None:
    upstream = FakeUpstream()
    owner = worker(dbs, clock, upstream)
    disk = SlowDisk(owner, fail=True)
    disk.release.set()
    result = await call(owner)
    await owner.settle()
    assert result.status == 200
    assert owner.stats.store_failures == 1
    assert rows(dbs) == []
    clock.advance(1)
    assert (await call(owner)).cache_state is CacheState.HIT


async def test_waiting_cache_db_writes_are_bounded(dbs: Any, clock: FakeClock, monkeypatch: pytest.MonkeyPatch) -> None:
    """Plan P9: at most `MAX_PENDING_WRITES` writes wait at once per worker; the rest are skipped and counted, so
    a locked cache.db cannot pile up bodies in memory. Every caller is still answered at once."""
    monkeypatch.setattr(service_module, "MAX_PENDING_WRITES", 2)
    owner = worker(dbs, clock, FakeUpstream())
    disk = SlowDisk(owner)
    results = [await call(owner, f"games.roblox.com/v1/games/votes?universeIds={n}") for n in range(5)]
    await asyncio.sleep(0.05)
    assert all(r.status == 200 for r in results)
    assert disk.started == 2
    assert owner.stats.store_skipped == 3
    disk.release.set()
    await owner.settle()
    assert len(rows(dbs)) == 2


# --- big answers reach other workers (finding SF-NOSTORE) ---------------------------------------------------------


@pytest.mark.parametrize(
    "settings", [{"cache_max_body": 1024}, {"cache_disk_enabled": 0}], ids=["over_max_body", "disk_tier_off"]
)
async def test_big_unstored_answer_reaches_another_worker_through_a_handoff_row(
    dbs: Any, second_dbs: Any, clock: FakeClock, settings: dict[str, Any]
) -> None:
    gate = asyncio.Event()
    owner_up, follower_up = FakeUpstream(lambda req, n: ok(BIG), gate=gate), FakeUpstream()
    owner = worker(dbs, clock, owner_up, "w1", **settings)
    follower = worker(second_dbs, clock, follower_up, "w2", **settings)
    first = asyncio.create_task(call(owner))
    await owner_up.started.wait()
    second = asyncio.create_task(call(follower))
    await asyncio.sleep(0.1)
    gate.set()
    mine, theirs = await asyncio.gather(first, second)
    await owner.settle()
    assert (mine.cache_state, theirs.cache_state) == (CacheState.MISS, CacheState.COALESCED)
    assert theirs.body == BIG
    assert theirs.status == 200
    assert follower_up.count == 0
    assert owner.stats.handoffs == 1
    key = (await owner.peek(make_request(VOTES))).key
    assert key is not None
    assert rows(dbs) == [(key.text + HANDOFF_SUFFIX, len(BIG))]  # only the handoff row: the answer is no entry
    assert key.handoff_id not in follower.store.memory  # read once, never promoted into the memory tier
    assert len(follower.store.memory) == 0
    clock.advance(HANDOFF_TTL_S + 1)
    report = await owner.maintain()  # also runs (dead rows only) while the disk tier is off
    assert report is not None
    assert report.dead == 1
    assert rows(dbs) == []


async def test_handoff_row_never_answers_a_lookup(dbs: Any, clock: FakeClock) -> None:
    owner = worker(dbs, clock, FakeUpstream(lambda req, n: ok(BIG)), cache_max_body=1024)
    await call(owner)
    await owner.settle()
    assert len(rows(dbs)) == 1
    owner.store.memory.clear()
    clock.advance(1)
    again = await call(owner)
    assert again.cache_state is CacheState.MISS  # a handoff row is not an entry: the next request fetches again
    assert await owner.key_spread() == []  # and it never counts as key spread evidence


# --- the lease hook in the upstream's reservation (plan 6.3, 7.3) -------------------------------------------------


class RacingUpstream(FakeUpstream):
    """Records the `lease` it receives. With `race`, another worker inserts the key's lease first (the window
    between this request's look and its reservation), so the hook loses and `SingleFlightLost` is raised."""

    def __init__(self, hot: Any, clock: FakeClock, *, race: bool = False) -> None:
        super().__init__()
        self.hot = hot
        self.clock = clock
        self.race = race
        self.leases: list[Any] = []

    async def fetch(
        self, req: Any, *, priority: Any, stale_available: bool, purpose: str = "caller", lease: Any = None
    ) -> Any:
        self.leases.append(lease)
        if self.race and isinstance(lease, FlightLease):
            name, now_ms = lease.name, self.clock.now_ms()
            self.hot.write_sync(
                lambda conn: conn.execute(
                    "INSERT INTO lease (name, holder, expires_ms, epoch, payload_json) VALUES (?, 'w9', ?, 1, ?)",
                    (name, now_ms + 30_000, json.dumps({"f": "winner"})),
                )
            )
        return await super().fetch(
            req, priority=priority, stale_available=stale_available, purpose=purpose, lease=lease
        )


async def test_upstream_receives_the_lease_hook(dbs: Any, clock: FakeClock) -> None:
    upstream = RacingUpstream(dbs.hot, clock)
    owner = worker(dbs, clock, upstream)
    await call(owner)
    await owner.settle()
    assert len(upstream.leases) == 1
    assert isinstance(upstream.leases[0], FlightLease)
    holder = dbs.hot.read_sync(
        lambda conn: conn.execute("SELECT holder FROM lease WHERE name LIKE ?", (LEASE_PREFIX + "%",)).fetchone()
    )
    assert holder is not None
    assert holder[0] == "w1"


async def test_lost_lease_makes_the_request_a_follower_without_a_call(dbs: Any, clock: FakeClock) -> None:
    upstream = RacingUpstream(dbs.hot, clock, race=True)
    service = worker(dbs, clock, upstream)
    task = asyncio.create_task(call(service))
    await asyncio.sleep(0.2)
    assert upstream.leases_lost == 1
    assert upstream.count == 0  # nothing was "sent": the lease was lost inside the reservation
    outcome = FlightOutcome(
        OutcomeKind.SHARED, status=200, reason=ReasonCode.UPSTREAM_OK.value, body=b'{"winner":true}'
    )
    published = json.dumps({"f": "winner", "o": outcome.to_doc()})
    dbs.hot.write_sync(
        lambda conn: conn.execute(
            "UPDATE lease SET payload_json = ?, expires_ms = ? WHERE holder = 'w9'",
            (published, clock.now_ms() + 1000),
        )
    )
    result = await asyncio.wait_for(task, 5)
    assert result.cache_state is CacheState.COALESCED
    assert result.body == b'{"winner":true}'
    assert upstream.count == 0


# --- one regex budget for the policy lookup in peek (plan 9.9) ------------------------------------------------------


async def test_peek_policy_lookup_runs_under_one_regex_budget(dbs: Any, clock: FakeClock) -> None:
    """Stored slow cache rules (as the migrator imports v1 patterns, unjudged) cost at most the request budget in
    `peek`, which runs before the abuse verdict, not one per-match timeout each."""
    slow = r"x+x+x+y"
    rules = tuple(CacheRuleRow(id=i, pattern=slow + "(?:q)?" * i, type="regex", ttl=60) for i in range(1, 17))
    service = CacheService(
        dbs=dbs,
        settings=FakeSettings(),
        rules=StaticRules(RulesSnapshot(version=1, loaded_at=0.0, cache_rules=rules)),
        clock=clock,
        upstream=FakeUpstream(),
        worker_id="w1",
    )
    req = make_request("games.roblox.com/" + "x" * 4000)
    before = regex_timeouts_total()
    started = time.perf_counter()
    peek = await service.peek(req)
    elapsed = time.perf_counter() - started
    assert regex_timeouts_total() > before
    assert peek.key is not None  # a rule cut off by the budget is "no rule": the default policy applies
    assert elapsed < REGEX_REQUEST_BUDGET_S + 0.25, f"peek took {elapsed * 1000:.0f} ms"


# --- followers read cache.db when the owner's outcome is late (plan 6.9 step 4, finding mp-12) ------------------


def never_publishes(service: CacheService, monkeypatch: pytest.MonkeyPatch) -> None:
    """hot.db refuses every outcome publish of this worker (busy), as when it stays locked until the worker stops."""

    async def busy(*_args: Any) -> None:
        raise SharedStateUnavailable("hot", "database is locked")

    monkeypatch.setattr(service.flights, "_publish_once", busy)


async def wait_for_rows(dbs: Any, count: int) -> None:
    for _ in range(200):
        if len(rows(dbs)) >= count:
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"cache.db never held {count} rows")


async def test_follower_serves_the_owners_stored_entry_when_its_outcome_never_arrives(
    dbs: Any, second_dbs: Any, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = asyncio.Event()
    owner_up, follower_up = FakeUpstream(gate=gate), FakeUpstream()
    owner = worker(dbs, clock, owner_up, "w1")
    follower = worker(second_dbs, clock, follower_up, "w2")
    never_publishes(owner, monkeypatch)
    first = asyncio.create_task(call(owner))
    await owner_up.started.wait()
    second = asyncio.create_task(call(follower))
    await asyncio.sleep(0.1)
    gate.set()
    mine = await first
    await wait_for_rows(dbs, 1)  # the owner's tail stored the entry; its publish keeps failing
    theirs = await asyncio.wait_for(second, 3)  # long before the follower's own wait (the owner deadline) ends
    assert (mine.cache_state, theirs.cache_state) == (CacheState.MISS, CacheState.COALESCED)
    assert theirs.body == mine.body
    assert follower_up.count == 0
    assert follower.flights.stats.store_answers == 1
    await owner.flights.close(grace_s=0.1)


async def test_follower_never_takes_an_older_entry_from_cache_db_for_a_fresh_copy_request(
    dbs: Any, second_dbs: Any, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A caller that sent `Cache-Control: no-cache` (honored) follows a flight that fetches a fresh copy. The
    entry already in cache.db is older than its request, so looking there never answers it with that entry."""
    settings = {"cache_respect_no_cache": 1, "cache_coalesce_wait_ms": 1500}
    gate = asyncio.Event()
    owner_up, follower_up = FakeUpstream(), FakeUpstream()
    owner = worker(dbs, clock, owner_up, "w1", **settings)
    follower = worker(second_dbs, clock, follower_up, "w2", **settings)
    old = await call(owner)
    await owner.settle()
    clock.advance(30)  # still fresh (lifetime 120 s), but stored well before the next requests
    never_publishes(owner, monkeypatch)
    owner_up.gate = gate
    fresh_copy = {"Cache-Control": "no-cache"}
    first = asyncio.create_task(owner.serve(make_request(VOTES, headers=fresh_copy)))
    await asyncio.sleep(0.1)
    assert owner_up.count == 2  # the owner fetches a fresh copy and holds the lease
    req = make_request(VOTES, headers=fresh_copy)
    theirs = await follower.serve(req, await follower.peek(req))
    assert theirs.reason is ReasonCode.COALESCE_TIMEOUT  # the old entry was there all along, and refused
    assert theirs.body != old.body
    assert follower_up.count == 0
    assert follower.flights.stats.store_answers == 0
    gate.set()
    await first
    await owner.flights.close(grace_s=0.1)


# --- credential answers fetched under a cache_private row stay private (finding cred-4) --------------------------


CURRENCY = "economy.roblox.com/v1/user/currency"


@pytest.mark.parametrize("how", ["upstream_says_private", "row_flipped_before_the_answer"])
async def test_answer_fetched_under_a_private_row_is_never_coalesced(
    dbs: Any, second_dbs: Any, clock: FakeClock, how: str
) -> None:
    """The request peeked a shared allowlist row (a credential key that may coalesce), but the answer came back
    private: the upstream fetched it under a `cache_private` row (`UpstreamResult.private`), or the row is private
    by the time the answer arrives. Nobody else gets it: not a follower in this worker, not one in another, not
    the store. Each request makes its own credential call."""
    rules = StaticRules(rules_snapshot(credential_allowlist=[{"pattern": CURRENCY, "cache_private": 0}]))
    private_rules = rules_snapshot(credential_allowlist=[{"pattern": CURRENCY, "cache_private": 1}], version=2)
    flag = how == "upstream_says_private"
    numbers = itertools.count(1)  # one numbering across both workers' upstreams

    def answer(req: Any, n: int) -> Any:
        body = f'{{"robux":"secret {next(numbers)}"}}'
        return ok(body, auth_class=AuthClass.CRED, egress=Egress.CREDENTIAL, private=flag)

    gate = asyncio.Event()
    owner_up, other_up = FakeUpstream(answer, gate=gate), FakeUpstream(answer)

    def cred_worker(db: Any, upstream: FakeUpstream, name: str) -> CacheService:
        return CacheService(
            dbs=db, settings=FakeSettings(), rules=rules, clock=clock, upstream=upstream, worker_id=name
        )

    owner, other = cred_worker(dbs, owner_up, "w1"), cred_worker(second_dbs, other_up, "w2")
    first = asyncio.create_task(call(owner, CURRENCY))
    await owner_up.started.wait()
    local = asyncio.create_task(call(owner, CURRENCY))
    remote = asyncio.create_task(call(other, CURRENCY))
    await asyncio.sleep(0.1)
    if not flag:
        rules.snapshot = private_rules  # an admin marks the endpoint private while the flight runs
    gate.set()
    results = await asyncio.wait_for(asyncio.gather(first, local, remote), 5)
    await owner.settle()
    await other.settle()
    assert [r.cache_state for r in results] == [CacheState.MISS] * 3
    assert len({r.body for r in results}) == 3  # three answers, each its own request's
    assert owner_up.count + other_up.count == 3
    assert owner.stats.private + other.stats.private == 3
    assert rows(dbs) == []  # never stored
