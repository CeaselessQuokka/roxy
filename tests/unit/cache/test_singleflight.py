"""Fleet single-flight (plan 6.9, fix F1) within one process, with real hot.db leases.

A second `SingleFlight` with its own `Database` objects (own threads, own connections) and holder stands in for
another worker; the real multi-process tests live in tests/multiprocess/test_singleflight_mp.py. Claim mode (the
lease in its own transaction) and hooked mode (the lease hook run inside the caller's transaction, as the upstream
reservation does) are both covered, plus the owner's tail: answering before the outcome is finished and published,
publish retries, and taking over this worker's own finished but unpublished flight.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from roxy.core.clock import FakeClock, SystemClock
from roxy.storage.db import Database, SharedStateUnavailable
from roxy.upstream.singleflight import (
    LEASE_PREFIX,
    Deferred,
    FlightOutcome,
    FlightStart,
    LeaseLost,
    OutcomeKind,
    Role,
    SingleFlight,
)


def _shared(status: int = 200, body: bytes = b"ok", reason: str = "upstream_ok", **fields: Any) -> FlightOutcome:
    return FlightOutcome(OutcomeKind.SHARED, status=status, body=body, reason=reason, **fields)


class Counter:
    """A fetch function that counts calls and can be held open with a gate."""

    def __init__(self, outcome: FlightOutcome | None = None, *, gate: asyncio.Event | None = None) -> None:
        self.calls = 0
        self.starts: list[FlightStart] = []
        self.outcome = outcome or _shared()
        self.gate = gate
        self.entered = asyncio.Event()

    async def __call__(self, start: FlightStart) -> tuple[str, FlightOutcome]:
        self.calls += 1
        self.starts.append(start)
        self.entered.set()
        if self.gate is not None:
            await self.gate.wait()
        return f"value-{self.calls}", self.outcome


@pytest.fixture
def hot(dbs: Any) -> Database:
    return dbs.hot


@pytest.fixture
def other_hot(dbs: Any) -> Any:
    """hot.db through a second Database object: another worker's connections."""
    db = Database("hot", dbs.hot.path)
    yield db
    db.close_sync()


def _flight(db: Database | None, holder: str, clock: Any = None) -> SingleFlight:
    return SingleFlight(db, clock or SystemClock(), holder, poll_start_s=0.01, poll_max_s=0.05)


async def test_same_process_followers_share_one_fetch(hot: Database) -> None:
    flights = _flight(hot, "w1")
    gate = asyncio.Event()
    fetch = Counter(gate=gate)
    runs = [asyncio.create_task(flights.run("k", fetch, owner_deadline_s=10, wait_s=10)) for _ in range(20)]
    await fetch.entered.wait()
    gate.set()
    results = await asyncio.gather(*runs)
    assert fetch.calls == 1
    roles = sorted(r.role for r in results)
    assert roles.count(Role.OWNER) == 1
    assert roles.count(Role.FOLLOWER) == 19
    assert all(r.value == "value-1" for r in results)  # same-process followers see the owner's value
    assert flights.inflight() <= 1  # answered; may stay joinable while its outcome is published (the tail)
    await flights.settle()
    assert flights.inflight() == 0
    assert flights.tails() == 0


async def test_followers_in_another_worker_get_the_outcome_not_a_call(hot: Database, other_hot: Database) -> None:
    owner_side, follower_side = _flight(hot, "w1"), _flight(other_hot, "w2")
    gate = asyncio.Event()
    owner_fetch, follower_fetch = Counter(_shared(body=b"shared"), gate=gate), Counter()
    owner = asyncio.create_task(owner_side.run("k", owner_fetch, owner_deadline_s=10, wait_s=10))
    await owner_fetch.entered.wait()
    followers = [
        asyncio.create_task(follower_side.run("k", follower_fetch, owner_deadline_s=10, wait_s=10)) for _ in range(5)
    ]
    await asyncio.sleep(0.1)
    gate.set()
    results = await asyncio.gather(owner, *followers)
    assert owner_fetch.calls == 1
    assert follower_fetch.calls == 0
    assert results[0].role is Role.OWNER
    for result in results[1:]:
        assert result.role is Role.FOLLOWER
        assert result.value is None
        assert result.outcome is not None
        assert result.outcome.body == b"shared"


async def test_owner_failure_is_shared_followers_never_go_upstream(hot: Database, other_hot: Database) -> None:
    owner_side, follower_side = _flight(hot, "w1"), _flight(other_hot, "w2")
    gate = asyncio.Event()
    failed = _shared(status=503, body=b"failed", reason="upstream_5xx", retry_after_s=5)
    owner_fetch, follower_fetch = Counter(failed, gate=gate), Counter()
    owner = asyncio.create_task(owner_side.run("k", owner_fetch, owner_deadline_s=10, wait_s=10))
    await owner_fetch.entered.wait()
    followers = [
        asyncio.create_task(follower_side.run("k", follower_fetch, owner_deadline_s=10, wait_s=10)) for _ in range(5)
    ]
    await asyncio.sleep(0.05)
    gate.set()
    results = await asyncio.gather(owner, *followers)
    assert owner_fetch.calls + follower_fetch.calls == 1
    assert all(r.outcome is not None and r.outcome.status == 503 and r.outcome.retry_after_s == 5 for r in results)


async def test_crashed_owner_is_taken_over_by_exactly_one_follower(dbs: Any, hot: Database) -> None:
    clock = FakeClock()
    now_ms = clock.now_ms()
    # A dead worker holds the lease (no outcome, expires in 2 s).
    hot.write_sync(
        lambda conn: conn.execute(
            "INSERT INTO lease (name, holder, expires_ms, epoch, payload_json) VALUES (?, 'dead', ?, 1, ?)",
            (LEASE_PREFIX + "k", now_ms + 2000, json.dumps({"f": "deadbeef"})),
        )
    )
    workers = [Database("hot", hot.path) for _ in range(3)]
    try:
        sides = [_flight(db, f"w{i}", clock) for i, db in enumerate(workers)]
        fetches = [Counter() for _ in sides]
        runs = [
            asyncio.create_task(side.run("k", f, owner_deadline_s=10, wait_s=10))
            for side, f in zip(sides, fetches, strict=True)
        ]
        await asyncio.sleep(0.2)
        assert sum(f.calls for f in fetches) == 0  # everyone waits for the (dead) owner
        clock.advance(3.0)  # the lease expires (plus the takeover margin)
        results = await asyncio.gather(*runs)
        assert sum(f.calls for f in fetches) == 1  # exactly one takes over, never all
        taker = next(f for f in fetches if f.calls)
        assert taker.starts[0].takeover is True
        assert sorted(r.role for r in results).count(Role.OWNER) == 1
    finally:
        for db in workers:
            db.close_sync()


async def test_follower_timeout_reports_the_owner_deadline(hot: Database, other_hot: Database) -> None:
    owner_side, follower_side = _flight(hot, "w1"), _flight(other_hot, "w2")
    gate = asyncio.Event()
    owner_fetch = Counter(gate=gate)
    owner = asyncio.create_task(owner_side.run("k", owner_fetch, owner_deadline_s=30, wait_s=30))
    await owner_fetch.entered.wait()
    result = await follower_side.run("k", Counter(), owner_deadline_s=30, wait_s=0.2)
    assert result.role is Role.TIMEOUT
    assert result.retry_after_s is not None
    assert 28 <= result.retry_after_s <= 30
    gate.set()
    await owner


async def test_lingering_outcome_answers_a_late_arrival_then_expires(hot: Database) -> None:
    clock = FakeClock()
    side = _flight(hot, "w1", clock)
    first = await side.run("k", Counter(_shared(status=503, reason="upstream_5xx")), owner_deadline_s=10, wait_s=5)
    assert first.role is Role.OWNER
    late = Counter()
    memo = await side.run("k", late, owner_deadline_s=10, wait_s=5)
    assert late.calls == 0
    assert memo.role is Role.FOLLOWER
    clock.advance(1.5)
    fresh = await side.run("k", late, owner_deadline_s=10, wait_s=5)
    assert late.calls == 1
    assert fresh.role is Role.OWNER


async def test_unshareable_outcome_makes_followers_compete_again(hot: Database, other_hot: Database) -> None:
    owner_side, follower_side = _flight(hot, "w1"), _flight(other_hot, "w2")
    gate = asyncio.Event()
    owner_fetch = Counter(FlightOutcome(OutcomeKind.NOSTORE, status=200), gate=gate)
    follower_fetch = Counter()
    owner = asyncio.create_task(owner_side.run("k", owner_fetch, owner_deadline_s=10, wait_s=10))
    await owner_fetch.entered.wait()
    follower = asyncio.create_task(follower_side.run("k", follower_fetch, owner_deadline_s=10, wait_s=10))
    await asyncio.sleep(0.05)
    gate.set()
    owner_result, follower_result = await asyncio.gather(owner, follower)
    assert owner_result.role is Role.OWNER
    assert owner_result.value == "value-1"
    assert follower_fetch.calls == 1
    assert follower_result.role is Role.OWNER
    assert follower_fetch.starts[0].takeover


async def test_fetch_exception_reaches_local_waiters_and_releases_followers(hot: Database, other_hot: Database) -> None:
    owner_side, follower_side = _flight(hot, "w1"), _flight(other_hot, "w2")
    gate = asyncio.Event()

    async def broken(start: FlightStart) -> tuple[str, FlightOutcome]:
        await gate.wait()
        raise RuntimeError("bug")

    owner = asyncio.create_task(owner_side.run("k", broken, owner_deadline_s=10, wait_s=10))
    local = asyncio.create_task(owner_side.run("k", broken, owner_deadline_s=10, wait_s=10))
    await asyncio.sleep(0.05)
    remote_fetch = Counter()
    remote = asyncio.create_task(follower_side.run("k", remote_fetch, owner_deadline_s=10, wait_s=10))
    await asyncio.sleep(0.05)
    gate.set()
    for task in (owner, local):
        with pytest.raises(RuntimeError, match="bug"):
            await task
    result = await remote
    assert remote_fetch.calls == 1
    assert result.role is Role.OWNER


async def test_disabled_coalescing_fetches_every_time(hot: Database) -> None:
    side = _flight(hot, "w1")
    fetch = Counter()
    results = await asyncio.gather(
        *(side.run("k", fetch, owner_deadline_s=5, wait_s=5, enabled=False) for _ in range(3))
    )
    assert fetch.calls == 3
    assert all(r.role is Role.SOLO for r in results)


async def test_hot_db_unavailable_degrades_to_local_coalescing(hot: Database, monkeypatch: pytest.MonkeyPatch) -> None:
    side = _flight(hot, "w1")

    async def unavailable(*_args: Any, **_kwargs: Any) -> Any:
        raise SharedStateUnavailable("hot", "database is locked")

    monkeypatch.setattr(hot, "write", unavailable)
    gate = asyncio.Event()
    fetch = Counter(gate=gate)
    runs = [asyncio.create_task(side.run("k", fetch, owner_deadline_s=5, wait_s=5)) for _ in range(4)]
    await fetch.entered.wait()
    gate.set()
    results = await asyncio.gather(*runs)
    assert fetch.calls == 1
    assert all(r.degraded for r in results)


async def test_try_lead_skips_when_another_worker_is_fetching(hot: Database, other_hot: Database) -> None:
    owner_side, refresher_side = _flight(hot, "w1"), _flight(other_hot, "w2")
    gate = asyncio.Event()
    owner_fetch = Counter(gate=gate)
    owner = asyncio.create_task(owner_side.run("k", owner_fetch, owner_deadline_s=10, wait_s=10))
    await owner_fetch.entered.wait()
    refresh = Counter()
    assert await refresher_side.try_lead("k", refresh, owner_deadline_s=10) is None
    assert refresh.calls == 0
    gate.set()
    await owner
    led = await refresher_side.try_lead("other", refresh, owner_deadline_s=10)
    assert led is not None
    assert led.role is Role.OWNER
    assert refresh.calls == 1


def test_outcome_round_trip_and_malformed_documents() -> None:
    outcome = FlightOutcome(
        OutcomeKind.SHARED,
        status=429,
        reason="upstream_cooldown",
        body=b"\x00\xffbusy",
        content_type="text/plain",
        upstream_status=429,
        retry_after_s=30,
        cooldown_s=30,
    )
    assert FlightOutcome.from_doc(json.loads(json.dumps(outcome.to_doc()))) == outcome
    stored = FlightOutcome(OutcomeKind.STORED, entry_id="a" * 24, stored_at=5)
    assert FlightOutcome.from_doc(stored.to_doc()) == stored
    for junk in (None, [], {"k": "nope"}, {"k": 3}, {"k": "shared", "b": "%%%"}):
        assert FlightOutcome.from_doc(junk) is None


# --- hooked mode: the lease rides in the caller's own transaction (plan 6.3, 7.3) --------------------------------


class Hooked(Counter):
    """A fetch that behaves like `UpstreamService.fetch(lease=...)`: it runs the lease hook inside ITS OWN hot.db
    write transaction (the bucket reservation) before doing anything else, and raises `LeaseLost` when the hook
    says another flight holds the lease (the upstream raises `SingleFlightLost` there)."""

    def __init__(
        self,
        db: Database,
        clock: Any,
        outcome: FlightOutcome | Deferred | None = None,
        *,
        gate: asyncio.Event | None = None,
        before_hook: Callable[[], Awaitable[None]] | None = None,
    ) -> None:
        super().__init__(gate=gate)
        self.db = db
        self.clock = clock
        self.result: FlightOutcome | Deferred = outcome or _shared()
        self.before_hook = before_hook
        self.hook_calls = 0
        self.lost = 0

    async def __call__(self, start: FlightStart) -> tuple[str, Any]:
        if start.lease is not None:
            if self.before_hook is not None:
                await self.before_hook()
            hook, now_ms = start.lease, self.clock.now_ms()
            self.hook_calls += 1
            if not await self.db.write(lambda conn: hook(conn, now_ms)):
                self.lost += 1
                raise LeaseLost("another flight holds the lease")
        self.calls += 1
        self.starts.append(start)
        self.entered.set()
        if self.gate is not None:
            await self.gate.wait()
        return f"value-{self.calls}", self.result


class CountingDb:
    """Counts the write transactions SingleFlight itself makes on hot.db (reads pass through)."""

    def __init__(self, db: Database) -> None:
        self._db = db
        self.writes = 0

    async def write(self, fn: Any, **kwargs: Any) -> Any:
        self.writes += 1
        return await self._db.write(fn, **kwargs)

    async def read(self, fn: Any) -> Any:
        return await self._db.read(fn)


def lease_row(db: Database, key: str = "k") -> tuple[str, int, str | None] | None:
    row = db.read_sync(
        lambda conn: conn.execute(
            "SELECT holder, expires_ms, payload_json FROM lease WHERE name = ?", (LEASE_PREFIX + key,)
        ).fetchone()
    )
    return None if row is None else (str(row[0]), int(row[1]), row[2])


async def test_hooked_lease_is_inserted_by_the_callers_transaction(hot: Database, other_hot: Database) -> None:
    """The owner's lease insert happens in the fetch's own transaction: SingleFlight adds only the publish write
    (claim mode needs a separate claim transaction first). Followers elsewhere never fetch."""
    counted = CountingDb(hot)
    owner_side = SingleFlight(counted, SystemClock(), "w1", poll_start_s=0.01, poll_max_s=0.05)  # type: ignore[arg-type]
    follower_side = _flight(other_hot, "w2")
    gate = asyncio.Event()
    owner_fetch = Hooked(hot, SystemClock(), _shared(body=b"the one"), gate=gate)
    follower_fetch = Hooked(other_hot, SystemClock())
    owner = asyncio.create_task(owner_side.run("k", owner_fetch, owner_deadline_s=10, wait_s=10, hooked=True))
    await owner_fetch.entered.wait()
    row = lease_row(hot)
    assert row is not None
    assert row[0] == "w1"  # inserted by the hook inside the fetch's transaction
    assert counted.writes == 0  # SingleFlight made no claim transaction of its own
    followers = [
        asyncio.create_task(follower_side.run("k", follower_fetch, owner_deadline_s=10, wait_s=10, hooked=True))
        for _ in range(3)
    ]
    await asyncio.sleep(0.05)
    gate.set()
    results = await asyncio.gather(owner, *followers)
    await owner_side.settle()
    assert owner_fetch.calls == 1
    assert follower_fetch.calls == 0
    assert follower_fetch.hook_calls == 0  # the look saw the live lease: no reservation was even attempted
    assert counted.writes == 1  # the publish
    assert [r.role for r in results] == [Role.OWNER] + [Role.FOLLOWER] * 3
    assert all(r.outcome is not None and r.outcome.body == b"the one" for r in results[1:])


async def test_hooked_lost_lease_follows_the_winner_and_fetches_nothing(hot: Database, other_hot: Database) -> None:
    """The race the hook exists for: our look saw no flight, but another worker inserted its lease before our
    reservation ran. The hook refuses, the fetch raises `LeaseLost`, and this call follows the winner."""
    side = _flight(other_hot, "w2")
    winner_payload = json.dumps({"f": "winner"})

    async def winner_inserts_first() -> None:
        now_ms = SystemClock().now_ms()
        await hot.write(
            lambda conn: conn.execute(
                "INSERT INTO lease (name, holder, expires_ms, epoch, payload_json) VALUES (?, 'w1', ?, 1, ?)",
                (LEASE_PREFIX + "k", now_ms + 10_000, winner_payload),
            )
        )

    fetch = Hooked(other_hot, SystemClock(), before_hook=winner_inserts_first)
    run = asyncio.create_task(side.run("k", fetch, owner_deadline_s=10, wait_s=10, hooked=True))
    await asyncio.sleep(0.1)
    assert fetch.lost == 1
    assert fetch.calls == 0
    published = json.dumps({"f": "winner", "o": _shared(body=b"from the winner").to_doc()})
    now_ms = SystemClock().now_ms()
    await hot.write(
        lambda conn: conn.execute(
            "UPDATE lease SET payload_json = ?, expires_ms = ? WHERE name = ?",
            (published, now_ms + 1000, LEASE_PREFIX + "k"),
        )
    )
    result = await run
    assert result.role is Role.FOLLOWER
    assert result.outcome is not None
    assert result.outcome.body == b"from the winner"
    assert fetch.calls == 0
    assert side.stats.leases_lost == 1


async def test_owner_is_answered_before_its_deferred_outcome_is_finished(hot: Database, other_hot: Database) -> None:
    """Findings CACHE-WAIT and SF-ORPHAN: the owner's caller gets its value as soon as the fetch returns; the
    deferred part (the cache.db store) and the publish run afterwards, and only other workers wait for them."""
    owner_side, follower_side = _flight(hot, "w1"), _flight(other_hot, "w2")
    stored = asyncio.Event()

    async def finish() -> FlightOutcome:
        await stored.wait()  # a slow cache.db write
        return FlightOutcome(OutcomeKind.STORED, status=200, entry_id="e" * 24, stored_at=1)

    gate = asyncio.Event()
    owner_fetch = Hooked(hot, SystemClock(), Deferred(finish), gate=gate)
    owner = asyncio.create_task(owner_side.run("k", owner_fetch, owner_deadline_s=10, wait_s=10, hooked=True))
    await owner_fetch.entered.wait()
    follower = asyncio.create_task(
        follower_side.run("k", Hooked(other_hot, SystemClock()), owner_deadline_s=10, wait_s=10, hooked=True)
    )
    gate.set()
    answered = await asyncio.wait_for(owner, 2)
    assert answered.role is Role.OWNER
    assert answered.value == "value-1"
    assert answered.outcome is None  # not finished yet
    assert owner_side.tails() == 1
    await asyncio.sleep(0.1)
    assert not follower.done()  # the other worker waits for the published outcome
    stored.set()
    followed = await asyncio.wait_for(follower, 5)
    assert followed.role is Role.FOLLOWER
    assert followed.outcome is not None
    assert followed.outcome.kind is OutcomeKind.STORED
    await owner_side.settle()
    assert owner_side.tails() == 0


async def test_private_outcome_sends_every_follower_back_to_compete(hot: Database, other_hot: Database) -> None:
    """Plan 6.9 (finding F2): an answer that belongs to its own request is never handed to anyone else, in this
    worker or another. Each waiting request competes again and makes its own fetch."""
    side, other_side = _flight(hot, "w1"), _flight(other_hot, "w2")
    gate = asyncio.Event()
    fetch = Hooked(hot, SystemClock(), FlightOutcome(OutcomeKind.PRIVATE), gate=gate)
    other_fetch = Hooked(other_hot, SystemClock(), FlightOutcome(OutcomeKind.PRIVATE))
    first = asyncio.create_task(side.run("k", fetch, owner_deadline_s=10, wait_s=10, hooked=True))
    await fetch.entered.wait()
    local = [asyncio.create_task(side.run("k", fetch, owner_deadline_s=10, wait_s=10, hooked=True)) for _ in range(2)]
    remote = asyncio.create_task(other_side.run("k", other_fetch, owner_deadline_s=10, wait_s=10, hooked=True))
    await asyncio.sleep(0.05)
    gate.set()
    results = await asyncio.gather(first, *local, remote)
    assert fetch.calls + other_fetch.calls == 4  # one fetch per request: nothing was shared
    assert all(r.role is Role.OWNER for r in results)
    assert sorted(str(r.value) for r in results[:3]) == ["value-1", "value-2", "value-3"]
    assert side.stats.private == 3


async def test_publish_is_retried_while_hot_db_refuses_it(
    hot: Database, other_hot: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Finding SF-ORPHAN: a publish that hot.db refuses (busy) is retried until it lands, so followers elsewhere
    get the outcome instead of waiting for the lease to expire."""
    owner_side, follower_side = _flight(hot, "w1"), _flight(other_hot, "w2")
    gate = asyncio.Event()
    owner_fetch = Hooked(hot, SystemClock(), _shared(status=503, body=b"failed", reason="upstream_5xx"), gate=gate)
    owner = asyncio.create_task(owner_side.run("k", owner_fetch, owner_deadline_s=30, wait_s=30, hooked=True))
    await owner_fetch.entered.wait()
    follower = asyncio.create_task(
        follower_side.run("k", Hooked(other_hot, SystemClock()), owner_deadline_s=30, wait_s=30, hooked=True)
    )
    real_write = hot.write
    refusals = 0

    async def busy_twice(fn: Any, **kwargs: Any) -> Any:
        nonlocal refusals
        if refusals < 2:
            refusals += 1
            raise SharedStateUnavailable("hot", "database is locked")
        return await real_write(fn, **kwargs)

    monkeypatch.setattr(hot, "write", busy_twice)
    gate.set()
    assert (await owner).role is Role.OWNER
    followed = await asyncio.wait_for(follower, 5)
    assert followed.outcome is not None
    assert followed.outcome.status == 503
    assert owner_side.stats.publish_retries == 2
    assert owner_side.stats.publish_failures == 0


async def test_this_workers_unpublished_flight_is_taken_over_at_once(
    hot: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Finding SF-ORPHAN in the owner's own worker: once the linger is over, a new request does not wait for the
    lease of a flight this worker already finished (its outcome could not be written); it starts a new one."""
    clock = FakeClock()
    side = SingleFlight(hot, clock, "w1", poll_start_s=0.01, poll_max_s=0.05)
    first = Hooked(hot, clock, _shared(status=503, body=b"failed", reason="upstream_5xx"))

    async def always_busy(*_args: Any) -> None:
        raise SharedStateUnavailable("hot", "database is locked")

    monkeypatch.setattr(side, "_publish_once", always_busy)
    answered = await side.run("k", first, owner_deadline_s=30, wait_s=30, hooked=True)
    assert answered.role is Role.OWNER
    clock.advance(1.5)  # the linger is over; the lease (30 s) is still live and carries no outcome
    second = Hooked(hot, clock, _shared(body=b"fresh"))
    again = await asyncio.wait_for(side.run("k", second, owner_deadline_s=30, wait_s=30, hooked=True), 2)
    assert again.role is Role.OWNER  # took the lease over at once, no waiting for its expiry
    assert second.calls == 1
    row = lease_row(hot)
    assert row is not None
    assert row[0] == "w1"
    await side.close(grace_s=0.1)


async def test_tail_table_full_finishes_in_the_driver_without_retries(hot: Database, other_hot: Database) -> None:
    side = SingleFlight(hot, SystemClock(), "w1", poll_start_s=0.01, poll_max_s=0.05, max_tails=0)
    follower_side = _flight(other_hot, "w2")
    gate = asyncio.Event()
    fetch = Hooked(hot, SystemClock(), _shared(body=b"inline"), gate=gate)
    owner = asyncio.create_task(side.run("k", fetch, owner_deadline_s=10, wait_s=10, hooked=True))
    await fetch.entered.wait()
    follower = asyncio.create_task(
        follower_side.run("k", Hooked(other_hot, SystemClock()), owner_deadline_s=10, wait_s=10, hooked=True)
    )
    gate.set()
    await owner
    followed = await asyncio.wait_for(follower, 5)
    assert followed.outcome is not None
    assert followed.outcome.body == b"inline"
    assert side.tails() == 0
    assert side.stats.tails_inline == 1


async def test_hooked_try_lead_skips_a_live_lease(hot: Database, other_hot: Database) -> None:
    owner_side, refresher_side = _flight(hot, "w1"), _flight(other_hot, "w2")
    gate = asyncio.Event()
    owner_fetch = Hooked(hot, SystemClock(), gate=gate)
    owner = asyncio.create_task(owner_side.run("k", owner_fetch, owner_deadline_s=10, wait_s=10, hooked=True))
    await owner_fetch.entered.wait()
    refresh = Hooked(other_hot, SystemClock())
    assert await refresher_side.try_lead("k", refresh, owner_deadline_s=10, hooked=True) is None
    assert refresh.calls == 0
    assert refresh.hook_calls == 0
    gate.set()
    await owner
    led = await refresher_side.try_lead("other", refresh, owner_deadline_s=10, hooked=True)
    assert led is not None
    assert led.role is Role.OWNER
    assert refresh.calls == 1
