"""Fleet single-flight (plan 6.9, fix F1) within one process, with real hot.db leases.

A second `SingleFlight` with its own `Database` objects (own threads, own connections) and holder stands in for
another worker; the real multi-process tests live in tests/multiprocess/test_singleflight_mp.py.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from roxy.core.clock import FakeClock, SystemClock
from roxy.storage.db import Database, SharedStateUnavailable
from roxy.upstream.singleflight import (
    LEASE_PREFIX,
    FlightOutcome,
    FlightStart,
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
    assert flights.inflight() == 0


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
