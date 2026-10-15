"""`Tarpit.plan_cooldown_retry`: the producer of the `upstream_cooldown_retry` category (plan 10.6, 15.3 F).

What this is
    Unit tests of the one hot.db transaction that remembers the `Retry-After` a client was given for a key and holds
    a retry of that key inside it with the `jitter` type: across two workers, per client and key, expiry, the
    bounded row count, the switches, bypass, the fleet cap and C7.

Why it exists
    Spec review finding F4: the category had a switch and a jitter branch but no producer. The end-to-end proof is
    `tests/integration/test_abuse_cooldown_retry.py`; these tests pin the edges.

How it works
    Two `Tarpit` objects over one temporary hot.db play two workers; a `FakeClock` moves time; the sleep records.

What to read next
    `roxy/abuse/tarpit.py` (module docstring, `plan_cooldown_retry`), `roxy/proxy/router.py` (`cooldown_retry_plan`).
"""

from __future__ import annotations

import random
from typing import Any

from abuse_support import FakeReq, FakeSettings

from roxy.abuse.tarpit import RETRY_CATEGORY, RETRY_PREFIX, RETRY_SLOTS, Tarpit, retry_fingerprint
from roxy.core.clock import FakeClock
from roxy.storage.db import SharedStateUnavailable

ON = {"tarpit_enabled": 1, "tarpit_on_upstream_cooldown_retry": 1}


class Sleeper:
    def __init__(self) -> None:
        self.calls: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


def worker(dbs: Any, clock: FakeClock, name: str, **overrides: Any) -> Tarpit:
    return Tarpit(
        FakeSettings({**ON, **overrides}),
        dbs.hot,
        clock,
        name,
        sleep=Sleeper(),
        monotonic=clock.monotonic,
        rng=random.Random(3),
    )


def req(**fields: Any) -> FakeReq:
    fields.setdefault("deadline_at", 10**9)
    return FakeReq(**fields)


def retry_rows(dbs: Any) -> int:
    sql = "SELECT count(*) FROM limiter WHERE bucket_key >= ? AND bucket_key < ?"
    return int(dbs.hot.read_sync(lambda c: c.execute(sql, (RETRY_PREFIX, RETRY_PREFIX + "\U0010ffff")).fetchone()[0]))


async def test_a_retry_inside_the_retry_after_is_jittered_on_any_worker(dbs: Any, fake_clock: FakeClock) -> None:
    a, b = worker(dbs, fake_clock, "a"), worker(dbs, fake_clock, "b")
    assert await a.plan_cooldown_retry(req(), key="k1", retry_after_s=30) is None  # the first answer: remembered
    fake_clock.advance(5)
    plan = await b.plan_cooldown_retry(req(), key="k1", retry_after_s=25, reason="r")  # the retry lands on worker b
    assert plan is not None
    assert plan.kind == "jitter"
    assert plan.category == RETRY_CATEGORY
    assert 0.5 <= plan.hold_s <= 3.0
    await plan.wait()
    await plan.release()
    assert await b.active_holds() == 0
    assert b.stats.snapshot()["categories"][RETRY_CATEGORY]["held"] == 1


async def test_after_the_retry_after_ran_out_it_is_a_fresh_answer(dbs: Any, fake_clock: FakeClock) -> None:
    pit = worker(dbs, fake_clock, "a")
    await pit.plan_cooldown_retry(req(), key="k1", retry_after_s=30)
    fake_clock.advance(31)
    assert await pit.plan_cooldown_retry(req(), key="k1", retry_after_s=30) is None
    fake_clock.advance(1)
    assert await pit.plan_cooldown_retry(req(), key="k1", retry_after_s=30) is not None  # inside the new one


async def test_other_clients_and_other_keys_are_not_retries(dbs: Any, fake_clock: FakeClock) -> None:
    pit = worker(dbs, fake_clock, "a")
    await pit.plan_cooldown_retry(req(), key="k1", retry_after_s=30)
    other_client = req(client_ip="198.51.100.3", limit_key="198.51.100.3")
    assert await pit.plan_cooldown_retry(other_client, key="k1", retry_after_s=30) is None
    # A key that lands in the same slot replaces the remembered one (fails open): never a false hold.
    slot = retry_fingerprint("k1") % RETRY_SLOTS
    twin = next(f"k{n}" for n in range(2, 10_000) if retry_fingerprint(f"k{n}") % RETRY_SLOTS == slot)
    assert await pit.plan_cooldown_retry(req(), key=twin, retry_after_s=30) is None


async def test_rows_per_client_are_bounded(dbs: Any, fake_clock: FakeClock) -> None:
    pit = worker(dbs, fake_clock, "a")
    for n in range(200):
        await pit.plan_cooldown_retry(req(), key=f"key-{n}", retry_after_s=30)
    assert retry_rows(dbs) <= RETRY_SLOTS


async def test_switches_and_bypass_hold_nothing_and_write_nothing(dbs: Any, fake_clock: FakeClock) -> None:
    for overrides in ({"tarpit_on_upstream_cooldown_retry": 0}, {"tarpit_enabled": 0}):
        pit = worker(dbs, fake_clock, "a", **overrides)
        for _ in range(2):
            assert await pit.plan_cooldown_retry(req(), key="k1", retry_after_s=30) is None
    pit = worker(dbs, fake_clock, "a")
    for _ in range(2):
        assert await pit.plan_cooldown_retry(req(bypass=True), key="k1", retry_after_s=30) is None
    assert retry_rows(dbs) == 0


async def test_the_fleet_cap_and_the_deadline_still_apply(dbs: Any, fake_clock: FakeClock) -> None:
    pit = worker(dbs, fake_clock, "a", tarpit_max_concurrent=0)
    await pit.plan_cooldown_retry(req(), key="k1", retry_after_s=30)
    assert await pit.plan_cooldown_retry(req(), key="k1", retry_after_s=30) is None  # no slot: instant
    assert pit.stats.snapshot()["skipped"] == 1
    pit = worker(dbs, fake_clock, "a")
    await pit.plan_cooldown_retry(req(), key="k2", retry_after_s=30)
    near_deadline = req(deadline_at=fake_clock.monotonic() + 1.0)  # less than the 2 s margin left
    assert await pit.plan_cooldown_retry(near_deadline, key="k2", retry_after_s=30) is None


async def test_without_shared_state_it_never_holds(dbs: Any, fake_clock: FakeClock) -> None:
    pit = worker(dbs, fake_clock, "a")

    async def broken(*_args: Any, **_kwargs: Any) -> Any:
        raise SharedStateUnavailable("hot", "database is locked")

    pit.hot_db.write = broken  # type: ignore[union-attr, method-assign]
    try:
        assert await pit.plan_cooldown_retry(req(), key="k1", retry_after_s=30) is None
        assert await pit.plan_cooldown_retry(req(), key="k1", retry_after_s=30) is None
    finally:
        del pit.hot_db.write  # type: ignore[union-attr]
