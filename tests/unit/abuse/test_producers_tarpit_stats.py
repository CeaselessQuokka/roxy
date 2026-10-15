"""Tarpit hold statistics: holds, skips, hold times by category, and the arrival gap after a hold or an instant refusal.

Covers the wave 3b producers lane, item 2 (parity row 78, TARPIT-TUNE, the Protection > Tarpit card): every
eligible refusal is handed to the metrics recorder in memory (held with its hold time, or skipped), the arrival row
in hot.db remembers whether that arrival was held (same row, same transaction), and `read_producers.tarpit_summary`
gives holds, skips, the mean and p95 hold and both gaps fleet-wide.
"""

from __future__ import annotations

import random
from typing import Any

import pytest
from abuse_support import FakeReq, FakeSettings

from roxy.abuse.tarpit import ARRIVAL_PREFIX, RETRY_CATEGORY, Tarpit
from roxy.core.clock import FakeClock
from roxy.metrics import read_producers
from roxy.metrics.producers import HOLD_BOUNDS_MS, OVERFLOW_BOUND, hold_bound
from roxy.metrics.recorder import MetricsRecorder
from roxy.storage.db import SharedStateUnavailable


class Sleeper:
    """`asyncio.sleep` stand-in that moves the fake clock (so measured hold times are the planned ones)."""

    def __init__(self, clock: FakeClock) -> None:
        self.clock = clock

    async def __call__(self, seconds: float) -> None:
        self.clock.advance(max(0.0, seconds))


def make_tarpit(dbs: Any, clock: FakeClock, recorder: Any, **overrides: Any) -> Tarpit:
    return Tarpit(
        FakeSettings(overrides),
        dbs.hot,
        clock,
        "w1",
        sleep=Sleeper(clock),
        monotonic=clock.monotonic,
        rng=random.Random(3),
        recorder=recorder,
    )


def summary(dbs: Any, clock: FakeClock) -> dict[str, Any]:
    now = int(clock.now())
    return dbs.metrics.read_sync(lambda conn: read_producers.tarpit_summary(conn, now - 3600, now + 60))


def arrival_flag(dbs: Any, ip: str) -> int:
    row = dbs.hot.read_sync(
        lambda conn: conn.execute(
            "SELECT window_start FROM limiter WHERE bucket_key = ?", (ARRIVAL_PREFIX + ip,)
        ).fetchone()
    )
    return int(row[0])


async def test_holds_are_recorded_with_category_kind_and_hold_time(dbs: Any, fake_clock: FakeClock) -> None:
    recorder = MetricsRecorder(dbs, FakeSettings(), fake_clock, worker_id="w1")
    pit = make_tarpit(dbs, fake_clock, recorder)
    held: list[float] = []
    for n in range(4):
        plan = await pit.plan("probe", FakeReq(client_ip=f"203.0.113.{n}", limit_key=f"203.0.113.{n}"))
        assert plan is not None
        await plan.wait()
        await plan.release()
        held.append(plan.hold_s)
    recorder.close()
    found = summary(dbs, fake_clock)
    assert (found["holds"], found["skipped"], found["eligible"]) == (4, 0, 4)
    assert found["mean_hold_s"] == pytest.approx(sum(held) / 4, abs=0.01)
    assert found["max_hold_s"] == pytest.approx(max(held), abs=0.01)
    assert 8 <= found["p95_hold_s"] <= 20  # inside the default 8 to 20 s range, to one bucket
    assert set(found["by_category"]) == {"probe"}
    assert found["by_kind"] == {"hold": {"holds": 4, "skipped": 0}}
    assert sum(b["holds"] for b in found["hold_histogram"]) == 4


async def test_skips_and_the_gaps_after_a_hold_and_after_an_instant_refusal(dbs: Any, fake_clock: FakeClock) -> None:
    recorder = MetricsRecorder(dbs, FakeSettings(), fake_clock, worker_id="w1")
    pit = make_tarpit(dbs, fake_clock, recorder, tarpit_max_concurrent=1)
    client = FakeReq()
    first = await pit.plan("probe", client)  # takes the only slot
    assert first is not None
    assert (first.gap_s, first.after_hold) == (0.0, None)  # a first arrival has no gap
    assert arrival_flag(dbs, client.limit_key) == 1  # this arrival was held
    fake_clock.advance(3)
    assert await pit.plan("probe", client) is None  # every slot taken: skipped, gap 3 s after a hold
    assert arrival_flag(dbs, client.limit_key) == 0  # this one was answered at once
    fake_clock.advance(5)
    assert await pit.plan("probe", client) is None  # skipped again, gap 5 s after an instant refusal
    await first.release()
    recorder.close()
    found = summary(dbs, fake_clock)
    assert (found["holds"], found["skipped"], found["eligible"]) == (1, 2, 3)
    assert found["skipped_pct"] == pytest.approx(66.67, abs=0.01)
    assert (found["gaps_after_hold"], found["gap_after_hold_s"]) == (1, 3.0)
    assert (found["gaps_after_instant"], found["gap_after_instant_s"]) == (1, 5.0)
    assert pit.stats.snapshot()["skipped"] == 2  # the worker's own card still counts them too


async def test_a_hot_db_outage_is_a_skip_without_a_gap(dbs: Any, fake_clock: FakeClock) -> None:
    recorder = MetricsRecorder(dbs, FakeSettings(), fake_clock, worker_id="w1")
    pit = make_tarpit(dbs, fake_clock, recorder)

    async def broken(*_args: Any, **_kwargs: Any) -> Any:
        raise SharedStateUnavailable("hot", "disk I/O error")

    real = dbs.hot.write
    dbs.hot.write = broken
    try:
        assert await pit.plan("ban", FakeReq()) is None  # fail closed (C7)
    finally:
        dbs.hot.write = real
    recorder.close()
    found = summary(dbs, fake_clock)
    assert (found["holds"], found["skipped"]) == (0, 1)
    assert found["by_category"]["ban"]["skipped"] == 1
    assert found["gaps_after_hold"] == found["gaps_after_instant"] == 0


async def test_cooldown_retries_are_jitter_holds(dbs: Any, fake_clock: FakeClock) -> None:
    recorder = MetricsRecorder(dbs, FakeSettings(), fake_clock, worker_id="w1")
    pit = make_tarpit(dbs, fake_clock, recorder, tarpit_on_upstream_cooldown_retry=1)
    client = FakeReq()
    assert await pit.plan_cooldown_retry(client, key="k1", retry_after_s=30) is None  # the first answer: no hold
    fake_clock.advance(2)
    plan = await pit.plan_cooldown_retry(client, key="k1", retry_after_s=30)  # a retry inside its Retry-After
    assert plan is not None
    assert plan.kind == "jitter"
    await plan.wait()
    await plan.release()
    recorder.close()
    found = summary(dbs, fake_clock)
    assert found["by_kind"] == {"jitter": {"holds": 1, "skipped": 0}}
    assert found["by_category"][RETRY_CATEGORY]["holds"] == 1
    assert found["by_category"][RETRY_CATEGORY]["mean_hold_s"] <= 3.0


async def test_two_workers_add_up_and_nothing_is_written_on_the_request(dbs: Any, fake_clock: FakeClock) -> None:
    first = MetricsRecorder(dbs, FakeSettings(), fake_clock, worker_id="w1")
    second = MetricsRecorder(dbs, FakeSettings(), fake_clock, worker_id="w2")
    writes = 0
    real = dbs.metrics.write

    async def counted(fn: Any, **kwargs: Any) -> Any:
        nonlocal writes
        writes += 1
        return await real(fn, **kwargs)

    dbs.metrics.write = counted
    try:
        for recorder, ip in ((first, "203.0.113.1"), (second, "203.0.113.2"), (second, "203.0.113.3")):
            plan = await make_tarpit(dbs, fake_clock, recorder).plan("probe", FakeReq(client_ip=ip, limit_key=ip))
            assert plan is not None
            await plan.wait()
            await plan.release()
    finally:
        dbs.metrics.write = real
    assert writes == 0  # memory only until the recorder flushes
    first.close()
    second.close()
    assert summary(dbs, fake_clock)["holds"] == 3


def test_hold_buckets_and_percentiles() -> None:
    assert hold_bound(0.0) == HOLD_BOUNDS_MS[0]
    assert hold_bound(0.25) == 250  # bounds are inclusive
    assert hold_bound(12.3) == 15000
    assert hold_bound(55.0) == 55000
    assert hold_bound(70.0) == OVERFLOW_BOUND
    counts = {10000: 90, 20000: 10}
    # The median is the 50th of 90 holds in the (8 s, 10 s] bucket: interpolated 8 + 50 / 90 x 2 s.
    assert read_producers.hold_percentile(counts, 0.5) == pytest.approx(8 + 50 / 90 * 2, abs=0.01)
    assert 15 < read_producers.hold_percentile(counts, 0.95) <= 20  # type: ignore[operator]
    assert read_producers.hold_percentile({OVERFLOW_BOUND: 3}, 0.95) == 55.0
    assert read_producers.hold_percentile({}, 0.95) is None
