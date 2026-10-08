"""The tarpit (plan 10.6, rows 47 and 123): cap formula, categories, types, fail closed, state fields."""

from __future__ import annotations

import random
from typing import Any

import pytest
from abuse_support import FakeReq, FakeSettings

from roxy.abuse.tarpit import DRIP_HEADERS, SLOT_PREFIX, Tarpit, capacity, category_enabled, hold_bounds
from roxy.config.catalog import CATALOG
from roxy.config.constants import TARPIT_CATEGORIES
from roxy.core.clock import FakeClock
from roxy.storage import leases
from roxy.storage.db import SharedStateUnavailable

DEFAULTS = {key: spec.default for key, spec in CATALOG.items()}


class Sleeper:
    def __init__(self, clock: FakeClock) -> None:
        self.clock = clock
        self.calls: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)
        self.clock.advance(max(0.0, seconds))


def tarpit(dbs: Any, clock: FakeClock, **overrides: Any) -> tuple[Tarpit, Sleeper]:
    sleeper = Sleeper(clock)
    return (
        Tarpit(
            FakeSettings(overrides),
            dbs.hot,
            clock,
            "w1",
            sleep=sleeper,
            monotonic=clock.monotonic,
            rng=random.Random(7),
        ),
        sleeper,
    )


def test_effective_cap_formula_defaults() -> None:
    cap = capacity(DEFAULTS)
    assert (cap.effective, cap.configured, cap.connection_budget, cap.budget_cap) == (50, 50, 4000, 1000)
    assert not cap.clamped
    assert cap.formula == "min(50, floor(4000 x 0.25)) = min(50, 1000) = 50"


def test_cap_clamped_by_the_connection_budget() -> None:
    cap = capacity(
        {**DEFAULTS, "tarpit_max_concurrent": 500, "tarpit_connection_budget": 100, "tarpit_max_capacity_fraction": 0.5}
    )
    assert cap.effective == 50
    assert cap.clamped
    assert cap.clamped_by == "connection_budget"


def test_categories_and_defaults() -> None:
    assert len(TARPIT_CATEGORIES) == 11
    enabled = [c for c in TARPIT_CATEGORIES if category_enabled(DEFAULTS, c)]
    # Plan 15.3 F defaults: 1,1,0,0,0,0,1,0,1,1,0.
    assert enabled == ["header_rule", "probe", "auth_attempt", "ban", "spam"]
    assert not category_enabled(DEFAULTS, "no_such_category")
    assert category_enabled({**DEFAULTS, "tarpit_on_user_agent_rule": 1}, "user_agent_rule")  # v1 bug B1 fixed


def test_hold_bounds_swap_when_reversed() -> None:
    assert hold_bounds({"tarpit_min_seconds": 20, "tarpit_max_seconds": 8}) == (8.0, 20.0)


async def test_hold_takes_a_slot_waits_and_releases(dbs: Any, fake_clock: FakeClock) -> None:
    pit, sleeper = tarpit(dbs, fake_clock)
    plan = await pit.plan("probe", FakeReq(), reason="Invalid URL (unsafe characters)")
    assert plan is not None
    assert plan.kind == "hold"
    assert 8 <= plan.hold_s <= 20
    assert await pit.active_holds() == 1
    await plan.wait()
    await plan.release()
    await plan.release()  # idempotent
    assert sleeper.calls == [plan.hold_s]
    assert await pit.active_holds() == 0
    snapshot = pit.stats.snapshot()
    assert snapshot["held"] == 1
    assert snapshot["categories"]["probe"]["held"] == 1
    assert "probe|Invalid URL (unsafe characters)" in snapshot["reasons"]


async def test_off_switches_and_bypass_never_hold(dbs: Any, fake_clock: FakeClock) -> None:
    pit, _ = tarpit(dbs, fake_clock)
    assert await pit.plan("throttle", FakeReq()) is None  # category off by default
    assert await pit.plan("probe", FakeReq(bypass=True)) is None
    off, _ = tarpit(dbs, fake_clock, tarpit_enabled=0)
    assert await off.plan("probe", FakeReq()) is None
    assert pit.stats.snapshot()["skipped"] == 0  # v1: nothing logged when the tarpit does not apply


async def test_over_the_cap_is_instant_and_counted_as_skipped(dbs: Any, fake_clock: FakeClock) -> None:
    pit, _ = tarpit(dbs, fake_clock, tarpit_max_concurrent=2)
    first = await pit.plan("probe", FakeReq())
    second = await pit.plan("probe", FakeReq())
    third = await pit.plan("probe", FakeReq())
    assert first is not None
    assert second is not None
    assert third is None
    assert pit.stats.snapshot()["skipped"] == 1
    await first.release()
    assert await pit.plan("probe", FakeReq()) is not None


async def test_zero_cap_skips_everything(dbs: Any, fake_clock: FakeClock) -> None:
    pit, _ = tarpit(dbs, fake_clock, tarpit_max_concurrent=0)
    assert await pit.plan("probe", FakeReq()) is None
    assert pit.stats.snapshot()["skipped"] == 1


async def test_fails_closed_without_shared_state(dbs: Any, fake_clock: FakeClock) -> None:
    pit, sleeper = tarpit(dbs, fake_clock)

    async def broken(*_args: Any, **_kwargs: Any) -> Any:
        raise SharedStateUnavailable("hot", "disk I/O error")

    real = dbs.hot.write
    dbs.hot.write = broken
    try:
        assert await pit.plan("probe", FakeReq()) is None
    finally:
        dbs.hot.write = real
    assert sleeper.calls == []
    assert pit.stats.snapshot()["skipped"] == 1
    # Holding resumes after recovery (v1 smoke test).
    assert await pit.plan("probe", FakeReq()) is not None


async def test_upstream_cooldown_retry_uses_jitter(dbs: Any, fake_clock: FakeClock) -> None:
    pit, _ = tarpit(dbs, fake_clock, tarpit_on_upstream_cooldown_retry=1)
    plan = await pit.plan("upstream_cooldown_retry", FakeReq())
    assert plan is not None
    assert plan.kind == "jitter"
    assert 0.5 <= plan.hold_s <= 3.0


async def test_hold_is_capped_by_the_request_deadline(dbs: Any, fake_clock: FakeClock) -> None:
    pit, _ = tarpit(dbs, fake_clock)
    plan = await pit.plan("probe", FakeReq(deadline_at=fake_clock.monotonic() + 5))
    assert plan is not None
    assert plan.hold_s == pytest.approx(3.0)
    assert await pit.plan("probe", FakeReq(deadline_at=fake_clock.monotonic() + 1)) is None


async def test_drip_streams_one_byte_per_interval(dbs: Any, fake_clock: FakeClock) -> None:
    pit, sleeper = tarpit(dbs, fake_clock, tarpit_default_type="drip", tarpit_min_seconds=3, tarpit_max_seconds=3)
    plan = await pit.plan("probe", FakeReq())
    assert plan is not None
    assert plan.response_headers == DRIP_HEADERS
    chunks = [chunk async for chunk in plan.drip_chunks(b'"Invalid URL"\n')]
    assert b"".join(chunks) == b'"Invalid URL"\n'
    assert chunks[:2] == [b'"', b"I"]
    assert sum(sleeper.calls) == pytest.approx(3.0)
    await plan.release()


async def test_arrival_gap_is_measured_across_refusals(dbs: Any, fake_clock: FakeClock) -> None:
    pit, _ = tarpit(dbs, fake_clock)
    first = await pit.plan("probe", FakeReq())
    assert first is not None
    assert first.gap_s == 0
    fake_clock.advance(4)
    second = await pit.plan("probe", FakeReq())
    assert second is not None
    assert second.gap_s == pytest.approx(4.0)


async def test_crashed_holder_slot_expires(dbs: Any, fake_clock: FakeClock) -> None:
    pit, _ = tarpit(dbs, fake_clock, tarpit_max_concurrent=1, tarpit_slot_grace_s=1)
    plan = await pit.plan("probe", FakeReq())
    assert plan is not None
    assert await pit.plan("probe", FakeReq()) is None
    fake_clock.advance(plan.hold_s + 2)  # the holder "crashed": never released
    assert await pit.plan("probe", FakeReq()) is not None


async def test_state_fields(dbs: Any, fake_clock: FakeClock) -> None:
    pit, _ = tarpit(dbs, fake_clock)
    plan = await pit.plan("probe", FakeReq())
    assert plan is not None
    state = await pit.state()
    assert state["enabled"] is True
    assert state["categories"] == ["header_rule", "probe", "auth_attempt", "ban", "spam"]
    assert state["all_categories"] == list(TARPIT_CATEGORIES)
    assert (state["min_seconds"], state["max_seconds"]) == (8.0, 20.0)
    assert state["max_concurrent"] == 50
    assert state["configured_concurrent"] == 50
    assert state["clamped"] is False
    assert state["active_holds"] == 1
    assert state["slots_free"] == 49
    assert state["capacity_used_pct"] == round(1 / 4000 * 100, 1)
    assert state["capacity_ceiling_pct"] == 25.0
    assert state["fleet_slots"] == 4000
    assert state["shared_state_ok"] is True
    names = await dbs.hot.read(
        lambda conn: [
            r[0]
            for r in conn.execute(
                "SELECT name FROM lease WHERE name >= ? AND name < ?", (SLOT_PREFIX, SLOT_PREFIX + "~")
            ).fetchall()
        ]
    )
    assert names == ["tarpit:0"]
    assert await dbs.hot.read(lambda conn: leases.count_slots(conn, SLOT_PREFIX, fake_clock.now_ms())) == 1
