"""GCRA math, bucket keys and rates, and the atomic multi-bucket reservation in hot.db (plan 7.3)."""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from upstream_fakes import FakeRules, FakeSettings, read_rows

from roxy.core.reasons import Egress
from roxy.upstream import buckets
from roxy.upstream.buckets import (
    BucketDefaults,
    BucketSpec,
    Denial,
    Grant,
    GuardDenial,
    earliest_slot_ms,
    gcra_advance_ms,
    gcra_earliest_ms,
    gcra_fill,
    reserve_in,
    reserve_txn,
    specs_for,
)

NOW = 1_760_000_000_000


# --- the pure math ----------------------------------------------------------------------------------------------------


def test_gcra_teaching_example() -> None:
    """The worked example in the `buckets.py` docstring, step by step."""
    spec = BucketSpec("endpoint:x", 120, 10)
    assert spec.interval_ms == 500
    assert spec.tolerance_ms == 4500
    now = 10_000.0
    tat = 0.0  # no row yet: a full bucket
    for k in range(10):
        earliest = gcra_earliest_ms(tat, spec, now)
        assert earliest == now, k
        tat = gcra_advance_ms(tat, spec, earliest)
    assert tat == 15_000
    assert gcra_earliest_ms(tat, spec, now) == 10_500  # the 11th waits one interval
    tat = gcra_advance_ms(tat, spec, 10_500)
    assert gcra_earliest_ms(tat, spec, 10_500) == 11_000  # then 500 ms spacing: 120 per minute
    assert gcra_earliest_ms(15_000, spec, 20_000) == 20_000  # after 5 s idle the full burst is back


@pytest.mark.parametrize(
    ("per_min", "burst", "interval", "tolerance"),
    [(600, 30, 100.0, 2900.0), (60, 1, 1000.0, 0.0), (7, 3, 60_000 / 7, 2 * 60_000 / 7), (20, 3, 3000.0, 6000.0)],
)
def test_interval_and_tolerance(per_min: float, burst: int, interval: float, tolerance: float) -> None:
    spec = BucketSpec("k", per_min, burst)
    assert spec.interval_ms == pytest.approx(interval)
    assert spec.tolerance_ms == pytest.approx(tolerance)
    assert spec.capacity_ms == pytest.approx(burst * interval)
    assert spec.rate_per_s == pytest.approx(per_min / 60)


def test_allowed_iff_now_at_least_tat_minus_tolerance() -> None:
    spec = BucketSpec("k", 60, 3)  # interval 1000, tolerance 2000
    assert gcra_earliest_ms(5000, spec, 3000) == 3000  # 3000 >= 5000 - 2000: allowed now
    assert gcra_earliest_ms(5001, spec, 3000) == 3001  # one millisecond too early
    assert gcra_advance_ms(5000, spec, 3000) == 6000  # TAT = max(TAT, now) + interval
    assert gcra_advance_ms(1000, spec, 3000) == 4000  # a TAT in the past restarts from now


def test_clock_stepping_back_is_harmless() -> None:
    spec = BucketSpec("k", 60, 1)
    tat = gcra_advance_ms(0, spec, 10_000)
    assert gcra_earliest_ms(tat, spec, 9_100) == 11_000  # the wall clock went back 0.9 s: still the same slot


def test_fill_levels() -> None:
    spec = BucketSpec("k", 60, 4)  # capacity 4000 ms
    assert gcra_fill(0, spec, 10_000) == 0.0
    assert gcra_fill(12_000, spec, 10_000) == 0.5
    assert gcra_fill(14_000, spec, 10_000) == 1.0
    assert gcra_fill(99_000, spec, 10_000) == 1.0


def test_earliest_slot_is_the_latest_bucket() -> None:
    a = BucketSpec("a", 60, 1)
    b = BucketSpec("b", 60, 2)
    slot, binding = earliest_slot_ms({"a": 12_000, "b": 13_000}, [a, b], 10_000)
    assert (slot, binding) == (12_000, "a")  # b allows at 13000 - 1000 = 12000 too; a binds first in order
    slot, binding = earliest_slot_ms({"a": 12_000, "b": 14_500}, [a, b], 10_000)
    assert (slot, binding) == (13_500, "b")
    assert earliest_slot_ms({}, [a, b], 10_000) == (10_000, "")


@pytest.mark.parametrize(("per_min", "burst"), [(0, 1), (-1, 1), (10, 0)])
def test_bucket_spec_rejects_nonsense(per_min: float, burst: int) -> None:
    with pytest.raises(ValueError, match="bucket"):
        BucketSpec("k", per_min, burst)


@given(
    per_min=st.floats(min_value=1, max_value=10_000, allow_nan=False),
    burst=st.integers(min_value=1, max_value=50),
    count=st.integers(min_value=1, max_value=80),
)
@settings(max_examples=150, deadline=None)
def test_property_slot_k_is_exact(per_min: float, burst: int, count: int) -> None:
    """N requests at one instant: request k goes at now + max(0, k - burst + 1) x interval. Exactly the rate."""
    spec = BucketSpec("k", per_min, burst)
    tat = 0.0
    now = 1_000_000.0
    for k in range(count):
        slot = gcra_earliest_ms(tat, spec, now)
        expected = now + max(0, k - burst + 1) * spec.interval_ms
        assert slot == pytest.approx(expected, rel=1e-9, abs=1e-6)
        tat = gcra_advance_ms(tat, spec, slot)


# --- keys and rates ---------------------------------------------------------------------------------------------------


def test_bucket_keys() -> None:
    assert buckets.egress_bucket_key(Egress.DIRECT) == "egress:direct"
    assert buckets.egress_bucket_key(Egress.CREDENTIAL, probe=True) == "egress:credential:probe"
    assert buckets.egress_bucket_key(Egress.ROTATOR, probe=True) == "egress:rotator"
    assert buckets.host_bucket_key("games.roblox.com") == "host:games.roblox.com"
    assert buckets.endpoint_bucket_key("games.roblox.com/v1/games") == "endpoint:games.roblox.com/v1/games"
    with pytest.raises(ValueError, match="none"):
        buckets.egress_bucket_key(Egress.NONE)


def test_default_rates_from_the_catalog() -> None:
    defaults = BucketDefaults.from_settings(FakeSettings())
    assert (defaults.global_.per_min, defaults.global_.burst) == (600, 30)
    assert (defaults.direct.per_min, defaults.direct.burst) == (300, 20)
    assert (defaults.rotator.per_min, defaults.rotator.burst) == (300, 20)
    assert (defaults.host.per_min, defaults.host.burst) == (240, 15)
    assert (defaults.endpoint.per_min, defaults.endpoint.burst) == (120, 10)
    # The account's 20 per minute is split: 18 for allowlisted traffic, 2 reserved for Roxy's own probes.
    assert (defaults.credential.per_min, defaults.credential.burst) == (18, 3)
    assert (defaults.credential_probe.per_min, defaults.credential_probe.burst) == (2, 2)


def test_specs_for_each_egress_and_overrides() -> None:
    defaults = BucketDefaults.from_settings(FakeSettings())
    rules = FakeRules()
    rules.limit("host:games.roblox.com", 100, 5)
    rules.limit("endpoint:games.roblox.com/v1/games", 30, 2, origin="adaptive")
    specs = specs_for(Egress.DIRECT, "games.roblox.com", "games.roblox.com/v1/games", defaults, rules.snapshot)
    assert [(s.key, s.per_min, s.burst) for s in specs] == [
        ("global", 600, 30),
        ("egress:direct", 300, 20),
        ("host:games.roblox.com", 100, 5),
        ("endpoint:games.roblox.com/v1/games", 30, 2),
    ]
    other = specs_for(
        Egress.ROTATOR, "users.roblox.com", "users.roblox.com/v1/users/{userId}", defaults, rules.snapshot
    )
    assert [(s.key, s.per_min) for s in other][1:] == [
        ("egress:rotator", 300),
        ("host:users.roblox.com", 240),
        ("endpoint:users.roblox.com/v1/users/{userId}", 120),
    ]
    probe = specs_for(Egress.CREDENTIAL, "users.roblox.com", "t", defaults, None, credential_probe=True)
    assert probe[1].key == "egress:credential:probe"
    shared = specs_for(Egress.CREDENTIAL, "users.roblox.com", "t", defaults, None)
    assert shared[1].key == "egress:credential"
    with pytest.raises(ValueError, match="none"):
        specs_for(Egress.NONE, "h", "t", defaults, None)


# --- reservations in hot.db -------------------------------------------------------------------------------------------


def tats(dbs: Any) -> dict[str, float]:
    return {str(k): float(v) for k, v in read_rows(dbs.hot, "SELECT bucket_key, tat_ms FROM upstream_bucket")}


SPECS = (BucketSpec("global", 600, 30), BucketSpec("egress:direct", 300, 20), BucketSpec("endpoint:e", 60, 1))


def test_reserve_advances_every_bucket(dbs: Any) -> None:
    result = dbs.hot.write_sync(lambda conn: reserve_in(conn, SPECS, NOW, 4000))
    assert isinstance(result, Grant)
    assert result.slot_ms == NOW
    assert tats(dbs) == {"global": NOW + 100, "egress:direct": NOW + 200, "endpoint:e": NOW + 1000}
    second = dbs.hot.write_sync(lambda conn: reserve_in(conn, SPECS, NOW, 4000))
    assert isinstance(second, Grant)
    assert second.slot_ms == NOW + 1000  # the endpoint bucket (60/min, burst 1) binds
    assert second.binding_key == "endpoint:e"
    assert second.wait_ms == 1000
    assert tats(dbs) == {"global": NOW + 1100, "egress:direct": NOW + 1200, "endpoint:e": NOW + 2000}


def test_reservation_never_leaks_tokens_when_one_bucket_denies(dbs: Any) -> None:
    dbs.hot.write_sync(lambda conn: reserve_in(conn, SPECS, NOW, 4000))
    before = tats(dbs)
    denied = dbs.hot.write_sync(lambda conn: reserve_in(conn, SPECS, NOW, 500))  # needs 1000 ms, may wait 500
    assert isinstance(denied, Denial)
    assert denied.binding_key == "endpoint:e"
    assert denied.retry_after_ms == 1000
    assert denied.reason == "busy"
    assert tats(dbs) == before  # global and egress buckets were NOT charged for the denied call


def test_refund_gives_back_exactly_one_interval(dbs: Any) -> None:
    dbs.hot.write_sync(lambda conn: reserve_in(conn, SPECS, NOW, 4000))
    grant = dbs.hot.write_sync(lambda conn: reserve_in(conn, SPECS, NOW, 4000))
    assert isinstance(grant, Grant)
    dbs.hot.write_sync(lambda conn: buckets.refund_in(conn, grant, NOW))
    assert tats(dbs) == {"global": NOW + 100, "egress:direct": NOW + 200, "endpoint:e": NOW + 1000}


def test_refund_after_others_moved_on_gives_back_one_interval(dbs: Any) -> None:
    grant = dbs.hot.write_sync(lambda conn: reserve_in(conn, SPECS, NOW, 4000))
    assert isinstance(grant, Grant)
    dbs.hot.write_sync(lambda conn: reserve_in(conn, SPECS, NOW, 4000))  # a later reservation depends on ours
    dbs.hot.write_sync(lambda conn: buckets.refund_in(conn, grant, NOW))
    assert tats(dbs) == {"global": NOW + 1000, "egress:direct": NOW + 1000, "endpoint:e": NOW + 1000}


def test_refund_never_below_now(dbs: Any) -> None:
    grant = dbs.hot.write_sync(lambda conn: reserve_in(conn, SPECS, NOW, 4000))
    other = dbs.hot.write_sync(lambda conn: reserve_in(conn, (BucketSpec("global", 600, 30),), NOW, 4000))
    assert isinstance(grant, Grant)
    assert isinstance(other, Grant)
    later = NOW + 50_000
    dbs.hot.write_sync(lambda conn: buckets.refund_in(conn, grant, later))
    assert tats(dbs)["global"] == later


def test_background_only_while_global_under_half_used(dbs: Any) -> None:
    specs = (BucketSpec("global", 60, 4), BucketSpec("endpoint:e", 6000, 100))  # global capacity 4000 ms
    for _ in range(2):
        result = dbs.hot.write_sync(lambda conn: reserve_in(conn, specs, NOW, 4000, background_global_limit=0.5))
        assert isinstance(result, Grant)
    denied = dbs.hot.write_sync(lambda conn: reserve_in(conn, specs, NOW, 4000, background_global_limit=0.5))
    assert isinstance(denied, Denial)
    assert denied.reason == "background"
    assert denied.binding_key == "global"
    interactive = dbs.hot.write_sync(lambda conn: reserve_in(conn, specs, NOW, 4000))
    assert isinstance(interactive, Grant)  # an interactive caller still gets the slot


def test_priority_horizon_is_the_max_wait(dbs: Any) -> None:
    specs = (BucketSpec("endpoint:e", 60, 1),)
    dbs.hot.write_sync(lambda conn: reserve_in(conn, specs, NOW, 0))
    assert isinstance(dbs.hot.write_sync(lambda conn: reserve_in(conn, specs, NOW, 999)), Denial)  # stale class
    assert isinstance(dbs.hot.write_sync(lambda conn: reserve_in(conn, specs, NOW, 1000)), Grant)  # interactive


def lease_rows(dbs: Any) -> list[tuple[Any, ...]]:
    return read_rows(dbs.hot, "SELECT name, holder FROM lease")


def insert_lease(conn: Any, now_ms: int) -> bool:
    conn.execute("INSERT INTO lease (name, holder, expires_ms, epoch) VALUES ('sf:k', 'me', ?, 1)", (now_ms + 36_000,))
    return True


def test_lease_hook_lost_takes_nothing(dbs: Any) -> None:
    outcome = dbs.hot.write_sync(lambda conn: reserve_txn(conn, SPECS, NOW, 4000, lease_hook=lambda c, n: False))
    assert outcome.lease_lost is True
    assert outcome.grant is None
    assert tats(dbs) == {}


def test_lease_hook_and_buckets_commit_together(dbs: Any) -> None:
    outcome = dbs.hot.write_sync(lambda conn: reserve_txn(conn, SPECS, NOW, 4000, lease_hook=insert_lease))
    assert outcome.granted
    assert lease_rows(dbs) == [("sf:k", "me")]
    assert set(tats(dbs)) == {"global", "egress:direct", "endpoint:e"}


def test_denial_rolls_back_the_lease_insert(dbs: Any) -> None:
    dbs.hot.write_sync(lambda conn: reserve_in(conn, SPECS, NOW, 4000))
    before = tats(dbs)
    outcome = dbs.hot.write_sync(lambda conn: reserve_txn(conn, SPECS, NOW, 0, lease_hook=insert_lease))
    assert outcome.denial is not None
    assert lease_rows(dbs) == []  # commits nothing (plan 7.3)
    assert tats(dbs) == before


def test_guard_denial_rolls_back_everything(dbs: Any) -> None:
    def guard(conn: Any, now_ms: int) -> GuardDenial | None:
        conn.execute("INSERT INTO lease (name, holder, expires_ms, epoch) VALUES ('brk:x', 'me', 1, 1)")
        return GuardDenial("cooldown", "endpoint:e:direct", 5000, "retry_after")

    outcome = dbs.hot.write_sync(
        lambda conn: reserve_txn(conn, SPECS, NOW, 4000, lease_hook=insert_lease, guards=[guard])
    )
    assert outcome.guard is not None
    assert outcome.guard.retry_after_s == 5
    assert lease_rows(dbs) == []
    assert tats(dbs) == {}


def test_exception_inside_reservation_rolls_back(dbs: Any) -> None:
    def broken(conn: Any, now_ms: int) -> GuardDenial | None:
        raise RuntimeError("bug")

    with pytest.raises(RuntimeError):
        dbs.hot.write_sync(lambda conn: reserve_txn(conn, SPECS, NOW, 4000, guards=[broken]))
    assert tats(dbs) == {}


async def test_async_reserve_and_refund(dbs: Any) -> None:
    clock_ms = [NOW]
    outcome = await buckets.reserve(dbs.hot, SPECS, now_ms=lambda: clock_ms[0], max_wait_ms=4000)
    assert outcome.grant is not None
    await buckets.refund(dbs.hot, outcome.grant, now_ms=lambda: clock_ms[0])
    assert all(value == 0 for value in tats(dbs).values())  # restored exactly: a full bucket again


def test_bucket_states_for_the_dashboard(dbs: Any) -> None:
    for _ in range(3):
        dbs.hot.write_sync(lambda conn: reserve_in(conn, SPECS, NOW, 10_000))
    states = {state.key: state for state in dbs.hot.read_sync(lambda conn: buckets.bucket_states(conn, NOW))}
    endpoint = states["endpoint:e"]
    assert endpoint.per_min == pytest.approx(60)
    assert endpoint.burst == 1
    assert endpoint.fill == 1.0
    assert endpoint.next_free_in_ms == pytest.approx(3000)
    # Global (600/min, burst 30, capacity 3000 ms) took slots at NOW, NOW+1000, NOW+2000: TAT = NOW + 2100.
    assert states["global"].fill == pytest.approx(2100 / 3000)
