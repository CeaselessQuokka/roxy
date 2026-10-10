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
    """The worked example in the `buckets.py` docstring (a plain bucket), step by step."""
    spec = BucketSpec("global", 120, 10)
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
    """Every bucket's TAT (meter rows left out)."""
    rows = read_rows(dbs.hot, "SELECT bucket_key, tat_ms FROM upstream_bucket")
    return {str(k): float(v) for k, v in rows if not str(k).startswith(buckets.METER_PREFIX)}


# "plain:e" is a plain GCRA bucket (any key outside `host:` and `endpoint:`): the reservation mechanics below are
# about TATs; window buckets and their meters have their own tests further down.
SPECS = (BucketSpec("global", 600, 30), BucketSpec("egress:direct", 300, 20), BucketSpec("plain:e", 60, 1))


def test_reserve_advances_every_bucket(dbs: Any) -> None:
    result = dbs.hot.write_sync(lambda conn: reserve_in(conn, SPECS, NOW, 4000))
    assert isinstance(result, Grant)
    assert result.slot_ms == NOW
    assert tats(dbs) == {"global": NOW + 100, "egress:direct": NOW + 200, "plain:e": NOW + 1000}
    second = dbs.hot.write_sync(lambda conn: reserve_in(conn, SPECS, NOW, 4000))
    assert isinstance(second, Grant)
    assert second.slot_ms == NOW + 1000  # the plain bucket (60/min, burst 1) binds
    assert second.binding_key == "plain:e"
    assert second.wait_ms == 1000
    assert tats(dbs) == {"global": NOW + 1100, "egress:direct": NOW + 1200, "plain:e": NOW + 2000}
    assert read_rows(dbs.hot, "SELECT bucket_key FROM upstream_bucket WHERE bucket_key LIKE 'meter:%'") == []


def test_reservation_never_leaks_tokens_when_one_bucket_denies(dbs: Any) -> None:
    dbs.hot.write_sync(lambda conn: reserve_in(conn, SPECS, NOW, 4000))
    before = tats(dbs)
    denied = dbs.hot.write_sync(lambda conn: reserve_in(conn, SPECS, NOW, 500))  # needs 1000 ms, may wait 500
    assert isinstance(denied, Denial)
    assert denied.binding_key == "plain:e"
    assert denied.retry_after_ms == 1000
    assert denied.reason == "busy"
    assert tats(dbs) == before  # global and egress buckets were NOT charged for the denied call


def test_refund_gives_back_exactly_one_interval(dbs: Any) -> None:
    dbs.hot.write_sync(lambda conn: reserve_in(conn, SPECS, NOW, 4000))
    grant = dbs.hot.write_sync(lambda conn: reserve_in(conn, SPECS, NOW, 4000))
    assert isinstance(grant, Grant)
    dbs.hot.write_sync(lambda conn: buckets.refund_in(conn, grant, NOW))
    assert tats(dbs) == {"global": NOW + 100, "egress:direct": NOW + 200, "plain:e": NOW + 1000}


def test_refund_after_others_moved_on_gives_back_one_interval(dbs: Any) -> None:
    grant = dbs.hot.write_sync(lambda conn: reserve_in(conn, SPECS, NOW, 4000))
    assert isinstance(grant, Grant)
    dbs.hot.write_sync(lambda conn: reserve_in(conn, SPECS, NOW, 4000))  # a later reservation depends on ours
    dbs.hot.write_sync(lambda conn: buckets.refund_in(conn, grant, NOW))
    assert tats(dbs) == {"global": NOW + 1000, "egress:direct": NOW + 1000, "plain:e": NOW + 1000}


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
    specs = (BucketSpec("plain:e", 60, 1),)
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
    assert set(tats(dbs)) == {"global", "egress:direct", "plain:e"}


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
    plain = states["plain:e"]
    assert plain.per_min == pytest.approx(60)
    assert plain.burst == 1
    assert plain.fill == 1.0
    assert plain.next_free_in_ms == pytest.approx(3000)
    # Global (600/min, burst 30, capacity 3000 ms) took slots at NOW, NOW+1000, NOW+2000: TAT = NOW + 2100.
    assert states["global"].fill == pytest.approx(2100 / 3000)


def test_bucket_states_use_window_spacing_and_leave_meters_out(dbs: Any) -> None:
    specs = (BucketSpec("endpoint:e", 60, 1),)
    for _ in range(3):
        dbs.hot.write_sync(lambda conn: reserve_in(conn, specs, NOW, 10_000))
    states = dbs.hot.read_sync(lambda conn: buckets.bucket_states(conn, NOW))
    assert [state.key for state in states] == ["endpoint:e"]  # the meter row is not a bucket
    (endpoint,) = states
    assert (endpoint.per_min, endpoint.burst, endpoint.fill) == (pytest.approx(60), 1, 1.0)
    assert endpoint.next_free_in_ms == pytest.approx(3 * 61_000 / 60)  # the window bucket's spacing, not 1000 ms


# --- window buckets: rate plus burst inside one window (finding LOAD-1) -----------------------------------------------


def test_window_keys() -> None:
    assert buckets.is_windowed("endpoint:games.roblox.com/v1/games")
    assert buckets.is_windowed("host:games.roblox.com")
    for key in ("global", "egress:direct", "egress:credential:probe", "plain:e", "meter:endpoint:x"):
        assert not buckets.is_windowed(key), key
    assert buckets.meter_key("endpoint:x") == "meter:endpoint:x"


@pytest.mark.parametrize(
    ("per_min", "burst", "effective_burst", "interval"),
    [
        (120, 10, 10, 61_000 / 111),  # the endpoint default: 10 at once, then 109.2 a minute
        (240, 15, 15, 61_000 / 226),  # the host default
        (60, 1, 1, 61_000 / 60),
        (58.8, 4, 4, 61_000 / 55),  # a fractional limit: a window holds 58 whole calls
        (6, 10, 6, 61_000.0),  # a burst can never be larger than the whole window
        (0.5, 1, 1, 61_000.0),  # below one a minute: still one call per window
    ],
)
def test_window_bucket_spacing(per_min: float, burst: int, effective_burst: int, interval: float) -> None:
    spec = BucketSpec("endpoint:e", per_min, burst)
    assert spec.windowed
    assert spec.effective_burst == effective_burst
    assert spec.interval_ms == pytest.approx(interval)
    assert spec.tolerance_ms == pytest.approx((effective_burst - 1) * interval)
    assert spec.capacity_ms == pytest.approx(effective_burst * interval)
    assert spec.rate_per_s == pytest.approx(per_min / 60)  # the configured rate is what the row stores
    assert spec.steady_per_min == pytest.approx(60_000 / interval)
    plain = BucketSpec("egress:direct", per_min, burst)  # Roxy's own ceilings keep the plan 7.3 formula
    assert not plain.windowed
    assert plain.interval_ms == pytest.approx(60_000 / per_min)
    assert plain.effective_burst == burst


def booked(spec: BucketSpec, arrivals: list[float]) -> list[float]:
    """Slot times GCRA gives to calls arriving at `arrivals` (sorted, nobody gives up)."""
    tat = 0.0
    slots = []
    for at in sorted(arrivals):
        slot = gcra_earliest_ms(tat, spec, at)
        tat = gcra_advance_ms(tat, spec, slot)
        slots.append(slot)
    return slots


def busiest(slots: list[float], span_ms: float) -> int:
    """The most slots any closed span of `span_ms` holds (Roblox counting a minute, both ends included)."""
    best, first = 0, 0
    for index, at in enumerate(slots):
        while at - slots[first] > span_ms:
            first += 1
        best = max(best, index - first + 1)
    return best


def test_plain_gcra_lets_rate_plus_burst_into_one_minute() -> None:
    """Why window buckets exist: plain GCRA at 120 a minute, burst 10, puts 130 calls in one closed minute (129 in
    one rolling minute), which a Roblox limit of 120 a minute refuses. The window bucket puts 119 there, and 120
    into its rolling 61 s window (the margin)."""
    arrivals = [float(NOW)] * 400
    assert busiest(booked(BucketSpec("global", 120, 10), arrivals), 60_000) == 130
    window = booked(BucketSpec("endpoint:e", 120, 10), arrivals)
    assert busiest(window, 60_000) == 119
    assert busiest(window, 61_000 - 0.01) == 120


@given(
    per_min=st.floats(min_value=1, max_value=400, allow_nan=False),
    burst=st.integers(min_value=1, max_value=40),
    gaps=st.lists(st.floats(min_value=0, max_value=5_000, allow_nan=False), min_size=1, max_size=600),
)
@settings(max_examples=200, deadline=None)
def test_property_window_bucket_never_overfills_a_minute(per_min: float, burst: int, gaps: list[float]) -> None:
    """Any arrival pattern: no closed span of 60 s holds more than `per_min` (rounded down) granted calls, and
    neither does any rolling window of 61 s (the margin)."""
    spec = BucketSpec("endpoint:e", per_min, burst)
    arrivals, at = [], float(NOW)
    for gap in gaps:
        at += gap
        arrivals.append(at)
    slots = booked(spec, arrivals)
    assert busiest(slots, 60_000) <= spec.window_calls
    assert busiest(slots, 61_000 - 0.01) <= spec.window_calls


# --- window meters ----------------------------------------------------------------------------------------------------


def test_window_meter_counts_rolls_and_estimates() -> None:
    meter = buckets.WindowMeter(1000.0)
    for k in range(30):
        meter = meter.counted(1000 + 1000 * k)  # 30 calls, one a second, from the meter's first call
    assert (meter.start_ms, meter.current, meter.previous) == (1000.0, 30, 0)
    assert meter.estimate(31_000) == 30  # a cold start measures exactly
    meter = meter.counted(61_000)  # the first window ended at 61,000: it becomes the previous one
    assert (meter.start_ms, meter.current, meter.previous) == (61_000.0, 1, 30)
    assert meter.estimate(91_000) == pytest.approx(1 + 30 * 0.5)  # half of the previous window is still inside
    assert meter.estimate(121_000) == 1  # the previous window is fully outside the last minute
    assert meter.estimate(181_000) == 0  # two windows of silence: nothing left
    assert meter.counted(200_000) == buckets.WindowMeter(200_000.0, 1, 0)


def test_window_meter_uncounts_a_refunded_call() -> None:
    meter = buckets.WindowMeter(1000.0, 5, 7)
    assert meter.uncounted(2000) == buckets.WindowMeter(1000.0, 4, 7)  # in the current window
    assert meter.uncounted(500) == buckets.WindowMeter(1000.0, 5, 6)  # in the previous window
    assert meter.uncounted(-70_000) == meter  # aged out: nothing to give back
    assert buckets.WindowMeter(1000.0, 0, 0).uncounted(2000) == buckets.WindowMeter(1000.0, 0, 0)
    assert buckets.WindowMeter(1000.0, 1, 0).uncounted(900) == buckets.WindowMeter(1000.0, 0, 0)  # booked early


WINDOW_SPECS = (
    BucketSpec("global", 600, 30),
    BucketSpec("egress:direct", 300, 20),
    BucketSpec("host:h", 240, 15),
    BucketSpec("endpoint:h/e", 120, 10),
)


def test_reservation_counts_window_buckets_and_refund_uncounts(dbs: Any) -> None:
    grants = [dbs.hot.write_sync(lambda conn: reserve_in(conn, WINDOW_SPECS, NOW, 4000)) for _ in range(3)]
    assert all(isinstance(grant, Grant) for grant in grants)
    meters = dbs.hot.read_sync(lambda conn: buckets.read_meters(conn, ["host:h", "endpoint:h/e", "global"]))
    assert meters == {
        "host:h": buckets.WindowMeter(float(NOW), 3, 0),
        "endpoint:h/e": buckets.WindowMeter(float(NOW), 3, 0),
    }  # only window buckets have meters
    last = grants[-1]
    assert isinstance(last, Grant)
    dbs.hot.write_sync(lambda conn: buckets.refund_in(conn, last, NOW))
    observed = dbs.hot.read_sync(
        lambda conn: buckets.observed_calls(conn, ["global", "host:h", "endpoint:h/e", "endpoint:other"], NOW + 5000)
    )
    assert observed == {"host:h": 2, "endpoint:h/e": 2}  # unknown and plain keys are absent


def test_a_denied_reservation_counts_nothing(dbs: Any) -> None:
    specs = (BucketSpec("endpoint:h/e", 60, 1),)
    dbs.hot.write_sync(lambda conn: reserve_in(conn, specs, NOW, 4000))
    denied = dbs.hot.write_sync(lambda conn: reserve_in(conn, specs, NOW, 0))
    assert isinstance(denied, Denial)
    assert dbs.hot.read_sync(lambda conn: buckets.read_meters(conn, ["endpoint:h/e"]))["endpoint:h/e"].current == 1


def test_window_backlog_tat() -> None:
    cut = BucketSpec("endpoint:h/e", 42.7, 3)  # 42 in any minute: interval 61,000 / 40 = 1525 ms
    meter = buckets.WindowMeter(float(NOW), 61, 0)  # 61 calls since NOW (the 429 came 28 s later)
    # Paced at the new limit, 61 calls from NOW take 61 intervals: the next call waits for that backlog.
    assert buckets.window_backlog_tat(meter, cut, NOW + 28_000) == pytest.approx(NOW + 61 * 1525)
    one = buckets.WindowMeter(float(NOW), 1, 0)
    assert buckets.window_backlog_tat(one, cut, NOW + 30_000) == pytest.approx(NOW + 1525)  # placed at its real time
    rolled = buckets.WindowMeter(float(NOW), 30, 0)
    assert buckets.window_backlog_tat(rolled, cut, NOW + 200_000) == 0.0  # two windows ago: nothing left


def test_a_lowered_limit_holds_for_windows_that_began_before_it(dbs: Any) -> None:
    """After a cut, the calls made at the old pace are still in Roblox's minute: the first reservation under the
    lower limit starts from their backlog, so every minute that holds a new call holds at most the new limit."""
    old = (BucketSpec("endpoint:h/e", 120, 10),)
    sent = []
    for k in range(61):  # 61 calls in 28 s at the old limit (the replay's busiest endpoint, packed tighter)
        grant = dbs.hot.write_sync(lambda conn, k=k: reserve_in(conn, old, NOW + 460 * k, 60_000))
        assert isinstance(grant, Grant)
        sent.append(grant.slot_ms)
    new = (BucketSpec("endpoint:h/e", 42.7, 3),)
    fresh = []
    at: float = NOW + 59_000  # the cooldown is over
    for _ in range(60):
        grant = dbs.hot.write_sync(lambda conn, at=at: reserve_in(conn, new, int(at), 120_000))
        assert isinstance(grant, Grant)
        fresh.append(grant.slot_ms)
        at = max(at, grant.slot_ms)
    assert fresh[0] >= NOW + 61 * 1525 - 2 * 1525 - 1  # it waited for the backlog, not only for the cooldown
    calls = sorted(sent + fresh)
    for slot in fresh:
        assert sum(1 for t in calls if slot - 60_000 <= t <= slot) <= 42  # every minute with a new call: at most 42


def test_a_raised_limit_starts_from_its_tat(dbs: Any) -> None:
    slow = (BucketSpec("endpoint:h/e", 60, 1),)
    dbs.hot.write_sync(lambda conn: reserve_in(conn, slow, NOW, 4000))
    fast = (BucketSpec("endpoint:h/e", 120, 10),)
    grant = dbs.hot.write_sync(lambda conn: reserve_in(conn, fast, NOW + 100, 4000))
    assert isinstance(grant, Grant)
    assert grant.slot_ms == NOW + 100  # no backlog: only a lower limit looks back


def test_routing_reads_the_same_paced_tats_as_the_reservation(dbs: Any) -> None:
    old = (BucketSpec("endpoint:h/e", 120, 10),)
    for k in range(30):
        dbs.hot.write_sync(lambda conn, k=k: reserve_in(conn, old, NOW + 600 * k, 60_000))
    new = (BucketSpec("global", 600, 30), BucketSpec("endpoint:h/e", 30, 2))
    at = NOW + 20_000
    stored = dbs.hot.read_sync(lambda conn: buckets.read_tats(conn, ["endpoint:h/e"]))["endpoint:h/e"]
    paced = dbs.hot.read_sync(lambda conn: buckets.paced_tats(conn, new, at))
    assert paced["endpoint:h/e"] > stored  # the lowered limit's backlog, which the stored TAT does not show
    grant = dbs.hot.write_sync(lambda conn: reserve_in(conn, new, at, 120_000))
    assert isinstance(grant, Grant)
    assert grant.slot_ms == pytest.approx(paced["endpoint:h/e"] - new[1].tolerance_ms)  # routing saw this slot


def test_idle_meters_are_pruned_like_idle_buckets(dbs: Any) -> None:
    from roxy.storage import retention

    dbs.hot.write_sync(lambda conn: reserve_in(conn, WINDOW_SPECS, NOW, 4000))
    later_s = NOW / 1000 + 2 * 3600
    policy = retention.RetentionPolicy()
    dbs.hot.write_sync(lambda conn: retention.prune_upstream_buckets(conn, later_s, policy, 1000))
    assert read_rows(dbs.hot, "SELECT bucket_key FROM upstream_bucket") == []
