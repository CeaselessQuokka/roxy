"""The circuit breaker state machine (plan 7.10) and its fleet-wide half-open probe lease."""

from __future__ import annotations

from typing import Any

import pytest
from upstream_fakes import FakeSettings, read_rows

from roxy.upstream import breaker
from roxy.upstream.breaker import BreakerPolicy, BreakerRow, BreakerState

POLICY = BreakerPolicy.from_settings(FakeSettings())
KEY = "endpoint:games.roblox.com/v1/games:direct"
T0 = 1_760_000_000.0


def fail(row: BreakerRow | None, at: float) -> tuple[BreakerRow, Any]:
    return breaker.record_failure(row, KEY, at, POLICY)


def test_policy_defaults() -> None:
    assert (POLICY.failure_threshold, POLICY.window_s, POLICY.failure_ratio, POLICY.open_s) == (5, 30, 0.5, 30)
    assert POLICY.max_open_s == 600
    assert POLICY.probe_ttl_s == 20  # request_timeout + 5


def test_opens_after_threshold_failures_in_window() -> None:
    row: BreakerRow | None = None
    for i in range(4):
        row, transition = fail(row, T0 + i)
        assert transition is None
        assert breaker.effective_state(row, T0 + i) is BreakerState.CLOSED
    row, transition = fail(row, T0 + 4)
    assert transition is not None
    assert (transition.from_state, transition.to_state, transition.reason) == (
        BreakerState.CLOSED,
        BreakerState.OPEN,
        "failure_threshold",
    )
    assert breaker.effective_state(row, T0 + 5) is BreakerState.OPEN
    assert row.half_open_at == T0 + 4 + 30


def test_ratio_must_exceed_half() -> None:
    row: BreakerRow | None = None
    row, _ = fail(row, T0)
    for i in range(5):
        updated = breaker.record_success(row, T0 + 0.1 * (i + 1), POLICY)
        assert updated is not None
        row = updated
    for i in range(4):
        row, transition = fail(row, T0 + 1 + i)
    # 5 failures and 5 successes: ratio 0.5 is not above 0.5, so it stays closed.
    assert transition is None
    assert row.failures == 5
    assert breaker.effective_state(row, T0 + 6) is BreakerState.CLOSED
    row, transition = fail(row, T0 + 6)
    assert transition is not None  # 6 of 11 > 0.5


def test_window_rolls_over() -> None:
    row: BreakerRow | None = None
    for i in range(4):
        row, _ = fail(row, T0 + i)
    row, transition = fail(row, T0 + 31)  # the old window ended: counting starts again
    assert transition is None
    assert row is not None
    assert row.failures == 1


def test_success_on_a_healthy_breaker_writes_nothing() -> None:
    assert breaker.record_success(None, T0, POLICY) is None
    clean = BreakerRow(KEY, window_start=T0)
    assert breaker.record_success(clean, T0 + 1, POLICY) is None


def test_trip_opens_at_once_for_the_cooldown() -> None:
    row, transition = breaker.trip(None, KEY, T0, 45)
    assert transition is not None
    assert transition.reason == "rate_limited"
    assert row.half_open_at == T0 + 45
    admission = breaker.admission(row, T0 + 10)
    assert (admission.allowed, admission.retry_in_s) == (False, 35)
    longer, again = breaker.trip(row, KEY, T0 + 10, 60)
    assert again is None  # extended while open: no new transition
    assert longer.half_open_at == T0 + 70
    same, nothing = breaker.trip(longer, KEY, T0 + 11, 5)
    assert nothing is None
    assert same.half_open_at == T0 + 70


def test_half_open_admits_one_probe() -> None:
    row, _ = breaker.trip(None, KEY, T0, 30)
    assert breaker.effective_state(row, T0 + 30) is BreakerState.HALF_OPEN
    admission = breaker.admission(row, T0 + 30)
    assert (admission.allowed, admission.needs_probe_lease) == (True, True)


def test_probe_success_closes() -> None:
    row, _ = breaker.trip(None, KEY, T0, 30)
    closed, transition = breaker.probe_result(row, KEY, T0 + 31, False, POLICY)
    assert closed.state is BreakerState.CLOSED
    assert transition is not None
    assert transition.to_state is BreakerState.CLOSED
    assert breaker.admission(closed, T0 + 31).allowed is True


def test_probe_failure_reopens_doubled_and_capped() -> None:
    row, _ = breaker.trip(None, KEY, T0, 30)
    now = T0 + 30
    expected = [60, 120, 240, 480, 600, 600]
    for want in expected:
        row, transition = breaker.probe_result(row, KEY, now, True, POLICY)
        assert transition is not None
        assert transition.reason == "probe_failed"
        assert row.open_duration_s == want
        now = row.half_open_at or now


def test_failures_while_open_are_ignored() -> None:
    row, _ = breaker.trip(None, KEY, T0, 30)
    again, transition = fail(row, T0 + 1)
    assert transition is None
    assert again == row


def test_open_row_without_reopening_time_is_probed() -> None:
    odd = BreakerRow(KEY, state=BreakerState.OPEN, opened_at=T0, half_open_at=None)
    assert breaker.effective_state(odd, T0) is BreakerState.HALF_OPEN


def test_breaker_keys() -> None:
    assert breaker.breaker_keys("games.roblox.com", "games.roblox.com/v1/x", "rotator") == (
        "endpoint:games.roblox.com/v1/x:rotator",
        "host:games.roblox.com:rotator",
    )


def test_save_load_roundtrip(dbs: Any) -> None:
    row, _ = breaker.trip(None, KEY, T0 + 0.25, 30.5)
    dbs.hot.write_sync(lambda c: breaker.save(c, row))
    loaded = dbs.hot.read_sync(lambda c: breaker.load(c, [KEY, "missing"]))
    assert loaded == {KEY: row}  # sub-second precision survives the REAL columns


def test_probe_lease_is_fleet_wide_single(dbs: Any) -> None:
    now_ms = int(T0 * 1000)
    assert dbs.hot.write_sync(lambda c: breaker.try_acquire_probe(c, KEY, "worker-a:1", now_ms, 20)) is True
    assert dbs.hot.write_sync(lambda c: breaker.try_acquire_probe(c, KEY, "worker-b:1", now_ms + 5, 20)) is False
    remaining = dbs.hot.read_sync(lambda c: breaker.probe_lease_remaining_s(c, KEY, now_ms + 5000))
    assert remaining == pytest.approx(15)
    dbs.hot.write_sync(lambda c: breaker.release_probe(c, KEY, "worker-a:1"))
    assert dbs.hot.write_sync(lambda c: breaker.try_acquire_probe(c, KEY, "worker-b:1", now_ms + 6, 20)) is True
    # A probe holder that never reports back frees the lease when it expires.
    assert dbs.hot.write_sync(lambda c: breaker.try_acquire_probe(c, KEY, "worker-c:1", now_ms + 21_000, 20)) is True


def test_reset_and_snapshot(dbs: Any) -> None:
    row, _ = breaker.trip(None, KEY, T0, 30)
    dbs.hot.write_sync(lambda c: breaker.save(c, row))
    dbs.hot.write_sync(lambda c: breaker.try_acquire_probe(c, KEY, "w", int(T0 * 1000), 20))
    view = dbs.hot.read_sync(lambda c: breaker.snapshot(c, T0 + 10))
    assert view == [{"key": KEY, "state": "open", "failures": 0, "successes": 0, "reopens_in_s": 20, "open_s": 30}]
    assert dbs.hot.write_sync(breaker.reset_all) == 1
    assert read_rows(dbs.hot, "SELECT key FROM breaker") == []
    assert read_rows(dbs.hot, "SELECT name FROM lease WHERE name LIKE 'brk:%'") == []
