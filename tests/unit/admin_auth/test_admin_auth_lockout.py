"""Lockout bookkeeping (plan 9.5): keys, the sliding window, release and clear, the global guard, the row bound."""

from __future__ import annotations

from typing import Any

import pytest

from roxy.admin.auth import lockout


def test_ip_prefix_groups_networks() -> None:
    assert lockout.ip_prefix("203.0.113.77") == "203.0.113.0/24"
    assert lockout.ip_prefix("2001:db8:1:2:3:4:5:6") == "2001:db8:1:2::/64"
    assert lockout.ip_prefix("::ffff:203.0.113.9") == "203.0.113.0/24"
    assert lockout.ip_prefix("garbage") == "garbage"


def test_lockout_key_hashes_the_username_case_insensitively() -> None:
    key = lockout.lockout_key("Owner", "203.0.113.5")
    assert key == lockout.lockout_key("owner ", "203.0.113.200")
    assert "owner" not in key.lower().split("|", 1)[1]
    assert key != lockout.lockout_key("other", "203.0.113.5")
    assert key != lockout.lockout_key("owner", "203.0.114.5")


def test_reserve_counts_before_checking_and_refuses_at_the_limit(dbs: Any) -> None:
    key = lockout.lockout_key("owner", "203.0.113.5")
    now = 1_000_000
    results = [dbs.hot.write_sync(lambda c: lockout.reserve(c, key, now, 5, 600)) for _ in range(5)]
    assert all(r.allowed for r in results)
    assert [r.failures_before for r in results] == [0, 1, 2, 3, 4]
    assert results[-1].last_chance
    assert not results[-2].last_chance
    refused = dbs.hot.write_sync(lambda c: lockout.reserve(c, key, now + 10, 5, 600))
    assert not refused.allowed
    assert refused.retry_after_s == 590
    assert lockout.LOCKOUT_TEXT.format(seconds=590) == "Too many attempts; try again in 590 seconds."


def test_window_slides_one_failure_at_a_time(dbs: Any) -> None:
    key = lockout.lockout_key("owner", "203.0.113.5")
    for offset in range(5):
        dbs.hot.write_sync(lambda c, o=offset: lockout.reserve(c, key, 1_000_000 + o * 100, 5, 600))
    # At 1_000_599 the first failure (at 1_000_000) is still inside the window; at 1_000_600 it has left it.
    assert not dbs.hot.write_sync(lambda c: lockout.reserve(c, key, 1_000_599, 5, 600)).allowed
    allowed = dbs.hot.write_sync(lambda c: lockout.reserve(c, key, 1_000_600, 5, 600))
    assert allowed.allowed
    assert allowed.failures_before == 4


def test_release_and_clear(dbs: Any) -> None:
    key = lockout.lockout_key("owner", "203.0.113.5")
    first = dbs.hot.write_sync(lambda c: lockout.reserve(c, key, 1000, 5, 600))
    dbs.hot.write_sync(lambda c: lockout.reserve(c, key, 1000, 5, 600))
    dbs.hot.write_sync(lambda c: lockout.release(c, first.subject))
    assert dbs.hot.read_sync(lambda c: lockout.failures(c, key, 1000, 600)) == 1
    dbs.hot.write_sync(lambda c: lockout.clear(c, key))
    assert dbs.hot.read_sync(lambda c: lockout.failures(c, key, 1000, 600)) == 0


def test_global_guard_engages_once_per_minute_window(dbs: Any) -> None:
    ticks = [dbs.hot.write_sync(lambda c: lockout.global_tick(c, 5000, 3)) for _ in range(5)]
    assert [t.engaged for t in ticks] == [False, False, False, True, True]
    assert [t.just_engaged for t in ticks] == [False, False, False, True, False]
    later = dbs.hot.write_sync(lambda c: lockout.global_tick(c, 5060, 3))
    assert later.count == 1
    assert not later.engaged
    stepped_back = dbs.hot.write_sync(lambda c: lockout.global_tick(c, 5059, 3))
    assert stepped_back.count == 2  # a clock that steps back a little stays in the window


def test_rows_are_bounded(dbs: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lockout, "MAX_TRACKED_LOGIN_IPS", 150)
    for i in range(300):
        key = lockout.lockout_key(f"user{i}", "203.0.113.5")
        dbs.hot.write_sync(lambda c, k=key, n=i: lockout.reserve(c, k, 1000 + n, 5, 600))
    total = dbs.hot.read_sync(lambda c: c.execute("SELECT count(*) FROM login_failures").fetchone()[0])
    assert total <= 150


def test_top_prefixes(dbs: Any) -> None:
    for ip in ("203.0.113.1", "203.0.113.2", "198.51.100.1"):
        key = lockout.lockout_key("owner", ip)
        dbs.hot.write_sync(lambda c, k=key: lockout.reserve(c, k, 1000, 5, 600))
    top = dbs.hot.read_sync(lambda c: lockout.top_prefixes(c, 1000, 600))
    assert top[0] == ("203.0.113.0/24", 2)
