"""Retry-After and x-ratelimit parsing (a corpus), cooldown lengths, shared rows, escalation, distinct exits."""

from __future__ import annotations

import random
from datetime import UTC, datetime
from email.utils import format_datetime
from typing import Any

import pytest
from upstream_fakes import FakeSettings, read_rows

from roxy.core.reasons import Egress
from roxy.upstream import cooldowns
from roxy.upstream.cooldowns import CooldownPolicy, CooldownSource, RateLimitInfo

NOW_S = 1_760_000_000.0
NOW_MS = int(NOW_S * 1000)


def http_date(offset_s: float) -> str:
    return format_datetime(datetime.fromtimestamp(NOW_S + offset_s, tz=UTC), usegmt=True)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("30", 30.0),
        (" 30 ", 30.0),
        ("0", 0.0),
        ("1.5", 1.5),
        ("120", 120.0),
        ("99999999", 99999999.0),  # absurd, but a number: the clamp handles it
        (http_date(45), 45.0),
        (http_date(-300), 0.0),  # a date in the past means "now"
        ("Sunday, 06-Nov-94 08:49:37 GMT", 0.0),  # obsolete RFC 850 form, long past
        ("Sun Nov  6 08:49:37 1994", 0.0),  # asctime form, long past
        ("", None),
        ("   ", None),
        (None, None),
        ("-5", None),
        ("soon", None),
        ("30s", None),
        ("1e3", None),
        ("Thu, 99 Foo 2025 99:99:99 GMT", None),
        ("0x1E", None),
    ],
)
def test_retry_after_corpus(value: str | None, expected: float | None) -> None:
    parsed = cooldowns.parse_retry_after(value, NOW_S)
    if expected is None:
        assert parsed is None
    else:
        assert parsed == pytest.approx(expected, abs=1.0)


def test_retry_after_http_date_is_exact() -> None:
    assert (
        cooldowns.parse_retry_after(
            "Wed, 21 Oct 2015 07:28:00 GMT", datetime(2015, 10, 21, 7, 27, tzinfo=UTC).timestamp()
        )
        == 60
    )


@pytest.mark.parametrize(
    ("headers", "limit", "remaining", "reset"),
    [
        ({"x-ratelimit-limit": "60", "x-ratelimit-remaining": "0", "x-ratelimit-reset": "12"}, 60, 0, 12),
        ({"X-RateLimit-Remaining": "5"}, None, 5, None),
        ({"x-ratelimit-limit": "30, 30;w=60", "x-ratelimit-remaining": "29"}, 30, 29, None),
        ({"x-ratelimit-reset": str(int(NOW_S) + 40)}, None, None, 40),  # an absolute Unix time
        ({"x-ratelimit-remaining": "lots", "x-ratelimit-limit": "10"}, 10, None, None),
    ],
)
def test_ratelimit_headers(
    headers: dict[str, str], limit: float | None, remaining: float | None, reset: float | None
) -> None:
    info = cooldowns.parse_ratelimit_headers(headers, NOW_S)
    assert info is not None
    assert (info.limit, info.remaining) == (limit, remaining)
    if reset is None:
        assert info.reset_s is None
    else:
        assert info.reset_s == pytest.approx(reset)


def test_ratelimit_absent() -> None:
    assert cooldowns.parse_ratelimit_headers({"content-type": "application/json"}, NOW_S) is None
    assert RateLimitInfo(None, 0, 5).exhausted is True
    assert RateLimitInfo(None, 1, 5).exhausted is False
    assert RateLimitInfo(None, None, 5).exhausted is False


POLICY = CooldownPolicy.from_settings(FakeSettings())


def test_policy_from_catalog_defaults() -> None:
    assert (POLICY.default_s, POLICY.min_s, POLICY.max_s) == (30, 1, 600)
    assert POLICY.credential_default_s == 60
    assert (POLICY.host_escalation_endpoints, POLICY.host_escalation_window_s) == (3, 60)
    assert (POLICY.rotator_distinct_exits, POLICY.rotator_window_s) == (3, 60)


@pytest.mark.parametrize(("retry_after", "expected"), [(30, 30), (0, 1), (0.2, 1), (5000, 600), (600, 600)])
def test_retry_after_is_clamped(retry_after: float, expected: float) -> None:
    seconds, source = cooldowns.cooldown_duration(retry_after, None, 1, POLICY, random.Random(1))
    assert (seconds, source) == (expected, CooldownSource.RETRY_AFTER)


def test_ratelimit_reset_used_when_exhausted() -> None:
    seconds, source = cooldowns.cooldown_duration(None, RateLimitInfo(60, 0, 12), 1, POLICY, random.Random(1))
    assert (seconds, source) == (12, CooldownSource.RATELIMIT_RESET)
    # Retry-After wins over the rate limit headers.
    seconds, source = cooldowns.cooldown_duration(7, RateLimitInfo(60, 0, 12), 1, POLICY, random.Random(1))
    assert (seconds, source) == (7, CooldownSource.RETRY_AFTER)


@pytest.mark.parametrize(("repeat", "base"), [(1, 30), (2, 60), (3, 120), (4, 240), (5, 480), (6, 600), (40, 600)])
def test_default_backoff_for_repeated_429s(repeat: int, base: float) -> None:
    rng = random.Random(repeat)
    for _ in range(20):
        seconds, source = cooldowns.cooldown_duration(None, None, repeat, POLICY, rng)
        assert source is CooldownSource.DEFAULT
        assert base <= seconds <= min(600, base * 1.1)  # up to 10 % jitter, never past the max


def test_credential_default_is_longer() -> None:
    seconds, _ = cooldowns.cooldown_duration(None, None, 1, POLICY, random.Random(3), credential=True)
    assert 60 <= seconds <= 66


def test_keys() -> None:
    assert (
        cooldowns.endpoint_key("games.roblox.com/v1/games", Egress.DIRECT)
        == "endpoint:games.roblox.com/v1/games:direct"
    )
    assert cooldowns.host_key("games.roblox.com", "rotator") == "host:games.roblox.com:rotator"
    assert cooldowns.egress_key(Egress.CREDENTIAL) == "egress:credential"
    assert cooldowns.keys_for("h.roblox.com", "h.roblox.com/x", Egress.CREDENTIAL)[-1] == "credential"
    assert "credential" not in cooldowns.keys_for("h.roblox.com", "h.roblox.com/x", Egress.DIRECT)


def test_repeat_count() -> None:
    assert cooldowns.repeat_count(None, NOW_MS, POLICY) == 1
    active = cooldowns.CooldownRow("k", NOW_MS + 1000, "default", NOW_S, 2)
    assert cooldowns.repeat_count(active, NOW_MS, POLICY) == 2  # same episode: no growth
    ended = cooldowns.CooldownRow("k", NOW_MS - 10_000, "default", NOW_S, 2)
    assert cooldowns.repeat_count(ended, NOW_MS, POLICY) == 3
    long_ago = cooldowns.CooldownRow("k", NOW_MS - 601_000, "default", NOW_S, 5)
    assert cooldowns.repeat_count(long_ago, NOW_MS, POLICY) == 1


def test_open_cooldown_never_shortens(dbs: Any) -> None:
    first = dbs.hot.write_sync(lambda c: cooldowns.open_cooldown(c, "k", 30, CooldownSource.RETRY_AFTER, NOW_MS, 1))
    assert first.was_active is False
    assert first.row.until_ms == NOW_MS + 30_000
    shorter = dbs.hot.write_sync(lambda c: cooldowns.open_cooldown(c, "k", 5, CooldownSource.DEFAULT, NOW_MS + 1000, 1))
    assert shorter.was_active is True
    assert shorter.row.until_ms == NOW_MS + 30_000
    assert shorter.row.source == "retry_after"
    longer = dbs.hot.write_sync(lambda c: cooldowns.open_cooldown(c, "k", 60, "default", NOW_MS + 2000, 2))
    assert longer.row.until_ms == NOW_MS + 62_000
    active = dbs.hot.read_sync(lambda c: cooldowns.read_active(c, ["k", "other"], NOW_MS + 61_000))
    assert list(active) == ["k"]
    assert active["k"].remaining_s(NOW_MS + 61_000) == pytest.approx(1)
    assert dbs.hot.read_sync(lambda c: cooldowns.read_active(c, ["k"], NOW_MS + 62_000)) == {}


def open_endpoint(dbs: Any, template: str, egress: Egress, at_ms: int) -> None:
    key = cooldowns.endpoint_key(template, egress)
    dbs.hot.write_sync(lambda c: cooldowns.open_cooldown(c, key, 30, "retry_after", at_ms, 1))


def test_host_escalation_evidence(dbs: Any) -> None:
    open_endpoint(dbs, "games.roblox.com/v1/a", Egress.DIRECT, NOW_MS - 70_000)  # outside the 60 s window
    open_endpoint(dbs, "games.roblox.com/v1/b", Egress.DIRECT, NOW_MS - 10_000)
    open_endpoint(dbs, "games.roblox.com/v1/c", Egress.DIRECT, NOW_MS)
    open_endpoint(dbs, "games.roblox.com/v1/d", Egress.ROTATOR, NOW_MS)  # another egress
    open_endpoint(dbs, "gamesx.roblox.com/v1/e", Egress.DIRECT, NOW_MS)  # another host sharing a prefix
    count = dbs.hot.read_sync(
        lambda c: cooldowns.distinct_templates_cooling(c, "games.roblox.com", "direct", NOW_S - 60)
    )
    assert count == 2
    hosts = dbs.hot.read_sync(lambda c: cooldowns.distinct_hosts_cooling(c, Egress.DIRECT, NOW_S - 60))
    assert hosts == 2


def test_rotator_distinct_exit_rule(dbs: Any) -> None:
    def record(exit_id: str, at_ms: int) -> int:
        return dbs.hot.write_sync(lambda c: cooldowns.record_rotator_exit_429(c, "t/x", exit_id, at_ms, 60))

    assert record("s1", NOW_MS) == 1
    assert record("s1", NOW_MS + 1000) == 1  # the same exit again is still one exit
    assert record("s2", NOW_MS + 2000) == 2
    assert record("s3", NOW_MS + 3000) == 3
    assert (
        dbs.hot.write_sync(lambda c: cooldowns.record_rotator_exit_429(c, "t/y", "s1", NOW_MS, 60)) == 1
    )  # per template
    assert record("s4", NOW_MS + 62_500) == 2  # s1 and s2 expired from the window; s3 and s4 remain


def test_clear_all(dbs: Any) -> None:
    open_endpoint(dbs, "games.roblox.com/v1/a", Egress.DIRECT, NOW_MS)
    dbs.hot.write_sync(lambda c: cooldowns.record_rotator_exit_429(c, "t", "s1", NOW_MS, 60))
    assert dbs.hot.write_sync(cooldowns.clear_all) == 1
    assert read_rows(dbs.hot, "SELECT key FROM cooldown") == []
    assert read_rows(dbs.hot, "SELECT name FROM lease WHERE name LIKE 'r429:%'") == []


def test_active_rows(dbs: Any) -> None:
    open_endpoint(dbs, "games.roblox.com/v1/a", Egress.DIRECT, NOW_MS)
    rows = dbs.hot.read_sync(lambda c: cooldowns.active_rows(c, NOW_MS + 1))
    assert [row.key for row in rows] == ["endpoint:games.roblox.com/v1/a:direct"]
    assert dbs.hot.read_sync(lambda c: cooldowns.active_rows(c, NOW_MS + 31_000)) == []
