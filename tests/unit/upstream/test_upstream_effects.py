"""Side effects of a finished call in hot.db (plan 7.5, 7.9, 7.10), row by row, without any network."""

from __future__ import annotations

import random
from typing import Any

import pytest
from upstream_fakes import FakeSettings, read_rows

from roxy.core.reasons import Egress
from roxy.upstream import breaker
from roxy.upstream.adaptive import AttributionKind
from roxy.upstream.breaker import BreakerPolicy, BreakerRow, BreakerState
from roxy.upstream.cooldowns import CooldownPolicy, RateLimitInfo
from roxy.upstream.effects import CallFacts, EffectsConfig, apply_call_outcome, should_record
from roxy.upstream.status import AttemptKind

CONFIG = EffectsConfig(
    cooldown=CooldownPolicy.from_settings(FakeSettings()), breaker=BreakerPolicy.from_settings(FakeSettings())
)
NOW_MS = 1_760_000_000_000
HOST = "games.roblox.com"
TEMPLATE = "games.roblox.com/v1/games"


def facts(kind: AttemptKind, egress: Egress = Egress.DIRECT, template: str = TEMPLATE, **kw: Any) -> CallFacts:
    return CallFacts(egress=egress, host=template.split("/", 1)[0], template=template, kind=kind, holder="h", **kw)


def apply(dbs: Any, call: CallFacts, at_ms: int = NOW_MS) -> Any:
    return dbs.hot.write_sync(lambda conn: apply_call_outcome(conn, call, CONFIG, at_ms, random.Random(1)))


def cooldown_keys(dbs: Any) -> dict[str, str]:
    return {str(k): str(s) for k, s in read_rows(dbs.hot, "SELECT key, source FROM cooldown")}


def breaker_rows(dbs: Any) -> dict[str, BreakerRow]:
    return dbs.hot.read_sync(lambda c: breaker.load(c, [f"endpoint:{TEMPLATE}:direct", f"host:{HOST}:direct"]))


def test_direct_429_cools_the_endpoint_and_trips_its_breaker(dbs: Any) -> None:
    effects = apply(dbs, facts(AttemptKind.RATE_LIMITED, retry_after_s=30))
    assert effects.counted_429
    assert effects.first_in_episode
    assert effects.cooldown_s == pytest.approx(30)
    assert effects.cooldown_source == "retry_after"
    assert cooldown_keys(dbs) == {f"endpoint:{TEMPLATE}:direct": "retry_after"}
    rows = breaker_rows(dbs)
    endpoint = rows[f"endpoint:{TEMPLATE}:direct"]
    assert breaker.effective_state(endpoint, NOW_MS / 1000 + 1) is BreakerState.OPEN
    assert endpoint.half_open_at == pytest.approx(NOW_MS / 1000 + 30)
    assert rows[f"host:{HOST}:direct"].failures == 1
    assert effects.attribution is not None
    assert effects.attribution.kind is AttributionKind.ENDPOINT
    assert [t.reason for t in effects.transitions] == ["rate_limited"]


def test_second_429_in_the_same_episode_is_not_first(dbs: Any) -> None:
    apply(dbs, facts(AttemptKind.RATE_LIMITED, retry_after_s=30))
    effects = apply(dbs, facts(AttemptKind.RATE_LIMITED, retry_after_s=5), NOW_MS + 1000)
    assert effects.first_in_episode is False
    assert effects.cooldown_s == pytest.approx(29)  # the active cooldown is never shortened


def test_three_templates_escalate_to_the_host(dbs: Any) -> None:
    for i, path in enumerate(["/v1/a", "/v1/b"]):
        effects = apply(dbs, facts(AttemptKind.RATE_LIMITED, template=HOST + path, retry_after_s=20), NOW_MS + i)
        assert effects.attribution is not None
        assert effects.attribution.kind is AttributionKind.ENDPOINT
    effects = apply(dbs, facts(AttemptKind.RATE_LIMITED, template=HOST + "/v1/c", retry_after_s=20), NOW_MS + 5)
    assert effects.attribution is not None
    assert effects.attribution.kind is AttributionKind.HOST
    assert effects.attribution.bucket_key == f"host:{HOST}"
    assert f"host:{HOST}:direct" in cooldown_keys(dbs)


def test_429s_across_hosts_open_an_egress_cooldown(dbs: Any) -> None:
    apply(dbs, facts(AttemptKind.RATE_LIMITED, template="users.roblox.com/v1/users/{userId}", retry_after_s=20))
    effects = apply(dbs, facts(AttemptKind.RATE_LIMITED, retry_after_s=20), NOW_MS + 10)
    assert effects.attribution is not None
    assert effects.attribution.kind is AttributionKind.EGRESS
    assert effects.attribution.bucket_key is None  # nothing per endpoint is lowered
    assert "egress:direct" in cooldown_keys(dbs)


def test_credential_429_sets_the_fleet_credential_cooldown(dbs: Any) -> None:
    effects = apply(dbs, facts(AttemptKind.RATE_LIMITED, egress=Egress.CREDENTIAL))
    keys = cooldown_keys(dbs)
    assert keys[f"endpoint:{TEMPLATE}:credential"] == "default"
    assert keys["credential"] == "default"
    assert 60 <= (effects.cooldown_s or 0) <= 66  # credential_cooldown_default_s with jitter


def test_rotator_429_counts_only_with_distinct_exits(dbs: Any) -> None:
    for i, exit_id in enumerate(["s1", "s2"]):
        effects = apply(dbs, facts(AttemptKind.RATE_LIMITED, egress=Egress.ROTATOR, exit_id=exit_id), NOW_MS + i)
        assert effects.counted_429 is False
        assert effects.distinct_exits == i + 1
        assert cooldown_keys(dbs) == {}
    effects = apply(dbs, facts(AttemptKind.RATE_LIMITED, egress=Egress.ROTATOR, exit_id="s3"), NOW_MS + 2)
    assert effects.counted_429 is True
    assert f"endpoint:{TEMPLATE}:rotator" in cooldown_keys(dbs)
    assert effects.attribution is None  # rotator 429s never lower a rate (each exit is a different IP)


def test_server_errors_count_toward_both_breakers(dbs: Any) -> None:
    for i in range(5):
        effects = apply(dbs, facts(AttemptKind.SERVER_ERROR, status=503), NOW_MS + i * 1000)
    rows = breaker_rows(dbs)
    assert breaker.effective_state(rows[f"endpoint:{TEMPLATE}:direct"], NOW_MS / 1000 + 5) is BreakerState.OPEN
    assert breaker.effective_state(rows[f"host:{HOST}:direct"], NOW_MS / 1000 + 5) is BreakerState.OPEN
    assert len(effects.transitions) == 2
    assert cooldown_keys(dbs) == {}  # 5xx never opens a cooldown


def test_ratelimit_remaining_zero_on_success(dbs: Any) -> None:
    call = facts(AttemptKind.SUCCESS, status=200, ratelimit=RateLimitInfo(60, 0, 12))
    effects = apply(dbs, call)
    assert cooldown_keys(dbs) == {f"endpoint:{TEMPLATE}:direct": "ratelimit_reset"}
    assert effects.cooldown_s == pytest.approx(12)


def test_half_open_probe_success_closes_and_releases(dbs: Any) -> None:
    key = f"endpoint:{TEMPLATE}:direct"
    row, _ = breaker.trip(None, key, NOW_MS / 1000 - 40, 30)
    dbs.hot.write_sync(lambda c: breaker.save(c, row))
    dbs.hot.write_sync(lambda c: breaker.try_acquire_probe(c, key, "h", NOW_MS, 20))
    effects = apply(dbs, facts(AttemptKind.SUCCESS, status=200, probe_keys=(key,)))
    assert breaker_rows(dbs)[key].state is BreakerState.CLOSED
    assert [t.reason for t in effects.transitions] == ["probe_succeeded"]
    assert read_rows(dbs.hot, "SELECT name FROM lease WHERE name LIKE 'brk:%'") == []


def test_half_open_probe_failure_reopens_doubled(dbs: Any) -> None:
    key = f"endpoint:{TEMPLATE}:direct"
    row, _ = breaker.trip(None, key, NOW_MS / 1000 - 40, 30)
    dbs.hot.write_sync(lambda c: breaker.save(c, row))
    effects = apply(dbs, facts(AttemptKind.TIMEOUT, probe_keys=(key,)))
    reopened = breaker_rows(dbs)[key]
    assert reopened.open_duration_s == 60
    assert [t.reason for t in effects.transitions] == ["probe_failed"]


def test_probe_that_hit_a_429_reopens_for_the_retry_after(dbs: Any) -> None:
    key = f"endpoint:{TEMPLATE}:direct"
    row, _ = breaker.trip(None, key, NOW_MS / 1000 - 40, 30)
    dbs.hot.write_sync(lambda c: breaker.save(c, row))
    apply(dbs, facts(AttemptKind.RATE_LIMITED, retry_after_s=90, probe_keys=(key,)))
    assert breaker_rows(dbs)[key].open_duration_s == pytest.approx(90)


def test_neutral_outcome_only_releases_the_probe(dbs: Any) -> None:
    key = f"endpoint:{TEMPLATE}:direct"
    row, _ = breaker.trip(None, key, NOW_MS / 1000 - 40, 30)
    dbs.hot.write_sync(lambda c: breaker.save(c, row))
    dbs.hot.write_sync(lambda c: breaker.try_acquire_probe(c, key, "h", NOW_MS, 20))
    effects = apply(dbs, facts(AttemptKind.EGRESS_DISABLED, probe_keys=(key,)))
    assert effects.transitions == []
    assert breaker_rows(dbs)[key] == row
    assert read_rows(dbs.hot, "SELECT name FROM lease WHERE name LIKE 'brk:%'") == []


def test_should_record() -> None:
    now = NOW_MS / 1000
    assert should_record(facts(AttemptKind.SUCCESS), {}, now) is False  # the common case costs no write
    assert should_record(facts(AttemptKind.DEFINITIVE, status=404), {}, now) is False
    assert should_record(facts(AttemptKind.RATE_LIMITED), {}, now) is True
    assert should_record(facts(AttemptKind.SERVER_ERROR), {}, now) is True
    assert should_record(facts(AttemptKind.SUCCESS, probe_keys=("k",)), {}, now) is True
    limited = facts(AttemptKind.SUCCESS, ratelimit=RateLimitInfo(None, 0, 3))
    assert should_record(limited, {}, now) is True
    counting = {f"endpoint:{TEMPLATE}:direct": BreakerRow(f"endpoint:{TEMPLATE}:direct", failures=2, window_start=now)}
    assert should_record(facts(AttemptKind.SUCCESS), counting, now) is True
