"""The UP-* rules (UP-429-HOST to UP-BREAKER-FLAP) against their committed fixtures, plus their numbers and helpers.

What this is
    Every case of every `up_*` fixture of the fourteen upstream rules in `roxy/insights/rules/upstream.py` (the file's
    own case and each variant) run through the harness, which evaluates the rule through the engine's per-rule entry
    point (switch, severity override, evidence minimum, fingerprint). Then explicit checks of the numbers the
    fixtures only bound (bucket rates, early retries, z statistics), `safe_auto` per rule, the help text and settings
    of every rule, and unit tests of the pure helpers and of the two provider reads the family adds
    (`insights/providers_rules_upstream.py`).

Why it exists
    Plan 19.10 row 11: the fixtures were written from the 11.5 table before the rules; passing them unchanged is the
    acceptance criterion. The explicit checks pin the arithmetic (7.3 cuts and raises, 80% headroom, the 95% test)
    so a later refactor cannot drift inside a fixture's tolerance unnoticed.

What to read next
    `tests/insights/harness.py` (the loader), `roxy/insights/rules/upstream.py`, `tests/fixtures/insights/README.md`.
"""

from __future__ import annotations

import dataclasses

import pytest

from insights.harness import fixture_ids, loaded, run_case
from roxy.insights.context import InsightContext
from roxy.insights.models import ProposedChange, Recommendation
from roxy.insights.providers_rules_upstream import (
    SAMPLE_SOURCE,
    arms_from_samples,
    rotator_status,
    span_window,
    ua_experiment_arms,
)
from roxy.insights.rules import load_rules
from roxy.insights.rules.upstream import minute_runs, proportion_interval, two_proportion_z

UPSTREAM_RULES = {
    "UP-429-HOST": "up_429_host",
    "UP-429-CREDENTIAL": "up_429_credential",
    "UP-429-AMPLIFY": "up_429_amplify",
    "UP-RETRYAFTER-IGNORED": "up_retryafter_ignored",
    "UP-4XX-SPIKE": "up_4xx_spike",
    "UP-CSRF-LOOP": "up_csrf_loop",
    "UP-CHALLENGE": "up_challenge",
    "UP-UA-EXPERIMENT": "up_ua_experiment",
    "UP-5XX": "up_5xx",
    "UP-TIMEOUT": "up_timeout",
    "UP-LATENCY": "up_latency",
    "UP-QUEUE-SAT": "up_queue_sat",
    "UP-BUCKET-TUNE": "up_bucket_tune",
    "UP-BREAKER-FLAP": "up_breaker_flap",
}
PREFIXES = tuple(f"{slug}__" for slug in UPSTREAM_RULES.values())
CASES = fixture_ids(PREFIXES)


def _change(rec: Recommendation, kind: str, **fields: object) -> ProposedChange:
    """The recommendation's one change of `kind` whose fields equal `fields`."""
    for change in rec.changes:
        if change.kind == kind and all(getattr(change, k) == v for k, v in fields.items()):
            return change
    raise AssertionError(f"no {kind} change with {fields} in {[c.to_dict() for c in rec.changes]}")


# ------------------------------------------------------------------------------------------- fixtures


@pytest.mark.parametrize(
    ("stem", "case"), CASES, ids=[stem if case is None else f"{stem}[{case}]" for stem, case in CASES]
)
async def test_upstream_rule_fixture(stem: str, case: str | None) -> None:
    await run_case(stem, case)


def test_every_upstream_rule_has_fixtures_for_fires_quiet_switch_and_thresholds() -> None:
    by_rule: dict[str, list[str]] = {}
    for stem, case in CASES:
        by_rule.setdefault(stem.split("__", 1)[0], []).append(case or stem.split("__", 1)[1])
    assert set(by_rule) == set(UPSTREAM_RULES.values())
    for slug, cases in by_rule.items():
        assert "disabled" in cases, slug  # the per-rule switch (19.10)
        assert len(cases) >= 4, slug


def test_registry_holds_every_upstream_rule_with_help_text_and_settings() -> None:
    rules = load_rules()
    for rule_id, slug in UPSTREAM_RULES.items():
        rule = rules[rule_id]
        assert rule.family == "upstream"
        assert rule.slug == slug
        help_text = rule.help_text
        assert len(help_text.splitlines()) >= 3, rule_id
        assert not help_text.startswith(" "), rule_id
        card = rule.describe()
        for name, key in card["settings"]["params"].items():
            assert f"`{name}`" in help_text, f"{rule_id} help text does not name its threshold {name}"
            assert rule.setting_key(name) == key
        assert rule.triggers, rule_id
    # Only UP-BUCKET-TUNE may be auto-applied: its changes are one bucket row, bounded like the 7.3 controller.
    assert {rule_id for rule_id in UPSTREAM_RULES if rules[rule_id].safe_auto} == {"UP-BUCKET-TUNE"}


# ------------------------------------------------------------------------------------- explicit numbers


async def test_up_429_host_numbers() -> None:
    recs = await run_case("up_429_host__three_templates")
    (rec,) = recs
    assert rec.subject == "host:games.roblox.com"
    assert rec.evidence.metric("roblox_429") == 27
    assert rec.evidence.metric("templates_with_429") == 3
    bucket = _change(rec, "bucket_override", bucket_key="host:games.roblox.com")
    peak = rec.evidence.metric("peak_calls_per_min_with_429")
    assert peak > 0
    # 80% of the call rate that drew the 429s, never above the 7.3 cut (240 - 30% = 168).
    assert bucket.proposed["per_min"] == min(168, int(peak * 0.8))
    assert rec.safe_auto is False
    shifted = await run_case("up_429_host__rotator_available")
    routes = [c for c in shifted[0].changes if c.kind == "routing_rule"]
    assert len(routes) == 3
    assert {c.proposed["mode"] for c in routes} == {"prefer_rotator"}
    assert shifted[0].evidence.details["rotator"]["quota_used_pct"] == pytest.approx(10.5)


async def test_up_429_credential_numbers() -> None:
    (rec,) = await run_case("up_429_credential__works_anonymously")
    assert rec.severity == "critical"
    assert rec.subject == "credential"
    setting = _change(rec, "setting", key="credential_bucket_per_min")
    assert (setting.current, setting.proposed) == (20, 14)
    removed = _change(rec, "credential_allowlist_remove")
    assert removed.match == {"pattern": "games.roblox.com/v1/games/*/favorites/count", "type": "glob"}
    assert removed.current["id"] == 3
    (allowlisted,) = await run_case("up_429_credential__allowlisted_endpoint")
    assert allowlisted.evidence.metric("credential_429") == 3
    assert allowlisted.evidence.metric("retry_after_max_s") == 60
    assert allowlisted.evidence.metric("credential_bucket_fill_peak_pct") == 100


async def test_up_429_amplify_numbers() -> None:
    (rec,) = await run_case("up_429_amplify__fallback_and_retries")
    assert rec.evidence.metric("calls_per_request") == 2.0
    assert rec.evidence.metric("roblox_429") == 500
    assert rec.evidence.details["attempts_by_kind"] == {"fallback_429": 400, "first": 500, "retry_5xx": 200}
    assert _change(rec, "setting", key="upstream_max_attempts").proposed == 2
    (light,) = await run_case("up_429_amplify__light_fallback", "calls_per_request_1_2")
    assert light.evidence.metric("calls_per_request") == 1.25
    assert [c.key for c in light.changes] == ["fallback_on_429"]  # no 5xx retries: attempts stay


async def test_up_retryafter_ignored_counts_early_retries_per_client_and_key() -> None:
    (rec,) = await run_case("up_retryafter_ignored__polling_script")
    assert rec.evidence.metric("clients_retrying_early") == 1
    assert rec.evidence.metric("most_early_retries_one_client") == 47  # 48 requests, the first was told to wait
    (rec,) = await run_case("up_retryafter_ignored__polling_script", "strike_on_retry_off")
    assert [c.kind for c in rec.changes] == ["tarpit_category"]  # the plan's first remedy while the tarpit is on
    (wide,) = await run_case("up_retryafter_ignored__just_under", "window_40_adds_earlier_episode")
    assert wide.evidence.metric("most_early_retries_one_client") == 36  # 18 per episode, two episodes


async def test_up_4xx_spike_branches() -> None:
    (blocked,) = await run_case("up_4xx_spike__anonymous_401_spike")
    assert blocked.evidence.details["branch"] == "every_path"
    assert blocked.changes[0].table == "rules_endpoint_block"  # 401 answers are never negative-cached (7.7)
    assert blocked.evidence.metric("rejection_rate_pct") == 90.0
    assert blocked.evidence.metric("baseline_rate_pct") == 25.0
    (owner,) = await run_case("up_4xx_spike__anonymous_only_works_with_credential")
    assert owner.evidence.details["branch"] == "anonymous_only"
    (allow,) = await run_case("up_4xx_spike__credential_endpoint_401")
    assert allow.evidence.details["branch"] == "credential_401"
    (cached,) = await run_case("up_4xx_spike__just_under_thresholds", "baseline_multiple_2_5")
    assert cached.changes[0].table == "rules_cache"  # 403 answers can be negative-cached
    assert cached.changes[0].proposed["negative_ttl"] >= 60


async def test_up_csrf_loop_share_and_second_403() -> None:
    (share,) = await run_case("up_csrf_loop__stale_tokens")
    assert share.subject == "csrf_token_cache"
    assert share.evidence.metric("csrf_retry_pct") == 30.0
    assert _change(share, "setting", key="csrf_token_cache_s").proposed == 600  # back to the default
    (loop,) = await run_case("up_csrf_loop__second_403")
    assert loop.subject == "catalog.roblox.com/v1/catalog/items/details"
    assert loop.changes[0].table == "rules_endpoint_block"
    (halved,) = await run_case("up_csrf_loop__just_under", "retry_pct_15")
    assert _change(halved, "setting", key="csrf_token_cache_s").proposed == 300


async def test_up_ua_experiment_numbers() -> None:
    (rec,) = await run_case("up_ua_experiment__alt_ua_wins")
    assert rec.evidence.metric("z") == pytest.approx(14.62, abs=0.01)
    arms = {arm["user_agent"]: arm for arm in rec.evidence.details["arms"]}
    low, high = arms["Roxy/2 (+https://roxy.test)"]["ci95_pct"]
    assert low < 0.151 < high
    assert rec.evidence.details["source"] == "provider"


async def test_up_bucket_tune_numbers_and_safe_auto() -> None:
    (tight,) = await run_case("up_bucket_tune__too_tight")
    assert tight.changes[0].proposed == {"per_min": 66, "burst": 10}
    assert tight.safe_auto is True  # one bucket row, bounded step (11.2)
    (loose,) = await run_case("up_bucket_tune__too_loose_endpoint")
    assert loose.changes[0].proposed == {"per_min": 140, "burst": 10}
    (host,) = await run_case("up_bucket_tune__too_loose_host")
    assert host.changes[0].proposed == {"per_min": 168, "burst": 15}
    assert host.evidence.details["attribution"]["kind"] == "host"


async def test_up_latency_and_queue_causes() -> None:
    (slow,) = await run_case("up_latency__upstream_slow")
    change = slow.changes[0]
    assert change.proposed == {"ttl": 120, "stale_ttl": 120}  # TTL doubled (no samples), SWR doubled from 60
    (rotator,) = await run_case("up_latency__rotator_slow")
    assert [c.kind for c in rotator.changes] == ["routing_rule"]
    (queued,) = await run_case("up_latency__queue_dominated_recent_429s")
    assert queued.evidence.metric("queue_wait_share_of_p95") >= 0.5
    (sat,) = await run_case("up_queue_sat__queue_drops")
    assert sat.evidence.metric("drop_pct") == pytest.approx(100 * 120 / 7920, abs=0.001)
    assert [c.kind for c in sat.changes] == ["rule_upsert"]


async def test_up_breaker_flap_and_timeout_numbers() -> None:
    (flap,) = await run_case("up_breaker_flap__search_flapping")
    assert flap.evidence.metric("openings_last_hour") == 9
    assert _change(flap, "setting", key="breaker_open_s").proposed == 60
    (direct,) = await run_case("up_timeout__direct_timeouts")
    assert _change(direct, "setting", key="request_timeout").proposed == 22  # 15 x 1.5, inside the owner deadline
    (rotator,) = await run_case("up_timeout__rotator_timeouts")
    assert _change(rotator, "setting", key="rotator_weight").proposed == 25


# ------------------------------------------------------------------------------------- helpers, providers


def test_minute_runs_merges_consecutive_minutes() -> None:
    assert minute_runs([120, 60, 180, 600, 660]) == [(60, 240), (600, 720)]
    assert minute_runs([]) == []


def test_two_proportion_test_and_interval() -> None:
    assert two_proportion_z(90, 59_800, 428, 61_200) == pytest.approx(14.62, abs=0.01)
    assert two_proportion_z(115, 30_100, 122, 30_400) < 1.96  # noise: the fixture's no-difference case
    assert two_proportion_z(0, 0, 1, 10) == 0.0
    rate, low, high = proportion_interval(90, 59_800)
    assert low < rate < high
    assert low >= 0.0
    assert high <= 1.0
    assert proportion_interval(0, 0) == (0.0, 0.0, 0.0)


def test_arms_from_samples_uses_the_egress_arm_assignment() -> None:
    from roxy.config.catalog import DEFAULTS
    from roxy.core.reasons import Egress
    from roxy.egress.headers import HeaderProfiles

    settings = {**DEFAULTS, "ua_experiment_enabled": 1, "ua_experiment_alt_user_agent": "Roxy/2 (+https://roxy.test)"}
    profiles = HeaderProfiles(settings, "")
    keys = [f"{i:024x}" for i in range(40)]
    samples: list[dict[str, object]] = [
        {"egress": "direct", "upstream_status": 429 if i % 4 == 0 else 200, "key_id": key, "endpoint_template": "t"}
        for i, key in enumerate(keys)
    ]
    samples.append({"egress": "rotator", "upstream_status": 429, "key_id": keys[0]})  # not a direct call
    samples.append({"egress": "direct", "upstream_status": None, "key_id": keys[1]})  # never reached Roblox
    data = arms_from_samples(samples, settings)
    assert data["source"] == SAMPLE_SOURCE
    by_arm = {arm["arm"]: arm for arm in data["arms"]}
    expected = {"primary": [0, 0], "alt": [0, 0]}
    for i, key in enumerate(keys):
        arm = profiles.ua_variant(Egress.DIRECT, key)
        expected[arm][0] += 1
        expected[arm][1] += 1 if i % 4 == 0 else 0
    for arm, (calls, limited) in expected.items():
        assert (by_arm[arm]["calls"], by_arm[arm]["roblox_429"]) == (calls, limited)
    assert by_arm["alt"]["user_agent"] == "Roxy/2 (+https://roxy.test)"
    assert by_arm["primary"]["user_agent"] == DEFAULTS["direct_user_agent"]


async def test_ua_experiment_arms_fall_back_to_request_samples() -> None:
    """Production has no per-arm counter yet: with the provider silent, the arms come from the samples."""
    state = await loaded("up_retryafter_ignored__polling_script")
    base = state.engine.context(state.now)
    settings = {**dict(base.settings), "ua_experiment_enabled": 1}
    ctx = dataclasses.replace(base, settings=settings, _memo={}, _locks={})
    data = await ua_experiment_arms(ctx)
    assert data is not None
    assert data["source"] == SAMPLE_SOURCE
    calls = sum(arm["calls"] for arm in data["arms"])
    limited = sum(arm["roblox_429"] for arm in data["arms"])
    samples = await ctx.samples(ctx.window(hours=24))
    direct = [s for s in samples if s["egress"] == "direct" and s["upstream_status"] is not None]
    assert calls == len(direct)
    assert limited == sum(1 for s in direct if s["upstream_status"] == 429)
    off = dataclasses.replace(base, _memo={}, _locks={})
    assert await ua_experiment_arms(off) is None  # the experiment is off in this fixture


async def test_rotator_status_reads_the_rotators_own_budget() -> None:
    state = await loaded("up_429_host__rotator_available")
    ctx: InsightContext = state.engine.context(state.now)
    status = await rotator_status(ctx)
    assert status.available
    assert status.cycle_bytes == 7 * 300_000_000  # seven day rows since the billing day, 2.1 GB
    assert status.quota_bytes == 20_000_000_000
    assert status.to_dict()["quota_used_pct"] == 10.5
    closed = dataclasses.replace(ctx, settings={**dict(ctx.settings), "rotator_enabled": 0}, _memo={}, _locks={})
    assert not (await rotator_status(closed)).available


def test_span_window_is_half_open_utc() -> None:
    window = span_window(60.5, 3600.9, "hour")
    assert (window.start, window.end, window.granularity, window.tz) == (60, 3600, "hour", "UTC")


# --------------------------------------------------------------------- branches the fixtures do not reach


async def _evaluate_with(stem: str, rule_id: str, **settings: object) -> list[Recommendation]:
    """One rule through the engine's per-rule entry point on a loaded fixture, with some settings replaced (values
    that pass the catalog; this is the leader's path, only the settings snapshot differs)."""
    state = await loaded(stem)
    base = state.engine.context(state.now)
    ctx = dataclasses.replace(base, settings={**dict(base.settings), **settings}, _memo={}, _locks={})
    outcome = await state.engine.evaluate_rule(rule_id, ctx=ctx)
    assert outcome.error is None, outcome.error
    return outcome.recommendations


async def test_up_timeout_rotator_without_weight_changes_the_session_mode() -> None:
    (rec,) = await _evaluate_with("up_timeout__rotator_timeouts", "UP-TIMEOUT", rotator_weight=0)
    change = _change(rec, "setting", key="rotator_session_mode")
    assert (change.current, change.proposed) == ("sticky_until_429", "sticky")
    (rec,) = await _evaluate_with(
        "up_timeout__rotator_timeouts", "UP-TIMEOUT", rotator_weight=0, rotator_session_mode="per_request"
    )
    assert [c.kind for c in rec.changes] == ["manual"]


async def test_up_timeout_raise_stays_inside_the_owner_deadline() -> None:
    # request_deadline_s 40 leaves 38 s: 4 s queue + 2 attempts x timeout + 2 s backoff, so at most 16 s.
    (rec,) = await _evaluate_with("up_timeout__direct_timeouts", "UP-TIMEOUT", request_deadline_s=40)
    assert _change(rec, "setting", key="request_timeout").proposed == 16
    (rec,) = await _evaluate_with("up_timeout__direct_timeouts", "UP-TIMEOUT", request_deadline_s=36)
    assert [c.kind for c in rec.changes] == ["manual"]  # no raise fits: check the network instead


async def test_up_retryafter_ignored_with_the_tarpit_off() -> None:
    (rec,) = await _evaluate_with(
        "up_retryafter_ignored__polling_script", "UP-RETRYAFTER-IGNORED", tarpit_enabled=0, throttle_strike_on_retry=0
    )
    assert [(c.kind, c.key) for c in rec.changes] == [("setting", "throttle_strike_on_retry")]
    (rec,) = await _evaluate_with("up_retryafter_ignored__polling_script", "UP-RETRYAFTER-IGNORED", tarpit_enabled=0)
    assert [c.kind for c in rec.changes] == ["setting", "tarpit_category"]
    assert rec.changes[0].key == "tarpit_enabled"


async def test_up_ua_experiment_keeps_a_current_user_agent_that_already_wins() -> None:
    recs = await _evaluate_with(
        "up_ua_experiment__alt_ua_wins",
        "UP-UA-EXPERIMENT",
        direct_user_agent="Roxy/2 (+https://roxy.test)",
        ua_experiment_alt_user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/141.0.0.0 Safari/537.36",
    )
    assert recs == []


async def test_up_bucket_tune_leaves_controller_managed_buckets_alone() -> None:
    # The headshot endpoint bucket runs at the default rate (no upstream_limits row), turned away 4,800 of 165,300
    # attempts in a 429-free day: too tight. While the adaptive controller runs it raises such a bucket itself
    # (plan 7.3), so the recommendation appears only with the controller off.
    stem = "up_queue_sat__long_waits"
    assert await _evaluate_with(stem, "UP-BUCKET-TUNE", adaptive_rate_enabled=1) == []
    (rec,) = await _evaluate_with(stem, "UP-BUCKET-TUNE", adaptive_rate_enabled=0)
    assert rec.subject == "endpoint:thumbnails.roblox.com/v1/users/avatar-headshot"
    assert rec.changes[0].proposed == {"per_min": 132, "burst": 10}
    assert rec.evidence.details["fill_history"]  # hourly attempts, rejections and peak fill (parity row 77)


async def test_cache_change_covers_the_endpoints_method() -> None:
    from roxy.insights.rules.upstream import cache_change

    state = await loaded("up_bucket_tune__too_tight")  # no cache rules at all
    ctx = state.engine.context(state.now)
    batch = "thumbnails.roblox.com/v1/batch"
    change = await cache_change(ctx, batch, raise_ttl=True, raise_swr=False, method="POST")
    assert change is not None
    assert change.current is None
    assert change.proposed["methods"] == "GET,POST"
    assert change.proposed["ttl"] == 240  # cache_ttl_seconds 120 doubled: the tuner has no samples here
    assert await cache_change(ctx, batch, raise_ttl=True, raise_swr=False, method="PUT") is None
    off = dataclasses.replace(ctx, settings={**dict(ctx.settings), "cache_post_requests": "off"}, _memo={}, _locks={})
    assert await cache_change(off, batch, raise_ttl=True, raise_swr=False, method="POST") is None
    slow = await loaded("up_latency__upstream_slow")  # the avatar rule caches GET only
    ctx = slow.engine.context(slow.now)
    change = await cache_change(
        ctx, "avatar.roblox.com/v1/users/{userId}/avatar", raise_ttl=False, raise_swr=False, method="POST"
    )
    assert change is not None
    assert change.proposed == {"methods": "GET,POST"}
