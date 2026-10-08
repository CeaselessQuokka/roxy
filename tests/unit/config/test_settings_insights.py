"""Catalog content tests for settings group J (Insights) and the recommendation rule catalog (11.5, 15.3 J2).

These pin the plan's contract: every key and rule id is present, every default is valid against its own range,
every help text an admin relies on is filled in, and nothing breaks the style rule C5.
"""

import dataclasses
import re
from pathlib import Path
from typing import Any

import pytest

from roxy.config import insight_params
from roxy.config.insight_params import INSIGHT_RULES
from roxy.config.settings import insights
from roxy.config.spec import Apply, Group, InsightRuleSpec, ParamSpec, SettingSpec, SettingType

# --- Plan tables, copied explicitly so a missing or renamed key fails here -------------------------------------

EXPECTED_J_DEFAULTS: dict[str, Any] = {
    "insights_enabled": 1,
    "insights_interval_s": 30,
    "insights_auto_apply": 0,
    "auto_apply_max_per_hour": 3,
    "auto_apply_max_step_pct": 50,
    "auto_apply_watch_minutes": 30,
    "auto_apply_rollback_threshold_pct": 20,
    "recommendation_expiry_days": 7,
    "dismiss_cooldown_days": 7,
    "insight_cred_probe_cost_max_per_hour": 6,
}

EXPECTED_J_RANGES: dict[str, tuple[float, float]] = {
    "insights_interval_s": (5, 3600),
    "auto_apply_max_per_hour": (0, 20),
    "auto_apply_max_step_pct": (5, 200),
    "auto_apply_watch_minutes": (5, 240),
    "auto_apply_rollback_threshold_pct": (5, 100),
    "recommendation_expiry_days": (1, 90),
    "dismiss_cooldown_days": (0, 365),
    "insight_cred_probe_cost_max_per_hour": (1, 60),
}

# Plan 11.5, in table order.
EXPECTED_RULE_IDS = [
    "UP-429-ENDPOINT",
    "UP-429-HOST",
    "UP-429-CREDENTIAL",
    "UP-429-AMPLIFY",
    "UP-RETRYAFTER-IGNORED",
    "UP-4XX-SPIKE",
    "UP-CSRF-LOOP",
    "UP-CHALLENGE",
    "UP-UA-EXPERIMENT",
    "UP-5XX",
    "UP-TIMEOUT",
    "UP-LATENCY",
    "UP-QUEUE-SAT",
    "UP-BUCKET-TUNE",
    "UP-BREAKER-FLAP",
    "CACHE-LOW-HIT",
    "CACHE-TTL-TUNE",
    "CACHE-KEYSPLIT",
    "CACHE-PRESSURE",
    "CACHE-OFF",
    "CACHE-NEG",
    "HOT-ENDPOINT",
    "EGR-BURN",
    "EGR-UNDERUSE",
    "EGR-POOL-BURNED",
    "EGR-CALIBRATE",
    "CRED-EXPIRING",
    "CRED-UNUSED",
    "CRED-ROTATOR-GUARD",
    "ABUSE-SPAM",
    "ABUSE-BOT",
    "ABUSE-DIST",
    "FILTER-ADD",
    "FILTER-REMOVE",
    "FILTER-COLLATERAL",
    "TARPIT-TUNE",
    "THROTTLE-TUNE",
    "PLACE-HEAVY",
    "SYS-DISK",
    "SYS-WORKER-SAT",
    "SYS-LOOP-LAG",
    "SYS-ERRORS",
    "SYS-METRICS-DROP",
    "SYS-CHANGE-REGRESSION",
    "SYS-HEALTH-FAIL",
    "SEC-ADMIN-ALLOWLIST",
    "SEC-BYPASS-FOREVER",
    "HOST-ADD",
    "CRED-PROBE-COST",
    "SEC-DEFAULTS",
]

# Plan 15.3 J2: param name -> default, per rule.
EXPECTED_PARAMS: dict[str, dict[str, float]] = {
    "UP-429-ENDPOINT": {"min_429s": 20, "share_pct": 2, "window_min": 60, "high_confidence_n": 50},
    "UP-429-HOST": {"min_templates": 3, "window_min": 15},
    "UP-429-CREDENTIAL": {"min_429s": 1},
    "UP-429-AMPLIFY": {"calls_per_request": 1.3},
    "UP-RETRYAFTER-IGNORED": {"min_retries": 20, "window_min": 10},
    "UP-4XX-SPIKE": {"baseline_multiple": 3, "min_responses": 20, "min_calls": 100, "window_min": 30},
    "UP-CSRF-LOOP": {"retry_pct": 20, "window_min": 30},
    "UP-CHALLENGE": {"min_pages": 5, "window_min": 15},
    "UP-UA-EXPERIMENT": {"min_calls_per_arm": 10000},
    "UP-5XX": {"rate_pct": 5, "window_min": 10, "min_calls": 100},
    "UP-TIMEOUT": {"rate_pct": 2, "window_min": 10},
    "UP-LATENCY": {"p95_ms": 1500, "p99_ms": 4000, "window_min": 30, "min_calls": 200},
    "UP-QUEUE-SAT": {"drop_pct": 0.5, "p95_wait_ms": 2000},
    "UP-BUCKET-TUNE": {"clean_hours": 24, "rejection_pct": 1, "raise_pct": 10, "lower_pct": 30},
    "UP-BREAKER-FLAP": {"openings_per_hour": 6},
    "CACHE-LOW-HIT": {"top_n": 10, "max_hit_ratio_pct": 30, "window_min": 60},
    "CACHE-TTL-TUNE": {"identical_raise_pct": 90, "identical_lower_pct": 50, "min_refetches": 50, "window_h": 24},
    "CACHE-KEYSPLIT": {"min_entries": 5, "distinct_pct": 80, "max_hit_pct": 10},
    "CACHE-PRESSURE": {"young_eviction_pct": 5, "window_min": 60},
    "CACHE-NEG": {"min_404_per_hour": 100},
    "HOT-ENDPOINT": {"top_n": 5},
    "HOST-ADD": {"min_places": 5, "min_ips": 50, "window_h": 24},
    "EGR-BURN": {"projected_pct": 90},
    "EGR-UNDERUSE": {"direct_429_pct": 2, "rotator_429_max_pct": 5, "quota_used_max_pct": 30},
    "EGR-POOL-BURNED": {"rotator_429_pct": 20, "window_min": 30},
    "EGR-CALIBRATE": {"diff_pct": 10},
    "CRED-UNUSED": {"min_comparisons": 20, "identical_pct": 100},
    "ABUSE-BOT": {"min_requests_per_hour": 500},
    "FILTER-ADD": {"refusals_per_hour": 1000, "hours": 3},
    "FILTER-REMOVE": {"idle_rule_days": 30, "idle_bypass_days": 7},
    "FILTER-COLLATERAL": {"served_pct": 95},
    "TARPIT-TUNE": {"skipped_pct": 10},
    "THROTTLE-TUNE": {"legit_throttled_pct": 5},
    "PLACE-HEAVY": {"share_pct": 40, "window_min": 60},
    "SYS-DISK": {"budget_pct": 70, "free_disk_pct": 15, "dims_per_minute": 1500},
    "SYS-WORKER-SAT": {"cpu_pct": 85, "window_min": 10},
    "SYS-LOOP-LAG": {"p99_ms": 100, "window_min": 5},
    "SYS-ERRORS": {"baseline_multiple": 5, "caller_500_pct": 0.5, "window_min": 15},
    "SYS-CHANGE-REGRESSION": {"worse_pct": 25, "watch_min": 30, "baseline_h": 2},
    "SEC-ADMIN-ALLOWLIST": {"max_networks": 3, "days": 30},
}

# Plan 15.3 J2, last paragraph: these fire on any occurrence and only get `_enabled` and `_severity`.
EXPECTED_NO_PARAM_RULES = {
    "CACHE-OFF",
    "CRED-PROBE-COST",
    "CRED-EXPIRING",
    "CRED-ROTATOR-GUARD",
    "ABUSE-SPAM",
    "ABUSE-DIST",
    "SYS-METRICS-DROP",
    "SYS-HEALTH-FAIL",
    "SEC-BYPASS-FOREVER",
    "SEC-DEFAULTS",
}

ALLOWED_FAMILIES = {"upstream", "cache", "abuse", "egress", "credential", "filter", "system", "security", "host"}
ALLOWED_PAGES = {"recommendations#engine"}

NUMERIC_TYPES = {SettingType.INT, SettingType.FLOAT, SettingType.DURATION, SettingType.BYTES, SettingType.PERCENT}
DASHES = (chr(0x2014), chr(0x2013))  # em dash, en dash
# Bracketed so this file does not trip the style check it enforces (plan C5).
BRITISH = [
    r"behavio[u]r",
    r"colo[u]r",
    r"favo[u]r",
    r"optimi[s]e",
    r"analy[s]e",
    r"normali[s]e",
    r"cancel[l]ed",
    r"label[l]ed",
    r"catalo[g]ue",
    r"licen[c]e",
    r"defen[c]e",
    r"whi[l]st",
    r"amon[g]st",
]


def _strings(value: Any) -> list[str]:
    """Every string inside a spec (recursing into tuples and nested dataclasses)."""
    if isinstance(value, str):
        return [value]
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return [s for f in dataclasses.fields(value) for s in _strings(getattr(value, f.name))]
    if isinstance(value, (tuple, list)):
        return [s for item in value for s in _strings(item)]
    return []


def _assert_style(text: str, where: str) -> None:
    for dash in DASHES:
        assert dash not in text, f"{where}: dash character found"
    for pattern in BRITISH:
        assert not re.search(pattern, text, re.IGNORECASE), f"{where}: non-US spelling matching {pattern}"


def _assert_default_valid(spec: SettingSpec) -> None:
    value = spec.default
    if spec.type == SettingType.BOOL:
        assert value in (0, 1), spec.key
    elif spec.type in NUMERIC_TYPES:
        assert isinstance(value, (int, float)), spec.key
        assert not isinstance(value, bool), spec.key
        if spec.type in (SettingType.INT, SettingType.DURATION, SettingType.BYTES):
            assert isinstance(value, int), spec.key
        assert spec.min is not None, spec.key
        assert spec.max is not None, spec.key
        assert spec.min <= value <= spec.max, spec.key
    elif spec.type == SettingType.ENUM:
        assert value in spec.option_values(), spec.key
    elif spec.type == SettingType.STRING:
        assert isinstance(value, str), spec.key
        if spec.max_length is not None:
            assert len(value) <= spec.max_length, spec.key


def _by_key() -> dict[str, SettingSpec]:
    return {spec.key: spec for spec in insights.SETTINGS}


# --- Group J settings -----------------------------------------------------------------------------------------


def test_every_group_j_key_present_once() -> None:
    keys = [spec.key for spec in insights.SETTINGS]
    assert len(keys) == len(set(keys))
    assert set(keys) == set(EXPECTED_J_DEFAULTS)


@pytest.mark.parametrize("key", sorted(EXPECTED_J_DEFAULTS))
def test_group_j_defaults_and_ranges_match_plan(key: str) -> None:
    spec = _by_key()[key]
    assert spec.default == EXPECTED_J_DEFAULTS[key]
    if key in EXPECTED_J_RANGES:
        assert (spec.min, spec.max) == EXPECTED_J_RANGES[key]
    _assert_default_valid(spec)


@pytest.mark.parametrize("spec", insights.SETTINGS, ids=lambda s: s.key)
def test_group_j_spec_complete(spec: SettingSpec) -> None:
    assert spec.group == Group.INSIGHTS
    assert spec.label.strip()
    assert spec.description.strip()
    assert spec.pages
    assert set(spec.pages) <= ALLOWED_PAGES
    assert spec.apply == Apply.LIVE
    if spec.type in NUMERIC_TYPES:
        assert spec.if_raised.strip()
        assert spec.if_lowered.strip()
        assert spec.unit.strip()
    if spec.type == SettingType.BOOL:
        assert spec.if_enabled.strip()
        assert spec.if_disabled.strip()
    for condition in spec.high_risk_if:
        assert condition.why.strip()
    # A default is never itself a high-risk value.
    assert spec.is_high_risk_value(spec.default) is None
    # Auto-apply never tunes the engine or its own guardrails.
    assert spec.auto_apply_bounds is None
    assert not spec.sensitive
    assert set(spec.related_recommendations) <= set(INSIGHT_RULES)
    for text in _strings(spec):
        _assert_style(text, spec.key)


def test_auto_apply_is_off_and_pending_owner_decision() -> None:
    spec = _by_key()["insights_auto_apply"]
    assert spec.default == 0
    assert spec.pending_owner_verification


# --- Rule catalog (insight_params) -----------------------------------------------------------------------------


def test_every_rule_from_plan_present_in_order() -> None:
    assert list(INSIGHT_RULES) == EXPECTED_RULE_IDS
    assert set(EXPECTED_PARAMS) | EXPECTED_NO_PARAM_RULES == set(EXPECTED_RULE_IDS)
    assert not set(EXPECTED_PARAMS) & EXPECTED_NO_PARAM_RULES


@pytest.mark.parametrize("rule_id", EXPECTED_RULE_IDS)
def test_rule_spec_complete(rule_id: str) -> None:
    rule = INSIGHT_RULES[rule_id]
    assert isinstance(rule, InsightRuleSpec)
    assert rule.rule_id == rule_id
    assert rule.family in ALLOWED_FAMILIES
    assert rule.title.strip()
    assert rule.slug == rule_id.lower().replace("-", "_")
    for text in _strings(rule):
        _assert_style(text, rule_id)


@pytest.mark.parametrize("rule_id", EXPECTED_RULE_IDS)
def test_rule_params_match_plan(rule_id: str) -> None:
    rule = INSIGHT_RULES[rule_id]
    if rule_id in EXPECTED_NO_PARAM_RULES:
        assert rule.params == ()
        return
    assert {p.name: p.default for p in rule.params} == pytest.approx(EXPECTED_PARAMS[rule_id])
    assert len({p.name for p in rule.params}) == len(rule.params)


@pytest.mark.parametrize(
    "param",
    [(rule.rule_id, p) for rule in INSIGHT_RULES.values() for p in rule.params],
    ids=lambda item: f"{item[0]}:{item[1].name}",
)
def test_param_spec_valid(param: tuple[str, ParamSpec]) -> None:
    rule_id, p = param
    assert re.fullmatch(r"[a-z][a-z0-9_]*", p.name), rule_id
    assert p.name not in ("enabled", "severity"), "collides with the generated per-rule switches"
    assert p.min <= p.default <= p.max, f"{rule_id}.{p.name}"
    assert p.min < p.max
    assert p.label.strip()
    assert p.unit.strip()
    assert p.if_raised.strip()
    assert p.if_lowered.strip()
    if p.is_int:
        for bound in (p.default, p.min, p.max):
            assert float(bound).is_integer(), f"{rule_id}.{p.name} is_int but {bound} is fractional"


def test_fractional_defaults_are_not_int() -> None:
    fractional = {(r.rule_id, p.name) for r in INSIGHT_RULES.values() for p in r.params if not p.is_int}
    for rule_id, name in [
        ("UP-429-AMPLIFY", "calls_per_request"),
        ("UP-QUEUE-SAT", "drop_pct"),
        ("SYS-ERRORS", "caller_500_pct"),
    ]:
        assert (rule_id, name) in fractional


def test_generated_keys_unique_and_clear_of_group_j() -> None:
    generated: list[str] = []
    for rule in INSIGHT_RULES.values():
        generated += [f"insight_{rule.slug}_enabled", f"insight_{rule.slug}_severity"]
        generated += [f"insight_{rule.slug}_{p.name}" for p in rule.params]
    assert len(generated) == len(set(generated))
    assert not set(generated) & set(EXPECTED_J_DEFAULTS)
    # The examples spelled out in plan 11.1.
    for key in (
        "insight_up_429_endpoint_min_429s",
        "insight_up_429_endpoint_share_pct",
        "insight_up_429_endpoint_window_min",
        "insight_cache_low_hit_max_hit_ratio_pct",
        "insight_up_latency_p95_ms",
    ):
        assert key in generated


@pytest.mark.parametrize("module", [insights, insight_params], ids=lambda m: m.__name__)
def test_source_has_no_dash_characters(module: Any) -> None:
    text = Path(module.__file__).read_text(encoding="utf-8")
    for dash in DASHES:
        assert dash not in text


# --- fix pass: spec review 10 -----------------------------------------------------------------------------------------


def test_every_threshold_says_what_it_measures() -> None:
    """Spec review 10: a threshold's description must define the measured value, not repeat its label."""
    from roxy.config import catalog
    from roxy.config.insight_params import INSIGHT_RULES, PARAM_DEFINITIONS

    expected = {f"{rule.rule_id}.{param.name}" for rule in INSIGHT_RULES.values() for param in rule.params}
    assert set(PARAM_DEFINITIONS) == expected
    for rule in INSIGHT_RULES.values():
        for param in rule.params:
            spec = catalog.CATALOG[f"insight_{rule.slug}_{param.name}"]
            definition = PARAM_DEFINITIONS[f"{rule.rule_id}.{param.name}"]
            assert spec.description.startswith(definition), spec.key
            assert not spec.description.startswith(param.label.rstrip(".") + "."), spec.key  # not the bare label
            assert len(definition.split()) >= 8, spec.key
    cpu = catalog.CATALOG["insight_sys_worker_sat_cpu_pct"].description
    assert "worker processes" in cpu
