"""Catalog content tests for the tarpit settings group (plan 15.3 F, 10.6 and 15.6).

Every key in the plan table must be declared exactly once with the plan's v2 default and range, every default
must validate against its own bounds, every text field the spec requires must be filled in, and no text may use
a dash character or a British spelling (plan C5). The checks are written out here, not shared, so this file does
not depend on fixtures other agents own.
"""

from __future__ import annotations

import math
import re
from typing import Any

import pytest

from roxy.config.settings.tarpit import SETTINGS
from roxy.config.spec import Apply, Group, SettingSpec, SettingType

# key -> (v2 default, min, max) from the plan 15.3 F table. None means "not a number range".
EXPECTED: dict[str, tuple[Any, float | None, float | None]] = {
    "tarpit_enabled": (1, None, None),
    "tarpit_min_seconds": (8, 0, 55),
    "tarpit_max_seconds": (20, 1, 55),
    "tarpit_max_concurrent": (50, 0, 500),
    "tarpit_max_capacity_fraction": (0.25, 0.05, 0.5),
    "tarpit_connection_budget": (4000, 100, 100000),
    "tarpit_slot_grace_s": (15, 1, 120),
    "tarpit_default_type": ("hold", None, None),
    "tarpit_drip_interval_ms": (1000, 100, 10000),
    "tarpit_jitter_min_ms": (500, 0, 10000),
    "tarpit_jitter_max_ms": (3000, 0, 10000),
    # Category switches: plan order header_rule, probe, throttle, throttle_all, endpoint_rule, blocked_endpoint,
    # auth_attempt, user_agent_rule, ban, spam, upstream_cooldown_retry -> 1,1,0,0,0,0,1,0,1,1,0.
    "tarpit_on_header_rule": (1, None, None),
    "tarpit_on_probe": (1, None, None),
    "tarpit_on_throttle": (0, None, None),
    "tarpit_on_throttle_all": (0, None, None),
    "tarpit_on_endpoint_rule": (0, None, None),
    "tarpit_on_blocked_endpoint": (0, None, None),
    "tarpit_on_auth_attempt": (1, None, None),
    "tarpit_on_user_agent_rule": (0, None, None),
    "tarpit_on_ban": (1, None, None),
    "tarpit_on_spam": (1, None, None),
    "tarpit_on_upstream_cooldown_retry": (0, None, None),
}

# v1 defaults for keys that existed in v1 (runtime settings or former constants); app/runtime.py, app/config.py.
EXPECTED_V1: dict[str, Any] = {
    "tarpit_enabled": 1,
    "tarpit_min_seconds": 8,
    "tarpit_max_seconds": 20,
    "tarpit_max_concurrent": 6,
    "tarpit_max_capacity_fraction": 0.5,
    "tarpit_slot_grace_s": 15,
    "tarpit_on_header_rule": 1,
    "tarpit_on_probe": 1,
    "tarpit_on_throttle": 0,
    "tarpit_on_throttle_all": 0,
    "tarpit_on_endpoint_rule": 0,
    "tarpit_on_blocked_endpoint": 0,
    "tarpit_on_auth_attempt": 0,
}

PAGES = ("protection#tarpit",)
ENUM_OPTIONS = {"tarpit_default_type": {"hold", "drip", "jitter"}}

# Keys from other groups that these specs may link to (all are plan 15.3 keys).
EXTERNAL_RELATED = {
    "request_deadline_s",
    "allowed_requests_per_minute",
    "global_throttle_limit",
    "user_agent_rules_enabled",
    "ban_disguise_as_throttle",
    "throttle_strike_on_retry",
}

# Every rule id in plan 11.5.
# fmt: off
RULE_IDS = {
    "UP-429-ENDPOINT", "UP-429-HOST", "UP-429-CREDENTIAL", "UP-429-AMPLIFY", "UP-RETRYAFTER-IGNORED",
    "UP-4XX-SPIKE", "UP-CSRF-LOOP", "UP-CHALLENGE", "UP-UA-EXPERIMENT", "UP-5XX", "UP-TIMEOUT", "UP-LATENCY",
    "UP-QUEUE-SAT", "UP-BUCKET-TUNE", "UP-BREAKER-FLAP", "CACHE-LOW-HIT", "CACHE-TTL-TUNE", "CACHE-KEYSPLIT",
    "CACHE-PRESSURE", "CACHE-OFF", "CACHE-NEG", "HOT-ENDPOINT", "EGR-BURN", "EGR-UNDERUSE", "EGR-POOL-BURNED",
    "EGR-CALIBRATE", "CRED-EXPIRING", "CRED-UNUSED", "CRED-ROTATOR-GUARD", "ABUSE-SPAM", "ABUSE-BOT",
    "ABUSE-DIST", "FILTER-ADD", "FILTER-REMOVE", "FILTER-COLLATERAL", "TARPIT-TUNE", "THROTTLE-TUNE",
    "PLACE-HEAVY", "SYS-DISK", "SYS-WORKER-SAT", "SYS-LOOP-LAG", "SYS-ERRORS", "SYS-METRICS-DROP",
    "SYS-CHANGE-REGRESSION", "SYS-HEALTH-FAIL", "SEC-ADMIN-ALLOWLIST", "SEC-BYPASS-FOREVER", "HOST-ADD",
    "CRED-PROBE-COST", "SEC-DEFAULTS",
}
# fmt: on

NUMERIC = {SettingType.INT, SettingType.FLOAT, SettingType.DURATION, SettingType.BYTES, SettingType.PERCENT}
# The dash characters banned by plan C5, built with chr() so this file never contains them.
DASHES = (chr(0x2014), chr(0x2013))
# British spellings (plan C5). The brackets keep each pattern from matching its own source text.
BRITISH = re.compile(
    r"behavio[u]r|colo[u]r|hono[u]r|favo[u]r|neighbo[u]r|analy[s]e|optimi[s]e|normali[s]e|initiali[s]e|"
    r"recogni[s]e|summari[s]e|authori[s]e|prioriti[s]e|customi[s]e|cent[r]e\b|licen[c]e|defen[c]e|catalo[g]ue|"
    r"dialo[g]ue|cancel[l]ed|label[l]ed|model[l]ed|enro[l]ment|\benro[l]\b|\bgr[e]y\b|judge[m]ent|whi[l]st|"
    r"amon[g]st|randomi[s]e",
    re.IGNORECASE,
)

BY_KEY: dict[str, SettingSpec] = {spec.key: spec for spec in SETTINGS}


def _texts(spec: SettingSpec) -> list[str]:
    """Every human-readable string on a spec, including options and risk reasons."""
    texts = [spec.label, spec.description, spec.unit, spec.if_raised, spec.if_lowered, spec.if_enabled]
    texts += [spec.if_disabled, spec.notes]
    texts += [part for option in spec.options for part in (option.label, option.description)]
    texts += [condition.why for condition in spec.high_risk_if]
    return texts


def test_every_plan_key_is_declared_exactly_once() -> None:
    keys = [spec.key for spec in SETTINGS]
    assert len(keys) == len(set(keys)), "duplicate keys"
    assert set(keys) == set(EXPECTED), f"missing {set(EXPECTED) - set(keys)}, extra {set(keys) - set(EXPECTED)}"


@pytest.mark.parametrize("key", sorted(EXPECTED))
def test_default_and_range_match_the_plan(key: str) -> None:
    spec = BY_KEY[key]
    default, low, high = EXPECTED[key]
    assert spec.default == default
    assert spec.min == low
    assert spec.max == high


@pytest.mark.parametrize("spec", SETTINGS, ids=lambda spec: spec.key)
def test_default_validates_against_its_own_bounds(spec: SettingSpec) -> None:
    if spec.type in NUMERIC:
        assert spec.min is not None
        assert spec.max is not None
        assert spec.min <= spec.default <= spec.max
        assert not isinstance(spec.default, bool)
        if spec.type is not SettingType.FLOAT:
            assert isinstance(spec.default, int)
        assert spec.step is not None
        assert spec.step > 0
        steps = (spec.default - spec.min) / spec.step
        assert math.isclose(steps, round(steps), abs_tol=1e-9), "default is not on a step boundary"
    elif spec.type is SettingType.BOOL:
        assert type(spec.default) is int
        assert spec.default in (0, 1)
    elif spec.type is SettingType.ENUM:
        values = spec.option_values()
        assert len(values) == len(set(values)), "duplicate option values"
        assert set(values) == ENUM_OPTIONS[spec.key]
        assert spec.default in values
    else:
        pytest.fail(f"unexpected type {spec.type} for {spec.key}")


@pytest.mark.parametrize("spec", SETTINGS, ids=lambda spec: spec.key)
def test_required_text_is_present(spec: SettingSpec) -> None:
    assert spec.label.strip()
    assert spec.description.strip()
    if spec.type in NUMERIC:
        assert spec.unit.strip()
        assert spec.if_raised.strip()
        assert spec.if_lowered.strip()
    elif spec.type is SettingType.BOOL:
        assert spec.if_enabled.strip()
        assert spec.if_disabled.strip()
    elif spec.type is SettingType.ENUM:
        assert spec.options
        for option in spec.options:
            assert option.label.strip()
            assert option.description.strip()
    for condition in spec.high_risk_if:
        assert condition.why.strip()


@pytest.mark.parametrize("spec", SETTINGS, ids=lambda spec: spec.key)
def test_text_style(spec: SettingSpec) -> None:
    for text in _texts(spec):
        assert not any(dash in text for dash in DASHES), f"dash character in {spec.key}: {text!r}"
        assert BRITISH.search(text) is None, f"British spelling in {spec.key}: {text!r}"


@pytest.mark.parametrize("spec", SETTINGS, ids=lambda spec: spec.key)
def test_metadata(spec: SettingSpec) -> None:
    assert spec.group is Group.TARPIT
    assert spec.pages == PAGES
    assert spec.apply is Apply.LIVE
    assert spec.sensitive is False
    assert spec.renamed_from is None
    assert spec.pending_owner_verification is False
    assert spec.v1_default == EXPECTED_V1.get(spec.key)
    assert spec.is_high_risk_value(spec.default) is None, "the shipped default must not be a high-risk value"
    if spec.high_risk_if:
        assert "SEC-DEFAULTS" in spec.related_recommendations
    assert set(spec.related_recommendations) <= RULE_IDS
    assert spec.key not in spec.related_settings
    assert len(spec.related_settings) == len(set(spec.related_settings))
    for related in spec.related_settings:
        assert related in BY_KEY or related in EXTERNAL_RELATED, f"{spec.key} links to unknown key {related}"


@pytest.mark.parametrize("spec", [s for s in SETTINGS if s.auto_apply_bounds is not None], ids=lambda s: s.key)
def test_auto_apply_bounds_inside_range(spec: SettingSpec) -> None:
    assert spec.auto_apply_bounds is not None
    low, high = spec.auto_apply_bounds
    assert spec.min is not None
    assert spec.max is not None
    assert spec.min <= low < high <= spec.max
    assert low <= spec.default <= high


def test_cross_field_defaults_are_consistent() -> None:
    assert BY_KEY["tarpit_min_seconds"].default <= BY_KEY["tarpit_max_seconds"].default
    assert BY_KEY["tarpit_jitter_min_ms"].default <= BY_KEY["tarpit_jitter_max_ms"].default
    # Plan 10.6: with defaults the effective cap is min(50, floor(4000 x 0.25)) = 50.
    budget = BY_KEY["tarpit_connection_budget"].default * BY_KEY["tarpit_max_capacity_fraction"].default
    assert min(BY_KEY["tarpit_max_concurrent"].default, math.floor(budget)) == 50
