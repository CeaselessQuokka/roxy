"""Catalog content tests for the admin security and sessions group (plan 15.3 G, 9.5, 9.6 and 15.6).

Every key in the plan table must be declared exactly once with the plan's v2 default and range, every default
must validate against its own bounds, every text field the spec requires must be filled in, no value that weakens
login security may ship as a default, and the recommendation engine may never auto-tune any of these (plan 11.4).
The checks are written out here, not shared, so this file does not depend on fixtures other agents own.
"""

from __future__ import annotations

import math
import re
from typing import Any

import pytest

from roxy.config.settings.admin_security import SETTINGS
from roxy.config.spec import Apply, Group, Risk, SettingSpec, SettingType

# key -> (v2 default, min, max) from the plan 15.3 G table. None means "not a number range".
EXPECTED: dict[str, tuple[Any, float | None, float | None]] = {
    "admin_session_idle_timeout_s": (900, 60, 86400),
    "admin_heartbeat_interval_s": (30, 5, 300),
    "admin_activity_window_s": (60, 10, 900),
    "admin_session_max_age_s": (43200, 600, 604800),
    "admin_reauth_window_s": (600, 60, 3600),
    "admin_login_max_failures": (5, 1, 100),
    "admin_login_window_s": (600, 60, 86400),
    "admin_login_global_max_per_min": (30, 1, 1000),
    "admin_login_global_delay_s": (5, 0, 30),
    "admin_email_code_enabled": (0, None, None),
    "two_fa_expiration": (300, 30, 900),
    "email_code_digits": (16, 8, 20),
    "challenge_expiration": (120, 30, 600),
    "admin_trusted_devices_enabled": (1, None, None),
    "trusted_device_days": (30, 1, 90),
    "invalidation_link_ttl_s": (86400, 600, 604800),
    "admin_allowlist_enabled": (0, None, None),
}

# v1 defaults for keys that existed in v1 (runtime settings or former constants); app/runtime.py, app/config.py.
EXPECTED_V1: dict[str, Any] = {
    "admin_session_idle_timeout_s": 120,
    "admin_heartbeat_interval_s": 10,
    "admin_login_max_failures": 5,
    "admin_login_window_s": 600,
    "two_fa_expiration": 60,
    "email_code_digits": 16,
    "challenge_expiration": 60,
    "trusted_device_days": 30,
    "invalidation_link_ttl_s": 86400,
}

PAGES = ("security#admin-access",)

# Values that must be flagged as high risk (each weakens login security), checked against `is_high_risk_value`.
MUST_BE_HIGH_RISK: dict[str, Any] = {
    "admin_email_code_enabled": 1,
    "admin_session_idle_timeout_s": 86400,
    "admin_session_max_age_s": 604800,
    "admin_login_max_failures": 100,
    "admin_login_window_s": 60,
    "admin_login_global_delay_s": 0,
}

# Keys from other groups that these specs may link to (all are plan 15.3 keys).
EXTERNAL_RELATED: set[str] = set()

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
    for condition in spec.high_risk_if:
        assert condition.why.strip()


@pytest.mark.parametrize("spec", SETTINGS, ids=lambda spec: spec.key)
def test_text_style(spec: SettingSpec) -> None:
    for text in _texts(spec):
        assert not any(dash in text for dash in DASHES), f"dash character in {spec.key}: {text!r}"
        assert BRITISH.search(text) is None, f"British spelling in {spec.key}: {text!r}"


@pytest.mark.parametrize("spec", SETTINGS, ids=lambda spec: spec.key)
def test_metadata(spec: SettingSpec) -> None:
    assert spec.group is Group.ADMIN_SECURITY
    assert spec.pages == PAGES
    assert spec.apply is Apply.LIVE
    assert spec.sensitive is False
    assert spec.renamed_from is None
    assert spec.pending_owner_verification is False
    assert spec.v1_default == EXPECTED_V1.get(spec.key)
    # Plan 11.4: auto-apply never touches security settings.
    assert spec.auto_apply_bounds is None
    assert spec.is_high_risk_value(spec.default) is None, "the shipped default must not be a high-risk value"
    if spec.high_risk_if:
        assert "SEC-DEFAULTS" in spec.related_recommendations
    assert set(spec.related_recommendations) <= RULE_IDS
    assert spec.key not in spec.related_settings
    assert len(spec.related_settings) == len(set(spec.related_settings))
    for related in spec.related_settings:
        assert related in BY_KEY or related in EXTERNAL_RELATED, f"{spec.key} links to unknown key {related}"


@pytest.mark.parametrize("key", sorted(MUST_BE_HIGH_RISK))
def test_weakening_values_are_flagged_high_risk(key: str) -> None:
    assert BY_KEY[key].is_high_risk_value(MUST_BE_HIGH_RISK[key])


def test_owner_decisions_are_reflected() -> None:
    # D5: the emailed code is off and is the one high-risk switch in this group.
    assert BY_KEY["admin_email_code_enabled"].risk is Risk.HIGH
    # D6: the admin allowlist ships off, and SEC-ADMIN-ALLOWLIST is what proposes turning it on.
    assert "SEC-ADMIN-ALLOWLIST" in BY_KEY["admin_allowlist_enabled"].related_recommendations
    # The heartbeat must fire well inside the idle timeout, or active sessions would expire.
    assert BY_KEY["admin_heartbeat_interval_s"].default * 3 <= BY_KEY["admin_session_idle_timeout_s"].default
