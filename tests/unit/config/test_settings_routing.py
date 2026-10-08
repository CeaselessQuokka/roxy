"""Tests for the Routing and egress settings group (plan 15.3 A).

What this is
    Checks on `roxy.config.settings.routing.SETTINGS`: every key from the plan table is declared exactly once,
    every default passes its own range, options and list bounds, every required help text is present, page
    anchors and recommendation ids are real, and the text follows the house style (plan C5).

Why it exists
    The catalog is the single source of truth for settings (plan P3). A missing key or a default outside its
    own range would only surface when the catalog self-check runs at import, so this group is checked on its
    own as well.

How it works
    Plain assertions over the frozen `SettingSpec` objects. No database, network or app is needed.

What to read next
    `src/roxy/config/settings/routing.py`, then `src/roxy/config/catalog.py` (the whole-catalog self-check).
"""

from __future__ import annotations

import dataclasses
import re
from typing import Any

import pytest

from roxy.config.settings import routing
from roxy.config.spec import Group, OptionSpec, RiskCondition, SettingSpec, SettingType

# Every key of plan 15.3 A, one entry per key (rows that combine keys with "/" are split).
EXPECTED_KEYS = (
    "direct_enabled",
    "direct_weight",
    "rotator_weight",
    "direct_shift_threshold_pct",
    "rotator_enabled",
    "rotator_cooldown_s",
    "rotator_max_failures",
    "rotator_session_mode",
    "rotator_sticky_seconds",
    "rotator_country",
    "rotator_session_username_template",
    "rotator_max_sessions",
    "rotator_cooldown_distinct_exits",
    "rotator_cooldown_window_s",
    "rotator_quota_gb_per_month",
    "rotator_price_per_gb_usd",
    "rotator_billing_day",
    "rotator_budget_alert_pcts",
    "rotator_hard_stop_pct",
    "rotator_daily_cap_mb",
    "rotator_tls_overhead_bytes",
    "rotator_probe_timeout_s",
    "rotator_recent_ips",
    "strict_host_allowlist",
    "allowed_roblox_hosts",
    "upstream_max_attempts",
    "fallback_on_429",
    "request_timeout",
    "upstream_connect_timeout_s",
    "direct_user_agent",
    "ua_experiment_enabled",
    "ua_experiment_days",
    "ua_experiment_alt_user_agent",
)

# v2 defaults from the plan table (15.3 A); the host list and the UA strings are checked separately.
EXPECTED_DEFAULTS: dict[str, Any] = {
    "direct_enabled": 1,
    "direct_weight": 100,
    "rotator_weight": 0,
    "direct_shift_threshold_pct": 80,
    "rotator_enabled": 1,
    "rotator_cooldown_s": 60,
    "rotator_max_failures": 3,
    "rotator_session_mode": "sticky_until_429",
    "rotator_sticky_seconds": 300,
    "rotator_country": "",
    "rotator_session_username_template": "",
    "rotator_max_sessions": 16,
    "rotator_cooldown_distinct_exits": 3,
    "rotator_cooldown_window_s": 60,
    "rotator_quota_gb_per_month": 0,
    "rotator_price_per_gb_usd": 0,
    "rotator_billing_day": 1,
    "rotator_budget_alert_pcts": [50, 80, 95],
    "rotator_hard_stop_pct": 100,
    "rotator_daily_cap_mb": 0,
    "rotator_tls_overhead_bytes": 6000,
    "rotator_probe_timeout_s": 10,
    "rotator_recent_ips": 50,
    "strict_host_allowlist": 1,
    "upstream_max_attempts": 2,
    "fallback_on_429": 0,
    "request_timeout": 15,
    "upstream_connect_timeout_s": 5,
    "ua_experiment_enabled": 0,
    "ua_experiment_days": 7,
}

# Ranges from the plan table: key -> (min, max).
EXPECTED_RANGES: dict[str, tuple[float, float]] = {
    "direct_weight": (0, 1000),
    "rotator_weight": (0, 1000),
    "direct_shift_threshold_pct": (0, 100),
    "rotator_cooldown_s": (5, 3600),
    "rotator_max_failures": (1, 50),
    "rotator_sticky_seconds": (10, 3600),
    "rotator_max_sessions": (1, 256),
    "rotator_cooldown_distinct_exits": (1, 20),
    "rotator_cooldown_window_s": (10, 3600),
    "rotator_quota_gb_per_month": (0, 100000),
    "rotator_price_per_gb_usd": (0, 100),
    "rotator_billing_day": (1, 28),
    "rotator_hard_stop_pct": (0, 200),
    "rotator_daily_cap_mb": (0, 1000000),
    "rotator_tls_overhead_bytes": (0, 50000),
    "rotator_probe_timeout_s": (1, 60),
    "rotator_recent_ips": (0, 500),
    "upstream_max_attempts": (1, 5),
    "request_timeout": (1, 120),
    "upstream_connect_timeout_s": (1, 30),
    "ua_experiment_days": (1, 30),
}

# v1 keys and defaults (plan 15.3 A, 15.4 and 18.3): key -> (renamed_from, v1_default).
EXPECTED_V1: dict[str, tuple[str | None, Any]] = {
    "direct_weight": ("token_weight", 75),
    "rotator_weight": ("rotate_weight", 25),
    "direct_shift_threshold_pct": ("token_danger_zone", 60),
    "rotator_enabled": ("rotate_enabled", 1),
    "rotator_cooldown_s": ("rotate_cooldown", 60),
    "rotator_max_failures": ("rotate_max_failures", 3),
    "upstream_max_attempts": ("max_retries_per_request", 3),
    "request_timeout": (None, 15),
    "rotator_probe_timeout_s": (None, 10),
    "rotator_recent_ips": (None, 20),
    "fallback_on_429": (None, 1),
}

# DESIGN.md section 9: every valid `pages` anchor.
VALID_PAGE_ANCHORS = frozenset(
    {
        "upstream#routing",
        "upstream#hosts",
        "upstream#buckets",
        "upstream#concurrency",
        "upstream#cooldowns",
        "upstream#breakers",
        "upstream#queue",
        "upstream#retries",
        "egress#rotator",
        "egress#budget",
        "credential#status",
        "credential#budget",
        "cache#settings",
        "cache#coalescing",
        "recommendations#preview-settings",
        "recommendations#engine",
        "data#retention",
        "data#record-caps",
        "data#exports",
        "protection#throttle",
        "protection#limits",
        "protection#places",
        "clients#places",
        "protection#ua-rules",
        "protection#spam",
        "protection#bans",
        "protection#bot",
        "clients#client-score",
        "protection#challenge",
        "protection#bypass",
        "protection#ignored-paths",
        "protection#tarpit",
        "security#admin-access",
        "settings#alerts",
        "system#alerts",
        "health#schedule",
        "system#metrics-pipeline",
        "live#tail",
        "live#capture",
        "settings#public-site",
        "topbar#pause",
        "topbar#throttle-all",
        "user-menu#preferences",
    }
)

# Plan 15.6: the card each routing key must appear on.
REQUIRED_PAGE: dict[str, str] = {
    "direct_enabled": "upstream#routing",
    "direct_weight": "upstream#routing",
    "rotator_weight": "upstream#routing",
    "direct_shift_threshold_pct": "upstream#routing",
    "fallback_on_429": "upstream#routing",
    "upstream_max_attempts": "upstream#routing",
    "request_timeout": "upstream#routing",
    "upstream_connect_timeout_s": "upstream#routing",
    "direct_user_agent": "upstream#routing",
    "ua_experiment_enabled": "upstream#routing",
    "ua_experiment_days": "upstream#routing",
    "ua_experiment_alt_user_agent": "upstream#routing",
    "strict_host_allowlist": "upstream#hosts",
    "allowed_roblox_hosts": "upstream#hosts",
}

# Plan 11.5: every recommendation rule id.
KNOWN_RULE_IDS = frozenset(
    {
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
    }
)

# Settings that guard security: auto-apply may never move them (plan 11.4).
SECURITY_KEYS = ("strict_host_allowlist", "allowed_roblox_hosts")

NUMERIC_TYPES = frozenset(
    {SettingType.INT, SettingType.FLOAT, SettingType.DURATION, SettingType.BYTES, SettingType.PERCENT}
)
LIST_TYPES = frozenset({SettingType.LIST_STR, SettingType.LIST_INT, SettingType.LIST_CIDR})

# Plan C5: British spellings, written with one bracketed letter so this file does not match itself.
BANNED_SPELLINGS = (
    r"behavio[u]r",
    r"colo[u]r",
    r"hono[u]r",
    r"favo[u]r",
    r"analy[s]e",
    r"optimi[s]e",
    r"organi[s]e",
    r"normali[s]e",
    r"seriali[s]e",
    r"initiali[s]e",
    r"utili[s]e",
    r"recogni[s]e",
    r"minimi[s]e",
    r"maximi[s]e",
    r"prioriti[s]e",
    r"customi[s]e",
    r"summari[s]e",
    r"authori[s]e",
    r"categori[s]e",
    r"cent[r]e\b",
    r"licen[c]e",
    r"defen[c]e",
    r"offen[c]e",
    r"catalo[g]ue",
    r"dialo[g]ue",
    r"cancel[l]ed",
    r"cancel[l]ing",
    r"label[l]ed",
    r"model[l]ed",
    r"signal[l]ed",
    r"\benro[l]\b",
    r"enro[l]ment",
    r"\bfulfi[l]\b",
    r"\bgr[e]y\b",
    r"judge[m]ent",
    r"whi[l]st",
    r"amon[g]st",
)
DASHES = (chr(0x2014), chr(0x2013))  # em dash and en dash, built from code points so this file stays ASCII

ROBLOX_HOST = re.compile(r"(?:[a-z0-9-]+\.)+roblox\.com")


def _by_key() -> dict[str, SettingSpec]:
    return {spec.key: spec for spec in routing.SETTINGS}


def _all_text(spec: SettingSpec) -> list[str]:
    """Every human-readable string in one spec: plain fields, option texts, risk reasons and string defaults."""
    texts: list[str] = []
    for field in dataclasses.fields(spec):
        value = getattr(spec, field.name)
        if isinstance(value, str):
            texts.append(value)
        elif isinstance(value, (list, tuple)):
            for item in value:
                if isinstance(item, str):
                    texts.append(item)
                elif isinstance(item, OptionSpec):
                    texts.extend((item.value, item.label, item.description))
                elif isinstance(item, RiskCondition):
                    texts.append(item.why)
    return texts


def test_every_expected_key_is_present_exactly_once() -> None:
    keys = [spec.key for spec in routing.SETTINGS]
    assert len(keys) == len(set(keys)), "duplicate keys in routing.SETTINGS"
    assert set(keys) == set(EXPECTED_KEYS)
    assert len(EXPECTED_KEYS) == len(set(EXPECTED_KEYS))


def test_every_spec_is_in_the_routing_group() -> None:
    for spec in routing.SETTINGS:
        assert isinstance(spec, SettingSpec)
        assert spec.group is Group.ROUTING, spec.key


@pytest.mark.parametrize(("key", "expected"), sorted(EXPECTED_DEFAULTS.items()))
def test_defaults_match_the_plan(key: str, expected: Any) -> None:
    assert _by_key()[key].default == expected


@pytest.mark.parametrize(("key", "bounds"), sorted(EXPECTED_RANGES.items()))
def test_ranges_match_the_plan(key: str, bounds: tuple[float, float]) -> None:
    spec = _by_key()[key]
    assert (spec.min, spec.max) == bounds


@pytest.mark.parametrize("spec", routing.SETTINGS, ids=lambda spec: spec.key)
def test_default_validates_against_its_own_constraints(spec: SettingSpec) -> None:
    value = spec.default
    if spec.type is SettingType.BOOL:
        assert value in (0, 1)
        assert not isinstance(value, bool)
    elif spec.type in NUMERIC_TYPES:
        assert isinstance(value, (int, float))
        assert not isinstance(value, bool)
        if spec.type in (SettingType.INT, SettingType.DURATION, SettingType.BYTES):
            assert isinstance(value, int)
        assert spec.min is not None
        assert spec.max is not None
        assert spec.min <= spec.max
        assert spec.min <= value <= spec.max
        if spec.step:
            assert spec.step > 0
    elif spec.type is SettingType.ENUM:
        assert spec.options, "an enum needs options"
        assert len(set(spec.option_values())) == len(spec.options)
        assert value in spec.option_values()
    elif spec.type is SettingType.STRING:
        assert isinstance(value, str)
        if spec.max_length is not None:
            assert len(value) <= spec.max_length
    elif spec.type in LIST_TYPES:
        assert isinstance(value, list)
        if spec.max_length is not None:
            assert len(value) <= spec.max_length
        for item in value:
            if spec.type is SettingType.LIST_INT:
                assert isinstance(item, int)
                if spec.item_min is not None:
                    assert item >= spec.item_min
                if spec.item_max is not None:
                    assert item <= spec.item_max
            else:
                assert isinstance(item, str)
                assert item
                if spec.item_max_length is not None:
                    assert len(item) <= spec.item_max_length
    else:  # pragma: no cover - a new type needs a new branch here
        pytest.fail(f"unhandled type {spec.type} for {spec.key}")


@pytest.mark.parametrize("spec", routing.SETTINGS, ids=lambda spec: spec.key)
def test_required_text_is_present(spec: SettingSpec) -> None:
    assert spec.label.strip()
    assert spec.description.strip()
    if spec.type in NUMERIC_TYPES or spec.type is SettingType.LIST_INT:
        assert spec.if_raised.strip(), f"{spec.key} needs if_raised"
        assert spec.if_lowered.strip(), f"{spec.key} needs if_lowered"
    if spec.type is SettingType.BOOL:
        assert spec.if_enabled.strip(), f"{spec.key} needs if_enabled"
        assert spec.if_disabled.strip(), f"{spec.key} needs if_disabled"
    if spec.type is SettingType.ENUM:
        for option in spec.options:
            assert option.label.strip(), f"{spec.key}={option.value} needs a label"
            assert option.description.strip(), f"{spec.key}={option.value} needs a description"
    for condition in spec.high_risk_if:
        assert condition.why.strip(), f"{spec.key} risk condition needs a reason"


@pytest.mark.parametrize("spec", routing.SETTINGS, ids=lambda spec: spec.key)
def test_pages_are_valid_anchors(spec: SettingSpec) -> None:
    assert spec.pages, f"{spec.key} needs at least one page anchor"
    for anchor in spec.pages:
        assert anchor in VALID_PAGE_ANCHORS, f"{spec.key}: unknown anchor {anchor}"


def test_pages_follow_plan_15_6() -> None:
    specs = _by_key()
    for key, anchor in REQUIRED_PAGE.items():
        assert anchor in specs[key].pages, key
    for key, spec in specs.items():
        if key.startswith("rotator_"):
            assert "egress#rotator" in spec.pages, key
    for key in ("rotator_quota_gb_per_month", "rotator_price_per_gb_usd"):
        assert "egress#budget" in specs[key].pages


@pytest.mark.parametrize("spec", routing.SETTINGS, ids=lambda spec: spec.key)
def test_related_links_are_well_formed(spec: SettingSpec) -> None:
    for rule_id in spec.related_recommendations:
        assert rule_id in KNOWN_RULE_IDS, f"{spec.key}: unknown rule {rule_id}"
    assert spec.key not in spec.related_settings
    for other in spec.related_settings:
        assert re.fullmatch(r"[a-z][a-z0-9_]*", other), other
    if spec.high_risk_if:
        assert "SEC-DEFAULTS" in spec.related_recommendations, spec.key


@pytest.mark.parametrize(("key", "expected"), sorted(EXPECTED_V1.items()))
def test_v1_names_and_defaults(key: str, expected: tuple[str | None, Any]) -> None:
    spec = _by_key()[key]
    assert (spec.renamed_from, spec.v1_default) == expected


def test_only_the_session_template_is_pending_owner_verification() -> None:
    pending = {spec.key for spec in routing.SETTINGS if spec.pending_owner_verification}
    assert pending == {"rotator_session_username_template"}


def test_auto_apply_bounds_are_inside_the_range_and_never_on_security_settings() -> None:
    specs = _by_key()
    for key in SECURITY_KEYS:
        assert specs[key].auto_apply_bounds is None, key
    for spec in routing.SETTINGS:
        if spec.auto_apply_bounds is None:
            continue
        low, high = spec.auto_apply_bounds
        assert spec.min is not None
        assert spec.max is not None
        assert spec.min <= low <= high <= spec.max, spec.key
        assert spec.related_recommendations, f"{spec.key} has bounds but no rule that could move it"


def test_no_default_is_a_high_risk_value() -> None:
    # Plan P1: every feature ships in its safest configuration.
    for spec in routing.SETTINGS:
        assert spec.is_high_risk_value(spec.default) is None, spec.key


def test_high_risk_conditions_fire_on_the_dangerous_values() -> None:
    specs = _by_key()
    assert specs["strict_host_allowlist"].is_high_risk_value(0)
    assert specs["fallback_on_429"].is_high_risk_value(1)
    assert specs["rotator_hard_stop_pct"].is_high_risk_value(0)
    assert specs["rotator_hard_stop_pct"].is_high_risk_value(150)
    assert specs["rotator_hard_stop_pct"].is_high_risk_value(100) is None


def test_no_setting_here_is_secret() -> None:
    # Nothing in this group holds a secret: the gateway URL lives in rotator_store or a systemd credential.
    assert not any(spec.sensitive for spec in routing.SETTINGS)


def test_default_host_allowlist() -> None:
    hosts = _by_key()["allowed_roblox_hosts"].default
    assert hosts == list(routing.DEFAULT_ALLOWED_ROBLOX_HOSTS)
    assert len(hosts) == 33
    assert len(set(hosts)) == len(hosts)
    for host in hosts:
        assert ROBLOX_HOST.fullmatch(host), host
    assert "games.roblox.com" in hosts


def test_user_agent_defaults() -> None:
    specs = _by_key()
    assert specs["direct_user_agent"].default == routing.DEFAULT_DIRECT_USER_AGENT
    assert specs["direct_user_agent"].default.startswith("Mozilla/5.0")
    alt = specs["ua_experiment_alt_user_agent"].default
    assert alt == routing.DEFAULT_UA_EXPERIMENT_ALT_USER_AGENT
    assert alt.startswith("Roxy/2")
    assert routing.SITE_ORIGIN_PLACEHOLDER in alt


def test_session_mode_options() -> None:
    spec = _by_key()["rotator_session_mode"]
    assert spec.option_values() == ("per_request", "sticky", "sticky_until_429")


@pytest.mark.parametrize("spec", routing.SETTINGS, ids=lambda spec: spec.key)
def test_text_follows_house_style(spec: SettingSpec) -> None:
    for text in _all_text(spec):
        for dash in DASHES:
            assert dash not in text, f"{spec.key}: dash character in {text!r}"
        for pattern in BANNED_SPELLINGS:
            assert not re.search(pattern, text, re.IGNORECASE), f"{spec.key}: {pattern} in {text!r}"
