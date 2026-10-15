"""Tests for the metrics settings group (plan 15.3 I): every key is declared, valid, and fully explained.

What this is
    Checks over `roxy.config.settings.metrics.SETTINGS` that do not need the assembled catalog.

Why it exists
    The catalog is generated documentation as much as validation (plan P3). A missing retention key, a default
    outside its own range, an empty "what happens if" text, a high-risk default or a dash character would reach
    the settings editor, the generated docs and the LLM export, so each is caught here, next to the content.

How it works
    The expected keys, defaults, ranges and v1 lineage are copied from plan 15.3 I, 6.10 and 18.3 into explicit
    tables below (combined plan rows are split into one key each), so a silent change to the module fails.

What to read next
    `src/roxy/config/settings/metrics.py`, then the catalog-wide checks in `roxy/config/catalog.py`.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

from roxy.config.settings.metrics import SETTINGS
from roxy.config.spec import Apply, Group, Risk, SettingSpec, SettingType

KIB = 1024
MIB = 1024 * KIB
GIB = 1024 * MIB

# Every key of plan 15.3 I, one entry per key (rows with "/" or "," are split), including every
# retention_*_days key named in plan 6.10.
EXPECTED_KEYS = [
    "metrics_flush_interval_ms",
    "metrics_queue_max",
    "retention_minute_days",
    "retention_hour_days",
    "retention_day_days",
    "retention_client_minute_days",
    "retention_client_hour_days",
    "retention_client_day_days",
    "retention_events_days",
    "retention_upstream_429_days",
    "retention_recommendations_days",
    "retention_health_days",
    "retention_fingerprints_days",
    "retention_errors_days",
    "retention_anomalies_days",
    "retention_audit_days",
    "retention_settings_history_days",
    "retention_expired_bans_days",
    "retention_exports_days",
    "retention_snapshots_days",
    "events_max_rows",
    "upstream_429_max_rows",
    "health_runs_max",
    "snapshots_max_bytes",
    "storage_total_budget_gb",
    "maintenance_hour",
    "live_tail_buffer",
    "max_exploit_records",
    "max_login_records",
    "max_crawl_records",
    "max_throttle_records",
    "max_endpoint_records",
    "max_header_name_records",
    "max_header_value_records",
    "max_user_agent_records",
    "max_error_records",
    "endpoint_recent_requests",
    "activity_tracking",
    "max_ip_activity_records",
    "max_caller_records",
    "auto_ignore_high_cardinality",
    "capture_enabled",
    "capture_max_records",
    "capture_max_bytes",
    "capture_max_body",
    "capture_ttl_seconds",
    "capture_sample_served_pct",
    "log_hash_client_ips",
    "export_include_ips",
    "export_stable_ip_hash",
]

# v2 defaults from plan 15.3 I and 6.10 (DESIGN.md section 0 overrides none of these keys).
EXPECTED_DEFAULTS: dict[str, Any] = {
    "metrics_flush_interval_ms": 2000,
    "metrics_queue_max": 50000,
    "retention_minute_days": 14,
    "retention_hour_days": 400,
    "retention_day_days": 0,
    "retention_client_minute_days": 3,
    "retention_client_hour_days": 90,
    "retention_client_day_days": 730,
    "retention_events_days": 90,
    "retention_upstream_429_days": 90,
    "retention_recommendations_days": 365,
    "retention_health_days": 180,
    "retention_fingerprints_days": 90,
    "retention_errors_days": 180,
    "retention_anomalies_days": 90,
    "retention_audit_days": 730,
    "retention_settings_history_days": 0,
    "retention_expired_bans_days": 30,
    "retention_exports_days": 14,
    "retention_snapshots_days": 7,
    "events_max_rows": 2000000,
    "upstream_429_max_rows": 200000,
    "health_runs_max": 2000,
    "snapshots_max_bytes": 2147483648,
    "storage_total_budget_gb": 12,
    "maintenance_hour": 4,
    "live_tail_buffer": 500,
    "max_exploit_records": 5000,
    "max_login_records": 5000,
    "max_crawl_records": 5000,
    "max_throttle_records": 5000,
    "max_endpoint_records": 5000,
    "max_header_name_records": 1000,
    "max_header_value_records": 500,
    "max_user_agent_records": 5000,
    "max_error_records": 2000,
    "endpoint_recent_requests": 10,
    "activity_tracking": 1,
    "max_ip_activity_records": 500,
    "max_caller_records": 500,
    "auto_ignore_high_cardinality": 1,
    "capture_enabled": 1,
    "capture_max_records": 2000,
    "capture_max_bytes": 67108864,
    "capture_max_body": 16384,
    "capture_ttl_seconds": 900,
    "capture_sample_served_pct": 20,
    "log_hash_client_ips": 0,
    "export_include_ips": 0,
    "export_stable_ip_hash": 0,
}

# (min, max) from plan 15.3 I; booleans are not listed.
_RETENTION_RANGE = (1, 3650)
EXPECTED_RANGES: dict[str, tuple[int, int]] = {
    "metrics_flush_interval_ms": (250, 60000),
    "metrics_queue_max": (1000, 1000000),
    "retention_minute_days": (1, 90),
    "retention_hour_days": (7, 3650),
    "retention_day_days": (0, 36500),
    "retention_client_minute_days": (1, 30),
    "retention_client_hour_days": (7, 400),
    "retention_client_day_days": (30, 3650),
    "retention_events_days": _RETENTION_RANGE,
    "retention_upstream_429_days": _RETENTION_RANGE,
    "retention_recommendations_days": _RETENTION_RANGE,
    "retention_health_days": _RETENTION_RANGE,
    "retention_fingerprints_days": _RETENTION_RANGE,
    "retention_errors_days": _RETENTION_RANGE,
    "retention_anomalies_days": _RETENTION_RANGE,
    "retention_audit_days": (400, 3650),
    "retention_settings_history_days": (0, 3650),
    "retention_expired_bans_days": _RETENTION_RANGE,
    "retention_exports_days": _RETENTION_RANGE,
    "retention_snapshots_days": _RETENTION_RANGE,
    "events_max_rows": (10000, 50000000),
    "upstream_429_max_rows": (10000, 50000000),
    "health_runs_max": (100, 100000),
    "snapshots_max_bytes": (0, 100 * GIB),
    "storage_total_budget_gb": (1, 1000),
    "maintenance_hour": (0, 23),
    "live_tail_buffer": (0, 5000),
    "max_exploit_records": (0, 1000000),
    "max_login_records": (0, 1000000),
    "max_crawl_records": (0, 1000000),
    "max_throttle_records": (0, 1000000),
    "max_endpoint_records": (1, 100000),
    "max_header_name_records": (1, 100000),
    "max_header_value_records": (1, 100000),
    "max_user_agent_records": (1, 100000),
    "max_error_records": (1, 100000),
    "endpoint_recent_requests": (0, 50),
    "max_ip_activity_records": (1, 100000),
    "max_caller_records": (1, 100000),
    "capture_max_records": (0, 100000),
    "capture_max_bytes": (0, 1 * GIB),
    "capture_max_body": (0, 512 * KIB),
    "capture_ttl_seconds": (0, 86400),
    "capture_sample_served_pct": (0, 100),
}

BOOL_KEYS = {
    "activity_tracking",
    "auto_ignore_high_cardinality",
    "capture_enabled",
    "log_hash_client_ips",
    "export_include_ips",
    "export_stable_ip_hash",
}

# v1 lineage (plan 18.3 and app/runtime.py): key -> (renamed_from, v1_default).
EXPECTED_V1: dict[str, tuple[str | None, Any]] = {
    "metrics_flush_interval_ms": ("autosave_interval", 30),
    "live_tail_buffer": ("max_live_requests", 150),
    "max_exploit_records": (None, 20),
    "max_login_records": (None, 20),
    "max_crawl_records": (None, 20),
    "max_throttle_records": (None, 20),
    "max_endpoint_records": (None, 200),
    "max_header_name_records": (None, 300),
    "max_header_value_records": (None, 200),
    "max_user_agent_records": (None, 1000),
    "max_error_records": (None, 1000),
    "endpoint_recent_requests": (None, 5),
    "activity_tracking": (None, 1),
    "max_ip_activity_records": (None, 400),
    "max_caller_records": (None, 200),
    "auto_ignore_high_cardinality": (None, 1),
    "capture_enabled": (None, 1),
    "capture_max_records": (None, 250),
    "capture_max_bytes": (None, 4 * MIB),
    "capture_max_body": (None, 16 * KIB),
    "capture_ttl_seconds": (None, 900),
}

# Dashboard anchors from DESIGN.md section 9 that this group may use.
ALLOWED_PAGES = {
    "system#metrics-pipeline",
    "live#tail",
    "live#capture",
    "data#retention",
    "data#record-caps",
    "data#exports",
}

# Plan 11.5 rule ids.
KNOWN_RULE_IDS = {
    "UP-429-ENDPOINT", "UP-429-HOST", "UP-429-CREDENTIAL", "UP-429-AMPLIFY", "UP-RETRYAFTER-IGNORED",
    "UP-4XX-SPIKE", "UP-CSRF-LOOP", "UP-CHALLENGE", "UP-UA-EXPERIMENT", "UP-5XX", "UP-TIMEOUT", "UP-LATENCY",
    "UP-QUEUE-SAT", "UP-BUCKET-TUNE", "UP-BREAKER-FLAP", "CACHE-LOW-HIT", "CACHE-TTL-TUNE", "CACHE-KEYSPLIT",
    "CACHE-PRESSURE", "CACHE-OFF", "CACHE-NEG", "HOT-ENDPOINT", "EGR-BURN", "EGR-UNDERUSE", "EGR-POOL-BURNED",
    "EGR-CALIBRATE", "CRED-EXPIRING", "CRED-UNUSED", "CRED-ROTATOR-GUARD", "ABUSE-SPAM", "ABUSE-BOT",
    "ABUSE-DIST", "FILTER-ADD", "FILTER-REMOVE", "FILTER-COLLATERAL", "TARPIT-TUNE", "THROTTLE-TUNE",
    "PLACE-HEAVY", "SYS-DISK", "SYS-WORKER-SAT", "SYS-LOOP-LAG", "SYS-ERRORS", "SYS-METRICS-DROP",
    "SYS-CHANGE-REGRESSION", "SYS-HEALTH-FAIL", "SEC-ADMIN-ALLOWLIST", "SEC-BYPASS-FOREVER", "HOST-ADD",
    "CRED-PROBE-COST", "SEC-DEFAULTS",
}  # fmt: skip

# Keys from other groups this module may cross-link to (all named in plan 15.3).
EXTERNAL_RELATED = {
    "ui_timezone",
    "recommendation_expiry_days",
    "health_auto_interval_h",
    "cache_max_bytes",
    "max_body_bytes",
    "allowed_requests_per_minute",
    "user_agent_rules_enabled",
}

# Privacy and security keys: never auto-applied (plan 11.4).
NO_AUTO_APPLY = {
    "retention_audit_days",
    "max_login_records",
    "max_exploit_records",
    "activity_tracking",
    "log_hash_client_ips",
    "export_include_ips",
    "export_stable_ip_hash",
    "capture_enabled",
    "capture_ttl_seconds",
}

# British spellings banned by plan C5. The brackets keep this file from tripping the style check itself.
BANNED_SPELLINGS = [
    r"behavio[u]r", r"colo[u]r", r"hono[u]r", r"favo[u]r", r"analy[s]e", r"optimi[s]e", r"normali[s]e",
    r"seriali[s]e", r"initiali[s]e", r"utili[s]e", r"recogni[s]e", r"minimi[s]e", r"maximi[s]e",
    r"prioriti[s]e", r"summari[s]e", r"authori[s]e", r"categori[s]e", r"organi[s]e", r"cent[r]e\b",
    r"licen[c]e", r"defen[c]e", r"offen[c]e", r"catalo[g]ue", r"dialo[g]ue", r"cancel[l]ed", r"label[l]ed",
    r"model[l]ed", r"signal[l]ed", r"travel[l]ed", r"\benro[l]\b", r"enro[l]ment", r"\bfulfi[l]\b",
    r"program[m]e", r"arte[f]act", r"\bgr[e]y\b", r"judge[m]ent", r"whi[l]st", r"amon[g]st",
]  # fmt: skip
DASHES = (chr(0x2013), chr(0x2014))  # en dash and em dash, built from code points so this file has none

BY_KEY: dict[str, SettingSpec] = {spec.key: spec for spec in SETTINGS}


def _texts(spec: SettingSpec) -> list[str]:
    """Every human-readable string of one spec."""
    texts = [
        spec.label,
        spec.description,
        spec.unit,
        spec.if_raised,
        spec.if_lowered,
        spec.if_enabled,
        spec.if_disabled,
        spec.notes,
    ]
    texts += [condition.why for condition in spec.high_risk_if]
    texts += [f"{option.label} {option.description}" for option in spec.options]
    return texts


def test_every_expected_key_is_declared_exactly_once() -> None:
    keys = [spec.key for spec in SETTINGS]
    assert len(keys) == len(set(keys)), "duplicate keys"
    assert set(keys) == set(EXPECTED_KEYS)
    assert len(EXPECTED_KEYS) == len(set(EXPECTED_KEYS))


def test_tables_cover_every_key() -> None:
    assert set(EXPECTED_DEFAULTS) == set(EXPECTED_KEYS)
    assert set(EXPECTED_RANGES) | BOOL_KEYS == set(EXPECTED_KEYS)


@pytest.mark.parametrize("key", EXPECTED_KEYS)
def test_group_apply_and_since(key: str) -> None:
    spec = BY_KEY[key]
    assert spec.group is Group.METRICS
    assert spec.apply is Apply.LIVE  # plan 15.3 I: every key hot-reloads
    assert spec.since == "2.0"
    assert spec.sensitive is False  # no secrets in this group
    assert spec.pending_owner_verification is False


@pytest.mark.parametrize("key", EXPECTED_KEYS)
def test_default_matches_plan(key: str) -> None:
    spec = BY_KEY[key]
    assert spec.default == EXPECTED_DEFAULTS[key]
    assert type(spec.default) is int  # bytes, durations, days and booleans are all plain integers here


@pytest.mark.parametrize("key", EXPECTED_KEYS)
def test_default_validates_against_its_own_bounds(key: str) -> None:
    spec = BY_KEY[key]
    if spec.type is SettingType.BOOL:
        assert spec.default in (0, 1)
        assert spec.min is None
        assert spec.max is None
        return
    assert spec.type in {SettingType.INT, SettingType.BYTES, SettingType.DURATION, SettingType.PERCENT}
    assert spec.min is not None
    assert spec.max is not None
    assert (spec.min, spec.max) == EXPECTED_RANGES[key]
    assert spec.min <= spec.default <= spec.max
    assert spec.step is not None
    assert spec.step > 0
    assert spec.unit, "numbers need a unit"
    if spec.options:
        assert spec.default in spec.option_values()


@pytest.mark.parametrize("key", EXPECTED_KEYS)
def test_required_text_is_present(key: str) -> None:
    spec = BY_KEY[key]
    assert spec.label.strip()
    assert spec.description.strip()
    sentences = re.findall(r"[.!?](?:\s|$)", spec.description.strip())
    assert 1 <= len(sentences) <= 3, f"{key}: description should be 1 to 3 sentences"
    if spec.type is SettingType.BOOL:
        assert spec.if_enabled.strip()
        assert spec.if_disabled.strip()
        assert not spec.if_raised
        assert not spec.if_lowered
    else:
        assert spec.if_raised.strip()
        assert spec.if_lowered.strip()
        assert not spec.if_enabled
        assert not spec.if_disabled
    for condition in spec.high_risk_if:
        assert condition.why.strip()


@pytest.mark.parametrize("key", EXPECTED_KEYS)
def test_text_has_no_dashes_or_british_spelling(key: str) -> None:
    for text in _texts(BY_KEY[key]):
        for dash in DASHES:
            assert dash not in text, f"{key}: dash character in {text!r}"
        for pattern in BANNED_SPELLINGS:
            assert not re.search(pattern, text, re.IGNORECASE), f"{key}: {pattern} in {text!r}"


@pytest.mark.parametrize("key", EXPECTED_KEYS)
def test_pages_are_valid_anchors(key: str) -> None:
    pages = BY_KEY[key].pages
    assert pages, "at least one dashboard anchor"
    assert set(pages) <= ALLOWED_PAGES
    assert len(pages) == len(set(pages))


def test_pages_follow_plan_15_6() -> None:
    for key in EXPECTED_KEYS:
        pages = BY_KEY[key].pages
        if key.startswith("metrics_"):
            assert "system#metrics-pipeline" in pages
        if key.startswith("retention_") or key in {
            "events_max_rows",
            "upstream_429_max_rows",
            "health_runs_max",
            "snapshots_max_bytes",
            "storage_total_budget_gb",
            "maintenance_hour",
        }:
            assert "data#retention" in pages
        if re.fullmatch(r"max_\w+_records", key) or key in {
            "endpoint_recent_requests",
            "activity_tracking",
            "auto_ignore_high_cardinality",
        }:
            assert "data#record-caps" in pages
        if key.startswith("capture_"):
            assert "live#capture" in pages
        if key.startswith("export_") or key == "log_hash_client_ips":
            assert "data#exports" in pages
    assert set(BY_KEY["live_tail_buffer"].pages) == {"system#metrics-pipeline", "live#tail"}


@pytest.mark.parametrize("key", EXPECTED_KEYS)
def test_defaults_are_never_high_risk(key: str) -> None:
    spec = BY_KEY[key]
    assert spec.is_high_risk_value(spec.default) is None
    if spec.high_risk_if:
        assert spec.risk in {Risk.MEDIUM, Risk.HIGH}
        assert "SEC-DEFAULTS" in spec.related_recommendations


def test_high_risk_values() -> None:
    assert BY_KEY["export_include_ips"].risk is Risk.HIGH
    assert BY_KEY["export_include_ips"].is_high_risk_value(1)
    assert BY_KEY["export_stable_ip_hash"].is_high_risk_value(1)
    assert BY_KEY["snapshots_max_bytes"].is_high_risk_value(0)
    assert BY_KEY["activity_tracking"].is_high_risk_value(0)
    assert BY_KEY["max_login_records"].is_high_risk_value(0)
    assert BY_KEY["capture_ttl_seconds"].is_high_risk_value(7200)
    assert BY_KEY["metrics_queue_max"].is_high_risk_value(500000)
    assert BY_KEY["metrics_queue_max"].is_high_risk_value(200000) is None


def test_retention_special_cases() -> None:
    # Plan 6.10: the audit log keeps at least 400 days, enforced.
    assert BY_KEY["retention_audit_days"].min == 400
    # 0 means forever only for day rollups and settings history; every other retention key needs at least 1.
    zero_means_forever = {"retention_day_days", "retention_settings_history_days"}
    for key in EXPECTED_KEYS:
        spec = BY_KEY[key]
        if key.startswith("retention_") and key not in zero_means_forever:
            assert spec.min is not None
            assert spec.min >= 1, key
    # Day rollups: 0 or 30 and up; 1 to 29 would delete days before they are compacted into months.
    day = BY_KEY["retention_day_days"]
    assert day.is_high_risk_value(0) is None
    assert day.is_high_risk_value(30) is None
    for value in (1, 15, 29):
        assert day.is_high_risk_value(value), value


def test_byte_values_are_exact_integers() -> None:
    assert BY_KEY["snapshots_max_bytes"].default == 2147483648
    assert BY_KEY["snapshots_max_bytes"].max == 107374182400
    assert BY_KEY["capture_max_bytes"].default == 67108864
    assert BY_KEY["capture_max_bytes"].max == 1073741824
    assert BY_KEY["capture_max_body"].max == 524288
    for key in ("snapshots_max_bytes", "capture_max_bytes", "capture_max_body"):
        assert BY_KEY[key].type is SettingType.BYTES
        assert BY_KEY[key].unit == "bytes"


@pytest.mark.parametrize("key", EXPECTED_KEYS)
def test_related_links_are_known(key: str) -> None:
    spec = BY_KEY[key]
    assert set(spec.related_recommendations) <= KNOWN_RULE_IDS
    assert key not in spec.related_settings
    for other in spec.related_settings:
        assert other in BY_KEY or other in EXTERNAL_RELATED, f"{key}: unknown related setting {other}"


def test_auto_apply_bounds() -> None:
    with_bounds = {spec.key for spec in SETTINGS if spec.auto_apply_bounds is not None}
    assert with_bounds == {"metrics_flush_interval_ms", "metrics_queue_max"}
    assert not with_bounds & NO_AUTO_APPLY
    for key in with_bounds:
        spec = BY_KEY[key]
        assert spec.auto_apply_bounds is not None
        low, high = spec.auto_apply_bounds
        assert spec.min is not None
        assert spec.max is not None
        assert spec.min <= low <= spec.default <= high <= spec.max
        assert spec.is_high_risk_value(high) is None, "auto-apply must never reach a high-risk value"
        assert "SYS-METRICS-DROP" in spec.related_recommendations


@pytest.mark.parametrize("key", EXPECTED_KEYS)
def test_v1_lineage(key: str) -> None:
    spec = BY_KEY[key]
    renamed_from, v1_default = EXPECTED_V1.get(key, (None, None))
    assert spec.renamed_from == renamed_from
    assert spec.v1_default == v1_default
