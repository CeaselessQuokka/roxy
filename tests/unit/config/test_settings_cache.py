"""Tests for the cache settings group (plan 15.3 D): every key is declared, valid, and fully explained.

What this is
    Checks over `roxy.config.settings.cache.SETTINGS` that do not need the assembled catalog.

Why it exists
    The catalog is generated documentation as much as validation (plan P3). A missing key, a default outside
    its own range, an empty "what happens if" text or a dash character would reach the settings editor, the
    generated docs and the LLM export, so each is caught here, next to the content.

How it works
    The expected keys, defaults and ranges are copied from plan 15.3 D (with the DESIGN.md section 0 memory
    overrides) into explicit tables below, so a silent change to the module fails a test.

What to read next
    `src/roxy/config/settings/cache.py`, then the catalog-wide checks in `roxy/config/catalog.py`.
"""

from __future__ import annotations

import re
from dataclasses import fields

import pytest

from roxy.config.settings.cache import SETTINGS
from roxy.config.spec import Apply, Group, SettingSpec, SettingType

MIB = 1024 * 1024
GIB = 1024 * MIB

# Every key of plan 15.3 D, one entry per key (rows with "/" are split).
EXPECTED_KEYS = [
    "cache_enabled",
    "cache_ttl_seconds",
    "cache_error_ttl_seconds",
    "cache_swr_seconds",
    "cache_stale_seconds",
    "cache_disk_enabled",
    "cache_max_entries",
    "cache_max_bytes",
    "cache_max_body",
    "cache_memory_entries",
    "cache_memory_bytes",
    "cache_eviction_policy",
    "cache_compress",
    "cache_coalesce",
    "cache_coalesce_wait_ms",
    "cache_post_requests",
    "cache_respect_no_cache",
    "cache_serve_throttled",
    "cache_negative_429",
    "cache_default_rules_enabled",
    "ttl_tuner_enabled",
    "ttl_tuner_max_s",
    "swr_max_inflight",
    "request_sample_pct",
    "request_sample_hours",
    "request_sample_max_rows",
]

# v2 defaults from the plan; the two memory-tier values are the DESIGN.md section 0 overrides.
EXPECTED_DEFAULTS = {
    "cache_enabled": 1,
    "cache_ttl_seconds": 120,
    "cache_error_ttl_seconds": 60,
    "cache_swr_seconds": 60,
    "cache_stale_seconds": 600,
    "cache_disk_enabled": 1,
    "cache_max_entries": 200000,
    "cache_max_bytes": 536870912,
    "cache_max_body": 1048576,
    "cache_memory_entries": 1000,
    "cache_memory_bytes": 16777216,
    "cache_eviction_policy": "hybrid",
    "cache_compress": 1,
    "cache_coalesce": 1,
    "cache_coalesce_wait_ms": 0,
    "cache_post_requests": "allowlist",
    "cache_respect_no_cache": 0,
    "cache_serve_throttled": 0,
    "cache_negative_429": 1,
    "cache_default_rules_enabled": 1,
    "ttl_tuner_enabled": 1,
    "ttl_tuner_max_s": 3600,
    "swr_max_inflight": 50,
    "request_sample_pct": 100,
    "request_sample_hours": 24,
    "request_sample_max_rows": 3000000,
}

# Ranges from the plan table (min, max).
EXPECTED_RANGES = {
    "cache_ttl_seconds": (0, 86400),
    "cache_error_ttl_seconds": (0, 3600),
    "cache_swr_seconds": (0, 86400),
    "cache_stale_seconds": (0, 86400),
    "cache_max_entries": (0, 5000000),
    "cache_max_bytes": (0, 16 * GIB),
    "cache_max_body": (0, 8 * MIB),
    "cache_memory_entries": (0, 100000),
    "cache_memory_bytes": (0, GIB),
    "cache_coalesce_wait_ms": (0, 60000),
    "ttl_tuner_max_s": (60, 86400),
    "swr_max_inflight": (0, 1000),
    "request_sample_pct": (0, 100),
    "request_sample_hours": (1, 168),
    "request_sample_max_rows": (10000, 50000000),
}

EXPECTED_OPTIONS = {
    "cache_eviction_policy": {"lru", "lfu", "hybrid"},
    "cache_post_requests": {"off", "allowlist", "all"},
}

# Keys that existed in v1 (app/runtime.py) and their v1 defaults (app/config.py).
EXPECTED_V1_DEFAULTS = {
    "cache_enabled": 1,
    "cache_ttl_seconds": 60,
    "cache_error_ttl_seconds": 0,
    "cache_stale_seconds": 600,
    "cache_disk_enabled": 1,
    "cache_max_entries": 3000,
    "cache_max_bytes": 32 * MIB,
    "cache_max_body": 256 * 1024,
    "cache_memory_entries": 400,
    "cache_memory_bytes": 8 * MIB,
    "cache_coalesce": 1,
    "cache_coalesce_wait_ms": 1500,
    "cache_post_requests": 0,
    "cache_respect_no_cache": 0,
    "cache_serve_throttled": 0,
}

# Dashboard anchors from DESIGN.md section 9 (the subset this group may use is checked against all of them).
ALLOWED_PAGES = {
    "upstream#routing", "upstream#hosts", "upstream#buckets", "upstream#concurrency", "upstream#cooldowns",
    "upstream#breakers", "upstream#queue", "upstream#retries", "egress#rotator", "egress#budget",
    "credential#status", "credential#budget", "cache#settings", "cache#coalescing",
    "recommendations#preview-settings", "recommendations#engine", "data#retention", "data#record-caps",
    "data#exports", "protection#throttle", "protection#limits", "protection#places", "clients#places",
    "protection#ua-rules", "protection#spam", "protection#bans", "protection#bot", "clients#client-score",
    "protection#challenge", "protection#bypass", "protection#ignored-paths", "protection#tarpit",
    "security#admin-access", "settings#alerts", "system#alerts", "health#schedule", "system#metrics-pipeline",
    "live#tail", "live#capture", "settings#public-site", "topbar#pause", "topbar#throttle-all",
    "user-menu#preferences",
}  # fmt: skip

# Rule ids from plan 11.5.
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
}  # fmt: skip

NUMERIC_TYPES = {SettingType.INT, SettingType.FLOAT, SettingType.DURATION, SettingType.BYTES, SettingType.PERCENT}

# A few British spellings (plan C5) that are easy to slip into settings help text. The square brackets are the
# plan C5 trick: `colo[u]r` matches the British word while the pattern text itself does not, so this file passes
# scripts/check_style.py.
BRITISH = re.compile(
    r"\b(behavio[u]r|colo[u]r|hono[u]r|favo[u]r|analy[s]e|optimi[s]e|normali[s]e|seriali[s]e|initiali[s]e|"
    r"cent[r]e|licen[c]e|defen[c]e|catalo[g]ue|dialo[g]ue|cancel[l]ed|cancel[l]ing|label[l]ed|model[l]ed|"
    r"enro[l]|fulfi[l]|gr[e]y|judge[m]ent|whi[l]st)\b",
    re.IGNORECASE,
)
DASHES = (chr(0x2014), chr(0x2013))  # em dash, en dash (built from code points so this file stays dash free)

BY_KEY = {spec.key: spec for spec in SETTINGS}


def _texts(spec: SettingSpec) -> list[str]:
    """Every human-readable string in a spec, including option text and risk reasons."""
    out: list[str] = []
    for f in fields(spec):
        value = getattr(spec, f.name)
        if isinstance(value, str):
            out.append(value)
    for option in spec.options:
        out.extend([option.value, option.label, option.description])
    out.extend(condition.why for condition in spec.high_risk_if)
    return out


def _sentences(text: str) -> int:
    return len(re.findall(r"[.!?](?:\s|$)", text.strip()))


def test_every_plan_key_present_exactly_once() -> None:
    keys = [spec.key for spec in SETTINGS]
    assert len(keys) == len(set(keys)), "duplicate keys"
    assert sorted(keys) == sorted(EXPECTED_KEYS)


def test_all_specs_are_cache_group_live_and_not_sensitive() -> None:
    for spec in SETTINGS:
        assert spec.group is Group.CACHE, spec.key
        assert spec.apply is Apply.LIVE, spec.key
        assert spec.sensitive is False, spec.key
        assert spec.renamed_from is None, spec.key  # no key in group D was renamed from v1


@pytest.mark.parametrize("key", EXPECTED_KEYS)
def test_default_matches_plan(key: str) -> None:
    spec = BY_KEY[key]
    assert spec.default == EXPECTED_DEFAULTS[key]
    assert type(spec.default) is type(EXPECTED_DEFAULTS[key]), "defaults keep their exact type (bytes are int)"


@pytest.mark.parametrize("key", sorted(EXPECTED_RANGES))
def test_range_matches_plan(key: str) -> None:
    spec = BY_KEY[key]
    assert (spec.min, spec.max) == EXPECTED_RANGES[key]


@pytest.mark.parametrize("spec", SETTINGS, ids=lambda s: s.key)
def test_default_validates_against_own_bounds(spec: SettingSpec) -> None:
    if spec.type in NUMERIC_TYPES:
        assert spec.min is not None
        assert spec.max is not None
        assert spec.min <= spec.default <= spec.max
        assert isinstance(spec.default, int | float)
        assert not isinstance(spec.default, bool)
        if spec.type in {SettingType.INT, SettingType.BYTES, SettingType.DURATION}:
            assert isinstance(spec.default, int)
        assert spec.unit, "numbers carry a unit"
        if spec.step:
            assert (spec.default - spec.min) % spec.step == 0
    elif spec.type is SettingType.BOOL:
        assert spec.default in (0, 1)
        assert spec.min is None
        assert spec.max is None
    elif spec.type is SettingType.ENUM:
        assert spec.default in spec.option_values()
        assert set(spec.option_values()) == EXPECTED_OPTIONS[spec.key]
    else:  # pragma: no cover - this group only uses the types above
        pytest.fail(f"unexpected type {spec.type} for {spec.key}")


@pytest.mark.parametrize("spec", SETTINGS, ids=lambda s: s.key)
def test_required_text_present(spec: SettingSpec) -> None:
    assert spec.label.strip()
    assert spec.description.strip()
    assert 1 <= _sentences(spec.description) <= 3, "description is 1 to 3 sentences"
    if spec.type in NUMERIC_TYPES:
        assert spec.if_raised.strip()
        assert spec.if_lowered.strip()
    elif spec.type is SettingType.BOOL:
        assert spec.if_enabled.strip()
        assert spec.if_disabled.strip()
    elif spec.type is SettingType.ENUM:
        assert len(spec.options) >= 2
        assert len(set(spec.option_values())) == len(spec.options)
        for option in spec.options:
            assert option.label.strip()
            assert option.description.strip()


@pytest.mark.parametrize("spec", SETTINGS, ids=lambda s: s.key)
def test_text_style(spec: SettingSpec) -> None:
    for text in _texts(spec):
        for dash in DASHES:
            assert dash not in text, f"{spec.key}: dash character in {text!r}"
        assert not BRITISH.search(text), f"{spec.key}: British spelling in {text!r}"


@pytest.mark.parametrize("spec", SETTINGS, ids=lambda s: s.key)
def test_pages_are_known_anchors(spec: SettingSpec) -> None:
    assert spec.pages, "at least one dashboard anchor"
    assert set(spec.pages) <= ALLOWED_PAGES


def test_pages_follow_plan_15_6() -> None:
    for spec in SETTINGS:
        if spec.key.startswith("request_sample_"):
            assert set(spec.pages) == {"recommendations#preview-settings", "data#retention"}
        else:
            assert "cache#settings" in spec.pages
        if spec.key.startswith("cache_coalesce"):
            assert "cache#coalescing" in spec.pages


@pytest.mark.parametrize("spec", SETTINGS, ids=lambda s: s.key)
def test_cross_links(spec: SettingSpec) -> None:
    assert set(spec.related_recommendations) <= RULE_IDS
    assert spec.key not in spec.related_settings
    for other in spec.related_settings:
        if other.startswith(("cache_", "ttl_tuner_", "swr_", "request_sample_")):
            assert other in BY_KEY, f"{spec.key} links to unknown cache key {other}"
    if spec.high_risk_if:
        assert "SEC-DEFAULTS" in spec.related_recommendations


@pytest.mark.parametrize("spec", SETTINGS, ids=lambda s: s.key)
def test_high_risk_conditions_explained_and_default_safe(spec: SettingSpec) -> None:
    for condition in spec.high_risk_if:
        assert condition.why.strip()
    assert spec.is_high_risk_value(spec.default) is None, "a default value is never high risk"


@pytest.mark.parametrize("spec", [s for s in SETTINGS if s.auto_apply_bounds], ids=lambda s: s.key)
def test_auto_apply_bounds_are_safe(spec: SettingSpec) -> None:
    assert spec.auto_apply_bounds is not None
    low, high = spec.auto_apply_bounds
    assert spec.min is not None
    assert spec.max is not None
    assert spec.min <= low <= spec.default <= high <= spec.max
    assert spec.is_high_risk_value(low) is None
    assert spec.is_high_risk_value(high) is None


def test_auto_apply_only_where_a_rule_proposes_the_key() -> None:
    with_bounds = {spec.key for spec in SETTINGS if spec.auto_apply_bounds}
    assert with_bounds == {"cache_error_ttl_seconds", "cache_max_entries", "cache_max_bytes"}
    for spec in SETTINGS:
        if spec.type in {SettingType.BOOL, SettingType.ENUM}:
            assert spec.auto_apply_bounds is None


def test_v1_defaults() -> None:
    for key, v1 in EXPECTED_V1_DEFAULTS.items():
        assert BY_KEY[key].v1_default == v1, key
    for spec in SETTINGS:
        if spec.key not in EXPECTED_V1_DEFAULTS:
            assert spec.v1_default is None, f"{spec.key} is new in v2"


def test_dangerous_values_are_flagged() -> None:
    assert BY_KEY["cache_enabled"].is_high_risk_value(0)
    assert BY_KEY["cache_post_requests"].is_high_risk_value("all")
    assert BY_KEY["cache_respect_no_cache"].is_high_risk_value(1)
    assert BY_KEY["cache_coalesce"].is_high_risk_value(0)
    assert BY_KEY["cache_negative_429"].is_high_risk_value(0)
    assert BY_KEY["cache_memory_bytes"].is_high_risk_value(64 * MIB)
    assert BY_KEY["cache_memory_bytes"].is_high_risk_value(32 * MIB) is None


def test_no_pending_owner_verification_in_group_d() -> None:
    assert not any(spec.pending_owner_verification for spec in SETTINGS)
