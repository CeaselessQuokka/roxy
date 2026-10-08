"""Unit tests for the Upstream pacing and resilience settings group (plan 15.3 C, `roxy.config.settings.upstream`).

What this is
    Checks on every `SettingSpec` in the Upstream group: the plan's keys are all there with the plan's defaults
    and ranges, defaults fit their own specs, the admin-facing text is present and clean, the dashboard anchors
    follow plan 15.6, and the cross-setting rules of DESIGN.md section 4 hold at the defaults.

Why it exists
    The settings editor, the docs and the LLM export are generated from these specs (plan P3), so a missing key
    or a default that breaks a cross rule would ship straight to the admin, or make the catalog refuse to load.

How it works
    Plain pytest over the imported list; no database or network.

What to read next
    `tests/unit/config/test_settings_credential.py` (same checks for group B), then the catalog self check tests.
"""

import re
from pathlib import Path
from typing import Any

import pytest

from roxy.config.settings import upstream
from roxy.config.spec import Apply, Group, SettingSpec, SettingType

# Every key of plan 15.3 C: key -> (v2 default, min, max). Rows that combine keys with "/" are split.
# DESIGN.md section 0 overrides none of these defaults.
EXPECTED: dict[str, tuple[Any, float, float]] = {
    "global_bucket_per_min": (600, 1, 10000),
    "global_bucket_burst": (30, 1, 500),
    "direct_bucket_per_min": (300, 1, 10000),
    "direct_bucket_burst": (20, 1, 500),
    "rotator_bucket_per_min": (300, 1, 10000),
    "rotator_bucket_burst": (20, 1, 500),
    "host_bucket_default_per_min": (240, 1, 10000),
    "host_bucket_default_burst": (15, 1, 500),
    "endpoint_bucket_default_per_min": (120, 1, 10000),
    "endpoint_bucket_default_burst": (10, 1, 500),
    "adaptive_rate_enabled": (1, 0, 1),
    "adaptive_decrease_pct": (30, 5, 90),
    "adaptive_increase_pct": (10, 1, 50),
    "adaptive_probe_after_h": (24, 1, 168),
    "adaptive_min_per_min": (6, 1, 600),
    "adaptive_max_per_min": (600, 10, 10000),
    "aimd_enabled": (0, 0, 1),
    "aimd_initial": (8, 1, 256),
    "aimd_min": (1, 1, 256),
    "aimd_max": (32, 1, 256),
    "aimd_increase_after": (50, 1, 10000),
    "aimd_decrease_factor": (0.5, 0.1, 0.95),
    "cooldown_default_s": (30, 1, 3600),
    "cooldown_min_s": (1, 1, 3600),
    "cooldown_max_s": (600, 1, 3600),
    "cooldown_host_escalation_endpoints": (3, 2, 50),
    "cooldown_host_escalation_window_s": (60, 10, 3600),
    "breaker_failure_threshold": (5, 1, 1000),
    "breaker_window_s": (30, 5, 600),
    "breaker_failure_ratio": (0.5, 0.05, 1),
    "breaker_open_s": (30, 1, 600),
    "backoff_base_ms": (200, 10, 10000),
    "backoff_cap_ms": (2000, 10, 10000),
    "queue_wait_interactive_ms": (4000, 0, 20000),
    "queue_wait_stale_ms": (500, 0, 5000),
    "queue_wait_background_ms": (10000, 0, 60000),
    "queue_wait_admin_ms": (10000, 0, 60000),
    "queue_wait_internal_ms": (30000, 0, 60000),
    "queue_max_length": (500, 10, 10000),
    "request_deadline_s": (60, 10, 90),
    "csrf_token_cache_s": (600, 0, 3600),
}

BOOL_KEYS = {"adaptive_rate_enabled", "aimd_enabled"}

# Plan 15.6 mapping for this group: key prefix -> the anchor every key with that prefix must carry.
PAGE_BY_PREFIX: dict[str, str] = {
    "global_bucket_": "upstream#buckets",
    "direct_bucket_": "upstream#buckets",
    "rotator_bucket_": "upstream#buckets",
    "host_bucket_": "upstream#buckets",
    "endpoint_bucket_": "upstream#buckets",
    "adaptive_": "upstream#buckets",
    "aimd_": "upstream#concurrency",
    "cooldown_": "upstream#cooldowns",
    "breaker_": "upstream#breakers",
    "backoff_": "upstream#cooldowns",
    "queue_": "upstream#queue",
    "request_deadline_s": "upstream#queue",
    "csrf_token_cache_s": "upstream#retries",
}

# DESIGN.md section 9: the only anchors a `pages` entry may use.
KNOWN_ANCHORS = {
    "topbar#pause",
    "topbar#throttle-all",
    "user-menu#preferences",
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
} | {f"protection#spam-{d}" for d in ("rate", "refused", "probe", "auth", "enum", "bust", "dist")}

# Plan 11.5 rule ids.
KNOWN_RULES = {
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

# Plan C5: a few British spellings (bracketed so this file does not trip the style check itself).
BRITISH = re.compile(
    r"behavio[u]r|colo[u]r|hono[u]r|favo[u]r|analy[s]e|optimi[s]e|normali[s]e|seriali[s]e|initiali[s]e|"
    r"utili[s]e|recogni[s]e|minimi[s]e|maximi[s]e|prioriti[s]e|customi[s]e|summari[s]e|authori[s]e|"
    r"categori[s]e|finali[s]e|\bcent[r]e\b|licen[c]e|defen[c]e|offen[c]e|catalo[g]ue|dialo[g]ue|cancel[l]ed|"
    r"cancel[l]ing|label[l]ed|label[l]ing|model[l]ed|signal[l]ed|\benro[l]\b|enro[l]ment|\bfulfi[l]\b|"
    r"program[m]e|\bgr[e]y\b|judge[m]ent|whi[l]st|amon[g]st",
    re.IGNORECASE,
)
DASHES = (chr(0x2014), chr(0x2013))  # em dash, en dash (built from code points so this file stays dash free)

NUMERIC = {SettingType.INT, SettingType.FLOAT, SettingType.DURATION, SettingType.BYTES, SettingType.PERCENT}

# Plan defaults of keys owned by the routing group (15.3 A), needed for the deadline budget of plan 5.2.
REQUEST_TIMEOUT_S = 15
UPSTREAM_MAX_ATTEMPTS = 2

SPECS: list[SettingSpec] = upstream.SETTINGS
BY_KEY = {spec.key: spec for spec in SPECS}


def _d(key: str) -> Any:
    return BY_KEY[key].default


def _texts(spec: SettingSpec) -> list[str]:
    """Every admin-facing string of one spec."""
    texts = [spec.label, spec.description, spec.if_raised, spec.if_lowered, spec.if_enabled, spec.if_disabled]
    texts += [spec.notes, spec.unit]
    texts += [c.why for c in spec.high_risk_if]
    texts += [o.label for o in spec.options] + [o.description for o in spec.options]
    return texts


def test_every_plan_key_present_exactly_once() -> None:
    keys = [spec.key for spec in SPECS]
    assert len(keys) == len(set(keys)), "duplicate keys"
    assert set(keys) == set(EXPECTED)


def test_group_and_apply() -> None:
    for spec in SPECS:
        assert spec.group is Group.UPSTREAM, spec.key
        assert spec.apply is Apply.LIVE, spec.key  # plan 15.3 C: every key is Live


@pytest.mark.parametrize("key", sorted(EXPECTED))
def test_default_and_range_match_plan(key: str) -> None:
    spec = BY_KEY[key]
    default, low, high = EXPECTED[key]
    assert spec.default == default
    if key in BOOL_KEYS:
        assert spec.type is SettingType.BOOL
    else:
        assert (spec.min, spec.max) == (low, high)


@pytest.mark.parametrize("spec", SPECS, ids=lambda s: s.key)
def test_default_validates_against_own_spec(spec: SettingSpec) -> None:
    value = spec.default
    if spec.type in NUMERIC:
        assert isinstance(value, int | float)
        assert not isinstance(value, bool)
        if spec.type in {SettingType.INT, SettingType.DURATION, SettingType.BYTES}:
            assert isinstance(value, int)
        assert spec.min is not None
        assert spec.max is not None
        assert spec.min <= value <= spec.max
        assert spec.step is not None
        assert spec.step > 0
    elif spec.type is SettingType.BOOL:
        assert value in (0, 1)
        assert type(value) is int  # stored as 0 or 1, never True or False
    elif spec.type is SettingType.ENUM:
        assert value in spec.option_values()
    else:  # pragma: no cover - a new type in this group needs a new branch here
        pytest.fail(f"untested type {spec.type} for {spec.key}")


@pytest.mark.parametrize("spec", SPECS, ids=lambda s: s.key)
def test_required_text_present(spec: SettingSpec) -> None:
    assert spec.label.strip()
    assert spec.description.strip()
    assert spec.pages, "at least one dashboard anchor"
    if spec.type in NUMERIC:
        assert spec.unit.strip()
        assert spec.if_raised.strip()
        assert spec.if_lowered.strip()
    if spec.type is SettingType.BOOL:
        assert spec.if_enabled.strip()
        assert spec.if_disabled.strip()
    if spec.type is SettingType.ENUM:
        assert spec.options
        for option in spec.options:
            assert option.label.strip()
            assert option.description.strip()


@pytest.mark.parametrize("spec", SPECS, ids=lambda s: s.key)
def test_pages_follow_plan_15_6(spec: SettingSpec) -> None:
    for page in spec.pages:
        assert page in KNOWN_ANCHORS, page
    expected = [page for prefix, page in PAGE_BY_PREFIX.items() if spec.key.startswith(prefix)]
    assert expected, f"no 15.6 row for {spec.key}"
    assert expected[0] in spec.pages


def test_rotator_buckets_also_on_egress_rotator() -> None:
    # 15.6 also maps every rotator_* key to Egress > Rotator.
    for key in ("rotator_bucket_per_min", "rotator_bucket_burst"):
        assert "egress#rotator" in BY_KEY[key].pages


@pytest.mark.parametrize("spec", SPECS, ids=lambda s: s.key)
def test_text_style(spec: SettingSpec) -> None:
    for text in _texts(spec):
        assert not any(d in text for d in DASHES), (spec.key, text)
        assert not BRITISH.search(text), (spec.key, BRITISH.search(text))


def test_module_source_has_no_dash_characters() -> None:
    source = Path(upstream.__file__).read_text(encoding="utf-8")
    assert not any(d in source for d in DASHES)


@pytest.mark.parametrize("spec", SPECS, ids=lambda s: s.key)
def test_risk_conditions_explained_and_default_is_safe(spec: SettingSpec) -> None:
    for condition in spec.high_risk_if:
        assert condition.why.strip()
    assert spec.is_high_risk_value(spec.default) is None, "a shipped default must never be a high-risk value"
    if spec.high_risk_if:
        # SEC-DEFAULTS (plan 11.5) is the rule that proposes restoring a safer value.
        assert "SEC-DEFAULTS" in spec.related_recommendations


@pytest.mark.parametrize("spec", SPECS, ids=lambda s: s.key)
def test_related_recommendations_are_known_rules(spec: SettingSpec) -> None:
    for rule_id in spec.related_recommendations:
        assert rule_id in KNOWN_RULES, rule_id


@pytest.mark.parametrize("spec", SPECS, ids=lambda s: s.key)
def test_auto_apply_bounds_inside_range(spec: SettingSpec) -> None:
    assert spec.sensitive is False
    if spec.auto_apply_bounds is None:
        return
    low, high = spec.auto_apply_bounds
    assert spec.min is not None
    assert spec.max is not None
    assert spec.min <= low <= spec.default <= high <= spec.max
    assert spec.related_recommendations, "auto-apply needs a rule that proposes the change"


def test_bucket_defaults_are_never_auto_applied() -> None:
    # Plan 11.2: a change to a global bucket default is never safe_auto.
    for spec in SPECS:
        if "bucket" in spec.key or spec.key.startswith("adaptive_"):
            assert spec.auto_apply_bounds is None, spec.key


def test_related_settings_do_not_point_at_self() -> None:
    for spec in SPECS:
        assert spec.key not in spec.related_settings


def test_cross_rules_hold_at_defaults() -> None:
    # DESIGN.md section 4 cross rules that involve this group.
    assert _d("aimd_min") <= _d("aimd_initial") <= _d("aimd_max")
    assert _d("cooldown_min_s") <= _d("cooldown_default_s") <= _d("cooldown_max_s")
    assert _d("adaptive_min_per_min") <= _d("adaptive_max_per_min")
    assert _d("adaptive_min_per_min") <= _d("endpoint_bucket_default_per_min") <= _d("adaptive_max_per_min")
    assert _d("backoff_base_ms") <= _d("backoff_cap_ms")
    # Plan 5.2: owner_deadline = interactive wait + request_timeout x attempts + backoff cap = 36 s at defaults.
    owner_deadline_s = (
        _d("queue_wait_interactive_ms") / 1000 + REQUEST_TIMEOUT_S * UPSTREAM_MAX_ATTEMPTS + _d("backoff_cap_ms") / 1000
    )
    assert owner_deadline_s == 36
    assert owner_deadline_s <= _d("request_deadline_s") - 2
    assert BY_KEY["request_deadline_s"].max == 90  # nginx proxy_read_timeout (100 s) minus 10 s


def test_buckets_nest_sensibly_at_defaults() -> None:
    # No single egress, host or endpoint bucket may exceed the global ceiling at the defaults.
    for key in ("direct_bucket_per_min", "rotator_bucket_per_min", "host_bucket_default_per_min"):
        assert _d(key) <= _d("global_bucket_per_min"), key
    assert _d("endpoint_bucket_default_per_min") <= _d("host_bucket_default_per_min")


def test_risky_values_are_flagged() -> None:
    assert BY_KEY["global_bucket_per_min"].is_high_risk_value(1201) is not None
    assert BY_KEY["direct_bucket_per_min"].is_high_risk_value(601) is not None
    assert BY_KEY["cooldown_max_s"].is_high_risk_value(30) is not None
    assert BY_KEY["cooldown_default_s"].is_high_risk_value(2) is not None
    assert BY_KEY["queue_max_length"].is_high_risk_value(5000) is not None


def test_no_v1_lineage_in_this_group() -> None:
    # Every key in 15.3 C is new in v2 (no "was" column), and none is pending owner verification.
    for spec in SPECS:
        assert spec.renamed_from is None, spec.key
        assert spec.v1_default is None, spec.key
        assert spec.pending_owner_verification is False, spec.key
