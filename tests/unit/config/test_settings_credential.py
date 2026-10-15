"""Unit tests for the Credential settings group (plan 15.3 B, `roxy.config.settings.credential`).

What this is
    Checks on every `SettingSpec` in the Credential group: the plan's keys are all there, defaults match the
    plan and fit their own ranges, the help text an admin reads is present and clean, and the account-safety
    rules (no auto-apply on the credential, the allowlist is high risk when non-empty) hold.

Why it exists
    The settings editor, the docs and the LLM export are generated from these specs (plan P3), so a missing
    key, a default outside its own range or an empty "what happens if" text would ship straight to the admin.

How it works
    Plain pytest over the imported list; no database or network.

What to read next
    `tests/unit/config/test_settings_upstream.py` (same checks for group C), then the catalog self check tests.
"""

import re
from pathlib import Path
from typing import Any

import pytest

from roxy.config.settings import credential
from roxy.config.spec import Apply, Group, SettingSpec, SettingType

# Every key of plan 15.3 B with its v2 default (DESIGN.md section 0 overrides none of them).
EXPECTED_DEFAULTS: dict[str, Any] = {
    "credential_enabled": 1,
    "credential_bucket_per_min": 20,
    "credential_bucket_burst": 3,
    "credential_probe_interval_min": 30,
    "credential_probe_url": "https://users.roblox.com/v1/users/authenticated",
    "credential_probe_reserved_per_min": 2,
    "credential_cooldown_default_s": 60,
}

# (min, max) from the plan table.
EXPECTED_RANGES: dict[str, tuple[float, float]] = {
    "credential_bucket_per_min": (1, 120),
    "credential_bucket_burst": (1, 20),
    "credential_probe_interval_min": (0, 1440),
    "credential_probe_reserved_per_min": (1, 10),
    "credential_cooldown_default_s": (5, 3600),
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

SPECS: list[SettingSpec] = credential.SETTINGS
BY_KEY = {spec.key: spec for spec in SPECS}


def _texts(spec: SettingSpec) -> list[str]:
    """Every admin-facing string of one spec."""
    texts = [spec.label, spec.description, spec.if_raised, spec.if_lowered, spec.if_enabled, spec.if_disabled]
    texts += [spec.notes, spec.unit]
    texts += [c.why for c in spec.high_risk_if]
    texts += [o.label for o in spec.options] + [o.description for o in spec.options]
    if isinstance(spec.default, str):
        texts.append(spec.default)
    return texts


def test_every_plan_key_present_exactly_once() -> None:
    keys = [spec.key for spec in SPECS]
    assert len(keys) == len(set(keys)), "duplicate keys"
    assert set(keys) == set(EXPECTED_DEFAULTS)


def test_group_and_apply() -> None:
    for spec in SPECS:
        assert spec.group is Group.CREDENTIAL, spec.key
        assert spec.apply is Apply.LIVE, spec.key  # plan 15.3 B: every key is Live


@pytest.mark.parametrize("key", sorted(EXPECTED_DEFAULTS))
def test_default_matches_plan(key: str) -> None:
    assert BY_KEY[key].default == EXPECTED_DEFAULTS[key]


@pytest.mark.parametrize("key", sorted(EXPECTED_RANGES))
def test_range_matches_plan(key: str) -> None:
    spec = BY_KEY[key]
    assert (spec.min, spec.max) == EXPECTED_RANGES[key]


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
    elif spec.type is SettingType.STRING:
        assert isinstance(value, str)
        assert spec.max_length is not None
        assert len(value) <= spec.max_length
    elif spec.type is SettingType.LIST_STR:
        assert isinstance(value, list)
        assert spec.max_length is not None
        assert len(value) <= spec.max_length
        assert spec.item_max_length is not None
        for item in value:
            assert isinstance(item, str)
            assert len(item) <= spec.item_max_length
    else:  # pragma: no cover - a new type in this group needs a new branch here
        pytest.fail(f"untested type {spec.type} for {spec.key}")


@pytest.mark.parametrize("spec", SPECS, ids=lambda s: s.key)
def test_required_text_present(spec: SettingSpec) -> None:
    assert spec.label.strip()
    assert spec.description.strip()
    assert spec.pages, "at least one dashboard anchor"
    if spec.type in NUMERIC:
        assert spec.unit.strip()
    if spec.type in NUMERIC or spec.type is SettingType.LIST_STR:  # lists: adding and removing entries
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
def test_pages_are_known_anchors(spec: SettingSpec) -> None:
    for page in spec.pages:
        assert page in KNOWN_ANCHORS or page.startswith("recommendations#rule-"), page
    # Plan 15.6: every credential_* key lives on the Credential page.
    assert any(page.startswith("credential#") for page in spec.pages)


@pytest.mark.parametrize("spec", SPECS, ids=lambda s: s.key)
def test_text_style(spec: SettingSpec) -> None:
    for text in _texts(spec):
        assert not any(d in text for d in DASHES), (spec.key, text)
        assert not BRITISH.search(text), (spec.key, BRITISH.search(text))


def test_module_source_has_no_dash_characters() -> None:
    source = Path(credential.__file__).read_text(encoding="utf-8")
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
def test_no_auto_apply_and_nothing_sensitive(spec: SettingSpec) -> None:
    # Plan 11.4: auto-apply never touches the credential. No setting here holds the secret itself (C1).
    assert spec.auto_apply_bounds is None
    assert spec.sensitive is False


def test_related_settings_do_not_point_at_self() -> None:
    for spec in SPECS:
        assert spec.key not in spec.related_settings


def test_the_allowlist_is_the_table_not_a_setting() -> None:
    # Spec review 3: a list setting next to the `credential_allowlist` table could not hold the required
    # `cache_private` choice and was read by nothing; the table (plan 6.2, 9.13) is the only allowlist.
    assert "credential_endpoint_allowlist" not in BY_KEY


def test_risky_values_are_flagged() -> None:
    assert BY_KEY["credential_bucket_per_min"].is_high_risk_value(61) is not None
    assert BY_KEY["credential_bucket_per_min"].is_high_risk_value(60) is None
    assert BY_KEY["credential_bucket_burst"].is_high_risk_value(11) is not None
    assert BY_KEY["credential_probe_interval_min"].is_high_risk_value(4) is not None
    assert BY_KEY["credential_probe_interval_min"].is_high_risk_value(0) is None
    assert BY_KEY["credential_probe_url"].is_high_risk_value("https://users.roblox.com/v1/other") is not None
    assert BY_KEY["credential_cooldown_default_s"].is_high_risk_value(10) is not None


def test_cross_rules_hold_at_defaults() -> None:
    # DESIGN.md section 4: credential_probe_reserved_per_min < credential_bucket_per_min.
    assert EXPECTED_DEFAULTS["credential_probe_reserved_per_min"] < EXPECTED_DEFAULTS["credential_bucket_per_min"]
    # Even the reserve's maximum leaves room for allowlisted traffic under the default credential rate.
    assert BY_KEY["credential_probe_reserved_per_min"].max is not None
    assert BY_KEY["credential_probe_reserved_per_min"].max < BY_KEY["credential_bucket_per_min"].default


def test_v1_lineage() -> None:
    # Plan 15.4 and 18.3: renamed v1 keys keep their alias and v1 default for the "v1 -> v2" display.
    assert BY_KEY["credential_cooldown_default_s"].renamed_from == "token_expiration_cooldown"
    assert BY_KEY["credential_cooldown_default_s"].v1_default == 15
    assert BY_KEY["credential_bucket_per_min"].renamed_from == "token_budget_requests"
    assert BY_KEY["credential_bucket_per_min"].v1_default == 95
    assert BY_KEY["credential_probe_url"].v1_default == "https://accountinformation.roblox.com/v1/birthdate"
    for spec in SPECS:
        assert spec.pending_owner_verification is False  # nothing in 15.3 B is pending
