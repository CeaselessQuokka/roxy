"""Catalog content checks for `roxy.config.settings.throttling` (plan 15.3 E without the spam detectors).

What this is
    Tests that every throttling and abuse detection key from the plan table is declared, that each default
    passes its own validation (range, options, list limits), and that every text the settings editor shows
    is present and follows the writing rules (plan C5).

Why it exists
    The catalog is the contract between the dashboard, validation and the docs (plan P3). A missing key or an
    invalid default would only surface at import of `catalog.py`; these tests pin the group content on its own.

How it works
    The expected keys are listed explicitly (copied from plan 15.3 E), then each spec is checked by type.

What to read next
    `src/roxy/config/settings/throttling.py`, then `tests/unit/config/test_settings_spam.py`.
"""

import ipaddress
import re

import pytest

from roxy.config.settings import throttling
from roxy.config.spec import Apply, Group, Risk, SettingSpec, SettingType

THROTTLING_KEYS = {
    "allowed_requests_per_minute",
    "throttle_reset_duration",
    "throttle_window_mode",
    "throttle_count_cache_hits",
    "stale_ip_duration",
    "throttle_escalation_enabled",
    "throttle_strike_decay_seconds",
    "throttle_strike_on_retry",
    "global_throttle_limit",
    "global_throttle_period",
    "user_agent_rules_enabled",
}

ABUSE_KEYS = {
    "flood_limit_per_minute",
    "place_limit_enabled",
    "place_limit_per_minute",
    "place_limit_key",
    "roblox_egress_cidrs",
    "ipv6_limit_prefix",
    "ban_disguise_as_throttle",
    "bot_score_block_threshold",
    "bot_score_legit_max",
    "bot_score_abuse_min",
    "bot_weight_library_ua",
    "bot_weight_no_roblox_signature",
    "bot_weight_probes",
    "bot_weight_refusals",
    "bot_weight_timing",
    "bot_weight_header_order",
    "bot_weight_cache_busting",
    "challenge_enabled",
    "challenge_difficulty_bits",
    "challenge_trigger_score",
    "challenge_cookie_minutes",
    "bypass_default_expiry_h",
    "max_body_bytes",
    "max_header_count",
    "max_header_bytes",
    "max_url_length",
}

EXPECTED_KEYS = THROTTLING_KEYS | ABUSE_KEYS

# v2 defaults from plan 15.3 E. DESIGN.md section 0 overrides one: the owner reversed D10 on 2026-10-07, so
# `throttle_count_cache_hits` is 1 (cache hits count, because serving them still costs Roxy resources).
EXPECTED_DEFAULTS = {
    "allowed_requests_per_minute": 10,
    "throttle_reset_duration": 50,
    "throttle_window_mode": "gcra",
    "throttle_count_cache_hits": 1,
    "stale_ip_duration": 60,
    "throttle_escalation_enabled": 1,
    "throttle_strike_decay_seconds": 1800,
    "throttle_strike_on_retry": 1,
    "global_throttle_limit": 1,
    "global_throttle_period": 60,
    "user_agent_rules_enabled": 1,
    "flood_limit_per_minute": 300,
    "place_limit_enabled": 0,
    "place_limit_per_minute": 600,
    "place_limit_key": "place_prefix",
    "roblox_egress_cidrs": [],
    "ipv6_limit_prefix": 64,
    "ban_disguise_as_throttle": 1,
    "bot_score_block_threshold": 0,
    "bot_score_legit_max": 30,
    "bot_score_abuse_min": 80,
    "bot_weight_library_ua": 25,
    "bot_weight_no_roblox_signature": 15,
    "bot_weight_probes": 25,
    "bot_weight_refusals": 15,
    "bot_weight_timing": 10,
    "bot_weight_header_order": 5,
    "bot_weight_cache_busting": 5,
    "challenge_enabled": 0,
    "challenge_difficulty_bits": 18,
    "challenge_trigger_score": 80,
    "challenge_cookie_minutes": 30,
    "bypass_default_expiry_h": 24,
    "max_body_bytes": 2097152,
    "max_header_count": 100,
    "max_header_bytes": 8192,
    "max_url_length": 4096,
}

# Keys that existed in v1 (app/runtime.py `_settings`) and their v1 defaults.
EXPECTED_V1_DEFAULTS = {
    "allowed_requests_per_minute": 10,
    "throttle_reset_duration": 50,
    "stale_ip_duration": 60,
    "throttle_escalation_enabled": 1,
    "throttle_strike_decay_seconds": 1800,
    "global_throttle_limit": 1,
    "global_throttle_period": 60,
    "user_agent_rules_enabled": 1,
}

# Dashboard anchors from DESIGN.md section 9.
ALLOWED_PAGES = {
    "protection#throttle",
    "topbar#throttle-all",
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
}

# Rule ids from plan 11.5 that these settings may name.
KNOWN_RULE_IDS = {
    "THROTTLE-TUNE",
    "PLACE-HEAVY",
    "UP-RETRYAFTER-IGNORED",
    "FILTER-COLLATERAL",
    "SEC-BYPASS-FOREVER",
    "SEC-DEFAULTS",
    "ABUSE-SPAM",
    "ABUSE-BOT",
    "ABUSE-DIST",
}

NUMBER_TYPES = {SettingType.INT, SettingType.FLOAT, SettingType.DURATION, SettingType.BYTES, SettingType.PERCENT}
INTEGER_TYPES = {SettingType.INT, SettingType.DURATION, SettingType.BYTES}
LIST_TYPES = {SettingType.LIST_STR, SettingType.LIST_INT, SettingType.LIST_CIDR}

# Plan C5: no em or en dash, US spelling. Patterns follow scripts/style_words.txt (square brackets keep the
# patterns themselves from matching).
DASHES = (chr(0x2014), chr(0x2013))  # em dash, en dash (built with chr so this file contains neither)
BRITISH = re.compile(
    r"behavio[u]r|colo[u]r|hono[u]r|favo[u]r|analy[s]e|optimi[s]e|normali[s]e|seriali[s]e|initiali[s]e|"
    r"utili[s]e|recogni[s]e|minimi[s]e|maximi[s]e|prioriti[s]e|customi[s]e|summari[s]e|authori[s]e|"
    r"cent[r]e\b|licen[c]e|defen[c]e|offen[c]e|catalo[g]ue|dialo[g]ue|cancel[l]ed|label[l]ed|model[l]ed|"
    r"\benro[l]\b|enro[l]ment|\bfulfi[l]\b|\bgr[e]y\b|judge[m]ent|whi[l]st|amon[g]st",
    re.IGNORECASE,
)

BY_KEY = {spec.key: spec for spec in throttling.SETTINGS}


def _texts(spec: SettingSpec) -> list[str]:
    """Every human-readable string a spec carries."""
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
    texts += [part for option in spec.options for part in (option.value, option.label, option.description)]
    texts += [condition.why for condition in spec.high_risk_if]
    return texts


def _default_is_valid(spec: SettingSpec) -> None:
    """Assert the default passes the same checks validation applies to an admin's value."""
    default = spec.default
    if spec.type in NUMBER_TYPES:
        assert not isinstance(default, bool), spec.key
        if spec.type in INTEGER_TYPES:
            assert isinstance(default, int), spec.key
        else:
            assert isinstance(default, int | float), spec.key
        assert spec.min is not None, spec.key
        assert spec.max is not None, spec.key
        assert spec.min <= spec.max, spec.key
        assert spec.min <= default <= spec.max, spec.key
    elif spec.type is SettingType.BOOL:
        assert default in (0, 1), spec.key
        assert not isinstance(default, bool), spec.key
    elif spec.type is SettingType.ENUM:
        assert len(spec.options) >= 2, spec.key
        assert len(set(spec.option_values())) == len(spec.options), spec.key
        assert default in spec.option_values(), spec.key
    elif spec.type in LIST_TYPES:
        assert isinstance(default, list), spec.key
        assert spec.max_length is not None, spec.key
        assert len(default) <= spec.max_length, spec.key
        for item in default:
            assert isinstance(item, str), spec.key
            if spec.item_max_length is not None:
                assert len(item) <= spec.item_max_length, spec.key
            if spec.type is SettingType.LIST_CIDR:
                ipaddress.ip_network(item, strict=True)
    else:
        pytest.fail(f"{spec.key}: unexpected type {spec.type}")


def test_every_plan_key_is_present_exactly_once() -> None:
    keys = [spec.key for spec in throttling.SETTINGS]
    assert len(keys) == len(set(keys)), "duplicate keys"
    assert set(keys) == EXPECTED_KEYS


def test_groups_split_throttle_from_detection() -> None:
    for key in THROTTLING_KEYS:
        assert BY_KEY[key].group is Group.THROTTLING, key
    for key in ABUSE_KEYS:
        assert BY_KEY[key].group is Group.ABUSE, key


@pytest.mark.parametrize("key", sorted(EXPECTED_KEYS))
def test_default_matches_plan_and_validates(key: str) -> None:
    spec = BY_KEY[key]
    assert spec.default == EXPECTED_DEFAULTS[key]
    _default_is_valid(spec)


@pytest.mark.parametrize("key", sorted(EXPECTED_KEYS))
def test_required_text_present(key: str) -> None:
    spec = BY_KEY[key]
    assert spec.label.strip()
    assert spec.description.strip()
    if spec.type in NUMBER_TYPES or spec.type in LIST_TYPES:
        assert spec.if_raised.strip()
        assert spec.if_lowered.strip()
        if spec.type in NUMBER_TYPES:
            assert spec.unit.strip()
    elif spec.type is SettingType.BOOL:
        assert spec.if_enabled.strip()
        assert spec.if_disabled.strip()
    elif spec.type is SettingType.ENUM:
        for option in spec.options:
            assert option.label.strip()
            assert option.description.strip()
    for condition in spec.high_risk_if:
        assert condition.why.strip()


@pytest.mark.parametrize("key", sorted(EXPECTED_KEYS))
def test_writing_rules(key: str) -> None:
    for text in _texts(BY_KEY[key]):
        assert not any(dash in text for dash in DASHES), text
        assert not BRITISH.search(text), text


@pytest.mark.parametrize("key", sorted(EXPECTED_KEYS))
def test_metadata(key: str) -> None:
    spec = BY_KEY[key]
    assert spec.pages, "every setting needs at least one dashboard card"
    assert set(spec.pages) <= ALLOWED_PAGES
    assert spec.apply is Apply.LIVE
    assert set(spec.related_recommendations) <= KNOWN_RULE_IDS
    assert key not in spec.related_settings
    assert spec.auto_apply_bounds is None, "protection settings are never auto-applied (plan 11.4)"
    assert not spec.sensitive
    assert spec.renamed_from is None
    assert spec.v1_default == EXPECTED_V1_DEFAULTS.get(key)
    # The shipped default must never be a high-risk value, or SEC-DEFAULTS would fire on a fresh install.
    assert spec.is_high_risk_value(spec.default) is None
    if spec.high_risk_if:
        assert spec.risk in (Risk.MEDIUM, Risk.HIGH)
        assert "SEC-DEFAULTS" in spec.related_recommendations


def test_related_settings_inside_this_module_exist() -> None:
    """Cross links to keys of this group must name real keys (links to other groups are checked by catalog.py)."""
    prefixes = ("throttle_", "bot_", "challenge_", "place_limit_", "max_", "global_throttle_")
    for spec in throttling.SETTINGS:
        for related in spec.related_settings:
            assert re.fullmatch(r"[a-z0-9_]+", related), related
            if related.startswith(prefixes):
                assert related in EXPECTED_KEYS, f"{spec.key} links to unknown {related}"


def test_high_risk_examples() -> None:
    assert BY_KEY["place_limit_key"].is_high_risk_value("place")
    assert BY_KEY["ipv6_limit_prefix"].is_high_risk_value(128)
    assert BY_KEY["ipv6_limit_prefix"].is_high_risk_value(48) is None
    assert BY_KEY["bypass_default_expiry_h"].is_high_risk_value(0)
    assert BY_KEY["throttle_strike_decay_seconds"].is_high_risk_value(0)
    assert BY_KEY["flood_limit_per_minute"].is_high_risk_value(20000)


def test_byte_limits_never_exceed_nginx() -> None:
    assert BY_KEY["max_body_bytes"].max == 2 * 1024 * 1024
    assert BY_KEY["max_header_bytes"].max == 8 * 1024
