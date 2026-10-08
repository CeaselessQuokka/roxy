"""Catalog content checks for `roxy.config.settings.spam` (plan 15.3 E2 plus the spam master switches).

What this is
    Tests that every spam detector key from plan 15.3 E2 (seven detectors, six keys each) and the two master
    switches from 15.3 E are declared with the plan's defaults, that each default passes its own validation,
    and that all editor text is present and follows the writing rules (plan C5).

Why it exists
    The detectors can ban clients automatically, so their catalog entries must be exactly what the plan says;
    a wrong default here would arm or loosen a detector without anyone choosing it.

How it works
    The expected keys and defaults are written out explicitly from the E2 table, then each spec is checked by
    type, plus a few detector-specific rules (ban ordering, risky ban actions).

What to read next
    `src/roxy/config/settings/spam.py`, then plan 10.3.
"""

import re

import pytest

from roxy.config.settings import spam
from roxy.config.spec import Apply, Group, Risk, SettingSpec, SettingType

# Plan 15.3 E2, row by row: (enabled, threshold, window_s, action, ban_minutes, ban_max_minutes).
E2_TABLE = {
    "rate": (1, 5, 600, "ban", 60, 10080),
    "refused": (1, 200, 600, "ban", 30, 1440),
    "probe": (1, 5, 600, "ban", 60, 1440),
    "auth": (1, 3, 3600, "ban", 60, 10080),
    "enum": (1, 500, 600, "recommend", 0, 0),
    "bust": (1, 0.9, 600, "recommend", 0, 0),
    "dist": (1, 50, 300, "recommend", 0, 0),
}
SUFFIXES = ("enabled", "threshold", "window_s", "action", "ban_minutes", "ban_max_minutes")

EXPECTED_DEFAULTS: dict[str, object] = {"spam_enabled": 1, "spam_dry_run": 1}
for _detector, _row in E2_TABLE.items():
    for _suffix, _value in zip(SUFFIXES, _row, strict=True):
        EXPECTED_DEFAULTS[f"spam_{_detector}_{_suffix}"] = _value

EXPECTED_KEYS = {
    "spam_enabled",
    "spam_dry_run",
    "spam_rate_enabled",
    "spam_rate_threshold",
    "spam_rate_window_s",
    "spam_rate_action",
    "spam_rate_ban_minutes",
    "spam_rate_ban_max_minutes",
    "spam_refused_enabled",
    "spam_refused_threshold",
    "spam_refused_window_s",
    "spam_refused_action",
    "spam_refused_ban_minutes",
    "spam_refused_ban_max_minutes",
    "spam_probe_enabled",
    "spam_probe_threshold",
    "spam_probe_window_s",
    "spam_probe_action",
    "spam_probe_ban_minutes",
    "spam_probe_ban_max_minutes",
    "spam_auth_enabled",
    "spam_auth_threshold",
    "spam_auth_window_s",
    "spam_auth_action",
    "spam_auth_ban_minutes",
    "spam_auth_ban_max_minutes",
    "spam_enum_enabled",
    "spam_enum_threshold",
    "spam_enum_window_s",
    "spam_enum_action",
    "spam_enum_ban_minutes",
    "spam_enum_ban_max_minutes",
    "spam_bust_enabled",
    "spam_bust_threshold",
    "spam_bust_window_s",
    "spam_bust_action",
    "spam_bust_ban_minutes",
    "spam_bust_ban_max_minutes",
    "spam_dist_enabled",
    "spam_dist_threshold",
    "spam_dist_window_s",
    "spam_dist_action",
    "spam_dist_ban_minutes",
    "spam_dist_ban_max_minutes",
}

ACTIONS = ("ban", "strike", "tarpit", "recommend")
KNOWN_RULE_IDS = {"ABUSE-SPAM", "ABUSE-DIST", "FILTER-COLLATERAL", "SEC-DEFAULTS"}
NUMBER_TYPES = {SettingType.INT, SettingType.FLOAT, SettingType.DURATION, SettingType.BYTES, SettingType.PERCENT}
INTEGER_TYPES = {SettingType.INT, SettingType.DURATION, SettingType.BYTES}

DASHES = (chr(0x2014), chr(0x2013))  # em dash, en dash (built with chr so this file contains neither)
BRITISH = re.compile(
    r"behavio[u]r|colo[u]r|hono[u]r|favo[u]r|analy[s]e|optimi[s]e|normali[s]e|seriali[s]e|initiali[s]e|"
    r"utili[s]e|recogni[s]e|minimi[s]e|maximi[s]e|prioriti[s]e|customi[s]e|summari[s]e|authori[s]e|"
    r"cent[r]e\b|licen[c]e|defen[c]e|offen[c]e|catalo[g]ue|dialo[g]ue|cancel[l]ed|label[l]ed|model[l]ed|"
    r"\benro[l]\b|enro[l]ment|\bfulfi[l]\b|\bgr[e]y\b|judge[m]ent|whi[l]st|amon[g]st",
    re.IGNORECASE,
)

BY_KEY = {spec.key: spec for spec in spam.SETTINGS}


def _texts(spec: SettingSpec) -> list[str]:
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


def test_every_plan_key_is_present_exactly_once() -> None:
    keys = [spec.key for spec in spam.SETTINGS]
    assert len(keys) == len(set(keys)), "duplicate keys"
    assert set(keys) == EXPECTED_KEYS
    assert set(EXPECTED_DEFAULTS) == EXPECTED_KEYS
    assert tuple(E2_TABLE) == spam.DETECTOR_IDS


@pytest.mark.parametrize("key", sorted(EXPECTED_KEYS))
def test_default_matches_plan_and_validates(key: str) -> None:
    spec = BY_KEY[key]
    assert spec.default == EXPECTED_DEFAULTS[key]
    default = spec.default
    if spec.type in NUMBER_TYPES:
        assert not isinstance(default, bool)
        assert isinstance(default, int) if spec.type in INTEGER_TYPES else isinstance(default, int | float)
        assert spec.min is not None
        assert spec.max is not None
        assert spec.min <= default <= spec.max
    elif spec.type is SettingType.BOOL:
        assert default in (0, 1)
        assert not isinstance(default, bool)
    elif spec.type is SettingType.ENUM:
        assert spec.option_values() == ACTIONS
        assert default in spec.option_values()
    else:
        pytest.fail(f"{key}: unexpected type {spec.type}")


@pytest.mark.parametrize("key", sorted(EXPECTED_KEYS))
def test_required_text_present(key: str) -> None:
    spec = BY_KEY[key]
    assert spec.label.strip()
    assert spec.description.strip()
    if spec.type in NUMBER_TYPES:
        assert spec.unit.strip()
        assert spec.if_raised.strip()
        assert spec.if_lowered.strip()
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
    assert spec.group is Group.ABUSE
    assert spec.apply is Apply.LIVE
    assert spec.auto_apply_bounds is None, "protection settings are never auto-applied (plan 11.4)"
    assert not spec.sensitive
    assert spec.renamed_from is None, "no spam setting existed in v1"
    assert spec.v1_default is None, "no spam setting existed in v1"
    assert set(spec.related_recommendations) <= KNOWN_RULE_IDS
    assert key not in spec.related_settings
    assert spec.is_high_risk_value(spec.default) is None
    if spec.high_risk_if:
        assert spec.risk in (Risk.MEDIUM, Risk.HIGH)
        assert "SEC-DEFAULTS" in spec.related_recommendations
    if key in ("spam_enabled", "spam_dry_run"):
        assert spec.pages == ("protection#spam",)
    else:
        detector = key.removeprefix("spam_").split("_", 1)[0]
        assert spec.pages == (f"protection#spam-{detector}",)


@pytest.mark.parametrize("detector", sorted(E2_TABLE))
def test_detector_ranges(detector: str) -> None:
    window = BY_KEY[f"spam_{detector}_window_s"]
    assert (window.min, window.max, window.unit) == (10, 86400, "seconds")
    for suffix in ("ban_minutes", "ban_max_minutes"):
        ban = BY_KEY[f"spam_{detector}_{suffix}"]
        # 0 is allowed so the recommend-only detectors can ship the plan's 0 defaults; 10080 is 7 days.
        assert (ban.min, ban.max, ban.unit) == (0, 10080, "minutes")
    first = BY_KEY[f"spam_{detector}_ban_minutes"].default
    cap = BY_KEY[f"spam_{detector}_ban_max_minutes"].default
    assert first <= cap
    if BY_KEY[f"spam_{detector}_action"].default == "ban":
        assert first >= 1


def test_ban_is_risky_only_where_the_plan_recommends() -> None:
    for detector in ("enum", "bust", "dist"):
        assert BY_KEY[f"spam_{detector}_action"].is_high_risk_value("ban")
    for detector in ("rate", "refused", "probe", "auth"):
        assert BY_KEY[f"spam_{detector}_action"].is_high_risk_value("ban") is None


def test_dry_run_off_is_high_risk() -> None:
    dry_run = BY_KEY["spam_dry_run"]
    assert dry_run.risk is Risk.HIGH
    assert dry_run.is_high_risk_value(0)


def test_related_spam_keys_exist() -> None:
    for spec in spam.SETTINGS:
        for related in spec.related_settings:
            if related.startswith("spam_"):
                assert related in EXPECTED_KEYS, f"{spec.key} links to unknown {related}"
