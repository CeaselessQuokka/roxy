"""Tests for `roxy.config.catalog` (plan 11.1, 15.1 to 15.6; DESIGN.md section 4) and scripts/gen_settings_docs.py.

Most tests use small synthetic specs so they test the framework, not the content. The tests that read the real
catalog skip a key politely when its group module is not loaded (build-time partial mode,
ROXY_CATALOG_PARTIAL=1), and `test_catalog_self_check_passes` is the one that reports content problems.
"""

from __future__ import annotations

import dataclasses
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from roxy.config import catalog
from roxy.config.catalog import (
    CATALOG,
    DEFAULTS,
    INSIGHT_RULES,
    REDACTED,
    SELF_CHECK_PROBLEMS,
    CatalogError,
    SettingValidationError,
    by_group,
    catalog_self_check,
    catalog_version,
    insight_rule_settings,
    is_known_anchor,
    load_style_words,
    min_max_pairs,
    owner_deadline_s,
    search,
    to_public_dict,
    validate_cross,
    validate_spec_value,
    validate_value,
)
from roxy.config.spec import (
    Group,
    InsightRuleSpec,
    OptionSpec,
    ParamSpec,
    Risk,
    RiskCondition,
    RiskOp,
    SettingSpec,
    SettingType,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
EM_DASH = chr(0x2014)
EN_DASH = chr(0x2013)


# --- Helpers ----------------------------------------------------------------------------------------------------------


def make_spec(key: str = "demo_value", kind: SettingType = SettingType.INT, **overrides: Any) -> SettingSpec:
    """A valid synthetic spec of the given type; `overrides` replace any field."""
    fields: dict[str, Any] = {
        "key": key,
        "group": Group.CACHE,
        "label": "Demo value",
        "type": kind,
        "description": "Does a demo thing.",
        "pages": ("cache#settings",),
    }
    if kind in (SettingType.INT, SettingType.FLOAT, SettingType.DURATION, SettingType.BYTES, SettingType.PERCENT):
        fields |= {"default": 5, "min": 0, "max": 100, "if_raised": "More of it.", "if_lowered": "Less of it."}
        if kind is SettingType.DURATION:
            fields["unit"] = "seconds"
            fields["max"] = 86400
        if kind is SettingType.BYTES:
            fields["unit"] = "bytes"
            fields["max"] = 2 * 1024**3
    elif kind is SettingType.BOOL:
        fields |= {"default": 1, "if_enabled": "It runs.", "if_disabled": "It stops."}
    elif kind is SettingType.ENUM:
        fields |= {
            "default": "fast",
            "options": (OptionSpec("fast", "Fast", "Goes fast."), OptionSpec("safe", "Safe", "Goes safely.")),
        }
    elif kind is SettingType.STRING:
        fields |= {"default": "hello", "max_length": 20}
    else:
        fields |= {"default": []}
    fields |= overrides
    return SettingSpec(**fields)


def uk(*pieces: str) -> str:
    """Join pieces of a British spelling (kept in pieces so this file passes the style check)."""
    return "".join(pieces)


def must_refuse(spec: SettingSpec, raw: Any, fragment: str = "") -> str:
    with pytest.raises(SettingValidationError) as caught:
        validate_spec_value(spec, raw)
    assert caught.value.key == spec.key
    assert fragment in caught.value.message, caught.value.message
    return caught.value.message


def real(key: str) -> SettingSpec:
    """A real catalog spec, or skip when its group module is not loaded yet (partial mode)."""
    spec = CATALOG.get(key)
    if spec is None:
        pytest.skip(f"{key} is not in the catalog yet (partial build)")
    return spec


def load_docs_script() -> ModuleType:
    path = REPO_ROOT / "scripts" / "gen_settings_docs.py"
    spec = importlib.util.spec_from_file_location("roxy_gen_settings_docs", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --- The real catalog -------------------------------------------------------------------------------------------------


def test_catalog_self_check_passes() -> None:
    """Unique keys, valid defaults, help text, page anchors, no dashes, US spelling, consistent defaults."""
    assert list(SELF_CHECK_PROBLEMS) == []
    assert catalog_self_check() == []


def test_every_setting_on_a_feature_page() -> None:
    """Plan 15.6 acceptance test: every key is editable inline on at least one known dashboard card."""
    assert CATALOG, "the catalog is empty"
    for key, spec in CATALOG.items():
        assert spec.pages, key
        assert all(is_known_anchor(anchor) for anchor in spec.pages), (key, spec.pages)


def test_every_group_module_is_accounted_for() -> None:
    loaded = {origin.rsplit(".", 1)[-1] for origin in catalog.SPEC_ORIGINS.values()}
    missing = {item.module.rsplit(".", 1)[-1] for item in catalog.MISSING_MODULES}
    if not catalog.PARTIAL:
        assert missing == set()
    for name in catalog.GROUP_MODULES:
        assert name in loaded or name in missing or name == "insight_params", name


def test_defaults_are_canonical_and_round_trip() -> None:
    assert set(DEFAULTS) == set(CATALOG)
    for key, spec in CATALOG.items():
        assert validate_spec_value(spec, DEFAULTS[key]) == DEFAULTS[key], key
    json.dumps(DEFAULTS)  # every default is plain JSON data


def test_defaults_pass_every_cross_rule() -> None:
    assert validate_cross(DEFAULTS) == []
    assert validate_cross({}) == []


def test_unknown_key_is_refused() -> None:
    with pytest.raises(SettingValidationError) as caught:
        validate_value("no_such_setting", 1)
    assert caught.value.message == "Unknown setting"


# --- Partial mode and module loading ----------------------------------------------------------------------------------


def test_partial_mode_reads_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(catalog.PARTIAL_ENV, "1")
    assert catalog.partial_mode()
    monkeypatch.setenv(catalog.PARTIAL_ENV, "0")
    assert not catalog.partial_mode()
    monkeypatch.delenv(catalog.PARTIAL_ENV)
    assert not catalog.partial_mode()


def test_missing_group_module_is_tolerated_only_in_partial_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(catalog, "GROUP_MODULES", ("not_written_yet_for_test",))
    specs, missing = catalog.load_group_specs(partial=True)
    assert specs == []
    assert [item.module for item in missing] == ["roxy.config.settings.not_written_yet_for_test"]
    with pytest.raises(CatalogError, match=r"not_written_yet_for_test"):
        catalog.load_group_specs(partial=False)


def test_missing_third_party_module_is_always_an_error() -> None:
    with pytest.raises(CatalogError):
        catalog._import_source("roxy_test_no_such_third_party_package", True, [])


def test_missing_insight_params_tolerated_only_in_partial_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(catalog, "INSIGHT_PARAMS_MODULE", "roxy.config.not_written_insight_params")
    missing: list[catalog.MissingModule] = []
    assert catalog.load_insight_rules(True, missing) == {}
    assert missing
    assert missing[0].module == "roxy.config.not_written_insight_params"
    with pytest.raises(CatalogError):
        catalog.load_insight_rules(False, [])


def test_strict_import_in_a_fresh_process() -> None:
    """Without ROXY_CATALOG_PARTIAL the import succeeds only when every source module exists."""
    env = {k: v for k, v in os.environ.items() if k != catalog.PARTIAL_ENV}
    env["PYTHONPATH"] = str(REPO_ROOT / "src")
    result = subprocess.run(
        [sys.executable, "-c", "import roxy.config.catalog as c; print(len(c.CATALOG))"],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if catalog.MISSING_MODULES:
        assert result.returncode != 0
        assert "CatalogError" in result.stderr
    else:
        assert result.returncode == 0, result.stderr
        assert int(result.stdout.strip()) == len(CATALOG)


# --- Generated per-rule settings (plan 11.1, 15.3 J2) -----------------------------------------------------------------


def test_insight_rule_settings_from_a_synthetic_rule() -> None:
    rule = InsightRuleSpec(
        rule_id="UP-429-ENDPOINT",
        family="upstream",
        title="Roblox 429s concentrated on an endpoint",
        params=(
            ParamSpec("min_429s", 20, 1, 10000, "responses", "Minimum Roblox 429s"),
            ParamSpec("calls_per_request", 1.3, 1.0, 5.0, "calls", "Calls per request", is_int=False),
        ),
    )
    generated = {spec.key: spec for spec in insight_rule_settings({rule.rule_id: rule})}
    assert list(generated) == [
        "insight_up_429_endpoint_enabled",
        "insight_up_429_endpoint_severity",
        "insight_up_429_endpoint_min_429s",
        "insight_up_429_endpoint_calls_per_request",
    ]
    enabled = generated["insight_up_429_endpoint_enabled"]
    assert (enabled.type, enabled.default, enabled.group) == (SettingType.BOOL, 1, Group.INSIGHT_RULES)
    severity = generated["insight_up_429_endpoint_severity"]
    assert severity.type is SettingType.ENUM
    assert severity.default == "auto"
    assert severity.option_values() == ("auto", "info", "warn", "critical")
    assert all(option.description for option in severity.options)
    count = generated["insight_up_429_endpoint_min_429s"]
    assert (count.type, count.default, count.min, count.max, count.unit) == (
        SettingType.INT,
        20,
        1,
        10000,
        "responses",
    )
    assert count.if_raised == "Fires less often, only on stronger evidence."
    ratio = generated["insight_up_429_endpoint_calls_per_request"]
    assert ratio.type is SettingType.FLOAT
    assert ratio.default == pytest.approx(1.3)
    for spec in generated.values():
        assert spec.pages == ("recommendations#rule-up_429_endpoint",)
        assert spec.related_recommendations == ("UP-429-ENDPOINT",)
    assert catalog_self_check(generated.values(), partial=True, style_words=[]) == []


def test_silencing_a_guard_rule_is_flagged_as_risky() -> None:
    rule = InsightRuleSpec("CRED-ROTATOR-GUARD", "credential", "Leak guard tripped")
    enabled = insight_rule_settings({rule.rule_id: rule})[0]
    assert enabled.risk is Risk.MEDIUM
    assert enabled.is_high_risk_value(0)
    assert enabled.is_high_risk_value(1) is None


def test_every_insight_rule_has_its_generated_settings() -> None:
    if not INSIGHT_RULES:
        pytest.skip("roxy.config.insight_params is not written yet (partial build)")
    for rule in INSIGHT_RULES.values():
        slug = rule.slug
        assert CATALOG[f"insight_{slug}_enabled"].default == 1
        assert CATALOG[f"insight_{slug}_severity"].default == "auto"
        for param in rule.params:
            spec = CATALOG[f"insight_{slug}_{param.name}"]
            assert spec.group is Group.INSIGHT_RULES
            assert spec.pages == (f"recommendations#rule-{slug}",)
            assert DEFAULTS[spec.key] == pytest.approx(param.default)


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        ("insight_up_429_endpoint_min_429s", 20),
        ("insight_up_429_endpoint_share_pct", 2),
        ("insight_up_429_endpoint_window_min", 60),
        ("insight_cache_low_hit_max_hit_ratio_pct", 30),
        ("insight_up_latency_p95_ms", 1500),
        ("insight_up_429_amplify_calls_per_request", 1.3),
    ],
)
def test_plan_examples_of_rule_thresholds(key: str, expected: float) -> None:
    """The examples in plan 11.1 and 15.3 J2."""
    real(key)
    assert DEFAULTS[key] == pytest.approx(expected)


# --- validate_value, one type at a time -------------------------------------------------------------------------------


def test_int_values() -> None:
    spec = make_spec(min=0, max=5000, unit="requests")
    assert validate_spec_value(spec, 1500) == 1500
    assert validate_spec_value(spec, "1,500") == 1500
    assert validate_spec_value(spec, " 1_500 ") == 1500
    assert validate_spec_value(spec, 1500.0) == 1500
    assert isinstance(validate_spec_value(spec, "15"), int)
    must_refuse(spec, 1500.5, "whole number")
    must_refuse(spec, True, "not true or false")
    must_refuse(spec, "lots", "Expected a number")
    must_refuse(spec, float("nan"), "finite")
    must_refuse(spec, 5001, "between 0 and 5000 requests")
    must_refuse(spec, -1, "between 0 and 5000")
    must_refuse(spec, [1], "Expected a number")


def test_float_values() -> None:
    spec = make_spec(kind=SettingType.FLOAT, default=0.5, min=0.1, max=0.95)
    assert validate_spec_value(spec, "0.5") == 0.5
    assert validate_spec_value(spec, 0.1) == 0.1
    must_refuse(spec, float("inf"), "finite")
    must_refuse(spec, "inf", "finite")
    must_refuse(spec, 1, "between 0.1 and 0.95")


def test_bool_values() -> None:
    spec = make_spec(kind=SettingType.BOOL)
    for raw, expected in [(True, 1), (False, 0), (1, 1), (0, 0), ("1", 1), ("on", 1), ("FALSE", 0), (" no ", 0)]:
        assert validate_spec_value(spec, raw) == expected, raw
    for raw in (2, "maybe", None, [1]):
        must_refuse(spec, raw, "Expected 0 or 1")


def test_enum_values() -> None:
    spec = make_spec(kind=SettingType.ENUM)
    assert validate_spec_value(spec, "safe") == "safe"
    assert validate_spec_value(spec, " SAFE ") == "safe"
    must_refuse(spec, "slow", "Must be one of: fast, safe")
    must_refuse(spec, 1, "Must be one of")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [(90, 90), ("90", 90), ("90s", 90), ("15m", 900), ("2h", 7200), ("1h30m", 5400), ("1d", 86400), (" 2 H ", 7200)],
)
def test_duration_in_seconds(raw: Any, expected: int) -> None:
    assert validate_spec_value(make_spec(kind=SettingType.DURATION), raw) == expected


def test_duration_in_milliseconds() -> None:
    spec = make_spec(kind=SettingType.DURATION, unit="ms", default=200, max=60000)
    assert validate_spec_value(spec, 250) == 250
    assert validate_spec_value(spec, "250ms") == 250
    assert validate_spec_value(spec, "1.5s") == 1500
    assert validate_spec_value(spec, "1m") == 60000
    must_refuse(spec, "2m", "between 0 and 60000 ms")


def test_duration_errors() -> None:
    spec = make_spec(kind=SettingType.DURATION)
    must_refuse(spec, "500ms", "whole number of seconds")
    must_refuse(spec, "10 parsecs", "Unknown time unit")
    must_refuse(spec, "soon", "duration such as 90, 90s, 15m or 2h")
    must_refuse(spec, "2d", "between 0 and 86400")
    must_refuse(spec, 1.5, "whole number of seconds")


def test_duration_parser_cannot_be_made_to_backtrack() -> None:
    """Security review L3: "1s  1s  ... !" took exponential time (3x per part) on the event loop."""
    import time

    spec = make_spec(kind=SettingType.DURATION, max=10**9)
    for raw in ("1s  " * 16 + "!", "1s " * 200 + "x!", "9" * 5000 + "s"):
        started = time.perf_counter()
        must_refuse(spec, raw, "duration such as 90, 90s, 15m or 2h")
        assert time.perf_counter() - started < 0.05, raw[:20]
    assert validate_spec_value(spec, "1h 30m 15s") == 5415
    assert validate_spec_value(spec, " 2 h 1 m ") == 7260


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (65536, 65536),
        ("64 MiB", 64 * 1024**2),
        ("64MiB", 64 * 1024**2),
        ("1 GiB", 1024**3),
        ("1.5 GiB", 1536 * 1024**2),
        ("0.5 KiB", 512),
        ("2 MB", 2_000_000),
        ("512 bytes", 512),
        ("1,048,576", 1048576),
    ],
)
def test_bytes_values(raw: Any, expected: int) -> None:
    assert validate_spec_value(make_spec(kind=SettingType.BYTES), raw) == expected


def test_bytes_errors_and_other_units() -> None:
    spec = make_spec(kind=SettingType.BYTES)
    must_refuse(spec, "0.1 KiB", "whole number of bytes")
    must_refuse(spec, "64 XB", "size such as 65536, 64 KiB")
    must_refuse(spec, "3 GiB", "between 0 and")
    megabytes = make_spec(kind=SettingType.BYTES, unit="MB", default=0, max=1_000_000)
    assert validate_spec_value(megabytes, 5) == 5
    assert validate_spec_value(megabytes, "1 GB") == 1000


def test_percent_values() -> None:
    spec = make_spec(kind=SettingType.PERCENT, default=80, min=None, max=None)
    assert validate_spec_value(spec, "50%") == 50
    assert isinstance(validate_spec_value(spec, 50), int)
    assert validate_spec_value(spec, 50.5) == 50.5
    must_refuse(spec, 101, "between 0 and 100 percent")
    wide = make_spec(kind=SettingType.PERCENT, default=0.5, min=0, max=200, unit="percent")
    assert validate_spec_value(wide, "150") == 150.0
    assert isinstance(validate_spec_value(wide, "150"), float)


def test_string_values() -> None:
    spec = make_spec(kind=SettingType.STRING)
    assert validate_spec_value(spec, "  hi there  ") == "hi there"
    assert validate_spec_value(spec, "line one\r\nline two") == "line one\nline two"
    must_refuse(spec, "x" * 21, "longer than 20 characters")
    message = must_refuse(spec, f"down {EM_DASH} back", "em dash or en dash")
    assert "semicolon" in message
    assert EM_DASH not in message
    must_refuse(spec, f"1{EN_DASH}2", "em dash or en dash")
    must_refuse(spec, "bell\x07", "control character")
    must_refuse(spec, 5, "Expected text")
    unbounded = make_spec(kind=SettingType.STRING, max_length=None)
    must_refuse(unbounded, "x" * (catalog.DEFAULT_STRING_MAX_LENGTH + 1), "longer than 2000")


def test_list_of_strings() -> None:
    spec = make_spec(kind=SettingType.LIST_STR, max_length=3, item_max_length=10)
    assert validate_spec_value(spec, ["a", " b ", "", "a"]) == ["a", "b"]
    assert validate_spec_value(spec, "a, b\nc") == ["a", "b", "c"]
    assert validate_spec_value(spec, "") == []
    must_refuse(spec, "a,b,c,d", "Too many items (4); the limit is 3")
    must_refuse(spec, ["x" * 11], "longer than 10")
    must_refuse(spec, [f"a{EM_DASH}b"], "em dash")
    must_refuse(spec, [1], "must be text")
    must_refuse(spec, {"a": 1}, "Expected a list")


def test_list_of_ints() -> None:
    spec = make_spec(kind=SettingType.LIST_INT, item_min=1, item_max=100, max_length=10)
    assert validate_spec_value(spec, "50, 80,95,80") == [50, 80, 95]
    assert validate_spec_value(spec, [50, "80"]) == [50, 80]
    must_refuse(spec, [0], "below the minimum 1")
    must_refuse(spec, "50,101", "above the maximum 100")
    must_refuse(spec, ["x"], "not a whole number")


def test_list_of_cidrs() -> None:
    spec = make_spec(kind=SettingType.LIST_CIDR, max_length=5)
    assert validate_spec_value(spec, "10.0.0.7/8\n192.0.2.1, 2001:DB8::1/64, 10.1.2.3/8") == [
        "10.0.0.0/8",
        "192.0.2.1/32",
        "2001:db8::/64",
    ]
    must_refuse(spec, ["10.0.0.300"], "not a valid IP address or CIDR range")
    must_refuse(spec, ["example.com"], "not a valid IP address")


# --- Key-specific checks (real keys) ----------------------------------------------------------------------------------


def test_timezone_names() -> None:
    real("ui_timezone")
    assert validate_value("ui_timezone", "UTC") == "UTC"
    assert validate_value("ui_timezone", "America/New_York") == "America/New_York"
    with pytest.raises(SettingValidationError, match=r"Unknown time zone"):
        validate_value("ui_timezone", "Mars/Olympus_Mons")
    with pytest.raises(SettingValidationError):
        validate_value("ui_timezone", "../etc/passwd")


def test_credential_probe_url() -> None:
    real("credential_probe_url")
    for good in ("https://users.roblox.com/v1/users/authenticated", "users.roblox.com/v1/users/authenticated"):
        assert validate_value("credential_probe_url", good) == good
    for bad in (
        "http://users.roblox.com/v1/users/authenticated",
        "https://users.roblox.com.evil.example/v1",
        "https://user:pw@users.roblox.com/v1",
        "https://users.roblox.com:8443/v1",
        "https://users.roblox.com:notaport/v1",
    ):
        with pytest.raises(SettingValidationError, match=r"https URL on a roblox.com host"):
            validate_value("credential_probe_url", bad)


def test_allowed_roblox_hosts() -> None:
    real("allowed_roblox_hosts")
    assert validate_value("allowed_roblox_hosts", ["Games.Roblox.com.", "users", "games.roblox.com"]) == [
        "games.roblox.com",
        "users",
    ]
    with pytest.raises(SettingValidationError, match=r"not a roblox.com host"):
        validate_value("allowed_roblox_hosts", ["evil.example.com"])
    with pytest.raises(SettingValidationError, match=r"not a roblox.com host"):
        validate_value("allowed_roblox_hosts", ["bad host"])


def test_the_credential_allowlist_is_not_a_setting() -> None:
    """Spec review 3: the `credential_allowlist` table (with its required `cache_private`) is the only allowlist;
    a list setting could not hold `cache_private` and nothing read it."""
    with pytest.raises(SettingValidationError, match="Unknown setting"):
        validate_value("credential_endpoint_allowlist", ["games.roblox.com/v1/*"])
    with pytest.raises(SettingValidationError, match="Unknown setting"):
        validate_value("ignored_paths", ["games.roblox.com/v1/games"])


def test_retention_forever_or_at_least_thirty_days() -> None:
    real("retention_day_days")
    assert validate_value("retention_day_days", 0) == 0
    assert validate_value("retention_day_days", 30) == 30
    with pytest.raises(SettingValidationError, match=r"at least 30 days"):
        validate_value("retention_day_days", 10)


def test_rotator_username_template() -> None:
    real("rotator_session_username_template")
    key = "rotator_session_username_template"
    assert validate_value(key, "") == ""
    assert validate_value(key, "{user}-session-{session}") == "{user}-session-{session}"
    with pytest.raises(SettingValidationError, match=r"must contain"):
        validate_value(key, "{user}")
    with pytest.raises(SettingValidationError, match=r"Unknown placeholder"):
        validate_value(key, "{user}{session}{password}")
    with pytest.raises(SettingValidationError, match=r"cannot contain"):
        validate_value(key, "{user}:{session}")


def test_user_agent_header_injection_is_refused() -> None:
    real("direct_user_agent")
    with pytest.raises(SettingValidationError):
        validate_value("direct_user_agent", "Mozilla/5.0\r\nX-Evil: 1")
    with pytest.raises(SettingValidationError, match=r"printable ASCII"):
        validate_value("direct_user_agent", "Mozilla/5.0 caf" + chr(0xE9))


def test_site_links_must_be_https() -> None:
    spec = make_spec("site_demo_links", SettingType.STRING, max_length=200, default="See https://example.org")
    assert validate_spec_value(spec, "See https://example.org") == "See https://example.org"
    must_refuse(spec, "See http://example.org", "https://")
    must_refuse(spec, "javascript:alert(1)", "plain https://")


# --- Cross-field rules ------------------------------------------------------------------------------------------------


def test_min_max_pairs_are_found_by_name() -> None:
    keys = [
        "cooldown_min_s",
        "cooldown_max_s",
        "adaptive_min_per_min",
        "adaptive_max_per_min",
        "spam_rate_ban_minutes",
        "spam_rate_ban_max_minutes",
        "bot_score_legit_max",
        "lonely_min",
    ]
    assert min_max_pairs(keys) == [
        ("adaptive_min_per_min", "adaptive_max_per_min"),
        ("cooldown_min_s", "cooldown_max_s"),
        ("spam_rate_ban_minutes", "spam_rate_ban_max_minutes"),
    ]


def test_min_max_rule_on_a_synthetic_catalog() -> None:
    low = make_spec("hold_min_s", SettingType.DURATION, default=5)
    high = make_spec("hold_max_s", SettingType.DURATION, default=10)
    synthetic = {low.key: low, high.key: high}
    assert validate_cross({}, catalog=synthetic) == []
    issues = validate_cross({"hold_min_s": 20}, catalog=synthetic)
    assert [(issue.rule, issue.keys) for issue in issues] == [("min_max", ("hold_min_s", "hold_max_s"))]
    assert "hold_min_s (20) must not be greater than hold_max_s (10)" in issues[0].message


@pytest.mark.parametrize(
    ("changes", "rule"),
    [
        ({"tarpit_min_seconds": 30, "tarpit_max_seconds": 20}, "min_max"),
        ({"tarpit_jitter_min_ms": 5000, "tarpit_jitter_max_ms": 1000}, "min_max"),
        ({"aimd_initial": 64}, "chain"),
        ({"aimd_min": 16, "aimd_initial": 8}, "chain"),
        ({"cooldown_default_s": 2000}, "chain"),
        ({"backoff_base_ms": 5000, "backoff_cap_ms": 2000}, "chain"),
        ({"credential_probe_reserved_per_min": 20, "credential_bucket_per_min": 20}, "credential_reserve"),
        ({"bot_score_legit_max": 90}, "bot_score_bands"),
        ({"request_deadline_s": 30}, "owner_deadline"),
        ({"request_deadline_s": 20}, "tarpit_deadline"),
        ({"request_deadline_s": 95}, "deadline_max"),
        ({"cache_coalesce_wait_ms": 59000}, "coalesce_deadline"),
        ({"credential_probe_url": "https://economy.roblox.com/v1/x", "allowed_roblox_hosts": ["users"]}, "probe_host"),
    ],
)
def test_cross_rules_on_the_real_catalog(changes: dict[str, Any], rule: str) -> None:
    for key in changes:
        real(key)
    issues = validate_cross(changes)
    assert rule in {issue.rule for issue in issues}, issues
    for issue in issues:
        assert issue.message
        assert issue.keys
        assert EM_DASH not in issue.message
        assert EN_DASH not in issue.message


def test_probe_host_rule_respects_the_strict_switch() -> None:
    for key in ("credential_probe_url", "allowed_roblox_hosts", "strict_host_allowlist"):
        real(key)
    changes = {"credential_probe_url": "users.roblox.com/v1/users/authenticated", "allowed_roblox_hosts": ["games"]}
    assert "probe_host" in {issue.rule for issue in validate_cross(changes)}
    assert "probe_host" not in {issue.rule for issue in validate_cross(changes | {"strict_host_allowlist": 0})}
    short_names = {"credential_probe_url": "https://users.roblox.com/v1/x", "allowed_roblox_hosts": ["users"]}
    assert validate_cross(short_names) == []


def test_owner_deadline_matches_plan_5_2() -> None:
    for key in ("queue_wait_interactive_ms", "request_timeout", "upstream_max_attempts", "backoff_cap_ms"):
        real(key)
    assert owner_deadline_s(DEFAULTS) == pytest.approx(36.0)
    assert owner_deadline_s({}) is None


# --- The self check finds each kind of mistake ------------------------------------------------------------------------


def test_self_check_reports_each_kind_of_mistake() -> None:
    broken = [
        make_spec("dup_key"),
        make_spec("dup_key"),
        make_spec("Bad-Key"),
        make_spec("no_raise_text", if_raised=""),
        make_spec("no_enable_text", SettingType.BOOL, if_disabled=""),
        make_spec("bad_option", SettingType.ENUM, options=(OptionSpec("fast", "Fast", ""),)),
        make_spec("bad_default", default=1000),
        make_spec("no_pages", pages=()),
        make_spec("odd_page", pages=("upstream#nowhere",)),
        make_spec("dashed_text", description=f"One {EM_DASH} two."),
        make_spec("reversed_range", min=10, max=1, default=5),
        make_spec("bad_bounds", auto_apply_bounds=(50, 500)),
        make_spec("silent_risk", high_risk_if=(RiskCondition(RiskOp.EQ, 0, " "),)),
        make_spec("current_alias", renamed_from="dup_key"),
        make_spec("no_label", label=" "),
    ]
    problems = "\n".join(catalog_self_check(broken, partial=True, style_words=[]))
    expected = [
        "dup_key: declared more than once",
        "'Bad-Key': keys are lowercase snake_case",
        "no_raise_text: a number setting needs both if_raised and if_lowered text",
        "no_enable_text: a bool setting needs both if_enabled and if_disabled text",
        "bad_option: option 'fast' needs a value, a label and a description",
        "bad_default: default 1000 is invalid: Must be between 0 and 100",
        "no_pages: pages is empty",
        "odd_page: page anchor 'upstream#nowhere' is not in the DESIGN.md section 9 vocabulary",
        "dashed_text: description contains an em or en dash",
        "reversed_range: min 10 is greater than max 1",
        "bad_bounds: auto_apply_bounds (50, 500) leave the min/max range",
        "silent_risk: a high_risk_if condition has no explanation",
        "current_alias: renamed_from 'dup_key' is also a current key",
        "no_label: label is empty",
    ]
    for line in expected:
        assert line in problems, line


def test_self_check_reports_defaults_that_break_cross_rules() -> None:
    low = make_spec("gap_min_ms", SettingType.DURATION, unit="ms", default=900)
    high = make_spec("gap_max_ms", SettingType.DURATION, unit="ms", default=100)
    problems = catalog_self_check([low, high], partial=True, style_words=[])
    assert any("defaults break a cross-field rule: gap_min_ms (900)" in line for line in problems)


def test_related_settings_must_exist_unless_partial() -> None:
    spec = make_spec("lonely", related_settings=("not_a_key",))
    assert catalog_self_check([spec], partial=True, style_words=[]) == []
    assert catalog_self_check([spec], partial=False, style_words=[]) == [
        "lonely: related setting 'not_a_key' does not exist"
    ]


def test_style_words_are_applied(tmp_path: Path) -> None:
    words_file = tmp_path / "style_words.txt"
    words_file.write_text(
        "# comment\n[words]\ncolo[u]r          color\nanaly[s]e   analyze\n\\benro[l]\\b  enroll\n"
        "[exceptions]\nhttps?://\\S+\n",
        encoding="utf-8",
    )
    words, exceptions = load_style_words(words_file)
    assert [word.source for word in words] == ["colo[u]r", "analy[s]e", r"\benro[l]\b"]
    assert [word.replacement for word in words] == ["color", "analyze", "enroll"]
    assert len(exceptions) == 1

    def flagged(text: str) -> bool:
        spec = make_spec("styled", description=text)
        return bool(catalog_self_check([spec], partial=True, style_words=words, style_exceptions=exceptions))

    # British spellings are built from pieces so this file passes the plan C5 style check itself.
    assert flagged(f"The {uk('col', 'our')} of the dashboard.")
    assert flagged(f"{uk('Col', 'ours')} change.")
    assert flagged(f"Roxy is {uk('analy', 'sing')} traffic.")
    assert flagged(f"Please {uk('enr', 'ol')}.")
    assert not flagged("The color of the dashboard.")
    assert not flagged("You enrolled.")  # an explicit \b pattern matches the exact word only
    assert not flagged(f"See https://example.org/{uk('col', 'our')} for details.")


def test_missing_style_words_file_means_no_word_rules(tmp_path: Path) -> None:
    assert load_style_words(tmp_path / "absent.txt") == ([], [])


def test_the_repository_style_words_file_is_understood() -> None:
    path = REPO_ROOT / "scripts" / "style_words.txt"
    if not path.exists():
        pytest.skip("scripts/style_words.txt is not written yet")
    words, _exceptions = load_style_words(path)
    assert len(words) >= 40
    assert any(word.regex.search(uk("behavi", "our")) for word in words)
    assert not any(word.regex.search("behavior") for word in words)
    assert not any(word.regex.search("a short description of the setting") for word in words)


# --- Anchors, grouping, search, export --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "anchor",
    [
        "upstream#routing",
        "egress#budget",
        "protection#spam-dist",
        "recommendations#rule-up_429_endpoint",
        "topbar#pause",
        "topbar#throttle-all",
        "user-menu#preferences",
        "settings#public-site",
        "live#tail",
    ],
)
def test_known_anchors(anchor: str) -> None:
    assert is_known_anchor(anchor)


@pytest.mark.parametrize(
    "anchor", ["upstream", "upstream#nowhere", "protection#spam-other", "recommendations#rule-UP-1", ""]
)
def test_unknown_anchors(anchor: str) -> None:
    assert not is_known_anchor(anchor)


def test_by_group_keeps_settings_page_order() -> None:
    first = make_spec("first_in_cache", group=Group.CACHE)
    routing = make_spec("a_routing_key", group=Group.ROUTING)
    second = make_spec("second_in_cache", group=Group.CACHE)
    grouped = by_group({spec.key: spec for spec in (first, routing, second)})
    assert list(grouped) == [Group.ROUTING, Group.CACHE]
    assert [spec.key for spec in grouped[Group.CACHE]] == ["first_in_cache", "second_in_cache"]
    real_grouped = by_group()
    assert sum(len(specs) for specs in real_grouped.values()) == len(CATALOG)
    assert real_grouped == catalog.GROUPED


def test_search_ranks_keys_first() -> None:
    specs = [
        make_spec("cache_ttl_seconds", label="Cache lifetime", description="How long a 2xx stays."),
        make_spec("cache_serve_throttled", label="Serve throttled callers", description="Uses the cache ttl."),
        make_spec("ttl_tuner_max_s", label="Tuner ceiling", description="Caps cache TTL suggestions."),
        make_spec("other_thing", group=Group.ROUTING, risk=Risk.HIGH, description="Unrelated."),
    ]
    synthetic = {spec.key: spec for spec in specs}
    assert [s.key for s in search("cache_ttl_seconds", catalog=synthetic)] == ["cache_ttl_seconds"]
    assert [s.key for s in search("ttl cache", catalog=synthetic)][:1] == ["cache_ttl_seconds"]
    assert search("ttl", catalog=synthetic)[0].key == "ttl_tuner_max_s"
    assert [s.key for s in search("", group=Group.ROUTING, catalog=synthetic)] == ["other_thing"]
    assert [s.key for s in search("", risk="high", catalog=synthetic)] == ["other_thing"]
    assert search("no such words here", catalog=synthetic) == []


def test_public_dict_redacts_sensitive_values() -> None:
    secret = make_spec("demo_secret", SettingType.STRING, sensitive=True, default="", max_length=64)
    plain = make_spec("demo_plain", high_risk_if=(RiskCondition(RiskOp.GT, 50, "Too much."),))
    synthetic = {secret.key: secret, plain.key: plain}
    exported = to_public_dict({"demo_secret": "fake-token-for-test", "demo_plain": 60}, catalog=synthetic)
    text = json.dumps(exported)
    assert "fake-token-for-test" not in text
    entries = {entry["key"]: entry for group in exported["groups"] for entry in group["settings"]}
    assert entries["demo_secret"]["value"] == REDACTED
    assert entries["demo_secret"]["default"] == REDACTED
    assert entries["demo_secret"]["changed"] is True
    assert entries["demo_plain"]["value"] == 60
    assert entries["demo_plain"]["high_risk_reason"] == "Too much."
    compact = to_public_dict(catalog=synthetic, include_text=False)
    compact_entry = compact["groups"][0]["settings"][0]
    assert "description" not in compact_entry
    assert "value" not in compact_entry


def test_public_dict_of_the_real_catalog_is_json() -> None:
    exported = to_public_dict(DEFAULTS)
    assert exported["setting_count"] == len(CATALOG)
    assert exported["catalog_version"] == catalog.CATALOG_VERSION
    text = json.dumps(exported)
    assert EM_DASH not in text
    assert EN_DASH not in text


def test_catalog_version_tracks_defaults() -> None:
    spec = make_spec("versioned")
    changed = dataclasses.replace(spec, default=6)
    assert catalog_version({spec.key: spec}) == catalog_version({spec.key: spec})
    assert catalog_version({spec.key: spec}) != catalog_version({changed.key: changed})


def test_v1_names_resolve_to_current_keys() -> None:
    assert catalog.resolve_key("definitely_not_a_key") is None
    for key, spec in CATALOG.items():
        assert catalog.resolve_key(key) == key
        if spec.renamed_from:
            assert catalog.resolve_key(spec.renamed_from) == key


# --- docs/SETTINGS.md generator ---------------------------------------------------------------------------------------


def test_settings_docs_cover_every_key_and_group() -> None:
    docs = load_docs_script()
    text = docs.render(catalog)
    for key in CATALOG:
        assert f"### `{key}`" in text, key
    for group in catalog.GROUPED:
        assert f'<a id="group-{group.value}"></a>' in text
    assert "## Cross-field rules" in text
    assert EM_DASH not in text
    assert EN_DASH not in text
    assert text == docs.render(catalog)  # deterministic, so --check can compare byte for byte


def test_settings_docs_block_has_every_field() -> None:
    docs = load_docs_script()
    spec = make_spec("cache_demo_bytes", SettingType.BYTES, default=64 * 1024**2, renamed_from="old_demo")
    block = "\n".join(docs.render_spec(spec, catalog))
    for field_name in (
        "Label",
        "Type",
        "Default",
        "Range",
        "If raised",
        "If lowered",
        "Risk",
        "Applies",
        "Dashboard",
        "Related recommendations",
        "Auto-apply bounds",
        "Sensitive",
        "v1 key",
        "Notes",
    ):
        assert f"| {field_name} |" in block, field_name
    assert "67108864 bytes (64 MiB)" in block
    assert "`old_demo`" in block


def test_settings_docs_check_mode(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    docs = load_docs_script()
    output = tmp_path / "SETTINGS.md"
    assert docs.main(["--check", "--output", str(output)]) == 1
    assert docs.main(["--output", str(output)]) == 0
    assert docs.main(["--check", "--output", str(output)]) == 0
    output.write_text(output.read_text(encoding="utf-8") + "edited by hand\n", encoding="utf-8")
    assert docs.main(["--check", "--output", str(output)]) == 1
    capsys.readouterr()


# --- fix pass: spec review 5 and 9 ------------------------------------------------------------------------------------


def test_a_ban_action_needs_ban_lengths() -> None:
    """Spec review 5: plan E2 gives ban lengths 1 to 10080 while the action is ban; 0 means "no length"."""
    from roxy.config.catalog import validate_cross

    assert validate_cross({}) == []
    issues = validate_cross({"spam_rate_ban_minutes": 0})  # spam_rate defaults to ban
    assert [issue.rule for issue in issues] == ["ban_length"]
    assert issues[0].keys == ("spam_rate_action", "spam_rate_ban_minutes")
    keys = {issue.keys[1] for issue in validate_cross({"spam_enum_action": "ban"})}
    assert keys == {"spam_enum_ban_minutes", "spam_enum_ban_max_minutes"}
    assert (
        validate_cross({"spam_enum_action": "ban", "spam_enum_ban_minutes": 5, "spam_enum_ban_max_minutes": 60}) == []
    )
    assert validate_cross({"spam_rate_action": "strike", "spam_rate_ban_minutes": 0}) == []


def test_threshold_pairs_from_help_text_are_checked() -> None:
    """Spec review 9: the help text promises p95 <= p99 and "lower" below "raise"; now they are enforced."""
    from roxy.config.catalog import cross_rule_descriptions, validate_cross

    assert validate_cross({"insight_up_latency_p95_ms": 5000, "insight_up_latency_p99_ms": 1000})
    assert validate_cross(
        {"insight_cache_ttl_tune_identical_raise_pct": 50, "insight_cache_ttl_tune_identical_lower_pct": 90}
    )
    assert validate_cross({"insight_up_latency_p95_ms": 900, "insight_up_latency_p99_ms": 1000}) == []
    text = "\n".join(cross_rule_descriptions())
    assert "`insight_up_latency_p95_ms` <= `insight_up_latency_p99_ms`" in text
    assert "`spam_enum_ban_minutes` >= 1" in text
