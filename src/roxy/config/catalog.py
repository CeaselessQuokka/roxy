"""The settings catalog: every runtime setting, assembled, checked and validated in one place.

What this is
    `CATALOG` (key -> `SettingSpec`) for every runtime setting Roxy has, plus the functions that validate a value
    (`validate_value`), validate a whole set of values against each other (`validate_cross`), check the catalog
    itself (`catalog_self_check`), and serve it to the settings API, the editor's search box, the generated
    docs/SETTINGS.md and the LLM export (`by_group`, `search`, `spec_to_dict`, `to_public_dict`).

Why it exists
    Plan principle P3 and section 15: a setting is declared once, and everything else is generated from that
    declaration. v1 kept a separate list in the UI and the server, so the UI could post a key the server did not
    know (the `tarpit_on_user_agent_rule` bug) and nothing checked that help text existed. Here an unknown key is
    refused, a default that fails its own validation stops the process from starting, and the text an admin
    reads in the editor is the same text the docs and the LLM export show.

How it works
    1. Import every group module in `roxy.config.settings` (each exports `SETTINGS: list[SettingSpec]`). While
       the remake is being built, `ROXY_CATALOG_PARTIAL=1` lets modules that are not written yet be skipped;
       without it a missing module is an error, so production never runs with half a catalog.
    2. Generate the per-rule recommendation settings (plan 11.1, 15.3 J2) from
       `roxy.config.insight_params.INSIGHT_RULES`: `insight_<slug>_enabled`, `insight_<slug>_severity` and one
       `insight_<slug>_<param>` per `ParamSpec`.
    3. Run `catalog_self_check()`: unique keys, every default valid, the help text each type needs, at least one
       dashboard anchor from the DESIGN.md section 9 vocabulary, no em or en dash, no British spelling from
       `scripts/style_words.txt` (when that file is present), and the defaults pass the cross-field rules.
       Problems raise `CatalogError` at import; in partial mode they are kept in `SELF_CHECK_PROBLEMS` and
       reported by the tests instead, so one unfinished module does not hide every other result.
    Values are validated by type (`validate_value`), then by a few key-specific checks (time zone names, host
    names, URLs), then together (`validate_cross`: every `*_min`/`*_max` pair, the AIMD and cooldown chains, and
    the request deadline budget from plan 5.2).

What to read next
    `roxy/config/spec.py` (the field meanings), one group module such as `roxy/config/settings/cache.py`, then
    `roxy/config/runtime.py` (how the current values are held and hot-reloaded) and
    `roxy/config/settings_service.py` (how a change is validated, audited and published).
"""

from __future__ import annotations

import hashlib
import importlib
import ipaddress
import itertools
import json
import math
import os
import re
import string
import warnings
import zoneinfo
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from types import ModuleType
from typing import Any, Final
from urllib.parse import urlsplit

from roxy.config.spec import (
    GROUP_LABELS,
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

# --- Constants --------------------------------------------------------------------------------------------------------

PARTIAL_ENV: Final = "ROXY_CATALOG_PARTIAL"
SETTINGS_PACKAGE: Final = "roxy.config.settings"
INSIGHT_PARAMS_MODULE: Final = "roxy.config.insight_params"

# The group modules, in Settings page order (DESIGN.md section 4).
GROUP_MODULES: Final[tuple[str, ...]] = (
    "routing",
    "credential",
    "upstream",
    "cache",
    "throttling",
    "spam",
    "tarpit",
    "admin_security",
    "alerts",
    "metrics",
    "insights",
    "public_site",
)

# Plan C5: these two characters are banned everywhere, including setting values an admin types.
EM_DASH: Final = chr(0x2014)  # code points, so this file never contains the characters themselves
EN_DASH: Final = chr(0x2013)
DASH_MESSAGE: Final = (
    "Contains an em dash or en dash, which Roxy does not use anywhere (style rule C5). "
    "Use a semicolon, colon, comma, parentheses or a plain hyphen instead."
)

# Bounds for text values whose spec does not set its own (plan P9: nothing is unbounded).
DEFAULT_STRING_MAX_LENGTH: Final = 2000
DEFAULT_LIST_MAX_ITEMS: Final = 1000
DEFAULT_ITEM_MAX_LENGTH: Final = 500

# What sensitive values become in exports (plan 15.1 `sensitive`).
REDACTED: Final = "[redacted]"

# Dashboard vocabulary for the `pages` field (DESIGN.md section 9).
PAGES: Final[tuple[str, ...]] = (
    "overview",
    "recommendations",
    "traffic",
    "upstream",
    "egress",
    "cache",
    "endpoints",
    "clients",
    "protection",
    "live",
    "security",
    "health",
    "settings",
    "credential",
    "data",
    "audit",
    "system",
    "help",
)
NON_PAGE_HOMES: Final[frozenset[str]] = frozenset({"topbar#pause", "topbar#throttle-all", "user-menu#preferences"})
SPAM_DETECTORS: Final[tuple[str, ...]] = ("rate", "refused", "probe", "auth", "enum", "bust", "dist")
CARD_ANCHORS: Final[frozenset[str]] = frozenset(
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
    }
    | {f"protection#spam-{detector}" for detector in SPAM_DETECTORS}
)
_RULE_ANCHOR = re.compile(r"recommendations#rule-[a-z0-9_]+")

_KEY_FORMAT = re.compile(r"[a-z][a-z0-9_]{0,79}")
_NUMERIC_TYPES: Final = frozenset(
    {SettingType.INT, SettingType.FLOAT, SettingType.DURATION, SettingType.BYTES, SettingType.PERCENT}
)
_LIST_TYPES: Final = frozenset({SettingType.LIST_STR, SettingType.LIST_INT, SettingType.LIST_CIDR})

# Control characters are refused in every text value; newline and tab are allowed in free text (home page copy).
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_LIST_SEPARATORS = re.compile(r"[,\n]")


# --- Errors and result types ------------------------------------------------------------------------------------------


class SettingValidationError(ValueError):
    """A value was refused for one setting. `message` is written for the admin and is safe to show as is."""

    def __init__(self, key: str, message: str) -> None:
        super().__init__(f"{key}: {message}")
        self.key = key
        self.message = message


class CatalogError(RuntimeError):
    """The catalog itself is broken (a programming error, found at import time)."""

    def __init__(self, problems: Sequence[str]) -> None:
        self.problems = list(problems)
        shown = "\n  ".join(self.problems[:60])
        more = f"\n  ... and {len(self.problems) - 60} more" if len(self.problems) > 60 else ""
        super().__init__(f"settings catalog check failed ({len(self.problems)} problems):\n  {shown}{more}")


@dataclass(frozen=True, slots=True)
class CrossIssue:
    """One broken cross-field rule (plan 15.2): which keys, what is wrong, and a stable rule id."""

    keys: tuple[str, ...]
    message: str
    rule: str


@dataclass(frozen=True, slots=True)
class MissingModule:
    """A catalog source that was skipped in partial mode, and why."""

    module: str
    reason: str


@dataclass(frozen=True, slots=True)
class StyleWord:
    """One banned spelling from `scripts/style_words.txt` (plan C5)."""

    source: str
    replacement: str
    regex: re.Pattern[str]


def partial_mode() -> bool:
    """True when `ROXY_CATALOG_PARTIAL=1` (build time only: lets unwritten group modules be skipped)."""
    return os.environ.get(PARTIAL_ENV, "") == "1"


# --- Loading the group modules ----------------------------------------------------------------------------------------


def _import_source(name: str, partial: bool, missing: list[MissingModule]) -> ModuleType | None:
    """Import one catalog source; in partial mode, a not-yet-written Roxy module is skipped and recorded."""
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError as exc:
        absent = exc.name or ""
        if partial and (absent == "roxy" or absent.startswith("roxy.")):
            missing.append(MissingModule(name, f"{absent} is not written yet"))
            return None
        raise CatalogError([f"cannot import {name}: {exc}"]) from exc


def load_group_specs(partial: bool) -> tuple[list[tuple[str, SettingSpec]], list[MissingModule]]:
    """Every `SettingSpec` from the group modules, each with the module it came from."""
    found: list[tuple[str, SettingSpec]] = []
    missing: list[MissingModule] = []
    for short_name in GROUP_MODULES:
        name = f"{SETTINGS_PACKAGE}.{short_name}"
        module = _import_source(name, partial, missing)
        if module is None:
            continue
        settings = getattr(module, "SETTINGS", None)
        if not isinstance(settings, list | tuple):
            raise CatalogError([f"{name} does not export SETTINGS as a list of SettingSpec"])
        for spec in settings:
            if not isinstance(spec, SettingSpec):
                raise CatalogError([f"{name}.SETTINGS contains {type(spec).__name__}, not SettingSpec"])
            found.append((name, spec))
    return found, missing


def load_insight_rules(partial: bool, missing: list[MissingModule]) -> dict[str, InsightRuleSpec]:
    """`INSIGHT_RULES` from `roxy.config.insight_params` (empty in partial mode when it is not written yet)."""
    module = _import_source(INSIGHT_PARAMS_MODULE, partial, missing)
    if module is None:
        return {}
    rules = getattr(module, "INSIGHT_RULES", None)
    if not isinstance(rules, Mapping):
        raise CatalogError([f"{INSIGHT_PARAMS_MODULE} does not export INSIGHT_RULES as a dict"])
    result: dict[str, InsightRuleSpec] = {}
    for rule_id, rule in rules.items():
        if not isinstance(rule, InsightRuleSpec):
            raise CatalogError([f"INSIGHT_RULES[{rule_id!r}] is {type(rule).__name__}, not InsightRuleSpec"])
        result[str(rule_id)] = rule
    return result


# --- Generated per-rule settings (plan 11.1, 15.3 J2) -----------------------------------------------------------------

SEVERITY_OPTIONS: Final[tuple[OptionSpec, ...]] = (
    OptionSpec(
        "auto",
        "Automatic",
        "Use the severity the rule computes from its evidence (recommended).",
    ),
    OptionSpec(
        "info",
        "Info",
        "Always report this rule's findings as info: they are listed on the Recommendations page but sit below "
        "the default alert level (alert_min_severity = warn), so no alert is sent for them.",
    ),
    OptionSpec(
        "warn",
        "Warn",
        "Always report this rule's findings as warn (may need action soon); with the default alert settings each "
        "new finding is also sent as an alert.",
    ),
    OptionSpec(
        "critical",
        "Critical",
        "Always report this rule's findings as critical (urgent); they are alerted at every alert_min_severity "
        "level, so use this only for rules you must never miss.",
    ),
)

# Families whose rules watch the account, the leak guard or risky settings: silencing them is a real risk.
_GUARD_FAMILIES: Final = frozenset({"credential", "security"})


def _sentence(text: str) -> str:
    text = text.strip()
    return text if text.endswith((".", "!", "?")) else f"{text}."


def _param_default(param: ParamSpec) -> int | float:
    return int(param.default) if param.is_int else float(param.default)


def load_param_definitions(partial: bool, missing: list[MissingModule]) -> dict[str, str]:
    """`PARAM_DEFINITIONS` from `roxy.config.insight_params`: what each threshold measures (spec review 10)."""
    module = _import_source(INSIGHT_PARAMS_MODULE, partial, missing)
    found = getattr(module, "PARAM_DEFINITIONS", None) if module is not None else None
    return {str(key): str(text) for key, text in found.items()} if isinstance(found, Mapping) else {}


def insight_rule_settings(
    rules: Mapping[str, InsightRuleSpec], definitions: Mapping[str, str] | None = None
) -> list[SettingSpec]:
    """The generated `insight_<slug>_*` settings for every recommendation rule (group `insight_rules`).

    A threshold's description opens with its definition from `definitions` (`"<rule id>.<param>"`), which says
    what is measured, over what and whose; without one it falls back to the label.
    """
    defined = definitions or {}
    generated: list[SettingSpec] = []
    for rule in rules.values():
        slug = rule.slug
        anchor = f"recommendations#rule-{slug}"
        enabled_key = f"insight_{slug}_enabled"
        severity_key = f"insight_{slug}_severity"
        param_keys = tuple(f"insight_{slug}_{param.name}" for param in rule.params)
        detects = _sentence(rule.title)
        guard = rule.family in _GUARD_FAMILIES
        generated.append(
            SettingSpec(
                key=enabled_key,
                group=Group.INSIGHT_RULES,
                label=f"{rule.rule_id}: rule enabled",
                type=SettingType.BOOL,
                default=1,
                description=(
                    f"Turns the {rule.rule_id} recommendation rule on or off ({rule.family} family). "
                    f"It detects: {detects}"
                ),
                pages=(anchor,),
                if_enabled=(
                    "The rule is evaluated on every insights run and on trigger events, and opens a "
                    "recommendation when its evidence crosses its thresholds."
                ),
                if_disabled=(
                    "The rule is silenced entirely: it is not evaluated and opens no new recommendations, so the "
                    "problem it watches for goes unreported."
                ),
                risk=Risk.MEDIUM if guard else Risk.LOW,
                high_risk_if=(
                    (
                        RiskCondition(
                            RiskOp.EQ,
                            0,
                            f"{rule.rule_id} watches the {rule.family} side of Roxy; silencing it hides account "
                            "or security problems until they cause damage.",
                        ),
                    )
                    if guard
                    else ()
                ),
                related_settings=(severity_key, *param_keys),
                related_recommendations=(rule.rule_id,),
            )
        )
        generated.append(
            SettingSpec(
                key=severity_key,
                group=Group.INSIGHT_RULES,
                label=f"{rule.rule_id}: severity",
                type=SettingType.ENUM,
                default="auto",
                options=SEVERITY_OPTIONS,
                description=(
                    f"The severity {rule.rule_id} recommendations are reported with. auto keeps the severity the "
                    "rule computes from its evidence; the other values force one level, which also decides "
                    "whether an alert is sent (compare alert_min_severity)."
                ),
                pages=(anchor,),
                related_settings=(enabled_key, "alert_min_severity"),
                related_recommendations=(rule.rule_id,),
            )
        )
        for param, key in zip(rule.params, param_keys, strict=True):
            generated.append(
                SettingSpec(
                    key=key,
                    group=Group.INSIGHT_RULES,
                    label=f"{rule.rule_id}: {param.label}",
                    type=SettingType.INT if param.is_int else SettingType.FLOAT,
                    default=_param_default(param),
                    unit=param.unit,
                    min=param.min,
                    max=param.max,
                    step=1 if param.is_int else None,
                    description=(
                        f"{defined.get(f'{rule.rule_id}.{param.name}') or _sentence(param.label)} A threshold of "
                        f"the {rule.rule_id} recommendation rule, in {param.unit}; the rule detects: {detects}"
                    ),
                    pages=(anchor,),
                    if_raised=param.if_raised,
                    if_lowered=param.if_lowered,
                    related_settings=(enabled_key,),
                    related_recommendations=(rule.rule_id,),
                )
            )
    return generated


# --- Value parsing helpers --------------------------------------------------------------------------------------------


def _fail(spec: SettingSpec, message: str) -> SettingValidationError:
    return SettingValidationError(spec.key, message)


def _format_number(value: float | int) -> str:
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


_THOUSANDS = re.compile(r"[+-]?\d{1,3}(?:,\d{3})+(?:\.\d+)?")


def _parse_number(spec: SettingSpec, raw: Any) -> int | float:
    """A finite int or float from a JSON number or a numeric string ("1500", "1,500", "1_500", "0.5")."""
    if isinstance(raw, bool):
        raise _fail(spec, "Expected a number, not true or false")
    if isinstance(raw, int):
        return raw
    if isinstance(raw, float):
        if not math.isfinite(raw):
            raise _fail(spec, "Expected a finite number")
        return raw
    if isinstance(raw, str):
        text = raw.strip().replace("_", "")
        if _THOUSANDS.fullmatch(text):
            text = text.replace(",", "")
        try:
            return int(text)
        except ValueError:
            pass
        try:
            number = float(text)
        except ValueError:
            raise _fail(spec, f"Expected a number, got {raw.strip()[:40]!r}") from None
        if not math.isfinite(number):
            raise _fail(spec, "Expected a finite number")
        return number
    raise _fail(spec, f"Expected a number, got {type(raw).__name__}")


def _as_whole(spec: SettingSpec, value: int | float | Fraction, what: str = "a whole number") -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, Fraction):
        if value.denominator != 1:
            raise _fail(spec, f"Must be {what}")
        return int(value)
    if not value.is_integer():
        raise _fail(spec, f"Must be {what}")
    return int(value)


def _check_range(spec: SettingSpec, value: int | float) -> None:
    low, high = spec.min, spec.max
    unit = f" {spec.unit}" if spec.unit else ""
    if low is not None and high is not None and not low <= value <= high:
        raise _fail(spec, f"Must be between {_format_number(low)} and {_format_number(high)}{unit}")
    if low is not None and value < low:
        raise _fail(spec, f"Must be at least {_format_number(low)}{unit}")
    if high is not None and value > high:
        raise _fail(spec, f"Must be at most {_format_number(high)}{unit}")


# Durations: plain numbers are in the setting's own unit; suffixed text is converted ("90s", "15m", "2h").
_DURATION_SUFFIX_MS: Final[dict[str, int]] = {
    "ms": 1,
    "msec": 1,
    "millisecond": 1,
    "milliseconds": 1,
    "s": 1000,
    "sec": 1000,
    "secs": 1000,
    "second": 1000,
    "seconds": 1000,
    "m": 60_000,
    "min": 60_000,
    "mins": 60_000,
    "minute": 60_000,
    "minutes": 60_000,
    "h": 3_600_000,
    "hr": 3_600_000,
    "hrs": 3_600_000,
    "hour": 3_600_000,
    "hours": 3_600_000,
    "d": 86_400_000,
    "day": 86_400_000,
    "days": 86_400_000,
    "w": 604_800_000,
    "week": 604_800_000,
    "weeks": 604_800_000,
}
# One or more "<number><unit>" parts, optionally separated by spaces. Each piece of the pattern can only match one
# kind of character next to its neighbors (digits, then letters, then spaces before the next digits), so there is
# exactly one way to match any text and no backtracking blowup; the old form, with `\s*` at both ends of the
# repeated group, took exponential time on input such as "1s  1s  1s ... !" (security review L3).
_DURATION_TEXT = re.compile(r"\d+(?:\.\d+)?\s*[a-z]+(?:\s*\d+(?:\.\d+)?\s*[a-z]+)*")
_DURATION_PART = re.compile(r"(\d+(?:\.\d+)?)\s*([a-z]+)")
MAX_DURATION_TEXT = 64
"""Longest duration text accepted ("1h 30m 15s" is 10 characters); longer text is refused before any matching."""


def _duration_unit_ms(unit: str) -> int:
    """Milliseconds in one unit of a duration setting (seconds unless the spec says otherwise)."""
    return _DURATION_SUFFIX_MS.get(unit.strip().lower(), 1000)


def _duration_unit_name(unit: str) -> str:
    factor = _duration_unit_ms(unit)
    return {1: "milliseconds", 1000: "seconds", 60_000: "minutes", 3_600_000: "hours"}.get(factor, unit or "seconds")


def parse_duration(spec: SettingSpec, raw: Any) -> int:
    """A duration in the setting's unit: 90, "90", "90s", "15m", "2h", "1h30m", "500ms" (ms settings)."""
    unit_ms = _duration_unit_ms(spec.unit)
    hint = f"Enter a duration such as 90, 90s, 15m or 2h (a plain number means {_duration_unit_name(spec.unit)})"
    if isinstance(raw, str) and re.search(r"[A-Za-z]", raw):
        text = raw.strip().lower()
        if len(text) > MAX_DURATION_TEXT or not _DURATION_TEXT.fullmatch(text):
            raise _fail(spec, hint)
        total_ms = Fraction(0)
        for amount, suffix in _DURATION_PART.findall(text):
            factor = _DURATION_SUFFIX_MS.get(suffix)
            if factor is None:
                raise _fail(spec, f"Unknown time unit {suffix!r}. {hint}")
            total_ms += Fraction(amount) * factor
        return _as_whole(spec, total_ms / unit_ms, f"a whole number of {_duration_unit_name(spec.unit)}")
    try:
        number = _parse_number(spec, raw)
    except SettingValidationError:
        raise _fail(spec, hint) from None
    return _as_whole(spec, number, f"a whole number of {_duration_unit_name(spec.unit)}")


# Byte sizes: SI suffixes are powers of 1000, IEC suffixes (KiB, MiB, GiB) powers of 1024.
_BYTE_SUFFIX: Final[dict[str, int]] = {
    "b": 1,
    "byte": 1,
    "bytes": 1,
    "kb": 1000,
    "mb": 1000**2,
    "gb": 1000**3,
    "tb": 1000**4,
    "kib": 1024,
    "mib": 1024**2,
    "gib": 1024**3,
    "tib": 1024**4,
}
_BYTES_TEXT = re.compile(r"(\d+(?:\.\d+)?)\s*([a-z]+)")


def parse_bytes(spec: SettingSpec, raw: Any) -> int:
    """A size in the setting's unit (bytes unless it says otherwise): 65536, "64 KiB", "64 MiB", "1 GiB"."""
    unit_bytes = _BYTE_SUFFIX.get(spec.unit.strip().lower(), 1)
    hint = "Enter a size such as 65536, 64 KiB, 64 MiB or 1 GiB (KB, MB and GB are powers of 1000)"
    if isinstance(raw, str) and re.search(r"[A-Za-z]", raw):
        text = raw.strip().lower().replace(",", "").replace("_", "")
        found = _BYTES_TEXT.fullmatch(text)
        if found is None or found.group(2) not in _BYTE_SUFFIX:
            raise _fail(spec, hint)
        total = Fraction(found.group(1)) * _BYTE_SUFFIX[found.group(2)]
        return _as_whole(spec, total / unit_bytes, f"a whole number of {spec.unit or 'bytes'}")
    try:
        number = _parse_number(spec, raw)
    except SettingValidationError:
        raise _fail(spec, hint) from None
    return _as_whole(spec, number, f"a whole number of {spec.unit or 'bytes'}")


def _check_text(spec: SettingSpec, text: str, max_length: int, what: str = "Text") -> str:
    if EM_DASH in text or EN_DASH in text:
        raise _fail(spec, DASH_MESSAGE)
    if _CONTROL_CHARS.search(text):
        raise _fail(spec, f"{what} contains a control character")
    if len(text) > max_length:
        raise _fail(spec, f"{what} is longer than {max_length} characters")
    return text


# --- Validators per type ----------------------------------------------------------------------------------------------


def _validate_int(spec: SettingSpec, raw: Any) -> int:
    value = _as_whole(spec, _parse_number(spec, raw))
    _check_range(spec, value)
    return value


def _validate_float(spec: SettingSpec, raw: Any) -> float:
    value = float(_parse_number(spec, raw))
    _check_range(spec, value)
    return value


def _validate_bool(spec: SettingSpec, raw: Any) -> int:
    if isinstance(raw, bool):
        return int(raw)
    if isinstance(raw, int | float) and raw in (0, 1):
        return int(raw)
    if isinstance(raw, str):
        text = raw.strip().lower()
        if text in ("1", "true", "yes", "on"):
            return 1
        if text in ("0", "false", "no", "off"):
            return 0
    raise _fail(spec, "Expected 0 or 1 (off or on)")


def _validate_enum(spec: SettingSpec, raw: Any) -> str:
    allowed = spec.option_values()
    if isinstance(raw, str):
        text = raw.strip()
        if text in allowed:
            return text
        for option in allowed:
            if option.lower() == text.lower():
                return option
    raise _fail(spec, f"Must be one of: {', '.join(allowed)}")


def _validate_duration(spec: SettingSpec, raw: Any) -> int:
    value = parse_duration(spec, raw)
    _check_range(spec, value)
    return value


def _validate_bytes(spec: SettingSpec, raw: Any) -> int:
    value = parse_bytes(spec, raw)
    _check_range(spec, value)
    return value


def _validate_percent(spec: SettingSpec, raw: Any) -> int | float:
    text = raw.strip().removesuffix("%").strip() if isinstance(raw, str) else raw
    number = _parse_number(spec, text)
    low = 0.0 if spec.min is None else spec.min
    high = 100.0 if spec.max is None else spec.max
    unit = f" {spec.unit}" if spec.unit else " percent"
    if not low <= number <= high:
        raise _fail(spec, f"Must be between {_format_number(low)} and {_format_number(high)}{unit}")
    integral = float(number).is_integer()
    if integral and isinstance(spec.default, int) and not isinstance(spec.default, bool):
        return int(number)
    return float(number)


def _validate_string(spec: SettingSpec, raw: Any) -> str:
    if not isinstance(raw, str):
        raise _fail(spec, f"Expected text, got {type(raw).__name__}")
    text = raw.replace("\r\n", "\n").strip()
    return _check_text(spec, text, spec.max_length or DEFAULT_STRING_MAX_LENGTH)


def _list_items(spec: SettingSpec, raw: Any) -> list[Any]:
    """The raw items of a list value: a JSON list, or text separated by commas or new lines."""
    if isinstance(raw, str):
        items: list[Any] = [part.strip() for part in _LIST_SEPARATORS.split(raw)]
    elif isinstance(raw, list | tuple):
        items = [item.strip() if isinstance(item, str) else item for item in raw]
    else:
        raise _fail(spec, f"Expected a list, got {type(raw).__name__}")
    return [item for item in items if item != ""]


def _dedupe(items: Iterable[Any]) -> list[Any]:
    seen: set[Any] = set()
    result: list[Any] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _check_item_count(spec: SettingSpec, items: Sequence[Any]) -> None:
    limit = spec.max_length or DEFAULT_LIST_MAX_ITEMS
    if len(items) > limit:
        raise _fail(spec, f"Too many items ({len(items)}); the limit is {limit}")


def _validate_list_str(spec: SettingSpec, raw: Any) -> list[str]:
    item_limit = spec.item_max_length or DEFAULT_ITEM_MAX_LENGTH
    result: list[str] = []
    for item in _list_items(spec, raw):
        if not isinstance(item, str):
            raise _fail(spec, f"Every item must be text, got {type(item).__name__}")
        result.append(_check_text(spec, item, item_limit, what=f"Item {item[:40]!r}"))
    result = _dedupe(result)
    _check_item_count(spec, result)
    return result


def _validate_list_int(spec: SettingSpec, raw: Any) -> list[int]:
    result: list[int] = []
    for item in _list_items(spec, raw):
        try:
            value = _as_whole(spec, _parse_number(spec, item))
        except SettingValidationError:
            raise _fail(spec, f"Item {str(item)[:40]!r} is not a whole number") from None
        if spec.item_min is not None and value < spec.item_min:
            raise _fail(spec, f"Item {value} is below the minimum {_format_number(spec.item_min)}")
        if spec.item_max is not None and value > spec.item_max:
            raise _fail(spec, f"Item {value} is above the maximum {_format_number(spec.item_max)}")
        result.append(value)
    result = _dedupe(result)
    _check_item_count(spec, result)
    return result


def _validate_list_cidr(spec: SettingSpec, raw: Any) -> list[str]:
    item_limit = spec.item_max_length or 64
    result: list[str] = []
    for item in _list_items(spec, raw):
        if not isinstance(item, str) or len(item) > item_limit:
            raise _fail(spec, f"Item {str(item)[:40]!r} is not a valid IP address or CIDR range")
        try:
            # strict=False accepts "10.0.0.7/8" and normalizes it to the network address, "10.0.0.0/8";
            # a bare address becomes a single-address network (/32 or /128).
            network = ipaddress.ip_network(item, strict=False)
        except ValueError:
            raise _fail(spec, f"Item {item[:40]!r} is not a valid IP address or CIDR range") from None
        result.append(str(network))
    result = _dedupe(result)
    _check_item_count(spec, result)
    return result


_TYPE_VALIDATORS: Final[dict[SettingType, Callable[[SettingSpec, Any], Any]]] = {
    SettingType.INT: _validate_int,
    SettingType.FLOAT: _validate_float,
    SettingType.BOOL: _validate_bool,
    SettingType.ENUM: _validate_enum,
    SettingType.DURATION: _validate_duration,
    SettingType.BYTES: _validate_bytes,
    SettingType.PERCENT: _validate_percent,
    SettingType.STRING: _validate_string,
    SettingType.LIST_STR: _validate_list_str,
    SettingType.LIST_INT: _validate_list_int,
    SettingType.LIST_CIDR: _validate_list_cidr,
}


# --- Key-specific checks (formats a type alone cannot express) --------------------------------------------------------

_ROBLOX_HOST = re.compile(r"(?:[a-z0-9-]+\.)*roblox\.com")
_HOST_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST_NAME = re.compile(rf"{_HOST_LABEL}(?:\.{_HOST_LABEL})*")
_PRINTABLE_ASCII = re.compile(r"[\x20-\x7e]*")


def _check_timezone(spec: SettingSpec, value: Any) -> Any:
    name = str(value)
    if not name or name.startswith("/") or ".." in name:
        raise _fail(spec, "Enter an IANA time zone name such as America/New_York or UTC")
    try:
        zoneinfo.ZoneInfo(name)
    except (zoneinfo.ZoneInfoNotFoundError, ValueError):
        raise _fail(spec, f"Unknown time zone {name!r}; use an IANA name such as America/New_York") from None
    return value


def _check_country(spec: SettingSpec, value: Any) -> Any:
    if value and not re.fullmatch(r"[A-Za-z]{2}", str(value)):
        raise _fail(spec, "Enter a two letter ISO country code (for example us), or leave it empty for any country")
    return value


def _check_username_template(spec: SettingSpec, value: Any) -> Any:
    text = str(value)
    if not text:
        return value
    allowed = {"user", "session", "country"}
    names: set[str] = set()
    try:
        parsed = list(string.Formatter().parse(text))
    except ValueError:
        raise _fail(spec, "Unbalanced braces; placeholders look like {user}, {session} and {country}") from None
    for _literal, field_name, format_spec, conversion in parsed:
        if field_name is None:
            continue
        if field_name not in allowed or format_spec or conversion:
            raise _fail(spec, f"Unknown placeholder {{{field_name}}}; use {{user}}, {{session}} and {{country}}")
        names.add(field_name)
    if "session" not in names:
        raise _fail(spec, "The template must contain {session}, or be empty to turn sticky sessions off")
    if re.search(r"[\s:@/]", text):
        raise _fail(spec, "A proxy user name cannot contain spaces, ':', '@' or '/'")
    return value


def _check_probe_url(spec: SettingSpec, value: Any) -> Any:
    text = str(value)
    message = "Must be an https URL on a roblox.com host, such as https://users.roblox.com/v1/users/authenticated"
    parts = urlsplit(text if "://" in text else f"https://{text}")
    try:
        port = parts.port
    except ValueError:
        raise _fail(spec, message) from None
    host = (parts.hostname or "").lower()
    if (
        parts.scheme != "https"
        or parts.username is not None
        or parts.password is not None
        or port not in (None, 443)
        or not _ROBLOX_HOST.fullmatch(host)
        or re.search(r"\s", text)
    ):
        raise _fail(spec, message)
    return value


def _check_hosts(spec: SettingSpec, value: Any) -> Any:
    hosts: list[str] = []
    for item in value:
        host = str(item).lower().removesuffix(".")
        if not _HOST_NAME.fullmatch(host) or ("." in host and not host.endswith(".roblox.com")):
            raise _fail(spec, f"{str(item)[:60]!r} is not a roblox.com host name (for example games.roblox.com)")
        hosts.append(host)
    return _dedupe(hosts)


def _check_header_value(spec: SettingSpec, value: Any) -> Any:
    # Sent to Roblox as a header value: printable ASCII only, so no header injection through CR or LF.
    if not _PRINTABLE_ASCII.fullmatch(str(value)):
        raise _fail(spec, "A User-Agent may contain printable ASCII characters only")
    return value


def _check_site_links(spec: SettingSpec, value: Any) -> Any:
    lowered = str(value).lower()
    if "http://" in lowered:
        raise _fail(spec, "Links must use https://")
    if "javascript:" in lowered or "data:" in lowered:
        raise _fail(spec, "Links must be plain https:// links")
    return value


def _check_forever_or_30(spec: SettingSpec, value: Any) -> Any:
    if value != 0 and value < 30:
        raise _fail(spec, "Use 0 (keep forever) or at least 30 days")
    return value


_KEY_CHECKS: Final[tuple[tuple[Callable[[str], bool], Callable[[SettingSpec, Any], Any]], ...]] = (
    (lambda key: key == "ui_timezone", _check_timezone),
    (lambda key: key == "rotator_country", _check_country),
    (lambda key: key == "rotator_session_username_template", _check_username_template),
    (lambda key: key == "credential_probe_url", _check_probe_url),
    (lambda key: key == "allowed_roblox_hosts", _check_hosts),
    (lambda key: key.endswith("_user_agent"), _check_header_value),
    (lambda key: key.startswith("site_"), _check_site_links),
    (lambda key: key == "retention_day_days", _check_forever_or_30),
)


# --- Public validation API --------------------------------------------------------------------------------------------


def validate_spec_value(spec: SettingSpec, raw: Any) -> Any:
    """Validate and normalize one value for `spec`; return the canonical value or raise SettingValidationError.

    Canonical forms: bool -> 0 or 1; int, duration, bytes -> int; float -> float; percent -> int when whole and
    the default is an int, else float; enum and string -> str; lists -> list (trimmed, deduplicated, CIDRs
    normalized). Plain numbers for durations and sizes are in the setting's own unit.
    """
    validator = _TYPE_VALIDATORS.get(spec.type)
    if validator is None:
        raise _fail(spec, f"Unsupported setting type {spec.type!r}")
    value = validator(spec, raw)
    for applies, check in _KEY_CHECKS:
        if applies(spec.key):
            value = check(spec, value)
    return value


def validate_value(key: str, raw: Any, *, catalog: Mapping[str, SettingSpec] | None = None) -> Any:
    """Validate one value for setting `key` (DESIGN.md section 4); unknown keys are refused."""
    spec = (CATALOG if catalog is None else catalog).get(key)
    if spec is None:
        raise SettingValidationError(key, "Unknown setting")
    return validate_spec_value(spec, raw)


# --- Cross-field rules (plan 15.2, 5.2) -------------------------------------------------------------------------------


def min_max_pairs(keys: Iterable[str]) -> list[tuple[str, str]]:
    """Every (lower, upper) pair found by name: `<x>_min_<y>` with `<x>_max_<y>`, and spam ban lengths."""
    keyset = set(keys)
    pairs: list[tuple[str, str]] = []
    for key in sorted(keyset):
        parts = key.split("_")
        for index, part in enumerate(parts):
            if part != "min":
                continue
            other = "_".join([*parts[:index], "max", *parts[index + 1 :]])
            if other in keyset:
                pairs.append((key, other))
        if key.endswith("_ban_minutes"):
            other = key.removesuffix("_ban_minutes") + "_ban_max_minutes"
            if other in keyset:
                pairs.append((key, other))
    return pairs


def ban_length_rules(keys: Iterable[str]) -> list[tuple[str, tuple[str, str]]]:
    """(`<x>_action`, (`<x>_ban_minutes`, `<x>_ban_max_minutes`)) for every detector that can ban (plan E2):
    while the action is `ban`, both lengths must be at least 1 minute."""
    keyset = set(keys)
    rules: list[tuple[str, tuple[str, str]]] = []
    for key in sorted(keyset):
        if not key.endswith("_action"):
            continue
        prefix = key.removesuffix("_action")
        first, cap = f"{prefix}_ban_minutes", f"{prefix}_ban_max_minutes"
        if first in keyset and cap in keyset:
            rules.append((key, (first, cap)))
    return rules


# Ordered chains (each value at most the next) that the name rule above cannot find, including thresholds whose
# help text says one must stay at or below another (spec review 9).
CHAINS: Final[tuple[tuple[str, ...], ...]] = (
    ("aimd_min", "aimd_initial", "aimd_max"),
    ("cooldown_min_s", "cooldown_default_s", "cooldown_max_s"),
    ("backoff_base_ms", "backoff_cap_ms"),
    ("insight_up_latency_p95_ms", "insight_up_latency_p99_ms"),
    ("insight_cache_ttl_tune_identical_lower_pct", "insight_cache_ttl_tune_identical_raise_pct"),
)

# The deadline middleware answers 504 at request_deadline_s; inner budgets must leave it 2 s of room (plan 5.2).
DEADLINE_HEADROOM_S: Final = 2
REQUEST_DEADLINE_MAX_S: Final = 90  # nginx proxy_read_timeout (100 s) minus 10 s


def owner_deadline_s(values: Mapping[str, Any]) -> float | None:
    """Plan 5.2: queue_wait_interactive_ms + request_timeout x upstream_max_attempts + backoff_cap_ms, in seconds."""
    try:
        return (
            float(values["queue_wait_interactive_ms"]) / 1000
            + float(values["request_timeout"]) * float(values["upstream_max_attempts"])
            + float(values["backoff_cap_ms"]) / 1000
        )
    except (KeyError, TypeError, ValueError):
        return None


def _number(values: Mapping[str, Any], key: str) -> float | None:
    value = values.get(key)
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def _host_names(items: Any) -> set[str]:
    names: set[str] = set()
    for item in items if isinstance(items, list | tuple) else ():
        host = str(item).lower().removesuffix(".")
        names.add(host if host.endswith(".roblox.com") or host == "roblox.com" else f"{host}.roblox.com")
    return names


def cross_rule_descriptions(keys: Iterable[str] | None = None) -> list[str]:
    """Plain-English list of the cross-field rules that apply to `keys` (for docs and the editor)."""
    keyset = set(CATALOG if keys is None else keys)
    lines = [f"`{low}` <= `{high}`" for low, high in min_max_pairs(keyset)]
    for chain in CHAINS:
        if all(key in keyset for key in chain):
            lines.append(" <= ".join(f"`{key}`" for key in chain))
    for action_key, (first, cap) in ban_length_rules(keyset):
        lines.append(f"`{first}` >= 1 and `{cap}` >= 1 while `{action_key}` = ban")
    lines += [
        "`credential_probe_reserved_per_min` < `credential_bucket_per_min`",
        "`bot_score_legit_max` < `bot_score_abuse_min`",
        "owner deadline (`queue_wait_interactive_ms` + `request_timeout` x `upstream_max_attempts` + "
        f"`backoff_cap_ms`) <= `request_deadline_s` - {DEADLINE_HEADROOM_S} s",
        f"`tarpit_max_seconds` <= `request_deadline_s` - {DEADLINE_HEADROOM_S} s",
        f"`cache_coalesce_wait_ms` (when not 0) <= `request_deadline_s` - {DEADLINE_HEADROOM_S} s",
        f"`request_deadline_s` <= {REQUEST_DEADLINE_MAX_S}",
        "the host of `credential_probe_url` is in `allowed_roblox_hosts` when `strict_host_allowlist` = 1",
    ]
    return lines


def validate_cross(values: Mapping[str, Any], *, catalog: Mapping[str, SettingSpec] | None = None) -> list[CrossIssue]:
    """Check settings against each other (DESIGN.md section 4). Keys missing from `values` use their defaults."""
    specs = CATALOG if catalog is None else catalog
    merged: dict[str, Any] = {key: spec.default for key, spec in specs.items()}
    merged.update(values)
    issues: list[CrossIssue] = []

    for low_key, high_key in min_max_pairs(merged.keys() & specs.keys()):
        low, high = _number(merged, low_key), _number(merged, high_key)
        if low is not None and high is not None and low > high:
            issues.append(
                CrossIssue(
                    (low_key, high_key),
                    f"{low_key} ({_format_number(low)}) must not be greater than {high_key} ({_format_number(high)})",
                    "min_max",
                )
            )

    for chain in CHAINS:
        if not all(key in specs for key in chain):
            continue
        for left_key, right_key in itertools.pairwise(chain):
            left, right = _number(merged, left_key), _number(merged, right_key)
            if left is not None and right is not None and left > right:
                issues.append(
                    CrossIssue(
                        chain,
                        f"{' <= '.join(chain)} must hold, but {left_key} ({_format_number(left)}) is greater than "
                        f"{right_key} ({_format_number(right)})",
                        "chain",
                    )
                )

    reserved = _number(merged, "credential_probe_reserved_per_min")
    bucket = _number(merged, "credential_bucket_per_min")
    if reserved is not None and bucket is not None and reserved >= bucket:
        issues.append(
            CrossIssue(
                ("credential_probe_reserved_per_min", "credential_bucket_per_min"),
                f"credential_probe_reserved_per_min ({_format_number(reserved)}) must be below "
                f"credential_bucket_per_min ({_format_number(bucket)}), or allowlisted traffic gets no share",
                "credential_reserve",
            )
        )

    legit_max = _number(merged, "bot_score_legit_max")
    abuse_min = _number(merged, "bot_score_abuse_min")
    if legit_max is not None and abuse_min is not None and legit_max >= abuse_min:
        issues.append(
            CrossIssue(
                ("bot_score_legit_max", "bot_score_abuse_min"),
                f"bot_score_legit_max ({_format_number(legit_max)}) must be below bot_score_abuse_min "
                f"({_format_number(abuse_min)}), or one client counts as both legitimate and abusive",
                "bot_score_bands",
            )
        )

    deadline = _number(merged, "request_deadline_s")
    if deadline is not None:
        if deadline > REQUEST_DEADLINE_MAX_S:
            issues.append(
                CrossIssue(
                    ("request_deadline_s",),
                    f"request_deadline_s ({_format_number(deadline)}) must be at most {REQUEST_DEADLINE_MAX_S} "
                    "seconds (nginx proxy_read_timeout is 100 s and must stay 10 s above it)",
                    "deadline_max",
                )
            )
        budget = deadline - DEADLINE_HEADROOM_S
        owner_keys = ("queue_wait_interactive_ms", "request_timeout", "upstream_max_attempts", "backoff_cap_ms")
        owner = owner_deadline_s(merged) if all(key in specs for key in owner_keys) else None
        if owner is not None and owner > budget:
            issues.append(
                CrossIssue(
                    (*owner_keys, "request_deadline_s"),
                    f"The single-flight owner deadline ({_format_number(round(owner, 3))} s = "
                    "queue_wait_interactive_ms + request_timeout x upstream_max_attempts + backoff_cap_ms) must "
                    f"be at most request_deadline_s minus {DEADLINE_HEADROOM_S} s ({_format_number(budget)} s)",
                    "owner_deadline",
                )
            )
        tarpit_max = _number(merged, "tarpit_max_seconds") if "tarpit_max_seconds" in specs else None
        if tarpit_max is not None and tarpit_max > budget:
            issues.append(
                CrossIssue(
                    ("tarpit_max_seconds", "request_deadline_s"),
                    f"tarpit_max_seconds ({_format_number(tarpit_max)}) must be at most request_deadline_s minus "
                    f"{DEADLINE_HEADROOM_S} s ({_format_number(budget)} s), or holds end in a 504",
                    "tarpit_deadline",
                )
            )
        coalesce_ms = _number(merged, "cache_coalesce_wait_ms") if "cache_coalesce_wait_ms" in specs else None
        if coalesce_ms is not None and coalesce_ms > 0 and coalesce_ms / 1000 > budget:
            issues.append(
                CrossIssue(
                    ("cache_coalesce_wait_ms", "request_deadline_s"),
                    f"cache_coalesce_wait_ms ({_format_number(coalesce_ms)} ms) must be at most request_deadline_s "
                    f"minus {DEADLINE_HEADROOM_S} s ({_format_number(budget * 1000)} ms), or use 0 for the owner "
                    "deadline",
                    "coalesce_deadline",
                )
            )

    for action_key, ban_keys in ban_length_rules(specs.keys()):
        if merged.get(action_key) != "ban":
            continue
        for ban_key in ban_keys:
            minutes = _number(merged, ban_key)
            if minutes is not None and minutes < 1:
                issues.append(
                    CrossIssue(
                        (action_key, ban_key),
                        f"{ban_key} must be at least 1 minute while {action_key} is ban (0 means no ban length is "
                        "set, which is only valid for the other actions)",
                        "ban_length",
                    )
                )

    if {"credential_probe_url", "allowed_roblox_hosts", "strict_host_allowlist"} <= specs.keys():
        strict = _number(merged, "strict_host_allowlist")
        url = str(merged.get("credential_probe_url") or "")
        host = (urlsplit(url if "://" in url else f"https://{url}").hostname or "").lower()
        if strict == 1 and host and host not in _host_names(merged.get("allowed_roblox_hosts")):
            issues.append(
                CrossIssue(
                    ("credential_probe_url", "allowed_roblox_hosts", "strict_host_allowlist"),
                    f"credential_probe_url uses {host}, which is not in allowed_roblox_hosts",
                    "probe_host",
                )
            )
    return issues


# --- Style words (plan C5) --------------------------------------------------------------------------------------------

_STYLE_WORDS_PATH: Final = Path(__file__).resolve().parents[3] / "scripts" / "style_words.txt"
_SECTION_HEADER = re.compile(r"\[\s*([a-z_]+)\s*\]", re.IGNORECASE)
# Inflections a banned word may carry (the file's header lists them); a pattern ending in "e" also matches with
# the "e" dropped before the suffixes in _E_DROP_SUFFIXES (the "-ing" form of a word ending in "e" loses it).
_WORDS = re.compile(r"[A-Za-z]+")
_STYLE_SUFFIXES: Final = "s|es|d|ed|ing|ings|er|ers|able|al|ful|less|ation|ations|ly"
_E_DROP_SUFFIXES: Final = "ing|ings|er|ers|able|ation|ations"


def _style_regex(pattern: str) -> re.Pattern[str] | None:
    """Compile one banned-word pattern into a whole-word, inflection-aware, case-insensitive regex."""
    if pattern.startswith(r"\b") or pattern.endswith(r"\b"):
        source = rf"(?<![A-Za-z])(?:{pattern})(?![A-Za-z])"  # an explicit \b means "this exact word only"
    else:
        alternatives = [rf"(?:{pattern})(?:{_STYLE_SUFFIXES})?"]
        if pattern.endswith("e"):
            alternatives.append(rf"(?:{pattern[:-1]})(?:{_E_DROP_SUFFIXES})")
        source = rf"(?<![A-Za-z])(?:{'|'.join(alternatives)})(?![A-Za-z])"
    try:
        compiled = re.compile(source, re.IGNORECASE)
    except re.error:
        return None
    return None if compiled.fullmatch("") else compiled


def load_style_words(path: Path | None = None) -> tuple[list[StyleWord], list[re.Pattern[str]]]:
    """Banned spellings and exception patterns from `scripts/style_words.txt`; empty when the file is absent.

    Format (the file's own header, plan C5): a `[words]` section with one `<case-insensitive regex> <US
    replacement>` per line, and an `[exceptions]` section with one case-insensitive regex per line whose matches
    (URLs, identifiers) the word rules skip. Blank lines and `#` comments are ignored. Lines before any section
    header count as words. A pattern that does not compile, or that matches the empty string, is skipped rather
    than flagging every text.
    """
    source = _STYLE_WORDS_PATH if path is None else path
    try:
        lines = source.read_text(encoding="utf-8").splitlines()
    except OSError:
        return [], []
    words: list[StyleWord] = []
    exceptions: list[re.Pattern[str]] = []
    section = "words"
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        header = _SECTION_HEADER.fullmatch(stripped)
        if header:
            section = header.group(1).lower()
            continue
        if section == "exceptions":
            try:
                exception = re.compile(stripped, re.IGNORECASE)
            except re.error:
                continue
            if not exception.fullmatch(""):
                exceptions.append(exception)
            continue
        if section != "words":
            continue
        pattern, *rest = stripped.split(None, 1)
        compiled = _style_regex(pattern)
        if compiled is not None:
            words.append(StyleWord(pattern, rest[0].strip() if rest else "", compiled))
    return words, exceptions


def _spec_texts(spec: SettingSpec) -> list[tuple[str, str]]:
    """(field name, text) for every human-readable text of a spec, including string defaults."""
    texts = [
        ("label", spec.label),
        ("description", spec.description),
        ("unit", spec.unit),
        ("if_raised", spec.if_raised),
        ("if_lowered", spec.if_lowered),
        ("if_enabled", spec.if_enabled),
        ("if_disabled", spec.if_disabled),
        ("notes", spec.notes),
    ]
    for option in spec.options:
        texts.append((f"option {option.value} label", option.label))
        texts.append((f"option {option.value} description", option.description))
    for condition in spec.high_risk_if:
        texts.append(("high_risk_if why", condition.why))
    if isinstance(spec.default, str):
        texts.append(("default", spec.default))
    elif isinstance(spec.default, list | tuple):
        texts.extend(("default item", item) for item in spec.default if isinstance(item, str))
    return [(name, text) for name, text in texts if text]


# --- Self check -------------------------------------------------------------------------------------------------------


def is_known_anchor(anchor: str) -> bool:
    """Whether `anchor` belongs to the DESIGN.md section 9 vocabulary."""
    return anchor in NON_PAGE_HOMES or anchor in CARD_ANCHORS or bool(_RULE_ANCHOR.fullmatch(anchor))


def _check_spec_fields(spec: SettingSpec) -> list[str]:
    key = spec.key
    problems: list[str] = []
    if not isinstance(spec.group, Group):
        problems.append(f"{key}: group {spec.group!r} is not a Group")
    if not isinstance(spec.type, SettingType):
        problems.append(f"{key}: type {spec.type!r} is not a SettingType")
        return problems
    if not spec.label.strip():
        problems.append(f"{key}: label is empty")
    if not spec.description.strip():
        problems.append(f"{key}: description is empty")
    if spec.type in _NUMERIC_TYPES:
        if not spec.if_raised.strip() or not spec.if_lowered.strip():
            problems.append(f"{key}: a number setting needs both if_raised and if_lowered text")
        if spec.min is not None and spec.max is not None and spec.min > spec.max:
            problems.append(f"{key}: min {spec.min} is greater than max {spec.max}")
    if spec.type is SettingType.BOOL and (not spec.if_enabled.strip() or not spec.if_disabled.strip()):
        problems.append(f"{key}: a bool setting needs both if_enabled and if_disabled text")
    if spec.type is SettingType.ENUM:
        values = spec.option_values()
        if not values:
            problems.append(f"{key}: an enum setting needs options")
        if len(set(values)) != len(values):
            problems.append(f"{key}: option values repeat")
        for option in spec.options:
            if not option.value or not option.label.strip() or not option.description.strip():
                problems.append(f"{key}: option {option.value!r} needs a value, a label and a description")
    if spec.auto_apply_bounds is not None:
        low, high = spec.auto_apply_bounds
        if low > high:
            problems.append(f"{key}: auto_apply_bounds {spec.auto_apply_bounds} are reversed")
        if (spec.min is not None and low < spec.min) or (spec.max is not None and high > spec.max):
            problems.append(f"{key}: auto_apply_bounds {spec.auto_apply_bounds} leave the min/max range")
    if not isinstance(spec.risk, Risk):
        problems.append(f"{key}: risk {spec.risk!r} is not a Risk")
    for condition in spec.high_risk_if:
        if not condition.why.strip():
            problems.append(f"{key}: a high_risk_if condition has no explanation")
    if not spec.since:
        problems.append(f"{key}: since is empty")
    try:
        validate_spec_value(spec, spec.default)
    except SettingValidationError as exc:
        problems.append(f"{key}: default {spec.default!r} is invalid: {exc.message}")
    if not spec.pages:
        problems.append(f"{key}: pages is empty; every setting needs at least one dashboard anchor (plan 15.6)")
    for anchor in spec.pages:
        if not is_known_anchor(anchor):
            problems.append(f"{key}: page anchor {anchor!r} is not in the DESIGN.md section 9 vocabulary")
    return problems


def catalog_self_check(
    specs: Iterable[SettingSpec] | None = None,
    *,
    partial: bool | None = None,
    style_words: Sequence[StyleWord] | None = None,
    style_exceptions: Sequence[re.Pattern[str]] | None = None,
) -> list[str]:
    """Every problem with the catalog, as readable lines (empty when the catalog is sound).

    `partial` (default: `ROXY_CATALOG_PARTIAL`) relaxes only one check: a `related_settings` entry may name a key
    from a group module that is not written yet. `style_words` and `style_exceptions` default to the contents of
    `scripts/style_words.txt` (none when the file is absent, as in an installed package).
    """
    all_specs = list(ALL_SPECS if specs is None else specs)
    is_partial = partial_mode() if partial is None else partial
    if style_words is None:
        style_words, loaded_exceptions = load_style_words()
        style_exceptions = loaded_exceptions if style_exceptions is None else style_exceptions
    exception_patterns = list(style_exceptions or ())
    # The catalog is checked at every import, so the word check is done once per distinct word, not once per
    # text: each word of a text (after the exception patterns are blanked out) is looked up in `verdicts`, and
    # only a word never seen before is matched against the banned patterns (combined into one regex).
    any_word = re.compile("|".join(word.regex.pattern for word in style_words), re.IGNORECASE) if style_words else None
    verdicts: dict[str, StyleWord | None] = {}

    def banned(word_text: str) -> StyleWord | None:
        if word_text not in verdicts:
            hit = any_word is not None and any_word.fullmatch(word_text) is not None
            verdicts[word_text] = next((w for w in style_words if w.regex.fullmatch(word_text)), None) if hit else None
        return verdicts[word_text]

    problems: list[str] = []
    by_key: dict[str, SettingSpec] = {}
    for spec in all_specs:
        if not isinstance(spec, SettingSpec):
            problems.append(f"{spec!r} is not a SettingSpec")
            continue
        if not _KEY_FORMAT.fullmatch(spec.key):
            problems.append(f"{spec.key!r}: keys are lowercase snake_case, at most 80 characters")
        if spec.key in by_key:
            problems.append(f"{spec.key}: declared more than once")
            continue
        by_key[spec.key] = spec
        problems.extend(_check_spec_fields(spec))
        for field_name, text in _spec_texts(spec):
            if EM_DASH in text or EN_DASH in text:
                problems.append(f"{spec.key}: {field_name} contains an em or en dash (plan C5)")
            if any_word is None:
                continue
            checked = text
            for exception in exception_patterns:
                checked = exception.sub(" ", checked)
            for word_text in dict.fromkeys(_WORDS.findall(checked)):
                rule = banned(word_text)
                if rule is not None:
                    problems.append(
                        f"{spec.key}: {field_name} uses {word_text!r}; write {rule.replacement or 'US English'}"
                    )

    aliases: dict[str, str] = {}
    for spec in by_key.values():
        if spec.renamed_from:
            if spec.renamed_from in by_key:
                problems.append(f"{spec.key}: renamed_from {spec.renamed_from!r} is also a current key")
            if spec.renamed_from in aliases:
                owner = aliases[spec.renamed_from]
                problems.append(f"{spec.key}: renamed_from {spec.renamed_from!r} is already used by {owner}")
            aliases[spec.renamed_from] = spec.key
        if not is_partial:
            for related in spec.related_settings:
                if related not in by_key:
                    problems.append(f"{spec.key}: related setting {related!r} does not exist")

    defaults: dict[str, Any] = {}
    for key, spec in by_key.items():
        try:
            defaults[key] = validate_spec_value(spec, spec.default)
        except SettingValidationError:
            defaults[key] = spec.default
    for issue in validate_cross(defaults, catalog=by_key):
        problems.append(f"defaults break a cross-field rule: {issue.message}")
    return problems


# --- Helpers for the API, the editor, the docs and the LLM export -----------------------------------------------------


def by_group(catalog: Mapping[str, SettingSpec] | None = None) -> dict[Group, tuple[SettingSpec, ...]]:
    """Settings per group, in Settings page order (the Group enum order), declaration order inside a group."""
    specs = CATALOG if catalog is None else catalog
    grouped: dict[Group, list[SettingSpec]] = {group: [] for group in Group}
    for spec in specs.values():
        grouped.setdefault(spec.group, []).append(spec)
    return {group: tuple(items) for group, items in grouped.items() if items}


def search(
    query: str,
    *,
    group: Group | str | None = None,
    risk: Risk | str | None = None,
    catalog: Mapping[str, SettingSpec] | None = None,
) -> list[SettingSpec]:
    """Editor search (plan 15.2): every word must appear in the key, v1 key, label or description.

    Ranked: exact key, key prefix, key contains the query, key contains every word, label contains every word,
    then the rest (matched through the description or v1 key); ties keep catalog order.
    """
    specs = CATALOG if catalog is None else catalog
    needle = query.strip().lower()
    terms = needle.split()
    ranked: list[tuple[int, int, SettingSpec]] = []
    for position, spec in enumerate(specs.values()):
        if group is not None and spec.group != group:
            continue
        if risk is not None and spec.risk != risk:
            continue
        key = spec.key
        label = spec.label.lower()
        haystack = " ".join((key, spec.renamed_from or "", label, spec.description.lower()))
        if not all(term in haystack for term in terms):
            continue
        if not needle or key == needle:
            rank = 0
        elif key.startswith(needle):
            rank = 1
        elif needle in key:
            rank = 2
        elif all(term in key for term in terms):
            rank = 3
        elif all(term in label for term in terms):
            rank = 4
        else:
            rank = 5
        ranked.append((rank, position, spec))
    ranked.sort(key=lambda item: (item[0], item[1]))
    return [spec for _rank, _position, spec in ranked]


def resolve_key(name: str) -> str | None:
    """The current key for `name`, accepting v1 names (`renamed_from`); None when unknown."""
    if name in CATALOG:
        return name
    return ALIASES.get(name)


def _jsonable(value: Any) -> Any:
    """Tuples become lists so the result serializes the same way everywhere."""
    if isinstance(value, list | tuple):
        return [_jsonable(item) for item in value]
    return value


def spec_to_dict(spec: SettingSpec) -> dict[str, Any]:
    """Every field of a spec as JSON-ready data (sensitive defaults redacted)."""
    return {
        "key": spec.key,
        "group": spec.group.value,
        "group_label": GROUP_LABELS.get(spec.group, spec.group.value),
        "label": spec.label,
        "type": spec.type.value,
        "unit": spec.unit,
        "default": REDACTED if spec.sensitive else _jsonable(spec.default),
        "min": spec.min,
        "max": spec.max,
        "step": spec.step,
        "options": [
            {"value": option.value, "label": option.label, "description": option.description} for option in spec.options
        ],
        "description": spec.description,
        "if_raised": spec.if_raised,
        "if_lowered": spec.if_lowered,
        "if_enabled": spec.if_enabled,
        "if_disabled": spec.if_disabled,
        "risk": spec.risk.value,
        "high_risk_if": [
            {"op": condition.op.value, "value": _jsonable(condition.value), "why": condition.why}
            for condition in spec.high_risk_if
        ],
        "apply": spec.apply.value,
        "pages": list(spec.pages),
        "related_settings": list(spec.related_settings),
        "related_rules": list(spec.related_rules),
        "related_recommendations": list(spec.related_recommendations),
        "auto_apply_bounds": None if spec.auto_apply_bounds is None else list(spec.auto_apply_bounds),
        "sensitive": spec.sensitive,
        "since": spec.since,
        "renamed_from": spec.renamed_from,
        "v1_default": REDACTED if spec.sensitive and spec.v1_default is not None else _jsonable(spec.v1_default),
        "max_length": spec.max_length,
        "item_max_length": spec.item_max_length,
        "item_min": spec.item_min,
        "item_max": spec.item_max,
        "pending_owner_verification": spec.pending_owner_verification,
        "notes": spec.notes,
    }


def to_public_dict(
    values: Mapping[str, Any] | None = None,
    *,
    include_text: bool = True,
    catalog: Mapping[str, SettingSpec] | None = None,
) -> dict[str, Any]:
    """The catalog (and, when given, the current values) for the LLM export and the settings API.

    Sensitive settings show `[redacted]` for value and default; `changed` still says whether the value differs
    from the default, which reveals nothing about the value itself. `include_text=False` drops the long help
    texts for a compact listing.
    """
    specs = CATALOG if catalog is None else catalog
    groups: list[dict[str, Any]] = []
    for group, members in by_group(specs).items():
        entries: list[dict[str, Any]] = []
        for spec in members:
            entry = spec_to_dict(spec)
            if not include_text:
                for field_name in ("description", "if_raised", "if_lowered", "if_enabled", "if_disabled", "notes"):
                    entry.pop(field_name, None)
                entry["options"] = [option["value"] for option in entry["options"]]
            if values is not None:
                current = values.get(spec.key, spec.default)
                entry["changed"] = current != spec.default
                entry["value"] = REDACTED if spec.sensitive else _jsonable(current)
                entry["high_risk_reason"] = None if spec.sensitive else spec.is_high_risk_value(current)
            entries.append(entry)
        groups.append({"id": group.value, "label": GROUP_LABELS.get(group, group.value), "settings": entries})
    return {
        "schema": "roxy.settings_catalog/1",
        "catalog_version": catalog_version(specs),
        "setting_count": len(specs),
        "cross_field_rules": cross_rule_descriptions(specs.keys()),
        "groups": groups,
    }


def catalog_version(catalog: Mapping[str, SettingSpec] | None = None) -> str:
    """A short hash of every key, type and default: export files carry it so an import can spot drift."""
    specs = CATALOG if catalog is None else catalog
    material = [
        [spec.key, spec.type.value, REDACTED if spec.sensitive else _jsonable(spec.default)] for spec in specs.values()
    ]
    digest = hashlib.sha256(json.dumps(material, sort_keys=True, default=str).encode("utf-8")).hexdigest()
    return digest[:16]


def defaults() -> dict[str, Any]:
    """Every key with its canonical default value."""
    return dict(DEFAULTS)


# --- Assembly (runs once, at import) ----------------------------------------------------------------------------------

PARTIAL: Final[bool] = partial_mode()
_missing: list[MissingModule] = []
_group_specs, _group_missing = load_group_specs(PARTIAL)
_missing.extend(_group_missing)
INSIGHT_RULES: Final[dict[str, InsightRuleSpec]] = load_insight_rules(PARTIAL, _missing)
PARAM_DEFINITIONS: Final[dict[str, str]] = load_param_definitions(PARTIAL, [])  # its module is counted above
MISSING_MODULES: Final[tuple[MissingModule, ...]] = tuple(_missing)

# Every declared spec in order, duplicates included (the self check reports them); then the catalog itself,
# first declaration winning. Treat CATALOG as read-only: it is shared by every request in the process.
_sourced: list[tuple[str, SettingSpec]] = [
    *_group_specs,
    *((INSIGHT_PARAMS_MODULE, spec) for spec in insight_rule_settings(INSIGHT_RULES, PARAM_DEFINITIONS)),
]
ALL_SPECS: Final[tuple[SettingSpec, ...]] = tuple(spec for _origin, spec in _sourced)
SPEC_ORIGINS: Final[dict[str, str]] = {spec.key: origin for origin, spec in reversed(_sourced)}
CATALOG: Final[dict[str, SettingSpec]] = {}
for _spec in ALL_SPECS:
    CATALOG.setdefault(_spec.key, _spec)
GROUPED: Final[dict[Group, tuple[SettingSpec, ...]]] = by_group(CATALOG)
ALIASES: Final[dict[str, str]] = {spec.renamed_from: key for key, spec in CATALOG.items() if spec.renamed_from}

SELF_CHECK_PROBLEMS: Final[tuple[str, ...]] = tuple(catalog_self_check(ALL_SPECS, partial=PARTIAL))
if SELF_CHECK_PROBLEMS and not PARTIAL:
    raise CatalogError(SELF_CHECK_PROBLEMS)
if SELF_CHECK_PROBLEMS:
    warnings.warn(str(CatalogError(SELF_CHECK_PROBLEMS)), RuntimeWarning, stacklevel=1)


def _canonical_default(spec: SettingSpec) -> Any:
    try:
        return validate_spec_value(spec, spec.default)
    except SettingValidationError:  # only reachable in partial mode, where problems are reported, not raised
        return spec.default


DEFAULTS: Final[dict[str, Any]] = {key: _canonical_default(spec) for key, spec in CATALOG.items()}
CATALOG_VERSION: Final[str] = catalog_version(CATALOG)

__all__ = [
    "ALIASES",
    "ALL_SPECS",
    "CARD_ANCHORS",
    "CATALOG",
    "CATALOG_VERSION",
    "CHAINS",
    "DEFAULTS",
    "GROUPED",
    "GROUP_MODULES",
    "INSIGHT_RULES",
    "MISSING_MODULES",
    "NON_PAGE_HOMES",
    "PAGES",
    "PARTIAL",
    "PARTIAL_ENV",
    "REDACTED",
    "SELF_CHECK_PROBLEMS",
    "SEVERITY_OPTIONS",
    "SPEC_ORIGINS",
    "CatalogError",
    "CrossIssue",
    "MissingModule",
    "SettingValidationError",
    "StyleWord",
    "by_group",
    "catalog_self_check",
    "catalog_version",
    "cross_rule_descriptions",
    "defaults",
    "insight_rule_settings",
    "is_known_anchor",
    "load_group_specs",
    "load_insight_rules",
    "load_style_words",
    "min_max_pairs",
    "owner_deadline_s",
    "parse_bytes",
    "parse_duration",
    "partial_mode",
    "resolve_key",
    "search",
    "spec_to_dict",
    "to_public_dict",
    "validate_cross",
    "validate_spec_value",
    "validate_value",
]
