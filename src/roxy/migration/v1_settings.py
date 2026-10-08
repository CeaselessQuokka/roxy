"""The 71 v1 runtime settings and the plan 18.3 import rule for each: what to import, map, clamp or never import.

What this is
    `V1_SETTINGS`, the v1 settings table (default, range, and the plan 18.3 rule with the v2 key), and
    `plan_settings(runtime)`, a pure function that turns the v1 `Settings` map into one `SettingDecision` per key:
    import (with the value already clamped into the v2 range) or skip, each with the notes the report shows.

Why it exists
    v1 stored every setting's value, untouched defaults included, so a blind import would turn every v1 default
    into an explicit v2 override and silently undo the new v2 defaults. Plan 18.3 therefore imports a value only
    when the owner changed it in v1, never imports keys whose meaning changed (they are reported next to the v2
    default instead), maps renamed keys (`rotate_cooldown` to `rotator_cooldown_s`, `max_live_requests` to
    `live_tail_buffer`), imports some caps only when they are larger than the v2 default, and clamps into the v2
    range with a report line. The catalog's `renamed_from` aliases cannot be used for this: several of them name
    keys whose meaning changed, so this module keeps its own explicit table.

How it works
    For each v1 key: read the stored value the way v1 restored it (`int()`, then clamp into the v1 range; an
    unreadable value is skipped, as v1 skipped it), compare it with the v1 default, apply the rule, clamp into the
    v2 catalog range, then validate with `catalog.validate_spec_value`. Nothing here touches a database; the
    runner applies the decisions through the settings service (source `import`), which adds history and audit
    rows and bumps `config_version`.

What to read next
    `roxy/migration/runner.py` (`_import_settings`), `roxy/config/catalog.py`, and REMAKE_PLAN.md 18.3.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

from roxy.config import catalog
from roxy.config.catalog import SettingValidationError


class Rule(StrEnum):
    """Plan 18.3 import rules."""

    IF_CHANGED = "if_changed"  # import when different from the v1 default
    IF_LARGER = "if_changed_and_larger"  # ... and only when larger than the v2 default
    NEVER = "never"  # meaning changed: report v1 value and v2 default side by side
    CACHE_POST = "cache_post"  # 1 maps to `all` with a high-risk warning; 0 is not imported


@dataclass(frozen=True, slots=True)
class V1Setting:
    """One v1 setting (app/runtime.py `_settings`) and how plan 18.3 treats it."""

    default: int
    minimum: int
    maximum: int
    rule: Rule
    v2_key: str | None = None  # None means the same key
    why: str = ""

    def target(self, key: str) -> str:
        return self.v2_key or key


_NEVER_RECORDS = "It bounded an in-memory ring in v1; v2 keeps these records on disk with a much larger cap."

V1_SETTINGS: Final[dict[str, V1Setting]] = {
    "allowed_requests_per_minute": V1Setting(10, 1, 100000, Rule.IF_CHANGED),
    "throttle_reset_duration": V1Setting(50, 1, 86400, Rule.IF_CHANGED),
    "stale_ip_duration": V1Setting(60, 1, 86400, Rule.IF_CHANGED),
    "max_retries_per_request": V1Setting(
        3, 0, 20, Rule.NEVER, "upstream_max_attempts", "It was never read in v1, so it never did anything."
    ),
    "two_fa_expiration": V1Setting(
        60,
        5,
        600,
        Rule.NEVER,
        None,
        "The factor it governs is off by default in v2, and the v1 value was tuned for the mandatory email code.",
    ),
    "challenge_expiration": V1Setting(
        60, 5, 600, Rule.NEVER, None, "Its meaning changed: it is now the login transaction lifetime."
    ),
    "token_expiration_cooldown": V1Setting(
        15,
        1,
        86400,
        Rule.NEVER,
        "credential_cooldown_default_s",
        "Its meaning changed: v2 uses one fleet-wide credential cooldown that honors Retry-After.",
    ),
    "request_timeout": V1Setting(15, 1, 120, Rule.IF_CHANGED),
    "email_cooldown": V1Setting(600, 0, 86400, Rule.IF_CHANGED),
    "error_email_cooldown": V1Setting(300, 0, 86400, Rule.IF_CHANGED),
    "autosave_interval": V1Setting(
        30,
        1,
        3600,
        Rule.NEVER,
        "metrics_flush_interval_ms",
        "Statistics are no longer saved to a JSON file; the metrics batch writer flushes every 2 seconds.",
    ),
    "max_live_requests": V1Setting(150, 0, 1000, Rule.IF_CHANGED, "live_tail_buffer"),
    "max_exploit_records": V1Setting(20, 1, 1000, Rule.NEVER, None, _NEVER_RECORDS),
    "max_login_records": V1Setting(20, 1, 1000, Rule.NEVER, None, _NEVER_RECORDS),
    "max_crawl_records": V1Setting(20, 1, 5000, Rule.NEVER, None, _NEVER_RECORDS),
    "max_throttle_records": V1Setting(20, 1, 5000, Rule.NEVER, None, _NEVER_RECORDS),
    "max_endpoint_records": V1Setting(200, 1, 5000, Rule.IF_LARGER),
    "max_header_name_records": V1Setting(300, 1, 5000, Rule.IF_LARGER),
    "max_header_value_records": V1Setting(200, 1, 5000, Rule.IF_LARGER),
    "max_user_agent_records": V1Setting(1000, 1, 20000, Rule.IF_LARGER),
    "max_error_records": V1Setting(1000, 1, 20000, Rule.IF_LARGER),
    "endpoint_recent_requests": V1Setting(5, 0, 25, Rule.IF_LARGER),
    "activity_tracking": V1Setting(1, 0, 1, Rule.IF_CHANGED),
    "max_ip_activity_records": V1Setting(400, 1, 20000, Rule.IF_LARGER),
    "max_caller_records": V1Setting(200, 1, 20000, Rule.IF_LARGER),
    "capture_enabled": V1Setting(1, 0, 1, Rule.IF_CHANGED),
    "capture_max_records": V1Setting(250, 0, 1000, Rule.IF_LARGER),
    "capture_max_bytes": V1Setting(4194304, 0, 67108864, Rule.IF_LARGER),
    "capture_max_body": V1Setting(16384, 0, 524288, Rule.IF_CHANGED),
    "capture_ttl_seconds": V1Setting(900, 0, 86400, Rule.IF_CHANGED),
    "throttle_escalation_enabled": V1Setting(1, 0, 1, Rule.IF_CHANGED),
    "throttle_strike_decay_seconds": V1Setting(1800, 0, 604800, Rule.IF_CHANGED),
    "user_agent_rules_enabled": V1Setting(1, 0, 1, Rule.IF_CHANGED),
    "cache_enabled": V1Setting(1, 0, 1, Rule.IF_CHANGED),
    "cache_ttl_seconds": V1Setting(60, 0, 86400, Rule.IF_CHANGED),
    "cache_error_ttl_seconds": V1Setting(0, 0, 3600, Rule.IF_CHANGED),
    "cache_disk_enabled": V1Setting(1, 0, 1, Rule.IF_CHANGED),
    "cache_max_entries": V1Setting(3000, 0, 100000, Rule.IF_LARGER),
    "cache_max_bytes": V1Setting(33554432, 0, 536870912, Rule.IF_LARGER),
    "cache_max_body": V1Setting(262144, 0, 4194304, Rule.IF_LARGER),
    "cache_memory_entries": V1Setting(400, 0, 20000, Rule.IF_LARGER),
    "cache_memory_bytes": V1Setting(8388608, 0, 134217728, Rule.IF_LARGER),
    "cache_stale_seconds": V1Setting(600, 0, 86400, Rule.IF_CHANGED),
    "cache_serve_throttled": V1Setting(0, 0, 1, Rule.IF_CHANGED),
    "cache_coalesce": V1Setting(1, 0, 1, Rule.IF_CHANGED),
    "cache_coalesce_wait_ms": V1Setting(
        1500,
        0,
        10000,
        Rule.NEVER,
        None,
        "Its meaning changed: v2 followers wait up to the owner deadline (0) instead of giving up early.",
    ),
    "cache_post_requests": V1Setting(0, 0, 1, Rule.CACHE_POST),
    "cache_respect_no_cache": V1Setting(0, 0, 1, Rule.IF_CHANGED),
    "auto_ignore_high_cardinality": V1Setting(1, 0, 1, Rule.IF_CHANGED),
    "diagnostics_flush_interval": V1Setting(
        10,
        0,
        3600,
        Rule.NEVER,
        "metrics_flush_interval_ms",
        "The dashboard no longer merges per-worker statistics; the metrics batch writer replaced the merge.",
    ),
    "token_budget_requests": V1Setting(
        95,
        1,
        10000,
        Rule.NEVER,
        "credential_bucket_per_min",
        "A burstable count per window became a paced rate per minute.",
    ),
    "token_budget_window": V1Setting(
        65, 1, 3600, Rule.NEVER, "credential_bucket_burst", "A window length became a burst size."
    ),
    "global_throttle_limit": V1Setting(1, 1, 100000, Rule.IF_CHANGED),
    "global_throttle_period": V1Setting(60, 1, 86400, Rule.IF_CHANGED),
    "token_weight": V1Setting(
        75,
        0,
        1000,
        Rule.NEVER,
        "direct_weight",
        "75 was the credential's share of traffic; direct_weight is anonymous traffic (owner decision D1).",
    ),
    "rotate_weight": V1Setting(
        25,
        0,
        1000,
        Rule.NEVER,
        "rotator_weight",
        "Decision D13 chose 0 on purpose: the rotator is used only when the direct path cannot serve.",
    ),
    "token_danger_zone": V1Setting(
        60,
        0,
        100000,
        Rule.NEVER,
        "direct_shift_threshold_pct",
        "A count of credential uses became a bucket fill percentage.",
    ),
    "rotate_enabled": V1Setting(1, 0, 1, Rule.IF_CHANGED, "rotator_enabled"),
    "rotate_cooldown": V1Setting(60, 0, 86400, Rule.IF_CHANGED, "rotator_cooldown_s"),
    "rotate_max_failures": V1Setting(3, 1, 100, Rule.IF_CHANGED, "rotator_max_failures"),
    "tarpit_enabled": V1Setting(1, 0, 1, Rule.IF_CHANGED),
    "tarpit_min_seconds": V1Setting(8, 0, 55, Rule.IF_CHANGED),
    "tarpit_max_seconds": V1Setting(20, 1, 55, Rule.IF_CHANGED),
    "tarpit_max_concurrent": V1Setting(
        6,
        0,
        64,
        Rule.NEVER,
        None,
        "The v1 cap counted gthread request slots; an async hold costs almost nothing (v2 default 50).",
    ),
    "tarpit_on_header_rule": V1Setting(1, 0, 1, Rule.IF_CHANGED),
    "tarpit_on_probe": V1Setting(1, 0, 1, Rule.IF_CHANGED),
    "tarpit_on_throttle": V1Setting(0, 0, 1, Rule.IF_CHANGED),
    "tarpit_on_throttle_all": V1Setting(0, 0, 1, Rule.IF_CHANGED),
    "tarpit_on_endpoint_rule": V1Setting(0, 0, 1, Rule.IF_CHANGED),
    "tarpit_on_blocked_endpoint": V1Setting(0, 0, 1, Rule.IF_CHANGED),
    "tarpit_on_auth_attempt": V1Setting(0, 0, 1, Rule.IF_CHANGED),
}
"""Every v1 setting (71). Defaults and ranges are app/runtime.py lines 155-298 with DEBUG off."""


class Action(StrEnum):
    """What the plan says to do with one key, before any database is consulted."""

    IMPORT = "import"
    SKIP_DEFAULT = "skip_default"
    SKIP_ABSENT = "skip_absent"
    SKIP_NEVER = "skip_never"
    SKIP_NOT_LARGER = "skip_not_larger"
    SKIP_UNREADABLE = "skip_unreadable"
    SKIP_UNKNOWN = "skip_unknown"
    SKIP_INVALID = "skip_invalid"


@dataclass(slots=True)
class SettingDecision:
    """The plan for one v1 key. `value` is the canonical v2 value to import (only for Action.IMPORT)."""

    v1_key: str
    v2_key: str | None
    action: Action
    v1_raw: Any = None
    v1_value: int | None = None
    v1_default: int | None = None
    v2_default: Any = None
    value: Any = None
    saved_at: int | None = None
    notes: list[str] = field(default_factory=list)
    warning: str | None = None  # a report warning for when the value ends up in v2 (plan 18.3 "high-risk")

    def as_report(self, status: str) -> dict[str, Any]:
        return {
            "v1_key": self.v1_key,
            "v2_key": self.v2_key,
            "v1_value": self.v1_value if self.v1_value is not None else _short(self.v1_raw),
            "v1_default": self.v1_default,
            "v2_default": self.v2_default,
            "value": self.value,
            "plan": self.action.value,
            "status": status,
            "saved_in_v1_at": self.saved_at,
            "notes": list(self.notes),
        }


def _short(value: Any) -> Any:
    text = repr(value)
    return text if len(text) <= 60 else text[:57] + "..."


def v1_int(raw: Any) -> int | None:
    """v1 `_restore_from`: `int(value)` (True is 1, "25" is 25, 2.9 is 2); None when v1 skipped the value."""
    if isinstance(raw, float) and not math.isfinite(raw):
        return None
    try:
        return int(raw)
    except (TypeError, ValueError, OverflowError):
        return None


def _v2_clamp(spec_key: str, value: Any, notes: list[str]) -> Any:
    """Clamp a number into the v2 catalog range, with a report note (plan 18.3)."""
    spec = catalog.CATALOG[spec_key]
    if not isinstance(value, int | float) or isinstance(value, bool):
        return value
    clamped = value
    if spec.min is not None and clamped < spec.min:
        clamped = type(value)(spec.min)
    if spec.max is not None and clamped > spec.max:
        clamped = type(value)(spec.max)
    if clamped != value:
        low = "none" if spec.min is None else f"{spec.min:g}"
        high = "none" if spec.max is None else f"{spec.max:g}"
        notes.append(f"clamped from {value} to {clamped} (the v2 range is {low} to {high})")
    return clamped


def plan_setting(key: str, raw: Any, *, present: bool, saved_at: Any = None) -> SettingDecision:
    """The plan 18.3 decision for one v1 key (see the module docstring)."""
    meta = V1_SETTINGS.get(key)
    if meta is None:
        return SettingDecision(
            key, None, Action.SKIP_UNKNOWN, v1_raw=raw, notes=["not a v1 setting; ignored (v1 ignored it too)"]
        )
    v2_key = meta.target(key)
    spec = catalog.CATALOG.get(v2_key)
    decision = SettingDecision(
        key,
        v2_key,
        Action.SKIP_DEFAULT,
        v1_raw=raw,
        v1_default=meta.default,
        v2_default=catalog.DEFAULTS.get(v2_key) if spec else None,
    )
    if v2_key != key:
        decision.notes.append(f"renamed to {v2_key}")
    saved = v1_int(saved_at)
    if saved and saved > 0:
        decision.saved_at = saved
    if not present:
        decision.action = Action.SKIP_ABSENT
        decision.v1_value = meta.default
        return decision
    value = v1_int(raw)
    if value is None:
        decision.action = Action.SKIP_UNREADABLE
        decision.notes.append("the stored value is not a whole number; v1 skipped it too and used its default")
        return decision
    if not meta.minimum <= value <= meta.maximum:
        clamped = max(meta.minimum, min(meta.maximum, value))
        decision.notes.append(
            f"stored value {value} is outside the v1 range {meta.minimum} to {meta.maximum}; v1 used {clamped}"
        )
        value = clamped
    decision.v1_value = value
    changed = value != meta.default
    if meta.rule is Rule.NEVER:
        decision.action = Action.SKIP_NEVER
        decision.notes.append(meta.why)
        if changed:
            decision.notes.append("you changed this in v1; decide by hand whether the v2 default suits you")
        return decision
    if not changed:
        decision.action = Action.SKIP_DEFAULT
        return decision
    if spec is None:  # pragma: no cover - the catalog test guarantees every target exists
        decision.action = Action.SKIP_UNKNOWN
        decision.notes.append(f"{v2_key} is not in the v2 catalog")
        return decision
    candidate: Any = value
    if meta.rule is Rule.CACHE_POST:
        if value != 1:
            decision.action = Action.SKIP_DEFAULT
            return decision
        candidate = "all"
        decision.notes.append(
            "HIGH RISK: v1 cached every POST; mapped to 'all'. Consider 'allowlist', which caches only the "
            "read-only lookups v2 knows are safe"
        )
        decision.warning = (
            "HIGH RISK: cache_post_requests is 'all' because v1 cached every POST; a POST that changes something "
            "can then be answered from the cache. Consider 'allowlist' (only the read-only lookups v2 knows are safe)"
        )
    elif meta.rule is Rule.IF_LARGER:
        v2_default = catalog.DEFAULTS[v2_key]
        if not value > v2_default:
            decision.action = Action.SKIP_NOT_LARGER
            decision.notes.append(
                f"not imported: v1 caps were sized for in-memory stores, and {value} is not larger than the v2 "
                f"default {v2_default}"
            )
            return decision
    candidate = _v2_clamp(v2_key, candidate, decision.notes)
    try:
        decision.value = catalog.validate_spec_value(spec, candidate)
    except SettingValidationError as exc:
        decision.action = Action.SKIP_INVALID
        decision.notes.append(f"v2 refused the value: {exc.message}")
        return decision
    decision.action = Action.IMPORT
    return decision


def plan_settings(runtime: dict[str, Any]) -> list[SettingDecision]:
    """One decision per v1 setting (in v1 table order), plus one per unknown key found in the file."""
    stored = runtime.get("Settings")
    stored_values: dict[str, Any] = stored if isinstance(stored, dict) else {}
    updated = runtime.get("SettingsUpdated")
    stored_updated: dict[str, Any] = updated if isinstance(updated, dict) else {}
    decisions = [
        plan_setting(key, stored_values.get(key), present=key in stored_values, saved_at=stored_updated.get(key))
        for key in V1_SETTINGS
    ]
    decisions += [
        plan_setting(str(key), value, present=True) for key, value in stored_values.items() if key not in V1_SETTINGS
    ]
    return decisions


__all__ = ["V1_SETTINGS", "Action", "Rule", "SettingDecision", "V1Setting", "plan_setting", "plan_settings", "v1_int"]
