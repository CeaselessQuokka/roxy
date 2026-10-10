"""Settings API (`/admin/api/v1/settings`): the full catalog editor of plan 15.2, as JSON.

What this is
    The routes behind the Settings page and every inline setting control (plan 14.1, 15.2, 15.6):
      * `GET /settings`: the catalog with current values, grouped (plan 15.1 groups), with search (key, v1 key,
        label, description) and filters: `group`, `risk`, `changed` ("changed from default") and
        `has_recommendation` ("has open recommendation"). Each entry carries its metadata, value, default, risk,
        "what happens if" texts, related links, the last change (who, when, why) and its open recommendations.
      * `GET /settings/{key}`: one setting with its recent history and its related settings.
      * `POST /settings/preview`: the server-side diff of a batch before it is saved: old and new values, the
        consequence text of each change, risk and reason requirements, restart notes and the cross-field rules a
        batch would break. Nothing is written.
      * `PATCH /settings`: save only the dirty keys of a batch with one reason (plan 15.2 "Review changes");
        `PUT /settings/{key}`: one key (inline editors); `POST /settings/{key}/reset`: back to the default
        (parity row 124).
      * `GET /settings/history` and `GET /settings/{key}/history`: history, global and per key, as tables (paging,
        sorting, search, filters, `format=csv|json`); `POST /settings/history/{id}/revert`: one-click revert.
      * `GET /settings/export`, `POST /settings/import/preview`, `POST /settings/import`: overrides as a JSON
        document with the catalog version; an import shows its diff first and applies atomically with a reason.

Why it exists
    Plan 15.2 and DESIGN.md section 13. The editor sends only the keys an admin changed (v1 posted every setting
    on every save), every change is validated against the catalog and the cross-field rules, and a high-risk
    change needs a reason and an explicit confirmation (plan 15.1 `risk`).

How it works
    Every write goes through `config/settings_service.py SettingsService`, which validates, writes the settings,
    history and audit rows and bumps `config_version` in ONE control.db transaction, so every worker reloads within
    a second; its refusals become 422 errors with one message per key (`common.run_mutation`). Before calling it,
    the API refuses a batch that holds a high-risk change without `confirm_high_risk: true` (422
    `confirmation_required`) or without a reason (422 on `reason`); the service checks the reason again. A change
    of an `admin_security` or `credential` setting, a sensitive one or `export_include_ips` (`needs_fresh_mfa`)
    needs a second factor entered within `admin_reauth_window_s` (403 `reauth_required`, plan 9.6), in every
    writer here (PATCH, PUT, reset, revert, import); previews name those keys (`fresh_mfa_keys`). The quick checks
    read this worker's snapshot; the same rules run again inside the write transaction on the keys it is about to
    write (`WriteRules`, a `SettingsService` guard), so a snapshot that lags behind another worker's change never
    lets a stale session or an arming batch through (finding secfix-1). Reads come
    from this worker's settings snapshot (values), `config/read_settings.py` (history) and
    `metrics/read_recommended_settings.py` (open recommendations). Sensitive settings (`spec.sensitive`) are shown
    as `[redacted]` everywhere, and their history holds only `{fingerprint, masked}` (plan 6.2).

What to read next
    `roxy/config/settings_service.py`, `roxy/config/catalog.py`, `roxy/admin/api/common.py`.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Annotated, Any, Final

from fastapi import Depends, Path, Query, Request
from pydantic import Field
from starlette.responses import Response

from roxy.admin.api import common
from roxy.admin.api.common import (
    AdminSession,
    ApiBody,
    Column,
    CsrfChecked,
    ExportFormatDep,
    TableQuery,
    TableSpec,
    actor_for,
    request_id_of,
    run_mutation,
    table_params,
)
from roxy.admin.auth.deps import AdminPrincipal, ReauthRequired
from roxy.admin.auth.sessions import FULL_MFA_LEVELS
from roxy.config import audit, catalog, read_settings
from roxy.config.constants import MAX_REASON_LENGTH
from roxy.config.runtime import same_value, thaw
from roxy.config.settings_service import RESET, PendingWrite, SettingsService, UpdateResult, service_for
from roxy.config.spec import GROUP_LABELS, Apply, Group, Risk, SettingSpec, SettingType
from roxy.deps import get_ctx
from roxy.metrics.read_recommended_settings import open_setting_recommendations

router = common.area_router("settings")

KEY_PATTERN: Final = r"^[a-z][a-z0-9_]{0,79}$"
MAX_CHANGES: Final = 1000
"""Keys one batch, preview or import may name (plan P9; the catalog has about 500)."""

MAX_IMPORT_DOCUMENT_KEYS: Final = 16
"""Top-level fields an import document may have (`schema`, `catalog_version`, `overrides`, ...)."""

RECENT_HISTORY: Final = 10
NUMERIC_TYPES: Final = frozenset(
    {SettingType.INT, SettingType.FLOAT, SettingType.DURATION, SettingType.BYTES, SettingType.PERCENT}
)
HIGH_RISK_SETTING: Final = "This is a high-risk setting."
CONFIRM_MESSAGE: Final = "This is a high-risk change; confirm it with confirm_high_risk."
REASON_MESSAGE: Final = "Give a reason: this batch holds a high-risk change and the reason goes in the audit log."
EXPORT_TARGET: Final = "settings:overrides"
ARM_ONLY_SETTINGS: Final[dict[str, str]] = {"spam_dry_run": "/admin/api/v1/protection/spam/arm"}
"""Settings this editor may never switch off, with the route that does it instead. `spam_dry_run` 0 arms the spam
detectors (real bans), which plan 10.3 allows only after the collateral preview: `POST /protection/spam/arm` with
the preview's token. Turning the dry run back on (1), resetting it to its default (1) and leaving it as it is are
always allowed."""
ARM_ONLY_MESSAGE: Final = "Arm the spam detectors from the Protection page: it first shows who would have been banned."
FRESH_MFA_GROUPS: Final[frozenset[Group]] = frozenset({Group.ADMIN_SECURITY, Group.CREDENTIAL})
"""Settings groups whose every change needs a fresh second factor (plan 9.6): `admin_security` decides who may sign
in and what a session may do (the re-auth window itself, session lifetimes, lockouts, the admin network allowlist),
`credential` what the one Roblox account is used for (C1, D1)."""
FRESH_MFA_SETTINGS: Final[frozenset[str]] = frozenset({"export_include_ips", "health_auto_include_credential"})
"""Single settings outside those groups that need it as well, because each turns on for good what an action guarded
by the factor does once: `export_include_ips` puts raw client addresses in every download, which the LLM export
allows only with a fresh second factor (plan 9.15, 12.2); `health_auto_include_credential` makes every scheduled
Check Proxy Health run call Roblox with the credential (H-CRED-AUTH), which a manual run does only with a fresh
second factor (DESIGN 14.4, finding secfix-6). Arming the spam detectors (`spam_dry_run` off) is the third such
switch; it has its own route (`ARM_ONLY_SETTINGS`)."""

HISTORY_TABLE: Final = TableSpec(
    name="settings_history",
    columns=(
        Column("id", "Change", "The history entry number; revert links point at it."),
        Column("changed_at", "When", "When the change was saved (Unix seconds).", "s"),
        Column("key", "Setting", "The setting key."),
        Column("old", "Before", "The override before the change; empty means the catalog default.", sortable=False),
        Column("new", "After", "The override after the change; empty means the catalog default.", sortable=False),
        Column("changed_by", "Changed by", "Who made the change (admin:<name>, recommendation, import, ...)."),
        Column("source", "Source", "Where the change came from (admin, revert, import, recommendation:<id>, ...)."),
        Column("reason", "Reason", "The reason given with the change.", sortable=False),
    ),
    default_sort="id",
)


# ================================================================================================ helpers


def settings_service(ctx: Any) -> SettingsService:
    """The settings service for this request. Sensitive values are fingerprinted with a key derived from the
    `ip_hash_key` credential when it exists, so fingerprints match across workers and restarts
    (`config.settings_service.service_for`, shared with every other settings writer)."""
    return service_for(ctx)


def _spec_or_404(key: str) -> SettingSpec:
    resolved = catalog.resolve_key(key)
    if resolved is None or resolved not in catalog.CATALOG:
        raise common.not_found("No setting has that key.")
    return catalog.CATALOG[resolved]


def default_of(spec: SettingSpec) -> Any:
    """The canonical catalog default of a setting."""
    return catalog.DEFAULTS.get(spec.key, spec.default)


def shown(spec: SettingSpec | None, value: Any) -> Any:
    """A value as the API shows it: `[redacted]` for a sensitive setting, JSON shapes (lists, not tuples)."""
    if spec is not None and spec.sensitive and value is not None:
        return catalog.REDACTED
    return thaw(value)


def risk_reason(spec: SettingSpec, value: Any) -> str | None:
    """Why setting `spec` to `value` is high risk (a reason and a confirmation are needed), or None."""
    why = spec.is_high_risk_value(value)
    if why:
        return why
    return HIGH_RISK_SETTING if spec.risk is Risk.HIGH else None


def consequence(spec: SettingSpec, old: Any, new: Any) -> tuple[str, str]:
    """`(direction, text)`: what the change does, from the catalog's "what happens if" texts (plan 15.1)."""
    if spec.type is SettingType.BOOL:
        return ("enabled", spec.if_enabled) if new else ("disabled", spec.if_disabled)
    if spec.type is SettingType.ENUM:
        option = next((o for o in spec.options if o.value == new), None)
        return "changed", option.description if option else spec.description
    if spec.type in NUMERIC_TYPES:
        try:
            if float(new) > float(old):
                return "raised", spec.if_raised
            if float(new) < float(old):
                return "lowered", spec.if_lowered
        except (TypeError, ValueError):
            pass
    return "changed", spec.description


def entry(
    spec: SettingSpec,
    snapshot: Any,
    *,
    latest: Mapping[str, Mapping[str, Any]],
    recommendations: Mapping[str, Sequence[Mapping[str, Any]]],
    include_text: bool = True,
) -> dict[str, Any]:
    """One editor row: the catalog metadata plus value, default, risk, last change and open recommendations."""
    data = catalog.spec_to_dict(spec)
    if not include_text:
        for name in ("description", "if_raised", "if_lowered", "if_enabled", "if_disabled", "notes"):
            data.pop(name, None)
        data["options"] = [option["value"] for option in data["options"]]
    value = snapshot[spec.key]
    default = default_of(spec)
    overridden = bool(snapshot.is_overridden(spec.key))
    updated_at, updated_by = snapshot.meta.get(spec.key, (None, None))
    last = latest.get(spec.key)
    data.update(
        value=shown(spec, value),
        default=shown(spec, default),
        overridden=overridden,
        changed=overridden and not same_value(value, default),
        high_risk_reason=None if spec.sensitive else spec.is_high_risk_value(value),
        needs_reason=spec.risk is Risk.HIGH or bool(spec.high_risk_if),
        needs_fresh_mfa=needs_fresh_mfa(spec),
        updated_at=updated_at if overridden else None,
        updated_by=updated_by if overridden else None,
        last_change=None if last is None else _history_item(last, link=True),
        open_recommendations=list(recommendations.get(spec.key, ())),
    )
    return data


def _effective(key: str, override: Any) -> Any:
    spec = catalog.CATALOG.get(key)
    if spec is None:
        return override
    return shown(spec, default_of(spec) if override is None else override)


def _history_item(row: Mapping[str, Any], *, link: bool) -> dict[str, Any]:
    """A history row for the API: overrides, effective values, and a revert link when a revert is possible."""
    key = str(row["key"])
    spec = catalog.CATALOG.get(key)
    revertible = spec is not None and not (spec.sensitive and row.get("old") is not None)
    item = {
        "id": row["id"],
        "key": key,
        "old": row.get("old"),
        "new": row.get("new"),
        "old_effective": _effective(key, row.get("old")),
        "new_effective": _effective(key, row.get("new")),
        "changed_at": row["changed_at"],
        "changed_by": row["changed_by"],
        "reason": row.get("reason"),
        "source": row["source"],
        "revertible": revertible,
    }
    if link and revertible:
        item["revert_url"] = f"{common.API_PREFIX}/settings/history/{row['id']}/revert"
    return item


def _change(change: Any) -> dict[str, Any]:
    spec = catalog.CATALOG.get(change.key)
    return {
        "key": change.key,
        "old": shown(spec, change.old),
        "new": shown(spec, change.new),
        "overridden": change.overridden,
        "history_id": change.history_id,
        "audit_id": change.audit_id,
    }


def result_answer(result: UpdateResult) -> dict[str, Any]:
    """What a write answers: the keys that changed (with history and audit ids), the unchanged ones, warnings."""
    return {
        "changed": [_change(change) for change in result.changes],
        "unchanged": list(result.unchanged),
        "config_version": result.config_version,
        "warnings": list(result.warnings),
    }


def preview_changes(changes: Mapping[str, Any], snapshot: Any) -> dict[str, Any]:
    """The server-side diff of a batch (plan 15.2 "Review changes"): pure, nothing is written.

    Each item has a `status`: `change`, `unchanged`, `invalid` (with the catalog's message) or `unknown`. The
    cross-field rules are checked on the overrides as they would be after the batch, and only rules that involve a
    changed key are reported (an old problem never blocks a new edit, as in the service).
    """
    items: list[dict[str, Any]] = []
    merged: dict[str, Any] = dict(snapshot.overrides)
    changed: set[str] = set()
    for raw_key, raw_value in changes.items():
        key = str(raw_key)
        resolved = catalog.resolve_key(key)
        if resolved is None or resolved not in catalog.CATALOG:
            items.append({"key": key, "status": "unknown", "message": "Unknown setting"})
            continue
        spec = catalog.CATALOG[resolved]
        current = snapshot[resolved]
        try:
            value = catalog.validate_spec_value(spec, raw_value)
        except catalog.SettingValidationError as exc:
            items.append(
                {"key": resolved, "status": "invalid", "current": shown(spec, current), "message": exc.message}
            )
            continue
        default = default_of(spec)
        base = {
            "key": resolved,
            "label": spec.label,
            "current": shown(spec, current),
            "new": shown(spec, value),
            "default": shown(spec, default),
            "unit": spec.unit,
        }
        if same_value(value, current):
            items.append({**base, "status": "unchanged"})
            continue
        direction, text = consequence(spec, current, value)
        why = risk_reason(spec, value)
        changed.add(resolved)
        if same_value(value, default):
            merged.pop(resolved, None)
        else:
            merged[resolved] = value
        items.append(
            {
                **base,
                "status": "change",
                "back_to_default": same_value(value, default),
                "direction": direction,
                "consequence": text,
                "risk": spec.risk.value,
                "high_risk_reason": why,
                "needs_reason": why is not None,
                "apply": spec.apply.value,
                "restart_needed": spec.apply is Apply.RESTART,
            }
        )
    cross = [
        {"keys": list(issue.keys), "message": issue.message}
        for issue in catalog.validate_cross(merged)
        if changed.intersection(issue.keys)
    ]
    blocked = any(item["status"] in ("invalid", "unknown") for item in items) or bool(cross)
    risky = [item["key"] for item in items if item.get("needs_reason")]
    fresh = fresh_mfa_keys(sorted(changed))
    return {
        "ok": not blocked,
        "items": items,
        "cross": cross,
        "changes": sum(1 for item in items if item["status"] == "change"),
        "reason_required": bool(risky),
        "confirm_required": bool(risky),
        "high_risk_keys": risky,
        "fresh_mfa_required": bool(fresh),
        "fresh_mfa_keys": fresh,
        "config_version": snapshot.version,
    }


def needs_fresh_mfa(spec: SettingSpec) -> bool:
    """Whether changing `spec`, either way, needs a second factor entered within `admin_reauth_window_s` (plan 9.6).

    True for a sensitive setting, the `FRESH_MFA_GROUPS` and `FRESH_MFA_SETTINGS`. Every settings writer of the API
    asks this one question (this editor, PUT, reset, revert and import here; the recommendations API for an apply
    or an undo), so no path changes these settings with a stale session. Without it a session whose factor went
    stale could raise `admin_reauth_window_s` and pass every fresh-factor guard again (review finding apisec-1).
    """
    return spec.sensitive or spec.group in FRESH_MFA_GROUPS or spec.key in FRESH_MFA_SETTINGS


def fresh_mfa_keys(keys: Iterable[str]) -> list[str]:
    """The keys among `keys` (catalog keys or v1 names) that need a fresh second factor (`needs_fresh_mfa`)."""
    out: list[str] = []
    for key in keys:
        resolved = catalog.resolve_key(str(key))
        spec = catalog.CATALOG.get(resolved) if resolved else None
        if spec is not None and needs_fresh_mfa(spec) and spec.key not in out:
            out.append(spec.key)
    return out


async def require_fresh_for(request: Request, keys: Iterable[str]) -> None:
    """403 `reauth_required` (with `Roxy-Reauth: required`) unless the second factor is fresh, when any of `keys`
    needs one (see `needs_fresh_mfa`); nothing is checked for a batch of ordinary settings."""
    if fresh_mfa_keys(keys):
        await common.admin_fresh_mfa(request)


def changing_keys(preview: Mapping[str, Any]) -> list[str]:
    """The keys a `preview_changes` answer would actually change (unchanged values need no second factor)."""
    return [str(item["key"]) for item in preview["items"] if item["status"] == "change"]


def check_risk(risky: Sequence[str], *, reason: str, confirmed: bool) -> str:
    """422 unless a batch with high-risk changes is confirmed and has a reason; returns the trimmed reason."""
    if risky and not confirmed:
        raise common.validation_error(
            dict.fromkeys(risky, CONFIRM_MESSAGE), CONFIRM_MESSAGE, code="confirmation_required"
        )
    text = common.require_reason(reason, required=False)
    if risky and not text:
        raise common.validation_error({"reason": REASON_MESSAGE}, REASON_MESSAGE)
    return text


def refuse_arming(changes: Mapping[str, Any], snapshot: Any) -> None:
    """422 `confirmation_required` when a batch would switch an `ARM_ONLY_SETTINGS` key off (see that constant).

    Only a change from on to off is refused; a value that does not validate is left to the usual checks.
    """
    fields: dict[str, str] = {}
    for raw_key, raw_value in changes.items():
        key = catalog.resolve_key(str(raw_key)) or str(raw_key)
        if key not in ARM_ONLY_SETTINGS or raw_value is RESET:
            continue
        try:
            value = catalog.validate_value(key, raw_value)
        except (catalog.SettingValidationError, KeyError):
            continue
        if not value and bool(snapshot.get(key)):
            fields[key] = f"{ARM_ONLY_MESSAGE} ({ARM_ONLY_SETTINGS[key]})"
    if fields:
        raise common.validation_error(fields, ARM_ONLY_MESSAGE, code="confirmation_required")


@dataclass(frozen=True, slots=True)
class WriteRules:
    """The editor's rules judged again inside the write transaction (a `SettingsService` guard, finding secfix-1).

    The routes first check a request against this worker's settings snapshot (quick answers, the previews). That
    snapshot may be up to `CONFIG_POLL_INTERVAL_S` behind a change another worker made, while the service writes every
    key whose value in control.db differs from the request: a stale session could put an `admin_security` value back
    that "changes nothing" by the snapshot. So the same rules run again on exactly the keys the transaction is about
    to write (`PendingWrite.dirty`), against what control.db holds:
      * a key that `needs_fresh_mfa`, unless the second factor was entered within the `admin_reauth_window_s`
        control.db holds (the value before this write): 403 `reauth_required`;
      * an `ARM_ONLY_SETTINGS` key going from on to off, unless `arming_allowed` (only the arm route): 422
        `confirmation_required`;
      * with `confirmed` False, a high-risk value (`risk_reason`): 422 `confirmation_required`. None means the route
        decided its confirmation from data that does not lag (a revert's history row, an import preview read from
        control.db).
    `factor_age_s` is the age of the session's real second factor in seconds (None for a trusted-device or bootstrap
    session, which is never fresh).
    """

    factor_age_s: float | None
    confirmed: bool | None = None
    arming_allowed: bool = False

    def fresh(self, pending: PendingWrite) -> bool:
        """Whether the second factor is fresh by the re-auth window control.db holds."""
        if self.factor_age_s is None:
            return False
        try:
            window = float(pending.value("admin_reauth_window_s"))
        except (TypeError, ValueError):
            return False
        return self.factor_age_s <= window

    def __call__(self, pending: PendingWrite) -> None:
        if fresh_mfa_keys(pending.dirty) and not self.fresh(pending):
            raise ReauthRequired()
        if not self.arming_allowed:
            arming = {
                key: f"{ARM_ONLY_MESSAGE} ({ARM_ONLY_SETTINGS[key]})"
                for key, (old, new) in pending.dirty.items()
                if key in ARM_ONLY_SETTINGS and bool(old) and not bool(new)
            }
            if arming:
                raise common.validation_error(arming, ARM_ONLY_MESSAGE, code="confirmation_required")
        if self.confirmed is False:
            risky = [
                key
                for key, (_old, new) in pending.dirty.items()
                if key in catalog.CATALOG and risk_reason(catalog.CATALOG[key], new)
            ]
            if risky:
                raise common.validation_error(
                    dict.fromkeys(risky, CONFIRM_MESSAGE), CONFIRM_MESSAGE, code="confirmation_required"
                )


def write_rules(
    ctx: Any, admin: AdminPrincipal, *, confirmed: bool | None = None, arming_allowed: bool = False
) -> WriteRules:
    """The `WriteRules` of a request by `admin` (the age of its second factor on this worker's clock)."""
    age = float(ctx.clock.now()) - float(admin.mfa_at) if admin.mfa_level in FULL_MFA_LEVELS else None
    return WriteRules(age, confirmed=confirmed, arming_allowed=arming_allowed)


def _errors_or_none(preview: Mapping[str, Any]) -> None:
    """422 `invalid_settings` with one message per key when the preview found unknown or invalid values."""
    fields = {
        str(item["key"]): str(item.get("message") or "Not valid.")
        for item in preview["items"]
        if item["status"] in ("invalid", "unknown")
    }
    for issue in preview["cross"]:
        for key in issue["keys"]:
            fields.setdefault(str(key), str(issue["message"]))
    if fields:
        raise common.validation_error(fields, "The change was refused; nothing was saved.", code="invalid_settings")


async def _snapshot_reads(ctx: Any) -> tuple[dict[str, dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    latest = await ctx.dbs.control.read(read_settings.latest_changes)
    recommendations = await ctx.dbs.metrics.read(open_setting_recommendations)
    return latest, recommendations


# ================================================================================================ bodies


class ChangesBody(ApiBody):
    """`POST /settings/preview`: the batch to check."""

    changes: dict[str, Any] = Field(min_length=1, max_length=MAX_CHANGES)


class UpdateBody(ApiBody):
    """`PATCH /settings`: the dirty keys of a batch, one reason, and the high-risk confirmation."""

    changes: dict[str, Any] = Field(min_length=1, max_length=MAX_CHANGES)
    reason: str = Field(default="", max_length=MAX_REASON_LENGTH)
    confirm_high_risk: bool = False


class ValueBody(ApiBody):
    """`PUT /settings/{key}`: one new value (an inline setting control)."""

    value: Any
    reason: str = Field(default="", max_length=MAX_REASON_LENGTH)
    confirm_high_risk: bool = False


class ReasonBody(ApiBody):
    """A reason only (reset to default)."""

    reason: str = Field(default="", max_length=MAX_REASON_LENGTH)


class RevertBody(ApiBody):
    """`POST /settings/history/{id}/revert`."""

    reason: str = Field(default="", max_length=MAX_REASON_LENGTH)
    confirm_high_risk: bool = False


class ImportPreviewBody(ApiBody):
    """`POST /settings/import/preview`: an exported document (or a bare `{key: value}` object)."""

    document: dict[str, Any] = Field(max_length=MAX_CHANGES)
    replace: bool = False


class ImportBody(ImportPreviewBody):
    """`POST /settings/import`: the document, a reason and the high-risk confirmation."""

    reason: str = Field(default="", max_length=MAX_REASON_LENGTH)
    confirm_high_risk: bool = False


# ================================================================================================ catalog


@router.get("")
async def list_settings(
    request: Request,
    _admin: AdminSession,
    q: Annotated[str | None, Query(max_length=common.MAX_SEARCH_CHARS)] = None,
    group: Annotated[str | None, Query(max_length=40)] = None,
    risk: Annotated[str | None, Query(max_length=16)] = None,
    changed: bool = False,
    has_recommendation: bool = False,
    include_text: bool = True,
) -> dict[str, Any]:
    """The catalog editor listing (plan 15.2): grouped entries, search, and filters."""
    fields: dict[str, str] = {}
    if group is not None and group not in {g.value for g in Group}:
        fields["group"] = f"Choose one of: {', '.join(g.value for g in Group)}."
    if risk is not None and risk not in {r.value for r in Risk}:
        fields["risk"] = f"Choose one of: {', '.join(r.value for r in Risk)}."
    if fields:
        raise common.validation_error(fields, "The filters are not valid.")
    ctx = get_ctx(request)
    snapshot = ctx.settings.snapshot()
    latest, recommendations = await _snapshot_reads(ctx)
    query = (q or "").strip()
    matches = catalog.search(query, group=group, risk=risk)
    if changed:
        matches = [spec for spec in matches if snapshot.is_overridden(spec.key)]
    if has_recommendation:
        matches = [spec for spec in matches if spec.key in recommendations]
    by_group: dict[str, list[dict[str, Any]]] = {}
    for spec in matches:
        by_group.setdefault(spec.group.value, []).append(
            entry(spec, snapshot, latest=latest, recommendations=recommendations, include_text=include_text)
        )
    groups = [
        {"id": g.value, "label": GROUP_LABELS.get(g, g.value), "settings": by_group[g.value]}
        for g in Group
        if g.value in by_group
    ]
    return {
        "catalog_version": catalog.CATALOG_VERSION,
        "config_version": snapshot.version,
        "total": len(catalog.CATALOG),
        "count": len(matches),
        "changed_count": sum(1 for key in catalog.CATALOG if snapshot.is_overridden(key)),
        "with_recommendation_count": len(recommendations),
        "ranked_keys": [spec.key for spec in matches] if query else None,
        "groups": groups,
        "cross_field_rules": catalog.cross_rule_descriptions(catalog.CATALOG.keys()),
    }


@router.get("/values")
async def values(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """Every current value in one small map (sensitive ones `[redacted]`), the overridden keys and the version."""
    snapshot = get_ctx(request).settings.snapshot()
    return {
        "config_version": snapshot.version,
        "values": {key: shown(spec, snapshot[key]) for key, spec in catalog.CATALOG.items()},
        "overridden": sorted(key for key in catalog.CATALOG if snapshot.is_overridden(key)),
    }


@router.post("/preview")
async def preview(request: Request, body: ChangesBody, _admin: AdminSession, _csrf: CsrfChecked) -> dict[str, Any]:
    """The server-side diff preview of a batch: nothing is written (plan 15.2 "Review changes")."""
    ctx = get_ctx(request)
    return preview_changes(body.changes, ctx.settings.snapshot())


@router.patch("")
async def update_settings(
    request: Request, body: UpdateBody, admin: AdminSession, _csrf: CsrfChecked
) -> dict[str, Any]:
    """Save the dirty keys of a batch, atomically, with one reason (plan 15.2)."""
    ctx = get_ctx(request)
    checked = preview_changes(body.changes, ctx.settings.snapshot())
    _errors_or_none(checked)
    refuse_arming(body.changes, ctx.settings.snapshot())
    await require_fresh_for(request, changing_keys(checked))
    reason = check_risk(checked["high_risk_keys"], reason=body.reason, confirmed=body.confirm_high_risk)
    result = await run_mutation(
        settings_service(ctx).update(
            body.changes,
            actor_for(admin),
            reason,
            "admin",
            request_id=request_id_of(request),
            guard=write_rules(ctx, admin, confirmed=body.confirm_high_risk),
        )
    )
    return result_answer(result)


# ================================================================================================ history


async def _history_table(
    request: Request,
    admin: Any,
    tq: TableQuery,
    fmt: Any,
    *,
    key: str | None,
    source: str | None,
    actor: str | None,
    since: str | None,
    until: str | None,
) -> Any:
    ctx = get_ctx(request)
    tz = str(ctx.settings.get("ui_timezone") or "UTC")
    window: dict[str, int | None] = {"since": None, "until": None}
    problems: dict[str, str] = {}
    for name, raw in (("from", since), ("to", until)):
        if raw:
            try:
                window["since" if name == "from" else "until"] = int(common.parse_instant(raw, tz=tz))
            except ValueError as exc:
                problems[name] = str(exc)
    if problems:
        raise common.validation_error(problems, "The time filter is not valid.", code="invalid_range")
    filters = {"key": key, "source": source, "actor": actor, "q": tq.q, **window}

    def read(page: int, size: int) -> Any:
        def run(conn: Any) -> tuple[list[dict[str, Any]], int]:
            return read_settings.history_page(
                conn,
                key=key,
                source=source,
                actor=actor,
                q=tq.q,
                since=window["since"],
                until=window["until"],
                sort=tq.sort,
                descending=tq.descending,
                limit=size,
                offset=(page - 1) * size,
            )

        return run

    if fmt is not None:

        async def fetch(page: int, size: int) -> tuple[list[dict[str, Any]], int]:
            rows, total = await ctx.dbs.control.read(read(page, size))
            return [_history_item(row, link=False) for row in rows], total

        kept = {k: v for k, v in filters.items() if v}
        return await common.export_pages(request, admin, HISTORY_TABLE, fetch, fmt, tq=tq, filters=kept)
    rows, total = await ctx.dbs.control.read(read(tq.page, tq.page_size))
    answer = common.table_answer(HISTORY_TABLE, tq, [_history_item(row, link=True) for row in rows], total)
    answer["filters"] = filters
    answer["sources"] = await ctx.dbs.control.read(read_settings.history_sources)
    return answer


@router.get("/history", response_model=None)
async def global_history(
    request: Request,
    admin: AdminSession,
    tq: Annotated[TableQuery, Depends(table_params(HISTORY_TABLE))],
    fmt: ExportFormatDep,
    key: Annotated[str | None, Query(max_length=80)] = None,
    source: Annotated[str | None, Query(max_length=80)] = None,
    actor: Annotated[str | None, Query(max_length=80)] = None,
    from_: Annotated[str | None, Query(alias="from", max_length=common.MAX_TIME_TEXT)] = None,
    to: Annotated[str | None, Query(max_length=common.MAX_TIME_TEXT)] = None,
) -> Any:
    """Every settings change, newest first (plan 15.2 "history per key and global"); `format` downloads it."""
    return await _history_table(request, admin, tq, fmt, key=key, source=source, actor=actor, since=from_, until=to)


@router.post("/history/{history_id}/revert")
async def revert(
    request: Request,
    history_id: Annotated[int, Path(ge=1, le=2**62)],
    body: RevertBody,
    admin: AdminSession,
    _csrf: CsrfChecked,
) -> dict[str, Any]:
    """Put a key back to the value it had before history entry `history_id` (itself audited, source `revert`)."""
    ctx = get_ctx(request)
    row = await ctx.dbs.control.read(lambda conn: read_settings.history_entry(conn, history_id))
    if row is None:
        raise common.not_found("No settings history entry has that id.")
    spec = catalog.CATALOG.get(str(row["key"]))
    risky: list[str] = []
    if spec is not None and row.get("old") is not None and not spec.sensitive:
        try:
            target = catalog.validate_spec_value(spec, row["old"])
        except catalog.SettingValidationError:
            target = None  # the service refuses it with its own message
        if target is not None and risk_reason(spec, target):
            risky.append(spec.key)
        if target is not None:
            refuse_arming({spec.key: target}, ctx.settings.snapshot())
    await require_fresh_for(request, [str(row["key"])])
    reason = check_risk(risky, reason=body.reason, confirmed=body.confirm_high_risk)
    result = await run_mutation(
        settings_service(ctx).revert(
            history_id, actor_for(admin), reason, request_id=request_id_of(request), guard=write_rules(ctx, admin)
        )
    )
    return {**result_answer(result), "reverted": history_id}


# ================================================================================================ export, import


@router.get("/export", response_model=None)
async def export_overrides(request: Request, admin: AdminSession) -> Response:
    """Every current override as a JSON file with the catalog version (plan 15.2); the download is audited."""
    ctx = get_ctx(request)
    document = await run_mutation(settings_service(ctx).export_overrides())
    at_ms = int(ctx.clock.now() * 1000)
    filename = f"roxy_settings_{at_ms}.json"
    details = {
        "format": "json",
        "overrides": len(document.get("overrides", {})),
        "catalog_version": document.get("catalog_version"),
        "filename": filename,
    }
    actor = actor_for(admin)
    request_id = request_id_of(request)

    def write(conn: Any) -> int:
        return audit.record(
            conn, actor, common.EXPORT_AUDIT_ACTION, EXPORT_TARGET, None, details, None, request_id, at=at_ms // 1000
        )

    await run_mutation(ctx.dbs.control.write(write))
    content = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
    response = Response(content=content, media_type="application/json")
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    response.headers["Cache-Control"] = common.NO_STORE
    return response


def _import_answer(preview: Any) -> dict[str, Any]:
    items = []
    risky: list[str] = []
    for item in preview.items:
        spec = catalog.CATALOG.get(item.key)
        shaped: dict[str, Any] = {
            "key": item.key,
            "status": item.status,
            "current": shown(spec, item.current),
            "new": shown(spec, item.new),
            "default": shown(spec, item.default),
            "message": item.message,
        }
        planned = preview.plan.get(item.key, RESET)
        if spec is not None and item.status == "change" and planned is not RESET:
            why = risk_reason(spec, planned)
            shaped["high_risk_reason"] = why
            if why:
                risky.append(item.key)
        items.append(shaped)
    return {
        "ok": preview.ok,
        "catalog_version_matches": preview.catalog_version_matches,
        "items": items,
        "changes": len(preview.changes),
        "cross": [{"keys": list(issue.keys), "message": issue.message} for issue in preview.cross],
        "high_risk_keys": risky,
        "reason_required": bool(risky),
        "confirm_required": bool(risky),
        "fresh_mfa_keys": fresh_mfa_keys(item.key for item in preview.changes),
    }


@router.post("/import/preview")
async def import_preview(
    request: Request, body: ImportPreviewBody, _admin: AdminSession, _csrf: CsrfChecked
) -> dict[str, Any]:
    """Validate an exported document and show the diff an import would apply (nothing is written)."""
    ctx = get_ctx(request)
    preview = await run_mutation(settings_service(ctx).preview_import(body.document, replace=body.replace))
    return _import_answer(preview)


@router.post("/import")
async def import_overrides(
    request: Request, body: ImportBody, admin: AdminSession, _csrf: CsrfChecked
) -> dict[str, Any]:
    """Apply an exported document atomically with a reason (refused entirely if any entry is invalid)."""
    ctx = get_ctx(request)
    service = settings_service(ctx)
    preview = await run_mutation(service.preview_import(body.document, replace=body.replace))
    answer = _import_answer(preview)
    refuse_arming({key: value for key, value in preview.plan.items() if value is not RESET}, ctx.settings.snapshot())
    await require_fresh_for(request, [item.key for item in preview.changes])
    reason = check_risk(answer["high_risk_keys"], reason=body.reason, confirmed=body.confirm_high_risk)
    if not reason:  # an import replaces many values at once: plan 15.2 "applies atomically with a reason"
        raise common.validation_error({"reason": "Give a reason for this import; it goes in the audit log."})
    result = await run_mutation(
        service.import_overrides(
            body.document,
            actor_for(admin),
            reason,
            replace=body.replace,
            request_id=request_id_of(request),
            guard=write_rules(ctx, admin),
        )
    )
    return {**result_answer(result), "catalog_version_matches": preview.catalog_version_matches}


# ================================================================================================ one key


@router.get("/{key}")
async def get_setting(
    request: Request, key: Annotated[str, Path(pattern=KEY_PATTERN)], _admin: AdminSession
) -> dict[str, Any]:
    """One setting: its editor entry, its recent history and its related settings."""
    spec = _spec_or_404(key)
    ctx = get_ctx(request)
    snapshot = ctx.settings.snapshot()
    latest, recommendations = await _snapshot_reads(ctx)

    def recent(conn: Any) -> tuple[list[dict[str, Any]], int]:
        return read_settings.history_page(conn, key=spec.key, limit=RECENT_HISTORY)

    rows, total = await ctx.dbs.control.read(recent)
    related = [
        entry(catalog.CATALOG[name], snapshot, latest=latest, recommendations=recommendations, include_text=False)
        for name in spec.related_settings
        if name in catalog.CATALOG
    ]
    return {
        "setting": entry(spec, snapshot, latest=latest, recommendations=recommendations),
        "history": [_history_item(row, link=True) for row in rows],
        "history_total": total,
        "related": related,
        "config_version": snapshot.version,
    }


@router.put("/{key}")
async def set_setting(
    request: Request,
    key: Annotated[str, Path(pattern=KEY_PATTERN)],
    body: ValueBody,
    admin: AdminSession,
    _csrf: CsrfChecked,
) -> dict[str, Any]:
    """Save one key (an inline setting control on a feature page, plan 15.6)."""
    spec = _spec_or_404(key)
    ctx = get_ctx(request)
    changes = {spec.key: body.value}
    checked = preview_changes(changes, ctx.settings.snapshot())
    _errors_or_none(checked)
    refuse_arming(changes, ctx.settings.snapshot())
    await require_fresh_for(request, changing_keys(checked))
    reason = check_risk(checked["high_risk_keys"], reason=body.reason, confirmed=body.confirm_high_risk)
    result = await run_mutation(
        settings_service(ctx).update(
            changes,
            actor_for(admin),
            reason,
            "admin",
            request_id=request_id_of(request),
            guard=write_rules(ctx, admin, confirmed=body.confirm_high_risk),
        )
    )
    return result_answer(result)


@router.post("/{key}/reset")
async def reset_setting(
    request: Request,
    key: Annotated[str, Path(pattern=KEY_PATTERN)],
    body: ReasonBody,
    admin: AdminSession,
    _csrf: CsrfChecked,
) -> dict[str, Any]:
    """Remove the override so the key follows its catalog default again (parity row 124).

    A reset of a key at its default changes nothing and needs no second factor; whether the key has an override is
    decided inside the write on what control.db holds (`write_rules`), never on this worker's snapshot alone, which
    may not show an override another worker just wrote (finding secfix-1)."""
    spec = _spec_or_404(key)
    ctx = get_ctx(request)
    if ctx.settings.snapshot().is_overridden(spec.key):  # the quick answer; the write's guard decides
        await require_fresh_for(request, [spec.key])
    reason = common.require_reason(body.reason, required=False)
    result = await run_mutation(
        settings_service(ctx).reset_to_default(
            spec.key, actor_for(admin), reason, request_id=request_id_of(request), guard=write_rules(ctx, admin)
        )
    )
    return result_answer(result)


@router.get("/{key}/history", response_model=None)
async def key_history(
    request: Request,
    key: Annotated[str, Path(pattern=KEY_PATTERN)],
    admin: AdminSession,
    tq: Annotated[TableQuery, Depends(table_params(HISTORY_TABLE))],
    fmt: ExportFormatDep,
    source: Annotated[str | None, Query(max_length=80)] = None,
    actor: Annotated[str | None, Query(max_length=80)] = None,
    from_: Annotated[str | None, Query(alias="from", max_length=common.MAX_TIME_TEXT)] = None,
    to: Annotated[str | None, Query(max_length=common.MAX_TIME_TEXT)] = None,
) -> Any:
    """The history of one key (a key removed from the catalog still shows its history)."""
    resolved = catalog.resolve_key(key) or key
    return await _history_table(
        request, admin, tq, fmt, key=resolved, source=source, actor=actor, since=from_, until=to
    )


__all__ = [
    "FRESH_MFA_GROUPS",
    "FRESH_MFA_SETTINGS",
    "HISTORY_TABLE",
    "MAX_CHANGES",
    "WriteRules",
    "changing_keys",
    "check_risk",
    "consequence",
    "default_of",
    "entry",
    "fresh_mfa_keys",
    "needs_fresh_mfa",
    "preview_changes",
    "require_fresh_for",
    "result_answer",
    "risk_reason",
    "router",
    "settings_service",
    "shown",
    "write_rules",
]
