"""Recommendations API (`/admin/api/v1/recommendations`): the list, the detail drawer, preview, apply and undo.

What this is
    The routes behind the Recommendations page (plan 11.2, 11.3, 14.1) and the bell in the top bar:
      * `GET /recommendations`: every recommendation as a table (paging, sorting, search, `format=csv|json`) with
        the filters of plan 14.1: `state` (default `open`; `all` for every state), `severity`, `family` and
        `rule`, plus the counts the filter chips and the bell show.
      * `GET /recommendations/{id}`: the drawer: the plan 11.2 object (evidence, the changes with their current
        values), the digest of its changes, what can be done with it now (and why not), its rule and that rule's
        settings, every action taken on it, its auto-apply watch window and earlier recommendations with the same
        fingerprint.
      * `GET /recommendations/{id}/preview`: the dry run (plan 11.3): the validated diff of every change, what an
        apply will ask for (a reason, the high-risk confirmation, a fresh second factor), and the replay of the
        last hour of request samples (`window=1h|6h|24h`, up to `request_sample_hours`) under the proposal.
      * `POST /recommendations/{id}/apply` (with the previewed `changes_digest`), `POST .../undo`,
        `POST .../snooze` (`1h`, `1d`, `1w` or `until`) and `POST .../dismiss` (a reason from the plan 11.3
        dropdown; `other` needs a text).
      * `GET /recommendations/history` (every action, a table with filters and export) and
        `GET /recommendations/{id}/history`.
      * `GET /recommendations/rules` and `GET /recommendations/rules/{rule}`: the "Tune this rule" drawer of plan
        11.1 (every rule of the catalog with its on/off switch, severity override and thresholds, as settings
        editor rows), and `GET /recommendations/settings`: the engine and preview settings cards. Edits go
        through the settings API (`PATCH /settings`), so they are validated, audited and hot-reloaded like every
        other setting.

Why it exists
    Plan 11.3 and P4: a recommendation is previewed, applied exactly as previewed, and can be undone exactly. The
    engine (`roxy/insights`) owns the lifecycle and the actions; this module is the thin HTTP layer DESIGN.md
    section 13 asks for: it parses, checks the guards, calls `insights/actions.py` and `insights/simulate.py`
    through the engine, and shapes the answer.

How it works
    * Reads: `insights/read_recommendations.py` (paged list, facets, history, watch windows), turned into
      `Recommendation` objects with `insights.engine.row_to_recommendation`.
    * Actions: `RecommendationActions` (`ctx.insight_actions` once the lifespan wires it, else one built over this
      worker's stores with the same audited services the settings and rules APIs use). Apply writes every change
      through `SettingsService` and `RulesService` (each with its audit row and `config_version` bump), with
      `source = recommendation:<id>`; a failed change rolls the others back, and undo refuses a change that was
      superseded since (409 `superseded`).
    * Apply refuses when the recommendation changed since the admin previewed it (409 `changed_since_preview`:
      the body carries the digest the preview showed), asks for `confirm_high_risk` and a reason when a setting
      would take a high-risk value (the settings editor's rule, `settings.check_risk`), and asks for a fresh
      second factor (403 `reauth_required`) when a change, or its undo, touches the admin's security: admin
      security or credential settings, the admin allowlist, or the credential allowlist (plan 9.6, D6, C1). Those
      decisions are made on one read of the recommendation, and the action compares the same digest again inside
      its lease (`expected_digest`), so an evaluation that rewrites the proposal in between is refused (409), never
      applied without its confirmation or second factor (P4).
    * Another action holding the recommendation is 409 `wrong_state`; a hot.db that cannot be written is 503
      `unavailable` with `Retry-After` (C7), never "another request".
    * The dry run replays up to `simulate.MAX_SAMPLES` samples in pure Python, so it runs on a worker thread with
      its own event loop (the event loop of this worker keeps serving), one at a time per worker with a short
      queue (429 beyond it), and its result is kept for `DRY_RUN_CACHE_S` per recommendation and window.
    * Values of sensitive settings are shown as `[redacted]` everywhere (`settings.shown`).

What to read next
    `roxy/insights/actions.py`, `roxy/insights/simulate.py`, `roxy/insights/engine.py`,
    `roxy/insights/read_recommendations.py`, `roxy/admin/api/settings.py`.
"""

from __future__ import annotations

import asyncio
import functools
import logging
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Annotated, Any, Final, Literal

from fastapi import Depends, Path, Query, Request
from pydantic import Field

from roxy.admin.api import common
from roxy.admin.api import settings as settings_api
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
    table_params,
)
from roxy.admin.auth.deps import AdminPrincipal
from roxy.config import catalog, read_settings
from roxy.config.constants import MAX_REASON_LENGTH
from roxy.config.insight_params import INSIGHT_RULES
from roxy.config.spec import Group, InsightRuleSpec, SettingSpec
from roxy.deps import get_ctx
from roxy.insights import read_recommendations as reads
from roxy.insights import simulate
from roxy.insights.actions import CHANGED_MESSAGE as ACTION_CHANGED_MESSAGE
from roxy.insights.actions import ActionError, ActionResult, AppliedChange, PreviewItem, RecommendationActions
from roxy.insights.engine import InsightsEngine, row_to_recommendation
from roxy.insights.models import (
    ACTIVE_STATES,
    APPLIED_STATES,
    DISMISS_REASONS,
    SEVERITIES,
    SNOOZE_DURATIONS_S,
    STATES,
    Recommendation,
    changes_digest,
)
from roxy.insights.rules import load_rules
from roxy.metrics.read_recommended_settings import open_setting_recommendations
from roxy.rules.service import RulesService
from roxy.storage.db import SharedStateUnavailable

log = logging.getLogger(__name__)

router = common.area_router("recommendations")

REC_ID_PATTERN: Final = r"^rec_[0-9A-Za-z]{1,64}$"
RULE_PATTERN: Final = r"^[A-Za-z0-9_-]{2,48}$"
DEFAULT_STATES: Final[tuple[str, ...]] = ("open",)
ALL_STATES: Final = "all"
FAMILIES: Final[tuple[str, ...]] = tuple(sorted({spec.family for spec in INSIGHT_RULES.values()}))
FILTER_TEXT_MAX: Final = 600
"""Longest comma-separated filter value (`state=open,snoozed`, `rule=UP-429-ENDPOINT,...`)."""

PREVIEW_WINDOWS_S: Final[dict[str, int]] = {"1h": 3600, "6h": 6 * 3600, "24h": 24 * 3600}
"""Dry-run windows (plan 11.3: the last hour by default, up to 24 h; `simulate.dry_run` caps at
`request_sample_hours`)."""
DRY_RUN_SLOTS: Final = 1
"""Dry runs one worker computes at once (each may replay `simulate.MAX_SAMPLES` samples)."""
DRY_RUN_QUEUE: Final = 4
"""Dry runs that may wait for a slot; one more is refused with 429 (plan P9)."""
DRY_RUN_CACHE_ENTRIES: Final = 32
DRY_RUN_CACHE_S: Final = 60.0
"""How long a dry-run result is reused for the same recommendation, changes, window and configuration."""
MAX_SNOOZE_S: Final = 90 * 86_400
"""Latest `until` a snooze may name (the presets are 1 hour, 1 day and 1 week)."""
MAX_DRAWER_OPEN: Final = 20
"""Open recommendations of one rule listed in its tuning drawer."""
MAX_HISTORY_ON_DETAIL: Final = 50
"""Actions shown in the detail drawer (the full list is `GET /{id}/history`)."""

SETTING_TARGET: Final = "setting:"
SENSITIVE_GROUPS: Final[frozenset[Group]] = settings_api.FRESH_MFA_GROUPS
"""Settings groups whose change (or its undo) needs a fresh second factor when a recommendation makes it (plan
9.6). The one rule is `settings.needs_fresh_mfa` (these groups, sensitive settings and `settings.FRESH_MFA_SETTINGS`),
shared with the settings editor (finding apisec-1), so the two lists can never drift."""

_ACTION_ERRORS: Final[dict[str, tuple[int, str]]] = {
    "not_found": (404, "not_found"),
    "conflict": (409, "wrong_state"),
    "busy": (409, "wrong_state"),
    "changed": (409, "changed_since_preview"),
    "superseded": (409, "superseded"),
    "invalid": (422, "invalid_change"),
    "manual": (422, "manual_change"),
}
"""`ActionError.code` -> (status, section 13 code). A busy hot.db is not an `ActionError`: the action raises
`SharedStateUnavailable`, which `common.service_errors` answers as 503 `unavailable`."""

CHANGED_MESSAGE: Final = ACTION_CHANGED_MESSAGE

LIST_TABLE: Final = TableSpec(
    name="recommendations",
    columns=(
        Column("id", "Id", "The recommendation's id (rec_...).", sortable=False),
        Column("severity", "Severity", "critical, warn or info (most severe first by default)."),
        Column("title", "Recommendation", "What the rule found, in one line.", sortable=False, caller_text=True),
        Column("rule_id", "Rule", "The rule that made it (plan 11.5)."),
        Column(
            "family",
            "Family",
            "upstream, cache, egress, credential, abuse, filter, system, security, host.",
            sortable=False,
        ),
        Column(
            "subject",
            "Subject",
            "What it is about: an endpoint, a client, a rule row, a setting.",
            sortable=False,
            caller_text=True,
        ),
        Column("state", "State", "open, snoozed, applied, auto_applied, rolled_back, dismissed, resolved, expired."),
        Column("confidence", "Confidence", "How sure the rule is, from the amount of evidence.", sortable=False),
        Column("risk", "Risk", "How risky the proposed change is.", sortable=False),
        Column("expected_impact", "Expected impact", "What the change should do, with numbers.", sortable=False),
        Column("updated_at", "Updated", "When the evidence or state last changed (Unix seconds).", "timestamp"),
        Column("created_at", "Created", "When the rule first raised it (Unix seconds).", "timestamp"),
        Column("expires_at", "Expires", "When it expires without action (Unix seconds).", "timestamp"),
    ),
    default_sort="severity",
)

HISTORY_TABLE: Final = TableSpec(
    name="recommendation_actions",
    columns=(
        Column("id", "Action", "The action number."),
        Column("at", "When", "When it happened (Unix seconds).", "timestamp"),
        Column("action", "What", "apply, undo, snooze, dismiss, auto_apply or auto_rollback."),
        Column("recommendation_id", "Recommendation", "The recommendation it acted on.", sortable=False),
        Column("rule_id", "Rule", "The rule of that recommendation."),
        Column("title", "Title", "The recommendation's title.", sortable=False),
        Column("actor", "Who", "admin:<name>, or the automatic actor of auto-apply.", sortable=False),
        Column("summary", "Details", "What the action did, in short.", sortable=False),
    ),
    default_sort="at",
)

RULES_TABLE: Final = TableSpec(
    name="recommendation_rules",
    columns=(
        Column("id", "Rule", "The rule id (plan 11.5)."),
        Column("family", "Family", "The rule's family."),
        Column("title", "Detects", "What the rule looks for.", sortable=False),
        Column("enabled", "On", "Whether the rule runs (insight_<rule>_enabled)."),
        Column("severity_override", "Severity", "auto keeps the rule's own severity; else every result gets this."),
        Column("open", "Open", "Open recommendations of this rule right now.", "count"),
        Column("implemented", "Implemented", "Whether this build has the rule's code."),
        Column("safe_auto", "Safe to auto-apply", "Whether auto-apply may ever apply this rule's changes."),
    ),
    default_sort="order",
    default_order="asc",
    extra_sort_keys=("order",),
)


# ================================================================================================ helpers


def engine_for(request: Request) -> InsightsEngine:
    """The engine of this worker: `ctx.insights` once the lifespan wires it, else one that only reads the tables
    (built without rules: listing, previewing and acting never evaluate a rule)."""
    ctx = get_ctx(request)
    wired = getattr(ctx, "insights", None)
    if isinstance(wired, InsightsEngine):
        return wired
    return InsightsEngine(dbs=ctx.dbs, settings=ctx.settings, rules=ctx.rules, clock=ctx.clock, rule_set={})


def actions_for(request: Request) -> RecommendationActions:
    """The audited actions of this worker (`ctx.insight_actions` when wired), over the same services the settings
    API (`settings.settings_service`, fingerprints keyed like every other writer) and the rules APIs use."""
    ctx = get_ctx(request)
    wired = getattr(ctx, "insight_actions", None)
    if isinstance(wired, RecommendationActions):
        return wired
    return RecommendationActions(
        engine=engine_for(request),
        settings_service=settings_api.settings_service(ctx),
        rules_service=RulesService(ctx.dbs.control, clock=ctx.clock, store=ctx.rules),
        clock=ctx.clock,
    )


def action_error(exc: ActionError) -> common.ApiError:
    """The section 13 error of an action refusal (`ActionError.code`, see `_ACTION_ERRORS`)."""
    status, code = _ACTION_ERRORS.get(exc.code, (422, "invalid_change"))
    return common.ApiError(status, code, exc.message, fields=exc.fields)


async def _act[T](call: Awaitable[T]) -> T:
    """Await an action, mapping its refusals (and the services' own) to section 13 errors."""
    try:
        with common.service_errors():
            return await call
    except ActionError as exc:
        raise action_error(exc) from exc


def _spec_of_target(target: str) -> SettingSpec | None:
    if not target.startswith(SETTING_TARGET):
        return None
    return catalog.CATALOG.get(target[len(SETTING_TARGET) :])


def safe_value(target: str, value: Any) -> Any:
    """A value as the API may show it: a sensitive setting's value is `[redacted]` (settings editor rule)."""
    return settings_api.shown(_spec_of_target(target), value)


def _change_target(change: Mapping[str, Any]) -> str:
    kind = str(change.get("kind") or "")
    if kind in ("setting", "host_add"):
        return f"{SETTING_TARGET}{change.get('key') or ''}"
    if kind == "tarpit_category":
        return f"{SETTING_TARGET}tarpit_on_{change.get('category') or ''}"
    return ""


def safe_payload(rec: Recommendation) -> dict[str, Any]:
    """The plan 11.2 object, with sensitive setting values redacted in its changes."""
    payload = rec.to_payload()
    changes: list[dict[str, Any]] = []
    for change in payload.get("changes") or []:
        item = dict(change)
        target = _change_target(item)
        for name in ("current", "proposed"):
            if name in item:
                item[name] = safe_value(target, item[name])
        changes.append(item)
    payload["changes"] = changes
    return payload


def _epoch(value: float | None) -> int | None:
    return None if value is None else int(value)


def card(rec: Recommendation) -> dict[str, Any]:
    """One list row: what the Recommendations table and the bell show (times as Unix seconds)."""
    kinds = list(rec.change_kinds)
    return {
        "id": rec.id,
        "rule_id": rec.rule_id,
        "family": rec.family,
        "subject": rec.subject,
        "severity": rec.severity,
        "computed_severity": rec.computed_severity or rec.severity,
        "confidence": rec.confidence,
        "title": rec.title,
        "expected_impact": rec.expected_impact,
        "risk": rec.risk,
        "safe_auto": rec.safe_auto,
        "state": rec.state,
        "created_at": _epoch(rec.created_at),
        "updated_at": _epoch(rec.updated_at),
        "expires_at": _epoch(rec.expires_at),
        "snoozed_until": _epoch(rec.snoozed_until),
        "dismissed_reason": rec.dismissed_reason,
        "change_kinds": kinds,
        "manual": "manual" in kinds,
        "dry_run_available": rec.dry_run_available,
        "url": f"{common.API_PREFIX}/recommendations/{rec.id}",
    }


def _split(raw: str | None, *, allowed: Iterable[str], field_name: str, fields: dict[str, str]) -> tuple[str, ...]:
    """A comma-separated filter checked against a closed vocabulary (one message per bad filter)."""
    if raw is None or not raw.strip():
        return ()
    values = tuple(dict.fromkeys(part.strip() for part in raw.split(",") if part.strip()))
    known = tuple(allowed)
    unknown = [value for value in values if value not in known]
    if unknown:
        fields[field_name] = f"Unknown value {unknown[0][:60]!r}; choose from: {', '.join(known)}."
    if len(values) > reads.MAX_FILTER_VALUES:
        fields[field_name] = f"Name at most {reads.MAX_FILTER_VALUES} values."
    return values


def _rule_id(raw: str) -> str | None:
    """A rule id from its id (`UP-429-ENDPOINT`) or slug (`up_429_endpoint`), or None."""
    text = raw.strip()
    if text in INSIGHT_RULES:
        return text
    for rule_id, spec in INSIGHT_RULES.items():
        if spec.slug == text.lower():
            return rule_id
    return None


@dataclass(frozen=True, slots=True)
class ListFilters:
    """The validated filters of the list."""

    states: tuple[str, ...]
    severities: tuple[str, ...]
    families: tuple[str, ...]
    rule_ids: tuple[str, ...]

    def as_read(self, q: str) -> reads.RecommendationFilter:
        rule_ids = set(self.rule_ids)
        if self.families:
            by_family = {rid for rid, spec in INSIGHT_RULES.items() if spec.family in self.families}
            rule_ids = (rule_ids & by_family) if rule_ids else by_family
            if not rule_ids:
                rule_ids = {"*none*"}  # the families name no rule: nothing matches
        return reads.RecommendationFilter(self.states, self.severities, tuple(sorted(rule_ids)), q)

    def echo(self) -> dict[str, list[str]]:
        return {
            "state": list(self.states) or [ALL_STATES],
            "severity": list(self.severities),
            "family": list(self.families),
            "rule": list(self.rule_ids),
        }


async def list_filters(
    state: Annotated[str | None, Query(max_length=FILTER_TEXT_MAX)] = None,
    severity: Annotated[str | None, Query(max_length=FILTER_TEXT_MAX)] = None,
    family: Annotated[str | None, Query(max_length=FILTER_TEXT_MAX)] = None,
    rule: Annotated[str | None, Query(max_length=FILTER_TEXT_MAX)] = None,
) -> ListFilters:
    """The list filters (comma-separated values; `state=all` for every state)."""
    fields: dict[str, str] = {}
    if state is not None and state.strip() == ALL_STATES:
        states: tuple[str, ...] = ()
    elif state is None:
        states = DEFAULT_STATES
    else:
        states = _split(state, allowed=STATES, field_name="state", fields=fields)
    severities = _split(severity, allowed=SEVERITIES, field_name="severity", fields=fields)
    families = _split(family, allowed=FAMILIES, field_name="family", fields=fields)
    rule_ids = _split(rule, allowed=INSIGHT_RULES, field_name="rule", fields=fields)
    if fields:
        raise common.validation_error(fields, "The filters are not valid.", code="invalid_filter")
    return ListFilters(states, severities, families, rule_ids)


ListFiltersDep = Annotated[ListFilters, Depends(list_filters)]


def _counts(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Facet counts: by state, and by severity, family and rule among open recommendations (the bell)."""
    by_state = dict.fromkeys(STATES, 0)
    open_severity = dict.fromkeys(SEVERITIES, 0)
    open_family = dict.fromkeys(FAMILIES, 0)
    open_rule: dict[str, int] = {}
    for row in rows:
        count = int(row["count"])
        by_state[str(row["state"])] = by_state.get(str(row["state"]), 0) + count
        if row["state"] != "open":
            continue
        open_severity[str(row["severity"])] = open_severity.get(str(row["severity"]), 0) + count
        spec = INSIGHT_RULES.get(str(row["rule_id"]))
        family = spec.family if spec is not None else "other"
        open_family[family] = open_family.get(family, 0) + count
        open_rule[str(row["rule_id"])] = open_rule.get(str(row["rule_id"]), 0) + count
    return {
        "open": by_state.get("open", 0),
        "by_state": by_state,
        "open_by_severity": open_severity,
        "open_by_family": open_family,
        "open_by_rule": open_rule,
    }


async def _get(request: Request, rec_id: str) -> Recommendation:
    row = await get_ctx(request).dbs.metrics.read(lambda conn: reads.get_row(conn, rec_id))
    if row is None:
        raise common.not_found("No recommendation has that id.")
    return row_to_recommendation(row)


# ------------------------------------------------------------------------------------------- the rule catalog


def _metadata(rules: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        rule_id: {"help": rule.help_text, "safe_auto": bool(rule.safe_auto), "triggers": sorted(rule.triggers)}
        for rule_id, rule in rules.items()
    }


@functools.lru_cache(maxsize=1)
def _implemented() -> dict[str, dict[str, Any]]:
    """Help text, `safe_auto` and triggers of every rule this build implements (rules are code: read once)."""
    return _metadata(load_rules())


def _rule_meta(request: Request) -> dict[str, dict[str, Any]]:
    """The implemented rules' metadata: the worker's engine's rules when wired, else the rule package's.

    A rule module that fails to import is a bug the leader's engine reports at startup; here it only costs the
    help texts (every rule then shows its catalog title and `implemented: false`), so the drawer stays usable.
    """
    wired = getattr(get_ctx(request), "insights", None)
    rules = getattr(wired, "rules", None)
    if isinstance(wired, InsightsEngine) and rules:
        return _metadata(rules)
    try:
        return _implemented()
    except Exception:
        log.exception("insight_rules_unavailable")
        return {}


def rule_keys(spec: InsightRuleSpec) -> list[str]:
    """The catalog settings of one rule: its switch, its severity override and one per threshold (plan 11.1)."""
    keys = [f"insight_{spec.slug}_enabled", f"insight_{spec.slug}_severity"]
    keys.extend(f"insight_{spec.slug}_{param.name}" for param in spec.params)
    return [key for key in keys if key in catalog.CATALOG]


def rule_card(
    rule_id: str, snapshot: Any, meta: Mapping[str, Mapping[str, Any]], open_counts: Mapping[str, int]
) -> dict[str, Any]:
    """One rule as the tuning list shows it (current values from this worker's settings snapshot)."""
    spec = INSIGHT_RULES[rule_id]
    known = meta.get(rule_id)
    slug = spec.slug
    params = []
    for param in spec.params:
        key = f"insight_{slug}_{param.name}"
        params.append(
            {
                "name": param.name,
                "key": key,
                "label": param.label,
                "unit": param.unit,
                "value": snapshot[key] if key in catalog.CATALOG else None,
                "default": param.default,
                "min": param.min,
                "max": param.max,
            }
        )
    enabled_key = f"insight_{slug}_enabled"
    severity_key = f"insight_{slug}_severity"
    return {
        "id": rule_id,
        "slug": slug,
        "family": spec.family,
        "title": spec.title,
        "help": known["help"] if known else spec.title,
        "implemented": known is not None,
        "safe_auto": bool(known["safe_auto"]) if known else False,
        "triggers": list(known["triggers"]) if known else [],
        "enabled": bool(snapshot[enabled_key]) if enabled_key in catalog.CATALOG else True,
        "severity_override": str(snapshot[severity_key]) if severity_key in catalog.CATALOG else "auto",
        "params": params,
        "open": int(open_counts.get(rule_id, 0)),
        "anchor": f"recommendations#rule-{slug}",
        "settings": {
            "enabled": enabled_key,
            "severity": severity_key,
            "params": {param.name: f"insight_{slug}_{param.name}" for param in spec.params},
        },
        "url": f"{common.API_PREFIX}/recommendations/rules/{rule_id}",
    }


# ------------------------------------------------------------------------------------- what an action needs


def _sensitive(target: str, before: Any, after: Any) -> bool:
    """Whether writing `after` over `before` touches the admin's security (see the module docstring).

    A credential allowlist row that exists afterwards widens (or changes) what the credential is used for, as the
    credential allowlist API's create and update do (fresh second factor); removing one only narrows it.
    """
    spec = _spec_of_target(target)
    if spec is not None:
        return settings_api.needs_fresh_mfa(spec)
    table = target.split(":", 1)[0]
    if table == "access_list":
        return any(isinstance(row, Mapping) and str(row.get("kind")) == "allow_admin" for row in (before, after))
    return table == "credential_allowlist" and after is not None


def sensitive_targets(items: Iterable[PreviewItem | AppliedChange], *, undo: bool = False) -> list[str]:
    """The targets among a preview or an applied change list that need a fresh second factor. With `undo`, the
    direction is reversed: an undo writes each change's `before` back (undoing a removal creates the row again)."""
    return [
        item.target
        for item in items
        if (
            _sensitive(item.target, item.after, item.before)
            if undo
            else _sensitive(item.target, item.before, item.after)
        )
    ]


def risky_keys(items: Iterable[PreviewItem]) -> list[str]:
    """Setting keys an apply would set to a high-risk value (they need `confirm_high_risk` and a reason)."""
    out: list[str] = []
    for item in items:
        spec = _spec_of_target(item.target)
        if spec is not None and item.valid and settings_api.risk_reason(spec, item.after):
            out.append(spec.key)
    return out


def preview_item(item: PreviewItem) -> dict[str, Any]:
    out = item.to_dict()
    out["before"] = safe_value(item.target, item.before)
    out["after"] = safe_value(item.target, item.after)
    return out


def applied_item(item: AppliedChange | Mapping[str, Any]) -> dict[str, Any]:
    out = item.to_dict() if isinstance(item, AppliedChange) else dict(item)
    target = str(out.get("target") or "")
    out["before"] = safe_value(target, out.get("before"))
    out["after"] = safe_value(target, out.get("after"))
    return out


def allowed_actions(rec: Recommendation) -> dict[str, dict[str, Any]]:
    """What can be done with a recommendation now, and why not (the drawer's buttons)."""
    active = rec.state in ACTIVE_STATES
    manual = "manual" in rec.change_kinds
    not_open = f"It is {rec.state}; only open or snoozed recommendations can be changed."
    apply_why = not_open if not active else ("It needs a manual change; there is nothing to apply." if manual else None)
    if active and not manual and not rec.changes:
        apply_why = "It proposes no change."
    undo_why = (
        None if rec.state in APPLIED_STATES else f"It is {rec.state}; only applied recommendations can be undone."
    )
    return {
        "preview": {"allowed": True, "why": None},
        "apply": {"allowed": apply_why is None, "why": apply_why},
        "undo": {"allowed": undo_why is None, "why": undo_why},
        "snooze": {"allowed": active, "why": None if active else not_open},
        "dismiss": {"allowed": active, "why": None if active else not_open},
    }


def _summary(action: Mapping[str, Any]) -> str:
    details = action.get("details") or {}
    kind = action.get("action")
    if not isinstance(details, Mapping):
        return ""
    if kind in ("apply", "auto_apply"):
        count = len(details.get("changes") or [])
        reason = str(details.get("reason") or "")
        return f"{count} change{'s' if count != 1 else ''}" + (f": {reason}" if reason else "")
    if kind == "snooze":
        return f"until {details.get('until')}"
    if kind == "dismiss":
        text = str(details.get("text") or "")
        return str(details.get("reason") or "") + (f": {text}" if text else "")
    return str(details.get("reason") or "")


def history_item(action: Mapping[str, Any]) -> dict[str, Any]:
    """One action for the API (sensitive values in applied changes redacted)."""
    details = action.get("details")
    if isinstance(details, Mapping) and isinstance(details.get("changes"), list):
        details = {**details, "changes": [applied_item(change) for change in details["changes"]]}
    item = {
        "id": action["id"],
        "at": action["at"],
        "action": action["action"],
        "recommendation_id": action["recommendation_id"],
        "actor": common.clean_message(action.get("actor") or "", 120),
        "summary": common.clean_message(_summary(action), 300),
        "details": details,
    }
    for name in ("rule_id", "severity", "state", "title", "subject"):
        if name in action:
            item[name] = action[name]
    return item


# ------------------------------------------------------------------------------------------------- dry runs


@dataclass
class DryRunGate:
    """One worker's dry runs: `DRY_RUN_SLOTS` at once, `DRY_RUN_QUEUE` waiting, a small result cache (P9)."""

    slots: asyncio.Semaphore = field(default_factory=lambda: asyncio.Semaphore(DRY_RUN_SLOTS))
    waiting: int = 0
    cache: OrderedDict[tuple[Any, ...], tuple[float, dict[str, Any]]] = field(default_factory=OrderedDict)

    def cached(self, key: tuple[Any, ...], now: float) -> dict[str, Any] | None:
        found = self.cache.get(key)
        if found is None:
            return None
        at, report = found
        if now - at > DRY_RUN_CACHE_S or now < at:
            self.cache.pop(key, None)
            return None
        return report

    def keep(self, key: tuple[Any, ...], now: float, report: dict[str, Any]) -> None:
        self.cache[key] = (now, report)
        self.cache.move_to_end(key)
        while len(self.cache) > DRY_RUN_CACHE_ENTRIES:
            self.cache.popitem(last=False)

    async def run(self, compute: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        """Run `compute` on a worker thread once a slot is free (429 when `DRY_RUN_QUEUE` already wait).

        The slot is released when the THREAD finishes, not when the request ends: a thread cannot be stopped, so a
        canceled request (the client left, the deadline passed) must not let another replay start beside it.
        """
        if self.waiting >= DRY_RUN_QUEUE:
            raise common.rate_limited("Too many dry runs are waiting on this worker; try again in a moment.", 2)
        self.waiting += 1
        try:
            await self.slots.acquire()
        finally:
            self.waiting -= 1
        # The replay is pure Python over up to simulate.MAX_SAMPLES samples: a thread keeps the event loop free.
        task = asyncio.ensure_future(asyncio.to_thread(compute))
        task.add_done_callback(self._finished)
        return await asyncio.shield(task)

    def _finished(self, task: asyncio.Future[dict[str, Any]]) -> None:
        self.slots.release()
        if not task.cancelled():
            task.exception()  # retrieved, so a replay whose request is gone never logs "exception never retrieved"


def _gate(request: Request) -> DryRunGate:
    state = request.app.state
    gate = getattr(state, "recommendation_dry_runs", None)
    if not isinstance(gate, DryRunGate):
        gate = DryRunGate()
        state.recommendation_dry_runs = gate
    return gate


def _replay(engine: InsightsEngine, rec: Recommendation, window_s: int) -> dict[str, Any]:
    """Run `simulate.dry_run` (through the engine) on this thread with its own event loop; database reads still go
    through the databases' reader threads (`Database.read` works from any loop)."""
    report = asyncio.run(engine.dry_run(rec, window_s=window_s))
    return dict(report.to_dict())


async def dry_run(request: Request, rec: Recommendation, window_s: int) -> dict[str, Any]:
    """The 11.3 dry-run report of `rec` (cached briefly; see `DryRunGate`)."""
    ctx = get_ctx(request)
    if not simulate.can_simulate(rec):
        return {"available": False, "window_s": window_s, "note": "No change of this recommendation can be replayed."}
    gate = _gate(request)
    now = float(ctx.clock.monotonic())
    key = (rec.id, changes_digest(rec.changes), window_s, ctx.settings.version, getattr(ctx.rules, "version", None))
    found = gate.cached(key, now)
    if found is not None:
        return {**found, "cached": True}
    engine = engine_for(request)
    try:
        report = await gate.run(lambda: _replay(engine, rec, window_s))
    except (common.ApiError, SharedStateUnavailable):
        raise
    except Exception:
        log.exception("recommendation_dry_run_failed", extra={"fields": {"recommendation": rec.id}})
        return {
            "available": False,
            "window_s": window_s,
            "note": "The simulation failed on this worker; the diff above is still exact.",
        }
    report["computed_at"] = int(ctx.clock.now())
    gate.keep(key, now, report)
    return {**report, "cached": False}


# ================================================================================================= bodies


class ApplyBody(ApiBody):
    """`POST /{id}/apply`: the digest the preview showed, a reason, and the high-risk confirmation."""

    changes_digest: str = Field(pattern=r"^[0-9a-f]{16}$")
    reason: str = Field(default="", max_length=MAX_REASON_LENGTH)
    confirm_high_risk: bool = False


class ReasonBody(ApiBody):
    """`POST /{id}/undo`: an optional reason for the audit log."""

    reason: str = Field(default="", max_length=MAX_REASON_LENGTH)


class SnoozeBody(ApiBody):
    """`POST /{id}/snooze`: a preset (`1h`, `1d`, `1w`) or `until` (ISO 8601 or Unix seconds), not both."""

    duration: Literal["1h", "1d", "1w"] | None = None
    until: str | int | float | None = Field(default=None, union_mode="left_to_right")

    def until_text(self) -> str | None:
        """`until` as text for `common.parse_instant` (which bounds its length)."""
        return None if self.until is None else str(self.until)


class DismissBody(ApiBody):
    """`POST /{id}/dismiss`: a reason from the plan 11.3 dropdown; `other` also needs a text."""

    reason: Literal["not_accurate", "intended_behavior", "will_handle_manually", "other"]
    text: str = Field(default="", max_length=500)


RecId = Annotated[str, Path(pattern=REC_ID_PATTERN, max_length=72)]
WindowQuery = Annotated[Literal["1h", "6h", "24h"], Query()]


# ================================================================================================= routes


@router.get("", response_model=None)
async def list_recommendations(
    request: Request,
    admin: AdminSession,
    filters: ListFiltersDep,
    tq: Annotated[TableQuery, Depends(table_params(LIST_TABLE))],
    fmt: ExportFormatDep,
) -> Any:
    """The Recommendations table with its filters and counts (plan 14.1); `format=csv|json` downloads it."""
    ctx = get_ctx(request)
    wanted = filters.as_read(tq.q)

    def read_page(page: int, size: int) -> Awaitable[tuple[list[dict[str, Any]], int]]:
        return ctx.dbs.metrics.read(
            lambda conn: reads.list_page(
                conn, wanted, sort=tq.sort, descending=tq.descending, limit=size, offset=(page - 1) * size
            )
        )

    with common.service_errors():
        if fmt is not None:

            async def cards(page: int, size: int) -> tuple[list[dict[str, Any]], int]:
                rows, total = await read_page(page, size)
                return [card(row_to_recommendation(row)) for row in rows], total

            return await common.export_pages(request, admin, LIST_TABLE, cards, fmt, tq=tq, filters=filters.echo())
        rows, total = await read_page(tq.page, tq.page_size)
        facets = await ctx.dbs.metrics.read(reads.facets)
    answer = common.table_answer(LIST_TABLE, tq, [card(row_to_recommendation(row)) for row in rows], total)
    answer.update(
        filters=filters.echo(),
        counts=_counts(facets),
        vocabulary={
            "states": list(STATES),
            "severities": list(SEVERITIES),
            "families": list(FAMILIES),
            "dismiss_reasons": [{"value": k, "label": v} for k, v in DISMISS_REASONS.items()],
            "snooze": list(SNOOZE_DURATIONS_S),
            "preview_windows": list(PREVIEW_WINDOWS_S),
        },
        engine={
            "enabled": bool(ctx.settings.bool("insights_enabled")),
            "auto_apply": bool(ctx.settings.bool("insights_auto_apply")),
            "interval_s": ctx.settings.int("insights_interval_s"),
        },
    )
    return answer


@router.get("/history", response_model=None)
async def global_history(
    request: Request,
    admin: AdminSession,
    tq: Annotated[TableQuery, Depends(table_params(HISTORY_TABLE))],
    fmt: ExportFormatDep,
    action: Annotated[str | None, Query(max_length=FILTER_TEXT_MAX)] = None,
    rule: Annotated[str | None, Query(max_length=FILTER_TEXT_MAX)] = None,
    recommendation: Annotated[str | None, Query(pattern=REC_ID_PATTERN, max_length=72)] = None,
    from_: Annotated[str | None, Query(alias="from", max_length=common.MAX_TIME_TEXT)] = None,
    to: Annotated[str | None, Query(max_length=common.MAX_TIME_TEXT)] = None,
) -> Any:
    """Every apply, undo, snooze, dismiss, auto-apply and automatic rollback (plan 14.1 "history")."""
    ctx = get_ctx(request)
    fields: dict[str, str] = {}
    actions = _split(action, allowed=reads.ACTIONS, field_name="action", fields=fields)
    rule_ids = _split(rule, allowed=INSIGHT_RULES, field_name="rule", fields=fields)
    tz = str(ctx.settings.get("ui_timezone") or "UTC")
    bounds: dict[str, int | None] = {"from": None, "to": None}
    for name, raw in (("from", from_), ("to", to)):
        if raw is None:
            continue
        try:
            bounds[name] = int(common.parse_instant(raw, tz=tz))
        except ValueError as exc:
            fields[name] = str(exc)
    if fields:
        raise common.validation_error(fields, "The filters are not valid.", code="invalid_filter")

    def read_page(page: int, size: int) -> Awaitable[tuple[list[dict[str, Any]], int]]:
        return ctx.dbs.metrics.read(
            lambda conn: reads.history_page(
                conn,
                actions=actions,
                rule_ids=rule_ids,
                recommendation_id=recommendation,
                since=bounds["from"],
                until=bounds["to"],
                sort=tq.sort,
                descending=tq.descending,
                limit=size,
                offset=(page - 1) * size,
            )
        )

    echo = {"action": list(actions), "rule": list(rule_ids), "recommendation": recommendation, **bounds}
    with common.service_errors():
        if fmt is not None:

            async def items(page: int, size: int) -> tuple[list[dict[str, Any]], int]:
                rows, total = await read_page(page, size)
                return [history_item(row) for row in rows], total

            return await common.export_pages(request, admin, HISTORY_TABLE, items, fmt, tq=tq, filters=echo)
        rows, total = await read_page(tq.page, tq.page_size)
    answer = common.table_answer(HISTORY_TABLE, tq, [history_item(row) for row in rows], total)
    answer["filters"] = echo
    return answer


@router.get("/rules", response_model=None)
async def list_rules(
    request: Request,
    admin: AdminSession,
    tq: Annotated[TableQuery, Depends(table_params(RULES_TABLE))],
    fmt: ExportFormatDep,
    family: Annotated[str | None, Query(max_length=FILTER_TEXT_MAX)] = None,
) -> Any:
    """Every rule of the catalog with its switch, severity override, thresholds and open count (plan 11.1)."""
    ctx = get_ctx(request)
    fields: dict[str, str] = {}
    families = _split(family, allowed=FAMILIES, field_name="family", fields=fields)
    if fields:
        raise common.validation_error(fields, "The filters are not valid.", code="invalid_filter")
    snapshot = ctx.settings.snapshot()
    with common.service_errors():
        facets = await ctx.dbs.metrics.read(reads.facets)
    open_counts = _counts(facets)["open_by_rule"]
    meta = _rule_meta(request)
    rows = []
    for order, rule_id in enumerate(INSIGHT_RULES):
        if families and INSIGHT_RULES[rule_id].family not in families:
            continue
        item = rule_card(rule_id, snapshot, meta, open_counts)
        item["order"] = order
        rows.append(item)
    if fmt is not None:
        everything, total = common.page_rows(rows, TableQuery(1, common.MAX_EXPORT_ROWS, tq.sort, tq.order, tq.q))
        return await common.export_table(
            request, admin, RULES_TABLE, everything, fmt, total=total, tq=tq, filters={"family": list(families)}
        )
    items, total = common.page_rows(rows, tq, search_keys=("id", "slug", "family", "title"))
    answer = common.table_answer(RULES_TABLE, tq, items, total)
    answer.update(
        families=list(FAMILIES),
        implemented=sum(1 for row in rows if row["implemented"]),
        insights_enabled=bool(ctx.settings.bool("insights_enabled")),
    )
    return answer


async def _setting_entries(request: Request, keys: Sequence[str]) -> list[dict[str, Any]]:
    """Settings editor rows (`settings.entry`) for `keys`: value, default, range, texts, last change."""
    ctx = get_ctx(request)
    snapshot = ctx.settings.snapshot()
    wanted = list(keys)
    with common.service_errors():
        latest = await ctx.dbs.control.read(lambda conn: read_settings.latest_changes(conn, wanted))
        recommended = await ctx.dbs.metrics.read(open_setting_recommendations)
    return [
        settings_api.entry(catalog.CATALOG[key], snapshot, latest=latest, recommendations=recommended)
        for key in wanted
        if key in catalog.CATALOG
    ]


SAVE_HINT: Final = {
    "method": "PATCH",
    "url": f"{common.API_PREFIX}/settings",
    "body": {"changes": {"<key>": "<value>"}, "reason": "<why>"},
}
"""Where tuning edits go: the settings API (validated, audited, hot-reloaded)."""


@router.get("/rules/{rule}")
async def rule_drawer(
    request: Request, rule: Annotated[str, Path(pattern=RULE_PATTERN)], _admin: AdminSession
) -> dict[str, Any]:
    """One rule's "Tune this rule" drawer: its settings as editor rows and its open recommendations."""
    rule_id = _rule_id(rule)
    if rule_id is None:
        raise common.not_found("No recommendation rule has that id.")
    ctx = get_ctx(request)
    spec = INSIGHT_RULES[rule_id]
    snapshot = ctx.settings.snapshot()
    filters = reads.RecommendationFilter(states=tuple(sorted(ACTIVE_STATES)), rule_ids=(rule_id,))
    with common.service_errors():
        facets = await ctx.dbs.metrics.read(reads.facets)
        rows, total = await ctx.dbs.metrics.read(lambda conn: reads.list_page(conn, filters, limit=MAX_DRAWER_OPEN))
    entries = await _setting_entries(request, rule_keys(spec))
    return {
        "rule": rule_card(rule_id, snapshot, _rule_meta(request), _counts(facets)["open_by_rule"]),
        "settings": entries,
        "active": {"items": [card(row_to_recommendation(row)) for row in rows], "total": total},
        "save": SAVE_HINT,
        "config_version": snapshot.version,
    }


@router.get("/settings")
async def engine_settings(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """The engine card (`recommendations#engine`) and the preview card (`recommendations#preview-settings`)."""
    cards: dict[str, list[str]] = {"engine": [], "preview": []}
    for key, spec in catalog.CATALOG.items():
        if "recommendations#engine" in spec.pages:
            cards["engine"].append(key)
        elif "recommendations#preview-settings" in spec.pages:
            cards["preview"].append(key)
    return {
        "engine": await _setting_entries(request, cards["engine"]),
        "preview": await _setting_entries(request, cards["preview"]),
        "save": SAVE_HINT,
        "config_version": get_ctx(request).settings.version,
    }


@router.get("/{rec_id}")
async def detail(request: Request, rec_id: RecId, _admin: AdminSession) -> dict[str, Any]:
    """The detail drawer of one recommendation (see the module docstring)."""
    ctx = get_ctx(request)
    rec = await _get(request, rec_id)
    with common.service_errors():
        actions = await ctx.dbs.metrics.read(lambda conn: reads.actions_of(conn, rec.id, limit=MAX_HISTORY_ON_DETAIL))
        watch = await ctx.dbs.metrics.read(lambda conn: reads.watch_of(conn, rec.id))
        earlier = await ctx.dbs.metrics.read(
            lambda conn: reads.same_fingerprint(conn, rec.fingerprint, exclude_id=rec.id)
        )
        facets = await ctx.dbs.metrics.read(reads.facets)
    rule = None
    if rec.rule_id in INSIGHT_RULES:
        open_counts = _counts(facets)["open_by_rule"]
        rule = rule_card(rec.rule_id, ctx.settings.snapshot(), _rule_meta(request), open_counts)
    base = f"{common.API_PREFIX}/recommendations/{rec.id}"
    return {
        "recommendation": safe_payload(rec),
        "card": card(rec),
        "changes_digest": changes_digest(rec.changes),
        "allowed": allowed_actions(rec),
        "rule": rule,
        "history": [history_item(action) for action in actions],
        "watch": watch,
        "earlier": earlier,
        "dismiss_reasons": [{"value": k, "label": v} for k, v in DISMISS_REASONS.items()],
        "snooze": list(SNOOZE_DURATIONS_S),
        "links": {
            "preview": f"{base}/preview",
            "apply": f"{base}/apply",
            "undo": f"{base}/undo",
            "snooze": f"{base}/snooze",
            "dismiss": f"{base}/dismiss",
            "history": f"{base}/history",
            "tune": f"{common.API_PREFIX}/recommendations/rules/{rec.rule_id}",
        },
    }


@router.get("/{rec_id}/history")
async def detail_history(request: Request, rec_id: RecId, _admin: AdminSession) -> dict[str, Any]:
    """Every action taken on one recommendation, newest first (bounded by `read_recommendations.MAX_ACTIONS`)."""
    rec = await _get(request, rec_id)
    with common.service_errors():
        actions = await get_ctx(request).dbs.metrics.read(lambda conn: reads.actions_of(conn, rec.id))
    return {
        "id": rec.id,
        "items": [history_item(action) for action in actions],
        "capped": len(actions) >= reads.MAX_ACTIONS,
    }


@router.get("/{rec_id}/preview")
async def preview(request: Request, rec_id: RecId, _admin: AdminSession, window: WindowQuery = "1h") -> dict[str, Any]:
    """The dry run of plan 11.3: the validated diff, what an apply needs, and the replay over request samples."""
    rec = await _get(request, rec_id)
    items = await _act(actions_for(request).preview(rec.id))
    diff = [preview_item(item) for item in items]
    risky = risky_keys(items)
    sensitive = sensitive_targets(items)
    report = await dry_run(request, rec, PREVIEW_WINDOWS_S[window])
    return {
        "id": rec.id,
        "state": rec.state,
        "changes_digest": changes_digest(rec.changes),
        "diff": diff,
        "ok": all(item.valid for item in items) and bool(items),
        "requires": {
            "reason": bool(risky),
            "confirm_high_risk": bool(risky),
            "high_risk_keys": risky,
            "fresh_mfa": bool(sensitive),
            "sensitive_targets": sensitive,
        },
        "window": window,
        "dry_run": report,
    }


async def _fresh_if(request: Request, admin: AdminPrincipal, needed: bool) -> AdminPrincipal:
    """The `fresh_mfa` guard, only when the action touches the admin's security (plan 9.6)."""
    if not needed:
        return admin
    fresh: AdminPrincipal = await common.admin_fresh_mfa(request)
    return fresh


@router.post("/{rec_id}/apply")
async def apply(
    request: Request, rec_id: RecId, body: ApplyBody, admin: AdminSession, _csrf: CsrfChecked
) -> dict[str, Any]:
    """Apply every change of an open recommendation, exactly as previewed (plan 11.3, P4)."""
    rec = await _get(request, rec_id)
    actions = actions_for(request)
    items = await _act(actions.preview_of(rec))  # the diff of exactly the changes whose digest is compared below
    admin = await _fresh_if(request, admin, bool(sensitive_targets(items)))
    if body.changes_digest != changes_digest(rec.changes):
        raise common.conflict(CHANGED_MESSAGE, code="changed_since_preview")
    if rec.state not in ACTIVE_STATES:
        raise common.conflict(f"This recommendation is {rec.state}; only open ones can be applied.", code="wrong_state")
    if not rec.changes:
        raise common.validation_error(
            {}, "This recommendation proposes no change; there is nothing to apply.", code="nothing_to_apply"
        )
    reason = settings_api.check_risk(risky_keys(items), reason=body.reason, confirmed=body.confirm_high_risk)
    # The risk and second factor decisions above hold for this digest only; the action checks it again inside the
    # recommendation's lease, after any evaluation that rewrote the proposal (409 changed_since_preview then).
    result: ActionResult = await _act(
        actions.apply(
            rec.id,
            actor_for(admin),
            reason,
            request_id=request_id_of(request),
            expected_digest=body.changes_digest,
        )
    )
    with common.service_errors():
        watch = await get_ctx(request).dbs.metrics.read(lambda conn: reads.watch_of(conn, rec.id))
    return {
        "recommendation": card(result.recommendation),
        "action": result.action,
        "action_id": result.action_id,
        "applied": [applied_item(change) for change in result.changes],
        "watch": watch,
    }


async def _last_applied(request: Request, rec_id: str) -> list[AppliedChange]:
    """What the last apply of a recommendation wrote (from its action row), for the undo's fresh MFA check."""
    actions = await get_ctx(request).dbs.metrics.read(lambda conn: reads.actions_of(conn, rec_id))
    for action in actions:
        if action["action"] in ("apply", "auto_apply") and isinstance(action.get("details"), Mapping):
            changes = action["details"].get("changes") or []
            return [AppliedChange(**change) for change in changes if isinstance(change, Mapping)]
    return []


@router.post("/{rec_id}/undo")
async def undo(
    request: Request, rec_id: RecId, body: ReasonBody, admin: AdminSession, _csrf: CsrfChecked
) -> dict[str, Any]:
    """Revert exactly what the last apply wrote; refused (409 `superseded`) when a key changed since."""
    rec = await _get(request, rec_id)
    with common.service_errors():
        applied = await _last_applied(request, rec.id)
    admin = await _fresh_if(request, admin, bool(sensitive_targets(applied, undo=True)))
    reason = common.require_reason(body.reason, required=False)
    result: ActionResult = await _act(actions_for(request).undo(rec.id, actor_for(admin), reason))
    return {
        "recommendation": card(result.recommendation),
        "action": result.action,
        "action_id": result.action_id,
        "reverted": [applied_item(change) for change in result.changes],
    }


@router.post("/{rec_id}/snooze")
async def snooze(
    request: Request, rec_id: RecId, body: SnoozeBody, admin: AdminSession, _csrf: CsrfChecked
) -> dict[str, Any]:
    """Hide an open recommendation for 1 hour, 1 day, 1 week, or until a time (plan 11.3)."""
    ctx = get_ctx(request)
    if (body.duration is None) == (body.until is None):
        message = "Choose a snooze length (1h, 1d or 1w) or an until time, not both."
        raise common.validation_error({"duration": message}, message)
    until: float | None = None
    text = body.until_text()
    if text is not None:
        try:
            until = common.parse_instant(text, tz=str(ctx.settings.get("ui_timezone") or "UTC"))
        except ValueError as exc:
            raise common.validation_error({"until": str(exc)}) from None
        now = ctx.clock.now()
        if until <= now:
            raise common.validation_error({"until": "Choose a time in the future."})
        if until - now > MAX_SNOOZE_S:
            raise common.validation_error({"until": f"Snooze for at most {MAX_SNOOZE_S // 86_400} days."})
    rec = await _get(request, rec_id)
    snoozed = await _act(actions_for(request).snooze(rec.id, actor_for(admin), duration=body.duration, until=until))
    return {"recommendation": card(snoozed)}


@router.post("/{rec_id}/dismiss")
async def dismiss(
    request: Request, rec_id: RecId, body: DismissBody, admin: AdminSession, _csrf: CsrfChecked
) -> dict[str, Any]:
    """Close a recommendation with a reason; its fingerprint stays quiet for `dismiss_cooldown_days` (11.3)."""
    ctx = get_ctx(request)
    rec = await _get(request, rec_id)
    dismissed = await _act(actions_for(request).dismiss(rec.id, actor_for(admin), body.reason, body.text))
    quiet_s = float(ctx.settings.get("dismiss_cooldown_days")) * 86_400
    return {
        "recommendation": card(dismissed),
        "quiet_until": int((dismissed.updated_at or ctx.clock.now()) + quiet_s),
        "reopens_if": "its severity rises above the dismissed one",
    }


__all__ = [
    "FAMILIES",
    "HISTORY_TABLE",
    "LIST_TABLE",
    "RULES_TABLE",
    "SENSITIVE_GROUPS",
    "DryRunGate",
    "action_error",
    "actions_for",
    "allowed_actions",
    "card",
    "engine_for",
    "risky_keys",
    "router",
    "rule_card",
    "rule_keys",
    "safe_payload",
    "sensitive_targets",
]
