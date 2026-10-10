"""The Protection page API (`/admin/api/v1/protection`): switches, bans, lists, limits, rules, detectors, tarpit.

What this is
    The routes behind plan 14.1 "Protection" and the top-bar switches, in the DESIGN.md section 13 shapes:
      * Switches: pause with a message and a scheduled window, throttle-all with its limit, period and "since"
        marker, each with the text callers get and the refusals since the state began (rows 49, 114, 115); the
        throttle-all watch with v1's columns (requests and refusals since it began, rates, busiest endpoint, last
        seen; row 135).
      * Bans with countdowns and evidence; create, lift one, lift a subject; the plan 6.8 "bans only" reset with a
        preview. Deny list, admin allowlist and bypass entries (CIDR, expiry with the `bypass_default_expiry_h`
        default, "never" needs confirmation, "Bypass my IP" with the address Roxy resolved, row 113).
      * Throttle: every Protection setting (`PATCH /settings`, restricted to settings shown on this page, with the
        settings editor's high-risk confirmation, plus reset to default), the ladder editor with reset to defaults
        (rows 40, 125), the strike board with forgive one and all (row 41), who is throttled right now (row 118),
        the throttled history, and the plan 6.8 limiter reset.
      * Rules: User-Agent rules with ordering and the dry-run tester (row 44), request filters with the tester and
        presets (row 45), endpoint blocks and endpoint rules (rows 43, 46) with their attempts tabs (row 75), ignored
        paths (row 50). Rule and list rows carry their hits in the range and since they were added (plan 10.9), and
        `GET /rule-hits` charts one row's hits over time.
      * Detectors and heuristics: spam detector states, dry-run results and the FILTER-COLLATERAL preview required
        before arming (plan 10.3), the tarpit state with the effective cap fields (row 123) and the fleet's hold
        statistics for the range (row 78), bot heuristics and the challenge state (plan 10.7, 10.8).
      * The pipeline diagram with per-check refusal counts and per-table rule hits for the range, the `ua_rule_hit`
        and `throttle_tier` counters (row 76), and refusals by reason (row 116).

Why it exists
    v1 spread these over a dozen `/admin/...` POST endpoints with ad hoc answers. Here every route follows one
    convention (section 13): `require_admin("session")` on everything, `require_csrf` on every change, bodies that
    refuse unknown fields, changes through the services that write the audit row and bump `config_version` in the
    same transaction, paged tables that export as CSV or JSON, and errors as `{"error": {code, message, fields}}`.

How it works
    - Reads call the read models next to their data: `abuse/*` (states, strike board, watches, testers),
      `abuse/read_bans.py`, `abuse/read_spam.py`, `metrics/read_protection.py` and `metrics/queries.py`.
    - Rule and list changes go through `rules/service.py RulesService` (validation, caps, duplicates, audit,
      `config_version`); settings through `config/settings_service.py`; the switches through `abuse/pause.py` and
      `abuse/throttle_all.py`, whose `ValueError` (a dash in a caller-visible message, an empty window) is a 422.
    - Three changes have no service function yet and are composed here from public helpers, each in ONE transaction
      with its audit row: the bulk bans reset (control.db: delete, audit, `config_version`), and forgiving strikes and
      resetting limiter state (hot.db rows; the audit row goes to control.db right after, because one SQLite
      transaction cannot span two files; the audit row records the exact counts). The report asks the integrator to
      move them into their owning modules.
    - Units in column metadata: `count`, `requests`, `seconds`, `percent`, `timestamp` (epoch seconds) and
      `timestamp_ms` (epoch milliseconds); text columns have none. Client address columns are `ip=True`, so exports
      hash them unless `export_include_ips` is on.
    - Tables backed by SQL are sorted by the read model; tables of a few hundred rule rows are sorted in memory.

What to read next
    `roxy/admin/api/common.py` (the shared layer), `roxy/abuse/pipeline.py` (what these settings drive), then
    `roxy/admin/api/clients.py` and `roxy/admin/api/security.py`.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import sqlite3
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import replace
from typing import Annotated, Any, Final, Literal

from fastapi import Depends, Path, Query, Request
from pydantic import ConfigDict, Field, field_validator

from roxy.abuse import read_bans, read_spam
from roxy.abuse.blocks import match_block
from roxy.abuse.bot import SIGNALS
from roxy.abuse.bypass import add_bypass, bypass_my_ip
from roxy.abuse.endpoint_rules import match_endpoint_rule
from roxy.abuse.header_rules import (
    MAX_TEST_HEADERS,
    MAX_TEST_NAME,
    MAX_TEST_VALUE,
    explain_header_rules,
    parse_header_text,
)
from roxy.abuse.messages import checked_state_reason, downtime_default
from roxy.abuse.pause import STATE_KEY as PAUSE_KEY
from roxy.abuse.pause import PauseState, clear_schedule, schedule_pause, set_pause
from roxy.abuse.read_spam import COLLATERAL_WINDOW_S, SERVED_PCT_SETTING
from roxy.abuse.state import read_state_value
from roxy.abuse.tarpit import ARRIVAL_PREFIX, RETRY_PREFIX
from roxy.abuse.throttle import forgive, ladder_from, strike_board, throttle_watch
from roxy.abuse.throttle_all import STATE_KEY as THROTTLE_ALL_KEY
from roxy.abuse.throttle_all import ThrottleAllState, set_throttle_all, throttle_all_watch
from roxy.abuse.ua_rules import explain_user_agent_rules
from roxy.admin.api import settings as settings_api
from roxy.admin.api.common import (
    AdminFreshMfa,
    AdminSession,
    ApiBody,
    Column,
    CsrfChecked,
    ExportFormat,
    ExportFormatDep,
    TableQuery,
    TableSpec,
    TimeRange,
    TimeRangeDep,
    actor_for,
    add_caller_text,
    area_router,
    conflict,
    export_pages,
    export_table,
    not_found,
    page_rows,
    parse_instant,
    request_id_of,
    require_reason,
    run_mutation,
    series_answer,
    service_errors,
    table_answer,
    table_params,
    unavailable,
    validation_error,
)
from roxy.admin.auth.deps import AdminPrincipal
from roxy.config import audit
from roxy.config.catalog import CATALOG, DASH_MESSAGE, EM_DASH, EN_DASH, SettingValidationError, validate_value
from roxy.config.constants import MAX_REASON_LENGTH, TARPIT_CATEGORIES
from roxy.config.runtime import bump_config_version
from roxy.config.settings_service import SettingsService, service_for
from roxy.deps import get_ctx
from roxy.metrics import queries, read_producers, read_protection, security_events
from roxy.metrics.annotate import insert_annotation
from roxy.metrics.read_clients import client_totals
from roxy.metrics.read_protection import CHECK_REASONS
from roxy.rules.match import regex_budget
from roxy.rules.service import RuleChange, RulesService
from roxy.storage.db import SharedStateUnavailable

log = logging.getLogger(__name__)

router = area_router("protection")

PAGE_PREFIX: Final = "protection#"
"""Settings whose catalog `pages` name a Protection card may be changed here (plan 14.1, 15.6)."""
ARM_ONLY_SETTING: Final = "spam_dry_run"
MAX_SETTING_CHANGES: Final = 120
MAX_TEXT_HEADERS: Final = 65_536
"""Most characters of pasted header text the request filter tester reads (200 headers of plain size)."""
MAX_RECENT_SAMPLES: Final = 40
"""v1 offered the 40 most recent live requests as tester samples."""
HEADER_EXAMPLE: Final[tuple[tuple[str, str], ...]] = (
    ("User-Agent", "Roblox/WinInet"),
    ("Xeno-Fingerprint", "4f3a91c0"),
    ("Accept", "*/*"),
    ("Content-Type", "application/json"),
)
"""v1's "Use an example" lines (`dashboard.js:4732-4737`)."""
BAN_RESET_CONFIRM: Final = "all bans"
LIMITER_RESET_CONFIRM: Final = "limiter state"
MAX_BAN_MINUTES: Final = 365 * 24 * 60
MAX_EXPIRY_HOURS: Final = 24 * 3650.0
TARPIT_LABELS: Final[dict[str, str]] = {
    "header_rule": "Caught by a Request Filter",
    "probe": "Not a Roblox URL",
    "throttle": "Per-IP rate limit",
    "throttle_all": "Global throttle-all",
    "endpoint_rule": "Per-endpoint rate rule",
    "blocked_endpoint": "Blocked endpoint",
    "auth_attempt": "Sent a ROBLOSECURITY cookie",
    "user_agent_rule": "Hit a client (User-Agent) rule",
    "ban": "Banned or denied client",
    "spam": "Flagged by a spam detector",
    "upstream_cooldown_retry": "Retried inside its Retry-After",
}
"""The category labels of the tarpit card (v1 `TARPIT_CATEGORY_LABELS`, plus the categories v2 added)."""

HIT_COLUMNS: Final[tuple[Column, ...]] = (
    Column(
        "hits",
        "Hits",
        "Requests this row matched in the range, whatever the verdict (plan 10.9).",
        "requests",
        sortable=False,
    ),
    Column("hits_total", "Hits (all time)", "Requests this row matched since it was added.", "requests"),
    Column("last_hit_at", "Last hit", "When a request last matched this row; empty: never.", "timestamp"),
)
"""Per-rule hit columns of the rule and list tables (`metrics/read_protection.py rule_hit_columns`): the hit history
FILTER-REMOVE and SEC-BYPASS-FOREVER read, shown next to each row."""
RULE_HIT_TABLES: Final[dict[str, str]] = {
    "ua-rules": "rules_user_agent",
    "header-rules": "rules_header",
    "endpoint-blocks": "rules_endpoint_block",
    "endpoint-rules": "rules_endpoint_limit",
    "access": "access_list",
    "bans": "bans",
}
"""`GET /rule-hits` table names (the page's route names) to the rule tables the abuse checks report hits for
(`abuse/checks/base.py MATCH_TABLES`)."""


# =============================================================================================== small helpers


def _ctx(request: Request) -> Any:
    return get_ctx(request)


def _abuse(ctx: Any) -> Any:
    """The worker's abuse pipeline, or 503 while the worker is still starting (C7: no guessing)."""
    pipeline = getattr(ctx, "abuse", None)
    if pipeline is None:
        raise unavailable("The abuse layer is not running yet; try again in a moment.")
    return pipeline


def _rules(ctx: Any) -> RulesService:
    return RulesService(ctx.dbs.control, clock=ctx.clock, store=ctx.rules)


def _settings_service(ctx: Any) -> SettingsService:
    return service_for(ctx)  # the keyed service every settings writer shares (fingerprints compare)


def _now(ctx: Any) -> int:
    return int(ctx.clock.now())


def _range_ms(tr: TimeRange) -> tuple[int, int]:
    return tr.window.start * 1000, tr.window.end * 1000


def _setting(ctx: Any, key: str) -> Any:
    return ctx.settings.get(key)


def audit_reason(text: str | None, *, required: bool = False) -> str:
    """An audit reason: bounded, no dash or control characters (plan C5); required for high-risk changes."""
    value = require_reason(text, required=required)
    if EM_DASH in value or EN_DASH in value:
        raise validation_error({"reason": DASH_MESSAGE})
    if any(ord(char) < 32 and char not in "\n\t" for char in value):
        raise validation_error({"reason": "The reason contains a control character."})
    return value


def _switch_error(exc: ValueError, field: str = "message") -> Exception:
    """The switch writers' `ValueError` (a dash in a caller-visible text, an empty window) as a 422."""
    text = str(exc) or "The value is not valid."
    return validation_error({field: text}, text, code="validation_failed")


def _single_order(tq: TableQuery, order: str = "desc") -> None:
    """Tables whose read model sorts in SQL by one fixed order refuse the other one (no silent re-sort)."""
    if tq.order != order:
        raise validation_error(
            {"order": f"This table is listed in one order only ({order})."}, code="invalid_table_query"
        )


Fetch = Callable[[int, int], Awaitable[tuple[Sequence[Any], int]]]


def _with_extra(answer: dict[str, Any], extra: Mapping[str, Any] | None) -> dict[str, Any]:
    """`answer` with a route's extra fields; an extra `caller_text` is added to the columns the table declared, never
    put in their place (`common.add_caller_text`, finding secfix-5)."""
    if extra:
        fields = dict(extra)
        caller_text = fields.pop("caller_text", None)
        answer.update(fields)
        if caller_text:
            add_caller_text(answer, caller_text)
    return answer


async def _table_or_export(
    request: Request,
    admin: AdminPrincipal,
    spec: TableSpec,
    tq: TableQuery,
    fmt: ExportFormat | None,
    fetch: Fetch,
    *,
    filters: Mapping[str, Any] | None = None,
    tr: TimeRange | None = None,
    extra: Mapping[str, Any] | None = None,
) -> Any:
    """A paged read model as a section 13 table, or every page of it as a CSV or JSON download."""
    if fmt is not None:
        return await export_pages(request, admin, spec, fetch, fmt, tq=tq, filters=filters, tr=tr)
    items, total = await fetch(tq.page, tq.page_size)
    return _with_extra(table_answer(spec, tq, items, total), extra)


async def _list_or_export(
    request: Request,
    admin: AdminPrincipal,
    spec: TableSpec,
    tq: TableQuery,
    fmt: ExportFormat | None,
    rows: Sequence[Mapping[str, Any]],
    *,
    search_keys: Sequence[str] = (),
    filters: Mapping[str, Any] | None = None,
    tr: TimeRange | None = None,
    extra: Mapping[str, Any] | None = None,
) -> Any:
    """A small in-memory list (rule rows) as a table, searched, sorted and paged here, or exported whole."""
    if fmt is not None:
        everything, total = page_rows(rows, replace(tq, page=1, page_size=max(1, len(rows))), search_keys=search_keys)
        return await export_table(request, admin, spec, everything, fmt, total=total, tq=tq, filters=filters, tr=tr)
    items, total = page_rows(rows, tq, search_keys=search_keys)
    return _with_extra(table_answer(spec, tq, items, total), extra)


async def _with_rule_hits(ctx: Any, table: str, rows: list[dict[str, Any]], tr: TimeRange) -> None:
    """Fill `HIT_COLUMNS` on rule or list rows of `table` (keyed by the row id, as the abuse checks report hits)."""
    start, end = tr.window.start, tr.window.end
    with service_errors():
        hits = await ctx.dbs.metrics.read(lambda conn: read_protection.rule_hit_columns(conn, table, start, end))
    for row in rows:
        found = hits.get(str(row.get("id")), {})
        row["hits"] = int(found.get("hits") or 0)
        row["hits_total"] = int(found.get("hits_total") or 0)
        row["last_hit_at"] = found.get("last_hit_at")


async def _audit_row(
    ctx: Any,
    admin: AdminPrincipal,
    request: Request,
    action: str,
    target: str,
    *,
    before: Any = None,
    after: Any = None,
    reason: str = "",
) -> int:
    """One audit row in control.db for a change made in another database (hot.db), written right after it."""
    actor = actor_for(admin)
    now = _now(ctx)
    request_id = request_id_of(request)

    def write(conn: sqlite3.Connection) -> int:
        return audit.record(
            conn, actor, action, target, before, after, reason or None, request_id, at=now, secret=False
        )

    try:
        audit_id: int = await ctx.dbs.control.write(write)
    except SharedStateUnavailable:
        log.error("protection_audit_failed", extra={"fields": {"action": action, "target": target}})
        raise unavailable(
            "The change was made, but its audit row could not be written because control.db is busy; "
            "the server log has the details."
        ) from None
    return audit_id


async def _annotate(ctx: Any, label: str, audit_id: int | None) -> None:
    """A chart marker for a state reset (plan 6.8). Kind `config_change`: no counters were deleted, so it must not
    make KPI tiles claim partial data (which a `reset` marker does). Best effort: a busy metrics.db only logs."""
    at = _now(ctx)

    def write(conn: sqlite3.Connection) -> None:
        insert_annotation(conn, at, "config_change", label, audit_id)

    try:
        await ctx.dbs.metrics.write(write, busy_timeout_ms=1000)
    except SharedStateUnavailable:
        log.warning("protection_annotation_failed", extra={"fields": {"label": label[:80]}})


def _change(change: RuleChange) -> dict[str, Any]:
    """What a rules service write did, for the answer."""
    return {
        "action": change.action,
        "key": change.key,
        "changed": change.changed,
        "item": change.after,
        "before": change.before if change.action in ("update", "delete") else None,
        "config_version": change.config_version,
        "audit_id": change.audit_id,
        "warnings": list(change.warnings),
    }


# =============================================================================================== pause


class PauseBody(ApiBody):
    """Switch the pause on or off (`paused` null toggles) and optionally replace the message callers get."""

    paused: bool | None = None
    message: str | None = Field(None, max_length=MAX_REASON_LENGTH)


class ScheduleBody(ApiBody):
    """A maintenance window `[start, end)`: ISO 8601 (no offset: `ui_timezone`) or epoch seconds."""

    start: str | int = Field(union_mode="left_to_right")
    end: str | int = Field(union_mode="left_to_right")
    message: str = Field("", max_length=MAX_REASON_LENGTH)


async def _drops_since(ctx: Any, reason: str, since: float) -> int | None:
    """Refusals with `reason` since `since` (row 114), from the rollups; None when there is no "since"."""
    if since <= 0:
        return None
    now = ctx.clock.now()
    return int(await ctx.dbs.metrics.read(lambda conn: queries.drops_since(conn, reason, since, now)))


async def _pause_view(ctx: Any, state: PauseState) -> dict[str, Any]:
    now = ctx.clock.now()
    text, source = state.message(now, str(_setting(ctx, "pause_message_default") or ""))
    since = state.active_since(now)
    scheduled = None
    if state.scheduled_start is not None and state.scheduled_end is not None:
        scheduled = {
            "start": state.scheduled_start,
            "end": state.scheduled_end,
            "message": state.scheduled_reason,
            "by": state.scheduled_by,
            "in_window": state.in_scheduled_window(now),
            "ends_in_s": max(0, int(state.scheduled_end - now)),
        }
    return {
        "paused": state.paused,
        "active": state.active(now),
        "message": state.reason,
        "since": state.since or None,
        "active_since": since or None,
        "scheduled": scheduled,
        "callers_see": {"status": 503, "body": text, "message_source": source, "retry_after_s": state.retry_after(now)},
        "drops_since_start": await _drops_since(ctx, "paused", since),
    }


async def _read_pause(ctx: Any) -> PauseState:
    return PauseState.from_json(await ctx.dbs.control.read(lambda conn: read_state_value(conn, PAUSE_KEY)))


@router.get("/pause")
async def pause_state(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """The pause switch, the scheduled window, what callers get and the refusals since it began (rows 49, 114)."""
    ctx = _ctx(request)
    with service_errors():
        return await _pause_view(ctx, await _read_pause(ctx))


@router.post("/pause")
async def pause_set(request: Request, admin: AdminSession, _csrf: CsrfChecked, body: PauseBody) -> dict[str, Any]:
    """Pause or resume the proxy; switching it on starts a new "since" marker (row 114)."""
    ctx = _ctx(request)
    try:
        state = await run_mutation(
            set_pause(
                ctx.dbs.control,
                ctx.clock,
                actor_for(admin),
                paused=body.paused,
                reason=body.message,
                request_id=request_id_of(request),
            )
        )
    except ValueError as exc:
        raise _switch_error(exc) from None
    await _refresh_switches(ctx)
    return await _pause_view(ctx, state)


@router.put("/pause/schedule")
async def pause_schedule(
    request: Request, admin: AdminSession, _csrf: CsrfChecked, body: ScheduleBody
) -> dict[str, Any]:
    """Schedule a maintenance window (plan 4.3 row 49)."""
    ctx = _ctx(request)
    tz = str(_setting(ctx, "ui_timezone") or "UTC")
    fields: dict[str, str] = {}
    bounds: dict[str, int] = {}
    for name, raw in (("start", body.start), ("end", body.end)):
        try:
            bounds[name] = int(parse_instant(str(raw), tz=tz))
        except ValueError as exc:
            fields[name] = str(exc)
    if fields:
        raise validation_error(fields, "The scheduled window is not valid.")
    try:
        state = await run_mutation(
            schedule_pause(
                ctx.dbs.control,
                ctx.clock,
                actor_for(admin),
                start=bounds["start"],
                end=bounds["end"],
                reason=body.message,
                request_id=request_id_of(request),
            )
        )
    except ValueError as exc:
        field = "message" if DASH_MESSAGE in str(exc) or "character" in str(exc) else "end"
        raise _switch_error(exc, field) from None
    await _refresh_switches(ctx)
    return await _pause_view(ctx, state)


@router.delete("/pause/schedule")
async def pause_unschedule(request: Request, admin: AdminSession, _csrf: CsrfChecked) -> dict[str, Any]:
    """Remove the scheduled window (the manual switch is untouched)."""
    ctx = _ctx(request)
    state = await run_mutation(
        clear_schedule(ctx.dbs.control, ctx.clock, actor_for(admin), request_id=request_id_of(request))
    )
    await _refresh_switches(ctx)
    return await _pause_view(ctx, state)


async def _refresh_switches(ctx: Any) -> None:
    """Let this worker see its own switch change at once (the others follow `config_version` within a second)."""
    pipeline = getattr(ctx, "abuse", None)
    switches = getattr(pipeline, "switches", None)
    if switches is None:
        return
    try:
        await switches.refresh_if_changed()
    except SharedStateUnavailable:  # pragma: no cover - refresh_if_changed never raises for this
        log.warning("protection_switch_refresh_failed")


# =============================================================================================== throttle-all


class ThrottleAllBody(ApiBody):
    """Switch the emergency limit on or off (`enabled` null toggles); `limit` and `period` are its settings (a
    high-risk value of either needs `confirm_high_risk` and a reason, as in Settings)."""

    enabled: bool | None = None
    message: str | None = Field(None, max_length=MAX_REASON_LENGTH)
    limit: int | None = None
    period: int | None = None
    reason: str | None = Field(None, max_length=MAX_REASON_LENGTH)
    confirm_high_risk: bool = False


async def _throttle_all_view(ctx: Any, state: ThrottleAllState) -> dict[str, Any]:
    text, source = state.message(str(_setting(ctx, "pause_message_default") or ""))
    return {
        "enabled": state.enabled,
        "message": state.reason,
        "since": state.since or None,
        "limit": int(_setting(ctx, "global_throttle_limit")),
        "period": int(_setting(ctx, "global_throttle_period")),
        "callers_see": {"status": 429, "body": text, "message_source": source},
        "default_message": downtime_default(_setting(ctx, "pause_message_default")),
        "drops_since_start": await _drops_since(ctx, "throttle_all", state.since if state.enabled else 0),
    }


@router.get("/throttle-all")
async def throttle_all_state(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """The emergency per-IP limit: state, limit, "since" marker and refusals since it began (rows 42, 114, 115)."""
    ctx = _ctx(request)
    with service_errors():
        raw = await ctx.dbs.control.read(lambda conn: read_state_value(conn, THROTTLE_ALL_KEY))
        return await _throttle_all_view(ctx, ThrottleAllState.from_json(raw))


@router.post("/throttle-all")
async def throttle_all_set(
    request: Request, admin: AdminSession, _csrf: CsrfChecked, body: ThrottleAllBody
) -> dict[str, Any]:
    """Change the limit and period (settings service, refused values are a 422: v1 bug B16), then the switch."""
    ctx = _ctx(request)
    actor = actor_for(admin)
    request_id = request_id_of(request)
    reason = audit_reason(body.reason)
    if body.message is not None:
        try:
            checked_state_reason(body.message)  # refused before the limit changes, so nothing half applies
        except ValueError as exc:
            raise _switch_error(exc) from None
    changes = {
        key: value
        for key, value in (("global_throttle_limit", body.limit), ("global_throttle_period", body.period))
        if value is not None
    }
    if changes:
        # The settings editor's rules first (finding apisec-4), so a refused value changes nothing at all.
        await check_settings_change(request, ctx, changes, reason=reason, confirmed=body.confirm_high_risk)
        await run_mutation(
            _settings_service(ctx).update(
                changes,
                actor,
                reason or "throttle-all limit",
                request_id=request_id,
                guard=settings_api.write_rules(ctx, admin, confirmed=body.confirm_high_risk),
            )
        )
    try:
        state = await run_mutation(
            set_throttle_all(
                ctx.dbs.control, ctx.clock, actor, enabled=body.enabled, reason=body.message, request_id=request_id
            )
        )
    except ValueError as exc:
        raise _switch_error(exc) from None
    await _refresh_switches(ctx)
    return await _throttle_all_view(ctx, state)


WATCH_ALL_SPEC: Final = TableSpec(
    name="throttle_all_watch",
    columns=(
        Column(
            "ip",
            "Client",
            "The client key (IPv6 grouped by its network) hitting the emergency limit.",
            ip=True,
            sortable=False,
        ),
        Column("count", "Requests this window", "Requests counted in the current emergency window.", "count"),
        Column("limited", "Refused now", "Whether the client is over the emergency limit right now.", sortable=False),
        Column(
            "reset_in_s",
            "Window ends in",
            "Seconds until the client's emergency window starts again.",
            "seconds",
            sortable=False,
        ),
        Column(
            "requests",
            "Requests",
            "Requests from this client since throttle-all was switched on (counted from that minute).",
            "requests",
            sortable=False,
        ),
        Column(
            "refused",
            "Refused",
            "Of those, requests Roxy turned away (throttle-all or any other refusal).",
            "requests",
            sortable=False,
        ),
        Column(
            "rate1",
            "Rate",
            "Requests in the last 60 seconds (rate5 and rate60: last 5 and 60 minutes).",
            "count",
            sortable=False,
        ),
        Column("rate5", "Rate (5 min)", "Requests in the last 5 minutes.", "count", sortable=False),
        Column("rate60", "Rate (60 min)", "Requests in the last 60 minutes.", "count", sortable=False),
        Column(
            "top_endpoint",
            "Top endpoint",
            "What it asks for most since throttle-all began (each minute's busiest endpoint; caller text).",
            sortable=False,
            caller_text=True,
        ),
        Column(
            "last_seen_ms",
            "Last seen",
            "Its newest request: exact while its Live rows are kept (15 minutes), else the start of that minute.",
            "timestamp_ms",
            sortable=False,
        ),
    ),
    default_sort="count",
)
WATCH_ALL_CALLER_TEXT: Final = ("top_endpoint",)
WATCH_ACTIVITY_KEYS: Final = ("requests", "refused", "rate1", "rate5", "rate60", "top_endpoint", "last_seen_ms")


@router.get("/throttle-all/watch")
async def throttle_all_watch_table(
    request: Request,
    admin: AdminSession,
    tq: Annotated[TableQuery, Depends(table_params(WATCH_ALL_SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    """Who is hitting the emergency limit right now, fullest first (row 135), with v1's watch columns: requests and
    refusals since throttle-all began, rates, the busiest endpoint and when it was last seen (finding parity-4).

    The limiter rows (hot.db) pick and order the page; client activity (metrics.db) fills the v1 columns for that
    page only. A client key that is an IPv6 network has no per-address activity, so those columns are None there.
    """
    ctx = _ctx(request)
    _single_order(tq)
    limit_setting = int(_setting(ctx, "global_throttle_limit"))
    period = int(_setting(ctx, "global_throttle_period"))
    with service_errors():
        raw = await ctx.dbs.control.read(lambda conn: read_state_value(conn, THROTTLE_ALL_KEY))
    state = ThrottleAllState.from_json(raw)
    now = ctx.clock.now()
    # The "since" marker of the running emergency limit; with it off, the rows left are at most one period old.
    since = float(state.since) if state.enabled and state.since else now - period

    async def fetch(page: int, size: int) -> tuple[Sequence[Any], int]:
        offset = (page - 1) * size
        data = await throttle_all_watch(
            ctx.dbs.hot, now_ms=ctx.clock.now_ms(), limit_setting=limit_setting, limit=size, offset=offset
        )
        rows = [dict(row) for row in data["rows"]]
        keys = [str(row["ip"]) for row in rows]
        activity = await ctx.dbs.metrics.read(
            lambda conn: read_protection.watch_activity(conn, keys, since=since, now=now)
        )
        for row in rows:
            found = activity.get(str(row["ip"]), {})
            for key in WATCH_ACTIVITY_KEYS:
                row[key] = found.get(key)
        return rows, int(data["total"])

    with service_errors():
        return await _table_or_export(
            request,
            admin,
            WATCH_ALL_SPEC,
            tq,
            fmt,
            fetch,
            extra={"since": since, "caller_text": list(WATCH_ALL_CALLER_TEXT)},
        )


# =============================================================================================== bans


BAN_SPEC: Final = TableSpec(
    name="bans",
    columns=(
        Column("id", "Id", "The ban's number."),
        Column(
            "subject_type",
            "Type",
            "ip, cidr (a network), place (a Roblox-Id) or ua_hash (a User-Agent).",
            sortable=False,
        ),
        Column("subject", "Subject", "What is banned.", ip=True),
        Column("active", "Active", "Whether the ban is in force now.", sortable=False),
        Column("expires_in_s", "Ends in", "Seconds left; empty for a permanent ban.", "seconds", sortable=False),
        Column("expires_at", "Ends at", "When the ban ends; empty for a permanent ban.", "timestamp"),
        Column("created_at", "Created", "When the ban was created.", "timestamp"),
        Column("created_by", "Created by", "An admin, or auto:<detector> for an automatic ban.", sortable=False),
        Column("origin", "Origin", "manual or auto.", sortable=False),
        Column("hits", "Requests refused", "Requests this ban refused (counted every few seconds).", "count"),
        Column("last_hit_at", "Last refused", "When this ban last refused a request.", "timestamp"),
        Column("evidence", "Evidence", "The reason code and the text the creator stored.", sortable=False),
    ),
    default_sort="created_at",
)


class BanBody(ApiBody):
    """A manual ban. Give `minutes` for a temporary ban, or `permanent: true`."""

    subject_type: Literal["ip", "cidr", "place", "ua_hash"]
    subject: str = Field(min_length=1, max_length=200)
    minutes: int | None = Field(None, ge=1, le=MAX_BAN_MINUTES)
    permanent: bool = False
    message: str = Field("", max_length=MAX_REASON_LENGTH)
    reason: str | None = Field(None, max_length=MAX_REASON_LENGTH)


class LiftBody(ApiBody):
    """Lift every ban of one subject (active or expired)."""

    subject_type: Literal["ip", "cidr", "place", "ua_hash"]
    subject: str = Field(min_length=1, max_length=200)
    reason: str | None = Field(None, max_length=MAX_REASON_LENGTH)


class BanResetBody(ApiBody):
    """Plan 6.8 "bans only" reset. Scope `all` needs `confirm` typed as "all bans"."""

    scope: Literal["all", "auto", "expired", "detector"]
    detector: str | None = Field(None, max_length=64)
    confirm: str | None = Field(None, max_length=64)
    reason: str = Field(max_length=MAX_REASON_LENGTH)


@router.get("/bans")
async def bans_table(
    request: Request,
    admin: AdminSession,
    tq: Annotated[TableQuery, Depends(table_params(BAN_SPEC))],
    fmt: ExportFormatDep,
    state: Annotated[Literal["active", "expired", "all"], Query()] = "active",
    origin: Annotated[Literal["any", "manual", "auto"], Query()] = "any",
    detector: Annotated[str | None, Query(max_length=64)] = None,
    subject_type: Annotated[Literal["ip", "cidr", "place", "ua_hash"] | None, Query()] = None,
) -> Any:
    """Bans with countdowns and evidence (plan 10.9), filtered and paged in SQL."""
    ctx = _ctx(request)
    if detector is not None and detector not in read_bans.AUTO_DETECTORS:
        raise validation_error({"detector": f"Choose one of: {', '.join(read_bans.AUTO_DETECTORS)}."})
    now = _now(ctx)
    filters = {"state": state, "origin": origin, "detector": detector, "subject_type": subject_type}
    active_total: list[int] = [0]

    async def fetch(page: int, size: int) -> tuple[Sequence[Any], int]:
        data = await ctx.dbs.control.read(
            lambda conn: read_bans.ban_page(
                conn,
                now=now,
                state=state,
                origin=origin,
                detector=detector,
                subject_type=subject_type,
                search=tq.q,
                sort=tq.sort,
                descending=tq.descending,
                limit=size,
                offset=(page - 1) * size,
            )
        )
        active_total[0] = int(data["active_total"])
        return data["rows"], int(data["total"])

    with service_errors():
        answer = await _table_or_export(request, admin, BAN_SPEC, tq, fmt, fetch, filters=filters)
    if isinstance(answer, dict):
        answer["active_total"] = active_total[0]
        answer["disguised"] = bool(_setting(ctx, "ban_disguise_as_throttle"))
    return answer


@router.get("/bans/reset")
async def bans_reset_preview(
    request: Request,
    _admin: AdminSession,
    scope: Annotated[Literal["all", "auto", "expired", "detector"], Query()],
    detector: Annotated[str | None, Query(max_length=64)] = None,
) -> dict[str, Any]:
    """What a bans reset would delete, before anything is deleted (plan 6.8)."""
    ctx = _ctx(request)
    now = _now(ctx)
    try:
        read_bans.reset_scope(scope, now=now, detector=detector)
    except ValueError as exc:
        raise validation_error({"detector": str(exc)}) from None
    with service_errors():
        preview: dict[str, Any] = await ctx.dbs.control.read(
            lambda conn: read_bans.reset_preview(conn, scope, now=now, detector=detector)
        )
    preview["confirm_text"] = BAN_RESET_CONFIRM if scope == "all" else None
    preview["leaves_alone"] = "Deny list entries made by hand, rules and settings."
    return preview


@router.post("/bans/reset")
async def bans_reset(request: Request, admin: AdminSession, _csrf: CsrfChecked, body: BanResetBody) -> dict[str, Any]:
    """Delete bans by scope in ONE control.db transaction with its audit row and `config_version` bump (6.8)."""
    ctx = _ctx(request)
    reason = audit_reason(body.reason, required=True)
    if body.scope == "all" and (body.confirm or "").strip().lower() != BAN_RESET_CONFIRM:
        raise validation_error(
            {"confirm": f'Type "{BAN_RESET_CONFIRM}" to delete every ban.'}, code="confirmation_required"
        )
    now = _now(ctx)
    try:
        where, params = read_bans.reset_scope(body.scope, now=now, detector=body.detector)
    except ValueError as exc:
        raise validation_error({"detector": str(exc)}) from None
    actor = actor_for(admin)
    request_id = request_id_of(request)

    def write(conn: sqlite3.Connection) -> dict[str, Any]:
        preview = read_bans.reset_preview(conn, body.scope, now=now, detector=body.detector)
        if not preview["rows"]:
            return {**preview, "deleted": 0, "audit_id": None}
        deleted = conn.execute(f"DELETE FROM bans{where}", params).rowcount  # noqa: S608  # reset_scope constants
        audit_id = audit.record(
            conn,
            actor,
            "bans.reset",
            f"bans:{body.scope}" + (f":{body.detector}" if body.detector else ""),
            None,
            {"deleted": deleted, "active": preview["active"], "by_subject_type": preview["by_subject_type"]},
            reason,
            request_id,
            at=now,
            secret=False,
        )
        bump_config_version(conn, now)
        return {**preview, "deleted": int(deleted), "audit_id": audit_id}

    with service_errors():
        result: dict[str, Any] = await ctx.dbs.control.write(write)
    if result["deleted"]:
        await _reload_rules(ctx)
        await _annotate(ctx, f"Bans reset ({body.scope}): {result['deleted']} deleted", result["audit_id"])
    return result


async def _reload_rules(ctx: Any) -> None:
    try:
        await ctx.rules.reload()
    except SharedStateUnavailable:  # the change is committed; the config watcher catches up within a second
        log.warning("protection_rules_reload_failed")


@router.get("/bans/{ban_id}")
async def ban_detail(
    request: Request, _admin: AdminSession, ban_id: Annotated[int, Path(ge=1, le=2**62)]
) -> dict[str, Any]:
    """One ban with its evidence: the stored reason and the detector events about the subject."""
    ctx = _ctx(request)
    with service_errors():
        row = await ctx.dbs.control.read(lambda conn: read_bans.ban_row(conn, ban_id))
    if row is None:
        raise not_found("No ban has that id.")
    view = read_bans.ban_view(row, _now(ctx))
    events: list[dict[str, Any]] = []
    if view["subject_type"] in ("ip", "cidr"):
        subject = f"ip:{view['subject']}"
        try:
            events = await ctx.dbs.metrics.read(lambda conn: read_protection.subject_events(conn, subject))
        except SharedStateUnavailable:
            events = []
    view["detector_events"] = events
    return view


@router.post("/bans")
async def ban_create(request: Request, admin: AdminSession, _csrf: CsrfChecked, body: BanBody) -> dict[str, Any]:
    """Ban a subject by hand (an active ban of the same subject is extended instead, the later end wins)."""
    ctx = _ctx(request)
    if body.permanent == (body.minutes is not None):
        raise validation_error({"minutes": "Give the ban length in minutes, or set permanent (not both)."})
    expires_at = None if body.permanent else _now(ctx) + int(body.minutes or 0) * 60
    row = {
        "subject_type": body.subject_type,
        "subject": body.subject,
        "reason_code": "admin",
        "reason_text": body.message,
        "expires_at": expires_at,
    }
    change = await run_mutation(
        _rules(ctx).create("bans", row, actor_for(admin), audit_reason(body.reason), request_id=request_id_of(request))
    )
    answer = _change(change)
    answer["ban"] = read_bans.ban_view(change.after or {}, _now(ctx)) if change.after else None
    answer["extended_existing"] = change.action == "update"
    return answer


@router.post("/bans/lift")
async def ban_lift_subject(request: Request, admin: AdminSession, _csrf: CsrfChecked, body: LiftBody) -> dict[str, Any]:
    """Lift every ban of one subject ("unban this IP")."""
    ctx = _ctx(request)
    change = await run_mutation(
        _rules(ctx).unban(
            body.subject_type,
            body.subject,
            actor_for(admin),
            audit_reason(body.reason),
            request_id=request_id_of(request),
        )
    )
    return {"lifted": len(change.before or []), "subject": change.key, "config_version": change.config_version}


@router.delete("/bans/{ban_id}")
async def ban_lift(
    request: Request,
    admin: AdminSession,
    _csrf: CsrfChecked,
    ban_id: Annotated[int, Path(ge=1, le=2**62)],
    reason: Annotated[str | None, Query(max_length=MAX_REASON_LENGTH)] = None,
) -> dict[str, Any]:
    """Lift one ban by id."""
    ctx = _ctx(request)
    change = await run_mutation(
        _rules(ctx).delete("bans", ban_id, actor_for(admin), audit_reason(reason), request_id=request_id_of(request))
    )
    return _change(change)


# =============================================================================================== access lists


ACCESS_SPEC: Final = TableSpec(
    name="access_list",
    columns=(
        Column("id", "Id", "The entry's number."),
        Column("cidr", "Network", "An address (/32 or /128) or a CIDR range.", ip=True),
        Column("note", "Note", "Private note."),
        Column(
            "active",
            "Active",
            "False once the entry expired (it stays listed until retention removes it).",
            sortable=False,
        ),
        Column("expires_at", "Expires", "When the entry stops working; empty means never.", "timestamp"),
        Column("expires_in_s", "Expires in", "Seconds left; empty means never.", "seconds"),
        Column("created_by", "Added by", "Who added the entry."),
        Column("created_at", "Added", "When the entry was added.", "timestamp"),
        *HIT_COLUMNS,
    ),
    default_sort="created_at",
)


class AccessBody(ApiBody):
    """A deny, admin allowlist or bypass entry. Bypass entries expire after `bypass_default_expiry_h` unless
    `expires_in_h` says otherwise; `never: true` needs `confirm_never: true` (plan 4.1 row 6)."""

    cidr: str = Field(min_length=1, max_length=100)
    note: str = Field("", max_length=MAX_REASON_LENGTH)
    expires_in_h: float | None = Field(None, gt=0, le=MAX_EXPIRY_HOURS, allow_inf_nan=False)
    never: bool = False
    confirm_never: bool = False
    reason: str | None = Field(None, max_length=MAX_REASON_LENGTH)


def _access_view(row: Mapping[str, Any], now: int) -> dict[str, Any]:
    expires_at = row.get("expires_at")
    return {
        "id": int(row["id"]),
        "kind": row["kind"],
        "cidr": row["cidr"],
        "note": row.get("note") or "",
        "active": expires_at is None or int(expires_at) > now,
        "expires_at": expires_at,
        "expires_in_s": None if expires_at is None else max(0, int(expires_at) - now),
        "created_by": row.get("created_by") or "",
        "created_at": row.get("created_at"),
    }


async def _access_rows(ctx: Any, kind: str) -> list[dict[str, Any]]:
    now = _now(ctx)
    with service_errors():
        rows = await _rules(ctx).list_rows("access_list")
    return [_access_view(row, now) for row in rows if row["kind"] == kind]


def _covers(cidr: str, ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except (TypeError, ValueError):
        return False


@router.get("/access/bypass/me")
async def bypass_me_state(request: Request, admin: AdminSession) -> dict[str, Any]:
    """Your address as Roxy resolved it (plan 9.11; v1 "YourIP", row 113) and whether a bypass entry covers it."""
    ctx = _ctx(request)
    rows = await _access_rows(ctx, "bypass")
    covering = [row for row in rows if row["active"] and _covers(row["cidr"], admin.ip)]
    return {
        "ip": admin.ip,
        "bypassed": bool(covering),
        "entries": covering,
        "default_expiry_h": float(_setting(ctx, "bypass_default_expiry_h")),
    }


@router.post("/access/bypass/me")
async def bypass_me(request: Request, admin: AdminSession, _csrf: CsrfChecked) -> dict[str, Any]:
    """Bypass the admin's own address with the default expiry (row 113)."""
    ctx = _ctx(request)
    change = await run_mutation(
        bypass_my_ip(
            _rules(ctx),
            admin.ip,
            actor_for(admin),
            now=ctx.clock.now(),
            default_expiry_h=float(_setting(ctx, "bypass_default_expiry_h")),
            request_id=request_id_of(request),
        )
    )
    answer = _change(change)
    answer["ip"] = admin.ip
    return answer


@router.get("/access/{kind}")
async def access_table(
    request: Request,
    admin: AdminSession,
    kind: Literal["deny", "allow_admin", "bypass"],
    tr: TimeRangeDep,
    tq: Annotated[TableQuery, Depends(table_params(ACCESS_SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    """The deny list, the admin allowlist (D6) or the bypass list, each entry with its hits in the range and since
    it was added (`HIT_COLUMNS`; the admin allowlist is not an abuse check, so its entries record none)."""
    ctx = _ctx(request)
    rows = await _access_rows(ctx, kind)
    await _with_rule_hits(ctx, "access_list", rows, tr)
    extra: dict[str, Any] = {"kind": kind, "your_ip": admin.ip, "range": tr.info()}
    if kind == "bypass":
        extra["default_expiry_h"] = float(_setting(ctx, "bypass_default_expiry_h"))
    if kind == "allow_admin":
        extra["allowlist_enabled"] = bool(_setting(ctx, "admin_allowlist_enabled"))
    return await _list_or_export(
        request,
        admin,
        ACCESS_SPEC,
        tq,
        fmt,
        rows,
        search_keys=("cidr", "note", "created_by"),
        filters={"kind": kind},
        tr=tr,
        extra=extra,
    )


async def _add_access(request: Request, admin: AdminPrincipal, kind: str, body: AccessBody) -> dict[str, Any]:
    ctx = _ctx(request)
    reason = audit_reason(body.reason)
    actor = actor_for(admin)
    request_id = request_id_of(request)
    if kind == "bypass":
        call = add_bypass(
            _rules(ctx),
            body.cidr,
            actor,
            now=ctx.clock.now(),
            default_expiry_h=float(_setting(ctx, "bypass_default_expiry_h")),
            expires_in_h=body.expires_in_h,
            never=body.never,
            confirm_never=body.confirm_never,
            note=body.note,
            reason=reason,
            request_id=request_id,
        )
    else:
        if body.never and body.expires_in_h is not None:
            raise validation_error({"never": "Choose an expiry or never, not both."})
        expires_at = None if body.expires_in_h is None else int(ctx.clock.now() + body.expires_in_h * 3600)
        row = {"kind": kind, "cidr": body.cidr, "note": body.note, "expires_at": expires_at}
        call = _rules(ctx).create("access_list", row, actor, reason, request_id=request_id)
    change = await run_mutation(call)
    answer = _change(change)
    if change.after:
        answer["item"] = _access_view(change.after, _now(ctx))
    return answer


async def _delete_access(
    request: Request, admin: AdminPrincipal, kind: str, entry_id: int, reason: str | None, *, confirm_lockout: bool
) -> dict[str, Any]:
    ctx = _ctx(request)
    service = _rules(ctx)
    with service_errors():
        row = await service.get_row("access_list", entry_id)
    if row is None or row["kind"] != kind:
        raise not_found(f"No {kind.replace('_', ' ')} entry has that id.")
    if kind == "allow_admin" and bool(_setting(ctx, "admin_allowlist_enabled")) and not confirm_lockout:
        rest = [r for r in await _access_rows(ctx, "allow_admin") if r["id"] != entry_id and r["active"]]
        if _covers(row["cidr"], admin.ip) and not any(_covers(r["cidr"], admin.ip) for r in rest):
            raise validation_error(
                {
                    "confirm_lockout": f"Removing {row['cidr']} hides the dashboard from your own address ({admin.ip}) "
                    "while the admin allowlist is on; repeat with confirm_lockout=true if that is intended."
                },
                code="confirmation_required",
            )
    change = await run_mutation(
        service.delete(
            "access_list", entry_id, actor_for(admin), audit_reason(reason), request_id=request_id_of(request)
        )
    )
    return _change(change)


@router.post("/access/allow_admin")
async def allow_admin_add(
    request: Request, admin: AdminFreshMfa, _csrf: CsrfChecked, body: AccessBody
) -> dict[str, Any]:
    """Add an admin allowlist network (D6). A fresh second factor is required: the list decides who sees /admin."""
    return await _add_access(request, admin, "allow_admin", body)


@router.delete("/access/allow_admin/{entry_id}")
async def allow_admin_delete(
    request: Request,
    admin: AdminFreshMfa,
    _csrf: CsrfChecked,
    entry_id: Annotated[int, Path(ge=1, le=2**62)],
    reason: Annotated[str | None, Query(max_length=MAX_REASON_LENGTH)] = None,
    confirm_lockout: Annotated[bool, Query()] = False,
) -> dict[str, Any]:
    """Remove an admin allowlist network; refused when it would hide /admin from your own address."""
    return await _delete_access(request, admin, "allow_admin", entry_id, reason, confirm_lockout=confirm_lockout)


@router.post("/access/{kind}")
async def access_add(
    request: Request,
    admin: AdminSession,
    _csrf: CsrfChecked,
    kind: Literal["deny", "bypass"],
    body: AccessBody,
) -> dict[str, Any]:
    """Add a deny list or bypass entry (CIDR aware; bypass expiry defaults to `bypass_default_expiry_h`)."""
    return await _add_access(request, admin, kind, body)


@router.delete("/access/{kind}/{entry_id}")
async def access_delete(
    request: Request,
    admin: AdminSession,
    _csrf: CsrfChecked,
    kind: Literal["deny", "bypass"],
    entry_id: Annotated[int, Path(ge=1, le=2**62)],
    reason: Annotated[str | None, Query(max_length=MAX_REASON_LENGTH)] = None,
) -> dict[str, Any]:
    """Remove a deny list or bypass entry."""
    return await _delete_access(request, admin, kind, entry_id, reason, confirm_lockout=False)


# =============================================================================================== settings


class SettingsBody(ApiBody):
    """Changes to settings shown on the Protection page (`{key: value}`); a high-risk value needs a reason and
    `confirm_high_risk: true`, exactly as in the settings editor (one risk rule for every settings writer)."""

    changes: dict[str, Any]
    reason: str | None = Field(None, max_length=MAX_REASON_LENGTH)
    confirm_high_risk: bool = False

    @field_validator("changes")
    @classmethod
    def _bounded(cls, value: dict[str, Any]) -> dict[str, Any]:
        if not value:
            raise ValueError("Name at least one setting.")
        if len(value) > MAX_SETTING_CHANGES:
            raise ValueError(f"At most {MAX_SETTING_CHANGES} settings in one change.")
        return value


class SettingResetBody(ApiBody):
    """Put one Protection setting back to its catalog default (parity row 124)."""

    key: str = Field(min_length=1, max_length=100)
    reason: str | None = Field(None, max_length=MAX_REASON_LENGTH)


def protection_keys() -> list[str]:
    """Every catalog setting with a Protection card in its `pages` (plan 15.6)."""
    return sorted(key for key, spec in CATALOG.items() if any(page.startswith(PAGE_PREFIX) for page in spec.pages))


def _setting_view(ctx: Any, key: str) -> dict[str, Any]:
    spec = CATALOG[key]
    return {
        "key": key,
        "value": _setting(ctx, key),
        "default": spec.default,
        "label": spec.label,
        "pages": list(spec.pages),
        "risk": str(getattr(spec.risk, "value", spec.risk)),
    }


def _check_protection_keys(changes: Mapping[str, Any]) -> None:
    allowed = set(protection_keys())
    fields: dict[str, str] = {}
    for key, raw in changes.items():
        if key not in allowed:
            fields[key] = "Not a Protection setting; change it on its own page or in Settings."
            continue
        if key == ARM_ONLY_SETTING:
            try:
                armed = not bool(validate_value(key, raw))
            except SettingValidationError:
                continue  # the settings service reports the bad value itself
            if armed:
                fields[key] = (
                    "Turning dry run off arms automatic bans: review GET /protection/spam/collateral, then confirm "
                    "it with POST /protection/spam/arm."
                )
    if fields:
        raise validation_error(fields, "Some settings cannot be changed here.", code="invalid_settings")


async def check_settings_change(
    request: Request, ctx: Any, changes: Mapping[str, Any], *, reason: str | None, confirmed: bool
) -> None:
    """The settings editor's rules for a batch written from this page, in the editor's order.

    A key that needs a fresh second factor (`settings.require_fresh_for`, finding apisec-1: an admin security,
    credential or sensitive setting) answers 403 `reauth_required` with a stale factor; no Protection setting is one
    today, so this guards the future. A batch holding a high-risk value (a `high_risk_if` condition of the catalog,
    or a setting of risk `high`) is refused with 422 `confirmation_required` unless `confirmed`, and with 422 when it
    has no reason (DESIGN 13.1): the same `admin/api/settings.py preview_changes` and `check_risk` the editor,
    imports and reverts run, so the Protection page is never a way around them (finding apisec-4). A batch with an
    unknown or invalid value is left to the settings service, which refuses the whole batch with
    `invalid_settings` and saves nothing. These are the quick answers from this worker's snapshot; every write here
    also passes `settings.write_rules` as the service's guard, which judges the same rules again on what control.db
    holds inside the write (finding secfix-1).
    """
    checked = settings_api.preview_changes(changes, ctx.settings.snapshot())
    if checked["ok"]:
        await settings_api.require_fresh_for(request, settings_api.changing_keys(checked))
        settings_api.check_risk(checked["high_risk_keys"], reason=reason or "", confirmed=confirmed)


@router.get("/settings")
async def settings_list(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """Every setting shown on the Protection page with its live value, default and risk."""
    ctx = _ctx(request)
    return {"items": [_setting_view(ctx, key) for key in protection_keys()]}


@router.patch("/settings")
async def settings_change(
    request: Request, admin: AdminSession, _csrf: CsrfChecked, body: SettingsBody
) -> dict[str, Any]:
    """Change Protection settings through the settings service (validated, audited, `config_version` bumped).

    A high-risk value needs `confirm_high_risk: true` and a reason (`check_settings_change`), as in Settings.
    """
    ctx = _ctx(request)
    _check_protection_keys(body.changes)
    await check_settings_change(request, ctx, body.changes, reason=body.reason, confirmed=body.confirm_high_risk)
    result = await run_mutation(
        _settings_service(ctx).update(
            body.changes,
            actor_for(admin),
            audit_reason(body.reason),
            request_id=request_id_of(request),
            guard=settings_api.write_rules(ctx, admin, confirmed=body.confirm_high_risk),
        )
    )
    return {
        "changed": [change.key for change in result.changes],
        "unchanged": list(result.unchanged),
        "warnings": list(result.warnings),
        "config_version": result.config_version,
        "items": [_setting_view(ctx, key) for key in sorted(body.changes) if key in CATALOG],
    }


@router.post("/settings/reset")
async def settings_reset(
    request: Request, admin: AdminSession, _csrf: CsrfChecked, body: SettingResetBody
) -> dict[str, Any]:
    """Reset one Protection setting to its default (row 124); the editor's fresh-factor rule applies, as in
    `POST /settings/{key}/reset` (a reset to the catalog default needs no high-risk confirmation there either)."""
    ctx = _ctx(request)
    if body.key not in set(protection_keys()):
        raise validation_error({"key": "Not a Protection setting."}, code="invalid_settings")
    if ctx.settings.snapshot().is_overridden(body.key):  # the quick answer; the write's guard decides (secfix-1)
        await settings_api.require_fresh_for(request, [body.key])
    result = await run_mutation(
        _settings_service(ctx).reset_to_default(
            body.key,
            actor_for(admin),
            audit_reason(body.reason),
            request_id=request_id_of(request),
            guard=settings_api.write_rules(ctx, admin),
        )
    )
    return {
        "changed": [change.key for change in result.changes],
        "config_version": result.config_version,
        "item": _setting_view(ctx, body.key),
    }


# =============================================================================================== throttle and ladder


THROTTLE_KEYS: Final[tuple[str, ...]] = (
    "allowed_requests_per_minute",
    "throttle_reset_duration",
    "throttle_window_mode",
    "throttle_escalation_enabled",
    "throttle_strike_decay_seconds",
    "throttle_strike_on_retry",
    "throttle_count_cache_hits",
    "stale_ip_duration",
    "ipv6_limit_prefix",
    "flood_limit_per_minute",
    "place_limit_enabled",
    "place_limit_key",
    "place_limit_per_minute",
)


class TierBody(ApiBody):
    """One ladder rung (the service validates the ranges and the ban rule)."""

    multiplier: float = Field(allow_inf_nan=False)
    message: str = Field("", max_length=MAX_REASON_LENGTH)
    note: str = Field("", max_length=MAX_REASON_LENGTH)
    action: str = Field("throttle", max_length=16)
    ban_minutes: int | None = None


class LadderBody(ApiBody):
    """The whole ladder, rung 1 first (an empty list is a flat ladder)."""

    tiers: list[TierBody] = Field(max_length=50)
    reason: str | None = Field(None, max_length=MAX_REASON_LENGTH)


class ReasonBody(ApiBody):
    reason: str | None = Field(None, max_length=MAX_REASON_LENGTH)


async def _ladder_view(ctx: Any, tr: TimeRange | None) -> dict[str, Any]:
    with service_errors():
        rows = await _rules(ctx).list_rows("throttle_tiers")
    hits: dict[int, int] = {}
    if tr is not None:
        start, end = _range_ms(tr)
        hits = await ctx.dbs.metrics.read(lambda conn: read_protection.tier_hits(conn, start, end))
    window = int(_setting(ctx, "throttle_reset_duration"))
    rungs = []
    for row in rows:
        multiplier = float(row["multiplier"] or 1.0)
        rungs.append(
            {
                "position": int(row["position"]),
                "multiplier": multiplier,
                "message": row["message"] or "",
                "note": row["note"] or "",
                "action": row["action"] or "throttle",
                "ban_minutes": row["ban_minutes"],
                "wait_s": int(window * multiplier),
                "hits": hits.get(int(row["position"]), 0) if tr is not None else None,
            }
        )
    return {
        "rungs": rungs,
        "escalation_enabled": bool(_setting(ctx, "throttle_escalation_enabled")),
        "decay_s": int(_setting(ctx, "throttle_strike_decay_seconds")),
        "window_s": window,
        "range": tr.info() if tr is not None else None,
    }


@router.get("/throttle")
async def throttle_state(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """The per-IP limit, flood and place limits, and the ladder (rows 39, 40)."""
    ctx = _ctx(request)
    return {
        "settings": {key: _setting(ctx, key) for key in THROTTLE_KEYS},
        "ladder": await _ladder_view(ctx, None),
    }


@router.get("/ladder")
async def ladder_state(request: Request, _admin: AdminSession, tr: TimeRangeDep) -> dict[str, Any]:
    """The escalation ladder with each rung's wait and how many new strikes reached it in the range (row 76)."""
    return await _ladder_view(_ctx(request), tr)


@router.put("/ladder")
async def ladder_replace(request: Request, admin: AdminSession, _csrf: CsrfChecked, body: LadderBody) -> dict[str, Any]:
    """Replace the whole ladder (v1 `/admin/throttle/tiers`)."""
    ctx = _ctx(request)
    tiers = [tier.model_dump() for tier in body.tiers]
    change = await run_mutation(
        _rules(ctx).replace_throttle_tiers(
            tiers, actor_for(admin), audit_reason(body.reason), request_id=request_id_of(request)
        )
    )
    return {"changed": change.changed, "config_version": change.config_version, **await _ladder_view(ctx, None)}


@router.post("/ladder/reset")
async def ladder_reset(request: Request, admin: AdminSession, _csrf: CsrfChecked, body: ReasonBody) -> dict[str, Any]:
    """Restore the four shipped rungs (row 125, with the C5 replacement message)."""
    ctx = _ctx(request)
    change = await run_mutation(
        _rules(ctx).reset_throttle_tiers(actor_for(admin), audit_reason(body.reason), request_id=request_id_of(request))
    )
    return {"changed": change.changed, "config_version": change.config_version, **await _ladder_view(ctx, None)}


STRIKE_SPEC: Final = TableSpec(
    name="strike_board",
    columns=(
        Column("ip", "Client", "The client key carrying strikes.", ip=True, sortable=False),
        Column("strikes", "Strikes", "Strikes left after decay.", "count"),
        Column("tier", "Rung", "The ladder rung those strikes reach.", sortable=False),
        Column("multiplier", "Multiplier", "That rung's multiplier of the throttle window.", sortable=False),
        Column("message", "Message", "What that rung tells the caller.", sortable=False),
        Column("throttled", "Throttled now", "Whether a penalty is running.", sortable=False),
        Column("reset_in", "Penalty ends in", "Seconds left on the running penalty.", "seconds", sortable=False),
        Column("last_strike_at", "Last strike", "When the last strike was added.", "timestamp", sortable=False),
        Column(
            "decays_in", "Drops a rung in", "Seconds until one strike decays (0: never).", "seconds", sortable=False
        ),
    ),
    default_sort="strikes",
)


class ForgiveBody(ApiBody):
    """Forgive one client's strikes (`ip`) or everyone's (`all: true`). A running penalty is not lifted (v1 B19)."""

    ip: str | None = Field(None, max_length=64)
    all: bool = False
    reason: str | None = Field(None, max_length=MAX_REASON_LENGTH)


@router.get("/strikes")
async def strikes_table(
    request: Request,
    admin: AdminSession,
    tq: Annotated[TableQuery, Depends(table_params(STRIKE_SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    """The strike board, worst first, paged on the server (row 41)."""
    ctx = _ctx(request)
    _single_order(tq)
    with service_errors():
        ladder = ladder_from(_rules_snapshot(ctx).throttle_tiers)
    decay = int(_setting(ctx, "throttle_strike_decay_seconds"))

    async def fetch(page: int, size: int) -> tuple[Sequence[Any], int]:
        offset = (page - 1) * size
        data = await strike_board(ctx.dbs.hot, now_s=_now(ctx), decay_s=decay, ladder=ladder, limit=size, offset=offset)
        return data["rows"], int(data["total"])

    with service_errors():
        return await _table_or_export(request, admin, STRIKE_SPEC, tq, fmt, fetch)


def _rules_snapshot(ctx: Any) -> Any:
    return ctx.rules.snapshot


@router.post("/strikes/forgive")
async def strikes_forgive(
    request: Request, admin: AdminSession, _csrf: CsrfChecked, body: ForgiveBody
) -> dict[str, Any]:
    """Wipe strike history for one client or everyone (v1 forgive); audited with the count."""
    ctx = _ctx(request)
    who = (body.ip or "").strip()
    if bool(who) == body.all:
        raise validation_error({"ip": "Name one client in ip, or set all to forgive everyone (not both)."})
    reason = audit_reason(body.reason)
    with service_errors():
        forgiven = await forgive(ctx.dbs.hot, who or None)
    audit_id = await _audit_row(
        ctx, admin, request, "strikes.forgive", f"strikes:{who or 'all'}", after={"forgiven": forgiven}, reason=reason
    )
    return {"forgiven": forgiven, "scope": who or "all", "audit_id": audit_id}


WATCH_SPEC: Final = TableSpec(
    name="throttle_watch",
    columns=(
        Column("ip", "Client", "A client whose throttle penalty is running.", ip=True, sortable=False),
        Column("strikes", "Strikes", "Its strikes (before decay).", "count", sortable=False),
        Column("tier", "Rung", "The rung its last strike reached.", sortable=False),
        Column("time_left_s", "Time left", "Seconds until the penalty ends.", "seconds"),
    ),
    default_sort="time_left_s",
)


@router.get("/throttle/watch")
async def throttle_watch_table(
    request: Request,
    admin: AdminSession,
    tq: Annotated[TableQuery, Depends(table_params(WATCH_SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    """Who is being throttled right now, with time left, longest penalty first (row 118)."""
    ctx = _ctx(request)
    _single_order(tq)

    async def fetch(page: int, size: int) -> tuple[Sequence[Any], int]:
        offset = (page - 1) * size
        data = await throttle_watch(ctx.dbs.hot, now_s=_now(ctx), limit=size, offset=offset)
        return data["rows"], int(data["total"])

    with service_errors():
        return await _table_or_export(request, admin, WATCH_SPEC, tq, fmt, fetch)


THROTTLED_SPEC: Final = TableSpec(
    name="throttled_history",
    columns=(
        Column("ip", "Client", "A client that became throttled.", ip=True),
        Column("count", "Times throttled", "How often it became throttled in the range.", "count"),
        Column("last_ms", "Last throttled", "When it last became throttled.", "timestamp_ms"),
    ),
    default_sort="count",
)


@router.get("/throttle/history")
async def throttled_history(
    request: Request,
    admin: AdminSession,
    tr: TimeRangeDep,
    tq: Annotated[TableQuery, Depends(table_params(THROTTLED_SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    """Clients that became throttled in the range (v1 "Throttled IPs", row 80), most often first."""
    ctx = _ctx(request)
    start, end = _range_ms(tr)
    with service_errors():
        rows = await ctx.dbs.metrics.read(
            lambda conn: security_events.summary_by_ip(
                conn, security_events.THROTTLED, start, end, limit=read_protection.MAX_GROUPS
            )
        )
    return await _list_or_export(request, admin, THROTTLED_SPEC, tq, fmt, rows, search_keys=("ip",), tr=tr)


# --- limiter state reset (plan 6.8) ---------------------------------------------------------------------------


_KEPT_LIMITER_PREFIXES: Final = (ARRIVAL_PREFIX, RETRY_PREFIX)
"""Limiter rows that are tarpit bookkeeping, not limits: a limiter reset keeps them."""
_CLIENT_PREFIXES: Final = ("flood:", "tall:")
_CLIENT_SUFFIX_PREFIXES: Final = ("ep:", "ua:")


class LimiterResetBody(ApiBody):
    """Plan 6.8 "Limiter state": strikes, limiter buckets and throttle-all buckets, for everyone or one client.

    Unlike forgive, a reset also ends running penalties. Scope `all` needs `confirm` typed as "limiter state".
    """

    scope: Literal["all", "client"]
    client: str | None = Field(None, max_length=64)
    confirm: str | None = Field(None, max_length=64)
    reason: str = Field(max_length=MAX_REASON_LENGTH)


def _upper(prefix: str) -> str:
    """The first string after every string that starts with `prefix` (range scans on the primary key)."""
    return prefix[:-1] + chr(ord(prefix[-1]) + 1)


def _limiter_where(scope: str, client: str | None) -> tuple[str, list[Any], str, list[Any]]:
    """(limiter WHERE, params, strikes WHERE, params) of a limiter reset."""
    if scope == "all":
        kept = " AND ".join("NOT (bucket_key >= ? AND bucket_key < ?)" for _ in _KEPT_LIMITER_PREFIXES)
        kept_params: list[Any] = [part for prefix in _KEPT_LIMITER_PREFIXES for part in (prefix, _upper(prefix))]
        return f" WHERE {kept}", kept_params, "", []
    key = str(client)
    clauses = ["bucket_key = ?"]
    params: list[Any] = [key]
    for prefix in _CLIENT_PREFIXES:
        clauses.append("bucket_key = ?")
        params.append(prefix + key)
    suffix = "|" + key
    for prefix in _CLIENT_SUFFIX_PREFIXES:
        clauses.append("(bucket_key >= ? AND bucket_key < ? AND substr(bucket_key, -?) = ?)")
        params += [prefix, _upper(prefix), len(suffix), suffix]
    return " WHERE " + " OR ".join(clauses), params, " WHERE ip = ?", [key]


def _limiter_client(scope: str, client: str | None) -> str | None:
    if scope == "all":
        return None
    text = (client or "").strip()
    try:
        if "/" in text:
            return str(ipaddress.ip_network(text, strict=False))
        return str(ipaddress.ip_address(text))
    except ValueError:
        raise validation_error({"client": "Name the client by its address or its IPv6 network key."}) from None


def _limiter_counts(conn: sqlite3.Connection, scope: str, client: str | None) -> dict[str, int]:
    where, params, swhere, sparams = _limiter_where(scope, client)
    limiter = int(conn.execute(f"SELECT count(*) FROM limiter{where}", params).fetchone()[0])  # noqa: S608
    strikes = int(conn.execute(f"SELECT count(*) FROM strikes{swhere}", sparams).fetchone()[0])  # noqa: S608
    return {"limiter_rows": limiter, "strike_rows": strikes}


@router.get("/limiter/reset")
async def limiter_reset_preview(
    request: Request,
    _admin: AdminSession,
    scope: Annotated[Literal["all", "client"], Query()],
    client: Annotated[str | None, Query(max_length=64)] = None,
) -> dict[str, Any]:
    """How many limiter and strike rows a limiter reset would delete (plan 6.8 preview)."""
    ctx = _ctx(request)
    key = _limiter_client(scope, client)
    with service_errors():
        counts = await ctx.dbs.hot.read(lambda conn: _limiter_counts(conn, scope, key))
    return {
        "scope": scope,
        "client": key,
        **counts,
        "confirm_text": LIMITER_RESET_CONFIRM if scope == "all" else None,
        "leaves_alone": "Bans, rules, settings and tarpit bookkeeping.",
    }


@router.post("/limiter/reset")
async def limiter_reset(
    request: Request, admin: AdminSession, _csrf: CsrfChecked, body: LimiterResetBody
) -> dict[str, Any]:
    """Delete limiter and strike rows in one hot.db transaction, then audit the exact counts (plan 6.8)."""
    ctx = _ctx(request)
    reason = audit_reason(body.reason, required=True)
    key = _limiter_client(body.scope, body.client)
    if body.scope == "all" and (body.confirm or "").strip().lower() != LIMITER_RESET_CONFIRM:
        raise validation_error(
            {"confirm": f'Type "{LIMITER_RESET_CONFIRM}" to reset every client.'}, code="confirmation_required"
        )
    where, params, swhere, sparams = _limiter_where(body.scope, key)

    def write(conn: sqlite3.Connection) -> dict[str, int]:
        limiter = conn.execute(f"DELETE FROM limiter{where}", params).rowcount  # noqa: S608  # constant clauses
        strikes = conn.execute(f"DELETE FROM strikes{swhere}", sparams).rowcount  # noqa: S608
        return {"limiter_rows": int(limiter), "strike_rows": int(strikes)}

    with service_errors():
        counts = await ctx.dbs.hot.write(write)
    audit_id = await _audit_row(
        ctx, admin, request, "limiter.reset", f"limiter:{key or 'all'}", after=counts, reason=reason
    )
    await _annotate(ctx, f"Limiter state reset ({key or 'all clients'})", audit_id)
    return {"scope": body.scope, "client": key, **counts, "audit_id": audit_id}


# =============================================================================================== rule tables


def _rule_view(table: str, row: Mapping[str, Any]) -> dict[str, Any]:
    """A stored rule row as JSON (booleans as booleans)."""
    out = dict(row)
    for name in ("enabled", "cache_private", "identical_anonymous", "auto"):
        if name in out and isinstance(out[name], int):
            out[name] = bool(out[name])
    if table == "rules_user_agent":
        out.setdefault("scope", "ip")
        if out.get("scope") is None:
            out["scope"] = "ip"
    return out


async def _rule_rows(ctx: Any, table: str) -> list[dict[str, Any]]:
    with service_errors():
        rows = await _rules(ctx).list_rows(table)
    return [_rule_view(table, row) for row in rows]


async def _create_rule(
    request: Request, admin: AdminPrincipal, table: str, data: Mapping[str, Any], reason: str | None
) -> dict[str, Any]:
    ctx = _ctx(request)
    change = await run_mutation(
        _rules(ctx).create(table, dict(data), actor_for(admin), audit_reason(reason), request_id=request_id_of(request))
    )
    answer = _change(change)
    answer["item"] = _rule_view(table, change.after) if change.after else None
    return answer


async def _update_rule(
    request: Request, admin: AdminPrincipal, table: str, key: Any, data: Mapping[str, Any], reason: str | None
) -> dict[str, Any]:
    ctx = _ctx(request)
    if not data:
        raise validation_error({"body": "Name at least one field to change."})
    change = await run_mutation(
        _rules(ctx).update(
            table, key, dict(data), actor_for(admin), audit_reason(reason), request_id=request_id_of(request)
        )
    )
    answer = _change(change)
    answer["item"] = _rule_view(table, change.after) if change.after else None
    return answer


async def _delete_rule(
    request: Request, admin: AdminPrincipal, table: str, key: Any, reason: str | None
) -> dict[str, Any]:
    ctx = _ctx(request)
    change = await run_mutation(
        _rules(ctx).delete(table, key, actor_for(admin), audit_reason(reason), request_id=request_id_of(request))
    )
    return _change(change)


def _fields(model: ApiBody) -> dict[str, Any]:
    """The fields a body actually set, without the audit reason."""
    return {key: value for key, value in model.model_dump(exclude_unset=True).items() if key != "reason"}


RuleKey = Annotated[str, Path(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")]
IntKey = Annotated[int, Path(ge=1, le=2**62)]
ReasonQuery = Annotated[str | None, Query(max_length=MAX_REASON_LENGTH)]


# --- User-Agent rules (row 44) --------------------------------------------------------------------------------


UA_SPEC: Final = TableSpec(
    name="ua_rules",
    columns=(
        Column("position", "Order", "Evaluation order: the first enabled rule that matches decides.", "count"),
        Column("id", "Id", "The rule id."),
        Column("needle", "Matches", "The User-Agent text the rule matches."),
        Column("mode", "Mode", "contains, exact or regex.", sortable=False),
        Column("kind", "Limit type", "burst (N per period) or cooldown (a gap between requests).", sortable=False),
        Column("scope", "Scope", "Per IP, or shared by every IP.", sortable=False),
        Column("limit", "Limit", "Requests allowed per period (burst rules).", "count", sortable=False),
        Column("period", "Per", "The burst window in seconds.", "seconds", sortable=False),
        Column("cooldown", "Cooldown", "Seconds between requests (cooldown rules).", "seconds", sortable=False),
        Column("message", "Message", "What a limited caller is told (empty: the default text).", sortable=False),
        Column("note", "Note", "Private note.", sortable=False),
        Column("enabled", "Enabled", "Disabled rules are skipped.", sortable=False),
        Column("allowed", "Allowed", "Requests this rule matched and allowed in the range.", "requests"),
        Column("refused", "Refused", "Requests this rule refused in the range.", "requests"),
        *HIT_COLUMNS,
    ),
    default_sort="position",
    default_order="asc",
)


class UaRuleBody(ApiBody):
    """A User-Agent rule (validated by `rules/models.py UserAgentRuleIn`)."""

    needle: str = Field(max_length=1000)
    mode: str | None = Field(None, max_length=16)
    kind: str | None = Field(None, max_length=16)
    scope: str | None = Field(None, max_length=16)
    limit: int | None = None
    period: int | None = None
    cooldown: float | None = Field(None, allow_inf_nan=False)
    message: str | None = Field(None, max_length=MAX_REASON_LENGTH)
    note: str | None = Field(None, max_length=MAX_REASON_LENGTH)
    enabled: bool | None = None
    reason: str | None = Field(None, max_length=MAX_REASON_LENGTH)


class UaRulePatch(ApiBody):
    needle: str | None = Field(None, max_length=1000)
    mode: str | None = Field(None, max_length=16)
    kind: str | None = Field(None, max_length=16)
    scope: str | None = Field(None, max_length=16)
    limit: int | None = None
    period: int | None = None
    cooldown: float | None = Field(None, allow_inf_nan=False)
    message: str | None = Field(None, max_length=MAX_REASON_LENGTH)
    note: str | None = Field(None, max_length=MAX_REASON_LENGTH)
    enabled: bool | None = None
    reason: str | None = Field(None, max_length=MAX_REASON_LENGTH)


class UaOrderBody(ApiBody):
    ids: list[str] = Field(max_length=200)
    reason: str | None = Field(None, max_length=MAX_REASON_LENGTH)


class UaTestBody(ApiBody):
    """The dry-run tester: which saved rule (and the draft) would limit this User-Agent."""

    user_agent: str = Field(max_length=2000)
    draft: UaRuleBody | None = None


@router.get("/ua-rules")
async def ua_rules_table(
    request: Request,
    admin: AdminSession,
    tr: TimeRangeDep,
    tq: Annotated[TableQuery, Depends(table_params(UA_SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    """User-Agent rules in evaluation order with their allowed and refused counts in the range (rows 44, 76)."""
    ctx = _ctx(request)
    rows = await _rule_rows(ctx, "rules_user_agent")
    start, end = _range_ms(tr)
    hits = await ctx.dbs.metrics.read(lambda conn: read_protection.ua_rule_hits(conn, start, end))
    for row in rows:
        counts = hits.get(str(row["id"]), {})
        row["allowed"] = counts.get("allowed", 0)
        row["refused"] = counts.get("refused", 0)
        row["last_hit_ms"] = counts.get("last_ms")
    await _with_rule_hits(ctx, "rules_user_agent", rows, tr)
    extra = {"rules_enabled": bool(_setting(ctx, "user_agent_rules_enabled")), "range": tr.info()}
    return await _list_or_export(
        request, admin, UA_SPEC, tq, fmt, rows, search_keys=("needle", "note", "message", "id"), tr=tr, extra=extra
    )


@router.post("/ua-rules")
async def ua_rule_create(request: Request, admin: AdminSession, _csrf: CsrfChecked, body: UaRuleBody) -> dict[str, Any]:
    """Add a User-Agent rule at the end of the order (v1 ids: 8 hex characters)."""
    data = {k: v for k, v in _fields(body).items() if v is not None}
    return await _create_rule(request, admin, "rules_user_agent", data, body.reason)


@router.put("/ua-rules/order")
async def ua_rules_order(
    request: Request, admin: AdminSession, _csrf: CsrfChecked, body: UaOrderBody
) -> dict[str, Any]:
    """Set the evaluation order: list every rule id once, first match first."""
    ctx = _ctx(request)
    change = await run_mutation(
        _rules(ctx).reorder_user_agent_rules(
            body.ids, actor_for(admin), audit_reason(body.reason), request_id=request_id_of(request)
        )
    )
    return {"changed": change.changed, "order": change.after, "config_version": change.config_version}


@router.post("/ua-rules/test")
async def ua_rules_test(request: Request, _admin: AdminSession, _csrf: CsrfChecked, body: UaTestBody) -> dict[str, Any]:
    """The dry-run tester (row 44): v1 `explain_user_agent_rules`, which also reflects the master switch (B13)."""
    ctx = _ctx(request)
    if not body.user_agent.strip():
        raise validation_error({"user_agent": "Paste a User-Agent to test against."})
    draft = {k: v for k, v in _fields(body.draft).items() if v is not None} if body.draft is not None else None
    snapshot = _rules_snapshot(ctx)
    enabled = bool(_setting(ctx, "user_agent_rules_enabled"))

    def run() -> dict[str, Any]:
        with regex_budget(fresh=True):  # each regex has its timeout; the budget caps the whole test
            return explain_user_agent_rules(snapshot, body.user_agent, enabled=enabled, draft=draft)

    return await asyncio.to_thread(run)  # regex matching and draft validation stay off the event loop


@router.patch("/ua-rules/{rule_id}")
async def ua_rule_update(
    request: Request, admin: AdminSession, _csrf: CsrfChecked, rule_id: RuleKey, body: UaRulePatch
) -> dict[str, Any]:
    """Change some fields of a User-Agent rule (its id and order stay)."""
    data = {k: v for k, v in _fields(body).items() if v is not None or k in ("message", "note")}
    return await _update_rule(request, admin, "rules_user_agent", rule_id, data, body.reason)


@router.delete("/ua-rules/{rule_id}")
async def ua_rule_delete(
    request: Request, admin: AdminSession, _csrf: CsrfChecked, rule_id: RuleKey, reason: ReasonQuery = None
) -> dict[str, Any]:
    return await _delete_rule(request, admin, "rules_user_agent", rule_id, reason)


# --- request filters (header rules, rows 45, 112) --------------------------------------------------------------


HEADER_SPEC: Final = TableSpec(
    name="header_rules",
    columns=(
        Column("id", "Id", "The rule number (insertion order is the evaluation order)."),
        Column("header", "Header", "The header the rule looks at; empty means any header.", sortable=False),
        Column("scope", "Match against", "key (the name), value, or either.", sortable=False),
        Column("mode", "Mode", "contains, exact or regex.", sortable=False),
        Column("needle", "Text", "The text the rule matches."),
        Column("message", "Reply", "Empty: a disguised throttle answer (stealth 429).", sortable=False),
        Column("note", "Note", "Private note.", sortable=False),
        Column("enabled", "Enabled", "Disabled rules are skipped.", sortable=False),
        Column("canonical_key", "Rule key", "header|scope|mode|needle (row 112).", sortable=False),
        *HIT_COLUMNS,
    ),
    default_sort="id",
    default_order="asc",
)


class HeaderRuleBody(ApiBody):
    needle: str = Field(max_length=1000)
    header: str | None = Field(None, max_length=512)
    scope: str | None = Field(None, max_length=16)
    mode: str | None = Field(None, max_length=16)
    message: str | None = Field(None, max_length=MAX_REASON_LENGTH)
    note: str | None = Field(None, max_length=MAX_REASON_LENGTH)
    enabled: bool | None = None
    reason: str | None = Field(None, max_length=MAX_REASON_LENGTH)


class HeaderRulePatch(ApiBody):
    needle: str | None = Field(None, max_length=1000)
    header: str | None = Field(None, max_length=512)
    scope: str | None = Field(None, max_length=16)
    mode: str | None = Field(None, max_length=16)
    message: str | None = Field(None, max_length=MAX_REASON_LENGTH)
    note: str | None = Field(None, max_length=MAX_REASON_LENGTH)
    enabled: bool | None = None
    reason: str | None = Field(None, max_length=MAX_REASON_LENGTH)


class HeaderDraft(ApiBody):
    needle: str = Field(max_length=1000)
    header: str | None = Field(None, max_length=512)
    scope: str | None = Field(None, max_length=16)
    mode: str | None = Field(None, max_length=16)


class HeaderTestBody(ApiBody):
    """Headers as `Name: value` lines, a list of `[name, value]` pairs, or an object; plus an optional draft."""

    headers: str | list[list[str]] | dict[str, str]
    draft: HeaderDraft | None = None

    model_config = ConfigDict(extra="forbid", str_max_length=MAX_TEXT_HEADERS)

    @field_validator("headers")
    @classmethod
    def _bounded(cls, value: Any) -> Any:
        if isinstance(value, list | dict) and len(value) > MAX_TEST_HEADERS:
            raise ValueError(f"Too many headers (max {MAX_TEST_HEADERS})")
        return value


def _test_pairs(raw: str | list[list[str]] | dict[str, str]) -> list[tuple[str, str]]:
    if isinstance(raw, str):
        pairs = parse_header_text(raw)
    elif isinstance(raw, dict):
        pairs = [(str(k)[:MAX_TEST_NAME], str(v)[:MAX_TEST_VALUE]) for k, v in raw.items()]
    else:
        pairs = []
        for item in raw:
            if len(item) != 2:
                raise validation_error({"headers": "Each header is a [name, value] pair."})
            pairs.append((str(item[0])[:MAX_TEST_NAME], str(item[1])[:MAX_TEST_VALUE]))
    pairs = [(name.strip(), value) for name, value in pairs if name.strip()]
    if not pairs:
        raise validation_error({"headers": "Add at least one header to test against."})
    if len(pairs) > MAX_TEST_HEADERS:
        raise validation_error({"headers": f"Too many headers (max {MAX_TEST_HEADERS})."})
    return pairs


@router.get("/header-rules")
async def header_rules_table(
    request: Request,
    admin: AdminSession,
    tr: TimeRangeDep,
    tq: Annotated[TableQuery, Depends(table_params(HEADER_SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    """Request filters (header rules), first match wins in id order (rows 45, 112), with their hits."""
    ctx = _ctx(request)
    rows = await _rule_rows(ctx, "rules_header")
    await _with_rule_hits(ctx, "rules_header", rows, tr)
    return await _list_or_export(
        request,
        admin,
        HEADER_SPEC,
        tq,
        fmt,
        rows,
        search_keys=("header", "needle", "note", "message"),
        tr=tr,
        extra={"disguised_by_default": True, "range": tr.info()},
    )


@router.post("/header-rules")
async def header_rule_create(
    request: Request, admin: AdminSession, _csrf: CsrfChecked, body: HeaderRuleBody
) -> dict[str, Any]:
    """Add a request filter; the same filter twice is refused (409, row 112)."""
    data = {k: v for k, v in _fields(body).items() if v is not None}
    return await _create_rule(request, admin, "rules_header", data, body.reason)


@router.post("/header-rules/test")
async def header_rules_test(
    request: Request, _admin: AdminSession, _csrf: CsrfChecked, body: HeaderTestBody
) -> dict[str, Any]:
    """The request filter tester (row 45): every rule's hit, which one would refuse, and the draft's verdict."""
    ctx = _ctx(request)
    pairs = _test_pairs(body.headers)
    draft = {k: v for k, v in body.draft.model_dump().items() if v is not None} if body.draft is not None else None
    snapshot = _rules_snapshot(ctx)

    def run() -> dict[str, Any]:
        with regex_budget(fresh=True):
            return explain_header_rules(snapshot, pairs, draft)

    return await asyncio.to_thread(run)


@router.get("/header-rules/presets")
async def header_rules_presets(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """Tester presets: v1's example lines, and the newest live requests as samples (row 45).

    The live feed keeps each request's User-Agent and Roblox-Id but not its other headers (open a capture for the
    full set), so a sample holds those two lines.
    """
    ctx = _ctx(request)
    with service_errors():
        rows = await ctx.dbs.metrics.read(lambda conn: read_protection.recent_live_rows(conn, limit=MAX_RECENT_SAMPLES))
    samples = []
    for row in rows:
        lines = []
        if row.get("user_agent"):
            lines.append(f"User-Agent: {row['user_agent']}")
        if row.get("place"):
            lines.append(f"Roblox-Id: {row['place']}")
        if lines:
            samples.append(
                {
                    "at_ms": row.get("at_ms"),
                    "ip": row.get("ip"),
                    "capture_id": row.get("capture_id") or None,
                    "text": "\n".join(lines),
                }
            )
    return {
        "example": "\n".join(f"{name}: {value}" for name, value in HEADER_EXAMPLE),
        "samples": samples,
        "samples_note": "Live rows keep only the User-Agent and Roblox-Id headers.",
    }


@router.patch("/header-rules/{rule_id}")
async def header_rule_update(
    request: Request, admin: AdminSession, _csrf: CsrfChecked, rule_id: IntKey, body: HeaderRulePatch
) -> dict[str, Any]:
    data = {k: v for k, v in _fields(body).items() if v is not None or k in ("message", "note", "header")}
    return await _update_rule(request, admin, "rules_header", rule_id, data, body.reason)


@router.delete("/header-rules/{rule_id}")
async def header_rule_delete(
    request: Request, admin: AdminSession, _csrf: CsrfChecked, rule_id: IntKey, reason: ReasonQuery = None
) -> dict[str, Any]:
    return await _delete_rule(request, admin, "rules_header", rule_id, reason)


# --- endpoint blocks and rules (rows 43, 46), with their attempts tabs (row 75) ------------------------------------


BLOCK_SPEC: Final = TableSpec(
    name="endpoint_blocks",
    columns=(
        Column("id", "Id", "The block number."),
        Column("pattern", "Pattern", "Glob (host/path, * is one segment, subpaths match) or regex."),
        Column("type", "Type", "glob or regex.", sortable=False),
        Column(
            "message", "Reply", "What callers get instead of the default text (empty: the default).", sortable=False
        ),
        Column("note", "Note", "Private note.", sortable=False),
        Column("enabled", "Enabled", "Disabled blocks are skipped.", sortable=False),
        Column("created_at", "Added", "When the block was added.", "timestamp"),
        *HIT_COLUMNS,
    ),
    default_sort="created_at",
)
ENDPOINT_RULE_SPEC: Final = TableSpec(
    name="endpoint_rules",
    columns=(
        Column("id", "Id", "The rule number."),
        Column("pattern", "Pattern", "Glob or regex; the most specific matching rule applies."),
        Column("type", "Type", "glob or regex.", sortable=False),
        Column("scope", "Scope", "ip (clamped to the per-IP allowance), place, or global.", sortable=False),
        Column("limit", "Limit", "Requests allowed per period.", "count"),
        Column("period", "Per", "The window in seconds.", "seconds"),
        Column("message", "Reply", "What callers get instead of the default text.", sortable=False),
        Column("note", "Note", "Private note.", sortable=False),
        Column("enabled", "Enabled", "Disabled rules are skipped.", sortable=False),
        Column("created_at", "Added", "When the rule was added.", "timestamp"),
        *HIT_COLUMNS,
    ),
    default_sort="created_at",
)
ATTEMPT_SPEC: Final = TableSpec(
    name="refusal_attempts",
    columns=(
        # The refused path and methods are what the caller sent (caller text, DESIGN 13.1; finding secfix-5).
        Column(
            "path",
            "Endpoint",
            "The path asked for (the endpoint template when the detail was folded).",
            caller_text=True,
        ),
        Column("attempts", "Attempts", "Refusals in the range.", "requests"),
        Column(
            "clients",
            "Distinct clients",
            "Distinct client hashes among them (a lower bound, see unattributed).",
            "count",
        ),
        Column(
            "unattributed",
            "Unattributed",
            "Attempts recorded without a client (folded over the event budget).",
            "requests",
        ),
        Column("methods", "Methods", "HTTP methods seen.", sortable=False, caller_text=True),
        Column(
            "refused_by",
            "Refused by",
            "The rules that refused these attempts, as each refusal recorded them (pattern, or the canonical key of "
            "a request filter; the id alone once the rule was deleted). Refusals recorded before rules were kept "
            "with the refusal have none.",
            sortable=False,
        ),
        Column(
            "current_rule",
            "Matching rule now",
            "The rule that matches this path today (rules may have changed).",
            sortable=False,
        ),
        Column("last_ms", "Last attempt", "When the latest attempt was refused.", "timestamp_ms"),
    ),
    default_sort="attempts",
)
ATTEMPT_RULE_TABLE: Final[dict[str, str]] = {
    "endpoint_blocked": "rules_endpoint_block",
    "endpoint_rule": "rules_endpoint_limit",
    "header_rule": "rules_header",
}
"""The rule table whose rows refused each attempts tab's refusals (the key of a refusal event's `detail.rules`)."""


def _rule_label(snapshot: Any, table: str, rule_id: str) -> str:
    """How an attempts row names a refusing rule: its pattern (a request filter: its canonical key), else its id."""
    rows = {
        "rules_endpoint_block": getattr(snapshot, "endpoint_blocks", ()),
        "rules_endpoint_limit": getattr(snapshot, "endpoint_limits", ()),
        "rules_header": getattr(snapshot, "header_rules", ()),
    }.get(table, ())
    for row in rows:
        if str(getattr(row, "id", "")) == rule_id:
            return str(getattr(row, "pattern", None) or getattr(row, "canonical_key", None) or f"#{rule_id}")
    return f"#{rule_id} (deleted)"


class BlockBody(ApiBody):
    pattern: str = Field(max_length=1200)
    type: str | None = Field(None, max_length=16)
    message: str | None = Field(None, max_length=MAX_REASON_LENGTH)
    note: str | None = Field(None, max_length=MAX_REASON_LENGTH)
    enabled: bool | None = None
    reason: str | None = Field(None, max_length=MAX_REASON_LENGTH)


class BlockPatch(ApiBody):
    pattern: str | None = Field(None, max_length=1200)
    type: str | None = Field(None, max_length=16)
    message: str | None = Field(None, max_length=MAX_REASON_LENGTH)
    note: str | None = Field(None, max_length=MAX_REASON_LENGTH)
    enabled: bool | None = None
    reason: str | None = Field(None, max_length=MAX_REASON_LENGTH)


class EndpointRuleBody(ApiBody):
    pattern: str = Field(max_length=1200)
    limit: int
    period: int | None = None
    type: str | None = Field(None, max_length=16)
    scope: str | None = Field(None, max_length=16)
    message: str | None = Field(None, max_length=MAX_REASON_LENGTH)
    note: str | None = Field(None, max_length=MAX_REASON_LENGTH)
    enabled: bool | None = None
    reason: str | None = Field(None, max_length=MAX_REASON_LENGTH)


class EndpointRulePatch(ApiBody):
    pattern: str | None = Field(None, max_length=1200)
    limit: int | None = None
    period: int | None = None
    type: str | None = Field(None, max_length=16)
    scope: str | None = Field(None, max_length=16)
    message: str | None = Field(None, max_length=MAX_REASON_LENGTH)
    note: str | None = Field(None, max_length=MAX_REASON_LENGTH)
    enabled: bool | None = None
    reason: str | None = Field(None, max_length=MAX_REASON_LENGTH)


async def _attempts(
    request: Request,
    admin: AdminPrincipal,
    reason: str,
    tr: TimeRange,
    tq: TableQuery,
    fmt: ExportFormat | None,
    matcher: Callable[[Any, str], Any] | None,
) -> Any:
    ctx = _ctx(request)
    start, end = _range_ms(tr)
    snapshot = _rules_snapshot(ctx)
    rule_table = ATTEMPT_RULE_TABLE.get(reason)

    def annotate(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        for row in rows:
            # The rules that refused, as the refusal events recorded them (`detail.rules`; the deferred P9 item
            # "the attempts tabs show the rule that refused at the time").
            ids = [str(i) for i in row.pop("rule_ids", None) or ()]
            row["refused_by"] = [_rule_label(snapshot, rule_table, i) for i in ids] if rule_table else []
            # One request's regex budget per path: the rule a request for this path would match today.
            with regex_budget(fresh=True):
                rule = matcher(snapshot, str(row.get("path") or "").lower()) if matcher else None
            row["current_rule"] = getattr(rule, "pattern", None)
        return rows

    async def fetch(page: int, size: int) -> tuple[Sequence[Any], int]:
        data = await ctx.dbs.metrics.read(
            lambda conn: read_protection.refusal_attempts(
                conn,
                reason,
                start,
                end,
                search=tq.q,
                sort=tq.sort,
                descending=tq.descending,
                limit=size,
                offset=(page - 1) * size,
                rule_table=rule_table,
            )
        )
        rows = await asyncio.to_thread(annotate, list(data["rows"]))  # pattern matching off the event loop
        return rows, int(data["total"])

    with service_errors():
        return await _table_or_export(
            request, admin, ATTEMPT_SPEC, tq, fmt, fetch, filters={"reason": reason}, tr=tr, extra={"reason": reason}
        )


@router.get("/endpoint-blocks")
async def blocks_table(
    request: Request,
    admin: AdminSession,
    tr: TimeRangeDep,
    tq: Annotated[TableQuery, Depends(table_params(BLOCK_SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    """Endpoint blocks (row 46): every matching block refuses with 403; each with its hits."""
    ctx = _ctx(request)
    rows = await _rule_rows(ctx, "rules_endpoint_block")
    await _with_rule_hits(ctx, "rules_endpoint_block", rows, tr)
    return await _list_or_export(
        request,
        admin,
        BLOCK_SPEC,
        tq,
        fmt,
        rows,
        search_keys=("pattern", "note", "message"),
        tr=tr,
        extra={"range": tr.info()},
    )


@router.post("/endpoint-blocks")
async def block_create(request: Request, admin: AdminSession, _csrf: CsrfChecked, body: BlockBody) -> dict[str, Any]:
    data = {k: v for k, v in _fields(body).items() if v is not None}
    return await _create_rule(request, admin, "rules_endpoint_block", data, body.reason)


@router.get("/endpoint-blocks/attempts")
async def block_attempts(
    request: Request,
    admin: AdminSession,
    tr: TimeRangeDep,
    tq: Annotated[TableQuery, Depends(table_params(ATTEMPT_SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    """Blocked endpoint attempts in the range (v1 "Blocked Endpoint Attempts", row 75)."""
    return await _attempts(request, admin, "endpoint_blocked", tr, tq, fmt, match_block)


@router.patch("/endpoint-blocks/{rule_id}")
async def block_update(
    request: Request, admin: AdminSession, _csrf: CsrfChecked, rule_id: IntKey, body: BlockPatch
) -> dict[str, Any]:
    data = {k: v for k, v in _fields(body).items() if v is not None or k in ("message", "note")}
    return await _update_rule(request, admin, "rules_endpoint_block", rule_id, data, body.reason)


@router.delete("/endpoint-blocks/{rule_id}")
async def block_delete(
    request: Request, admin: AdminSession, _csrf: CsrfChecked, rule_id: IntKey, reason: ReasonQuery = None
) -> dict[str, Any]:
    return await _delete_rule(request, admin, "rules_endpoint_block", rule_id, reason)


@router.get("/endpoint-rules")
async def endpoint_rules_table(
    request: Request,
    admin: AdminSession,
    tr: TimeRangeDep,
    tq: Annotated[TableQuery, Depends(table_params(ENDPOINT_RULE_SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    """Endpoint rate rules (row 43): the most specific matching rule applies; each with its hits."""
    ctx = _ctx(request)
    rows = await _rule_rows(ctx, "rules_endpoint_limit")
    await _with_rule_hits(ctx, "rules_endpoint_limit", rows, tr)
    return await _list_or_export(
        request,
        admin,
        ENDPOINT_RULE_SPEC,
        tq,
        fmt,
        rows,
        search_keys=("pattern", "note", "message"),
        tr=tr,
        extra={"per_ip_allowance": int(_setting(ctx, "allowed_requests_per_minute")), "range": tr.info()},
    )


@router.post("/endpoint-rules")
async def endpoint_rule_create(
    request: Request, admin: AdminSession, _csrf: CsrfChecked, body: EndpointRuleBody
) -> dict[str, Any]:
    data = {k: v for k, v in _fields(body).items() if v is not None}
    return await _create_rule(request, admin, "rules_endpoint_limit", data, body.reason)


@router.get("/endpoint-rules/attempts")
async def endpoint_rule_attempts(
    request: Request,
    admin: AdminSession,
    tr: TimeRangeDep,
    tq: Annotated[TableQuery, Depends(table_params(ATTEMPT_SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    """Rate-limited attempts in the range (v1 "Rate-Limited Attempts", row 75)."""
    return await _attempts(request, admin, "endpoint_rule", tr, tq, fmt, match_endpoint_rule)


@router.get("/header-rules/attempts")
async def header_rule_attempts(
    request: Request,
    admin: AdminSession,
    tr: TimeRangeDep,
    tq: Annotated[TableQuery, Depends(table_params(ATTEMPT_SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    """Header-blocked attempts in the range (v1 "Header-Blocked Attempts", row 75)."""
    return await _attempts(request, admin, "header_rule", tr, tq, fmt, None)


@router.patch("/endpoint-rules/{rule_id}")
async def endpoint_rule_update(
    request: Request, admin: AdminSession, _csrf: CsrfChecked, rule_id: IntKey, body: EndpointRulePatch
) -> dict[str, Any]:
    data = {k: v for k, v in _fields(body).items() if v is not None or k in ("message", "note")}
    return await _update_rule(request, admin, "rules_endpoint_limit", rule_id, data, body.reason)


@router.delete("/endpoint-rules/{rule_id}")
async def endpoint_rule_delete(
    request: Request, admin: AdminSession, _csrf: CsrfChecked, rule_id: IntKey, reason: ReasonQuery = None
) -> dict[str, Any]:
    return await _delete_rule(request, admin, "rules_endpoint_limit", rule_id, reason)


# --- ignored paths (row 50) ----------------------------------------------------------------------------------------


IGNORED_SPEC: Final = TableSpec(
    name="ignored_paths",
    columns=(
        Column("pattern", "Path", "A glob without the leading slash; every path under it matches too."),
        Column("note", "Note", "Private note.", sortable=False),
    ),
    default_sort="pattern",
    default_order="asc",
)


class IgnoredPathBody(ApiBody):
    pattern: str = Field(max_length=1200)
    note: str | None = Field(None, max_length=MAX_REASON_LENGTH)
    reason: str | None = Field(None, max_length=MAX_REASON_LENGTH)


@router.get("/ignored-paths")
async def ignored_paths_table(
    request: Request,
    admin: AdminSession,
    tq: Annotated[TableQuery, Depends(table_params(IGNORED_SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    """Paths answered 404 without logging (row 50)."""
    rows = await _rule_rows(_ctx(request), "ignored_paths")
    return await _list_or_export(request, admin, IGNORED_SPEC, tq, fmt, rows, search_keys=("pattern", "note"))


@router.post("/ignored-paths")
async def ignored_path_create(
    request: Request, admin: AdminSession, _csrf: CsrfChecked, body: IgnoredPathBody
) -> dict[str, Any]:
    data = {k: v for k, v in _fields(body).items() if v is not None}
    return await _create_rule(request, admin, "ignored_paths", data, body.reason)


@router.delete("/ignored-paths")
async def ignored_path_delete(
    request: Request,
    admin: AdminSession,
    _csrf: CsrfChecked,
    pattern: Annotated[str, Query(min_length=1, max_length=1200)],
    reason: ReasonQuery = None,
) -> dict[str, Any]:
    """Remove an ignored path (named by its stored pattern, in the query string)."""
    return await _delete_rule(request, admin, "ignored_paths", pattern, reason)


# =============================================================================================== spam detectors


SPAM_EVENTS_SPEC: Final = TableSpec(
    name="spam_detections",
    columns=(
        Column("at_ms", "When", "When the detector decided (newest first).", "timestamp_ms"),
        Column(
            "kind",
            "Decision",
            "spam_would_ban (dry run), spam_ban, spam_strike, spam_tarpit or spam_detected.",
            sortable=False,
        ),
        Column("detector", "Detector", "SPAM-RATE, SPAM-PROBE, ...", sortable=False),
        Column(
            "subject",
            "Subject",
            "ip:<client>, place:<id>, or a fleet-wide subject (a place id is the caller's Roblox-Id header).",
            sortable=False,
            caller_text=True,
        ),
        Column(
            "action", "Action", "What was done (a trusted game server gets a strike instead of a ban).", sortable=False
        ),
        Column("value", "Measured", "The measured value.", sortable=False),
        Column("threshold", "Threshold", "The detector threshold.", sortable=False),
        Column("window_s", "Window", "The detector window in seconds.", "seconds", sortable=False),
        Column("evidence", "Evidence", "The detector's summary.", sortable=False),
    ),
    default_sort="at_ms",
)


class ArmBody(ApiBody):
    """Arm the spam detectors (dry run off): repeat the token of the collateral preview you reviewed."""

    confirm_collateral: str = Field(min_length=32, max_length=32, pattern=r"^[0-9a-f]{32}$")
    reason: str = Field(max_length=MAX_REASON_LENGTH)


@router.get("/spam")
async def spam_state(request: Request, _admin: AdminSession, tr: TimeRangeDep) -> dict[str, Any]:
    """The spam detectors (plan 10.3): master switch, dry run, each detector and its decisions in the range."""
    ctx = _ctx(request)
    values = ctx.settings.snapshot()
    start, end = _range_ms(tr)
    with service_errors():
        counts = await ctx.dbs.metrics.read(lambda conn: read_protection.spam_counts(conn, start, end))
    detectors = read_spam.detector_states(values)
    for item in detectors:
        item["decisions"] = counts.get(item["label"], {})
    pipeline = getattr(ctx, "abuse", None)
    spam = getattr(pipeline, "spam", None)
    worker = None
    if spam is not None:
        worker = {
            "flushes": spam.flushes,
            "detections": spam.detections_total,
            "dropped": spam.dropped,
            "folded": spam.folded,
            "evicted": spam.evicted,
            "pending_subjects": spam.pending_subjects(),
        }
    return {
        "enabled": bool(_setting(ctx, "spam_enabled")),
        "dry_run": bool(_setting(ctx, "spam_dry_run")),
        "detectors": detectors,
        "range": tr.info(),
        "this_worker": worker,
    }


@router.get("/spam/events")
async def spam_events_table(
    request: Request,
    admin: AdminSession,
    tr: TimeRangeDep,
    tq: Annotated[TableQuery, Depends(table_params(SPAM_EVENTS_SPEC))],
    fmt: ExportFormatDep,
    kind: Annotated[Literal["all", "would_ban", "ban", "strike", "tarpit", "recommend"], Query()] = "all",
    detector: Annotated[str | None, Query(max_length=16, pattern=r"^SPAM-[A-Z]{1,8}$")] = None,
) -> Any:
    """Detector decisions, newest first; `kind=would_ban` is the dry-run result list."""
    ctx = _ctx(request)
    _single_order(tq)
    kinds = {
        "all": read_protection.SPAM_EVENTS,
        "would_ban": ("spam_would_ban",),
        "ban": ("spam_ban",),
        "strike": ("spam_strike",),
        "tarpit": ("spam_tarpit",),
        "recommend": ("spam_detected",),
    }[kind]
    start, end = _range_ms(tr)

    async def fetch(page: int, size: int) -> tuple[Sequence[Any], int]:
        data = await ctx.dbs.metrics.read(
            lambda conn: read_protection.spam_events(
                conn, start, end, kinds=kinds, detector=detector, limit=size, offset=(page - 1) * size
            )
        )
        return data["rows"], int(data["total"])

    with service_errors():
        return await _table_or_export(
            request, admin, SPAM_EVENTS_SPEC, tq, fmt, fetch, filters={"kind": kind, "detector": detector}, tr=tr
        )


async def _collateral(ctx: Any) -> dict[str, Any]:
    now = ctx.clock.now()
    end_s = int(now) + 60
    start_s = int(now) - COLLATERAL_WINDOW_S
    start_s -= start_s % 60
    window = queries.Window(start_s, end_s, "hour", str(_setting(ctx, "ui_timezone") or "UTC"))
    served_pct = float(_setting(ctx, SERVED_PCT_SETTING))

    def read(conn: sqlite3.Connection) -> dict[str, Any]:
        would = read_protection.would_ban_subjects(conn, start_s * 1000, end_s * 1000)
        keys = [key for key in (read_spam.client_key_of(str(item["subject"])) for item in would) if key]
        return {"would": would, "totals": client_totals(conn, "ip", keys, window)}

    with service_errors():
        data = await ctx.dbs.metrics.read(read)
    entries = read_spam.collateral(data["would"], data["totals"], served_pct=served_pct)
    legit = [entry for entry in entries if entry["legitimate_looking"]]
    return {
        "window": {"from": start_s, "to": end_s, "days": COLLATERAL_WINDOW_S // 86_400},
        "served_pct_threshold": served_pct,
        "would_ban": entries,
        "legitimate_looking": legit,
        "token": read_spam.collateral_token(entries),
        "dry_run": bool(_setting(ctx, "spam_dry_run")),
        "note": (
            "Built from the detectors' own dry-run decisions of the last 7 days; arming bans these clients' "
            "addresses when a detector fires again."
        ),
    }


@router.get("/spam/collateral")
async def spam_collateral(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """FILTER-COLLATERAL preview (plan 10.3): who the detectors would have banned, and who looks legitimate."""
    return await _collateral(_ctx(request))


@router.post("/spam/arm")
async def spam_arm(request: Request, admin: AdminFreshMfa, _csrf: CsrfChecked, body: ArmBody) -> dict[str, Any]:
    """Switch dry run off after confirming the collateral list (a fresh second factor: this arms automatic bans)."""
    ctx = _ctx(request)
    reason = audit_reason(body.reason, required=True)
    preview = await _collateral(ctx)
    if preview["token"] != body.confirm_collateral:
        raise conflict(
            "The collateral list changed since that preview; review GET /protection/spam/collateral again.",
            fields={"confirm_collateral": "Out of date."},
        )
    result = await run_mutation(
        _settings_service(ctx).update(
            {ARM_ONLY_SETTING: 0},
            actor_for(admin),
            f"{reason} (collateral list {body.confirm_collateral} "
            f"confirmed, {len(preview['legitimate_looking'])} legitimate-looking)",
            request_id=request_id_of(request),
            guard=settings_api.write_rules(ctx, admin, arming_allowed=True),  # the one route that may arm
        )
    )
    return {
        "dry_run": bool(_setting(ctx, ARM_ONLY_SETTING)),
        "changed": [change.key for change in result.changes],
        "config_version": result.config_version,
        "confirmed": len(preview["legitimate_looking"]),
    }


@router.post("/spam/disarm")
async def spam_disarm(request: Request, admin: AdminSession, _csrf: CsrfChecked, body: ReasonBody) -> dict[str, Any]:
    """Switch dry run back on (always allowed: it only stops automatic bans)."""
    ctx = _ctx(request)
    reason = audit_reason(body.reason) or "spam detectors back to dry run"
    result = await run_mutation(
        _settings_service(ctx).update(
            {ARM_ONLY_SETTING: 1}, actor_for(admin), reason, request_id=request_id_of(request)
        )
    )
    return {"dry_run": bool(_setting(ctx, ARM_ONLY_SETTING)), "config_version": result.config_version}


# =============================================================================================== tarpit, bot, challenge


@router.get("/tarpit")
async def tarpit_state(request: Request, _admin: AdminSession, tr: TimeRangeDep) -> dict[str, Any]:
    """The tarpit card (rows 78, 123): switches, the effective cap and which term clamped it, holds in progress,
    and the hold statistics of the range.

    `active_holds` is fleet-wide (hot.db leases, None while hot.db cannot be read); `stats` counts this worker's
    holds since it started (`stats_scope`). `history` is fleet-wide over the range (`metrics/read_producers.py
    tarpit_summary`, `history_scope`): eligible refusals, holds, skips and the skipped share, mean, p95 and longest
    hold, by category and by kind, the hold histogram, and the mean arrival gap after a held and after an instant
    refusal (v1's "Time Between Requests", TARPIT-TUNE's evidence).
    """
    ctx = _ctx(request)
    state: dict[str, Any] = await _abuse(ctx).tarpit.state()
    start, end = tr.window.start, tr.window.end
    with service_errors():
        history = await ctx.dbs.metrics.read(lambda conn: read_producers.tarpit_summary(conn, start, end))
    state["category_labels"] = {name: TARPIT_LABELS.get(name, name) for name in TARPIT_CATEGORIES}
    state["stats_scope"] = "this_worker"
    state["worker_id"] = ctx.worker_id
    state["history"] = history
    state["history_scope"] = "fleet"
    state["range"] = tr.info()
    return state


BOT_KEYS: Final[tuple[str, ...]] = (
    "bot_score_legit_max",
    "bot_score_abuse_min",
    "bot_score_block_threshold",
    "roblox_egress_cidrs",
)
CHALLENGE_KEYS: Final[tuple[str, ...]] = (
    "challenge_enabled",
    "challenge_trigger_score",
    "challenge_difficulty_bits",
    "challenge_cookie_minutes",
)


@router.get("/bot")
async def bot_state(request: Request, _admin: AdminSession, tr: TimeRangeDep) -> dict[str, Any]:
    """Bot heuristics (plan 10.7) and the browser challenge (10.8): weights, thresholds, state, refusals."""
    ctx = _ctx(request)
    pipeline = _abuse(ctx)
    with service_errors():
        hits = await ctx.dbs.metrics.read(lambda conn: read_protection.check_hits(conn, tr.window))
    weights = {name: float(_setting(ctx, f"bot_weight_{name}")) for name in SIGNALS}
    return {
        "weights": weights,
        "settings": {key: _setting(ctx, key) for key in BOT_KEYS},
        "block_enabled": int(_setting(ctx, "bot_score_block_threshold")) > 0,
        "challenge": {
            "settings": {key: _setting(ctx, key) for key in CHALLENGE_KEYS},
            "available": pipeline.challenge_key is not None,
            "unavailable_reason": None
            if pipeline.challenge_key is not None
            else "the ip_hash_key credential is not configured, so challenge puzzles cannot be signed",
        },
        "refused": {
            "challenge": hits["by_check"].get("challenge", 0),
            "bot_score": hits["by_check"].get("bot_score", 0),
        },
        "tracked_clients": len(pipeline.bot),
        "tracker_scope": "this_worker",
        "range": tr.info(),
    }


# =============================================================================================== pipeline and refusals


@router.get("/pipeline")
async def pipeline_diagram(request: Request, _admin: AdminSession, tr: TimeRangeDep) -> dict[str, Any]:
    """The pipeline diagram (plan 10.9, row 5): every check in order with its refusals in the range, plus the
    `ua_rule_hit` and `throttle_tier` counters (row 76) and the rule rows' hits per table in the range
    (`rule_hits`, whatever the verdict; each table's rows are listed with theirs)."""
    ctx = _ctx(request)
    pipeline = _abuse(ctx)
    start, end = _range_ms(tr)

    def read(conn: sqlite3.Connection) -> dict[str, Any]:
        return {
            "hits": read_protection.check_hits(conn, tr.window),
            "ua": read_protection.ua_rule_hits(conn, start, end),
            "tiers": read_protection.tier_hits(conn, start, end),
            "rule_hits": read_protection.rule_hit_totals(conn, tr.window.start, tr.window.end),
        }

    with service_errors():
        data = await ctx.dbs.metrics.read(read)
    hits = data["hits"]
    checks = []
    for item in pipeline.describe():
        name = str(item["name"])
        checks.append({**item, "reasons": list(CHECK_REASONS.get(name, ())), "refused": hits["by_check"].get(name, 0)})
    ua_totals = {
        "allowed": sum(v["allowed"] for v in data["ua"].values()),
        "refused": sum(v["refused"] for v in data["ua"].values()),
    }
    return {
        "range": tr.info(),
        "requests": hits["requests"],
        "evaluated": hits["evaluated"],
        "refused": hits["refused"],
        "other_refusals": hits["other_refusals"],
        "checks": checks,
        "ua_rule_hits": {"total": ua_totals, "by_rule": data["ua"]},
        "throttle_tiers": {str(tier): count for tier, count in sorted(data["tiers"].items())},
        "rule_hits": data["rule_hits"],
        "this_worker": pipeline.stats.snapshot(),
    }


@router.get("/rule-hits")
async def rule_hit_history(
    request: Request,
    _admin: AdminSession,
    tr: TimeRangeDep,
    table: Annotated[
        Literal["ua-rules", "header-rules", "endpoint-blocks", "endpoint-rules", "access", "bans"], Query()
    ],
    rule_id: Annotated[str, Query(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")],
) -> dict[str, Any]:
    """One rule row's hits over the range (plan 10.9 "hit history"; FILTER-REMOVE's evidence), a series answer.

    `table` names the list the row is in (the route name of its table); `rule_id` is the row id the table shows.
    """
    ctx = _ctx(request)
    name = RULE_HIT_TABLES[table]
    with service_errors():
        points = await ctx.dbs.metrics.read(
            lambda conn: read_protection.rule_hit_points(conn, name, rule_id, tr.window)
        )
    series = [{"key": "hits", "label": "Hits", "unit": "requests", "points": points}]
    answer = series_answer(tr, series)
    answer["table"] = table
    answer["rule_id"] = rule_id
    answer["total"] = sum(int(value) for _start, value in points)
    return answer


REFUSALS_SPEC: Final = TableSpec(
    name="refusal_reasons",
    columns=(
        Column("reason", "Reason", "The refusal or failure reason code."),
        Column("requests", "Count", "Requests refused or failed with this reason in the range (exact).", "requests"),
        Column("last_status", "Status", "The status code the newest of them got.", ""),
        Column(
            "last_path",
            "Last path",
            "The path the newest of them asked for (caller text: shown as plain text, never as markup).",
            sortable=False,
            caller_text=True,
        ),
        Column(
            "clients",
            "Unique clients",
            "Distinct client hashes among them (a lower bound, see unattributed).",
            "count",
        ),
        Column(
            "unattributed",
            "Unattributed",
            "Refusals recorded without a client (folded over the event budget).",
            "requests",
        ),
        Column("first_ms", "First seen", "When the oldest of them was recorded.", "timestamp_ms"),
        Column("last_ms", "Last seen", "When the newest of them was recorded.", "timestamp_ms"),
        Column("message_source", "Message", "Custom versus default message counts (row 116).", sortable=False),
    ),
    default_sort="requests",
)
"""v1's Refusal Reasons columns (plan 14.1 row 10, parity row 72, finding parity-3); the last IP is replaced by the
distinct client count (plan 9.15, as the attempts tabs, row 75)."""
CALLER_TEXT_COLUMNS: Final[tuple[str, ...]] = ("last_path",)
"""Columns whose values are caller text: a page shows them escaped (never as HTML), plan 9.16."""


@router.get("/refusals")
async def refusals(
    request: Request,
    admin: AdminSession,
    tr: TimeRangeDep,
    tq: Annotated[TableQuery, Depends(table_params(REFUSALS_SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    """Refusals and failures by reason (v1 section 10 "Refusal Reasons", rows 72 and 116): count, the newest status
    and path, distinct clients, first and last seen, and the custom versus default message split; a section 13
    table (sorted, searched and paged here, exported as CSV or JSON)."""
    ctx = _ctx(request)
    with service_errors():
        rows = await ctx.dbs.metrics.read(lambda conn: queries.refusal_reasons(conn, tr.window))
    return await _list_or_export(
        request,
        admin,
        REFUSALS_SPEC,
        tq,
        fmt,
        rows,
        search_keys=("reason", "last_path"),
        tr=tr,
        extra={"range": tr.info(), "caller_text": list(CALLER_TEXT_COLUMNS)},
    )


__all__ = ["audit_reason", "protection_keys", "router"]
