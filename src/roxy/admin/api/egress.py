"""Egress API (`/admin/api/v1/egress`): bytes per egress, the rotator budget, exit IPs and sessions (plan 8.4, 8.5).

What this is
    The routes behind the Egress page (plan 14.1):
      * `GET /usage`: metered bytes and calls per egress over the range, plus this worker's live meters.
      * `GET /rotator/budget`: the KPI tiles (this cycle used, projected, remaining, cost so far), the projection
        with its 90 percent band (plan 8.4), the hard stop and the daily cap.
      * `GET /rotator/daily`: one bar per day of the billing cycle with the cumulative total and the quota line.
      * `GET /bytes-per-request`: how many calls fell in each size slot (per-minute averages, labeled as such).
      * `GET /top-endpoints`: endpoints by wire bytes on one egress (default the rotator), a table with export.
      * `GET /share`: each egress's share of upstream calls over time.
      * `GET /exit-ips`: the rotator's recent exit IPs, masked to /24 (IPv6 /48) unless `reveal=true`, which is
        audited (`egress.exit_ips_reveal`) before anything is shown.
      * `POST /rotator/probe`: "Verify rotation now": ask the IP echo service through the rotator (parity row 32).
      * `GET /sessions`: rotator session mode, open sessions, the fleet-wide park and failure streak, 429s per exit.
      * `GET /provider-report` and `POST /provider-report`: the provider's own byte figure for this cycle, typed in
        from its dashboard, next to Roxy's metered count (the input of EGR-CALIBRATE, plan 8.4).
      * `GET /trips` and `POST /{egress}/enable`: egresses the leak guard disabled, and re-enabling one (fresh
        second factor, a reason, audited; plan C2 item 4).

Why it exists
    Every rotator byte costs money and the plan has a monthly quota, a hard stop and cost projections (8.4); the
    owner also needs to see that the rotator works (exit IPs, sessions) without exposing the exit addresses by
    default (privacy, row 32). Numbers come from metrics.db (`egress_usage`, the rollups), so every worker shows the
    same; per-worker values (meters, open sessions, recent exit IPs) say so (`this_worker`).

How it works
    Thin routes over `metrics/read_upstream.py`, `egress/read_state.py` and the live `EgressClients`; each read
    route's work is a module function (`usage_answer`, `budget_answer`, `sessions_answer`, ...) that the Egress
    page (`roxy/admin/pages/egress.py`) calls too, so the page and the API show the same numbers. Bytes are
    decimal (1 GB = 10^9 bytes, the provider's unit). Writes go through the services: `EgressClients.enable_egress`
    writes its audit row in the same transaction as the change; the provider report is stored in metrics.db and
    audited in control.db (if the audit row cannot be written, the report is taken back and the answer is 503).

What to read next
    `roxy/egress/rotator.py`, `roxy/egress/clients.py`, `roxy/egress/read_state.py`, `roxy/admin/api/rotator.py`.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any, Final, Literal

from fastapi import Depends, Path, Request
from pydantic import Field

from roxy.admin.api import common
from roxy.admin.api.common import (
    AdminFreshMfa,
    AdminSession,
    ApiBody,
    Column,
    CsrfChecked,
    ExportFormatDep,
    TableQuery,
    TableSpec,
    TimeRange,
    TimeRangeDep,
    table_params,
)
from roxy.admin.api.routing_rules import Reason
from roxy.config import audit
from roxy.core.reasons import Egress
from roxy.deps import get_ctx
from roxy.egress import read_state
from roxy.egress.rotator import DECIMAL_GB, day_start_for, mask_ip, usage_since
from roxy.metrics import queries, read_history, read_upstream
from roxy.storage.db import SharedStateUnavailable

log = logging.getLogger("roxy.admin.api.egress")

router = common.area_router("egress")

EGRESSES: Final = (Egress.DIRECT.value, Egress.ROTATOR.value, Egress.CREDENTIAL.value)
MAX_PROVIDER_GB: Final = 1_000_000.0
REVEAL_ACTION: Final = "egress.exit_ips_reveal"
PROVIDER_ACTION: Final = "egress.provider_report"
DAY_S: Final = 86_400

EgressName = Literal["direct", "rotator", "credential"]

TOP_SPEC: Final = TableSpec(
    name="egress_top_endpoints",
    columns=(
        Column("template", "Endpoint", "The endpoint template.", caller_text=True),
        Column(
            "bytes", "Bytes", "Metered wire bytes (request, response, TLS and proxy overhead) in the range.", "bytes"
        ),
        Column("calls", "Calls", "Upstream calls through this egress in the range.", "count"),
        Column("bytes_per_call", "Bytes per call", "Bytes divided by calls.", "bytes"),
        Column("bytes_in", "Bytes in", "Wire bytes received.", "bytes"),
        Column("bytes_out", "Bytes out", "Wire bytes sent.", "bytes"),
        Column("share_pct", "Share", "This endpoint's part of the egress's bytes in the range.", "pct"),
    ),
    default_sort="bytes",
)


def _egress(request: Request) -> Any:
    return egress_of(get_ctx(request))


def egress_of(ctx: Any) -> Any:
    """The running `EgressClients`, or 503 while the worker is still starting (C7: never a 500)."""
    egress = ctx.egress
    if egress is None:
        raise common.unavailable("The egress layer is not running yet; try again shortly.")
    return egress


def _gb(size: float) -> float:
    return round(size / DECIMAL_GB, 4)


# ------------------------------------------------------------------------------------------------ usage


@router.get("/usage")
async def usage(request: Request, _admin: AdminSession, tr: TimeRangeDep) -> dict[str, Any]:
    """Metered bytes and calls per egress over the range (all workers), plus this worker's live meters."""
    return await usage_answer(get_ctx(request), tr)


async def usage_answer(ctx: Any, tr: TimeRange) -> dict[str, Any]:
    """The answer of `GET /egress/usage` (the Egress page's Usage card renders it, plan P6)."""
    egress = egress_of(ctx)
    window = tr.window

    def read(conn: Any) -> tuple[dict[str, int], dict[str, Any]]:
        return queries.egress_bytes(conn, window), queries.egress_usage_series(conn, window)

    totals, series = await ctx.dbs.metrics.read(read)
    items = []
    for name in EGRESSES:
        found = series["egress"].get(name, {})
        calls = sum(int(v) for v in found.get("requests", []))
        size = int(totals.get(name, 0))
        enabled, why = egress.is_enabled(Egress(name))
        items.append(
            {
                "egress": name,
                "bytes": size,
                "gb": _gb(size),
                "calls": calls,
                "bytes_per_call": round(size / calls, 1) if calls else None,
                "enabled": bool(enabled),
                "disabled_reason": why or None,
            }
        )
    stats = egress.stats()
    return {
        "range": tr.info(),
        "items": items,
        "metering_mode": stats.get("metering_mode"),
        "metering_note": "socket: bytes counted on the wire; estimate: computed, see plan 8.3",
        "this_worker": {"meters": stats.get("meters"), "usage": stats.get("usage"), "guard": stats.get("guard")},
    }


# ----------------------------------------------------------------------------------------------- budget


def _budget_settings(settings: Any) -> dict[str, Any]:
    return {
        "rotator_quota_gb_per_month": float(settings.get("rotator_quota_gb_per_month")),
        "rotator_price_per_gb_usd": float(settings.get("rotator_price_per_gb_usd")),
        "rotator_billing_day": int(settings.get("rotator_billing_day")),
        "rotator_hard_stop_pct": float(settings.get("rotator_hard_stop_pct")),
        "rotator_daily_cap_mb": float(settings.get("rotator_daily_cap_mb")),
        "rotator_budget_alert_pcts": list(settings.get("rotator_budget_alert_pcts") or ()),
    }


@router.get("/rotator/budget")
async def rotator_budget(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """This billing cycle: used, projected (with a 90 percent band), remaining and cost (plan 8.4, D12)."""
    return await budget_answer(get_ctx(request))


async def budget_answer(ctx: Any) -> dict[str, Any]:
    """The answer of `GET /egress/rotator/budget` (the Egress page's Budget card renders it)."""
    egress = egress_of(ctx)
    settings = _budget_settings(ctx.settings)
    now = ctx.clock.now()
    start, end = read_state.billing_cycle(now, settings["rotator_billing_day"])
    today = day_start_for(now)

    def read(conn: Any) -> tuple[int, list[int], int]:
        used = usage_since(conn, Egress.ROTATOR.value, start)
        trailing = read_upstream.rotator_daily_bytes(conn, today - read_state.TRAILING_DAYS * DAY_S, today)
        return used, trailing, usage_since(conn, Egress.ROTATOR.value, today)

    used, trailing, today_bytes = await ctx.dbs.metrics.read(read)
    projection = read_state.project_cycle(
        cycle_start=start, cycle_end=end, now_s=now, used_bytes=used, trailing=trailing
    )
    quota = int(settings["rotator_quota_gb_per_month"] * DECIMAL_GB)
    price = settings["rotator_price_per_gb_usd"]
    remaining = max(0, quota - used) if quota > 0 else None
    snapshot = egress.rotator.usage_snapshot()
    tiles = [
        common.kpi_tile(
            "rotator_cycle_bytes",
            label="Used this cycle",
            value=used,
            unit="bytes",
            good_direction="down",
            help="Metered rotator bytes since the cycle began (all workers, as flushed to metrics.db).",
        ),
        common.kpi_tile(
            "rotator_projected_bytes",
            label="Projected",
            value=projection.projected_bytes,
            unit="bytes",
            good_direction="down",
            help="Used plus the blended daily rate times the days left in the cycle.",
        ),
        common.kpi_tile(
            "rotator_remaining_bytes",
            label="Remaining",
            value=remaining,
            unit="bytes",
            good_direction="up",
            help="Quota minus used (unknown while rotator_quota_gb_per_month is 0).",
            notice=None if quota > 0 else "Set rotator_quota_gb_per_month to see what is left (plan D12).",
        ),
        common.kpi_tile(
            "rotator_cost_usd",
            label="Cost so far",
            value=read_state.cost_usd(used, price),
            unit="usd",
            good_direction="down",
            help="Used times rotator_price_per_gb_usd (decimal GB).",
            notice=None if price > 0 else "Set rotator_price_per_gb_usd to see the cost (plan D12).",
        ),
    ]
    return {
        "cycle": {"start": start, "end": end, "today_bytes": today_bytes},
        "tiles": tiles,
        "projection": projection.as_dict()
        | {
            "projected_pct_of_quota": read_state.pct_of(projection.projected_bytes, quota),
            "projected_cost_usd": read_state.cost_usd(projection.projected_bytes or 0, price)
            if projection.projected_bytes is not None
            else None,
            "sentence": _projection_sentence(projection, quota, price),
        },
        "quota_bytes": quota or None,
        "hard_stop_bytes": snapshot.hard_stop_bytes or None,
        "daily_cap_bytes": snapshot.daily_cap_bytes or None,
        "stopped": snapshot.stopped,
        "stop_reason": snapshot.stop_reason,
        "settings": settings,
        "settings_card": "egress#budget",
    }


def _projection_sentence(projection: read_state.Projection, quota: int, price: float) -> str:
    """Plan 8.4's sentence: "At this rate you will use 14.2 GB of 20 GB this cycle (71%), about 42.60 USD"."""
    if projection.projected_bytes is None:
        return "Not enough rotator usage yet to project this cycle."
    text = f"At this rate you will use {_gb(projection.projected_bytes)} GB"
    if quota > 0:
        text += f" of {_gb(quota)} GB this cycle ({read_state.pct_of(projection.projected_bytes, quota)}%)"
    else:
        text += " this cycle"
    cost = read_state.cost_usd(projection.projected_bytes, price)
    if cost is not None:
        text += f", about {cost:.2f} USD"
    return text + "."


@router.get("/rotator/daily")
async def rotator_daily(
    request: Request, _admin: AdminSession, cycle: Literal["current", "previous"] = "current"
) -> dict[str, Any]:
    """One bar per UTC day of the billing cycle (bytes, cumulative) with the quota and an even-pace line."""
    return await daily_answer(get_ctx(request), cycle)


async def daily_answer(ctx: Any, cycle: Literal["current", "previous"] = "current") -> dict[str, Any]:
    """The answer of `GET /egress/rotator/daily` (the Budget card's daily bars)."""
    settings = _budget_settings(ctx.settings)
    now = ctx.clock.now()
    start, end = read_state.billing_cycle(now, settings["rotator_billing_day"])
    if cycle == "previous":
        start, end = read_state.previous_cycle(start, settings["rotator_billing_day"])
    values = await ctx.dbs.metrics.read(lambda conn: read_upstream.rotator_daily_bytes(conn, start, end))
    quota = int(settings["rotator_quota_gb_per_month"] * DECIMAL_GB)
    days = len(values)
    cumulative = 0
    bars = []
    for i, value in enumerate(values):
        day = start + i * DAY_S
        cumulative += value
        bars.append(
            {
                "start": day,
                "bytes": value,
                "cumulative_bytes": cumulative,
                "even_pace_bytes": round(quota * (i + 1) / days) if quota > 0 and days else None,
                "future": day > now,
            }
        )
    return {
        "cycle": {"start": start, "end": end, "which": cycle},
        "days": bars,
        "quota_bytes": quota or None,
        "daily_cap_bytes": int(settings["rotator_daily_cap_mb"] * 1_000_000) or None,
        "hard_stop_bytes": int(quota * settings["rotator_hard_stop_pct"] / 100) if quota > 0 else None,
    }


# ------------------------------------------------------------------------------------------ bytes and calls


@router.get("/bytes-per-request")
async def bytes_per_request(
    request: Request, _admin: AdminSession, tr: TimeRangeDep, egress: EgressName = "rotator"
) -> dict[str, Any]:
    """How many calls fell in each bytes-per-call slot on one egress (from per-minute averages; see `basis`)."""
    return await bytes_per_request_answer(get_ctx(request), tr, egress)


async def bytes_per_request_answer(ctx: Any, tr: TimeRange, egress: str = "rotator") -> dict[str, Any]:
    """The answer of `GET /egress/bytes-per-request` (the Top endpoints card shows the distribution)."""
    window = tr.window
    data = await ctx.dbs.metrics.read(lambda conn: read_upstream.bytes_per_call_histogram(conn, window, egress))
    return {"range": tr.info(), **data}


@router.get("/top-endpoints")
async def top_endpoints(
    request: Request,
    admin: AdminSession,
    tr: TimeRangeDep,
    tq: Annotated[TableQuery, Depends(table_params(TOP_SPEC))],
    fmt: ExportFormatDep,
    egress: EgressName = "rotator",
) -> Any:
    """Endpoints by metered wire bytes on one egress (default the rotator: the ones that cost money)."""
    rows, total_bytes = await top_endpoint_rows(get_ctx(request), tr, egress)
    if fmt is not None:
        whole = common.TableQuery(1, common.MAX_EXPORT_ROWS, tq.sort, tq.order, tq.q)
        items, total = common.page_rows(rows, whole, search_keys=TOP_SEARCH)
        return await common.export_table(
            request, admin, TOP_SPEC, items, fmt, total=total, tq=tq, tr=tr, filters={"egress": egress}
        )
    return top_endpoints_answer(rows, total_bytes, tq, tr, egress)


TOP_SEARCH: Final = ("template",)


async def top_endpoint_rows(ctx: Any, tr: TimeRange, egress: str = "rotator") -> tuple[list[dict[str, Any]], int]:
    """Every endpoint's metered bytes on one egress in the range, with its share, and the egress's total bytes."""
    window = tr.window
    rows = await ctx.dbs.metrics.read(lambda conn: read_upstream.endpoint_bytes(conn, window, egress))
    total_bytes = sum(row["bytes"] for row in rows)
    for row in rows:
        row["share_pct"] = round(row["bytes"] * 100.0 / total_bytes, 2) if total_bytes else None
    return rows, total_bytes


def top_endpoints_answer(
    rows: list[dict[str, Any]], total_bytes: int, tq: TableQuery, tr: TimeRange, egress: str
) -> dict[str, Any]:
    """One page of `top_endpoint_rows` as the `GET /egress/top-endpoints` answer (the page's card renders it)."""
    items, total = common.page_rows(rows, tq, search_keys=TOP_SEARCH)
    return common.table_answer(TOP_SPEC, tq, items, total) | {
        "range": tr.info(),
        "egress": egress,
        "total_bytes": total_bytes,
    }


@router.get("/share")
async def call_share(request: Request, _admin: AdminSession, tr: TimeRangeDep) -> dict[str, Any]:
    """Upstream calls per egress over time, and each egress's share of the calls in every bucket."""
    return await share_answer(get_ctx(request), tr)


async def share_answer(ctx: Any, tr: TimeRange) -> dict[str, Any]:
    """The answer of `GET /egress/share` (calls and share per egress as series)."""
    window = tr.window
    data = await queries.series(ctx.dbs.metrics, window, metrics=["upstream_calls"], group_by="egress")
    buckets = data["buckets"]
    groups = {name: values.get("upstream_calls", []) for name, values in data["groups"].items()}
    totals = [sum(int(group[i] or 0) for group in groups.values()) for i in range(len(buckets))]
    series = []
    for name in EGRESSES:
        values = [int(v or 0) for v in groups.get(name, [0] * len(buckets))]
        shares = [round(v * 100.0 / t, 2) if t else None for v, t in zip(values, totals, strict=True)]
        series.append(
            common.series_entry(f"calls:{name}", f"Calls: {name}", "count", list(zip(buckets, values, strict=True)))
        )
        series.append(
            common.series_entry(f"share:{name}", f"Share: {name}", "pct", list(zip(buckets, shares, strict=True)))
        )
    return common.series_answer(tr, series)


# --------------------------------------------------------------------------------------- exit IPs, sessions


@router.get("/exit-ips")
async def exit_ips(request: Request, admin: AdminSession, reveal: bool = False) -> dict[str, Any]:
    """This worker's recent rotator exit IPs, masked to /24 (IPv6 /48); `reveal=true` shows them whole, audited."""
    ctx = get_ctx(request)
    egress = _egress(request)
    items = egress.rotator.recent_exit_ips(masked=not reveal)
    if reveal:
        actor = common.actor_for(admin)
        request_id = common.request_id_of(request)
        now = int(ctx.clock.now())
        details = {"count": len(items)}

        def write(conn: Any) -> int:
            return audit.record(
                conn, actor, REVEAL_ACTION, "egress:rotator:exit_ips", None, details, None, request_id, at=now
            )

        with common.service_errors():  # no audit row, no reveal (fail closed, plan 9.7)
            await ctx.dbs.control.write(write)
    return exit_ips_view(items, masked=not reveal)


EXIT_IPS_NOTE: Final = "Exit IPs are kept per worker (the last rotator_recent_ips probes); never in the LLM export."


def exit_ips_view(items: list[dict[str, Any]], *, masked: bool) -> dict[str, Any]:
    """The `GET /egress/exit-ips` answer around `RotatorPool.recent_exit_ips` items (the Egress page shows the
    masked form; only this audited route reveals them)."""
    return {"items": items, "masked": masked, "this_worker": True, "note": EXIT_IPS_NOTE}


@router.post("/rotator/probe")
async def probe_rotator(request: Request, _admin: AdminSession, _csrf: CsrfChecked) -> dict[str, Any]:
    """Verify rotation now: which exit IP the rotator gives (shown masked; the exit IP list can reveal it)."""
    egress = _egress(request)
    result = await egress.rotator.exit_ip_probe()
    return {
        "configured": result.configured,
        "enabled": result.enabled,
        "exit_ip": mask_ip(result.exit_ip) if result.exit_ip else "",
        "ok": bool(result.exit_ip),
        "error": common.clean_message(result.error, 300) if result.error else "",
        "latency_ms": result.latency_ms,
        "at": result.at,
    }


@router.get("/sessions")
async def sessions(request: Request, _admin: AdminSession, tr: TimeRangeDep) -> dict[str, Any]:
    """Rotator session health: mode, open sessions, the fleet-wide park and streak, and 429s per exit."""
    return await sessions_answer(get_ctx(request), tr)


async def sessions_answer(ctx: Any, tr: TimeRange) -> dict[str, Any]:
    """The answer of `GET /egress/sessions` (the Egress page's Sessions and Rotator cards)."""
    egress = egress_of(ctx)
    pool = egress.rotator
    settings = ctx.settings
    now_ms = int(ctx.clock.now_ms())
    window = tr.window
    with common.service_errors():
        health = await ctx.dbs.hot.read(lambda conn: read_state.rotator_health(conn, now_ms))
    exits = await ctx.dbs.metrics.read(lambda conn: read_upstream.exit_status_counts(conn, window.start, window.end))
    template_set = bool(str(settings.get("rotator_session_username_template") or ""))
    available, why, retry = pool.availability()
    return {
        "range": tr.info(),
        "configured": bool(pool.configured()),
        "available": bool(available),
        "unavailable_reason": why or None,
        "retry_after_s": retry,
        "mode": str(settings.get("rotator_session_mode")),
        "effective_mode": pool.effective_mode(),
        "username_template_set": template_set,
        "mode_note": None
        if template_set
        else "Sticky modes need rotator_session_username_template; until it is set every request gets a new exit.",
        "sticky_seconds": settings.get("rotator_sticky_seconds"),
        "max_sessions": settings.get("rotator_max_sessions"),
        "open_sessions_this_worker": pool.session_count(),
        "health": health,
        "exits": exits,
        "exits_note": "An exit is a short hash of a rotator session (never its IP).",
        "session_lifetimes": None,
        "settings_card": "egress#rotator",
    }


# ---------------------------------------------------------------------------------------- provider report


class ProviderReportBody(ApiBody):
    """`POST /provider-report`: the provider dashboard's figure for this cycle, in decimal GB."""

    reported_gb: Annotated[float, Field(ge=0, le=MAX_PROVIDER_GB, allow_inf_nan=False)]
    reason: Reason = ""


async def provider_view(ctx: Any) -> dict[str, Any]:
    """The answer of `GET /egress/provider-report` (the Egress page's Budget card shows it next to its form)."""
    billing_day = int(ctx.settings.get("rotator_billing_day"))
    start, end = read_state.billing_cycle(ctx.clock.now(), billing_day)

    def read(conn: Any) -> tuple[dict[str, Any] | None, int]:
        return read_history.latest_provider_report(conn), usage_since(conn, Egress.ROTATOR.value, start)

    latest, metered = await ctx.dbs.metrics.read(read)
    diff_pct = None
    if latest is not None and int(latest.get("reported_bytes") or 0) > 0:
        reported = int(latest["reported_bytes"])
        diff_pct = round((metered - reported) * 100.0 / reported, 2)
    return {
        "cycle": {"start": start, "end": end},
        "latest": latest,
        "metered_bytes": metered,
        "diff_pct": diff_pct,
        "threshold_pct": ctx.settings.get("insight_egr_calibrate_diff_pct"),
        "note": "EGR-CALIBRATE compares Roxy's metered bytes with the newest figure entered here.",
    }


@router.get("/provider-report")
async def provider_report(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """The newest provider figure, Roxy's metered bytes for the cycle, and how far apart they are."""
    return await provider_view(get_ctx(request))


@router.post("/provider-report", status_code=201)
async def add_provider_report(
    request: Request, admin: AdminSession, _csrf: CsrfChecked, body: ProviderReportBody
) -> dict[str, Any]:
    """Record the provider's byte figure for this cycle (EGR-CALIBRATE input; audited)."""
    ctx = get_ctx(request)
    reason = common.require_reason(body.reason, required=False)
    actor = common.actor_for(admin)
    request_id = common.request_id_of(request)
    now = int(ctx.clock.now())
    reported = round(body.reported_gb * DECIMAL_GB)
    with common.service_errors():
        report_id = await ctx.dbs.metrics.write(
            lambda conn: read_upstream.insert_provider_report(conn, now, reported, actor.label)
        )
    after = {"reported_bytes": reported, "report_id": report_id}

    def write(conn: Any) -> int:
        return audit.record(
            conn, actor, PROVIDER_ACTION, "egress:rotator", None, after, reason or None, request_id, at=now
        )

    try:
        audit_id = await ctx.dbs.control.write(write)
    except SharedStateUnavailable:
        try:
            await ctx.dbs.metrics.write(lambda conn: read_upstream.delete_provider_report(conn, report_id))
        except SharedStateUnavailable:
            log.error("provider_report_unaudited", extra={"fields": {"report_id": report_id}})
        raise common.unavailable("control.db is busy, so the figure could not be audited and was not kept.") from None
    return await provider_view(ctx) | {"audit_id": audit_id}


# ----------------------------------------------------------------------------------- leak guard trips


@router.get("/trips")
async def trips(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """Egresses the leak guard disabled (fleet-wide rows), where it found the credential, and since when."""
    return await trips_answer(get_ctx(request))


async def trips_answer(ctx: Any) -> dict[str, Any]:
    """The answer of `GET /egress/trips` (the Egress page's Leak guard card)."""
    egress = egress_of(ctx)
    with common.service_errors():
        rows = await ctx.dbs.control.read(read_state.leak_trips)
    items = [
        {"egress": name, "tripped_here": egress.tripped(Egress(name)), **rows.get(name, {})}
        for name in (Egress.DIRECT.value, Egress.ROTATOR.value)
        if name in rows or egress.tripped(Egress(name))
    ]
    return {"items": items, "runbook": "Leak guard"}


class EnableBody(ApiBody):
    """`POST /{egress}/enable`: why the egress is safe again (required; it goes in the audit row)."""

    reason: Reason


@router.post("/{name}/enable")
async def enable_egress(
    request: Request,
    admin: AdminFreshMfa,
    _csrf: CsrfChecked,
    body: EnableBody,
    name: Annotated[str, Path(max_length=16)],
) -> dict[str, Any]:
    """Re-enable an egress the leak guard disabled (fresh second factor, reason required, audited)."""
    if name not in (Egress.DIRECT.value, Egress.ROTATOR.value):
        raise common.validation_error({"egress": "Only direct and rotator can be disabled by the leak guard."})
    reason = common.require_reason(body.reason, required=True)
    egress = _egress(request)
    changed = await common.run_mutation(
        egress.enable_egress(
            Egress(name), common.actor_for(admin), reason=reason, request_id=common.request_id_of(request)
        )
    )
    if not changed:
        raise common.conflict(f"The {name} egress is not disabled by the leak guard.", code="wrong_state")
    enabled, why = egress.is_enabled(Egress(name))
    return {"egress": name, "enabled": bool(enabled), "disabled_reason": why or None}


__all__ = [
    "EXIT_IPS_NOTE",
    "TOP_SPEC",
    "budget_answer",
    "bytes_per_request_answer",
    "daily_answer",
    "egress_of",
    "exit_ips_view",
    "provider_view",
    "router",
    "sessions_answer",
    "share_answer",
    "top_endpoint_rows",
    "top_endpoints_answer",
    "trips_answer",
    "usage_answer",
]
