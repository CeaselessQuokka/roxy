"""Admin API: the Overview page (`/admin/api/v1/overview`, plan 14.1 Overview row, 11.6, parity rows 1 to 3, 86, 130).

What this is
    The numbers the Overview page shows, as JSON:
      * `GET /overview`: everything at once (status strip, top 3 recommendations, KPI tiles, Visitors card, the
        requests in versus upstream out chart, the outcome breakdown, top endpoints, top places, recent notable
        events), for one time range.
      * `GET /overview/status`: the status strip alone (proxy, credential, rotator, leader, version, workers).
      * `GET /overview/kpis`: the KPI tiles with sparklines and deltas.
      * `GET /overview/visitors`: the Visitors card (human, crawler and unknown visitors; home and admin page
        visits; robots.txt crawls; row 130).
      * `GET /overview/chart`: requests in versus upstream calls out over the range (with comparison overlay).
      * `GET /overview/recommendations`: the three most severe open recommendations and the open count.
      * `GET /overview/events`: recent notable events as a paged, exportable table.

Why it exists
    The Overview answers "is Roxy healthy and is Roblox still happy with us" at a glance. Plan 11.6 replaced v1's
    lifetime banner ("Roblox has rate-limited us 579 times") with windowed, honest tiles: avoided upstream calls
    (P6: caller demand minus every caller upstream call, refusals excluded), Roblox 429s and Roblox 429s per 10,000
    caller requests next to v1's lifetime baseline (imported into `legacy_totals`), and deltas against a
    comparison period so a change can be judged.

How it works
    Thin: every number comes from a read model (`metrics/queries.py` kpis, series, top N and clients;
    `metrics/read_dashboard.py` for the v1 baseline, visits, sparklines and events; `roxy.insights` for
    recommendations; the worker's own state objects for the status strip). KPI deltas use the requested
    `compare` mode, and the previous period when none is given, so every tile has a delta. Sparklines are the
    same range at a granularity of at most 60 points. Cards that read optional parts (recommendations,
    notable events) degrade open: a failure is a notice on that card, never a failed page (plan C7 lets metrics
    degrade open).

What to read next
    `roxy/admin/api/common.py` (time ranges, tiles, tables), `roxy/metrics/queries.py`,
    `roxy/metrics/read_dashboard.py`, then `roxy/admin/api/traffic.py`.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import replace
from typing import Annotated, Any, Final

from fastapi import Depends, Request

from roxy.admin.api.common import (
    AdminSession,
    Column,
    ExportFormatDep,
    TableQuery,
    TableSpec,
    TimeRange,
    TimeRangeDep,
    annotation_entries,
    area_router,
    export_table,
    kpi_from_read_model,
    kpi_tile,
    page_rows,
    range_info,
    reset_notices,
    series_answer,
    series_from_read_model,
    table_answer,
    table_params,
)
from roxy.deps import get_ctx
from roxy.lifespan import optional_import
from roxy.metrics import queries, read_dashboard
from roxy.metrics.queries import Window
from roxy.scheduler import heartbeat, leader
from roxy.storage import leases
from roxy.storage.db import SharedStateUnavailable

log = logging.getLogger(__name__)

router = area_router("overview")

KPI_KEYS: Final[tuple[str, ...]] = (
    "requests",
    "requests_last_hour",
    "avoided_pct",
    "avoided",
    "upstream_calls",
    "roblox_429",
    "roblox_429_per_10k",
    "roxy_429",
    "status_5xx",
    "roblox_5xx",
    "status_2xx",
    "status_4xx",
    "p95_ms",
    "rotator_bytes_today",
    "active_bans",
    "service_uptime_s",
    "served_cache",
    "errors_hidden",
)
"""The plan 14.1 Overview KPI tiles in display order, plus the two P6 companions (cache serves, errors hidden)."""

SPARK_METRICS: Final[tuple[str, ...]] = (
    "requests",
    "avoided_pct",
    "avoided",
    "upstream_calls",
    "roblox_429",
    "roblox_429_per_10k",
    "roxy_429",
    "status_5xx",
    "roblox_5xx",
    "status_2xx",
    "status_4xx",
    "p95_ms",
    "served_cache",
    "errors_hidden",
)
CHART_METRICS: Final[tuple[str, ...]] = ("requests", "demand", "upstream_calls", "served_cache")
TOP_ROWS: Final = 10
EVENT_ROWS: Final = 20
TOP_RECOMMENDATIONS: Final = 3
MAX_RECOMMENDATIONS_READ: Final = 50

VISITOR_LABELS: Final[dict[str, tuple[str, str]]] = {
    "human_visitors": ("Human visitors", "Visits to the home page from browsers that do not look like bots."),
    "crawler_visitors": ("Crawler visitors", "Visits to the home page from search engines, scripts and other bots."),
    "unknown_visitors": ("Unknown visitors", "Visits to the home page that sent no User-Agent at all."),
    "home_visits": ("Home page visits", "Every load of the public home page."),
    "admin_visits": (
        "Admin page visits",
        "Loads of the admin login page; your own visits stop counting once this browser has signed in (v1 rule).",
    ),
    "robots_crawls": ("robots.txt crawls", "Fetches of robots.txt, almost all of them search engines."),
    "sitemap_crawls": ("Sitemap crawls", "Fetches of sitemap.xml."),
}

OUTCOME_LABELS: Final[dict[str, str]] = {
    "served_upstream": "Served by Roblox",
    "served_cache": "Served from cache",
    "refused": "Refused by Roxy",
    "failed": "Failed",
}

EXTRA_TILES: Final[dict[str, tuple[str, str, str]]] = {
    "requests_last_hour": (
        "Requests (last hour)",
        "requests",
        "Proxy requests in the last 60 minutes, whatever range is selected: the number that says whether Roxy is "
        "busy right now. The delta compares with the hour before.",
    ),
    "rotator_bytes_today": (
        "Rotator bytes today",
        "bytes",
        "Bytes sent and received through the DataImpulse rotator since local midnight (ui_timezone), an estimate "
        "of what the provider bills. The delta compares with the same part of yesterday.",
    ),
    "active_bans": (
        "Active bans",
        "count",
        "IP, network, place and User-Agent bans in force right now, whatever range is selected.",
    ),
    "service_uptime_s": (
        "Service uptime",
        "s",
        "How long this color's oldest running worker has been up. Workers recycle on purpose, so this restarts "
        "only when every worker of the color was replaced (a deploy or a restart).",
    ),
}

EVENTS_SPEC: Final = TableSpec(
    name="overview_events",
    columns=(
        Column("at_ms", "Time", "When it happened (epoch milliseconds).", "ms"),
        Column("type", "Event", "What happened: a breaker, a cooldown, a credential change, a purge, a ban."),
        Column("severity", "Severity", "info, warn or critical."),
        Column("reason", "Reason", "The reason code recorded with the event.", sortable=False),
        Column("endpoint_template", "Endpoint", "The endpoint it concerns, when it concerns one.", sortable=False),
        Column("detail", "Detail", "Everything recorded with the event (secrets are never recorded).", sortable=False),
    ),
    default_sort="at_ms",
)


# --------------------------------------------------------------------------------------------- helpers


def tz_of(ctx: Any) -> str:
    return str(ctx.settings.get("ui_timezone") or "UTC")


def _points(data: Mapping[str, Any], metric: str) -> list[list[Any]]:
    """`[[bucket start, value], ...]` of one metric of an ungrouped `queries.series` answer."""
    values = (data.get("groups") or {}).get("all", {}).get(metric, [])
    return [[start, value] for start, value in zip(data.get("buckets") or [], values, strict=False)]


def _pct(part: float, whole: float) -> float | None:
    return round(part * 100.0 / whole, 2) if whole else None


def _delta(current: Any, previous: Any) -> tuple[float | None, float | None]:
    if not isinstance(current, int | float) or not isinstance(previous, int | float):
        return None, None
    change = current - previous
    return round(change, 4), (round(change * 100.0 / previous, 2) if previous else None)


def _effective_compare(tr: TimeRange) -> str:
    """The comparison of the KPI tiles: the one asked for, else the previous period (tiles always have a delta)."""
    return tr.compare or "previous"


# --------------------------------------------------------------------------------------------- status strip


def _leader_view(conn: sqlite3.Connection) -> tuple[str, int, int] | None:
    return leases.holder_epoch(conn, leader.LEADER_LEASE)


def _pid_of(worker_id: str) -> int | None:
    """The pid inside a worker id `<host>:<pid>:<random>` (the host name is not shown on the dashboard)."""
    parts = worker_id.split(":")
    if len(parts) >= 3 and parts[-2].isdigit():
        return int(parts[-2])
    return None


async def build_status(ctx: Any) -> dict[str, Any]:
    """The status strip (plan 14.1): proxy state with drops since it began (row 114), credential, rotator,
    leader, version and workers. Read from this worker's live state plus three small shared reads."""
    now = ctx.clock.now()
    now_ms = ctx.clock.now_ms()
    switches = getattr(getattr(ctx, "abuse", None), "switches", None)
    proxy: dict[str, Any] = {"ready": bool(getattr(ctx, "ready", False)), "abuse_ready": switches is not None}
    paused = throttle_all = False
    paused_since = throttle_since = 0.0
    if switches is not None:
        paused = bool(switches.pause.active(now))
        paused_since = float(switches.pause.active_since(now)) if paused else 0.0
        throttle_all = bool(switches.throttle_all.enabled)
        throttle_since = float(switches.throttle_all.since) if throttle_all else 0.0
    state = "starting"
    if proxy["ready"] and switches is not None:
        state = "paused" if paused else ("throttle_all" if throttle_all else "running")
    proxy.update(
        state=state,
        paused=paused,
        paused_since=paused_since or None,
        throttle_all=throttle_all,
        throttle_all_since=throttle_since or None,
    )

    def drops(conn: sqlite3.Connection) -> tuple[int | None, int | None]:
        pause_drops = queries.drops_since(conn, "paused", paused_since, now) if paused else None
        throttle_drops = queries.drops_since(conn, "throttle_all", throttle_since, now) if throttle_all else None
        return pause_drops, throttle_drops

    if paused or throttle_all:
        proxy["pause_drops"], proxy["throttle_all_drops"] = await ctx.dbs.metrics.read(drops)
    else:
        proxy["pause_drops"] = proxy["throttle_all_drops"] = None

    credential: dict[str, Any] = {"status": "not_built"}
    manager = getattr(getattr(ctx, "egress", None), "credential", None)
    if manager is not None:
        found = manager.status()
        # Never the value, never its fingerprint: the strip only says whether the credential can be used.
        credential = {
            "status": found.status,
            "enabled": bool(found.enabled),
            "present": bool(found.present),
            "cooldown_remaining_s": float(found.cooldown_remaining_s),
            "problem": found.problem,
        }

    rotator: dict[str, Any] = {"configured": False, "usable": False, "reason": "not_built", "retry_after_s": None}
    pool = getattr(getattr(ctx, "egress", None), "rotator", None)
    if pool is not None:
        usable, reason, retry_after = pool.availability()
        rotator = {
            "configured": bool(pool.configured()),
            "usable": bool(usable),
            "reason": reason or None,
            "retry_after_s": retry_after,
        }

    lead: dict[str, Any] = {"this_worker": False, "pid": None, "epoch": None, "expires_in_s": None}
    elector = getattr(ctx, "leader", None)
    if elector is not None:
        lead["this_worker"] = bool(elector.is_leader)
    try:
        holder = await ctx.dbs.hot.read(_leader_view)
    except SharedStateUnavailable:
        holder = None
        lead["unavailable"] = True
    if holder is not None:
        holder_id, epoch, expires_ms = holder
        live = expires_ms > now_ms
        lead.update(
            pid=_pid_of(holder_id) if live else None,
            epoch=int(epoch),
            expires_in_s=round(max(0, expires_ms - now_ms) / 1000.0, 1) if live else 0.0,
        )

    color = str(getattr(ctx, "color", "") or "")
    counts = await ctx.dbs.metrics.read(lambda conn: heartbeat.fresh_counts(conn, now))
    workers = {
        "color": color,
        "fresh": int(counts.get(color, 0)),
        "expected": int(getattr(ctx.env, "workers", 0) or 0),
        "fresh_by_color": counts,
    }
    version = {
        "release": str(getattr(ctx, "release", "") or ""),
        "config_version": int(getattr(ctx.settings, "version", 0) or 0),
        "color": color,
    }
    return {
        "at": now,
        "proxy": proxy,
        "credential": credential,
        "rotator": rotator,
        "leader": lead,
        "version": version,
        "workers": workers,
    }


# --------------------------------------------------------------------------------------------- KPI tiles


def _active_bans(ctx: Any, now: float) -> int:
    """Bans in force now, from this worker's rules snapshot (reloaded within a second of any ban change)."""
    snapshot = getattr(getattr(ctx, "rules", None), "snapshot", None)
    bans = getattr(snapshot, "bans", None)
    rows = getattr(bans, "rows", ()) or ()
    return sum(1 for row in rows if row.expires_at is None or row.expires_at > now)


def _service_uptime(ctx: Any, conn: sqlite3.Connection, now: float) -> int | None:
    color = str(getattr(ctx, "color", "") or "")
    fresh = [row for row in heartbeat.fleet_view(conn, now) if row["fresh"] and (row.get("color") or "") == color]
    if not fresh:
        return None
    return max(0, int(now) - min(int(row["started_at"]) for row in fresh))


def _hour_windows(now: float, tz: str) -> tuple[Window, Window]:
    """The trailing hour (as `queries.kpis` counts it) and the hour before it."""
    current = Window(int(now) - 3600, int(now) + 1, "minute", tz)
    return current, Window(current.start - 3600, current.start, "minute", tz)


def _rotator_today(conn: sqlite3.Connection, now: float, tz: str) -> dict[str, Any]:
    start = read_dashboard.day_start(now, tz)
    end = int(now) - int(now) % 60 + 60
    today = Window(start, end, "hour", tz)
    yesterday = Window(start - 86_400, end - 86_400, "hour", tz)
    usage = queries.egress_usage_series(conn, today)
    spark = usage["egress"].get("rotator", {}).get("bytes", [0] * len(usage["buckets"]))
    return {
        "value": queries.egress_bytes(conn, today).get("rotator", 0),
        "previous": queries.egress_bytes(conn, yesterday).get("rotator", 0),
        "sparkline": [[b, v] for b, v in zip(usage["buckets"], spark, strict=False)],
    }


def _extra_tile(
    key: str, value: Any, *, previous: Any = None, sparkline: Sequence[Sequence[Any]] = (), notice: str | None = None
) -> dict[str, Any]:
    label, unit, help_text = EXTRA_TILES[key]
    delta, delta_pct = _delta(value, previous)
    direction = {"requests_last_hour": "neutral", "rotator_bytes_today": "down"}.get(key, "neutral")
    return kpi_tile(
        key,
        label=label,
        value=value,
        unit=unit,
        delta=delta,
        delta_pct=delta_pct,
        good_direction=direction,  # type: ignore[arg-type]
        sparkline=sparkline,
        help=help_text,
        notice=notice,
    )


def _baseline_notice(baseline: Mapping[str, Any] | None) -> str | None:
    if not baseline or baseline.get("value") is None:
        return None
    return f"v1 lifetime baseline: {baseline['value']} per 10,000 requests (imported from v1, a lifetime figure)."


async def build_kpis(ctx: Any, tr: TimeRange) -> dict[str, Any]:
    """Every Overview KPI tile with its sparkline and delta (see the module docstring)."""
    window = tr.window
    compare = _effective_compare(tr)
    now = ctx.clock.now()
    tz = window.tz
    spark_window = read_dashboard.sparkline_window(window)
    hour, before = _hour_windows(now, tz)

    def read(conn: sqlite3.Connection) -> dict[str, Any]:
        return {
            "kpis": queries.kpis_sync(conn, window, now=now, compare=compare),
            "spark": queries.series_sync(conn, spark_window, metrics=list(SPARK_METRICS)),
            "hour_spark": queries.series_sync(conn, hour, metrics=["requests"]),
            "previous_hour": queries.totals_sync(conn, before)["requests"],
            "rotator": _rotator_today(conn, now, tz),
            "uptime": _service_uptime(ctx, conn, now),
            "legacy": read_dashboard.legacy_baseline(conn),
        }

    data = await ctx.dbs.metrics.read(read)
    tiles_in = data["kpis"]["tiles"]
    spark = data["spark"]
    legacy = data["legacy"]
    tiles: list[dict[str, Any]] = []
    for key in KPI_KEYS:
        if key == "requests_last_hour":
            tiles.append(
                _extra_tile(
                    key,
                    tiles_in[key]["value"],
                    previous=data["previous_hour"],
                    sparkline=_points(data["hour_spark"], "requests"),
                )
            )
        elif key == "rotator_bytes_today":
            rot = data["rotator"]
            tiles.append(_extra_tile(key, rot["value"], previous=rot["previous"], sparkline=rot["sparkline"]))
        elif key == "active_bans":
            tiles.append(_extra_tile(key, _active_bans(ctx, now)))
        elif key == "service_uptime_s":
            tiles.append(_extra_tile(key, data["uptime"]))
        else:
            tile = kpi_from_read_model(key, tiles_in[key], sparkline=_points(spark, key))
            current = tiles_in.get(key, {})
            if key == "avoided_pct":
                avoided, demand = tiles_in["avoided"]["value"], tiles_in["demand"]["value"]
                if demand:
                    tile["notice"] = (
                        f"{avoided:,} of {demand:,} caller requests needed no call to Roblox (refused requests are "
                        "not counted as demand)."
                    )
            elif key == "roblox_429":
                calls = tiles_in["upstream_calls"]["value"]
                share = _pct(float(current.get("value") or 0), float(calls or 0))
                if share is not None:
                    tile["notice"] = f"{share}% of the upstream calls made for callers."
            elif key == "roblox_429_per_10k":
                baseline = legacy.get("roblox_429_per_10k")
                tile["baseline"] = baseline  # v1 lifetime value from legacy_totals (plan 11.6), None when absent
                tile["notice"] = _baseline_notice(baseline)
            tiles.append(tile)
    return {
        "range": tr.info(),
        "compare": {"mode": compare, "range": data["kpis"].get("compare", {}).get("window")},
        "sparkline_granularity": spark_window.granularity,
        "sparkline_range": range_info(spark_window),
        "tiles": tiles,
        "notices": reset_notices(data["kpis"].get("notices") or [], tz=tz),
    }


# --------------------------------------------------------------------------------------------- visitors


async def build_visitors(ctx: Any, tr: TimeRange) -> dict[str, Any]:
    """The Visitors card (row 130): the v1 tiles plus unknown visitors and sitemap fetches, with deltas."""
    window = tr.window
    other = queries.comparison_window(window, _effective_compare(tr))
    spark_window = read_dashboard.sparkline_window(window)

    def read(conn: sqlite3.Connection) -> tuple[dict[str, int], dict[str, int], dict[str, Any]]:
        return (
            queries.visitor_kpis(conn, window),
            queries.visitor_kpis(conn, other),
            read_dashboard.visit_series(conn, spark_window),
        )

    current, previous, series = await ctx.dbs.metrics.read(read)
    tiles = []
    for key in read_dashboard.VISIT_KEYS:
        label, help_text = VISITOR_LABELS[key]
        delta, delta_pct = _delta(current.get(key, 0), previous.get(key, 0))
        points = [[b, v] for b, v in zip(series["buckets"], series["values"][key], strict=False)]
        tiles.append(
            kpi_tile(
                key,
                label=label,
                value=current.get(key, 0),
                unit="count",
                delta=delta,
                delta_pct=delta_pct,
                sparkline=points,
                help=help_text,
            )
        )
    return {"range": tr.info(), "compare": {"mode": _effective_compare(tr), "range": range_info(other)}, "tiles": tiles}


# --------------------------------------------------------------------------------------------- chart


async def build_chart(ctx: Any, tr: TimeRange) -> dict[str, Any]:
    """Requests in versus upstream calls out (plus demand and cache serves), with the comparison overlay."""
    db = ctx.dbs.metrics
    data = await queries.series(db, tr.window, metrics=list(CHART_METRICS))
    series: list[dict[str, Any]] = []
    for metric in CHART_METRICS:
        series += series_from_read_model(data, metric)
    compare_series = None
    if tr.compare_window is not None:
        other = await queries.series(db, tr.compare_window, metrics=list(CHART_METRICS))
        compare_series = [entry for metric in CHART_METRICS for entry in series_from_read_model(other, metric)]
    start, end = tr.window.start, tr.window.end

    def marks(conn: sqlite3.Connection) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        return queries.chart_annotations(conn, start, end), queries.reset_annotations(conn, start, end)

    annotations, resets = await db.read(marks)
    return series_answer(
        tr,
        series,
        compare_series=compare_series,
        annotations=annotation_entries(annotations),
        notices=reset_notices(resets, tz=tr.window.tz),
    )


# --------------------------------------------------------------------------------------------- tables


async def build_breakdown(ctx: Any, tr: TimeRange) -> dict[str, Any]:
    """Outcome breakdown, top endpoints and top places for the range (each at most `TOP_ROWS` rows)."""
    window = tr.window
    now = ctx.clock.now()
    top_page = queries.Page(size=TOP_ROWS, sort="requests")

    def read(conn: sqlite3.Connection) -> dict[str, Any]:
        return {
            "outcomes": queries.top_n_sync(conn, window, "outcome", page=queries.Page(size=10, sort="requests")),
            "endpoints": queries.endpoint_table_sync(conn, window, page=top_page),
            "places": queries.client_table_sync(conn, window, "place", now=now, page=top_page),
        }

    data = await ctx.dbs.metrics.read(read)
    total = sum(int(row["requests"]) for row in data["outcomes"]["rows"])
    outcomes = []
    for row in data["outcomes"]["rows"]:
        key = str(row["key"])
        item: dict[str, Any] = {
            "outcome": key,
            "label": OUTCOME_LABELS.get(key, key),
            "requests": int(row["requests"]),
            "share_pct": _pct(float(row["requests"]), float(total)),
        }
        if key == "served_upstream":
            # OPTIONS answered locally are recorded with this outcome (the closest value of the closed enum);
            # nothing reached Roblox for them, so they are shown apart (P6, finding spec-7).
            item["answered_locally"] = int(row["requests"]) - int(row["served_upstream"])
        outcomes.append(item)
    endpoint_keys = ("key", "requests", "demand", "upstream_calls", "avoided_pct", "hit_ratio", "roblox_429", "p95_ms")
    place_keys = ("key", "requests", "refused", "served", "refused_pct", "rate1", "rate5", "rate60", "top_endpoint")
    return {
        "outcomes": {"total": total, "items": outcomes},
        "top_endpoints": [{k: row.get(k) for k in endpoint_keys} for row in data["endpoints"]["rows"]],
        "top_places": [{k: row.get(k) for k in place_keys} for row in data["places"]["rows"]],
    }


async def build_events(ctx: Any, window: Window, *, limit: int = EVENT_ROWS, offset: int = 0) -> dict[str, Any]:
    start_ms, end_ms = window.start * 1000, window.end * 1000
    found: dict[str, Any] = await ctx.dbs.metrics.read(
        lambda conn: read_dashboard.notable_events(conn, start_ms, end_ms, limit=limit, offset=offset)
    )
    return found


# --------------------------------------------------------------------------------------------- recommendations


def _recommendation_card(rec: Any) -> dict[str, Any]:
    payload = rec.to_payload()
    keep = (
        "id",
        "rule_id",
        "family",
        "subject",
        "severity",
        "confidence",
        "title",
        "expected_impact",
        "risk",
        "state",
        "updated_at",
    )
    return {key: payload.get(key) for key in keep}


async def build_recommendations(ctx: Any) -> dict[str, Any]:
    """The top `TOP_RECOMMENDATIONS` open recommendations, most severe and newest first (plan 14.1, row 86).

    Read through `roxy.insights.engine` when the package is installed (the engine is built without its rules,
    so this is only a read of the `recommendations` table).
    """
    engine_mod = optional_import("roxy.insights.engine")
    if engine_mod is None:
        return {"available": False, "items": [], "open": 0}
    engine = engine_mod.InsightsEngine(
        dbs=ctx.dbs, settings=ctx.settings, rules=ctx.rules, clock=ctx.clock, rule_set={}
    )
    found = await engine.list(states=("open",), limit=MAX_RECOMMENDATIONS_READ)
    return {
        "available": True,
        "open": len(found),
        "open_capped": len(found) >= MAX_RECOMMENDATIONS_READ,
        "items": [_recommendation_card(rec) for rec in found[:TOP_RECOMMENDATIONS]],
    }


async def _optional(name: str, call: Any, fallback: dict[str, Any], notices: list[str]) -> dict[str, Any]:
    """Run one optional card; a failure becomes a notice instead of failing the page (metrics degrade open)."""
    try:
        result: dict[str, Any] = await call
        return result
    except (SharedStateUnavailable, sqlite3.Error) as exc:
        log.warning("overview_card_failed", extra={"fields": {"card": name, "error": str(exc)[:200]}})
        notices.append(f"The {name} card could not be read right now; try again shortly.")
        return fallback


# --------------------------------------------------------------------------------------------- routes


@router.get("")
async def overview(request: Request, _admin: AdminSession, tr: TimeRangeDep) -> dict[str, Any]:
    """Everything the Overview page shows for the range (see the module docstring)."""
    ctx = get_ctx(request)
    notices: list[str] = []
    status = await build_status(ctx)
    kpis = await build_kpis(ctx, tr)
    visitors = await build_visitors(ctx, tr)
    chart = await build_chart(ctx, tr)
    breakdown = await build_breakdown(ctx, tr)
    events = await _optional("events", build_events(ctx, tr.window), {"total": 0, "rows": []}, notices)
    recommendations = await _optional(
        "recommendations", build_recommendations(ctx), {"available": False, "items": [], "open": 0}, notices
    )
    return {
        "range": tr.info(),
        "status": status,
        "recommendations": recommendations,
        "kpis": kpis,
        "visitors": visitors,
        "requests_vs_upstream": chart,
        **breakdown,
        "events": events,
        "notices": [*kpis["notices"], *notices],
    }


@router.get("/status")
async def overview_status(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """The status strip alone (refreshed by the dashboard more often than the rest)."""
    return await build_status(get_ctx(request))


@router.get("/kpis")
async def overview_kpis(request: Request, _admin: AdminSession, tr: TimeRangeDep) -> dict[str, Any]:
    """The KPI tiles with sparklines and deltas."""
    return await build_kpis(get_ctx(request), tr)


@router.get("/visitors")
async def overview_visitors(request: Request, _admin: AdminSession, tr: TimeRangeDep) -> dict[str, Any]:
    """The Visitors card (row 130)."""
    return await build_visitors(get_ctx(request), tr)


@router.get("/chart")
async def overview_chart(request: Request, _admin: AdminSession, tr: TimeRangeDep) -> dict[str, Any]:
    """Requests in versus upstream calls out (a series answer)."""
    return await build_chart(get_ctx(request), tr)


@router.get("/recommendations")
async def overview_recommendations(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """The top three open recommendations (the full list is on the Recommendations page)."""
    return await build_recommendations(get_ctx(request))


@router.get("/events")
async def overview_events(
    request: Request,
    admin: AdminSession,
    tr: TimeRangeDep,
    tq: Annotated[TableQuery, Depends(table_params(EVENTS_SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    """The newest notable events in the range (at most `MAX_EVENTS_PAGE` of them, the card is a recent list),
    sorted, searched and paged on the server; `format=csv|json` downloads them."""
    ctx = get_ctx(request)
    found = await build_events(ctx, tr.window, limit=read_dashboard.MAX_EVENTS_PAGE)
    rows = list(found["rows"])
    keys = ("type", "severity", "reason", "endpoint_template")
    if fmt is not None:
        ordered, total = page_rows(rows, replace(tq, page=1, page_size=max(1, len(rows))), search_keys=keys)
        return await export_table(request, admin, EVENTS_SPEC, ordered, fmt, total=total, tq=tq, tr=tr)
    items, total = page_rows(rows, tq, search_keys=keys)
    answer = table_answer(EVENTS_SPEC, tq, items, total)
    answer["capped"] = int(found["total"]) > len(rows)  # older events exist beyond the recent list
    return answer


__all__ = [
    "KPI_KEYS",
    "build_breakdown",
    "build_chart",
    "build_events",
    "build_kpis",
    "build_recommendations",
    "build_status",
    "build_visitors",
    "router",
]
