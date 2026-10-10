"""Admin API: the Traffic page (`/admin/api/v1/traffic`, plan 14.1 Traffic row, 14.2, 14.3, parity rows 68 to 70,
131 and 132).

What this is
    Charts and tables of what went through Roxy over a time range:
      * `GET /traffic/requests`: requests over time stacked by outcome (served by Roblox, served from cache,
        refused, failed), with the comparison overlay and chart annotations.
      * `GET /traffic/bytes`: caller and upstream bytes in and out over time, with totals per egress (14.3).
      * `GET /traffic/verbs` and `/traffic/verbs/table`: requests by HTTP method (v1 "Counts by Method").
      * `GET /traffic/status` (`view=class` or `view=source`) and `/traffic/status/sources`: status classes over
        time, and v1's "Who returned it?" table of status codes by source with the 429 verdict (rows 68, 132).
      * `GET /traffic/heatmap`: hour of day by weekday in `ui_timezone`.
      * `GET /traffic/latency` and `/traffic/latency/split`: p50, p95 and p99 over time, and the split per verb,
        per egress, per host or per outcome (row 131, v1's Proxy Timings toggle).
      * `GET /traffic/trends`: week over week, month over month and year over year tables with sparklines (14.3).

Why it exists
    v1 kept 180 minutes of traffic in a JSON file and drew the last 60; everything else was a lifetime counter
    (rows 69, 70). v2 answers "when?" for every number, compares periods, and keeps the source split that tells
    "Roblox is rate limiting us" (act now) from "Roxy is rate limiting callers" (the system working).

How it works
    Thin over `metrics/queries.py` (series, totals, top N, `answer_source_counts`) and `metrics/read_dashboard.py`
    (the heatmap fold, sparkline windows). Roblox 429s always come from the `upstream_429` log, counted once per
    upstream attempt, never from caller status codes. "Who returned it?" reads the source through
    `queries.ANSWER_SOURCE_SQL`: a Roblox 5xx passed on after the retries (`upstream_5xx`) carries Roblox's status
    and Roxy's text, so it counts as Roblox's (`relay`), in the table, the source series and the `roblox_5xx` and
    `roxy_5xx` tiles alike (finding parity-1). A series' reset notices name only resets of the data it reads
    (`queries.reset_touches`, plan 6.8). Tables page and sort on the server and export as CSV or JSON through the
    shared `export_table` (audited, formula guarded).

What to read next
    `roxy/admin/api/common.py`, `roxy/metrics/queries.py`, `roxy/admin/api/endpoints.py`.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from dataclasses import replace
from typing import Annotated, Any, Final

from fastapi import Depends, Query, Request

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
    export_pages,
    export_table,
    page_rows,
    range_info,
    reset_notices,
    series_answer,
    series_from_read_model,
    table_answer,
    table_from_read_model,
    table_params,
    validation_error,
)
from roxy.deps import get_ctx
from roxy.metrics import queries, read_dashboard
from roxy.metrics.catalog import METRICS

router = area_router("traffic")

BYTE_METRICS: Final[tuple[str, ...]] = (
    "caller_bytes_in",
    "caller_bytes_out",
    "upstream_bytes_in",
    "upstream_bytes_out",
    "cache_bytes_out",
)
STATUS_METRICS: Final[tuple[str, ...]] = ("status_2xx", "status_4xx", "status_5xx", "roxy_429", "roblox_429")
LATENCY_METRICS: Final[tuple[str, ...]] = ("p50_ms", "p95_ms", "p99_ms", "queue_wait_p95_ms")
HEATMAP_METRICS: Final[tuple[str, ...]] = ("requests", "demand", "upstream_calls", "served_cache", "refused", "failed")
SPLITS: Final[dict[str, str]] = {
    "method": "method",
    "verb": "method",
    "egress": "egress",
    "host": "host",
    "outcome": "outcome",
}
"""Latency split choices (row 131): `verb` is v1's name for the HTTP method."""
MAX_SERIES_GROUPS: Final = 10
TREND_METRICS: Final[tuple[str, ...]] = (
    "requests",
    "demand",
    "avoided",
    "avoided_pct",
    "upstream_calls",
    "roblox_429",
    "roblox_429_per_10k",
    "roxy_429",
    "status_5xx",
    "errors_hidden",
    "p95_ms",
    "caller_bytes_out",
    "upstream_bytes_in",
)
TREND_PERIODS: Final[tuple[tuple[str, str, str], ...]] = (
    ("week", "Week over week", "7d"),
    ("month", "Month over month", "30d"),
    ("year", "Year over year", "1y"),
)
"""(key, label, range): each compares the trailing range with the one just before it."""

SOURCE_LABELS: Final[dict[str, tuple[str, str]]] = {
    "roblox": ("Roblox to caller", "Roblox's own answer, passed to the caller as it came."),
    "relay": (
        "Roblox to caller (relayed)",
        "Roblox's answer passed to the caller after Roxy reformatted it: pretty printed, the browser view, or a "
        "Roblox server error passed on with Roxy's retry text after the allowed retries.",
    ),
    "roxy": ("Roxy (its own answers)", "Statuses Roxy produced: refusals, its own errors, pause, limits."),
    "cache": ("Cache to caller", "Answers from Roxy's cache: Roblox never saw these requests."),
    "internal": ("Roxy's own calls", "Roxy's own probes and lookups, not caller traffic."),
}
"""v1 SOURCE_LABELS and hints (dashboard.md 4.16), reworded for v2's sources and plan C5."""

VERB_COLUMNS: Final[tuple[Column, ...]] = (
    Column("key", "Method", "The HTTP method callers used (HEAD is counted as GET, as it runs as GET)."),
    Column("requests", "Requests", "Every request with this method.", "requests"),
    Column("served_upstream", "Served by Roblox", METRICS["served_upstream"].description, "requests"),
    Column("served_cache", "Served from cache", METRICS["served_cache"].description, "requests"),
    Column("refused", "Refused", METRICS["refused"].description, "requests"),
    Column("failed", "Failed", METRICS["failed"].description, "requests"),
    Column("status_2xx", "2xx", "Successful answers sent to callers.", "requests"),
    Column("status_4xx", "4xx", "Client error answers sent to callers.", "requests"),
    Column("status_5xx", "5xx", "Server error answers sent to callers.", "requests"),
    Column("p95_ms", "p95", METRICS["p95_ms"].description, "ms"),
)
VERBS_SPEC: Final = TableSpec(name="traffic_verbs", columns=VERB_COLUMNS, default_sort="requests")

SOURCES_SPEC: Final = TableSpec(
    name="traffic_status_sources",
    columns=(
        Column("source", "Source", "Who produced the status code the caller received."),
        Column("source_label", "Who returned it", "The source in plain words.", sortable=False),
        Column("status", "Status code", "The HTTP status code.", ""),
        Column("requests", "Requests", "How many requests got this status from this source.", "requests"),
    ),
    default_sort="requests",
)

SPLIT_COLUMNS: Final[tuple[Column, ...]] = (
    Column("key", "Group", "The verb, egress, host or outcome."),
    Column("requests", "Requests", "Requests in the group (the latency histogram covers caller traffic).", "requests"),
    Column("p50_ms", "p50", METRICS["p50_ms"].description, "ms"),
    Column("p95_ms", "p95", METRICS["p95_ms"].description, "ms"),
    Column("p99_ms", "p99", METRICS["p99_ms"].description, "ms"),
    Column("queue_wait_p95_ms", "Queue wait p95", METRICS["queue_wait_p95_ms"].description, "ms", sortable=False),
    Column("failed", "Failed", METRICS["failed"].description, "requests"),
)
SPLIT_SPEC: Final = TableSpec(name="traffic_latency_split", columns=SPLIT_COLUMNS, default_sort="requests")


# --------------------------------------------------------------------------------------------- helpers


async def _series_answer(
    ctx: Any,
    tr: TimeRange,
    metrics: Sequence[str],
    *,
    group_by: str | None = None,
    labels: dict[str, str] | None = None,
) -> dict[str, Any]:
    """A section 13 series answer for `metrics` (optionally grouped), with comparison, annotations and notices.

    The plan 6.8 notices name only resets of what the metrics read (`queries.kpi_tables`: the rollups, plus the
    429 log or the egress usage for the metrics that read those), so clearing the login history never marks a
    traffic chart as partial.
    """
    db = ctx.dbs.metrics
    tables = {name for metric in metrics for name in queries.kpi_tables(metric)}
    latency = any(metric in LATENCY_METRICS for metric in metrics)
    cache = any(metric in queries.CACHE_STATE_KPIS for metric in metrics)
    kwargs: dict[str, Any] = {"metrics": list(metrics)}
    if group_by:
        kwargs.update(group_by=group_by, max_groups=MAX_SERIES_GROUPS)
    data = await queries.series(db, tr.window, **kwargs)
    series = [
        entry for metric in metrics for entry in series_from_read_model(data, metric, label=(labels or {}).get(metric))
    ]
    compare_series = None
    if tr.compare_window is not None:
        other = await queries.series(db, tr.compare_window, **kwargs)
        compare_series = [
            entry
            for metric in metrics
            for entry in series_from_read_model(other, metric, label=(labels or {}).get(metric))
        ]
    start, end = tr.window.start, tr.window.end

    def marks(conn: sqlite3.Connection) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        return queries.chart_annotations(conn, start, end), queries.reset_annotations(conn, start, end)

    annotations, resets = await db.read(marks)
    touching = [row for row in resets if queries.reset_touches(row, tables, latency=latency, cache=cache)]
    return series_answer(
        tr,
        series,
        compare_series=compare_series,
        annotations=annotation_entries(annotations),
        notices=reset_notices(touching, tz=tr.window.tz),
    )


def _good_direction(metric: str) -> str:
    spec = METRICS.get(metric)
    return {"higher": "up", "lower": "down"}.get(spec.better if spec else "neutral", "neutral")


def _delta(current: Any, previous: Any) -> tuple[float | None, float | None]:
    if not isinstance(current, int | float) or not isinstance(previous, int | float):
        return None, None
    change = current - previous
    return round(change, 4), (round(change * 100.0 / previous, 2) if previous else None)


# --------------------------------------------------------------------------------------------- routes


@router.get("/requests")
async def traffic_requests(request: Request, _admin: AdminSession, tr: TimeRangeDep) -> dict[str, Any]:
    """Requests over time stacked by outcome (plus the comparison and markers)."""
    return await _series_answer(get_ctx(request), tr, ["requests"], group_by="outcome")


@router.get("/bytes")
async def traffic_bytes(request: Request, _admin: AdminSession, tr: TimeRangeDep) -> dict[str, Any]:
    """Caller and upstream bytes over time (plan 14.3 definitions), with totals and wire bytes per egress."""
    ctx = get_ctx(request)
    answer = await _series_answer(ctx, tr, BYTE_METRICS)
    window = tr.window

    def read(conn: sqlite3.Connection) -> tuple[dict[str, Any], dict[str, int]]:
        return queries.totals_sync(conn, window), queries.egress_bytes(conn, window)

    totals, by_egress = await ctx.dbs.metrics.read(read)
    answer["totals"] = {metric: totals.get(metric) for metric in BYTE_METRICS}
    answer["by_egress"] = by_egress
    return answer


@router.get("/verbs")
async def traffic_verbs(request: Request, _admin: AdminSession, tr: TimeRangeDep) -> dict[str, Any]:
    """Requests over time per HTTP method (v1 "Requests" section, now time-bucketed)."""
    return await _series_answer(get_ctx(request), tr, ["requests"], group_by="method")


async def _dimension_table(
    request: Request,
    admin: Any,
    spec: TableSpec,
    dimension: str,
    tr: TimeRange,
    tq: TableQuery,
    fmt: Any,
) -> Any:
    """One `queries.top_n` table over `dimension`, paged in the read model, or its export."""
    ctx = get_ctx(request)
    db = ctx.dbs.metrics
    if fmt is not None:

        async def fetch(page: int, size: int) -> tuple[list[Any], int]:
            data = await queries.top_n(db, tr.window, dimension, page=replace(tq.metrics_page(), page=page, size=size))
            return list(data["rows"]), int(data["total"])

        return await export_pages(request, admin, spec, fetch, fmt, tq=tq, tr=tr)
    data = await queries.top_n(db, tr.window, dimension, page=tq.metrics_page())
    return table_from_read_model(spec, tq, data)


@router.get("/verbs/table")
async def traffic_verbs_table(
    request: Request,
    admin: AdminSession,
    tr: TimeRangeDep,
    tq: Annotated[TableQuery, Depends(table_params(VERBS_SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    """Counts by method: served, refused, failed and status classes per verb (v1 "Counts by Method")."""
    return await _dimension_table(request, admin, VERBS_SPEC, "method", tr, tq, fmt)


@router.get("/status")
async def traffic_status(
    request: Request,
    _admin: AdminSession,
    tr: TimeRangeDep,
    view: Annotated[str, Query(max_length=16)] = "class",
) -> dict[str, Any]:
    """Status classes over time (`view=class`, with Roxy's and Roblox's 429s), or requests by who produced the
    caller's status (`view=source`: Roblox, relayed, Roxy, cache, internal; `queries.ANSWER_SOURCE_SQL`)."""
    if view not in ("class", "source"):
        raise validation_error({"view": "Choose class or source."}, "The view is not valid.")
    ctx = get_ctx(request)
    if view == "source":
        return await _series_answer(ctx, tr, ["requests"], group_by="answer_source")
    return await _series_answer(ctx, tr, STATUS_METRICS)


def _verdict(roblox_429: int | None, roxy_429: int) -> dict[str, str]:
    """v1's "Who returned it?" verdict (dashboard.md 4.16), with the C5 replacements and v2's 429 log."""
    if roblox_429:
        return {
            "tone": "bad",
            "text": f"Roblox has rate-limited Roxy {roblox_429:,} time(s) in this range. This is the one to act on: "
            "reduce upstream volume (cache, pacing), or the address and the account behind Roxy are at risk.",
        }
    if roxy_429:
        return {
            "tone": "ok",
            "text": f"All {roxy_429:,} of the 429s are Roxy's own: Roxy turning callers away, not Roblox turning "
            "Roxy away. Nothing to do upstream.",
        }
    return {"tone": "muted", "text": "No rate limiting recorded from either side in this range."}


@router.get("/status/sources")
async def traffic_status_sources(
    request: Request,
    admin: AdminSession,
    tr: TimeRangeDep,
    tq: Annotated[TableQuery, Depends(table_params(SOURCES_SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    """Status codes by who produced them (rows 68, 132), with v1's four tiles and the 429 verdict.

    The table and the tiles read one definition of "who": a Roblox 5xx passed on after the retries is Roblox's
    (`relay` in the table, counted by `roblox_5xx`), and `roxy_5xx` ("Our own failures") counts only Roxy's own.
    """
    ctx = get_ctx(request)
    window = tr.window

    def read(conn: sqlite3.Connection) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        return queries.answer_source_counts(conn, window), queries.totals_sync(conn, window)

    pairs, totals = await ctx.dbs.metrics.read(read)
    rows: list[dict[str, Any]] = [
        {
            "source": str(item["source"]),
            "source_label": SOURCE_LABELS.get(str(item["source"]), (str(item["source"]), ""))[0],
            "status": int(item["status"]),
            "requests": int(item["requests"]),
        }
        for item in pairs
    ]
    if fmt is not None:
        ordered, total = page_rows(rows, _all_rows(tq, len(rows)), search_keys=("source", "source_label"))
        return await export_table(request, admin, SOURCES_SPEC, ordered, fmt, total=total, tq=tq, tr=tr)
    items, total = page_rows(rows, tq, search_keys=("source", "source_label"))
    answer = table_answer(SOURCES_SPEC, tq, items, total)
    answer["tiles"] = {
        "roblox_429": totals.get("roblox_429"),
        "roxy_429": totals.get("roxy_429"),
        "roblox_5xx": totals.get("roblox_5xx"),
        "roxy_5xx": totals.get("roxy_5xx"),
    }
    answer["verdict"] = _verdict(totals.get("roblox_429"), int(totals.get("roxy_429") or 0))
    answer["sources"] = {key: {"label": label, "help": hint} for key, (label, hint) in SOURCE_LABELS.items()}
    answer["range"] = tr.info()
    return answer


def _all_rows(tq: TableQuery, count: int) -> TableQuery:
    """The same sort and search as `tq`, as one page holding every row (exports)."""
    return replace(tq, page=1, page_size=max(1, count))


@router.get("/heatmap")
async def traffic_heatmap(
    request: Request,
    _admin: AdminSession,
    tr: TimeRangeDep,
    metric: Annotated[str, Query(max_length=32)] = "requests",
) -> dict[str, Any]:
    """Hour of day by weekday in `ui_timezone` for one measure (plan 14.1 Traffic, 14.5 Heatmap).

    The range is read at hour granularity; a range longer than `queries.MAX_POINTS` hours uses its most recent
    hours, and says so in `notices`.
    """
    if metric not in HEATMAP_METRICS:
        raise validation_error({"metric": f"Choose one of: {', '.join(HEATMAP_METRICS)}."}, "The metric is not valid.")
    ctx = get_ctx(request)
    window = tr.window
    notices: list[str] = []
    start = window.start
    if (window.end - start) // 3600 > queries.MAX_POINTS - 1:
        start = window.end - (queries.MAX_POINTS - 1) * 3600
        notices.append(f"Only the most recent {queries.MAX_POINTS - 1} hours of this range are shown.")
    hourly = queries.resolve_window(None, now=window.end, tz=window.tz, start=start, end=window.end, granularity="hour")
    data = await queries.series(ctx.dbs.metrics, hourly, metrics=[metric])
    values = (data.get("groups") or {}).get("all", {}).get(metric, [])
    return {
        "range": tr.info(),
        "read": range_info(hourly),
        "metric": metric,
        "label": METRICS[metric].label if metric in METRICS else metric,
        "unit": METRICS[metric].unit if metric in METRICS else "",
        "heatmap": read_dashboard.heatmap(data["buckets"], values, window.tz),
        "notices": notices,
    }


@router.get("/latency")
async def traffic_latency(
    request: Request,
    _admin: AdminSession,
    tr: TimeRangeDep,
    split: Annotated[str, Query(max_length=16)] = "none",
) -> dict[str, Any]:
    """p50, p95 and p99 latency over time (`split=none`), or p95 per verb, egress, host or outcome (row 131)."""
    ctx = get_ctx(request)
    if split == "none":
        answer = await _series_answer(ctx, tr, LATENCY_METRICS)
    elif split in SPLITS:
        answer = await _series_answer(ctx, tr, ["p95_ms"], group_by=SPLITS[split])
    else:
        choices = ", ".join(("none", *SPLITS))
        raise validation_error({"split": f"Choose one of: {choices}."}, "The split is not valid.")
    answer["split"] = split
    answer["notices"].append(
        "Latency is the time Roxy took to answer, Roblox's time included; it is measured per caller request, so "
        "Roxy's own probes are not part of it."
    )
    return answer


@router.get("/latency/split")
async def traffic_latency_split(
    request: Request,
    admin: AdminSession,
    tr: TimeRangeDep,
    tq: Annotated[TableQuery, Depends(table_params(SPLIT_SPEC))],
    fmt: ExportFormatDep,
    by: Annotated[str, Query(max_length=16)] = "method",
) -> Any:
    """Latency percentiles per verb, egress, host or outcome as a table (v1 Proxy Timings, row 131)."""
    if by not in SPLITS:
        raise validation_error({"by": f"Choose one of: {', '.join(SPLITS)}."}, "The split is not valid.")
    answer = await _dimension_table(request, admin, SPLIT_SPEC, SPLITS[by], tr, tq, fmt)
    if isinstance(answer, dict):
        answer["by"] = by
    return answer


async def _trend_period(ctx: Any, key: str, label: str, range_key: str) -> dict[str, Any]:
    now = ctx.clock.now()
    tz = str(ctx.settings.get("ui_timezone") or "UTC")
    current = queries.resolve_window(range_key, now=now, tz=tz)
    previous = queries.comparison_window(current, "previous")
    spark_window = read_dashboard.sparkline_window(current)

    def read(conn: sqlite3.Connection) -> dict[str, Any]:
        return {
            "now": queries.totals_sync(conn, current),
            "before": queries.totals_sync(conn, previous),
            "spark": queries.series_sync(conn, spark_window, metrics=list(TREND_METRICS)),
            "resets": queries.reset_annotations(conn, current.start, current.end),
            "baseline_resets": queries.reset_annotations(conn, previous.start, previous.end),
        }

    data = await ctx.dbs.metrics.read(read)
    now_totals, before_totals, spark = data["now"], data["before"], data["spark"]
    values = (spark.get("groups") or {}).get("all", {})
    rows = []
    for metric in TREND_METRICS:
        spec = METRICS.get(metric)
        delta, delta_pct = _delta(now_totals.get(metric), before_totals.get(metric))
        row = {
            "metric": metric,
            "label": spec.label if spec else metric,
            "unit": spec.unit if spec else "",
            "current": now_totals.get(metric),
            "previous": before_totals.get(metric),
            "delta": delta,
            "delta_pct": delta_pct,
            "good_direction": _good_direction(metric),
            "sparkline": [[b, v] for b, v in zip(spark["buckets"], values.get(metric, []), strict=False)],
        }
        # Plan 6.8 (finding LOGICFIX-1): a reset of this metric's data in either period replaces the delta with a
        # notice (`partial: true`), as the Overview tiles do.
        queries.mark_kpi_partial(row, metric, data["resets"], data["baseline_resets"], tz)
        rows.append(row)
    reset_rows = queries.touching_resets([*data["resets"], *data["baseline_resets"]], TREND_METRICS)
    return {
        "key": key,
        "label": label,
        "range": range_info(current),
        "previous_range": range_info(previous),
        "sparkline_granularity": spark_window.granularity,
        "sparkline_range": range_info(spark_window),
        "rows": rows,
        "notices": reset_notices(reset_rows, tz=tz),
    }


@router.get("/trends")
async def traffic_trends(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """Week over week, month over month and year over year tables for the key metrics, with sparklines (14.3).

    Each period is the trailing range (7, 30 or 365 days) compared with the same length just before it; the
    global range picker does not apply here.
    """
    ctx = get_ctx(request)
    periods = [await _trend_period(ctx, key, label, range_key) for key, label, range_key in TREND_PERIODS]
    return {"periods": periods}


__all__ = ["router", "traffic_heatmap", "traffic_trends"]
