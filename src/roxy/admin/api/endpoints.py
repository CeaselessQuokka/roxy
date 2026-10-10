"""Admin API: the Endpoints page (`/admin/api/v1/endpoints`, plan 14.1 Endpoints row, parity rows 74, 89).

What this is
    * `GET /endpoints`: every endpoint template with its volume, trend against the comparison period, upstream
      calls, hit ratio, Roblox 429s and latency percentiles, plus v1 Top Endpoints' methods, last request, last
      status and last caller; paged, sorted and searched on the server, filterable by host and method, exportable
      as CSV or JSON.
    * `GET /endpoints/detail?template=...`: the drill-down of one template: totals with deltas, requests by
      outcome and latency over time, its Roblox 429s, who calls it (places and hashed clients over the range,
      addresses and places in the last 15 minutes), the concrete paths behind the template, its most recent
      requests, and every rule that applies to it (blocks, rate rules, cache rule, routing, credential allowlist,
      ignored paths, upstream bucket overrides).
    * `GET /endpoints/recent?template=...`: just the recent requests (the drill-down's refresh).

Why it exists
    v1's Top Endpoints showed lifetime counts, a three-level tree and a recent ring of five requests per template
    (row 74). v2 keeps the templating (placeholders such as `{universeId}`) and the concrete-path view, adds trends
    and the numbers that matter for Roblox (upstream calls, 429s, hit ratio), and pages on the server so 2,000
    templates never ship whole to the browser (row 89).

How it works
    The table is `queries.endpoint_table` (one rollup read); the trend reads the comparison window once for the
    keys on the page only, and `read_dashboard.endpoint_recency` adds the methods and the newest request of the
    same page in the same read. The drill-down filters the same read models by `endpoint_template`. Concrete paths and
    recent requests come from the live rows (the last 15 minutes, every worker); callers over the whole range come
    from request samples, whose client column holds keyed IP hashes only. "Applies" is decided by the worker's
    rules snapshot with the real matchers (`RulesSnapshot.*_for`), evaluated on the template itself and on the
    concrete paths seen, under one regex budget (plan 9.9).

What to read next
    `roxy/metrics/queries.py` (`endpoint_table`, `series`), `roxy/metrics/read_dashboard.py`,
    `roxy/rules/store.py` (the snapshot lookups).
"""

from __future__ import annotations

import re
import sqlite3
from collections import Counter
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
    add_caller_text,
    area_router,
    export_pages,
    range_info,
    reset_notices,
    series_answer,
    series_from_read_model,
    table_from_read_model,
    table_params,
    validation_error,
)
from roxy.deps import get_ctx
from roxy.metrics import queries, read_dashboard
from roxy.metrics.catalog import METRICS
from roxy.rules.match import regex_budget

router = area_router("endpoints")

MAX_TEMPLATE_CHARS: Final = 255
MAX_HOST_CHARS: Final = 253
RECENT_DEFAULT: Final = 25
RECENT_MAX: Final = 200
CONCRETE_MAX: Final = 50
RULE_TARGETS_MAX: Final = 5
"""Concrete paths (besides the template) that applicable rules are evaluated on."""
_CONTROL: Final = re.compile(r"[\x00-\x1f\x7f]")
_METHOD: Final = re.compile(r"[A-Z]{1,12}")

TABLE_COLUMNS: Final[tuple[Column, ...]] = (
    Column(
        "key",
        "Endpoint",
        "The endpoint template: ids and other changing parts collapsed into placeholders.",
        caller_text=True,
    ),
    Column("requests", "Requests", METRICS["requests"].description, "requests"),
    Column("previous_requests", "Previous", "Requests in the comparison period.", "requests", sortable=False),
    Column("trend_pct", "Trend", "Change in requests against the comparison period.", "percent", sortable=False),
    Column("demand", "Demand", METRICS["demand"].description, "requests"),
    Column("upstream_calls", "Upstream calls", METRICS["upstream_calls"].description, "calls"),
    Column("avoided_pct", "Avoided", METRICS["avoided_pct"].description, "percent"),
    Column("hit_ratio", "Hit ratio", METRICS["hit_ratio"].description, "ratio"),
    Column("roblox_429", "Roblox 429s", METRICS["roblox_429"].description, "count"),
    Column("failed", "Failed", METRICS["failed"].description, "requests"),
    Column("p50_ms", "p50", METRICS["p50_ms"].description, "ms"),
    Column("p95_ms", "p95", METRICS["p95_ms"].description, "ms"),
    Column("p99_ms", "p99", METRICS["p99_ms"].description, "ms"),
    Column(
        "methods",
        "Methods",
        "Requests per HTTP method in the range, busiest first (v1's `GET:3 POST:1`).",
        sortable=False,
        caller_text=True,
    ),
    Column(
        "last_request_ms",
        "Last request",
        "When the newest request in the range arrived: exact when its Live row is still kept (15 minutes), else the "
        "start of its minute or hour (see last_request_precision).",
        "timestamp_ms",
        sortable=False,
    ),
    Column(
        "last_request_precision",
        "Last request precision",
        "exact, minute, hour, day or month.",
        sortable=False,
    ),
    Column(
        "last_status",
        "Last status",
        "What Roxy answered the newest request with (known while its Live row is kept).",
        sortable=False,
    ),
    Column(
        "last_caller",
        "Last caller",
        "Client address of the newest request (known while its Live row is kept).",
        ip=True,
        sortable=False,
    ),
    Column(
        "last_place",
        "Last place",
        "Roblox-Id (place) of the newest request, as the caller sent it (caller text).",
        sortable=False,
        caller_text=True,
    ),
)
TABLE_SPEC: Final = TableSpec(name="endpoints", columns=TABLE_COLUMNS, default_sort="requests")
TABLE_CALLER_TEXT: Final = ("key", "last_place")
"""Columns of the table holding text a caller chose (the template comes from the caller's path): shown as plain
text, never as markup."""
RECENCY_KEYS: Final = (
    "methods",
    "last_request_ms",
    "last_request_precision",
    "last_status",
    "last_caller",
    "last_place",
)
DETAIL_TOTALS: Final[tuple[str, ...]] = (
    "requests",
    "demand",
    "upstream_calls",
    "avoided",
    "avoided_pct",
    "served_upstream",
    "served_cache",
    "refused",
    "failed",
    "errors_hidden",
    "hit_ratio",
    "roblox_429",
    "roblox_429_per_10k",
    "status_2xx",
    "status_4xx",
    "status_5xx",
    "p50_ms",
    "p95_ms",
    "p99_ms",
    "caller_bytes_out",
    "upstream_bytes_in",
)


# --------------------------------------------------------------------------------------------- parameters


def checked_template(value: str | None) -> str:
    """A template query value: 1 to 255 printable characters (the recorder's own bound), or a 422."""
    text = (value or "").strip()
    if not text:
        raise validation_error({"template": "Give the endpoint template to show."}, "The template is missing.")
    if len(text) > MAX_TEMPLATE_CHARS or _CONTROL.search(text):
        raise validation_error({"template": f"A template is at most {MAX_TEMPLATE_CHARS} printable characters."})
    return text


def _filters(host: str | None, method: str | None) -> dict[str, str]:
    fields: dict[str, str] = {}
    out: dict[str, str] = {}
    if host:
        clean = host.strip().lower()
        if len(clean) > MAX_HOST_CHARS or _CONTROL.search(clean) or "/" in clean:
            fields["host"] = "Give a host name such as games.roblox.com."
        else:
            out["host"] = clean
    if method:
        upper = method.strip().upper()
        if not _METHOD.fullmatch(upper):
            fields["method"] = "Give an HTTP method such as GET or POST."
        else:
            out["method"] = upper
    if fields:
        raise validation_error(fields, "The filters are not valid.")
    return out


def _trend(current: Any, previous: Any) -> float | None:
    if not isinstance(current, int | float) or not isinstance(previous, int | float) or not previous:
        return None
    return round((current - previous) * 100.0 / previous, 2)


def _with_recency(conn: sqlite3.Connection, window: queries.Window, rows: list[dict[str, Any]]) -> None:
    """Add v1's Methods, Last Request, Last Status and Last Caller to one page of rows (finding parity-13)."""
    found = read_dashboard.endpoint_recency(conn, window, [str(row["key"]) for row in rows])
    for row in rows:
        extra = found.get(str(row["key"]), {})
        for key in RECENCY_KEYS:
            row[key] = extra.get(key, {} if key == "methods" else None)


# --------------------------------------------------------------------------------------------- the table


@router.get("")
async def endpoints_table(
    request: Request,
    admin: AdminSession,
    tr: TimeRangeDep,
    tq: Annotated[TableQuery, Depends(table_params(TABLE_SPEC))],
    fmt: ExportFormatDep,
    host: Annotated[str | None, Query(max_length=MAX_HOST_CHARS)] = None,
    method: Annotated[str | None, Query(max_length=12)] = None,
) -> Any:
    """Every endpoint template in the range (server-side paging, sorting and search; `host` and `method` filter).

    `previous_requests` and `trend_pct` compare with the requested comparison, or the previous period. An export
    leaves them empty (the trend is read for the shown page only). Each row also carries v1's Top Endpoints columns
    (`methods`, `last_request_ms` with its precision, `last_status`, `last_caller`, `last_place`; parity row 74).
    """
    ctx = get_ctx(request)
    db = ctx.dbs.metrics
    filters = _filters(host, method)
    if fmt is not None:

        async def fetch(page: int, size: int) -> tuple[list[Any], int]:
            page_spec = replace(tq.metrics_page(), page=page, size=size)

            def read_page(conn: sqlite3.Connection) -> dict[str, Any]:
                data = queries.endpoint_table_sync(conn, tr.window, page=page_spec, filters=filters or None)
                _with_recency(conn, tr.window, data["rows"])
                return data

            data = await db.read(read_page)
            return list(data["rows"]), int(data["total"])

        return await export_pages(request, admin, TABLE_SPEC, fetch, fmt, tq=tq, filters=filters, tr=tr)
    return await table_page(ctx, tr, tq, filters)


def table_filters(host: str | None, method: str | None) -> dict[str, str]:
    """The table's `host` and `method` filters, normalized (422 `validation_failed` naming the bad one)."""
    return _filters(host, method)


async def table_page(ctx: Any, tr: TimeRange, tq: TableQuery, filters: dict[str, str]) -> dict[str, Any]:
    """One page of the endpoints table with its trend and v1's recency columns (the `GET /endpoints` answer); the
    Endpoints dashboard page calls it too, so both show the same rows."""
    db = ctx.dbs.metrics
    other = tr.compare_window or queries.comparison_window(tr.window, "previous")
    window = tr.window

    def read(conn: sqlite3.Connection) -> tuple[dict[str, Any], dict[str, Any]]:
        data = queries.endpoint_table_sync(conn, window, page=tq.metrics_page(), filters=filters or None)
        keys = [row["key"] for row in data["rows"]]
        previous: dict[str, Any] = {}
        if keys:
            before = queries.top_n_sync(
                conn,
                other,
                "endpoint_template",
                page=queries.Page(size=max(queries.PAGE_SIZES), sort="requests"),
                filters={**filters, "endpoint_template": keys},
            )
            previous = {row["key"]: row["requests"] for row in before["rows"]}
        _with_recency(conn, window, data["rows"])
        return data, previous

    data, previous = await db.read(read)
    for row in data["rows"]:
        row["previous_requests"] = int(previous.get(row["key"], 0))
        row["trend_pct"] = _trend(row["requests"], row["previous_requests"])
    answer = table_from_read_model(TABLE_SPEC, tq, data)
    answer["compare"] = {"mode": tr.compare or "previous", "range": range_info(other)}
    answer["filters"] = filters
    add_caller_text(answer, TABLE_CALLER_TEXT)
    return answer


# --------------------------------------------------------------------------------------------- drill-down


def _host_of(template: str) -> str:
    return template.split("/", 1)[0].lower()


def _row_dict(row: Any) -> dict[str, Any] | None:
    if row is None:
        return None
    dump = getattr(row, "model_dump", None)
    return dict(dump()) if callable(dump) else dict(row)


def applicable_rules(snapshot: Any, template: str, concrete: list[str]) -> dict[str, Any]:
    """Which rule of each family applies to the template and to its recently seen concrete paths.

    Rules match `host/path` targets, not templates, so the template's placeholders stand in for any value
    (a `*` glob segment matches them) and the concrete paths show what real requests met. Evaluated with the
    snapshot's own matchers (most specific wins, ties to the lowest id), under one regex budget (plan 9.9).
    """
    host = _host_of(template)
    targets: list[dict[str, Any]] = []
    seen: set[str] = set()
    with regex_budget():
        for kind, target in [("template", template)] + [("path", path) for path in concrete[:RULE_TARGETS_MAX]]:
            if target in seen:
                continue
            seen.add(target)
            path = target.split("/", 1)[1] if "/" in target else ""
            targets.append(
                {
                    "kind": kind,
                    "target": target,
                    "endpoint_block": _row_dict(snapshot.endpoint_block_for(target)),
                    "endpoint_rule": _row_dict(snapshot.endpoint_limit_for(target)),
                    "cache_rule": _row_dict(snapshot.cache_rule_for(target)),
                    "routing_rule": _row_dict(snapshot.routing_rule_for(target)),
                    "credential_allowlist": _row_dict(snapshot.credential_rule_for(target, "GET")),
                    "ignored_path": bool(snapshot.is_ignored_path(path)) if path else False,
                }
            )
    return {
        "targets": targets,
        "upstream_limits": {
            "host": _row_dict(snapshot.upstream_limit(f"host:{host}")),
            "endpoint": _row_dict(snapshot.upstream_limit(f"endpoint:{template}")),
        },
        "rules_version": getattr(snapshot, "version", None),
    }


def _live_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Concrete paths and callers among the recent live rows of one template."""
    paths: Counter[str] = Counter()
    last_seen: dict[str, int] = {}
    ips: Counter[str] = Counter()
    places: Counter[str] = Counter()
    for row in rows:
        url = str(row.get("url") or "")
        if url:
            paths[url] += 1
            last_seen[url] = max(last_seen.get(url, 0), int(row.get("at_ms") or 0))
        if row.get("ip"):
            ips[str(row["ip"])] += 1
        if row.get("place"):
            places[str(row["place"])] += 1
    return {
        "concrete_paths": [
            {"path": path, "requests": count, "last_at_ms": last_seen.get(path)}
            for path, count in paths.most_common(CONCRETE_MAX)
        ],
        "ips": [{"ip": ip, "requests": count} for ip, count in ips.most_common(10)],
        "places": [{"place": place, "requests": count} for place, count in places.most_common(10)],
    }


async def _recent(ctx: Any, template: str, limit: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = await ctx.dbs.metrics.read(lambda conn: queries.endpoint_recent(conn, template, limit))
    return rows


async def _series(ctx: Any, tr: TimeRange, template: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Requests by outcome and the latency percentiles of one template, as two series answers."""
    db = ctx.dbs.metrics
    filters = {"endpoint_template": template}
    outcomes = await queries.series(db, tr.window, metrics=["requests"], filters=filters, group_by="outcome")
    latency = await queries.series(db, tr.window, metrics=["p50_ms", "p95_ms", "p99_ms"], filters=filters)
    compare_outcomes = compare_latency = None
    if tr.compare_window is not None:
        other_o = await queries.series(db, tr.compare_window, metrics=["requests"], filters=filters, group_by="outcome")
        other_l = await queries.series(db, tr.compare_window, metrics=["p50_ms", "p95_ms", "p99_ms"], filters=filters)
        compare_outcomes = series_from_read_model(other_o, "requests")
        compare_latency = [e for m in ("p50_ms", "p95_ms", "p99_ms") for e in series_from_read_model(other_l, m)]
    return (
        series_answer(tr, series_from_read_model(outcomes, "requests"), compare_series=compare_outcomes),
        series_answer(
            tr,
            [e for m in ("p50_ms", "p95_ms", "p99_ms") for e in series_from_read_model(latency, m)],
            compare_series=compare_latency,
        ),
    )


@router.get("/detail")
async def endpoint_detail(
    request: Request,
    _admin: AdminSession,
    tr: TimeRangeDep,
    template: Annotated[str | None, Query(max_length=MAX_TEMPLATE_CHARS * 4)] = None,
) -> dict[str, Any]:
    """The drill-down of one endpoint template (see the module docstring)."""
    return await detail_answer(get_ctx(request), tr, checked_template(template))


async def detail_answer(ctx: Any, tr: TimeRange, name: str) -> dict[str, Any]:
    """The `GET /endpoints/detail` answer for one checked template (`checked_template`); the dashboard's
    drill-down renders this same answer."""
    window = tr.window
    other = tr.compare_window or queries.comparison_window(window, "previous")
    filters = {"endpoint_template": name}
    start_ms, end_ms = window.start * 1000, window.end * 1000

    def read(conn: sqlite3.Connection) -> dict[str, Any]:
        return {
            "current": queries.totals_sync(conn, window, filters=filters),
            "previous": queries.totals_sync(conn, other, filters=filters),
            "callers": read_dashboard.endpoint_callers(conn, name, start_ms, end_ms),
            "upstream_429": read_dashboard.endpoint_429s(conn, name, start_ms, end_ms),
            "recent": queries.endpoint_recent(conn, name, RECENT_MAX),
            "resets": queries.reset_annotations(conn, window.start, window.end),
            "baseline_resets": queries.reset_annotations(conn, other.start, other.end),
        }

    data = await ctx.dbs.metrics.read(read)
    totals: dict[str, Any] = {}
    for key in DETAIL_TOTALS:
        current, previous = data["current"].get(key), data["previous"].get(key)
        delta = (
            round(current - previous, 4)
            if isinstance(current, int | float) and isinstance(previous, int | float)
            else None
        )
        totals[key] = {"value": current, "previous": previous, "delta": delta, "delta_pct": _trend(current, previous)}
        # Plan 6.8 (finding LOGICFIX-1): a reset of what this total reads, in either window, replaces its delta
        # with a notice (a reset marker names tables, not endpoints, so any such reset counts here).
        queries.mark_kpi_partial(totals[key], key, data["resets"], data["baseline_resets"], window.tz)
    reset_rows = queries.touching_resets([*data["resets"], *data["baseline_resets"]], DETAIL_TOTALS)
    by_outcome, latency = await _series(ctx, tr, name)
    recent = list(data["recent"])
    live = _live_summary(recent)
    snapshot = ctx.rules.snapshot
    concrete = [item["path"] for item in live["concrete_paths"]]
    cache_rule = None
    with regex_budget():
        found = snapshot.cache_rule_for(name)
    if found is not None:
        cache_rule = _row_dict(found)
    return {
        "template": name,
        "host": _host_of(name),
        "range": tr.info(),
        "compare": {"mode": tr.compare or "previous", "range": range_info(other)},
        "totals": totals,
        "requests_by_outcome": by_outcome,
        "latency": latency,
        "upstream_429": data["upstream_429"],
        "cache": {
            "rule": cache_rule,
            "ttl_s": cache_rule["ttl"] if cache_rule else int(ctx.settings.int("cache_ttl_seconds")),
            "hit_ratio": data["current"].get("hit_ratio"),
        },
        "top_callers": {
            "range": {
                "samples": data["callers"]["samples"],
                "places": data["callers"]["places"],
                "clients": data["callers"]["clients"],
            },
            "last_15_minutes": {"ips": live["ips"], "places": live["places"], "rows_seen": len(recent)},
        },
        "concrete_paths": live["concrete_paths"],
        "recent_requests": recent[:RECENT_DEFAULT],
        "rules": applicable_rules(snapshot, name, concrete),
        "notices": [
            "Concrete paths, recent requests and the last 15 minutes of callers come from the live rows, which "
            "keep 15 minutes and at most 50 rows per second per worker.",
            "Callers over the range come from request samples (served and failed requests); clients are shown as "
            "keyed hashes of their addresses.",
            *reset_notices(reset_rows, tz=window.tz),
        ],
    }


@router.get("/recent")
async def endpoint_recent(
    request: Request,
    _admin: AdminSession,
    template: Annotated[str | None, Query(max_length=MAX_TEMPLATE_CHARS * 4)] = None,
    limit: Annotated[int, Query(ge=1, le=RECENT_MAX)] = RECENT_DEFAULT,
) -> dict[str, Any]:
    """The newest requests of one template (live rows of every worker, the last 15 minutes), newest first."""
    return await recent_answer(get_ctx(request), checked_template(template), limit)


async def recent_answer(ctx: Any, name: str, limit: int = RECENT_DEFAULT) -> dict[str, Any]:
    """The `GET /endpoints/recent` answer for one checked template (at most `RECENT_MAX` rows)."""
    rows = await _recent(ctx, name, max(1, min(int(limit), RECENT_MAX)))
    return {"template": name, "items": rows, "total": len(rows)}


__all__ = [
    "RECENT_DEFAULT",
    "RECENT_MAX",
    "TABLE_CALLER_TEXT",
    "TABLE_SPEC",
    "applicable_rules",
    "checked_template",
    "detail_answer",
    "recent_answer",
    "router",
    "table_filters",
    "table_page",
]
