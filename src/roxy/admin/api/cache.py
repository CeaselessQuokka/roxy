"""Admin API: the Cache page (`/admin/api/v1/cache`, plan 14.1 Cache row, parity rows 52 to 67).

What this is
    * Numbers: `GET /cache/stats` (hit and avoided ratios with deltas, cache states, the 5 minute, hour and day
      hit ratios v1 showed, stored rows and bytes against the budgets, the memory tier, evictions, disk health),
      `GET /cache/ratios` and `GET /cache/states` (the same over time), `GET /cache/endpoints` (where the cache
      works: hit ratio, TTL and rule, stale serves, revalidations, negative hits per endpoint; exportable).
    * Rules (row 55): `GET`, `POST /cache/rules`, `PATCH` and `DELETE /cache/rules/{id}` with methods (GET and
      POST), TTL, stale-while-revalidate window, negative TTL and normalization flags.
    * Ignored parameters (row 54): `GET`, `POST /cache/ignored-params` and `DELETE /cache/ignored-params/{name}`,
      with the v1 suggestion list and the parameters the key spread suspects.
    * `GET /cache/spread`: the key spread diagnostic (row 65).
    * The browser (row 66): `GET /cache/entries` (search, sort, page), `GET /cache/entries/{id}` (inspect, body
      included), `POST /cache/entries/{id}/refresh` (fetch it from Roblox again, POST entries too, since v2 keeps
      the request body), and `POST /cache/purge` by id, pattern (glob or regex), host, rule, the browser search
      (`search`: exactly what the same `q` lists, one shared condition, v1 bug 4), expired, or all.

Why it exists
    The cache is Roxy's strongest defense against Roblox rate limits (plan 2.5), and v1's Response Cache section was
    the most used part of the dashboard. v2 keeps every control, fixes v1's browser bugs (sorting always
    descending, "purge matching" using a different rule than the search, a regex rule purged as a glob; dashboard.md
    section 13 bugs 3 to 5) and makes "avoided" honest (P6): demand minus every caller upstream call.

How it works
    Thin. Numbers come from `metrics/queries.py` and `metrics/read_history.py`; rules go through
    `rules/service.py` (audit row and `config_version` bump in one control.db transaction); purges through
    `CacheService.purge` (the generation moves first, every worker's memory tier drops within 250 ms). Every purge
    writes its `cache.purge` audit row FIRST and is refused (503) when control.db cannot take it, so no purge is
    ever unaudited (plan 9.7 with C7). The browser reads `cache/read_browser.py`, which hides single-flight handoff
    rows (key text ending in " !flight"). A refresh rebuilds the entry's request from its stored key (method, host,
    path, parameters, forwarded headers, body), checks it still maps to the same entry id, and runs it through the
    real cache path (`CacheService.peek` then `serve` with the stored copy set aside), so it pays its way in the
    buckets, joins an in-flight fetch of the same key instead of calling twice, and is stored by the same rules as
    any other answer; its upstream call is recorded as Roxy's own (`admin_cache_refresh`), never as caller demand.
    Entries fetched with the credential are never refreshed from here (C1, P1: purge them instead).
    Every read route delegates to a plain helper (`stats_answer`, `cache_series`, `endpoints_answer`,
    `rules_answer`, `rule_view`, `ignored_params_answer`, `spread_answer`, `entries_answer`, `entry_answer`) that the
    Cache dashboard page (`roxy/admin/pages/cache.py`) calls too, so the page and the API show the same numbers.

What to read next
    `roxy/cache/service.py`, `roxy/cache/store.py`, `roxy/cache/read_browser.py`, `roxy/rules/service.py`.
"""

from __future__ import annotations

import asyncio
import dataclasses
import re
import sqlite3
import time
from collections.abc import Mapping
from typing import Annotated, Any, Final, Literal
from urllib.parse import unquote

from fastapi import Body, Depends, Path, Query, Request
from pydantic import Field, ValidationError

from roxy.admin.api import common
from roxy.admin.api.common import (
    AdminSession,
    ApiBody,
    Column,
    CsrfChecked,
    ExportFormatDep,
    TableQuery,
    TableSpec,
    TimeRange,
    TimeRangeDep,
    actor_for,
    annotation_entries,
    area_router,
    collect_pages,
    conflict,
    export_pages,
    export_table,
    kpi_from_read_model,
    not_found,
    page_rows,
    range_info,
    request_id_of,
    require_reason,
    reset_notices,
    run_mutation,
    series_answer,
    series_from_read_model,
    service_errors,
    table_answer,
    table_params,
    unavailable,
    validation_error,
)
from roxy.admin.auth.deps import AdminPrincipal
from roxy.cache import read_browser
from roxy.cache.keys import CRED_SUFFIX
from roxy.cache.policy import CacheSettings
from roxy.cache.store import PurgeScope
from roxy.config import audit
from roxy.config.constants import MAX_CACHE_IGNORED_PARAMS, MAX_REASON_LENGTH, SUGGESTED_CACHE_IGNORED_PARAMS
from roxy.core.ids import new_request_id
from roxy.core.reasons import AuthClass, Outcome
from roxy.core.redact import redact_text
from roxy.deps import get_ctx
from roxy.metrics import queries, read_history
from roxy.metrics.catalog import METRICS
from roxy.proxy import validate
from roxy.proxy.context import ProxyRequest, endpoint_template, is_browser
from roxy.proxy.router import allowed_hosts, setting
from roxy.rules.match import PatternValidationError, regex_budget
from roxy.rules.models import RULE_TABLES
from roxy.rules.service import RulesService

router = area_router("cache")

CACHE_RULES: Final = "rules_cache"
IGNORED_PARAMS: Final = "cache_ignored_params"
MAX_PATTERN_CHARS: Final = 1000
MAX_NOTE_CHARS: Final = 500
MAX_LIST_ITEMS: Final = 16
MAX_PARAM_CHARS: Final = 400
MAX_INSPECT_BODY: Final = 256 * 1024
"""Body characters an inspect answer carries at most (`body_truncated` says when more were stored)."""
REFRESH_SETTLE_S: Final = 5.0
REFRESH_PURPOSE: Final = "admin_cache_refresh"
ENTRY_ID_RE: Final = re.compile(r"[0-9a-f]{24}")
ENTRY_GONE: Final = "That entry has expired or been evicted."
"""v1's inspect and refresh 404 text (dashboard.md 4.2), with a closing period."""
NOT_PROXYABLE: Final = "That entry's URL is no longer proxyable."
RECENT_WINDOWS: Final[tuple[tuple[str, int], ...]] = (("5m", 300), ("1h", 3600), ("24h", 86_400))
"""v1's CacheRates windows (5, 60 and 1440 minutes; v1's "24 h" really covered 3 h, bug B13)."""
STATE_METRICS: Final[tuple[str, ...]] = (
    "cache_hit",
    "cache_revalidating",
    "cache_stale",
    "cache_coalesced",
    "cache_miss",
)
RATIO_METRICS: Final[tuple[str, ...]] = ("hit_ratio", "avoided_pct")
"""The series of `GET /cache/ratios`."""
STATE_LABELS: Final[dict[str, str]] = {
    "cache_hit": "Hit (fresh copy)",
    "cache_revalidating": "Revalidating (copy served, refresh running)",
    "cache_stale": "Stale (old copy, Roblox unavailable)",
    "cache_coalesced": "Coalesced (shared another caller's fetch)",
    "cache_miss": "Miss (fetched from Roblox)",
}

TILE_KEYS: Final[tuple[str, ...]] = (
    "hit_ratio",
    "avoided_pct",
    "avoided",
    "served_cache",
    "errors_hidden",
    "cache_bytes_out",
    "demand",
    "upstream_calls",
)

ENDPOINT_COLUMNS: Final[tuple[Column, ...]] = (
    Column("key", "Endpoint", "The endpoint template (ids collapsed into placeholders).", caller_text=True),
    Column("requests", "Requests", METRICS["requests"].description, "requests"),
    Column("hit_ratio", "Hit ratio", METRICS["hit_ratio"].description, "ratio"),
    Column("cache_hit", "Hits", "Answered from a fresh copy: Roblox never saw these.", "requests"),
    Column(
        "cache_stale",
        "Stale serves",
        "An expired copy handed over because Roblox failed or was cooling down.",
        "requests",
    ),
    Column("cache_revalidating", "Revalidations", "An expired copy served while one refresh ran.", "requests"),
    Column("cache_coalesced", "Coalesced", "Requests that shared another caller's fetch.", "requests"),
    Column("cache_miss", "Misses", "Fetched from Roblox because there was no usable copy.", "requests"),
    Column(
        "negative_hits",
        "Negative hits",
        "Stored refusals (404 and friends) replayed without asking Roblox.",
        "requests",
        sortable=False,
    ),
    Column("cache_bytes_out", "Served bytes", METRICS["cache_bytes_out"].description, "bytes"),
    Column("upstream_calls", "Upstream calls", METRICS["upstream_calls"].description, "calls"),
    Column(
        "ttl_s",
        "TTL",
        "How long an answer stays fresh: the matching rule's TTL, else the default.",
        "s",
        sortable=False,
    ),
    Column("rule_id", "Rule", "The cache rule matching the template (empty when the default applies).", sortable=False),
)
ENDPOINTS_SPEC: Final = TableSpec(name="cache_endpoints", columns=ENDPOINT_COLUMNS, default_sort="requests")

RULE_COLUMNS: Final[tuple[Column, ...]] = (
    Column("id", "Id", "The rule's number."),
    Column("pattern", "Pattern", "Which endpoints the rule covers (glob: `*` is one path segment; regex)."),
    Column("type", "Type", "glob or regex."),
    Column("ttl", "TTL", "How long an answer stays fresh; 0 means never cache these endpoints.", "s"),
    Column("stale_ttl", "Revalidate window", "How long after expiry the copy is served while one refresh runs.", "s"),
    Column("negative_ttl", "Negative TTL", "How long a definite refusal (404 and friends) is kept.", "s"),
    Column("methods", "Methods", "GET, and POST for batch lookups that only read."),
    Column("normalize_flags", "Normalization", "sort_csv:<param> sorts an id list; casefold_path lowercases."),
    Column("note", "Note", "Your reminder of why the rule exists. Never sent anywhere."),
    Column("enabled", "Enabled", "Whether the rule is in force."),
    Column("origin", "Origin", "default (shipped), admin, or recommendation."),
    Column("created_at", "Added", "When the rule was created.", "s"),
    Column("updated_at", "Updated", "When the rule last changed.", "s"),
)
RULES_SPEC: Final = TableSpec(name="cache_rules", columns=RULE_COLUMNS, default_sort="id", default_order="asc")

BROWSER_COLUMNS: Final[tuple[Column, ...]] = (
    Column(
        "key",
        "Question",
        "The exact question this answer is for: method, endpoint and every parameter.",
        caller_text=True,
    ),
    Column("status", "Status", "The status Roblox answered with.", sortable=False),
    Column("size", "Size", "Bytes this answer counts against the disk budget.", "bytes"),
    Column("hits", "Times reused", "How many times this answer was handed to a caller.", "count"),
    Column("stored_at", "Stored", "When the answer was fetched from Roblox.", "s"),
    Column("expires_at", "Fresh until", "When it stops counting as current.", "s"),
    Column("last_hit_at", "Last reused", "When it was last handed to a caller.", "s"),
    Column(
        "state", "State", "fresh, stale (still usable while Roblox fails), expired, or a 429 marker.", sortable=False
    ),
    Column("rule_id", "Rule", "The rule that decided its lifetime (empty: the default).", sortable=False),
)
BROWSER_SPEC: Final = TableSpec(name="cache_entries", columns=BROWSER_COLUMNS, default_sort="hits")
BROWSER_SORTS: Final[dict[str, str]] = {
    "key": "key",
    "size": "bytes",
    "hits": "hits",
    "stored_at": "stored",
    "expires_at": "expires",
    "last_hit_at": "last_hit",
}


# --------------------------------------------------------------------------------------------- bodies


class CacheRuleCreate(ApiBody):
    """A new cache rule (row 55). Ranges are checked by the rules service (422 with one message per field)."""

    pattern: str = Field(max_length=MAX_PATTERN_CHARS)
    type: Literal["glob", "regex"] = "glob"
    ttl: int | None = None
    stale_ttl: int = 0
    negative_ttl: int = 0
    methods: list[str] = Field(default_factory=lambda: ["GET"], max_length=MAX_LIST_ITEMS)
    normalize_flags: list[str] = Field(default_factory=list, max_length=MAX_LIST_ITEMS)
    note: str = Field(default="", max_length=MAX_NOTE_CHARS)
    enabled: bool = True
    reason: str | None = Field(default=None, max_length=MAX_REASON_LENGTH * 2)
    purge: bool = True
    """Drop stored answers the rule now covers, so it applies at once (v1 purged on add)."""


class CacheRuleUpdate(ApiBody):
    """Fields to change on a cache rule; anything left out keeps its value."""

    pattern: str | None = Field(default=None, max_length=MAX_PATTERN_CHARS)
    type: Literal["glob", "regex"] | None = None
    ttl: int | None = None
    stale_ttl: int | None = None
    negative_ttl: int | None = None
    methods: list[str] | None = Field(default=None, max_length=MAX_LIST_ITEMS)
    normalize_flags: list[str] | None = Field(default=None, max_length=MAX_LIST_ITEMS)
    note: str | None = Field(default=None, max_length=MAX_NOTE_CHARS)
    enabled: bool | None = None
    reason: str | None = Field(default=None, max_length=MAX_REASON_LENGTH * 2)
    purge: bool = True


class RemoveBody(ApiBody):
    """The optional body of a DELETE: why, and whether to drop the stored answers the change affects."""

    reason: str | None = Field(default=None, max_length=MAX_REASON_LENGTH * 2)
    purge: bool = True


class IgnoredParamBody(ApiBody):
    """A query parameter to leave out of cache keys (row 54). Case-sensitive, exact, as in v1."""

    name: str = Field(max_length=MAX_PARAM_CHARS)
    note: str = Field(default="", max_length=MAX_NOTE_CHARS)
    reason: str | None = Field(default=None, max_length=MAX_REASON_LENGTH * 2)
    purge: bool = True
    """Drop exactly the stored answers keyed with this parameter (v1 emptied the whole cache)."""


class PurgeBody(ApiBody):
    """What to purge (row 66). `value` is the id, pattern, host, rule id, or the browser's search text (`search`:
    "Purge matching" removes exactly what `GET /cache/entries?q=` lists, v1 bug 4); `all` needs `confirm: true`."""

    scope: Literal["id", "pattern", "host", "rule", "search", "expired", "all"]
    value: str | None = Field(default=None, max_length=MAX_PATTERN_CHARS)
    type: Literal["glob", "regex"] = "glob"
    include_stale: bool = False
    """For `expired`: also drop answers past their lifetime that are still inside their stale window."""
    confirm: bool = False
    reason: str | None = Field(default=None, max_length=MAX_REASON_LENGTH * 2)


# --------------------------------------------------------------------------------------------- helpers


def _cache(ctx: Any) -> Any:
    cache = getattr(ctx, "cache", None)
    if cache is None:
        raise unavailable("The cache is not running on this worker yet; try again shortly.")
    return cache


def _service(ctx: Any) -> RulesService:
    return RulesService(ctx.dbs.control, clock=ctx.clock, store=ctx.rules)


def _delta(current: Any, previous: Any) -> tuple[float | None, float | None]:
    if not isinstance(current, int | float) or not isinstance(previous, int | float):
        return None, None
    change = current - previous
    return round(change, 4), (round(change * 100.0 / previous, 2) if previous else None)


def _row(table: str, entry: Mapping[str, Any] | None) -> dict[str, Any]:
    """A stored rule row in its typed form (`rules/models.py` row model: methods and flags as lists), JSON-ready."""
    if not entry:
        return {}
    try:
        data = RULE_TABLES[table].row_model.model_validate(dict(entry)).model_dump()
    except ValidationError:
        data = dict(entry)
    return {key: list(value) if isinstance(value, tuple) else value for key, value in data.items()}


async def purge_audited(
    request: Request, principal: AdminPrincipal, scope: PurgeScope, reason: str, *, cause: str
) -> dict[str, Any]:
    """Audit, then run one purge (see the module docstring); returns the purge report as a dict."""
    ctx = get_ctx(request)
    cache = _cache(ctx)
    try:
        checked = scope.validated()
    except PatternValidationError:
        raise
    except ValueError as exc:
        raise validation_error({"value": str(exc)}, "The purge is not valid.") from None
    actor = actor_for(principal)
    request_id = request_id_of(request)
    details = {"scope": checked.label, "kind": checked.kind.value, "cause": cause}
    target = f"cache:{checked.label}"[:200]
    now = int(ctx.clock.now())

    def write(conn: sqlite3.Connection) -> int:
        return audit.record(conn, actor, "cache.purge", target, None, details, reason or None, request_id, at=now)

    with service_errors():
        audit_id = await ctx.dbs.control.write(write)
    with service_errors():
        report = await cache.purge(checked, actor)
    return {**dataclasses.asdict(report), "audit_id": audit_id}


# --------------------------------------------------------------------------------------------- numbers


@router.get("/stats")
async def cache_stats(request: Request, _admin: AdminSession, tr: TimeRangeDep) -> dict[str, Any]:
    """Hit and avoided ratios with deltas, cache states, v1's short-window hit ratios, size, evictions, disk."""
    return await stats_answer(get_ctx(request), tr)


async def stats_answer(ctx: Any, tr: TimeRange) -> dict[str, Any]:
    """The `GET /cache/stats` answer (the Cache page's statistics card reads the same function, plan P6)."""
    window = tr.window
    other = tr.compare_window or queries.comparison_window(window, "previous")
    now = ctx.clock.now()
    tz = window.tz
    recent = [(name, queries.Window(int(now) - span, int(now) + 1, "minute", tz)) for name, span in RECENT_WINDOWS]

    def read(conn: sqlite3.Connection) -> dict[str, Any]:
        return {
            "current": queries.totals_sync(conn, window),
            "previous": queries.totals_sync(conn, other),
            "recent": {name: queries.totals_sync(conn, w) for name, w in recent},
            "history": read_history.cache_summary(conn, window.start, window.end),
            "resets": queries.reset_annotations(conn, window.start, window.end),
            "baseline_resets": queries.reset_annotations(conn, other.start, other.end),
        }

    data = await ctx.dbs.metrics.read(read)
    current, previous = data["current"], data["previous"]
    tiles = []
    for key in TILE_KEYS:
        delta, delta_pct = _delta(current.get(key), previous.get(key))
        tile = {"value": current.get(key), "delta": delta, "delta_pct": delta_pct}
        # Plan 6.8 (finding LOGICFIX-1): a reset of this tile's data in either window replaces its delta.
        queries.mark_kpi_partial(tile, key, data["resets"], data["baseline_resets"], tz)
        tiles.append(kpi_from_read_model(key, tile) | ({"partial": True} if tile.get("partial") else {}))
    # The page notices: every reset inside the range (as before), and a reset of the comparison window that made a
    # tile partial (its tile says so; the page names it too).
    listed = {row.get("id") for row in data["resets"]}
    reset_rows = [*data["resets"], *queries.touching_resets(data["baseline_resets"], TILE_KEYS, seen=listed)]
    cs = CacheSettings.read(ctx.settings)
    cache = getattr(ctx, "cache", None)
    size: dict[str, Any] = {"rows": None, "bytes": None}
    worker: dict[str, Any] = {}
    disk: dict[str, Any] = {}
    if cache is not None:
        shared = cache.store.shared
        if shared is not None:
            with service_errors():
                rows, stored_bytes = await shared.totals()
            size = {"rows": rows, "bytes": stored_bytes}
        state = cache.state()
        worker = {"memory": state["Memory"], "generation": state["Generation"], "stats": state["Stats"]}
        disk = cache.disk_status()
        disk.pop("Dir", None)  # server paths stay on the System page
        disk.pop("File", None)
    size.update(max_entries=cs.max_entries, max_bytes=cs.max_bytes, disk_enabled=cs.disk_enabled)
    return {
        "range": tr.info(),
        "compare": {"mode": tr.compare or "previous", "range": range_info(other)},
        "tiles": tiles,
        "states": {key: current.get(key) for key in STATE_METRICS},
        "recent_hit_ratio": {
            name: {
                "hit_ratio": totals.get("hit_ratio"),
                "served_cache": totals.get("served_cache"),
                "cache_miss": totals.get("cache_miss"),
            }
            for name, totals in data["recent"].items()
        },
        "size": size,
        "evictions": {"range": data["history"], "this_worker": worker.get("stats", {}).get("evictions")},
        "this_worker": worker,
        "disk": disk,
        "settings": {
            "enabled": cs.enabled,
            "ttl_s": cs.ttl_s,
            "stale_s": cs.stale_s,
            "swr_s": cs.swr_s,
            "error_ttl_s": cs.error_ttl_s,
            "post_mode": cs.post_mode,
            "coalesce": cs.coalesce,
            "memory_entries": cs.memory_entries,
            "memory_bytes": cs.memory_bytes,
        },
        "notices": reset_notices(reset_rows, tz=tz),
    }


async def cache_series(ctx: Any, tr: TimeRange, metrics: tuple[str, ...], labels: Mapping[str, str]) -> dict[str, Any]:
    """A series answer for `metrics` (the `/cache/ratios` and `/cache/states` routes and the Cache page charts)."""
    db = ctx.dbs.metrics
    data = await queries.series(db, tr.window, metrics=list(metrics))
    series = [e for m in metrics for e in series_from_read_model(data, m, label=labels.get(m))]
    compare = None
    if tr.compare_window is not None:
        other = await queries.series(db, tr.compare_window, metrics=list(metrics))
        compare = [e for m in metrics for e in series_from_read_model(other, m, label=labels.get(m))]
    start, end = tr.window.start, tr.window.end

    def marks(conn: sqlite3.Connection) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        return queries.chart_annotations(conn, start, end), queries.reset_annotations(conn, start, end)

    annotations, resets = await db.read(marks)
    return series_answer(
        tr,
        series,
        compare_series=compare,
        annotations=annotation_entries(annotations),
        notices=reset_notices(resets, tz=tr.window.tz),
    )


@router.get("/ratios")
async def cache_ratios(request: Request, _admin: AdminSession, tr: TimeRangeDep) -> dict[str, Any]:
    """Hit ratio and avoided upstream calls (percent) over time."""
    return await cache_series(get_ctx(request), tr, RATIO_METRICS, {})


@router.get("/states")
async def cache_states(request: Request, _admin: AdminSession, tr: TimeRangeDep) -> dict[str, Any]:
    """Requests per `Roxy-Cache` state over time (hit, revalidating, stale, coalesced, miss)."""
    return await cache_series(get_ctx(request), tr, STATE_METRICS, STATE_LABELS)


def _rule_columns(ctx: Any, rows: list[dict[str, Any]]) -> None:
    """Add the matching rule and the TTL that applies to each endpoint row (from the rules snapshot)."""
    snapshot = ctx.rules.snapshot
    default_ttl = int(ctx.settings.int("cache_ttl_seconds"))
    with regex_budget():
        for row in rows:
            rule = snapshot.cache_rule_for(str(row["key"]))
            row["rule_id"] = rule.id if rule is not None else None
            row["ttl_s"] = rule.ttl if rule is not None else default_ttl


@router.get("/endpoints")
async def cache_endpoints(
    request: Request,
    admin: AdminSession,
    tr: TimeRangeDep,
    tq: Annotated[TableQuery, Depends(table_params(ENDPOINTS_SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    """Where the cache is working, one row per endpoint template (v1 "Where the cache is working")."""
    ctx = get_ctx(request)
    if fmt is not None:

        async def fetch_all(page: int, size: int) -> tuple[list[Any], int]:
            # One page at a time, joined with its negative counts and rule columns before the next is read
            # (finding mpjobs-5: a download holds one page of rows, never the whole table).
            page_spec = dataclasses.replace(tq.metrics_page(), page=page, size=size)
            return await _endpoint_rows(ctx, tr, page_spec)

        return await export_pages(request, admin, ENDPOINTS_SPEC, fetch_all, fmt, tq=tq, tr=tr)
    return await endpoints_answer(ctx, tr, tq)


async def _endpoint_negatives(ctx: Any, tr: TimeRange, keys: list[str]) -> dict[str, int]:
    """Stored refusals replayed (`cache_negative`) per endpoint template of `keys` in the range."""
    if not keys:
        return {}
    filters: dict[str, Any] = {"reason_code": "cache_negative", "endpoint_template": keys}

    async def fetch(page: int, size: int) -> tuple[list[Any], int]:
        page_spec = queries.Page(page=page, size=size, sort="requests")
        data = await queries.top_n(ctx.dbs.metrics, tr.window, "endpoint_template", page=page_spec, filters=filters)
        return list(data["rows"]), int(data["total"])

    rows, _total = await collect_pages(fetch)
    return {str(row["key"]): int(row["requests"]) for row in rows}


async def _endpoint_rows(ctx: Any, tr: TimeRange, page_spec: queries.Page) -> tuple[list[Any], int]:
    """One page of endpoint rows with their negative hits, matching rule and TTL."""
    data = await queries.endpoint_table(ctx.dbs.metrics, tr.window, page=page_spec)
    rows = list(data["rows"])
    counts = await _endpoint_negatives(ctx, tr, [str(row["key"]) for row in rows])
    for row in rows:
        row["negative_hits"] = counts.get(str(row["key"]), 0)
    _rule_columns(ctx, rows)
    return rows, int(data["total"])


async def endpoints_answer(ctx: Any, tr: TimeRange, tq: TableQuery) -> dict[str, Any]:
    """The `GET /cache/endpoints` table answer (the Cache page's per-endpoint card reads the same function)."""
    rows, total = await _endpoint_rows(ctx, tr, tq.metrics_page())
    return table_answer(ENDPOINTS_SPEC, tq, rows, total)


# --------------------------------------------------------------------------------------------- rules


@router.get("/rules")
async def cache_rules(
    request: Request,
    admin: AdminSession,
    tq: Annotated[TableQuery, Depends(table_params(RULES_SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    """Every cache rule (at most `MAX_CACHE_RULES`, 500), searched, sorted and paged on the server."""
    ctx = get_ctx(request)
    if fmt is not None:
        rows = [_row(CACHE_RULES, row) for row in await _service(ctx).list_rows(CACHE_RULES)]
        everything = dataclasses.replace(tq, page=1, page_size=max(1, len(rows)))
        ordered, total = page_rows(rows, everything, search_keys=RULE_SEARCH_KEYS)
        return await export_table(request, admin, RULES_SPEC, ordered, fmt, total=total, tq=tq)
    return await rules_answer(ctx, tq)


RULE_SEARCH_KEYS: Final[tuple[str, ...]] = ("pattern", "note", "type", "origin")


async def rules_answer(ctx: Any, tq: TableQuery) -> dict[str, Any]:
    """The `GET /cache/rules` table answer (the Cache page's rules card reads the same function)."""
    rows = [_row(CACHE_RULES, row) for row in await _service(ctx).list_rows(CACHE_RULES)]
    items, total = page_rows(rows, tq, search_keys=RULE_SEARCH_KEYS)
    answer = table_answer(RULES_SPEC, tq, items, total)
    answer["default_ttl_s"] = int(ctx.settings.int("cache_ttl_seconds"))
    return answer


async def rule_view(ctx: Any, rule_id: int) -> dict[str, Any] | None:
    """One cache rule in its typed form, or None (the inspector's rule and the page's rule drawer)."""
    found = await _service(ctx).get_row(CACHE_RULES, int(rule_id))
    return _row(CACHE_RULES, found) if found is not None else None


def _rule_fields(body: ApiBody, *, exclude_unset: bool) -> dict[str, Any]:
    fields = body.model_dump(exclude_unset=exclude_unset, exclude={"reason", "purge"})
    return {key: value for key, value in fields.items() if value is not None or not exclude_unset}


@router.post("/rules", status_code=201)
async def cache_rule_create(
    request: Request, admin: AdminSession, _csrf: CsrfChecked, body: CacheRuleCreate
) -> dict[str, Any]:
    """Add a cache rule; by default drop the stored answers it now covers (glob or regex, as its type says)."""
    ctx = get_ctx(request)
    reason = require_reason(body.reason, required=False)
    row = {key: value for key, value in _rule_fields(body, exclude_unset=False).items() if value is not None}
    row["origin"] = "admin"
    change = await run_mutation(
        _service(ctx).create(CACHE_RULES, row, actor_for(admin), reason, request_id=request_id_of(request))
    )
    purged = None
    if body.purge:
        scope = PurgeScope.pattern(str(change.after["pattern"]), str(change.after["type"]))
        purged = await purge_audited(request, admin, scope, reason, cause=f"cache rule {change.key} added")
    return {
        "rule": _row(CACHE_RULES, change.after),
        "config_version": change.config_version,
        "audit_id": change.audit_id,
        "purge": purged,
    }


@router.patch("/rules/{rule_id}")
async def cache_rule_update(
    request: Request,
    admin: AdminSession,
    _csrf: CsrfChecked,
    body: CacheRuleUpdate,
    rule_id: common.RowId,
) -> dict[str, Any]:
    """Change a cache rule; by default drop the answers stored under it (and under its new pattern)."""
    ctx = get_ctx(request)
    reason = require_reason(body.reason, required=False)
    changes = _rule_fields(body, exclude_unset=True)
    if not changes:
        raise validation_error({"body": "Give at least one field to change."}, "Nothing to change.")
    change = await run_mutation(
        _service(ctx).update(CACHE_RULES, rule_id, changes, actor_for(admin), reason, request_id=request_id_of(request))
    )
    purges: list[dict[str, Any]] = []
    if body.purge and change.changed:
        purges.append(
            await purge_audited(request, admin, PurgeScope.rule(rule_id), reason, cause=f"cache rule {rule_id} changed")
        )
        before, after = change.before or {}, change.after or {}
        if (before.get("pattern"), before.get("type")) != (after.get("pattern"), after.get("type")):
            scope = PurgeScope.pattern(str(after["pattern"]), str(after["type"]))
            purges.append(await purge_audited(request, admin, scope, reason, cause=f"cache rule {rule_id} changed"))
    return {
        "rule": _row(CACHE_RULES, change.after),
        "changed": change.changed,
        "config_version": change.config_version,
        "audit_id": change.audit_id,
        "purges": purges,
    }


@router.delete("/rules/{rule_id}")
async def cache_rule_delete(
    request: Request,
    admin: AdminSession,
    _csrf: CsrfChecked,
    rule_id: common.RowId,
    body: Annotated[RemoveBody | None, Body()] = None,
) -> dict[str, Any]:
    """Remove a cache rule; by default drop the answers stored under it (they would keep its lifetime)."""
    ctx = get_ctx(request)
    options = body or RemoveBody()
    reason = require_reason(options.reason, required=False)
    change = await run_mutation(
        _service(ctx).delete(CACHE_RULES, rule_id, actor_for(admin), reason, request_id=request_id_of(request))
    )
    purged = None
    if options.purge:
        purged = await purge_audited(
            request, admin, PurgeScope.rule(rule_id), reason, cause=f"cache rule {rule_id} removed"
        )
    return {
        "deleted": _row(CACHE_RULES, change.before),
        "config_version": change.config_version,
        "audit_id": change.audit_id,
        "purge": purged,
    }


# --------------------------------------------------------------------------------------------- ignored params


def _spread_dict(group: Any) -> dict[str, Any]:
    return {
        "key": group.key,
        "method": group.method,
        "path": f"{group.host}/{group.path}" if group.path else group.host,
        "entries": group.entries,
        "hits": group.hits,
        "bytes": group.bytes,
        "varying": [
            {
                "name": v.name,
                "values": v.values,
                "ratio": round(v.ratio, 3),
                "samples": [redact_text(sample) for sample in v.samples],
            }
            for v in group.varying
        ],
        "suspect": group.suspect,
        "suspect_param": group.suspect_param,
    }


@router.get("/ignored-params")
async def cache_ignored_params(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """Query parameters left out of cache keys, the v1 suggestions not yet ignored, and the key spread's suspects."""
    return await ignored_params_answer(get_ctx(request))


async def ignored_params_answer(ctx: Any) -> dict[str, Any]:
    """The `GET /cache/ignored-params` answer (the Cache page's ignored parameters card reads the same function)."""
    rows = [_row(IGNORED_PARAMS, row) for row in await _service(ctx).list_rows(IGNORED_PARAMS)]
    ignored = {str(row["name"]) for row in rows}
    suspects: list[dict[str, Any]] = []
    cache = getattr(ctx, "cache", None)
    if cache is not None:
        with service_errors():
            groups = await cache.key_spread(limit=25)
        for group in groups:
            if group.suspect and group.suspect_param and group.suspect_param not in ignored:
                suspects.append(
                    {
                        "param": group.suspect_param,
                        "path": f"{group.host}/{group.path}",
                        "entries": group.entries,
                        "hits": group.hits,
                    }
                )
    return {
        "items": rows,
        "total": len(rows),
        "cap": MAX_CACHE_IGNORED_PARAMS,
        "suggestions": [name for name in SUGGESTED_CACHE_IGNORED_PARAMS if name not in ignored],
        "suspects": suspects,
    }


@router.post("/ignored-params", status_code=201)
async def cache_ignored_param_add(
    request: Request, admin: AdminSession, _csrf: CsrfChecked, body: IgnoredParamBody
) -> dict[str, Any]:
    """Leave a parameter out of cache keys; by default drop exactly the answers keyed with it (row 54)."""
    ctx = get_ctx(request)
    reason = require_reason(body.reason, required=False)
    row = {"name": body.name, "note": body.note, "origin": "admin"}
    change = await run_mutation(
        _service(ctx).create(IGNORED_PARAMS, row, actor_for(admin), reason, request_id=request_id_of(request))
    )
    purged = None
    if body.purge:
        name = str(change.after["name"])
        purged = await purge_audited(request, admin, PurgeScope.param(name), reason, cause=f"ignored param {name}")
    return {
        "param": _row(IGNORED_PARAMS, change.after),
        "config_version": change.config_version,
        "audit_id": change.audit_id,
        "purge": purged,
    }


@router.delete("/ignored-params/{name}")
async def cache_ignored_param_remove(
    request: Request,
    admin: AdminSession,
    _csrf: CsrfChecked,
    name: Annotated[str, Path(max_length=MAX_PARAM_CHARS)],
    body: Annotated[RemoveBody | None, Body()] = None,
) -> dict[str, Any]:
    """Put a parameter back into cache keys; by default drop the answers stored without it (they were shared by
    callers that sent different values, which would now be wrong)."""
    ctx = get_ctx(request)
    options = body or RemoveBody()
    reason = require_reason(options.reason, required=False)
    change = await run_mutation(
        _service(ctx).delete(IGNORED_PARAMS, name, actor_for(admin), reason, request_id=request_id_of(request))
    )
    purged = None
    if options.purge:
        purged = await purge_audited(request, admin, PurgeScope.param(name), reason, cause=f"ignored param {name}")
    return {
        "deleted": _row(IGNORED_PARAMS, change.before),
        "config_version": change.config_version,
        "audit_id": change.audit_id,
        "purge": purged,
    }


@router.get("/spread")
async def cache_spread(
    request: Request, _admin: AdminSession, limit: Annotated[int, Query(ge=1, le=100)] = 25
) -> dict[str, Any]:
    """The key spread diagnostic (row 65): endpoints whose stored answers split on a changing parameter."""
    return await spread_answer(get_ctx(request), limit)


async def spread_answer(ctx: Any, limit: int) -> dict[str, Any]:
    """The `GET /cache/spread` answer (the Cache page's key spread card reads the same function)."""
    cache = _cache(ctx)
    with service_errors():
        groups = await cache.key_spread(limit=limit)
    ignored = {str(row["name"]) for row in await _service(ctx).list_rows(IGNORED_PARAMS)}
    return {
        "items": [_spread_dict(group) for group in groups],
        "ignored": sorted(ignored),
        "suggested": [name for name in SUGGESTED_CACHE_IGNORED_PARAMS if name not in ignored],
    }


# --------------------------------------------------------------------------------------------- browser


@router.get("/entries")
async def cache_entries(
    request: Request,
    _admin: AdminSession,
    tq: Annotated[TableQuery, Depends(table_params(BROWSER_SPEC))],
) -> dict[str, Any]:
    """One page of stored answers (row 66): search by any part of the key, sort either way, no bodies."""
    return await entries_answer(get_ctx(request), tq)


async def entries_answer(ctx: Any, tq: TableQuery) -> dict[str, Any]:
    """The `GET /cache/entries` answer (the Cache page's browser card reads the same function)."""
    cache = _cache(ctx)
    await cache.flush()  # this worker's buffered hit counts first, so "Times reused" is current
    now = ctx.clock.now()
    sort = BROWSER_SORTS[tq.sort]
    with service_errors():
        found = await ctx.dbs.cache.read(
            lambda conn: read_browser.browse(
                conn,
                query=tq.q,
                sort=sort,
                descending=tq.descending,
                offset=tq.offset,
                limit=tq.page_size,
                now=now,
            )
        )
    answer = table_answer(BROWSER_SPEC, tq, found["rows"], found["total"])
    answer["fresh"] = found["fresh"]
    return answer


def _entry_id(entry_id: str) -> str:
    if not ENTRY_ID_RE.fullmatch(entry_id):
        raise validation_error({"entry_id": "An entry id is 24 lowercase hex characters."})
    return entry_id


def _inspect(found: Mapping[str, Any], now: float, rule: Any) -> dict[str, Any]:
    """The inspector view in API names; bodies scrubbed and cut (runs on a worker thread)."""
    body = str(found.get("Body") or "")
    request_body = found.get("RequestBody")
    return {
        "id": found["Id"],
        "key": found["Key"],
        "auth_class": found["AuthClass"],
        "method": found["Method"],
        "path": found["Path"],
        "params": found.get("Params") or [],
        "stripped": found.get("Stripped") or [],
        "status": found["Status"],
        "content_type": found.get("ContentType"),
        "body": redact_text(body[:MAX_INSPECT_BODY]),
        "body_length": found.get("BodyLength"),
        "body_truncated": len(body) > MAX_INSPECT_BODY,
        "request_body": None if request_body is None else redact_text(str(request_body)[:MAX_INSPECT_BODY]),
        "stored_at": found["StoredAt"],
        "expires_at": found["ExpiresAt"],
        "stale_until": found["StaleUntil"],
        "ttl": found["TTL"],
        "age_s": found["Age"],
        "state": read_browser.entry_state(
            negative=bool(found["Negative"]),
            status=int(found["Status"]),
            expires_at=int(found["ExpiresAt"]),
            stale_until=int(found["StaleUntil"]),
            now=now,
        ),
        "negative": bool(found["Negative"]),
        "hits": found["Hits"],
        "last_hit_at": found.get("LastHit"),
        "rule_id": found.get("Rule"),
        "rule": rule,
        "egress": found.get("Egress"),
        "bytes": found.get("Bytes"),
    }


@router.get("/entries/{entry_id}")
async def cache_entry(
    request: Request, _admin: AdminSession, entry_id: Annotated[str, Path(max_length=64)]
) -> dict[str, Any]:
    """Inspect one stored answer, body included (scrubbed, at most 256 KiB shown)."""
    return await entry_answer(get_ctx(request), entry_id)


async def entry_answer(ctx: Any, entry_id: str) -> dict[str, Any]:
    """The `GET /cache/entries/{id}` answer (the Cache page's inspector drawer reads the same function); 422 for a
    malformed id, 404 for an entry that is gone."""
    cache = _cache(ctx)
    with service_errors():
        found = await cache.get_entry(_entry_id(entry_id))
    if found is None or read_browser.is_handoff_key(found.get("Key")):
        raise not_found(ENTRY_GONE)
    rule = await rule_view(ctx, int(found["Rule"])) if found.get("Rule") is not None else None
    return await asyncio.to_thread(_inspect, found, ctx.clock.now(), rule)


def _vary_from_key(key: str) -> dict[str, str]:
    """The forwarded caller headers a key text carries (` ^name=value`, `cache/keys.py`), decoded."""
    headers: dict[str, str] = {}
    for token in key.split(" ")[2:]:
        if token.startswith("^") and "=" in token:
            name, value = token[1:].split("=", 1)
            headers[name.lower()] = unquote(value)
    return headers


def _refresh_request(ctx: Any, principal: AdminPrincipal, entry: Any, req_body: bytes | None) -> ProxyRequest:
    """The proxy request that asks Roblox for `entry` again, validated like a caller's (plan 9.10)."""
    raw_path = "/" + entry.host + validate.quote_path("/" + entry.path if entry.path else "/")
    query_string = validate.encode_query(entry.params)
    parse = validate.parse_target(
        raw_path,
        query_string,
        entry.method,
        allowed_hosts=allowed_hosts(ctx),
        strict_host_allowlist=bool(setting(ctx, "strict_host_allowlist")),
        max_url_length=int(setting(ctx, "max_url_length")),
    )
    if parse.problem is not None:
        raise conflict(NOT_PROXYABLE, code="wrong_state")
    headers = _vary_from_key(entry.key)
    body = (req_body or b"") if entry.method != "GET" else b""
    return ProxyRequest(
        request_id=new_request_id(ctx.clock),
        received_ms=ctx.clock.now_ms(),
        deadline_at=time.monotonic() + float(setting(ctx, "request_deadline_s")),
        client_ip=principal.ip,
        limit_key=principal.ip,
        method=parse.method,
        host=parse.host,
        path=parse.path,
        query=list(parse.query),
        prettyprint=False,
        body=body,
        content_type=headers.get("content-type"),
        headers=headers,
        header_names_in_order=list(headers),
        user_agent="",
        place_id=None,
        is_browser=is_browser(""),
        template=endpoint_template(parse.host, parse.path),
        target=parse.target,
        raw_query=parse.raw_query,
        raw_path=parse.raw_target,
    )


@router.post("/entries/{entry_id}/refresh")
async def cache_entry_refresh(
    request: Request,
    admin: AdminSession,
    _csrf: CsrfChecked,
    entry_id: Annotated[str, Path(max_length=64)],
) -> dict[str, Any]:
    """Fetch one stored answer from Roblox again and replace the copy (row 66; POST entries too)."""
    ctx = get_ctx(request)
    cache = _cache(ctx)
    entry_id = _entry_id(entry_id)
    shared = cache.store.shared
    if shared is None:
        raise not_found(ENTRY_GONE)
    with service_errors():
        found = await shared.get_row(entry_id)
    if found is None or read_browser.is_handoff_key(found[0].key):
        raise not_found(ENTRY_GONE)
    entry, req_body = found
    if entry.is_marker:
        raise conflict(
            "This row is a 429 marker, not an answer; it ends by itself when Roblox's cooldown does.",
            code="wrong_state",
        )
    if entry.auth_class is AuthClass.CRED or entry.key.endswith(CRED_SUFFIX):
        raise conflict(
            "Answers fetched with the credential are not refreshed from the dashboard (plan C1); purge it instead "
            "and the next caller request fetches it again.",
            code="wrong_state",
        )
    req = _refresh_request(ctx, admin, entry, req_body)
    peek = await cache.peek(req)
    if peek.key is None:
        raise conflict(
            "Caching no longer applies to this request (cache off, POST caching off for it, or a rule with a "
            "lifetime of 0); purge the entry instead.",
            code="wrong_state",
        )
    if peek.key.id != entry_id:
        raise conflict(
            "The cache rules or ignored parameters changed since this answer was stored, so a fetch would store a "
            "different entry; purge this one instead.",
            code="wrong_state",
        )
    actor = actor_for(admin)
    request_id = request_id_of(request)
    now = int(ctx.clock.now())

    def write(conn: sqlite3.Connection) -> int:
        details = {"entry": entry_id, "key": entry.key[:200], "method": entry.method}
        return audit.record(conn, actor, "cache.refresh", f"cache:{entry_id}", None, details, None, request_id, at=now)

    with service_errors():
        audit_id = await ctx.dbs.control.write(write)
    forced = dataclasses.replace(peek, fresh=None, stale=None, bypassed=False)  # set the stored copy aside
    started = time.monotonic()
    result = await cache.serve(req, forced)
    elapsed_ms = (time.monotonic() - started) * 1000.0
    await cache.settle(REFRESH_SETTLE_S)
    recorder = getattr(ctx, "recorder", None)
    ok = result.outcome in (Outcome.SERVED_UPSTREAM, Outcome.SERVED_CACHE) and 200 <= int(result.status) < 400
    if recorder is not None and int(result.upstream_calls or 0) > 0:
        # Roxy's own call, not caller demand: counted as internal, so "avoided" stays honest (P6).
        recorder.record_internal_call(
            REFRESH_PURPOSE,
            ok=ok,
            status=result.upstream_status,
            duration_ms=elapsed_ms,
            endpoint_template=req.template,
            host=req.host,
            method=req.method,
            egress=result.egress,
            auth_class=result.auth_class,
            calls=int(result.upstream_calls),
            bytes_in=int(result.upstream_bytes_in),
            bytes_out=int(result.upstream_bytes_out),
            trigger="admin",
        )
    with service_errors():
        after = await shared.get_row(entry_id)
    stored = (
        after is not None
        and after[0].stored_at >= entry.stored_at
        and (after[0].stored_at != entry.stored_at or after[0].expires_at != entry.expires_at)
    )
    if ok:
        message = "Fetched from Roblox; the stored copy was replaced." if stored else "Fetched from Roblox."
    else:
        message = f"Roblox did not give a usable answer ({result.status}); the stored copy was left alone."
    return {
        "ok": ok,
        "message": message,
        "status": int(result.status),
        "upstream_status": result.upstream_status,
        "cache_state": str(result.cache_state),
        "reason": str(result.reason),
        "upstream_calls": int(result.upstream_calls or 0),
        "stored": stored,
        "entry": None
        if after is None
        else {"stored_at": after[0].stored_at, "expires_at": after[0].expires_at, "status": after[0].status},
        "audit_id": audit_id,
    }


@router.post("/purge")
async def cache_purge(request: Request, admin: AdminSession, _csrf: CsrfChecked, body: PurgeBody) -> dict[str, Any]:
    """Purge by id, pattern (glob or regex), host, rule, the browser search (`search`: exactly the entries the same
    `q` lists, one shared matcher), expired, or all (`confirm: true`); audited first."""
    reason = require_reason(body.reason, required=False)
    value = (body.value or "").strip()
    if body.scope in ("id", "pattern", "host", "rule", "search") and not value:
        raise validation_error({"value": f"Give the {body.scope} to purge."}, "Nothing to purge.")
    if body.scope == "all" and not body.confirm:
        raise validation_error(
            {"confirm": "Purge all empties the whole cache; send confirm: true to go ahead."},
            "Purge all needs a confirmation.",
            code="confirmation_required",
        )
    scope: PurgeScope
    if body.scope == "id":
        scope = PurgeScope.entry(_entry_id(value))
    elif body.scope == "pattern":
        scope = PurgeScope.pattern(value, body.type)
    elif body.scope == "host":
        scope = PurgeScope.host(value)
    elif body.scope == "rule":
        if not value.isdigit():
            raise validation_error({"value": "A rule id is a whole number."})
        scope = PurgeScope.rule(int(value))
    elif body.scope == "search":
        try:
            scope = read_browser.purge_scope(value)
        except ValueError as exc:
            raise validation_error({"value": str(exc)}, "The purge is not valid.") from None
    elif body.scope == "expired":
        scope = PurgeScope.expired(include_stale=body.include_stale)
    else:
        scope = PurgeScope.all()
    report = await purge_audited(request, admin, scope, reason, cause="admin purge")
    removed = int(report["removed"])
    report["message"] = f"{removed} {'entry' if removed == 1 else 'entries'} removed."
    return report


__all__ = [
    "BROWSER_SPEC",
    "ENDPOINTS_SPEC",
    "RATIO_METRICS",
    "RULES_SPEC",
    "STATE_LABELS",
    "STATE_METRICS",
    "cache_series",
    "endpoints_answer",
    "entries_answer",
    "entry_answer",
    "ignored_params_answer",
    "purge_audited",
    "router",
    "rule_view",
    "rules_answer",
    "spread_answer",
    "stats_answer",
]
