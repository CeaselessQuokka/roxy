"""Export API (`/admin/api/v1/export`): any dataset as a CSV or JSON download, through the shared export guard.

What this is
    `GET /export/datasets` lists every exportable dataset (name, label, description, columns, whether it takes a
    time range). `GET /export/{dataset}?format=csv|json` downloads one, for a time range where that applies
    (`range`, `from`, `to` as everywhere else). Every table route of the other areas also accepts `format=`
    (DESIGN.md section 13); this area adds the Data page's "exports per dataset" card (plan 14.1, parity row 88)
    and the datasets that have no table route of their own. The LLM export is another area (`export_llm`, served
    at `/export/llm`).

Why it exists
    v1 exported a few tables as CSV from the browser, formula guarded (parity row 88). v2 exports every dataset as
    CSV or JSON from the server, with the same guards everywhere: `common.export_pages` quotes every cell, puts an
    apostrophe before a cell that would start a spreadsheet formula, hashes client IP addresses (in every cell)
    unless `export_include_ips` is on (plan 9.15, 12.3), caps the rows (`MAX_EXPORT_ROWS`), the bytes
    (`MAX_EXPORT_BYTES`) and the downloads a worker builds at once (`MAX_CONCURRENT_EXPORTS`), and writes the audit
    row (`export.download`) before the file leaves (plan 9.7; a refused audit write is a 503 and no file).

How it works
    `DATASETS` maps a name to a `TableSpec` (columns, labels, help, which columns hold IP addresses) and a page
    reader over the existing read model (`metrics/queries.py`, `metrics/security_events.py`,
    `metrics/read_errors.py`, `config/read_audit.py`, `config/read_settings.py`, the System and Data areas).
    `common.export_pages` reads one page at a time and drops it once it is in the file; a read model that has no
    pages (a summary, or rows it caps itself at the export cap) is one page (`_whole`).

What to read next
    `roxy/admin/api/common.py` (`export_pages`, `ExportBuilder`, `export_ip_policy`).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Annotated, Any, Final

from fastapi import Path, Request

from roxy.admin.api import common
from roxy.admin.api.audit import AUDIT_TABLE
from roxy.admin.api.common import AdminSession, Column, ExportFormatDep, TableSpec, TimeRange, TimeRangeDep
from roxy.admin.api.settings import HISTORY_TABLE, default_of, shown
from roxy.admin.api.system import ERRORS_TABLE, WORKERS_TABLE, fleet
from roxy.config import catalog, read_audit, read_settings
from roxy.deps import get_ctx
from roxy.metrics import queries, read_errors, read_history, security_events

router = common.area_router("export")

PAGE: Final = max(common.PAGE_SIZES)

_MEASURE_COLUMNS: Final = (
    Column("requests", "Requests", "Caller requests in the range.", "count"),
    Column("demand", "Demand", "Requests that wanted an answer (not refused, not local, not internal).", "count"),
    Column("served_upstream", "From Roblox", "Answered with a fresh call to Roblox.", "count"),
    Column("served_cache", "From cache", "Answered from Roxy's cache.", "count"),
    Column("refused", "Refused", "Refused by Roxy (limits, rules, pause).", "count"),
    Column("failed", "Failed", "Roxy could not get an answer.", "count"),
    Column("upstream_calls", "Upstream calls", "Calls made to Roblox for callers.", "count"),
    Column("avoided", "Avoided calls", "Demand minus upstream calls (plan P6).", "count"),
    Column("hit_ratio", "Hit ratio", "Share of cache lookups answered from the cache.", "ratio"),
    Column("roblox_429", "Roblox 429s", "429 answers Roblox sent.", "count"),
    Column("status_4xx", "4xx", "Answers with a 4xx status.", "count"),
    Column("status_5xx", "5xx", "Answers with a 5xx status.", "count"),
    Column("p50_ms", "p50", "Median latency.", "ms"),
    Column("p95_ms", "p95", "95th percentile latency.", "ms"),
    Column("p99_ms", "p99", "99th percentile latency.", "ms"),
)

_CLIENT_COLUMNS: Final = (
    Column("requests", "Requests", "Requests in the range.", "count"),
    Column("refused", "Refused", "Requests refused.", "count"),
    Column("served", "Served", "Requests answered.", "count"),
    Column("bytes", "Bytes", "Bytes sent to this client.", "bytes"),
    Column("refused_pct", "Refused %", "Share refused.", "percent"),
    Column("top_endpoint", "Top endpoint", "The busiest endpoint template."),
    Column("rate1", "Rate 1 min", "Requests per minute over the last minute.", "per_min"),
    Column("rate5", "Rate 5 min", "Requests per minute over the last 5 minutes.", "per_min"),
    Column("rate60", "Rate 60 min", "Requests per minute over the last hour.", "per_min"),
    Column(
        "last_seen",
        "Last seen",
        "Its newest request in the range, to the minute (coarser for compacted data).",
        "timestamp",
    ),
    Column(
        "peers",
        "Peers",
        "Distinct places for an address, distinct addresses for a place (a lower bound under a flood).",
        "count",
        sortable=False,
    ),
)

_SECURITY_COLUMNS: Final = (
    Column("id", "Event", "The event number."),
    Column("at_ms", "When", "When it happened (Unix milliseconds).", "ms_time"),
    Column("reason", "Reason", "The reason or signature."),
    Column("count", "Count", "How many times (aggregated rows carry their count).", "count"),
    Column("ip", "Client", "The client address.", ip=True),
    Column("target", "Target", "What was asked for (redacted).", sortable=False),
    Column("path", "Path", "The path (redacted).", sortable=False),
    Column("user_agent", "User-Agent", "The User-Agent.", sortable=False),
    Column("username", "Username", "The username tried (logins).", sortable=False),
    Column("successful", "Successful", "Whether a login succeeded.", sortable=False),
)

Rows = tuple[list[dict[str, Any]], int]
Pages = Callable[[Any, TimeRange], common.PageFetch]
"""How a dataset is read: `pages(ctx, tr)` gives a page reader, `fetch(page, page_size) -> (items, total)`."""


@dataclass(frozen=True, slots=True)
class Dataset:
    """One exportable dataset: its table spec, whether it takes a time range, and how to read it (page by page)."""

    spec: TableSpec
    label: str
    description: str
    ranged: bool
    pages: Pages


def _spec(name: str, columns: tuple[Column, ...], default_sort: str) -> TableSpec:
    return TableSpec(name=name, columns=columns, default_sort=default_sort)


def _whole(read: Callable[[Any, TimeRange], Awaitable[Rows]]) -> Pages:
    """A reader for a dataset its read model returns in one piece (a small summary, or rows capped by the read
    model at `MAX_EXPORT_ROWS`): all of it is page 1."""

    def pages(ctx: Any, tr: TimeRange) -> common.PageFetch:
        async def fetch(number: int, _size: int) -> Rows:
            if number > 1:
                return [], 0
            return await read(ctx, tr)

        return fetch

    return pages


def _top(dimension: str) -> Pages:
    def pages(ctx: Any, tr: TimeRange) -> common.PageFetch:
        async def fetch(number: int, size: int) -> Rows:
            data = await queries.top_n(
                ctx.dbs.metrics, tr.window, dimension, page=queries.Page(number, size, "requests")
            )
            return list(data["rows"]), int(data["total"])

        return fetch

    return pages


def _clients(kind: str) -> Pages:
    def pages(ctx: Any, tr: TimeRange) -> common.PageFetch:
        now = ctx.clock.now()

        async def fetch(number: int, size: int) -> Rows:
            data = await queries.client_table(
                ctx.dbs.metrics,
                tr.window,
                kind,
                now=now,
                page=queries.Page(number, size, "requests"),
                extras=True,  # Last seen and peers, as the Clients tables show (finding parity-7)
            )
            return list(data["rows"]), int(data["total"])

        return fetch

    return pages


def _security(event_type: str) -> Pages:
    def pages(ctx: Any, tr: TimeRange) -> common.PageFetch:
        since, until = tr.window.start * 1000, tr.window.end * 1000

        async def fetch(number: int, size: int) -> Rows:
            data = await ctx.dbs.metrics.read(
                lambda conn: security_events.ring(
                    conn, event_type, since_ms=since, until_ms=until, limit=size, offset=(number - 1) * size
                )
            )
            return list(data["items"]), int(data["total"])

        return fetch

    return pages


async def _rows(ctx: Any, tr: TimeRange, read: Callable[[Any], list[dict[str, Any]]]) -> Rows:
    rows: list[dict[str, Any]] = await ctx.dbs.metrics.read(read)
    return rows[: common.MAX_EXPORT_ROWS], len(rows)


async def _refusals(ctx: Any, tr: TimeRange) -> Rows:
    return await _rows(ctx, tr, lambda conn: queries.refusal_reasons(conn, tr.window))


async def _internal(ctx: Any, tr: TimeRange) -> Rows:
    return await _rows(ctx, tr, lambda conn: queries.internal_calls(conn, tr.window))


def _429s(ctx: Any, tr: TimeRange) -> common.PageFetch:
    """The Roblox 429 log page by page (one page held at a time, finding mpjobs-5), with the honest total from the
    rollups (P6: rows the recorder folded over its budget are counted there)."""
    start, end = tr.window.start, tr.window.end

    async def fetch(number: int, size: int) -> Rows:
        def read(conn: Any) -> Rows:
            rows = read_history.upstream_429_rows(conn, start, end, limit=size, offset=(number - 1) * size)
            total = read_history.roblox_429_counts(conn, start, end, group_by=()).get((), 0)
            return rows, max(total, (number - 1) * size + len(rows))

        result: Rows = await ctx.dbs.metrics.read(read)
        return result

    return fetch


def _errors(ctx: Any, _tr: TimeRange) -> common.PageFetch:
    async def fetch(number: int, size: int) -> Rows:
        rows, total = await ctx.dbs.metrics.read(
            lambda conn: read_errors.errors_page(conn, limit=size, offset=(number - 1) * size)
        )
        return list(rows), int(total)

    return fetch


def _audit(ctx: Any, tr: TimeRange) -> common.PageFetch:
    async def fetch(number: int, size: int) -> Rows:
        rows, total = await ctx.dbs.control.read(
            lambda conn: read_audit.audit_page(
                conn, since=tr.window.start, until=tr.window.end, limit=size, offset=(number - 1) * size
            )
        )
        return list(rows), int(total)

    return fetch


def _history(ctx: Any, tr: TimeRange) -> common.PageFetch:
    async def fetch(number: int, size: int) -> Rows:
        rows, total = await ctx.dbs.control.read(
            lambda conn: read_settings.history_page(
                conn, since=tr.window.start, until=tr.window.end, limit=size, offset=(number - 1) * size
            )
        )
        return list(rows), int(total)

    return fetch


SETTINGS_TABLE: Final = _spec(
    "settings",
    (
        Column("key", "Key", "The setting key."),
        Column("group", "Group", "The Settings page group."),
        Column("label", "Label", "The setting's name."),
        Column("value", "Value", "The current value ([redacted] for a sensitive setting).", sortable=False),
        Column("default", "Default", "The catalog default.", sortable=False),
        Column("overridden", "Changed", "Whether an admin changed it from the default."),
        Column("unit", "Unit", "The unit.", sortable=False),
        Column("risk", "Risk", "low, medium or high."),
        Column("apply", "Applies", "live (within a second) or restart."),
    ),
    "key",
)


async def _settings(ctx: Any, _tr: TimeRange) -> Rows:
    snapshot = ctx.settings.snapshot()
    rows = [
        {
            "key": spec.key,
            "group": spec.group.value,
            "label": spec.label,
            "value": shown(spec, snapshot[spec.key]),
            "default": shown(spec, default_of(spec)),
            "overridden": snapshot.is_overridden(spec.key),
            "unit": spec.unit,
            "risk": spec.risk.value,
            "apply": spec.apply.value,
        }
        for spec in catalog.CATALOG.values()
    ]
    return rows, len(rows)


async def _workers(ctx: Any, _tr: TimeRange) -> Rows:
    data = await fleet(ctx)
    rows: list[dict[str, Any]] = data["workers"]
    return rows, len(rows)


DATASETS: Final[dict[str, Dataset]] = {
    "endpoints": Dataset(
        _spec("endpoints", (Column("key", "Endpoint", "The endpoint template."), *_MEASURE_COLUMNS), "requests"),
        "Endpoints",
        "Every endpoint template with its traffic, cache, 429 and latency numbers.",
        True,
        _top("endpoint_template"),
    ),
    "hosts": Dataset(
        _spec("hosts", (Column("key", "Host", "The Roblox host."), *_MEASURE_COLUMNS), "requests"),
        "Hosts",
        "Every Roblox host with its traffic, cache, 429 and latency numbers.",
        True,
        _top("host"),
    ),
    "clients_ip": Dataset(
        _spec("clients_ip", (Column("key", "Client", "The client address.", ip=True), *_CLIENT_COLUMNS), "requests"),
        "Clients by IP address",
        "Every client address with its requests, refusals, bytes and rates.",
        True,
        _clients("ip"),
    ),
    "clients_place": Dataset(
        _spec("clients_place", (Column("key", "Place", "The place id (Roblox-Id)."), *_CLIENT_COLUMNS), "requests"),
        "Clients by place",
        "Every place (experience) with its requests, refusals, bytes and rates.",
        True,
        _clients("place"),
    ),
    "refusal_reasons": Dataset(
        _spec(
            "refusal_reasons",
            (
                Column("reason", "Reason", "The refusal or failure reason code."),
                Column("requests", "Requests", "Requests with this reason.", "count"),
                Column("last_status", "Status", "The status code the newest of them got."),
                Column("last_path", "Last path", "The path the newest of them asked for.", sortable=False),
                Column("clients", "Unique clients", "Distinct client hashes (a lower bound).", "count"),
                Column("unattributed", "Unattributed", "Refusals recorded without a client.", "count"),
                Column("first_ms", "First seen", "When the oldest was recorded.", "timestamp_ms"),
                Column("last_ms", "Last seen", "When the newest was recorded.", "timestamp_ms"),
                Column("message_source", "Message", "Custom versus default message counts (row 116).", sortable=False),
            ),
            "requests",
        ),
        "Refusal reasons",
        "Refusals and failures by reason, with the custom versus default message split.",
        True,
        _whole(_refusals),
    ),
    "internal_calls": Dataset(
        _spec(
            "internal_calls",
            (
                Column("purpose", "Call site", "What Roxy called Roblox for."),
                Column("count", "Calls", "Calls made.", "count"),
                Column("failed", "Failed", "Calls that failed.", "count"),
                Column("mean_ms", "Mean", "Mean duration.", "ms"),
                Column("last_ms", "Last call", "When the last call was made (Unix milliseconds).", "ms_time"),
                Column("last_error", "Last error", "The last error.", sortable=False),
            ),
            "count",
        ),
        "Internal calls",
        "Roxy's own calls to Roblox (probes, lookups) by purpose.",
        True,
        _whole(_internal),
    ),
    "upstream_429": Dataset(
        _spec(
            "upstream_429",
            (
                Column("at_ms", "When", "When Roblox answered 429 (Unix milliseconds).", "ms_time"),
                Column("endpoint_template", "Endpoint", "The endpoint template."),
                Column("host", "Host", "The Roblox host."),
                Column("egress", "Egress", "The path the call took."),
                Column("retry_after_s", "Retry-After", "What Roblox asked to wait.", "s"),
                Column("ratelimit_headers_json", "Rate limit headers", "Roblox's rate limit headers.", sortable=False),
                Column("request_id", "Request", "The request id."),
            ),
            "at_ms",
        ),
        "Roblox 429s",
        "Every 429 Roblox sent in the range.",
        True,
        _429s,
    ),
    "probes": Dataset(
        _spec("probes", _SECURITY_COLUMNS, "id"),
        "Probes",
        "Probe and exploit attempts.",
        True,
        _security(security_events.PROBE),
    ),
    "logins": Dataset(
        _spec("logins", _SECURITY_COLUMNS, "id"),
        "Admin logins",
        "Admin login attempts.",
        True,
        _security(security_events.LOGIN),
    ),
    "crawls": Dataset(
        _spec("crawls", _SECURITY_COLUMNS, "id"),
        "Crawls",
        "robots.txt and sitemap fetches.",
        True,
        _security(security_events.CRAWL),
    ),
    "throttled": Dataset(
        _spec("throttled", _SECURITY_COLUMNS, "id"),
        "Throttled clients",
        "Clients that became throttled.",
        True,
        _security(security_events.THROTTLED),
    ),
    "errors": Dataset(ERRORS_TABLE, "Errors", "Error signatures with counts and last detail.", False, _errors),
    "audit": Dataset(AUDIT_TABLE, "Audit log", "Every admin and automatic action in the range.", True, _audit),
    "settings": Dataset(SETTINGS_TABLE, "Settings", "Every setting with its current value.", False, _whole(_settings)),
    "settings_history": Dataset(HISTORY_TABLE, "Settings history", "Every settings change.", True, _history),
    "workers": Dataset(WORKERS_TABLE, "Workers", "The worker fleet (parity row 84).", False, _whole(_workers)),
}
"""Every exportable dataset, by name."""


@router.get("/datasets")
async def datasets(_admin: AdminSession) -> dict[str, Any]:
    """Every dataset this area exports, with its columns and whether a time range applies."""
    return datasets_answer()


def datasets_answer() -> dict[str, Any]:
    """The `GET /export/datasets` answer (the Data page's exports card lists the same datasets)."""
    return {
        "datasets": [
            {
                "name": name,
                "label": item.label,
                "description": item.description,
                "ranged": item.ranged,
                "columns": item.spec.columns_info(),
                "url": f"{common.API_PREFIX}/export/{name}",
            }
            for name, item in DATASETS.items()
        ],
        "formats": list(common.EXPORT_FORMATS),
        "max_rows": common.MAX_EXPORT_ROWS,
        "llm_export": f"{common.API_PREFIX}/export/llm",
    }


@router.get("/{dataset}", response_model=None)
async def export_dataset(
    request: Request,
    dataset: Annotated[str, Path(pattern=r"^[a-z][a-z0-9_]{0,47}$")],
    admin: AdminSession,
    fmt: ExportFormatDep,
    tr: TimeRangeDep,
) -> Any:
    """Download one dataset as CSV or JSON (formula guarded, IP addresses hashed by policy, audited)."""
    item = DATASETS.get(dataset)
    if item is None:
        raise common.not_found("No dataset has that name; see /export/datasets.")
    if fmt is None:
        raise common.validation_error(
            {"format": "Choose csv or json."}, "Choose an export format.", code="invalid_format"
        )
    fetch = item.pages(get_ctx(request), tr)
    return await common.export_pages(request, admin, item.spec, fetch, fmt, tr=tr if item.ranged else None)


__all__ = ["DATASETS", "Dataset", "datasets_answer", "router"]
