"""Read models for the dashboard's Overview, Traffic, Endpoints and Live views (admin API part C, plan 14.1).

What this is
    Plain functions over a metrics.db connection (run them inside `Database.read`), plus two pure helpers:
      * `legacy_baseline(conn)`: the v1 lifetime figures the migrator stored in `legacy_totals` (plan 11.6: the
        Overview tile "Roblox 429s per 10,000 caller requests" shows v1's lifetime value next to the live one).
      * `notable_events(conn, start_ms, end_ms, ...)`: the Overview's "recent notable events" (breakers, cooldowns,
        credential and rotator changes, bans, purges, recommendations, health runs), newest first, paged.
      * `pair_counts(conn, window, first, second)`: requests summed by two dimensions at once, a generic
        two-dimension count (the Traffic page's "who returned it?" table now reads `queries.answer_source_counts`,
        which counts a Roblox 5xx Roxy passed on as Roblox's, finding parity-1).
      * `recent_live(conn, limit, before_id)` and `live_row(conn, request_id, ...)`: the Live view's rows of every
        worker, newest first, and one request's row; `LiveQuery` and `parse_live_query(...)` are the Live view's
        filter, shared by the Live API and the event stream so both drop exactly the same rows.
      * `endpoint_callers(...)` and `endpoint_429s(...)`: who calls one endpoint (request samples) and the Roblox
        429s it drew (the `upstream_429` log).
      * `endpoint_recency(conn, window, templates)`: v1 Top Endpoints' Methods, Last Request, Last Status and Last
        Caller columns for one page of templates (rollups, refined by the newest Live row).
      * `visit_series(conn, window)`: visitor classes per bucket (sparklines of the Visitors card, row 130).
      * `heatmap(buckets, values, tz)`: hour of day by weekday, folded from hourly buckets (plan 14.1 Traffic).
      * `sparkline_window(window)`: the same time range at a granularity with at most `SPARK_POINTS` buckets.

Why it exists
    DESIGN.md section 13: read models live next to their data, and the API modules stay thin. These views need
    shapes `metrics/queries.py` does not produce (two group columns, the events table filtered by kind, the
    imported v1 figures), so they are written once here and reused by the API and the dashboard pages (P11).

How it works
    Every query is an indexed range read with a bound (`limit`, plan P9). `pair_counts` reuses
    `queries.level_pieces`, so it reads the same rollup levels as every other chart and never counts a request
    twice. Dimension names are checked against `queries.FILTER_COLUMNS` before they reach the SQL text. Times are
    epoch seconds (or milliseconds where the column is `at_ms`); windows are half open `[start, end)`.

What to read next
    `roxy/metrics/queries.py` (the main read models), `roxy/admin/api/overview.py` and `roxy/admin/api/traffic.py`
    (who calls these).
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Final

from roxy.core.reasons import CacheState, Egress, Outcome, ReasonCode
from roxy.metrics import queries
from roxy.metrics.live import LIVE_EVENT, LiveFilter
from roxy.metrics.queries import Window
from roxy.metrics.rollups import bucket_floor, bucket_next, zone

LEGACY_PREFIX: Final = "v1."
LEGACY_KEYS: Final[dict[str, str]] = {
    "roblox_429_per_10k": "v1.roblox_429_per_10k_requests",
    "roblox_429_total": "v1.roblox_429_total",
    "requests_total": "v1.requests_total",
}
"""The `legacy_totals` rows the Overview shows (written by `migration/stats_import.py`, owner decision D17)."""

MAX_LABEL_CHARS: Final = 300

NOTABLE_EVENT_TYPES: Final[frozenset[str]] = frozenset(
    {
        "breaker_open",
        "breaker_half_open",
        "breaker_closed",
        "upstream_429_attribution",
        "credential_cooldown",
        "credential_rotated",
        "credential_replaced",
        "credential_rejected",
        "credential_probe",
        "leak_blocked",
        "rotator_parked",
        "abuse_degraded",
        "abuse_degraded_recovered",
        "spam_ban",
        "spam_would_ban",
        "cache_purge",
        "cache_eviction",
        "recommendation",
        "health_run_finished",
    }
)
"""Event types the Overview lists as "recent notable events". High-volume kinds (live rows, refusals, visits,
probes, retries, aggregated counters) have their own pages and would drown these out."""

MAX_EVENTS_PAGE: Final = 250
MAX_LIVE_ROWS: Final = 2000
"""Most live rows one read returns (the Live view shows at most 500; the rest is filter headroom, plan P9)."""
MAX_CALLERS: Final = 100
MAX_RECENCY_TEMPLATES: Final = 250
"""Most templates `endpoint_recency` answers in one call: one table page (`queries.PAGE_SIZES` maximum)."""
SPARK_POINTS: Final = 61
"""Most points in a KPI sparkline: enough to show a shape, small enough for a tile. 61 keeps the one hour range at
its own minute buckets (60 whole minutes plus the open one), so its sparkline covers exactly the tile's range."""
SPARK_UNITS: Final[tuple[str, ...]] = ("minute", "hour", "day", "week", "month", "year")
WEEKDAYS: Final[tuple[str, ...]] = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")


# ------------------------------------------------------------------------------------------- legacy figures


def _clean_legacy(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    number = value.get("value")
    if isinstance(number, bool) or not isinstance(number, int | float):
        number = None
    since = value.get("since")
    return {
        "value": number,
        "label": str(value.get("label") or "")[:MAX_LABEL_CHARS],
        "since": int(since) if isinstance(since, int | float) and not isinstance(since, bool) else None,
        "source": str(value.get("source") or "")[:40],
    }


def legacy_baseline(conn: sqlite3.Connection) -> dict[str, dict[str, Any]]:
    """`{name: {value, label, since, source}}` for the `LEGACY_KEYS` rows that exist (empty without a v1 import)."""
    names = {key: name for name, key in LEGACY_KEYS.items()}
    marks = ", ".join("?" for _ in names)
    rows = conn.execute(
        f"SELECT key, value_json FROM legacy_totals WHERE key IN ({marks})",  # noqa: S608 (placeholders only)
        tuple(names),
    ).fetchall()
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        try:
            cleaned = _clean_legacy(json.loads(row[1]))
        except (TypeError, ValueError):
            cleaned = None
        if cleaned is not None:
            out[names[str(row[0])]] = cleaned
    return out


# --------------------------------------------------------------------------------------------- events


def _detail(text: Any) -> dict[str, Any]:
    try:
        value = json.loads(text) if text else {}
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def notable_events(
    conn: sqlite3.Connection,
    start_ms: int,
    end_ms: int,
    *,
    limit: int = 20,
    offset: int = 0,
    types: Iterable[str] = NOTABLE_EVENT_TYPES,
    severity: str | None = None,
) -> dict[str, Any]:
    """`{total, rows}`: events of `types` in `[start_ms, end_ms)`, newest first (`events_type_at` index)."""
    wanted = sorted(set(types) & NOTABLE_EVENT_TYPES)
    if not wanted:
        return {"total": 0, "rows": []}
    marks = ", ".join("?" for _ in wanted)
    where = f"type IN ({marks}) AND at_ms >= ? AND at_ms < ?"
    params: list[Any] = [*wanted, int(start_ms), int(end_ms)]
    if severity:
        where += " AND severity = ?"
        params.append(str(severity))
    total = int(conn.execute(f"SELECT count(*) FROM events WHERE {where}", params).fetchone()[0])  # noqa: S608
    rows = conn.execute(
        f"SELECT id, at_ms, type, severity, reason_code, endpoint_template, detail_json FROM events "  # noqa: S608
        f"WHERE {where} ORDER BY at_ms DESC, id DESC LIMIT ? OFFSET ?",
        (*params, max(1, min(int(limit), MAX_EVENTS_PAGE)), max(0, int(offset))),
    ).fetchall()
    return {
        "total": total,
        "rows": [
            {
                "id": int(r["id"]),
                "at_ms": int(r["at_ms"]),
                "type": str(r["type"]),
                "severity": str(r["severity"]),
                "reason": r["reason_code"],
                "endpoint_template": r["endpoint_template"],
                "detail": _detail(r["detail_json"]),
            }
            for r in rows
        ],
    }


# ------------------------------------------------------------------------------------------ two dimensions


def pair_counts(
    conn: sqlite3.Connection,
    window: Window,
    first: str,
    second: str,
    *,
    filters: Mapping[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Requests summed by two `dims` columns over the window: `[{first: a, second: b, "requests": n}]`, most first.

    Reads exactly the rollup pieces `queries.level_pieces` chooses for the window, so the totals agree with every
    chart of the same range.
    """
    for column in (first, second, *(filters or {})):
        if column not in queries.FILTER_COLUMNS:
            raise ValueError(f"unknown dimension {column!r}")
    if first == second:
        raise ValueError("choose two different dimensions")
    where = ""
    params: list[Any] = []
    for column, value in (filters or {}).items():
        where += f" AND d.{column} = ?"
        params.append(int(value) if column == "status" else str(value))
    totals: dict[tuple[Any, Any], int] = {}
    base = queries.BASE_LEVEL[window.granularity]
    for table, lo, hi in queries.level_pieces(conn, base, window.start, window.end):
        sql = (
            f"SELECT d.{first} AS a, d.{second} AS b, sum(r.requests) AS n FROM {table} r "  # noqa: S608 (checked names)
            f"JOIN dims d ON d.dim_hash = r.dim_hash WHERE r.bucket_start >= ? AND r.bucket_start < ?{where} "
            "GROUP BY a, b"
        )
        for row in conn.execute(sql, (lo, hi, *params)):
            key = (row["a"], row["b"])
            totals[key] = totals.get(key, 0) + int(row["n"] or 0)
    out = [{first: a, second: b, "requests": n} for (a, b), n in totals.items() if n]
    out.sort(key=lambda item: (-int(item["requests"]), str(item[first]), str(item[second])))
    return out


# ------------------------------------------------------------------------------------------------ live


def recent_live(
    conn: sqlite3.Connection, limit: int = 500, before_id: int | None = None
) -> list[tuple[int, dict[str, Any]]]:
    """`(event id, live row)` pairs of every worker's recent requests, newest written first (the last 15 minutes,
    row 81). Ordered by event id, so `before_id` (the smallest id of the previous page) pages without gaps."""
    bound = max(1, min(int(limit), MAX_LIVE_ROWS))
    upper = int(before_id) if before_id is not None else (1 << 62)
    rows = conn.execute(
        "SELECT id, detail_json FROM events WHERE type = ? AND id < ? ORDER BY id DESC LIMIT ?",
        (LIVE_EVENT, upper, bound),
    ).fetchall()
    return [(int(r["id"]), _detail(r["detail_json"])) for r in rows]


MAX_FILTER_VALUES: Final = 16
MAX_FILTER_TEXT: Final = 200
OUTCOME_VALUES: Final = frozenset(str(o) for o in Outcome)
REASON_VALUES: Final = frozenset(str(r) for r in ReasonCode)
EGRESS_VALUES: Final = frozenset(str(e) for e in Egress)
CACHE_VALUES: Final = frozenset(str(c) for c in CacheState)


@dataclass(frozen=True, slots=True)
class LiveQuery:
    """The Live view's filter (plan 14.1 Live: outcome, status, egress, cache state, client, endpoint, text).

    `base` is the `metrics.live.LiveFilter` for the exact fields (an `EventTail` subscription prefilters with it);
    the rest matches the way the dashboard's own filter does (static/js/live_tail.js): a status class such as
    `4xx`, and case-insensitive substrings of the client (address or place) and of the endpoint (template or
    path), so the server never drops a row the page would have shown.
    """

    base: LiveFilter = field(default_factory=LiveFilter)
    status_classes: frozenset[int] = frozenset()
    client: str = ""
    endpoint: str = ""

    def matches(self, row: Mapping[str, Any]) -> bool:
        entry = dict(row)
        if not self.base.matches(entry):
            return False
        if self.status_classes and int(entry.get("status") or 0) // 100 not in self.status_classes:
            return False
        if self.client and self.client not in f"{entry.get('ip') or ''} {entry.get('place') or ''}".lower():
            return False
        where = f"{entry.get('template') or ''} {entry.get('url') or ''}".lower()
        return not self.endpoint or self.endpoint in where

    def describe(self) -> dict[str, Any]:
        """The filter as plain values (echoed in answers)."""
        return {
            "outcome": sorted(self.base.outcomes),
            "reason": sorted(self.base.reasons),
            "status": sorted(self.base.statuses) + [f"{n}xx" for n in sorted(self.status_classes)],
            "egress": sorted(self.base.egress),
            "cache": sorted(self.base.cache),
            "client": self.client,
            "endpoint": self.endpoint,
            "q": self.base.text,
        }


def _values(name: str, raw: str | None, allowed: frozenset[str], problems: dict[str, str]) -> frozenset[str]:
    if not raw:
        return frozenset()
    items = [item.strip() for item in raw.split(",") if item.strip()]
    if len(items) > MAX_FILTER_VALUES:
        problems[name] = f"Give at most {MAX_FILTER_VALUES} values."
        return frozenset()
    unknown = [item for item in items if item not in allowed]
    if unknown:
        problems[name] = f"Unknown value {unknown[0][:40]!r}."
        return frozenset()
    return frozenset(items)


def parse_live_query(
    *,
    outcome: str | None = None,
    reason: str | None = None,
    status: str | None = None,
    egress: str | None = None,
    cache: str | None = None,
    client: str | None = None,
    endpoint: str | None = None,
    q: str | None = None,
) -> tuple[LiveQuery, dict[str, str]]:
    """A `LiveQuery` from request parameters (comma separated lists), and `{field: problem}` for bad ones."""
    problems: dict[str, str] = {}
    outcomes = _values("outcome", outcome, OUTCOME_VALUES, problems)
    reasons = _values("reason", reason, REASON_VALUES, problems)
    egresses = _values("egress", egress, EGRESS_VALUES, problems)
    caches = _values("cache", cache.upper() if cache and cache.lower() != "n/a" else cache, CACHE_VALUES, problems)
    codes: set[int] = set()
    classes: set[int] = set()
    if status:
        items = [item.strip().lower() for item in status.split(",") if item.strip()]
        for item in items[: MAX_FILTER_VALUES + 1]:
            if len(item) == 3 and item[0] in "12345" and item[1:] == "xx":
                classes.add(int(item[0]))
            elif item.isdigit() and 100 <= int(item) <= 599:
                codes.add(int(item))
            else:
                problems["status"] = "Give status codes (429) or classes (4xx), separated by commas."
        if len(items) > MAX_FILTER_VALUES:
            problems["status"] = f"Give at most {MAX_FILTER_VALUES} values."
    texts = {"client": client, "endpoint": endpoint, "q": q}
    for name, value in texts.items():
        if value and len(value) > MAX_FILTER_TEXT:
            problems[name] = f"At most {MAX_FILTER_TEXT} characters."
    base = LiveFilter(
        outcomes=outcomes,
        reasons=reasons,
        statuses=frozenset(codes),
        egress=egresses,
        cache=caches,
        text=(q or "").strip()[:MAX_FILTER_TEXT],
    )
    query = LiveQuery(
        base=base,
        status_classes=frozenset(classes),
        client=(client or "").strip().lower()[:MAX_FILTER_TEXT],
        endpoint=(endpoint or "").strip().lower()[:MAX_FILTER_TEXT],
    )
    return query, problems


_CROCKFORD: Final = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
ULID_SLACK_MS: Final = 180_000
"""A live row is written when the request ends; its id was made when it arrived. The request deadline (60 s at
most by the catalog's cross rule, plus a tarpit hold inside it) keeps the gap well under three minutes."""


def ulid_ms(request_id: str) -> int | None:
    """The millisecond timestamp in the first 10 characters of a ULID request id (`core/ids.py`), else None."""
    head = str(request_id)[:10].upper()
    if len(str(request_id)) != 26 or len(head) != 10:
        return None
    value = 0
    for char in head:
        digit = _CROCKFORD.find(char)
        if digit < 0:
            return None
        value = value * 32 + digit
    return value


def live_row(conn: sqlite3.Connection, request_id: str, *, since_ms: int, until_ms: int) -> dict[str, Any] | None:
    """The live row of one request id (any worker), or None once it aged out (15 minutes) or was never written.

    The search is bounded to `[since_ms, until_ms)` on the `(type, at_ms)` index, narrowed further to the
    request's own arrival time when the id is a ULID.
    """
    arrived = ulid_ms(request_id)
    if arrived is not None:
        since_ms = max(since_ms, arrived - 1000)
        until_ms = min(until_ms, arrived + ULID_SLACK_MS)
    rows = conn.execute(
        "SELECT detail_json FROM events WHERE type = ? AND at_ms >= ? AND at_ms < ? "
        "AND json_extract(detail_json, '$.request_id') = ? ORDER BY id DESC LIMIT 1",
        (LIVE_EVENT, int(since_ms), int(until_ms), str(request_id)),
    ).fetchall()
    return _detail(rows[0]["detail_json"]) if rows else None


# --------------------------------------------------------------------------------------------- callers


def endpoint_callers(
    conn: sqlite3.Connection, template: str, start_ms: int, end_ms: int, limit: int = 10
) -> dict[str, Any]:
    """Who calls one endpoint template in `[start_ms, end_ms)`, from `request_samples` (served and failed
    requests, at `request_sample_pct`): `{samples, places: [{place, requests}], clients: [{client_hash, requests}]}`.

    Clients are the keyed IP hashes the samples store, never raw addresses (plan 9.15).
    """
    bound = max(1, min(int(limit), MAX_CALLERS))
    params = (str(template), int(start_ms), int(end_ms))
    where = "endpoint_template = ? AND at_ms >= ? AND at_ms < ?"
    samples = int(conn.execute(f"SELECT count(*) FROM request_samples WHERE {where}", params).fetchone()[0])  # noqa: S608
    places = conn.execute(
        f"SELECT place, count(*) AS n FROM request_samples WHERE {where} AND place IS NOT NULL AND place != '' "  # noqa: S608
        "GROUP BY place ORDER BY n DESC, place LIMIT ?",
        (*params, bound),
    ).fetchall()
    clients = conn.execute(
        f"SELECT client_hash, count(*) AS n FROM request_samples WHERE {where} AND client_hash IS NOT NULL "  # noqa: S608
        "GROUP BY client_hash ORDER BY n DESC, client_hash LIMIT ?",
        (*params, bound),
    ).fetchall()
    return {
        "samples": samples,
        "places": [{"place": str(r["place"]), "requests": int(r["n"])} for r in places],
        "clients": [{"client_hash": str(r["client_hash"]), "requests": int(r["n"])} for r in clients],
    }


def endpoint_429s(
    conn: sqlite3.Connection, template: str, start_ms: int, end_ms: int, limit: int = 20
) -> dict[str, Any]:
    """Roblox 429s of one endpoint template in `[start_ms, end_ms)` from the `upstream_429` log (every attempt
    Roblox refused, whatever the caller got): `{total, by_egress, recent}` with the newest rows first."""
    params = (str(template), int(start_ms), int(end_ms))
    where = "endpoint_template = ? AND at_ms >= ? AND at_ms < ?"
    by_egress = {
        str(r[0]): int(r[1])
        for r in conn.execute(f"SELECT egress, count(*) FROM upstream_429 WHERE {where} GROUP BY egress", params)  # noqa: S608
    }
    rows = conn.execute(
        f"SELECT at_ms, egress, retry_after_s, ratelimit_headers_json, request_id FROM upstream_429 WHERE {where} "  # noqa: S608
        "ORDER BY at_ms DESC, id DESC LIMIT ?",
        (*params, max(1, min(int(limit), MAX_CALLERS))),
    ).fetchall()
    recent = []
    for r in rows:
        item = dict(r)
        item["ratelimit_headers"] = _detail(item.pop("ratelimit_headers_json"))
        recent.append(item)
    return {"total": sum(by_egress.values()), "by_egress": by_egress, "recent": recent}


def endpoint_recency(conn: sqlite3.Connection, window: Window, templates: Iterable[str]) -> dict[str, dict[str, Any]]:
    """v1 Top Endpoints' Methods, Last Request, Last Status and Last Caller for the given templates in `window`
    (plan 14.1 row 11, parity row 74, finding parity-13). At most `MAX_RECENCY_TEMPLATES` templates (one page).

    Per template: `methods` (`{method: requests}`, busiest first, the v1 `GET:3 POST:1` column), and the newest
    request in the window: `last_request_ms` with its `last_request_precision`. The rollups give the start of the
    newest bucket holding one (`minute` for the minute level, which always answers the tail of a window, else
    `hour`, `day` or `month`); when the newest Live row of the template (kept 15 minutes) lies in the window and in
    that bucket or later, it gives the exact time (`exact`) and the `last_status`, `last_caller` (the client
    address, as the Live view shows it) and `last_place` of that request, which the rollups do not keep (None).
    Reads the same rollup pieces as `queries.endpoint_table`, so the methods sum to the table's requests.
    """
    wanted = list(dict.fromkeys(str(t) for t in templates if t))[:MAX_RECENCY_TEMPLATES]
    if not wanted:
        return {}
    marks = ", ".join("?" for _ in wanted)
    methods: dict[str, dict[str, int]] = {}
    newest: dict[str, tuple[int, str]] = {}
    base = queries.BASE_LEVEL[window.granularity]
    for table, lo, hi in queries.level_pieces(conn, base, window.start, window.end):
        precision = queries.LEVEL_UNIT[table]
        rows = conn.execute(
            f"SELECT d.endpoint_template AS t, d.method AS m, sum(r.requests) AS n, max(r.bucket_start) AS last "  # noqa: S608
            f"FROM {table} r JOIN dims d ON d.dim_hash = r.dim_hash WHERE r.bucket_start >= ? AND r.bucket_start < ? "
            f"AND d.endpoint_template IN ({marks}) GROUP BY t, m",
            (lo, hi, *wanted),
        ).fetchall()
        for row in rows:
            template, count = str(row["t"]), int(row["n"] or 0)
            if count <= 0:
                continue
            per = methods.setdefault(template, {})
            per[str(row["m"])] = per.get(str(row["m"]), 0) + count
            last = int(row["last"])
            if template not in newest or last > newest[template][0]:
                newest[template] = (last, precision)
    live = conn.execute(
        f"SELECT endpoint_template AS t, max(id) AS id, at_ms, detail_json FROM events "  # noqa: S608 (placeholders)
        f"WHERE type = ? AND endpoint_template IN ({marks}) GROUP BY t",
        (LIVE_EVENT, *wanted),
    ).fetchall()
    latest = {str(row["t"]): (int(row["at_ms"]), _detail(row["detail_json"])) for row in live}
    out: dict[str, dict[str, Any]] = {}
    for template in wanted:
        if template not in methods:
            continue
        bucket, precision = newest[template]
        item: dict[str, Any] = {
            "methods": dict(sorted(methods[template].items(), key=lambda kv: (-kv[1], kv[0]))),
            "last_request_ms": bucket * 1000,
            "last_request_precision": precision,
            "last_status": None,
            "last_caller": None,
            "last_place": None,
        }
        found = latest.get(template)
        if found is not None and bucket * 1000 <= found[0] < window.end * 1000 and found[0] >= window.start * 1000:
            at_ms, detail = found
            item.update(
                last_request_ms=at_ms,
                last_request_precision="exact",
                last_status=detail.get("status"),
                last_caller=detail.get("ip") or None,
                last_place=detail.get("place") or None,
            )
        out[template] = item
    return out


# ---------------------------------------------------------------------------------------------- visits

VISIT_KEYS: Final[tuple[str, ...]] = (
    "human_visitors",
    "crawler_visitors",
    "unknown_visitors",
    "home_visits",
    "admin_visits",
    "robots_crawls",
    "sitemap_crawls",
)


def _visit_keys(page: Any, visitor: Any) -> list[str]:
    """The `VISIT_KEYS` one visit event adds to (the same rules as `queries.visitor_kpis`)."""
    if page == "home":
        keys = ["home_visits"]
        if visitor in ("human", "crawler", "unknown"):
            keys.append(f"{visitor}_visitors")
        return keys
    if page == "admin":
        return ["admin_visits"]
    if page == "robots":
        return ["robots_crawls"]
    if page == "sitemap":
        return ["sitemap_crawls"]
    return []


def visit_series(conn: sqlite3.Connection, window: Window) -> dict[str, Any]:
    """`{buckets, values: {key: [n per bucket]}}` for the Visitors card's sparklines (row 130)."""
    unit_ms = 60_000 if window.granularity == "minute" else 3_600_000
    rows = conn.execute(
        f"SELECT (at_ms / {unit_ms}) * {unit_ms // 1000} AS b, json_extract(detail_json, '$.page') AS page, "  # noqa: S608
        "json_extract(detail_json, '$.visitor') AS visitor, sum(coalesce(json_extract(detail_json, '$.count'), 1)) "
        "AS n FROM events WHERE type = 'visit' AND at_ms >= ? AND at_ms < ? GROUP BY b, page, visitor",
        (window.start * 1000, window.end * 1000),
    ).fetchall()
    starts = queries.bucket_starts(window)
    index = {start: i for i, start in enumerate(starts)}
    values = {key: [0] * len(starts) for key in VISIT_KEYS}
    zi = zone(window.tz)
    for row in rows:
        slot = index.get(bucket_floor(int(row["b"]), window.granularity, zi))
        if slot is None:
            continue
        for key in _visit_keys(row["page"], row["visitor"]):
            values[key][slot] += int(row["n"] or 0)
    values["admin_visits"] = [max(0, n) for n in values["admin_visits"]]  # discounts are negative (v1 clamp)
    return {"buckets": starts, "values": values}


# --------------------------------------------------------------------------------------- pure helpers


def sparkline_window(window: Window) -> Window:
    """The same range at the finest granularity with at most `SPARK_POINTS` buckets.

    Buckets are aligned to their unit, so a coarser unit can start the sparkline up to one bucket before the
    range (a 6 hour range at hour granularity starts on the hour). Answers name the sparkline's own range.
    """
    start = SPARK_UNITS.index(window.granularity) if window.granularity in SPARK_UNITS else 0
    for unit in SPARK_UNITS[start:]:
        candidate = queries.resolve_window(
            None, now=window.end, tz=window.tz, start=window.start, end=window.end, granularity=unit
        )
        try:
            if len(queries.bucket_starts(candidate)) <= SPARK_POINTS:
                return candidate
        except ValueError:
            continue
    return queries.resolve_window(
        None, now=window.end, tz=window.tz, start=window.start, end=window.end, granularity="year"
    )


def heatmap(buckets: Sequence[int], values: Sequence[Any], tz: str) -> dict[str, Any]:
    """Hour of day by weekday in `tz` from hourly bucket starts and their values (plan 14.1 Traffic, 14.5).

    `cells[d][h]` sums every bucket that began on weekday `d` (Monday is 0) at local hour `h`; `days[d]` counts how
    many such weekdays the range covered, so a reader can turn sums into averages honestly.
    """
    zi = zone(tz)
    cells = [[0] * 24 for _ in WEEKDAYS]
    seen_days: list[set[str]] = [set() for _ in WEEKDAYS]
    for start, value in zip(buckets, values, strict=False):
        local = datetime.fromtimestamp(int(start), zi)
        day = local.weekday()
        seen_days[day].add(local.date().isoformat())
        cells[day][local.hour] += int(value or 0)
    return {
        "tz": tz,
        "weekdays": list(WEEKDAYS),
        "hours": list(range(24)),
        "cells": cells,
        "days": [len(days) for days in seen_days],
        "max": max((max(row) for row in cells), default=0),
    }


def day_start(now: float, tz: str) -> int:
    """Local midnight of `now` in `tz` (the start of "today" for the rotator bytes tile)."""
    return bucket_floor(now, "day", zone(tz))


def next_bucket(start: int, unit: str, tz: str) -> int:
    """`rollups.bucket_next` with a zone name (for callers that build windows by hand)."""
    return bucket_next(start, unit, zone(tz))


__all__ = [
    "LEGACY_KEYS",
    "MAX_LIVE_ROWS",
    "MAX_RECENCY_TEMPLATES",
    "NOTABLE_EVENT_TYPES",
    "SPARK_POINTS",
    "VISIT_KEYS",
    "WEEKDAYS",
    "LiveQuery",
    "day_start",
    "endpoint_429s",
    "endpoint_callers",
    "endpoint_recency",
    "heatmap",
    "legacy_baseline",
    "live_row",
    "next_bucket",
    "notable_events",
    "pair_counts",
    "parse_live_query",
    "recent_live",
    "sparkline_window",
    "ulid_ms",
    "visit_series",
]
