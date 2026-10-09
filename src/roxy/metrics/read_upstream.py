"""Read models of metrics.db for the Upstream, Egress and Credential pages (plan 7.12, 8.5, 14.1).

What this is
    Plain functions over a metrics.db connection (run them inside `Database.read`) that answer what the admin API
    of those pages asks and `metrics/queries.py` or `metrics/read_history.py` do not answer yet:
      * `roblox_429_timeline`: Roblox 429s per bucket for the endpoints with the most 429s, plus the rest.
      * `live_row`, `request_429_rows`, `recent_429s_for`: what is known about one request id and the 429 that
        opened the cooldown it met (the "why did this request wait?" explainer, `upstream/read_trace.py`).
      * `recent_events`: newest-first `events` rows of some types (adaptive rate changes, credential probes).
      * `attempt_kind_totals`, `exit_status_counts`: upstream calls by attempt kind, and rotator exits by status.
      * `bucket_series`: one upstream bucket's attempts, rejections and fullest fill per chart bucket.
      * `endpoint_bytes`, `bytes_per_call_histogram`: wire bytes per endpoint and per call on one egress.
      * `rotator_daily_bytes`: metered bytes per UTC day of one egress (the Egress page bars and projection).
      * Two small writes of the tables these pages own the input of: `insert_provider_report` (the provider's
        byte figure for EGR-CALIBRATE, plan 8.4) and `insert_annotation` (a chart marker for an admin action).

Why it exists
    DESIGN.md section 13: read models live next to their data, and API modules stay thin. These answers are new
    shapes of existing tables (`upstream_429`, `events`, `bucket_minute`, `upstream_attempt_minute`, the rollups,
    `egress_usage`), so they sit beside the other metrics read models instead of inside an API module.

How it works
    Every query is bounded (P9): the chart ones group in SQL to at most one row per chart bucket and series, the
    tables carry a `LIMIT`, and the request lookups use the time an id was minted (a ULID starts with its
    millisecond timestamp) to read only the indexed time range around it. Times are Unix seconds unless a name
    ends in `_ms`. Numbers are honest (P6): a value the data cannot give is None, never a guessed zero, and the
    per-call byte histogram says it is built from per-minute averages.

What to read next
    `roxy/metrics/queries.py` (windows, rollup levels), `roxy/metrics/read_history.py` (the insight history
    tables), `roxy/upstream/read_trace.py` (the explainer that reads these rows).
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Final

from roxy.metrics import annotate, queries
from roxy.metrics.live import LIVE_EVENT
from roxy.metrics.queries import Window
from roxy.metrics.rollups import bucket_floor, zone

MAX_SERIES: Final = 20
"""Most endpoint series one 429 timeline carries (the rest are summed into `other`)."""

MAX_EVENTS: Final = 500
MAX_EXITS: Final = 100
MAX_ATTEMPT_GROUPS: Final = 200
MAX_REQUEST_429S: Final = 16

BYTES_EDGES: Final[tuple[int, ...]] = (
    1024,
    2048,
    4096,
    8192,
    16_384,
    32_768,
    65_536,
    131_072,
    262_144,
    524_288,
    1_048_576,
)
"""Upper bounds (exclusive) of the bytes-per-call histogram slots; the last slot is "1 MiB and more"."""

_CROCKFORD: Final = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_ULID_LENGTH: Final = 26


def ulid_time_ms(request_id: str) -> int | None:
    """The millisecond timestamp a request id (a ULID, `core/ids.py`) was minted at, or None for another shape."""
    text = request_id.strip().upper()
    if len(text) != _ULID_LENGTH or any(ch not in _CROCKFORD for ch in text):
        return None
    value = 0
    for ch in text[:10]:
        value = value * 32 + _CROCKFORD.index(ch)
    return value


def _unit_s(window: Window) -> int:
    """The SQL grouping unit for a window: minutes for minute charts, hours for everything coarser."""
    return 60 if window.granularity == "minute" else 3600


# ------------------------------------------------------------------------------------------------- 429s


def roblox_429_timeline(
    conn: sqlite3.Connection, window: Window, *, top: int = 10, egress: str | None = None
) -> dict[str, Any]:
    """Roblox 429s per chart bucket for the `top` endpoints with the most 429s in the window, plus `other`.

    Answers `{buckets, series: {template: [n, ...]}, other: [n, ...], all: [n, ...], totals: {template: n}, total}`
    (`all` is every 429 per bucket, the series and `other` together). Every 429
    Roblox sent is in `upstream_429` (plan 6.2), whatever the caller got, so `total` is exact; the per-bucket
    counts are grouped in SQL by minute (minute charts) or hour, then folded into the window's buckets.
    """
    top = max(1, min(int(top), MAX_SERIES))
    starts = queries.bucket_starts(window)
    index = {start: i for i, start in enumerate(starts)}
    zi = zone(window.tz)
    clauses = "at_ms >= ? AND at_ms < ?"
    params: list[Any] = [window.start * 1000, window.end * 1000]
    if egress:
        clauses += " AND egress = ?"
        params.append(str(egress))
    total = int(conn.execute(f"SELECT count(*) FROM upstream_429 WHERE {clauses}", params).fetchone()[0])  # noqa: S608 (fixed text)
    ranked = conn.execute(
        f"SELECT endpoint_template, count(*) AS n FROM upstream_429 WHERE {clauses} "  # noqa: S608 (fixed text)
        "GROUP BY endpoint_template ORDER BY n DESC, endpoint_template LIMIT ?",
        (*params, top),
    ).fetchall()
    totals = {str(row[0]): int(row[1]) for row in ranked}
    unit = _unit_s(window)
    time_expr = f"(at_ms / 1000) - ((at_ms / 1000) % {unit})"
    series: dict[str, list[int]] = {template: [0] * len(starts) for template in totals}
    every: list[int] = [0] * len(starts)
    if totals:
        marks = ", ".join("?" for _ in totals)
        rows = conn.execute(
            f"SELECT {time_expr} AS b, endpoint_template AS g, count(*) AS n FROM upstream_429 "  # noqa: S608 (fixed)
            f"WHERE {clauses} AND endpoint_template IN ({marks}) GROUP BY b, g",
            (*params, *totals),
        ).fetchall()
        for row in rows:
            slot = index.get(bucket_floor(int(row[0]), window.granularity, zi))
            if slot is not None:
                series[str(row[1])][slot] += int(row[2])
    for row in conn.execute(
        f"SELECT {time_expr} AS b, count(*) AS n FROM upstream_429 WHERE {clauses} GROUP BY b",  # noqa: S608 (fixed)
        params,
    ).fetchall():
        slot = index.get(bucket_floor(int(row[0]), window.granularity, zi))
        if slot is not None:
            every[slot] += int(row[1])
    other = [max(0, n - sum(values[i] for values in series.values())) for i, n in enumerate(every)]
    return {"buckets": starts, "series": series, "other": other, "all": every, "totals": totals, "total": total}


def _429_item(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    raw = item.pop("ratelimit_headers_json", None)
    try:
        item["ratelimit_headers"] = json.loads(raw) if raw else {}
    except ValueError:
        item["ratelimit_headers"] = {}
    return item


def request_429_rows(conn: sqlite3.Connection, request_id: str, start_ms: int, end_ms: int) -> list[dict[str, Any]]:
    """The Roblox 429s one request met (oldest first), searched in the indexed time range `[start_ms, end_ms)`."""
    rows = conn.execute(
        "SELECT at_ms, endpoint_template, host, egress, retry_after_s, ratelimit_headers_json, request_id "
        "FROM upstream_429 WHERE at_ms >= ? AND at_ms < ? AND request_id = ? ORDER BY at_ms LIMIT ?",
        (int(start_ms), int(end_ms), request_id, MAX_REQUEST_429S),
    ).fetchall()
    return [_429_item(row) for row in rows]


def recent_429s_for(
    conn: sqlite3.Connection, template: str, before_ms: int, lookback_ms: int, limit: int = 5
) -> list[dict[str, Any]]:
    """The newest 429s of one endpoint template in `[before_ms - lookback_ms, before_ms]`, newest first."""
    rows = conn.execute(
        "SELECT at_ms, endpoint_template, host, egress, retry_after_s, ratelimit_headers_json, request_id "
        "FROM upstream_429 WHERE endpoint_template = ? AND at_ms <= ? AND at_ms >= ? ORDER BY at_ms DESC LIMIT ?",
        (template, int(before_ms), int(before_ms) - max(0, int(lookback_ms)), max(1, min(int(limit), 50))),
    ).fetchall()
    return [_429_item(row) for row in rows]


# ------------------------------------------------------------------------------------------- one request


def live_row(conn: sqlite3.Connection, request_id: str, start_ms: int, end_ms: int) -> dict[str, Any] | None:
    """The Live row (`metrics/live.py live_entry`) of `request_id`, searched in `[start_ms, end_ms)`, or None.

    Live rows are kept 15 minutes (`LIVE_KEEP_S`) and sampled above 50 per second per worker, so None means
    "not recorded or no longer kept", never "the request did not happen".
    """
    row = conn.execute(
        "SELECT id, at_ms, detail_json FROM events WHERE type = ? AND at_ms >= ? AND at_ms < ? "
        "AND json_extract(detail_json, '$.request_id') = ? ORDER BY id DESC LIMIT 1",
        (LIVE_EVENT, int(start_ms), int(end_ms), request_id),
    ).fetchone()
    if row is None:
        return None
    try:
        detail = json.loads(row["detail_json"]) if row["detail_json"] else {}
    except ValueError:
        return None
    return detail if isinstance(detail, dict) else None


# ----------------------------------------------------------------------------------------------- events


def recent_events(
    conn: sqlite3.Connection,
    types: Iterable[str],
    start_ms: int,
    end_ms: int,
    *,
    reasons: Iterable[str] | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """`events` rows of `types` (and `reasons` when given) in `[start_ms, end_ms)`, NEWEST first, detail parsed.

    `read_history.events_between` answers oldest first (what the rules need); a table of recent changes needs the
    newest ones when there are more than its limit.
    """
    wanted = sorted({str(t) for t in types})
    if not wanted:
        return []
    clause = f"type IN ({', '.join('?' for _ in wanted)})"
    params: list[Any] = list(wanted)
    chosen = sorted({str(r) for r in reasons}) if reasons is not None else []
    if reasons is not None:
        if not chosen:
            return []
        clause += f" AND reason_code IN ({', '.join('?' for _ in chosen)})"
        params += chosen
    rows = conn.execute(
        f"SELECT id, at_ms, type, severity, reason_code, endpoint_template, detail_json FROM events "  # noqa: S608
        f"WHERE {clause} AND at_ms >= ? AND at_ms < ? ORDER BY at_ms DESC, id DESC LIMIT ?",
        (*params, int(start_ms), int(end_ms), max(1, min(int(limit), MAX_EVENTS))),
    ).fetchall()
    out: list[dict[str, Any]] = []
    for row in rows:
        try:
            detail = json.loads(row["detail_json"]) if row["detail_json"] else {}
        except ValueError:
            detail = {}
        item = {key: row[key] for key in ("id", "at_ms", "type", "severity", "reason_code", "endpoint_template")}
        item["detail"] = detail if isinstance(detail, dict) else {}
        item["count"] = int(item["detail"].get("count", 1) or 1)
        out.append(item)
    return out


# --------------------------------------------------------------------------------------------- attempts


def attempt_kind_totals(conn: sqlite3.Connection, start: int, end: int) -> list[dict[str, Any]]:
    """Upstream calls in `[start, end)` summed by attempt kind and egress (`upstream_attempt_minute`)."""
    rows = conn.execute(
        "SELECT kind, egress, sum(count) AS n FROM upstream_attempt_minute "
        "WHERE bucket_start >= ? AND bucket_start < ? GROUP BY kind, egress ORDER BY n DESC LIMIT ?",
        (int(start), int(end), MAX_ATTEMPT_GROUPS),
    ).fetchall()
    return [{"kind": str(r["kind"]), "egress": str(r["egress"]), "calls": int(r["n"] or 0)} for r in rows]


def exit_status_counts(conn: sqlite3.Connection, start: int, end: int, limit: int = 50) -> list[dict[str, Any]]:
    """Rotator calls per exit (a short hash of the session, never an IP) with 429s and failures, busiest first."""
    rows = conn.execute(
        "SELECT exit_id, sum(count) AS calls, sum(CASE WHEN status = 429 THEN count ELSE 0 END) AS n429, "
        "sum(CASE WHEN status >= 500 OR status < 0 THEN count ELSE 0 END) AS failures, "
        "min(bucket_start) AS first_seen, max(bucket_start) AS last_seen FROM upstream_attempt_minute "
        "WHERE egress = 'rotator' AND exit_id != '' AND bucket_start >= ? AND bucket_start < ? "
        "GROUP BY exit_id ORDER BY calls DESC LIMIT ?",
        (int(start), int(end), max(1, min(int(limit), MAX_EXITS))),
    ).fetchall()
    out = []
    for r in rows:
        calls = int(r["calls"] or 0)
        n429 = int(r["n429"] or 0)
        out.append(
            {
                "exit_id": str(r["exit_id"]),
                "calls": calls,
                "roblox_429": n429,
                "rate_429_pct": round(n429 * 100.0 / calls, 2) if calls else None,
                "failures": int(r["failures"] or 0),
                "first_seen": int(r["first_seen"]),
                "last_seen": int(r["last_seen"]),
            }
        )
    return out


# ---------------------------------------------------------------------------------------------- buckets


def bucket_series(conn: sqlite3.Connection, bucket_key: str, window: Window) -> dict[str, Any]:
    """One bucket's reservations (`attempts`), refusals (`rejections`) and fullest fill per chart bucket.

    From `bucket_minute`, grouped in SQL by minute or hour and folded into the window's buckets. The fill is the
    peak (a maximum, never an average), None for a bucket without data.
    """
    starts = queries.bucket_starts(window)
    index = {start: i for i, start in enumerate(starts)}
    zi = zone(window.tz)
    unit = _unit_s(window)
    attempts = [0] * len(starts)
    rejections = [0] * len(starts)
    peak: list[float | None] = [None] * len(starts)
    rows = conn.execute(
        f"SELECT bucket_start - (bucket_start % {unit}) AS b, sum(attempts) AS a, sum(rejections) AS r, "  # noqa: S608
        "max(fill_pct_peak) AS p FROM bucket_minute WHERE bucket_key = ? AND bucket_start >= ? AND bucket_start < ? "
        "GROUP BY b",
        (bucket_key, window.start, window.end),
    ).fetchall()
    for row in rows:
        slot = index.get(bucket_floor(int(row["b"]), window.granularity, zi))
        if slot is None:
            continue
        attempts[slot] += int(row["a"] or 0)
        rejections[slot] += int(row["r"] or 0)
        value = float(row["p"] or 0.0)
        current = peak[slot]
        peak[slot] = value if current is None else max(current, value)
    return {"buckets": starts, "attempts": attempts, "rejections": rejections, "fill_pct_peak": peak}


# ------------------------------------------------------------------------------------------------ bytes


def endpoint_bytes(conn: sqlite3.Connection, window: Window, egress: str) -> list[dict[str, Any]]:
    """Wire bytes and calls per endpoint template on one egress in the window, most bytes first.

    From the rollups (`upstream_bytes_in`, `upstream_bytes_out`: the metered wire bytes of each call, plan 8.3),
    so one row per template that used the egress (bounded by the templating vocabulary, about 2,000).
    """
    data = queries.collect(conn, window, filters={"egress": egress}, group_by="endpoint_template", bucketed=False)
    out: list[dict[str, Any]] = []
    for (_bucket, template), totals in data.items():
        values = totals.values
        calls = int(values["upstream_calls"]) + int(values["internal_calls"])
        size = int(values["upstream_bytes_in"]) + int(values["upstream_bytes_out"])
        if not calls and not size:
            continue
        out.append(
            {
                "template": str(template),
                "calls": calls,
                "bytes_in": int(values["upstream_bytes_in"]),
                "bytes_out": int(values["upstream_bytes_out"]),
                "bytes": size,
                "bytes_per_call": round(size / calls, 1) if calls else None,
            }
        )
    out.sort(key=lambda row: (-int(row["bytes"]), str(row["template"])))
    return out


def bytes_per_call_histogram(conn: sqlite3.Connection, window: Window, egress: str) -> dict[str, Any]:
    """How many calls fell in each bytes-per-call slot (`BYTES_EDGES`) on one egress in the window.

    Per-call sizes are not stored; each rollup row (one minute, or hour, of one endpoint and outcome) gives the
    average size of its calls, and the row's calls are counted in that average's slot. The answer says so
    (`basis`), so the chart is read as a distribution of averages, not of single calls (P6).
    """
    case = " ".join(f"WHEN per < {edge} THEN {i}" for i, edge in enumerate(BYTES_EDGES))
    slot_expr = f"CASE {case} ELSE {len(BYTES_EDGES)} END"
    counts = [0] * (len(BYTES_EDGES) + 1)
    base = queries.BASE_LEVEL[window.granularity]
    for table, lo, hi in queries.level_pieces(conn, base, window.start, window.end):
        rows = conn.execute(
            f"SELECT {slot_expr} AS slot, sum(calls) AS calls FROM ("  # noqa: S608 (fixed table names and edges)
            "SELECT r.upstream_calls AS calls, (r.upstream_bytes_in + r.upstream_bytes_out) * 1.0 / r.upstream_calls "
            f"AS per FROM {table} r JOIN dims d ON d.dim_hash = r.dim_hash "
            "WHERE r.bucket_start >= ? AND r.bucket_start < ? AND d.egress = ? AND r.upstream_calls > 0) GROUP BY slot",
            (lo, hi, egress),
        ).fetchall()
        for row in rows:
            counts[int(row["slot"])] += int(row["calls"] or 0)
    slots = []
    lower = 0
    for i, count in enumerate(counts):
        upper = BYTES_EDGES[i] if i < len(BYTES_EDGES) else None
        slots.append({"from_bytes": lower, "to_bytes": upper, "calls": count})
        lower = upper or lower
    return {
        "egress": egress,
        "slots": slots,
        "calls": sum(counts),
        "basis": "average bytes per call of each minute (or hour) and endpoint; single call sizes are not stored",
    }


def rotator_daily_bytes(conn: sqlite3.Connection, start: int, end: int, egress: str = "rotator") -> list[int]:
    """Metered wire bytes of one egress per UTC day in `[start, end)` (both at UTC midnight), from `egress_usage`."""
    window = Window(int(start), int(end), "day", "UTC")
    usage = queries.egress_usage_series(conn, window)
    found = usage["egress"].get(egress)
    if found is None:
        return [0] * len(usage["buckets"])
    return [int(value) for value in found["bytes"]]


# ------------------------------------------------------------------------------------------- the writes


def insert_provider_report(conn: sqlite3.Connection, at: int, reported_bytes: int, entered_by: str) -> int:
    """Store the provider's byte figure the admin typed in (EGR-CALIBRATE reads the newest); returns its id."""
    cursor = conn.execute(
        "INSERT INTO egress_provider_reports (at, reported_bytes, entered_by) VALUES (?, ?, ?)",
        (int(at), int(reported_bytes), entered_by[:80]),
    )
    return int(cursor.lastrowid or 0)


def delete_provider_report(conn: sqlite3.Connection, report_id: int) -> None:
    """Remove one provider report (the API takes back a figure whose audit row could not be written)."""
    conn.execute("DELETE FROM egress_provider_reports WHERE id = ?", (int(report_id),))


def insert_annotation(conn: sqlite3.Connection, at: int, kind: str, label: str, audit_id: int | None) -> int:
    """A chart marker linking to its audit row: `metrics/annotate.py insert_annotation`, the table's one writer
    (kept under this name for the Upstream area)."""
    return annotate.insert_annotation(conn, at, kind, label, audit_id)


def values_by_key(rows: Sequence[Mapping[str, Any]], key: str) -> dict[str, Mapping[str, Any]]:
    """Rows indexed by one of their fields (small helper for the API's joins of read models)."""
    return {str(row.get(key)): row for row in rows}


__all__ = [
    "BYTES_EDGES",
    "MAX_SERIES",
    "attempt_kind_totals",
    "bucket_series",
    "bytes_per_call_histogram",
    "delete_provider_report",
    "endpoint_bytes",
    "exit_status_counts",
    "insert_annotation",
    "insert_provider_report",
    "live_row",
    "recent_429s_for",
    "recent_events",
    "request_429_rows",
    "roblox_429_timeline",
    "rotator_daily_bytes",
    "ulid_time_ms",
    "values_by_key",
]
