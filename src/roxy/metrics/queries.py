"""Read models: the numbers the dashboard, the recommendations engine and the LLM export ask for.

What this is
    Functions that turn the rollup tables into answers: time windows and automatic granularity
    (`resolve_window`, `comparison_window`), time series for any range (`series`), KPI tiles with comparisons
    (`kpis`), top-N tables with server-side sorting and paging (`top_n`, `endpoint_table`, `client_table`),
    percentiles from histograms, and the smaller views the parity rows need: drops since a state began (row 114),
    refusal reasons with the custom versus default message split (116), retries by status and reason (117),
    visitor tiles (130), internal calls, recent Roblox 429s, egress usage, dimension counts and the LLM export
    summary (plan 12.3). Every function either takes a `Database` (async) or a connection (sync, to run inside
    `Database.read`).

Why it exists
    Plan 14.2 and 14.3: every metric can be asked "when?" for any range, from the last 15 minutes to all time,
    compared with the previous period, last week, last month or last year, filtered by any dimension, and paged
    on the server so a table of 2,000 endpoints never ships whole to the browser (row 89).

How it works
    - A window `[start, end)` is aligned to its granularity (minute up to 24 h, hour up to 30 days, day up to a
      year, month beyond; plan 14.2). Days, weeks, months and years are local to `ui_timezone`.
    - Reading combines levels. The base level is the coarsest table that fits the granularity (`rollup_day` for
      days and weeks, `rollup_month` for months and years). Each compacted level is complete up to its
      watermark (the end of its newest bucket); time after the watermark is read from the next finer level, down
      to `rollup_minute`, which is always current. So a 30 day chart reads hours plus the last few minutes, and
      nothing is counted twice.
    - One SQL statement per level computes every measure as a conditional sum over the joined `dims` row (for
      example `demand`, `refused`, `roxy_429`) plus the histogram sums; Python then re-buckets, derives ratios
      and percentiles. Filter and group columns are checked against a fixed list before they reach SQL.
    - Honest definitions (P6) live in `metrics/catalog.py`; this module implements them: `avoided` is demand
      minus upstream calls for caller traffic; `errors_hidden` counts stale serves after an upstream failure.

What to read next
    `roxy/metrics/catalog.py` (what each measure means), `roxy/metrics/rollups.py` (how the levels are built).
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any

from roxy.metrics import histograms
from roxy.metrics.histograms import register_sql_functions
from roxy.metrics.live import LIVE_EVENT
from roxy.metrics.rollups import HOUR_S, bucket_floor, bucket_next, zone
from roxy.storage.db import Database

GRANULARITIES: tuple[str, ...] = ("minute", "hour", "day", "week", "month", "year")
RANGES: dict[str, int] = {
    "live": 900,
    "1h": 3600,
    "6h": 6 * 3600,
    "24h": 86_400,
    "7d": 7 * 86_400,
    "30d": 30 * 86_400,
    "90d": 90 * 86_400,
    "1y": 365 * 86_400,
}
"""The global time picker ranges (plan 14.2). `all` and custom ranges are handled by `resolve_window`."""

COMPARISONS: tuple[str, ...] = ("previous", "week", "month", "year")
PAGE_SIZES: tuple[int, ...] = (10, 25, 50, 100, 250)
MAX_POINTS = 5000
"""Most buckets one series may have; a finer request is refused (choose a coarser granularity)."""

FILTER_COLUMNS: tuple[str, ...] = (
    "endpoint_template",
    "host",
    "method",
    "egress",
    "outcome",
    "reason_code",
    "status",
    "source",
    "cache_state",
    "auth_class",
)
"""`dims` columns that may be filtered or grouped on. Nothing else reaches the SQL text."""

STATUS_CLASSES = {"1xx": (100, 199), "2xx": (200, 299), "3xx": (300, 399), "4xx": (400, 499), "5xx": (500, 599)}

# Conditional sums computed for every bucket and group. Names are fixed; the SQL is a module constant.
MEASURES: tuple[tuple[str, str], ...] = (
    ("requests", "sum(r.requests)"),
    (
        "demand",
        "sum(CASE WHEN d.outcome != 'refused' AND d.reason_code != 'options_local' AND d.source != 'internal' "
        "THEN r.requests ELSE 0 END)",
    ),
    ("served_upstream", "sum(CASE WHEN d.outcome = 'served_upstream' THEN r.requests ELSE 0 END)"),
    ("served_cache", "sum(CASE WHEN d.outcome = 'served_cache' THEN r.requests ELSE 0 END)"),
    ("refused", "sum(CASE WHEN d.outcome = 'refused' THEN r.requests ELSE 0 END)"),
    ("failed", "sum(CASE WHEN d.outcome = 'failed' THEN r.requests ELSE 0 END)"),
    ("upstream_calls", "sum(CASE WHEN d.source != 'internal' THEN r.upstream_calls ELSE 0 END)"),
    ("internal_calls", "sum(CASE WHEN d.source = 'internal' THEN r.upstream_calls ELSE 0 END)"),
    ("errors", "sum(CASE WHEN d.source != 'internal' THEN r.errors ELSE 0 END)"),
    ("errors_hidden", "sum(CASE WHEN d.reason_code = 'cache_stale_error' THEN r.requests ELSE 0 END)"),
    ("status_2xx", "sum(CASE WHEN d.status BETWEEN 200 AND 299 THEN r.requests ELSE 0 END)"),
    ("status_4xx", "sum(CASE WHEN d.status BETWEEN 400 AND 499 THEN r.requests ELSE 0 END)"),
    ("status_5xx", "sum(CASE WHEN d.status BETWEEN 500 AND 599 THEN r.requests ELSE 0 END)"),
    ("roxy_429", "sum(CASE WHEN d.status = 429 AND d.source = 'roxy' THEN r.requests ELSE 0 END)"),
    (
        "roblox_5xx",
        "sum(CASE WHEN d.status BETWEEN 500 AND 599 AND d.source IN ('roblox', 'relay') THEN r.requests ELSE 0 END)",
    ),
    ("timeouts", "sum(CASE WHEN d.reason_code = 'upstream_timeout' THEN r.requests ELSE 0 END)"),
    ("paused", "sum(CASE WHEN d.reason_code = 'paused' THEN r.requests ELSE 0 END)"),
    ("throttle_all", "sum(CASE WHEN d.reason_code = 'throttle_all' THEN r.requests ELSE 0 END)"),
    ("cache_hit", "sum(CASE WHEN d.cache_state = 'HIT' THEN r.requests ELSE 0 END)"),
    ("cache_stale", "sum(CASE WHEN d.cache_state = 'STALE' THEN r.requests ELSE 0 END)"),
    ("cache_revalidating", "sum(CASE WHEN d.cache_state = 'REVALIDATING' THEN r.requests ELSE 0 END)"),
    ("cache_coalesced", "sum(CASE WHEN d.cache_state = 'COALESCED' THEN r.requests ELSE 0 END)"),
    ("cache_miss", "sum(CASE WHEN d.cache_state = 'MISS' THEN r.requests ELSE 0 END)"),
    ("caller_bytes_in", "sum(r.caller_bytes_in)"),
    ("caller_bytes_out", "sum(r.caller_bytes_out)"),
    ("cache_bytes_out", "sum(CASE WHEN d.outcome = 'served_cache' THEN r.caller_bytes_out ELSE 0 END)"),
    ("upstream_bytes_in", "sum(r.upstream_bytes_in)"),
    ("upstream_bytes_out", "sum(r.upstream_bytes_out)"),
)
MEASURE_NAMES: tuple[str, ...] = tuple(name for name, _ in MEASURES)
HIST_MEASURES: tuple[tuple[str, str], ...] = (
    ("latency_hist", "roxy_hist_sum(CASE WHEN d.source != 'internal' THEN r.latency_hist END)"),
    ("queue_wait_hist", "roxy_hist_sum(CASE WHEN d.source != 'internal' THEN r.queue_wait_hist END)"),
)

LEVEL_ORDER: tuple[str, ...] = ("rollup_month", "rollup_day", "rollup_hour", "rollup_minute")
BASE_LEVEL = {
    "minute": "rollup_minute",
    "hour": "rollup_hour",
    "day": "rollup_day",
    "week": "rollup_day",
    "month": "rollup_month",
    "year": "rollup_month",
}
LEVEL_UNIT = {"rollup_month": "month", "rollup_day": "day", "rollup_hour": "hour", "rollup_minute": "minute"}

SORTABLE: tuple[str, ...] = (
    *MEASURE_NAMES,
    "avoided",
    "avoided_pct",
    "hit_ratio",
    "p50_ms",
    "p95_ms",
    "p99_ms",
    "roblox_429",
    "key",
)


# --------------------------------------------------------------------------------------------- windows


@dataclass(frozen=True, slots=True)
class Window:
    """A half-open time range `[start, end)` aligned to `granularity`, with the zone used for local buckets."""

    start: int
    end: int
    granularity: str
    tz: str = "UTC"

    @property
    def span(self) -> int:
        return self.end - self.start


def auto_granularity(span_s: float) -> str:
    """Plan 14.2: minute up to 24 h, hour up to 30 days, day up to a year, month beyond."""
    if span_s <= 86_400:
        return "minute"
    if span_s <= 30 * 86_400:
        return "hour"
    if span_s <= 366 * 86_400:
        return "day"
    return "month"


def resolve_window(
    range_key: str | None,
    *,
    now: float,
    tz: str = "UTC",
    start: float | None = None,
    end: float | None = None,
    granularity: str | None = None,
    earliest: float | None = None,
) -> Window:
    """A window for a picker range (`1h`, `24h`, `7d`, ..., `all`) or a custom `start`/`end`.

    The end includes the current (open) bucket; the start is floored to the granularity. `all` starts at
    `earliest` (the oldest data, see `earliest_data`).
    """
    if start is not None and end is not None:
        lo, hi = float(start), float(end)
    elif range_key == "all":
        lo, hi = float(earliest if earliest is not None else now - 86_400), float(now)
    else:
        span = RANGES.get(range_key or "24h")
        if span is None:
            raise ValueError(f"unknown range {range_key!r}")
        lo, hi = now - span, now
    if hi <= lo:
        raise ValueError("the window end must be after its start")
    unit = granularity or auto_granularity(hi - lo)
    if unit not in GRANULARITIES:
        raise ValueError(f"unknown granularity {unit!r}")
    zi = zone(tz)
    aligned_start = bucket_floor(lo, unit, zi)
    floor_end = bucket_floor(hi, unit, zi)
    # The end is exclusive: a window ending inside a bucket includes that whole (still open) bucket.
    aligned_end = floor_end if floor_end == hi else bucket_next(floor_end, unit, zi)
    return Window(aligned_start, aligned_end, unit, tz)


def _shift_months(ts: int, months: int, tz: str) -> int:
    zi = zone(tz)
    local = datetime.fromtimestamp(ts, zi)
    month_index = local.month - 1 + months
    year = local.year + month_index // 12
    month = month_index % 12 + 1
    day = min(local.day, 28)  # every month has day 28; keeps the shift defined for the 29th to 31st
    shifted = local.replace(year=year, month=month, day=day)
    return int(shifted.timestamp())


def comparison_window(window: Window, mode: str) -> Window:
    """The window to compare with: previous period, same period last week, last month or last year."""
    if mode == "previous":
        return replace(window, start=window.start - window.span, end=window.start)
    if mode == "week":
        return replace(window, start=window.start - 7 * 86_400, end=window.end - 7 * 86_400)
    if mode == "month":
        return replace(
            window, start=_shift_months(window.start, -1, window.tz), end=_shift_months(window.end, -1, window.tz)
        )
    if mode == "year":
        return replace(
            window, start=_shift_months(window.start, -12, window.tz), end=_shift_months(window.end, -12, window.tz)
        )
    raise ValueError(f"unknown comparison {mode!r}")


def bucket_starts(window: Window) -> list[int]:
    """Every bucket start of the window (bounded by `MAX_POINTS`)."""
    zi = zone(window.tz)
    out: list[int] = []
    t = window.start
    while t < window.end:
        out.append(t)
        if len(out) > MAX_POINTS:
            raise ValueError("too many points for this range; choose a coarser granularity")
        t = bucket_next(t, window.granularity, zi)
    return out


# ------------------------------------------------------------------------------------------ level union


def _filter_sql(filters: Mapping[str, Any] | None) -> tuple[str, list[Any]]:
    if not filters:
        return "", []
    clauses: list[str] = []
    params: list[Any] = []
    for key, value in filters.items():
        if value is None or value == "" or value == []:
            continue
        if key == "status_class":
            classes = [value] if isinstance(value, str) else list(value)
            parts = []
            for name in classes:
                if name not in STATUS_CLASSES:
                    raise ValueError(f"unknown status class {name!r}")
                lo, hi = STATUS_CLASSES[name]
                parts.append("d.status BETWEEN ? AND ?")
                params += [lo, hi]
            clauses.append("(" + " OR ".join(parts) + ")")
            continue
        if key not in FILTER_COLUMNS:
            raise ValueError(f"unknown filter {key!r}")
        values = list(value) if isinstance(value, list | tuple | set | frozenset) else [value]
        clauses.append(f"d.{key} IN ({', '.join('?' for _ in values)})")
        params += [int(v) if key == "status" else str(v) for v in values]
    return (" AND " + " AND ".join(clauses)) if clauses else "", params


def _watermark_end(conn: sqlite3.Connection, table: str) -> int | None:
    """End of the newest compacted bucket of a level (None when the level is empty)."""
    if table == "rollup_minute":
        return None
    tz_col = ", tz" if table in ("rollup_day", "rollup_month") else ""
    row = conn.execute(f"SELECT bucket_start{tz_col} FROM {table} ORDER BY bucket_start DESC LIMIT 1").fetchone()  # noqa: S608 (LEVEL_ORDER)
    if row is None:
        return None
    unit = LEVEL_UNIT[table]
    return bucket_next(int(row[0]), unit, zone(row[1]) if tz_col else None)


def level_pieces(conn: sqlite3.Connection, base: str, start: int, end: int) -> list[tuple[str, int, int]]:
    """Which table answers which part of `[start, end)`: the base level up to its watermark, then finer levels."""
    pieces: list[tuple[str, int, int]] = []
    cursor = start
    for table in LEVEL_ORDER[LEVEL_ORDER.index(base) :]:
        if cursor >= end:
            break
        if table == "rollup_minute":
            pieces.append((table, cursor, end))
            cursor = end
            break
        if table == "rollup_hour" and cursor % HOUR_S:
            # A half-hour zone's day boundary: the partial hour comes from minutes.
            edge = min(end, cursor - cursor % HOUR_S + HOUR_S)
            pieces.append(("rollup_minute", cursor, edge))
            cursor = edge
        mark = _watermark_end(conn, table)
        hi = min(end, mark) if mark is not None else cursor
        if hi > cursor:
            pieces.append((table, cursor, hi))
            cursor = hi
    return pieces


def _measure_rows(
    conn: sqlite3.Connection,
    table: str,
    start: int,
    end: int,
    *,
    filters: Mapping[str, Any] | None,
    group_by: str | None,
    time_unit: str | None,
) -> list[sqlite3.Row]:
    if group_by is not None and group_by not in FILTER_COLUMNS:
        raise ValueError(f"unknown group {group_by!r}")
    where, params = _filter_sql(filters)
    if time_unit is None:
        time_expr = "NULL"
    elif time_unit == "hour" and table == "rollup_minute":
        time_expr = "r.bucket_start - r.bucket_start % 3600"
    else:
        time_expr = "r.bucket_start"  # re-bucketed to local days and longer in Python
    group_expr = f"d.{group_by}" if group_by else "NULL"
    measures = ", ".join(f"{sql} AS {name}" for name, sql in (*MEASURES, *HIST_MEASURES))
    sql = (
        f"SELECT {time_expr} AS b, {group_expr} AS g, {measures} "  # noqa: S608 (identifiers are fixed constants)
        f"FROM {table} r JOIN dims d ON d.dim_hash = r.dim_hash "
        f"WHERE r.bucket_start >= ? AND r.bucket_start < ?{where} GROUP BY b, g"
    )
    return conn.execute(sql, (start, end, *params)).fetchall()


@dataclass(slots=True)
class Totals:
    """Summed measures for one bucket and group, plus the two histograms."""

    values: dict[str, int]
    latency: list[int]
    queue_wait: list[int]

    @classmethod
    def zero(cls) -> Totals:
        return cls(dict.fromkeys(MEASURE_NAMES, 0), histograms.empty(), histograms.empty())

    def add_row(self, row: sqlite3.Row) -> None:
        for name in MEASURE_NAMES:
            self.values[name] += int(row[name] or 0)
        if row["latency_hist"]:
            histograms.add_into(self.latency, histograms.decode(row["latency_hist"]))
        if row["queue_wait_hist"]:
            histograms.add_into(self.queue_wait, histograms.decode(row["queue_wait_hist"]))

    def add(self, other: Totals) -> None:
        for name in MEASURE_NAMES:
            self.values[name] += other.values[name]
        histograms.add_into(self.latency, other.latency)
        histograms.add_into(self.queue_wait, other.queue_wait)

    def derived(self, roblox_429: int | None = None) -> dict[str, Any]:
        """Every measure plus the derived ones (P6 definitions in metrics/catalog.py)."""
        v = dict(self.values)
        demand = v["demand"]
        avoided = demand - v["upstream_calls"]
        cache_served = v["cache_hit"] + v["cache_stale"] + v["cache_revalidating"] + v["cache_coalesced"]
        lookups = cache_served + v["cache_miss"]
        lat = histograms.percentiles(self.latency)
        out: dict[str, Any] = {
            **v,
            "avoided": avoided,
            "avoided_pct": round(avoided * 100.0 / demand, 2) if demand else None,
            "hit_ratio": round(cache_served / lookups, 4) if lookups else None,
            "p50_ms": lat["p50"],
            "p95_ms": lat["p95"],
            "p99_ms": lat["p99"],
            "p99_overflow": histograms.is_overflow(self.latency, 0.99),
            "queue_wait_p95_ms": histograms.percentile(self.queue_wait, 0.95),
        }
        # None means "the 429 log cannot answer this slice" (for example a group by outcome), never zero.
        out["roblox_429"] = roblox_429
        out["roblox_429_per_10k"] = (
            round(roblox_429 * 10_000.0 / demand, 2) if roblox_429 is not None and demand else None
        )
        return out


def collect(
    conn: sqlite3.Connection,
    window: Window,
    *,
    filters: Mapping[str, Any] | None = None,
    group_by: str | None = None,
    bucketed: bool = True,
) -> dict[tuple[int | None, Any], Totals]:
    """`{(bucket start or None, group value or None): Totals}` for the window, reading every level once."""
    register_sql_functions(conn)
    zi = zone(window.tz)
    base = BASE_LEVEL[window.granularity]
    out: dict[tuple[int | None, Any], Totals] = {}
    for table, lo, hi in level_pieces(conn, base, window.start, window.end):
        unit = None
        if bucketed:
            unit = "hour" if window.granularity == "hour" else LEVEL_UNIT[table]
        for row in _measure_rows(conn, table, lo, hi, filters=filters, group_by=group_by, time_unit=unit):
            bucket = bucket_floor(int(row["b"]), window.granularity, zi) if bucketed and row["b"] is not None else None
            key = (bucket, row["g"])
            totals = out.get(key)
            if totals is None:
                totals = out[key] = Totals.zero()
            totals.add_row(row)
    return out


def _count_429(
    conn: sqlite3.Connection, window: Window, *, group_col: str | None = None, bucketed: bool = True,
    filters: Mapping[str, Any] | None = None,
) -> dict[tuple[int | None, Any], int] | None:  # fmt: skip
    """Roblox 429s from `upstream_429` (every one, whatever the caller got), bucketed like `collect`.

    None when the grouping or a filter is something the 429 log does not record (for example `outcome`): then
    there is no honest count, and callers show the 429 column as unknown instead of zero.
    """
    allowed = {"endpoint_template", "host", "egress"}
    if group_col is not None and group_col not in allowed:
        return None
    clauses = ["at_ms >= ?", "at_ms < ?"]
    params: list[Any] = [window.start * 1000, window.end * 1000]
    for key, value in (filters or {}).items():
        if key in allowed and value not in (None, "", []):
            values = list(value) if isinstance(value, list | tuple | set | frozenset) else [value]
            clauses.append(f"{key} IN ({', '.join('?' for _ in values)})")
            params += [str(v) for v in values]
        elif key not in allowed and value not in (None, "", []):
            return None
    unit_s = 60 if window.granularity == "minute" else HOUR_S
    time_expr = f"(at_ms / 1000) - ((at_ms / 1000) % {unit_s})" if bucketed else "NULL"
    group_expr = group_col or "NULL"
    rows = conn.execute(
        f"SELECT {time_expr} AS b, {group_expr} AS g, count(*) AS n FROM upstream_429 "  # noqa: S608 (fixed names)
        f"WHERE {' AND '.join(clauses)} GROUP BY b, g",
        params,
    ).fetchall()
    zi = zone(window.tz)
    out: dict[tuple[int | None, Any], int] = {}
    for row in rows:
        bucket = bucket_floor(int(row["b"]), window.granularity, zi) if bucketed else None
        slot = (bucket, row["g"])
        out[slot] = out.get(slot, 0) + int(row["n"])
    return out


# ---------------------------------------------------------------------------------------------- series


def series_sync(
    conn: sqlite3.Connection,
    window: Window,
    *,
    metrics: Sequence[str] | None = None,
    filters: Mapping[str, Any] | None = None,
    group_by: str | None = None,
    max_groups: int = 10,
) -> dict[str, Any]:
    """A chart: one value list per metric per group, one value per bucket (zeros for empty buckets)."""
    starts = bucket_starts(window)
    data = collect(conn, window, filters=filters, group_by=group_by)
    found_429 = _count_429(conn, window, group_col=group_by, filters=filters)
    counts_429 = found_429 or {}
    groups: dict[Any, dict[int, Totals]] = {}
    for (bucket, group), totals in data.items():
        groups.setdefault(group, {})[int(bucket or 0)] = totals
    for (bucket, group), _n in counts_429.items():
        groups.setdefault(group, {}).setdefault(int(bucket or 0), Totals.zero())
    ranked = sorted(groups, key=lambda g: -sum(t.values["requests"] for t in groups[g].values()))
    shown, rest = ranked[:max_groups], ranked[max_groups:]
    wanted = list(metrics) if metrics else ["requests"]
    out_groups: dict[str, dict[str, list[Any]]] = {}

    def build(name: str, members: list[Any]) -> None:
        values: dict[str, list[Any]] = {m: [] for m in wanted}
        for start in starts:
            totals = Totals.zero()
            n429 = 0
            for member in members:
                found = groups.get(member, {}).get(start)
                if found is not None:
                    totals.add(found)
                n429 += counts_429.get((start, member), 0)
            derived = totals.derived(roblox_429=n429 if found_429 is not None else None)
            for metric in wanted:
                values[metric].append(derived.get(metric))
        out_groups[name] = values

    for group in shown:
        build("all" if group is None else str(group), [group])
    if rest:
        build("other groups", rest)
    if not out_groups:
        build("all", [None])
    return {
        "granularity": window.granularity,
        "start": window.start,
        "end": window.end,
        "tz": window.tz,
        "buckets": starts,
        "metrics": wanted,
        "groups": out_groups,
    }


async def series(db: Database, window: Window, **kwargs: Any) -> dict[str, Any]:
    """`series_sync` on a reader thread (one consistent snapshot)."""
    return await db.read(lambda conn: series_sync(conn, window, **kwargs))


# ------------------------------------------------------------------------------------------------ totals


def totals_sync(
    conn: sqlite3.Connection, window: Window, *, filters: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """All measures summed over the window (one KPI value per measure)."""
    data = collect(conn, window, filters=filters, bucketed=False)
    totals = Totals.zero()
    for item in data.values():
        totals.add(item)
    found_429 = _count_429(conn, window, bucketed=False, filters=filters)
    out = totals.derived(roblox_429=sum(found_429.values()) if found_429 is not None else None)
    out["rotator_bytes"] = egress_bytes(conn, window).get("rotator", 0)
    return out


def _delta(current: Any, previous: Any) -> dict[str, Any]:
    if not isinstance(current, int | float) or not isinstance(previous, int | float):
        return {"previous": previous, "delta": None, "delta_pct": None}
    delta = current - previous
    pct = round(delta * 100.0 / previous, 2) if previous else None
    return {"previous": previous, "delta": round(delta, 4), "delta_pct": pct}


KPI_KEYS: tuple[str, ...] = (
    "requests",
    "demand",
    "avoided",
    "avoided_pct",
    "upstream_calls",
    "internal_calls",
    "roblox_429",
    "roblox_429_per_10k",
    "roxy_429",
    "status_5xx",
    "roblox_5xx",
    "status_2xx",
    "status_4xx",
    "served_cache",
    "errors_hidden",
    "timeouts",
    "p95_ms",
    "rotator_bytes",
)


def kpis_sync(conn: sqlite3.Connection, window: Window, *, now: float, compare: str | None = None) -> dict[str, Any]:
    """KPI tiles (plan 14.1 Overview) with an optional comparison and reset notices (plan 6.8)."""
    current = totals_sync(conn, window)
    last_hour = Window(int(now) - 3600, int(now) + 1, "minute", window.tz)
    tiles: dict[str, Any] = {key: {"value": current.get(key)} for key in KPI_KEYS}
    tiles["requests_last_hour"] = {"value": totals_sync(conn, last_hour)["requests"]}
    notices = reset_annotations(conn, window.start, window.end)
    result: dict[str, Any] = {"window": _window_dict(window), "tiles": tiles, "notices": notices}
    if compare:
        other = comparison_window(window, compare)
        previous = totals_sync(conn, other)
        for key in KPI_KEYS:
            tiles[key].update(_delta(current.get(key), previous.get(key)))
        result["compare"] = {"mode": compare, "window": _window_dict(other)}
        result["notices"] = notices + reset_annotations(conn, other.start, other.end)
    return result


async def kpis(db: Database, window: Window, *, now: float, compare: str | None = None) -> dict[str, Any]:
    return await db.read(lambda conn: kpis_sync(conn, window, now=now, compare=compare))


def _window_dict(window: Window) -> dict[str, Any]:
    return {"start": window.start, "end": window.end, "granularity": window.granularity, "tz": window.tz}


def reset_annotations(conn: sqlite3.Connection, start: int, end: int) -> list[dict[str, Any]]:
    """Reset markers inside `[start, end)`: a KPI over such a window covers partial data (plan 6.8)."""
    rows = conn.execute(
        "SELECT id, at, label, audit_id FROM annotations WHERE kind = 'reset' AND at >= ? AND at < ? ORDER BY at",
        (start, end),
    ).fetchall()
    return [{"id": r["id"], "at": r["at"], "label": r["label"], "audit_id": r["audit_id"]} for r in rows]


def chart_annotations(conn: sqlite3.Connection, start: int, end: int, limit: int = 500) -> list[dict[str, Any]]:
    """Every chart marker in the window (config changes, resets, deploys, incidents)."""
    rows = conn.execute(
        "SELECT id, at, kind, label, audit_id FROM annotations WHERE at >= ? AND at < ? ORDER BY at LIMIT ?",
        (start, end, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def drops_since(conn: sqlite3.Connection, reason: str, since_s: float, now: float) -> int:
    """Requests refused with `reason` (`paused` or `throttle_all`) since the state began (row 114 banner)."""
    # Hour granularity: whole compacted hours plus minute rows at both edges (level_pieces handles the edges).
    window = Window(int(since_s) - int(since_s) % 60, int(now) + 60, "hour")
    data = collect(conn, window, filters={"reason_code": reason}, bucketed=False)
    return sum(t.values["requests"] for t in data.values())


# ----------------------------------------------------------------------------------------------- top N


@dataclass(frozen=True, slots=True)
class Page:
    """Server-side paging and sorting (row 89): 1-based page, a size from PAGE_SIZES, a SORTABLE key."""

    page: int = 1
    size: int = 25
    sort: str = "requests"
    descending: bool = True
    search: str = ""

    def checked(self) -> Page:
        if self.size not in PAGE_SIZES:
            raise ValueError(f"page size must be one of {PAGE_SIZES}")
        if self.sort not in SORTABLE:
            raise ValueError(f"cannot sort by {self.sort!r}")
        return replace(self, page=max(1, int(self.page)), search=self.search[:200])


def _sort_value(row: dict[str, Any], key: str) -> Any:
    value = row.get(key)
    if value is None:
        return (1, 0)  # missing values sort last whatever the direction
    return (0, value)


def _paged(rows: list[dict[str, Any]], page: Page) -> dict[str, Any]:
    present = [r for r in rows if r.get(page.sort) is not None]
    missing = [r for r in rows if r.get(page.sort) is None]
    present.sort(key=lambda r: (r[page.sort], str(r.get("key"))), reverse=page.descending)
    ordered = present + missing
    first = (page.page - 1) * page.size
    return {
        "total": len(ordered),
        "page": page.page,
        "size": page.size,
        "sort": page.sort,
        "descending": page.descending,
        "rows": ordered[first : first + page.size],
    }


def top_n_sync(
    conn: sqlite3.Connection,
    window: Window,
    dimension: str,
    *,
    page: Page | None = None,
    filters: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """One row per value of `dimension` with every measure, sorted and paged on the server."""
    page = (page or Page()).checked()
    data = collect(conn, window, filters=filters, group_by=dimension, bucketed=False)
    found_429 = _count_429(conn, window, group_col=dimension, bucketed=False, filters=filters)
    counts_429 = found_429 or {}
    rows: list[dict[str, Any]] = []
    keys = {group for (_b, group) in data} | {group for (_b, group) in counts_429}
    for key in keys:
        totals = data.get((None, key), Totals.zero())
        row = totals.derived(roblox_429=counts_429.get((None, key), 0) if found_429 is not None else None)
        row["key"] = key
        if page.search and page.search.lower() not in str(key).lower():
            continue
        rows.append(row)
    return _paged(rows, page)


async def top_n(db: Database, window: Window, dimension: str, **kwargs: Any) -> dict[str, Any]:
    return await db.read(lambda conn: top_n_sync(conn, window, dimension, **kwargs))


def endpoint_table_sync(conn: sqlite3.Connection, window: Window, *, page: Page | None = None,
                        filters: Mapping[str, Any] | None = None) -> dict[str, Any]:  # fmt: skip
    """The Endpoints page table: per template volume, upstream calls, hit ratio, 429s, latency (plan 14.1)."""
    return top_n_sync(conn, window, "endpoint_template", page=page, filters=filters)


async def endpoint_table(db: Database, window: Window, **kwargs: Any) -> dict[str, Any]:
    return await db.read(lambda conn: endpoint_table_sync(conn, window, **kwargs))


def top_values(conn: sqlite3.Connection, column: str, since_s: float, until_s: float, limit: int) -> list[str]:
    """The busiest values of one dimension in a time range (vocabulary refresh, plan 6.2)."""
    window = Window(int(since_s) - int(since_s) % HOUR_S, int(until_s), "hour")
    data = collect(conn, window, group_by=column, bucketed=False)
    ranked = sorted(((t.values["requests"], str(g)) for (_b, g), t in data.items() if g is not None), reverse=True)
    return [name for _n, name in ranked[:limit]]


# ------------------------------------------------------------------------------------------------ clients

CLIENT_LEVELS: tuple[tuple[str, str], ...] = (
    ("client_day", "day"),
    ("client_hour", "hour"),
    ("client_minute", "minute"),
)
CLIENT_SORTABLE = ("requests", "refused", "served", "bytes", "refused_pct", "rate1", "rate5", "rate60", "key")


def _client_watermark_end(conn: sqlite3.Connection, table: str, unit: str, tz: str) -> int | None:
    if unit == "minute":
        return None
    row = conn.execute(f"SELECT max(bucket_start) FROM {table}").fetchone()  # noqa: S608 (CLIENT_LEVELS)
    if row is None or row[0] is None:
        return None
    return bucket_next(int(row[0]), unit, zone(tz) if unit == "day" else None)


def trailing_rate(per_minute: Mapping[int, int], now: float, window_s: int) -> float:
    """Requests in the trailing `window_s` seconds, estimated from minute buckets (row 73: no flapping at :00).

    Minutes fully inside the window count whole; the oldest, partly covered minute counts in proportion to the
    part inside the window (requests assumed spread evenly over a minute).
    """
    start = now - window_s
    total = 0.0
    for minute, count in per_minute.items():
        lo, hi = minute, minute + 60
        overlap = max(0.0, min(hi, now) - max(lo, start))
        covered = min(hi, now) - lo
        if overlap <= 0 or covered <= 0:
            continue
        total += count * (overlap / covered)
    return round(total, 2)


def client_table_sync(
    conn: sqlite3.Connection,
    window: Window,
    client_type: str,
    *,
    now: float,
    page: Page | None = None,
) -> dict[str, Any]:
    """The Clients page table for `ip` or `place`: totals in the window plus Rate1/5/60 (plan 14.1, row 73)."""
    if client_type not in ("ip", "place"):
        raise ValueError("client_type must be 'ip' or 'place'")
    page = page or Page(sort="requests")
    if page.size not in PAGE_SIZES or page.sort not in CLIENT_SORTABLE:
        raise ValueError("invalid page size or sort key")
    acc: dict[str, dict[str, Any]] = {}
    cursor = window.start
    for table, unit in CLIENT_LEVELS:
        if cursor >= window.end:
            break
        zi = zone(window.tz) if unit == "day" else None
        mark = _client_watermark_end(conn, table, unit, window.tz)
        if unit == "minute":
            hi = window.end
        elif mark is None or cursor != bucket_floor(cursor, unit, zi):
            continue  # nothing compacted, or the window does not start on a bucket of this level
        else:
            # Never past the window: a coarse row covers its whole bucket.
            hi = min(mark, bucket_floor(window.end, unit, zi))
        if hi <= cursor:
            continue
        params: list[Any] = [client_type, cursor, hi]
        search = ""
        if page.search:
            search = " AND instr(lower(client_key), ?) > 0"
            params.append(page.search.lower())
        rows = conn.execute(
            f"SELECT client_key, sum(requests) AS requests, sum(refused) AS refused, sum(served) AS served, "  # noqa: S608
            f"sum(bytes) AS bytes, max(requests) AS busiest, top_endpoint FROM {table} "
            f"WHERE client_type = ? AND bucket_start >= ? AND bucket_start < ?{search} GROUP BY client_key",
            params,
        ).fetchall()
        for r in rows:
            item = acc.setdefault(
                r["client_key"],
                {"key": r["client_key"], "requests": 0, "refused": 0, "served": 0, "bytes": 0, "top_endpoint": None,
                 "_busiest": -1},
            )  # fmt: skip
            for col in ("requests", "refused", "served", "bytes"):
                item[col] += int(r[col] or 0)
            if int(r["busiest"] or 0) > item["_busiest"]:
                item["_busiest"] = int(r["busiest"] or 0)
                item["top_endpoint"] = r["top_endpoint"]
        cursor = hi
    rows_out = []
    for item in acc.values():
        item.pop("_busiest", None)
        item["refused_pct"] = round(item["refused"] * 100.0 / item["requests"], 2) if item["requests"] else None
        rows_out.append(item)
    needs_rates = page.sort in ("rate1", "rate5", "rate60")
    if needs_rates:
        _attach_rates(conn, client_type, rows_out, now)
    result = _paged(rows_out, page)
    if not needs_rates:
        _attach_rates(conn, client_type, result["rows"], now)
    return result


def _attach_rates(conn: sqlite3.Connection, client_type: str, rows: list[dict[str, Any]], now: float) -> None:
    keys = [r["key"] for r in rows]
    if not keys:
        return
    per_key: dict[str, dict[int, int]] = {}
    for chunk_start in range(0, len(keys), 500):
        chunk = keys[chunk_start : chunk_start + 500]
        marks = ", ".join("?" for _ in chunk)
        for r in conn.execute(
            f"SELECT client_key, bucket_start, requests FROM client_minute WHERE client_type = ? "  # noqa: S608
            f"AND bucket_start >= ? AND client_key IN ({marks})",
            (client_type, int(now) - 3660, *chunk),
        ):
            per_key.setdefault(r["client_key"], {})[int(r["bucket_start"])] = int(r["requests"])
    for row in rows:
        minutes = per_key.get(row["key"], {})
        row["rate1"] = trailing_rate(minutes, now, 60)
        row["rate5"] = trailing_rate(minutes, now, 300)
        row["rate60"] = trailing_rate(minutes, now, 3600)


async def client_table(db: Database, window: Window, client_type: str, **kwargs: Any) -> dict[str, Any]:
    return await db.read(lambda conn: client_table_sync(conn, window, client_type, **kwargs))


def client_timeline(conn: sqlite3.Connection, client_type: str, key: str, start: int, end: int) -> list[dict[str, Any]]:
    """One client's minute rows (drill-down timeline, row 73)."""
    rows = conn.execute(
        "SELECT bucket_start, requests, refused, served, bytes, top_endpoint FROM client_minute "
        "WHERE client_type = ? AND client_key = ? AND bucket_start >= ? AND bucket_start < ? ORDER BY bucket_start",
        (client_type, key, start, end),
    ).fetchall()
    return [dict(r) for r in rows]


# ----------------------------------------------------------------------------------- events based views


def _event_sum(conn: sqlite3.Connection, event_type: str, start: int, end: int, group_sql: str) -> list[sqlite3.Row]:
    return conn.execute(
        f"SELECT {group_sql} AS g, sum(coalesce(json_extract(detail_json, '$.count'), 1)) AS n "  # noqa: S608 (fixed)
        "FROM events WHERE type = ? AND at_ms >= ? AND at_ms < ? GROUP BY g ORDER BY n DESC",
        (event_type, start * 1000, end * 1000),
    ).fetchall()


def refusal_reasons(conn: sqlite3.Connection, window: Window) -> list[dict[str, Any]]:
    """Refusals and failures by reason code (exact, from rollups) with the custom versus default message split
    (row 116, from refusal events; aggregated rows carry their count)."""
    data = collect(conn, window, filters={"outcome": ["refused", "failed"]}, group_by="reason_code", bucketed=False)
    split: dict[str, dict[str, int]] = {}
    for event_type in ("refusal", "failure"):
        for r in conn.execute(
            "SELECT reason_code, coalesce(json_extract(detail_json, '$.message_source'), '') AS src, "
            "sum(coalesce(json_extract(detail_json, '$.count'), 1)) AS n FROM events "
            "WHERE type = ? AND at_ms >= ? AND at_ms < ? GROUP BY reason_code, src",
            (event_type, window.start * 1000, window.end * 1000),
        ):
            split.setdefault(str(r["reason_code"]), {})[str(r["src"]) or "unknown"] = int(r["n"])
    out = []
    for (_b, reason), totals in data.items():
        out.append(
            {"reason": reason, "requests": totals.values["requests"], "message_source": split.get(str(reason), {})}
        )
    out.sort(key=lambda r: -r["requests"])
    return out


def retry_stats(conn: sqlite3.Connection, window: Window) -> dict[str, Any]:
    """Retries by status, by reason and by egress (row 117; v1 `retry_counts` plus the returned reasons list)."""

    def grouped(path: str) -> dict[str, int]:
        return {str(r["g"]): int(r["n"]) for r in _event_sum(conn, "upstream_retry", window.start, window.end,
                                                             f"json_extract(detail_json, '{path}')")}  # fmt: skip

    by_status = grouped("$.status")
    return {
        "total": sum(by_status.values()),
        "by_status": by_status,
        "by_reason": grouped("$.reason"),
        "by_egress": grouped("$.egress"),
    }


def visitor_kpis(conn: sqlite3.Connection, window: Window) -> dict[str, int]:
    """The Overview Visitors card (row 130): visitor classes, page visits and robots.txt crawls."""
    rows = conn.execute(
        "SELECT json_extract(detail_json, '$.page') AS page, json_extract(detail_json, '$.visitor') AS visitor, "
        "sum(coalesce(json_extract(detail_json, '$.count'), 1)) AS n FROM events "
        "WHERE type = 'visit' AND at_ms >= ? AND at_ms < ? GROUP BY page, visitor",
        (window.start * 1000, window.end * 1000),
    ).fetchall()
    out = {
        "human_visitors": 0,
        "crawler_visitors": 0,
        "unknown_visitors": 0,
        "home_visits": 0,
        "admin_visits": 0,
        "robots_crawls": 0,
        "sitemap_crawls": 0,
    }
    for r in rows:
        n = int(r["n"] or 0)
        page, visitor = r["page"], r["visitor"]
        if page == "home":
            out["home_visits"] += n
            if visitor in ("human", "crawler", "unknown"):
                out[f"{visitor}_visitors"] += n
        elif page == "admin":
            out["admin_visits"] += n
        elif page == "robots":
            out["robots_crawls"] += n
        elif page == "sitemap":
            out["sitemap_crawls"] += n
    out["admin_visits"] = max(0, out["admin_visits"])  # v1 clamped the owner's own discounted visits at zero
    return out


def internal_calls(conn: sqlite3.Connection, window: Window) -> list[dict[str, Any]]:
    """Roxy's own upstream calls by purpose (v1 `internal_requests`): count, failed, mean time, last error."""
    rows = conn.execute(
        """
        SELECT reason_code AS purpose,
               sum(coalesce(json_extract(detail_json, '$.count'), 1)) AS n,
               sum(CASE WHEN json_extract(detail_json, '$.ok') THEN 0
                        ELSE coalesce(json_extract(detail_json, '$.count'), 1) END) AS failed,
               avg(json_extract(detail_json, '$.duration_ms')) AS mean_ms,
               max(at_ms) AS last_ms
        FROM events WHERE type = 'internal_call' AND at_ms >= ? AND at_ms < ? GROUP BY purpose ORDER BY n DESC
        """,
        (window.start * 1000, window.end * 1000),
    ).fetchall()
    out = []
    for r in rows:
        last_error = conn.execute(
            "SELECT json_extract(detail_json, '$.error') AS e, at_ms FROM events WHERE type = 'internal_call' "
            "AND reason_code = ? AND json_extract(detail_json, '$.ok') = 0 ORDER BY id DESC LIMIT 1",
            (r["purpose"],),
        ).fetchone()
        out.append(
            {
                "purpose": r["purpose"],
                "count": int(r["n"]),
                "failed": int(r["failed"] or 0),
                "mean_ms": round(float(r["mean_ms"]), 3) if r["mean_ms"] is not None else None,
                "last_ms": int(r["last_ms"]),
                "last_error": last_error["e"] if last_error else None,
                "last_error_ms": int(last_error["at_ms"]) if last_error else None,
            }
        )
    return out


def recent_429s(conn: sqlite3.Connection, limit: int = 50) -> list[dict[str, Any]]:
    """The newest Roblox 429 rows (LLM export `upstream_429_samples`, Upstream page)."""
    rows = conn.execute(
        "SELECT at_ms, endpoint_template, host, egress, retry_after_s, ratelimit_headers_json, request_id "
        "FROM upstream_429 ORDER BY id DESC LIMIT ?",
        (max(1, min(int(limit), 1000)),),
    ).fetchall()
    out = []
    for r in rows:
        item = dict(r)
        raw = item.pop("ratelimit_headers_json")
        item["ratelimit_headers"] = json.loads(raw) if raw else {}
        out.append(item)
    return out


def _egress_rows(conn: sqlite3.Connection, start: int, end: int, base: str, tz: str) -> list[sqlite3.Row]:
    """`egress_usage` rows answering `[start, end)`: the base granularity up to its newest bucket, then finer."""
    order = ("month", "day", "hour", "minute")
    zi = zone(tz)
    cursor = start
    out: list[sqlite3.Row] = []
    for granularity in order[order.index(base) :]:
        if cursor >= end:
            break
        local = zi if granularity in ("day", "month") else None
        if granularity == "minute":
            hi = end
        else:
            if cursor != bucket_floor(cursor, granularity, local):
                continue
            row = conn.execute(
                "SELECT max(bucket_start) FROM egress_usage WHERE granularity = ?", (granularity,)
            ).fetchone()
            if row[0] is None:
                continue
            hi = min(bucket_next(int(row[0]), granularity, local), bucket_floor(end, granularity, local))
        if hi <= cursor:
            continue
        out += conn.execute(
            "SELECT bucket_start, egress, requests, req_bytes, resp_bytes, overhead_bytes FROM egress_usage "
            "WHERE granularity = ? AND bucket_start >= ? AND bucket_start < ?",
            (granularity, cursor, hi),
        ).fetchall()
        cursor = hi
    return out


_EGRESS_BASE = {"minute": "minute", "hour": "hour", "day": "day", "week": "day", "month": "month", "year": "month"}


def egress_bytes(conn: sqlite3.Connection, window: Window) -> dict[str, int]:
    """Total wire bytes (request, response and overhead) per egress in the window (Egress page, KPI tile)."""
    totals: dict[str, int] = {}
    for r in _egress_rows(conn, window.start, window.end, _EGRESS_BASE[window.granularity], window.tz):
        size = int(r["req_bytes"] or 0) + int(r["resp_bytes"] or 0) + int(r["overhead_bytes"] or 0)
        totals[str(r["egress"])] = totals.get(str(r["egress"]), 0) + size
    return totals


def egress_usage_series(conn: sqlite3.Connection, window: Window) -> dict[str, Any]:
    """Bytes and requests per egress per bucket (Egress page daily bars; plan 8.5)."""
    zi = zone(window.tz)
    acc: dict[tuple[int, str], list[int]] = {}
    for r in _egress_rows(conn, window.start, window.end, _EGRESS_BASE[window.granularity], window.tz):
        key = (bucket_floor(int(r["bucket_start"]), window.granularity, zi), str(r["egress"]))
        item = acc.setdefault(key, [0, 0, 0, 0])
        for i, col in enumerate(("requests", "req_bytes", "resp_bytes", "overhead_bytes")):
            item[i] += int(r[col] or 0)
    starts = bucket_starts(window)
    egresses = sorted({e for (_b, e) in acc})
    return {
        "buckets": starts,
        "egress": {
            e: {
                "requests": [acc.get((b, e), [0, 0, 0, 0])[0] for b in starts],
                "bytes": [sum(acc.get((b, e), [0, 0, 0, 0])[1:]) for b in starts],
            }
            for e in egresses
        },
    }


def dims_per_minute(conn: sqlite3.Connection, start: int, end: int) -> float | None:
    """Average number of distinct dimension rows per minute (System page; SYS-DISK fires above 1,500)."""
    row = conn.execute(
        "SELECT count(*) * 1.0 / max(1, count(DISTINCT bucket_start)) FROM rollup_minute "
        "WHERE bucket_start >= ? AND bucket_start < ?",
        (start, end),
    ).fetchone()
    return round(float(row[0]), 2) if row and row[0] is not None else None


def earliest_data(conn: sqlite3.Connection) -> int | None:
    """The oldest bucket in any rollup level (start of the `all` range)."""
    found = []
    for table in LEVEL_ORDER:
        row = conn.execute(f"SELECT min(bucket_start) FROM {table}").fetchone()  # noqa: S608 (LEVEL_ORDER)
        if row and row[0] is not None:
            found.append(int(row[0]))
    return min(found) if found else None


def errors_table(
    conn: sqlite3.Connection, *, limit: int = 50, offset: int = 0, by: str = "last_seen"
) -> dict[str, Any]:
    """The System > Errors view: signatures with counts, last detail and `module:line` (row 72), paged."""
    order = {"last_seen": "last_seen DESC", "count": "count DESC, last_seen DESC"}.get(by)
    if order is None:
        raise ValueError("sort errors by 'last_seen' or 'count'")
    total = int(conn.execute("SELECT count(*) FROM errors").fetchone()[0])
    rows = conn.execute(
        f"SELECT signature, count, first_seen, last_seen, source, last_detail, module_line FROM errors "  # noqa: S608
        f"ORDER BY {order} LIMIT ? OFFSET ?",
        (max(1, min(int(limit), 250)), max(0, int(offset))),
    ).fetchall()
    return {"total": total, "rows": [dict(r) for r in rows]}


def endpoint_recent(conn: sqlite3.Connection, template: str, limit: int = 10) -> list[dict[str, Any]]:
    """Recent requests and concrete paths of one template, from the live rows of the last 15 minutes."""
    rows = conn.execute(
        "SELECT detail_json FROM events WHERE type = ? AND endpoint_template = ? ORDER BY id DESC LIMIT ?",
        (LIVE_EVENT, template, max(1, min(int(limit), 200))),
    ).fetchall()
    out = []
    for r in rows:
        try:
            out.append(json.loads(r["detail_json"]))
        except (TypeError, ValueError):
            continue
    return out


# ------------------------------------------------------------------------------------------- LLM export


def llm_rollup_summary(conn: sqlite3.Connection, window: Window) -> list[dict[str, Any]]:
    """Plan 12.3 `rollups`: per day (per hour for windows up to 24 h) requests, avoided calls, upstream calls,
    429s by egress, 5xx, timeouts, p50/p95/p99, bytes in and out, rotator bytes."""
    unit = "hour" if window.span <= 86_400 else "day"
    w = Window(bucket_floor(window.start, unit, zone(window.tz)), window.end, unit, window.tz)
    data = collect(conn, w)
    by_egress = _count_429(conn, w, group_col="egress") or {}
    usage = egress_usage_series(conn, w)
    out = []
    for i, start in enumerate(bucket_starts(w)):
        totals = data.get((start, None), Totals.zero())
        n429 = {str(g): n for (b, g), n in by_egress.items() if b == start}
        d = totals.derived(roblox_429=sum(n429.values()))
        rotator = usage["egress"].get("rotator", {}).get("bytes", [0] * (i + 1))
        out.append(
            {
                "start": start,
                "requests": d["requests"],
                "avoided_upstream_calls": d["avoided"],
                "upstream_calls": d["upstream_calls"],
                "roblox_429_by_egress": n429,
                "status_5xx": d["status_5xx"],
                "timeouts": d["timeouts"],
                "p50_ms": d["p50_ms"],
                "p95_ms": d["p95_ms"],
                "p99_ms": d["p99_ms"],
                "caller_bytes_in": d["caller_bytes_in"],
                "caller_bytes_out": d["caller_bytes_out"],
                "upstream_bytes_in": d["upstream_bytes_in"],
                "upstream_bytes_out": d["upstream_bytes_out"],
                "rotator_bytes": rotator[i] if i < len(rotator) else 0,
            }
        )
    return out


def llm_top_endpoints(conn: sqlite3.Connection, window: Window, limit: int = 50) -> dict[str, list[dict[str, Any]]]:
    """Plan 12.3 `top_endpoints`: top 50 by requests and by upstream calls, with hit ratio, 429s, percentiles."""
    by_requests = top_n_sync(conn, window, "endpoint_template", page=Page(size=100, sort="requests"))["rows"][:limit]
    by_calls = top_n_sync(conn, window, "endpoint_template", page=Page(size=100, sort="upstream_calls"))["rows"][:limit]
    keep = ("key", "requests", "upstream_calls", "hit_ratio", "roblox_429", "p50_ms", "p95_ms", "p99_ms")
    return {
        "by_requests": [{k: r.get(k) for k in keep} for r in by_requests],
        "by_upstream_calls": [{k: r.get(k) for k in keep} for r in by_calls],
    }


def values_in(rows: Iterable[Mapping[str, Any]], key: str) -> list[Any]:
    """Small helper for callers that render one column of a page."""
    return [row.get(key) for row in rows]
