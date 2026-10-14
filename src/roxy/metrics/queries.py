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
      nothing is counted twice. A sum over the whole window (totals, KPI tiles, top-N tables) reads the coarsest
      rows that tile it instead (`cover_pieces`: whole days, whole hours, minutes only at the edges), and a chart
      sums only the measures its metrics read (`measures_for`); both for plan 6.7's dashboard targets.
    - One SQL statement per level computes every measure as a conditional sum over the joined `dims` row (for
      example `demand`, `refused`, `roxy_429`) plus the histogram sums; Python then re-buckets, derives ratios
      and percentiles. Filter and group columns are checked against a fixed list before they reach SQL.
    - Honest definitions (P6) live in `metrics/catalog.py`; this module implements them: `avoided` is demand
      minus upstream calls for caller traffic; `errors_hidden` counts stale serves after an upstream failure;
      "who returned it" reads the source through `ANSWER_SOURCE_SQL` (a Roblox 5xx passed on after the retries is
      Roblox's). A KPI tile over a reset of its own data gets a notice instead of a delta (`kpis_sync`, plan 6.8).

What to read next
    `roxy/metrics/catalog.py` (what each measure means), `roxy/metrics/rollups.py` (how the levels are built).
"""

from __future__ import annotations

import calendar
import json
import sqlite3
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Any

from roxy.metrics import annotate, histograms, read_client_extras
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

ANSWER_SOURCE_SQL = "(CASE WHEN d.source = 'roxy' AND d.reason_code = 'upstream_5xx' THEN 'relay' ELSE d.source END)"
"""Who produced the status the caller received (v1 "Who returned it?", parity row 132; finding parity-1).

A Roblox 5xx that survived the allowed retries (`upstream_5xx`, plan 7.13) reaches the caller with Roblox's own status
and Roxy's retry text, but the request path records it with source `roxy` (the text is Roxy's). The status is
Roblox's, so every "who returned it" number reads such a row as `relay` (Roblox's answer, reshaped by Roxy): "5xx from
Roblox" counts it and "5xx from Roxy" (Roxy's own failures) does not. Rows recorded with `roblox` or `relay` keep
their source."""

GROUP_EXPRESSIONS: dict[str, str] = {"answer_source": ANSWER_SOURCE_SQL}
"""Computed dimensions that may be grouped on (never filtered): `answer_source` is `source` read through
`ANSWER_SOURCE_SQL`, the source series of Traffic > Status codes."""

# Conditional sums computed for every bucket and group. Names are fixed; the SQL is a module constant.
MEASURES: tuple[tuple[str, str], ...] = (
    ("requests", "sum(r.requests)"),
    (
        "demand",
        "sum(CASE WHEN d.outcome != 'refused' AND d.reason_code != 'options_local' AND d.source != 'internal' "
        "THEN r.requests ELSE 0 END)",
    ),
    # A local OPTIONS answer is recorded as `served_upstream` (the closest outcome of the closed enum) with reason
    # `options_local`; nothing went to Roblox, so it is not "Served from Roblox" (P6, finding spec-7).
    (
        "served_upstream",
        "sum(CASE WHEN d.outcome = 'served_upstream' AND d.reason_code != 'options_local' THEN r.requests ELSE 0 END)",
    ),
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
        f"sum(CASE WHEN d.status BETWEEN 500 AND 599 AND {ANSWER_SOURCE_SQL} IN ('roblox', 'relay') "
        "THEN r.requests ELSE 0 END)",
    ),
    (
        "roxy_5xx",
        f"sum(CASE WHEN d.status BETWEEN 500 AND 599 AND {ANSWER_SOURCE_SQL} = 'roxy' THEN r.requests ELSE 0 END)",
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
    (
        "latency_hist",
        "group_concat(CASE WHEN d.source != 'internal' AND r.latency_hist IS NOT NULL THEN hex(r.latency_hist) END)",
    ),
    (
        "queue_wait_hist",
        "group_concat(CASE WHEN d.source != 'internal' AND r.queue_wait_hist IS NOT NULL "
        "THEN hex(r.queue_wait_hist) END)",
    ),
)
"""The histogram blobs of a group, as one comma-separated hex text each (`Totals.add_row` decodes and adds them).

Not the `roxy_hist_sum` aggregate the compaction uses: an aggregate written in Python is called once per row with
the GIL taken and given back around every call, so two reader threads summing at once (two cards of one page, two
admins) spent most of their time handing the GIL to each other (plan 6.7; measured two to three times slower than
one after the other). `group_concat` and `hex` run in SQLite's C code; Python decodes each group's blobs in one go."""
HIST_NAMES: tuple[str, ...] = tuple(name for name, _ in HIST_MEASURES)

METRIC_HISTOGRAMS: dict[str, str] = {
    "p50_ms": "latency_hist",
    "p95_ms": "latency_hist",
    "p99_ms": "latency_hist",
    "p99_overflow": "latency_hist",
    "queue_wait_p95_ms": "queue_wait_hist",
}
"""Derived metrics read from a histogram (`Totals.derived`)."""
METRIC_MEASURES: dict[str, tuple[str, ...]] = {
    "avoided": ("demand", "upstream_calls"),
    "avoided_pct": ("demand", "upstream_calls"),
    "hit_ratio": ("cache_hit", "cache_stale", "cache_revalidating", "cache_coalesced", "cache_miss"),
    "roblox_429": (),
    "roblox_429_per_10k": ("demand",),
}
"""The measures each other derived metric is computed from (`Totals.derived`; every name of `MEASURE_NAMES` is its
own measure). A series computes only what its metrics read (`measures_for`)."""


def measures_for(metrics: Iterable[str]) -> tuple[tuple[str, ...] | None, tuple[str, ...] | None]:
    """`(measures, histograms)` a series of `metrics` reads; None means every one (a metric this table does not
    know reads everything, as before the table existed).

    Why: each measure is a conditional sum evaluated for every rollup row, and each histogram is decoded in Python
    blob by blob (`HIST_MEASURES`), so a chart of requests over 90 days at hour granularity (600,000 rows at plan
    6.6's volume) spent seconds on sums nobody asked for (plan 6.7: any chart query over 90 days under 500 ms).
    `requests` is always summed: `series_sync` ranks its groups by it.
    """
    names = {"requests"}
    hists: set[str] = set()
    for metric in metrics:
        if metric in METRIC_HISTOGRAMS:
            hists.add(METRIC_HISTOGRAMS[metric])
        elif metric in METRIC_MEASURES:
            names.update(METRIC_MEASURES[metric])
        elif metric in MEASURE_NAMES:
            names.add(metric)
        else:
            return None, None
    return tuple(n for n in MEASURE_NAMES if n in names), tuple(h for h in HIST_NAMES if h in hists)


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
    """`ts` moved by `months` calendar months on the local wall clock; a day the target month lacks (the 29th to
    the 31st) becomes that month's last day (review finding truth-1: clamping every day to the 28th cut windows
    short)."""
    zi = zone(tz)
    local = datetime.fromtimestamp(ts, zi)
    month_index = local.month - 1 + months
    year = local.year + month_index // 12
    month = month_index % 12 + 1
    day = min(local.day, calendar.monthrange(year, month)[1])
    shifted = local.replace(year=year, month=month, day=day)
    return int(shifted.timestamp())


def _shift_local_days(ts: int, days: int, tz: str) -> int:
    """`ts` moved by `days` whole days on the local wall clock (a day across a daylight saving change is 23 or 25
    hours long, so local midnight stays local midnight)."""
    zi = zone(tz)
    local = datetime.fromtimestamp(ts, zi).replace(tzinfo=None) + timedelta(days=days)
    return int(local.replace(tzinfo=zi).timestamp())


def _local_days(window: Window) -> int:
    """Whole local days the window spans (day, week and month windows start and end on local midnights)."""
    zi = zone(window.tz)
    first = datetime.fromtimestamp(window.start, zi).date()
    last = datetime.fromtimestamp(window.end, zi).date()
    return max(1, (last - first).days)


def _local_months(window: Window) -> int:
    zi = zone(window.tz)
    first = datetime.fromtimestamp(window.start, zi)
    last = datetime.fromtimestamp(window.end, zi)
    return max(1, (last.year - first.year) * 12 + last.month - first.month)


CALENDAR_UNITS = frozenset({"day", "week", "month"})
"""Granularities whose buckets start on local midnights: their comparisons move by whole local days or months, so
every compared bucket starts at local midnight and holds as many buckets as the window (finding truth-11)."""


def _ending(window: Window, start: int) -> int:
    """The end of a comparison window that starts at `start` and holds as many buckets as `window`."""
    if window.granularity == "month":
        return _shift_months(start, _local_months(window), window.tz)
    if window.granularity in CALENDAR_UNITS:
        return _shift_local_days(start, _local_days(window), window.tz)
    return start + window.span


def comparison_window(window: Window, mode: str) -> Window:
    """The window to compare with: previous period, same period last week, last month or last year.

    The comparison always holds as many buckets as the window (charts overlay bucket j on bucket j): minute and hour
    windows move by their exact length; day, week and month windows move by whole local days or months, so a window
    holding a daylight saving change is still compared day by day from local midnight (review finding truth-11).
    Month and year comparisons move the start by calendar months (the 31st becomes the last day of a shorter month)
    and keep the window's length, so a range ending on the 29th to 31st is never cut short (finding truth-1).
    """
    tz = window.tz
    if mode == "previous":
        if window.granularity == "month":
            start = _shift_months(window.start, -_local_months(window), tz)
        elif window.granularity in CALENDAR_UNITS:
            start = _shift_local_days(window.start, -_local_days(window), tz)
        else:
            start = window.start - window.span
        return replace(window, start=start, end=window.start)
    if mode == "week":
        if window.granularity in CALENDAR_UNITS:
            start = _shift_local_days(window.start, -7, tz)
        else:
            start = window.start - 7 * 86_400
        return replace(window, start=start, end=_ending(window, start))
    if mode in ("month", "year"):
        start = _shift_months(window.start, -1 if mode == "month" else -12, tz)
        return replace(window, start=start, end=_ending(window, start))
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


def _whole_days(conn: sqlite3.Connection, start: int, end: int) -> tuple[int, int] | None:
    """`(lo, hi)`: the first contiguous run of compacted day buckets that lie wholly inside `[start, end)`, or None.

    Each `rollup_day` row knows its zone (`tz`), so a bucket ends where `bucket_next` in that zone says (23 or 25
    hours across a DST change). The run stops at a gap or an overlap (a day with no traffic, a `ui_timezone`
    change) and is used only when both its ends are on whole hours (never in a half-hour zone), so the hours on
    either side of it tile the rest of the window exactly.
    """
    rows = conn.execute(
        "SELECT bucket_start, max(tz) AS tz FROM rollup_day WHERE bucket_start >= ? AND bucket_start < ? "
        "GROUP BY bucket_start ORDER BY bucket_start",
        (start, end),
    ).fetchall()
    lo: int | None = None
    hi: int | None = None
    for row in rows:
        bucket = int(row["bucket_start"])
        if hi is not None and bucket != hi:
            break
        stop = bucket_next(bucket, "day", zone(row["tz"]))
        if stop > end:
            break
        lo = bucket if lo is None else lo
        hi = stop
    if lo is None or hi is None or lo % HOUR_S or hi % HOUR_S:
        return None
    return lo, hi


def cover_pieces(conn: sqlite3.Connection, start: int, end: int) -> list[tuple[str, int, int]]:
    """Which rows answer `[start, end)` when only the window's sum is wanted (totals, KPI tiles and top-N tables;
    never the buckets of a chart): whole compacted days from `rollup_day`, whole hours from `rollup_hour`, and the
    minutes at either edge and after the hour watermark from `rollup_minute`.

    A sum does not care which level its rows come from, and every level holds the same rows summed (compaction),
    so a 24 hour total reads about 24 hour rows per dimension combination instead of 1,440 minute rows, and a 30
    day total about 30 day rows instead of 720 hour rows (plan 6.7: dashboard first render under 300 ms; at plan
    6.6's volume a 24 hour total read 120,000 minute rows and called the histogram aggregate twice for each).
    """
    days = _whole_days(conn, start, end)
    if days is None:
        return _hour_pieces(conn, start, end)
    lo, hi = days
    pieces = _hour_pieces(conn, start, lo) if start < lo else []
    pieces.append(("rollup_day", lo, hi))
    if hi < end:
        pieces += _hour_pieces(conn, hi, end)
    return pieces


def _hour_pieces(conn: sqlite3.Connection, start: int, end: int) -> list[tuple[str, int, int]]:
    """`[start, end)` as minutes up to the first whole hour, whole compacted hours (never one that runs past `end`
    or past the hour watermark), and minutes for the rest."""
    first = min(end, start + (-start) % HOUR_S)
    pieces: list[tuple[str, int, int]] = []
    if start < first:
        pieces.append(("rollup_minute", start, first))
    mark = _watermark_end(conn, "rollup_hour")
    last = min(end - end % HOUR_S, mark) if mark is not None else first
    if last > first:
        pieces.append(("rollup_hour", first, last))
        first = last
    if first < end:
        if pieces and pieces[-1][0] == "rollup_minute":
            pieces[-1] = ("rollup_minute", pieces[-1][1], end)  # no whole hour between: one minute read
        else:
            pieces.append(("rollup_minute", first, end))
    return pieces


def total_pieces(conn: sqlite3.Connection, window: Window) -> list[tuple[str, int, int]]:
    """The pieces a sum over the whole window reads: `cover_pieces` for a minute or hour window (one that fits the
    finer levels' retention), else the base level as `level_pieces` reads it (day and month windows already read
    their coarse level)."""
    base = BASE_LEVEL[window.granularity]
    if base in ("rollup_minute", "rollup_hour"):
        return cover_pieces(conn, window.start, window.end)
    return level_pieces(conn, base, window.start, window.end)


def _measure_rows(
    conn: sqlite3.Connection,
    table: str,
    start: int,
    end: int,
    *,
    filters: Mapping[str, Any] | None,
    group_by: str | None,
    time_unit: str | None,
    measures: Sequence[str] | None = None,
    hists: Sequence[str] | None = None,
) -> list[sqlite3.Row]:
    """One level's rows of the window, grouped by bucket and group: every measure and histogram sum, or only
    `measures` and `hists` when given (`measures_for`; a measure left out reads as 0 in `Totals`)."""
    if group_by is not None and group_by not in FILTER_COLUMNS and group_by not in GROUP_EXPRESSIONS:
        raise ValueError(f"unknown group {group_by!r}")
    where, params = _filter_sql(filters)
    if time_unit is None:
        time_expr = "NULL"
    elif time_unit == "hour" and table == "rollup_minute":
        time_expr = "r.bucket_start - r.bucket_start % 3600"
    else:
        time_expr = "r.bucket_start"  # re-bucketed to local days and longer in Python
    group_expr = GROUP_EXPRESSIONS.get(group_by or "") or (f"d.{group_by}" if group_by else "NULL")
    chosen = [(name, sql) for name, sql in MEASURES if measures is None or name in measures] + [
        (name, sql) for name, sql in HIST_MEASURES if hists is None or name in hists
    ]
    measures_sql = ", ".join(f"{sql} AS {name}" for name, sql in chosen)
    sql = (
        f"SELECT {time_expr} AS b, {group_expr} AS g, {measures_sql} "  # noqa: S608 (identifiers are fixed constants)
        f"FROM {table} r JOIN dims d ON d.dim_hash = r.dim_hash "
        f"WHERE r.bucket_start >= ? AND r.bucket_start < ?{where} GROUP BY b, g"
    )
    return conn.execute(sql, (start, end, *params)).fetchall()


def _add_hex_blobs(target: list[int], text: str) -> None:
    """Add every histogram blob of one `HIST_MEASURES` column (hex texts joined by commas) into `target`."""
    for part in str(text).split(","):
        if part:
            histograms.add_blob_into(target, bytes.fromhex(part))


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
        """Add one row of `_measure_rows`; a measure or histogram the row does not carry stays as it is."""
        present = row.keys()
        for name in present:
            if name in self.values:  # the measures (never `b`, `g` or a histogram)
                self.values[name] += int(row[name] or 0)
        if "latency_hist" in present and row["latency_hist"]:
            _add_hex_blobs(self.latency, row["latency_hist"])
        if "queue_wait_hist" in present and row["queue_wait_hist"]:
            _add_hex_blobs(self.queue_wait, row["queue_wait_hist"])

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
    measures: Sequence[str] | None = None,
    hists: Sequence[str] | None = None,
) -> dict[tuple[int | None, Any], Totals]:
    """`{(bucket start or None, group value or None): Totals}` for the window, reading every level once.

    Bucketed (a chart), each level up to its watermark answers its own buckets (`level_pieces`); not bucketed (one
    sum per group), the window is read from the coarsest rows that tile it (`total_pieces`). `measures` and `hists`
    narrow what is summed (`measures_for`); None sums everything.
    """
    register_sql_functions(conn)
    zi = zone(window.tz)
    base = BASE_LEVEL[window.granularity]
    out: dict[tuple[int | None, Any], Totals] = {}
    pieces = level_pieces(conn, base, window.start, window.end) if bucketed else total_pieces(conn, window)
    for table, lo, hi in pieces:
        unit = None
        if bucketed:
            unit = "hour" if window.granularity == "hour" else LEVEL_UNIT[table]
        rows = _measure_rows(
            conn, table, lo, hi, filters=filters, group_by=group_by, time_unit=unit, measures=measures, hists=hists
        )
        for row in rows:
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
    """A chart: one value list per metric per group, one value per bucket (zeros for empty buckets). Only the
    measures and histograms the metrics read are summed (`measures_for`)."""
    starts = bucket_starts(window)
    wanted = list(metrics) if metrics else ["requests"]
    measures, hists = measures_for(wanted)
    data = collect(conn, window, filters=filters, group_by=group_by, measures=measures, hists=hists)
    found_429 = _count_429(conn, window, group_col=group_by, filters=filters)
    counts_429 = found_429 or {}
    groups: dict[Any, dict[int, Totals]] = {}
    for (bucket, group), totals in data.items():
        groups.setdefault(group, {})[int(bucket or 0)] = totals
    for (bucket, group), _n in counts_429.items():
        groups.setdefault(group, {}).setdefault(int(bucket or 0), Totals.zero())
    ranked = sorted(groups, key=lambda g: -sum(t.values["requests"] for t in groups[g].values()))
    shown, rest = ranked[:max_groups], ranked[max_groups:]
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
    conn: sqlite3.Connection,
    window: Window,
    *,
    filters: Mapping[str, Any] | None = None,
    metrics: Sequence[str] | None = None,
) -> dict[str, Any]:
    """All measures summed over the window (one KPI value per measure), or with `metrics` only those (the answer
    then holds just those keys; `measures_for` decides what is summed)."""
    measures, hists = measures_for(metrics) if metrics is not None else (None, None)
    data = collect(conn, window, filters=filters, bucketed=False, measures=measures, hists=hists)
    totals = Totals.zero()
    for item in data.values():
        totals.add(item)
    found_429 = _count_429(conn, window, bucketed=False, filters=filters)
    out = totals.derived(roblox_429=sum(found_429.values()) if found_429 is not None else None)
    if metrics is not None:
        wanted = set(metrics)
        out = {key: value for key, value in out.items() if key in wanted}
        if "rotator_bytes" not in wanted:
            return out
    out["rotator_bytes"] = egress_bytes(conn, window).get("rotator", 0)
    return out


def answer_source_counts(conn: sqlite3.Connection, window: Window) -> list[dict[str, Any]]:
    """Requests by who produced the caller's status and by status (v1 "Who returned it?", rows 68 and 132):
    `[{source, status, requests}]`, most first. `source` is read through `ANSWER_SOURCE_SQL`, so a Roblox 5xx
    passed on with Roxy's retry text is Roblox's (`relay`), as the `roblox_5xx` tile counts it."""
    totals: dict[tuple[str, int], int] = {}
    for table, lo, hi in total_pieces(conn, window):
        sql = (
            f"SELECT {ANSWER_SOURCE_SQL} AS a, d.status AS b, sum(r.requests) AS n FROM {table} r "  # noqa: S608 (constants)
            "JOIN dims d ON d.dim_hash = r.dim_hash WHERE r.bucket_start >= ? AND r.bucket_start < ? GROUP BY a, b"
        )
        for row in conn.execute(sql, (lo, hi)):
            key = (str(row["a"]), int(row["b"] or 0))
            totals[key] = totals.get(key, 0) + int(row["n"] or 0)
    ordered = sorted(((-n, a, b) for (a, b), n in totals.items() if n))
    return [{"source": a, "status": b, "requests": -negative} for negative, a, b in ordered]


def change(current: Any, previous: Any) -> tuple[float | None, float | None]:
    """`(delta, delta_pct)` of a number against its comparison: the one formula of every delta the admin API shows
    (the Overview, Cache, Traffic and Endpoints helpers call it).

    The percent divides by the size of the baseline (`abs(previous)`), so its sign always follows the change: a
    number that goes from -1 to 5 went up by 600%, never "down 600%" (review finding truth-2; the avoided calls and
    the avoided share are negative by design, plan P6). No baseline (0 or missing) gives no percent.
    """
    if not isinstance(current, int | float) or not isinstance(previous, int | float):
        return None, None
    delta = current - previous
    pct = round(delta * 100.0 / abs(previous), 2) if previous else None
    return round(delta, 4), pct


def _delta(current: Any, previous: Any) -> dict[str, Any]:
    delta, pct = change(current, previous)
    return {"previous": previous, "delta": delta, "delta_pct": pct}


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


ROLLUP_TABLES: tuple[str, ...] = tuple(f"metrics.{table}" for table in LEVEL_ORDER)
"""The rollup levels as `<db>.<table>` names, the way a reset marker lists what it deleted (`reset_tables`)."""
KPI_SOURCES: dict[str, tuple[str, ...]] = {
    "roblox_429": ("metrics.upstream_429",),
    "roblox_429_per_10k": ("metrics.upstream_429", *ROLLUP_TABLES),
    "rotator_bytes": ("metrics.egress_usage",),
}
"""Tables a KPI tile reads, where it is not only the rollups (every other tile, `requests_last_hour` included)."""
LATENCY_KPIS: frozenset[str] = frozenset({"p50_ms", "p95_ms", "p99_ms"})
"""Numbers that read the latency histograms, so a latency-only reset (`<table>#latency`) makes them partial too."""
LATENCY_PART = "latency"
CACHE_STATE_KPIS: frozenset[str] = frozenset(
    {"hit_ratio", "cache_hit", "cache_miss", "cache_stale", "cache_revalidating", "cache_coalesced"}
)
"""Numbers that read the rollups' cache lookup states, so a cache statistics reset (`<table>#cache_state`: lookups
moved to the `cleared` state, requests kept; finding parity-8) makes them partial too."""
CACHE_STATE_PART = "cache_state"
LAST_HOUR_KPIS: tuple[str, ...] = ("requests_last_hour", "failures_last_hour")
"""Tiles of the trailing hour, whatever range is selected (the Overview's v1 tiles 10 and 11)."""


def kpi_tables(key: str) -> tuple[str, ...]:
    """The `<db>.<table>` names KPI tile `key` is computed from."""
    return KPI_SOURCES.get(key, ROLLUP_TABLES)


def reset_touches(row: Mapping[str, Any], tables: Iterable[str], *, latency: bool = False, cache: bool = False) -> bool:
    """Whether the reset marker `row` (from `reset_annotations`) deleted data a number read from `tables` uses.

    A marker lists what it deleted in `reset_tables`: `<db>.<table>` for deleted rows, `<db>.<table>#latency` for
    rollup rows whose latency histograms were emptied (their counts kept), which matters only to a `latency`
    number, and `<db>.<table>#cache_state` for rollup rows whose cache lookup state was cleared (their counts kept),
    which matters only to a `cache` number (`CACHE_STATE_KPIS`). A marker without that list (written before it
    existed, or by a writer that does not know) may have touched anything, so it counts (plan 6.8: a misleading delta
    is worse than a missing one).
    """
    scope = row.get("reset_tables")
    if scope is None:
        return True
    wanted = set(tables)
    for entry in scope:
        name, _, part = str(entry).partition("#")
        if name not in wanted:
            continue
        if not part or (part == LATENCY_PART and latency) or (part == CACHE_STATE_PART and cache):
            return True
    return False


def _when(at: Any, tz: str) -> str:
    return datetime.fromtimestamp(int(at or 0), zone(tz)).strftime("%Y-%m-%d %H:%M %Z")


def reset_tile_notice(row: Mapping[str, Any], tz: str, *, comparison: bool) -> str:
    """The plan 6.8 tile notice for reset marker `row`: dates only (a marker's label may name a client)."""
    tail = f"this {'comparison' if comparison else 'value'} covers partial data."
    if row.get("until") is not None:
        return f"Data from {_when(row.get('at'), tz)} to {_when(row.get('until'), tz)} was reset; {tail}"
    return f"Data reset on {_when(row.get('at'), tz)}; {tail}"


def mark_partial(
    tile: dict[str, Any],
    tables: Iterable[str],
    current: Sequence[Mapping[str, Any]],
    baseline: Sequence[Mapping[str, Any]],
    tz: str,
    *,
    latency: bool = False,
    cache: bool = False,
) -> bool:
    """Plan 6.8 on one number with a delta: a reset of the data it reads (`tables`, see `reset_touches`) in its own
    window (`current`, `reset_annotations` rows) or its comparison window (`baseline`) replaces the delta with a
    notice: `notice` and `partial: true` are set, `delta` and `delta_pct` become null when present, and the baseline
    `previous` stays as read (never synthesized). Returns whether the number is partial.

    The one helper every delta of the admin API goes through (the Overview tiles in `kpis_sync`, the Cache page
    tiles, the endpoint drill-down totals, the rotator tile and the Traffic trends; review round 4 finding
    LOGICFIX-1: those built their deltas outside `kpis_sync` and never asked).
    """
    wanted = tuple(tables)
    mine = [row for row in current if reset_touches(row, wanted, latency=latency, cache=cache)]
    theirs = [row for row in baseline if reset_touches(row, wanted, latency=latency, cache=cache)]
    if not mine and not theirs:
        return False
    tile["notice"] = reset_tile_notice((mine or theirs)[0], tz, comparison=not mine)
    tile["partial"] = True
    if "delta" in tile:
        tile["delta"] = None
        tile["delta_pct"] = None
    return True


def mark_kpi_partial(
    tile: dict[str, Any],
    key: str,
    current: Sequence[Mapping[str, Any]],
    baseline: Sequence[Mapping[str, Any]],
    tz: str,
) -> bool:
    """`mark_partial` for a measure of this module (`key`): the tables it reads (`kpi_tables`), and whether it reads
    the latency histograms (`LATENCY_KPIS`) or the cache lookup states (`CACHE_STATE_KPIS`)."""
    return mark_partial(
        tile, kpi_tables(key), current, baseline, tz, latency=key in LATENCY_KPIS, cache=key in CACHE_STATE_KPIS
    )


def touching_resets(
    rows: Iterable[Mapping[str, Any]], keys: Iterable[str], *, seen: set[Any] | None = None
) -> list[Mapping[str, Any]]:
    """The reset markers among `rows` that touch any of the measures `keys` (each once, by id; `seen` carries the
    ids already listed across calls): what a page's `notices` should name next to its partial numbers."""
    names = tuple(keys)
    tables = {table for key in names for table in kpi_tables(key)}
    latency = any(key in LATENCY_KPIS for key in names)
    cache = any(key in CACHE_STATE_KPIS for key in names)
    seen = set() if seen is None else seen
    out: list[Mapping[str, Any]] = []
    for row in rows:
        if row.get("id") not in seen and reset_touches(row, tables, latency=latency, cache=cache):
            seen.add(row.get("id"))
            out.append(row)
    return out


def kpis_sync(conn: sqlite3.Connection, window: Window, *, now: float, compare: str | None = None) -> dict[str, Any]:
    """KPI tiles (plan 14.1 Overview) with an optional comparison and reset notices (plan 6.8).

    Plan 6.8, finding parity-12: a tile whose own window or comparison window overlaps a reset of the data it reads
    (`reset_touches`) carries a `notice` and `partial: true`, and its `delta` and `delta_pct` are null instead of a
    misleading number. Other tiles keep their delta. The page `notices` list only resets that touched a tile.
    The last-hour tiles (`LAST_HOUR_KPIS`: `requests_last_hour`, `failures_last_hour`) are checked over their hour
    and the hour before (the Overview compares the two).
    """
    current = totals_sync(conn, window)
    last_hour = Window(int(now) - 3600, int(now) + 1, "minute", window.tz)
    tiles: dict[str, Any] = {key: {"value": current.get(key)} for key in KPI_KEYS}
    hour_totals = totals_sync(conn, last_hour)
    tiles["requests_last_hour"] = {"value": hour_totals["requests"]}
    # v1's twin tile (finding parity-2): failed outcomes in the same trailing hour, so the live stream carries it.
    tiles["failures_last_hour"] = {"value": hour_totals["failed"]}
    current_resets = reset_annotations(conn, window.start, window.end)
    baseline_resets: list[dict[str, Any]] = []
    result: dict[str, Any] = {"window": _window_dict(window), "tiles": tiles}
    if compare:
        other = comparison_window(window, compare)
        previous = totals_sync(conn, other)
        for key in KPI_KEYS:
            tiles[key].update(_delta(current.get(key), previous.get(key)))
        result["compare"] = {"mode": compare, "window": _window_dict(other)}
        baseline_resets = reset_annotations(conn, other.start, other.end)
    for key in KPI_KEYS:
        mark_kpi_partial(tiles[key], key, current_resets, baseline_resets, window.tz)
    hour_resets = reset_annotations(conn, last_hour.start - 3600, last_hour.end)
    for key in LAST_HOUR_KPIS:
        mark_kpi_partial(tiles[key], key, hour_resets, [], window.tz)
    every_table = {name for key in (*KPI_KEYS, *LAST_HOUR_KPIS) for name in kpi_tables(key)}
    seen: set[Any] = set()
    notices: list[dict[str, Any]] = []
    for row in (*current_resets, *baseline_resets):
        if row["id"] not in seen and reset_touches(row, every_table, latency=True):
            seen.add(row["id"])
            notices.append(row)
    result["notices"] = notices
    return result


async def kpis(db: Database, window: Window, *, now: float, compare: str | None = None) -> dict[str, Any]:
    return await db.read(lambda conn: kpis_sync(conn, window, now=now, compare=compare))


def _window_dict(window: Window) -> dict[str, Any]:
    return {"start": window.start, "end": window.end, "granularity": window.granularity, "tz": window.tz}


def reset_annotations(conn: sqlite3.Connection, start: int, end: int) -> list[dict[str, Any]]:
    """Reset markers that touch `[start, end)`: a KPI over such a window covers partial data (plan 6.8).

    A reset of one instant (`until` NULL) counts when it lies inside the window; a ranged reset (its deleted range
    `[at, until)`, `metrics/annotate.py`) counts when that range overlaps the window, so a window strictly
    inside a deleted range is flagged too. Each row carries `reset_tables`: what the reset deleted
    (`annotate.reset_tables_of`), or None when the marker does not say (`reset_touches` then counts it everywhere).
    """
    scoped = annotate.has_reset_tables(conn)
    extra = f", {annotate.RESET_TABLES_COLUMN}" if scoped else ""
    rows = conn.execute(
        f"SELECT id, at, until, label, audit_id{extra} FROM annotations WHERE kind = 'reset' AND at < ? "  # noqa: S608 (fixed column name)
        "AND (CASE WHEN until IS NULL THEN at >= ? ELSE until > ? END) ORDER BY at LIMIT 100",
        (end, start, start),
    ).fetchall()
    return [
        {
            "id": r["id"],
            "at": r["at"],
            "until": r["until"],
            "label": r["label"],
            "audit_id": r["audit_id"],
            "reset_tables": annotate.reset_tables_of(r[annotate.RESET_TABLES_COLUMN]) if scoped else None,
        }
        for r in rows
    ]


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


def ordered_rows(rows: list[dict[str, Any]], sort: str, *, descending: bool = True) -> list[dict[str, Any]]:
    """`rows` in table order: by `sort` (ties by key), rows without a value last (`_paged` and the unpaged reads)."""
    present = [r for r in rows if r.get(sort) is not None]
    missing = [r for r in rows if r.get(sort) is None]
    present.sort(key=lambda r: (r[sort], str(r.get("key"))), reverse=descending)
    return present + missing


def _paged(rows: list[dict[str, Any]], page: Page) -> dict[str, Any]:
    ordered = ordered_rows(rows, page.sort, descending=page.descending)
    first = (page.page - 1) * page.size
    return {
        "total": len(ordered),
        "page": page.page,
        "size": page.size,
        "sort": page.sort,
        "descending": page.descending,
        "rows": ordered[first : first + page.size],
    }


def top_rows_sync(
    conn: sqlite3.Connection,
    window: Window,
    dimension: str,
    *,
    filters: Mapping[str, Any] | None = None,
    search: str = "",
) -> list[dict[str, Any]]:
    """Every row of `top_n_sync` (one per value of `dimension`, every measure), unsorted and unpaged: one read for
    a caller that needs them all (the insights rules, gaps_insights G7: paging re-ran the whole aggregate per page)."""
    data = collect(conn, window, filters=filters, group_by=dimension, bucketed=False)
    found_429 = _count_429(conn, window, group_col=dimension, bucketed=False, filters=filters)
    counts_429 = found_429 or {}
    rows: list[dict[str, Any]] = []
    keys = {group for (_b, group) in data} | {group for (_b, group) in counts_429}
    for key in keys:
        totals = data.get((None, key), Totals.zero())
        row = totals.derived(roblox_429=counts_429.get((None, key), 0) if found_429 is not None else None)
        row["key"] = key
        if search and search.lower() not in str(key).lower():
            continue
        rows.append(row)
    return rows


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
    return _paged(top_rows_sync(conn, window, dimension, filters=filters, search=page.search), page)


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
CLIENT_SORTABLE = (
    "requests",
    "refused",
    "served",
    "bytes",
    "refused_pct",
    "rate1",
    "rate5",
    "rate60",
    "last_seen",
    "key",
)


IP_KEY_ORDER_MIN_S = 6 * 3600
"""From this many seconds of address minutes on, `_client_totals` sums them in key order through
`client_minute_ip_rows` (every kept minute, no sort) instead of sorting the window's rows read by time (measured
crossover at plan 6.6's volume with the default 3 days of client minutes: about 9 hours)."""


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


def _client_totals(
    conn: sqlite3.Connection, window: Window, client_type: str, search_text: str = ""
) -> tuple[list[dict[str, Any]], list[tuple[str, int, int]]]:
    """Every client of a type with its totals in the window (`key`, `requests`, `refused`, `served`, `bytes`,
    `top_endpoint`, `refused_pct`; unsorted), and the `(table, start, end)` pieces that were read: each client level
    from the coarsest whose compacted rows start on the window, then the finer ones (row 73)."""
    acc: dict[str, dict[str, Any]] = {}
    pieces: list[tuple[str, int, int]] = []
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
        source, type_sql = table, "client_type = ?"
        params: list[Any] = [client_type, cursor, hi]
        if table == "client_minute" and client_type == "ip" and hi - cursor >= IP_KEY_ORDER_MIN_S:
            # Many hours of address minutes: `client_minute_ip_rows` (metrics migration 0009) holds every summed
            # column in key order, so each address is summed as the index is walked instead of sorting the window's
            # rows (720,000 for 24 hours at plan 6.6's volume; 0.2 s to 0.08 s, plan 6.7). The walk reads every kept
            # address minute, so a short window keeps the time-ordered primary key. The literal type repeats the
            # partial index's WHERE term, which `INDEXED BY` needs; the sums are the same rows either way.
            source, type_sql = "client_minute INDEXED BY client_minute_ip_rows", "client_type = 'ip'"
            params = [cursor, hi]
        search = ""
        if search_text:
            search = " AND instr(lower(client_key), ?) > 0"
            params.append(search_text.lower())
        # `top_endpoint` is a bare column taken from the row of `max(requests)` (SQLite's min/max rule), so this
        # statement keeps exactly one max(); `last_seen` is read by `read_client_extras.attach_last_seen`.
        rows = conn.execute(
            f"SELECT client_key, sum(requests) AS requests, sum(refused) AS refused, sum(served) AS served, "  # noqa: S608
            f"sum(bytes) AS bytes, max(requests) AS busiest, top_endpoint FROM {source} "
            f"WHERE {type_sql} AND bucket_start >= ? AND bucket_start < ?{search} GROUP BY client_key",
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
        pieces.append((table, cursor, hi))
        cursor = hi
    rows_out = []
    for item in acc.values():
        item.pop("_busiest", None)
        item["refused_pct"] = round(item["refused"] * 100.0 / item["requests"], 2) if item["requests"] else None
        rows_out.append(item)
    return rows_out, pieces


def client_rows_sync(
    conn: sqlite3.Connection, window: Window, client_type: str, *, limit: int | None = None
) -> list[dict[str, Any]]:
    """Every client of a type in the window with the totals of `client_table_sync` (no Rate1/5/60 and no extras),
    busiest first, at most `limit`: one read for a caller that needs them all (the insights rules; paging through
    `client_table_sync` re-ran the whole aggregate and a rates read for every page of 250, 3.2 s of a day's
    evaluation at 2,000 addresses, gaps_insights G7)."""
    if client_type not in ("ip", "place"):
        raise ValueError("client_type must be 'ip' or 'place'")
    rows, _pieces = _client_totals(conn, window, client_type)
    ordered = ordered_rows(rows, "requests")
    return ordered if limit is None else ordered[: max(0, int(limit))]


def client_table_sync(
    conn: sqlite3.Connection,
    window: Window,
    client_type: str,
    *,
    now: float,
    page: Page | None = None,
    extras: bool = False,
) -> dict[str, Any]:
    """The Clients page table for `ip` or `place`: totals in the window plus Rate1/5/60 (plan 14.1, row 73).

    With `extras` (the Clients page and its export), v1's Callers and Top Talkers columns too (finding parity-7):
    `last_seen` is the start of the newest bucket with a request in the window (the minute for recent traffic; the
    hour or day where only compacted rows remain), and `peers` the distinct places one IP called as, or the distinct
    IPs one place was called from, in the window (`read_client_extras.peer_counts`, from the `pair` client rows;
    None for the folded `other` row). Callers that only need the numbers (insights, health, the Overview, the LLM
    export) leave it off and pay nothing for them. Sorting by `last_seen` reads it for every row either way.
    """
    if client_type not in ("ip", "place"):
        raise ValueError("client_type must be 'ip' or 'place'")
    page = page or Page(sort="requests")
    if page.size not in PAGE_SIZES or page.sort not in CLIENT_SORTABLE:
        raise ValueError("invalid page size or sort key")
    rows_out, pieces = _client_totals(conn, window, client_type, page.search)
    needs_rates = page.sort in ("rate1", "rate5", "rate60")
    if needs_rates:
        _attach_rates(conn, client_type, rows_out, now)
    if page.sort == "last_seen":
        read_client_extras.attach_last_seen(conn, client_type, rows_out, pieces)
    result = _paged(rows_out, page)
    if not needs_rates:
        _attach_rates(conn, client_type, result["rows"], now)
    if not extras:
        return result
    if page.sort != "last_seen":
        read_client_extras.attach_last_seen(conn, client_type, result["rows"], pieces)
    peers = read_client_extras.peer_counts(conn, client_type, [str(row["key"]) for row in result["rows"]], pieces)
    for row in result["rows"]:
        row["peers"] = peers.get(str(row["key"]), 0) if row["key"] != read_client_extras.OTHER_KEY else None
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


REFUSAL_EVENT_TYPES = "type IN ('refusal', 'failure')"
"""The refusal and failure events (the recorder's `_record_refusal_event`), written exactly as the WHERE term of the
partial indexes `events_refusal_sources` and `events_refusal_clients` (metrics migration 0009): SQLite uses a partial
index only for a query that repeats its WHERE term."""

LOOSE_SCAN_MAX_KEYS = 4096
"""How many distinct clients of one reason `_reason_clients` counts by index seeks (two per client, whatever the
window) before it reads the reason's whole range of `events_refusal_clients` in order instead (bounded by the events
cap). A bound on work, not a tuning knob (plan P9)."""


def _reason_where(reason: str | None) -> str:
    """The refusal and failure events of one reason (`reason_code IS NULL` for a row without one), bound as
    `:reason`; every read below goes through the migration 0009 indexes that lead with `reason_code`."""
    return f"{REFUSAL_EVENT_TYPES} AND " + ("reason_code IS NULL" if reason is None else "reason_code = :reason")


def _event_reasons(conn: sqlite3.Connection) -> list[str | None]:
    """Every reason of the kept refusal and failure events, in SQLite's order (None first when a row has none): one
    index seek per reason (`events_refusal_sources`), never a scan of the events."""
    found: list[str | None] = []
    if conn.execute(f"SELECT 1 FROM events WHERE {_reason_where(None)} LIMIT 1").fetchone() is not None:  # noqa: S608
        found.append(None)
    where = f"{REFUSAL_EVENT_TYPES} AND reason_code > :after"
    value = conn.execute(f"SELECT min(reason_code) FROM events WHERE {REFUSAL_EVENT_TYPES}").fetchone()[0]  # noqa: S608
    while value is not None:
        found.append(str(value))
        value = conn.execute(f"SELECT min(reason_code) FROM events WHERE {where}", {"after": value}).fetchone()[0]  # noqa: S608
    return found


@dataclass(slots=True)
class _ReasonEvents:
    """One reason's refusal and failure events in a window: `{message source: count}` (a folded row counts as many
    occurrences as it stands for), the oldest and newest event time (None without an event in the window), and the
    stored source values that have an event in the window (`raw_sources`, for `_newest_per_reason`)."""

    sources: dict[str, int]
    first_ms: int | None = None
    last_ms: int | None = None
    raw_sources: list[Any] = field(default_factory=list)


def _reason_events(conn: sqlite3.Connection, reason: str | None, start_ms: int, end_ms: int) -> _ReasonEvents:
    """The message sources of one reason in `[start_ms, end_ms)`, read from `events_refusal_sources`: every source
    the reason has in the kept events (a loose index scan, one seek each), then one index range per source, so the
    cost is the window's index entries of that reason and never a JSON parse (plan 6.7). The same numbers as grouping
    the window's events by `coalesce(json_extract(detail_json, '$.message_source'), '')` and summing
    `coalesce(json_extract(detail_json, '$.count'), 1)`: the generated columns are those expressions."""
    where = _reason_where(reason)
    bound: dict[str, Any] = {"reason": reason, "lo": int(start_ms), "hi": int(end_ms)}
    out = _ReasonEvents({})
    source = conn.execute(f"SELECT min(detail_message_source) FROM events WHERE {where}", bound).fetchone()[0]  # noqa: S608
    while source is not None:
        row = conn.execute(
            f"SELECT sum(detail_count), min(at_ms), max(at_ms) FROM events WHERE {where} "  # noqa: S608 (constants)
            "AND detail_message_source = :source AND at_ms >= :lo AND at_ms < :hi",
            {**bound, "source": source},
        ).fetchone()
        if row[1] is not None:
            out.raw_sources.append(source)
            key = str(source) or "unknown"
            out.sources[key] = out.sources.get(key, 0) + int(row[0] or 0)
            out.first_ms = int(row[1]) if out.first_ms is None else min(out.first_ms, int(row[1]))
            out.last_ms = int(row[2]) if out.last_ms is None else max(out.last_ms, int(row[2]))
        source = conn.execute(
            f"SELECT min(detail_message_source) FROM events WHERE {where} AND detail_message_source > :source",  # noqa: S608
            {**bound, "source": source},
        ).fetchone()[0]
    return out


def _reason_clients(conn: sqlite3.Connection, reason: str | None, start_ms: int, end_ms: int) -> tuple[int, int]:
    """`(distinct client hashes, unattributed count)` of one reason's events in `[start_ms, end_ms)`, from
    `events_refusal_clients` (reason, client hash, time).

    Distinct clients: a loose index scan walks the reason's distinct hashes (one seek each) and asks the index whether
    each has an event in the window (one seek each), so a 24 hour and a 90 day window cost the same; past
    `LOOSE_SCAN_MAX_KEYS` hashes it reads the reason's index range in hash order instead, which counts distinct values
    without sorting. Either way the answer is `count(DISTINCT ip_hash)` over the window's events. The unattributed
    count (folded rows, which lost their client) is one index range of the NULL hashes."""
    where = _reason_where(reason)
    bound: dict[str, Any] = {"reason": reason, "lo": int(start_ms), "hi": int(end_ms), "cap": LOOSE_SCAN_MAX_KEYS}
    row = conn.execute(
        "WITH RECURSIVE k(ip, n) AS ("  # noqa: S608 (constants)
        f" SELECT (SELECT min(ip_hash) FROM events WHERE {where}), 0"
        f" UNION ALL SELECT (SELECT min(ip_hash) FROM events WHERE {where} AND ip_hash > k.ip), k.n + 1"
        " FROM k WHERE k.ip IS NOT NULL AND k.n < :cap)"
        " SELECT coalesce(sum(CASE WHEN k.ip IS NOT NULL AND EXISTS (SELECT 1 FROM events"
        f" WHERE {where} AND ip_hash = k.ip AND at_ms >= :lo AND at_ms < :hi) THEN 1 ELSE 0 END), 0),"
        " max(k.ip IS NULL) FROM k",
        bound,
    ).fetchone()
    clients = int(row[0])
    if not row[1]:  # more distinct clients than the seek budget: one ordered pass over the reason's range
        clients = int(
            conn.execute(
                f"SELECT count(DISTINCT ip_hash) FROM events INDEXED BY events_refusal_clients WHERE {where} "  # noqa: S608
                "AND ip_hash IS NOT NULL AND at_ms >= :lo AND at_ms < :hi",
                bound,
            ).fetchone()[0]
        )
    unattributed = conn.execute(
        f"SELECT sum(detail_count) FROM events WHERE {where} AND ip_hash IS NULL "  # noqa: S608 (constants)
        "AND at_ms >= :lo AND at_ms < :hi",
        bound,
    ).fetchone()[0]
    return clients, int(unattributed or 0)


def _newest_per_reason(
    conn: sqlite3.Connection, path: str, window: Window, found: Mapping[str, _ReasonEvents]
) -> dict[str, Any]:
    """`{reason: value}`: the detail field `path` of the newest refusal or failure event of each reason that has it.

    `found` holds each reason's events in the window (`_reason_events`: its newest time and its message sources).
    Each source of the reason is walked newest first through `events_refusal_sources` (only that reason's rows,
    whatever their type), starting at the reason's newest time, so the read stops at the first event that has the
    field; the newest of the sources' answers by `(at_ms, id)` is the reason's. Walking the `(type, at_ms)` index
    instead read every event of the other type for a reason that has only one (a failure reason looked for among the
    refusals): 2 s per field over 90 days at plan 6.6's volume (plan 6.7).
    """
    out: dict[str, Any] = {}
    for reason, events in found.items():
        if events.last_ms is None:
            continue
        best: sqlite3.Row | None = None
        for source in events.raw_sources:
            row = conn.execute(
                "SELECT at_ms, id, json_extract(detail_json, :path) AS v FROM events "  # noqa: S608 (constants)
                f"WHERE {_reason_where(reason)} AND detail_message_source = :source AND at_ms >= :lo AND at_ms <= :hi "
                "AND json_extract(detail_json, :path) IS NOT NULL ORDER BY at_ms DESC, id DESC LIMIT 1",
                {
                    "path": path,
                    "reason": reason,
                    "source": source,
                    "lo": window.start * 1000,
                    "hi": min(events.last_ms, window.end * 1000 - 1),
                },
            ).fetchone()
            if row is not None and (best is None or (row["at_ms"], row["id"]) > (best["at_ms"], best["id"])):
                best = row
        if best is not None:
            out[reason] = best["v"]
    return out


def refusal_reasons(conn: sqlite3.Connection, window: Window) -> list[dict[str, Any]]:
    """Refusals and failures by reason code (exact, from rollups) with the custom versus default message split
    (row 116, from refusal events; aggregated rows carry their count), plus v1's Refusal Reasons columns (plan
    14.1 row 10, parity row 72, finding parity-3), read from the same events:

    - `last_status` and `last_path`: the newest event's status and path (the path is caller text: show it escaped);
    - `clients`: distinct client hashes; a lower bound when `unattributed` > 0 (refusals past the recorder's event
      budget are summed per minute without the client);
    - `first_ms` and `last_ms`: the oldest and newest event (a summed row carries its minute's start).

    These are None or 0 for a reason whose events were already pruned (`retention_events_days`) while its counts
    remain in the rollups.

    The event columns are read per listed reason through the migration 0009 indexes (`_reason_events`,
    `_reason_clients`): no JSON is parsed and no window is sorted, so 90 days cost about what a day did (plan 6.7; it
    parsed every event of the window four ways, 7 s over 90 days at plan 6.6's volume). The numbers are the ones
    grouping the window's events gave (`tests/unit/metrics/test_metrics_event_facts.py` compares them).
    """
    data = collect(conn, window, filters={"outcome": ["refused", "failed"]}, group_by="reason_code", bucketed=False)
    start_ms, end_ms = window.start * 1000, window.end * 1000
    events: dict[str, _ReasonEvents] = {}
    clients: dict[str, tuple[int, int]] = {}
    for (_b, reason), _totals in data.items():
        name = str(reason)
        found = _reason_events(conn, name, start_ms, end_ms)
        events[name] = found
        if found.last_ms is not None:  # no event of the reason in the window: no client to count
            clients[name] = _reason_clients(conn, name, start_ms, end_ms)
    statuses = _newest_per_reason(conn, "$.status", window, events)
    paths = _newest_per_reason(conn, "$.path", window, events)
    out = []
    for (_b, reason), totals in data.items():
        name = str(reason)
        found = events[name]
        status = statuses.get(name)
        counted, unattributed = clients.get(name, (0, 0))
        out.append(
            {
                "reason": reason,
                "requests": totals.values["requests"],
                "message_source": found.sources,
                "last_status": int(status) if isinstance(status, int | float) else None,
                "last_path": str(paths[name])[:200] if paths.get(name) is not None else None,
                "clients": counted,
                "unattributed": unattributed,
                "first_ms": found.first_ms,
                "last_ms": found.last_ms,
            }
        )
    out.sort(key=lambda r: -r["requests"])
    return out


def message_source_split(
    conn: sqlite3.Connection, window: Window, reasons: Iterable[str | None] | None = None
) -> dict[str, dict[str, int]]:
    """`{reason: {message source: count}}`: whose words the refused and failed callers of the window got (row 116;
    `custom`, `default`, `roxy`, `roblox`, or `unknown` for rows that do not say), from the refusal and failure
    events (a summed row carries its count). The `message_source` column of `refusal_reasons`. `reasons` limits it
    to those reasons (every reason of the kept events when None); a reason without an event in the window is left
    out. Read through `events_refusal_sources` (`_reason_events`)."""
    names = _event_reasons(conn) if reasons is None else list(dict.fromkeys(reasons))
    split: dict[str, dict[str, int]] = {}
    for reason in names:
        found = _reason_events(conn, reason, window.start * 1000, window.end * 1000)
        if found.last_ms is not None:
            split[str(reason)] = found.sources
    return split


def returned_reasons(conn: sqlite3.Connection, window: Window) -> dict[str, int]:
    """`{message source: count}` over every reason `refusal_reasons` lists (v1's "Returned Reasons", row 22): the
    same numbers as summing that table's `message_source` column, read with `message_source_split` for exactly
    those reasons and none of the table's other reads (the Upstream retries card needs only this)."""
    reasons = collect(
        conn, window, filters={"outcome": ["refused", "failed"]}, group_by="reason_code", bucketed=False,
        measures=("requests",), hists=(),
    )  # fmt: skip
    listed = sorted({str(reason) for (_b, reason) in reasons})
    out: dict[str, int] = {}
    for sources in message_source_split(conn, window, listed).values():
        for source, count in sources.items():
            out[source] = out.get(source, 0) + int(count)
    return out


def reason_counts(conn: sqlite3.Connection, window: Window, reasons: Iterable[str]) -> dict[str, dict[str, Any]]:
    """`{reason: {requests, last_ms}}` for some refusal or failure reasons: the `requests` and `last_ms` columns
    `refusal_reasons` gives them (the Protection limit cards show only these two numbers for one or two reasons).

    `requests` comes from the rollups as there. `last_ms`, the newest event of the reason in the window, is one
    index seek per message source of the reason (`_reason_last_ms`, `events_refusal_sources`), whatever the window
    (plan 6.7).
    """
    wanted = sorted({str(reason) for reason in reasons})
    if not wanted:
        return {}
    data = collect(
        conn, window, filters={"outcome": ["refused", "failed"], "reason_code": wanted}, group_by="reason_code",
        bucketed=False, measures=("requests",), hists=(),
    )  # fmt: skip
    start_ms, end_ms = window.start * 1000, window.end * 1000
    out: dict[str, dict[str, Any]] = {}
    for (_b, reason), totals in data.items():
        name = str(reason)
        out[name] = {"requests": totals.values["requests"], "last_ms": _reason_last_ms(conn, name, start_ms, end_ms)}
    return out


def _reason_last_ms(conn: sqlite3.Connection, reason: str, start_ms: int, end_ms: int) -> int | None:
    """The newest refusal or failure event time of one reason in `[start_ms, end_ms)`: for each message source the
    reason has (a loose scan), the last index entry before the end (`events_refusal_sources` ends in time)."""
    where = _reason_where(reason)
    bound: dict[str, Any] = {"reason": reason, "lo": int(start_ms), "hi": int(end_ms)}
    newest: int | None = None
    source = conn.execute(f"SELECT min(detail_message_source) FROM events WHERE {where}", bound).fetchone()[0]  # noqa: S608
    while source is not None:
        last = conn.execute(
            f"SELECT max(at_ms) FROM events WHERE {where} AND detail_message_source = :source "  # noqa: S608
            "AND at_ms >= :lo AND at_ms < :hi",
            {**bound, "source": source},
        ).fetchone()[0]
        if last is not None:
            newest = int(last) if newest is None else max(newest, int(last))
        source = conn.execute(
            f"SELECT min(detail_message_source) FROM events WHERE {where} AND detail_message_source > :source",  # noqa: S608
            {**bound, "source": source},
        ).fetchone()[0]
    return newest


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
