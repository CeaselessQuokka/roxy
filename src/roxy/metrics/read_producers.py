"""Read models for the producer history: rule hits per minute, tarpit holds, bot scores, metrics drops, disk growth.

What this is
    Plain functions over a metrics.db connection (run them inside `Database.read`) for the schema version 5 tables
    (`storage/migrations/metrics/0005_producer_history.sql`):
      * `rule_hit_counts`, `rule_hit_series`: hits per rule row in a window, and one rule's minutes (plan 10.9
        per-rule hit counts, FILTER-REMOVE "hit history").
      * `tarpit_summary`: holds, skips, eligible refusals, mean and p95 hold, arrival gaps after a hold and after an
        instant refusal, in total and by category (parity row 78, TARPIT-TUNE, the Protection > Tarpit card).
      * `client_scores`, `client_score_history`: the latest recorded bot score per client address, and one client's
        hours (ABUSE-BOT, THROTTLE-TUNE, ABUSE-DIST, the Clients drill-down).
      * `pipeline_drops`: metrics items dropped by every worker in a window, and by worker (SYS-METRICS-DROP, System
        > Metrics pipeline).
      * `disk_growth`, `latest_disk_sample`, `latest_table_sizes`, `rollup_rows_avg`: Roxy's storage over time, the
        latest table sizes and the minute rollup rows written per minute (SYS-DISK, the Data page projection).

Why it exists
    DESIGN.md section 13: read models live next to their data, so the insights providers, the admin API and the
    LLM export read one definition of each number (principle P6). The recorder (`metrics/producers.py`) and the
    disk sampler (`metrics/disk_history.py`) are the writers; this module is the reader.

How it works
    Every time is Unix seconds and every window half open `[start, end)`. Minute and hour tables are summed with one
    indexed range read. Results are small dicts and lists bounded by `MAX_ROWS` (plan P9). Percentiles come from the
    fixed-bucket hold histogram (interpolated inside the bucket, like `metrics/histograms.py`), so they are accurate
    to within one bucket and can be read for any range.

What to read next
    `roxy/insights/context.py` (`DefaultProviders`, which turns these into the provider seams the rules read), then
    `roxy/metrics/producers.py` (the writer).
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping, Sequence
from typing import Any, Final

from roxy.metrics.producers import HOLD_BOUNDS_MS, OVERFLOW_BOUND

MAX_ROWS: Final = 50_000
"""Most rows one read returns (plan P9)."""


def _bounded(limit: int | None) -> int:
    return MAX_ROWS if limit is None else max(1, min(int(limit), MAX_ROWS))


# ------------------------------------------------------------------------------------------------ rule hits


def rule_hit_counts(
    conn: sqlite3.Connection, start: int, end: int, table: str | None = None
) -> dict[tuple[str, str], int]:
    """`{(table_name, rule_key): hits}` in `[start, end)`, for one table or all of them."""
    clause = " AND table_name = ?" if table is not None else ""
    params: list[Any] = [int(start), int(end)]
    if table is not None:
        params.append(table)
    rows = conn.execute(
        "SELECT table_name, rule_key, sum(hits) FROM rule_hit_minute "  # noqa: S608 (fixed text)
        f"WHERE bucket_start >= ? AND bucket_start < ?{clause} GROUP BY table_name, rule_key LIMIT ?",
        (*params, MAX_ROWS),
    ).fetchall()
    return {(str(r[0]), str(r[1])): int(r[2] or 0) for r in rows}


def rule_hit_series(conn: sqlite3.Connection, table: str, key: Any, start: int, end: int) -> list[tuple[int, int]]:
    """`[(minute, hits)]` of one rule row in `[start, end)`, oldest first."""
    rows = conn.execute(
        "SELECT bucket_start, hits FROM rule_hit_minute WHERE table_name = ? AND rule_key = ? "
        "AND bucket_start >= ? AND bucket_start < ? ORDER BY bucket_start LIMIT ?",
        (table, str(key), int(start), int(end), MAX_ROWS),
    ).fetchall()
    return [(int(r[0]), int(r[1] or 0)) for r in rows]


# --------------------------------------------------------------------------------------------------- tarpit


def hold_percentile(counts: Mapping[int, int], q: float) -> float | None:
    """The `q` quantile (0..1) of holds in seconds from `{bound_ms: holds}`, interpolated inside its bucket.

    A quantile that lands in the overflow bucket reports the last bound (55 s, the plan 10.6 hard cap).
    """
    total = sum(max(0, int(n)) for n in counts.values())
    if total <= 0:
        return None
    rank = max(0.0, min(1.0, float(q))) * total
    seen = 0.0
    lower = 0.0
    for bound in (*HOLD_BOUNDS_MS, OVERFLOW_BOUND):
        n = max(0, int(counts.get(bound, 0)))
        if bound == OVERFLOW_BOUND:
            if n and seen + n >= rank:
                return HOLD_BOUNDS_MS[-1] / 1000
            break
        if n and seen + n >= rank:
            share = (rank - seen) / n
            return round((lower + share * (bound - lower)) / 1000, 3)
        seen += n
        lower = float(bound)
    return HOLD_BOUNDS_MS[-1] / 1000


def _tarpit_view(acc: Sequence[float], hist: Mapping[int, int] | None) -> dict[str, Any]:
    holds, skipped = int(acc[0]), int(acc[1])
    eligible = holds + skipped
    gaps_hold, gaps_instant = int(acc[4]), int(acc[6])
    return {
        "eligible": eligible,
        "holds": holds,
        "skipped": skipped,
        "skipped_pct": round(skipped * 100.0 / eligible, 2) if eligible else None,
        "mean_hold_s": round(float(acc[2]) / holds, 3) if holds else None,
        "p95_hold_s": hold_percentile(hist, 0.95) if hist else None,
        "max_hold_s": round(float(acc[3]), 3),
        "gaps_after_hold": gaps_hold,
        "gap_after_hold_s": round(float(acc[5]) / gaps_hold, 3) if gaps_hold else None,
        "gaps_after_instant": gaps_instant,
        "gap_after_instant_s": round(float(acc[7]) / gaps_instant, 3) if gaps_instant else None,
    }


def tarpit_summary(conn: sqlite3.Connection, start: int, end: int) -> dict[str, Any]:
    """Tarpit statistics of `[start, end)` fleet-wide: totals, by category and by hold type (module docstring)."""
    rows = conn.execute(
        "SELECT category, kind, sum(holds), sum(skipped), sum(held_s_sum), max(held_s_max), sum(gaps_after_hold), "
        "sum(gap_after_hold_s_sum), sum(gaps_after_instant), sum(gap_after_instant_s_sum) FROM tarpit_minute "
        "WHERE bucket_start >= ? AND bucket_start < ? GROUP BY category, kind LIMIT ?",
        (int(start), int(end), MAX_ROWS),
    ).fetchall()
    hist_rows = conn.execute(
        "SELECT category, bound_ms, sum(holds) FROM tarpit_hold_minute WHERE bucket_start >= ? AND bucket_start < ? "
        "GROUP BY category, bound_ms LIMIT ?",
        (int(start), int(end), MAX_ROWS),
    ).fetchall()
    total = [0.0] * 8
    categories: dict[str, list[float]] = {}
    kinds: dict[str, dict[str, int]] = {}
    for row in rows:
        values = [float(v or 0) for v in row[2:]]
        acc = [values[0], values[1], values[2], values[3], values[4], values[5], values[6], values[7]]
        for target in (total, categories.setdefault(str(row[0]), [0.0] * 8)):
            for i in (0, 1, 2, 4, 5, 6, 7):
                target[i] += acc[i]
            target[3] = max(target[3], acc[3])
        kind = kinds.setdefault(str(row[1]), {"holds": 0, "skipped": 0})
        kind["holds"] += int(acc[0])
        kind["skipped"] += int(acc[1])
    hist_total: dict[int, int] = {}
    hist_by: dict[str, dict[int, int]] = {}
    for category, bound, n in hist_rows:
        hist_total[int(bound)] = hist_total.get(int(bound), 0) + int(n or 0)
        per = hist_by.setdefault(str(category), {})
        per[int(bound)] = per.get(int(bound), 0) + int(n or 0)
    summary = _tarpit_view(total, hist_total)
    summary["by_category"] = {name: _tarpit_view(acc, hist_by.get(name)) for name, acc in sorted(categories.items())}
    summary["by_kind"] = dict(sorted(kinds.items()))
    summary["hold_histogram"] = [
        {"le_ms": bound, "holds": hist_total.get(bound, 0)} for bound in (*HOLD_BOUNDS_MS, OVERFLOW_BOUND)
    ]
    summary["window"] = {"from": int(start), "to": int(end)}
    return summary


# ------------------------------------------------------------------------------------------------ bot scores


def client_scores(conn: sqlite3.Connection, since: int, *, limit: int | None = None) -> dict[str, int]:
    """`{client address: score}`: for each client seen since `since`, the largest score of its latest hour."""
    rows = conn.execute(
        "SELECT client_key, score_max FROM client_score_hour WHERE bucket_start >= ? "
        "ORDER BY bucket_start DESC LIMIT ?",
        (int(since), _bounded(limit)),
    ).fetchall()
    out: dict[str, int] = {}
    for key, value in rows:  # newest hour first: the first row seen of a client is its latest hour
        out.setdefault(str(key), int(value))
    return out


def client_score_history(
    conn: sqlite3.Connection, client_key: str, since: int, *, limit: int | None = None
) -> list[dict[str, Any]]:
    """One client's recorded hours since `since`, oldest first."""
    rows = conn.execute(
        "SELECT bucket_start, score_max, score_last, last_at, samples FROM client_score_hour "
        "WHERE client_key = ? AND bucket_start >= ? ORDER BY bucket_start LIMIT ?",
        (str(client_key), int(since), _bounded(limit)),
    ).fetchall()
    return [dict(r) for r in rows]


# ------------------------------------------------------------------------------------------- metrics drops


def pipeline_drops(conn: sqlite3.Connection, start: int, end: int) -> dict[str, Any]:
    """Items every worker dropped in `[start, end)`: totals, per worker, and how many minutes had drops."""
    rows = conn.execute(
        "SELECT worker_id, sum(dropped), sum(history_dropped), sum(capture_dropped), count(*) "
        "FROM metrics_pipeline_minute WHERE bucket_start >= ? AND bucket_start < ? GROUP BY worker_id LIMIT ?",
        (int(start), int(end), MAX_ROWS),
    ).fetchall()
    workers = {
        str(r[0]): {"dropped": int(r[1] or 0), "history_dropped": int(r[2] or 0), "capture_dropped": int(r[3] or 0)}
        for r in rows
    }
    return {
        "dropped": sum(w["dropped"] for w in workers.values()),
        "history_dropped": sum(w["history_dropped"] for w in workers.values()),
        "capture_dropped": sum(w["capture_dropped"] for w in workers.values()),
        "minutes_with_drops": sum(int(r[4] or 0) for r in rows),
        "workers": workers,
        "window": {"from": int(start), "to": int(end)},
    }


# ------------------------------------------------------------------------------------------------ disk


def _files(text: Any) -> dict[str, Any]:
    try:
        value = json.loads(text) if text else {}
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def disk_growth(conn: sqlite3.Connection, since: int, *, limit: int | None = None) -> list[dict[str, Any]]:
    """Disk samples since `since`, oldest first: `{at, total_bytes (Roxy's storage), disk_total_bytes,
    free_bytes}`. `total_bytes` is the storage figure SYS-DISK projects (the fixture README `growth` shape)."""
    rows = conn.execute(
        "SELECT at, storage_bytes, total_bytes, free_bytes FROM disk_samples WHERE at >= ? ORDER BY at LIMIT ?",
        (int(since), _bounded(limit)),
    ).fetchall()
    return [
        {
            "at": int(r[0]),
            "total_bytes": int(r[1] or 0),
            "disk_total_bytes": int(r[2] or 0),
            "free_bytes": int(r[3] or 0),
        }
        for r in rows
    ]


def latest_disk_sample(conn: sqlite3.Connection) -> dict[str, Any] | None:
    """The newest disk sample with its per-file sizes, or None."""
    row = conn.execute(
        "SELECT at, total_bytes, free_bytes, storage_bytes, files_json, rollup_rows_per_min FROM disk_samples "
        "ORDER BY at DESC LIMIT 1"
    ).fetchone()
    if row is None:
        return None
    out = dict(row)
    out["files"] = _files(out.pop("files_json", None))
    return out


def latest_table_sizes(conn: sqlite3.Connection) -> dict[str, Any]:
    """`{"at": sample time or None, "tables": {"<db>.<table>": bytes}}` from the newest table size sample."""
    row = conn.execute("SELECT max(at) FROM table_size_samples").fetchone()
    at = None if row is None or row[0] is None else int(row[0])
    if at is None:
        return {"at": None, "tables": {}}
    rows = conn.execute(
        "SELECT db, table_name, bytes FROM table_size_samples WHERE at = ? ORDER BY bytes DESC LIMIT ?",
        (at, MAX_ROWS),
    ).fetchall()
    return {"at": at, "tables": {f"{r[0]}.{r[1]}": int(r[2] or 0) for r in rows}}


def table_growth(
    conn: sqlite3.Connection, db: str, table: str, since: int, *, limit: int | None = None
) -> list[tuple[int, int]]:
    """`[(at, bytes)]` of one table's samples since `since`, oldest first (the Data page growth line)."""
    rows = conn.execute(
        "SELECT at, bytes FROM table_size_samples WHERE db = ? AND table_name = ? AND at >= ? ORDER BY at LIMIT ?",
        (db, table, int(since), _bounded(limit)),
    ).fetchall()
    return [(int(r[0]), int(r[1] or 0)) for r in rows]


def rollup_rows_avg(conn: sqlite3.Connection, since: int) -> float | None:
    """The mean of the samples' minute rollup rows written per minute since `since` (None without samples)."""
    row = conn.execute(
        "SELECT avg(rollup_rows_per_min), count(rollup_rows_per_min) FROM disk_samples WHERE at >= ?", (int(since),)
    ).fetchone()
    if row is None or not row[1]:
        return None
    return round(float(row[0]), 2)


__all__ = [
    "MAX_ROWS",
    "client_score_history",
    "client_scores",
    "disk_growth",
    "hold_percentile",
    "latest_disk_sample",
    "latest_table_sizes",
    "pipeline_drops",
    "rollup_rows_avg",
    "rule_hit_counts",
    "rule_hit_series",
    "table_growth",
    "tarpit_summary",
]
