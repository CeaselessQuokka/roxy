"""Read models for the insight history tables: bucket fill, worker samples, cache evictions, rule hits, errors.

What this is
    Plain functions over a metrics.db connection (run them inside `Database.read`) that answer the questions the
    recommendation rules ask of the schema version 2 tables (`storage/migrations/metrics/0002_insight_history.sql`):
    bucket attempts, rejections and fill peaks (`bucket_summary`, `bucket_history`), worker CPU and loop lag per
    minute (`worker_history`), shared cache stores and evictions (`cache_summary`, `eviction_passes`), when rule rows
    last matched (`rule_hits`), error occurrences (`error_counts`, `error_series`), upstream calls by attempt
    (`attempt_rows`), the admin-entered provider byte figure (`latest_provider_report`), plus `events_between` for
    the event types the rules read (breaker openings, credential probes, spam detections, logins), the version 1
    reads the rules need with groupings `metrics/queries.py` does not offer (`roblox_429_counts` per template, egress
    and minute, `upstream_429_rows`, `samples_between`, `latest_health_run`, `anomalies_between`, `heartbeats`),
    and `prune_history`, the retention step for the version 2 tables.

Why it exists
    DESIGN.md section 13: read models live next to their data, so the dashboard, the LLM export and the insights
    engine read one definition of each number (P6). The recorder writes these tables (`metrics/recorder.py`, batch
    kind `metrics.insight_history`); this module is the only reader.

How it works
    Every time argument is Unix seconds and every window is half open `[start, end)`. Minute tables are summed with
    one indexed range read; results are small dicts and lists, bounded by `limit` arguments (plan P9).

What to read next
    `roxy/metrics/recorder.py` (the writers), `roxy/insights/context.py` (how rules reach these functions).
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from typing import Any, Final

MAX_ROWS: Final = 50_000
"""Most rows one history read returns (a bound, plan P9; minute tables of one week stay far below it)."""


def _bounded(limit: int | None) -> int:
    return MAX_ROWS if limit is None else max(1, min(int(limit), MAX_ROWS))


# ----------------------------------------------------------------------------------------------- buckets


def bucket_summary(
    conn: sqlite3.Connection, start: int, end: int, keys: Iterable[str] | None = None
) -> dict[str, dict[str, float]]:
    """`{bucket_key: {attempts, rejections, fill_pct_peak, minutes}}` summed over `[start, end)`."""
    wanted = sorted(set(keys)) if keys is not None else []
    clause = ""
    params: list[Any] = [int(start), int(end)]
    if wanted:
        clause = f" AND bucket_key IN ({', '.join('?' for _ in wanted)})"
        params += wanted
    rows = conn.execute(
        "SELECT bucket_key, sum(attempts) AS a, sum(rejections) AS r, max(fill_pct_peak) AS p, count(*) AS m "  # noqa: S608
        f"FROM bucket_minute WHERE bucket_start >= ? AND bucket_start < ?{clause} GROUP BY bucket_key",
        params,
    ).fetchall()
    return {
        str(r["bucket_key"]): {
            "attempts": int(r["a"] or 0),
            "rejections": int(r["r"] or 0),
            "fill_pct_peak": float(r["p"] or 0.0),
            "minutes": int(r["m"] or 0),
        }
        for r in rows
    }


def bucket_history(conn: sqlite3.Connection, bucket_key: str, start: int, end: int) -> list[dict[str, Any]]:
    """One bucket's minutes in `[start, end)`, oldest first."""
    rows = conn.execute(
        "SELECT bucket_start, attempts, rejections, fill_pct_peak FROM bucket_minute "
        "WHERE bucket_key = ? AND bucket_start >= ? AND bucket_start < ? ORDER BY bucket_start LIMIT ?",
        (bucket_key, int(start), int(end), MAX_ROWS),
    ).fetchall()
    return [dict(r) for r in rows]


# ----------------------------------------------------------------------------------------------- workers


def worker_history(conn: sqlite3.Connection, start: int, end: int) -> dict[str, list[dict[str, Any]]]:
    """`{worker_id: [{bucket_start, cpu_pct, cpu_pct_max, loop_lag_ms_p99, open_conns, rss}]}`, oldest first."""
    rows = conn.execute(
        "SELECT bucket_start, worker_id, samples, cpu_pct_sum, cpu_pct_max, loop_lag_ms_p99, open_conns, rss "
        "FROM worker_minute WHERE bucket_start >= ? AND bucket_start < ? ORDER BY bucket_start LIMIT ?",
        (int(start), int(end), MAX_ROWS),
    ).fetchall()
    out: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        samples = int(r["samples"] or 0)
        out.setdefault(str(r["worker_id"]), []).append(
            {
                "bucket_start": int(r["bucket_start"]),
                "cpu_pct": (float(r["cpu_pct_sum"]) / samples) if samples else None,
                "cpu_pct_max": r["cpu_pct_max"],
                "loop_lag_ms_p99": r["loop_lag_ms_p99"],
                "open_conns": r["open_conns"],
                "rss": r["rss"],
            }
        )
    return out


# ------------------------------------------------------------------------------------------------- cache


def cache_summary(conn: sqlite3.Connection, start: int, end: int) -> dict[str, Any]:
    """Stores, evictions, young evictions and mean eviction ages in `[start, end)`."""
    row = conn.execute(
        "SELECT sum(stores), sum(evictions), sum(young_evictions), sum(evicted_age_s_sum), sum(young_age_s_sum) "
        "FROM cache_minute WHERE bucket_start >= ? AND bucket_start < ?",
        (int(start), int(end)),
    ).fetchone()
    stores, evictions, young, age_sum, young_age_sum = (float(v or 0) for v in row)
    return {
        "stores": int(stores),
        "evictions": int(evictions),
        "young_evictions": int(young),
        "mean_eviction_age_s": round(age_sum / evictions, 1) if evictions else None,
        "mean_young_age_s": round(young_age_sum / young, 1) if young else None,
    }


def eviction_passes(conn: sqlite3.Connection, start: int, end: int, limit: int | None = None) -> list[dict[str, Any]]:
    """Eviction passes in `[start, end)`, oldest first."""
    rows = conn.execute(
        "SELECT at, entries_before, bytes_before, evicted, freed_bytes FROM cache_eviction_passes "
        "WHERE at >= ? AND at < ? ORDER BY at LIMIT ?",
        (int(start), int(end), _bounded(limit)),
    ).fetchall()
    return [dict(r) for r in rows]


# ------------------------------------------------------------------------------------------------- rules


def rule_hits(conn: sqlite3.Connection, table: str | None = None) -> dict[tuple[str, str], dict[str, int | None]]:
    """`{(table_name, rule_key): {hits, first_hit_at, last_hit_at}}` for one table or all of them."""
    if table is None:
        rows = conn.execute(
            "SELECT table_name, rule_key, hits, first_hit_at, last_hit_at FROM rule_hits LIMIT ?", (MAX_ROWS,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT table_name, rule_key, hits, first_hit_at, last_hit_at FROM rule_hits WHERE table_name = ? LIMIT ?",
            (table, MAX_ROWS),
        ).fetchall()
    return {
        (str(r["table_name"]), str(r["rule_key"])): {
            "hits": int(r["hits"] or 0),
            "first_hit_at": r["first_hit_at"],
            "last_hit_at": r["last_hit_at"],
        }
        for r in rows
    }


# ------------------------------------------------------------------------------------------------ errors


def error_signatures(conn: sqlite3.Connection, limit: int = 2000) -> list[dict[str, Any]]:
    """Every row of the `errors` table (signature summaries), newest first."""
    rows = conn.execute(
        "SELECT signature, count, first_seen, last_seen, source, last_detail, module_line, traceback_redacted "
        "FROM errors ORDER BY last_seen DESC LIMIT ?",
        (max(1, min(int(limit), MAX_ROWS)),),
    ).fetchall()
    return [dict(r) for r in rows]


def error_counts(conn: sqlite3.Connection, start: int, end: int) -> dict[str, int]:
    """`{signature: occurrences}` in `[start, end)`."""
    rows = conn.execute(
        "SELECT signature, sum(count) AS n FROM error_minute WHERE bucket_start >= ? AND bucket_start < ? "
        "GROUP BY signature",
        (int(start), int(end)),
    ).fetchall()
    return {str(r["signature"]): int(r["n"] or 0) for r in rows}


def error_series(conn: sqlite3.Connection, signature: str, start: int, end: int) -> list[tuple[int, int]]:
    """`[(minute, count)]` of one signature in `[start, end)`, oldest first."""
    rows = conn.execute(
        "SELECT bucket_start, count FROM error_minute WHERE signature = ? AND bucket_start >= ? AND bucket_start < ? "
        "ORDER BY bucket_start LIMIT ?",
        (signature, int(start), int(end), MAX_ROWS),
    ).fetchall()
    return [(int(r[0]), int(r[1])) for r in rows]


# -------------------------------------------------------------------------------------------- attempts


def attempt_rows(conn: sqlite3.Connection, start: int, end: int, template: str | None = None) -> list[dict[str, Any]]:
    """Upstream calls by attempt in `[start, end)`, summed over minutes (one row per distinct attempt shape)."""
    clause = " AND endpoint_template = ?" if template is not None else ""
    params: list[Any] = [int(start), int(end)]
    if template is not None:
        params.append(template)
    rows = conn.execute(
        "SELECT endpoint_template, egress, attempt, kind, status, challenge, html_body, exit_id, sum(count) AS n "  # noqa: S608
        f"FROM upstream_attempt_minute WHERE bucket_start >= ? AND bucket_start < ?{clause} "
        "GROUP BY endpoint_template, egress, attempt, kind, status, challenge, html_body, exit_id LIMIT ?",
        (*params, MAX_ROWS),
    ).fetchall()
    out = []
    for r in rows:
        item = dict(r)
        item["status"] = None if int(item["status"]) < 0 else int(item["status"])
        item["challenge"] = bool(item["challenge"])
        item["html_body"] = bool(item["html_body"])
        item["count"] = int(item.pop("n") or 0)
        out.append(item)
    return out


# -------------------------------------------------------------------------------------------- provider


def latest_provider_report(conn: sqlite3.Connection) -> dict[str, Any] | None:
    """The newest admin-entered provider byte figure, or None."""
    row = conn.execute(
        "SELECT at, reported_bytes, entered_by FROM egress_provider_reports ORDER BY at DESC, id DESC LIMIT 1"
    ).fetchone()
    return dict(row) if row is not None else None


# ---------------------------------------------------------------------------------------------- events


def events_between(
    conn: sqlite3.Connection, types: Iterable[str], start: int, end: int, limit: int | None = None
) -> list[dict[str, Any]]:
    """`events` rows of the given types in `[start, end)` seconds, oldest first, `detail` parsed.

    Aggregated rows carry their `count` in the detail (the recorder sums them per minute); `count` is set to 1
    for individual rows so callers can always sum it.
    """
    wanted = sorted(set(types))
    if not wanted:
        return []
    marks = ", ".join("?" for _ in wanted)
    rows = conn.execute(
        f"SELECT id, at_ms, type, severity, reason_code, ip_hash, place, endpoint_template, detail_json FROM events "  # noqa: S608
        f"WHERE type IN ({marks}) AND at_ms >= ? AND at_ms < ? ORDER BY at_ms, id LIMIT ?",
        (*wanted, int(start) * 1000, int(end) * 1000, _bounded(limit)),
    ).fetchall()
    out = []
    for r in rows:
        try:
            detail = json.loads(r["detail_json"]) if r["detail_json"] else {}
        except ValueError:
            detail = {}
        item = dict(r)
        item.pop("detail_json", None)
        item["detail"] = detail if isinstance(detail, dict) else {}
        item["count"] = int(item["detail"].get("count", 1) or 1) if isinstance(item["detail"], dict) else 1
        out.append(item)
    return out


# ------------------------------------------------------------------------------------ 429s and samples

_429_GROUPS: Final[frozenset[str]] = frozenset({"endpoint_template", "host", "egress"})


def roblox_429_counts(
    conn: sqlite3.Connection,
    start: int,
    end: int,
    *,
    group_by: Iterable[str] = ("endpoint_template",),
    per_minute: bool = False,
    where: dict[str, Any] | None = None,
) -> dict[tuple[Any, ...], int]:
    """Roblox 429s from `upstream_429` in `[start, end)`, grouped by any of endpoint_template, host and egress (the
    egress of the attempt that got the 429), and by minute when `per_minute`. Keys are tuples in `group_by` order
    (the minute first when `per_minute`)."""
    groups = [g for g in group_by if g in _429_GROUPS]
    if len(groups) != len(list(group_by)):
        raise ValueError("upstream_429 can be grouped by endpoint_template, host and egress only")
    clauses = ["at_ms >= ?", "at_ms < ?"]
    params: list[Any] = [int(start) * 1000, int(end) * 1000]
    for key, value in (where or {}).items():
        if key not in _429_GROUPS:
            raise ValueError(f"upstream_429 cannot be filtered by {key!r}")
        values = list(value) if isinstance(value, list | tuple | set | frozenset) else [value]
        clauses.append(f"{key} IN ({', '.join('?' for _ in values)})")
        params += [str(v) for v in values]
    columns = (["(at_ms / 60000) * 60"] if per_minute else []) + groups
    select = ", ".join(columns) if columns else "NULL"
    group = f" GROUP BY {', '.join(columns)}" if columns else ""
    rows = conn.execute(
        f"SELECT {select}, count(*) FROM upstream_429 WHERE {' AND '.join(clauses)}{group} LIMIT ?",  # noqa: S608 (fixed names)
        (*params, MAX_ROWS),
    ).fetchall()
    out: dict[tuple[Any, ...], int] = {}
    for row in rows:
        group_key = tuple(row[: len(columns)]) if columns else ()
        out[group_key] = out.get(group_key, 0) + int(row[-1])
    return out


def upstream_429_rows(
    conn: sqlite3.Connection,
    start: int,
    end: int,
    template: str | None = None,
    limit: int | None = None,
    *,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """`upstream_429` rows in `[start, end)` (optionally one template), oldest first (ties by row id, so pages read
    with `offset` never repeat or skip a row; the `upstream_429` export reads it page by page, finding mpjobs-5)."""
    clause = " AND endpoint_template = ?" if template is not None else ""
    params: list[Any] = [int(start) * 1000, int(end) * 1000]
    if template is not None:
        params.append(template)
    rows = conn.execute(
        "SELECT at_ms, endpoint_template, host, egress, retry_after_s, ratelimit_headers_json, request_id "  # noqa: S608
        f"FROM upstream_429 WHERE at_ms >= ? AND at_ms < ?{clause} ORDER BY at_ms, id LIMIT ? OFFSET ?",
        (*params, _bounded(limit), max(0, int(offset))),
    ).fetchall()
    return [dict(r) for r in rows]


def samples_between(
    conn: sqlite3.Connection, start: int, end: int, templates: Iterable[str] | None = None, limit: int | None = None
) -> list[dict[str, Any]]:
    """`request_samples` rows in `[start, end)` seconds (optionally only some templates), in time order."""
    wanted = sorted(set(templates)) if templates is not None else []
    clause = f" AND endpoint_template IN ({', '.join('?' for _ in wanted)})" if wanted else ""
    rows = conn.execute(
        "SELECT id, at_ms, key_id, endpoint_template, method, client_hash, place, cache_state, upstream_status, "  # noqa: S608
        f"egress, body_hash, bytes, auth_class, sample_pct FROM request_samples WHERE at_ms >= ? AND at_ms < ?{clause} "
        "ORDER BY at_ms, id LIMIT ?",
        (int(start) * 1000, int(end) * 1000, *wanted, _bounded(limit)),
    ).fetchall()
    return [dict(r) for r in rows]


def refusal_samples_between(
    conn: sqlite3.Connection, start: int, end: int, limit: int | None = None
) -> list[dict[str, Any]]:
    """`refusal_samples` rows (requests a limiter refused, metrics.db schema 7) in `[start, end)` seconds, in time
    order: the refused part of the stream a limit dry run replays (`insights/simulate.py _limit_replays`)."""
    rows = conn.execute(
        "SELECT id, at_ms, reason, endpoint_template, method, client_hash, place, sample_pct FROM refusal_samples "
        "WHERE at_ms >= ? AND at_ms < ? ORDER BY at_ms, id LIMIT ?",
        (int(start) * 1000, int(end) * 1000, _bounded(limit)),
    ).fetchall()
    return [dict(r) for r in rows]


def latest_health_run(conn: sqlite3.Connection) -> dict[str, Any] | None:
    """The newest Check Proxy Health run with its results, or None."""
    run = conn.execute(
        "SELECT id, started_at, finished_at, trigger, summary, version FROM health_runs "
        "ORDER BY started_at DESC, id DESC LIMIT 1"
    ).fetchone()
    if run is None:
        return None
    results = conn.execute(
        "SELECT check_id, status, value, threshold, explanation, fix_link, duration_ms FROM health_results "
        "WHERE run_id = ? ORDER BY check_id",
        (run["id"],),
    ).fetchall()
    out = dict(run)
    out["results"] = [dict(r) for r in results]
    return out


def anomalies_between(conn: sqlite3.Connection, start: int, end: int, limit: int | None = None) -> list[dict[str, Any]]:
    """`anomalies` rows detected in `[start, end)`, newest first."""
    rows = conn.execute(
        "SELECT id, at, metric, baseline, observed, zscore, window FROM anomalies WHERE at >= ? AND at < ? "
        "ORDER BY at DESC LIMIT ?",
        (int(start), int(end), _bounded(limit)),
    ).fetchall()
    return [dict(r) for r in rows]


def heartbeats(conn: sqlite3.Connection, fresh_after: int) -> list[dict[str, Any]]:
    """`worker_heartbeat` rows seen at or after `fresh_after` (the live fleet)."""
    rows = conn.execute(
        "SELECT * FROM worker_heartbeat WHERE last_seen >= ? ORDER BY pid LIMIT 256", (int(fresh_after),)
    ).fetchall()
    return [dict(r) for r in rows]


# --------------------------------------------------------------------------------------------- retention

HISTORY_TABLES: Final[dict[str, str]] = {
    "bucket_minute": "bucket_start",
    "worker_minute": "bucket_start",
    "cache_minute": "bucket_start",
    "cache_eviction_passes": "at",
    "error_minute": "bucket_start",
    "upstream_attempt_minute": "bucket_start",
    "egress_provider_reports": "at",
}
"""Time-keyed history tables and their time column (rule_hits is keyed by rule, pruned by idle time)."""


def prune_history(
    conn: sqlite3.Connection, now_s: float, keep_days: dict[str, float], *, limit: int = 20_000
) -> dict[str, int]:
    """Delete rows older than each table's `keep_days` entry (at most `limit` rows per table per call).

    `rule_hits` rows whose last hit is older than its `keep_days` entry are deleted too: a rule that has not
    matched for that long reads the same as one that never matched (idle since it was created).
    """
    deleted: dict[str, int] = {}
    for table, column in HISTORY_TABLES.items():
        days = keep_days.get(table)
        if days is None or days <= 0:
            continue
        cutoff = int(now_s - days * 86_400)
        if table in ("cache_eviction_passes", "egress_provider_reports"):
            sql = f"DELETE FROM {table} WHERE id IN (SELECT id FROM {table} WHERE {column} < ? LIMIT ?)"  # noqa: S608 (HISTORY_TABLES)
        else:
            # Minute tables: whole minutes at a time, the oldest first (`limit` minutes per call).
            sql = (
                f"DELETE FROM {table} WHERE {column} IN "  # noqa: S608 (HISTORY_TABLES)
                f"(SELECT DISTINCT {column} FROM {table} WHERE {column} < ? ORDER BY {column} LIMIT ?)"
            )
        deleted[table] = conn.execute(sql, (cutoff, limit)).rowcount
    days = keep_days.get("rule_hits")
    if days is not None and days > 0:
        cutoff = int(now_s - days * 86_400)
        deleted["rule_hits"] = conn.execute(
            "DELETE FROM rule_hits WHERE (table_name, rule_key) IN "
            "(SELECT table_name, rule_key FROM rule_hits WHERE last_hit_at < ? LIMIT ?)",
            (cutoff, limit),
        ).rowcount
    return deleted


__all__ = [
    "HISTORY_TABLES",
    "MAX_ROWS",
    "anomalies_between",
    "attempt_rows",
    "bucket_history",
    "bucket_summary",
    "cache_summary",
    "error_counts",
    "error_series",
    "error_signatures",
    "events_between",
    "eviction_passes",
    "heartbeats",
    "latest_health_run",
    "latest_provider_report",
    "prune_history",
    "refusal_samples_between",
    "roblox_429_counts",
    "rule_hits",
    "samples_between",
    "upstream_429_rows",
    "worker_history",
]
