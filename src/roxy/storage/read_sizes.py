"""Read model of storage use: every database file and table with rows, bytes, oldest row and a 30 day projection.

What this is
    `measure_database(conn, name, now_s, limits)` measures one SQLite database on a maintenance connection: for
    every table its row count, its bytes on disk (table plus its indexes, from SQLite's `dbstat` virtual table),
    its oldest row, the rows added in the last 7 days and a projection of rows and bytes 30 days from now.
    `file_sizes(paths)` reads the size of each database file and its `-wal` and `-shm` companions.
    `TABLES` holds what is known about each table (time column, and the retention settings that bound it, plan
    6.10); tables a later migration adds are measured too, with rows and bytes only.

Why it exists
    Plan 6.6 ("The System page shows each table's rows, bytes, oldest row, and projected size in 30 days"), parity
    rows 85 and 133 (v1 "What's Being Stored" and the persistence card), and the Data page (plan 14.1). The tables
    belong to the storage layer, so the measurement lives here (DESIGN.md section 13).

How it works
    The caller runs `measure_database` through `Database.maintenance` (a short-lived connection on a worker thread):
    a scan of a large metrics.db can take a second or more and must neither hold the event loop nor occupy the read
    pool the dashboard and the hot path use. `dbstat` with `aggregate = 1` returns one row per table or index; an
    index is added to its table. Counting uses `count(*)`, the oldest row uses `min()` of an indexed time column.
    Projection (an estimate, and labeled one): rows added per day over the last 7 days (or since the oldest row,
    when the table is younger), times 30, added to today's rows; then bounded by the table's row cap, and by the
    steady state `rows per day x max age` when the table has a max age (older rows are pruned by the retention
    job). Bytes follow the current bytes per row. A table without a time column projects its current size.

What to read next
    `roxy/storage/retention.py` (the caps and ages that bound the projection), `roxy/admin/api/data.py`.
"""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal

DAY_S: Final = 86_400
GROWTH_WINDOW_S: Final = 7 * DAY_S
"""How far back new rows are counted to estimate daily growth."""

PROJECTION_DAYS: Final = 30
MAX_TABLES: Final = 200
"""Tables measured per database (plan P9); the schema has far fewer."""


@dataclass(frozen=True, slots=True)
class TableMeta:
    """What the storage layer knows about one table.

    `time_col` is an indexed column holding when a row was written (`unit` seconds or milliseconds); `age` names
    the `RetentionPolicy` field (= catalog setting) holding its max age and `age_unit_s` that field's unit in
    seconds; `cap` names the policy field holding its row cap. `label` is the plain-English name.
    """

    table: str
    label: str
    time_col: str | None = None
    unit: Literal["s", "ms"] = "s"
    age: str | None = None
    age_unit_s: int = DAY_S
    cap: str | None = None


def _t(table: str, label: str, time_col: str | None = None, **kwargs: Any) -> TableMeta:
    return TableMeta(table, label, time_col, **kwargs)


TABLES: Final[dict[str, tuple[TableMeta, ...]]] = {
    "metrics": (
        _t("rollup_minute", "Per-minute traffic totals", "bucket_start", age="retention_minute_days"),
        _t("rollup_hour", "Per-hour traffic totals", "bucket_start", age="retention_hour_days"),
        _t("rollup_day", "Per-day traffic totals", "bucket_start", age="retention_day_days"),
        _t("rollup_month", "Per-month traffic totals", "bucket_start", age="retention_day_days"),
        _t("dims", "Dimension combinations (endpoint, status, outcome)"),
        _t("client_minute", "Per-minute client activity", "bucket_start", age="retention_client_minute_days"),
        _t("client_hour", "Per-hour client activity", "bucket_start", age="retention_client_hour_days"),
        _t("client_day", "Per-day client activity", "bucket_start", age="retention_client_day_days"),
        _t(
            "upstream_429",
            "Roblox 429 log",
            "at_ms",
            unit="ms",
            age="retention_upstream_429_days",
            cap="upstream_429_max_rows",
        ),
        _t("events", "Event log", "at_ms", unit="ms", age="retention_events_days", cap="events_max_rows"),
        _t(
            "request_samples",
            "Request samples",
            "at_ms",
            unit="ms",
            age="request_sample_hours",
            age_unit_s=3600,
            cap="request_sample_max_rows",
        ),
        _t("annotations", "Chart markers", "at", cap="annotations_max_rows"),
        _t("egress_usage", "Egress byte accounting", "bucket_start"),
        _t(
            "recommendations",
            "Recommendations",
            "updated_at",
            age="retention_recommendations_days",
            cap="recommendations_max_rows",
        ),
        _t("recommendation_actions", "Recommendation actions", "at", age="retention_recommendations_days"),
        _t("health_runs", "Health check runs", "started_at", age="retention_health_days", cap="health_runs_max"),
        _t("health_results", "Health check results"),
        _t("captures", "Captured bodies", "at", age="capture_ttl_seconds", age_unit_s=1, cap="capture_max_records"),
        _t(
            "fingerprint_headers",
            "Header name fingerprints",
            "last_seen",
            age="retention_fingerprints_days",
            cap="max_header_name_records",
        ),
        _t(
            "fingerprint_values",
            "Header value fingerprints",
            "last_seen",
            age="retention_fingerprints_days",
            cap="max_header_value_records",
        ),
        _t(
            "fingerprint_user_agents",
            "User-Agent fingerprints",
            "last_seen",
            age="retention_fingerprints_days",
            cap="max_user_agent_records",
        ),
        _t("errors", "Error signatures", "last_seen", age="retention_errors_days", cap="max_error_records"),
        _t("anomalies", "Detected anomalies", "at", age="retention_anomalies_days", cap="anomalies_max_rows"),
        _t("worker_heartbeat", "Worker heartbeats", "last_seen", cap="heartbeat_max_rows"),
        _t("legacy_totals", "Imported v1 lifetime totals"),
        _t("bucket_minute", "Upstream bucket fill history", "bucket_start"),
        _t("worker_minute", "Worker CPU and loop lag history", "bucket_start"),
        _t("cache_minute", "Cache store and eviction history", "bucket_start"),
        _t("cache_eviction_passes", "Cache eviction passes", "at"),
        _t("rule_hits", "Rule hit evidence", "last_hit_at"),
        _t("error_minute", "Error occurrences per minute", "bucket_start"),
        _t("upstream_attempt_minute", "Upstream attempts per minute", "bucket_start"),
        _t("egress_provider_reports", "Rotator provider byte reports", "at"),
        _t("recommendation_watches", "Recommendation watch windows", "started_at"),
        _t("health_job_status", "Published leader job status", "published_at"),
    ),
    "control": (
        _t("settings", "Setting overrides"),
        _t(
            "settings_history",
            "Settings history",
            "changed_at",
            age="retention_settings_history_days",
            cap="settings_history_max_rows",
        ),
        _t("audit_log", "Audit log", "at", age="retention_audit_days"),
        _t("bans", "Bans"),
        _t("access_list", "Bypass, admin allowlist and deny list"),
        _t("admin_sessions", "Admin sessions", "expires_at"),
        _t("admin_prefs", "Admin preferences"),
    ),
    "hot": (
        _t("limiter", "Rate limiter state", "updated_at"),
        _t("strikes", "Throttle strikes", "last_strike_at"),
        _t("lease", "Leases"),
        _t("job_runs", "Job idempotency keys", "started_at"),
        _t("email_gate", "Alert dedupe", "last_sent_at", cap="email_gate_max_rows"),
        _t("spam_windows", "Spam detector windows", "updated_at"),
    ),
    "cache": (
        _t("entries", "Cached responses", "stored_at"),
        _t("change_observations", "TTL tuning observations", "day", age="change_observations_days"),
    ),
}
"""Known tables per database. Any other table found is measured with rows and bytes only."""


def meta_for(db: str, table: str) -> TableMeta | None:
    """The known metadata of `db.table`, or None."""
    for meta in TABLES.get(db, ()):
        if meta.table == table:
            return meta
    return None


def _table_bytes(conn: sqlite3.Connection) -> dict[str, int] | None:
    """Bytes per table (indexes added to their table) from `dbstat`, or None when SQLite lacks it."""
    owners = {
        str(row[0]): str(row[1])
        for row in conn.execute("SELECT name, tbl_name FROM sqlite_master WHERE type IN ('table', 'index')")
    }
    try:
        rows = conn.execute("SELECT name, pgsize FROM dbstat WHERE aggregate = 1").fetchall()
    except sqlite3.Error:
        return None
    out: dict[str, int] = {}
    for name, size in rows:
        owner = owners.get(str(name), str(name))
        out[owner] = out.get(owner, 0) + int(size or 0)
    return out


def _seconds(value: Any, unit: str) -> int | None:
    if value is None:
        return None
    number = int(value)
    return number // 1000 if unit == "ms" else number


def project(
    rows: int,
    bytes_: int | None,
    *,
    rows_recent: int | None,
    oldest_s: int | None,
    now_s: float,
    max_age_s: int | None,
    cap: int | None,
) -> dict[str, Any]:
    """The 30 day projection of one table (see the module docstring for the method)."""
    if rows_recent is None:
        return {"rows": rows, "bytes": bytes_, "rows_per_day": None, "method": "no time column: current size"}
    span = GROWTH_WINDOW_S
    if oldest_s is not None:
        span = max(3600, min(GROWTH_WINDOW_S, int(now_s) - oldest_s))
    per_day = rows_recent * DAY_S / span
    projected = rows + per_day * PROJECTION_DAYS
    method = "rows added per day over the last 7 days x 30, added to today's rows"
    if max_age_s:
        steady = per_day * max_age_s / DAY_S
        if steady < projected:
            projected = steady
            method += "; bounded by the max age (older rows are pruned)"
    if cap is not None and cap > 0 and projected > cap:
        projected = cap
        method += "; bounded by the row cap"
    projected_rows = round(projected)
    per_row = (bytes_ / rows) if bytes_ is not None and rows else None
    projected_bytes = round(projected_rows * per_row) if per_row is not None else None
    return {"rows": projected_rows, "bytes": projected_bytes, "rows_per_day": round(per_day, 2), "method": method}


def _limit(limits: Mapping[str, Any], name: str | None) -> int | None:
    if name is None:
        return None
    value = limits.get(name)
    try:
        return None if value is None else int(value)
    except (TypeError, ValueError):
        return None


def measure_table(
    conn: sqlite3.Connection,
    db: str,
    table: str,
    *,
    now_s: float,
    bytes_by_table: Mapping[str, int] | None,
    limits: Mapping[str, Any],
) -> dict[str, Any]:
    """Rows, bytes, oldest row, growth and projection of one table (table names come from sqlite_master)."""
    quoted = '"' + table.replace('"', '""') + '"'  # an identifier read from sqlite_master, quoted as SQL requires
    rows = int(conn.execute(f"SELECT count(*) FROM {quoted}").fetchone()[0])  # noqa: S608 (schema identifier)
    meta = meta_for(db, table)
    bytes_ = None if bytes_by_table is None else int(bytes_by_table.get(table, 0))
    oldest_s: int | None = None
    newest_s: int | None = None
    rows_recent: int | None = None
    if meta is not None and meta.time_col is not None:
        column = meta.time_col  # a module constant
        row = conn.execute(f"SELECT min({column}), max({column}) FROM {quoted}").fetchone()  # noqa: S608 (constants)
        oldest_s, newest_s = _seconds(row[0], meta.unit), _seconds(row[1], meta.unit)
        cutoff = int(now_s) - GROWTH_WINDOW_S
        bound = cutoff * 1000 if meta.unit == "ms" else cutoff
        rows_recent = int(
            conn.execute(f"SELECT count(*) FROM {quoted} WHERE {column} >= ?", (bound,)).fetchone()[0]  # noqa: S608
        )
    age_value = _limit(limits, meta.age if meta else None)
    max_age_s = age_value * meta.age_unit_s if meta is not None and age_value else None
    cap = _limit(limits, meta.cap if meta else None)
    status = "ok"
    if cap is not None and cap > 0 and rows > cap:
        status = "over_cap"
    elif max_age_s and oldest_s is not None and oldest_s < now_s - max_age_s:
        status = "pruning_due"
    return {
        "db": db,
        "table": table,
        "label": meta.label if meta else table,
        "rows": rows,
        "bytes": bytes_,
        "oldest": oldest_s,
        "newest": newest_s,
        "rows_last_7d": rows_recent,
        "max_age_s": max_age_s,
        "max_age_setting": meta.age if meta else None,
        "row_cap": cap,
        "row_cap_setting": meta.cap if meta else None,
        "retention_status": status,
        "projection_30d": project(
            rows, bytes_, rows_recent=rows_recent, oldest_s=oldest_s, now_s=now_s, max_age_s=max_age_s, cap=cap
        ),
    }


def measure_database(conn: sqlite3.Connection, db: str, now_s: float, limits: Mapping[str, Any]) -> dict[str, Any]:
    """Every table of one database (sizes from dbstat, which may be absent: then `bytes` is None)."""
    page_size = int(conn.execute("PRAGMA page_size").fetchone()[0])
    pages = int(conn.execute("PRAGMA page_count").fetchone()[0])
    free = int(conn.execute("PRAGMA freelist_count").fetchone()[0])
    names = [
        str(row[0])
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name LIMIT ?",
            (MAX_TABLES,),
        )
    ]
    by_table = _table_bytes(conn)
    tables = [measure_table(conn, db, name, now_s=now_s, bytes_by_table=by_table, limits=limits) for name in names]
    return {
        "db": db,
        "page_size": page_size,
        "pages": pages,
        "free_pages": free,
        "bytes": page_size * pages,
        "free_bytes": page_size * free,
        "dbstat": by_table is not None,
        "tables": tables,
    }


def file_sizes(paths: Iterable[Path]) -> dict[str, dict[str, int]]:
    """`{file name: {bytes, wal_bytes, shm_bytes}}` for database files (missing files count 0)."""

    def size(path: Path) -> int:
        try:
            return int(os.stat(path).st_size)
        except OSError:
            return 0

    out: dict[str, dict[str, int]] = {}
    for path in paths:
        out[path.name] = {
            "bytes": size(path),
            "wal_bytes": size(Path(f"{path}-wal")),
            "shm_bytes": size(Path(f"{path}-shm")),
        }
    return out


__all__ = [
    "MAX_TABLES",
    "PROJECTION_DAYS",
    "TABLES",
    "TableMeta",
    "file_sizes",
    "measure_database",
    "measure_table",
    "meta_for",
    "project",
]
