"""Retention and maintenance: keep every table and file bounded, and keep SQLite files healthy.

What this is
    One pruning function per table in plan 6.10 (max age first, then row cap, oldest first), the prune runner
    the leader's jobs call (`run_retention`, `run_hot_prune`), file pruning for `exports/` and `snapshots/`, and
    the maintenance helpers from plan 6.5: `incremental_vacuum`, PASSIVE and TRUNCATE checkpoints with timing,
    `daily_truncate_due`, `quick_check` and `optimize`.

Why it exists
    Plan principle P9: every table has a cap, so neither traffic nor an attacker can grow the disk without bound.
    Deleting rows alone does not shrink a file, so the leader follows each prune with `incremental_vacuum`, and
    checkpoints keep the WAL files small.

How it works
    - Every pruning function has the same shape, `fn(conn, now_s, policy, limit) -> rows deleted`, and deletes
      at most `limit` rows per call. The runner calls it in its own short write transaction again and again until
      it returns less than `limit`, yielding between batches, so a big prune never holds the write lock long
      (the hot path keeps admitting requests in between).
    - `RetentionPolicy` carries the setting values (catalog group I) with the plan 6.10 defaults. A value of 0
      days means "forever" where the plan allows it.
    - Special rules: the audit log keeps at least 400 days and can only be deleted through its prune gate (the
      triggers in control/0001_initial.sql check SQLite's own clock); `settings_history` never loses the newest
      row of any key; open recommendations are never pruned; the `leader` lease row is never pruned, so its epoch
      (fencing token) keeps counting up. Rows that enforce a limit outlive the longest period the limit can
      have: an alert dedupe row outlives the longest alert cooldown (`ALERT_GATE_KEEP_S`), a login failure slot the
      longest lockout window the catalog accepts (`LOGIN_WINDOW_MAX_S`), so pruning never reopens either early.

What to read next
    `roxy/scheduler/jobs.py` (`register_storage_jobs` wires these to the leader), then
    `roxy/storage/migrations/control/0001_initial.sql` (the audit log triggers).
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import logging
import os
import sqlite3
import time
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from roxy.config.catalog import CATALOG
from roxy.storage.db import Database, Databases

log = logging.getLogger(__name__)

DAY_S = 86_400
BATCH_ROWS = 5000
"""Rows deleted per transaction (plan 6.5 uses the same batch size for Purge All)."""

AUDIT_MIN_DAYS = 400
"""The audit log keeps at least this many days whatever the setting says (plan 6.2, 6.10)."""

OPEN_RECOMMENDATION_STATES = ("open", "snoozed")
"""Recommendations in these states are never pruned (plan 6.10: closed items only)."""

NEVER_PRUNED_LEASES = frozenset({"leader"})
"""Lease rows kept forever so their epoch never restarts at 1 (plan 5.6 fencing)."""

INCREMENTAL_VACUUM_PAGES = 2000
"""Pages returned to the file system per `incremental_vacuum` step (plan 6.5)."""

ALERT_GATE_KEEP_S = 45 * DAY_S
"""How long an alert dedupe row (`email_gate` key `alert:<cooldown key>`) is kept after the alert last went out.

Longer than any alert cooldown Roxy uses (the rotator quota alert waits up to 40 days, one per billing cycle, plan
17.7), so retention never re-opens a cooldown early. The hourly cap rows keep the one day idle."""

ALERT_GATE_PREFIX = "alert:"
"""`notify/gate.py ALERT_PREFIX` (repeated here: storage sits below notify and must not import it)."""

_PREFIX_END = "\U0010ffff"  # largest code point: `key < prefix + this` closes a primary key range scan


def _catalog_max(key: str, fallback: int) -> int:
    """The largest value a catalog setting accepts: a retention bound that must cover any live value of it."""
    spec = CATALOG.get(key)
    maximum = getattr(spec, "max", None) if spec is not None else None
    return int(maximum) if isinstance(maximum, int | float) else fallback


LOGIN_WINDOW_MAX_S = _catalog_max("admin_login_window_s", DAY_S)
"""The longest login lockout window an admin may configure (plan 15.3 G, 86400 s): failure slots are kept at least
this long, so no live window ever loses a failure it still counts (the lockout itself drops older ones)."""


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    """Every retention value from plan 6.10. Field names match catalog setting keys where a setting exists."""

    retention_minute_days: int = 14
    retention_hour_days: int = 400
    retention_day_days: int = 0  # 0 = forever (day and month rollups)
    retention_client_minute_days: int = 3
    retention_client_hour_days: int = 90
    retention_client_day_days: int = 730
    max_ip_activity_records: int = 500  # top IP clients kept per bucket, plus one "other" row
    max_caller_records: int = 500  # top place (experience) clients kept per bucket, plus one "other" row
    retention_upstream_429_days: int = 90
    upstream_429_max_rows: int = 200_000
    retention_events_days: int = 90
    events_max_rows: int = 2_000_000
    request_sample_hours: int = 24
    request_sample_max_rows: int = 3_000_000
    retention_recommendations_days: int = 365
    recommendations_max_rows: int = 50_000
    retention_health_days: int = 180
    health_runs_max: int = 2000
    capture_ttl_seconds: int = 900
    capture_max_records: int = 2000
    capture_max_bytes: int = 64 * 1024 * 1024
    retention_fingerprints_days: int = 90
    max_header_name_records: int = 1000
    max_header_value_records: int = 500
    max_user_agent_records: int = 5000
    retention_errors_days: int = 180
    max_error_records: int = 2000
    retention_anomalies_days: int = 90
    anomalies_max_rows: int = 100_000
    heartbeat_max_age_s: int = DAY_S
    heartbeat_max_rows: int = 256
    annotations_max_rows: int = 100_000
    retention_audit_days: int = 730  # never below AUDIT_MIN_DAYS
    retention_settings_history_days: int = 0  # 0 = forever
    settings_history_max_rows: int = 100_000
    retention_expired_bans_days: int = 30
    change_observations_days: int = 90
    # hot.db (pruned every minute)
    stale_ip_duration: int = 60  # idle limiter rows
    strike_idle_s: int = 1800  # throttle_strike_decay_seconds
    expired_lease_grace_s: int = 60
    cooldown_grace_s: int = 3600
    upstream_bucket_idle_s: int = 3600
    breaker_idle_s: int = DAY_S
    aimd_idle_s: int = DAY_S
    job_runs_days: int = 7
    email_gate_idle_s: int = DAY_S  # the hourly cap rows (`cap:`, `capdrop:`)
    email_gate_alert_idle_s: int = ALERT_GATE_KEEP_S  # alert dedupe rows: longer than any alert cooldown
    email_gate_max_rows: int = 10_000
    login_failures_idle_s: int = LOGIN_WINDOW_MAX_S  # never shorter than any lockout window (plan 9.5, 15.3 G)
    admin_login_window_s: int = 0  # the live lockout window (from_settings); the prune keeps at least this too
    spam_windows_idle_s: int = DAY_S
    # files
    retention_exports_days: int = 14
    exports_max_files: int = 400
    retention_snapshots_days: int = 7
    snapshots_max_bytes: int = 2 * 1024 * 1024 * 1024

    @classmethod
    def from_settings(cls, get: Callable[[str], Any]) -> RetentionPolicy:
        """Build a policy from a settings getter (for example `ctx.settings.get`). Keys the getter does not know
        keep their defaults, so this works before every setting exists in the catalog."""
        values: dict[str, Any] = {}
        for f in dataclasses.fields(cls):
            try:
                value = get(_SETTING_ALIASES.get(f.name, f.name))
                if value is not None:
                    values[f.name] = int(value)
            except (LookupError, AttributeError, ValueError, TypeError):
                continue  # unknown key or unusable value: keep the plan 6.10 default
        return cls(**values)


_SETTING_ALIASES = {"strike_idle_s": "throttle_strike_decay_seconds"}
"""Policy fields whose catalog setting has a different name."""

Pruner = Callable[[sqlite3.Connection, float, RetentionPolicy, int], int]


# ------------------------------------------------------------------------------------------------- primitives


def _cutoff(now_s: float, days: float) -> int | None:
    """Unix seconds before which rows are old enough to delete, or None for "keep forever" (days <= 0)."""
    if days <= 0:
        return None
    return int(now_s - days * DAY_S)


def delete_batch(
    conn: sqlite3.Connection, table: str, key: str, where: str, params: Iterable[Any], order: str, limit: int
) -> int:
    """Delete at most `limit` rows of `table` matching `where`, in `order` (oldest first).

    `key` names the row identity: `rowid` for ordinary tables, or the primary key columns of a WITHOUT ROWID
    table (for example `bucket_start, dim_hash`; SQLite compares them as a row value). Table and column names
    come from this module's constants, never from user input.
    """
    if limit <= 0:
        return 0
    target = f"({key})" if "," in key else key
    sql = (
        f"DELETE FROM {table} WHERE {target} IN "  # noqa: S608 (identifiers are module constants)
        f"(SELECT {key} FROM {table} WHERE {where} ORDER BY {order} LIMIT ?)"
    )
    return conn.execute(sql, (*params, limit)).rowcount


def prune_age_then_cap(
    conn: sqlite3.Connection,
    table: str,
    *,
    key: str,
    time_col: str,
    cutoff: int | None,
    cap: int | None,
    limit: int,
    order: str | None = None,
    extra_where: str = "1",
    extra_params: tuple[Any, ...] = (),
) -> int:
    """Delete rows older than `cutoff` (by `time_col`), then the oldest rows beyond `cap`, at most `limit` total."""
    order_by = order or time_col
    deleted = 0
    if cutoff is not None:
        deleted += delete_batch(
            conn, table, key, f"({extra_where}) AND {time_col} < ?", (*extra_params, cutoff), order_by, limit
        )
    if cap is not None and deleted < limit:
        count_sql = f"SELECT count(*) FROM {table} WHERE {extra_where}"  # noqa: S608 (module constants)
        count = conn.execute(count_sql, extra_params).fetchone()[0]
        excess = int(count) - cap
        if excess > 0:
            deleted += delete_batch(conn, table, key, extra_where, extra_params, order_by, min(excess, limit - deleted))
    return deleted


# --------------------------------------------------------------------------------------- metrics.db tables

_ROLLUP_KEY = "bucket_start, dim_hash"
_CLIENT_KEY = "bucket_start, client_type, client_key"


def prune_rollup_minute(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`rollup_minute`: `retention_minute_days` (14). No row cap (bounded by dims, plan 6.2)."""
    return prune_age_then_cap(
        conn,
        "rollup_minute",
        key=_ROLLUP_KEY,
        time_col="bucket_start",
        cutoff=_cutoff(now_s, policy.retention_minute_days),
        cap=None,
        limit=limit,
    )


def prune_rollup_hour(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`rollup_hour`: `retention_hour_days` (400)."""
    return prune_age_then_cap(
        conn,
        "rollup_hour",
        key=_ROLLUP_KEY,
        time_col="bucket_start",
        cutoff=_cutoff(now_s, policy.retention_hour_days),
        cap=None,
        limit=limit,
    )


def prune_rollup_day(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`rollup_day`: `retention_day_days` (0 = forever)."""
    return prune_age_then_cap(
        conn,
        "rollup_day",
        key=_ROLLUP_KEY,
        time_col="bucket_start",
        cutoff=_cutoff(now_s, policy.retention_day_days),
        cap=None,
        limit=limit,
    )


def prune_rollup_month(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`rollup_month`: `retention_day_days` (0 = forever)."""
    return prune_age_then_cap(
        conn,
        "rollup_month",
        key=_ROLLUP_KEY,
        time_col="bucket_start",
        cutoff=_cutoff(now_s, policy.retention_day_days),
        cap=None,
        limit=limit,
    )


def cap_client_rows(
    conn: sqlite3.Connection,
    table: str,
    *,
    keep_top: int,
    closed_before: int,
    lookback_s: int,
    limit: int,
    keep_top_places: int | None = None,
) -> int:
    """Enforce "top N per client type per bucket plus one `other` row" on closed buckets (plan 6.4).

    N is `keep_top` for IP clients (`max_ip_activity_records`) and `keep_top_places` for place clients
    (`max_caller_records`; `keep_top` when None). Rows beyond the top N by requests are added into the bucket's
    `other` row and deleted, so totals stay exact. Only buckets in `[closed_before - lookback_s, closed_before)`
    are examined, so the query stays small; the leader's compaction normally does this as each bucket closes and
    this is the safety net that makes the caps in plan 6.10 hold. Deletes at most `limit` rows. Returns rows
    folded.
    """
    if limit <= 0:
        return 0
    places = keep_top if keep_top_places is None else keep_top_places
    rows = conn.execute(
        f"""
        WITH crowded AS (
            SELECT bucket_start, client_type FROM {table}
            WHERE bucket_start >= ? AND bucket_start < ? AND client_key != 'other'
            GROUP BY bucket_start, client_type
            HAVING count(*) > CASE client_type WHEN 'place' THEN ? ELSE ? END
        ),
        ranked AS (
            SELECT c.bucket_start, c.client_type, c.client_key, c.requests, c.refused, c.served, c.bytes,
                   row_number() OVER (PARTITION BY c.bucket_start, c.client_type
                                      ORDER BY c.requests DESC, c.client_key) AS rank
            FROM {table} AS c JOIN crowded USING (bucket_start, client_type)
            WHERE c.client_key != 'other'
        )
        SELECT bucket_start, client_type, client_key, requests, refused, served, bytes
        FROM ranked WHERE rank > CASE client_type WHEN 'place' THEN ? ELSE ? END LIMIT ?
        """,  # noqa: S608 (table is one of the three client tables named in this module)
        (closed_before - lookback_s, closed_before, places, keep_top, places, keep_top, limit),
    ).fetchall()
    if not rows:
        return 0
    totals: dict[tuple[int, str], list[int]] = {}
    for bucket, ctype, _key, requests, refused, served, size in rows:
        acc = totals.setdefault((int(bucket), str(ctype)), [0, 0, 0, 0])
        acc[0] += int(requests)
        acc[1] += int(refused)
        acc[2] += int(served)
        acc[3] += int(size)
    for (bucket, ctype), (requests, refused, served, size) in totals.items():
        conn.execute(
            f"""
            INSERT INTO {table} (bucket_start, client_type, client_key, requests, refused, served, bytes,
                                 top_endpoint)
            VALUES (?, ?, 'other', ?, ?, ?, ?, NULL)
            ON CONFLICT (bucket_start, client_type, client_key) DO UPDATE SET
                requests = requests + excluded.requests, refused = refused + excluded.refused,
                served = served + excluded.served, bytes = bytes + excluded.bytes
            """,  # noqa: S608
            (bucket, ctype, requests, refused, served, size),
        )
    conn.executemany(
        f"DELETE FROM {table} WHERE bucket_start = ? AND client_type = ? AND client_key = ?",  # noqa: S608
        [(r[0], r[1], r[2]) for r in rows],
    )
    return len(rows)


def _prune_client(
    conn: sqlite3.Connection, table: str, days: int, bucket_s: int, now_s: float, policy: RetentionPolicy, limit: int
) -> int:
    deleted = prune_age_then_cap(
        conn, table, key=_CLIENT_KEY, time_col="bucket_start", cutoff=_cutoff(now_s, days), cap=None, limit=limit
    )
    if deleted < limit:
        closed_before = int(now_s // bucket_s * bucket_s)  # the current bucket is still open
        deleted += cap_client_rows(
            conn,
            table,
            keep_top=policy.max_ip_activity_records,
            keep_top_places=policy.max_caller_records,
            closed_before=closed_before,
            lookback_s=bucket_s * 48,
            limit=limit - deleted,
        )
    return deleted


def prune_client_minute(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`client_minute`: `retention_client_minute_days` (3); 501 rows per type per minute."""
    return _prune_client(conn, "client_minute", policy.retention_client_minute_days, 60, now_s, policy, limit)


def prune_client_hour(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`client_hour`: `retention_client_hour_days` (90); 501 rows per type per hour."""
    return _prune_client(conn, "client_hour", policy.retention_client_hour_days, 3600, now_s, policy, limit)


def prune_client_day(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`client_day`: `retention_client_day_days` (730); 501 rows per type per day."""
    return _prune_client(conn, "client_day", policy.retention_client_day_days, DAY_S, now_s, policy, limit)


def prune_upstream_429(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`upstream_429`: `retention_upstream_429_days` (90), `upstream_429_max_rows` (200,000)."""
    cutoff = _cutoff(now_s, policy.retention_upstream_429_days)
    return prune_age_then_cap(
        conn,
        "upstream_429",
        key="rowid",
        time_col="at_ms",
        cutoff=None if cutoff is None else cutoff * 1000,
        cap=policy.upstream_429_max_rows,
        limit=limit,
        order="id",
    )


def prune_events(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`events`: `retention_events_days` (90), `events_max_rows` (2,000,000)."""
    cutoff = _cutoff(now_s, policy.retention_events_days)
    return prune_age_then_cap(
        conn,
        "events",
        key="rowid",
        time_col="at_ms",
        cutoff=None if cutoff is None else cutoff * 1000,
        cap=policy.events_max_rows,
        limit=limit,
        order="id",
    )


def prune_request_samples(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`request_samples`: `request_sample_hours` (24), `request_sample_max_rows` (3,000,000)."""
    cutoff_ms = int((now_s - policy.request_sample_hours * 3600) * 1000) if policy.request_sample_hours > 0 else None
    return prune_age_then_cap(
        conn,
        "request_samples",
        key="rowid",
        time_col="at_ms",
        cutoff=cutoff_ms,
        cap=policy.request_sample_max_rows,
        limit=limit,
        order="id",
    )


def prune_egress_usage(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`egress_usage`: minute rows like minute rollups, hour like hour rollups, day and month like day rollups."""
    deleted = 0
    for granularity, days in (
        ("minute", policy.retention_minute_days),
        ("hour", policy.retention_hour_days),
        ("day", policy.retention_day_days),
        ("month", policy.retention_day_days),
    ):
        if deleted >= limit:
            break
        deleted += prune_age_then_cap(
            conn,
            "egress_usage",
            key="bucket_start, egress, granularity",
            time_col="bucket_start",
            cutoff=_cutoff(now_s, days),
            cap=None,
            limit=limit - deleted,
            extra_where="granularity = ?",
            extra_params=(granularity,),
        )
    return deleted


def prune_recommendations(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`recommendations`: closed items older than `retention_recommendations_days` (365), cap 50,000 closed
    items. Open (and snoozed) recommendations are never pruned."""
    placeholders = ", ".join("?" for _ in OPEN_RECOMMENDATION_STATES)
    return prune_age_then_cap(
        conn,
        "recommendations",
        key="rowid",
        time_col="updated_at",
        cutoff=_cutoff(now_s, policy.retention_recommendations_days),
        cap=policy.recommendations_max_rows,
        limit=limit,
        extra_where=f"state NOT IN ({placeholders})",
        extra_params=OPEN_RECOMMENDATION_STATES,
    )


def prune_recommendation_actions(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`recommendation_actions`: actions of pruned recommendations, then age and the 50,000 row cap."""
    deleted = delete_batch(
        conn,
        "recommendation_actions",
        "rowid",
        "recommendation_id NOT IN (SELECT id FROM recommendations)",
        (),
        "id",
        limit,
    )
    if deleted < limit:
        deleted += prune_age_then_cap(
            conn,
            "recommendation_actions",
            key="rowid",
            time_col="at",
            cutoff=_cutoff(now_s, policy.retention_recommendations_days),
            cap=policy.recommendations_max_rows,
            limit=limit - deleted,
            order="id",
        )
    return deleted


def prune_health(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`health_runs` and `health_results`: `retention_health_days` (180), `health_runs_max` (2,000 runs).
    Results go with their run, and orphaned results are removed."""
    run_ids: list[int] = []
    cutoff = _cutoff(now_s, policy.retention_health_days)
    if cutoff is not None:
        run_ids = [
            int(r[0])
            for r in conn.execute(
                "SELECT id FROM health_runs WHERE started_at < ? ORDER BY id LIMIT ?", (cutoff, limit)
            )
        ]
    if len(run_ids) < limit:
        remaining = int(conn.execute("SELECT count(*) FROM health_runs").fetchone()[0]) - len(run_ids)
        take = min(remaining - policy.health_runs_max, limit - len(run_ids))
        chosen = set(run_ids)
        if take > 0:
            # Oldest runs first; the ones already chosen by age are skipped (at most len(chosen) of them).
            for row in conn.execute("SELECT id FROM health_runs ORDER BY id LIMIT ?", (take + len(chosen),)).fetchall():
                if take <= 0:
                    break
                if int(row[0]) not in chosen:
                    run_ids.append(int(row[0]))
                    take -= 1
    if run_ids:
        conn.executemany("DELETE FROM health_results WHERE run_id = ?", [(i,) for i in run_ids])
        conn.executemany("DELETE FROM health_runs WHERE id = ?", [(i,) for i in run_ids])
    deleted = len(run_ids)
    if deleted < limit:
        deleted += delete_batch(
            conn,
            "health_results",
            "run_id, check_id",
            "run_id NOT IN (SELECT id FROM health_runs)",
            (),
            "run_id",
            limit - deleted,
        )
    return deleted


def prune_captures(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`captures`: `capture_ttl_seconds` (900), `capture_max_records` (2,000), `capture_max_bytes` (64 MiB)."""
    cutoff = int(now_s - policy.capture_ttl_seconds) if policy.capture_ttl_seconds > 0 else None
    deleted = prune_age_then_cap(
        conn,
        "captures",
        key="rowid",
        time_col="at",
        cutoff=cutoff,
        cap=policy.capture_max_records,
        limit=limit,
        order="id",
    )
    if deleted >= limit:
        return deleted
    total = int(conn.execute("SELECT coalesce(sum(bytes), 0) FROM captures").fetchone()[0])
    excess = total - policy.capture_max_bytes
    if excess <= 0:
        return deleted
    victims: list[int] = []
    rows = conn.execute("SELECT id, bytes FROM captures ORDER BY id LIMIT ?", (limit - deleted,)).fetchall()
    for capture_id, size in rows:
        if excess <= 0:
            break
        victims.append(int(capture_id))
        excess -= int(size or 0)
    conn.executemany("DELETE FROM captures WHERE id = ?", [(i,) for i in victims])
    return deleted + len(victims)


def prune_fingerprint_headers(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`fingerprint_headers`: `retention_fingerprints_days` (90 since last seen), `max_header_name_records`."""
    return prune_age_then_cap(
        conn,
        "fingerprint_headers",
        key="name",
        time_col="last_seen",
        cutoff=_cutoff(now_s, policy.retention_fingerprints_days),
        cap=policy.max_header_name_records,
        limit=limit,
    )


def prune_fingerprint_values(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`fingerprint_values`: `retention_fingerprints_days` (90 since last seen), `max_header_value_records`."""
    return prune_age_then_cap(
        conn,
        "fingerprint_values",
        key="rowid",
        time_col="last_seen",
        cutoff=_cutoff(now_s, policy.retention_fingerprints_days),
        cap=policy.max_header_value_records,
        limit=limit,
    )


def prune_fingerprint_user_agents(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`fingerprint_user_agents`: `retention_fingerprints_days` (90 since last seen), `max_user_agent_records`."""
    return prune_age_then_cap(
        conn,
        "fingerprint_user_agents",
        key="rowid",
        time_col="last_seen",
        cutoff=_cutoff(now_s, policy.retention_fingerprints_days),
        cap=policy.max_user_agent_records,
        limit=limit,
    )


def prune_errors(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`errors`: `retention_errors_days` (180 since last seen), `max_error_records` (2,000)."""
    return prune_age_then_cap(
        conn,
        "errors",
        key="rowid",
        time_col="last_seen",
        cutoff=_cutoff(now_s, policy.retention_errors_days),
        cap=policy.max_error_records,
        limit=limit,
    )


def prune_anomalies(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`anomalies`: `retention_anomalies_days` (90), 100,000 rows."""
    return prune_age_then_cap(
        conn,
        "anomalies",
        key="rowid",
        time_col="at",
        cutoff=_cutoff(now_s, policy.retention_anomalies_days),
        cap=policy.anomalies_max_rows,
        limit=limit,
        order="id",
    )


def prune_worker_heartbeat(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`worker_heartbeat`: rows not seen for 1 day, 256 rows."""
    return prune_age_then_cap(
        conn,
        "worker_heartbeat",
        key="rowid",
        time_col="last_seen",
        cutoff=int(now_s - policy.heartbeat_max_age_s),
        cap=policy.heartbeat_max_rows,
        limit=limit,
    )


def prune_annotations(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`annotations`: kept forever, 100,000 rows (oldest first)."""
    return prune_age_then_cap(
        conn,
        "annotations",
        key="rowid",
        time_col="at",
        cutoff=None,
        cap=policy.annotations_max_rows,
        limit=limit,
        order="id",
    )


# --------------------------------------------------------------------------------------- control.db tables


def prune_audit_log(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`audit_log`: `retention_audit_days` (730), never less than 400 days. No row cap.

    The table's triggers refuse every DELETE unless `audit_prune_gate` holds a cutoff at least 400 days before
    SQLite's own clock, so this is the only code path that can remove audit rows. The gate row lives only inside
    this transaction.
    """
    if policy.retention_audit_days <= 0:
        return 0  # 0 means keep forever
    days = max(policy.retention_audit_days, AUDIT_MIN_DAYS)
    cutoff = int(now_s) - days * DAY_S
    # Never ask for more than the trigger allows (it uses the real clock, whatever clock the caller uses).
    cutoff = min(cutoff, int(time.time()) - AUDIT_MIN_DAYS * DAY_S)
    conn.execute("DELETE FROM audit_prune_gate")
    conn.execute("INSERT INTO audit_prune_gate (id, cutoff_at) VALUES (1, ?)", (cutoff,))
    try:
        deleted = delete_batch(conn, "audit_log", "rowid", "at < ?", (cutoff,), "id", limit)
    finally:
        conn.execute("DELETE FROM audit_prune_gate")
    return deleted


def prune_settings_history(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`settings_history`: `retention_settings_history_days` (0 = forever), 100,000 rows, oldest first, and
    never the newest row of any key (so every current value keeps its history entry and can be reverted)."""
    keep_latest = "id NOT IN (SELECT max(id) FROM settings_history GROUP BY key)"
    deleted = 0
    cutoff = _cutoff(now_s, policy.retention_settings_history_days)
    if cutoff is not None:
        deleted += delete_batch(
            conn, "settings_history", "rowid", f"changed_at < ? AND {keep_latest}", (cutoff,), "id", limit
        )
    if deleted < limit:
        # The cap counts every row, but only rows that are not the newest of their key may be removed.
        total = int(conn.execute("SELECT count(*) FROM settings_history").fetchone()[0])
        excess = total - policy.settings_history_max_rows
        if excess > 0:
            deleted += delete_batch(
                conn, "settings_history", "rowid", keep_latest, (), "id", min(excess, limit - deleted)
            )
    return deleted


def prune_admin_sessions(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`admin_sessions`: expired rows (hourly)."""
    return delete_batch(conn, "admin_sessions", "id_hash", "expires_at < ?", (int(now_s),), "expires_at", limit)


def prune_trusted_devices(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`trusted_devices`: expired rows (hourly)."""
    return delete_batch(conn, "trusted_devices", "rowid", "expires_at < ?", (int(now_s),), "expires_at", limit)


def prune_invalidation_tokens(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`invalidation_tokens`: expired rows (hourly)."""
    return delete_batch(conn, "invalidation_tokens", "token_hash", "expires_at < ?", (int(now_s),), "expires_at", limit)


def prune_bans(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`bans`: expired bans are kept `retention_expired_bans_days` (30) as evidence, then deleted. Permanent
    bans (expires_at NULL) are never pruned. Removing long-expired bans does not change the active set, so no
    config_version bump is needed."""
    cutoff = _cutoff(now_s, policy.retention_expired_bans_days)
    if cutoff is None:
        return 0
    return delete_batch(
        conn, "bans", "rowid", "expires_at IS NOT NULL AND expires_at < ?", (cutoff,), "expires_at", limit
    )


# ------------------------------------------------------------------------------------------ cache.db tables


def prune_change_observations(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`change_observations` (not listed in plan 6.10; bounded here so every table has a limit): 90 days."""
    return prune_age_then_cap(
        conn,
        "change_observations",
        key="endpoint_template, day",
        time_col="day",
        cutoff=_cutoff(now_s, policy.change_observations_days),
        cap=None,
        limit=limit,
    )


# ------------------------------------------------------------------------------------------ hot.db tables


def prune_expired_leases(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`lease`: rows expired more than `expired_lease_grace_s` ago, except the `leader` row (its epoch must keep
    counting up, plan 5.6)."""
    keep = ", ".join("?" for _ in NEVER_PRUNED_LEASES)
    cutoff_ms = int((now_s - policy.expired_lease_grace_s) * 1000)
    return delete_batch(
        conn,
        "lease",
        "name",
        f"expires_ms < ? AND name NOT IN ({keep})",
        (cutoff_ms, *sorted(NEVER_PRUNED_LEASES)),
        "expires_ms",
        limit,
    )


def prune_cooldowns(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`cooldown`: rows that ended more than `cooldown_grace_s` ago (the grace keeps `hits` for a while)."""
    cutoff_ms = int((now_s - policy.cooldown_grace_s) * 1000)
    return delete_batch(conn, "cooldown", "key", "until_ms < ?", (cutoff_ms,), "until_ms", limit)


def prune_limiter(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`limiter`: rows idle for `stale_ip_duration` (60 s) whose GCRA time is in the past.

    An idle GCRA row with `tat_ms <= now` is equivalent to no row (a full bucket), so deleting it changes no
    decision. Callers that keep long fixed windows must keep `updated_at` fresh for the window's length.
    """
    return delete_batch(
        conn,
        "limiter",
        "bucket_key",
        "updated_at < ? AND tat_ms <= ?",
        (int(now_s - policy.stale_ip_duration), int(now_s * 1000)),
        "updated_at",
        limit,
    )


def prune_strikes(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`strikes`: IPs that are not throttled and have had no strike for `strike_idle_s` (strike decay)."""
    return delete_batch(
        conn,
        "strikes",
        "ip",
        "throttled_until < ? AND last_strike_at < ?",
        (int(now_s), int(now_s - policy.strike_idle_s)),
        "last_strike_at",
        limit,
    )


def prune_upstream_buckets(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`upstream_bucket`: idle buckets that are full again (`tat_ms` in the past), equivalent to no row."""
    return delete_batch(
        conn,
        "upstream_bucket",
        "bucket_key",
        "updated_at < ? AND tat_ms <= ?",
        (int(now_s - policy.upstream_bucket_idle_s), int(now_s * 1000)),
        "updated_at",
        limit,
    )


def prune_breakers(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`breaker`: closed breakers with no activity for `breaker_idle_s`."""
    return delete_batch(
        conn,
        "breaker",
        "key",
        "state = 'closed' AND window_start < ?",
        (int(now_s - policy.breaker_idle_s),),
        "window_start",
        limit,
    )


def prune_aimd(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`aimd`: idle keys with nothing in flight."""
    return delete_batch(
        conn,
        "aimd",
        "key",
        "inflight <= 0 AND last_change_at < ?",
        (int(now_s - policy.aimd_idle_s),),
        "last_change_at",
        limit,
    )


def prune_job_runs(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`job_runs`: 7 days."""
    return delete_batch(
        conn,
        "job_runs",
        "idem_key",
        "started_at < ?",
        (int(now_s - policy.job_runs_days * DAY_S),),
        "started_at",
        limit,
    )


def prune_email_gate(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`email_gate`, in three steps, at most `limit` rows in all:

    1. Alert dedupe rows (`alert:<cooldown key>`) not sent for `email_gate_alert_idle_s` (45 days): longer than any
       alert cooldown (the rotator quota alert waits up to 40 days), so the fleet-wide dedupe of plan 17.7 holds for
       the whole cooldown. A one day idle would let a long cooldown alert out again after a day.
    2. Every other row (the hourly cap rows `cap:` and `capdrop:`, useful for an hour) not touched for a day.
    3. The oldest rows beyond `email_gate_max_rows` (plan P9: the alert keys are bounded too).
    """
    low, high = ALERT_GATE_PREFIX, ALERT_GATE_PREFIX + _PREFIX_END
    deleted = delete_batch(
        conn,
        "email_gate",
        "key",
        "key >= ? AND key < ? AND last_sent_at < ?",
        (low, high, int(now_s - max(policy.email_gate_alert_idle_s, policy.email_gate_idle_s))),
        "last_sent_at",
        limit,
    )
    if deleted < limit:
        deleted += delete_batch(
            conn,
            "email_gate",
            "key",
            "NOT (key >= ? AND key < ?) AND last_sent_at < ?",
            (low, high, int(now_s - policy.email_gate_idle_s)),
            "last_sent_at",
            limit - deleted,
        )
    if deleted < limit:
        deleted += prune_age_then_cap(
            conn,
            "email_gate",
            key="key",
            time_col="last_sent_at",
            cutoff=None,
            cap=max(1, policy.email_gate_max_rows),
            limit=limit - deleted,
        )
    return deleted


def prune_login_failures(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`login_failures`: failure slots older than any lockout window can count, and the stale global row.

    The idle is `login_failures_idle_s` (the largest `admin_login_window_s` the catalog accepts, a day) and never
    less than the live window: pruning a slot still inside the configured window would reset the lockout early and
    hand an attacker `admin_login_max_failures` new guesses (plan 9.5, C6). The table stays bounded anyway: the
    lockout drops slots older than its window on every attempt and trims the oldest beyond
    `MAX_TRACKED_LOGIN_IPS` rows at insert time (`admin/auth/lockout.py`).
    """
    idle_s = max(policy.login_failures_idle_s, policy.admin_login_window_s)
    return delete_batch(
        conn,
        "login_failures",
        "subject",
        "window_start < ?",
        (int(now_s - idle_s),),
        "window_start",
        limit,
    )


def prune_spam_windows(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`spam_windows`: subjects with no update for longer than the longest detector window."""
    return delete_batch(
        conn,
        "spam_windows",
        "subject",
        "updated_at < ?",
        (int(now_s - policy.spam_windows_idle_s),),
        "updated_at",
        limit,
    )


def prune_csrf_cache(conn: sqlite3.Connection, now_s: float, policy: RetentionPolicy, limit: int) -> int:
    """`csrf_cache`: expired tokens."""
    return delete_batch(conn, "csrf_cache", "egress_identity", "expires_at < ?", (int(now_s),), "expires_at", limit)


# ------------------------------------------------------------------------------------------------ runners


@dataclass(frozen=True, slots=True)
class RetentionTask:
    """One table's pruning function and the database it runs on."""

    db: str
    table: str
    fn: Pruner


RETENTION_TASKS: tuple[RetentionTask, ...] = (
    RetentionTask("metrics", "rollup_minute", prune_rollup_minute),
    RetentionTask("metrics", "rollup_hour", prune_rollup_hour),
    RetentionTask("metrics", "rollup_day", prune_rollup_day),
    RetentionTask("metrics", "rollup_month", prune_rollup_month),
    RetentionTask("metrics", "client_minute", prune_client_minute),
    RetentionTask("metrics", "client_hour", prune_client_hour),
    RetentionTask("metrics", "client_day", prune_client_day),
    RetentionTask("metrics", "upstream_429", prune_upstream_429),
    RetentionTask("metrics", "events", prune_events),
    RetentionTask("metrics", "request_samples", prune_request_samples),
    RetentionTask("metrics", "egress_usage", prune_egress_usage),
    RetentionTask("metrics", "recommendations", prune_recommendations),
    RetentionTask("metrics", "recommendation_actions", prune_recommendation_actions),
    RetentionTask("metrics", "health_runs", prune_health),
    RetentionTask("metrics", "captures", prune_captures),
    RetentionTask("metrics", "fingerprint_headers", prune_fingerprint_headers),
    RetentionTask("metrics", "fingerprint_values", prune_fingerprint_values),
    RetentionTask("metrics", "fingerprint_user_agents", prune_fingerprint_user_agents),
    RetentionTask("metrics", "errors", prune_errors),
    RetentionTask("metrics", "anomalies", prune_anomalies),
    RetentionTask("metrics", "worker_heartbeat", prune_worker_heartbeat),
    RetentionTask("metrics", "annotations", prune_annotations),
    RetentionTask("control", "audit_log", prune_audit_log),
    RetentionTask("control", "settings_history", prune_settings_history),
    RetentionTask("control", "admin_sessions", prune_admin_sessions),
    RetentionTask("control", "trusted_devices", prune_trusted_devices),
    RetentionTask("control", "invalidation_tokens", prune_invalidation_tokens),
    RetentionTask("control", "bans", prune_bans),
    RetentionTask("cache", "change_observations", prune_change_observations),
)
"""Run by the leader every 10 minutes (plan 6.10)."""

HOT_TASKS: tuple[RetentionTask, ...] = (
    RetentionTask("hot", "lease", prune_expired_leases),
    RetentionTask("hot", "cooldown", prune_cooldowns),
    RetentionTask("hot", "limiter", prune_limiter),
    RetentionTask("hot", "strikes", prune_strikes),
    RetentionTask("hot", "upstream_bucket", prune_upstream_buckets),
    RetentionTask("hot", "breaker", prune_breakers),
    RetentionTask("hot", "aimd", prune_aimd),
    RetentionTask("hot", "job_runs", prune_job_runs),
    RetentionTask("hot", "email_gate", prune_email_gate),
    RetentionTask("hot", "login_failures", prune_login_failures),
    RetentionTask("hot", "spam_windows", prune_spam_windows),
    RetentionTask("hot", "csrf_cache", prune_csrf_cache),
)
"""Run by the leader every minute (plan 6.10, hot.db row)."""

Writer = Callable[[Database, Callable[[sqlite3.Connection], int]], Awaitable[int]]
"""How the runner writes: `db.write` by default, or a leader job's fenced write (`JobContext.fenced_write`)."""


async def _default_writer(db: Database, fn: Callable[[sqlite3.Connection], int]) -> int:
    return await db.write(fn)


async def run_tasks(
    dbs: Databases,
    tasks: Iterable[RetentionTask],
    policy: RetentionPolicy,
    now_s: float,
    *,
    writer: Writer | None = None,
    batch: int = BATCH_ROWS,
    max_batches: int = 200,
    pause_s: float = 0.0,
) -> dict[str, int]:
    """Run each task in batches of `batch` rows until it deletes fewer than `batch` (or `max_batches` ran).

    Each batch is its own short write transaction; `pause_s` yields between batches so other writers (the
    request path) get the lock. Returns rows deleted per `db.table`.
    """
    write = writer or _default_writer
    results: dict[str, int] = {}
    for task in tasks:
        db = dbs.get(task.db)
        total = 0
        for _ in range(max_batches):
            fn = _bind(task.fn, now_s, policy, batch)
            deleted = await write(db, fn)
            total += deleted
            if deleted < batch:
                break
            await asyncio.sleep(pause_s)
        results[f"{task.db}.{task.table}"] = total
        if total:
            log.info("retention_pruned", extra={"fields": {"db": task.db, "table": task.table, "rows": total}})
    return results


def _bind(fn: Pruner, now_s: float, policy: RetentionPolicy, batch: int) -> Callable[[sqlite3.Connection], int]:
    def run(conn: sqlite3.Connection) -> int:
        return fn(conn, now_s, policy, batch)

    return run


async def run_retention(
    dbs: Databases,
    policy: RetentionPolicy,
    now_s: float,
    *,
    writer: Writer | None = None,
    batch: int = BATCH_ROWS,
    vacuum: bool = True,
) -> dict[str, int]:
    """The 10 minute leader job: prune every table in `RETENTION_TASKS`, then `incremental_vacuum` the files
    that lost rows (plan 6.5, 6.10)."""
    results = await run_tasks(dbs, RETENTION_TASKS, policy, now_s, writer=writer, batch=batch, pause_s=0.01)
    if vacuum:
        touched = {key.split(".", 1)[0] for key, rows in results.items() if rows}
        for name in sorted(touched):
            await dbs.get(name).maintenance(incremental_vacuum)
    return results


async def run_hot_prune(
    dbs: Databases, policy: RetentionPolicy, now_s: float, *, writer: Writer | None = None, batch: int = BATCH_ROWS
) -> dict[str, int]:
    """The 1 minute leader job: prune hot.db (plan 6.10)."""
    return await run_tasks(dbs, HOT_TASKS, policy, now_s, writer=writer, batch=batch)


# ------------------------------------------------------------------------------------------------- files


def prune_directory(
    directory: Path | str,
    now_s: float,
    *,
    max_age_days: float,
    max_files: int | None = None,
    max_bytes: int | None = None,
) -> list[Path]:
    """Delete regular files in `directory` older than `max_age_days`, then the oldest beyond `max_files` and
    `max_bytes`. For `exports/` (14 days, 400 files) and `snapshots/` (7 days, 2 GiB). Returns deleted paths.

    Only plain files directly inside the directory are considered; subdirectories and symlinks are left alone.
    """
    folder = Path(directory)
    if not folder.is_dir():
        return []
    files: list[tuple[float, int, Path]] = []
    for entry in os.scandir(folder):
        if entry.is_file(follow_symlinks=False):
            info = entry.stat(follow_symlinks=False)
            files.append((info.st_mtime, info.st_size, Path(entry.path)))
    files.sort()  # oldest first
    doomed: list[Path] = []
    keep: list[tuple[float, int, Path]] = []
    for mtime, size, path in files:
        if max_age_days > 0 and mtime < now_s - max_age_days * DAY_S:
            doomed.append(path)
        else:
            keep.append((mtime, size, path))
    if max_files is not None and len(keep) > max_files:
        overflow = len(keep) - max_files
        doomed += [p for _, _, p in keep[:overflow]]
        keep = keep[overflow:]
    if max_bytes is not None:
        total = sum(size for _, size, _ in keep)
        while keep and total > max_bytes:
            _, size, path = keep.pop(0)
            doomed.append(path)
            total -= size
    for path in doomed:
        with contextlib.suppress(FileNotFoundError):
            path.unlink()
    if doomed:
        log.info("files_pruned", extra={"fields": {"dir": str(folder), "files": len(doomed)}})
    return doomed


# ------------------------------------------------------------------------------------------- maintenance


@dataclass(frozen=True, slots=True)
class CheckpointResult:
    """`PRAGMA wal_checkpoint` result plus how long it took (recorded as a metric, plan 6.5)."""

    mode: str
    busy: bool
    wal_frames: int
    checkpointed_frames: int
    duration_ms: float


def checkpoint(conn: sqlite3.Connection, mode: str = "PASSIVE") -> CheckpointResult:
    """Run a WAL checkpoint on an autocommit connection (use `Database.maintenance`).

    PASSIVE (every 5 minutes on hot, control and metrics) copies what it can without taking the write lock or
    waiting for readers, so it can never stall rate-limit admits. TRUNCATE (once a day on cache and metrics)
    also resets the WAL file to zero bytes; it waits for readers, so it runs with a short busy timeout.
    """
    mode = mode.upper()
    if mode not in {"PASSIVE", "FULL", "RESTART", "TRUNCATE"}:
        raise ValueError(f"unknown checkpoint mode {mode!r}")
    started = time.perf_counter()
    row = conn.execute(f"PRAGMA wal_checkpoint({mode})").fetchone()
    duration_ms = (time.perf_counter() - started) * 1000
    busy, wal_frames, done = (int(row[0]), int(row[1]), int(row[2])) if row else (0, -1, -1)
    return CheckpointResult(mode, bool(busy), wal_frames, done, duration_ms)


def truncate_checkpoint(conn: sqlite3.Connection, busy_timeout_ms: int = 1000) -> CheckpointResult:
    """TRUNCATE checkpoint that waits at most `busy_timeout_ms` for readers and writers, then gives up."""
    previous = int(conn.execute("PRAGMA busy_timeout").fetchone()[0])
    conn.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
    try:
        return checkpoint(conn, "TRUNCATE")
    finally:
        conn.execute(f"PRAGMA busy_timeout={previous}")


def daily_truncate_due(
    now_s: float,
    *,
    maintenance_hour: int,
    tz_name: str,
    last_run_day: str | None,
    last_minute_rate: float | None = None,
    median_rate_24h: float | None = None,
) -> tuple[bool, str]:
    """Decide whether the daily TRUNCATE checkpoint (and optimize) should run now (plan 6.5).

    Due when the local hour in `tz_name` equals `maintenance_hour`, it has not run today, and (when both rates are
    known) the previous minute's request rate is below the 24 h median. Returns `(due, local_day)`; record
    `local_day` after a successful run and pass it back as `last_run_day`.
    """
    try:
        zone = ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError, ValueError):
        zone = ZoneInfo("UTC")
    local = datetime.fromtimestamp(now_s, zone)
    day = local.strftime("%Y-%m-%d")
    if local.hour != maintenance_hour or last_run_day == day:
        return False, day
    if last_minute_rate is not None and median_rate_24h is not None and last_minute_rate >= median_rate_24h:
        return False, day
    return True, day


def incremental_vacuum(conn: sqlite3.Connection, pages: int = INCREMENTAL_VACUUM_PAGES) -> int:
    """Return up to `pages` free pages to the file system (needs `auto_vacuum=INCREMENTAL`). Returns pages freed.

    Runs on an autocommit connection (`Database.maintenance`), in small steps so the write lock is short.
    """
    before = int(conn.execute("PRAGMA freelist_count").fetchone()[0])
    if before == 0:
        return 0
    conn.execute(f"PRAGMA incremental_vacuum({int(pages)})").fetchall()  # fetchall steps it to completion
    after = int(conn.execute("PRAGMA freelist_count").fetchone()[0])
    return before - after


def quick_check(conn: sqlite3.Connection, max_errors: int = 100) -> list[str]:
    """`PRAGMA quick_check`: an empty list means the file is healthy (plan 6.5, H-DB-INTEGRITY)."""
    rows = [str(r[0]) for r in conn.execute(f"PRAGMA quick_check({int(max_errors)})").fetchall()]
    return [] if rows == ["ok"] else rows


def optimize(conn: sqlite3.Connection) -> None:
    """`PRAGMA optimize`: refresh query planner statistics where they are stale (daily and on close)."""
    conn.execute("PRAGMA optimize")


def database_sizes(conn: sqlite3.Connection) -> dict[str, int]:
    """Page counts and sizes for the System and Data pages."""
    page_size = int(conn.execute("PRAGMA page_size").fetchone()[0])
    pages = int(conn.execute("PRAGMA page_count").fetchone()[0])
    free = int(conn.execute("PRAGMA freelist_count").fetchone()[0])
    return {
        "page_size": page_size,
        "pages": pages,
        "free_pages": free,
        "bytes": page_size * pages,
        "free_bytes": page_size * free,
    }
