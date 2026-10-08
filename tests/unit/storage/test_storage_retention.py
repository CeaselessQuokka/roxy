"""Unit tests for roxy.storage.retention (plan 6.10 and 6.5)."""

from __future__ import annotations

import asyncio
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

import pytest

from roxy.storage import retention
from roxy.storage.retention import (
    HOT_TASKS,
    RETENTION_TASKS,
    RetentionPolicy,
    daily_truncate_due,
    prune_directory,
    run_hot_prune,
    run_retention,
)

DAY = 86_400
NOW = float(int(time.time()))  # real time: the audit triggers check SQLite's own clock


def _count(db: Any, table: str, where: str = "1") -> int:
    return int(db.read_sync(lambda c: c.execute(f"SELECT count(*) FROM {table} WHERE {where}").fetchone()[0]))


def _loop(db: Any, fn: Any, policy: RetentionPolicy, limit: int = 5000) -> int:
    total = 0
    while True:
        deleted = db.write_sync(lambda c: fn(c, NOW, policy, limit))
        total += deleted
        if deleted < limit:
            return total


def test_every_plan_6_10_table_has_a_pruner() -> None:
    covered = {t.table for t in RETENTION_TASKS + HOT_TASKS}
    plan = {
        "rollup_minute",
        "rollup_hour",
        "rollup_day",
        "rollup_month",
        "client_minute",
        "client_hour",
        "client_day",
        "upstream_429",
        "events",
        "request_samples",
        "egress_usage",
        "recommendations",
        "recommendation_actions",
        "health_runs",
        "captures",
        "fingerprint_headers",
        "fingerprint_values",
        "fingerprint_user_agents",
        "errors",
        "anomalies",
        "worker_heartbeat",
        "annotations",
        "audit_log",
        "settings_history",
        "admin_sessions",
        "trusted_devices",
        "invalidation_tokens",
        "bans",
        "lease",
        "cooldown",
        "limiter",
        "job_runs",
    }
    assert plan <= covered


def test_rollups_by_age_and_forever(dbs) -> None:
    def fill(conn: sqlite3.Connection) -> None:
        for table in ("rollup_minute", "rollup_hour", "rollup_day", "rollup_month"):
            for age_days in (1, 20, 500, 5000):
                conn.execute(
                    f"INSERT INTO {table} (bucket_start, dim_hash) VALUES (?, 1)", (int(NOW - age_days * DAY),)
                )

    dbs.metrics.write_sync(fill)
    policy = RetentionPolicy()
    assert _loop(dbs.metrics, retention.prune_rollup_minute, policy) == 3  # older than 14 days
    assert _loop(dbs.metrics, retention.prune_rollup_hour, policy) == 2  # older than 400 days
    assert _loop(dbs.metrics, retention.prune_rollup_day, policy) == 0  # 0 = forever
    assert _loop(dbs.metrics, retention.prune_rollup_month, RetentionPolicy(retention_day_days=1000)) == 1


def test_events_age_then_cap_oldest_first(dbs) -> None:
    def fill(conn: sqlite3.Connection) -> None:
        rows = [(int((NOW - 100 * DAY) * 1000), "old")] * 5
        rows += [(int(NOW * 1000) + i, "new") for i in range(20)]
        conn.executemany("INSERT INTO events (at_ms, type, severity) VALUES (?, ?, 'info')", rows)

    dbs.metrics.write_sync(fill)
    deleted = _loop(dbs.metrics, retention.prune_events, RetentionPolicy(events_max_rows=12), limit=4)
    assert deleted == 5 + 8
    remaining = dbs.metrics.read_sync(lambda c: [r[0] for r in c.execute("SELECT at_ms FROM events ORDER BY id")])
    assert remaining == [int(NOW * 1000) + i for i in range(8, 20)]  # the newest 12 survive


def test_upstream_429_and_request_samples(dbs) -> None:
    def fill(conn: sqlite3.Connection) -> None:
        old, new = int((NOW - 91 * DAY) * 1000), int(NOW * 1000)
        conn.executemany(
            "INSERT INTO upstream_429 (at_ms, endpoint_template, host, egress) VALUES (?, 't', 'h', 'direct')",
            [(old,), (new,), (new,)],
        )
        conn.executemany(
            "INSERT INTO request_samples (at_ms, endpoint_template, method) VALUES (?, 't', 'GET')",
            [(int((NOW - 25 * 3600) * 1000),), (new,)],
        )

    dbs.metrics.write_sync(fill)
    assert _loop(dbs.metrics, retention.prune_upstream_429, RetentionPolicy(upstream_429_max_rows=1)) == 2
    assert _loop(dbs.metrics, retention.prune_request_samples, RetentionPolicy()) == 1


def test_settings_history_never_loses_the_newest_row_per_key(dbs) -> None:
    def fill(conn: sqlite3.Connection) -> None:
        for i in range(6):
            for key in ("a", "b"):
                conn.execute(
                    "INSERT INTO settings_history (key, new_json, changed_at, changed_by, source) "
                    "VALUES (?, ?, ?, 'admin', 'admin')",
                    (key, str(i), int(NOW - (10 - i) * DAY)),
                )

    dbs.control.write_sync(fill)
    _loop(dbs.control, retention.prune_settings_history, RetentionPolicy(settings_history_max_rows=1))
    rows = dbs.control.read_sync(
        lambda c: sorted(tuple(r) for r in c.execute("SELECT key, new_json FROM settings_history"))
    )
    assert rows == [("a", "5"), ("b", "5")]  # over the cap, but the latest of each key always stays
    _loop(dbs.control, retention.prune_settings_history, RetentionPolicy(retention_settings_history_days=1))
    assert _count(dbs.control, "settings_history") == 2


def test_audit_log_keeps_at_least_400_days(dbs) -> None:
    def fill(conn: sqlite3.Connection) -> None:
        for age in (10, 300, 399, 401, 800):
            conn.execute("INSERT INTO audit_log (at, actor, action) VALUES (?, 'admin', 'x')", (int(NOW - age * DAY),))

    dbs.control.write_sync(fill)
    # A setting below the minimum is raised to 400 days.
    assert _loop(dbs.control, retention.prune_audit_log, RetentionPolicy(retention_audit_days=30)) == 2
    assert _count(dbs.control, "audit_log") == 3
    assert _count(dbs.control, "audit_prune_gate") == 0  # the gate is closed again
    assert _loop(dbs.control, retention.prune_audit_log, RetentionPolicy(retention_audit_days=0)) == 0
    # A clock running in the future cannot push the cutoff past the real 400 days.
    future = retention.prune_audit_log
    deleted = dbs.control.write_sync(lambda c: future(c, NOW + 1000 * DAY, RetentionPolicy(), 5000))
    assert deleted == 0
    assert _count(dbs.control, "audit_log") == 3


def test_recommendations_open_items_are_never_pruned(dbs) -> None:
    def fill(conn: sqlite3.Connection) -> None:
        for i, state in enumerate(["open", "snoozed", "dismissed", "applied", "dismissed"]):
            conn.execute(
                "INSERT INTO recommendations (id, rule_id, fingerprint, state, severity, payload_json, created_at,"
                " updated_at) VALUES (?, 'R', ?, ?, 'low', '{}', 0, ?)",
                (f"rec_{i}", str(i), state, int(NOW - 400 * DAY)),
            )
            conn.execute(
                "INSERT INTO recommendation_actions (recommendation_id, action, at, actor) "
                "VALUES (?, 'snooze', ?, 'a')",
                (f"rec_{i}", int(NOW)),
            )

    dbs.metrics.write_sync(fill)
    assert _loop(dbs.metrics, retention.prune_recommendations, RetentionPolicy()) == 3
    states = dbs.metrics.read_sync(lambda c: sorted(r[0] for r in c.execute("SELECT state FROM recommendations")))
    assert states == ["open", "snoozed"]
    assert _loop(dbs.metrics, retention.prune_recommendation_actions, RetentionPolicy()) == 3


def test_health_runs_cap_takes_results_along(dbs) -> None:
    def fill(conn: sqlite3.Connection) -> None:
        for i in range(5):
            run_id = conn.execute(
                "INSERT INTO health_runs (started_at, trigger) VALUES (?, 'manual')",
                (int(NOW - (200 if i == 0 else 1) * DAY),),
            ).lastrowid
            conn.execute("INSERT INTO health_results (run_id, check_id, status) VALUES (?, 'H-X', 'pass')", (run_id,))
        conn.execute("INSERT INTO health_results (run_id, check_id, status) VALUES (999, 'H-ORPHAN', 'pass')")

    dbs.metrics.write_sync(fill)
    _loop(dbs.metrics, retention.prune_health, RetentionPolicy(health_runs_max=2))
    assert dbs.metrics.read_sync(lambda c: [r[0] for r in c.execute("SELECT id FROM health_runs ORDER BY id")]) == [
        4,
        5,
    ]
    assert _count(dbs.metrics, "health_results") == 2


def test_captures_by_ttl_count_and_bytes(dbs) -> None:
    def fill(conn: sqlite3.Connection) -> None:
        conn.execute("INSERT INTO captures (at, bytes) VALUES (?, 10)", (int(NOW - 2000),))
        for _ in range(6):
            conn.execute("INSERT INTO captures (at, bytes) VALUES (?, 100)", (int(NOW),))

    dbs.metrics.write_sync(fill)
    policy = RetentionPolicy(capture_max_records=5, capture_max_bytes=250)
    assert _loop(dbs.metrics, retention.prune_captures, policy) == 5  # 1 expired, 1 over count, 3 over bytes
    assert dbs.metrics.read_sync(lambda c: c.execute("SELECT sum(bytes) FROM captures").fetchone()[0]) == 200


def test_fingerprints_errors_anomalies_heartbeats_annotations(dbs) -> None:
    def fill(conn: sqlite3.Connection) -> None:
        for i in range(4):
            seen = int(NOW - (100 if i == 0 else i) * DAY)
            conn.execute(
                "INSERT INTO fingerprint_headers (name, first_seen, last_seen) VALUES (?, 0, ?)", (f"h{i}", seen)
            )
            conn.execute(
                "INSERT INTO fingerprint_values (value_hash, name, first_seen, last_seen) VALUES (?, 'h', 0, ?)",
                (f"v{i}", seen),
            )
            conn.execute(
                "INSERT INTO fingerprint_user_agents (ua_hash, user_agent, first_seen, last_seen) "
                "VALUES (?, 'u', 0, ?)",
                (f"u{i}", seen),
            )
            conn.execute("INSERT INTO errors (signature, first_seen, last_seen) VALUES (?, 0, ?)", (f"e{i}", seen))
            conn.execute("INSERT INTO anomalies (at, metric) VALUES (?, 'm')", (seen,))
            conn.execute("INSERT INTO worker_heartbeat (pid, started_at, last_seen) VALUES (?, 0, ?)", (i + 1, seen))
            conn.execute("INSERT INTO annotations (at, kind, label) VALUES (?, 'deploy', 'x')", (seen,))

    dbs.metrics.write_sync(fill)
    policy = RetentionPolicy(
        max_header_name_records=2,
        max_header_value_records=2,
        max_user_agent_records=2,
        max_error_records=2,
        anomalies_max_rows=2,
        heartbeat_max_rows=2,
        annotations_max_rows=2,
    )
    assert _loop(dbs.metrics, retention.prune_fingerprint_headers, policy) == 2
    assert _loop(dbs.metrics, retention.prune_fingerprint_values, policy) == 2
    assert _loop(dbs.metrics, retention.prune_fingerprint_user_agents, policy) == 2
    assert _loop(dbs.metrics, retention.prune_errors, policy) == 2
    assert _loop(dbs.metrics, retention.prune_anomalies, policy) == 2
    assert _loop(dbs.metrics, retention.prune_worker_heartbeat, policy) == 3  # older than 1 day, then the cap
    assert _loop(dbs.metrics, retention.prune_annotations, policy) == 2
    # The least recently seen are the ones removed.
    names = dbs.metrics.read_sync(lambda c: sorted(r[0] for r in c.execute("SELECT name FROM fingerprint_headers")))
    assert names == ["h1", "h2"]


def test_client_rows_beyond_the_top_fold_into_other(dbs) -> None:
    bucket = int(NOW // 60 * 60) - 120  # a closed minute

    def fill(conn: sqlite3.Connection) -> None:
        for i in range(8):
            conn.execute(
                "INSERT INTO client_minute (bucket_start, client_type, client_key, requests, refused, served, bytes) "
                "VALUES (?, 'ip', ?, ?, 1, ?, 10)",
                (bucket, f"198.51.100.{i}", i + 1, i),
            )

    dbs.metrics.write_sync(fill)
    total_before = dbs.metrics.read_sync(lambda c: c.execute("SELECT sum(requests) FROM client_minute").fetchone()[0])
    _loop(dbs.metrics, retention.prune_client_minute, RetentionPolicy(max_ip_activity_records=3))
    rows = dbs.metrics.read_sync(
        lambda c: {r[0]: r[1] for r in c.execute("SELECT client_key, requests FROM client_minute")}
    )
    assert set(rows) == {"198.51.100.7", "198.51.100.6", "198.51.100.5", "other"}  # top 3 plus one other row
    assert rows["other"] == 1 + 2 + 3 + 4 + 5
    total_after = dbs.metrics.read_sync(lambda c: c.execute("SELECT sum(requests) FROM client_minute").fetchone()[0])
    assert total_after == total_before


def test_place_clients_follow_max_caller_records(dbs) -> None:
    """Spec review 7: places have their own cap (`max_caller_records`), separate from IPs."""
    bucket = int(NOW // 60 * 60) - 120

    def fill(conn: sqlite3.Connection) -> None:
        for i in range(8):
            for ctype, key in (("ip", f"198.51.100.{i}"), ("place", f"{1000 + i}")):
                conn.execute(
                    "INSERT INTO client_minute (bucket_start, client_type, client_key, requests, refused, served, "
                    "bytes) VALUES (?, ?, ?, ?, 0, ?, 10)",
                    (bucket, ctype, key, i + 1, i + 1),
                )

    dbs.metrics.write_sync(fill)
    policy = RetentionPolicy.from_settings({"max_ip_activity_records": 5, "max_caller_records": 2}.get)
    assert (policy.max_ip_activity_records, policy.max_caller_records) == (5, 2)
    _loop(dbs.metrics, retention.prune_client_minute, policy)

    def kept(conn: sqlite3.Connection, ctype: str) -> set[str]:
        sql = "SELECT client_key FROM client_minute WHERE client_type = ? AND client_key != 'other'"
        return {r[0] for r in conn.execute(sql, (ctype,))}

    assert dbs.metrics.read_sync(lambda c: kept(c, "place")) == {"1007", "1006"}
    assert len(dbs.metrics.read_sync(lambda c: kept(c, "ip"))) == 5


def test_egress_usage_follows_rollup_retention(dbs) -> None:
    def fill(conn: sqlite3.Connection) -> None:
        for granularity in ("minute", "hour", "day", "month"):
            conn.execute(
                "INSERT INTO egress_usage (bucket_start, egress, granularity) VALUES (?, 'direct', ?)",
                (int(NOW - 500 * DAY), granularity),
            )

    dbs.metrics.write_sync(fill)
    assert _loop(dbs.metrics, retention.prune_egress_usage, RetentionPolicy()) == 2  # minute and hour only


def test_control_expiry_tables(dbs) -> None:
    def fill(conn: sqlite3.Connection) -> None:
        uid = conn.execute(
            "INSERT INTO admin_users (username, password_hash, created_at) VALUES ('o', 'h', 0)"
        ).lastrowid
        for name, exp in (("s1", NOW - 1), ("s2", NOW + 3600)):
            conn.execute(
                "INSERT INTO admin_sessions (id_hash, user_id, created_at, last_seen_at, expires_at, epoch, "
                "csrf_secret_hash, mfa_level) VALUES (?, ?, 0, 0, ?, 0, 'x', 'full')",
                (name, uid, int(exp)),
            )
            conn.execute(
                "INSERT INTO trusted_devices (token_hash, user_id, created_at, expires_at) VALUES (?, ?, 0, ?)",
                (name, uid, int(exp)),
            )
            conn.execute(
                "INSERT INTO invalidation_tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                (name, uid, int(exp)),
            )
        for expires in (None, NOW - 31 * DAY, NOW - 1 * DAY):
            conn.execute(
                "INSERT INTO bans (subject_type, subject, reason_code, created_at, expires_at, created_by) "
                "VALUES ('ip', '192.0.2.1', 'spam', 0, ?, 'admin')",
                (None if expires is None else int(expires),),
            )

    dbs.control.write_sync(fill)
    policy = RetentionPolicy()
    assert _loop(dbs.control, retention.prune_admin_sessions, policy) == 1
    assert _loop(dbs.control, retention.prune_trusted_devices, policy) == 1
    assert _loop(dbs.control, retention.prune_invalidation_tokens, policy) == 1
    assert _loop(dbs.control, retention.prune_bans, policy) == 1  # permanent and recently expired bans stay
    assert _count(dbs.control, "bans") == 2


def test_hot_prune_keeps_the_leader_row_and_live_state(dbs) -> None:
    now_ms = int(NOW * 1000)

    def fill(conn: sqlite3.Connection) -> None:
        conn.execute("INSERT INTO lease VALUES ('leader', 'w', 0, 7, NULL)")
        conn.execute("INSERT INTO lease VALUES ('sf:old', 'w', ?, 1, NULL)", (now_ms - 120_000,))
        conn.execute("INSERT INTO lease VALUES ('sf:live', 'w', ?, 1, NULL)", (now_ms + 10_000,))
        conn.execute("INSERT INTO cooldown VALUES ('c:old', ?, 'default', 0, 1)", (now_ms - 7200_000,))
        conn.execute("INSERT INTO cooldown VALUES ('c:live', ?, 'retry_after', 0, 1)", (now_ms + 1000,))
        conn.execute("INSERT INTO limiter VALUES ('ip:idle', ?, 0, 0, ?)", (now_ms - 1, int(NOW - 120)))
        conn.execute("INSERT INTO limiter VALUES ('ip:throttled', ?, 0, 0, ?)", (now_ms + 60_000, int(NOW - 120)))
        conn.execute("INSERT INTO limiter VALUES ('ip:active', ?, 0, 0, ?)", (now_ms, int(NOW)))
        conn.execute("INSERT INTO strikes VALUES ('192.0.2.11', 1, ?, 0, 0)", (int(NOW - 4000),))
        conn.execute("INSERT INTO strikes VALUES ('192.0.2.12', 3, ?, 2, ?)", (int(NOW - 4000), int(NOW + 600)))
        conn.execute("INSERT INTO job_runs VALUES ('job:x:1', 1, ?, NULL)", (int(NOW - 8 * DAY),))
        conn.execute("INSERT INTO job_runs VALUES ('job:x:2', 1, ?, NULL)", (int(NOW),))
        conn.execute("INSERT INTO csrf_cache VALUES ('direct', 't', ?)", (int(NOW - 1),))

    dbs.hot.write_sync(fill)

    results = asyncio.run(run_hot_prune(dbs, RetentionPolicy(), NOW))
    assert results["hot.lease"] == 1
    assert results["hot.cooldown"] == 1
    assert results["hot.limiter"] == 1
    assert results["hot.strikes"] == 1
    assert results["hot.job_runs"] == 1
    assert results["hot.csrf_cache"] == 1
    leases = dbs.hot.read_sync(lambda c: sorted(r[0] for r in c.execute("SELECT name FROM lease")))
    assert leases == ["leader", "sf:live"]


async def test_run_retention_works_in_batches_and_vacuums(dbs) -> None:
    def fill(conn: sqlite3.Connection) -> None:
        old = int((NOW - 200 * DAY) * 1000)
        conn.executemany(
            "INSERT INTO events (at_ms, type, severity, detail_json) VALUES (?, 't', 'info', ?)",
            [(old, "x" * 200) for _ in range(12_000)],
        )

    dbs.metrics.write_sync(fill)
    writes_before = dbs.metrics.stats.writes
    results = await run_retention(dbs, RetentionPolicy(), NOW, batch=5000)
    assert results["metrics.events"] == 12_000
    assert dbs.metrics.stats.writes - writes_before >= 3  # 5000 + 5000 + 2000, each its own transaction
    free = dbs.metrics.read_sync(lambda c: c.execute("PRAGMA freelist_count").fetchone()[0])
    assert free == 0  # incremental_vacuum handed the freed pages back to the file system
    assert set(results) == {f"{t.db}.{t.table}" for t in RETENTION_TASKS}


async def test_custom_writer_is_used_for_every_batch(dbs) -> None:
    seen: list[str] = []

    async def writer(db: Any, fn: Any) -> int:
        seen.append(db.name)
        result: int = await db.write(fn)
        return result

    await run_retention(dbs, RetentionPolicy(), NOW, writer=writer, vacuum=False)
    assert set(seen) == {"metrics", "control", "cache"}


def test_policy_from_settings_uses_known_keys_and_aliases() -> None:
    values = {"retention_minute_days": 7, "events_max_rows": 10_000, "throttle_strike_decay_seconds": 900}

    def get(key: str) -> Any:
        return values[key]

    policy = RetentionPolicy.from_settings(get)
    assert policy.retention_minute_days == 7
    assert policy.events_max_rows == 10_000
    assert policy.strike_idle_s == 900
    assert policy.retention_hour_days == 400  # unknown to the getter: default kept


async def test_maintenance_helpers(dbs) -> None:
    passive = await dbs.hot.maintenance(retention.checkpoint)
    assert passive.mode == "PASSIVE"
    assert not passive.busy
    assert passive.duration_ms >= 0
    truncate = await dbs.cache.maintenance(retention.truncate_checkpoint)
    assert truncate.mode == "TRUNCATE"
    assert await dbs.control.maintenance(retention.quick_check) == []
    await dbs.metrics.maintenance(retention.optimize)
    sizes = await dbs.metrics.maintenance(retention.database_sizes)
    assert sizes["bytes"] == sizes["pages"] * sizes["page_size"]
    with pytest.raises(ValueError):
        await dbs.hot.maintenance(lambda c: retention.checkpoint(c, "BOGUS"))


def test_daily_truncate_due() -> None:
    # 2025-01-15 09:30 UTC is 04:30 in New York (EST).
    at = 1_736_933_400.0
    due, day = daily_truncate_due(at, maintenance_hour=4, tz_name="America/New_York", last_run_day=None)
    assert due
    assert day == "2025-01-15"
    assert not daily_truncate_due(at, maintenance_hour=4, tz_name="America/New_York", last_run_day=day)[0]
    assert not daily_truncate_due(at, maintenance_hour=5, tz_name="America/New_York", last_run_day=None)[0]
    busy = daily_truncate_due(
        at, maintenance_hour=4, tz_name="America/New_York", last_run_day=None, last_minute_rate=50, median_rate_24h=10
    )
    assert not busy[0]
    assert daily_truncate_due(at, maintenance_hour=9, tz_name="Not/AZone", last_run_day=None)[0]  # falls back to UTC


def test_prune_directory_by_age_count_and_bytes(tmp_path: Path) -> None:
    folder = tmp_path / "exports"
    folder.mkdir()
    for i in range(6):
        path = folder / f"f{i}.json"
        path.write_bytes(b"x" * 100)
        age = 30 * DAY if i == 0 else (6 - i) * 60
        os.utime(path, (NOW - age, NOW - age))
    (folder / "sub").mkdir()
    deleted = prune_directory(folder, NOW, max_age_days=14, max_files=4, max_bytes=250)
    assert sorted(p.name for p in deleted) == ["f0.json", "f1.json", "f2.json", "f3.json"]
    assert sorted(p.name for p in folder.iterdir()) == ["f4.json", "f5.json", "sub"]
    assert prune_directory(tmp_path / "missing", NOW, max_age_days=1) == []
