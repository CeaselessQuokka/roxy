"""Unit tests for roxy.storage.migrate and the schema in roxy/storage/migrations (plan 6.2)."""

from __future__ import annotations

import sqlite3
import stat
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from roxy.storage import migrate
from roxy.storage.db import DB_NAMES, PROFILES, connect, open_databases
from roxy.storage.migrate import (
    REQUIRED_SCHEMA,
    Migration,
    MigrationError,
    SchemaTooOld,
    apply_migrations,
    auto_migrate,
    auto_migrate_enabled,
    check_schema,
    discover,
    latest_expand_version,
    migrate_all,
    migrate_paths,
    recover_cache_db,
    split_statements,
)

# Every table and column of plan 6.2 (plus DESIGN.md D5 columns). Extra columns are allowed; missing ones fail.
PLAN_SCHEMA: dict[str, dict[str, set[str]]] = {
    "control": {
        "schema_version": {"version", "applied_at", "name"},
        "settings": {"key", "value_json", "updated_at", "updated_by"},
        "settings_history": {"id", "key", "old_json", "new_json", "changed_at", "changed_by", "reason", "source"},
        "audit_log": {
            "id",
            "at",
            "actor",
            "actor_ip",
            "action",
            "target",
            "before_json",
            "after_json",
            "reason",
            "request_id",
        },
        "rules_endpoint_block": {"id", "pattern", "type", "note", "message", "created_at", "created_by", "enabled"},
        "rules_endpoint_limit": {"id", "pattern", "type", "scope", "limit", "period", "message", "note", "enabled"},
        "rules_cache": {
            "id",
            "pattern",
            "type",
            "ttl",
            "stale_ttl",
            "negative_ttl",
            "methods",
            "normalize_flags",
            "note",
            "enabled",
            "origin",
        },
        "rules_user_agent": {
            "id",
            "needle",
            "mode",
            "kind",
            "scope",
            "limit",
            "period",
            "cooldown",
            "message",
            "note",
            "enabled",
            "position",
        },
        "rules_header": {"id", "canonical_key", "scope", "mode", "needle", "header", "message", "note", "enabled"},
        "rules_routing": {"id", "pattern", "type", "mode", "note", "enabled", "created_at", "created_by"},
        "upstream_limits": {"bucket_key", "per_min", "burst", "origin", "note", "updated_at", "updated_by"},
        "credential_allowlist": {
            "id",
            "pattern",
            "type",
            "methods",
            "cache_private",
            "identical_anonymous",
            "note",
            "enabled",
            "created_at",
            "created_by",
        },
        "throttle_tiers": {"position", "multiplier", "message", "note", "action", "ban_minutes"},
        "cache_ignored_params": {"name", "note", "origin"},
        "ignored_value_headers": {"name", "note", "auto"},
        "ignored_paths": {"pattern", "note"},
        "access_list": {"id", "kind", "cidr", "note", "expires_at", "created_by"},
        "bans": {
            "id",
            "subject_type",
            "subject",
            "reason_code",
            "reason_text",
            "created_at",
            "expires_at",
            "created_by",
            "hits",
            "last_hit_at",
        },
        "service_state": {"key", "value_json"},
        "admin_users": {
            "id",
            "username",
            "password_hash",
            "totp_secret_enc",
            "recovery_codes_hash_json",
            "created_at",
            "last_login_at",
            "mfa_bootstrap_pending",
            "email",
        },
        "admin_prefs": {"user_id", "key", "value_json", "updated_at"},
        "admin_passkeys": {
            "id",
            "user_id",
            "credential_id",
            "public_key",
            "sign_count",
            "transports",
            "name",
            "created_at",
            "last_used_at",
        },
        "admin_sessions": {
            "id_hash",
            "user_id",
            "created_at",
            "last_seen_at",
            "expires_at",
            "ip",
            "ua",
            "epoch",
            "csrf_secret_hash",
            "mfa_level",
        },
        "trusted_devices": {
            "id",
            "token_hash",
            "user_id",
            "name",
            "ua_family",
            "created_at",
            "last_used_at",
            "expires_at",
        },
        "invalidation_tokens": {"token_hash", "user_id", "expires_at", "used_at"},
        "credential_store": {"id", "ciphertext", "nonce", "set_at", "set_by"},
        "credential_meta": {
            "id",
            "fingerprint",
            "masked",
            "account_id_fingerprint",
            "superseded_fingerprints_json",
            "set_at",
            "set_by",
            "status",
            "status_at",
            "last_probe_at",
            "last_probe_result",
        },
        "rotator_store": {"id", "ciphertext", "nonce", "set_at", "set_by", "masked_host"},
    },
    "hot": {
        "schema_version": {"version", "applied_at", "name"},
        "limiter": {"bucket_key", "tat_ms", "window_start", "count", "updated_at"},
        "strikes": {"ip", "strikes", "last_strike_at", "tier", "throttled_until"},
        "upstream_bucket": {"bucket_key", "tat_ms", "burst", "rate_per_s", "updated_at"},
        "aimd": {"key", "limit", "inflight", "last_change_at"},
        "cooldown": {"key", "until_ms", "source", "set_at", "hits"},
        "breaker": {"key", "state", "opened_at", "half_open_at", "failures", "successes", "window_start"},
        "lease": {"name", "holder", "expires_ms", "epoch", "payload_json"},
        "job_runs": {"idem_key", "epoch", "started_at", "finished_at"},
        "email_gate": {"key", "last_sent_at"},
        "login_failures": {"subject", "count", "window_start"},
        "spam_windows": {"subject", "buckets_json", "updated_at"},
        "csrf_cache": {"egress_identity", "token", "expires_at"},
    },
    "metrics": {
        "schema_version": {"version", "applied_at", "name"},
        "dims": {
            "dim_hash",
            "endpoint_template",
            "template_version",
            "host",
            "method",
            "egress",
            "outcome",
            "reason_code",
            "status",
            "source",
            "cache_state",
            "auth_class",
        },
        **{
            table: {
                "bucket_start",
                "dim_hash",
                "requests",
                "caller_bytes_in",
                "caller_bytes_out",
                "upstream_calls",
                "upstream_bytes_in",
                "upstream_bytes_out",
                "errors",
                "latency_hist",
                "queue_wait_hist",
            }
            for table in ("rollup_minute", "rollup_hour", "rollup_day", "rollup_month")
        },
        **{
            table: {
                "bucket_start",
                "client_type",
                "client_key",
                "requests",
                "refused",
                "served",
                "bytes",
                "top_endpoint",
            }
            for table in ("client_minute", "client_hour", "client_day")
        },
        "upstream_429": {
            "id",
            "at_ms",
            "endpoint_template",
            "host",
            "egress",
            "retry_after_s",
            "ratelimit_headers_json",
            "request_id",
        },
        "events": {
            "id",
            "at_ms",
            "type",
            "severity",
            "reason_code",
            "ip_hash",
            "place",
            "endpoint_template",
            "detail_json",
        },
        "request_samples": {
            "id",
            "at_ms",
            "key_id",
            "endpoint_template",
            "method",
            "client_hash",
            "place",
            "cache_state",
            "upstream_status",
            "egress",
            "body_hash",
            "bytes",
            "auth_class",
        },
        "annotations": {"id", "at", "kind", "label", "audit_id"},
        "egress_usage": {
            "bucket_start",
            "egress",
            "granularity",
            "requests",
            "req_bytes",
            "resp_bytes",
            "overhead_bytes",
        },
        "recommendations": {
            "id",
            "rule_id",
            "fingerprint",
            "state",
            "severity",
            "payload_json",
            "created_at",
            "updated_at",
            "expires_at",
            "snoozed_until",
            "dismissed_reason",
        },
        "recommendation_actions": {"id", "recommendation_id", "action", "at", "actor", "details_json"},
        "health_runs": {"id", "started_at", "finished_at", "trigger", "summary", "version"},
        "health_results": {
            "run_id",
            "check_id",
            "status",
            "value",
            "threshold",
            "explanation",
            "fix_link",
            "duration_ms",
        },
        "captures": {"id", "at", "request_id", "outcome", "status", "compressed_blob", "bytes"},
        "fingerprint_headers": {"name"},
        "fingerprint_values": {"value_hash"},
        "fingerprint_user_agents": {"ua_hash"},
        "errors": {
            "signature",
            "count",
            "first_seen",
            "last_seen",
            "source",
            "last_detail",
            "module_line",
            "traceback_redacted",
        },
        "anomalies": {"id", "at", "metric", "baseline", "observed", "zscore", "window"},
        "worker_heartbeat": {
            "pid",
            "started_at",
            "last_seen",
            "rss",
            "requests",
            "proxied",
            "loop_lag_ms_p99",
            "open_conns",
            "inflight_upstream",
            "color",
            "max_requests",
            "counters_reset_at",
        },
        "legacy_totals": {"key", "value_json"},
    },
    "cache": {
        "schema_version": {"version", "applied_at", "name"},
        "entries": {
            "id",
            "key",
            "auth_class",
            "method",
            "host",
            "path",
            "params_json",
            "req_body",
            "status",
            "content_type",
            "headers_json",
            "body",
            "body_len",
            "stored_at",
            "expires_at",
            "stale_until",
            "ttl",
            "rule_id",
            "egress",
            "hits",
            "last_hit_at",
            "bytes",
            "negative",
        },
        "generation": {"id"},
        "change_observations": {"endpoint_template", "day", "refetches", "identical_bodies"},
    },
}

WITHOUT_ROWID = {
    "metrics": {"rollup_minute", "rollup_hour", "rollup_day", "rollup_month"},
}


def _tables(conn: sqlite3.Connection) -> dict[str, str]:
    rows = conn.execute(
        "SELECT name, sql FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    return {str(r[0]): str(r[1]) for r in rows}


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {str(r[1]) for r in conn.execute(f'PRAGMA table_info("{table}")')}


@pytest.mark.parametrize("db_name", DB_NAMES)
def test_schema_has_every_plan_table_and_column(dbs, db_name: str) -> None:
    db = dbs.get(db_name)

    def inspect(conn: sqlite3.Connection) -> tuple[dict[str, str], dict[str, set[str]]]:
        tables = _tables(conn)
        return tables, {t: _columns(conn, t) for t in tables}

    tables, columns = db.read_sync(inspect)
    expected = PLAN_SCHEMA[db_name]
    missing_tables = set(expected) - set(tables)
    assert not missing_tables, f"{db_name}.db is missing tables {sorted(missing_tables)}"
    for table, cols in expected.items():
        assert cols <= columns[table], f"{db_name}.{table} is missing columns {sorted(cols - columns[table])}"
    for table in WITHOUT_ROWID.get(db_name, set()):
        assert "WITHOUT ROWID" in tables[table].upper()


def test_entries_is_a_rowid_table_for_batched_purge(dbs) -> None:
    sql = dbs.cache.read_sync(lambda c: _tables(c)["entries"])
    assert "WITHOUT ROWID" not in sql.upper()
    indexes = dbs.cache.read_sync(lambda c: {r[1] for r in c.execute("PRAGMA index_list(entries)")})
    for name in ("entries_expires_at", "entries_last_hit_at", "entries_host", "entries_rule_id"):
        assert name in indexes


def test_migration_files_are_well_formed() -> None:
    for name in DB_NAMES:
        found = discover(name)
        assert found, f"no migrations for {name}"
        assert [m.version for m in found] == list(range(1, len(found) + 1))
        for m in found:
            assert m.kind in ("expand", "contract")
            assert m.statements()
            assert "\u2014" not in m.sql
            assert "\u2013" not in m.sql


def test_required_schema_matches_newest_expand_migration() -> None:
    assert {name: latest_expand_version(name) for name in DB_NAMES} == REQUIRED_SCHEMA


def test_split_statements_respects_triggers_strings_and_comments() -> None:
    sql = """
    -- a comment; with a semicolon
    CREATE TABLE a (x TEXT DEFAULT 'semi;colon');
    CREATE TRIGGER t BEFORE UPDATE ON a BEGIN SELECT RAISE(ABORT, 'no; way'); SELECT 1; END;
    INSERT INTO a VALUES ('1'); INSERT INTO a VALUES ('2');
    """
    statements = split_statements(sql)
    assert len(statements) == 4
    assert statements[1].startswith("CREATE TRIGGER")
    assert statements[1].endswith("END;")
    with pytest.raises(MigrationError):
        split_statements("CREATE TABLE b (x")


def test_migrate_is_idempotent_and_records_versions(env) -> None:
    dbs = open_databases(env)
    try:
        first = migrate_all(dbs)
        # Every expand migration of each database runs once, in order (metrics.db has six since the wave 3b review).
        assert {name: [m.version for m in ran] for name, ran in first.items()} == {
            name: list(range(1, REQUIRED_SCHEMA[name] + 1)) for name in DB_NAMES
        }
        second = migrate_all(dbs)
        assert all(ran == [] for ran in second.values())
        rows = dbs.control.read_sync(lambda c: c.execute("SELECT version, name FROM schema_version").fetchall())
        assert [tuple(r) for r in rows] == [(1, "initial")]
        metrics_rows = dbs.metrics.read_sync(lambda c: c.execute("SELECT version, name FROM schema_version").fetchall())
        assert [tuple(r) for r in metrics_rows] == [
            (1, "initial"),
            (2, "insight_history"),
            (3, "health_details"),
            (4, "annotation_range"),
            (5, "producer_history"),
            (6, "annotation_scope"),
            (7, "limit_samples"),
        ]
        assert check_schema(dbs) == REQUIRED_SCHEMA
    finally:
        dbs.close_all_sync()


def test_concurrent_migrations_apply_each_file_once(tmp_path: Path) -> None:
    paths = {name: tmp_path / f"{name}.db" for name in DB_NAMES}
    results: list[dict[str, list[Migration]]] = []
    errors: list[BaseException] = []

    def run() -> None:
        try:
            results.append(migrate_paths(paths))
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=run) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert not errors
    for name in DB_NAMES:
        # Each migration file ran exactly once across the four racing runners.
        applied = sorted(m.version for r in results for m in r[name])
        assert applied == list(range(1, REQUIRED_SCHEMA[name] + 1))
        conn = sqlite3.connect(str(paths[name]))
        assert conn.execute("SELECT count(*) FROM schema_version").fetchone()[0] == REQUIRED_SCHEMA[name]
        conn.close()


def test_check_schema_refuses_old_databases(env) -> None:
    dbs = open_databases(env)
    try:
        with pytest.raises(SchemaTooOld) as info:
            check_schema(dbs)
        assert set(info.value.problems) == set(DB_NAMES)
        assert "--expand" in str(info.value)
        migrate_all(dbs)
        with pytest.raises(SchemaTooOld):
            check_schema(dbs, required={**REQUIRED_SCHEMA, "control": REQUIRED_SCHEMA["control"] + 1})
    finally:
        dbs.close_all_sync()


def test_failed_migration_rolls_back_completely(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bad = Migration("hot", 1, "broken", "expand", "CREATE TABLE ok_table (a);\nCREATE TABLE broken (;\n")
    monkeypatch.setattr(migrate, "discover", lambda name: [bad])
    conn = connect(tmp_path / "hot.db", PROFILES["hot"], "maintenance")
    try:
        with pytest.raises(MigrationError, match="0001_broken"):
            apply_migrations(conn, "hot")
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        assert "ok_table" not in names
        assert conn.execute("SELECT count(*) FROM schema_version").fetchone()[0] == 0
    finally:
        conn.close()


def test_contract_migrations_need_the_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    expand = Migration("hot", 1, "add", "expand", "CREATE TABLE a (x);")
    contract = Migration("hot", 2, "drop", "contract", "-- kind: contract\nDROP TABLE a;")
    later = Migration("hot", 3, "more", "expand", "CREATE TABLE b (x);")
    monkeypatch.setattr(migrate, "discover", lambda name: [expand, contract, later])
    conn = connect(tmp_path / "hot.db", PROFILES["hot"], "maintenance")
    try:
        assert [m.version for m in apply_migrations(conn, "hot")] == [1, 3]
        assert [m.version for m in apply_migrations(conn, "hot", contract=True)] == [2]
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        assert "a" not in names
        assert "b" in names
    finally:
        conn.close()


def test_kind_header_is_parsed() -> None:
    assert migrate._kind_of("-- kind: contract\nDROP TABLE x;") == "contract"
    assert migrate._kind_of("-- something\n-- kind: expand\nCREATE TABLE x (a);") == "expand"
    assert migrate._kind_of("CREATE TABLE x (a);\n-- kind: contract") == "expand"


def test_auto_migrate_only_in_development(tmp_path: Path) -> None:
    production = SimpleNamespace(env="production", auto_migrate=True, state_dir=tmp_path / "p")
    development = SimpleNamespace(env="development", auto_migrate="1", state_dir=tmp_path / "d")
    assert not auto_migrate_enabled(production)
    assert not auto_migrate_enabled(SimpleNamespace(env="development", auto_migrate=False))
    assert auto_migrate_enabled(development)
    assert auto_migrate_enabled({"ROXY_ENV": "development", "ROXY_AUTO_MIGRATE": "1"})
    prod_dbs = open_databases(production)
    dev_dbs = open_databases(development)
    try:
        assert auto_migrate(prod_dbs, production) is False
        assert not (tmp_path / "p" / "control.db").exists()
        assert auto_migrate(dev_dbs, development) is True
        assert check_schema(dev_dbs)["control"] == 1
    finally:
        prod_dbs.close_all_sync()
        dev_dbs.close_all_sync()


def test_cli_expand_status_and_usage(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    state = tmp_path / "cli"
    assert migrate.main(["--expand", "--state-dir", str(state)]) == 0
    out = capsys.readouterr().out
    assert "control: applied 0001_initial (expand)" in out
    for name in DB_NAMES:
        assert stat.S_IMODE((state / f"{name}.db").stat().st_mode) == 0o640
    assert stat.S_IMODE(state.stat().st_mode) == 0o750
    assert migrate.main(["--expand", "--contract", "--state-dir", str(state)]) == 0
    assert "control: up to date" in capsys.readouterr().out
    assert migrate.main(["--status", "--state-dir", str(state)]) == 0
    assert "hot: version 1 (this release requires 1)" in capsys.readouterr().out
    assert migrate.main([]) == 2


def test_cli_uses_environment_paths(env, state_dir: Path) -> None:
    assert migrate.main(["--expand"]) == 0
    assert (state_dir / "control.db").exists()


def test_audit_log_is_append_only(dbs) -> None:
    now = int(time.time())

    def insert(conn: sqlite3.Connection, at: int) -> int:
        return int(
            conn.execute("INSERT INTO audit_log (at, actor, action) VALUES (?, 'admin', 'login')", (at,)).lastrowid
        )

    recent = dbs.control.write_sync(lambda c: insert(c, now))
    ancient = dbs.control.write_sync(lambda c: insert(c, now - 500 * 86400))
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        dbs.control.write_sync(lambda c: c.execute("UPDATE audit_log SET actor = 'x' WHERE id = ?", (recent,)))
    with pytest.raises(sqlite3.IntegrityError, match="retention job"):
        dbs.control.write_sync(lambda c: c.execute("DELETE FROM audit_log WHERE id = ?", (ancient,)))
    # Even the gate cannot be opened for rows younger than 400 days.
    with pytest.raises(sqlite3.IntegrityError, match="400 days"):
        dbs.control.write_sync(
            lambda c: c.execute("INSERT INTO audit_prune_gate (id, cutoff_at) VALUES (1, ?)", (now,))
        )

    def gated_delete(conn: sqlite3.Connection) -> int:
        conn.execute("INSERT INTO audit_prune_gate (id, cutoff_at) VALUES (1, ?)", (now - 450 * 86400,))
        deleted = conn.execute("DELETE FROM audit_log WHERE at < ?", (now - 450 * 86400,)).rowcount
        conn.execute("DELETE FROM audit_prune_gate")
        return int(deleted)

    assert dbs.control.write_sync(gated_delete) == 1
    assert dbs.control.read_sync(lambda c: c.execute("SELECT count(*) FROM audit_log").fetchone()[0]) == 1


def test_single_slot_and_method_checks(dbs) -> None:
    store = "INSERT INTO credential_store (id, ciphertext, nonce, set_at, set_by) VALUES (?, x'00', x'00', 0, 'a')"
    dbs.control.write_sync(lambda c: c.execute(store, (1,)))
    with pytest.raises(sqlite3.IntegrityError):
        dbs.control.write_sync(lambda c: c.execute(store, (2,)))  # C1: there is no second slot
    allow = (
        "INSERT INTO credential_allowlist (pattern, type, methods, cache_private, created_at, created_by) "
        "VALUES ('x', 'glob', ?, 1, 0, 'admin')"
    )
    dbs.control.write_sync(lambda c: c.execute(allow, ("GET,HEAD",)))
    with pytest.raises(sqlite3.IntegrityError):
        dbs.control.write_sync(lambda c: c.execute(allow, ("POST",)))
    with pytest.raises(sqlite3.IntegrityError):  # cache_private has no default on purpose
        dbs.control.write_sync(
            lambda c: c.execute(
                "INSERT INTO credential_allowlist (pattern, type, created_at, created_by) VALUES ('y','glob',0,'a')"
            )
        )


def test_admin_users_bootstrap_columns_and_seeded_state(dbs) -> None:
    dbs.control.write_sync(
        lambda c: c.execute(
            "INSERT INTO admin_users (username, password_hash, created_at, email) "
            "VALUES ('Owner', 'h', 0, 'o@x.invalid')"
        )
    )
    row = dbs.control.read_sync(
        lambda c: c.execute("SELECT mfa_bootstrap_pending, email FROM admin_users WHERE username = 'owner'").fetchone()
    )
    assert tuple(row) == (0, "o@x.invalid")
    state = dbs.control.read_sync(lambda c: dict(c.execute("SELECT key, value_json FROM service_state").fetchall()))
    assert state["config_version"] == "0"
    assert dbs.cache.read_sync(lambda c: c.execute("SELECT value FROM generation WHERE id = 1").fetchone()[0]) == 0


def test_recover_cache_db_replaces_a_damaged_file(tmp_path: Path) -> None:
    path = tmp_path / "cache.db"
    assert recover_cache_db(path) is None  # missing file: nothing to do
    migrate_paths({name: tmp_path / f"{name}.db" for name in DB_NAMES})
    assert recover_cache_db(path) is None  # healthy
    path.write_bytes(b"this is not a sqlite database" * 200)
    aside = recover_cache_db(path)
    assert aside is not None
    assert aside.exists()
    conn = sqlite3.connect(str(path))
    assert conn.execute("SELECT count(*) FROM entries").fetchone()[0] == 0
    conn.close()
