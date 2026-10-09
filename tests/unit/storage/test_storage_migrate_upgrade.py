"""Upgrading a state written by the previous release: the wave 3b metrics migrations are expand only (plan 5.5).

What this is
    Tests that migrate a temporary state to the schema of the previous release (metrics.db at version 1, every
    other database at its current version), fill it with rows the way that release wrote them, then run this
    release's `--expand` and check: only the new metrics migrations run (2 `insight_history`, 3 `health_details`,
    4 `annotation_range`), every old row survives with sensible defaults in the new columns, the previous release's
    own statements still work on the upgraded file (so the old color keeps running during a deploy), this release's
    writers and readers work on it, and `check_schema` passes.

Why it exists
    Plan 17.4: `deploy.sh` migrates (expand) BEFORE it switches colors, so for a while the old color runs on the new
    schema. An expand migration must never break the previous release's reads and writes, and must never lose data.

How it works
    `migrate.discover` is patched to stop metrics.db at version 1 for the first migration (what the previous release
    shipped), then restored. The "previous release statements" are the INSERTs that release made with its own
    column lists (copied here from the 0001 schema, not imported, since this release's code may have changed).

What to read next
    `roxy/storage/migrate.py`, then `roxy/storage/migrations/metrics/0002_insight_history.sql` up to
    `0004_annotation_range.sql`.
"""

from __future__ import annotations

import sqlite3
from typing import Any

import pytest

from roxy.health import store as health_store
from roxy.metrics import queries
from roxy.metrics.annotate import insert_annotation
from roxy.storage import migrate
from roxy.storage.db import open_databases
from roxy.storage.migrate import DB_NAMES, REQUIRED_SCHEMA, check_schema, migrate_all

PREVIOUS_METRICS_VERSION = 1
"""metrics.db schema version of the previous release (commit 2db0f16)."""


def _metrics_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {str(row[1]) for row in conn.execute(f'PRAGMA table_info("{table}")')}  # a test constant


def _previous_release_writes(conn: sqlite3.Connection) -> None:
    """Rows the previous release wrote, with its own column lists."""
    conn.execute(
        "INSERT INTO health_runs (id, started_at, finished_at, trigger, summary, version) VALUES (?, ?, ?, ?, ?, ?)",
        (7, 1_700_000_000, 1_700_000_030, "manual", '{"pass": 3, "warn": 1, "fail": 0}', "2db0f16"),
    )
    conn.execute(
        "INSERT INTO health_results (run_id, check_id, status, value, threshold, explanation, fix_link, duration_ms) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (7, "H-CLOCK", "pass", "0.1 s", "< 2 s", "The clock is in sync.", "/admin/system#clock", 12.5),
    )
    conn.execute(
        "INSERT INTO annotations (at, kind, label, audit_id) VALUES (?, ?, ?, ?)",
        (1_700_000_100, "reset", "Data reset: traffic", 41),
    )


@pytest.fixture
def previous_state(env: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    """A state migrated to the previous release's schema, with that release's rows in it."""
    real_discover = migrate.discover

    def previous(db_name: str) -> list[migrate.Migration]:
        found = real_discover(db_name)
        if db_name == "metrics":
            return [m for m in found if m.version <= PREVIOUS_METRICS_VERSION]
        return found

    monkeypatch.setattr(migrate, "discover", previous)
    dbs = open_databases(env)
    try:
        first = migrate_all(dbs)
        assert [m.version for m in first["metrics"]] == [1]
        dbs.metrics.write_sync(_previous_release_writes)
    finally:
        monkeypatch.setattr(migrate, "discover", real_discover)
    yield dbs
    dbs.close_all_sync()


def test_previous_schema_upgrades_with_the_new_metrics_migrations_only(previous_state: Any) -> None:
    dbs = previous_state
    ran = migrate_all(dbs)
    assert [m.name for m in ran["metrics"]] == ["insight_history", "health_details", "annotation_range"]
    assert all(m.kind == "expand" for m in ran["metrics"])
    assert {name: ran[name] for name in DB_NAMES if name != "metrics"} == {"control": [], "hot": [], "cache": []}
    assert check_schema(dbs) == REQUIRED_SCHEMA
    assert migrate_all(dbs)["metrics"] == []  # idempotent


def test_old_rows_survive_and_new_columns_have_defaults(previous_state: Any) -> None:
    dbs = previous_state
    migrate_all(dbs)

    def read(conn: sqlite3.Connection) -> dict[str, Any]:
        return {
            "run": dict(conn.execute("SELECT * FROM health_runs WHERE id = 7").fetchone()),
            "result": dict(conn.execute("SELECT * FROM health_results WHERE run_id = 7").fetchone()),
            "annotation": dict(conn.execute("SELECT * FROM annotations").fetchone()),
            "result_columns": _metrics_columns(conn, "health_results"),
            "tables": {str(r[0]) for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")},
        }

    seen = dbs.metrics.read_sync(read)
    assert seen["run"]["trigger"] == "manual"
    assert seen["run"]["options_json"] is None
    assert seen["run"]["actor"] is None
    assert seen["result"]["status"] == "pass"
    assert seen["result"]["critical"] == 0
    assert seen["result"]["detail_json"] is None
    assert {"critical", "measured", "unit", "detail_json", "finished_ms"} <= seen["result_columns"]
    assert seen["annotation"]["label"] == "Data reset: traffic"
    assert seen["annotation"]["until"] is None
    assert {"bucket_minute", "worker_minute", "rule_hits", "recommendation_watches", "health_job_status"} <= set(
        seen["tables"]
    )


def test_previous_release_statements_still_work_after_the_upgrade(previous_state: Any) -> None:
    """During a deploy the old color keeps writing with its own column lists (expand only, plan 5.5)."""
    dbs = previous_state
    migrate_all(dbs)

    def old_writer(conn: sqlite3.Connection) -> None:
        conn.execute(
            "INSERT INTO health_runs (started_at, finished_at, trigger, summary, version) VALUES (?, ?, ?, ?, ?)",
            (1_700_001_000, None, "schedule", None, "2db0f16"),
        )
        conn.execute(
            "INSERT INTO annotations (at, kind, label, audit_id) VALUES (?, 'config_change', ?, NULL)",
            (1_700_001_000, "Setting changed"),
        )

    dbs.metrics.write_sync(old_writer)
    old_reader = dbs.metrics.read_sync(
        lambda conn: conn.execute("SELECT id, at, kind, label, audit_id FROM annotations ORDER BY id").fetchall()
    )
    assert [row[2] for row in old_reader] == ["reset", "config_change"]


def test_this_releases_writers_and_readers_work_on_the_upgraded_file(previous_state: Any) -> None:
    dbs = previous_state
    migrate_all(dbs)

    def write(conn: sqlite3.Connection) -> int:
        health_store.write_job_status(
            conn, [{"name": "insights_evaluate", "interval_s": 30, "last_ok": True}], now=1_700_002_000, holder="w1"
        )
        return insert_annotation(conn, 1_700_000_000, "reset", "Data reset: 1 h", 42, until=1_700_003_600)

    assert dbs.metrics.write_sync(write) > 0
    # A window strictly inside the ranged reset is flagged, and so is the old instant reset inside its window.
    inside = dbs.metrics.read_sync(lambda conn: queries.reset_annotations(conn, 1_700_001_000, 1_700_002_000))
    assert [row["label"] for row in inside] == ["Data reset: 1 h"]
    assert inside[0]["until"] == 1_700_003_600
    around_old = dbs.metrics.read_sync(lambda conn: queries.reset_annotations(conn, 1_700_000_050, 1_700_000_200))
    assert [row["label"] for row in around_old] == ["Data reset: 1 h", "Data reset: traffic"]
    assert dbs.metrics.read_sync(lambda conn: queries.reset_annotations(conn, 1_700_003_600, 1_700_004_000)) == []
    status = dbs.metrics.read_sync(lambda conn: health_store.read_job_status(conn, 1_700_001_000))
    assert [fact.name for fact in status] == ["insights_evaluate"]
