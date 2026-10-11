"""Upgrading a state written by an earlier release: the wave 3b metrics migrations are expand only (plan 5.5).

What this is
    Tests that migrate a temporary state to the schema of an earlier release (metrics.db at version 1 for the wave 2
    release, commit 2db0f16, at version 4 for the wave 3b release, commit bb96d16, at version 6 for the review
    round 3 tree, at version 7 for the P11 checkpoint, commit 94ca1c3, or at version 8 for the P11 gaps round; every
    other database at its current version), fill it with rows the way that release wrote them, then run this
    release's `--expand` and check: only the newer metrics migrations run (2 `insight_history`, 3 `health_details`,
    4 `annotation_range`, 5 `producer_history`, 6 `annotation_scope`, 7 `limit_samples`, 8 `user_agent_detail`,
    9 `dashboard_read_indexes`), every old row survives with sensible defaults in the new columns, the earlier
    release's own statements still work on the upgraded file (so the old color keeps running during a deploy), this
    release's writers and readers work on it (the schema 5 producer tables, the schema 6 reset scope, the schema 7
    sample rates and refusal samples, the schema 8 User-Agent drill-down and the schema 9 event and client indexes
    included, which index the rows the earlier release wrote), and `check_schema` passes.

Why it exists
    Plan 17.4: `deploy.sh` migrates (expand) BEFORE it switches colors, so for a while the old color runs on the new
    schema. An expand migration must never break the previous release's reads and writes, and must never lose data.
    Every place that names the metrics schema number (`REQUIRED_SCHEMA`, DESIGN.md 14.2) moves with the newest file.

How it works
    `migrate.discover` is patched to stop metrics.db at the earlier release's version for the first migration (what
    that release shipped), then restored. The "earlier release statements" are the INSERTs that release made with
    its own column lists (copied here from the 0001 to 0004 schemas, not imported, since this release's code may have
    changed).

What to read next
    `roxy/storage/migrate.py`, then `roxy/storage/migrations/metrics/0002_insight_history.sql` up to
    `0009_dashboard_read_indexes.sql`.
"""

from __future__ import annotations

import sqlite3
from typing import Any

import pytest

from roxy.health import store as health_store
from roxy.metrics import queries, read_client_extras, read_clients, read_history, read_security, read_upstream
from roxy.metrics.annotate import insert_annotation
from roxy.metrics.fingerprints import FingerprintItem, RequestDetail, row_hash, write_fingerprints
from roxy.metrics.producers import TABLE_RULE_HITS, ProducerItem, write_producers
from roxy.metrics.read_producers import rule_hit_counts
from roxy.metrics.samples import RefusalSample, SampleRow, write_refusal_samples, write_samples
from roxy.storage import migrate
from roxy.storage.db import open_databases
from roxy.storage.migrate import DB_NAMES, REQUIRED_SCHEMA, check_schema, migrate_all

NEWER_MIGRATIONS: dict[int, list[str]] = {
    1: [  # wave 2 (2db0f16)
        "insight_history",
        "health_details",
        "annotation_range",
        "producer_history",
        "annotation_scope",
        "limit_samples",
        "user_agent_detail",
        "dashboard_read_indexes",
    ],
    4: [  # wave 3b (bb96d16)
        "producer_history",
        "annotation_scope",
        "limit_samples",
        "user_agent_detail",
        "dashboard_read_indexes",
    ],
    6: ["limit_samples", "user_agent_detail", "dashboard_read_indexes"],  # review round 3 (before round 4)
    7: ["user_agent_detail", "dashboard_read_indexes"],  # the P11 checkpoint (94ca1c3)
    8: ["dashboard_read_indexes"],  # the P11 gaps round (schema 8, the User-Agent drill-down)
}
"""metrics.db schema version of an earlier release -> the migrations this release adds on top of it, in order."""

OLD_UA_HASH = row_hash("Roblox/WinInet")
"""The key every release writes for this User-Agent (`fingerprints.row_hash`)."""

PRODUCER_TABLES = {
    "rule_hit_minute",
    "tarpit_minute",
    "tarpit_hold_minute",
    "client_score_hour",
    "metrics_pipeline_minute",
    "disk_samples",
    "table_size_samples",
}
"""The tables of `0005_producer_history.sql`."""


def _metrics_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {str(row[1]) for row in conn.execute(f'PRAGMA table_info("{table}")')}  # a test constant


def _old_event_and_client_writes(conn: sqlite3.Connection, base_s: int) -> None:
    """Events and client minutes with the column lists every release has written them with (`metrics/recorder.py
    write_events`, `metrics/rollups.py write_clients`): a refusal, a refusal folded over the event budget, a failure
    and a live row, and an address, a place and their pair. Schema 9 indexes them whoever wrote them."""
    at = base_s * 1000
    conn.executemany(
        "INSERT INTO events (at_ms, type, severity, reason_code, ip_hash, place, endpoint_template, detail_json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (
                at,
                "refusal",
                "info",
                "throttle",
                "00ab",
                "9100001",
                "t/x",
                '{"message_source":"default","method":"GET","path":"t/x/1","status":429}',
            ),
            (
                at + 60_000,
                "refusal",
                "info",
                "throttle",
                None,
                "9100001",
                "t/x",
                '{"aggregated":true,"count":3,"message_source":"default","status":429}',
            ),
            (
                at + 1,
                "failure",
                "warn",
                "upstream_5xx",
                "00ab",
                None,
                "t/x",
                '{"egress":"direct","method":"GET","status":502,"upstream_status":503}',
            ),
            (
                at + 2,
                "live",
                "info",
                "cache_hit",
                None,
                "9100001",
                "t/x",
                '{"ip":"203.0.113.4","place":"9100001","status":200}',
            ),
        ],
    )
    conn.executemany(
        "INSERT INTO client_minute (bucket_start, client_type, client_key, requests, refused, served, bytes, "
        "top_endpoint) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (bucket_start, client_type, client_key) DO UPDATE "
        "SET requests = requests + excluded.requests, refused = refused + excluded.refused, "
        "served = served + excluded.served, bytes = bytes + excluded.bytes",
        [
            (base_s, "ip", "203.0.113.4", 4, 1, 3, 900, "t/x"),
            (base_s, "place", "9100001", 4, 1, 3, 900, "t/x"),
            (base_s, "pair", "203.0.113.4|9100001", 4, 1, 3, 900, None),
        ],
    )


def _earlier_release_writes(version: int) -> Any:
    """Rows the earlier release wrote, with its own column lists."""

    def write(conn: sqlite3.Connection) -> None:
        conn.execute(
            "INSERT INTO health_runs (id, started_at, finished_at, trigger, summary, version) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (7, 1_700_000_000, 1_700_000_030, "manual", '{"pass": 3, "warn": 1, "fail": 0}', "2db0f16"),
        )
        conn.execute(
            "INSERT INTO health_results (run_id, check_id, status, value, threshold, explanation, fix_link, "
            "duration_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (7, "H-CLOCK", "pass", "0.1 s", "< 2 s", "The clock is in sync.", "/admin/system#clock", 12.5),
        )
        conn.execute(
            "INSERT INTO annotations (at, kind, label, audit_id) VALUES (?, ?, ?, ?)",
            (1_700_000_100, "reset", "Data reset: traffic", 41),
        )
        conn.execute(  # the request sample column list of every release before schema 7 (`metrics/samples.py`)
            "INSERT INTO request_samples (at_ms, key_id, endpoint_template, method, client_hash, place, cache_state, "
            "upstream_status, egress, body_hash, bytes, auth_class) VALUES (1, 'k', 't', 'GET', NULL, NULL, 'MISS', "
            "200, 'direct', NULL, 10, 'anon')"
        )
        conn.execute(  # the User-Agent upsert of every release before schema 8 (`metrics/fingerprints.py`)
            "INSERT INTO fingerprint_user_agents (ua_hash, user_agent, count, first_seen, last_seen) "
            "VALUES (?, 'Roblox/WinInet', 3, 1700000000, 1700000060)",
            (OLD_UA_HASH,),
        )
        _old_event_and_client_writes(conn, 1_700_000_000)
        if version >= 4:
            # The wave 3b release also wrote the schema 2 to 4 tables.
            conn.execute(
                "INSERT INTO health_job_status (name, interval_s, last_started_at, last_finished_at, last_ok, holder, "
                "published_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("llm_export_file", 3600, 1_700_000_000, 1_700_000_001, 1, "w0", 1_700_000_002),
            )

    return write


@pytest.fixture(params=sorted(NEWER_MIGRATIONS), ids=lambda version: f"from_metrics_{version}")
def previous_state(request: pytest.FixtureRequest, env: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    """A state migrated to an earlier release's schema, with that release's rows in it. Yields (dbs, version)."""
    version = int(request.param)
    real_discover = migrate.discover

    def earlier(db_name: str) -> list[migrate.Migration]:
        found = real_discover(db_name)
        if db_name == "metrics":
            return [m for m in found if m.version <= version]
        return found

    monkeypatch.setattr(migrate, "discover", earlier)
    dbs = open_databases(env)
    try:
        first = migrate_all(dbs)
        assert [m.version for m in first["metrics"]] == list(range(1, version + 1))
        dbs.metrics.write_sync(_earlier_release_writes(version))
    finally:
        monkeypatch.setattr(migrate, "discover", real_discover)
    yield dbs, version
    dbs.close_all_sync()


def test_newest_metrics_migration_is_covered_by_the_upgrade_from_every_earlier_release() -> None:
    """The newest metrics migration is what every earlier release's upgrade ends with (no file left untested)."""
    newest = [m.name for m in migrate.discover("metrics")][-1]
    assert REQUIRED_SCHEMA["metrics"] == len(migrate.discover("metrics"))
    assert all(names[-1] == newest for names in NEWER_MIGRATIONS.values())
    assert NEWER_MIGRATIONS[1] == [m.name for m in migrate.discover("metrics")][1:]


def test_previous_schema_upgrades_with_the_new_metrics_migrations_only(previous_state: Any) -> None:
    dbs, version = previous_state
    ran = migrate_all(dbs)
    assert [m.name for m in ran["metrics"]] == NEWER_MIGRATIONS[version]
    assert [m.version for m in ran["metrics"]] == list(range(version + 1, REQUIRED_SCHEMA["metrics"] + 1))
    assert all(m.kind == "expand" for m in ran["metrics"])
    assert {name: ran[name] for name in DB_NAMES if name != "metrics"} == {"control": [], "hot": [], "cache": []}
    assert check_schema(dbs) == REQUIRED_SCHEMA
    assert migrate_all(dbs)["metrics"] == []  # idempotent


def test_old_rows_survive_and_new_columns_have_defaults(previous_state: Any) -> None:
    dbs, version = previous_state
    migrate_all(dbs)

    def read(conn: sqlite3.Connection) -> dict[str, Any]:
        return {
            "run": dict(conn.execute("SELECT * FROM health_runs WHERE id = 7").fetchone()),
            "result": dict(conn.execute("SELECT * FROM health_results WHERE run_id = 7").fetchone()),
            "annotation": dict(conn.execute("SELECT * FROM annotations").fetchone()),
            "result_columns": _metrics_columns(conn, "health_results"),
            "tables": {str(r[0]) for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")},
            "jobs": [str(r[0]) for r in conn.execute("SELECT name FROM health_job_status")],
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
    assert seen["annotation"]["reset_tables"] is None  # an old marker: read as touching every number
    assert {"bucket_minute", "worker_minute", "rule_hits", "recommendation_watches", "health_job_status"} <= set(
        seen["tables"]
    )
    assert set(seen["tables"]) >= PRODUCER_TABLES
    assert "refusal_samples" in seen["tables"]  # schema 7
    assert seen["jobs"] == (["llm_export_file"] if version >= 4 else [])
    sample = dbs.metrics.read_sync(
        lambda conn: dict(conn.execute("SELECT at_ms, sample_pct FROM request_samples WHERE at_ms = 1").fetchone())
    )
    assert sample == {"at_ms": 1, "sample_pct": None}  # an old sample: the dry run reads its rate from history
    agent = dbs.metrics.read_sync(lambda conn: read_security.user_agent_detail(conn, OLD_UA_HASH))
    assert agent is not None
    assert (agent["user_agent"], agent["count"], agent["last_seen"]) == ("Roblox/WinInet", 3, 1_700_000_060)
    # Schema 8: an old User-Agent row keeps its counts and has no request detail (the drawer says so).
    assert not agent["has_detail"]
    assert (agent["last_path"], agent["last_caller"], agent["last_header_names"]) == (None, None, [])


def test_previous_release_statements_still_work_after_the_upgrade(previous_state: Any) -> None:
    """During a deploy the old color keeps writing with its own column lists (expand only, plan 5.5)."""
    dbs, _version = previous_state
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
        conn.execute(  # the old color's sample writer (no `sample_pct`) on the schema 7 file
            "INSERT INTO request_samples (at_ms, key_id, endpoint_template, method, client_hash, place, cache_state, "
            "upstream_status, egress, body_hash, bytes, auth_class) VALUES (2, 'k', 't', 'GET', NULL, NULL, 'HIT', "
            "NULL, 'none', NULL, 10, 'anon')"
        )
        conn.execute(  # the old color's User-Agent upsert (no request detail) on the schema 8 file
            "INSERT INTO fingerprint_user_agents (ua_hash, user_agent, count, first_seen, last_seen) "
            "VALUES (?, 'Roblox/WinInet', 2, 1700000100, 1700000200) "
            "ON CONFLICT (ua_hash) DO UPDATE SET count = count + excluded.count, "
            "first_seen = min(first_seen, excluded.first_seen), last_seen = max(last_seen, excluded.last_seen)",
            (OLD_UA_HASH,),
        )

    dbs.metrics.write_sync(old_writer)
    old_reader = dbs.metrics.read_sync(
        lambda conn: conn.execute("SELECT id, at, kind, label, audit_id FROM annotations ORDER BY id").fetchall()
    )
    assert [row[2] for row in old_reader] == ["reset", "config_change"]
    old_agents = dbs.metrics.read_sync(  # the old color's User-Agent reader
        lambda conn: conn.execute(
            "SELECT user_agent, count, first_seen, last_seen FROM fingerprint_user_agents"
        ).fetchall()
    )
    assert [tuple(row) for row in old_agents] == [("Roblox/WinInet", 5, 1_700_000_000, 1_700_000_200)]
    # Schema 9: the old color's event and client writes still work (the generated columns are VIRTUAL, never named
    # by its INSERTs), and its own JSON reads of the events still answer.
    dbs.metrics.write_sync(lambda conn: _old_event_and_client_writes(conn, 1_700_000_600))
    old_split = dbs.metrics.read_sync(
        lambda conn: conn.execute(
            "SELECT reason_code, coalesce(json_extract(detail_json, '$.message_source'), '') AS src, "
            "sum(coalesce(json_extract(detail_json, '$.count'), 1)) AS n FROM events "
            "WHERE type IN ('refusal', 'failure') AND at_ms >= ? AND at_ms < ? GROUP BY reason_code, src",
            (0, 2**62),
        ).fetchall()
    )
    assert sorted(tuple(row) for row in old_split) == [("throttle", "default", 8), ("upstream_5xx", "", 2)]


def test_this_releases_writers_and_readers_work_on_the_upgraded_file(previous_state: Any) -> None:
    dbs, _version = previous_state
    migrate_all(dbs)

    def write(conn: sqlite3.Connection) -> int:
        health_store.write_job_status(
            conn, [{"name": "insights_evaluate", "interval_s": 30, "last_ok": True}], now=1_700_002_000, holder="w1"
        )
        # Two workers' flushes of the same minute add up (schema 5, `metrics/producers.py`).
        hit = ProducerItem(TABLE_RULE_HITS, (1_700_000_040, "rules_endpoint_block", "7"), (2,))
        write_producers(conn, [hit])
        write_producers(conn, [ProducerItem(TABLE_RULE_HITS, hit.key, (3,))])
        return insert_annotation(
            conn, 1_700_000_000, "reset", "Data reset: 1 h", 42, until=1_700_003_600, tables=["metrics.events"]
        )

    assert dbs.metrics.write_sync(write) > 0
    # A window strictly inside the ranged reset is flagged, and so is the old instant reset inside its window.
    inside = dbs.metrics.read_sync(lambda conn: queries.reset_annotations(conn, 1_700_001_000, 1_700_002_000))
    assert [row["label"] for row in inside] == ["Data reset: 1 h"]
    assert inside[0]["until"] == 1_700_003_600
    assert inside[0]["reset_tables"] == ["metrics.events"]  # schema 6: the marker names what it deleted
    assert not queries.reset_touches(inside[0], queries.ROLLUP_TABLES)
    around_old = dbs.metrics.read_sync(lambda conn: queries.reset_annotations(conn, 1_700_000_050, 1_700_000_200))
    assert [row["label"] for row in around_old] == ["Data reset: 1 h", "Data reset: traffic"]
    assert dbs.metrics.read_sync(lambda conn: queries.reset_annotations(conn, 1_700_003_600, 1_700_004_000)) == []
    status = dbs.metrics.read_sync(lambda conn: health_store.read_job_status(conn, 1_700_001_000))
    assert [fact.name for fact in status] == ["insights_evaluate"]
    hits = dbs.metrics.read_sync(lambda conn: rule_hit_counts(conn, 1_700_000_000, 1_700_000_100))
    assert hits == {("rules_endpoint_block", "7"): 5}

    def write_samples_now(conn: sqlite3.Connection) -> None:  # schema 7: the sample rate and the refusal samples
        write_samples(
            conn, [SampleRow(5_000, "k", "t", "GET", "c", None, "MISS", 200, "direct", None, 1, "anon", 50.0)]
        )
        write_refusal_samples(conn, [RefusalSample(5_000, "throttle", "t", "GET", "c", None, 50.0)])

    dbs.metrics.write_sync(write_samples_now)
    samples = dbs.metrics.read_sync(lambda conn: read_history.samples_between(conn, 5, 6))
    refusals = dbs.metrics.read_sync(lambda conn: read_history.refusal_samples_between(conn, 5, 6))
    assert [(s["at_ms"], s["sample_pct"]) for s in samples] == [(5_000, 50.0)]
    assert [(r["reason"], r["sample_pct"]) for r in refusals] == [("throttle", 50.0)]

    def write_agent_detail(conn: sqlite3.Connection) -> None:  # schema 8: the User-Agent drill-down
        detail = RequestDetail("games.roblox.com/v1/games", "203.0.113.9", ["Host", "User-Agent", "Accept"])
        item = FingerprintItem("u", "Roblox/WinInet", 1, 1_700_000_300, 1_700_000_300, detail)
        write_fingerprints(conn, [item], value_cap=10)

    dbs.metrics.write_sync(write_agent_detail)
    agent = dbs.metrics.read_sync(lambda conn: read_security.user_agent_detail(conn, OLD_UA_HASH))
    assert agent is not None
    assert agent["count"] == 4
    assert agent["has_detail"]
    assert (agent["last_path"], agent["last_caller"], agent["last_detail_at"]) == (
        "games.roblox.com/v1/games",
        "203.0.113.9",
        1_700_000_300,
    )
    assert agent["last_header_names"] == ["host", "user-agent", "accept"]

    # Schema 9: the rows the earlier release wrote before the upgrade are in the new indexes (built by the migration),
    # so the index reads answer for them exactly as the JSON reads did.
    def schema_9_reads(conn: sqlite3.Connection) -> dict[str, Any]:
        window = queries.Window(1_699_999_000, 1_700_001_000, "minute", "UTC")
        pieces = [("client_minute", 1_699_999_000, 1_700_001_000)]
        return {
            "split": queries.message_source_split(conn, window),
            "failures": read_upstream.failure_log(conn, 1_699_999_000_000, 1_700_001_000_000),
            "place": read_clients.client_refusals(
                conn, start_ms=1_699_999_000_000, end_ms=1_700_001_000_000, place="9100001"
            ),
            "live": read_clients.recent_live(conn, ip="203.0.113.4"),
            "peers": read_client_extras.peer_counts(conn, "place", ["9100001"], pieces),
        }

    found = dbs.metrics.read_sync(schema_9_reads)
    assert found["split"] == {"throttle": {"default": 4}, "upstream_5xx": {"unknown": 1}}
    assert [(row["egress"], row["reason"], row["upstream_status"], row["count"]) for row in found["failures"]] == [
        ("direct", "upstream_5xx", 503, 1)
    ]
    assert found["place"] == [{"reason": "throttle", "count": 4, "last_ms": 1_700_000_060_000}]
    assert [row["place"] for row in found["live"]] == ["9100001"]
    assert found["peers"] == {"9100001": 1}
