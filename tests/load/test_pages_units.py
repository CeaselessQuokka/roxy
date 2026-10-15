"""Fast checks of the dashboard page scenario's own parts (tests/load/pages.py): seeding, parsing, summaries.

What this is
    Unit tests for `load.pages` that start no gunicorn: the daily curve and answer mix, the copies that stretch one
    seeded day over each retention (time order of ids kept), a whole seed at a tiny volume through Roxy's real
    writers, the page parser that finds cards and assets, the join of samples with Roxy's `http_request` log lines,
    and the summary that flags plan 6.7 misses.

Why it exists
    The page latency numbers in docs/PERFORMANCE.md are only as honest as the data under them and the timing join.
    A copy that lost the oldest days, a seed whose levels were never compacted, or a join that matched the wrong log
    line would each move the numbers without anyone noticing.

How it works
    Plain functions over an in-memory SQLite database or the conftest `dbs` fixture (temporary, migrated), with
    fixed seeds; the tiny seed walks the same code path as the real one with every count scaled down.

What to read next
    tests/load/pages.py, docs/PERFORMANCE.md "Dashboard pages".
"""

from __future__ import annotations

import json
import random
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from load import pages
from load.pages import (
    KINDS,
    RunSpec,
    Sample,
    Volume,
    copy_back,
    copy_back_by_id,
    diurnal,
    join_server_times,
    parse_page,
    summarize,
    with_params,
)

# ------------------------------------------------------------------------------------------------ seeding


def test_the_day_adds_up_and_follows_a_daily_curve() -> None:
    counts = diurnal(500_000, random.Random(1))
    assert len(counts) == 1440
    assert sum(counts) == 500_000
    assert min(counts) > 0
    night, evening = sum(counts[180:300]), sum(counts[1080:1200])
    assert evening > 2 * night  # busy evening, quiet night


def test_the_answer_mix_has_realistic_shares() -> None:
    total = sum(kind.weight for kind in KINDS)  # weights are relative (`pages.pick` draws by weight)

    def share(outcome: str) -> float:
        return sum(kind.weight for kind in KINDS if kind.outcome == outcome) * 100 / total

    assert 3 <= share("refused") <= 8
    assert 40 <= share("served_cache") <= 50
    assert 40 <= share("served_upstream") <= 50
    assert share("failed") < 5
    assert all(kind.check for kind in KINDS if kind.outcome == "refused")  # a refusal names its check


def _rollup_table(conn: sqlite3.Connection) -> None:
    conn.execute("CREATE TABLE r (bucket_start INTEGER, k TEXT, n INTEGER, PRIMARY KEY (bucket_start, k))")


def test_copy_back_fills_earlier_days_without_touching_existing_buckets() -> None:
    conn = sqlite3.connect(":memory:")
    _rollup_table(conn)
    day = 86_400
    conn.executemany("INSERT INTO r VALUES (?, ?, ?)", [(10 * day + 60 * m, "a", m) for m in range(3)])
    conn.execute("INSERT INTO r VALUES (?, 'a', 999)", (9 * day,))  # an existing bucket one day back
    written = copy_back(conn, "r", "bucket_start, k, n", lo=10 * day, hi=11 * day, days=range(1, 3))
    assert written == 5  # 3 rows for each of 2 days, minus the one bucket that existed
    rows = dict(conn.execute("SELECT bucket_start, n FROM r WHERE k = 'a'").fetchall())
    assert rows[9 * day] == 999  # INSERT OR IGNORE: never overwritten
    assert rows[8 * day + 120] == 2


def test_copy_back_by_id_keeps_ids_in_time_order() -> None:
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, at_ms INTEGER, type TEXT, detail_json TEXT)"
    )
    day_ms = 86_400_000
    conn.executemany(
        "INSERT INTO events (at_ms, type, detail_json) VALUES (?, ?, ?)",
        [(5 * day_ms + 1000, "refusal", "{}"), (5 * day_ms + 2000, "probe", "{}"), (4 * day_ms + 10, "health", "{}")],
    )
    written = copy_back_by_id(
        conn, "events", "at_ms, type, detail_json", lo_ms=5 * day_ms, hi_ms=6 * day_ms, days=3,
        where=" AND o.type IN ('refusal')",
    )  # fmt: skip
    assert written == 5  # 3 originals and the refusal copied 2 days back
    rows = conn.execute("SELECT id, at_ms, type FROM events ORDER BY id").fetchall()
    assert [r[1] for r in rows] == sorted(r[1] for r in rows)  # ids follow time
    assert [r[2] for r in rows].count("probe") == 1  # only the copied types are copied
    assert {r[1] for r in rows if r[2] == "refusal"} == {5 * day_ms + 1000, 4 * day_ms + 1000, 3 * day_ms + 1000}


async def test_a_tiny_seed_fills_every_level_through_the_real_writers(dbs: Any) -> None:
    from roxy.config.runtime import load_runtime_settings

    volume = Volume(
        requests_per_day=3_000, history_days=16, servers=40, places=6, probes_per_day=60, crawls_per_day=10,
        logins_per_day=4, audit_per_day=10, audit_days=5, settings_changes=4, health_runs=2,
    )  # fmt: skip
    settings = await load_runtime_settings(dbs)
    end_s = 1_760_000_400  # a minute boundary
    day = await pages.backfill_day(dbs, settings, None, end_s=end_s, volume=volume)
    assert day["requests"] == 3_000
    assert day["probe"] > 0
    extra = await pages.seed_health_and_recommendations(dbs, now_s=end_s, volume=volume)
    assert extra == {"health_runs": 2, "recommendations": 22}
    copied = await pages.stretch_history(dbs, end_s=end_s, volume=volume, tz="America/New_York")
    assert copied["rollup_minute"] > 0
    assert copied["rollup_hour"] > 0
    assert await pages.seed_audit(dbs, now_s=end_s, volume=volume) == 50

    def spans(conn: sqlite3.Connection) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for table in ("rollup_minute", "rollup_hour", "rollup_day", "client_minute", "client_hour", "client_day"):
            low, count = conn.execute(f"SELECT min(bucket_start), count(*) FROM {table}").fetchone()
            out[table] = (count, (end_s - low) / 86_400 if low else 0.0)
        out["months"] = conn.execute("SELECT count(*) FROM rollup_month").fetchone()[0]
        ids = [row[0] for row in conn.execute("SELECT at_ms FROM events ORDER BY id")]
        out["events_in_time_order"] = ids == sorted(ids)
        out["event_days"] = (end_s * 1000 - min(ids)) / 86_400_000
        out["samples"] = conn.execute("SELECT count(*) FROM request_samples").fetchone()[0]
        return out

    found = await dbs.metrics.read(spans)
    assert 13.9 < found["rollup_minute"][1] <= 14.0  # the minute retention (14 days)
    assert found["rollup_hour"][1] > 15  # every day of the history at hour level
    assert found["rollup_day"][0] > 0
    assert found["rollup_day"][1] > 15
    assert found["months"] > 0
    assert 2.9 < found["client_minute"][1] <= 3.0
    assert found["client_hour"][1] > 15
    assert found["events_in_time_order"]
    assert found["event_days"] > 15
    assert found["samples"] > 0
    audits = await dbs.control.read(lambda conn: conn.execute("SELECT count(*) FROM audit_log").fetchone()[0])
    assert audits >= 50
    history = await dbs.control.read(lambda conn: conn.execute("SELECT count(*) FROM settings_history").fetchone()[0])
    assert history >= 4  # the settings changes went through SettingsService
    reloaded = await load_runtime_settings(dbs)
    assert reloaded.get("cache_ttl_seconds") == 120  # the toggles end on the default


# ------------------------------------------------------------------------------------------- the client


PAGE = (
    '<!doctype html><html><head><link rel="stylesheet" href="/static/css/tokens.css?v=1">'
    '<link rel="stylesheet" href="/static/css/print.css" media="print">'
    '<script type="importmap" nonce="n">{"imports": {"roxy/page": "/static/js/page.js?v=2"}}</script>'
    '<script type="module" nonce="n" src="/static/js/app.js?v=3"></script></head><body>'
    '<section class="card page-card" id="kpis" data-card="kpis" '
    'data-card-src="/admin/overview/fragment/kpis?range=24h&amp;compare=none"></section>'
    '<section class="card page-card page-card--lazy" id="trends" data-card="trends" '
    'data-card-src="/admin/traffic/fragment/trends"></section><section class="plain"></section></body></html>'
)


def test_parse_page_finds_cards_and_the_assets_of_first_paint() -> None:
    found = parse_page(PAGE)
    assert found.cards == [
        ("kpis", "/admin/overview/fragment/kpis?range=24h&compare=none", False),
        ("trends", "/admin/traffic/fragment/trends", True),
    ]
    assert found.stylesheets == ["/static/css/tokens.css?v=1"]  # the print sheet never blocks a paint
    assert found.modules == ["/static/js/app.js?v=3"]
    assert json.loads(found.importmap)["imports"]["roxy/page"] == "/static/js/page.js?v=2"


def test_with_params_replaces_a_value() -> None:
    assert with_params("/admin/x?range=24h&q=a", range="90d") == "/admin/x?q=a&range=90d"
    assert with_params("/admin/x", page="2") == "/admin/x?page=2"


def test_server_times_join_on_the_request_id(tmp_path: Path) -> None:
    log = tmp_path / "gunicorn.log"
    lines = [
        "[2026-10-10 12:00:00 +0000] [1] [INFO] Booting worker with pid: 2",
        json.dumps({"event": "http_request", "request_id": "A", "ms": 12.5, "ttfb_ms": 11.0, "pid": 7}),
        json.dumps({"event": "other", "request_id": "B", "ms": 99}),
        '{"broken json',
    ]
    log.write_text("\n".join(lines) + "\n")
    first = Sample("default", "page", "audit", "(page)", "/admin/audit", request_id="A")
    second = Sample("default", "page", "audit", "(page)", "/admin/audit", request_id="B")
    assert join_server_times([first, second], log) == 1
    assert (first.server_ms, first.server_ttfb_ms, first.pid) == (12.5, 11.0, 7)
    assert second.server_ms is None


def test_run_specs() -> None:
    assert RunSpec.parse("quiet") == RunSpec("quiet", "")
    assert RunSpec.parse("load@0-1").name == "load@0-1"
    for bad in ("busy", "quiet@x", "load@0;1"):
        with pytest.raises(ValueError):
            RunSpec.parse(bad)


def test_summarize_flags_the_plan_targets() -> None:
    samples = [
        Sample("default", "page", "overview", "(page)", "/admin/overview", status=200, server_ms=410.0, bytes=1000),
        Sample("default", "fragment", "overview", "kpis", "/f", status=200, server_ms=20.0, bytes=10),
        Sample("90d", "series", "api", "traffic requests", "/a", status=200, server_ms=650.0),
        Sample("default", "page", "audit", "(page)", "/admin/audit", status=500, server_ms=5.0, bytes=10),
    ]
    summary = summarize(samples, {"overview": {"css_gzip_bytes": 24}}, leader=None)
    assert summary["pages"]["default:overview"]["first_paint_bytes"] == 1024
    assert summary["pages"]["default:overview"]["view_total_server_ms"]["p50"] == 430.0
    assert summary["pages_over_300ms"] == ["overview (page) p95 410.0 ms"]
    assert summary["charts_over_500ms"] == ["api traffic requests p95 650.0 ms"]
    assert summary["non_200"] == ["page audit (page): 500"]


def test_refresh_cache_entries_moves_them_forward_and_fills_up(tmp_path: Path) -> None:
    db = tmp_path / "cache.db"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE entries (id TEXT PRIMARY KEY, key TEXT NOT NULL, stored_at INTEGER, expires_at INTEGER, "
        "stale_until INTEGER, last_hit_at INTEGER, body BLOB)"
    )
    conn.executemany(
        "INSERT INTO entries VALUES (?, ?, ?, ?, ?, ?, ?)",
        [(f"id{n}", f"games.roblox.com/v1/games?universeIds={n}", 1000 + n, 1120 + n, 1240 + n, None, b"{}")
         for n in range(7)],
    )  # fmt: skip
    conn.commit()
    conn.close()
    assert pages.refresh_cache_entries(db, 50_000.0, target=20) == 20
    conn = sqlite3.connect(db)
    newest, oldest_expiry, keys = conn.execute(
        "SELECT max(stored_at), min(expires_at), count(DISTINCT key) FROM entries"
    ).fetchone()
    conn.close()
    assert newest == 50_000  # the newest entry was just stored
    assert oldest_expiry > 50_000 - 10  # alive again (TTLs kept)
    assert keys == 20


def test_a_copied_state_is_migrated_like_a_deploy_does(tmp_path: Path) -> None:
    """`migrate_copy` runs `--expand` on a run's copy (a template seeded at an older schema still starts) and reports
    what it applied; a second call has nothing to apply."""
    state = tmp_path / "state"
    state.mkdir()
    first = pages.migrate_copy(state)
    assert any("metrics: applied" in line for line in first["applied"])
    assert (state / "metrics.db").is_file()
    assert pages.migrate_copy(state)["applied"] == []
