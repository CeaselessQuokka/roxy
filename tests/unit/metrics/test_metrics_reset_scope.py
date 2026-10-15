"""Plan 6.8 on the KPI tiles: a reset of a tile's own data replaces its delta with a notice (finding parity-12).

What this is
    Unit tests of `metrics/queries.py` (`kpis_sync`, `reset_annotations`, `reset_touches`, `reset_tile_notice`) and
    `metrics/annotate.py` (`insert_annotation(tables=)`, `update_annotation(tables=)`, `reset_tables_of`) on a
    migrated temp metrics.db fed by the real recorder.

Why it exists
    Plan 6.8: "a KPI or comparison whose current or comparison window overlaps a reset of its family shows a notice
    ... instead of a misleading delta. Comparison baselines are never synthesized to hide the gap." The parity review
    found the opposite twice over: a reset of the previous hour's traffic left "+5 requests" on the tile, and a reset of
    any family (logins, for one) put the same page notice on every tile. These tests pin both halves: a tile whose own
    data was reset carries a notice and no delta, and a reset that names what it deleted leaves every other tile alone.

How it works
    A reset marker names what it deleted in the `annotations.reset_tables` column (expand migration
    `metrics/0006_annotation_scope.sql`; `with_scope_column` is a no-op on that schema and adds the column the same
    way on an older file). A marker that names nothing, or a file without the column (the previous release's), is
    read as touching every number (the safe reading, also tested). The clock is the `fake_clock`, so windows and
    notices are exact.

What to read next
    `roxy/metrics/queries.py` (`kpis_sync`), `roxy/metrics/annotate.py`, `roxy/admin/api/data.py` (who writes the
    markers), and the API test `test_parity_12_kpi_delta_over_a_reset_window_is_replaced_by_a_notice` in
    `tests/integration/admin_api/test_r3_parity_data.py`.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from typing import Any

from roxy.core.clock import FakeClock
from roxy.metrics import annotate
from roxy.metrics import queries as q
from roxy.metrics.recorder import MetricsRecorder, OutcomeEvent

Make = Callable[..., OutcomeEvent]


def with_scope_column(recorder: MetricsRecorder) -> None:
    """Add `annotations.reset_tables` as the requested expand migration does (no-op once it exists)."""

    def add(conn: sqlite3.Connection) -> None:
        if not annotate.has_reset_tables(conn):
            conn.execute(f"ALTER TABLE annotations ADD COLUMN {annotate.RESET_TABLES_COLUMN} TEXT")

    recorder.dbs.metrics.write_sync(add)


def mark(recorder: MetricsRecorder, at: int, *, until: int | None = None, tables: list[str] | None = None) -> int:
    return int(
        recorder.dbs.metrics.write_sync(
            lambda conn: annotate.insert_annotation(conn, at, "reset", "Data reset: x", 7, until=until, tables=tables)
        )
    )


def seed_two_hours(recorder: MetricsRecorder, make_event: Make, fake_clock: FakeClock) -> float:
    """4 requests (and one Roblox 429) an hour ago, 6 requests now; returns now."""
    for _ in range(4):
        recorder.record_outcome(make_event())
    recorder.record_upstream_429(
        endpoint_template="games.roblox.com/v1/games", host="games.roblox.com", egress="direct"
    )
    recorder.close()
    fake_clock.advance(3660)
    for _ in range(6):
        recorder.record_outcome(make_event())
    recorder.record_upstream_429(
        endpoint_template="games.roblox.com/v1/games", host="games.roblox.com", egress="direct"
    )
    recorder.close()
    return fake_clock.now()


def kpis(recorder: MetricsRecorder, now: float) -> dict[str, Any]:
    window = q.resolve_window("1h", now=now)
    result: dict[str, Any] = recorder.dbs.metrics.read_sync(
        lambda conn: q.kpis_sync(conn, window, now=now, compare="previous")
    )
    return result


async def test_a_marker_without_scope_blanks_every_delta_and_says_why(
    recorder: MetricsRecorder, make_event: Make, fake_clock: FakeClock
) -> None:
    now = seed_two_hours(recorder, make_event, fake_clock)
    mark(recorder, int(now) - 5400, until=int(now) - 3700)  # the comparison hour, a marker that names nothing
    result = kpis(recorder, now)
    requests, throttled = result["tiles"]["requests"], result["tiles"]["roblox_429"]
    assert (requests["value"], requests["previous"]) == (6, 4)  # the baseline is shown as read, never made up
    assert (requests["delta"], requests["delta_pct"], requests["partial"]) == (None, None, True)
    assert requests["notice"].endswith("was reset; this comparison covers partial data.")
    assert "Data reset: x" not in requests["notice"]  # dates only: a marker's label may name a client
    assert (throttled["delta"], throttled["partial"]) == (None, True)  # unknown scope: every tile is partial
    assert [row["reset_tables"] for row in result["notices"]] == [None]


async def test_a_traffic_reset_marks_only_the_tiles_that_read_the_rollups(
    recorder: MetricsRecorder, make_event: Make, fake_clock: FakeClock
) -> None:
    with_scope_column(recorder)
    now = seed_two_hours(recorder, make_event, fake_clock)
    rollups = list(q.ROLLUP_TABLES)
    mark(recorder, int(now) - 5400, until=int(now) - 3700, tables=rollups)
    result = kpis(recorder, now)
    tiles = result["tiles"]
    assert (tiles["requests"]["delta"], tiles["requests"]["partial"]) == (None, True)
    assert (tiles["p95_ms"]["delta"], tiles["p95_ms"]["partial"]) == (None, True)
    # The Roblox 429 count reads the 429 log, which this reset left alone: its delta stays.
    assert tiles["roblox_429"]["value"] == 1
    assert tiles["roblox_429"]["delta"] == 0
    assert "notice" not in tiles["roblox_429"]
    assert tiles["roblox_429_per_10k"]["delta"] is None  # 429s divided by rollup demand: partial
    assert [row["reset_tables"] for row in result["notices"]] == [sorted(rollups)]


async def test_a_reset_of_another_family_leaves_the_tiles_and_the_page_alone(
    recorder: MetricsRecorder, make_event: Make, fake_clock: FakeClock
) -> None:
    with_scope_column(recorder)
    now = seed_two_hours(recorder, make_event, fake_clock)
    mark(recorder, int(now) - 30, tables=["metrics.events"])  # logins, probes, crawls: event rows only
    result = kpis(recorder, now)
    tile = result["tiles"]["requests"]
    assert (tile["delta"], tile["delta_pct"]) == (2, 50.0)
    assert "notice" not in tile
    assert result["notices"] == []
    assert result["tiles"]["requests_last_hour"].get("notice") is None


async def test_a_reset_inside_the_current_window_says_the_value_is_partial(
    recorder: MetricsRecorder, make_event: Make, fake_clock: FakeClock
) -> None:
    with_scope_column(recorder)
    now = seed_two_hours(recorder, make_event, fake_clock)
    mark(recorder, int(now) - 10, tables=["metrics.rollup_minute"])
    result = kpis(recorder, now)
    tile = result["tiles"]["requests"]
    assert tile["delta"] is None
    assert tile["notice"].startswith("Data reset on ")
    assert tile["notice"].endswith("; this value covers partial data.")
    hour = result["tiles"]["requests_last_hour"]
    assert hour["value"] == 6
    assert hour["partial"] is True  # its hour (and the hour before, which the Overview compares with) was reset


async def test_a_latency_clear_marks_only_latency_tiles(
    recorder: MetricsRecorder, make_event: Make, fake_clock: FakeClock
) -> None:
    with_scope_column(recorder)
    now = seed_two_hours(recorder, make_event, fake_clock)
    mark(recorder, int(now) - 5400, until=int(now) - 3700, tables=[f"{name}#latency" for name in q.ROLLUP_TABLES])
    tiles = kpis(recorder, now)["tiles"]
    assert tiles["p95_ms"]["delta"] is None
    assert tiles["requests"]["delta"] == 2  # counts were kept: only the histograms were emptied


def test_reset_touches_reads_the_scope() -> None:
    unknown = {"reset_tables": None}
    events = {"reset_tables": ["metrics.events"]}
    latency = {"reset_tables": ["metrics.rollup_minute#latency"]}
    assert q.reset_touches(unknown, ["metrics.upstream_429"])
    assert not q.reset_touches(events, q.ROLLUP_TABLES)
    assert not q.reset_touches(latency, q.ROLLUP_TABLES)
    assert q.reset_touches(latency, q.ROLLUP_TABLES, latency=True)
    # A cache statistics reset clears the lookup states and keeps the requests (finding parity-8): only numbers that
    # read the cache states see it.
    cleared = {"reset_tables": ["metrics.rollup_minute#cache_state"]}
    assert not q.reset_touches(cleared, q.ROLLUP_TABLES)
    assert not q.reset_touches(cleared, q.ROLLUP_TABLES, latency=True)
    assert q.reset_touches(cleared, q.ROLLUP_TABLES, cache=True)
    assert "hit_ratio" in q.CACHE_STATE_KPIS
    assert "requests" not in q.CACHE_STATE_KPIS
    assert q.kpi_tables("rotator_bytes") == ("metrics.egress_usage",)
    assert q.kpi_tables("requests") == q.ROLLUP_TABLES


def test_a_file_without_the_scope_column_keeps_markers_unscoped() -> None:
    """The previous release's file (before `0006_annotation_scope.sql`): the list is left out, never an error."""
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE annotations (id INTEGER PRIMARY KEY, at INTEGER NOT NULL, kind TEXT NOT NULL, label TEXT, "
        "audit_id INTEGER, until INTEGER)"
    )
    assert not annotate.has_reset_tables(conn)
    marker = annotate.insert_annotation(conn, 100, "reset", "Data reset: x", 7, tables=["metrics.rollup_minute"])
    assert marker > 0
    assert annotate.update_annotation(conn, marker, tables=["metrics.events"])
    rows = [tuple(r) for r in conn.execute("SELECT id, kind FROM annotations").fetchall()]
    assert rows == [(marker, "reset")]
    conn.close()


async def test_annotate_stores_and_bounds_the_scope(recorder: MetricsRecorder) -> None:
    metrics = recorder.dbs.metrics
    with_scope_column(recorder)  # a no-op since metrics.db schema 6 has the column
    without = mark(recorder, 100)  # names nothing: read as touching every number
    many = [f"metrics.table_{i:03d}" for i in range(annotate.MAX_TABLES + 10)] + ["x" * 500]
    scoped = mark(recorder, 200, tables=many)

    def read(conn: sqlite3.Connection) -> dict[int, Any]:
        rows = conn.execute(f"SELECT id, {annotate.RESET_TABLES_COLUMN} FROM annotations").fetchall()
        return {int(r[0]): annotate.reset_tables_of(r[1]) for r in rows}

    stored = metrics.read_sync(read)
    assert stored[without] is None
    assert len(stored[scoped]) == annotate.MAX_TABLES
    assert all(len(name) <= annotate.MAX_TABLE_CHARS for name in stored[scoped])
    assert metrics.write_sync(lambda conn: annotate.update_annotation(conn, without, tables=["metrics.events"]))
    assert metrics.read_sync(read)[without] == ["metrics.events"]
    assert annotate.reset_tables_of("{not json") is None
    assert annotate.reset_tables_of('{"a": 1}') is None
