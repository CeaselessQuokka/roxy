"""Leader compaction: minutes to hours (UTC), hours to local days and months, idempotency, late data, zones (6.4)."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

import pytest

from roxy.metrics import histograms
from roxy.metrics.recorder import dims_hash
from roxy.metrics.rollups import (
    LEVELS,
    CompactionConfig,
    EgressDelta,
    RollupDelta,
    bucket_floor,
    bucket_next,
    compact_all,
    compact_level,
    write_egress_usage,
    write_rollups,
)

Rows = Callable[..., list[tuple[Any, ...]]]
NY = "America/New_York"


def _dims(n: int) -> tuple[Any, ...]:
    return (
        f"games.roblox.com/v1/e{n}",
        1,
        "games.roblox.com",
        "GET",
        "direct",
        "served_upstream",
        "upstream_ok",
        200,
        "roblox",
        "MISS",
        "anon",
    )


def _delta(minute: int, dim: int, requests: int, latency_ms: float = 40.0) -> RollupDelta:
    hist = histograms.empty()
    histograms.observe(hist, latency_ms, requests)
    dims = _dims(dim)
    return RollupDelta(
        minute,
        dims_hash(dims),
        dims,
        requests=requests,
        caller_bytes_out=requests * 10,
        upstream_calls=requests,
        latency_hist=histograms.encode(hist),
    )


def _ts(text: str, tz: str = "UTC") -> int:
    return int(datetime.fromisoformat(text).replace(tzinfo=ZoneInfo(tz)).timestamp())


def _fill(dbs: Any, start: int, minutes: int, dims: int = 2, per: int = 1) -> int:
    """One row per minute per dim with `per` requests; returns the total requests written."""
    deltas = [_delta(start + 60 * m, d, per) for m in range(minutes) for d in range(dims)]
    dbs.metrics.write_sync(lambda conn: write_rollups(conn, deltas))
    return per * minutes * dims


def _writer(dbs: Any) -> Callable[[Callable[[sqlite3.Connection], Any]], Any]:
    async def write(fn: Callable[[sqlite3.Connection], Any]) -> Any:
        return await dbs.metrics.write(fn)

    return write


def _sum(rows: Rows, table: str, where: str = "1", params: tuple[Any, ...] = ()) -> int:
    return int(rows(f"SELECT coalesce(sum(requests), 0) FROM {table} WHERE {where}", params)[0][0])


def test_bucket_helpers_handle_dst() -> None:
    tz = ZoneInfo(NY)
    spring = _ts("2025-03-09T00:00:00", NY)
    fall = _ts("2025-11-02T00:00:00", NY)
    assert bucket_next(spring, "day", tz) - spring == 23 * 3600
    assert bucket_next(fall, "day", tz) - fall == 25 * 3600
    assert bucket_floor(spring + 5 * 3600, "day", tz) == spring
    assert bucket_floor(_ts("2025-10-15T12:00:00", NY), "month", tz) == _ts("2025-10-01T00:00:00", NY)
    assert bucket_next(_ts("2025-12-31T00:00:00", NY), "month", tz) == _ts("2026-01-01T00:00:00", NY)
    assert bucket_floor(_ts("2025-10-16T12:00:00", NY), "week", tz) == _ts("2025-10-13T00:00:00", NY)  # Monday
    assert bucket_floor(125, "minute") == 120
    assert bucket_next(3600, "hour") == 7200


async def test_minutes_compact_into_hours_exactly(dbs: Any, metrics_rows: Rows) -> None:
    start = _ts("2025-10-09T10:00:00")
    total = _fill(dbs, start, 180, dims=3)
    now = start + 4 * 3600
    report = await compact_all(_writer(dbs), now, CompactionConfig(tz_name="UTC"))
    assert report["rollup_hour"] == [start, start + 3600, start + 7200]
    assert _sum(metrics_rows, "rollup_hour") == total
    rows = metrics_rows("SELECT bucket_start, dim_hash, requests, latency_hist FROM rollup_hour ORDER BY 1, 2")
    assert len(rows) == 9
    for row in rows:
        assert row[2] == 60
        assert sum(histograms.decode(row[3])) == 60


async def test_open_hour_waits_for_the_grace(dbs: Any, metrics_rows: Rows) -> None:
    start = _ts("2025-10-09T10:00:00")
    _fill(dbs, start, 60)
    report = await compact_all(_writer(dbs), start + 3600 + 30, CompactionConfig(tz_name="UTC", grace_s=120))
    assert report["rollup_hour"] == []
    report = await compact_all(_writer(dbs), start + 3600 + 121, CompactionConfig(tz_name="UTC", grace_s=120))
    assert report["rollup_hour"] == [start]


async def test_compaction_is_idempotent_and_picks_up_late_writes(dbs: Any, metrics_rows: Rows) -> None:
    start = _ts("2025-10-09T10:00:00")
    _fill(dbs, start, 120)
    config = CompactionConfig(tz_name="UTC")
    now = start + 3 * 3600
    await compact_all(_writer(dbs), now, config)
    first = metrics_rows("SELECT * FROM rollup_hour ORDER BY 1, 2")
    await compact_all(_writer(dbs), now, config)
    assert metrics_rows("SELECT * FROM rollup_hour ORDER BY 1, 2") == first
    # A worker flushes late into the last compacted hour: the next run recomputes it.
    late = [_delta(start + 3600 + 59 * 60, 0, 5)]
    dbs.metrics.write_sync(lambda conn: write_rollups(conn, late))
    await compact_all(_writer(dbs), now + 60, config)
    assert _sum(metrics_rows, "rollup_hour", "bucket_start = ?", (start + 3600,)) == 120 + 5


async def test_days_and_months_in_ui_timezone(dbs: Any, metrics_rows: Rows) -> None:
    # Two local New York days, written as minutes from 20:00 local on Oct 9 to 04:00 local on Oct 11.
    first = _ts("2025-10-09T20:00:00", NY)
    total = _fill(dbs, first, 32 * 60, dims=1)
    now = _ts("2025-11-03T12:00:00", NY)
    # Minute retention above the 25 days between the data and `now`, so the retention guard keeps out of the way.
    config = CompactionConfig(tz_name=NY, max_buckets=2000, minute_retention_days=60)
    await compact_all(_writer(dbs), now, config)
    days = metrics_rows("SELECT bucket_start, requests, tz FROM rollup_day ORDER BY 1")
    assert [d[0] for d in days] == [
        _ts("2025-10-09T00:00:00", NY),
        _ts("2025-10-10T00:00:00", NY),
        _ts("2025-10-11T00:00:00", NY),
    ]
    assert [d[1] for d in days] == [4 * 60, 24 * 60, 4 * 60]
    assert {d[2] for d in days} == {NY}
    months = metrics_rows("SELECT bucket_start, requests, tz FROM rollup_month")
    assert months == [(_ts("2025-10-01T00:00:00", NY), total, NY)]


async def test_half_hour_zone_days_take_edges_from_minutes(dbs: Any, metrics_rows: Rows) -> None:
    kolkata = "Asia/Kolkata"  # UTC+05:30: local midnight is 18:30 UTC
    start = _ts("2025-10-09T12:00:00")
    _fill(dbs, start, 24 * 60, dims=1)  # 12:00 UTC Oct 9 to 12:00 UTC Oct 10
    await compact_all(_writer(dbs), _ts("2025-10-12T00:00:00"), CompactionConfig(tz_name=kolkata, max_buckets=500))
    day_start = _ts("2025-10-10T00:00:00", kolkata)
    assert day_start % 3600 == 1800
    minutes_in_day = metrics_rows(
        "SELECT sum(requests) FROM rollup_minute WHERE bucket_start >= ? AND bucket_start < ?",
        (day_start, bucket_next(day_start, "day", ZoneInfo(kolkata))),
    )[0][0]
    assert _sum(metrics_rows, "rollup_day", "bucket_start = ?", (day_start,)) == minutes_in_day == 17 * 60 + 30
    assert _sum(metrics_rows, "rollup_day") == 24 * 60  # every minute in exactly one day


async def test_timezone_change_neither_loses_nor_doubles(dbs: Any, metrics_rows: Rows) -> None:
    start = _ts("2025-10-09T00:00:00", NY)
    total = _fill(dbs, start, 4 * 24 * 60, dims=1)
    await compact_all(_writer(dbs), _ts("2025-10-11T12:00:00", NY), CompactionConfig(tz_name=NY, max_buckets=500))
    before = metrics_rows("SELECT bucket_start, tz FROM rollup_day ORDER BY 1")
    assert {tz for _b, tz in before} == {NY}
    await compact_all(_writer(dbs), _ts("2025-10-20T00:00:00"), CompactionConfig(tz_name="UTC", max_buckets=500))
    days = metrics_rows("SELECT bucket_start, requests, tz FROM rollup_day ORDER BY 1")
    assert _sum(metrics_rows, "rollup_day") == total
    assert [tz for _b, _n, tz in days][: len(before)] == [NY] * len(before)  # old days keep their zone
    assert "UTC" in {tz for _b, _n, tz in days}


async def test_gaps_are_skipped_and_catch_up_is_bounded(dbs: Any, metrics_rows: Rows) -> None:
    start = _ts("2025-10-01T00:00:00")
    _fill(dbs, start, 30)
    later = start + 10 * 86_400
    _fill(dbs, later, 30)
    config = CompactionConfig(tz_name="UTC", max_buckets=1)
    now = later + 2 * 86_400
    first = await compact_all(_writer(dbs), now, config)
    assert first["rollup_hour"] == [start]
    second = await compact_all(_writer(dbs), now, config)
    assert second["rollup_hour"] == [start]  # the newest compacted hour is recomputed first (late writes)
    config = CompactionConfig(tz_name="UTC", max_buckets=10)
    third = await compact_all(_writer(dbs), now, config)
    assert later in third["rollup_hour"]  # ten empty days are jumped over with one index seek
    assert len(third["rollup_hour"]) == 2


async def test_minute_retention_guard(dbs: Any, metrics_rows: Rows) -> None:
    now = _ts("2025-10-20T00:00:00")
    old = now - 20 * 86_400
    _fill(dbs, old, 60)
    report = await compact_all(_writer(dbs), now, CompactionConfig(tz_name="UTC", minute_retention_days=14))
    assert report["rollup_hour"] == []  # older than minute retention: possibly partial, never compacted


async def test_egress_usage_compacts_by_granularity(dbs: Any, metrics_rows: Rows) -> None:
    start = _ts("2025-10-09T00:00:00", NY)
    deltas = [EgressDelta(start + 60 * m, "rotator", 1, 10, 20, 5) for m in range(26 * 60)]
    dbs.metrics.write_sync(lambda conn: write_egress_usage(conn, deltas))
    config = CompactionConfig(tz_name=NY, max_buckets=2000, minute_retention_days=60)
    await compact_all(_writer(dbs), _ts("2025-11-05T00:00:00", NY), config)
    by: dict[str, int] = dict(metrics_rows("SELECT granularity, sum(requests) FROM egress_usage GROUP BY granularity"))
    assert by == {"minute": 26 * 60, "hour": 26 * 60, "day": 26 * 60, "month": 26 * 60}
    assert metrics_rows("SELECT bucket_start FROM egress_usage WHERE granularity = 'day' ORDER BY 1") == [
        (start,),
        (_ts("2025-10-10T00:00:00", NY),),
    ]


async def test_compact_level_reports_completeness(dbs: Any) -> None:
    start = _ts("2025-10-09T00:00:00")
    _fill(dbs, start, 5 * 60)
    result = await compact_level(_writer(dbs), LEVELS["rollup_hour"], closed_until=start + 10 * 3600, max_buckets=2)
    assert result.buckets == [start, start + 3600]
    assert result.complete_until == start + 7200


@pytest.mark.parametrize("level", sorted(LEVELS))
def test_level_specs_are_consistent(level: str) -> None:
    spec = LEVELS[level]
    assert spec.unit in ("hour", "day", "month")
    assert spec.has_tz == (spec.dst in ("rollup_day", "rollup_month"))
