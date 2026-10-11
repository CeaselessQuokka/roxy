"""`rollups.rebuild_partial_buckets`: after a ranged reset, the buckets it covers in part agree with the level below.

What this is
    Unit tests over temp databases (`dbs`) for the gaps_latency lane's plan 6.8 fix (the API path is
    tests/integration/admin_api/test_api_data_ranged_rebuild.py): which buckets a range covers only in part
    (`straddling_buckets`), that a rebuilt hour equals the sum of its trimmed minutes, and that a bucket the
    compaction has not reached yet is never written ahead of it (it would move the level's watermark past hours not
    compacted yet), nor one whose minutes retention already thinned.

Why it exists
    A rebuild that wrote ahead of the compaction would hide hours from every reader of the hour level (they trust the
    watermark), and one that recomputed from thinned minutes would lose data: both worse than the bug it fixes.

What to read next
    `roxy/metrics/rollups.py` (`rebuild_partial_buckets`, `compact_level`).
"""

from __future__ import annotations

import sqlite3
from typing import Any

from roxy.metrics.recorder import dims_hash
from roxy.metrics.rollups import (
    LEVELS,
    RollupDelta,
    SourceFloors,
    rebuild_partial_buckets,
    recompute_bucket,
    straddling_buckets,
    write_rollups,
    zone,
)

H = 3600
BASE = 1_760_000_400 - 1_760_000_400 % 86_400  # a UTC midnight
DIMS = ("games.roblox.com/v1/games", 1, "games.roblox.com", "GET", "direct", "served_upstream", "upstream_ok", 200,
        "roblox", "MISS", "anon")  # fmt: skip


def test_straddling_buckets_are_the_ones_around_each_edge() -> None:
    assert straddling_buckets("hour", BASE + 10 * H + 1800, BASE + 14 * H + 1800, None) == [
        (BASE + 10 * H, BASE + 11 * H),
        (BASE + 14 * H, BASE + 15 * H),
    ]
    assert straddling_buckets("hour", BASE + 10 * H, BASE + 14 * H, None) == []  # whole hours: nothing in part
    assert straddling_buckets("hour", BASE + 10 * H + 60, BASE + 10 * H + 120, None) == [(BASE + 10 * H, BASE + 11 * H)]
    day = straddling_buckets("day", BASE + 10 * H, BASE + 14 * H, zone("UTC"))
    assert day == [(BASE, BASE + 86_400)]


def _minutes(hours: int) -> list[RollupDelta]:
    return [
        RollupDelta(BASE + minute * 60, dims_hash(DIMS), DIMS, requests=1 + minute % 3) for minute in range(hours * 60)
    ]


def _hours(conn: sqlite3.Connection) -> dict[int, int]:
    return {int(r[0]): int(r[1]) for r in conn.execute("SELECT bucket_start, requests FROM rollup_hour")}


def _reset(conn: sqlite3.Connection, start: int, end: int) -> None:
    """What a ranged reset deletes: every level's rows whose bucket starts in the range."""
    for table in ("rollup_minute", "rollup_hour", "rollup_day", "rollup_month"):
        conn.execute(f"DELETE FROM {table} WHERE bucket_start >= ? AND bucket_start < ?", (start, end))


async def test_a_partly_covered_hour_is_rebuilt_and_one_not_compacted_yet_is_left_to_the_compaction(dbs: Any) -> None:
    deltas = _minutes(6)

    def seed(conn: sqlite3.Connection) -> None:
        write_rollups(conn, deltas)
        for hour in range(4):  # the compaction reached hour 3; hours 4 and 5 are not compacted yet
            recompute_bucket(conn, LEVELS["rollup_hour"], BASE + hour * H, BASE + (hour + 1) * H)

    dbs.metrics.write_sync(seed)
    start, end = BASE + 3 * H + 1800, BASE + 5 * H + 1800

    def run(conn: sqlite3.Connection) -> list[tuple[str, int]]:
        _reset(conn, start, end)
        return rebuild_partial_buckets(
            conn, "rollup", start, end, tz_name="UTC", closed_until=BASE + 10 * H, floors=SourceFloors()
        )

    rebuilt = dbs.metrics.write_sync(run)
    hours = dbs.metrics.read_sync(_hours)
    minutes = dbs.metrics.read_sync(
        lambda conn: int(
            conn.execute(
                "SELECT sum(requests) FROM rollup_minute WHERE bucket_start >= ? AND bucket_start < ?",
                (BASE + 3 * H, BASE + 4 * H),
            ).fetchone()[0]
        )
    )
    assert rebuilt == [("rollup_hour", BASE + 3 * H)]
    assert hours[BASE + 3 * H] == minutes  # only the half hour before the range is left in it
    assert BASE + 5 * H not in hours  # never written ahead of the compaction


async def test_an_hour_whose_minutes_retention_thinned_is_left_whole(dbs: Any) -> None:
    deltas = _minutes(6)

    def seed(conn: sqlite3.Connection) -> None:
        write_rollups(conn, deltas)
        for hour in range(6):
            recompute_bucket(conn, LEVELS["rollup_hour"], BASE + hour * H, BASE + (hour + 1) * H)

    dbs.metrics.write_sync(seed)
    before = dbs.metrics.read_sync(_hours)
    start, end = BASE + 1 * H + 1800, BASE + 2 * H + 1800
    floors = SourceFloors(minute=BASE + 4 * H)  # minutes before hour 4 no longer whole

    def run(conn: sqlite3.Connection) -> list[tuple[str, int]]:
        _reset(conn, start, end)
        return rebuild_partial_buckets(
            conn, "rollup", start, end, tz_name="UTC", closed_until=BASE + 10 * H, floors=floors
        )

    assert dbs.metrics.write_sync(run) == []
    after = dbs.metrics.read_sync(_hours)
    assert after[BASE + 1 * H] == before[BASE + 1 * H]  # starts before the range: kept whole
    assert BASE + 2 * H not in after  # starts in it: deleted whole, as the reset left it
