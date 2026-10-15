"""Measure the real bytes per minute rollup row with SQLite's `dbstat` (plan 6.6 prototype, for docs/PERFORMANCE.md).

Plan 6.6 estimates about 250 bytes per `rollup_minute` row including index overhead and asks the build to measure it
on a day of data. This test writes 24 hours of synthetic minute rollups at the plan's worst case (400 active dimension
combinations per minute, 576,000 rows) through the real write path (`rollups.write_rollups`), with realistic counters
and sparse latency histograms, compacts the day into hours, and reads page usage from `dbstat`. The numbers are printed
(run with `-s` to see them) so they can be copied into docs/PERFORMANCE.md, and the test fails if a row grows beyond
twice the plan's estimate.
"""

from __future__ import annotations

import random
import sqlite3
from typing import Any

import pytest

from roxy.metrics import histograms
from roxy.metrics.recorder import dims_hash
from roxy.metrics.rollups import CompactionConfig, RollupDelta, compact_all, write_rollups

DIMS_PER_MINUTE = 400
MINUTES = 24 * 60
PLAN_ESTIMATE = 250
START = 1_760_000_400  # an hour boundary


def _dimension_space(rng: random.Random) -> list[tuple[Any, ...]]:
    outcomes = [
        ("served_upstream", "upstream_ok", 200, "roblox", "MISS"),
        ("served_cache", "cache_hit", 200, "cache", "HIT"),
        ("refused", "throttle", 429, "roxy", "n/a"),
        ("served_upstream", "upstream_4xx", 404, "roblox", "MISS"),
        ("failed", "upstream_5xx", 503, "roblox", "MISS"),
    ]
    space = []
    for i in range(DIMS_PER_MINUTE):
        outcome = outcomes[i % len(outcomes)]
        template = f"games.roblox.com/v1/games/{{gameId}}/endpoint{i // len(outcomes)}"
        egress = "none" if outcome[0] in ("refused", "served_cache") else rng.choice(["direct", "rotator"])
        space.append(
            (
                template,
                1,
                "games.roblox.com",
                rng.choice(["GET", "GET", "POST"]),
                egress,
                outcome[0],
                outcome[1],
                outcome[2],
                outcome[3],
                outcome[4],
                "anon",
            )
        )
    return space


def _minute_rows(minute: int, space: list[tuple[Any, ...]], rng: random.Random) -> list[RollupDelta]:
    rows = []
    for dims in space:
        requests = rng.randint(1, 60)
        latency = histograms.empty()
        for _ in range(min(requests, 6)):
            histograms.observe(latency, rng.lognormvariate(4.0, 1.0), max(1, requests // 6))
        queue = histograms.empty()
        queue[0] = requests
        calls = requests if dims[5] == "served_upstream" else 0
        rows.append(
            RollupDelta(
                minute,
                dims_hash(dims),
                dims,
                requests=requests,
                caller_bytes_in=requests * rng.randint(300, 900),
                caller_bytes_out=requests * rng.randint(200, 20_000),
                upstream_calls=calls,
                upstream_bytes_in=calls * rng.randint(2000, 30_000),
                upstream_bytes_out=calls * rng.randint(500, 1500),
                errors=1 if dims[5] == "failed" else 0,
                latency_hist=histograms.encode(latency),
                queue_wait_hist=histograms.encode(queue),
            )
        )
    return rows


def _usage(conn: sqlite3.Connection, names: tuple[str, ...]) -> int:
    marks = ", ".join("?" for _ in names)
    return int(
        conn.execute(f"SELECT coalesce(sum(pgsize), 0) FROM dbstat WHERE name IN ({marks})", names).fetchone()[0]
    )


@pytest.mark.timeout(600)
async def test_bytes_per_minute_rollup_row(dbs: Any, capsys: pytest.CaptureFixture[str]) -> None:
    rng = random.Random(2026)
    space = _dimension_space(rng)
    for hour in range(24):
        batch: list[RollupDelta] = []
        for m in range(60):
            batch += _minute_rows(START + (hour * 60 + m) * 60, space, rng)
        dbs.metrics.write_sync(lambda conn, b=batch: write_rollups(conn, b))

    def measure(conn: sqlite3.Connection) -> dict[str, float]:
        rows = conn.execute("SELECT count(*) FROM rollup_minute").fetchone()[0]
        table = _usage(conn, ("rollup_minute",))
        index = _usage(conn, ("rollup_minute_dim",))
        hist_bytes = conn.execute(
            "SELECT avg(length(latency_hist)), avg(length(queue_wait_hist)) FROM rollup_minute"
        ).fetchone()
        dims_bytes = _usage(conn, ("dims", "dims_endpoint_template", "dims_host"))
        return {
            "rows": rows,
            "table": table,
            "index": index,
            "per_row": (table + index) / rows,
            "table_per_row": table / rows,
            "latency_hist": float(hist_bytes[0]),
            "queue_hist": float(hist_bytes[1]),
            "dims_total": dims_bytes,
        }

    minute = dbs.metrics.read_sync(measure)
    assert minute["rows"] == DIMS_PER_MINUTE * MINUTES

    async def write(fn: Any) -> Any:
        return await dbs.metrics.write(fn)

    await compact_all(write, START + 26 * 3600, CompactionConfig(tz_name="UTC", max_buckets=48))

    def measure_hours(conn: sqlite3.Connection) -> dict[str, float]:
        rows = conn.execute("SELECT count(*) FROM rollup_hour").fetchone()[0]
        used = _usage(conn, ("rollup_hour", "rollup_hour_dim"))
        return {"rows": rows, "per_row": used / rows}

    hours = dbs.metrics.read_sync(measure_hours)
    day_mb = minute["per_row"] * DIMS_PER_MINUTE * MINUTES / 1e6
    with capsys.disabled():
        print()
        print(
            f"PERFORMANCE rollup_minute: {minute['rows']} rows, {minute['per_row']:.1f} bytes per row "
            f"(table {minute['table_per_row']:.1f} + index {minute['index'] / minute['rows']:.1f}); plan 6.6 "
            f"estimate {PLAN_ESTIMATE} B ({(minute['per_row'] / PLAN_ESTIMATE - 1) * 100:+.0f}%)"
        )
        print(
            f"PERFORMANCE histogram blobs: latency {minute['latency_hist']:.1f} B, queue wait "
            f"{minute['queue_hist']:.1f} B on average"
        )
        print(
            f"PERFORMANCE one day at {DIMS_PER_MINUTE} combinations per minute: {day_mb:.0f} MB of minute rows; "
            f"14 days {day_mb * 14 / 1000:.2f} GB"
        )
        print(
            f"PERFORMANCE rollup_hour: {hours['rows']} rows, {hours['per_row']:.1f} bytes per row; dims table "
            f"{minute['dims_total'] / 1024:.0f} KiB for {DIMS_PER_MINUTE} combinations"
        )
    assert minute["per_row"] < 2 * PLAN_ESTIMATE
    assert hours["rows"] == DIMS_PER_MINUTE * 24
