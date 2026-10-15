"""A ranged data reset shows the same at every granularity (plan 6.8; gaps_latency L5, latency.md open issue 10).

What this is
    Tests in the real app (`api_app`, the Data API's `POST /data/resets`) over three days of minute rollups compacted
    into hours, days and months by the real compaction, and a day of older hour rows whose minutes retention already
    pruned:
    - a date range reset that starts and ends inside hours (and crosses a local midnight) leaves every hour row equal
      to the sum of its minutes and every day row equal to the sum of its hours, and a total over a window (read from
      whole days and hours, `queries.total_pieces`) equal to the sum of the window's minutes;
    - where the minutes are gone, the hour rows decide (an hour that starts before the range is kept whole, one that
      starts in it is deleted whole) and the day is rebuilt from them;
    - the result names the rebuilt buckets (`rebuilt`).

Why it exists
    A ranged reset deletes the rows whose bucket starts in the range at every level, so a coarse row the range covered
    only in part kept the reset part or lost the time after the range, and the totals that read days and hours
    disagreed with the minutes they summarize.

How it works
    Rollups are written with the batch writer's `write_rollups` and compacted with `compact_all` in the app's
    `ui_timezone`; the reset goes through the API with its preview, as the Data page sends it.

What to read next
    `roxy/metrics/rollups.py` (`rebuild_partial_buckets`), `roxy/admin/api/data.py` (`execute_reset`).
"""

from __future__ import annotations

import random
import sqlite3
from typing import Any

from roxy.metrics import histograms
from roxy.metrics import queries as q
from roxy.metrics.recorder import dims_hash
from roxy.metrics.rollups import (
    LEVELS,
    CompactionConfig,
    RollupDelta,
    bucket_floor,
    bucket_next,
    compact_all,
    recompute_bucket,
    write_rollups,
    zone,
)

DIMS = [
    ("games.roblox.com/v1/games", 1, "games.roblox.com", "GET", "direct", "served_upstream", "upstream_ok", 200,
     "roblox", "MISS", "anon"),
    ("users.roblox.com/v1/users/{id}", 1, "users.roblox.com", "GET", "none", "refused", "throttle", 429, "roxy", "NA",
     "anon"),
]  # fmt: skip


def _deltas(end: int, days: int, seed: int = 3) -> list[RollupDelta]:
    rng = random.Random(seed)
    out = []
    for minute in range(days * 1440):
        start = end - days * 86_400 + minute * 60
        for dims in DIMS:
            requests = rng.randint(1, 9)
            latency = histograms.empty()
            histograms.observe(latency, rng.uniform(5, 400), requests)
            out.append(
                RollupDelta(start, dims_hash(dims), dims, requests=requests, caller_bytes_out=requests * 100,
                            latency_hist=histograms.encode(latency))
            )  # fmt: skip
    return out


def _level_sums(conn: sqlite3.Connection, table: str, extra: str = "") -> dict[int, int]:
    rows = conn.execute(f"SELECT bucket_start, sum(requests) FROM {table} {extra} GROUP BY bucket_start")
    return {int(r[0]): int(r[1]) for r in rows}


def _sum_between(conn: sqlite3.Connection, table: str, lo: int, hi: int) -> int:
    row = conn.execute(
        f"SELECT coalesce(sum(requests), 0) FROM {table} WHERE bucket_start >= ? AND bucket_start < ?",
        (lo, hi),
    ).fetchone()
    return int(row[0])


async def _reset(api: Any, api_json: Any, start: int, end: int) -> dict[str, Any]:
    scope = {"scope": "date_range", "families": ["traffic"], "from": str(start), "to": str(end)}
    preview = api_json(await api.post("data/resets/preview", json=scope))
    body: dict[str, Any] = api_json(
        await api.post("data/resets", json={**scope, "preview": preview["preview"], "reason": "partial range"})
    )
    return body


async def test_a_reset_inside_hours_and_days_agrees_at_every_level(api: Any, api_app: Any, api_json: Any) -> None:
    now = int(api_app.clock.now())
    end = now - now % 3600 - 3600  # three closed days of minutes, compacted
    tz = str(api_app.ctx.settings.get("ui_timezone"))
    metrics = api_app.ctx.dbs.metrics
    deltas = _deltas(end, 3)
    await metrics.write(lambda conn: write_rollups(conn, deltas))

    async def write(fn: Any) -> Any:
        return await metrics.write(fn)

    await compact_all(write, now, CompactionConfig(tz_name=tz, max_buckets=10_000))
    start_at, end_at = end - 40 * 3600 + 1830, end - 20 * 3600 - 1170  # inside hours, across a local midnight
    body = await _reset(api, api_json, start_at, end_at)
    rebuilt = body["result"]["rebuilt"]
    assert {"table": "rollup_hour", "bucket": start_at - start_at % 3600} in rebuilt
    assert {"table": "rollup_hour", "bucket": end_at - end_at % 3600} in rebuilt
    assert any(item["table"] == "rollup_day" for item in rebuilt)

    def check(conn: sqlite3.Connection) -> list[tuple[Any, Any]]:
        out = []
        minutes = _level_sums(conn, "rollup_minute")
        for hour, total in _level_sums(conn, "rollup_hour").items():
            out.append((total, sum(v for b, v in minutes.items() if hour <= b < hour + 3600)))
        days = conn.execute("SELECT bucket_start, sum(requests) FROM rollup_day GROUP BY bucket_start").fetchall()
        hours = _level_sums(conn, "rollup_hour")
        for day_start, total in days:
            day_end = int(bucket_next(int(day_start), "day", zone(tz)))
            out.append((int(total), sum(v for b, v in hours.items() if int(day_start) <= b < day_end)))
        for key in ("24h", "7d"):
            window = q.resolve_window(key, now=now, tz=tz)
            lo, hi = max(window.start, end - 3 * 86_400), min(window.end, end)
            totals = q.totals_sync(conn, q.Window(lo, hi, window.granularity, tz), metrics=["requests"])
            out.append((totals["requests"], _sum_between(conn, "rollup_minute", lo, hi)))
        return out

    pairs = await metrics.read(check)
    assert len(pairs) > 40
    assert all(coarse == fine for coarse, fine in pairs), [p for p in pairs if p[0] != p[1]]
    gone = await metrics.read(lambda conn: _sum_between(conn, "rollup_minute", start_at, end_at))
    assert gone == 0


async def test_without_minutes_the_hours_decide_and_the_day_follows(api: Any, api_app: Any, api_json: Any) -> None:
    now = int(api_app.clock.now())
    tz = str(api_app.ctx.settings.get("ui_timezone"))
    metrics = api_app.ctx.dbs.metrics
    day_start = int(bucket_floor(now - 30 * 86_400, "day", zone(tz)))  # older than the minutes' 14 days
    day_end = int(bucket_next(day_start, "day", zone(tz)))
    deltas = _deltas(day_end, 1, seed=8)

    def hours_only(conn: sqlite3.Connection) -> None:
        write_rollups(conn, deltas)  # minute rows only to build the hours, then gone as retention would leave it
        for hour in range(day_start, day_end, 3600):
            recompute_bucket(conn, LEVELS["rollup_hour"], hour, hour + 3600)
        conn.execute("DELETE FROM rollup_minute")
        recompute_bucket(conn, LEVELS["rollup_day"], day_start, day_end, tz)

    await metrics.write(hours_only)
    start_at, end_at = day_start + 10 * 3600 + 1800, day_start + 14 * 3600 + 1800
    body = await _reset(api, api_json, start_at, end_at)
    assert {"table": "rollup_day", "bucket": day_start} in body["result"]["rebuilt"]
    assert not any(item["table"] == "rollup_hour" for item in body["result"]["rebuilt"])

    def check(conn: sqlite3.Connection) -> tuple[dict[int, int], int]:
        hours = _level_sums(conn, "rollup_hour", f"WHERE bucket_start >= {day_start} AND bucket_start < {day_end}")
        day = conn.execute("SELECT sum(requests) FROM rollup_day WHERE bucket_start = ?", (day_start,)).fetchone()
        return hours, int(day[0])

    hours, day = await metrics.read(check)
    assert day_start + 10 * 3600 in hours  # it starts before the range: kept whole
    assert day_start + 11 * 3600 not in hours  # it starts in the range
    assert day_start + 14 * 3600 not in hours  # so does this one, which ends after it
    assert day_start + 15 * 3600 in hours
    assert day == sum(hours.values())
