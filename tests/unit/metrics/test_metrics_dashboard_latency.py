"""The read model changes made for plan 6.7's dashboard targets give the answers the slower reads gave.

What this is
    Unit tests over temp databases (`dbs`) for the latency lane's changes (.remake/p11_reports/latency.md):
    - `queries.cover_pieces` and `total_pieces`: a sum over a window read from whole days, whole hours and edge
      minutes equals the sum the level reads give, for windows that start and end anywhere (in the past too);
    - `_whole_days`: a run of day buckets stops at a gap and is never used in a half-hour zone;
    - `measures_for` and the narrowed `series_sync` and `totals_sync`: the same values for the metrics asked;
    - the `group_concat` histogram columns decode to what the `roxy_hist_sum` aggregate gives;
    - `read_upstream.last_failure_events` (newest first, in growing windows) equals a scan of every failure event;
    - `refusal_reasons` (newest status and path per reason by index) equals the window-function read, and
      `returned_reasons` equals its `message_source` column summed;
    - the multi-type event reads (`notable_events`, `recent_events`) read through `events_type_at`, and
      `recent_live` answers from the index when no live row is left.

Why it exists
    Each change trades how a number is read for speed; the number must not move (one source of truth, P6).

How it works
    Minute rollups for three days are written with the real writer and compacted with the real compaction; events
    are written as the recorder writes them. Each test compares the fast read with the slow one it replaced.

What to read next
    `roxy/metrics/queries.py` (`cover_pieces`, `measures_for`, `HIST_MEASURES`), `roxy/metrics/read_upstream.py`,
    `roxy/metrics/read_dashboard.py`, tests/load/pages.py (where the numbers were measured).
"""

from __future__ import annotations

import itertools
import json
import random
import sqlite3
from typing import Any

import pytest

from roxy.metrics import histograms, read_dashboard, read_upstream
from roxy.metrics import queries as q
from roxy.metrics.recorder import dims_hash
from roxy.metrics.rollups import CompactionConfig, RollupDelta, compact_all, write_rollups

NY = "America/New_York"
END = 1_760_000_400  # a whole hour (UTC)
DIMS = [
    ("games.roblox.com/v1/games", 1, "games.roblox.com", "GET", "direct", "served_upstream", "upstream_ok", 200,
     "roblox", "MISS", "anon"),
    ("games.roblox.com/v1/games", 1, "games.roblox.com", "GET", "none", "served_cache", "cache_hit", 200, "cache",
     "HIT", "anon"),
    ("users.roblox.com/v1/users/{id}", 1, "users.roblox.com", "GET", "none", "refused", "throttle", 429, "roxy", "NA",
     "anon"),
    ("users.roblox.com/v1/users/{id}", 1, "users.roblox.com", "GET", "rotator", "failed", "upstream_5xx", 503, "roxy",
     "MISS", "anon"),
    ("apis.roblox.com/x", 1, "apis.roblox.com", "GET", "credential", "served_upstream", "upstream_ok", 200,
     "internal", "NA", "cred"),
]  # fmt: skip


def _rollups(days: int = 3) -> list[RollupDelta]:
    rng = random.Random(7)
    out = []
    for minute in range(days * 1440):
        start = END - days * 86_400 + minute * 60
        for dims in DIMS:
            if rng.random() < 0.15:
                continue  # some minutes without a combination, as in real traffic
            requests = rng.randint(1, 30)
            latency = histograms.empty()
            for _ in range(min(requests, 4)):
                histograms.observe(latency, rng.lognormvariate(3.0, 1.0), max(1, requests // 4))
            queue = histograms.empty()
            queue[rng.randrange(3)] = requests
            calls = requests if dims[5] in ("served_upstream", "failed") else 0
            out.append(
                RollupDelta(
                    start, dims_hash(dims), dims, requests=requests, caller_bytes_in=requests * 10,
                    caller_bytes_out=requests * 900, upstream_calls=calls, upstream_bytes_in=calls * 1000,
                    upstream_bytes_out=calls * 200, errors=1 if dims[5] == "failed" else 0,
                    latency_hist=histograms.encode(latency), queue_wait_hist=histograms.encode(queue),
                )
            )  # fmt: skip
    return out


@pytest.fixture
async def rolled(dbs: Any) -> Any:
    """Three days of minute rows, compacted into hours and days (`America/New_York`) as the leader does."""
    deltas = _rollups()
    dbs.metrics.write_sync(lambda conn: write_rollups(conn, deltas))

    async def write(fn: Any) -> Any:
        return await dbs.metrics.write(fn)

    await compact_all(write, END + 180, CompactionConfig(tz_name=NY, max_buckets=10_000))
    return dbs


def _level_totals(conn: sqlite3.Connection, window: q.Window, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """`totals_sync` as it read before `cover_pieces`: every piece at the window's own base level."""
    with monkeypatch.context() as patch:
        patch.setattr(q, "total_pieces", lambda c, w: q.level_pieces(c, q.BASE_LEVEL[w.granularity], w.start, w.end))
        return q.totals_sync(conn, window)


@pytest.mark.parametrize("key", ["1h", "6h", "24h", "7d", "30d"])
@pytest.mark.parametrize("shift", [0, 2 * 3600 + 17 * 60, 86_400 + 600])
async def test_a_window_sum_from_the_coarsest_rows_equals_the_level_sum(
    rolled: Any, monkeypatch: pytest.MonkeyPatch, key: str, shift: int
) -> None:
    def check(conn: sqlite3.Connection) -> tuple[dict[str, Any], dict[str, Any], list[Any]]:
        window = q.resolve_window(key, now=END + 30 - shift, tz=NY)
        return q.totals_sync(conn, window), _level_totals(conn, window, monkeypatch), q.total_pieces(conn, window)

    fast, slow, pieces = await rolled.metrics.read(check)
    assert fast == slow
    assert fast["requests"] > 0
    assert all(lo < hi for _table, lo, hi in pieces)
    assert all(a[2] == b[1] for a, b in itertools.pairwise(pieces))  # contiguous, never overlapping


async def test_a_long_window_reads_days_and_a_day_window_reads_hours(rolled: Any) -> None:
    def pieces(conn: sqlite3.Connection) -> tuple[list[Any], list[Any]]:
        week = q.resolve_window("7d", now=END + 30, tz=NY)
        day = q.resolve_window("24h", now=END + 30, tz=NY)
        return q.total_pieces(conn, week), q.total_pieces(conn, day)

    week, day = await rolled.metrics.read(pieces)
    assert "rollup_day" in [table for table, _lo, _hi in week]
    tables = [table for table, _lo, _hi in day]
    assert "rollup_hour" in tables
    assert "rollup_day" not in tables


def test_whole_days_stop_at_a_gap_and_skip_a_half_hour_zone() -> None:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE rollup_day (bucket_start INTEGER, dim_hash INTEGER, tz TEXT)")
    day = 86_400
    rows = [(10 * day, 1, "UTC"), (11 * day, 1, "UTC"), (13 * day, 1, "UTC")]  # day 12 had no traffic
    conn.executemany("INSERT INTO rollup_day VALUES (?, ?, ?)", rows)
    assert q._whole_days(conn, 9 * day + 5, 20 * day) == (10 * day, 12 * day)
    assert q._whole_days(conn, 9 * day, 10 * day + 3600) is None  # no whole day inside
    conn.execute("DELETE FROM rollup_day")
    kolkata = 10 * day - 19_800  # local midnight in a UTC+05:30 zone: never a whole hour
    conn.executemany(
        "INSERT INTO rollup_day VALUES (?, ?, ?)", [(kolkata, 1, "Asia/Kolkata"), (kolkata + day, 1, "Asia/Kolkata")]
    )
    assert q._whole_days(conn, kolkata - 600, kolkata + 3 * day) is None


def test_measures_for_names_what_each_metric_reads() -> None:
    assert q.measures_for(["requests"]) == (("requests",), ())
    measures, hists = q.measures_for(["avoided_pct", "p95_ms"])
    assert set(measures or ()) == {"requests", "demand", "upstream_calls"}
    assert hists == ("latency_hist",)
    assert q.measures_for(["queue_wait_p95_ms"])[1] == ("queue_wait_hist",)
    assert q.measures_for(["requests", "no_such_metric"]) == (None, None)


@pytest.mark.parametrize(
    "metrics",
    [["requests"], ["p95_ms", "requests"], ["avoided_pct", "hit_ratio"], ["roblox_429_per_10k", "queue_wait_p95_ms"]],
)
@pytest.mark.parametrize("key", ["24h", "7d"])
async def test_a_narrowed_series_and_total_equal_the_full_ones(
    rolled: Any, monkeypatch: pytest.MonkeyPatch, metrics: list[str], key: str
) -> None:
    def read(conn: sqlite3.Connection) -> tuple[Any, Any, Any, Any]:
        window = q.resolve_window(key, now=END + 30, tz=NY)
        fast = q.series_sync(conn, window, metrics=metrics, group_by="outcome")
        total = q.totals_sync(conn, window, metrics=metrics)
        with monkeypatch.context() as patch:
            patch.setattr(q, "measures_for", lambda wanted: (None, None))
            full = q.series_sync(conn, window, metrics=metrics, group_by="outcome")
        whole = q.totals_sync(conn, window)
        return fast, full, total, whole

    fast, full, total, whole = await rolled.metrics.read(read)
    assert fast == full
    assert total == {key: whole[key] for key in metrics}


async def test_the_histogram_columns_decode_to_the_aggregate_sums(rolled: Any) -> None:
    def read(conn: sqlite3.Connection) -> tuple[dict[Any, Any], dict[Any, Any]]:
        histograms.register_sql_functions(conn)
        old_rows = conn.execute(
            "SELECT d.outcome AS g, roxy_hist_sum(CASE WHEN d.source != 'internal' THEN r.latency_hist END) AS l, "
            "roxy_hist_sum(CASE WHEN d.source != 'internal' THEN r.queue_wait_hist END) AS w "
            "FROM rollup_minute r JOIN dims d ON d.dim_hash = r.dim_hash GROUP BY g"
        ).fetchall()
        old = {r["g"]: (histograms.decode(r["l"]), histograms.decode(r["w"])) for r in old_rows}
        new = {}
        for row in q._measure_rows(conn, "rollup_minute", 0, 2**40, filters=None, group_by="outcome", time_unit=None):
            totals = q.Totals.zero()
            totals.add_row(row)
            new[row["g"]] = (totals.latency, totals.queue_wait)
        return old, new

    old, new = await rolled.metrics.read(read)
    assert old == new
    assert any(sum(latency) for latency, _queue in new.values())


# ------------------------------------------------------------------------------------------------ events


def _event(
    at_ms: int, kind: str, reason: str, detail: dict[str, Any], template: str = "games.roblox.com/v1/x"
) -> tuple[Any, ...]:
    return (at_ms, kind, "warn", reason, None, None, template, json.dumps(detail, sort_keys=True))


def _insert(conn: sqlite3.Connection, rows: list[tuple[Any, ...]]) -> None:
    conn.executemany(
        "INSERT INTO events (at_ms, type, severity, reason_code, ip_hash, place, endpoint_template, detail_json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        rows,
    )


def _failures(rng: random.Random) -> list[tuple[Any, ...]]:
    rows = []
    start = (END - 3 * 86_400) * 1000
    for n in range(4000):
        at = start + n * 60_000 + rng.randrange(1000)
        egress = rng.choice(["direct", "rotator", "rotator"])
        detail: dict[str, Any] = {
            "status": 503,
            "method": "GET",
            "path": f"games.roblox.com/v1/x/{n}",
            "egress": egress,
        }
        if rng.random() < 0.2:
            detail = {"status": 503, "egress": egress, "aggregated": True, "count": 4}
        rows.append(_event(at, "failure", "upstream_5xx", detail))
    # One egress whose only events are old: the walk must go back a long way for it.
    rows.append(_event(start - 86_400_000, "failure", "upstream_timeout", {"status": 504, "egress": "credential"}))
    return rows


async def test_last_failure_events_walks_back_to_the_answer_a_full_scan_gives(rolled: Any) -> None:
    rng = random.Random(3)
    rolled.metrics.write_sync(lambda conn: _insert(conn, _failures(rng)))
    # The recorder counts every failure in the rollups too: the old credential failure has its minute row.
    old = ("apis.roblox.com/x", 1, "apis.roblox.com", "GET", "credential", "failed", "upstream_timeout", 504, "roxy",
           "MISS", "cred")  # fmt: skip
    minute = END - 4 * 86_400
    delta = RollupDelta(minute - minute % 60, dims_hash(old), old, requests=1, upstream_calls=1, errors=1)
    rolled.metrics.write_sync(lambda conn: write_rollups(conn, [delta]))

    def read(conn: sqlite3.Connection) -> tuple[Any, Any, Any, Any]:
        def full(key_sql: str) -> dict[str, tuple[int, str]]:
            rows = conn.execute(
                f"SELECT {key_sql} AS k, max(at_ms) AS at_ms, reason_code FROM events WHERE type = 'failure' "
                "AND json_extract(detail_json, '$.aggregated') IS NULL GROUP BY k"
            ).fetchall()
            return {str(r["k"]): (int(r["at_ms"]), str(r["reason_code"])) for r in rows if r["k"]}

        return (
            read_upstream.last_failure_events(conn, "egress"),
            full("json_extract(detail_json, '$.egress')"),
            read_upstream.last_failure_events(conn, "host"),
            full("substr(endpoint_template, 1, instr(endpoint_template, '/') - 1)"),
        )

    by_egress, egress_scan, by_host, host_scan = await rolled.metrics.read(read)
    assert {k: (v["at_ms"], v["reason"]) for k, v in by_egress.items()} == egress_scan
    assert {k: (v["at_ms"], v["reason"]) for k, v in by_host.items()} == host_scan
    assert "credential" in by_egress  # found far back, because the rollups say it failed


async def test_refusal_reasons_newest_fields_and_returned_reasons(rolled: Any) -> None:
    rng = random.Random(5)
    rows = []
    start = (END - 86_400) * 1000
    for n in range(3000):
        reason = rng.choice(["throttle", "throttle", "upstream_5xx", "header_rule"])
        kind = "failure" if reason == "upstream_5xx" else "refusal"
        detail: dict[str, Any] = {
            "status": rng.choice([429, 403, 503]),
            "message_source": rng.choice(["default", "custom"]),
        }
        if rng.random() < 0.7:
            detail["path"] = f"users.roblox.com/v1/users/{n}"
        if rng.random() < 0.1:
            detail = {"status": 429, "aggregated": True, "count": 3}
        rows.append(_event(start + n * 20_000, kind, reason, detail))
    rolled.metrics.write_sync(lambda conn: _insert(conn, rows))

    def read(conn: sqlite3.Connection) -> tuple[Any, Any, Any, Any]:
        window = q.resolve_window("24h", now=END + 30, tz=NY)

        def ranked(path: str) -> dict[str, Any]:
            found = conn.execute(
                "SELECT reason_code, v FROM (SELECT reason_code, json_extract(detail_json, ?) AS v, "
                "row_number() OVER (PARTITION BY reason_code ORDER BY at_ms DESC, id DESC) AS rank FROM events "
                "WHERE type IN ('refusal', 'failure') AND at_ms >= ? AND at_ms < ? "
                "AND json_extract(detail_json, ?) IS NOT NULL) WHERE rank = 1",
                (path, window.start * 1000, window.end * 1000, path),
            ).fetchall()
            return {str(r["reason_code"]): r["v"] for r in found}

        return q.refusal_reasons(conn, window), ranked("$.status"), ranked("$.path"), q.returned_reasons(conn, window)

    reasons, statuses, paths, returned = await rolled.metrics.read(read)
    assert reasons
    for row in reasons:
        name = str(row["reason"])
        assert row["last_status"] == statuses.get(name)
        assert row["last_path"] == (str(paths[name])[:200] if name in paths else None)
    summed: dict[str, int] = {}
    for row in reasons:
        for source, count in row["message_source"].items():
            summed[source] = summed.get(source, 0) + count
    assert returned == summed


async def test_event_reads_of_several_types_use_the_type_index(dbs: Any) -> None:
    def plans(conn: sqlite3.Connection) -> list[str]:
        out = []
        for sql in (
            "SELECT id FROM events WHERE type IN ('breaker_open', 'leak_blocked') AND at_ms >= 0 AND at_ms < 9 "
            "ORDER BY +at_ms DESC, id DESC LIMIT 5",
        ):
            out += [str(tuple(row)[-1]) for row in conn.execute("EXPLAIN QUERY PLAN " + sql)]
        return out

    found = await dbs.metrics.read(plans)
    assert any("events_type_at" in line for line in found)
    rows = [
        _event(1000 + n, kind, "x", {})
        for n, kind in enumerate(["breaker_open", "refusal", "leak_blocked", "refusal", "breaker_open"])
    ]
    dbs.metrics.write_sync(lambda conn: _insert(conn, rows))
    notable = await dbs.metrics.read(lambda conn: read_dashboard.notable_events(conn, 0, 10_000, limit=10))
    assert [row["type"] for row in notable["rows"]] == ["breaker_open", "leak_blocked", "breaker_open"]
    recent = await dbs.metrics.read(
        lambda conn: read_upstream.recent_events(conn, ("breaker_open", "leak_blocked"), 0, 10_000)
    )
    assert [row["at_ms"] for row in recent] == [1004, 1002, 1000]


async def test_recent_live_without_live_rows_and_with_them(dbs: Any) -> None:
    rows = [_event(1000 + n, "refusal", "x", {}) for n in range(50)]
    dbs.metrics.write_sync(lambda conn: _insert(conn, rows))
    assert await dbs.metrics.read(lambda conn: read_dashboard.recent_live(conn, 10)) == []
    live = [_event(2000 + n, "live", "cache_hit", {"n": n}) for n in range(30)]
    dbs.metrics.write_sync(lambda conn: _insert(conn, live))
    found = await dbs.metrics.read(lambda conn: read_dashboard.recent_live(conn, 10))
    assert [row["n"] for _id, row in found] == list(range(29, 19, -1))
    older = await dbs.metrics.read(lambda conn: read_dashboard.recent_live(conn, 5, before_id=found[-1][0]))
    assert [row["n"] for _id, row in older] == [19, 18, 17, 16, 15]


def test_add_blob_into_adds_what_decode_gives_and_refuses_what_decode_refuses() -> None:
    rng = random.Random(11)
    for _ in range(500):
        counts = [rng.choice([0, 0, 1, 7, 127, 128, 300, 70_000, 2**40]) for _ in range(histograms.BUCKETS)]
        blob = histograms.encode(counts)
        if blob is None:
            continue
        expected = [rng.randrange(50) for _ in range(histograms.BUCKETS)]
        got = list(expected)
        histograms.add_into(expected, histograms.decode(blob))
        histograms.add_blob_into(got, blob)
        assert got == expected
    for bad in (
        b"\x03",
        b"\x03\x80",
        b"\x05\x01\x02\x01",
        bytes([histograms.BUCKETS, 1]),
        b"\x01" + b"\xff" * 10 + b"\x01",
    ):
        with pytest.raises(ValueError):
            histograms.decode(bad)
        with pytest.raises(ValueError):
            histograms.add_blob_into(histograms.empty(), bad)


async def test_failure_log_newest_row_per_group_is_the_grouped_newest(rolled: Any) -> None:
    rng = random.Random(9)
    rolled.metrics.write_sync(lambda conn: _insert(conn, _failures(rng)))

    def read(conn: sqlite3.Connection) -> tuple[list[dict[str, Any]], dict[tuple[Any, Any, Any], dict[str, Any]]]:
        start, end = (END - 4 * 86_400) * 1000, END * 1000
        rows = conn.execute(
            "SELECT json_extract(detail_json, '$.egress') AS egress, reason_code AS reason, "
            "json_extract(detail_json, '$.upstream_status') AS upstream_status, max(at_ms) AS at_ms, detail_json "
            "FROM events WHERE type = 'failure' AND at_ms >= ? AND at_ms < ? GROUP BY 1, 2, 3",
            (start, end),
        ).fetchall()
        newest = {(r["egress"], r["reason"], r["upstream_status"]): json.loads(r["detail_json"]) for r in rows}
        return read_upstream.failure_log(conn, start, end), newest

    log, newest = await rolled.metrics.read(read)
    assert log
    for row in log:
        detail = newest[(row["egress"], row["reason"], row["upstream_status"])]
        assert (row["last_path"], row["last_method"], row["last_status"]) == (
            detail.get("path"),
            detail.get("method"),
            detail.get("status"),
        )


async def test_reason_counts_are_the_refusal_table_columns(rolled: Any) -> None:
    rng = random.Random(13)
    start = (END - 86_400) * 1000
    events = []
    deltas = []
    for n in range(500):
        reason = rng.choice(["throttle", "header_rule"])
        at = start + n * 150_000 + rng.randrange(60_000)
        events.append(_event(at, "refusal", reason, {"status": 429, "message_source": "default"}))
        dims = ("users.roblox.com/v1/users/{id}", 1, "users.roblox.com", "GET", "none", "refused", reason, 429, "roxy",
                "NA", "anon")  # fmt: skip
        minute = at // 1000 - (at // 1000) % 60
        deltas.append(RollupDelta(minute, dims_hash(dims), dims, requests=1))
    rolled.metrics.write_sync(lambda conn: _insert(conn, events))
    rolled.metrics.write_sync(lambda conn: write_rollups(conn, deltas))

    def read(conn: sqlite3.Connection) -> list[tuple[Any, Any]]:
        out = []
        for key in ("1h", "24h", "7d"):
            window = q.resolve_window(key, now=END + 30, tz=NY)
            table = {str(r["reason"]): (r["requests"], r["last_ms"]) for r in q.refusal_reasons(conn, window)}
            fast = q.reason_counts(conn, window, [*table, "flood"])
            out.append((table, {name: (row["requests"], row["last_ms"]) for name, row in fast.items()}))
        return out

    for table, fast in await rolled.metrics.read(read):
        assert fast == table
