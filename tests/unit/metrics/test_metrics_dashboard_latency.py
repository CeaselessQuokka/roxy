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
      `recent_live` answers from the index when no live row is left;
    - the Overview's reads after the final review perf lane: `requests_recorded` (the "since when" notice of the
      Roblox answer tiles probes for a request instead of summing the range; bounded work, a primary key search),
      the KPI totals and the Outcomes and Top endpoints tables summing only what their cards show, and
      `visit_reads` (the Visitors card's numbers from the sparkline's rows when they tile the range).

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


# ------------------------------------------------------------------------------------------- the Overview's reads


def _vm_steps(conn: sqlite3.Connection, fn: Any) -> tuple[Any, int]:
    """`fn(conn)` and how many SQLite virtual machine instructions it ran (counted in steps of 100): the work a read
    does, measured without a clock."""
    steps = 0

    def tick() -> int:
        nonlocal steps
        steps += 1
        return 0  # never interrupt

    conn.set_progress_handler(tick, 100)
    try:
        return fn(conn), steps * 100
    finally:
        conn.set_progress_handler(None, 0)


def _statements(conn: sqlite3.Connection, fn: Any) -> tuple[Any, list[str]]:
    """`fn(conn)` and the SQL statements it ran."""
    seen: list[str] = []
    conn.set_trace_callback(seen.append)
    try:
        return fn(conn), seen
    finally:
        conn.set_trace_callback(None)


@pytest.mark.parametrize("key", ["1h", "6h", "24h", "7d", "30d"])
@pytest.mark.parametrize("shift", [0, 2 * 3600 + 17 * 60, 86_400 + 600, 5 * 86_400])
async def test_requests_recorded_answers_what_the_requests_sum_answers(rolled: Any, key: str, shift: int) -> None:
    def check(conn: sqlite3.Connection) -> tuple[bool, int]:
        window = q.resolve_window(key, now=END + 30 - shift, tz=NY)
        return q.requests_recorded(conn, window), q.totals_sync(conn, window, metrics=("requests",))["requests"]

    recorded, requests = await rolled.metrics.read(check)
    assert recorded == (requests > 0)


async def test_the_since_notice_probes_for_a_request_instead_of_summing_the_range(rolled: Any) -> None:
    """Final review perf lane: `answers_notice` summed every request before the upgrade to learn whether there was
    one (12 ms of each 90 day Overview KPI read with history); it now probes the same pieces and stops at the first
    request, so its work stays small however long the range and however much traffic it holds."""
    since = END - 600  # the counting began after three days of traffic
    rolled.metrics.write_sync(
        lambda conn: conn.execute(
            "UPDATE schema_version SET applied_at = ? WHERE version = ?", (since, q.ANSWERS_SCHEMA_VERSION)
        )
    )
    now = END + 30

    def read(conn: sqlite3.Connection) -> tuple[dict[str, Any], list[str]]:
        out = {}
        for key in ("24h", "7d"):
            window = q.resolve_window(key, now=now, tz=NY)
            cut = since - since % 60
            before = q.Window(window.start, cut, "minute" if cut - window.start <= 86_400 else "hour", NY)
            notice, probed = _vm_steps(conn, lambda c, window=window: q.answers_notice(c, [window], now=now))
            total, summed = _vm_steps(conn, lambda c, before=before: q.totals_sync(c, before, metrics=("requests",)))
            out[key] = (notice, probed, total["requests"], summed)
        plans = []
        for table in q.LEVEL_ORDER:
            sql = "EXPLAIN QUERY PLAN " + q.REQUESTS_PROBE_SQL.format(table=table)
            plans.append(" | ".join(str(tuple(row)[-1]) for row in conn.execute(sql, (0, 1))))
        return out, plans

    found, plans = await rolled.metrics.read(read)
    for key, (notice, probed, requests, summed) in found.items():
        assert notice is not None, key
        assert "counted since" in notice, key
        assert requests > 0, key
        # The sum walks every row of the range; the probe reads a few rows whatever the range holds.
        assert probed * 10 < summed, (key, probed, summed)
    for table, plan in zip(q.LEVEL_ORDER, plans, strict=True):
        assert f"SEARCH {table} USING PRIMARY KEY" in plan, plan  # a range of the time key, never a table scan


@pytest.mark.parametrize("key", ["24h", "7d"])
async def test_the_overview_reads_sum_only_what_their_cards_show(
    rolled: Any, monkeypatch: pytest.MonkeyPatch, key: str
) -> None:
    """Final review perf lane: the KPI totals, the last hour and the Outcomes and Top endpoints tables sum only the
    numbers their cards show (no queue wait histogram anywhere, no histogram at all for the outcome counts), and
    every number the cards show is the one the full sums give."""
    from roxy.admin.api import overview as ov

    now = END + 30

    def read(conn: sqlite3.Connection) -> dict[str, Any]:
        window = q.resolve_window(key, now=now, tz=NY)
        page = q.Page(size=10, sort="requests")
        kpis, kpi_sql = _statements(conn, lambda c: q.kpis_sync(c, window, now=now, compare="previous"))
        outcomes, outcome_sql = _statements(
            conn, lambda c: q.top_n_sync(c, window, "outcome", page=page, metrics=ov.OUTCOME_METRICS)
        )
        endpoints, endpoint_sql = _statements(
            conn, lambda c: q.endpoint_table_sync(c, window, page=page, metrics=ov.ENDPOINT_KEYS[1:])
        )
        with monkeypatch.context() as patch:
            patch.setattr(q, "measures_for", lambda wanted: (None, None))  # every measure and histogram
            full_kpis = q.kpis_sync(conn, window, now=now, compare="previous")
        return {
            "kpis": (kpis, full_kpis, kpi_sql),
            "outcomes": (outcomes, q.top_n_sync(conn, window, "outcome", page=page), outcome_sql),
            "endpoints": (endpoints, q.endpoint_table_sync(conn, window, page=page), endpoint_sql),
        }

    found = await rolled.metrics.read(read)
    kpis, full_kpis, kpi_sql = found["kpis"]
    assert kpis == full_kpis
    assert kpis["tiles"]["requests"]["value"] > 0
    assert kpis["tiles"]["p95_ms"]["value"] is not None
    assert not any("queue_wait_hist" in sql for sql in kpi_sql)
    for name, metrics in (("outcomes", ov.OUTCOME_METRICS), ("endpoints", ov.ENDPOINT_KEYS[1:])):
        narrowed, full, statements = found[name]
        assert narrowed["total"] == full["total"] > 1, name
        assert [row["key"] for row in narrowed["rows"]] == [row["key"] for row in full["rows"]], name
        shown = [{metric: row[metric] for metric in metrics} for row in full["rows"]]
        assert [{metric: row[metric] for metric in metrics} for row in narrowed["rows"]] == shown, name
        assert not any("queue_wait_hist" in sql for sql in statements), name
    assert not any("latency_hist" in sql for sql in found["outcomes"][2])  # two counts: no histogram decoded
    assert any("latency_hist" in sql for sql in found["endpoints"][2])  # the p95 column needs the latency one


VISIT_KINDS: list[tuple[str, str | None]] = [
    ("home", "human"),
    ("home", "crawler"),
    ("home", "unknown"),
    ("home", None),
    ("admin", None),
    ("robots", "crawler"),
    ("sitemap", "crawler"),
]


def _visit(at_ms: int, page: str, visitor: str | None, count: int | None) -> tuple[Any, ...]:
    detail: dict[str, Any] = {"page": page}
    if visitor is not None:
        detail["visitor"] = visitor
    if count is not None:
        detail["count"] = count
    return _event(at_ms, "visit", "", detail, template="")


@pytest.mark.parametrize("tz", ["UTC", NY, "Asia/Kolkata"])
@pytest.mark.parametrize("now", [END, END + 30, END + 1830])
async def test_the_visitors_card_reads_once_and_gives_the_two_reads_numbers(dbs: Any, tz: str, now: int) -> None:
    """Final review perf lane: `visit_reads` takes the card's numbers from the sparkline's rows when their buckets
    tile the range (one walk of the visit events instead of two at 90 days); the numbers and the sparklines are
    exactly the two separate reads', ends of the range included, and a range they cannot tile reads twice."""
    rng = random.Random(29)
    rows = [
        _visit(END * 1000 - rng.randrange(100 * 86_400_000), *rng.choice(VISIT_KINDS), rng.choice([None, 1, 2, 5]))
        for _ in range(3000)
    ]
    rows += [_visit(END * 1000 - rng.randrange(20 * 86_400_000), "admin", None, -1) for _ in range(40)]  # discounts
    windows = {key: q.resolve_window(key, now=now, tz=tz) for key in ("1h", "6h", "24h", "7d", "30d", "90d")}
    for window in windows.values():  # events on and next to both ends of each range
        for edge in (window.start, window.end):
            rows += [_visit(edge * 1000 + offset, "home", "human", 3) for offset in (-1, 0, 1)]
    dbs.metrics.write_sync(lambda conn: _insert(conn, rows))

    def read(conn: sqlite3.Connection) -> dict[str, Any]:
        out = {}
        for key, window in windows.items():
            spark = read_dashboard.sparkline_window(window)
            both, statements = _statements(conn, lambda c, s=spark, w=window: read_dashboard.visit_reads(c, s, w))
            apart = (read_dashboard.visit_series(conn, spark), q.visitor_kpis(conn, window))
            tiled = window.start % 3600 == 0 and window.end % 3600 == 0
            if spark.granularity == "minute":
                tiled = window.start % 60 == 0 and window.end % 60 == 0
            out[key] = (both, apart, sum("type = 'visit'" in sql for sql in statements), tiled)
        return out

    found = await dbs.metrics.read(read)
    for key, (both, apart, reads, tiled) in found.items():
        assert both == apart, (key, tz, now)
        assert sum(apart[1].values()) > 0, key
        assert reads == (1 if tiled else 2), (key, tz, now, reads)
    if tz != "Asia/Kolkata":
        assert found["90d"][3], "a 90 day range in a whole-hour zone is read once"
