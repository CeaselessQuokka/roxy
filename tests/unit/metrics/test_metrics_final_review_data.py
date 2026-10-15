"""Final review, fixer "data": the bounded client read, Roblox's answers per attempt, and the limit refusals' outcomes.

What this is
    Unit tests next to the modules the final review's data fixer changed (`.remake/final_review/fix_data.md`):
      * `queries.client_table_sync` and `client_rows_sync` stream the clients and rank them through a bounded heap
        (finding memory-2): every sort, direction, page and search gives exactly the rows the old read (every client
        summed in a dict, then `ordered_rows` and a slice) gave;
      * Roblox's answers per attempt (lead decision 11, findings v1parity-1 and data-3): the recorder counts each call
        of a trace by status class, the compaction keeps them in hours and days, the tiles read them for any range,
        a slice the answer tables do not keep reads unknown (None), and a range that starts before the counting began
        gets the "since when" notice only when the data clock is the migration's;
      * the size and method limit refusals record their outcome once, outside `/admin` and `/internal` (abuse-4).

Why it exists
    The reproductions in `tests/review_final/` pin each finding's one scenario; these pin the rules around them, so a
    later change to the read models keeps the numbers the dashboard shows.

How it works
    The migrated temp databases of `tests/conftest.py` (`dbs`, `fake_clock`) and the metrics fixtures of this folder
    (`recorder`, `settings`); rows written straight into the tables where the recorder is not the subject.

What to read next
    `roxy/metrics/queries.py` (`_client_totals`, `_count_answers`, `answers_notice`), `roxy/metrics/recorder.py`
    (`record_roblox_answer`, `record_limit_refusal`), `roxy/metrics/rollups.py` (the `roblox_answer_*` levels).
"""

from __future__ import annotations

import random
import sqlite3
from types import SimpleNamespace
from typing import Any

import pytest

from roxy.core.clock import FakeClock
from roxy.core.errors import ErrorEvent, ErrorHooks
from roxy.core.reasons import Egress, ReasonCode
from roxy.metrics import queries as q
from roxy.metrics import rollups
from roxy.metrics.recorder import MetricsRecorder
from roxy.metrics.security_events import counts_as_refusal, install_error_hooks

TEMPLATE = "games.roblox.com/v1/games"
DAY = 86_400


# ------------------------------------------------------------------------------------------ bounded client read


def _reference(conn: sqlite3.Connection, window: q.Window, client_type: str, search: str) -> list[dict[str, Any]]:
    """The read before finding memory-2: every client of the pieces summed in a dict (unsorted)."""
    acc: dict[str, dict[str, Any]] = {}
    for table, lo, hi in q._client_pieces(conn, window):
        for row in conn.execute(
            f"SELECT client_key, requests, refused, served, bytes, top_endpoint FROM {table} "
            "WHERE client_type = ? AND bucket_start >= ? AND bucket_start < ?",
            (client_type, lo, hi),
        ):
            key = str(row[0])
            if search and search.lower() not in key.lower():
                continue
            item = acc.setdefault(key, {"key": key, "requests": 0, "refused": 0, "served": 0, "bytes": 0})
            for position, column in enumerate(("requests", "refused", "served", "bytes"), start=1):
                item[column] += int(row[position])
    for item in acc.values():
        item["refused_pct"] = round(item["refused"] * 100.0 / item["requests"], 2) if item["requests"] else None
    return list(acc.values())


def _seed_clients(dbs: Any, now: int) -> None:
    rng = random.Random(5)
    start = now - now % 60 - 3 * 3600
    rows = []
    for minute in range(0, 3 * 60, 7):
        bucket = start + minute * 60
        for n in range(rng.randint(3, 9)):
            requests = rng.choice([1, 1, 2, 5, 5, 9])  # ties
            refused = min(requests, rng.choice([0, 0, 1, 2]))
            key = f"203.0.113.{rng.randint(1, 60)}"
            rows.append((bucket, "ip", key, requests, refused, requests - refused, 10 * n, "t/a"))
        # A client seen without a request (no refused share: it sorts last both ways).
        rows.append((bucket, "ip", f"198.51.100.{minute % 9}", 0, 0, 0, 0, None))
    dbs.metrics.write_sync(
        lambda conn: conn.executemany(
            "INSERT OR IGNORE INTO client_minute (bucket_start, client_type, client_key, requests, refused, served, "
            "bytes, top_endpoint) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
    )


@pytest.mark.parametrize("sort", ["requests", "refused", "served", "bytes", "refused_pct", "key", "last_seen"])
@pytest.mark.parametrize("descending", [True, False])
def test_the_streamed_client_table_gives_the_rows_of_the_old_read(
    dbs: Any, fake_clock: FakeClock, sort: str, descending: bool
) -> None:
    now = int(fake_clock.now())
    _seed_clients(dbs, now)
    window = q.resolve_window("6h", now=now)

    def read(conn: sqlite3.Connection) -> tuple[list[Any], list[Any], set[int]]:
        streamed: list[Any] = []
        totals: set[int] = set()
        for number in range(1, 9):  # every page of 10 (the seed holds about 70 clients), the last ones empty
            page = q.Page(page=number, size=10, sort=sort, descending=descending)
            result = q.client_table_sync(conn, window, "ip", now=now, page=page)
            totals.add(result["total"])
            streamed += [(row["key"], row["requests"], row["refused"], row.get(sort)) for row in result["rows"]]
        reference = _reference(conn, window, "ip", "")
        totals.add(len(reference))
        if sort == "last_seen":
            q.read_client_extras.attach_last_seen(conn, "ip", reference, q._client_pieces(conn, window))
        ordered = q.ordered_rows(reference, sort, descending=descending)
        expected = [(row["key"], row["requests"], row["refused"], row.get(sort)) for row in ordered]
        return streamed, expected, totals

    streamed, expected, totals = dbs.metrics.read_sync(read)
    assert len(totals) == 1, totals
    assert len(expected) > 30, len(expected)
    # Clients without a value (no share without requests) go last both ways: the old read kept them in arrival
    # order, the stream by key. Everything else is in exactly the old order.
    assert [row for row in streamed if row[3] is not None] == [row for row in expected if row[3] is not None]
    assert sorted(row for row in streamed if row[3] is None) == sorted(row for row in expected if row[3] is None)
    if sort == "refused_pct":
        assert streamed[-1][3] is None


def test_a_searched_and_limited_client_read_is_exact(dbs: Any, fake_clock: FakeClock) -> None:
    now = int(fake_clock.now())
    _seed_clients(dbs, now)
    window = q.resolve_window("6h", now=now)

    def read(conn: sqlite3.Connection) -> tuple[Any, ...]:
        page = q.Page(size=10, sort="requests", search="113.1")
        searched = q.client_table_sync(conn, window, "ip", now=now, page=page)
        reference = q.ordered_rows(_reference(conn, window, "ip", "113.1"), "requests")
        limited = q.client_rows_sync(conn, window, "ip", limit=4)
        everything = q.client_rows_sync(conn, window, "ip")
        none = q.client_rows_sync(conn, window, "ip", limit=0)
        return searched, reference, limited, everything, none

    searched, reference, limited, everything, none = dbs.metrics.read_sync(read)
    assert searched["total"] == len(reference)
    assert [row["key"] for row in searched["rows"]] == [row["key"] for row in reference[:10]]
    assert limited == everything[:4]
    assert none == []
    assert all("rate1" not in row for row in everything)  # the insights read carries no Rate1/5/60


def test_a_rate_sort_ranks_every_client_by_its_recent_minutes(dbs: Any, fake_clock: FakeClock) -> None:
    now = int(fake_clock.now())
    minute = now - now % 60
    rows = [
        (minute - 7200, "ip", "198.51.100.1", 50),  # busy long ago: rate 0
        (minute - 120, "ip", "198.51.100.2", 3),
        (minute - 60, "ip", "198.51.100.3", 7),
        (minute - 60, "ip", "198.51.100.4", 1),
    ]
    dbs.metrics.write_sync(
        lambda conn: conn.executemany(
            "INSERT INTO client_minute (bucket_start, client_type, client_key, requests, refused, served, bytes) "
            "VALUES (?, ?, ?, ?, 0, 0, 0)",
            rows,
        )
    )
    window = q.resolve_window("6h", now=now)
    result = dbs.metrics.read_sync(
        lambda conn: q.client_table_sync(conn, window, "ip", now=now, page=q.Page(size=10, sort="rate5"))
    )
    assert [row["key"] for row in result["rows"]] == ["198.51.100.3", "198.51.100.2", "198.51.100.4", "198.51.100.1"]
    assert result["rows"][-1]["rate5"] == 0.0
    assert result["total"] == 4


# ------------------------------------------------------------------------------------------ Roblox's answers


def _trace(*statuses: int | None, egress: str = "direct") -> Any:
    calls = [
        SimpleNamespace(number=n + 1, status=status, egress=egress, csrf_retry=False, redirect_hop=0)
        for n, status in enumerate(statuses)
    ]
    return SimpleNamespace(calls=calls, egress_identity="")


async def test_the_recorder_counts_roblox_answers_per_attempt(
    recorder: MetricsRecorder, fake_clock: FakeClock, dbs: Any, make_event: Any
) -> None:
    users = "users.roblox.com/v1/users/{id}"
    recorder.record_outcome(make_event(endpoint_template=TEMPLATE))  # the caller's own request and status
    recorder.record_outcome(make_event(endpoint_template=users, host="users.roblox.com", egress=Egress.ROTATOR))
    recorder.record_attempts(TEMPLATE, _trace(503, 200))  # a retried call: one 5xx, one 2xx
    recorder.record_attempts(TEMPLATE, _trace(404))
    recorder.record_attempts(TEMPLATE, _trace(None))  # no answer (a timeout): not Roblox's answer
    recorder.record_attempts(users, _trace(200, egress="rotator"))
    # Answers alone (a narrower reset left them) fill a row, never make one: this host had no caller traffic.
    recorder.record_attempts("thumbnails.roblox.com/v1/x", _trace(200))
    await recorder.flush()
    now = int(fake_clock.now())
    window = q.resolve_window("1h", now=now)

    def read(conn: sqlite3.Connection) -> tuple[Any, ...]:
        totals = q.totals_sync(conn, window)
        by_host = q.top_rows_sync(conn, window, "host")
        by_outcome = q.top_rows_sync(conn, window, "outcome")
        filtered = q.totals_sync(conn, window, filters={"egress": "rotator"})
        unknown = q.totals_sync(conn, window, filters={"method": "GET"})
        return totals, by_host, by_outcome, filtered, unknown

    totals, by_host, by_outcome, filtered, unknown = dbs.metrics.read_sync(read)
    assert (totals["status_2xx"], totals["status_4xx"], totals["roblox_5xx"]) == (3, 1, 1)
    # The caller's own view stays in the rollups: two requests, answered 200.
    assert (totals["requests"], totals["caller_2xx"], totals["caller_4xx"], totals["caller_roblox_5xx"]) == (2, 2, 0, 0)
    hosts = {row["key"]: (row["status_2xx"], row["status_4xx"], row["roblox_5xx"]) for row in by_host}
    assert hosts == {"games.roblox.com": (1, 1, 1), "users.roblox.com": (1, 0, 0)}
    assert [row["key"] for row in by_outcome] == ["served_upstream"]
    assert by_outcome[0]["status_2xx"] is None  # a slice the answer tables do not keep: unknown, never zero
    assert (filtered["status_2xx"], filtered["roblox_5xx"]) == (1, 0)
    assert unknown["status_2xx"] is None
    assert unknown["roblox_5xx"] is None


async def test_roblox_answers_survive_the_compaction_and_the_minute_retention(
    recorder: MetricsRecorder, fake_clock: FakeClock, dbs: Any
) -> None:
    from roxy.storage import retention

    recorder.record_attempts(TEMPLATE, _trace(503, 503, 200))
    await recorder.flush()
    fake_clock.advance(3 * 3600)

    async def write(fn: Any) -> Any:
        return await dbs.metrics.write(fn)

    config = rollups.CompactionConfig(tz_name="UTC")
    await rollups.compact_all(write, fake_clock.now(), config)
    fake_clock.advance(15 * DAY)
    await rollups.compact_all(write, fake_clock.now(), config)
    await retention.run_tasks(dbs, retention.RETENTION_TASKS, retention.RetentionPolicy(), fake_clock.now())
    left = dbs.metrics.read_sync(lambda conn: conn.execute("SELECT count(*) FROM roblox_answer_minute").fetchone()[0])
    assert left == 0
    now = int(fake_clock.now())
    for name in ("30d", "90d"):
        window = q.resolve_window(name, now=now)
        totals = dbs.metrics.read_sync(lambda conn, window=window: q.totals_sync(conn, window))
        assert (totals["status_2xx"], totals["roblox_5xx"]) == (1, 2), name
        series = dbs.metrics.read_sync(
            lambda conn, window=window: q.series_sync(conn, window, metrics=["roblox_5xx", "status_2xx"])
        )
        assert sum(series["groups"]["all"]["roblox_5xx"]) == 2, name


def test_the_since_notice_needs_traffic_from_before_the_counting(dbs: Any, fake_clock: FakeClock) -> None:
    now = int(fake_clock.now())
    since = now - 2 * 3600

    def stamp(conn: sqlite3.Connection) -> None:
        conn.execute("UPDATE schema_version SET applied_at = ? WHERE version = ?", (since, q.ANSWERS_SCHEMA_VERSION))

    dbs.metrics.write_sync(stamp)
    window = q.resolve_window("24h", now=now)
    assert dbs.metrics.read_sync(lambda conn: q.answers_notice(conn, [window], now=now)) is None  # no traffic before
    dims = (
        "t/x",
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
    key = 42

    def old_traffic(conn: sqlite3.Connection) -> None:
        conn.execute(
            f"INSERT INTO dims (dim_hash, {', '.join(rollups.DIM_COLUMNS)}) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (key, *dims),
        )
        conn.execute(
            "INSERT INTO rollup_minute (bucket_start, dim_hash, requests) VALUES (?, ?, 3)", (since - 600, key)
        )

    dbs.metrics.write_sync(old_traffic)
    notice = dbs.metrics.read_sync(lambda conn: q.answers_notice(conn, [window], now=now))
    assert notice is not None
    assert "counted since" in notice
    kpis = dbs.metrics.read_sync(lambda conn: q.kpis_sync(conn, window, now=now))
    assert kpis["tiles"]["status_2xx"]["notice"] == notice
    assert kpis["tiles"]["requests"].get("notice") is None
    # A migration time after the data clock is not an upgrade still to come (a test's fake clock): no notice.
    assert dbs.metrics.read_sync(lambda conn: q.answers_notice(conn, [window], now=since - 7200)) is None


# ------------------------------------------------------------------------------------------ limit refusals


def test_only_callers_limit_refusals_record_an_outcome(recorder: MetricsRecorder, metrics_rows: Any) -> None:
    hooks = ErrorHooks()
    install_error_hooks(hooks, lambda: recorder)
    for path, reason, status in (
        ("/games.roblox.com/v1/games", ReasonCode.URL_TOO_LONG, 414),
        ("/", ReasonCode.METHOD_NOT_ALLOWED, 405),
        ("/admin/api/v1/settings", ReasonCode.METHOD_NOT_ALLOWED, 405),  # the dashboard's own: not caller traffic
        ("/internal/version", ReasonCode.HEADERS_TOO_LARGE, 431),  # the operator paths: never counted
        ("/missing", None, 404),  # a plain client error: a probe only
    ):
        event = ErrorEvent(status, reason, "", "R1", "198.51.100.3", "GET", path, "curl/8")
        assert counts_as_refusal(event) == (path in ("/games.roblox.com/v1/games", "/"))
        hooks.client_error[0](event)
    recorder.close()
    rows = metrics_rows(
        "SELECT d.endpoint_template, d.reason_code, d.status, d.outcome, r.requests FROM rollup_minute r "
        "JOIN dims d ON d.dim_hash = r.dim_hash ORDER BY d.status"
    )
    assert rows == [
        ("(method_not_allowed)", "method_not_allowed", 405, "refused", 1),
        ("(url_too_long)", "url_too_long", 414, "refused", 1),
    ]
    probes = metrics_rows("SELECT count(*) FROM events WHERE type = 'probe'")
    assert probes == [(5,)]  # every client error is still a probe
