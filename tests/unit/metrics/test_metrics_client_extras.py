"""The Clients read models beyond one client's own rows: peers, last seen and recorded bot scores (finding parity-7).

What this is
    Unit tests of `metrics/read_client_extras.py` and the `pair` client rows (`rollups.pair_key`, the recorder's
    `_count_clients`) on a migrated temp metrics.db.

Why it exists
    v1's Callers and Top Talkers showed, per row, the last time a client was seen and its peer count ("IPs" of a place,
    "Places" of an IP), the owner's way to tell one game's many servers from one scraper cycling place ids. The pair
    rows that make it possible share the client tables with `ip` and `place` rows, so these tests pin the parts that
    could go wrong: a peer seen at two levels counts once, the folded `other` row is no peer, one address's key range
    never catches a longer address, a place id holding the separator still splits right, and the peer reads keep
    their index ranges under the planner statistics of a plan-size database (the query plans, not timings).

How it works
    Rows are written straight into `client_minute` and `client_hour` (and `client_score_hour`), then the read models
    run on the pieces a table read would use. One test goes through the real recorder instead.

What to read next
    `roxy/metrics/read_client_extras.py`, `roxy/metrics/queries.py` (`client_table_sync`), `roxy/metrics/rollups.py`.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from typing import Any

from roxy.core.clock import FakeClock
from roxy.metrics import queries as q
from roxy.metrics import read_client_extras as extras
from roxy.metrics.recorder import MetricsRecorder, OutcomeEvent
from roxy.metrics.rollups import PAIR_CLIENT_TYPE, pair_key, split_pair

HOUR = 1_759_996_800  # an hour start before the fake clock's time
MINUTE = HOUR + 3600


def put(dbs: Any, table: str, bucket: int, client_type: str, key: str, requests: int = 1) -> None:
    def write(conn: sqlite3.Connection) -> None:
        conn.execute(
            f"INSERT INTO {table} (bucket_start, client_type, client_key, requests, refused, served, bytes) "
            "VALUES (?, ?, ?, ?, 0, ?, 0)",
            (bucket, client_type, key, requests, requests),
        )

    dbs.metrics.write_sync(write)


def pair(dbs: Any, table: str, bucket: int, ip: str, place: str, requests: int = 1) -> None:
    key = pair_key(ip, place)
    assert key is not None
    put(dbs, table, bucket, PAIR_CLIENT_TYPE, key, requests)


PIECES = [("client_hour", HOUR, MINUTE), ("client_minute", MINUTE, MINUTE + 600)]


def test_pair_keys_split_at_the_first_separator() -> None:
    assert pair_key("203.0.113.5", "a|b") == "203.0.113.5|a|b"
    assert split_pair("203.0.113.5|a|b") == ("203.0.113.5", "a|b")
    assert pair_key("", "1") is None
    assert pair_key("1.2.3.4", "") is None
    assert pair_key("bad|ip", "1") is None
    assert split_pair("other") is None


def test_peer_counts_across_levels_count_each_peer_once(dbs: Any) -> None:
    pair(dbs, "client_hour", HOUR, "203.0.113.8", "111", 5)
    pair(dbs, "client_minute", MINUTE, "203.0.113.8", "111", 2)  # the same peer again, at the finer level
    pair(dbs, "client_minute", MINUTE, "203.0.113.8", "222")
    pair(dbs, "client_minute", MINUTE, "203.0.113.81", "333")  # a longer address: never inside .8's key range
    pair(dbs, "client_minute", MINUTE, "203.0.113.9", "a|b")
    put(dbs, "client_minute", MINUTE, PAIR_CLIENT_TYPE, "other", 40)  # the folded row is nobody's peer
    read = dbs.metrics.read_sync
    ips = read(lambda c: extras.peer_counts(c, "ip", ["203.0.113.8", "203.0.113.81", "198.51.100.1", "other"], PIECES))
    assert ips == {"203.0.113.8": 2, "203.0.113.81": 1}
    places = read(lambda c: extras.peer_counts(c, "place", ["111", "a|b", "999"], PIECES))
    assert places == {"111": 1, "a|b": 1}
    listing = read(lambda c: extras.peer_list(c, "ip", "203.0.113.8", PIECES))
    assert listing["total"] == 2
    assert [(p["key"], p["requests"], p["last_seen"]) for p in listing["items"]] == [
        ("111", 7, MINUTE),
        ("222", 1, MINUTE),
    ]
    assert read(lambda c: extras.peer_list(c, "place", "other", PIECES))["items"] == []
    assert read(lambda c: extras.peer_counts(c, "ip", ["203.0.113.8"], [])) == {}


def test_last_seen_is_the_newest_bucket_in_the_pieces(dbs: Any) -> None:
    put(dbs, "client_hour", HOUR, "ip", "203.0.113.8")
    put(dbs, "client_minute", MINUTE + 120, "ip", "203.0.113.8")
    put(dbs, "client_hour", HOUR, "ip", "203.0.113.9")
    rows: list[dict[str, Any]] = [{"key": "203.0.113.8"}, {"key": "203.0.113.9"}, {"key": "198.51.100.1"}]
    dbs.metrics.read_sync(lambda c: extras.attach_last_seen(c, "ip", rows, PIECES))
    assert [row["last_seen"] for row in rows] == [MINUTE + 120, HOUR, None]
    count = extras.KEY_CHUNK * extras.WHOLE_WINDOW_CHUNKS + 1
    many: list[dict[str, Any]] = [{"key": f"10.0.{i // 250}.{i % 250}"} for i in range(count)]
    many.append({"key": "203.0.113.8"})
    dbs.metrics.read_sync(lambda c: extras.attach_last_seen(c, "ip", many, PIECES))  # the whole-window path
    assert many[-1]["last_seen"] == MINUTE + 120
    assert many[0]["last_seen"] is None


def test_recorded_scores_answer_each_address_latest_hour(dbs: Any) -> None:
    def write(conn: sqlite3.Connection) -> None:
        for bucket, key, top, last in ((HOUR, "203.0.113.8", 80, 70), (MINUTE, "203.0.113.8", 30, 20),
                                       (HOUR, "203.0.113.9", 55, 55)):  # fmt: skip
            conn.execute(
                "INSERT INTO client_score_hour (bucket_start, client_key, score_max, score_last, last_at, samples) "
                "VALUES (?, ?, ?, ?, ?, 1)",
                (bucket, key, top, last, bucket + 10),
            )

    dbs.metrics.write_sync(write)
    found = dbs.metrics.read_sync(lambda c: extras.recorded_scores(c, ["203.0.113.8", "203.0.113.9", "x"], HOUR))
    assert found["203.0.113.8"] == {"score": 30, "score_last": 20, "at": MINUTE + 10, "hour": MINUTE}
    assert found["203.0.113.9"]["score"] == 55
    assert "x" not in found
    later = dbs.metrics.read_sync(lambda c: extras.recorded_scores(c, ["203.0.113.9"], MINUTE))
    assert later == {}  # only hours since `since`


async def test_the_client_table_carries_last_seen_and_peers(
    recorder: MetricsRecorder, make_event: Callable[..., OutcomeEvent], fake_clock: FakeClock
) -> None:
    recorder.record_outcome(make_event(client_ip="203.0.113.81", place_id="111"))
    recorder.record_outcome(make_event(client_ip="203.0.113.81", place_id="222"))
    recorder.record_outcome(make_event(client_ip="203.0.113.82", place_id="111"))
    recorder.record_outcome(make_event(client_ip="203.0.113.83", place_id=None))
    recorder.close()
    now = fake_clock.now()
    window = q.resolve_window("1h", now=now)
    read = recorder.dbs.metrics.read_sync
    ips = read(lambda c: q.client_table_sync(c, window, "ip", now=now, extras=True))
    rows = {row["key"]: row for row in ips["rows"]}
    assert (rows["203.0.113.81"]["peers"], rows["203.0.113.82"]["peers"], rows["203.0.113.83"]["peers"]) == (2, 1, 0)
    assert rows["203.0.113.81"]["last_seen"] == int(now) // 60 * 60
    places = read(lambda c: q.client_table_sync(c, window, "place", now=now, extras=True))
    assert {row["key"]: row["peers"] for row in places["rows"]} == {"111": 2, "222": 1}
    plain = read(lambda c: q.client_table_sync(c, window, "ip", now=now))  # insights, health, the LLM export
    assert all("peers" not in row and "last_seen" not in row for row in plain["rows"])
    sorted_rows = read(lambda c: q.client_table_sync(c, window, "ip", now=now, page=q.Page(sort="last_seen")))
    assert len(sorted_rows["rows"]) == 3
    assert all(row["last_seen"] == int(now) // 60 * 60 for row in sorted_rows["rows"])


PLAN_SIZE_STATS = (
    ("client_minute", "client_minute", "3048777 706 236 1"),
    ("client_minute", "client_minute_client", "3048777 1016259 736 1"),
    ("client_minute", "client_minute_pair_place", "1324689 9136 4"),
    ("client_minute", "client_minute_ip_rows", "1361826 681 1 1 1 1 1 1"),
    ("client_hour", "client_hour", "2476373 1147 383 1"),
    ("client_hour", "client_hour_client", "2476373 825458 598 1"),
    ("client_hour", "client_hour_pair_place", "1081659 7409 5"),
)
"""The `sqlite_stat1` rows `PRAGMA optimize` left for the client tables of the dashboard scenario's plan-size template
(2026-10-14: 3,048,777 client minute rows, 1,324,689 of them pairs; `tests/load/pages.py`)."""


def _with_plan_size_stats(conn: sqlite3.Connection) -> None:
    conn.execute("ANALYZE")  # creates sqlite_stat1, as the writer's close and the daily maintenance do (plan 6.5)
    conn.execute("DELETE FROM sqlite_stat1 WHERE tbl IN ('client_minute', 'client_hour')")
    conn.executemany("INSERT INTO sqlite_stat1 (tbl, idx, stat) VALUES (?, ?, ?)", PLAN_SIZE_STATS)


def test_peer_counts_keep_their_index_ranges_whatever_the_planner_statistics(dbs: Any) -> None:
    """With the statistics of a plan-size metrics.db, an address's peers are still its key range of `client_*_client`
    (never a skip-scan of `*_pair_place` over the window: 25 ms an address, 0.6 s for the 25 rows of Clients > IP
    addresses, `read_client_extras.KEY_INDEX`), and every count reads its index alone (a covering index), across
    levels too."""
    for minute in range(3):
        for n in range(4):
            pair(dbs, "client_minute", MINUTE + 60 * minute, f"203.0.113.{n}", str(111 + n % 2))
    pair(dbs, "client_hour", HOUR, "203.0.113.1", "333")
    dbs.metrics.write_sync(_with_plan_size_stats)
    ips = ["203.0.113.0", "203.0.113.1"]

    def read(conn: sqlite3.Connection) -> tuple[Any, ...]:
        statements: list[str] = []
        conn.set_trace_callback(statements.append)  # SQLite passes each statement with its values in place
        try:
            counts = extras.peer_counts(conn, "ip", ips, PIECES)
            one_level = extras.peer_counts(conn, "ip", ips, PIECES[1:])  # one level: a statement SQLite flattens
            places = extras.peer_counts(conn, "place", ["111", "112", "333"], PIECES)
            listing = extras.peer_list(conn, "ip", "203.0.113.1", PIECES)
        finally:
            conn.set_trace_callback(None)
        plans = {
            sql: [str(tuple(row)[-1]) for row in conn.execute(f"EXPLAIN QUERY PLAN {sql}")]
            for sql in statements
            if f"'{PAIR_CLIENT_TYPE}'" in sql
        }
        # The count without the index named: `count(DISTINCT <place part>)` is what draws the planner to the place
        # index (its rows come in place order, so the distinct needs no sort), and the statistics make a skip-scan of
        # it look cheap.
        unpinned, params = extras._union(PIECES[1:], *extras._ip_ranges(["203.0.113.0"]), columns=extras.KEY_COLUMNS)
        place_part = extras._sides("ip")[1]
        before = [
            str(tuple(row)[-1])
            for row in conn.execute(f"EXPLAIN QUERY PLAN SELECT count(DISTINCT {place_part}) FROM ({unpinned})", params)
        ]
        return counts, one_level, places, listing, plans, before

    # A fresh connection reads the statistics, as every reader does after the daily `PRAGMA optimize`.
    counts, one_level, places, listing, plans, before = dbs.metrics.maintenance_sync(read)
    assert counts == {"203.0.113.0": 1, "203.0.113.1": 2}
    assert one_level == {"203.0.113.0": 1, "203.0.113.1": 1}
    assert places == {"111": 2, "112": 2, "333": 1}
    assert listing["total"] == 2
    # The hazard is real with these statistics: left to itself the planner skip-scans the place index for an address.
    assert any("pair_place" in line and "ANY(" in line for line in before), before
    searches = {sql: [line for line in plan if line.startswith("SEARCH")] for sql, plan in plans.items()}
    address_reads = [sql for sql in searches if "client_key >= " in sql]
    assert len(address_reads) == 2 * len(ips) + 2  # the counts at two levels, at one level, and the listing's two
    for sql in address_reads:
        assert searches[sql], sql
        for line in searches[sql]:
            assert "INDEX client_minute_client (" in line or "INDEX client_hour_client (" in line, (sql, line)
            assert "client_key>? AND client_key<?" in line, (sql, line)
    for sql, lines in searches.items():
        if "count(DISTINCT" in sql.split(" FROM ", 1)[0]:  # a count (the listing reads its rows' numbers too)
            assert all("USING COVERING INDEX" in line for line in lines), (sql, lines)
        if "client_key >= " not in sql:  # the place counts: the place index, an equality per place
            assert all("_pair_place (<expr>=?" in line for line in lines), (sql, lines)
