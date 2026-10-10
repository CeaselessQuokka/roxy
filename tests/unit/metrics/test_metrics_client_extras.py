"""The Clients read models beyond one client's own rows: peers, last seen and recorded bot scores (finding parity-7).

What this is
    Unit tests of `metrics/read_client_extras.py` and the `pair` client rows (`rollups.pair_key`, the recorder's
    `_count_clients`) on a migrated temp metrics.db.

Why it exists
    v1's Callers and Top Talkers showed, per row, the last time a client was seen and its peer count ("IPs" of a place,
    "Places" of an IP), the owner's way to tell one game's many servers from one scraper cycling place ids. The pair
    rows that make it possible share the client tables with `ip` and `place` rows, so these tests pin the parts that
    could go wrong: a peer seen at two levels counts once, the folded `other` row is no peer, one address's key range
    never catches a longer address, and a place id holding the separator still splits right.

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
    many = [{"key": f"10.0.{i // 250}.{i % 250}"} for i in range(extras.KEY_CHUNK * extras.WHOLE_WINDOW_CHUNKS + 1)]
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
