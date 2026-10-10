"""The CACHE-NEG read model: repeated Roblox error answers per cache key (`metrics/read_refetch.py`).

What this is
    Unit tests of `error_refetches` on a migrated temp metrics.db: request samples are grouped by endpoint template,
    cache key and Roblox status, and only samples that reached Roblox through the cache path count.

Why it exists
    Since finding insights-7 a POST the cache had off (`cache_post_requests`) is sampled with the key the cache would
    use, so its repeated 404s now share a key id. CACHE-NEG proposes a longer error lifetime, which cannot avoid a
    single call the cache had off: those samples must not count (the cache_health_ops fixer's request 1 of review
    round 3), exactly as before the key id existed.

How it works
    Rows are inserted with the `request_samples` columns the recorder writes, then the read model is asked for the
    window. Plain SQL, no clock.

What to read next
    `roxy/metrics/read_refetch.py`, `roxy/insights/rules/cache.py` (CACHE-NEG), `roxy/cache/service.py` (`peek`).
"""

from __future__ import annotations

import sqlite3
from typing import Any

from roxy.metrics.read_refetch import error_refetches

TEMPLATE = "games.roblox.com/v1/games/{id}"


def _sample(
    conn: sqlite3.Connection, at_ms: int, key_id: str | None, status: int, cache_state: str, egress: str
) -> None:
    conn.execute(
        "INSERT INTO request_samples (at_ms, key_id, endpoint_template, method, cache_state, upstream_status, egress) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (at_ms, key_id, TEMPLATE, "POST" if cache_state == "OFF" else "GET", cache_state, status, egress),
    )


def test_samples_the_cache_had_off_never_count_as_refetches(dbs: Any) -> None:
    def seed(conn: sqlite3.Connection) -> None:
        for n in range(3):
            _sample(conn, 1_000_000 + n, "k-get", 404, "MISS", "direct")  # 3 fetches of one GET key: counts
        for n in range(4):
            _sample(conn, 1_000_100 + n, "k-post", 404, "OFF", "direct")  # a POST kept off: never counts
        _sample(conn, 1_000_200, None, 404, "MISS", "direct")  # no key: cannot be told apart
        _sample(conn, 1_000_300, "k-hit", 404, "HIT", "none")  # served from the cache: not a fetch

    dbs.metrics.write_sync(seed)
    groups = dbs.metrics.read_sync(lambda conn: error_refetches(conn, 900, 1100))
    assert [(g["key_id"], g["status"], g["fetches"]) for g in groups] == [("k-get", 404, 3)]
