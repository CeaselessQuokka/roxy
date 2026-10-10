"""The Roblox 429 log read page by page (`metrics/read_history.py upstream_429_rows(..., offset=)`).

What this is
    A unit test on a migrated temp metrics.db: rows of `upstream_429` read in pages with `limit` and `offset` come back
    oldest first, ties broken by row id, so the pages never repeat or skip a row.

Why it exists
    Finding mpjobs-5: a table download must hold one page of rows at a time. The `upstream_429` export dataset used to
    read up to 50,000 rows in one piece; it now pages through this read model (`admin/api/export.py`), which is only
    correct when the order is total (many 429s share one millisecond under a burst).

How it works
    Rows with repeated `at_ms` values are inserted, then read whole and in pages of 3; the concatenated pages must
    equal the whole read.

What to read next
    `roxy/metrics/read_history.py`, `roxy/admin/api/export.py` (`_429s`), `roxy/admin/api/common.py`
    (`export_pages`).
"""

from __future__ import annotations

import sqlite3
from typing import Any

from roxy.metrics.read_history import upstream_429_rows


def test_pages_of_the_429_log_never_repeat_or_skip_a_row(dbs: Any) -> None:
    def seed(conn: sqlite3.Connection) -> None:
        for n in range(10):
            conn.execute(
                "INSERT INTO upstream_429 (at_ms, endpoint_template, host, egress, request_id) VALUES (?, ?, ?, ?, ?)",
                (1_000_000 + (n // 4) * 1000, "games.roblox.com/v1/games", "games.roblox.com", "direct", f"r{n}"),
            )

    dbs.metrics.write_sync(seed)
    whole = dbs.metrics.read_sync(lambda conn: upstream_429_rows(conn, 900, 1100))
    assert len(whole) == 10
    paged: list[dict[str, Any]] = []
    for page in range(4):
        rows = dbs.metrics.read_sync(lambda conn, p=page: upstream_429_rows(conn, 900, 1100, limit=3, offset=p * 3))
        paged.extend(rows)
    assert [r["request_id"] for r in paged] == [r["request_id"] for r in whole]
    assert [r["request_id"] for r in whole] == [f"r{n}" for n in range(10)]  # oldest first, then by row id
