"""Read model: the same Roblox error answer fetched again and again for one cache key (CACHE-NEG, plan 11.5).

What this is
    `error_refetches(conn, start, end, statuses)` groups the request samples of `[start, end)` that fetched one of
    `statuses` from Roblox (by default 404 and 400) by endpoint template, cache key and status, and returns each
    group's sample count with its first and last time. A group of `n` samples is `n - 1` identical refetches: the
    first fetch had to happen, every later one asked Roblox a question it had already answered.

Why it exists
    CACHE-NEG fires on "> 100 identical 404 refetches per hour" and proposes a longer `cache_error_ttl_seconds`.
    Counting per key needs the cache key of each fetch, which only `request_samples` keeps (plan 6.2, 11.3); the
    rollups count statuses per endpoint, which cannot tell one deleted item polled 600 times from 600 different
    missing users. DESIGN.md section 13: read models live next to their data.

How it works
    One grouped SQL read over the `request_samples` time index. A sample counts as a fetch when it reached Roblox
    (`egress` is not `none`) and carries Roblox's status (`upstream_status`); samples without a cache key cannot be
    told apart and are left out, and so are samples the cache had off (`cache_state` `OFF`: a POST kept off by
    `cache_post_requests` carries the key the cache would use since finding insights-7, but a request the cache had
    off cannot be helped by the error lifetime CACHE-NEG proposes). Samples are a `request_sample_pct` share of
    requests: the caller scales counts (`roxy/insights/rules/cache.py`). Bounded by `MAX_GROUPS`, busiest first
    (plan P9). Run inside `Database.read`.

What to read next
    `roxy/metrics/samples.py` (what a sample holds), `roxy/insights/rules/cache.py` (CACHE-NEG).
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from typing import Any, Final

DEFAULT_STATUSES: Final[tuple[int, ...]] = (404, 400)
"""Plan 11.5 CACHE-NEG: "Repeated Roblox 404/400"."""
MAX_GROUPS: Final = 5000
"""Most (template, key, status) groups one read returns, most repeated first (P9)."""


def error_refetches(
    conn: sqlite3.Connection, start: int, end: int, statuses: Iterable[int] = DEFAULT_STATUSES
) -> list[dict[str, Any]]:
    """`[{endpoint_template, key_id, status, fetches, first_ms, last_ms}]` in `[start, end)` seconds, most first."""
    wanted = sorted({int(status) for status in statuses})
    if not wanted:
        return []
    marks = ", ".join("?" for _ in wanted)
    rows = conn.execute(
        "SELECT endpoint_template, key_id, upstream_status, count(*) AS n, min(at_ms) AS first_ms, "  # noqa: S608 (only ? marks)
        "max(at_ms) AS last_ms FROM request_samples "
        f"WHERE at_ms >= ? AND at_ms < ? AND upstream_status IN ({marks}) AND key_id IS NOT NULL "
        "AND coalesce(egress, 'none') != 'none' AND coalesce(cache_state, '') != 'OFF' "
        "GROUP BY endpoint_template, key_id, upstream_status ORDER BY n DESC, endpoint_template, key_id LIMIT ?",
        (int(start) * 1000, int(end) * 1000, *wanted, MAX_GROUPS),
    ).fetchall()
    return [
        {
            "endpoint_template": str(row[0]),
            "key_id": str(row[1]),
            "status": int(row[2]),
            "fetches": int(row[3]),
            "first_ms": int(row[4]),
            "last_ms": int(row[5]),
        }
        for row in rows
    ]


__all__ = ["DEFAULT_STATUSES", "MAX_GROUPS", "error_refetches"]
