"""Read model: the cache.db rows the key spread diagnostic groups (CACHE-KEYSPLIT and CACHE-LOW-HIT, plan 11.5).

What this is
    `spread_rows(conn, max_rows)` returns `(method, host, path, params_json, hits, bytes)` of the newest content
    entries of cache.db, the input of `cache/spread.py compute_spread` (the v1 Suspect rule, parity row 65), as a
    plain function over a connection.

Why it exists
    The recommendation engine evaluates rules over its own read-only context (`roxy/insights/context.py`), which
    reads databases through `Database.read` with a connection, not through a worker's `CacheService` (the leader
    may evaluate while its cache service is busy, and rules must not flush or touch the memory tier).
    `CacheService.key_spread` reads the same rows through `SharedTier.spread_rows`, an async method tied to the
    shared tier object. DESIGN.md section 13: read models live next to their data, in the owning package.

How it works
    The same query as `SharedTier.spread_rows` (`cache/store.py`): only rows of the current purge generation, no
    429 markers (they repeat a real entry's parameters), no single-flight handoff rows (key text ending in
    `keys.HANDOFF_SUFFIX`), newest first, at most `max_rows` (plan P9). The row size is `store.SIZE_SQL`, the bytes
    each row counts against `cache_max_bytes`. Run inside `Database.read` on the cache database.

What to read next
    `roxy/cache/spread.py` (the grouping and the Suspect test), `roxy/insights/rules/cache.py` (the rules).
"""

from __future__ import annotations

import sqlite3
from typing import Final

from roxy.cache.keys import HANDOFF_SUFFIX
from roxy.cache.spread import DEFAULT_MAX_ROWS
from roxy.cache.store import SIZE_SQL

SpreadTuple = tuple[str, str, str, str | None, int, int]

_SQL: Final = (
    f"SELECT method, host, path, params_json, hits, {SIZE_SQL} FROM entries "  # noqa: S608 (store constants only)
    "WHERE generation >= ? AND NOT (negative = 1 AND status = 429) AND substr(key, -?) != ? "
    "ORDER BY rowid DESC LIMIT ?"
)


def spread_rows(conn: sqlite3.Connection, max_rows: int = DEFAULT_MAX_ROWS) -> list[SpreadTuple]:
    """`(method, host, path, params_json, hits, bytes)` of up to `max_rows` content entries, newest first."""
    row = conn.execute("SELECT value FROM generation WHERE id = 1").fetchone()
    floor = int(row[0]) if row is not None else 0
    limit = max(1, min(int(max_rows), DEFAULT_MAX_ROWS))
    return [
        (str(r[0]), str(r[1]), str(r[2]), r[3], int(r[4] or 0), int(r[5] or 0))
        for r in conn.execute(_SQL, (floor, len(HANDOFF_SUFFIX), HANDOFF_SUFFIX, limit)).fetchall()
    ]


__all__ = ["SpreadTuple", "spread_rows"]
