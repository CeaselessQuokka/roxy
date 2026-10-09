"""Read model: how many cache entries a purge would remove, for the reset preview (plan 6.8 "Cache only").

What this is
    `purge_preview(conn, scope, now_s)` counts the `entries` rows a `PurgeScope` selects, with their bytes and the
    stored-at range, without deleting anything: `{rows, bytes, oldest, newest, scanned, complete}`.

Why it exists
    Plan 6.8: every reset shows a preview with exact row counts and dates before anything is deleted. The purge
    itself is `CacheService.purge` (cache/service.py), which bumps the generation first and deletes in batches;
    it reports what it removed only afterwards. The Data page needs the numbers first, and the read belongs to the
    cache package (DESIGN.md section 13).

How it works
    The selection mirrors `CacheStore._purge_rows` one to one: ALL is every row, HOST, RULE and EXPIRED are SQL
    conditions on indexed columns (EXPIRED counts rows whose stale window ended, or whose lifetime ended with
    `include_stale`), and PATTERN and PARAM test each row in Python with the store's own `target_matches` and
    parameter check. The Python scans read at most `MAX_SCAN` rows (plan P9); `complete` is False when the table
    holds more, and the counts are then a lower bound (the purge still removes every match). A change to
    `_purge_rows` must be mirrored here; `tests/integration/admin_api/test_api_data.py` compares both.

What to read next
    `roxy/cache/store.py` (`PurgeScope`, `_purge_rows`), `roxy/admin/api/data.py` (the reset preview).
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any, Final

from roxy.cache.store import PurgeKind, PurgeScope, target_matches

MAX_SCAN: Final = 200_000
"""Rows a pattern or parameter preview reads at most (the disk tier is bounded by `cache_max_bytes`)."""


def _summary(conn: sqlite3.Connection, where: str, params: tuple[Any, ...]) -> dict[str, Any]:
    row = conn.execute(
        f"SELECT count(*), coalesce(sum(bytes), 0), min(stored_at), max(stored_at) FROM entries WHERE {where}",  # noqa: S608 (fixed clauses)
        params,
    ).fetchone()
    return {
        "rows": int(row[0]),
        "bytes": int(row[1]),
        "oldest": None if row[2] is None else int(row[2]),
        "newest": None if row[3] is None else int(row[3]),
        "scanned": int(row[0]),
        "complete": True,
    }


def _param_mentioned(params_json: str | None, name: str) -> bool:
    """`store._params_mention` (kept private there): the entry's key mentions query parameter `name`."""
    if not params_json:
        return False
    try:
        doc = json.loads(params_json)
    except ValueError:
        return False
    if not isinstance(doc, dict):
        return False
    if name in doc.get("stripped", ()):
        return True
    return any(pair and pair[0] == name for pair in doc.get("params", ()))


def purge_preview(conn: sqlite3.Connection, scope: PurgeScope, now_s: int) -> dict[str, Any]:
    """What `CacheService.purge(scope)` would remove right now (see the module docstring)."""
    scope = scope.validated()
    kind = scope.kind
    if kind == PurgeKind.ALL:
        return _summary(conn, "1", ())
    if kind == PurgeKind.ID:
        return _summary(conn, "id = ?", (str(scope.value),))
    if kind == PurgeKind.HOST:
        return _summary(conn, "host = ?", (scope.value,))
    if kind == PurgeKind.RULE:
        return _summary(conn, "rule_id = ?", (scope.value,))
    if kind == PurgeKind.EXPIRED:
        column = "expires_at" if scope.include_stale else "stale_until"
        return _summary(conn, f"{column} <= ?", (int(now_s),))
    rows = bytes_ = scanned = 0
    oldest: int | None = None
    newest: int | None = None
    cursor = conn.execute("SELECT host, path, params_json, bytes, stored_at FROM entries LIMIT ?", (MAX_SCAN + 1,))
    for host, path, params_json, size, stored_at in cursor:
        scanned += 1
        if scanned > MAX_SCAN:
            break
        if kind == PurgeKind.PATTERN:
            hit = target_matches(str(scope.value), scope.pattern_type, f"{host}/{path}")
        else:
            hit = _param_mentioned(params_json, str(scope.value))
        if not hit:
            continue
        rows += 1
        bytes_ += int(size or 0)
        stamp = int(stored_at or 0)
        oldest = stamp if oldest is None else min(oldest, stamp)
        newest = stamp if newest is None else max(newest, stamp)
    return {
        "rows": rows,
        "bytes": bytes_,
        "oldest": oldest,
        "newest": newest,
        "scanned": min(scanned, MAX_SCAN),
        "complete": scanned <= MAX_SCAN,
    }


__all__ = ["MAX_SCAN", "purge_preview"]
