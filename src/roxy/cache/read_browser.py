"""Read model of the cache browser: one page of stored answers, without the single-flight handoff rows.

What this is
    `browse(conn, ...)` returns one page of cache.db `entries` (no bodies) with each entry's state worked out
    (`fresh`, `stale`, `expired` or `marker`), plus the totals the browser header shows. `entry_state(...)` is the
    same classification for one row, and `is_handoff_key(key)` tells a handoff row by its key text.

Why it exists
    Parity row 66 (browse, search, sort, page, inspect, refresh, purge). `CacheService.list_entries` keeps v1's
    shape and lists every row, including the short-lived handoff rows (key text ending in `" !flight"`) that carry
    a big answer to followers in other workers: they are plumbing, never a lookup result, and live ten seconds, so
    showing them would only confuse (CHANGES.md "handoff rows show in the cache browser" was an open item). The
    admin API needs section 13 sort and order names too. DESIGN.md section 13 puts that read here, next to the
    `entries` table, instead of in the API module.

How it works
    One read transaction: the purge-all generation first (rows from an older generation are already misses and are
    not shown), then a count and a page with `LIMIT ... OFFSET`. The search is a case-insensitive substring of the
    key text, as in v1, with `LIKE` wildcards escaped. Sort columns come from a fixed table (`SORTS`), the
    direction from two literals; ties are broken by id, so pages never overlap. The row size is counted with
    `store.SIZE_SQL`, the same expression the byte budget uses.

What to read next
    `roxy/cache/store.py` (the table and its budgets), `roxy/admin/api/cache.py` (the browser routes).
"""

from __future__ import annotations

import sqlite3
from typing import Any, Final

from roxy.cache.keys import HANDOFF_SUFFIX
from roxy.cache.store import SIZE_SQL
from roxy.config.constants import CACHE_PAGE_MAX

SORTS: Final[dict[str, str]] = {
    "hits": "hits",
    "stored": "stored_at",
    "expires": "expires_at",
    "bytes": SIZE_SQL,
    "key": "lower(key)",
    "last_hit": "last_hit_at",
}
"""Browser sort keys and their columns (v1's `hits`, `stored`, `expires`, `bytes`, `key`, plus `last_hit`)."""

_COLUMNS: Final = (
    "id, key, auth_class, method, host, path, status, content_type, body_len, stored_at, expires_at, stale_until, "
    "ttl, rule_id, egress, hits, last_hit_at, negative"
)
_NOT_HANDOFF: Final = "substr(key, -?) != ?"
MAX_QUERY_CHARS: Final = 200


def is_handoff_key(key: str | None) -> bool:
    """True for a single-flight handoff row (`cache/keys.py HANDOFF_SUFFIX`), which the browser never shows."""
    return bool(key) and str(key).endswith(HANDOFF_SUFFIX)


def entry_state(*, negative: bool, status: int, expires_at: int, stale_until: int, now: float) -> str:
    """`marker` (a per-key Roblox 429 marker), `fresh`, `stale` (past its lifetime, still usable while Roblox
    fails or cools down) or `expired` (waiting for the maintenance pass)."""
    if negative and status == 429:
        return "marker"
    if expires_at > now:
        return "fresh"
    if stale_until > now:
        return "stale"
    return "expired"


def _like(query: str) -> str:
    needle = query.strip().lower()[:MAX_QUERY_CHARS]
    return "%" + needle.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def browse(
    conn: sqlite3.Connection,
    *,
    query: str = "",
    sort: str = "hits",
    descending: bool = True,
    offset: int = 0,
    limit: int = 25,
    now: float,
) -> dict[str, Any]:
    """One browser page: `{total, fresh, rows}` (rows in the chosen order, no bodies)."""
    order = SORTS.get(sort)
    if order is None:
        raise ValueError(f"cannot sort the cache browser by {sort!r}")
    direction = "DESC" if descending else "ASC"
    needle = query.strip().lower()[:MAX_QUERY_CHARS]
    row = conn.execute("SELECT value FROM generation WHERE id = 1").fetchone()
    floor = int(row[0]) if row is not None else 0
    where = f"generation >= ? AND {_NOT_HANDOFF} AND (? = '' OR lower(key) LIKE ? ESCAPE '\\')"
    params: tuple[Any, ...] = (floor, len(HANDOFF_SUFFIX), HANDOFF_SUFFIX, needle, _like(needle))
    total, fresh = conn.execute(
        f"SELECT count(*), coalesce(sum(expires_at > ?), 0) FROM entries WHERE {where}",  # noqa: S608 (constants)
        (int(now), *params),
    ).fetchone()
    # `order` comes from SORTS and `direction` is one of two literals; every value is bound.
    rows = conn.execute(
        f"SELECT {_COLUMNS}, {SIZE_SQL} AS size FROM entries WHERE {where} "  # noqa: S608 (constants)
        f"ORDER BY {order} {direction}, id LIMIT ? OFFSET ?",
        (*params, max(1, min(int(limit), CACHE_PAGE_MAX)), max(0, int(offset))),
    ).fetchall()
    items: list[dict[str, Any]] = []
    for r in rows:
        stored_at, expires_at, stale_until = int(r["stored_at"]), int(r["expires_at"]), int(r["stale_until"])
        negative = bool(r["negative"])
        items.append(
            {
                "id": str(r["id"]),
                "key": str(r["key"]),
                "auth_class": str(r["auth_class"]),
                "method": str(r["method"]),
                "host": str(r["host"]),
                "path": str(r["path"]),
                "status": int(r["status"]),
                "content_type": r["content_type"],
                "body_len": int(r["body_len"] or 0),
                "size": int(r["size"] or 0),
                "stored_at": stored_at,
                "expires_at": expires_at,
                "stale_until": stale_until,
                "ttl": int(r["ttl"]),
                "rule_id": None if r["rule_id"] is None else int(r["rule_id"]),
                "egress": r["egress"],
                "hits": int(r["hits"] or 0),
                "last_hit_at": None if r["last_hit_at"] is None else int(r["last_hit_at"]),
                "negative": negative,
                "state": entry_state(
                    negative=negative, status=int(r["status"]), expires_at=expires_at, stale_until=stale_until, now=now
                ),
                "age_s": max(0, int(now - stored_at)),
                "expires_in_s": int(expires_at - now),
            }
        )
    return {"total": int(total or 0), "fresh": int(fresh or 0), "rows": items}


__all__ = ["SORTS", "browse", "entry_state", "is_handoff_key"]
