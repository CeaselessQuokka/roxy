"""Read models of the settings editor: history pages with filters, and the latest change of every key.

What this is
    `history_page(conn, ...)` returns one page of `settings_history` (sorted, filtered by key, source, actor, a
    search text and a time window) with the total for the pager. `latest_changes(conn)` returns the newest history
    row of every key ("last changed: who, when, why" on each row of the editor, plan 15.2). `history_entry(conn,
    id)` returns one row. Rows are plain dicts with the JSON columns decoded.

Why it exists
    Plan 15.2 asks for history per key and globally, with one-click revert, and DESIGN.md section 13 puts read
    models next to their data: `settings_history` is written by `config/settings_service.py`, so the reads the
    admin API needs live here, in the config package, instead of inside an API module. `SettingsService.history`
    pages by id only; the editor also needs totals, filters and sorting on the server (parity row 89).

How it works
    Plain parameterized SELECTs inside the caller's read transaction (`Database.read`). Sort columns come from the
    fixed `HISTORY_SORTS` allowlist, never from the request, and every value is a bound parameter. A search is a
    case-insensitive `instr` over the key, the reason and who changed it (no LIKE, so `%` and `_` in a search are
    plain characters). Page sizes are bounded by `MAX_PAGE_ROWS` (plan P9). History values are the stored
    OVERRIDES (NULL means "the catalog default", see settings_service.py); sensitive settings were stored as
    `{fingerprint, masked}` only, so nothing here can expose a secret value.

What to read next
    `roxy/config/settings_service.py` (the writer), `roxy/admin/api/settings.py` (the API that serves these).
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from typing import Any, Final

HISTORY_SORTS: Final[dict[str, str]] = {
    "id": "id",
    "changed_at": "changed_at",
    "key": "key",
    "source": "source",
    "changed_by": "changed_by",
}
"""Sortable history columns (request value -> SQL column). Anything else is refused by the API first."""

MAX_PAGE_ROWS: Final = 250
"""Rows one page may hold (the largest table page size, plan 14.5)."""

MAX_OFFSET: Final = 10_000_000
MAX_LATEST_KEYS: Final = 5000
"""Bound of `latest_changes`: far above the catalog size (keys removed from the catalog may still have history)."""

_COLUMNS: Final = "id, key, old_json, new_json, changed_at, changed_by, reason, source"


def decode_json(text: str | None) -> Any:
    """A JSON column decoded (None stays None; text that is not JSON is returned as is)."""
    if text is None:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return text


def history_row(row: sqlite3.Row | tuple[Any, ...]) -> dict[str, Any]:
    """One `settings_history` row as a dict: `old` and `new` are overrides, None meaning the catalog default."""
    return {
        "id": int(row[0]),
        "key": str(row[1]),
        "old": decode_json(row[2]),
        "new": decode_json(row[3]),
        "changed_at": int(row[4]),
        "changed_by": str(row[5]),
        "reason": row[6],
        "source": str(row[7]),
    }


def history_entry(conn: sqlite3.Connection, history_id: int) -> dict[str, Any] | None:
    """One history row by id, or None."""
    row = conn.execute(
        f"SELECT {_COLUMNS} FROM settings_history WHERE id = ?",  # noqa: S608 (fixed column list)
        (int(history_id),),
    ).fetchone()
    return None if row is None else history_row(row)


def _where(
    *,
    key: str | None,
    source: str | None,
    actor: str | None,
    q: str,
    since: int | None,
    until: int | None,
) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if key is not None:
        clauses.append("key = ?")
        params.append(key)
    if source is not None:
        clauses.append("source = ?")
        params.append(source)
    if actor is not None:
        clauses.append("changed_by = ?")
        params.append(actor)
    if since is not None:
        clauses.append("changed_at >= ?")
        params.append(int(since))
    if until is not None:
        clauses.append("changed_at < ?")
        params.append(int(until))
    needle = q.strip().lower()
    if needle:
        # instr() instead of LIKE: the admin's text is matched literally, `%` and `_` included.
        clauses.append(
            "(instr(lower(key), ?) > 0 OR instr(lower(coalesce(reason, '')), ?) > 0 OR instr(lower(changed_by), ?) > 0)"
        )
        params.extend([needle, needle, needle])
    return (" AND ".join(clauses) if clauses else "1"), params


def history_page(
    conn: sqlite3.Connection,
    *,
    key: str | None = None,
    source: str | None = None,
    actor: str | None = None,
    q: str = "",
    since: int | None = None,
    until: int | None = None,
    sort: str = "id",
    descending: bool = True,
    limit: int = 25,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """One page of settings history and the total matching rows. Ties are broken by id (newest first)."""
    column = HISTORY_SORTS.get(sort)
    if column is None:
        raise ValueError(f"cannot sort settings history by {sort!r}")
    where, params = _where(key=key, source=source, actor=actor, q=q, since=since, until=until)
    total = int(conn.execute(f"SELECT count(*) FROM settings_history WHERE {where}", params).fetchone()[0])  # noqa: S608 (fixed clauses)
    direction = "DESC" if descending else "ASC"
    page = max(1, min(int(limit), MAX_PAGE_ROWS))
    start = max(0, min(int(offset), MAX_OFFSET))
    rows = conn.execute(
        f"SELECT {_COLUMNS} FROM settings_history WHERE {where} "  # noqa: S608 (allowlisted sort column, fixed clauses)
        f"ORDER BY {column} {direction}, id DESC LIMIT ? OFFSET ?",
        (*params, page, start),
    ).fetchall()
    return [history_row(row) for row in rows], total


def latest_changes(conn: sqlite3.Connection, keys: Iterable[str] | None = None) -> dict[str, dict[str, Any]]:
    """The newest history row of every key (or of `keys`): key -> row. One indexed scan (`settings_history_key_id`)."""
    rows = conn.execute(
        f"SELECT {_COLUMNS} FROM settings_history WHERE id IN "  # noqa: S608 (fixed column list)
        "(SELECT max(id) FROM settings_history GROUP BY key) ORDER BY id DESC LIMIT ?",
        (MAX_LATEST_KEYS,),
    ).fetchall()
    wanted = None if keys is None else set(keys)
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        item = history_row(row)
        if wanted is None or item["key"] in wanted:
            out[item["key"]] = item
    return out


def history_sources(conn: sqlite3.Connection, limit: int = 100) -> list[dict[str, Any]]:
    """Distinct sources with their counts (the editor's source filter), most used first."""
    rows = conn.execute(
        "SELECT source, count(*) AS n FROM settings_history GROUP BY source ORDER BY n DESC LIMIT ?",
        (max(1, min(int(limit), 1000)),),
    ).fetchall()
    return [{"source": str(row[0]), "count": int(row[1])} for row in rows]


__all__ = [
    "HISTORY_SORTS",
    "MAX_LATEST_KEYS",
    "MAX_PAGE_ROWS",
    "decode_json",
    "history_entry",
    "history_page",
    "history_row",
    "history_sources",
    "latest_changes",
]
