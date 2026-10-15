"""Read model of the audit log: filtered pages, one entry with its before and after, facets, revert lookups.

What this is
    `audit_page(conn, ...)` returns one page of `audit_log` rows (newest first by default) filtered by action,
    actor, target (exact or by prefix), a search text and a time window, with the total. List rows carry a short
    preview of `before_json` and `after_json` (`PREVIEW_CHARS`), never the whole documents; `audit_entry(conn, id)`
    returns one row with both documents decoded, for the diff view. `audit_facets` lists the actions and actors
    seen (filter menus), and `settings_history_id` finds the `settings_history` row written in the same
    transaction as a settings audit row (the Audit page's revert link).

Why it exists
    Plan 9.7 and 14.1: the Audit page has search, filters, export, a diff view and revert links. DESIGN.md
    section 13 keeps read models next to their data, and `audit_log` belongs to `config/audit.py`.

How it works
    Parameterized SELECTs in the caller's read transaction. Sort columns come from `AUDIT_SORTS`; a prefix filter
    is a range scan (`target >= ? AND target < ? || U+10FFFF`) on the existing `(target, at)` and `(action, at)`
    indexes, and a search uses `instr` so `%` and `_` are plain characters. The secret rule (plan 6.2) was applied
    when the rows were written: secret targets hold only `{fingerprint, masked}`, so nothing here can expose one.
    Pages and previews are bounded (plan P9): 250 rows, 2000 characters per document preview.

What to read next
    `roxy/config/audit.py` (the writer and the secret rule), `roxy/admin/api/audit.py` (the Audit page API).
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any, Final

AUDIT_SORTS: Final[dict[str, str]] = {"id": "id", "at": "at", "action": "action", "actor": "actor", "target": "target"}
"""Sortable columns (request value -> SQL column)."""

MAX_PAGE_ROWS: Final = 250
MAX_OFFSET: Final = 10_000_000
PREVIEW_CHARS: Final = 2000
"""How much of `before_json` and `after_json` a list row carries (the entry view has the whole documents)."""

MAX_FACETS: Final = 500
_PREFIX_END: Final = "\U0010ffff"  # the largest code point: `x < prefix + this` closes a prefix range scan

SETTING_ACTIONS: Final[frozenset[str]] = frozenset(
    {"setting.update", "setting.reset", "setting.revert", "settings.import"}
)
"""Audit actions written by `SettingsService` together with a `settings_history` row (revertible from history)."""


def _decode(text: str | None) -> Any:
    if text is None:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return text


def _match(column: str, value: str, clauses: list[str], params: list[Any]) -> None:
    """Exact match, or a prefix match when `value` ends with `*` (`setting:*`, `rule.*`)."""
    if value.endswith("*"):
        prefix = value[:-1]
        if prefix:
            clauses.append(f"{column} >= ? AND {column} < ?")
            params.extend([prefix, prefix + _PREFIX_END])
        return
    clauses.append(f"{column} = ?")
    params.append(value)


def audit_where(
    *,
    action: str | None = None,
    actor: str | None = None,
    target: str | None = None,
    q: str = "",
    since: int | None = None,
    until: int | None = None,
) -> tuple[str, list[Any]]:
    """The WHERE clause and parameters of a filtered audit read (column names are fixed strings)."""
    clauses: list[str] = []
    params: list[Any] = []
    if action:
        _match("action", action, clauses, params)
    if actor:
        _match("actor", actor, clauses, params)
    if target:
        _match("target", target, clauses, params)
    if since is not None:
        clauses.append("at >= ?")
        params.append(int(since))
    if until is not None:
        clauses.append("at < ?")
        params.append(int(until))
    needle = q.strip().lower()
    if needle:
        clauses.append(
            "(instr(lower(action), ?) > 0 OR instr(lower(coalesce(target, '')), ?) > 0 "
            "OR instr(lower(actor), ?) > 0 OR instr(lower(coalesce(reason, '')), ?) > 0 "
            "OR instr(lower(coalesce(request_id, '')), ?) > 0)"
        )
        params.extend([needle] * 5)
    return (" AND ".join(clauses) if clauses else "1"), params


def _list_row(row: sqlite3.Row | tuple[Any, ...]) -> dict[str, Any]:
    return {
        "id": int(row[0]),
        "at": int(row[1]),
        "actor": str(row[2]),
        "actor_ip": row[3],
        "action": str(row[4]),
        "target": row[5],
        "reason": row[6],
        "request_id": row[7],
        "before_preview": row[8],
        "after_preview": row[9],
        "has_before": bool(row[10]),
        "has_after": bool(row[11]),
    }


def audit_page(
    conn: sqlite3.Connection,
    *,
    action: str | None = None,
    actor: str | None = None,
    target: str | None = None,
    q: str = "",
    since: int | None = None,
    until: int | None = None,
    sort: str = "id",
    descending: bool = True,
    limit: int = 25,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """One page of audit rows (previews only) and the total matching rows."""
    column = AUDIT_SORTS.get(sort)
    if column is None:
        raise ValueError(f"cannot sort the audit log by {sort!r}")
    where, params = audit_where(action=action, actor=actor, target=target, q=q, since=since, until=until)
    total = int(conn.execute(f"SELECT count(*) FROM audit_log WHERE {where}", params).fetchone()[0])  # noqa: S608 (fixed clauses)
    direction = "DESC" if descending else "ASC"
    rows = conn.execute(
        "SELECT id, at, actor, actor_ip, action, target, reason, request_id, "  # noqa: S608 (allowlisted sort, fixed clauses)
        f"substr(before_json, 1, {PREVIEW_CHARS}), substr(after_json, 1, {PREVIEW_CHARS}), "
        "before_json IS NOT NULL, after_json IS NOT NULL "
        f"FROM audit_log WHERE {where} ORDER BY {column} {direction}, id DESC LIMIT ? OFFSET ?",
        (*params, max(1, min(int(limit), MAX_PAGE_ROWS)), max(0, min(int(offset), MAX_OFFSET))),
    ).fetchall()
    return [_list_row(row) for row in rows], total


def audit_entry(conn: sqlite3.Connection, audit_id: int) -> dict[str, Any] | None:
    """One audit row with `before` and `after` decoded (bounded to 64 KiB each when written), or None."""
    row = conn.execute(
        "SELECT id, at, actor, actor_ip, action, target, before_json, after_json, reason, request_id "
        "FROM audit_log WHERE id = ?",
        (int(audit_id),),
    ).fetchone()
    if row is None:
        return None
    return {
        "id": int(row[0]),
        "at": int(row[1]),
        "actor": str(row[2]),
        "actor_ip": row[3],
        "action": str(row[4]),
        "target": row[5],
        "before": _decode(row[6]),
        "after": _decode(row[7]),
        "reason": row[8],
        "request_id": row[9],
    }


def audit_facets(conn: sqlite3.Connection, limit: int = 200) -> dict[str, list[dict[str, Any]]]:
    """The actions and actors in the log with their counts, most frequent first (filter menus)."""
    bound = max(1, min(int(limit), MAX_FACETS))
    actions = conn.execute(
        "SELECT action, count(*) AS n FROM audit_log GROUP BY action ORDER BY n DESC, action LIMIT ?", (bound,)
    ).fetchall()
    actors = conn.execute(
        "SELECT actor, count(*) AS n FROM audit_log GROUP BY actor ORDER BY n DESC, actor LIMIT ?", (bound,)
    ).fetchall()
    return {
        "actions": [{"action": str(r[0]), "count": int(r[1])} for r in actions],
        "actors": [{"actor": str(r[0]), "count": int(r[1])} for r in actors],
    }


def settings_history_id(conn: sqlite3.Connection, key: str, at: int, actor: str) -> int | None:
    """The `settings_history` id written with a settings audit row (same key, second and actor), or None.

    `SettingsService` writes both rows in one transaction with the same `now`; when one admin changed the same key
    twice in one second, the newest of those rows is returned (its revert restores the value before it).
    """
    row = conn.execute(
        "SELECT max(id) FROM settings_history WHERE key = ? AND changed_at = ? AND changed_by = ?",
        (key, int(at), actor),
    ).fetchone()
    return None if row is None or row[0] is None else int(row[0])


__all__ = [
    "AUDIT_SORTS",
    "MAX_PAGE_ROWS",
    "PREVIEW_CHARS",
    "SETTING_ACTIONS",
    "audit_entry",
    "audit_facets",
    "audit_page",
    "audit_where",
    "settings_history_id",
]
