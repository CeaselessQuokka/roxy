"""Read model of the error log for the System > Errors view: searchable pages and one signature in detail.

What this is
    `errors_page(conn, ...)` returns one page of the `errors` table (one row per error signature: count, first and
    last seen, source, last detail, `module:line`), sorted and searched on the server, with the total.
    `error_detail(conn, signature)` returns one signature with its redacted traceback (the last 20 frames, plan
    6.2) and, when the history table exists, its occurrences per hour over the last day.

Why it exists
    Plan 14.1 (System page: "errors view with signatures and tracebacks") and parity rows 16 and 72. The existing
    `queries.errors_table` sorts by two keys and has no search or detail; the System page needs both, and the
    table belongs to the metrics package (DESIGN.md section 13).

How it works
    Parameterized SELECTs with an allowlisted sort column; a search is `instr` over the signature, the source, the
    last detail and `module:line`. Text was redacted when it was recorded (`metrics/recorder.py`); it passes
    `core.redact.redact_text` once more here (defense in depth: a secret registered after the error was recorded
    is still removed). The hourly occurrences come from `error_minute` (metrics schema 2) and are skipped when that
    table does not exist yet.

What to read next
    `roxy/metrics/recorder.py` (`record_error`), `roxy/admin/api/system.py` (the routes).
"""

from __future__ import annotations

import sqlite3
from typing import Any, Final

from roxy.core.redact import redact_text

ERROR_SORTS: Final[dict[str, str]] = {
    "last_seen": "last_seen",
    "first_seen": "first_seen",
    "count": "count",
    "signature": "signature",
    "source": "source",
}
MAX_PAGE_ROWS: Final = 250
MAX_OFFSET: Final = 1_000_000
MAX_DETAIL_CHARS: Final = 2000
MAX_TRACEBACK_CHARS: Final = 32_768
"""Bounds of one answer (plan P9); the recorder already keeps at most 20 frames."""


def _clean(text: Any, limit: int) -> str | None:
    if text is None:
        return None
    return redact_text(str(text)[: limit * 2])[:limit]


def _row(row: sqlite3.Row | tuple[Any, ...]) -> dict[str, Any]:
    return {
        "signature": _clean(row[0], 300),
        "count": int(row[1] or 0),
        "first_seen": int(row[2] or 0),
        "last_seen": int(row[3] or 0),
        "source": row[4],
        "last_detail": _clean(row[5], MAX_DETAIL_CHARS),
        "module_line": _clean(row[6], 200),
        "has_traceback": bool(row[7]),
    }


def errors_page(
    conn: sqlite3.Connection,
    *,
    q: str = "",
    source: str | None = None,
    sort: str = "last_seen",
    descending: bool = True,
    limit: int = 25,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """One page of error signatures and the total matching rows."""
    column = ERROR_SORTS.get(sort)
    if column is None:
        raise ValueError(f"cannot sort errors by {sort!r}")
    clauses: list[str] = []
    params: list[Any] = []
    if source:
        clauses.append("source = ?")
        params.append(source)
    needle = q.strip().lower()
    if needle:
        clauses.append(
            "(instr(lower(signature), ?) > 0 OR instr(lower(coalesce(source, '')), ?) > 0 "
            "OR instr(lower(coalesce(last_detail, '')), ?) > 0 OR instr(lower(coalesce(module_line, '')), ?) > 0)"
        )
        params.extend([needle] * 4)
    where = " AND ".join(clauses) if clauses else "1"
    total = int(conn.execute(f"SELECT count(*) FROM errors WHERE {where}", params).fetchone()[0])  # noqa: S608 (fixed clauses)
    direction = "DESC" if descending else "ASC"
    rows = conn.execute(
        "SELECT signature, count, first_seen, last_seen, source, last_detail, module_line, "  # noqa: S608 (allowlisted)
        f"traceback_redacted IS NOT NULL FROM errors WHERE {where} ORDER BY {column} {direction}, signature "
        "LIMIT ? OFFSET ?",
        (*params, max(1, min(int(limit), MAX_PAGE_ROWS)), max(0, min(int(offset), MAX_OFFSET))),
    ).fetchall()
    return [_row(row) for row in rows], total


def _has_table(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)).fetchone()
    return row is not None


def error_detail(conn: sqlite3.Connection, signature: str, *, now: float | None = None) -> dict[str, Any] | None:
    """One signature with its redacted traceback and (schema 2) its hourly occurrences over the last 24 h."""
    row = conn.execute(
        "SELECT signature, count, first_seen, last_seen, source, last_detail, module_line, traceback_redacted "
        "FROM errors WHERE signature = ?",
        (signature,),
    ).fetchone()
    if row is None:
        return None
    out = _row(row)
    out["traceback"] = _clean(row[7], MAX_TRACEBACK_CHARS)
    hourly: list[list[int]] | None = None
    if now is not None and _has_table(conn, "error_minute"):
        start = int(now) - 86_400
        start -= start % 3600
        hourly = [
            [int(r[0]), int(r[1])]
            for r in conn.execute(
                "SELECT bucket_start - bucket_start % 3600 AS hour, sum(count) FROM error_minute "
                "WHERE signature = ? AND bucket_start >= ? GROUP BY hour ORDER BY hour",
                (signature, start),
            )
        ]
    out["hourly"] = hourly
    return out


def error_sources(conn: sqlite3.Connection, limit: int = 50) -> list[str]:
    """Distinct sources (the source filter of the errors view)."""
    rows = conn.execute(
        "SELECT DISTINCT source FROM errors WHERE source IS NOT NULL ORDER BY source LIMIT ?",
        (max(1, min(int(limit), 500)),),
    ).fetchall()
    return [str(r[0]) for r in rows]


__all__ = ["ERROR_SORTS", "MAX_PAGE_ROWS", "error_detail", "error_sources", "errors_page"]
