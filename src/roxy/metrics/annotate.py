"""Chart annotations: the one writer of the metrics.db `annotations` table (plan 6.8, 14.2).

What this is
    `insert_annotation(conn, at, kind, label, audit_id, until=None, tables=None)` writes one chart marker (a config
    change, a reset, a deploy, an incident) linked to the audit row of the action that caused it.
    `ANNOTATION_KINDS` is the closed set of kinds the table accepts. `has_reset_tables` and `reset_tables_of` read
    back what a reset marker says it deleted. `update_annotation` and `delete_annotation` let a data reset settle
    the marker it wrote before deleting anything (finding mpjobs-4).

Why it exists
    Three admin areas wrote their own `INSERT INTO annotations` (data resets, the protection state resets, the
    upstream state reset), each with its own bounds. One writer keeps the label bound, the kind check and the
    meaning of `until` in one place. `reset` is the only kind that changes what the dashboard says about numbers:
    a KPI tile whose window overlaps a reset shows a partial-data notice (`metrics/queries.py reset_annotations`),
    so a reset that deleted no counters must use `config_change` instead (P6, honest numbers). Plan 6.8 asks for
    that notice only on numbers of the reset's own family (finding parity-12): a reset of the login history must
    not blank the request tile's delta. So a reset marker can name what it deleted.

How it works
    The function runs inside the caller's metrics.db write transaction (a pure function over a connection, like
    `storage/leases.py`). `until` is the end of the time range a ranged data reset deleted (plan 6.8 "reset this
    range"): the marker sits at the range start (`at`), and a window that overlaps `[at, until)` gets the notice,
    even one strictly inside the deleted range. A reset without a range has `until` NULL and marks one instant.
    `until` arrived with the expand migration `metrics/0004_annotation_range.sql`; the previous release ignores it.
    `tables` (stored as JSON in the column `RESET_TABLES_COLUMN`) lists what a reset deleted: `<db>.<table>` for
    deleted rows, `<db>.<table>#latency` for rollup rows whose latency histograms were emptied, and
    `<db>.<table>#cache_state` for rollup rows whose cache lookup state was cleared. The column comes with the
    expand migration `metrics/0006_annotation_scope.sql`; on a file without it (the previous release's) the list is
    not stored and readers treat the marker as touching every number (`queries.reset_touches`), which is the safe
    reading. At most `MAX_TABLES` names are kept, each cut
    to `MAX_TABLE_CHARS`. (The module is not named `annotations`: every module here starts with
    `from __future__ import annotations`, which binds that name.)

What to read next
    `roxy/metrics/queries.py` (`reset_annotations`, `reset_touches`, `chart_annotations`), `roxy/admin/api/common.py`
    (`reset_notices`, `annotation_entries`), `roxy/admin/api/data.py` (the ranged data resets).
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from typing import Any, Final

ANNOTATION_KINDS: Final = frozenset({"config_change", "reset", "deploy", "incident"})
"""The kinds the table's CHECK constraint accepts (plan 6.2)."""

MAX_LABEL_CHARS: Final = 200
"""A marker's label is a short title; longer text is cut (the audit row holds the details)."""

RESET_TABLES_COLUMN: Final = "reset_tables"
"""The `annotations` column holding a reset's deleted tables as a JSON list (added by an expand migration)."""
MAX_TABLES: Final = 64
"""Most table names one marker keeps (a full statistics reset names about 40)."""
MAX_TABLE_CHARS: Final = 80
"""Longest table name kept (`<db>.<table>#latency` is far shorter)."""


def has_reset_tables(conn: sqlite3.Connection) -> bool:
    """Whether this metrics.db has the `reset_tables` column yet (one cheap PRAGMA)."""
    return any(str(row[1]) == RESET_TABLES_COLUMN for row in conn.execute("PRAGMA table_info(annotations)"))


def _tables_json(tables: Iterable[str]) -> str:
    names = sorted({str(name)[:MAX_TABLE_CHARS] for name in tables if str(name)})
    return json.dumps(names[:MAX_TABLES], separators=(",", ":"))


def reset_tables_of(raw: Any) -> list[str] | None:
    """The stored list of a marker (None when the marker does not say what it deleted, or the value is damaged)."""
    if raw is None:
        return None
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return None
    if not isinstance(value, list):
        return None
    return [str(item)[:MAX_TABLE_CHARS] for item in value[:MAX_TABLES]]


def insert_annotation(
    conn: sqlite3.Connection,
    at: int,
    kind: str,
    label: str,
    audit_id: int | None,
    *,
    until: int | None = None,
    tables: Iterable[str] | None = None,
) -> int:
    """Write one chart marker and return its id. `until` (a ranged reset's end) must not be before `at`.

    `tables` (resets only): what the reset deleted, `<db>.<table>` or `<db>.<table>#latency`; kept when the file
    has the column, otherwise left out (the marker then reads as touching every number).
    """
    if kind not in ANNOTATION_KINDS:
        raise ValueError(f"unknown annotation kind {kind!r}")
    if until is not None and int(until) < int(at):
        raise ValueError("an annotation range must not end before it starts")
    values: list[Any] = [int(at), kind, str(label)[:MAX_LABEL_CHARS], audit_id, None if until is None else int(until)]
    columns = "at, kind, label, audit_id, until"
    if tables is not None and has_reset_tables(conn):
        columns += f", {RESET_TABLES_COLUMN}"
        values.append(_tables_json(tables))
    marks = ", ".join("?" for _ in values)
    cursor = conn.execute(f"INSERT INTO annotations ({columns}) VALUES ({marks})", values)  # noqa: S608 (fixed names)
    return int(cursor.lastrowid or 0)


def update_annotation(
    conn: sqlite3.Connection,
    annotation_id: int,
    *,
    audit_id: int | None = None,
    label: str | None = None,
    tables: Iterable[str] | None = None,
) -> bool:
    """Point a marker at another audit row and/or give it another label (only the fields given change).

    A data reset writes its marker before it deletes anything, linked to its intent row, then links it to the row
    that records how it ended (`data.reset.done`, or `data.reset.failed` with an "incomplete" label; finding
    mpjobs-4). `tables` replaces what the marker says the reset deleted (kept when the file has the column).
    Returns whether the marker exists.
    """
    sets: list[str] = []
    values: list[Any] = []
    if audit_id is not None:
        sets.append("audit_id = ?")
        values.append(int(audit_id))
    if label is not None:
        sets.append("label = ?")
        values.append(str(label)[:MAX_LABEL_CHARS])
    if tables is not None and has_reset_tables(conn):
        sets.append(f"{RESET_TABLES_COLUMN} = ?")
        values.append(_tables_json(tables))
    if not sets:
        return conn.execute("SELECT 1 FROM annotations WHERE id = ?", (int(annotation_id),)).fetchone() is not None
    cursor = conn.execute(
        f"UPDATE annotations SET {', '.join(sets)} WHERE id = ?",  # noqa: S608 (fixed column names)
        (*values, int(annotation_id)),
    )
    return cursor.rowcount > 0


def delete_annotation(conn: sqlite3.Connection, annotation_id: int) -> bool:
    """Remove one marker (a data reset that failed before it changed anything leaves none behind)."""
    return conn.execute("DELETE FROM annotations WHERE id = ?", (int(annotation_id),)).rowcount > 0


__all__ = [
    "ANNOTATION_KINDS",
    "MAX_LABEL_CHARS",
    "MAX_TABLES",
    "MAX_TABLE_CHARS",
    "RESET_TABLES_COLUMN",
    "delete_annotation",
    "has_reset_tables",
    "insert_annotation",
    "reset_tables_of",
    "update_annotation",
]
