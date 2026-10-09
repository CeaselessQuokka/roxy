"""Chart annotations: the one writer of the metrics.db `annotations` table (plan 6.8, 14.2).

What this is
    `insert_annotation(conn, at, kind, label, audit_id, until=None)` writes one chart marker (a config change, a
    reset, a deploy, an incident) linked to the audit row of the action that caused it. `ANNOTATION_KINDS` is the
    closed set of kinds the table accepts.

Why it exists
    Three admin areas wrote their own `INSERT INTO annotations` (data resets, the protection state resets, the
    upstream state reset), each with its own bounds. One writer keeps the label bound, the kind check and the
    meaning of `until` in one place. `reset` is the only kind that changes what the dashboard says about numbers:
    a KPI tile whose window overlaps a reset shows a partial-data notice (`metrics/queries.py reset_annotations`),
    so a reset that deleted no counters must use `config_change` instead (P6, honest numbers).

How it works
    The function runs inside the caller's metrics.db write transaction (a pure function over a connection, like
    `storage/leases.py`). `until` is the end of the time range a ranged data reset deleted (plan 6.8 "reset this
    range"): the marker sits at the range start (`at`), and a window that overlaps `[at, until)` gets the notice,
    even one strictly inside the deleted range. A reset without a range has `until` NULL and marks one instant.
    `until` arrived with the expand migration `metrics/0004_annotation_range.sql`; the previous release ignores it.
    (The module is not named `annotations`: every module here starts with `from __future__ import annotations`,
    which binds that name.)

What to read next
    `roxy/metrics/queries.py` (`reset_annotations`, `chart_annotations`), `roxy/admin/api/common.py`
    (`reset_notices`, `annotation_entries`), `roxy/admin/api/data.py` (the ranged data resets).
"""

from __future__ import annotations

import sqlite3
from typing import Final

ANNOTATION_KINDS: Final = frozenset({"config_change", "reset", "deploy", "incident"})
"""The kinds the table's CHECK constraint accepts (plan 6.2)."""

MAX_LABEL_CHARS: Final = 200
"""A marker's label is a short title; longer text is cut (the audit row holds the details)."""


def insert_annotation(
    conn: sqlite3.Connection,
    at: int,
    kind: str,
    label: str,
    audit_id: int | None,
    *,
    until: int | None = None,
) -> int:
    """Write one chart marker and return its id. `until` (a ranged reset's end) must not be before `at`."""
    if kind not in ANNOTATION_KINDS:
        raise ValueError(f"unknown annotation kind {kind!r}")
    if until is not None and int(until) < int(at):
        raise ValueError("an annotation range must not end before it starts")
    cursor = conn.execute(
        "INSERT INTO annotations (at, kind, label, audit_id, until) VALUES (?, ?, ?, ?, ?)",
        (int(at), kind, str(label)[:MAX_LABEL_CHARS], audit_id, None if until is None else int(until)),
    )
    return int(cursor.lastrowid or 0)


__all__ = ["ANNOTATION_KINDS", "MAX_LABEL_CHARS", "insert_annotation"]
