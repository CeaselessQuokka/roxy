"""Read model: one egress's metered usage over a time span, split into requests, request, response and overhead bytes.

What this is
    `usage_split(conn, egress, start, end=None)` sums metrics.db `egress_usage` for one egress from `start` (and
    before `end` when given) into `requests`, `req_bytes`, `resp_bytes`, `overhead_bytes` and their `total_bytes`.

Why it exists
    EGR-CALIBRATE (plan 8.4, 8.6, 11.5) compares Roxy's metered rotator bytes for the billing cycle with the figure
    the admin read off the provider's dashboard, and needs the parts: in estimate metering mode `overhead_bytes` is
    `rotator_tls_overhead_bytes` times the new connections, which is the number the recommendation recalibrates.
    `egress/rotator.py usage_since` answers only the total. DESIGN.md section 13: read models live next to their
    data; the egress package owns the accounting these rows come from (`egress/accounting.py`).

How it works
    The same "finest rows that still exist" rule as `usage_since`: minute rows where they exist; hour rows only for
    whole hours before the oldest minute row; day rows only for whole days before the oldest hour (or minute) row.
    The leader compacts and prunes oldest first, so every byte is counted once (to within the one partly covered
    hour or day at a boundary, an estimate anyway, plan 8.3). With `end`, rows starting at or after `end` are left
    out. Three indexed range reads; run inside `Database.read` on the metrics database.

What to read next
    `roxy/egress/rotator.py` (`usage_since`, the budget), `roxy/insights/rules/egress.py` (EGR-CALIBRATE).
"""

from __future__ import annotations

import sqlite3
from typing import Final

COLUMNS: Final[tuple[str, ...]] = ("requests", "req_bytes", "resp_bytes", "overhead_bytes")
_LEVELS: Final[tuple[tuple[str, int], ...]] = (("minute", 60), ("hour", 3600), ("day", 86_400))


def usage_split(conn: sqlite3.Connection, egress: str, start: int, end: int | None = None) -> dict[str, int]:
    """`{requests, req_bytes, resp_bytes, overhead_bytes, total_bytes}` of `egress` in `[start, end)` (seconds)."""
    totals = dict.fromkeys(COLUMNS, 0)
    boundary: int | None = None
    for granularity, span in _LEVELS:
        sql = (
            "SELECT coalesce(sum(requests), 0), coalesce(sum(req_bytes), 0), coalesce(sum(resp_bytes), 0), "
            "coalesce(sum(overhead_bytes), 0), min(bucket_start) FROM egress_usage "
            "WHERE egress = ? AND granularity = ? AND bucket_start >= ?"
        )
        params: list[int | str] = [egress, granularity, int(start)]
        if end is not None:
            sql += " AND bucket_start < ?"
            params.append(int(end))
        if boundary is not None:
            sql += " AND bucket_start + ? <= ?"
            params += [span, boundary]
        row = conn.execute(sql, params).fetchone()
        for index, name in enumerate(COLUMNS):
            totals[name] += int(row[index] or 0)
        if row[4] is not None:
            boundary = int(row[4]) if boundary is None else min(boundary, int(row[4]))
    totals["total_bytes"] = totals["req_bytes"] + totals["resp_bytes"] + totals["overhead_bytes"]
    return totals


__all__ = ["COLUMNS", "usage_split"]
