"""Read models over cache.db for the recommendation rules: refetch observations and stored key texts.

What this is
    `change_observations(conn, start, end)` sums the `change_observations` day rows (refetches and identical bodies
    per endpoint template, plan F10) that overlap a time window; `key_texts(conn, ids)` returns the stored key text
    and parameters of cache entries by id, which the dry-run simulator needs to re-key request samples under a
    proposed rule (plan 11.3: normalization flags and ignored parameters change the key).

Why it exists
    DESIGN.md section 13: read models live next to their data. The cache service writes these rows
    (`cache/store.py`), the insights engine reads them through this module only.

How it works
    `change_observations.day` is the UTC day start in Unix seconds, so a day row counts for a window when
    `day < end` and `day + 86400 > start` (the day overlaps the window). Both functions are plain reads over a
    connection; run them inside `Database.read`. Results are bounded (plan P9).

What to read next
    `roxy/cache/store.py` (`ObservationBuffer`, the writer), `roxy/insights/simulate.py` (the reader).
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from typing import Any, Final

DAY_S: Final = 86_400
MAX_TEMPLATES: Final = 5000
"""Most templates one observation read returns (the metric vocabulary holds 2,000 per worker)."""
MAX_KEY_IDS: Final = 50_000
"""Most entry ids one `key_texts` call looks up."""


def change_observations(conn: sqlite3.Connection, start: float, end: float) -> dict[str, tuple[int, int]]:
    """`{endpoint_template: (refetches, identical_bodies)}` over the day rows overlapping `[start, end)`."""
    rows = conn.execute(
        "SELECT endpoint_template, sum(refetches) AS r, sum(identical_bodies) AS i FROM change_observations "
        "WHERE day < ? AND day + ? > ? GROUP BY endpoint_template ORDER BY r DESC LIMIT ?",
        (int(end), DAY_S, int(start), MAX_TEMPLATES),
    ).fetchall()
    return {str(r[0]): (int(r[1] or 0), int(r[2] or 0)) for r in rows}


def key_texts(conn: sqlite3.Connection, ids: Iterable[str]) -> dict[str, dict[str, Any]]:
    """`{entry_id: {key, method, host, path, params, stripped}}` for the ids that are stored (handoff rows and
    markers are never asked for: their ids are not sample key ids)."""
    wanted = list(dict.fromkeys(str(i) for i in ids))[:MAX_KEY_IDS]
    out: dict[str, dict[str, Any]] = {}
    for first in range(0, len(wanted), 500):
        chunk = wanted[first : first + 500]
        marks = ", ".join("?" for _ in chunk)
        for row in conn.execute(
            f"SELECT id, key, method, host, path, params_json FROM entries WHERE id IN ({marks})",  # noqa: S608
            chunk,
        ):
            params: list[tuple[str, str]] = []
            stripped: list[str] = []
            try:
                decoded = json.loads(row[5]) if row[5] else {}
            except ValueError:
                decoded = {}
            if isinstance(decoded, dict):
                params = [(str(p[0]), str(p[1])) for p in decoded.get("params", []) if len(p) == 2]
                stripped = [str(name) for name in decoded.get("stripped", [])]
            out[str(row[0])] = {
                "key": str(row[1]),
                "method": str(row[2]),
                "host": str(row[3]),
                "path": str(row[4]),
                "params": params,
                "stripped": stripped,
            }
    return out


__all__ = ["DAY_S", "change_observations", "key_texts"]
