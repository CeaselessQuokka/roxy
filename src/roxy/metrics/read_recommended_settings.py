"""Read model: which settings have an open recommendation (the settings editor's "has open recommendation" filter).

What this is
    `open_setting_recommendations(conn)` maps a setting key to the open (or snoozed) recommendations whose proposed
    changes touch it: `{key: [{id, rule_id, severity, state}, ...]}`.

Why it exists
    Plan 15.2: the editor filters by "has open recommendation", and each row links to the recommendation that
    would change it. Recommendations live in metrics.db (`recommendations`, plan 6.2), so the read lives in the
    metrics package (DESIGN.md section 13: read models next to their data).

How it works
    One bounded read of the active recommendations (newest first, `MAX_ROWS`), then each `payload_json` is parsed
    and its `changes` list scanned for kinds that name a setting (`setting`, and `host_add`, which edits the
    `allowed_roblox_hosts` setting; plan 11.2). A payload that does not parse is skipped, never fatal. Nothing here
    imports the insights package, so the editor keeps working while the engine is being changed.

What to read next
    `roxy/insights/models.py` (the payload shape), `roxy/admin/api/settings.py` (the filter).
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any, Final

ACTIVE_STATES: Final[tuple[str, ...]] = ("open", "snoozed")
"""Recommendation states that count as open (plan 11.1: the engine keeps updating them)."""

SETTING_CHANGE_KINDS: Final[frozenset[str]] = frozenset({"setting", "host_add"})
"""Change kinds whose `key` names a setting (plan 11.2)."""

MAX_ROWS: Final = 2000
"""Active recommendations read at most (plan P9); far above what the engine keeps open at once."""

MAX_PER_KEY: Final = 20


def open_setting_recommendations(conn: sqlite3.Connection, *, limit: int = MAX_ROWS) -> dict[str, list[dict[str, Any]]]:
    """Setting key -> the active recommendations that propose changing it (newest first, at most 20 per key)."""
    rows = conn.execute(
        "SELECT id, rule_id, severity, state, payload_json FROM recommendations WHERE state IN (?, ?) "
        "ORDER BY updated_at DESC LIMIT ?",
        (*ACTIVE_STATES, max(1, min(int(limit), MAX_ROWS))),
    ).fetchall()
    out: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        try:
            payload = json.loads(row[4] or "{}")
        except ValueError:
            continue
        changes = payload.get("changes") if isinstance(payload, dict) else None
        if not isinstance(changes, list):
            continue
        seen: set[str] = set()
        for change in changes:
            if not isinstance(change, dict) or change.get("kind") not in SETTING_CHANGE_KINDS:
                continue
            key = change.get("key") or ("allowed_roblox_hosts" if change.get("kind") == "host_add" else None)
            if not isinstance(key, str) or not key or key in seen:
                continue
            seen.add(key)
            bucket = out.setdefault(key, [])
            if len(bucket) < MAX_PER_KEY:
                bucket.append({"id": str(row[0]), "rule_id": str(row[1]), "severity": row[2], "state": row[3]})
    return out


__all__ = ["ACTIVE_STATES", "MAX_ROWS", "SETTING_CHANGE_KINDS", "open_setting_recommendations"]
