"""Read model of recent configuration changes: settings history and rule edits, for the recommendation rules.

What this is
    `recent_changes(conn, since, until, limit)` returns the settings changes (`settings_history`) and the rule,
    ban and access list edits (`audit_log` actions `rule.*` and `throttle_tiers.*`) made in a time window, oldest
    first, each as one dict with `kind`, `at`, `target`, `before`, `after`, `source` and the history or audit id.
    `service_state(conn, key)` reads one `service_state` value.

Why it exists
    Plan 11.1: rules see "recent config changes" (SYS-CHANGE-REGRESSION compares metrics before and after one;
    an applied recommendation's watch window starts at one). DESIGN.md section 13 puts read models next to their
    data; control.db is owned by the config and rules packages, so the read lives here.

How it works
    Two indexed range reads in the caller's read transaction (run inside `Database.read`). Values are decoded from
    their JSON columns; secret targets were stored as `{fingerprint, masked}` only (plan 6.2), so nothing here can
    expose a secret.

What to read next
    `roxy/config/settings_service.py` (the writer of settings history), `roxy/config/audit.py` (audit rows).
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any, Final

MAX_CHANGES: Final = 5000


def _decode(text: str | None) -> Any:
    if text is None:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return text


def recent_changes(conn: sqlite3.Connection, since: float, until: float, limit: int = 500) -> list[dict[str, Any]]:
    """Settings and rule changes with `since <= at < until`, oldest first (at most `limit`, plan P9)."""
    bound = max(1, min(int(limit), MAX_CHANGES))
    out: list[dict[str, Any]] = []
    for row in conn.execute(
        "SELECT id, key, old_json, new_json, changed_at, changed_by, reason, source FROM settings_history "
        "WHERE changed_at >= ? AND changed_at < ? ORDER BY changed_at, id LIMIT ?",
        (int(since), int(until), bound),
    ):
        out.append(
            {
                "kind": "setting",
                "id": int(row[0]),
                "target": f"setting:{row[1]}",
                "key": str(row[1]),
                "before": _decode(row[2]),
                "after": _decode(row[3]),
                "at": int(row[4]),
                "by": row[5],
                "reason": row[6],
                "source": row[7],
            }
        )
    for row in conn.execute(
        "SELECT id, at, actor, action, target, before_json, after_json, reason FROM audit_log "
        "WHERE at >= ? AND at < ? AND (action LIKE 'rule.%' OR action LIKE 'throttle_tiers.%') "
        "ORDER BY at, id LIMIT ?",
        (int(since), int(until), bound),
    ):
        out.append(
            {
                "kind": "rule",
                "id": int(row[0]),
                "target": row[4],
                "action": row[3],
                "before": _decode(row[5]),
                "after": _decode(row[6]),
                "at": int(row[1]),
                "by": row[2],
                "reason": row[7],
                "source": None,
            }
        )
    out.sort(key=lambda item: (item["at"], item["kind"], item["id"]))
    return out[:bound]


def service_state(conn: sqlite3.Connection, key: str) -> Any:
    """The decoded `service_state` value of `key`, or None."""
    row = conn.execute("SELECT value_json FROM service_state WHERE key = ?", (key,)).fetchone()
    return None if row is None else _decode(row[0])


__all__ = ["recent_changes", "service_state"]
