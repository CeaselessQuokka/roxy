"""Read model: is there CRED-UNUSED evidence for one credential allowlist row? (plan 6.2, 6.9, 11.5)

What this is
    `cred_unused_evidence(conn, recommendation_id=..., row_id=..., pattern=...)` reads one recommendation from
    metrics.db and answers its evidence summary when it is an active CRED-UNUSED recommendation about that
    allowlist row, else None.

Why it exists
    Plan 6.2 and 6.9: an allowlist row's `identical_anonymous` flag (which lets Roxy fetch that endpoint
    anonymously instead of with the credential) "can only be set from CRED-UNUSED evidence": identical answers on
    both paths, measured by the recommendation engine. The admin API sets the flag only when the request names
    such a recommendation, so a flag that weakens the D1 confinement never rests on an admin's guess.

How it works
    One SELECT by primary key. The recommendation must have `rule_id` CRED-UNUSED, be open or snoozed (an active
    finding, plan 11.1), and one of its proposed changes must name the row (`match.id` or `match.pattern` on table
    `credential_allowlist`, the shape `insights/models.py ProposedChange` stores). The answer carries the
    recommendation's evidence numbers (sample size and metrics) for the audit row.

What to read next
    `roxy/insights/models.py` (the payload shape), `roxy/admin/api/credential_allowlist.py` (who asks).
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any, Final

RULE_ID: Final = "CRED-UNUSED"
ACTIVE_STATES: Final = frozenset({"open", "snoozed"})
TABLE: Final = "credential_allowlist"


def cred_unused_evidence(
    conn: sqlite3.Connection, *, recommendation_id: str, row_id: int, pattern: str
) -> dict[str, Any] | None:
    """The evidence summary of an active CRED-UNUSED recommendation about allowlist row `row_id`, or None."""
    row = conn.execute(
        "SELECT id, rule_id, state, payload_json, created_at, updated_at FROM recommendations WHERE id = ?",
        (recommendation_id[:80],),
    ).fetchone()
    if row is None or row["rule_id"] != RULE_ID or row["state"] not in ACTIVE_STATES:
        return None
    try:
        payload = json.loads(row["payload_json"] or "{}")
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    named = False
    for change in payload.get("changes") or []:
        if not isinstance(change, dict) or change.get("table") != TABLE:
            continue
        raw_match = change.get("match")
        match: dict[str, Any] = raw_match if isinstance(raw_match, dict) else {}
        if str(match.get("id", "")) == str(row_id) or (match.get("pattern") and match.get("pattern") == pattern):
            named = True
            break
    if not named:
        return None
    raw_evidence = payload.get("evidence")
    evidence: dict[str, Any] = raw_evidence if isinstance(raw_evidence, dict) else {}
    metrics = [m for m in (evidence.get("metrics") or []) if isinstance(m, dict)][:20]
    return {
        "recommendation_id": str(row["id"]),
        "state": str(row["state"]),
        "created_at": int(row["created_at"]),
        "updated_at": int(row["updated_at"]),
        "sample_size": int(evidence.get("sample_size") or 0),
        "metrics": [{"name": str(m.get("name")), "value": m.get("value"), "unit": m.get("unit", "")} for m in metrics],
    }


__all__ = ["ACTIVE_STATES", "RULE_ID", "cred_unused_evidence"]
