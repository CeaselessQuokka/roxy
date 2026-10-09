"""Read model: Roxy's own calls that carried the Roblox credential, by what started them (CRED-PROBE-COST).

What this is
    `credential_calls(conn, start, end)` sums the `internal_call` events of `[start, end)` that used the credential,
    grouped by trigger (`scheduled`, `health`, `admin`, or "" when the producer gave none) and purpose
    (`credential_probe`, `health`, ...), with the newest call time of each group.

Why it exists
    Plan 13.3: every credential call spends the one account's budget, and CRED-PROBE-COST fires when Roxy's own
    credential calls exceed `insight_cred_probe_cost_max_per_hour` in an hour. Its evidence is "probe sources
    (scheduled, health, admin), counts", which `metrics/queries.py internal_calls` (grouped by purpose only, every
    egress together) does not answer. DESIGN.md section 13: read models live next to their data.

How it works
    `metrics/recorder.py record_internal_call` writes one `internal_call` event per call (purpose in `reason_code`,
    `trigger` and, for a credential call, `egress: credential` in the detail); beyond the per-type event budget it
    sums calls per minute with a `count` in the detail, keeping `trigger` and `egress`, so the totals here stay
    exact. One grouped SQL read; bounded by `MAX_GROUPS` (plan P9). Run inside `Database.read`.

What to read next
    `roxy/egress/credential.py` (the probes), `roxy/insights/rules/credential.py` (CRED-PROBE-COST).
"""

from __future__ import annotations

import sqlite3
from typing import Any, Final

CREDENTIAL_EGRESS: Final = "credential"
MAX_GROUPS: Final = 200
"""Most (trigger, purpose) groups one read returns (purposes and triggers are a small fixed vocabulary)."""


def credential_calls(conn: sqlite3.Connection, start: int, end: int) -> list[dict[str, Any]]:
    """`[{trigger, purpose, calls, failed, last_ms}]` of credential `internal_call` events in `[start, end)`."""
    rows = conn.execute(
        "SELECT coalesce(json_extract(detail_json, '$.trigger'), '') AS trigger, reason_code AS purpose, "
        "sum(coalesce(json_extract(detail_json, '$.count'), 1)) AS calls, "
        "sum(CASE WHEN json_extract(detail_json, '$.ok') THEN 0 "
        "ELSE coalesce(json_extract(detail_json, '$.count'), 1) END) AS failed, max(at_ms) AS last_ms "
        "FROM events WHERE type = 'internal_call' AND at_ms >= ? AND at_ms < ? "
        "AND json_extract(detail_json, '$.egress') = ? "
        "GROUP BY trigger, purpose ORDER BY calls DESC, trigger, purpose LIMIT ?",
        (int(start) * 1000, int(end) * 1000, CREDENTIAL_EGRESS, MAX_GROUPS),
    ).fetchall()
    return [
        {
            "trigger": str(row["trigger"] or ""),
            "purpose": str(row["purpose"] or ""),
            "calls": int(row["calls"] or 0),
            "failed": int(row["failed"] or 0),
            "last_ms": int(row["last_ms"] or 0),
        }
        for row in rows
    ]


__all__ = ["CREDENTIAL_EGRESS", "credential_calls"]
