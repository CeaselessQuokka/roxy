"""Read model of the credential's metadata for the recommendation rules (never the secret).

What this is
    `credential_meta(conn)` returns the `credential_meta` row (fingerprints, status, last probe) as a dict with
    `last_probe_result` decoded, or None when no credential was ever set. It never selects from `credential_store`.

Why it exists
    CRED-EXPIRING, CRED-UNUSED and CRED-PROBE-COST look at the credential's status and probe results (plan 11.5).
    Only `egress/credential.py` may read the secret (plan C2 item 1); metadata is public to the admin, and this
    module reads exactly the columns that hold no secret, next to the module that writes them (DESIGN.md 13).

How it works
    One SELECT of named columns on control.db inside the caller's read transaction (`Database.read`).

What to read next
    `roxy/egress/credential.py` (the writer of these columns).
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

_COLUMNS = (
    "fingerprint",
    "masked",
    "account_id_fingerprint",
    "set_at",
    "set_by",
    "status",
    "status_at",
    "last_probe_at",
    "last_probe_result",
)


def credential_meta(conn: sqlite3.Connection) -> dict[str, Any] | None:
    """The metadata row of the one credential slot (plan C1), or None."""
    row = conn.execute(f"SELECT {', '.join(_COLUMNS)} FROM credential_meta WHERE id = 1").fetchone()  # noqa: S608
    if row is None:
        return None
    out = dict(zip(_COLUMNS, tuple(row), strict=True))
    raw = out.get("last_probe_result")
    if isinstance(raw, str) and raw:
        try:
            out["last_probe_result"] = json.loads(raw)
        except ValueError:
            out["last_probe_result"] = {"result": raw}
    return out


__all__ = ["credential_meta"]
