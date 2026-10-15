"""Read model for the Protection > Bans card: bans with countdowns and evidence, filters, and reset previews.

What this is
    Functions over a control.db connection (run them inside `Database.read`, or inside a write transaction for the
    reset): `ban_page` (filtered, sorted and paged in SQL), `ban_view` (one stored row as the dashboard shows it:
    active or expired, seconds left, who created it and why), `reset_scope` (the WHERE clause of a plan 6.8 "bans
    only" reset: all, automatic only, expired only, or one detector) and `reset_preview` (how many rows that reset
    would delete, before anything is deleted).

Why it exists
    Plan 10.9 asks for "active bans with countdowns and evidence"; plan 6.8 for resets that show a preview first.
    Bans can number in the thousands (detectors ban automatically, `MAX_ACTIVE_BANS` 10,000, and expired rows are
    kept 30 days for the escalation count), so the table is paged in SQL instead of loading every row.

How it works
    - Active means `expires_at IS NULL OR expires_at > now`; a permanent ban has no countdown (`expires_in_s` None).
    - Origin: `created_by` `auto:<detector>` is automatic (`spam_rate`, `spam_probe`, ..., `throttle_ladder`);
      anything else (an admin, the CLI, the v1 import) is manual.
    - Evidence is what the ban row stores (`reason_code`, `reason_text`, hits and the last hit): a detector writes
      its measurement into `reason_text` (for example "SPAM-PROBE: 6 in 600 s (threshold 5)"); the route adds the
      detector events about the subject from metrics.db.
    - Every filter value is checked against a fixed list before it reaches SQL; sorting uses an allowlist.

What to read next
    `roxy/abuse/bans.py` (how bans are created and escalated), `roxy/rules/service.py` (create, extend, unban), then
    `roxy/admin/api/protection.py`.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from typing import Any, Final

from roxy.abuse.spam import DETECTORS

BAN_STATES: Final[tuple[str, ...]] = ("active", "expired", "all")
BAN_ORIGINS: Final[tuple[str, ...]] = ("any", "manual", "auto")
SUBJECT_TYPES: Final[tuple[str, ...]] = ("ip", "cidr", "place", "ua_hash")
AUTO_DETECTORS: Final[tuple[str, ...]] = (*(f"spam_{d}" for d in DETECTORS), "throttle_ladder")
"""Every `auto:<detector>` value `created_by` can hold (spam detectors and ladder ban rungs)."""
RESET_SCOPES: Final[tuple[str, ...]] = ("all", "auto", "expired", "detector")
BAN_SORTS: Final[dict[str, str]] = {
    "created_at": "created_at",
    "expires_at": "coalesce(expires_at, 9223372036854775807)",
    "hits": "hits",
    "last_hit_at": "coalesce(last_hit_at, 0)",
    "subject": "subject",
    "id": "id",
}
MAX_ROWS: Final = 250
_COLUMNS: Final = (
    "id, subject_type, subject, reason_code, reason_text, created_at, expires_at, created_by, hits, last_hit_at"
)


def detector_of(created_by: str | None) -> str | None:
    """The detector of an automatic ban (`auto:spam_rate` gives `spam_rate`), None for a manual one."""
    text = str(created_by or "")
    return text[len("auto:") :] if text.startswith("auto:") else None


def ban_view(row: Mapping[str, Any], now: int) -> dict[str, Any]:
    """One ban as the dashboard shows it: state, countdown, origin and evidence."""
    expires_at = row.get("expires_at")
    active = expires_at is None or int(expires_at) > now
    detector = detector_of(row.get("created_by"))
    return {
        "id": int(row["id"]),
        "subject_type": row["subject_type"],
        "subject": row["subject"],
        "active": active,
        "permanent": expires_at is None,
        "created_at": int(row["created_at"]),
        "expires_at": None if expires_at is None else int(expires_at),
        "expires_in_s": None if expires_at is None else max(0, int(expires_at) - now),
        "created_by": row.get("created_by") or "",
        "origin": "auto" if detector else "manual",
        "detector": detector,
        "hits": int(row.get("hits") or 0),
        "last_hit_at": row.get("last_hit_at"),
        "evidence": {
            "reason_code": row.get("reason_code") or "",
            "reason_text": row.get("reason_text") or "",
        },
    }


def _filters(
    *, now: int, state: str, origin: str, detector: str | None, subject_type: str | None, search: str
) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if state not in BAN_STATES:
        raise ValueError(f"state must be one of {', '.join(BAN_STATES)}")
    if origin not in BAN_ORIGINS:
        raise ValueError(f"origin must be one of {', '.join(BAN_ORIGINS)}")
    if state == "active":
        clauses.append("(expires_at IS NULL OR expires_at > ?)")
        params.append(now)
    elif state == "expired":
        clauses.append("expires_at IS NOT NULL AND expires_at <= ?")
        params.append(now)
    if origin == "auto":
        clauses.append("created_by LIKE 'auto:%'")
    elif origin == "manual":
        clauses.append("created_by NOT LIKE 'auto:%'")
    if detector:
        if detector not in AUTO_DETECTORS:
            raise ValueError(f"detector must be one of {', '.join(AUTO_DETECTORS)}")
        clauses.append("created_by = ?")
        params.append(f"auto:{detector}")
    if subject_type:
        if subject_type not in SUBJECT_TYPES:
            raise ValueError(f"subject_type must be one of {', '.join(SUBJECT_TYPES)}")
        clauses.append("subject_type = ?")
        params.append(subject_type)
    if search:
        clauses.append("(instr(lower(subject), ?) > 0 OR instr(lower(coalesce(reason_text, '')), ?) > 0)")
        params += [search.lower(), search.lower()]
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


def ban_page(
    conn: sqlite3.Connection,
    *,
    now: int,
    state: str = "active",
    origin: str = "any",
    detector: str | None = None,
    subject_type: str | None = None,
    search: str = "",
    sort: str = "created_at",
    descending: bool = True,
    limit: int = 25,
    offset: int = 0,
) -> dict[str, Any]:
    """`{total, rows, active_total}`: one page of bans as `ban_view` rows (ValueError for a bad filter or sort)."""
    order = BAN_SORTS.get(sort)
    if order is None:
        raise ValueError(f"cannot sort bans by {sort!r}")
    where, params = _filters(
        now=now, state=state, origin=origin, detector=detector, subject_type=subject_type, search=search
    )
    total = int(conn.execute(f"SELECT count(*) FROM bans{where}", params).fetchone()[0])  # noqa: S608  # checked
    rows = conn.execute(
        f"SELECT {_COLUMNS} FROM bans{where} ORDER BY {order} {'DESC' if descending else 'ASC'}, id DESC "  # noqa: S608
        "LIMIT ? OFFSET ?",
        (*params, max(1, min(int(limit), MAX_ROWS)), max(0, int(offset))),
    ).fetchall()
    active_total = int(
        conn.execute("SELECT count(*) FROM bans WHERE expires_at IS NULL OR expires_at > ?", (now,)).fetchone()[0]
    )
    return {"total": total, "active_total": active_total, "rows": [ban_view(dict(row), now) for row in rows]}


def ban_row(conn: sqlite3.Connection, ban_id: int) -> dict[str, Any] | None:
    """One stored ban by id (None when absent)."""
    row = conn.execute(f"SELECT {_COLUMNS} FROM bans WHERE id = ?", (int(ban_id),)).fetchone()  # noqa: S608  # constant
    return None if row is None else dict(row)


def reset_scope(scope: str, *, now: int, detector: str | None = None) -> tuple[str, tuple[Any, ...]]:
    """The WHERE clause and parameters of a plan 6.8 bans reset (ValueError for an unknown scope or detector)."""
    if scope == "all":
        return "", ()
    if scope == "auto":
        return " WHERE created_by LIKE 'auto:%'", ()
    if scope == "expired":
        return " WHERE expires_at IS NOT NULL AND expires_at <= ?", (now,)
    if scope == "detector":
        if detector not in AUTO_DETECTORS:
            raise ValueError(f"detector must be one of {', '.join(AUTO_DETECTORS)}")
        return " WHERE created_by = ?", (f"auto:{detector}",)
    raise ValueError(f"scope must be one of {', '.join(RESET_SCOPES)}")


def reset_preview(conn: sqlite3.Connection, scope: str, *, now: int, detector: str | None = None) -> dict[str, Any]:
    """What a bans reset would delete: total rows, active rows among them, and counts per subject type."""
    where, params = reset_scope(scope, now=now, detector=detector)
    rows = conn.execute(
        "SELECT subject_type, count(*) AS n, "  # noqa: S608  # `where` comes from reset_scope's constants
        "sum(CASE WHEN expires_at IS NULL OR expires_at > ? THEN 1 ELSE 0 END) AS active "
        f"FROM bans{where} GROUP BY subject_type",
        (now, *params),
    ).fetchall()
    by_type = {str(row["subject_type"]): int(row["n"]) for row in rows}
    return {
        "scope": scope,
        "detector": detector,
        "rows": sum(by_type.values()),
        "active": sum(int(row["active"] or 0) for row in rows),
        "by_subject_type": by_type,
    }


__all__ = [
    "AUTO_DETECTORS",
    "BAN_ORIGINS",
    "BAN_SORTS",
    "BAN_STATES",
    "RESET_SCOPES",
    "SUBJECT_TYPES",
    "ban_page",
    "ban_row",
    "ban_view",
    "detector_of",
    "reset_preview",
    "reset_scope",
]
