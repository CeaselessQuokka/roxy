"""Read models for the Protection page: per-check refusal counts, abuse event counters, attempts, spam detections.

What this is
    Functions over a metrics.db connection (run them inside `Database.read`, one snapshot each):
      * `CHECK_REASONS` and `check_hits(conn, window)`: how many requests each abuse check refused in a window
        (plan 10.9 "pipeline diagram with per-check hit counts for the selected range"), from the rollups.
      * `event_counts(conn, event_type, ...)`: sums of one `events` type grouped by its reason or detail keys, for
        the aggregated counters the abuse layer records (`ua_rule_hit`, `throttle_tier`, parity row 76; the
        blocked fingerprint counters, row 134; the spam detector events).
      * `refusal_attempts(conn, reason, ...)`: refusals of one reason grouped by path (the v1 "Blocked Endpoint
        Attempts", "Rate-Limited Attempts" and "Header-Blocked Attempts" tables, parity row 75), paged in SQL.
      * `spam_events(conn, ...)` and `would_ban_subjects(conn, ...)`: the spam detectors' decisions and dry-run
        results (plan 10.3), the input of the FILTER-COLLATERAL preview.

Why it exists
    The admin API stays thin (DESIGN.md section 13): it asks these functions and shapes the answer. Every number
    comes from the same rows the recorder writes, with one definition each (principle P6): a refusal is counted from
    the rollups (exact, never sampled), event counters weight aggregated rows by their `count`.

How it works
    - A refusal's rollup row carries its reason code; each check refuses with its own codes (`CHECK_REASONS`, pinned
      by a test against `abuse/checks`), so a GROUP BY reason gives the per-check counts without a new column.
    - Event rows are either individual (count 1) or summed per minute (`detail_json.count`), so every sum here is
      `sum(coalesce(json_extract(detail_json, '$.count'), 1))`.
    - Refusal events beyond the recorder's per-minute budget lose their per-occurrence detail (no path, no client
      hash); `refusal_attempts` groups those under their endpoint template and reports them as `unattributed`, so
      the client count is a lower bound and says so.
    - Only fixed column names reach the SQL text; detail keys are checked against a strict pattern first. Every
      query has a row bound (plan P9).

What to read next
    `roxy/metrics/queries.py` (`collect`, the rollup reader used here), `roxy/metrics/recorder.py` (what the events
    hold), then `roxy/admin/api/protection.py` (the routes).
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Mapping, Sequence
from typing import Any, Final

from roxy.metrics.queries import Window, collect

CHECK_REASONS: Final[dict[str, tuple[str, ...]]] = {
    "pause": ("paused",),
    "bans": ("banned", "deny_list"),
    "bypass": (),
    "flood": ("flood",),
    "spam": ("spam",),
    "throttle_all": ("throttle_all",),
    "throttle": ("throttle",),
    "place_limit": ("place_limit",),
    "challenge": ("challenge",),
    "bot_score": ("bot_score",),
    "user_agent_rule": ("user_agent_rule",),
    "ignored_path": ("ignored_path",),
    "unsafe_url": ("unsafe_url",),
    "not_roblox": ("not_roblox", "host_not_allowed"),
    "auth_smuggling": ("auth_smuggling",),
    "header_rule": ("header_rule",),
    "endpoint_blocked": ("endpoint_blocked",),
    "endpoint_rule": ("endpoint_rule",),
}
"""The reason codes each abuse check refuses with (`bypass` only marks a request, it never refuses)."""

UA_RULE_HIT_EVENT: Final = "ua_rule_hit"
TIER_EVENT: Final = "throttle_tier"
SPAM_EVENTS: Final[tuple[str, ...]] = ("spam_would_ban", "spam_ban", "spam_strike", "spam_tarpit", "spam_detected")
"""Event types the spam detectors record (`abuse/spam.py SpamDetectors._act`)."""
WOULD_BAN_EVENT: Final = "spam_would_ban"
REFUSAL_EVENT: Final = "refusal"

MAX_GROUPS: Final = 1000
"""Most groups one counter query returns (plan P9)."""
MAX_PAGE_ROWS: Final = 250
_DETAIL_KEY: Final = re.compile(r"[a-z_]{1,32}")
_COUNT: Final = "sum(coalesce(json_extract(detail_json, '$.count'), 1))"
ATTEMPT_SORTS: Final[dict[str, str]] = {
    "attempts": "attempts",
    "clients": "clients",
    "last_ms": "last_ms",
    "path": "path",
    "unattributed": "unattributed",
}


def _bounded(limit: int, cap: int = MAX_PAGE_ROWS) -> int:
    return max(1, min(int(limit), cap))


# ------------------------------------------------------------------------------------------ per-check counts


def check_hits(conn: sqlite3.Connection, window: Window) -> dict[str, Any]:
    """Requests, refusals by reason and per check in `window` (exact, from the rollups).

    `requests` counts every recorded proxy request (local OPTIONS answers included, they never reach the
    pipeline, so `evaluated` leaves them out).
    """
    totals = collect(conn, window, group_by="reason_code", bucketed=False)
    requests = 0
    options = 0
    for (_bucket, reason), item in totals.items():
        requests += item.values["requests"]
        if reason == "options_local":
            options += item.values["requests"]
    refused = collect(conn, window, filters={"outcome": "refused"}, group_by="reason_code", bucketed=False)
    by_reason = {str(reason): item.values["requests"] for (_bucket, reason), item in refused.items()}
    checks = {name: sum(by_reason.get(code, 0) for code in codes) for name, codes in CHECK_REASONS.items()}
    known = {code for codes in CHECK_REASONS.values() for code in codes}
    return {
        "requests": requests,
        "evaluated": requests - options,
        "refused": sum(by_reason.values()),
        "by_reason": by_reason,
        "by_check": checks,
        # Refusals no abuse check produced (the upstream guard's marker 400, an egress host refusal).
        "other_refusals": sum(n for code, n in by_reason.items() if code not in known),
    }


# ------------------------------------------------------------------------------------------- event counters


def event_counts(
    conn: sqlite3.Connection,
    event_type: str,
    start_ms: int,
    end_ms: int,
    *,
    keys: Sequence[str] = (),
    by_reason: bool = False,
    limit: int = MAX_GROUPS,
) -> list[dict[str, Any]]:
    """Sums of one event type in `[start_ms, end_ms)`, grouped by `reason` and/or detail keys, busiest first.

    Each row is `{reason?, <key>..., count, last_ms}`. Detail keys must be short snake_case names (they are put
    into the JSON path of the query).
    """
    for key in keys:
        if not _DETAIL_KEY.fullmatch(key):
            raise ValueError(f"not a detail key: {key!r}")
    names = (["reason"] if by_reason else []) + list(keys)
    exprs = (["reason_code"] if by_reason else []) + [f"json_extract(detail_json, '$.{key}')" for key in keys]
    select = ", ".join(f"{expr} AS g{i}" for i, expr in enumerate(exprs))
    group = ", ".join(f"g{i}" for i in range(len(exprs)))
    sql = (
        f"SELECT {select + ', ' if select else ''}{_COUNT} AS n, max(at_ms) AS last_ms FROM events "  # noqa: S608  # checked keys
        f"WHERE type = ? AND at_ms >= ? AND at_ms < ?{' GROUP BY ' + group if group else ''} "
        "ORDER BY n DESC LIMIT ?"
    )
    rows = conn.execute(sql, (event_type, int(start_ms), int(end_ms), _bounded(limit, MAX_GROUPS))).fetchall()
    out = []
    for row in rows:
        if row["n"] is None:
            continue  # an empty table answers one row of NULLs without a GROUP BY
        item: dict[str, Any] = {name: row[f"g{i}"] for i, name in enumerate(names)}
        item["count"] = int(row["n"])
        item["last_ms"] = int(row["last_ms"]) if row["last_ms"] is not None else None
        out.append(item)
    return out


def ua_rule_hits(conn: sqlite3.Connection, start_ms: int, end_ms: int) -> dict[str, dict[str, Any]]:
    """`{rule_id: {allowed, refused, last_ms}}` from the `ua_rule_hit` counter (parity row 76)."""
    out: dict[str, dict[str, Any]] = {}
    for row in event_counts(conn, UA_RULE_HIT_EVENT, start_ms, end_ms, keys=("rule_id", "result")):
        rule_id = str(row["rule_id"] or "")
        if not rule_id:
            continue
        entry = out.setdefault(rule_id, {"allowed": 0, "refused": 0, "last_ms": None})
        result = "refused" if row["result"] == "refused" else "allowed"
        entry[result] += row["count"]
        last = row["last_ms"]
        if last is not None and (entry["last_ms"] is None or last > entry["last_ms"]):
            entry["last_ms"] = last
    return out


def tier_hits(conn: sqlite3.Connection, start_ms: int, end_ms: int) -> dict[int, int]:
    """`{rung: new strikes that reached it}` from the `throttle_tier` counter (parity row 76)."""
    out: dict[int, int] = {}
    for row in event_counts(conn, TIER_EVENT, start_ms, end_ms, keys=("tier",)):
        try:
            tier = int(row["tier"])
        except (TypeError, ValueError):
            continue
        out[tier] = out.get(tier, 0) + row["count"]
    return out


# -------------------------------------------------------------------------------------------------- attempts


def refusal_attempts(
    conn: sqlite3.Connection,
    reason: str,
    start_ms: int,
    end_ms: int,
    *,
    search: str = "",
    sort: str = "attempts",
    descending: bool = True,
    limit: int = 25,
    offset: int = 0,
) -> dict[str, Any]:
    """Refusals with `reason` grouped by path (endpoint template when the detail was folded), paged in SQL.

    Rows: `path`, `template`, `attempts`, `clients` (distinct client hashes), `unattributed` (attempts recorded
    without a client hash: folded over the recorder's budget, or no `ip_hash_key`), `methods`, `last_ms`.
    """
    order = ATTEMPT_SORTS.get(sort)
    if order is None:
        raise ValueError(f"cannot sort attempts by {sort!r}")
    where = "type = ? AND reason_code = ? AND at_ms >= ? AND at_ms < ?"
    params: list[Any] = [REFUSAL_EVENT, reason, int(start_ms), int(end_ms)]
    path_expr = "coalesce(json_extract(detail_json, '$.path'), endpoint_template, '')"
    having = ""
    if search:
        having = " HAVING instr(lower(path), ?) > 0"
    grouped = (
        f"SELECT {path_expr} AS path, max(endpoint_template) AS template, {_COUNT} AS attempts, "  # noqa: S608  # constant clauses
        "count(DISTINCT ip_hash) AS clients, "
        f"sum(CASE WHEN ip_hash IS NULL THEN coalesce(json_extract(detail_json, '$.count'), 1) ELSE 0 END) "
        "AS unattributed, group_concat(DISTINCT json_extract(detail_json, '$.method')) AS methods, "
        f"max(at_ms) AS last_ms FROM events WHERE {where} GROUP BY path{having}"
    )
    group_params = [*params, search.lower()] if search else params
    total = int(conn.execute(f"SELECT count(*) FROM ({grouped})", group_params).fetchone()[0])  # noqa: S608
    direction = "DESC" if descending else "ASC"
    rows = conn.execute(
        f"SELECT * FROM ({grouped}) ORDER BY {order} {direction}, path LIMIT ? OFFSET ?",  # noqa: S608  # allowlisted
        (*group_params, _bounded(limit), max(0, int(offset))),
    ).fetchall()
    items = [
        {
            "path": row["path"],
            "template": row["template"],
            "attempts": int(row["attempts"] or 0),
            "clients": int(row["clients"] or 0),
            "unattributed": int(row["unattributed"] or 0),
            "methods": sorted(str(m) for m in str(row["methods"] or "").split(",") if m),
            "last_ms": int(row["last_ms"]) if row["last_ms"] is not None else None,
        }
        for row in rows
    ]
    return {"total": total, "rows": items}


# ----------------------------------------------------------------------------------------------- spam events


def _detail(raw: Any) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def spam_events(
    conn: sqlite3.Connection,
    start_ms: int,
    end_ms: int,
    *,
    kinds: Sequence[str] = SPAM_EVENTS,
    detector: str | None = None,
    limit: int = 25,
    offset: int = 0,
) -> dict[str, Any]:
    """The spam detectors' decisions, newest first: `{total, rows}` (each row the event's detail plus its kind)."""
    wanted = [kind for kind in kinds if kind in SPAM_EVENTS]
    if not wanted:
        return {"total": 0, "rows": []}
    marks = ", ".join("?" for _ in wanted)
    where = f"type IN ({marks}) AND at_ms >= ? AND at_ms < ?"
    params: list[Any] = [*wanted, int(start_ms), int(end_ms)]
    if detector:
        where += " AND json_extract(detail_json, '$.detector') = ?"
        params.append(detector)
    total = int(conn.execute(f"SELECT count(*) FROM events WHERE {where}", params).fetchone()[0])  # noqa: S608
    rows = conn.execute(
        f"SELECT id, at_ms, type, detail_json FROM events WHERE {where} ORDER BY id DESC LIMIT ? OFFSET ?",  # noqa: S608
        (*params, _bounded(limit), max(0, int(offset))),
    ).fetchall()
    items = []
    for row in rows:
        detail = _detail(row["detail_json"])
        items.append(
            {
                "id": int(row["id"]),
                "at_ms": int(row["at_ms"]),
                "kind": row["type"],
                "detector": detail.get("detector"),
                "subject": detail.get("subject"),
                "action": detail.get("action"),
                "configured_action": detail.get("configured_action"),
                "value": detail.get("value"),
                "threshold": detail.get("threshold"),
                "window_s": detail.get("window_s"),
                "game_server": bool(detail.get("game_server")),
                "ban_minutes": detail.get("ban_minutes"),
                "evidence": detail.get("evidence"),
            }
        )
    return {"total": total, "rows": items}


def spam_counts(conn: sqlite3.Connection, start_ms: int, end_ms: int) -> dict[str, dict[str, int]]:
    """`{detector: {event kind: count}}` in the window (the detector timelines' totals)."""
    out: dict[str, dict[str, int]] = {}
    marks = ", ".join("?" for _ in SPAM_EVENTS)
    rows = conn.execute(
        f"SELECT type, json_extract(detail_json, '$.detector') AS detector, {_COUNT} AS n FROM events "  # noqa: S608
        f"WHERE type IN ({marks}) AND at_ms >= ? AND at_ms < ? GROUP BY type, detector LIMIT ?",
        (*SPAM_EVENTS, int(start_ms), int(end_ms), MAX_GROUPS),
    ).fetchall()
    for row in rows:
        detector = str(row["detector"] or "unknown")
        entry = out.setdefault(detector, {})
        entry[str(row["type"])] = entry.get(str(row["type"]), 0) + int(row["n"] or 0)
    return out


def would_ban_subjects(
    conn: sqlite3.Connection, start_ms: int, end_ms: int, *, limit: int = MAX_GROUPS
) -> list[dict[str, Any]]:
    """Every subject a detector would have banned while in dry run (plan 10.3), most often first.

    Rows: `subject` (`ip:<client key>`), `detectors`, `count`, `first_ms`, `last_ms`, `game_server` (any of its
    events said the client looked like a trusted Roblox game server), `evidence` (the latest).
    """
    rows = conn.execute(
        "SELECT json_extract(detail_json, '$.subject') AS subject, "  # noqa: S608  # constant clauses only
        "group_concat(DISTINCT json_extract(detail_json, '$.detector')) AS detectors, "
        f"{_COUNT} AS n, min(at_ms) AS first_ms, max(at_ms) AS last_ms, "  # constant
        "max(coalesce(json_extract(detail_json, '$.game_server'), 0)) AS game_server, "
        "max(id) AS newest FROM events WHERE type = ? AND at_ms >= ? AND at_ms < ? "
        "GROUP BY subject ORDER BY n DESC, last_ms DESC LIMIT ?",
        (WOULD_BAN_EVENT, int(start_ms), int(end_ms), _bounded(limit, MAX_GROUPS)),
    ).fetchall()
    out = []
    for row in rows:
        if not row["subject"]:
            continue
        latest = conn.execute("SELECT detail_json FROM events WHERE id = ?", (row["newest"],)).fetchone()
        out.append(
            {
                "subject": str(row["subject"]),
                "detectors": sorted(str(d) for d in str(row["detectors"] or "").split(",") if d),
                "count": int(row["n"] or 0),
                "first_ms": int(row["first_ms"]),
                "last_ms": int(row["last_ms"]),
                "game_server": bool(row["game_server"]),
                "evidence": _detail(latest[0] if latest else None).get("evidence"),
            }
        )
    return out


def subject_events(
    conn: sqlite3.Connection, subject: str, *, kinds: Sequence[str] = SPAM_EVENTS, limit: int = 20
) -> list[dict[str, Any]]:
    """The newest detector events about one subject (`ip:<key>`), the evidence behind an automatic ban."""
    wanted = [kind for kind in kinds if kind in SPAM_EVENTS]
    if not wanted:
        return []
    marks = ", ".join("?" for _ in wanted)
    rows = conn.execute(
        f"SELECT id, at_ms, type, detail_json FROM events WHERE type IN ({marks}) "  # noqa: S608  # placeholders only
        "AND json_extract(detail_json, '$.subject') = ? ORDER BY id DESC LIMIT ?",
        (*wanted, subject, _bounded(limit, 100)),
    ).fetchall()
    return [{"at_ms": int(row["at_ms"]), "kind": row["type"], **_detail(row["detail_json"])} for row in rows]


def recent_live_rows(conn: sqlite3.Connection, *, limit: int = 40) -> list[dict[str, Any]]:
    """The newest live rows (kept 15 minutes), newest first: the request filter tester's samples (row 45)."""
    rows = conn.execute(
        "SELECT detail_json FROM events WHERE type = 'live' ORDER BY id DESC LIMIT ?", (_bounded(limit, 200),)
    ).fetchall()
    return [detail for detail in (_detail(row[0]) for row in rows) if detail]


def counts_by(rows: Sequence[Mapping[str, Any]], key: str) -> dict[str, int]:
    """Sum `count` per value of `key` over `event_counts` rows (small helper for the routes)."""
    out: dict[str, int] = {}
    for row in rows:
        name = str(row.get(key) or "")
        out[name] = out.get(name, 0) + int(row.get("count") or 0)
    return out


__all__ = [
    "ATTEMPT_SORTS",
    "CHECK_REASONS",
    "MAX_GROUPS",
    "SPAM_EVENTS",
    "TIER_EVENT",
    "UA_RULE_HIT_EVENT",
    "WOULD_BAN_EVENT",
    "check_hits",
    "counts_by",
    "event_counts",
    "recent_live_rows",
    "refusal_attempts",
    "spam_counts",
    "spam_events",
    "subject_events",
    "tier_hits",
    "ua_rule_hits",
    "would_ban_subjects",
]
