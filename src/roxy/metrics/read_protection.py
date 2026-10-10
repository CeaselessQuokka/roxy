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
      * `watch_activity(conn, keys, since=, now=)`: v1's throttle-all watch columns (requests and refusals since
        the state began, rates, busiest endpoint, last seen) for one page of watched clients (parity row 135).
      * `rule_hit_columns`, `rule_hit_totals`, `rule_hit_points`: per-rule hits in a range, the lifetime count and
        last hit, per-table sums, and one rule's hits over time (plan 10.9; `metrics/read_producers.py` and
        `metrics/read_history.py` hold the raw reads).

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

from roxy.metrics import read_history, read_producers
from roxy.metrics.queries import Window, bucket_starts, collect, trailing_rate
from roxy.metrics.read_clients import client_pieces, latest_user_agents
from roxy.metrics.rollups import bucket_floor, zone

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
ATTEMPT_RULE_TABLES: Final[frozenset[str]] = frozenset({"rules_endpoint_block", "rules_endpoint_limit", "rules_header"})
"""The rule tables an attempts tab names the refusing rows of (`abuse/checks/base.py TABLE_*`, the keys of a refusal
event's `detail.rules`)."""
MAX_ATTEMPT_RULE_IDS: Final = 8
"""Most refusing rule ids listed per attempts row (one path is normally refused by one rule)."""


def _bounded(limit: int, cap: int = MAX_PAGE_ROWS) -> int:
    return max(1, min(int(limit), cap))


# ------------------------------------------------------------------------------------------------ rule hits


def rule_hit_columns(conn: sqlite3.Connection, table: str, start: int, end: int) -> dict[str, dict[str, Any]]:
    """`{rule key: {hits, hits_total, last_hit_at}}` for one rule table (plan 10.9 per-rule hit counts, FILTER-REMOVE
    "hit history"): hits in `[start, end)` from `rule_hit_minute` (schema 5), and the lifetime count and the last
    hit (epoch seconds) from `rule_hits`. A hit is a request the rule's row matched, whatever the verdict."""
    out: dict[str, dict[str, Any]] = {}
    for (_table, key), hits in read_producers.rule_hit_counts(conn, start, end, table).items():
        out.setdefault(key, {"hits": 0, "hits_total": 0, "last_hit_at": None})["hits"] = hits
    for (_table, key), item in read_history.rule_hits(conn, table).items():
        entry = out.setdefault(key, {"hits": 0, "hits_total": 0, "last_hit_at": None})
        entry["hits_total"] = int(item.get("hits") or 0)
        entry["last_hit_at"] = item.get("last_hit_at")
    return out


def rule_hit_totals(conn: sqlite3.Connection, start: int, end: int) -> dict[str, int]:
    """Rule hits in `[start, end)` summed per rule table (the pipeline diagram's per-table hit counts)."""
    out: dict[str, int] = {}
    for (table, _key), hits in read_producers.rule_hit_counts(conn, start, end).items():
        out[table] = out.get(table, 0) + hits
    return dict(sorted(out.items()))


def rule_hit_points(conn: sqlite3.Connection, table: str, key: str, window: Window) -> list[list[int]]:
    """One rule row's hits per bucket of `window` (`[[bucket start, hits], ...]`, zeros included), folded from its
    minutes in `rule_hit_minute` into the window's granularity (local days and longer in its zone)."""
    starts = bucket_starts(window)
    index = {start: i for i, start in enumerate(starts)}
    values = [0] * len(starts)
    zi = zone(window.tz)
    for minute, hits in read_producers.rule_hit_series(conn, table, key, window.start, window.end):
        slot = index.get(bucket_floor(minute, window.granularity, zi))
        if slot is not None:
            values[slot] += hits
    return [[start, value] for start, value in zip(starts, values, strict=True)]


# ------------------------------------------------------------------------------------- throttle-all watch


def watch_activity(conn: sqlite3.Connection, keys: Sequence[str], *, since: float, now: float) -> dict[str, Any]:
    """v1's throttle-all watch columns (parity row 135, finding parity-4) for one page of watched client keys.

    Per key: `requests` and `refused` since the throttle-all "since" marker, `rate1`, `rate5` and `rate60` (the
    trailing-window rates of the Clients tables), `top_endpoint` (the busiest endpoint, each minute's busiest
    weighted by that minute's requests, as `read_clients.client_range`) and `last_seen_ms` (exact while the
    client's Live rows are kept, else the start of its newest minute). Client activity is per address: a key that
    is an IPv6 network (`/` in it) has no activity row and is left out (unknown, P6). Counting starts at the minute
    the marker falls in, because client rows are per minute (the same rule as the drops-since banner). At most
    `MAX_PAGE_ROWS` keys (one page).
    """
    wanted = [str(key) for key in dict.fromkeys(keys) if key and "/" not in str(key)][:MAX_PAGE_ROWS]
    if not wanted:
        return {}
    start = int(since) - int(since) % 60
    end = int(now) - int(now) % 60 + 60
    if end <= start:
        return {}
    # The minutes up to the first whole hour, then whole hours where the leader compacted them, then minutes.
    edge = min(end, start if start % 3600 == 0 else start - start % 3600 + 3600)
    pieces: list[tuple[str, int, int]] = [("client_minute", start, edge)] if edge > start else []
    if end > edge:
        pieces += client_pieces(conn, Window(edge, end, "minute"))
    marks = ", ".join("?" for _ in wanted)
    acc: dict[str, dict[str, Any]] = {}
    for table, lo, hi in pieces:
        rows = conn.execute(
            f"SELECT client_key, bucket_start, requests, refused, top_endpoint FROM {table} "  # noqa: S608 (fixed names)
            f"WHERE client_type = 'ip' AND client_key IN ({marks}) AND bucket_start >= ? AND bucket_start < ?",
            (*wanted, lo, hi),
        ).fetchall()
        for row in rows:
            item = acc.setdefault(str(row["client_key"]), {"requests": 0, "refused": 0, "last": 0, "endpoints": {}})
            count = int(row["requests"] or 0)
            item["requests"] += count
            item["refused"] += int(row["refused"] or 0)
            if count:
                item["last"] = max(item["last"], int(row["bucket_start"]))
            if row["top_endpoint"]:
                name = str(row["top_endpoint"])
                item["endpoints"][name] = item["endpoints"].get(name, 0) + count
    rates: dict[str, dict[int, int]] = {}
    for row in conn.execute(
        f"SELECT client_key, bucket_start, requests FROM client_minute WHERE client_type = 'ip' "  # noqa: S608
        f"AND client_key IN ({marks}) AND bucket_start >= ?",
        (*wanted, int(now) - 3660),
    ):
        rates.setdefault(str(row["client_key"]), {})[int(row["bucket_start"])] = int(row["requests"] or 0)
    live = latest_user_agents(conn, wanted)
    out: dict[str, Any] = {}
    for key, item in acc.items():
        endpoints: dict[str, int] = item["endpoints"]
        minutes = rates.get(key, {})
        seen = live.get(key)
        last_ms = item["last"] * 1000 if item["last"] else None
        if seen is not None and (last_ms is None or int(seen["at_ms"]) >= last_ms):
            last_ms = int(seen["at_ms"])
        out[key] = {
            "requests": item["requests"],
            "refused": item["refused"],
            "rate1": trailing_rate(minutes, now, 60),
            "rate5": trailing_rate(minutes, now, 300),
            "rate60": trailing_rate(minutes, now, 3600),
            "top_endpoint": max(endpoints.items(), key=lambda kv: (kv[1], kv[0]))[0] if endpoints else None,
            "last_seen_ms": last_ms,
        }
    return out


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
    rule_table: str | None = None,
) -> dict[str, Any]:
    """Refusals with `reason` grouped by path (endpoint template when the detail was folded), paged in SQL.

    Rows: `path`, `template`, `attempts`, `clients` (distinct client hashes), `unattributed` (attempts recorded
    without a client hash: folded over the recorder's budget, or no `ip_hash_key`), `methods`, `last_ms`, and with
    `rule_table` (one of `ATTEMPT_RULE_TABLES`) `rule_ids`: the row ids of that table the refusals recorded as the
    rule that refused them (`detail.rules`, written since review round 3; at most `MAX_ATTEMPT_RULE_IDS`, older
    refusals carry none).
    """
    order = ATTEMPT_SORTS.get(sort)
    if order is None:
        raise ValueError(f"cannot sort attempts by {sort!r}")
    if rule_table is not None and rule_table not in ATTEMPT_RULE_TABLES:
        raise ValueError(f"no attempts tab reads rule table {rule_table!r}")
    where = "type = ? AND reason_code = ? AND at_ms >= ? AND at_ms < ?"
    params: list[Any] = [REFUSAL_EVENT, reason, int(start_ms), int(end_ms)]
    path_expr = "coalesce(json_extract(detail_json, '$.path'), endpoint_template, '')"
    having = ""
    if search:
        having = " HAVING instr(lower(path), ?) > 0"
    # The json path is a bound parameter built from an allowlisted table name (never caller text).
    rule_ids = "group_concat(DISTINCT json_extract(detail_json, ?))" if rule_table is not None else "NULL"
    grouped = (
        f"SELECT {path_expr} AS path, max(endpoint_template) AS template, {_COUNT} AS attempts, "  # noqa: S608  # constant clauses
        "count(DISTINCT ip_hash) AS clients, "
        f"sum(CASE WHEN ip_hash IS NULL THEN coalesce(json_extract(detail_json, '$.count'), 1) ELSE 0 END) "
        "AS unattributed, group_concat(DISTINCT json_extract(detail_json, '$.method')) AS methods, "
        f"{rule_ids} AS rule_ids, max(at_ms) AS last_ms FROM events WHERE {where} GROUP BY path{having}"
    )
    select_params: list[Any] = [f"$.rules.{rule_table}"] if rule_table is not None else []
    group_params = [*select_params, *params, search.lower()] if search else [*select_params, *params]
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
            "rule_ids": sorted({str(i) for i in str(row["rule_ids"] or "").split(",") if i})[:MAX_ATTEMPT_RULE_IDS],
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
    "rule_hit_columns",
    "rule_hit_points",
    "rule_hit_totals",
    "spam_counts",
    "spam_events",
    "subject_events",
    "tier_hits",
    "ua_rule_hits",
    "watch_activity",
    "would_ban_subjects",
]
