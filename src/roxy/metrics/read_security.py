"""Read models for the Security page: request fingerprints, blocked fingerprints and CSP reports.

What this is
    Functions over a metrics.db connection (run them inside `Database.read`):
      * `header_names(conn, ...)`: the header name table (parity row 79): count, first and last seen, how many
        distinct values are stored, the share of requests that carried a new value, and whether the values are
        ignored or look unbounded (v1's "high cardinality" badge).
      * `header_values(conn, name, ...)`: one header's stored values, most frequent first (the v1 drill-down).
      * `user_agents(conn, ...)`: the User-Agent table.
      * `blocked_fingerprints(conn, ...)` and `blocked_rows(conn, ...)`: header names and User-Agents of requests a
        request filter refused (row 134, the "Blocked" tab), from the aggregated `blocked_header` and
        `blocked_user_agent` events; `blocked_rows` is the same as one exportable table.
      * `csp_reports(conn, ...)`: Content-Security-Policy violation reports (plan 9.2), grouped by what was blocked.
      * The per-header clears of v1's fingerprint tables (`.remake/v1notes/dashboard.md` 4.21, finding parity-11):
        `clear_header_values` ("Clear values": the values go, the header and its count stay and it is still
        recorded), `remove_header` ("Remove": the row and its values go), `remove_blocked_header` (the Blocked tab's
        "Remove"), with `header_counts` and `blocked_header_count` for the audit row written first. These few
        deletes of the tables this module reads sit here so the Security API stays thin.

Why it exists
    The fingerprint tables are written by the recorder (`metrics/fingerprints.py`) and the CSP reports by
    `public/csp_report.py`; this module is the one place that reads them for the dashboard, paged on the server
    (row 89) so a table with thousands of User-Agents never ships whole.

How it works
    - Sorting and searching happen in SQL over allowlisted column names; every query is bounded by a page size of
      at most 250 rows and an offset.
    - Stored values are already scrubbed and sensitive ones hashed at write time (`fp:<hash>`), so nothing here can
      reveal a secret; a header name that looked secret-shaped is stored as `fp:<hash>` too.
    - v1's badge rules are kept: values "not recorded" for an ignored header, "high cardinality" when at least 90%
      of the requests carried a value seen for the first time and the header was seen at least 100 times.

What to read next
    `roxy/metrics/fingerprints.py` (how rows are written and capped), `roxy/public/csp_report.py`, then
    `roxy/admin/api/security.py`.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Collection
from typing import Any, Final

from roxy.metrics.read_protection import event_counts

MAX_ROWS: Final = 250
HIGH_CARDINALITY_RATIO: Final = 0.9
HIGH_CARDINALITY_MIN_COUNT: Final = 100
"""v1 `dashboard.js`: the "high cardinality" badge at a 90% unique ratio once a header was seen 100 times."""
BLOCKED_HEADER_EVENT: Final = "blocked_header"
BLOCKED_UA_EVENT: Final = "blocked_user_agent"
CSP_EVENT: Final = "csp_report"

HEADER_SORTS: Final[dict[str, str]] = {
    "name": "h.name",
    "count": "h.count",
    "first_seen": "h.first_seen",
    "last_seen": "h.last_seen",
    "value_count": "value_count",
}
VALUE_SORTS: Final[dict[str, str]] = {"count": "count", "last_seen": "last_seen", "value": "value"}
UA_SORTS: Final[dict[str, str]] = {
    "count": "count",
    "first_seen": "first_seen",
    "last_seen": "last_seen",
    "user_agent": "user_agent",
}
CSP_SORTS: Final[dict[str, str]] = {"count": "n", "last_ms": "last_ms"}
_COUNT: Final = "sum(coalesce(json_extract(detail_json, '$.count'), 1))"


def _page(limit: int, offset: int) -> tuple[int, int]:
    return max(1, min(int(limit), MAX_ROWS)), max(0, int(offset))


def _order(sorts: dict[str, str], sort: str, descending: bool) -> str:
    column = sorts.get(sort)
    if column is None:
        raise ValueError(f"cannot sort by {sort!r}")
    return f"{column} {'DESC' if descending else 'ASC'}"


def header_names(
    conn: sqlite3.Connection,
    *,
    ignored: Collection[str] = (),
    search: str = "",
    sort: str = "count",
    descending: bool = True,
    limit: int = 25,
    offset: int = 0,
) -> dict[str, Any]:
    """The header name table with value statistics (see the module docstring)."""
    order = _order(HEADER_SORTS, sort, descending)
    size, skip = _page(limit, offset)
    where, params = ("WHERE instr(h.name, ?) > 0", [search.lower()]) if search else ("", [])
    total = int(conn.execute(f"SELECT count(*) FROM fingerprint_headers h {where}", params).fetchone()[0])  # noqa: S608
    rows = conn.execute(
        "SELECT h.name AS name, h.count AS count, h.first_seen AS first_seen, h.last_seen AS last_seen, "  # noqa: S608  # allowlisted order
        "(SELECT count(*) FROM fingerprint_values v WHERE v.name = h.name) AS value_count, "
        "(SELECT coalesce(sum(v.count), 0) FROM fingerprint_values v WHERE v.name = h.name) AS value_hits "
        f"FROM fingerprint_headers h {where} ORDER BY {order}, h.name LIMIT ? OFFSET ?",
        (*params, size, skip),
    ).fetchall()
    ignored_set = {name.lower() for name in ignored}
    items = []
    for row in rows:
        count = int(row["count"] or 0)
        distinct = int(row["value_count"] or 0)
        hits = int(row["value_hits"] or 0)
        ratio = round(distinct / hits, 4) if hits else None
        items.append(
            {
                "name": row["name"],
                "count": count,
                "first_seen": int(row["first_seen"]),
                "last_seen": int(row["last_seen"]),
                "value_count": distinct,
                "unique_ratio": ratio,
                "values_ignored": str(row["name"]).lower() in ignored_set,
                "high_cardinality": bool(
                    ratio is not None and ratio >= HIGH_CARDINALITY_RATIO and count >= HIGH_CARDINALITY_MIN_COUNT
                ),
            }
        )
    return {"total": total, "rows": items}


def header_values(
    conn: sqlite3.Connection,
    name: str,
    *,
    sort: str = "count",
    descending: bool = True,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """One header's stored values (already scrubbed or hashed), most frequent first by default."""
    order = _order(VALUE_SORTS, sort, descending)
    size, skip = _page(limit, offset)
    key = name.lower()
    total = int(conn.execute("SELECT count(*) FROM fingerprint_values WHERE name = ?", (key,)).fetchone()[0])
    rows = conn.execute(
        f"SELECT value, count, first_seen, last_seen FROM fingerprint_values WHERE name = ? "  # noqa: S608 (allowlisted)
        f"ORDER BY {order}, value_hash LIMIT ? OFFSET ?",
        (key, size, skip),
    ).fetchall()
    return {
        "total": total,
        "rows": [
            {
                "value": row["value"],
                "count": int(row["count"]),
                "first_seen": int(row["first_seen"]),
                "last_seen": int(row["last_seen"]),
            }
            for row in rows
        ],
    }


def user_agents(
    conn: sqlite3.Connection,
    *,
    search: str = "",
    sort: str = "count",
    descending: bool = True,
    limit: int = 25,
    offset: int = 0,
) -> dict[str, Any]:
    """The User-Agent table (stored text is scrubbed at write time), paged in SQL."""
    order = _order(UA_SORTS, sort, descending)
    size, skip = _page(limit, offset)
    where, params = ("WHERE instr(lower(user_agent), ?) > 0", [search.lower()]) if search else ("", [])
    total = int(conn.execute(f"SELECT count(*) FROM fingerprint_user_agents {where}", params).fetchone()[0])  # noqa: S608
    rows = conn.execute(
        f"SELECT user_agent, count, first_seen, last_seen FROM fingerprint_user_agents {where} "  # noqa: S608
        f"ORDER BY {order}, ua_hash LIMIT ? OFFSET ?",
        (*params, size, skip),
    ).fetchall()
    return {
        "total": total,
        "rows": [
            {
                "user_agent": row["user_agent"],
                "count": int(row["count"]),
                "first_seen": int(row["first_seen"]),
                "last_seen": int(row["last_seen"]),
            }
            for row in rows
        ],
    }


def blocked_fingerprints(
    conn: sqlite3.Connection, start_ms: int, end_ms: int, *, limit: int = MAX_ROWS
) -> dict[str, list[dict[str, Any]]]:
    """Header names and User-Agents of requests a request filter refused (row 134), busiest first."""
    headers = event_counts(conn, BLOCKED_HEADER_EVENT, start_ms, end_ms, by_reason=True, limit=limit)
    agents = event_counts(conn, BLOCKED_UA_EVENT, start_ms, end_ms, keys=("user_agent",), limit=limit)
    return {
        "headers": [{"name": row["reason"], "count": row["count"], "last_ms": row["last_ms"]} for row in headers],
        "user_agents": [
            {"user_agent": row["user_agent"], "count": row["count"], "last_ms": row["last_ms"]} for row in agents
        ],
    }


def blocked_rows(conn: sqlite3.Connection, start_ms: int, end_ms: int) -> list[dict[str, Any]]:
    """The Blocked tab as one table (v1 `exportBlockedFingerprints`: `Type,Header,Value,Count,LastSeen`): a row per
    blocked header name (`kind` `header`, `name`) and per blocked User-Agent (`kind` `user_agent`, `user_agent`),
    with `count` and `last_ms`; at most `MAX_ROWS` of each kind. Blocked requests keep no header values."""
    found = blocked_fingerprints(conn, start_ms, end_ms)
    rows: list[dict[str, Any]] = [
        {"kind": "header", "name": item["name"], "user_agent": None, "count": item["count"], "last_ms": item["last_ms"]}
        for item in found["headers"]
    ]
    rows += [
        {
            "kind": "user_agent",
            "name": None,
            "user_agent": item["user_agent"],
            "count": item["count"],
            "last_ms": item["last_ms"],
        }
        for item in found["user_agents"]
    ]
    return rows


# --------------------------------------------------------------------------------- per-header clears (v1 4.21)


def header_counts(conn: sqlite3.Connection, name: str) -> dict[str, int]:
    """`{headers, values}`: whether one (lowercased) header name has a row, and how many values it stores."""
    key = name.lower()
    headers = int(conn.execute("SELECT count(*) FROM fingerprint_headers WHERE name = ?", (key,)).fetchone()[0])
    values = int(conn.execute("SELECT count(*) FROM fingerprint_values WHERE name = ?", (key,)).fetchone()[0])
    return {"headers": headers, "values": values}


def clear_header_values(conn: sqlite3.Connection, name: str) -> int:
    """v1 "Clear values": delete one header's stored values, keep its row and count (it is still recorded)."""
    return int(conn.execute("DELETE FROM fingerprint_values WHERE name = ?", (name.lower(),)).rowcount)


def remove_header(conn: sqlite3.Connection, name: str) -> dict[str, int]:
    """v1 "Remove": delete one header's row and its stored values (a later request carrying it adds it again)."""
    key = name.lower()
    values = int(conn.execute("DELETE FROM fingerprint_values WHERE name = ?", (key,)).rowcount)
    headers = int(conn.execute("DELETE FROM fingerprint_headers WHERE name = ?", (key,)).rowcount)
    return {"headers": headers, "values": values}


def blocked_header_count(conn: sqlite3.Connection, name: str) -> int:
    """Blocked requests counted for one header name, over every kept `blocked_header` row."""
    row = conn.execute(
        f"SELECT {_COUNT} FROM events WHERE type = ? AND reason_code = ?",  # noqa: S608 (fixed text)
        (BLOCKED_HEADER_EVENT, name.lower()),
    ).fetchone()
    return int(row[0] or 0) if row else 0


def remove_blocked_header(conn: sqlite3.Connection, name: str) -> int:
    """v1 "Remove" on the Blocked tab: delete one header name's `blocked_header` rows; returns the rows deleted."""
    return int(
        conn.execute(
            "DELETE FROM events WHERE type = ? AND reason_code = ?", (BLOCKED_HEADER_EVENT, name.lower())
        ).rowcount
    )


def csp_reports(
    conn: sqlite3.Connection,
    start_ms: int,
    end_ms: int,
    *,
    directive: str = "",
    sort: str = "count",
    descending: bool = True,
    limit: int = 25,
    offset: int = 0,
) -> dict[str, Any]:
    """CSP violation reports grouped by (directive, blocked resource, page, source file), paged in SQL."""
    order = _order(CSP_SORTS, sort, descending)
    size, skip = _page(limit, offset)
    where = "type = ? AND at_ms >= ? AND at_ms < ?"
    params: list[Any] = [CSP_EVENT, int(start_ms), int(end_ms)]
    if directive:
        where += " AND json_extract(detail_json, '$.directive') = ?"
        params.append(directive)
    grouped = (
        "SELECT json_extract(detail_json, '$.directive') AS directive, "  # noqa: S608  # constant clauses
        "json_extract(detail_json, '$.blocked') AS blocked, json_extract(detail_json, '$.document') AS document, "
        "json_extract(detail_json, '$.source') AS source, json_extract(detail_json, '$.disposition') AS disposition, "
        f"{_COUNT} AS n, max(at_ms) AS last_ms FROM events WHERE {where} "
        "GROUP BY directive, blocked, document, source, disposition"
    )
    total = int(conn.execute(f"SELECT count(*) FROM ({grouped})", params).fetchone()[0])  # noqa: S608
    rows = conn.execute(
        f"SELECT * FROM ({grouped}) ORDER BY {order}, directive LIMIT ? OFFSET ?",  # noqa: S608  # allowlisted
        (*params, size, skip),
    ).fetchall()
    return {
        "total": total,
        "rows": [
            {
                "directive": row["directive"] or "",
                "blocked": row["blocked"] or "",
                "document": row["document"] or "",
                "source": row["source"] or "",
                "disposition": row["disposition"] or "",
                "count": int(row["n"] or 0),
                "last_ms": int(row["last_ms"]) if row["last_ms"] is not None else None,
            }
            for row in rows
        ],
    }


__all__ = [
    "CSP_SORTS",
    "HEADER_SORTS",
    "UA_SORTS",
    "VALUE_SORTS",
    "blocked_fingerprints",
    "blocked_header_count",
    "blocked_rows",
    "clear_header_values",
    "csp_reports",
    "header_counts",
    "header_names",
    "header_values",
    "remove_blocked_header",
    "remove_header",
    "user_agents",
]
