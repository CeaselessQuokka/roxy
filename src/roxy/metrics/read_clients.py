"""Read models for the Clients page drill-down: one client's totals, timeline and busiest endpoints over any range.

What this is
    Functions over a metrics.db connection (run them inside `Database.read`):
      * `client_range(conn, client_type, key, window)`: totals (requests, refused, served, bytes), a timeline with one
        point per bucket of the window, and the endpoints that were busiest, for one IP or place (plan 14.1 Clients,
        parity row 73 "drill-down").
      * `client_totals(conn, client_type, keys, window)`: the same totals for many clients at once (the
        FILTER-COLLATERAL preview asks for the served share of every client a detector would have banned).
      * `client_refusals(conn, ...)`: refusals of one client by reason in a window (from the refusal events).
      * `recent_live(conn, ip=..., place=..., limit=...)`: the newest live rows of one client (kept 15 minutes), the
        only place its User-Agent is kept, which the bot score needs.

Why it exists
    `metrics/queries.py client_table` answers "every client in a window"; a client page asks the opposite question,
    "everything about one client in a window", across the minute, hour and day tables. Keeping it here keeps the
    admin API thin and gives the page and any export one definition of each number (P6).

How it works
    - Client rows live at three levels (`client_minute`, `client_hour`, `client_day`), compacted by the leader. As in
      `client_table`, a level answers from the window start up to the end of its newest compacted bucket and the next
      finer level answers the rest, so nothing is counted twice; minutes always answer the tail.
    - The timeline re-buckets the rows into the window's granularity (`rollups.bucket_floor` in `ui_timezone`).
    - "Busiest endpoints" weights each bucket's `top_endpoint` by that bucket's requests: the rows keep only the
      busiest endpoint per bucket, so this ranks endpoints by the traffic of the buckets they led, and says so
      (`top_endpoints_basis`). It is exact for a client that calls one endpoint.
    - Everything is bounded: one key, or keys in chunks of 500; at most `queries.MAX_POINTS` buckets.

What to read next
    `roxy/metrics/queries.py` (`client_table`, `client_timeline`), `roxy/metrics/activity.py` (`client_detail`, the
    last hour), then `roxy/admin/api/clients.py`.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Sequence
from typing import Any, Final

from roxy.metrics.queries import CLIENT_LEVELS, Window, bucket_starts
from roxy.metrics.rollups import bucket_floor, bucket_next, zone

TOP_ENDPOINTS: Final = 10
KEY_CHUNK: Final = 500
MAX_LIVE_ROWS: Final = 50
TOP_ENDPOINTS_BASIS: Final = "busiest endpoint of each bucket, weighted by that bucket's requests"
_COLUMNS: Final = ("requests", "refused", "served", "bytes")
_COUNT: Final = "sum(coalesce(json_extract(detail_json, '$.count'), 1))"


def _watermark_end(conn: sqlite3.Connection, table: str, unit: str, tz: str) -> int | None:
    """End of the newest compacted bucket of a client level (None for minutes or an empty level)."""
    if unit == "minute":
        return None
    row = conn.execute(f"SELECT max(bucket_start) FROM {table}").fetchone()  # noqa: S608 (CLIENT_LEVELS names)
    if row is None or row[0] is None:
        return None
    return bucket_next(int(row[0]), unit, zone(tz) if unit == "day" else None)


def client_pieces(conn: sqlite3.Connection, window: Window) -> list[tuple[str, int, int]]:
    """Which client table answers which part of the window (coarsest first, then finer up to the end)."""
    pieces: list[tuple[str, int, int]] = []
    cursor = window.start
    for table, unit in CLIENT_LEVELS:
        if cursor >= window.end:
            break
        zi = zone(window.tz) if unit == "day" else None
        if unit == "minute":
            hi = window.end
        else:
            mark = _watermark_end(conn, table, unit, window.tz)
            if mark is None or cursor != bucket_floor(cursor, unit, zi):
                continue  # nothing compacted, or the window does not start on a bucket of this level
            hi = min(mark, bucket_floor(window.end, unit, zi))  # a coarse row covers its whole bucket
        if hi > cursor:
            pieces.append((table, cursor, hi))
            cursor = hi
    return pieces


def client_range(conn: sqlite3.Connection, client_type: str, key: str, window: Window) -> dict[str, Any]:
    """One client's totals, timeline and busiest endpoints in `window` (see the module docstring)."""
    if client_type not in ("ip", "place"):
        raise ValueError("client_type must be 'ip' or 'place'")
    starts = bucket_starts(window)
    zi = zone(window.tz)
    buckets: dict[int, dict[str, int]] = {start: dict.fromkeys(_COLUMNS, 0) for start in starts}
    totals = dict.fromkeys(_COLUMNS, 0)
    endpoints: dict[str, int] = {}
    for table, lo, hi in client_pieces(conn, window):
        rows = conn.execute(
            f"SELECT bucket_start, requests, refused, served, bytes, top_endpoint FROM {table} "  # noqa: S608 (names)
            "WHERE client_type = ? AND client_key = ? AND bucket_start >= ? AND bucket_start < ?",
            (client_type, key, lo, hi),
        ).fetchall()
        for row in rows:
            start = bucket_floor(int(row["bucket_start"]), window.granularity, zi)
            point = buckets.get(start)
            for column in _COLUMNS:
                value = int(row[column] or 0)
                totals[column] += value
                if point is not None:
                    point[column] += value
            if row["top_endpoint"]:
                name = str(row["top_endpoint"])
                endpoints[name] = endpoints.get(name, 0) + int(row["requests"] or 0)
    ranked = sorted(endpoints.items(), key=lambda kv: (-kv[1], kv[0]))[:TOP_ENDPOINTS]
    requests = totals["requests"]
    return {
        "kind": client_type,
        "key": key,
        **totals,
        "refused_pct": round(totals["refused"] * 100.0 / requests, 2) if requests else None,
        "served_pct": round(totals["served"] * 100.0 / requests, 2) if requests else None,
        "timeline": [{"t": start, **buckets[start]} for start in starts],
        "top_endpoints": [{"endpoint": name, "requests": count} for name, count in ranked],
        "top_endpoints_basis": TOP_ENDPOINTS_BASIS,
    }


def client_totals(
    conn: sqlite3.Connection, client_type: str, keys: Iterable[str], window: Window
) -> dict[str, dict[str, int]]:
    """`{key: {requests, refused, served, bytes}}` in `window` for each of `keys` that has rows."""
    wanted = list(dict.fromkeys(str(key) for key in keys if key))
    out: dict[str, dict[str, int]] = {}
    for table, lo, hi in client_pieces(conn, window):
        for first in range(0, len(wanted), KEY_CHUNK):
            chunk = wanted[first : first + KEY_CHUNK]
            marks = ", ".join("?" for _ in chunk)
            rows = conn.execute(
                f"SELECT client_key, sum(requests) AS requests, sum(refused) AS refused, sum(served) AS served, "  # noqa: S608
                f"sum(bytes) AS bytes FROM {table} WHERE client_type = ? AND bucket_start >= ? AND bucket_start < ? "
                f"AND client_key IN ({marks}) GROUP BY client_key",
                (client_type, lo, hi, *chunk),
            ).fetchall()
            for row in rows:
                entry = out.setdefault(str(row["client_key"]), dict.fromkeys(_COLUMNS, 0))
                for column in _COLUMNS:
                    entry[column] += int(row[column] or 0)
    return out


def client_refusals(
    conn: sqlite3.Connection,
    *,
    start_ms: int,
    end_ms: int,
    ip_hash: str | None = None,
    place: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Refusals of one client by reason code in `[start_ms, end_ms)` (refusal events; folded rows lose the client).

    Exactly one of `ip_hash` (the recorder's keyed hash of the address) or `place` names the client.
    """
    if (ip_hash is None) == (place is None):
        raise ValueError("pass exactly one of ip_hash or place")
    column, value = ("ip_hash", ip_hash) if ip_hash is not None else ("place", place)
    rows = conn.execute(
        f"SELECT reason_code, {_COUNT} AS n, max(at_ms) AS last_ms FROM events "  # noqa: S608  # fixed column names
        f"WHERE type = 'refusal' AND {column} = ? AND at_ms >= ? AND at_ms < ? "
        "GROUP BY reason_code ORDER BY n DESC LIMIT ?",
        (value, int(start_ms), int(end_ms), max(1, min(int(limit), 200))),
    ).fetchall()
    return [{"reason": row["reason_code"], "count": int(row["n"]), "last_ms": int(row["last_ms"])} for row in rows]


def recent_live(
    conn: sqlite3.Connection, *, ip: str | None = None, place: str | None = None, limit: int = 1
) -> list[dict[str, Any]]:
    """The newest live rows (last 15 minutes) of one client, by address or by place, newest first."""
    if (ip is None) == (place is None):
        raise ValueError("pass exactly one of ip or place")
    where = "json_extract(detail_json, '$.ip') = ?" if ip is not None else "place = ?"
    value = ip if ip is not None else place
    rows = conn.execute(
        f"SELECT detail_json FROM events WHERE type = 'live' AND {where} ORDER BY id DESC LIMIT ?",  # noqa: S608
        (value, max(1, min(int(limit), MAX_LIVE_ROWS))),
    ).fetchall()
    out = []
    for row in rows:
        try:
            item = json.loads(row[0]) if row[0] else {}
        except (TypeError, ValueError):
            continue
        if isinstance(item, dict):
            out.append(item)
    return out


def latest_user_agents(conn: sqlite3.Connection, ips: Sequence[str]) -> dict[str, dict[str, Any]]:
    """`{ip: {user_agent, place, at_ms}}` from the newest live row of each address (bounded by the live window)."""
    wanted = list(dict.fromkeys(ip for ip in ips if ip))[:KEY_CHUNK]
    if not wanted:
        return {}
    marks = ", ".join("?" for _ in wanted)
    rows = conn.execute(
        "SELECT json_extract(detail_json, '$.ip') AS ip, json_extract(detail_json, '$.user_agent') AS ua, "  # noqa: S608
        "json_extract(detail_json, '$.place') AS place, at_ms, max(id) FROM events "
        f"WHERE type = 'live' AND json_extract(detail_json, '$.ip') IN ({marks}) GROUP BY ip",
        wanted,
    ).fetchall()
    return {
        str(row["ip"]): {"user_agent": row["ua"] or "", "place": row["place"], "at_ms": int(row["at_ms"])}
        for row in rows
    }


__all__ = [
    "TOP_ENDPOINTS",
    "TOP_ENDPOINTS_BASIS",
    "client_pieces",
    "client_range",
    "client_refusals",
    "client_totals",
    "latest_user_agents",
    "recent_live",
]
