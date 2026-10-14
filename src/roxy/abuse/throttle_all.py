"""Throttle-all: the emergency per-IP limit ("Emergency per-IP limit" in the UI), with its "since" marker.

What this is
    `ThrottleAllState` (on or off, the reason, and since when) stored as JSON in control.db `service_state` under
    the key `throttle_all`; `set_throttle_all`, the audited writer behind the top-bar switch; and the watch of who
    the emergency limit turns away (plan 4.3 row 42, rows 114, 115, 135): `turned_away` picks its rows,
    `throttle_all_watch` and `throttle_all_windows` read the emergency windows in force.

Why it exists
    During an attack the owner needs one switch that clamps every client to a tiny allowance (default 1 request per
    60 s per IP) without editing rules. v1 kept the switch in its state file; v2 keeps it in control.db so every
    worker agrees within a second, and audits who flipped it and why.

How it works
    - While on, each client key gets `global_throttle_limit` requests per `global_throttle_period` seconds in a v1
      fixed window (limiter rows `tall:<limit_key>`, evaluated in the pipeline's single hot.db transaction). Bypass
      entries skip it (v1).
    - The refusal is 429 with the stored reason, or the pause default (the live `pause_message_default` setting,
      `Service down for maintenance.` unless the admin changed it) when none was given: v1 used its one downtime
      constant for both (bug B6/B13, kept for parity). The reason is checked when it is written (no em or en
      dash, plan C5, `messages.checked_state_reason`). `Roxy-Throttle-Reset` is the emergency window's remaining
      time and `Roxy-Global-Throttled: True`; `Roxy-Throttled` and `Roxy-Requests-Left` stay the per-IP values (v1
      B7).
    - Enabling records a new `since` marker (row 115). v1 deleted the drop counter instead; v2 keeps the history in
      the metrics rollups and the banner counts `throttle_all` refusals from the marker.
    - The watch (row 135) lists what v1's "Who is being throttled right now" listed: the clients Roxy turned away
      since the marker (v1: the IPs with Refused above 0, worst first), so the brake can be judged and released.
      They come from the client activity tables of metrics.db (`refused_clients`, counted from the marker's minute
      exactly like `metrics/read_protection.py watch_activity`, which fills the other columns), with each one's
      emergency window from hot.db when it still has one. A refusal counts nothing in the window, so a full window
      says only that the next request would be refused; it never puts a client on the list by itself, except where
      Roxy has no activity record to judge by (an IPv6 network key, or an address the recorder has not written
      yet): there the full window is the only evidence, and the row says its refusals are unknown.

What to read next
    `roxy/abuse/pause.py` (the other switch), then `roxy/abuse/checks/throttle_all.py` (the check itself).
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, replace
from typing import Any, Final

from roxy.abuse.messages import (
    DEFAULT_DOWNTIME_MESSAGE,
    MAX_STATE_REASON,
    checked_state_reason,
    clean_admin_message,
    downtime_default,
)
from roxy.abuse.state import read_state_value, write_state_value
from roxy.abuse.verdict import MessageSource
from roxy.config.audit import Actor
from roxy.core.client_ip import limit_key
from roxy.core.clock import Clock
from roxy.metrics.activity import OTHER_KEY
from roxy.metrics.queries import Window
from roxy.metrics.read_clients import client_pieces
from roxy.storage.db import Database

STATE_KEY: Final = "throttle_all"
KEY_PREFIX: Final = "tall:"
"""Limiter row prefix of the emergency limit (`tall:<limit_key>`)."""
MAX_WATCH_ROWS: Final = 1000
"""The most clients the watch lists (v1 showed its first 25): the ones turned away most first (plan P9 bound)."""
KEY_CHUNK: Final = 400
"""Keys per `IN (...)` list of one statement (well under SQLite's bound parameter limit)."""
WATCH_SORTS: Final[tuple[str, ...]] = ("refused", "count")
"""How the watch can be ordered (always most first): by refusals since the marker (v1's order), or by the requests
counted in the current window."""


@dataclass(frozen=True, slots=True)
class ThrottleAllState:
    """The stored throttle-all switch (`since` in Unix seconds, 0 while off)."""

    enabled: bool = False
    reason: str = ""
    since: float = 0.0

    @classmethod
    def from_json(cls, value: Any) -> ThrottleAllState:
        if not isinstance(value, dict):
            return cls()
        return cls(
            enabled=bool(value.get("enabled", False)),
            reason=str(value.get("reason", "") or "")[:MAX_STATE_REASON],
            since=float(value.get("since", 0.0) or 0.0),
        )

    def to_json(self) -> dict[str, Any]:
        return asdict(self)

    def message(self, default: str = DEFAULT_DOWNTIME_MESSAGE) -> tuple[str, MessageSource]:
        """`(text, message_source)` of the 429 body; `default` is the live `pause_message_default` setting."""
        text = clean_admin_message(self.reason, MAX_STATE_REASON)
        return (text, "custom") if text else (downtime_default(default), "default")


async def set_throttle_all(
    db: Database,
    clock: Clock,
    actor: Actor,
    *,
    enabled: bool | None = None,
    reason: str | None = None,
    request_id: str | None = None,
) -> ThrottleAllState:
    """Switch throttle-all on or off (None toggles), optionally replacing the reason (v1 `/admin/proxy/throttle_all`).

    The limit and period are ordinary settings (`global_throttle_limit`, `global_throttle_period`) changed through
    the settings service, which reports invalid values instead of ignoring them (v1 bug B16). Raises ValueError for
    a reason with an em or en dash or a control character (plan C5), before anything is written.
    """
    now = clock.now()
    stored = checked_state_reason(reason) if reason is not None else None

    def write(conn: sqlite3.Connection) -> ThrottleAllState:
        before = ThrottleAllState.from_json(read_state_value(conn, STATE_KEY))
        target = (not before.enabled) if enabled is None else bool(enabled)
        after = replace(before, enabled=target)
        if stored is not None:
            after = replace(after, reason=stored)
        if target and not before.enabled:
            after = replace(after, since=now)  # a new "since" marker every time it is switched on (row 115)
        if not target:
            after = replace(after, since=0.0)
        write_state_value(
            conn, STATE_KEY, after.to_json(), actor, "throttle_all.set", before.to_json(), reason, request_id, int(now)
        )
        return after

    return await db.write(write)


# ------------------------------------------------------------------------------------------------- the watch


def _window(key: str, count: int, tat_ms: int, *, now_ms: int, limit_setting: int) -> dict[str, Any]:
    """One emergency window in force: requests counted in it, whether it is full, and when it ends."""
    return {
        "ip": key,
        "count": int(count),
        # A refusal counts nothing (checks/throttle_all.py), so a full window means the NEXT request is refused.
        "limited": int(count) >= int(limit_setting),
        "reset_in_s": max(0, (int(tat_ms) - now_ms) // 1000),
    }


async def throttle_all_watch(
    db: Database, *, now_ms: int, limit_setting: int, limit: int = 25, offset: int = 0, full_only: bool = False
) -> dict[str, Any]:
    """Clients whose emergency window is in force, fullest first (`count`, `reset_in_s`, `limited`); `full_only`
    keeps the full windows (every further request of that client in its window is refused)."""
    limit = max(1, min(int(limit), MAX_WATCH_ROWS))

    def read(conn: sqlite3.Connection) -> dict[str, Any]:
        where = "bucket_key >= ? AND bucket_key < ? AND tat_ms > ?"
        params: tuple[Any, ...] = (KEY_PREFIX, KEY_PREFIX + "\U0010ffff", now_ms)
        if full_only:
            where += " AND count >= ?"
            params = (*params, int(limit_setting))
        total = conn.execute(f"SELECT count(*) FROM limiter WHERE {where}", params).fetchone()[0]  # noqa: S608  # constant clause
        rows = conn.execute(
            f"SELECT bucket_key, count, tat_ms FROM limiter WHERE {where} "  # noqa: S608  # constant clause
            "ORDER BY count DESC, tat_ms DESC LIMIT ? OFFSET ?",
            (*params, limit, max(0, int(offset))),
        ).fetchall()
        return {
            "total": int(total),
            "rows": [
                _window(str(r[0])[len(KEY_PREFIX) :], r[1], r[2], now_ms=now_ms, limit_setting=limit_setting)
                for r in rows
            ],
        }

    return await db.read(read)


def _chunks(keys: Sequence[str]) -> Iterable[Sequence[str]]:
    for first in range(0, len(keys), KEY_CHUNK):
        yield keys[first : first + KEY_CHUNK]


async def throttle_all_windows(
    db: Database, keys: Iterable[str], *, now_ms: int, limit_setting: int
) -> dict[str, dict[str, Any]]:
    """`{limit key: window}` for each key of `keys` whose emergency window is in force at `now_ms` (the others are
    left out: a client without a window would be admitted again)."""
    wanted = list(dict.fromkeys(str(key) for key in keys if key))[:MAX_WATCH_ROWS]
    if not wanted:
        return {}

    def read(conn: sqlite3.Connection) -> dict[str, dict[str, Any]]:
        found: dict[str, dict[str, Any]] = {}
        for chunk in _chunks(wanted):
            marks = ", ".join("?" for _ in chunk)
            rows = conn.execute(
                f"SELECT bucket_key, count, tat_ms FROM limiter WHERE bucket_key IN ({marks}) AND tat_ms > ?",  # noqa: S608  # placeholders only
                (*(KEY_PREFIX + key for key in chunk), now_ms),
            ).fetchall()
            for r in rows:
                key = str(r[0])[len(KEY_PREFIX) :]
                found[key] = _window(key, r[1], r[2], now_ms=now_ms, limit_setting=limit_setting)
        return found

    return await db.read(read)


def watch_pieces(conn: sqlite3.Connection, *, since: float, now: float) -> list[tuple[str, int, int]]:
    """Which client activity table answers which part of the watch's period: from the minute `since` falls in (client
    rows are per minute) to the end of `now`'s minute, the minutes up to the first whole hour, then the coarsest
    compacted level (`read_clients.client_pieces`). The same rule as `metrics/read_protection.py watch_activity`, so
    the rows this picks and the numbers it shows for them agree."""
    start = int(since) - int(since) % 60
    end = int(now) - int(now) % 60 + 60
    if end <= start:
        return []
    edge = min(end, start if start % 3600 == 0 else start - start % 3600 + 3600)
    pieces: list[tuple[str, int, int]] = [("client_minute", start, edge)] if edge > start else []
    if end > edge:
        pieces += client_pieces(conn, Window(edge, end, "minute"))
    return pieces


def refused_clients(
    conn: sqlite3.Connection, *, since: float, now: float, limit: int = MAX_WATCH_ROWS
) -> list[tuple[str, int]]:
    """`[(address, refused)]`: the addresses Roxy turned away since `since` (metrics.db client activity, any refusal,
    as v1's Refused), most refused first, at most `limit`. The folded `other` row is not a client."""
    pieces = watch_pieces(conn, since=since, now=now)
    if not pieces:
        return []
    # Table names come from `watch_pieces` (the fixed client levels), never from a caller.
    parts = " UNION ALL ".join(
        f"SELECT client_key, refused FROM {table} WHERE bucket_start >= ? AND bucket_start < ? "  # noqa: S608
        "AND client_type = 'ip' AND refused > 0"
        for table, _lo, _hi in pieces
    )
    params = [bound for _table, lo, hi in pieces for bound in (lo, hi)]
    rows = conn.execute(
        f"SELECT client_key, sum(refused) AS refused FROM ({parts}) WHERE client_key != ? "  # noqa: S608  # fixed names
        "GROUP BY client_key ORDER BY refused DESC, client_key LIMIT ?",
        (*params, OTHER_KEY, max(1, min(int(limit), MAX_WATCH_ROWS))),
    ).fetchall()
    return [(str(r[0]), int(r[1])) for r in rows]


def recorded_clients(conn: sqlite3.Connection, keys: Sequence[str], *, since: float, now: float) -> set[str]:
    """The addresses of `keys` that have any client activity row since `since` (the period of `watch_pieces`)."""
    wanted = list(dict.fromkeys(str(key) for key in keys if key))[:MAX_WATCH_ROWS]
    found: set[str] = set()
    if not wanted:
        return found
    for table, lo, hi in watch_pieces(conn, since=since, now=now):
        for chunk in _chunks(wanted):
            marks = ", ".join("?" for _ in chunk)
            rows = conn.execute(
                f"SELECT DISTINCT client_key FROM {table} WHERE client_type = 'ip' "  # noqa: S608  # fixed names
                f"AND client_key IN ({marks}) AND bucket_start >= ? AND bucket_start < ?",
                (*chunk, lo, hi),
            ).fetchall()
            found.update(str(r[0]) for r in rows)
    return found


def _ordered(rows: list[dict[str, Any]], sort: str) -> list[dict[str, Any]]:
    """Most first by `sort` (`refused` or `count`), then by the other one, then by client; unknown values last."""

    def known(value: Any) -> int:
        return -1 if value is None else int(value)

    def key(row: dict[str, Any]) -> tuple[int, int, str]:
        refused, count = known(row.get("refused")), known(row.get("count"))
        first, second = (count, refused) if sort == "count" else (refused, count)
        return (-first, -second, str(row.get("ip")))

    return sorted(rows, key=key)


async def turned_away(
    hot: Database,
    metrics: Database,
    *,
    since: float,
    now_ms: int,
    limit_setting: int,
    ipv6_prefix: int,
    sort: str = "refused",
    limit: int = 25,
    offset: int = 0,
) -> dict[str, Any]:
    """Row 135, v1's "Who is being throttled right now": the clients the emergency limit turned away since `since`
    (its marker), refused most first (`sort="count"`: fullest window first), `{total, rows}`.

    Each row: `ip` (the address, or the limit key where only a window speaks for it), `refused` (refusals since the
    marker, None when Roxy has no activity record for the client), and its window in force (`count`, `limited`,
    `reset_in_s`; None, False and None once its window ended: its next request would be admitted again). The
    module docstring says why a full window alone lists a client only where no activity record exists.
    """
    limit = max(1, min(int(limit), MAX_WATCH_ROWS))
    now = now_ms / 1000
    refused = await metrics.read(lambda conn: refused_clients(conn, since=since, now=now))
    keys = {ip: limit_key(ip, ipv6_prefix) for ip, _count in refused}
    windows = await throttle_all_windows(hot, keys.values(), now_ms=now_ms, limit_setting=limit_setting)
    rows: list[dict[str, Any]] = []
    for ip, count in refused:
        window = windows.get(keys[ip])
        rows.append(
            {
                "ip": ip,
                "refused": count,
                "count": window["count"] if window else None,
                "limited": bool(window and window["limited"]),
                "reset_in_s": window["reset_in_s"] if window else None,
            }
        )
    # Full windows nobody above accounts for: listed only where no activity record can say whether they were turned
    # away (an IPv6 network key never has one; an address may not be written yet, or was folded into `other`).
    full = await throttle_all_watch(
        hot, now_ms=now_ms, limit_setting=limit_setting, limit=MAX_WATCH_ROWS, full_only=True
    )
    covered = {*keys, *keys.values()}
    candidates = [row for row in full["rows"] if row["ip"] not in covered]
    addresses = [str(row["ip"]) for row in candidates if "/" not in str(row["ip"])]
    recorded: set[str] = set()
    if addresses:
        recorded = await metrics.read(lambda conn: recorded_clients(conn, addresses, since=since, now=now))
    rows += [{**row, "refused": None} for row in candidates if row["ip"] not in recorded]
    ordered = _ordered(rows, sort if sort in WATCH_SORTS else "refused")[:MAX_WATCH_ROWS]
    start = max(0, int(offset))
    return {"total": len(ordered), "rows": ordered[start : start + limit]}


__all__ = [
    "KEY_PREFIX",
    "MAX_WATCH_ROWS",
    "STATE_KEY",
    "WATCH_SORTS",
    "ThrottleAllState",
    "recorded_clients",
    "refused_clients",
    "set_throttle_all",
    "throttle_all_watch",
    "throttle_all_windows",
    "turned_away",
    "watch_pieces",
]
