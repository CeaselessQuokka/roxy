"""Throttle-all: the emergency per-IP limit ("Emergency per-IP limit" in the UI), with its "since" marker.

What this is
    `ThrottleAllState` (on or off, the reason, and since when) stored as JSON in control.db `service_state` under
    the key `throttle_all`; `set_throttle_all`, the audited writer behind the top-bar switch; and
    `throttle_all_watch`, the live table of who is hitting the emergency limit (plan 4.3 row 42, rows 114, 115, 135).

Why it exists
    During an attack the owner needs one switch that clamps every client to a tiny allowance (default 1 request per
    60 s per IP) without editing rules. v1 kept the switch in its state file; v2 keeps it in control.db so every
    worker agrees within a second, and audits who flipped it and why.

How it works
    - While on, each client key gets `global_throttle_limit` requests per `global_throttle_period` seconds in a v1
      fixed window (limiter rows `tall:<limit_key>`, evaluated in the pipeline's single hot.db transaction). Bypass
      entries skip it (v1).
    - The refusal is 429 with the stored reason, or `Service down for maintenance.` when none was given (v1 kept the
      pause text here too, bug B6; parity). `Roxy-Throttle-Reset` is the emergency window's remaining time and
      `Roxy-Global-Throttled: True`; `Roxy-Throttled` and `Roxy-Requests-Left` stay the per-IP values (v1 B7).
    - Enabling records a new `since` marker (row 115). v1 deleted the drop counter instead; v2 keeps the history in
      the metrics rollups and the banner counts `throttle_all` refusals from the marker.

What to read next
    `roxy/abuse/pause.py` (the other switch), then `roxy/abuse/checks/throttle_all.py` (the check itself).
"""

from __future__ import annotations

import sqlite3
from dataclasses import asdict, dataclass, replace
from typing import Any, Final

from roxy.abuse.messages import DEFAULT_DOWNTIME_MESSAGE, MAX_STATE_REASON, clean_admin_message
from roxy.abuse.state import read_state_value, write_state_value
from roxy.abuse.verdict import MessageSource
from roxy.config.audit import Actor
from roxy.core.clock import Clock
from roxy.storage.db import Database

STATE_KEY: Final = "throttle_all"
KEY_PREFIX: Final = "tall:"
"""Limiter row prefix of the emergency limit (`tall:<limit_key>`)."""


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

    def message(self) -> tuple[str, MessageSource]:
        """`(text, message_source)` of the 429 body."""
        text = clean_admin_message(self.reason, MAX_STATE_REASON)
        return (text, "custom") if text else (DEFAULT_DOWNTIME_MESSAGE, "default")


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
    the settings service, which reports invalid values instead of ignoring them (v1 bug B16).
    """
    now = clock.now()

    def write(conn: sqlite3.Connection) -> ThrottleAllState:
        before = ThrottleAllState.from_json(read_state_value(conn, STATE_KEY))
        target = (not before.enabled) if enabled is None else bool(enabled)
        after = replace(before, enabled=target)
        if reason is not None:
            after = replace(after, reason=clean_admin_message(reason, MAX_STATE_REASON))
        if target and not before.enabled:
            after = replace(after, since=now)  # a new "since" marker every time it is switched on (row 115)
        if not target:
            after = replace(after, since=0.0)
        write_state_value(
            conn, STATE_KEY, after.to_json(), actor, "throttle_all.set", before.to_json(), reason, request_id, int(now)
        )
        return after

    return await db.write(write)


async def throttle_all_watch(
    db: Database, *, now_ms: int, limit_setting: int, limit: int = 25, offset: int = 0
) -> dict[str, Any]:
    """Row 135: clients whose emergency window is in force, fullest first (`count`, `reset_in_s`, `limited`)."""
    limit = max(1, min(int(limit), 500))

    def read(conn: sqlite3.Connection) -> dict[str, Any]:
        where = "bucket_key >= ? AND bucket_key < ? AND tat_ms > ?"
        params = (KEY_PREFIX, KEY_PREFIX + "\U0010ffff", now_ms)
        total = conn.execute(f"SELECT count(*) FROM limiter WHERE {where}", params).fetchone()[0]  # noqa: S608  # constant clause
        rows = conn.execute(
            f"SELECT bucket_key, count, tat_ms FROM limiter WHERE {where} "  # noqa: S608  # constant clause
            "ORDER BY count DESC, tat_ms DESC LIMIT ? OFFSET ?",
            (*params, limit, max(0, int(offset))),
        ).fetchall()
        return {
            "total": int(total),
            "rows": [
                {
                    "ip": str(r[0])[len(KEY_PREFIX) :],
                    "count": int(r[1]),
                    "limited": int(r[1]) >= int(limit_setting),
                    "reset_in_s": max(0, (int(r[2]) - now_ms) // 1000),
                }
                for r in rows
            ],
        }

    return await db.read(read)


__all__ = ["KEY_PREFIX", "STATE_KEY", "ThrottleAllState", "set_throttle_all", "throttle_all_watch"]
