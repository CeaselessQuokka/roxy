"""Small shared state in control.db `service_state`: the read and audited-write helpers the admin switches use.

What this is
    `read_state_value(conn, key)` and `write_state_value(conn, key, value, ...)` for the JSON values in
    `service_state` (pause, throttle-all), plus `SwitchesCache`, the per-worker in-memory copy of both switches that
    the pipeline reads on every request.

Why it exists
    Plan 5.7: anything every worker must agree on lives in control.db, a change bumps `config_version` in the same
    transaction, and each worker reloads within about a second. Reading control.db on every proxy request would put
    a database read on the hot path, so the pipeline reads this cache instead (a field access), and the cache
    re-reads the two rows only when `config_version` moved.

How it works
    - `write_state_value` runs inside the caller's `BEGIN IMMEDIATE`: upsert the row, append an audit row with the
      before and after values, bump `config_version`. All or nothing.
    - `SwitchesCache.refresh_if_changed()` (called every second by the pipeline's loop) reads `config_version`; when
      it differs, it reads both rows in one read transaction. If control.db cannot be read the last good values stay
      in force (plan C7) and the failure is logged once per streak.

What to read next
    `roxy/abuse/pause.py` and `roxy/abuse/throttle_all.py` (the two switches), then `roxy/config/runtime.py`
    (the same `config_version` mechanism for settings).
"""

from __future__ import annotations

import json
import logging
import sqlite3
from typing import Any

from roxy.config import audit
from roxy.config.audit import Actor
from roxy.config.runtime import bump_config_version, read_config_version
from roxy.storage.db import Database, SharedStateUnavailable

log = logging.getLogger(__name__)


def read_state_value(conn: sqlite3.Connection, key: str) -> Any:
    """The decoded JSON value of `service_state[key]`, or None when missing or unreadable."""
    row = conn.execute("SELECT value_json FROM service_state WHERE key = ?", (key,)).fetchone()
    if row is None:
        return None
    try:
        return json.loads(row[0])
    except (TypeError, ValueError):
        log.error("service_state_unreadable", extra={"fields": {"key": key}})
        return None


def write_state_value(
    conn: sqlite3.Connection,
    key: str,
    value: Any,
    actor: Actor,
    action: str,
    before: Any,
    reason: str | None,
    request_id: str | None,
    now_s: int,
) -> int:
    """Upsert `service_state[key]`, audit it and bump `config_version` (inside the caller's write transaction)."""
    conn.execute(
        "INSERT INTO service_state (key, value_json, updated_at) VALUES (?, ?, ?) "
        "ON CONFLICT (key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at",
        (key, json.dumps(value, sort_keys=True), now_s),
    )
    audit.record(conn, actor, action, f"service_state:{key}", before, value, reason or None, request_id, at=now_s)
    return bump_config_version(conn, now_s)


class SwitchesCache:
    """The pause and throttle-all switches as this worker last saw them (see the module docstring)."""

    def __init__(self, db: Database | None) -> None:
        from roxy.abuse.pause import PauseState
        from roxy.abuse.throttle_all import ThrottleAllState

        self._db = db
        self.pause = PauseState()
        self.throttle_all = ThrottleAllState()
        self.version = -1
        self._failing = False

    def _load(self, conn: sqlite3.Connection) -> tuple[int, Any, Any]:
        from roxy.abuse.pause import STATE_KEY as PAUSE_KEY
        from roxy.abuse.throttle_all import STATE_KEY as THROTTLE_ALL_KEY

        return read_config_version(conn), read_state_value(conn, PAUSE_KEY), read_state_value(conn, THROTTLE_ALL_KEY)

    def _apply(self, version: int, pause: Any, throttle_all: Any) -> None:
        from roxy.abuse.pause import PauseState
        from roxy.abuse.throttle_all import ThrottleAllState

        self.pause = PauseState.from_json(pause)
        self.throttle_all = ThrottleAllState.from_json(throttle_all)
        self.version = version

    async def reload(self) -> None:
        """Read both switches now (raises `SharedStateUnavailable`; the old values stay)."""
        if self._db is None:
            return
        version, pause, throttle_all = await self._db.read(self._load)
        self._apply(version, pause, throttle_all)

    def reload_sync(self) -> None:
        """`reload` on the calling thread (tests and scripts)."""
        if self._db is not None:
            self._apply(*self._db.read_sync(self._load))

    async def refresh_if_changed(self) -> bool:
        """Reload when `config_version` moved. Never raises for an unavailable database (C7: keep last values)."""
        if self._db is None:
            return False
        try:
            version = await self._db.read(read_config_version)
            if version == self.version:
                self._failing = False
                return False
            await self.reload()
        except SharedStateUnavailable as exc:
            if not self._failing:
                log.warning("abuse_switches_refresh_failed", extra={"fields": {"error": str(exc)[:200]}})
            self._failing = True
            return False
        self._failing = False
        return True


__all__ = ["SwitchesCache", "read_state_value", "write_state_value"]
