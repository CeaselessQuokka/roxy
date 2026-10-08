"""Pause: the maintenance switch (503 for every proxy request), now also with a scheduled window.

What this is
    `PauseState` (whether Roxy is paused, why, since when, and an optional scheduled window) stored as JSON in
    control.db `service_state` under the key `pause`, plus `set_pause`, `schedule_pause` and `clear_schedule`, the
    audited writers the admin API and the top bar call (plan 4.3 row 49, row 114).

Why it exists
    v1 kept pause in its state file and every worker re-read the file at most once a second. v2 keeps it in
    control.db and bumps `config_version` in the same transaction, so every worker sees the change within a second
    (plan 5.7) and the audit log says who paused, when and why. A scheduled pause lets the owner announce
    maintenance ahead of time instead of remembering to flip the switch at 3 a.m.

How it works
    - Paused when the manual switch is on, or when `scheduled_start <= now < scheduled_end`.
    - Message: the manual reason (kept across toggles, like v1, and replaced only when a new reason is given), the
      scheduled reason during a scheduled window, else the live setting `pause_message_default` (catalog default
      `Service down for maintenance.`, v1's constant), which the check passes in; cut to 300 characters.
      Throttle-all without a reason shares that default (v1 used one constant for both, v1 notes B6/B13).
    - `Retry-After` (plan 7.13): seconds to `scheduled_end` during a scheduled window, else 60.
    - `since` is when the manual pause began (a new marker each time it is switched on), so the top-bar banner can
      count drops "since the state began" from the metrics rollups (row 114).
    - Each writer runs in ONE control.db transaction: read the old state, write the new one, append an audit row,
      bump `config_version`. Readers use `roxy/abuse/state.py`, which reloads on the version change.

What to read next
    `roxy/abuse/state.py` (how workers see this), then `roxy/abuse/throttle_all.py` (the other admin switch).
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from typing import Any, Final

from roxy.abuse.messages import DEFAULT_DOWNTIME_MESSAGE, MAX_STATE_REASON, clean_admin_message, downtime_default
from roxy.abuse.state import read_state_value, write_state_value
from roxy.abuse.verdict import MessageSource
from roxy.config.audit import Actor
from roxy.core.clock import Clock
from roxy.storage.db import Database

STATE_KEY: Final = "pause"
DEFAULT_RETRY_AFTER_S: Final = 60
"""Plan 7.13: `Retry-After` of a pause refusal when no scheduled end is known."""


@dataclass(frozen=True, slots=True)
class PauseState:
    """The stored pause state (times are Unix seconds)."""

    paused: bool = False
    reason: str = ""
    since: float = 0.0
    scheduled_start: int | None = None
    scheduled_end: int | None = None
    scheduled_reason: str = ""
    scheduled_by: str = ""

    @classmethod
    def from_json(cls, value: Any) -> PauseState:
        """Parse the stored JSON object; anything malformed is treated as "not paused" field by field."""
        if not isinstance(value, dict):
            return cls()

        def opt_int(name: str) -> int | None:
            raw = value.get(name)
            return int(raw) if isinstance(raw, int | float) and not isinstance(raw, bool) else None

        return cls(
            paused=bool(value.get("paused", False)),
            reason=str(value.get("reason", "") or "")[:MAX_STATE_REASON],
            since=float(value.get("since", 0.0) or 0.0),
            scheduled_start=opt_int("scheduled_start"),
            scheduled_end=opt_int("scheduled_end"),
            scheduled_reason=str(value.get("scheduled_reason", "") or "")[:MAX_STATE_REASON],
            scheduled_by=str(value.get("scheduled_by", "") or "")[:64],
        )

    def to_json(self) -> dict[str, Any]:
        return asdict(self)

    def in_scheduled_window(self, now: float) -> bool:
        start, end = self.scheduled_start, self.scheduled_end
        return start is not None and end is not None and start <= now < end

    def active(self, now: float) -> bool:
        """Whether proxy requests are refused with 503 right now."""
        return self.paused or self.in_scheduled_window(now)

    def message(self, now: float, default: str = DEFAULT_DOWNTIME_MESSAGE) -> tuple[str, MessageSource]:
        """`(text, message_source)` for the 503 body; `default` is the live `pause_message_default` setting."""
        if not self.paused and self.in_scheduled_window(now):
            text = clean_admin_message(self.scheduled_reason or self.reason, MAX_STATE_REASON)
        else:
            text = clean_admin_message(self.reason, MAX_STATE_REASON)
        return (text, "custom") if text else (downtime_default(default), "default")

    def retry_after(self, now: float) -> int:
        """Plan 7.13: seconds to the scheduled end during a scheduled window, else 60."""
        if not self.paused and self.in_scheduled_window(now) and self.scheduled_end is not None:
            return max(1, int(self.scheduled_end - now))
        return DEFAULT_RETRY_AFTER_S

    def active_since(self, now: float) -> float:
        """When the current pause began (for the banner), 0 when not paused."""
        if self.paused:
            return self.since
        if self.in_scheduled_window(now) and self.scheduled_start is not None:
            return float(self.scheduled_start)
        return 0.0


async def _write(
    db: Database,
    clock: Clock,
    actor: Actor,
    action: str,
    change: Callable[[PauseState, float], PauseState],
    reason: str,
    request_id: str | None,
) -> PauseState:
    now = clock.now()

    def write(conn: sqlite3.Connection) -> PauseState:
        before = PauseState.from_json(read_state_value(conn, STATE_KEY))
        after = change(before, now)
        write_state_value(
            conn, STATE_KEY, after.to_json(), actor, action, before.to_json(), reason, request_id, int(now)
        )
        return after

    return await db.write(write)


async def set_pause(
    db: Database,
    clock: Clock,
    actor: Actor,
    *,
    paused: bool | None = None,
    reason: str | None = None,
    request_id: str | None = None,
) -> PauseState:
    """Switch the manual pause on or off (None toggles), optionally replacing the reason (v1 `/admin/proxy/toggle`).

    Switching it on records a new `since` marker, so the drop counter of the banner restarts (v1 cleared
    `pause_drops`; v2 keeps history in the rollups and counts from the marker, row 114).
    """

    def change(before: PauseState, now: float) -> PauseState:
        target = (not before.paused) if paused is None else bool(paused)
        after = replace(before, paused=target)
        if reason is not None:
            after = replace(after, reason=clean_admin_message(reason, MAX_STATE_REASON))
        if target and not before.paused:
            after = replace(after, since=now)
        if not target:
            after = replace(after, since=0.0)
        return after

    return await _write(db, clock, actor, "pause.set", change, reason or "", request_id)


async def schedule_pause(
    db: Database,
    clock: Clock,
    actor: Actor,
    *,
    start: int,
    end: int,
    reason: str = "",
    request_id: str | None = None,
) -> PauseState:
    """Schedule a maintenance window `[start, end)` (Unix seconds). Raises ValueError for an empty window."""
    if int(end) <= int(start):
        raise ValueError("The scheduled pause must end after it starts")

    def change(before: PauseState, _now: float) -> PauseState:
        return replace(
            before,
            scheduled_start=int(start),
            scheduled_end=int(end),
            scheduled_reason=clean_admin_message(reason, MAX_STATE_REASON),
            scheduled_by=actor.label[:64],
        )

    return await _write(db, clock, actor, "pause.schedule", change, reason, request_id)


async def clear_schedule(
    db: Database, clock: Clock, actor: Actor, *, reason: str = "", request_id: str | None = None
) -> PauseState:
    """Remove the scheduled window (the manual switch is untouched)."""

    def change(before: PauseState, _now: float) -> PauseState:
        return replace(before, scheduled_start=None, scheduled_end=None, scheduled_reason="", scheduled_by="")

    return await _write(db, clock, actor, "pause.unschedule", change, reason, request_id)


__all__ = ["DEFAULT_RETRY_AFTER_S", "STATE_KEY", "PauseState", "clear_schedule", "schedule_pause", "set_pause"]
