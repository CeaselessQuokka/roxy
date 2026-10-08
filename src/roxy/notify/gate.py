"""The alert gate: fleet-wide dedupe by cooldown key and the per-channel hourly cap, in one hot.db transaction.

What this is
    `decide(conn, ...)`, a pure function over a hot.db connection (run it inside `db.write`), returning which
    channels may send this alert now and how many alerts were held back since the last one that went out. Plus
    `MemoryGate`, the per-worker fallback used only while hot.db cannot be written (plan C7).

Why it exists
    Every worker process sees the same errors. Without a shared gate, two workers send two copies of every alert,
    and a long incident sends one mail per error. Plan 17.7: one alert per cooldown key per gap for the whole
    fleet (plan C6), and at most `alert_rate_limit_per_hour` messages per channel per hour, except leak guard
    trips. What is held back is counted and reported in the next message ("Suppressed since last alert: N").

How it works
    Rows in hot.db `email_gate (key, last_sent_at, suppressed)`:
      * `alert:<cooldown key>`: `last_sent_at` is when this key last went out; `suppressed` counts alerts of the
        key held back since then.
      * `cap:<channel>`: the channel's current one-hour window. `last_sent_at` is the window START and
        `suppressed` holds the number of messages SENT in that window (the column is reused as a counter here).
      * `capdrop:<channel>`: messages the cap held back since the channel last sent one (`suppressed`).
    The whole decision (read, compare, update) happens in one BEGIN IMMEDIATE transaction, so two workers can
    never both decide to send. A key held back by the cap is not marked as sent, so it goes out as soon as the
    cap allows. Rows idle for a day are pruned by the leader (`storage/retention.py`).

What to read next
    `roxy/notify/notifier.py` (the caller), then `roxy/storage/migrations/hot/0001_initial.sql` (`email_gate`).
"""

from __future__ import annotations

import sqlite3
from collections import OrderedDict
from collections.abc import Sequence
from dataclasses import dataclass, field

ALERT_PREFIX = "alert:"
CAP_PREFIX = "cap:"
CAPDROP_PREFIX = "capdrop:"
CAP_WINDOW_S = 3600


@dataclass(frozen=True, slots=True)
class GateDecision:
    """`allowed` channels may send now; `suppressed` per allowed channel is the count to report."""

    allowed: tuple[str, ...]
    deduped: bool = False
    capped: tuple[str, ...] = ()
    suppressed: dict[str, int] = field(default_factory=dict)


def _get(conn: sqlite3.Connection, key: str) -> tuple[int, int] | None:
    row = conn.execute("SELECT last_sent_at, suppressed FROM email_gate WHERE key = ?", (key,)).fetchone()
    return None if row is None else (int(row[0]), int(row[1]))


def _set(conn: sqlite3.Connection, key: str, last_sent_at: int, suppressed: int) -> None:
    conn.execute(
        "INSERT INTO email_gate (key, last_sent_at, suppressed) VALUES (?, ?, ?) ON CONFLICT (key) DO UPDATE SET "
        "last_sent_at = excluded.last_sent_at, suppressed = excluded.suppressed",
        (key, last_sent_at, suppressed),
    )


def _bump_suppressed(conn: sqlite3.Connection, key: str, now: int) -> None:
    conn.execute(
        "INSERT INTO email_gate (key, last_sent_at, suppressed) VALUES (?, ?, 1) ON CONFLICT (key) DO UPDATE SET "
        "suppressed = suppressed + 1",
        (key, now),
    )


def _cap_allows(conn: sqlite3.Connection, channel: str, cap: int, now: int) -> bool:
    """Count one message in the channel's hourly window if there is room; return whether there was."""
    key = f"{CAP_PREFIX}{channel}"
    row = _get(conn, key)
    start, sent = (now, 0) if row is None or now - row[0] >= CAP_WINDOW_S else row
    if sent >= max(1, cap):
        return False
    _set(conn, key, start, sent + 1)
    return True


def decide(
    conn: sqlite3.Connection,
    *,
    cooldown_key: str | None,
    cooldown_s: int,
    channels: Sequence[str],
    cap: int,
    uncapped: bool,
    now: int,
) -> GateDecision:
    """Decide, atomically for the fleet, which channels send this alert now (see the module docstring)."""
    if not channels:
        return GateDecision(allowed=())
    alert_key = f"{ALERT_PREFIX}{cooldown_key}" if cooldown_key else None
    key_suppressed = 0
    if alert_key is not None:
        row = _get(conn, alert_key)
        # A clock that stepped back a little (now before last_sent_at) still counts as inside the gap.
        if row is not None and row[0] > 0 and now - row[0] < max(0, cooldown_s):
            _bump_suppressed(conn, alert_key, now)
            return GateDecision(allowed=(), deduped=True)
        key_suppressed = row[1] if row is not None else 0
    allowed: list[str] = []
    capped: list[str] = []
    suppressed: dict[str, int] = {}
    for channel in channels:
        if uncapped or _cap_allows(conn, channel, cap, now):
            allowed.append(channel)
            drop_key = f"{CAPDROP_PREFIX}{channel}"
            drops = _get(conn, drop_key)
            if drops is not None and drops[1]:
                _set(conn, drop_key, now, 0)
            suppressed[channel] = key_suppressed + (drops[1] if drops is not None else 0)
        else:
            capped.append(channel)
            _bump_suppressed(conn, f"{CAPDROP_PREFIX}{channel}", now)
    if alert_key is not None:
        if allowed:
            _set(conn, alert_key, now, 0)
        else:
            # Held back by the cap: not marked as sent, so it goes out once the cap allows, with this count.
            conn.execute(
                "INSERT INTO email_gate (key, last_sent_at, suppressed) VALUES (?, 0, 1) ON CONFLICT (key) DO UPDATE "
                "SET suppressed = suppressed + 1",
                (alert_key,),
            )
    return GateDecision(allowed=tuple(allowed), capped=tuple(capped), suppressed=suppressed)


class MemoryGate:
    """Per-worker dedupe used only while hot.db is unavailable (plan C7). Bounded LRU of cooldown keys."""

    def __init__(self, max_keys: int = 256) -> None:
        self._max = max_keys
        self._sent: OrderedDict[str, int] = OrderedDict()

    def allow(self, cooldown_key: str | None, cooldown_s: int, now: int) -> bool:
        if not cooldown_key:
            return True
        last = self._sent.get(cooldown_key)
        if last is not None and now - last < cooldown_s:
            return False
        self._sent[cooldown_key] = now
        self._sent.move_to_end(cooldown_key)
        while len(self._sent) > self._max:
            self._sent.popitem(last=False)
        return True
