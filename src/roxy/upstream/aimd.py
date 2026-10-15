"""AIMD adaptive concurrency (Tier 3, off by default): an optional cap on parallel calls per host and egress.

What this is
    Additive-increase, multiplicative-decrease: a concurrency limit per `(host, egress)` that grows slowly while
    calls succeed and halves on a 429, timeout or 5xx. In-flight calls hold counted lease slots in hot.db, so the
    limit holds across every worker and a crashed worker's slots expire on their own.

Why it exists
    Plan 7.4: Roblox limits rate, not concurrency, so adaptive RATE (`adaptive.py`) is the default control and this
    stays off (`aimd_enabled=0`). It is kept for hosts that show latency collapse under parallel load. Minimal on
    purpose: one row and a few counted leases per key.

How it works
    - The limit is stored as a REAL in hot.db `aimd."limit"`, starting at `aimd_initial` (8). Each success adds
      `1 / aimd_increase_after` (so 50 successes add 1, the plan's "+1 after every 50 consecutive successes"
      without a separate streak counter: any failure in between halves the limit anyway, which dominates).
      A failure multiplies it by `aimd_decrease_factor` (0.5). It stays within `[aimd_min, aimd_max]`.
    - A call may start only if it takes one of `floor(limit)` slot leases `aimd:<host>:<egress>:<n>` (the same
      counted-lease primitive the tarpit uses). The slot is taken inside the reservation transaction (a guard in
      `buckets.reserve`) and released in the post-call transaction with the result applied to the limit.
    - The `inflight` column mirrors the number of valid slots for the Upstream page chart.

What to read next
    `roxy/storage/leases.py` (`acquire_slot`), `roxy/upstream/buckets.py` (guards), `roxy/upstream/effects.py`.
"""

from __future__ import annotations

import math
import sqlite3
from dataclasses import dataclass
from typing import Any, Final

from roxy.core.reasons import Egress
from roxy.storage import leases

SLOT_PREFIX: Final = "aimd:"
RETRY_WHEN_FULL_MS: Final = 1000.0
"""How long a caller is told to wait when every slot is taken (calls take about a second)."""


@dataclass(frozen=True, slots=True)
class AimdPolicy:
    """The AIMD settings of plan 15.3 C."""

    enabled: bool = False
    initial: float = 8.0
    minimum: float = 1.0
    maximum: float = 32.0
    increase_after: int = 50
    decrease_factor: float = 0.5
    slot_ttl_s: float = 20.0  # a slot whose holder never reports back frees itself after this long

    @classmethod
    def from_settings(cls, settings: Any) -> AimdPolicy:
        minimum = float(settings.get("aimd_min"))
        maximum = max(minimum, float(settings.get("aimd_max")))
        return cls(
            enabled=bool(settings.get("aimd_enabled")),
            initial=min(maximum, max(minimum, float(settings.get("aimd_initial")))),
            minimum=minimum,
            maximum=maximum,
            increase_after=max(1, int(settings.get("aimd_increase_after"))),
            decrease_factor=float(settings.get("aimd_decrease_factor")),
            slot_ttl_s=float(settings.get("request_timeout")) + 5.0,
        )


def aimd_key(host: str, egress: Egress | str) -> str:
    return f"{host}:{Egress(egress).value}"


def next_limit(limit: float, ok: bool, policy: AimdPolicy) -> float:
    """Additive increase on success, multiplicative decrease on failure, kept within bounds."""
    if ok:
        return min(policy.maximum, limit + 1.0 / policy.increase_after)
    return max(policy.minimum, limit * policy.decrease_factor)


def current_limit(conn: sqlite3.Connection, key: str, policy: AimdPolicy, now_s: float) -> float:
    """The stored limit for `key` (inserting the initial value the first time)."""
    row = conn.execute('SELECT "limit" FROM aimd WHERE key = ?', (key,)).fetchone()
    if row is not None:
        return float(row[0])
    conn.execute(
        'INSERT INTO aimd (key, "limit", inflight, last_change_at) VALUES (?, ?, 0, ?)', (key, policy.initial, now_s)
    )
    return policy.initial


def _slot_prefix(key: str) -> str:
    return f"{SLOT_PREFIX}{key}:"


def acquire(conn: sqlite3.Connection, key: str, holder: str, policy: AimdPolicy, now_ms: int) -> str | None:
    """Take one in-flight slot for `key`, or None when `floor(limit)` calls are already in flight."""
    limit = current_limit(conn, key, policy, now_ms / 1000)
    cap = max(1, math.floor(limit))
    slot = leases.acquire_slot(conn, _slot_prefix(key), holder, cap, max(1, round(policy.slot_ttl_s * 1000)), now_ms)
    in_flight = leases.count_slots(conn, _slot_prefix(key), now_ms)
    conn.execute("UPDATE aimd SET inflight = ? WHERE key = ?", (in_flight, key))
    return slot


def release(
    conn: sqlite3.Connection, key: str, slot: str, holder: str, ok: bool | None, policy: AimdPolicy, now_ms: int
) -> float:
    """Free `slot` and apply the result to the limit (`ok=None`: nothing was sent, the limit is unchanged)."""
    leases.release(conn, slot, holder)
    limit = current_limit(conn, key, policy, now_ms / 1000)
    if ok is not None:
        limit = next_limit(limit, ok, policy)
    in_flight = leases.count_slots(conn, _slot_prefix(key), now_ms)
    conn.execute(
        'UPDATE aimd SET "limit" = ?, inflight = ?, last_change_at = ? WHERE key = ?',
        (limit, in_flight, now_ms / 1000, key),
    )
    return limit


__all__ = [
    "RETRY_WHEN_FULL_MS",
    "SLOT_PREFIX",
    "AimdPolicy",
    "acquire",
    "aimd_key",
    "current_limit",
    "next_limit",
    "release",
]
