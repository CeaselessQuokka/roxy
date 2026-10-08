"""Circuit breakers per endpoint and egress, and per host and egress, shared by every worker (plan 7.10).

What this is
    A three-state machine (closed, open, half-open) stored in hot.db's `breaker` table, with pure transition
    functions (`record_failure`, `record_success`, `trip`, `probe_result`), the admission rule (`admission`), and
    the fleet-wide half-open probe lease.

Why it exists
    When an endpoint keeps failing (5xx, timeouts) or Roblox says 429, sending more calls only adds load and makes
    callers wait for answers that will not come. A breaker "opens" after enough failures: for a while no call is
    made at all (callers get stale data or a 429 with `Retry-After`), then exactly one probe call tests whether the
    endpoint recovered. v1 had nothing like it (plan 2.5, F8).

How it works
    - Closed: calls flow. Failures within a window of `breaker_window_s` (30 s) are counted. The breaker opens
      when there are at least `breaker_failure_threshold` (5) failures AND the failure ratio exceeds
      `breaker_failure_ratio` (0.5). A Roblox 429 opens it at once, for the Retry-After duration.
    - Open: no calls until `half_open_at`. Then it is half-open: exactly one worker in the fleet may send a probe,
      because the probe needs the lease `brk:<key>`, taken inside the reservation transaction (`buckets.reserve`).
    - Half-open: the probe's success closes the breaker; its failure reopens it with the open time doubled
      (capped at 600 s).
    - Keys: `endpoint:<template>:<egress>` and `host:<host>:<egress>`. For the rotator, a 429 counts as a failure
      only under the distinct-exit rule of `cooldowns.py` (one burned exit is not the endpoint's fault).
    - Write cost: a success writes nothing while a breaker is closed with no failures in its window (the common
      case), so a healthy endpoint costs no extra transaction. Successes are counted only once a window holds a
      failure, so the ratio compares failures with the successes seen since the first failure; this errs toward
      opening slightly sooner, never toward hammering a failing endpoint.
    - Times: `opened_at`, `half_open_at` and `window_start` are wall clock seconds stored as REAL (sub-second
      precision; the retention job compares `window_start` with whole seconds, which works the same).

What to read next
    `roxy/upstream/effects.py` (where results are applied), `roxy/upstream/cooldowns.py` (the sibling mechanism for
    429s), and `roxy/upstream/service.py` (`_guards`, where admission is checked).
"""

from __future__ import annotations

import dataclasses
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

from roxy.core.reasons import Egress
from roxy.storage import leases

MAX_OPEN_S: Final = 600.0
"""Plan 7.10: a failed probe doubles the open time, capped at 600 s."""

PROBE_LEASE_PREFIX: Final = "brk:"


class BreakerState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass(frozen=True, slots=True)
class BreakerPolicy:
    """The breaker settings of plan 15.3 C."""

    failure_threshold: int = 5
    window_s: float = 30.0
    failure_ratio: float = 0.5
    open_s: float = 30.0
    max_open_s: float = MAX_OPEN_S
    probe_ttl_s: float = 20.0  # how long a half-open probe lease lives if its holder never reports back

    @classmethod
    def from_settings(cls, settings: Any) -> BreakerPolicy:
        return cls(
            failure_threshold=int(settings.get("breaker_failure_threshold")),
            window_s=float(settings.get("breaker_window_s")),
            failure_ratio=float(settings.get("breaker_failure_ratio")),
            open_s=float(settings.get("breaker_open_s")),
            probe_ttl_s=float(settings.get("request_timeout")) + 5.0,
        )


@dataclass(frozen=True, slots=True)
class BreakerRow:
    """One `breaker` row. `state` is the stored state; see `effective_state` for half-open."""

    key: str
    state: BreakerState = BreakerState.CLOSED
    opened_at: float | None = None
    half_open_at: float | None = None
    failures: int = 0
    successes: int = 0
    window_start: float = 0.0

    @property
    def open_duration_s(self) -> float:
        if self.opened_at is None or self.half_open_at is None:
            return 0.0
        return max(0.0, self.half_open_at - self.opened_at)


@dataclass(frozen=True, slots=True)
class Transition:
    """A state change, recorded as an event (plan P4)."""

    key: str
    from_state: BreakerState
    to_state: BreakerState
    reason: str
    open_s: float = 0.0


def breaker_keys(host: str, template: str, egress: Egress | str) -> tuple[str, str]:
    """The endpoint and host breaker keys of one call."""
    value = Egress(egress).value
    return f"endpoint:{template}:{value}", f"host:{host}:{value}"


def effective_state(row: BreakerRow | None, now_s: float) -> BreakerState:
    """Closed, open, or half-open (an open breaker whose `half_open_at` has passed)."""
    if row is None or row.state is BreakerState.CLOSED:
        return BreakerState.CLOSED
    if row.half_open_at is None or now_s >= row.half_open_at:
        return BreakerState.HALF_OPEN  # (a row without a reopening time can only come from a hand edit: probe it)
    return BreakerState.OPEN


@dataclass(frozen=True, slots=True)
class Admission:
    """May a call pass this breaker now?"""

    allowed: bool
    needs_probe_lease: bool = False  # half-open: allowed only for the one holder of the probe lease
    retry_in_s: float = 0.0


def admission(row: BreakerRow | None, now_s: float) -> Admission:
    state = effective_state(row, now_s)
    if state is BreakerState.CLOSED:
        return Admission(True)
    if state is BreakerState.HALF_OPEN:
        return Admission(True, needs_probe_lease=True)
    reopens_at = row.half_open_at if row is not None and row.half_open_at is not None else now_s
    return Admission(False, retry_in_s=max(0.0, reopens_at - now_s))


def _rolled(row: BreakerRow, now_s: float, policy: BreakerPolicy) -> BreakerRow:
    """Start a new counting window when the old one has ended."""
    if row.window_start + policy.window_s <= now_s:
        return dataclasses.replace(row, failures=0, successes=0, window_start=now_s)
    return row


def _opened(row: BreakerRow, now_s: float, open_s: float) -> BreakerRow:
    return dataclasses.replace(
        row,
        state=BreakerState.OPEN,
        opened_at=now_s,
        half_open_at=now_s + max(0.0, open_s),
        failures=0,
        successes=0,
        window_start=now_s,
    )


def _closed(key: str, now_s: float) -> BreakerRow:
    return BreakerRow(key=key, state=BreakerState.CLOSED, window_start=now_s)


def record_failure(
    row: BreakerRow | None, key: str, now_s: float, policy: BreakerPolicy
) -> tuple[BreakerRow, Transition | None]:
    """A failed call (5xx, timeout, connect error, a counted 429) that was NOT the half-open probe."""
    current = row or BreakerRow(key=key, window_start=now_s)
    state = effective_state(current, now_s)
    if state is not BreakerState.CLOSED:
        return current, None  # a request that was already in flight when the breaker opened: nothing new
    current = _rolled(current, now_s, policy)
    failures = current.failures + 1
    current = dataclasses.replace(current, failures=failures)
    ratio = failures / (failures + current.successes)
    if failures >= policy.failure_threshold and ratio > policy.failure_ratio:
        opened = _opened(current, now_s, policy.open_s)
        return opened, Transition(key, BreakerState.CLOSED, BreakerState.OPEN, "failure_threshold", policy.open_s)
    return current, None


def record_success(row: BreakerRow | None, now_s: float, policy: BreakerPolicy) -> BreakerRow | None:
    """A normal answer that was not the half-open probe. Returns the row to write, or None when nothing changes."""
    if row is None or effective_state(row, now_s) is not BreakerState.CLOSED:
        return None
    current = _rolled(row, now_s, policy)
    if current.failures == 0:
        return current if current != row else None  # the window rolled: write the reset once, else nothing
    return dataclasses.replace(current, successes=current.successes + 1)


def trip(row: BreakerRow | None, key: str, now_s: float, open_s: float) -> tuple[BreakerRow, Transition | None]:
    """Open at once (a Roblox 429) for `open_s`; an already open breaker keeps the later reopening time."""
    current = row or BreakerRow(key=key, window_start=now_s)
    state = effective_state(current, now_s)
    if state is BreakerState.OPEN and current.half_open_at is not None and current.half_open_at >= now_s + open_s:
        return current, None
    opened = _opened(current, now_s, open_s)
    if state is BreakerState.OPEN:
        return opened, None  # extended, same state
    return opened, Transition(key, state, BreakerState.OPEN, "rate_limited", open_s)


def probe_result(
    row: BreakerRow | None, key: str, now_s: float, failed: bool, policy: BreakerPolicy
) -> tuple[BreakerRow, Transition | None]:
    """The half-open probe finished: success closes; failure reopens with the open time doubled (max 600 s)."""
    current = row or BreakerRow(key=key, window_start=now_s)
    previous = effective_state(current, now_s)
    if not failed:
        closed = _closed(key, now_s)
        if previous is BreakerState.CLOSED:
            return closed, None
        return closed, Transition(key, previous, BreakerState.CLOSED, "probe_succeeded")
    doubled = min(policy.max_open_s, max(policy.open_s, current.open_duration_s * 2))
    reopened = _opened(current, now_s, doubled)
    return reopened, Transition(key, previous, BreakerState.OPEN, "probe_failed", doubled)


# --- hot.db ----------------------------------------------------------------------------------------------------------


def _to_row(raw: Any) -> BreakerRow:
    state = str(raw[1]) if raw[1] in {s.value for s in BreakerState} else BreakerState.CLOSED.value
    return BreakerRow(
        key=str(raw[0]),
        state=BreakerState(state),
        opened_at=None if raw[2] is None else float(raw[2]),
        half_open_at=None if raw[3] is None else float(raw[3]),
        failures=int(raw[4]),
        successes=int(raw[5]),
        window_start=float(raw[6]),
    )


def load(conn: sqlite3.Connection, keys: Iterable[str]) -> dict[str, BreakerRow]:
    """The stored rows for `keys`."""
    wanted = list(dict.fromkeys(keys))
    if not wanted:
        return {}
    marks = ", ".join("?" for _ in wanted)
    sql = f"SELECT key, state, opened_at, half_open_at, failures, successes, window_start FROM breaker WHERE key IN ({marks})"  # noqa: E501, S608 - only placeholders are interpolated
    rows = conn.execute(sql, wanted).fetchall()
    return {str(raw[0]): _to_row(raw) for raw in rows}


def save(conn: sqlite3.Connection, row: BreakerRow) -> None:
    conn.execute(
        "INSERT INTO breaker (key, state, opened_at, half_open_at, failures, successes, window_start) "
        "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(key) DO UPDATE SET state = excluded.state, "
        "opened_at = excluded.opened_at, half_open_at = excluded.half_open_at, failures = excluded.failures, "
        "successes = excluded.successes, window_start = excluded.window_start",
        (
            row.key,
            row.state.value,
            row.opened_at,
            row.half_open_at,
            row.failures,
            row.successes,
            row.window_start,
        ),
    )


def probe_lease_name(key: str) -> str:
    return PROBE_LEASE_PREFIX + key


def try_acquire_probe(conn: sqlite3.Connection, key: str, holder: str, now_ms: int, ttl_s: float) -> bool:
    """Take the fleet-wide half-open probe lease for `key` (inside the reservation transaction)."""
    grant = leases.acquire(conn, probe_lease_name(key), holder, max(1, round(ttl_s * 1000)), now_ms)
    return grant is not None


def probe_lease_remaining_s(conn: sqlite3.Connection, key: str, now_ms: int) -> float:
    info = leases.holder_epoch(conn, probe_lease_name(key))
    if info is None:
        return 0.0
    return max(0.0, (info[2] - now_ms) / 1000)


def release_probe(conn: sqlite3.Connection, key: str, holder: str) -> None:
    leases.release(conn, probe_lease_name(key), holder, delete=True)


def reset_all(conn: sqlite3.Connection) -> int:
    """Delete every breaker and probe lease (the "reset upstream state" action; buckets are never touched)."""
    deleted = conn.execute("DELETE FROM breaker").rowcount
    conn.execute(
        "DELETE FROM lease WHERE name >= ? AND name < ?", (PROBE_LEASE_PREFIX, PROBE_LEASE_PREFIX + "\U0010ffff")
    )
    return int(deleted)


def snapshot(conn: sqlite3.Connection, now_s: float, limit: int = 500) -> list[dict[str, Any]]:
    """Breakers that are not plainly closed and idle, for the Upstream page Breakers card."""
    rows = conn.execute(
        "SELECT key, state, opened_at, half_open_at, failures, successes, window_start FROM breaker "
        "WHERE state != 'closed' OR failures > 0 ORDER BY window_start DESC LIMIT ?",
        (max(1, limit),),
    ).fetchall()
    out: list[dict[str, Any]] = []
    for raw in rows:
        row = _to_row(raw)
        state = effective_state(row, now_s)
        out.append(
            {
                "key": row.key,
                "state": state.value,
                "failures": row.failures,
                "successes": row.successes,
                "reopens_in_s": max(0.0, (row.half_open_at or now_s) - now_s) if state is BreakerState.OPEN else 0.0,
                "open_s": row.open_duration_s,
            }
        )
    return out


__all__ = [
    "MAX_OPEN_S",
    "PROBE_LEASE_PREFIX",
    "Admission",
    "BreakerPolicy",
    "BreakerRow",
    "BreakerState",
    "Transition",
    "admission",
    "breaker_keys",
    "effective_state",
    "load",
    "probe_lease_name",
    "probe_lease_remaining_s",
    "probe_result",
    "record_failure",
    "record_success",
    "release_probe",
    "reset_all",
    "save",
    "snapshot",
    "trip",
    "try_acquire_probe",
]
