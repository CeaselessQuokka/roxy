"""Fleet-wide single-flight: one upstream fetch per cache key across every worker (plan 6.9, fix F1).

What this is
    `SingleFlight.run(key, fetch, ...)`: when many requests miss the same cache key at once, exactly one of them
    (the owner) runs `fetch`; the others (followers) wait and receive the owner's outcome. `try_lead` is the
    background variant used by stale-while-revalidate: lead the fetch if nobody else is fetching, else do nothing.

Why it exists
    v1 coalesced inside one worker only, released every waiter when the owner failed (so all of them went
    upstream at the worst moment), and gave up after 1.5 s although the owner could take 15 s (plan 2.5 root
    cause R5, v1 bug B15). With four workers a popular key that expired cost up to four calls at once, and a
    failing one many more.

How it works
    Two levels, both bounded:
    1. In this process, `_flights[key]` holds one `_Flight`: an asyncio future plus a driver task. Every request
       for the key awaits that future (same-worker followers, plan 6.9 step 1). The driver is its own task, so
       the fetch keeps going for everyone else even if the request that started it is canceled.
    2. Across processes, the driver claims the hot.db lease `sf:<key>` (the key is the cache key id plus the
       auth class) with `expires_ms = now + owner_deadline` (step 2). The lease payload names the flight.
       - The winner (owner) runs `fetch`, which stores the answer in cache.db, then publishes the outcome INTO
         the lease row and lets the row linger for one second (step 3). Outcomes: `stored` (read the entry from
         cache.db), `shared` (status, reason, Retry-After and a small body: failures, and answers that could not
         be stored), `nostore` (too big to share: compete again), `abandoned` (the owner's fetch raised or was
         canceled: compete again).
       - Followers in other processes poll the lease row with a backoff from 25 ms doubling to 250 ms until it
         carries an outcome, expires, or their own wait ends (step 4). They never call upstream after an owner
         failure: they receive its `shared` outcome (step 6).
       - Crash: a row that expired (plus a 250 ms margin for clock steps) without an outcome means the owner
         died. Each follower then tries to claim the lease in one `BEGIN IMMEDIATE` transaction whose UPDATE
         repeats what it read (compare and swap), so exactly one of them takes over and fetches; the rest follow
         the new flight (step 4: "one of them takes over the lease, never all").
       - Timeout: a follower whose wait ends while the owner still works gets `Role.TIMEOUT` and the owner's
         remaining deadline, rounded up, as its Retry-After (step 5).
    Plan 6.9 says the owner keeps its failure record in cache.db; here it rides in the lease row instead, because
    followers poll that row anyway: one read per poll instead of two, and the record goes away with the row
    (retention prunes expired leases after a 60 s grace). If hot.db cannot be used, flights still coalesce inside
    this process and are marked `degraded`; the upstream buckets still pace the calls.

What to read next
    `roxy/cache/service.py` (the fetch functions passed here and how each outcome is served), then
    `roxy/storage/leases.py` (the lease primitive) and `roxy/cache/swr.py` (the background refreshes).
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import math
import secrets
import sqlite3
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any, Final

from roxy.core.clock import Clock
from roxy.storage import leases
from roxy.storage.db import Database, SharedStateUnavailable

log = logging.getLogger(__name__)

LEASE_PREFIX: Final = "sf:"
POLL_START_S: Final = 0.025
"""First follower poll interval (plan 6.9 step 4: 25 ms, doubling)."""
POLL_MAX_S: Final = 0.25
"""Longest follower poll interval (plan 6.9 step 4: up to 250 ms)."""
OUTCOME_LINGER_MS: Final = 1000
"""How long a `stored` or `shared` outcome stays readable after the owner finished. Followers poll at least
every 250 ms, so each of them sees it; a request arriving in that second gets it at once (a one second failure
memo, the plan's "short negative or failure record")."""
TAKEOVER_MARGIN_MS: Final = 250
"""A lease must be expired by this much before a follower takes it over (the wall clock can step a little)."""
SHARE_BODY_MAX: Final = 8192
"""Largest body published in a `shared` outcome (hot.db rows stay small). Bigger answers publish `nostore`."""
MAX_FLIGHTS: Final = 10_000
"""Keys being fetched at once in one process (plan P9). Beyond it a request fetches alone, uncoalesced."""
LEASE_BUSY_TIMEOUT_MS: Final = 1000
"""How long a claim waits for hot.db's write lock before this flight degrades to in-process coalescing."""

_SELECT_LEASE: Final = "SELECT holder, expires_ms, payload_json FROM lease WHERE name = ?"


class OutcomeKind(StrEnum):
    """What the owner of a flight published for its followers."""

    STORED = "stored"  # the answer is in cache.db under `entry_id`
    SHARED = "shared"  # the answer itself (small): failures and answers that could not be stored
    NOSTORE = "nostore"  # an answer too big to share and not stored: followers compete again
    ABANDONED = "abandoned"  # the owner's fetch raised or was canceled: followers compete again


class Role(StrEnum):
    """How this call took part in its flight."""

    OWNER = "owner"  # this call's `fetch` ran
    FOLLOWER = "follower"  # another call's fetch answered this one (same process or another worker)
    TIMEOUT = "timeout"  # the wait ended before the owner finished (plan 6.9 step 5)
    SOLO = "solo"  # coalescing is off (`cache_coalesce` = 0, or the flight table is full): fetched alone
    SKIPPED = "skipped"  # `try_lead` found another flight already running


@dataclass(frozen=True, slots=True)
class FlightOutcome:
    """An owner's result as followers see it (also the JSON stored in the lease row)."""

    kind: OutcomeKind
    status: int | None = None
    reason: str | None = None
    body: bytes = b""
    content_type: str | None = None
    upstream_status: int | None = None
    retry_after_s: int | None = None
    cooldown_s: int | None = None
    entry_id: str | None = None
    stored_at: int | None = None

    def to_doc(self) -> dict[str, Any]:
        """Compact JSON form (short keys keep the hot.db row small; the body is base64)."""
        doc: dict[str, Any] = {"k": self.kind.value}
        fields = (
            ("s", self.status),
            ("r", self.reason),
            ("ct", self.content_type),
            ("us", self.upstream_status),
            ("ra", self.retry_after_s),
            ("cd", self.cooldown_s),
            ("e", self.entry_id),
            ("t", self.stored_at),
        )
        for name, value in fields:
            if value is not None:
                doc[name] = value
        if self.body:
            doc["b"] = base64.b64encode(self.body).decode("ascii")
        return doc

    @classmethod
    def from_doc(cls, doc: object) -> FlightOutcome | None:
        """Parse `to_doc` output; None for anything malformed (treated as "no outcome yet")."""
        if not isinstance(doc, dict):
            return None
        kind_text = doc.get("k")
        if not isinstance(kind_text, str):
            return None
        try:
            kind = OutcomeKind(kind_text)
            body = base64.b64decode(doc["b"], validate=True) if isinstance(doc.get("b"), str) else b""
        except (ValueError, TypeError):
            return None

        def number(name: str) -> int | None:
            value = doc.get(name)
            return value if isinstance(value, int) and not isinstance(value, bool) else None

        def text(name: str) -> str | None:
            value = doc.get(name)
            return value if isinstance(value, str) else None

        return cls(
            kind=kind,
            status=number("s"),
            reason=text("r"),
            body=body,
            content_type=text("ct"),
            upstream_status=number("us"),
            retry_after_s=number("ra"),
            cooldown_s=number("cd"),
            entry_id=text("e"),
            stored_at=number("t"),
        )


@dataclass(frozen=True, slots=True)
class FlightStart:
    """Passed to `fetch`: the flight id and whether this flight began after following another one."""

    flight_id: str
    takeover: bool
    """True when an earlier owner crashed, gave up, or could not share its answer. The fetch should first check
    whether that owner stored a fresh entry after all, before calling upstream."""


@dataclass(frozen=True, slots=True)
class FlightResult[T]:
    """What `run` returns to one caller."""

    role: Role
    outcome: FlightOutcome | None
    value: T | None = None
    """The owner's own value when the owner ran in this process (owners and same-process followers)."""
    waited_s: float = 0.0
    retry_after_s: int | None = None
    """For TIMEOUT: the owner's remaining deadline in whole seconds, at least 1 (plan 6.9 step 5)."""
    degraded: bool = False
    """hot.db could not be used: coalesced only inside this process."""


type FetchFn[T] = Callable[[FlightStart], Awaitable[tuple[T, FlightOutcome]]]
"""The owner's work: fetch, store, and say what followers should do. Returns `(value, outcome)`."""


@dataclass(frozen=True, slots=True)
class _Claim:
    granted: bool
    expires_ms: int
    outcome: FlightOutcome | None = None
    payload: str = ""


@dataclass(slots=True)
class SingleFlightStats:
    owned: int = 0
    followed_local: int = 0
    followed_remote: int = 0
    timeouts: int = 0
    takeovers: int = 0
    degraded: int = 0
    solo: int = 0
    skipped: int = 0


class _Flight[T]:
    """One key being fetched (or followed) in this process."""

    __slots__ = ("future", "lease_expires_ms", "owning", "task")

    def __init__(self, future: asyncio.Future[FlightResult[T]]) -> None:
        self.future = future
        self.owning = asyncio.Event()  # set once this process runs the fetch itself
        self.lease_expires_ms: int | None = None
        self.task: asyncio.Task[None] | None = None


def _new_flight_id() -> str:
    return secrets.token_hex(8)


def _parse_payload(text: str | None) -> FlightOutcome | None:
    if not text:
        return None
    try:
        doc = json.loads(text)
    except ValueError:
        return None
    return FlightOutcome.from_doc(doc.get("o")) if isinstance(doc, dict) else None


def _read_lease(conn: sqlite3.Connection, name: str) -> tuple[int, FlightOutcome | None] | None:
    row = conn.execute(_SELECT_LEASE, (name,)).fetchone()
    if row is None:
        return None
    return int(row[1]), _parse_payload(row[2])


class SingleFlight:
    """Fleet-wide request coalescing (module docstring). One instance per worker, shared by every request."""

    def __init__(
        self,
        hot: Database | None,
        clock: Clock,
        holder: str,
        *,
        poll_start_s: float = POLL_START_S,
        poll_max_s: float = POLL_MAX_S,
        linger_ms: int = OUTCOME_LINGER_MS,
        takeover_margin_ms: int = TAKEOVER_MARGIN_MS,
        max_flights: int = MAX_FLIGHTS,
    ) -> None:
        self._hot = hot
        self._clock = clock
        self._holder = holder
        self._poll_start = poll_start_s
        self._poll_max = poll_max_s
        self._linger_ms = linger_ms
        self._margin_ms = takeover_margin_ms
        self._max_flights = max_flights
        self._flights: dict[str, _Flight[Any]] = {}
        self._degraded_logged = False
        self.stats = SingleFlightStats()

    # ---- public API ----

    async def run[T](
        self,
        key: str,
        fetch: FetchFn[T],
        *,
        owner_deadline_s: float,
        wait_s: float,
        enabled: bool = True,
    ) -> FlightResult[T]:
        """Fetch `key` once for every concurrent caller (module docstring). Exceptions from `fetch` propagate to
        every caller of the same flight in this process; followers elsewhere compete again."""
        started = time.monotonic()
        if not enabled:
            self.stats.solo += 1
            value, outcome = await fetch(FlightStart(_new_flight_id(), takeover=False))
            return FlightResult(Role.SOLO, outcome, value)
        wait_until = started + max(0.0, wait_s)
        takeover = False
        while True:
            flight = self._flights.get(key)
            initiator = flight is None
            if flight is None:
                if len(self._flights) >= self._max_flights:
                    self.stats.solo += 1
                    value, outcome = await fetch(FlightStart(_new_flight_id(), takeover))
                    return FlightResult(Role.SOLO, outcome, value, degraded=True)
                flight = self._start(key, fetch, owner_deadline_s, wait_until, takeover, lead_only=False)
                result: FlightResult[Any] = await asyncio.shield(flight.future)
            else:
                waited = await self._wait_local(flight, wait_until)
                if waited is None:
                    return self._timeout(flight, started)
                result = waited
            waited_s = time.monotonic() - started
            if result.role is Role.OWNER:
                if initiator:
                    self.stats.owned += 1
                    return replace(result, waited_s=waited_s)
                self.stats.followed_local += 1
                return replace(result, role=Role.FOLLOWER, waited_s=waited_s)
            if result.role is Role.FOLLOWER and result.outcome is not None:
                if result.outcome.kind not in (OutcomeKind.NOSTORE, OutcomeKind.ABANDONED):
                    self.stats.followed_remote += 1
                    return replace(result, waited_s=waited_s)
            elif result.role is Role.TIMEOUT and initiator:
                self.stats.timeouts += 1
                return replace(result, waited_s=waited_s)
            # Compete again: the outcome could not be shared, the owner gave up, or our driver's wait (not ours)
            # ended. Bounded by our own wait.
            if time.monotonic() >= wait_until:
                return self._timeout(flight, started)
            takeover = True
            self.stats.takeovers += 1

    async def try_lead[T](self, key: str, fetch: FetchFn[T], *, owner_deadline_s: float) -> FlightResult[T] | None:
        """Run `fetch` as the owner if no flight for `key` is running anywhere; else return None at once."""
        if key in self._flights:
            self.stats.skipped += 1
            return None
        flight: _Flight[T] = self._start(key, fetch, owner_deadline_s, time.monotonic(), False, lead_only=True)
        result = await asyncio.shield(flight.future)
        if result.role is Role.SKIPPED:
            self.stats.skipped += 1
            return None
        self.stats.owned += 1
        return result

    def inflight(self) -> int:
        """Keys being fetched or followed in this process right now."""
        return len(self._flights)

    async def close(self) -> None:
        """Cancel every running flight (worker shutdown) and wait for the cancellations."""
        tasks = [flight.task for flight in self._flights.values() if flight.task is not None]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    # ---- local coordination ----

    def _start[T](
        self,
        key: str,
        fetch: FetchFn[T],
        owner_deadline_s: float,
        wait_until: float,
        takeover: bool,
        *,
        lead_only: bool,
    ) -> _Flight[T]:
        loop = asyncio.get_running_loop()
        flight: _Flight[T] = _Flight(loop.create_future())
        self._flights[key] = flight
        flight.task = loop.create_task(
            self._drive(key, flight, fetch, owner_deadline_s, wait_until, takeover, lead_only),
            name=f"roxy:singleflight:{key[:24]}",
        )
        return flight

    async def _wait_local(self, flight: _Flight[Any], wait_until: float) -> FlightResult[Any] | None:
        """Wait for this process's flight. No time limit while this process owns the fetch; otherwise until
        `wait_until`. None when the wait ended first."""
        future = flight.future
        while not future.done():
            if flight.owning.is_set():
                return await asyncio.shield(future)
            remaining = wait_until - time.monotonic()
            if remaining <= 0:
                return None
            owning = asyncio.ensure_future(flight.owning.wait())
            waiters: set[asyncio.Future[Any]] = {future, owning}
            try:
                await asyncio.wait(waiters, timeout=remaining, return_when=asyncio.FIRST_COMPLETED)
            finally:
                owning.cancel()
        return future.result()

    def _timeout(self, flight: _Flight[Any], started: float) -> FlightResult[Any]:
        self.stats.timeouts += 1
        return FlightResult(
            Role.TIMEOUT,
            None,
            None,
            waited_s=time.monotonic() - started,
            retry_after_s=self._remaining_s(flight.lease_expires_ms),
        )

    def _remaining_s(self, expires_ms: int | None) -> int:
        if expires_ms is None:
            return 1
        return max(1, math.ceil((expires_ms - self._clock.now_ms()) / 1000))

    async def _drive[T](
        self,
        key: str,
        flight: _Flight[T],
        fetch: FetchFn[T],
        owner_deadline_s: float,
        wait_until: float,
        takeover: bool,
        lead_only: bool,
    ) -> None:
        try:
            result = await self._drive_inner(key, flight, fetch, owner_deadline_s, wait_until, takeover, lead_only)
        except asyncio.CancelledError:
            if not flight.future.done():
                flight.future.cancel()
            raise
        except Exception as exc:  # handed to every waiter of this flight, which re-raise it
            if not flight.future.done():
                flight.future.set_exception(exc)
        else:
            if not flight.future.done():
                flight.future.set_result(result)
        finally:
            if self._flights.get(key) is flight:
                del self._flights[key]

    async def _drive_inner[T](
        self,
        key: str,
        flight: _Flight[T],
        fetch: FetchFn[T],
        owner_deadline_s: float,
        wait_until: float,
        takeover: bool,
        lead_only: bool,
    ) -> FlightResult[T]:
        name = LEASE_PREFIX + key
        ttl_ms = max(1, int(owner_deadline_s * 1000))
        flight_id = _new_flight_id()
        while True:
            claim = await self._claim(name, flight_id, ttl_ms)
            if claim is None:  # hot.db unavailable: coalesce inside this process only
                self.stats.degraded += 1
                flight.owning.set()
                value, outcome = await fetch(FlightStart(flight_id, takeover))
                return FlightResult(Role.OWNER, outcome, value, degraded=True)
            flight.lease_expires_ms = claim.expires_ms
            if claim.granted:
                flight.owning.set()
                return await self._own(name, flight_id, claim.payload, fetch, FlightStart(flight_id, takeover))
            if lead_only:
                return FlightResult(Role.SKIPPED, None, None)
            if claim.outcome is not None:  # a flight that just finished: its outcome answers us too
                return FlightResult(Role.FOLLOWER, claim.outcome, None)
            followed = await self._follow(name, flight, wait_until)
            if followed is not None:
                return followed
            flight_id, takeover = _new_flight_id(), True  # the owner died or its row vanished: compete for it

    # ---- the lease ----

    async def _claim(self, name: str, flight_id: str, ttl_ms: int) -> _Claim | None:
        """Claim the lease or learn who holds it. None when hot.db cannot be used (degraded)."""
        if self._hot is None:
            return None
        now_ms = self._clock.now_ms()

        def run(conn: sqlite3.Connection) -> _Claim:
            row = conn.execute(_SELECT_LEASE, (name,)).fetchone()
            if row is not None:
                expires = int(row[1])
                outcome = _parse_payload(row[2])
                if outcome is not None:
                    if expires > now_ms:
                        return _Claim(False, expires, outcome)
                elif expires + self._margin_ms > now_ms:
                    return _Claim(False, expires)  # a flight in progress (or just expired: wait a little more)
            payload = json.dumps({"f": flight_id}, separators=(",", ":"))
            # Insert, or take over an expired row with a compare and swap on its epoch (storage/leases.py).
            grant = leases.acquire(conn, name, self._holder, ttl_ms, now_ms, payload)
            if grant is None:
                current = _read_lease(conn, name)
                return _Claim(False, current[0] if current else now_ms, current[1] if current else None)
            return _Claim(True, grant.expires_ms, payload=payload)

        try:
            claim = await self._hot.write(run, busy_timeout_ms=LEASE_BUSY_TIMEOUT_MS)
        except (SharedStateUnavailable, sqlite3.Error) as exc:
            if not self._degraded_logged:
                log.warning("singleflight_degraded", extra={"fields": {"error": str(exc)[:200]}})
                self._degraded_logged = True
            return None
        if self._degraded_logged:
            log.info("singleflight_recovered")
            self._degraded_logged = False
        return claim

    async def _own[T](
        self, name: str, flight_id: str, payload: str, fetch: FetchFn[T], start: FlightStart
    ) -> FlightResult[T]:
        try:
            value, outcome = await fetch(start)
        except BaseException:
            await self._publish_quietly(name, payload, flight_id, FlightOutcome(OutcomeKind.ABANDONED), linger=False)
            raise
        linger = outcome.kind in (OutcomeKind.STORED, OutcomeKind.SHARED)
        await self._publish_quietly(name, payload, flight_id, outcome, linger=linger)
        return FlightResult(Role.OWNER, outcome, value)

    async def _publish_quietly(
        self, name: str, payload: str, flight_id: str, outcome: FlightOutcome, *, linger: bool
    ) -> None:
        """Write the outcome into our lease row (only if it is still ours). Failures are logged: followers then
        wait for the lease to expire and one of them takes over."""
        if self._hot is None:
            return
        # A lingering outcome stays valid briefly; any other outcome expires the row outright (0), so the next
        # claim takes it over at once even if the wall clock just stepped back.
        expires_ms = self._clock.now_ms() + self._linger_ms if linger else 0
        new_payload = json.dumps({"f": flight_id, "o": outcome.to_doc()}, separators=(",", ":"))

        def run(conn: sqlite3.Connection) -> int:
            return conn.execute(
                "UPDATE lease SET expires_ms = ?, payload_json = ? WHERE name = ? AND holder = ? AND payload_json = ?",
                (expires_ms, new_payload, name, self._holder, payload),
            ).rowcount

        try:
            # Shielded: a shutdown cancel during the write must not leave followers waiting for the full deadline.
            await asyncio.shield(self._hot.write(run, busy_timeout_ms=LEASE_BUSY_TIMEOUT_MS))
        except (SharedStateUnavailable, sqlite3.Error, asyncio.CancelledError) as exc:
            log.warning("singleflight_publish_failed", extra={"fields": {"lease": name[:40], "error": str(exc)[:200]}})

    async def _follow[T](self, name: str, flight: _Flight[T], wait_until: float) -> FlightResult[T] | None:
        """Poll the lease row with backoff (plan 6.9 step 4). None means "compete for the lease now"."""
        delay = self._poll_start
        while True:
            remaining = wait_until - time.monotonic()
            if remaining <= 0:
                return FlightResult(Role.TIMEOUT, None, None, retry_after_s=self._remaining_s(flight.lease_expires_ms))
            await asyncio.sleep(min(delay, remaining))
            delay = min(delay * 2, self._poll_max)
            if self._hot is None:
                return None
            try:
                row = await self._hot.read(lambda conn: _read_lease(conn, name))
            except (SharedStateUnavailable, sqlite3.Error):
                continue  # cannot see the row right now; keep waiting until our deadline
            if row is None:
                return None
            expires_ms, outcome = row
            flight.lease_expires_ms = expires_ms
            if outcome is not None:
                return FlightResult(Role.FOLLOWER, outcome, None)
            if expires_ms + self._margin_ms <= self._clock.now_ms():
                return None  # expired without an outcome: the owner crashed


__all__ = [
    "LEASE_PREFIX",
    "OUTCOME_LINGER_MS",
    "SHARE_BODY_MAX",
    "FetchFn",
    "FlightOutcome",
    "FlightResult",
    "FlightStart",
    "OutcomeKind",
    "Role",
    "SingleFlight",
    "SingleFlightStats",
]
