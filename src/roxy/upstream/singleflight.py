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
    2. Across processes, the hot.db lease `sf:<key>` (the key is the cache key id plus the auth class) with
       `expires_ms = now + owner_deadline` (step 2). The lease payload names the flight.
       - Look first (one read, no write lock): an outcome that still lingers answers at once, and a live lease
         without one is another worker fetching, so this call follows it.
       - Otherwise compete for the lease. In hooked mode (`hooked=True`, what the cache uses) the fetch receives
         `FlightStart.lease`, a hook the upstream service runs INSIDE its bucket reservation transaction: the
         lease insert and the bucket slots commit together or not at all (plan 6.3 and 7.3, one hot.db write per
         miss). A hook that finds another live flight makes the upstream raise `SingleFlightLost` before anything
         is reserved; the fetch turns it into `LeaseLost` and this call follows that flight. Without `hooked`
         the lease is claimed in a transaction of its own before `fetch` runs (fetches with no reservation).
       - The owner's answer reaches its caller and its same-process followers as soon as the fetch returns. What
         other workers need is finished afterwards by a bounded background tail: the fetch may return a
         `Deferred` outcome (the cache stores the answer in cache.db there), then the outcome is written INTO
         the lease row and lingers for one second (step 3). A locked cache.db or a busy hot.db therefore never
         delays an answer (findings CACHE-WAIT and SF-ORPHAN; C7: the cache is disposable). The flight stays
         joinable in this process until its tail is done or the linger ends.
       - Outcomes: `stored` (read the entry from cache.db), `shared` (status, reason, Retry-After and the body:
         inline when small, else in a short-lived cache.db handoff row named by `entry_id`), `nostore` (nothing
         could be shared: compete again), `private` (the answer belongs to the owner's own request alone, plan
         6.9 and C2: every other request competes again and makes its own call), `abandoned` (the owner's fetch
         raised or was canceled: compete again).
       - Publishing retries with a backoff until it lands or the lease would have expired anyway. Meanwhile this
         process knows the flight is over, so a new request here may take the lease over at once.
       - Followers in other processes poll the lease row with a backoff from 25 ms doubling to 250 ms until it
         carries an outcome, expires, or their own wait ends (step 4). They never call upstream after an owner
         failure: they receive its `shared` outcome (step 6).
       - A follower whose lease row still says "in progress" after `STORE_CHECK_AFTER_S` also looks where the
         owner stores its answer (`check`, the cache's cache.db read: plan 6.9 step 4 polls cache.db), every
         `STORE_CHECK_EVERY_S` and once more when its wait ends. The owner stores before it publishes, so an owner
         whose publish never landed (hot.db busy, then its worker stopped or was killed) still answers the
         followers that were waiting for it (finding mp-12), instead of leaving them on `coalesce_timeout`.
       - Crash: a row that expired (plus a 250 ms margin for clock steps) without an outcome means the owner
         died. The followers then compete again; the lease insert repeats what it read (compare and swap inside
         `BEGIN IMMEDIATE`), so exactly one of them takes over and fetches; the rest follow the new flight
         (step 4: "one of them takes over the lease, never all").
       - Timeout: a follower whose wait ends while the owner still works gets `Role.TIMEOUT` and the owner's
         remaining deadline, rounded up, as its Retry-After (step 5).
    Plan 6.9 says the owner keeps its failure record in cache.db; here it rides in the lease row instead, because
    followers poll that row anyway: one read per poll instead of two, and the record goes away with the row
    (retention prunes expired leases after a 60 s grace). If hot.db cannot be used, flights still coalesce inside
    this process and are marked `degraded`; the upstream buckets still pace the calls.

What to read next
    `roxy/cache/service.py` (the fetch functions passed here and how each outcome is served), then
    `roxy/upstream/buckets.py` (`reserve`, where the hook runs), `roxy/storage/leases.py` (the lease primitive)
    and `roxy/cache/swr.py` (the background refreshes).
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
from collections.abc import Awaitable, Callable, Coroutine
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
memo, the plan's "short negative or failure record"). The flight also stays joinable in its own process for this
long (or until its tail is done)."""
TAKEOVER_MARGIN_MS: Final = 250
"""A lease must be expired by this much before a follower takes it over (the wall clock can step a little)."""
SHARE_BODY_MAX: Final = 8192
"""Largest body published inline in a `shared` outcome (hot.db rows stay small). Bigger answers go through a
cache.db handoff row (`FlightOutcome.entry_id`), or publish `nostore` when even that is not possible."""
MAX_FLIGHTS: Final = 10_000
"""Keys being fetched at once in one process (plan P9). Beyond it a request fetches alone, uncoalesced."""
MAX_TAILS: Final = 1024
"""Background tails (deferred store plus outcome publish) running at once in one process (plan P9). Beyond it a
tail runs inside its flight's driver and publishes once, without retries (bounded by `MAX_FLIGHTS`)."""
LEASE_BUSY_TIMEOUT_MS: Final = 1000
"""How long one lease write waits for hot.db's write lock before giving up (the claim degrades to in-process
coalescing; a publish is retried)."""
PUBLISH_RETRY_START_S: Final = 0.1
PUBLISH_RETRY_MAX_S: Final = 1.0
"""Backoff between attempts to publish an outcome that hot.db refused (busy), until the lease would expire."""
TAIL_FINISH_TIMEOUT_S: Final = 10.0
"""Upper bound on a deferred outcome (the cache.db store plus a handoff write, each with its own busy budget)."""
STORE_CHECK_AFTER_S: Final = 1.0
"""How long a follower waits on a live lease before it also looks in the owner's store (`check`). An owner that
is alive publishes within milliseconds of its store, so a flight shorter than this costs followers no extra read."""
STORE_CHECK_EVERY_S: Final = 0.5
"""How often a follower looks in the owner's store after `STORE_CHECK_AFTER_S` (one read per waiting key and
worker: same-worker requests share one follower loop)."""

_SELECT_LEASE: Final = "SELECT holder, expires_ms, payload_json FROM lease WHERE name = ?"


class OutcomeKind(StrEnum):
    """What the owner of a flight published for its followers."""

    STORED = "stored"  # the answer is in cache.db under `entry_id`
    SHARED = "shared"  # the answer itself: failures and answers that could not be stored (body inline or handoff)
    NOSTORE = "nostore"  # an answer that could not be shared at all: followers compete again
    PRIVATE = "private"  # the answer belongs to the owner's own request (plan 6.9): everyone else competes again
    ABANDONED = "abandoned"  # the owner's fetch raised or was canceled: followers compete again


COMPETE_AGAIN: Final = frozenset({OutcomeKind.NOSTORE, OutcomeKind.PRIVATE, OutcomeKind.ABANDONED})
"""Outcomes that answer nobody but the owner: a follower that receives one competes for the lease again."""
LINGERING: Final = frozenset({OutcomeKind.STORED, OutcomeKind.SHARED})
"""Outcomes that stay readable for `OUTCOME_LINGER_MS`; any other outcome expires its row at once."""


class Role(StrEnum):
    """How this call took part in its flight."""

    OWNER = "owner"  # this call's `fetch` ran
    FOLLOWER = "follower"  # another call's fetch answered this one (same process or another worker)
    TIMEOUT = "timeout"  # the wait ended before the owner finished (plan 6.9 step 5)
    SOLO = "solo"  # coalescing is off (`cache_coalesce` = 0, or the flight table is full): fetched alone
    SKIPPED = "skipped"  # `try_lead` found another flight already running


class LeaseLost(Exception):
    """A hooked fetch found the lease held by another flight (the upstream raised `SingleFlightLost`).

    The fetch function raises this; `SingleFlight` catches it and follows the flight that won. Nothing was
    reserved or sent upstream.
    """


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
    """`stored`: the cache entry. `shared` with an empty body: the cache.db handoff row that holds the body."""
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


class Deferred:
    """An outcome the owner finishes after its own caller was answered (the cache.db store, a handoff row).

    `finish()` runs in the flight's background tail; its result is what followers in other workers receive.
    """

    __slots__ = ("finish",)

    def __init__(self, finish: Callable[[], Awaitable[FlightOutcome]]) -> None:
        self.finish = finish


class FlightLease:
    """The single-flight lease insert, run by the upstream inside its reservation transaction (hooked mode).

    `hook(conn, now_ms)` returns True when this flight now holds the lease (inserted, or taken over from an
    expired or finished flight) and False when another flight holds it; the upstream then raises
    `SingleFlightLost` and reserves nothing (`upstream/buckets.py: LeaseHook`). `claim_alone()` runs the same
    insert in a hot.db transaction of its own, for a fetch that has no reservation transaction (test doubles).
    It runs on the database writer thread: it only reads the values captured when it was made.
    """

    __slots__ = (
        "_clock",
        "_hot",
        "expires_ms",
        "finished",
        "granted",
        "holder",
        "margin_ms",
        "name",
        "payload",
        "ttl_ms",
    )

    def __init__(
        self,
        *,
        name: str,
        holder: str,
        payload: str,
        ttl_ms: int,
        margin_ms: int,
        finished: str | None,
        hot: Database | None,
        clock: Clock,
    ) -> None:
        self.name = name
        self.holder = holder
        self.payload = payload
        self.ttl_ms = ttl_ms
        self.margin_ms = margin_ms
        self.finished = finished  # the payload of a finished flight of ours whose outcome is still on its way
        self.granted = False
        self.expires_ms = 0
        self._hot = hot
        self._clock = clock

    def __call__(self, conn: sqlite3.Connection, now_ms: int) -> bool:
        row = conn.execute(_SELECT_LEASE, (self.name,)).fetchone()
        if row is not None:
            holder, expires, text = str(row[0]), int(row[1]), row[2]
            if holder == self.holder and text == self.payload:  # already ours (a second reservation of this fetch)
                self.granted, self.expires_ms = True, expires
                return True
            if not (holder == self.holder and text is not None and text == self.finished):
                outcome = _parse_payload(text)
                if outcome is not None and expires > now_ms:
                    return False  # a finished flight's outcome lingers: it answers this request
                if outcome is None and expires + self.margin_ms > now_ms:
                    return False  # another flight is in progress
        # Insert, or take over an expired (or our own finished) row with a compare and swap (storage/leases.py).
        grant = leases.acquire(conn, self.name, self.holder, self.ttl_ms, now_ms, self.payload)
        if grant is None:
            return False
        self.granted, self.expires_ms = True, grant.expires_ms
        return True

    async def claim_alone(self) -> bool:
        """Run the hook in one hot.db write transaction of its own. True when hot.db is unavailable (the caller
        proceeds uncoalesced across workers, like a degraded flight)."""
        if self._hot is None:
            return True
        now_ms = self._clock.now_ms()
        try:
            return bool(await self._hot.write(lambda conn: self(conn, now_ms), busy_timeout_ms=LEASE_BUSY_TIMEOUT_MS))
        except (SharedStateUnavailable, sqlite3.Error):
            return True


@dataclass(frozen=True, slots=True)
class FlightStart:
    """Passed to `fetch`: the flight id, whether this flight began after following another one, and the lease
    hook (hooked mode only) to hand to the upstream."""

    flight_id: str
    takeover: bool
    """True when an earlier owner crashed, gave up, or could not share its answer. The fetch should first check
    whether that owner stored a fresh entry after all, before calling upstream."""
    lease: FlightLease | None = None
    """Hooked mode: pass this as `lease=` to `UpstreamService.fetch` and raise `LeaseLost` on `SingleFlightLost`.
    None when there is no lease to take (coalescing off, the flight table full, claim mode)."""


@dataclass(frozen=True, slots=True)
class FlightResult[T]:
    """What `run` returns to one caller."""

    role: Role
    outcome: FlightOutcome | None
    """The outcome followers in other workers get. None for an owner whose outcome is still being finished."""
    value: T | None = None
    """The owner's own value when the owner ran in this process (owners and same-process followers)."""
    waited_s: float = 0.0
    retry_after_s: int | None = None
    """For TIMEOUT: the owner's remaining deadline in whole seconds, at least 1 (plan 6.9 step 5)."""
    degraded: bool = False
    """hot.db could not be used: coalesced only inside this process."""


type FetchFn[T] = Callable[[FlightStart], Awaitable[tuple[T, FlightOutcome | Deferred]]]
"""The owner's work: fetch and say what followers should get. Returns `(value, outcome or Deferred)`."""

type StoreCheck = Callable[[bool], Awaitable[FlightOutcome | None]]
"""A follower's look at where the owner stores its answer, called with `final` (True for the last look before a
timeout). Returns a `stored` or `shared` outcome for an answer found there, else None. Never called by owners."""

type _Tail = Callable[[bool], Coroutine[Any, Any, None]]
"""A flight's background tail, called with `retry` (False when the tail table is full)."""


@dataclass(frozen=True, slots=True)
class _Claim:
    granted: bool
    expires_ms: int
    outcome: FlightOutcome | None = None
    payload: str = ""


@dataclass(frozen=True, slots=True)
class _Publish:
    """Where an owner publishes its outcome: the lease row it holds."""

    name: str
    payload: str
    flight_id: str
    expires_ms: int


@dataclass(frozen=True, slots=True)
class _Seen:
    """One look at a lease row: `free` (compete), `live` (another flight runs), `outcome` (a lingering one)."""

    state: str
    expires_ms: int = 0
    outcome: FlightOutcome | None = None
    degraded: bool = False


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
    leases_lost: int = 0
    private: int = 0
    publish_retries: int = 0
    publish_failures: int = 0
    tails_inline: int = 0
    store_answers: int = 0
    """Followers answered from the owner's store (`check`) because its outcome was not published in time."""


class _Flight[T]:
    """One key being fetched (or followed) in this process."""

    __slots__ = ("future", "joinable_until_ms", "lease_expires_ms", "owning", "task")

    def __init__(self, future: asyncio.Future[FlightResult[T]]) -> None:
        self.future = future
        self.owning = asyncio.Event()  # set while this process runs the fetch itself
        self.lease_expires_ms: int | None = None
        self.joinable_until_ms: int | None = None  # set once answered: late arrivals share it until then
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


def _flight_payload(flight_id: str) -> str:
    return json.dumps({"f": flight_id}, separators=(",", ":"))


def _consume_result(task: asyncio.Future[Any]) -> None:
    """Done callback of a shielded write: mark its exception as seen. When the awaiting side was canceled (worker
    shutdown), nobody else reads it, and asyncio would log "Task exception was never retrieved" at error level. A
    publish that fails then changes nothing: the row still looks in progress, and followers find the answer in the
    owner's store (`check`) or take the lease over once it expires."""
    if not task.cancelled():
        task.exception()


def _read_row(conn: sqlite3.Connection, name: str) -> tuple[str, int, str | None] | None:
    row = conn.execute(_SELECT_LEASE, (name,)).fetchone()
    if row is None:
        return None
    return str(row[0]), int(row[1]), row[2]


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
        max_tails: int = MAX_TAILS,
        store_check_after_s: float = STORE_CHECK_AFTER_S,
        store_check_every_s: float = STORE_CHECK_EVERY_S,
    ) -> None:
        self._hot = hot
        self._clock = clock
        self._holder = holder
        self._poll_start = poll_start_s
        self._poll_max = poll_max_s
        self._check_after = store_check_after_s
        self._check_every = store_check_every_s
        self._linger_ms = linger_ms
        self._margin_ms = takeover_margin_ms
        self._max_flights = max_flights
        self._max_tails = max_tails
        self._flights: dict[str, _Flight[Any]] = {}
        self._tails: set[asyncio.Task[None]] = set()
        self._unpublished: dict[str, str] = {}  # lease name -> payload of a finished flight of ours, not yet published
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
        hooked: bool = False,
        check: StoreCheck | None = None,
    ) -> FlightResult[T]:
        """Fetch `key` once for every concurrent caller (module docstring). Exceptions from `fetch` propagate to
        every caller of the same flight in this process; followers elsewhere compete again. `check` is where a
        follower looks when the owner's outcome is late (the owner's store; module docstring)."""
        started = time.monotonic()
        if not enabled:
            self.stats.solo += 1
            return await self._solo(fetch, takeover=False, degraded=False)
        wait_until = started + max(0.0, wait_s)
        takeover = False
        while True:
            flight = self._flights.get(key)
            if flight is not None and not self._joinable(flight):
                flight = None  # answered longer ago than the linger: a new request starts a new flight
            initiator = flight is None
            if flight is None:
                if len(self._flights) >= self._max_flights and key not in self._flights:
                    self.stats.solo += 1
                    return await self._solo(fetch, takeover, degraded=True)
                flight = self._start(
                    key, fetch, owner_deadline_s, wait_until, takeover, lead_only=False, hooked=hooked, check=check
                )
                result: FlightResult[Any] = await asyncio.shield(flight.future)
            else:
                waited = await self._wait_local(flight, wait_until)
                if waited is None:
                    return await self._timed_out(flight, started, check)
                result = waited
            waited_s = time.monotonic() - started
            if result.role is Role.OWNER:
                if initiator:
                    self.stats.owned += 1
                    return replace(result, waited_s=waited_s)
                if result.outcome is None or result.outcome.kind is not OutcomeKind.PRIVATE:
                    self.stats.followed_local += 1
                    return replace(result, role=Role.FOLLOWER, waited_s=waited_s)
                # PRIVATE: the owner's answer is its own request's alone (plan 6.9); compete again.
            elif result.role is Role.FOLLOWER and result.outcome is not None:
                if result.outcome.kind not in COMPETE_AGAIN:
                    self.stats.followed_remote += 1
                    return replace(result, waited_s=waited_s)
            elif result.role is Role.TIMEOUT and initiator:
                self.stats.timeouts += 1
                return replace(result, waited_s=waited_s)
            # Compete again: the outcome could not be shared, the owner gave up, or our driver's wait (not ours)
            # ended. Bounded by our own wait.
            if time.monotonic() >= wait_until:
                return await self._timed_out(flight, started, check)
            takeover = True
            self.stats.takeovers += 1

    async def try_lead[T](
        self, key: str, fetch: FetchFn[T], *, owner_deadline_s: float, hooked: bool = False
    ) -> FlightResult[T] | None:
        """Run `fetch` as the owner if no flight for `key` is running anywhere; else return None at once."""
        running = self._flights.get(key)
        if running is not None and not running.future.done():  # an answered flight only finishes its tail
            self.stats.skipped += 1
            return None
        flight: _Flight[T] = self._start(
            key, fetch, owner_deadline_s, time.monotonic(), False, lead_only=True, hooked=hooked, check=None
        )
        result = await asyncio.shield(flight.future)
        if result.role is Role.SKIPPED:
            self.stats.skipped += 1
            return None
        self.stats.owned += 1
        return result

    def inflight(self) -> int:
        """Keys being fetched, followed or finished (still joinable) in this process right now."""
        return len(self._flights)

    def tails(self) -> int:
        """Background tails (deferred stores and outcome publishes) still running in this process."""
        return len(self._tails)

    async def settle(self, timeout_s: float = TAIL_FINISH_TIMEOUT_S) -> None:
        """Wait until every answered flight has finished its tail (stored and published), at most `timeout_s`.
        For tests and shutdown; requests never wait for this."""
        deadline = time.monotonic() + max(0.0, timeout_s)
        while True:
            pending: set[asyncio.Task[Any]] = {task for task in self._tails if not task.done()}
            for flight in self._flights.values():
                if flight.task is not None and not flight.task.done() and flight.future.done():
                    pending.add(flight.task)
            remaining = deadline - time.monotonic()
            if not pending or remaining <= 0:
                return
            await asyncio.wait(pending, timeout=remaining)

    async def close(self, grace_s: float = 2.0) -> None:
        """Worker shutdown: give tails `grace_s` to store and publish, then cancel everything still running."""
        await self.settle(grace_s)
        tasks = [flight.task for flight in self._flights.values() if flight.task is not None]
        tasks += list(self._tails)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    # ---- local coordination ----

    def _joinable(self, flight: _Flight[Any]) -> bool:
        """A flight in progress, or one answered less than the linger ago (same clock as the lease row)."""
        until = flight.joinable_until_ms
        return until is None or self._clock.now_ms() < until

    def _start[T](
        self,
        key: str,
        fetch: FetchFn[T],
        owner_deadline_s: float,
        wait_until: float,
        takeover: bool,
        *,
        lead_only: bool,
        hooked: bool,
        check: StoreCheck | None,
    ) -> _Flight[T]:
        loop = asyncio.get_running_loop()
        flight: _Flight[T] = _Flight(loop.create_future())
        self._flights[key] = flight
        flight.task = loop.create_task(
            self._drive(key, flight, fetch, owner_deadline_s, wait_until, takeover, lead_only, hooked, check),
            name=f"roxy:singleflight:{key[:24]}",
        )
        return flight

    async def _wait_local(self, flight: _Flight[Any], wait_until: float) -> FlightResult[Any] | None:
        """Wait for this process's flight. No time limit while this process owns the fetch (the fetch has its
        own deadline); otherwise until `wait_until`. None when the wait ended first."""
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

    async def _timed_out(self, flight: _Flight[Any], started: float, check: StoreCheck | None) -> FlightResult[Any]:
        """This call's wait ended while another worker's owner still works: one last look in the owner's store
        (its answer may be there although its outcome was never published), else `Role.TIMEOUT`."""
        found = await self._check_store(check, final=True)
        if found is not None:
            self.stats.followed_remote += 1
            return FlightResult(Role.FOLLOWER, found, None, waited_s=time.monotonic() - started)
        return self._timeout(flight, started)

    async def _check_store(self, check: StoreCheck | None, *, final: bool) -> FlightOutcome | None:
        """Run a follower's `check`. Only a `stored` or `shared` outcome answers; a failed look is "nothing there"
        (the store is disposable, C7)."""
        if check is None:
            return None
        try:
            found = await check(final)
        except Exception:
            log.exception("singleflight_store_check_failed")
            return None
        if found is None or found.kind not in LINGERING:
            return None
        self.stats.store_answers += 1
        return found

    def _remaining_s(self, expires_ms: int | None) -> int:
        if expires_ms is None:
            return 1
        return max(1, math.ceil((expires_ms - self._clock.now_ms()) / 1000))

    async def _solo[T](self, fetch: FetchFn[T], takeover: bool, *, degraded: bool) -> FlightResult[T]:
        """Fetch alone (coalescing off, or the flight table is full); a deferred outcome still finishes (stores)."""
        value, outcome = await fetch(FlightStart(_new_flight_id(), takeover))
        immediate, tail = self._owned_tail(outcome, None)
        if tail is not None and self._run_tail(tail) is None:
            await tail(False)  # the tail table is full: back pressure, this caller waits for its own store
        return FlightResult(Role.SOLO, immediate, value, degraded=degraded)

    async def _drive[T](
        self,
        key: str,
        flight: _Flight[T],
        fetch: FetchFn[T],
        owner_deadline_s: float,
        wait_until: float,
        takeover: bool,
        lead_only: bool,
        hooked: bool,
        check: StoreCheck | None,
    ) -> None:
        try:
            try:
                drive = self._drive_hooked if hooked else self._drive_claimed
                result, tail = await drive(key, flight, fetch, owner_deadline_s, wait_until, takeover, lead_only, check)
            except asyncio.CancelledError:
                if not flight.future.done():
                    flight.future.cancel()
                raise
            except Exception as exc:  # handed to every waiter of this flight, which re-raise it
                if not flight.future.done():
                    flight.future.set_exception(exc)
                return
            shareable = result.role is Role.OWNER and (result.outcome is None or result.outcome.kind in LINGERING)
            # Answered: late arrivals in this process may join only a shareable answer, and only for the linger.
            flight.joinable_until_ms = self._clock.now_ms() + (self._linger_ms if shareable else 0)
            if not flight.future.done():
                flight.future.set_result(result)
            if tail is not None:
                task = self._run_tail(tail)
                if task is None:
                    await tail(False)  # the tail table is full: finish here (answer already given), no retries
                elif shareable:
                    # Late arrivals in this process share the answer until the tail is done or the linger ends.
                    await asyncio.wait({task}, timeout=self._linger_ms / 1000)
        finally:
            if self._flights.get(key) is flight:
                del self._flights[key]

    async def _drive_claimed[T](
        self,
        key: str,
        flight: _Flight[T],
        fetch: FetchFn[T],
        owner_deadline_s: float,
        wait_until: float,
        takeover: bool,
        lead_only: bool,
        check: StoreCheck | None,
    ) -> tuple[FlightResult[T], _Tail | None]:
        """Claim mode: take the lease in a transaction of its own, then fetch."""
        name = LEASE_PREFIX + key
        ttl_ms = max(1, int(owner_deadline_s * 1000))
        while True:
            flight_id = _new_flight_id()
            claim = await self._claim(name, flight_id, ttl_ms)
            if claim is None:  # hot.db unavailable: coalesce inside this process only
                self.stats.degraded += 1
                flight.owning.set()
                value, outcome = await fetch(FlightStart(flight_id, takeover))
                immediate, tail = self._owned_tail(outcome, None)
                return FlightResult(Role.OWNER, immediate, value, degraded=True), tail
            flight.lease_expires_ms = claim.expires_ms
            if claim.granted:
                flight.owning.set()
                publish = _Publish(name, claim.payload, flight_id, claim.expires_ms)
                return await self._own(publish, fetch, FlightStart(flight_id, takeover))
            if lead_only:
                return FlightResult(Role.SKIPPED, None, None), None
            if claim.outcome is not None:  # a flight that just finished: its outcome answers us too
                return FlightResult(Role.FOLLOWER, claim.outcome, None), None
            followed = await self._follow(name, flight, wait_until, check)
            if followed is not None:
                return followed, None
            takeover = True  # the owner died or its row vanished: compete for it

    async def _drive_hooked[T](
        self,
        key: str,
        flight: _Flight[T],
        fetch: FetchFn[T],
        owner_deadline_s: float,
        wait_until: float,
        takeover: bool,
        lead_only: bool,
        check: StoreCheck | None,
    ) -> tuple[FlightResult[T], _Tail | None]:
        """Hooked mode: look, then fetch with the lease hook (the upstream inserts it with its bucket slots)."""
        name = LEASE_PREFIX + key
        ttl_ms = max(1, int(owner_deadline_s * 1000))
        while True:
            seen = await self._look(name)
            if seen.state == "outcome" and seen.outcome is not None:
                if lead_only:
                    return FlightResult(Role.SKIPPED, None, None), None
                return FlightResult(Role.FOLLOWER, seen.outcome, None), None
            if seen.state == "live":
                flight.lease_expires_ms = seen.expires_ms
                if lead_only:
                    return FlightResult(Role.SKIPPED, None, None), None
                followed = await self._follow(name, flight, wait_until, check)
                if followed is not None:
                    return followed, None
                takeover = True
                continue
            if seen.degraded:
                self.stats.degraded += 1
            flight_id = _new_flight_id()
            hook = FlightLease(
                name=name,
                holder=self._holder,
                payload=_flight_payload(flight_id),
                ttl_ms=ttl_ms,
                margin_ms=self._margin_ms,
                finished=self._unpublished.get(name),
                hot=self._hot,
                clock=self._clock,
            )
            flight.owning.set()  # this process runs the fetch now (it ends by its own deadline whatever happens)
            try:
                value, outcome = await fetch(FlightStart(flight_id, takeover, lease=hook))
            except LeaseLost:
                flight.owning.clear()
                self.stats.leases_lost += 1
                if lead_only:
                    return FlightResult(Role.SKIPPED, None, None), None
                followed = await self._follow(name, flight, wait_until, check)
                if followed is not None:
                    return followed, None
                takeover = True
                continue
            except BaseException:
                if hook.granted:
                    await self._abandon(_Publish(name, hook.payload, flight_id, hook.expires_ms))
                raise
            publish = _Publish(name, hook.payload, flight_id, hook.expires_ms) if hook.granted else None
            if hook.granted:
                flight.lease_expires_ms = hook.expires_ms
            immediate, tail = self._owned_tail(outcome, publish)
            return FlightResult(Role.OWNER, immediate, value, degraded=seen.degraded), tail

    # ---- the owner's tail ----

    def _owned_tail(
        self, outcome: FlightOutcome | Deferred, publish: _Publish | None
    ) -> tuple[FlightOutcome | None, _Tail | None]:
        """The outcome known now (None while deferred) and the tail that finishes and publishes it, if any."""
        immediate = outcome if isinstance(outcome, FlightOutcome) else None
        if immediate is not None and immediate.kind is OutcomeKind.PRIVATE:
            self.stats.private += 1
        if publish is None and immediate is not None:
            return immediate, None  # nothing to finish and nobody to tell
        if publish is not None:
            # From this moment the flight is over for this process: its lease row (no outcome yet) must not look
            # like a flight in progress to a new request or refresh here (`_classify`, the hook, `_follow`).
            self._unpublished[publish.name] = publish.payload
        answered_ms = self._clock.now_ms()  # the linger counts from the answer, however late the publish lands

        async def tail(retry: bool) -> None:
            await self._tail(outcome, publish, retry=retry, answered_ms=answered_ms)

        return immediate, tail

    def _run_tail(self, tail: _Tail) -> asyncio.Task[None] | None:
        """Start a tail in the background (bounded); None when the tail table is full."""
        if len(self._tails) >= self._max_tails:
            self.stats.tails_inline += 1
            return None
        task = asyncio.get_running_loop().create_task(tail(True), name="roxy:singleflight:tail")
        self._tails.add(task)
        task.add_done_callback(self._tails.discard)
        return task

    async def _tail(
        self, outcome: FlightOutcome | Deferred, publish: _Publish | None, *, retry: bool, answered_ms: int
    ) -> None:
        """Finish a deferred outcome (the cache.db store), then publish it into the lease row. `_owned_tail`
        registered the flight in `_unpublished`; the registration ends here, whatever happens."""
        try:
            final: FlightOutcome
            if isinstance(outcome, Deferred):
                try:
                    final = await asyncio.wait_for(outcome.finish(), TAIL_FINISH_TIMEOUT_S)
                except asyncio.CancelledError:
                    if publish is not None:
                        await self._abandon(publish)
                    raise
                except Exception:  # the answer was served; only sharing it failed: followers compete again
                    log.exception("singleflight_finish_failed")
                    final = FlightOutcome(OutcomeKind.NOSTORE)
            else:
                final = outcome
            if publish is not None:
                await self._publish(publish, final, retry=retry, answered_ms=answered_ms)
        finally:
            if publish is not None and self._unpublished.get(publish.name) == publish.payload:
                del self._unpublished[publish.name]

    async def _own[T](
        self, publish: _Publish, fetch: FetchFn[T], start: FlightStart
    ) -> tuple[FlightResult[T], _Tail | None]:
        try:
            value, outcome = await fetch(start)
        except BaseException:
            await self._abandon(publish)
            raise
        immediate, tail = self._owned_tail(outcome, publish)
        return FlightResult(Role.OWNER, immediate, value), tail

    # ---- the lease ----

    def _classify(self, name: str, row: tuple[str, int, str | None] | None, now_ms: int) -> _Seen:
        """What a lease row means for a request that is about to start a flight."""
        if row is None:
            return _Seen("free")
        holder, expires, text = row
        if holder == self._holder and text is not None and self._unpublished.get(name) == text:
            return _Seen("free", expires)  # a flight of ours that already answered; its outcome is on its way
        outcome = _parse_payload(text)
        if outcome is not None:
            return _Seen("outcome", expires, outcome) if expires > now_ms else _Seen("free", expires)
        if expires + self._margin_ms > now_ms:
            return _Seen("live", expires)  # in progress (or just expired: wait a little more)
        return _Seen("free", expires)

    async def _look(self, name: str) -> _Seen:
        """One read of the lease row (no write lock). Unreadable counts as free, marked degraded."""
        if self._hot is None:
            return _Seen("free", degraded=True)
        now_ms = self._clock.now_ms()
        try:
            row = await self._hot.read(lambda conn: _read_row(conn, name))
        except (SharedStateUnavailable, sqlite3.Error):
            return _Seen("free", degraded=True)
        return self._classify(name, row, now_ms)

    async def _claim(self, name: str, flight_id: str, ttl_ms: int) -> _Claim | None:
        """Claim mode: claim the lease or learn who holds it. None when hot.db cannot be used (degraded)."""
        if self._hot is None:
            return None
        now_ms = self._clock.now_ms()
        finished = self._unpublished.get(name)

        def run(conn: sqlite3.Connection) -> _Claim:
            row = _read_row(conn, name)
            if row is not None and not (row[0] == self._holder and row[2] is not None and row[2] == finished):
                expires = row[1]
                outcome = _parse_payload(row[2])
                if outcome is not None:
                    if expires > now_ms:
                        return _Claim(False, expires, outcome)
                elif expires + self._margin_ms > now_ms:
                    return _Claim(False, expires)  # a flight in progress (or just expired: wait a little more)
            payload = _flight_payload(flight_id)
            # Insert, or take over an expired row with a compare and swap on its epoch (storage/leases.py).
            grant = leases.acquire(conn, name, self._holder, ttl_ms, now_ms, payload)
            if grant is None:
                current = _read_row(conn, name)
                if current is None:
                    return _Claim(False, now_ms)
                return _Claim(False, current[1], _parse_payload(current[2]))
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

    async def _publish_once(self, publish: _Publish, outcome: FlightOutcome, answered_ms: int = 0) -> None:
        """Write the outcome into our lease row (only if it is still this flight's). Raises when hot.db refuses."""
        if self._hot is None:
            return
        # A lingering outcome stays valid for the linger after the ANSWER (a publish that landed late must not
        # make an old answer look new: its followers still read it, a new request starts a new flight). Any other
        # outcome expires the row outright (0), so the next claim takes it over at once even if the wall clock
        # just stepped back.
        expires_ms = answered_ms + self._linger_ms if outcome.kind in LINGERING else 0
        new_payload = json.dumps({"f": publish.flight_id, "o": outcome.to_doc()}, separators=(",", ":"))

        def run(conn: sqlite3.Connection) -> int:
            return conn.execute(
                "UPDATE lease SET expires_ms = ?, payload_json = ? WHERE name = ? AND holder = ? AND payload_json = ?",
                (expires_ms, new_payload, publish.name, self._holder, publish.payload),
            ).rowcount

        # Shielded: a shutdown cancel during the write must not leave followers waiting for the full deadline.
        write = asyncio.ensure_future(self._hot.write(run, busy_timeout_ms=LEASE_BUSY_TIMEOUT_MS))
        write.add_done_callback(_consume_result)  # nobody awaits it after a cancel: never "never retrieved"
        await asyncio.shield(write)

    async def _publish(self, publish: _Publish, outcome: FlightOutcome, *, retry: bool, answered_ms: int) -> None:
        """Publish with a backoff while hot.db is busy, until it lands or the lease would expire on its own (then
        followers take it over anyway). Gives up early if a newer flight of ours took the row over."""
        delay = PUBLISH_RETRY_START_S
        while True:
            try:
                await self._publish_once(publish, outcome, answered_ms)
                return
            except (SharedStateUnavailable, sqlite3.Error) as exc:
                log.warning(
                    "singleflight_publish_failed",
                    extra={"fields": {"lease": publish.name[:40], "error": str(exc)[:200], "retry": retry}},
                )
            if not retry or self._clock.now_ms() + delay * 1000 >= publish.expires_ms:
                self.stats.publish_failures += 1
                return
            if self._unpublished.get(publish.name) != publish.payload:
                return  # a newer flight of this process took the lease over: nothing left to tell
            self.stats.publish_retries += 1
            await asyncio.sleep(delay)
            delay = min(delay * 2, PUBLISH_RETRY_MAX_S)

    async def _abandon(self, publish: _Publish) -> None:
        """The owner's fetch raised or was canceled: expire the row at once so followers compete again."""
        try:
            await self._publish_once(publish, FlightOutcome(OutcomeKind.ABANDONED))
        except (SharedStateUnavailable, sqlite3.Error, asyncio.CancelledError) as exc:
            log.warning(
                "singleflight_publish_failed", extra={"fields": {"lease": publish.name[:40], "error": str(exc)[:200]}}
            )

    async def _follow[T](
        self, name: str, flight: _Flight[T], wait_until: float, check: StoreCheck | None = None
    ) -> FlightResult[T] | None:
        """Poll the lease row with backoff (plan 6.9 step 4), and the owner's store (`check`) once the flight has
        run `STORE_CHECK_AFTER_S` (module docstring). None means "compete for the lease now"."""
        delay = self._poll_start
        next_check = time.monotonic() + self._check_after
        while True:
            remaining = wait_until - time.monotonic()
            if remaining <= 0:
                found = await self._check_store(check, final=True)
                if found is not None:
                    return FlightResult(Role.FOLLOWER, found, None)
                return FlightResult(Role.TIMEOUT, None, None, retry_after_s=self._remaining_s(flight.lease_expires_ms))
            await asyncio.sleep(min(delay, remaining))
            delay = min(delay * 2, self._poll_max)
            if self._hot is None:
                return None
            try:
                row = await self._hot.read(lambda conn: _read_row(conn, name))
                readable = True
            except (SharedStateUnavailable, sqlite3.Error):
                row, readable = None, False  # cannot see the row right now; keep waiting until our deadline
            if readable and row is None:
                return None
            if row is not None:
                holder, expires_ms, text = row
                if holder == self._holder and text is not None and self._unpublished.get(name) == text:
                    return None  # our own finished flight: no outcome will help us more than competing now
                flight.lease_expires_ms = expires_ms
                outcome = _parse_payload(text)
                if outcome is not None:
                    # Any outcome the owner published answers its followers, even if its linger just ended: a
                    # follower never goes upstream after an owner failure because its poll came late (step 6).
                    return FlightResult(Role.FOLLOWER, outcome, None)
                if expires_ms + self._margin_ms <= self._clock.now_ms():
                    return None  # expired without an outcome: the owner crashed
            # Still in progress as far as the row says. The owner stores before it publishes, so look there too
            # (finding mp-12: an owner whose publish never landed, then whose worker stopped, still answers us).
            if check is not None and time.monotonic() >= next_check:
                next_check = time.monotonic() + self._check_every
                found = await self._check_store(check, final=False)
                if found is not None:
                    return FlightResult(Role.FOLLOWER, found, None)


__all__ = [
    "COMPETE_AGAIN",
    "LEASE_PREFIX",
    "LINGERING",
    "OUTCOME_LINGER_MS",
    "SHARE_BODY_MAX",
    "STORE_CHECK_AFTER_S",
    "STORE_CHECK_EVERY_S",
    "Deferred",
    "FetchFn",
    "FlightLease",
    "FlightOutcome",
    "FlightResult",
    "FlightStart",
    "LeaseLost",
    "OutcomeKind",
    "Role",
    "SingleFlight",
    "SingleFlightStats",
    "StoreCheck",
]
