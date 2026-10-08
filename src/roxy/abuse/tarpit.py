"""The tarpit: a deliberate delay before answering a request Roxy has already decided to refuse.

What this is
    `Tarpit.plan(category, req)` returns a `TarpitPlan` (hold, drip or jitter) or None; the router awaits
    `plan.wait()` (or streams `plan.drip_chunks(body)`) and then sends the normal refusal, and always calls
    `plan.release()` in a `finally`. Also `capacity` (the effective cap formula), `TarpitStats` and `Tarpit.state()`,
    the fields of the Protection > Tarpit card (plan 10.6, rows 47, 78, 123).

Why it exists
    A fast refusal lets a script retry thousands of times a minute; a slow one makes each attempt cost the abuser
    seconds while costing Roxy an idle coroutine and one socket. v1 slept a whole gthread worker thread per hold and
    capped holds at half the thread slots; v2 sleeps with `asyncio.sleep` and caps holds by connections instead.

How it works
    - Never for served requests, never for bypass entries, and only for categories whose `tarpit_on_<category>`
      switch is on (`user_agent_rule` finally has one; new: `ban`, `spam`, `upstream_cooldown_retry`).
    - Types: `hold` waits a random `tarpit_min_seconds..tarpit_max_seconds` (swapped if reversed, as v1);
      `drip` sends headers at once and the body one byte per `tarpit_drip_interval_ms` until the hold ends (with
      `X-Accel-Buffering: no` and `Content-Encoding: identity` so nginx neither buffers nor compresses it);
      `jitter` waits `tarpit_jitter_min_ms..tarpit_jitter_max_ms`. `upstream_cooldown_retry` always uses jitter.
      Every hold is capped at 55 s and at the request deadline minus 2 s, so nginx and gunicorn never time out first.
    - Fleet cap: `effective = min(tarpit_max_concurrent, floor(tarpit_connection_budget x
      tarpit_max_capacity_fraction))` (defaults: min(50, floor(4000 x 0.25)) = 50). A hold takes one counted lease
      `tarpit:<n>` in hot.db (`storage/leases.acquire_slot`, inside BEGIN IMMEDIATE, so the cap holds across every
      worker); the lease outlives the hold by `tarpit_slot_grace_s` in case the worker dies.
    - Fails closed (plan C7): if hot.db cannot be written, nothing is held and the refusal is instant, counted as
      skipped. Over the cap: the same.
    - Shutdown: `wake_all()` (called by `roxy.lifespan.begin_drain` when the worker starts stopping) ends every hold
      and drip in progress at once, so each held caller gets its refusal now, and plans no new hold. Every hold
      sleeps through `hold()`, which races the injected sleep against that wake-up event.
    - The same transaction records the client's arrival time (`limiter` row `tarpit_arrival:<key>`), so the gap
      between one client's tarpit-eligible refusals is measured across all workers (row 78, the true inter-arrival
      mean). Rows idle for `stale_ip_duration` are pruned, so gaps longer than that read as a first arrival.
    - `upstream_cooldown_retry` (plan 10.6, 15.3 F) has its own producer, `plan_cooldown_retry`, which the router
      calls when it answers a pacing failure (Roblox cooldown, upstream busy, queue full) with `Retry-After`. While
      the category is on, ONE hot.db write both checks and records "this client was told to wait until T for this
      key": `limiter` row `ucr:<client>|<slot>` holds T in `tat_ms` and a fingerprint of the key in `window_start`.
      A retry of the same key before T is held with the `jitter` type (and claims a slot like any hold); the row
      then moves to the new answer's T. Bounded: `RETRY_SLOTS` rows per client (the key's hash picks the slot; a
      collision only forgets an older key, which fails open for a delay), each one dead once T passes, so the
      retention job prunes it like any idle limiter row. Shared by every worker, because the row is in hot.db.
      With the category off (the default) nothing is read or written.

What to read next
    `roxy/storage/leases.py` (`acquire_slot`), then `roxy/abuse/pipeline.py` (who asks for a plan).
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import itertools
import logging
import math
import random
import sqlite3
import time
from collections import OrderedDict
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from roxy.config.constants import TARPIT_CATEGORIES
from roxy.core.clock import Clock
from roxy.core.scope import catalog_default
from roxy.storage import leases
from roxy.storage.db import Database, SharedStateUnavailable

log = logging.getLogger(__name__)

SLOT_PREFIX: Final = "tarpit:"
ARRIVAL_PREFIX: Final = "tarpit_arrival:"
RETRY_PREFIX: Final = "ucr:"
"""`limiter` rows of `upstream_cooldown_retry`: `ucr:<client>|<slot>` (see the module docstring)."""
RETRY_CATEGORY: Final = "upstream_cooldown_retry"
RETRY_SLOTS: Final = 8
"""At most this many remembered Retry-After answers per client (plan P9)."""
HARD_MAX_HOLD_S: Final = 55.0
"""Plan 10.6: holds never exceed 55 s (below `request_deadline_s`, nginx and gunicorn timeouts)."""
DEADLINE_MARGIN_S: Final = 2.0
SLOT_BUSY_TIMEOUT_MS: Final = 250
"""A hot path with a better fallback than waiting: refuse instantly rather than wait for the write lock."""
MAX_REASON_RECORDS: Final = 200
MAX_IP_RECORDS: Final = 200
DRIP_HEADERS: Final[dict[str, str]] = {"X-Accel-Buffering": "no", "Content-Encoding": "identity"}
KINDS: Final[tuple[str, ...]] = ("hold", "drip", "jitter")


@dataclass(frozen=True, slots=True)
class TarpitCapacity:
    """The effective fleet-wide cap and how it was derived (plan 10.6)."""

    effective: int
    configured: int
    connection_budget: int
    fraction: float
    budget_cap: int
    clamped: bool
    clamped_by: str | None

    @property
    def formula(self) -> str:
        return (
            f"min({self.configured}, floor({self.connection_budget} x {self.fraction:g})) = "
            f"min({self.configured}, {self.budget_cap}) = {self.effective}"
        )


def capacity(values: Mapping[str, Any]) -> TarpitCapacity:
    """`effective_cap = min(tarpit_max_concurrent, floor(tarpit_connection_budget x tarpit_max_capacity_fraction))`."""
    configured = max(0, int(values["tarpit_max_concurrent"]))
    budget = max(0, int(values["tarpit_connection_budget"]))
    fraction = float(values["tarpit_max_capacity_fraction"])
    budget_cap = math.floor(budget * fraction + 1e-9)
    effective = min(configured, budget_cap)
    clamped = configured > effective
    return TarpitCapacity(
        effective, configured, budget, fraction, budget_cap, clamped, "connection_budget" if clamped else None
    )


def _setting(values: Mapping[str, Any], key: str) -> Any:
    """The live value, or the catalog default when the snapshot lacks the key (never a second inline default)."""
    return values[key] if key in values else catalog_default(key)


def category_enabled(values: Mapping[str, Any], category: str) -> bool:
    """v1 `category_enabled`: a known category whose `tarpit_on_<category>` switch is on."""
    return category in TARPIT_CATEGORIES and bool(_setting(values, f"tarpit_on_{category}"))


def client_key(req: Any) -> str:
    """The client a hold is counted for: its limit key (IPv6 grouped by prefix), else its address."""
    return str(getattr(req, "limit_key", "") or getattr(req, "client_ip", "") or "unknown")


def retry_fingerprint(key: str) -> int:
    """A 56-bit fingerprint of a cache key (fits SQLite's signed 64-bit integer in `limiter.window_start`)."""
    return int.from_bytes(hashlib.blake2b(key.encode("utf-8", "surrogateescape"), digest_size=7).digest(), "big")


def hold_bounds(values: Mapping[str, Any]) -> tuple[float, float]:
    """`(low, high)` seconds of a hold; swapped when reversed (v1 `_bounds`)."""
    low, high = float(values["tarpit_min_seconds"]), float(values["tarpit_max_seconds"])
    return (high, low) if high < low else (low, high)


@dataclass(slots=True)
class _Counter:
    held: int = 0
    skipped: int = 0
    total_held_s: float = 0.0
    max_held_s: float = 0.0
    last_at: float = 0.0


@dataclass(slots=True)
class TarpitStats:
    """Per-worker tarpit statistics (bounded); the metrics layer merges workers (row 78)."""

    total: _Counter = field(default_factory=_Counter)
    categories: dict[str, _Counter] = field(default_factory=dict)
    reasons: OrderedDict[str, _Counter] = field(default_factory=OrderedDict)
    ips: OrderedDict[str, _Counter] = field(default_factory=OrderedDict)
    total_gap_s: float = 0.0
    gaps: int = 0

    @staticmethod
    def _bump(table: OrderedDict[str, _Counter], key: str, cap: int) -> _Counter:
        counter = table.get(key)
        if counter is None:
            counter = _Counter()
            table[key] = counter
            while len(table) > cap:
                table.popitem(last=False)
        table.move_to_end(key)
        return counter

    def record(
        self, *, category: str, reason: str, ip: str, held_s: float, skipped: bool, gap_s: float, at: float
    ) -> None:
        counters = [self.total, self.categories.setdefault(category, _Counter())]
        if reason:
            counters.append(self._bump(self.reasons, f"{category}|{reason[:160]}", MAX_REASON_RECORDS))
        counters.append(self._bump(self.ips, ip[:64] or "unknown", MAX_IP_RECORDS))
        for counter in counters:
            counter.last_at = max(counter.last_at, at)
            if skipped:
                counter.skipped += 1
            else:
                counter.held += 1
                counter.total_held_s += held_s
                counter.max_held_s = max(counter.max_held_s, held_s)
        if gap_s > 0:
            self.total_gap_s += gap_s
            self.gaps += 1

    def snapshot(self) -> dict[str, Any]:
        def view(counter: _Counter) -> dict[str, Any]:
            return {
                "held": counter.held,
                "skipped": counter.skipped,
                "total_held_s": round(counter.total_held_s, 3),
                "max_held_s": round(counter.max_held_s, 3),
                "last_at": counter.last_at,
            }

        return {
            **view(self.total),
            "mean_gap_s": round(self.total_gap_s / self.gaps, 3) if self.gaps else 0.0,
            "gaps": self.gaps,
            "categories": {name: view(c) for name, c in self.categories.items()},
            "reasons": {name: view(c) for name, c in self.reasons.items()},
            "ips": {name: view(c) for name, c in self.ips.items()},
        }


class TarpitPlan:
    """One admitted hold. Always `await release()` in a `finally`, even when the client disconnects."""

    def __init__(
        self,
        tarpit: Tarpit,
        *,
        kind: str,
        hold_s: float,
        category: str,
        reason: str,
        ip: str,
        slot: str,
        holder: str,
        gap_s: float,
        drip_interval_s: float,
    ) -> None:
        self._tarpit = tarpit
        self.kind = kind
        self.hold_s = hold_s
        self.category = category
        self.reason = reason
        self.ip = ip
        self.slot = slot
        self.holder = holder
        self.gap_s = gap_s
        self.drip_interval_s = drip_interval_s
        self._started: float | None = None
        self._released = False

    @property
    def response_headers(self) -> dict[str, str]:
        """Extra headers for a drip response (nginx must not buffer or compress it)."""
        return dict(DRIP_HEADERS) if self.kind == "drip" else {}

    async def wait(self) -> None:
        """Hold (or jitter) for the planned time before the refusal is sent (shorter if the worker drains)."""
        self._started = self._tarpit.monotonic()
        await self._tarpit.hold(self.hold_s)

    async def drip_chunks(self, body: bytes) -> AsyncIterator[bytes]:
        """The refusal body one byte per drip interval until the hold ends, then whatever is left (all of it at
        once when the worker starts draining, see `Tarpit.wake_all`)."""
        self._started = self._tarpit.monotonic()
        deadline = self._started + self.hold_s
        position = 0
        while (
            position < len(body)
            and not self._tarpit.draining
            and self._tarpit.monotonic() + self.drip_interval_s < deadline
        ):
            yield body[position : position + 1]
            position += 1
            await self._tarpit.hold(self.drip_interval_s)
        remaining = deadline - self._tarpit.monotonic()
        if remaining > 0:
            await self._tarpit.hold(remaining)
        if position < len(body):
            yield body[position:]

    async def release(self) -> None:
        """Record the hold and free the slot (idempotent; a failure leaves the lease to expire on its own)."""
        if self._released:
            return
        self._released = True
        held = 0.0 if self._started is None else max(0.0, self._tarpit.monotonic() - self._started)
        self._tarpit.stats.record(
            category=self.category,
            reason=self.reason,
            ip=self.ip,
            held_s=held,
            skipped=False,
            gap_s=self.gap_s,
            at=self._tarpit.clock.now(),
        )
        await self._tarpit.release_slot(self.slot, self.holder)


class Tarpit:
    """Plans holds against the fleet-wide cap (see the module docstring)."""

    def __init__(
        self,
        settings: Any,
        hot_db: Database | None,
        clock: Clock,
        worker_id: str,
        *,
        sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        rng: random.Random | None = None,
    ) -> None:
        self.settings = settings
        self.hot_db = hot_db
        self.clock = clock
        self.worker_id = worker_id
        self.sleep = sleep
        self.monotonic = monotonic
        self.rng = rng or random.Random()
        self.stats = TarpitStats()
        self._ids = itertools.count(1)
        self.draining = False  # set by `wake_all`: no new holds, running ones end now
        self._wake: tuple[asyncio.AbstractEventLoop, asyncio.Event] | None = None

    # ---- holding, and letting go at shutdown ----

    def _wake_event(self) -> asyncio.Event:
        """The event `wake_all` sets, made for the running loop (an app may run its lifespan on several loops)."""
        loop = asyncio.get_running_loop()
        if self._wake is None or self._wake[0] is not loop:
            event = asyncio.Event()
            if self.draining:
                event.set()
            self._wake = (loop, event)
        return self._wake[1]

    async def hold(self, seconds: float) -> None:
        """Sleep `seconds` with the injected sleep, but return at once when `wake_all` is called."""
        if seconds <= 0 or self.draining:
            return
        woken = asyncio.ensure_future(self._wake_event().wait())
        sleeper = asyncio.ensure_future(self.sleep(seconds))
        try:
            await asyncio.wait({sleeper, woken}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in (sleeper, woken):
                if not task.done():
                    task.cancel()
        if sleeper.done() and not sleeper.cancelled():
            sleeper.result()  # an error inside the sleep is not swallowed

    def wake_all(self) -> None:
        """The worker is shutting down (`roxy.lifespan.begin_drain`): every hold in progress ends now and the
        caller gets its refusal at once, and no new hold is planned, so uvicorn's graceful wait (and gunicorn's
        kill after `graceful_timeout`) never has to outlast a 55 s hold. Safe from any thread; never raises."""
        self.draining = True
        pair = self._wake
        if pair is None:
            return
        loop, event = pair
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is loop:
            event.set()
        elif not loop.is_closed():
            loop.call_soon_threadsafe(event.set)

    def _values(self) -> Mapping[str, Any]:
        snapshot = self.settings.snapshot()
        return snapshot if isinstance(snapshot, Mapping) else {}

    def _duration(self, kind: str, values: Mapping[str, Any]) -> float:
        if kind == "jitter":
            low, high = float(values["tarpit_jitter_min_ms"]), float(values["tarpit_jitter_max_ms"])
            low, high = (high, low) if high < low else (low, high)
            return (self.rng.uniform(low, high) if high > low else low) / 1000
        low, high = hold_bounds(values)
        return self.rng.uniform(low, high) if high > low else low

    def _eligible(self, values: Mapping[str, Any], category: str, req: Any) -> bool:
        """Tarpit on, the worker not draining, the caller not on the bypass list (never held, plan 10.6), the
        category's switch on."""
        if self.draining or not bool(_setting(values, "tarpit_enabled")) or getattr(req, "bypass", False):
            return False
        return category_enabled(values, category)

    def _kind(self, values: Mapping[str, Any], category: str) -> str:
        if category == RETRY_CATEGORY:
            return "jitter"  # plan 10.6: a retry inside its Retry-After only ever gets the short jitter delay
        kind = str(_setting(values, "tarpit_default_type"))
        return kind if kind in KINDS else "hold"

    def _hold_s(self, kind: str, values: Mapping[str, Any], req: Any) -> float:
        """The planned hold, capped at 55 s and at the request deadline minus 2 s (0 or less: nothing to hold)."""
        hold_s = min(self._duration(kind, values), HARD_MAX_HOLD_S)
        deadline_at = getattr(req, "deadline_at", None)
        if isinstance(deadline_at, int | float) and deadline_at > 0:
            hold_s = min(hold_s, deadline_at - self.monotonic() - DEADLINE_MARGIN_S)
        return hold_s

    def _ttl_ms(self, values: Mapping[str, Any], hold_s: float) -> int:
        grace_s = float(_setting(values, "tarpit_slot_grace_s"))
        return max(1, math.ceil((hold_s + grace_s) * 1000))

    def _make_plan(
        self,
        values: Mapping[str, Any],
        *,
        kind: str,
        hold_s: float,
        category: str,
        reason: str,
        ip: str,
        slot: str,
        holder: str,
        gap_s: float,
    ) -> TarpitPlan:
        drip_interval_s = max(0.1, float(_setting(values, "tarpit_drip_interval_ms")) / 1000)
        return TarpitPlan(
            self,
            kind=kind,
            hold_s=hold_s,
            category=category,
            reason=reason,
            ip=ip,
            slot=slot,
            holder=holder,
            gap_s=gap_s,
            drip_interval_s=drip_interval_s,
        )

    async def plan(self, category: str, req: Any, *, reason: str = "") -> TarpitPlan | None:
        """A hold for this refusal, or None (off, bypass, category off, nothing to hold, over the cap, no hot.db)."""
        values = self._values()
        if not self._eligible(values, category, req):
            return None
        kind = self._kind(values, category)
        hold_s = self._hold_s(kind, values, req)
        if hold_s <= 0:
            return None  # v1: nothing to hold is not logged at all
        ip = client_key(req)
        now_ms = self.clock.now_ms()
        cap = capacity(values)
        holder = f"{self.worker_id}#{next(self._ids)}"
        ttl_ms = self._ttl_ms(values, hold_s)
        slot: str | None = None
        gap_s = 0.0
        if self.hot_db is not None:
            try:
                slot, gap_s = await self.hot_db.write(
                    lambda conn: self._admit(conn, ip, holder, cap.effective, ttl_ms, now_ms),
                    busy_timeout_ms=SLOT_BUSY_TIMEOUT_MS,
                )
            except SharedStateUnavailable as exc:
                # Fail closed: no shared count means no hold (plan C7). The refusal goes out instantly.
                log.warning("tarpit_slot_unavailable", extra={"fields": {"error": str(exc)[:200]}})
                slot = None
        if slot is None:
            self.stats.record(
                category=category, reason=reason, ip=ip, held_s=0.0, skipped=True, gap_s=gap_s, at=now_ms / 1000
            )
            return None
        return self._make_plan(
            values, kind=kind, hold_s=hold_s, category=category, reason=reason, ip=ip, slot=slot, holder=holder,
            gap_s=gap_s,
        )  # fmt: skip

    async def plan_cooldown_retry(
        self, req: Any, *, key: str, retry_after_s: float, reason: str = ""
    ) -> TarpitPlan | None:
        """Remember the `Retry-After` this client was just given for `key`, and hold this answer (jitter) when it is
        itself a retry of `key` before an earlier `Retry-After` ran out (module docstring). None: no hold."""
        values = self._values()
        if self.hot_db is None or retry_after_s <= 0 or not self._eligible(values, RETRY_CATEGORY, req):
            return None
        ip = client_key(req)
        fingerprint = retry_fingerprint(key)
        row_key = f"{RETRY_PREFIX}{ip}|{fingerprint % RETRY_SLOTS}"
        hold_s = self._hold_s("jitter", values, req)
        now_ms = self.clock.now_ms()
        until_ms = now_ms + math.ceil(float(retry_after_s) * 1000)
        cap = capacity(values)
        holder = f"{self.worker_id}#{next(self._ids)}"
        ttl_ms = self._ttl_ms(values, max(0.0, hold_s))
        try:
            retry, slot, gap_s = await self.hot_db.write(
                lambda conn: self._admit_retry(
                    conn, row_key, fingerprint, until_ms, ip, holder, cap.effective if hold_s > 0 else 0, ttl_ms, now_ms
                ),
                busy_timeout_ms=SLOT_BUSY_TIMEOUT_MS,
            )
        except SharedStateUnavailable as exc:
            log.warning("tarpit_slot_unavailable", extra={"fields": {"error": str(exc)[:200]}})
            return None  # fail closed: no shared state, no hold (plan C7)
        if not retry or hold_s <= 0:
            return None
        if slot is None:
            self.stats.record(
                category=RETRY_CATEGORY, reason=reason, ip=ip, held_s=0.0, skipped=True, gap_s=gap_s, at=now_ms / 1000
            )
            return None
        return self._make_plan(
            values, kind="jitter", hold_s=hold_s, category=RETRY_CATEGORY, reason=reason, ip=ip, slot=slot,
            holder=holder, gap_s=gap_s,
        )  # fmt: skip

    @classmethod
    def _admit_retry(
        cls,
        conn: sqlite3.Connection,
        row_key: str,
        fingerprint: int,
        until_ms: int,
        ip: str,
        holder: str,
        cap: int,
        ttl_ms: int,
        now_ms: int,
    ) -> tuple[bool, str | None, float]:
        """One transaction: was this key's earlier Retry-After still running? Then claim a hold slot. Either way
        the row now holds this answer's Retry-After. Returns `(retry, slot, gap_s)`."""
        row = conn.execute("SELECT tat_ms, window_start FROM limiter WHERE bucket_key = ?", (row_key,)).fetchone()
        retry = row is not None and int(row[1]) == fingerprint and int(row[0]) > now_ms
        conn.execute(
            "INSERT INTO limiter (bucket_key, tat_ms, window_start, count, updated_at) VALUES (?, ?, ?, 1, ?) "
            "ON CONFLICT (bucket_key) DO UPDATE SET tat_ms = excluded.tat_ms, window_start = excluded.window_start, "
            "count = 1, updated_at = excluded.updated_at",
            (row_key, until_ms, fingerprint, now_ms // 1000),
        )
        if not retry or cap <= 0:
            return retry, None, 0.0
        slot, gap_s = cls._admit(conn, ip, holder, cap, ttl_ms, now_ms)
        return retry, slot, gap_s

    @staticmethod
    def _admit(
        conn: sqlite3.Connection, ip: str, holder: str, cap: int, ttl_ms: int, now_ms: int
    ) -> tuple[str | None, float]:
        """One transaction: record the arrival (for the gap metric) and claim a slot if one is free."""
        key = ARRIVAL_PREFIX + ip
        row = conn.execute("SELECT tat_ms FROM limiter WHERE bucket_key = ?", (key,)).fetchone()
        previous = int(row[0]) if row is not None else 0
        gap_s = max(0.0, (now_ms - previous) / 1000) if previous else 0.0
        conn.execute(
            "INSERT INTO limiter (bucket_key, tat_ms, window_start, count, updated_at) VALUES (?, ?, 0, 1, ?) "
            "ON CONFLICT (bucket_key) DO UPDATE SET tat_ms = excluded.tat_ms, count = count + 1, "
            "updated_at = excluded.updated_at",
            (key, now_ms, now_ms // 1000),
        )
        return leases.acquire_slot(conn, SLOT_PREFIX, holder, cap, ttl_ms, now_ms), gap_s

    async def release_slot(self, slot: str, holder: str) -> None:
        if self.hot_db is None:
            return
        # If hot.db is unavailable the lease simply expires on its own after the hold plus the grace time.
        with contextlib.suppress(SharedStateUnavailable):
            await self.hot_db.write(
                lambda conn: leases.release(conn, slot, holder), busy_timeout_ms=SLOT_BUSY_TIMEOUT_MS * 4
            )

    async def active_holds(self) -> int | None:
        """Valid slot leases fleet-wide, or None when hot.db cannot be read."""
        if self.hot_db is None:
            return 0
        now_ms = self.clock.now_ms()
        try:
            return await self.hot_db.read(lambda conn: leases.count_slots(conn, SLOT_PREFIX, now_ms))
        except SharedStateUnavailable:
            return None

    async def state(self) -> dict[str, Any]:
        """The Protection > Tarpit card (row 123, v1 `get_state` in snake_case)."""
        values = self._values()
        cap = capacity(values)
        active = await self.active_holds()
        holds = active or 0
        low, high = hold_bounds(values)
        budget = cap.connection_budget
        return {
            "enabled": bool(_setting(values, "tarpit_enabled")),
            "categories": [c for c in TARPIT_CATEGORIES if category_enabled(values, c)],
            "all_categories": list(TARPIT_CATEGORIES),
            "default_type": str(_setting(values, "tarpit_default_type")),
            "min_seconds": low,
            "max_seconds": high,
            "max_concurrent": cap.effective,
            "configured_concurrent": cap.configured,
            "connection_budget": budget,
            "capacity_fraction": cap.fraction,
            "budget_cap": cap.budget_cap,
            "clamped": cap.clamped,
            "clamped_by": cap.clamped_by,
            "formula": cap.formula,
            "fleet_slots": budget,
            "active_holds": active,
            "slots_free": max(0, cap.effective - holds),
            "capacity_used_pct": round(holds / budget * 100, 1) if budget else 0.0,
            "capacity_ceiling_pct": round(cap.fraction * 100, 1),
            "shared_state_ok": active is not None,
            "stats": self.stats.snapshot(),
        }


__all__ = [
    "ARRIVAL_PREFIX",
    "DRIP_HEADERS",
    "HARD_MAX_HOLD_S",
    "RETRY_CATEGORY",
    "RETRY_PREFIX",
    "RETRY_SLOTS",
    "SLOT_PREFIX",
    "Tarpit",
    "TarpitCapacity",
    "TarpitPlan",
    "TarpitStats",
    "capacity",
    "category_enabled",
    "client_key",
    "hold_bounds",
    "retry_fingerprint",
]
