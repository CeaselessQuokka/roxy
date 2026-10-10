"""The per-worker batch writer: collect metric items in memory, write them to SQLite every couple of seconds.

What this is
    `BatchWriter` holds one bounded queue per item kind (events, 429 rows, captures, fingerprints, spam window
    updates, ...) plus optional "sources" (callbacks that hand over a snapshot of in-memory counters, such as the
    recorder's rollup dict). `flush()` writes everything in one transaction per database; the worker's task
    supervisor calls it every `metrics_flush_interval_ms`. `flush_now()` does the same synchronously during
    shutdown, so stopping a worker does not lose the last seconds of statistics (plan 5.5).

Why it exists
    Writing one row per request would make every request wait for SQLite and would multiply write transactions
    by the request rate. Batching turns thousands of small writes into one transaction every 2 s (plan 6.3).
    Producers never touch the database; they call `ctx.recorder.*`, which calls `add()` here.

How it works
    - Each kind is registered once with a handler `handler(conn, items)` that writes a list of items with
      `executemany` or upserts, a target database, and a priority (higher survives longer).
    - The total number of queued items is bounded by `max_items` (setting `metrics_queue_max`, default 50,000;
      plan P9). On overflow the oldest item of the lowest priority kind is dropped; if the new item itself has
      the lowest priority, it is the one dropped. Every drop increments `dropped` (the `metrics_dropped` counter
      on the System page; recommendation SYS-METRICS-DROP fires when it is not zero).
    - A flush takes everything queued at that moment, then writes each database's share in one transaction.
      If the database is unavailable the items are put back and retried next time: metrics may degrade, but they
      never block requests (plan C7). Putting back respects priorities the same way `add()` does: lower priority
      items queued meanwhile are evicted first, and within a kind the oldest items go first.
    - Any other failure means some item cannot be written (a bug or bad data), and retrying it forever would
      block every kind that shares the database. So the flush retries each kind on its own, then splits a failing
      batch in halves until the bad items are found (bisection, at most `MAX_ISOLATION_WRITES` transactions per
      flush). Bad items are dropped, counted in `dropped` and logged; everything else is written.
    - A flush canceled at shutdown puts back whatever it had not written yet, so `flush_now()` can still write
      it. A write that had already started when the cancel arrived finishes on its own (it is never doubled).

What to read next
    `roxy/metrics/recorder.py` (the producer side), then `roxy/storage/db.py` (`write` and `write_sync`).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import sqlite3
import threading
import time
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from roxy.storage.db import Database, SharedStateUnavailable

log = logging.getLogger(__name__)

DEFAULT_MAX_ITEMS = 50_000
"""Default for `metrics_queue_max` (plan 15.3 I)."""

MAX_ISOLATION_WRITES = 64
"""Most transactions one flush spends finding unwritable items (about 2 x log2(n) per bad item in n)."""

Handler = Callable[[sqlite3.Connection, list[Any]], None]
"""Writes a batch of items of one kind. Runs on the database's writer thread inside the flush transaction."""

Source = Callable[[], list[Any]]
"""Returns (and forgets) the items accumulated since the last call, for example a swapped counter dict."""


@dataclass(slots=True)
class _Kind:
    name: str
    db: Database
    handler: Handler
    priority: int
    queue: deque[Any] = field(default_factory=deque)
    source: Source | None = None
    dropped: int = 0
    written: int = 0


@dataclass(frozen=True, slots=True)
class FlushResult:
    """What one flush did."""

    written: dict[str, int]
    failed_dbs: list[str]
    duration_ms: float


class _Abandoned(Exception):
    """The flush that queued this write was canceled before the write started; it must write nothing."""


@dataclass(slots=True)
class _WriteGuard:
    """Decides, under a lock shared with the writer thread, whether a canceled flush's write runs or not."""

    lock: threading.Lock = field(default_factory=threading.Lock)
    started: bool = False
    abandoned: bool = False

    def start(self) -> bool:
        """Called first thing on the writer thread: False if the flush already gave this write up."""
        with self.lock:
            if self.abandoned:
                return False
            self.started = True
            return True

    def abandon(self) -> bool:
        """Called by a canceled flush: True when the write never started (so it never will, and its items must be
        put back); False when it is already running (it finishes on its own and its items are written)."""
        with self.lock:
            self.abandoned = True
            return not self.started


class _Isolation:
    """Finds the items a handler cannot write: each kind alone first, then halves of a failing batch.

    A stack of `(kind, items)` segments to try. A failing segment of one item is dropped; a longer one is split
    in two and both halves are tried again. Highest priority kinds are tried first.
    """

    def __init__(self, writer: BatchWriter, kinds: list[str], taken: dict[str, list[Any]]) -> None:
        self._writer = writer
        ordered = sorted(kinds, key=lambda kind: writer._kinds[kind].priority, reverse=True)
        self._pending: list[tuple[str, list[Any]]] = [(kind, taken[kind]) for kind in reversed(ordered)]
        self.current: tuple[str, list[Any]] | None = None
        self.budget = MAX_ISOLATION_WRITES
        self.written: dict[str, int] = {}
        self.clean = True  # False once anything was dropped or put back

    def next(self) -> tuple[str, list[Any]] | None:
        """The next segment to try, or None when done."""
        while self._pending:
            kind, items = self._pending.pop()
            if self.budget <= 0:
                self._writer._drop_bad(kind, items, "too many failing writes in one flush")
                self.clean = False
                continue
            self.budget -= 1
            self.current = (kind, items)
            return self.current
        self.current = None
        return None

    def succeeded(self) -> None:
        assert self.current is not None
        kind, items = self.current
        self.written[kind] = self.written.get(kind, 0) + len(items)

    def failed(self, exc: BaseException) -> None:
        assert self.current is not None
        kind, items = self.current
        self.clean = False
        if len(items) == 1:
            self._writer._drop_bad(kind, items, f"{type(exc).__name__}: {exc}")
            return
        middle = len(items) // 2
        self._pending.append((kind, items[middle:]))
        self._pending.append((kind, items[:middle]))  # popped first, so the original order is kept

    def put_back(self, *, include_current: bool) -> None:
        """Requeue every segment not tried yet (and the current one when it surely did not run)."""
        segments = list(self._pending)
        if include_current and self.current is not None:
            segments.append(self.current)
        self._pending.clear()
        self.current = None
        if not segments:
            return
        self.clean = False
        merged: dict[str, list[Any]] = {}
        for kind, items in segments:
            merged.setdefault(kind, []).extend(items)
        self._writer._requeue_kinds(list(merged), merged)

    def finish(self, written: dict[str, int]) -> None:
        for kind, count in self.written.items():
            self._writer._kinds[kind].written += count
            written[kind] = written.get(kind, 0) + count


class BatchWriter:
    """Bounded per-kind queues flushed to SQLite in one transaction per database."""

    def __init__(self, *, max_items: int | Callable[[], int] = DEFAULT_MAX_ITEMS) -> None:
        # max_items may be a callable so a live setting change (`metrics_queue_max`) applies without a restart.
        self._max_items = max_items
        self._kinds: dict[str, _Kind] = {}
        # add() runs on the event loop thread; flush_now() may run on another thread during shutdown.
        self._lock = threading.Lock()
        self._total = 0
        self.dropped = 0
        self.flushes = 0
        self.flush_failures = 0
        self.last_flush_at: float | None = None
        self.last_flush_ms = 0.0
        # asyncio.Lock binds to an event loop on first use (Python 3.10+), so creating it here is safe.
        self._flush_lock = asyncio.Lock()

    # ------------------------------------------------------------------------------------------- registration

    def register(
        self, kind: str, db: Database, handler: Handler, *, priority: int = 0, source: Source | None = None
    ) -> None:
        """Declare an item kind: where it is written, how, and how important it is when the queue is full."""
        if kind in self._kinds:
            raise ValueError(f"batch kind {kind!r} already registered")
        self._kinds[kind] = _Kind(kind, db, handler, priority, source=source)

    def kinds(self) -> list[str]:
        return list(self._kinds)

    # ----------------------------------------------------------------------------------------------- producers

    def add(self, kind: str, item: Any) -> bool:
        """Queue one item. Never blocks and never raises for a full queue. Returns False if an item was dropped
        to make room and that item was this one."""
        spec = self._kinds[kind]
        with self._lock:
            limit = self._limit()
            if self._total >= limit and not self._make_room(spec.priority):
                spec.dropped += 1
                self.dropped += 1
                return False
            spec.queue.append(item)
            self._total += 1
            return True

    def add_many(self, kind: str, items: list[Any]) -> int:
        """Queue several items; returns how many were accepted."""
        return sum(1 for item in items if self.add(kind, item))

    def _limit(self) -> int:
        value = self._max_items() if callable(self._max_items) else self._max_items
        return max(1, int(value))

    def _make_room(self, incoming_priority: int) -> bool:
        """Drop the oldest item of the lowest priority non-empty kind whose priority is not above the incoming
        item's. Returns False if every queued item outranks the incoming one (the caller drops it instead)."""
        victims = [k for k in self._kinds.values() if k.queue and k.priority <= incoming_priority]
        if not victims:
            return False
        victim = min(victims, key=lambda k: k.priority)
        victim.queue.popleft()
        victim.dropped += 1
        self.dropped += 1
        self._total -= 1
        return True

    # ----------------------------------------------------------------------------------------------- flushing

    def _drain(self) -> dict[str, list[Any]]:
        """Take every queued item and every source snapshot, grouped by kind."""
        taken: dict[str, list[Any]] = {}
        with self._lock:
            for spec in self._kinds.values():
                if spec.queue:
                    taken[spec.name] = list(spec.queue)
                    spec.queue.clear()
            self._total = 0
        for spec in self._kinds.values():
            if spec.source is None:
                continue
            try:
                snapshot = spec.source()
            except Exception:
                log.exception("batch_source_failed", extra={"fields": {"kind": spec.name}})
                continue
            if snapshot:
                taken.setdefault(spec.name, []).extend(snapshot)
        return taken

    def _requeue_kinds(self, kinds: list[str], items_by_kind: dict[str, list[Any]]) -> None:
        """Put items that could not be written back at the front of their queues, keeping the bound.

        Higher priority kinds are put back first, and may evict queued items of lower priority kinds to make room,
        exactly as `add()` would. Within a kind the put-back items are the oldest, so they are the ones dropped
        when there is still not enough room.
        """
        with self._lock:
            for kind in sorted(kinds, key=lambda name: self._kinds[name].priority, reverse=True):
                self._requeue_locked(kind, items_by_kind.get(kind, []))

    def _requeue_locked(self, kind: str, items: list[Any]) -> None:
        if not items:
            return
        spec = self._kinds[kind]
        limit = self._limit()
        missing = len(items) - max(0, limit - self._total)
        while missing > 0 and self._evict_lower_locked(spec.priority):
            missing -= 1
        room = max(0, limit - self._total)
        keep = items[-room:] if room else []
        lost = len(items) - len(keep)
        if lost:
            spec.dropped += lost
            self.dropped += lost
        spec.queue.extendleft(reversed(keep))
        self._total += len(keep)

    def _evict_lower_locked(self, priority: int) -> bool:
        """Drop the oldest queued item of the lowest priority kind strictly below `priority`; False if none."""
        victims = [k for k in self._kinds.values() if k.queue and k.priority < priority]
        if not victims:
            return False
        victim = min(victims, key=lambda k: k.priority)
        victim.queue.popleft()
        victim.dropped += 1
        self.dropped += 1
        self._total -= 1
        return True

    def _drop_bad(self, kind: str, items: list[Any], reason: str) -> None:
        """Count and log items that cannot be written (they are never retried)."""
        spec = self._kinds[kind]
        with self._lock:
            spec.dropped += len(items)
            self.dropped += len(items)
        log.error(
            "batch_items_dropped",
            extra={"fields": {"kind": kind, "count": len(items), "reason": reason[:300]}},
        )

    def _group_by_db(self, taken: dict[str, list[Any]]) -> dict[str, tuple[Database, list[str]]]:
        groups: dict[str, tuple[Database, list[str]]] = {}
        for kind in taken:
            db = self._kinds[kind].db
            groups.setdefault(db.name, (db, []))[1].append(kind)
        return groups

    def _writer_for(
        self, taken: dict[str, list[Any]], kinds: list[str], guard: _WriteGuard | None = None
    ) -> Callable[[sqlite3.Connection], None]:
        def write_batch(conn: sqlite3.Connection) -> None:
            if guard is not None and not guard.start():
                raise _Abandoned()  # rolled back; the canceled flush already put these items back
            for kind in kinds:
                self._kinds[kind].handler(conn, taken[kind])

        return write_batch

    async def flush(self) -> FlushResult:
        """Write everything queued so far: one transaction per database. Safe to call concurrently."""
        async with self._flush_lock:
            return await self._flush_with(lambda db, fn: db.write(fn))

    def flush_now(self) -> FlushResult:
        """Synchronous flush for shutdown: writes on the calling thread with `write_sync`."""
        started = time.perf_counter()
        taken = self._drain()
        written: dict[str, int] = {}
        failed: list[str] = []
        for db_name, (db, kinds) in self._group_by_db(taken).items():
            try:
                db.write_sync(self._writer_for(taken, kinds))
            except SharedStateUnavailable as exc:
                self._log_failure(db_name, kinds, exc)
                self._requeue_kinds(kinds, taken)
                failed.append(db_name)
                continue
            except Exception as exc:
                self._log_failure(db_name, kinds, exc)
                if not self._isolate_sync(db, kinds, taken, written):
                    failed.append(db_name)
                continue
            self._on_success(kinds, taken, written)
        return self._finish(written, failed, started)

    async def _flush_with(
        self, write: Callable[[Database, Callable[[sqlite3.Connection], None]], Awaitable[None]]
    ) -> FlushResult:
        started = time.perf_counter()
        taken = self._drain()
        written: dict[str, int] = {}
        failed: list[str] = []
        groups = list(self._group_by_db(taken).items())
        for index, (db_name, (db, kinds)) in enumerate(groups):
            guard = _WriteGuard()
            try:
                await write(db, self._writer_for(taken, kinds, guard))
            except asyncio.CancelledError:
                # Shutdown canceled this flush (plan 5.5 must not lose the drained items): put back this group
                # unless its write already started, and every group not reached yet, then let the cancel go on.
                if guard.abandon():
                    self._requeue_kinds(kinds, taken)
                for _name, (_db, later) in groups[index + 1 :]:
                    self._requeue_kinds(later, taken)
                raise
            except SharedStateUnavailable as exc:
                self._log_failure(db_name, kinds, exc)
                self._requeue_kinds(kinds, taken)
                failed.append(db_name)
                continue
            except Exception as exc:
                self._log_failure(db_name, kinds, exc)
                if not await self._isolate(write, db, kinds, taken, written):
                    failed.append(db_name)
                continue
            self._on_success(kinds, taken, written)
        return self._finish(written, failed, started)

    async def _isolate(
        self,
        write: Callable[[Database, Callable[[sqlite3.Connection], None]], Awaitable[None]],
        db: Database,
        kinds: list[str],
        taken: dict[str, list[Any]],
        written: dict[str, int],
    ) -> bool:
        """Write what can be written after a batch failed for a reason other than an unavailable database."""
        isolation = _Isolation(self, kinds, taken)
        try:
            while (segment := isolation.next()) is not None:
                kind, items = segment
                guard = _WriteGuard()
                try:
                    await write(db, self._writer_for({kind: items}, [kind], guard))
                except asyncio.CancelledError:
                    isolation.put_back(include_current=guard.abandon())
                    raise
                except SharedStateUnavailable:
                    isolation.put_back(include_current=True)  # the database went away: retry next flush
                    break
                except Exception as exc:
                    isolation.failed(exc)
                else:
                    isolation.succeeded()
        finally:
            isolation.finish(written)
        return isolation.clean

    def _isolate_sync(
        self, db: Database, kinds: list[str], taken: dict[str, list[Any]], written: dict[str, int]
    ) -> bool:
        """`_isolate` for `flush_now` (writes on the calling thread)."""
        isolation = _Isolation(self, kinds, taken)
        try:
            while (segment := isolation.next()) is not None:
                kind, items = segment
                try:
                    db.write_sync(self._writer_for({kind: items}, [kind]))
                except SharedStateUnavailable:
                    isolation.put_back(include_current=True)
                    break
                except Exception as exc:
                    isolation.failed(exc)
                else:
                    isolation.succeeded()
        finally:
            isolation.finish(written)
        return isolation.clean

    def _on_success(self, kinds: list[str], taken: dict[str, list[Any]], written: dict[str, int]) -> None:
        for kind in kinds:
            count = len(taken[kind])
            self._kinds[kind].written += count
            written[kind] = count

    def _log_failure(self, db_name: str, kinds: list[str], exc: Exception) -> None:
        self.flush_failures += 1
        level = logging.WARNING if isinstance(exc, SharedStateUnavailable) else logging.ERROR
        log.log(
            level,
            "batch_flush_failed",
            extra={"fields": {"db": db_name, "kinds": kinds, "error": f"{type(exc).__name__}: {exc}"}},
        )

    def _finish(self, written: dict[str, int], failed: list[str], started: float) -> FlushResult:
        self.flushes += 1
        self.last_flush_at = time.time()
        self.last_flush_ms = (time.perf_counter() - started) * 1000
        return FlushResult(written, failed, self.last_flush_ms)

    async def run(self, interval_s: Callable[[], float], stop: asyncio.Event) -> None:
        """Flush every `interval_s()` seconds until `stop` is set, then flush once more.

        The interval is read before every sleep, so a change to `metrics_flush_interval_ms` applies on the next
        cycle. Normally started through `ctx.tasks.start(...)`.
        """
        while not stop.is_set():
            with contextlib.suppress(TimeoutError):  # the normal case: the interval passed without a stop request
                await asyncio.wait_for(stop.wait(), timeout=max(0.05, interval_s()))
            stopping = stop.is_set()
            try:
                await self.flush()
                if not stopping and stop.is_set():
                    # The stop came while that flush ran: an item added meanwhile (after the flush drained the
                    # queues) gets the promised last flush instead of being left behind.
                    await self.flush()
            except Exception:
                log.exception("batch_flush_loop_error")

    # ------------------------------------------------------------------------------------------------- status

    @property
    def metrics_dropped(self) -> int:
        """Items dropped since start (the `metrics_dropped` counter of plan 6.3, same as `dropped`)."""
        return self.dropped

    def queued(self) -> int:
        """Items waiting right now (all kinds)."""
        with self._lock:
            return self._total

    def stats(self) -> dict[str, Any]:
        """Queue sizes, drops and flush timing for the System page (metrics pipeline card)."""
        with self._lock:
            kinds = {
                name: {"queued": len(k.queue), "dropped": k.dropped, "written": k.written, "priority": k.priority}
                for name, k in self._kinds.items()
            }
            total = self._total
        return {
            "queued": total,
            "max_items": self._limit(),
            "dropped": self.dropped,
            "flushes": self.flushes,
            "flush_failures": self.flush_failures,
            "last_flush_at": self.last_flush_at,
            "last_flush_ms": round(self.last_flush_ms, 3),
            "kinds": kinds,
        }
