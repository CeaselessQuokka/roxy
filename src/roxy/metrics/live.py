"""The live request tail: a per-worker ring of recent requests plus an events-table tail shared by all workers.

What this is
    `live_entry(...)` builds one Live row from an outcome event (parity row 126: outcome, reason, upstream
    status, egress, attempts, retries, duration, bypass, capture id, cache state and age, plus request id, queue
    wait and place). `LiveRing` is the worker's bounded in-memory history (`live_tail_buffer`, default 500).
    `EventTail` follows the `events` table by id every 500 ms and fans new rows out to subscribers (the SSE
    stream, plan 14.11), so a dashboard connected to worker A sees requests served by worker B. `LiveFilter`
    is the Live page filter, and `prune_live_events` is the leader job that keeps only the last 15 minutes of
    live rows in the table.

Why it exists
    v1 merged each worker's live list into a JSON file and the dashboard polled it, so rows appeared late and
    out of order, and the outcome filter missed two outcomes (row 81). Here every request becomes an `events`
    row of type `live`; ids are AUTOINCREMENT (never reused, even after a reset), so "everything after id N" is
    an exact, cheap index range read, and `Last-Event-ID` reconnects resume where they left off.

How it works
    - The recorder appends each entry to the ring and queues it as a `live` event, at most
      `LIVE_EVENTS_PER_SECOND` per worker (plan 14.11: sampled above 50 per second); entries beyond that stay in
      the ring and are counted as sampled out, so the database write rate stays bounded during a flood.
    - Live rows hold no bodies and no headers (those are in captures, when captured); every caller-supplied
      field is scrubbed like a log line: the URL, query, User-Agent and upstream error with `redact_text`, the
      template, host and place id with `redact_label` (a credential piece in a path segment or in the
      `Roblox-Id` header must not reach the Live feed, plan C1 and 9.15).
    - `EventTail.poll_once` reads at most `batch` rows with `id > last_id` in one read transaction. Each
      subscriber has a bounded queue (plan P9); a slow subscriber loses its oldest items and the loss is counted
      and reported to it, instead of growing memory.
    - The `live` rows are deleted by the leader after `LIVE_KEEP_S` (15 minutes, the Live range of plan 14.2),
      so they never crowd the long-term event history.

What to read next
    `roxy/metrics/recorder.py` (`record_outcome`), `roxy/metrics/capture.py` (the bodies behind a row).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import sqlite3
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from roxy.core.redact import redact_label, redact_query, redact_text

if TYPE_CHECKING:
    from roxy.metrics.recorder import OutcomeEvent
    from roxy.storage.db import Database

log = logging.getLogger(__name__)

LIVE_EVENT = "live"
LIVE_KEEP_S = 900
"""How long live rows stay in the `events` table (the Live range is the last 15 minutes, plan 14.2)."""

LIVE_EVENTS_PER_SECOND = 50.0
"""Live rows one worker writes per second at most (plan 14.11 samples the stream above 50 per second)."""

MAX_URL_CHARS = 2000
MAX_QUERY_CHARS = 2000
MAX_UA_CHARS = 400
MAX_ERROR_CHARS = 300

TAIL_POLL_S = 0.5
TAIL_BATCH = 500
MAX_SUBSCRIBERS = 64
SUBSCRIBER_QUEUE = 1000


def live_entry(ev: OutcomeEvent, capture_id: str = "") -> dict[str, Any]:
    """One Live row (row 126 fields; `UpstreamMethod` became `egress`). Redacted, bounded, JSON-ready."""
    url = ev.path or ev.endpoint_template
    return {
        "request_id": ev.request_id,
        "at_ms": int(ev.at_ms),
        "ip": ev.client_ip[:64],
        "method": ev.method[:12],
        "url": redact_text(url)[:MAX_URL_CHARS],
        "query": redact_query(ev.query)[:MAX_QUERY_CHARS] if ev.query else "",
        "template": redact_label(ev.endpoint_template),
        "host": redact_label(ev.host),
        "status": int(ev.status),
        "outcome": str(ev.outcome),
        "reason": str(ev.reason),
        "source": str(ev.source),
        "place": redact_label(ev.place_id) if ev.place_id else ev.place_id,
        "user_agent": redact_text(ev.user_agent)[:MAX_UA_CHARS] if ev.user_agent else "",
        "upstream_status": ev.upstream_status,
        "egress": str(ev.egress),
        "upstream_error": redact_text(ev.upstream_error)[:MAX_ERROR_CHARS] if ev.upstream_error else "",
        "attempts": int(ev.attempts),
        "retries": int(ev.retries),
        "duration_ms": round(float(ev.latency_ms), 3),
        "queue_wait_ms": round(float(ev.queue_wait_ms), 3),
        "bypass": bool(ev.bypass),
        "capture_id": capture_id or ev.capture_id or "",
        "cache": str(ev.cache_state),
        "cache_age_s": ev.cache_age_s,
    }


@dataclass(frozen=True, slots=True)
class LiveFilter:
    """The Live page filter (plan 14.1: outcome, status, egress, cache state, client, endpoint, free text).

    Empty fields match everything. `outcomes` covers every outcome and reason, so no value is missing from the
    filter (row 81 "outcome filter complete": v1 lacked `user_agent_rule` and `ignored_path`).
    """

    outcomes: frozenset[str] = frozenset()
    reasons: frozenset[str] = frozenset()
    statuses: frozenset[int] = frozenset()
    egress: frozenset[str] = frozenset()
    cache: frozenset[str] = frozenset()
    client: str = ""
    endpoint: str = ""
    text: str = ""

    def matches(self, entry: dict[str, Any]) -> bool:
        if self.outcomes and entry.get("outcome") not in self.outcomes:
            return False
        if self.reasons and entry.get("reason") not in self.reasons:
            return False
        if self.statuses and entry.get("status") not in self.statuses:
            return False
        if self.egress and entry.get("egress") not in self.egress:
            return False
        if self.cache and entry.get("cache") not in self.cache:
            return False
        if self.client and self.client not in (entry.get("ip"), entry.get("place")):
            return False
        if (
            self.endpoint
            and self.endpoint not in (entry.get("template") or "")
            and self.endpoint not in (entry.get("url") or "")
        ):
            return False
        if self.text:
            needle = self.text.lower()
            haystack = " ".join(
                str(entry.get(k) or "") for k in ("url", "ip", "method", "place", "user_agent", "status", "outcome")
            ).lower()
            if needle not in haystack:
                return False
        return True


class LiveRing:
    """This worker's recent requests, newest last; bounded by `live_tail_buffer` (0 keeps none)."""

    def __init__(self, size: int = 500) -> None:
        self._ring: deque[dict[str, Any]] = deque(maxlen=max(0, int(size)))

    @property
    def size(self) -> int:
        return self._ring.maxlen or 0

    def resize(self, size: int) -> None:
        size = max(0, int(size))
        if size != self.size:
            self._ring = deque(self._ring, maxlen=size)

    def append(self, entry: dict[str, Any]) -> None:
        if self._ring.maxlen:
            self._ring.append(entry)

    def snapshot(self, live_filter: LiveFilter | None = None, limit: int = 500) -> list[dict[str, Any]]:
        """Newest first, filtered, at most `limit` rows."""
        out: list[dict[str, Any]] = []
        for entry in reversed(self._ring):
            if live_filter is None or live_filter.matches(entry):
                out.append(entry)
                if len(out) >= limit:
                    break
        return out

    def clear(self) -> None:
        self._ring.clear()

    def __len__(self) -> int:
        return len(self._ring)


class RateGate:
    """A token bucket: `allow()` is True at most `rate` times per second on average, with `burst` in hand."""

    def __init__(self, rate: float, burst: float, clock: Callable[[], float]) -> None:
        self.rate = rate
        self.burst = burst
        self._clock = clock
        self._tokens = burst
        self._at = clock()

    def allow(self) -> bool:
        now = self._clock()
        # max(0, ...) tolerates a clock that steps backwards (WSL does): no refill, never negative.
        self._tokens = min(self.burst, self._tokens + max(0.0, now - self._at) * self.rate)
        self._at = max(self._at, now)
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False


# ------------------------------------------------------------------------------------------ events tail


@dataclass(slots=True)
class TailItem:
    """One `events` row as delivered to a subscriber (`detail` parsed)."""

    id: int
    at_ms: int
    type: str
    severity: str
    reason: str | None
    endpoint_template: str | None
    detail: dict[str, Any]


@dataclass(eq=False)
class Subscription:
    """One subscriber (one SSE stream). Read with `await sub.get()`; `lost` counts items dropped for slowness."""

    types: frozenset[str] | None
    live_filter: LiveFilter | None
    queue: asyncio.Queue[TailItem] = field(default_factory=lambda: asyncio.Queue(SUBSCRIBER_QUEUE))
    lost: int = 0
    closed: bool = False

    def wants(self, item: TailItem) -> bool:
        if self.types is not None and item.type not in self.types:
            return False
        if item.type == LIVE_EVENT and self.live_filter is not None:
            return self.live_filter.matches(item.detail)
        return True

    def offer(self, item: TailItem) -> None:
        if self.closed or not self.wants(item):
            return
        if self.queue.full():
            with contextlib.suppress(asyncio.QueueEmpty):
                self.queue.get_nowait()  # drop the oldest: a slow reader must not grow memory (plan P9)
            self.lost += 1
        self.queue.put_nowait(item)

    async def get(self) -> TailItem:
        return await self.queue.get()


def _parse(row: sqlite3.Row) -> TailItem:
    try:
        detail = json.loads(row["detail_json"]) if row["detail_json"] else {}
    except ValueError:
        detail = {}
    return TailItem(
        id=int(row["id"]),
        at_ms=int(row["at_ms"]),
        type=str(row["type"]),
        severity=str(row["severity"]),
        reason=row["reason_code"],
        endpoint_template=row["endpoint_template"],
        detail=detail if isinstance(detail, dict) else {},
    )


def read_after(
    conn: sqlite3.Connection, after_id: int, limit: int, types: Iterable[str] | None = None
) -> list[TailItem]:
    """Events with `id > after_id`, oldest first (an index range read on the primary key)."""
    wanted = sorted(set(types)) if types is not None else []
    if wanted:
        marks = ", ".join("?" for _ in wanted)
        rows = conn.execute(
            f"SELECT id, at_ms, type, severity, reason_code, endpoint_template, detail_json FROM events "  # noqa: S608
            f"WHERE id > ? AND type IN ({marks}) ORDER BY id LIMIT ?",
            (int(after_id), *wanted, int(limit)),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, at_ms, type, severity, reason_code, endpoint_template, detail_json FROM events "
            "WHERE id > ? ORDER BY id LIMIT ?",
            (int(after_id), int(limit)),
        ).fetchall()
    return [_parse(r) for r in rows]


def max_event_id(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT coalesce(max(id), 0) FROM events").fetchone()
    return int(row[0])


class EventTail:
    """Follows `events` by id for this worker's subscribers (one poll per worker, not one per subscriber)."""

    def __init__(
        self,
        db: Database,
        *,
        poll_s: float = TAIL_POLL_S,
        batch: int = TAIL_BATCH,
        max_subscribers: int = MAX_SUBSCRIBERS,
    ) -> None:
        self.db = db
        self.poll_s = poll_s
        self.batch = batch
        self.max_subscribers = max_subscribers
        self.last_id: int | None = None
        self._subs: list[Subscription] = []
        self.polls = 0
        self.errors = 0

    def subscribe(self, *, types: Iterable[str] | None = None, live_filter: LiveFilter | None = None) -> Subscription:
        """Add a subscriber. Raises RuntimeError when `max_subscribers` are already connected (plan P9)."""
        if len(self._subs) >= self.max_subscribers:
            raise RuntimeError("too many live subscribers")
        sub = Subscription(frozenset(types) if types is not None else None, live_filter)
        self._subs.append(sub)
        return sub

    def unsubscribe(self, sub: Subscription) -> None:
        sub.closed = True
        with contextlib.suppress(ValueError):
            self._subs.remove(sub)

    async def backfill(self, sub: Subscription, after_id: int, limit: int = TAIL_BATCH) -> int:
        """Deliver rows after `after_id` to one subscriber (a reconnect with `Last-Event-ID`). Returns how many."""
        types = sub.types
        items = await self.db.read(lambda conn: read_after(conn, after_id, limit, types))
        upto = self.last_id if self.last_id is not None else None
        sent = 0
        for item in items:
            if upto is not None and item.id > upto:
                break  # newer rows arrive through the normal poll; never deliver one twice
            sub.offer(item)
            sent += 1
        return sent

    async def poll_once(self) -> int:
        """Read the rows added since the last poll and hand them to every subscriber. Returns rows read."""
        self.polls += 1
        if self.last_id is None:
            self.last_id = await self.db.read(max_event_id)  # start at "now": history is the ring's job
            return 0
        after = self.last_id
        items = await self.db.read(lambda conn: read_after(conn, after, self.batch))
        for item in items:
            for sub in list(self._subs):
                sub.offer(item)
        if items:
            self.last_id = items[-1].id
        return len(items)

    async def run(self, stop: asyncio.Event) -> None:
        """Poll every `poll_s` until `stop` is set (started per worker by the lifespan, plan 5.6 SSE tail)."""
        while not stop.is_set():
            try:
                read = await self.poll_once()
            except Exception as exc:  # metrics fail open: a busy database only delays the stream
                self.errors += 1
                log.warning("event_tail_poll_failed", extra={"fields": {"error": f"{type(exc).__name__}: {exc}"}})
                read = 0
            if read >= self.batch:
                continue  # behind: read the next batch at once
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=self.poll_s)

    @property
    def subscribers(self) -> int:
        return len(self._subs)


def prune_live_events(conn: sqlite3.Connection, now_s: float, keep_s: int = LIVE_KEEP_S, limit: int = 20_000) -> int:
    """Delete `live` rows older than `keep_s` (leader job). Uses the `(type, at_ms)` index."""
    cutoff_ms = int((now_s - keep_s) * 1000)
    return conn.execute(
        "DELETE FROM events WHERE id IN (SELECT id FROM events WHERE type = ? AND at_ms < ? ORDER BY at_ms LIMIT ?)",
        (LIVE_EVENT, cutoff_ms, int(limit)),
    ).rowcount
