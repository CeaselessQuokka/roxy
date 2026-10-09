"""The dashboard's event stream: `GET /admin/api/v1/stream` (Server-Sent Events, plan 14.11, parity rows 81 and 90).

What this is
    One long-lived HTTP response per dashboard tab that pushes what changed, as `text/event-stream` frames:
      * `kpi` every 2 seconds (coalesced: a slow reader gets the newest numbers, never a backlog): the Live range
        totals (requests, demand, avoided, upstream calls, Roblox and Roxy 429s, 5xx, p95), the requests of the
        last hour, the proxy's pause and emergency-limit state, and this stream's own sampling counters.
      * `live`: one row per request matching the client's filter (outcome, reason, status, egress, cache, client,
        endpoint, text: the Live page's filter), sampled when they arrive faster than 50 a second.
      * `recommendation`, `health`, `alert`, `breaker`, `cooldown`: notable events as the recorder, the insights
        engine and the health runner write them (`events` rows); `cooldown` also reports upstream cooldowns
        starting and ending (from hot.db, compared every 2 seconds).
      * `settings_changed` when the settings snapshot's `config_version` moves.
      * `unauthorized` (status 401) when the session expires or is revoked; the stream then ends, and the client's
        reconnect gets a real 401 (the session-expired overlay, row 119).
      * `gap` when a `Last-Event-ID` resume could not deliver everything that was missed (the page reloads).
    Comment lines (`: keepalive`) every 15 seconds keep proxies from closing an idle stream.

Why it exists
    v1 polled one large JSON document every few seconds from every open tab (row 90). Pushing deltas is cheaper and
    faster, and because every worker writes its events to the shared `events` table and each worker tails that
    table (`metrics/live.py EventTail`), a dashboard connected to worker A sees requests and events of worker B.

How it works
    * Guards: `require_admin("session", activity="never")` (watching the stream is not use; an unattended tab
      expires, plan 9.6) on an `AdminApiRoute`, so a bad parameter is a DESIGN.md section 13 error. The request
      deadline is switched off for this response only (`core/deadline.py disable_deadline`).
    * Bounds (plan P9, C6): at most `MAX_STREAMS_PER_SESSION` streams per session across the fleet (counted hot.db
      slot leases, renewed while open, expiring by themselves if a worker dies) and per worker in memory, which is
      also the fallback while hot.db cannot be written; at most `metrics.live.MAX_SUBSCRIBERS` per worker. Each
      stream has one bounded subscription queue (`metrics.live.SUBSCRIBER_QUEUE`, oldest dropped and counted as
      `lost`); `kpi` and cooldown changes come from one per-worker hub (`StreamHub`), computed once every 2 seconds
      for every stream of the worker and only while at least one is open.
    * Resume: frames that come from an `events` row carry `id: <row id>`. A reconnect with `Last-Event-ID: N` first
      replays rows with an id above N up to the tail's position at subscription time (at most `BACKFILL_MAX`), then
      continues with live rows above it, so no row is sent twice and none is skipped in between.
    * Session: every `SESSION_CHECK_S` the stream re-reads its session (without touching it); a session that is
      gone, idle past its timeout, revoked by the kill switch or past its absolute lifetime ends the stream with
      `unauthorized`. A worker that starts draining ends its streams at once, so shutdown never waits on them.

    * Mounting: `roxy.admin.api` builds its router on first use (`api_router`, `MOUNTED`), not at import, so this
      module may be imported before or after the API package; the mount checks see it fully built either way.

What to read next
    `roxy/metrics/live.py` (the tail and the live rows), `static/js/sse.js` (the client),
    `roxy/admin/api/live.py` (the first screen of the Live page).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import secrets
import sqlite3
import time
import weakref
from collections import deque
from collections.abc import AsyncIterator, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Annotated, Any, Final

from fastapi import Depends, Header, Query, Request
from starlette.responses import StreamingResponse

from roxy.admin.api.common import area_router, rate_limited, unavailable, validation_error
from roxy.admin.auth import sessions
from roxy.admin.auth.deps import AdminPrincipal, get_auth, require_admin
from roxy.admin.auth.flow import AuthError
from roxy.core.deadline import disable_deadline
from roxy.metrics import queries, read_dashboard
from roxy.metrics.live import LIVE_EVENT, RateGate, read_after
from roxy.storage import leases
from roxy.storage.db import SharedStateUnavailable

log = logging.getLogger(__name__)

router = area_router("stream")

stream_session = require_admin("session", activity="never")
"""The stream's guard: a signed-in admin; reading the stream never counts as activity (plan 9.6)."""

EVENT_KINDS: Final[tuple[str, ...]] = (
    "kpi",
    "live",
    "recommendation",
    "health",
    "alert",
    "settings_changed",
    "breaker",
    "cooldown",
)
"""The stream's event names (plan 14.11). `unauthorized` and `gap` are control events and are always sent."""

TYPE_KINDS: Final[dict[str, str]] = {
    LIVE_EVENT: "live",
    "recommendation": "recommendation",
    "health_run_started": "health",
    "health_result": "health",
    "health_run_finished": "health",
    "breaker_open": "breaker",
    "breaker_half_open": "breaker",
    "breaker_closed": "breaker",
    "credential_cooldown": "cooldown",
    "rotator_parked": "cooldown",
    "upstream_429_attribution": "cooldown",
    "leak_blocked": "alert",
    "credential_rotated": "alert",
    "credential_rejected": "alert",
    "abuse_degraded": "alert",
    "spam_ban": "alert",
}
"""Which `events.type` values the stream forwards, and under which event name."""

KPI_INTERVAL_S: Final = 2.0
"""Plan 14.11: `kpi` every 2 seconds."""
LIVE_RATE: Final = 50.0
"""Plan 14.11: live rows are sampled above 50 a second (per stream; the rest are counted, never queued)."""
HEARTBEAT_S: Final = 15.0
"""A comment line this often keeps nginx (`proxy_read_timeout` 100 s) and browsers from closing an idle stream."""
SESSION_CHECK_S: Final = 5.0
"""How often a stream re-reads its session (an expired or revoked session ends the stream this soon)."""
SESSION_FAILURES_MAX: Final = 3
"""Consecutive session checks that could not read control.db before the stream gives up (the reconnect decides)."""
TICK_S: Final = 0.25
"""The stream loop's longest sleep: how promptly a new `kpi`, setting or drain is noticed."""
MAX_STREAMS_PER_SESSION: Final = 6
"""Open streams per admin session (a page holds one, the Live page two; several tabs fit)."""
MAX_LOCAL_SESSIONS: Final = 256
"""Sessions one worker tracks stream counts for (plan P9); the slot leases are the fleet-wide bound."""
SLOT_TTL_MS: Final = 60_000
SLOT_RENEW_S: Final = 20.0
BACKFILL_MAX: Final = 500
"""Rows one `Last-Event-ID` resume replays at most; beyond that the client gets `gap` and reloads."""
DRAIN_PER_TICK: Final = 200
"""Subscription items one loop turn forwards before it looks at its timers again."""
MAX_COOLDOWN_ROWS: Final = 1000
COOLDOWN_SNAPSHOT_MAX: Final = 50
MAX_CHANGES: Final = 256
"""Cooldown changes the hub remembers for streams that are a little behind (plan P9)."""
RETRY_MS: Final = 3000
TAIL_WAIT_S: Final = 2.0
"""How long a new stream waits for a worker's tail to take its first position (only right after startup)."""
TAIL_WAIT_STEP_S: Final = 0.05
STREAM_KPIS: Final[tuple[str, ...]] = (
    "requests",
    "demand",
    "avoided",
    "avoided_pct",
    "upstream_calls",
    "roblox_429",
    "roxy_429",
    "status_5xx",
    "served_cache",
    "p95_ms",
    "requests_last_hour",
)
MAX_EVENT_PARAM: Final = 200


# ------------------------------------------------------------------------------------------------ frames


def frame(event: str, data: Any, event_id: int | None = None) -> bytes:
    """One SSE frame. JSON never holds a raw line break (it escapes them), so `data` is always one line."""
    text = json.dumps(data, separators=(",", ":"), ensure_ascii=False, default=str)
    head = f"id: {int(event_id)}\n" if event_id is not None else ""
    return f"{head}event: {event}\ndata: {text}\n\n".encode()


def comment(text: str) -> bytes:
    return f": {text}\n\n".encode()


def live_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    """A live row plus the names the dashboard's live tail reads (`client`, `endpoint`, `latency_ms`)."""
    out = dict(row)
    out.setdefault("client", row.get("ip"))
    out.setdefault("endpoint", row.get("url") or row.get("template"))
    out.setdefault("latency_ms", row.get("duration_ms"))
    return out


def parse_kinds(raw: str | None) -> frozenset[str]:
    """The `events` parameter: a comma separated subset of `EVENT_KINDS` (all of them when absent)."""
    if not raw:
        return frozenset(EVENT_KINDS)
    kinds = {item.strip() for item in raw.split(",") if item.strip()}
    unknown = sorted(kinds - set(EVENT_KINDS))
    if unknown:
        raise validation_error(
            {"events": f"Unknown event {unknown[0][:32]!r}; choose from {', '.join(EVENT_KINDS)}."},
            "The stream parameters are not valid.",
        )
    return frozenset(kinds)


def parse_last_event_id(header: str | None, query: str | None) -> int | None:
    """`Last-Event-ID` (header first, then the `last_event_id` parameter); anything but a small integer is ignored."""
    for raw in (header, query):
        text = (raw or "").strip()
        if text.isdigit() and len(text) <= 18:
            return int(text)
    return None


def tail_types(kinds: Iterable[str]) -> frozenset[str]:
    """The `events.type` values a stream with these event kinds subscribes to."""
    wanted = set(kinds)
    return frozenset(event_type for event_type, kind in TYPE_KINDS.items() if kind in wanted)


# ------------------------------------------------------------------------------------------------ the hub


@dataclass(slots=True)
class StreamHub:
    """Per-worker state shared by every stream of the worker: the newest `kpi` and the cooldown changes.

    One background task computes them every `KPI_INTERVAL_S` while at least one stream is open (one metrics.db
    read and one hot.db read per worker, whatever the number of streams), and stops when the last one closes.
    """

    ctx: Any
    kpi: dict[str, Any] | None = None
    kpi_seq: int = 0
    kpi_mono: float = 0.0
    """When `kpi` was computed (monotonic seconds): a new stream gets it at once only while it is fresh."""
    cooldowns: dict[str, dict[str, Any]] | None = None
    changes: deque[tuple[int, dict[str, Any]]] = field(default_factory=lambda: deque(maxlen=MAX_CHANGES))
    change_seq: int = 0
    users: int = 0
    task: asyncio.Task[None] | None = None
    errors: int = 0
    local_streams: dict[str, int] = field(default_factory=dict)
    releases: set[asyncio.Task[Any]] = field(default_factory=set)

    def join(self) -> None:
        self.users += 1
        if self.task is None or self.task.done():
            self.task = asyncio.get_running_loop().create_task(self._run(), name="roxy:sse-hub")

    def leave(self) -> None:
        self.users = max(0, self.users - 1)
        if self.users == 0 and self.task is not None:
            # Nobody is listening: no more reads until the next stream opens. The task is forgotten at once (a
            # canceled task is not `done()` until it next runs, and `join` must start a new one right away), and
            # what it knew is dropped, so the next start takes a fresh baseline instead of diffing against old rows.
            self.task.cancel()
            self.task = None
            self.kpi = None
            self.cooldowns = None

    async def _run(self) -> None:
        while self.users > 0:
            try:
                await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # a busy database delays the numbers; the streams go on (metrics fail open)
                self.errors += 1
                if self.errors == 1 or self.errors % 100 == 0:
                    log.warning("sse_hub_tick_failed", extra={"fields": {"error": f"{type(exc).__name__}: {exc}"}})
            await asyncio.sleep(KPI_INTERVAL_S)

    async def tick(self) -> None:
        """Compute the newest `kpi` and the cooldown changes (once per worker)."""
        self.kpi = await kpi_snapshot(self.ctx)
        self.kpi_seq += 1
        self.kpi_mono = time.monotonic()
        await self._cooldowns()

    async def _cooldowns(self) -> None:
        upstream = getattr(self.ctx, "upstream", None)
        if upstream is None:
            return
        try:
            rows = await upstream.cooldown_snapshot(limit=MAX_COOLDOWN_ROWS)
        except SharedStateUnavailable:
            return
        now_ms = self.ctx.clock.now_ms()
        current = {
            row.key: {
                "key": row.key,
                "until_ms": int(row.until_ms),
                "source": row.source,
                "remaining_s": round(row.remaining_s(now_ms), 1),
            }
            for row in rows
        }
        previous = self.cooldowns
        self.cooldowns = current
        if previous is None:
            return  # the first look is the baseline; new streams get it as a snapshot
        for key, item in current.items():
            old = previous.get(key)
            if old is None or old["until_ms"] != item["until_ms"]:
                self._change({"action": "started" if old is None else "extended", **item})
        for key, item in previous.items():
            if key not in current:
                self._change({"action": "ended", "key": key, "source": item["source"]})

    def _change(self, payload: dict[str, Any]) -> None:
        self.change_seq += 1
        self.changes.append((self.change_seq, payload))

    def changes_after(self, seq: int) -> list[tuple[int, dict[str, Any]]]:
        return [(n, payload) for n, payload in self.changes if n > seq]

    def snapshot(self) -> list[dict[str, Any]]:
        """The cooldowns active at the last look (a new stream's starting point), most recent end first."""
        rows = sorted((self.cooldowns or {}).values(), key=lambda item: -int(item["until_ms"]))
        return rows[:COOLDOWN_SNAPSHOT_MAX]

    # ---- the per-worker stream count (the fallback bound while hot.db cannot be written) ----

    def local_take(self, session: str) -> bool:
        count = self.local_streams.get(session, 0)
        if count >= MAX_STREAMS_PER_SESSION:
            return False
        if count == 0 and len(self.local_streams) >= MAX_LOCAL_SESSIONS:
            return False
        self.local_streams[session] = count + 1
        return True

    def local_give(self, session: str) -> None:
        count = self.local_streams.get(session, 0) - 1
        if count > 0:
            self.local_streams[session] = count
        else:
            self.local_streams.pop(session, None)

    def later(self, coro: Any) -> None:
        """Run a cleanup write on its own task, so a canceled response cannot cancel it (bounded by the slot cap)."""
        task = asyncio.get_running_loop().create_task(coro, name="roxy:sse-release")
        self.releases.add(task)
        task.add_done_callback(self.releases.discard)


def hub_for(request: Request) -> StreamHub:
    """This worker's hub (created on first use; rebuilt if the worker context was replaced)."""
    ctx = request.app.state.ctx
    hub = getattr(request.app.state, "sse_hub", None)
    if not isinstance(hub, StreamHub) or hub.ctx is not ctx:
        hub = StreamHub(ctx)
        request.app.state.sse_hub = hub
    return hub


async def kpi_snapshot(ctx: Any) -> dict[str, Any]:
    """The `kpi` payload: Live range totals (the last 15 minutes) from the same read model as the Overview."""
    now = ctx.clock.now()
    tz = str(ctx.settings.get("ui_timezone") or "UTC")
    window = queries.resolve_window("live", now=now, tz=tz)
    data = await queries.kpis(ctx.dbs.metrics, window, now=now)
    tiles = data["tiles"]
    switches = getattr(getattr(ctx, "abuse", None), "switches", None)
    proxy: dict[str, Any] = {"paused": None, "throttle_all": None}
    if switches is not None:
        proxy = {"paused": bool(switches.pause.active(now)), "throttle_all": bool(switches.throttle_all.enabled)}
    return {
        "at": now,
        "range": {"from": window.start, "to": window.end, "granularity": window.granularity, "tz": window.tz},
        "values": {key: tiles.get(key, {}).get("value") for key in STREAM_KPIS},
        "proxy": proxy,
        "config_version": int(getattr(ctx.settings, "version", 0) or 0),
    }


# ------------------------------------------------------------------------------------------------ slots


def _slot_prefix(principal: AdminPrincipal) -> str:
    return f"sse:{sessions.public_id(principal.session_id)}:"


async def _take_slot(ctx: Any, prefix: str, holder: str) -> tuple[str | None, bool]:
    """`(slot name, shared)`: a fleet-wide slot (None when the session is at its cap), or `(None, False)` when hot.db
    cannot be written (the per-worker count is then the only bound, C7)."""
    now_ms = ctx.clock.now_ms()
    try:
        slot = await ctx.dbs.hot.write(
            lambda conn: leases.acquire_slot(conn, prefix, holder, MAX_STREAMS_PER_SESSION, SLOT_TTL_MS, now_ms),
            busy_timeout_ms=1000,
        )
    except SharedStateUnavailable:
        return None, False
    return slot, True


async def _renew_slot(ctx: Any, slot: str, holder: str) -> bool:
    now_ms = ctx.clock.now_ms()
    try:
        renewed: bool = await ctx.dbs.hot.write(
            lambda conn: leases.renew(conn, slot, holder, SLOT_TTL_MS, now_ms), busy_timeout_ms=1000
        )
    except SharedStateUnavailable:
        return True  # keep streaming; the slot expires by itself if this worker can never write again
    return renewed


async def _release_slot(ctx: Any, slot: str, holder: str) -> None:
    with contextlib.suppress(SharedStateUnavailable, sqlite3.Error):
        await ctx.dbs.hot.write(lambda conn: leases.release(conn, slot, holder, delete=True), busy_timeout_ms=2000)


def _abandoned(
    ctx: Any, hub: StreamHub, sub: Any, joined: bool, session_key: str, slot: str | None, holder: str
) -> None:
    """Give back what a stream took when its response was dropped before the stream ever ran (the client left at
    once): a generator that never started runs no `finally`, so `Stream.close` would never be called."""
    tail = getattr(ctx, "live_tail", None)
    if tail is not None and sub is not None:
        tail.unsubscribe(sub)
    if joined:
        with contextlib.suppress(RuntimeError):  # canceling the hub task on a loop that already closed
            hub.leave()
    hub.local_give(session_key)
    if slot is not None:
        with contextlib.suppress(RuntimeError):  # no running loop: the slot lease expires by itself
            hub.later(_release_slot(ctx, slot, holder))


# ------------------------------------------------------------------------------------------------ one stream


@dataclass(slots=True, weakref_slot=True)
class Stream:
    """One open stream (one response). Created by the route; `run()` yields its frames."""

    request: Request
    ctx: Any
    hub: StreamHub
    principal: AdminPrincipal
    token: str
    kinds: frozenset[str]
    query: read_dashboard.LiveQuery
    after_id: int | None
    slot: str | None
    holder: str
    session_key: str
    sub: Any = None
    mark: int | None = None
    gate: RateGate = field(default_factory=lambda: RateGate(LIVE_RATE, LIVE_RATE, time.monotonic))
    sampled_out: int = 0
    sent: int = 0
    kpi_seq: int = 0
    change_seq: int = 0
    config_version: int = -1
    session_failures: int = 0
    closed: bool = False
    guard: Any = None
    """A `weakref.finalize` that gives everything back if this stream is dropped without running (`_abandoned`)."""

    async def start(self) -> None:
        """Subscribe to the worker's tail (with a prefilter) and note its position for an exact resume."""
        tail = self.ctx.live_tail
        types = tail_types(self.kinds)
        for _ in range(int(TAIL_WAIT_S / TAIL_WAIT_STEP_S)):
            if tail.last_id is not None:
                break
            await asyncio.sleep(TAIL_WAIT_STEP_S)  # only right after startup: the tail takes its first position
        self.sub = tail.subscribe(types=types, live_filter=self.query.base)
        self.mark = tail.last_id
        self.config_version = int(getattr(self.ctx.settings, "version", 0) or 0)
        self.change_seq = self.hub.change_seq
        self.hub.join()
        self.guard = weakref.finalize(
            self, _abandoned, self.ctx, self.hub, self.sub, True, self.session_key, self.slot, self.holder
        )

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self.guard is not None:
            self.guard.detach()  # cleaned up here, so the safety net must not run again
        tail = getattr(self.ctx, "live_tail", None)
        if tail is not None and self.sub is not None:
            tail.unsubscribe(self.sub)
        self.hub.leave()
        self.hub.local_give(self.session_key)
        if self.slot is not None:
            self.hub.later(_release_slot(self.ctx, self.slot, self.holder))

    def _item_frame(self, item: Any) -> bytes | None:
        """The frame of one tail item, or None when this stream does not want it (filter, kind, sampling)."""
        kind = TYPE_KINDS.get(item.type)
        if kind is None or kind not in self.kinds:
            return None
        if kind == "live":
            if not self.query.matches(item.detail):
                return None
            if not self.gate.allow():
                self.sampled_out += 1
                return None
            return frame("live", {**live_payload(item.detail), "event_id": item.id}, item.id)
        payload = {
            "type": item.type,
            "severity": item.severity,
            "reason": item.reason,
            "endpoint_template": item.endpoint_template,
            "at_ms": item.at_ms,
            "detail": item.detail,
        }
        return frame(kind, payload, item.id)

    async def backfill(self) -> AsyncIterator[bytes]:
        """Replay rows after `Last-Event-ID` up to the tail's position at subscription (see the module docstring)."""
        if self.after_id is None or self.mark is None or self.after_id >= self.mark:
            return
        after, mark = self.after_id, self.mark
        types = sorted(tail_types(self.kinds))
        items = await self.ctx.dbs.metrics.read(lambda conn: read_after(conn, after, BACKFILL_MAX, types))
        delivered_to = after
        for item in items:
            if item.id > mark:
                break
            delivered_to = item.id
            data = self._item_frame(item)
            if data is not None:
                yield data
        if len(items) >= BACKFILL_MAX and delivered_to < mark:
            yield frame("gap", {"after_id": after, "resumed_to": delivered_to, "position": mark})

    def _kpi_frame(self) -> bytes | None:
        kpi = self.hub.kpi
        if kpi is None or "kpi" not in self.kinds or self.hub.kpi_seq == self.kpi_seq:
            return None
        self.kpi_seq = self.hub.kpi_seq
        lost = int(getattr(self.sub, "lost", 0) or 0)
        return frame("kpi", {**kpi, "stream": {"live_sampled_out": self.sampled_out, "lost": lost}})

    def _change_frames(self) -> list[bytes]:
        out: list[bytes] = []
        if "cooldown" in self.kinds:
            for seq, payload in self.hub.changes_after(self.change_seq):
                out.append(frame("cooldown", payload))
                self.change_seq = seq
        if "settings_changed" in self.kinds:
            version = int(getattr(self.ctx.settings, "version", 0) or 0)
            if version != self.config_version:
                self.config_version = version
                out.append(frame("settings_changed", {"config_version": version}))
        return out

    async def _session_alive(self) -> bool:
        """Re-read the session without touching it; False once it is gone, expired, idle or revoked."""
        try:
            record = await get_auth(self.request).load_session(self.token)
        except AuthError:
            self.session_failures += 1
            return self.session_failures < SESSION_FAILURES_MAX
        self.session_failures = 0
        return record is not None and record.id_hash == self.principal.session_id

    async def run(self) -> AsyncIterator[bytes]:
        """The frames of this stream until the session ends, the worker drains or the client goes away."""
        try:
            yield f"retry: {RETRY_MS}\n\n".encode()
            async for data in self.backfill():
                yield data
            fresh = time.monotonic() - self.hub.kpi_mono <= 2 * KPI_INTERVAL_S
            self.kpi_seq = self.hub.kpi_seq  # an old `kpi` is never sent: the hub's next tick is
            if self.hub.kpi is not None and "kpi" in self.kinds and fresh:
                yield frame("kpi", {**self.hub.kpi, "stream": {"live_sampled_out": 0, "lost": 0}})
            snapshot_due = "cooldown" in self.kinds  # the cooldown list once, as soon as the hub has looked
            if snapshot_due and self.hub.cooldowns is not None:
                snapshot_due = False
                yield frame("cooldown", {"action": "snapshot", "active": self.hub.snapshot()})
            mono = time.monotonic
            next_session = mono() + SESSION_CHECK_S
            next_heartbeat = mono() + HEARTBEAT_S
            next_renew = mono() + SLOT_RENEW_S
            while True:
                if not getattr(self.ctx, "ready", True):
                    yield comment("server restarting")
                    return
                now = mono()
                if now >= next_session:
                    next_session = now + SESSION_CHECK_S
                    if not await self._session_alive():
                        yield frame(
                            "unauthorized", {"status": 401, "code": "unauthorized", "message": "Session expired"}
                        )
                        return
                if self.slot is not None and now >= next_renew:
                    next_renew = now + SLOT_RENEW_S
                    if not await _renew_slot(self.ctx, self.slot, self.holder):
                        slot, _shared = await _take_slot(self.ctx, _slot_prefix(self.principal), self.holder)
                        if slot is None and _shared:
                            yield comment("stream limit reached")
                            return
                        self.slot = slot
                kpi = self._kpi_frame()
                if kpi is not None:
                    yield kpi
                if snapshot_due and self.hub.cooldowns is not None:
                    snapshot_due = False
                    self.change_seq = self.hub.change_seq  # the snapshot already holds every earlier change
                    yield frame("cooldown", {"action": "snapshot", "active": self.hub.snapshot()})
                for data in self._change_frames():
                    yield data
                drained = 0
                while drained < DRAIN_PER_TICK:
                    try:
                        item = self.sub.queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break
                    drained += 1
                    queued = self._item_frame(item)
                    if queued is not None:
                        self.sent += 1
                        yield queued
                if now >= next_heartbeat:
                    next_heartbeat = now + HEARTBEAT_S
                    yield comment("keepalive")
                if drained >= DRAIN_PER_TICK:
                    continue  # behind: keep forwarding before sleeping
                try:
                    item = await asyncio.wait_for(self.sub.queue.get(), timeout=TICK_S)
                except TimeoutError:
                    continue
                arrived = self._item_frame(item)
                if arrived is not None:
                    self.sent += 1
                    yield arrived
        finally:
            self.close()


# ------------------------------------------------------------------------------------------------ the route

Param = Annotated[str | None, Query(max_length=MAX_EVENT_PARAM * 4)]


@router.get("")
async def stream(
    request: Request,
    principal: Annotated[AdminPrincipal, Depends(stream_session)],
    events: Param = None,
    outcome: Param = None,
    reason: Param = None,
    status: Param = None,
    egress: Param = None,
    cache: Param = None,
    client: Param = None,
    endpoint: Param = None,
    q: Param = None,
    last_event_id: Annotated[str | None, Query(max_length=32)] = None,
    last_event_id_header: Annotated[str | None, Header(alias="Last-Event-ID", max_length=32)] = None,
) -> StreamingResponse:
    """Open the event stream (see the module docstring). Query parameters filter the `live` rows exactly as the
    Live page's filter does; `events` picks the event kinds (all by default)."""
    kinds = parse_kinds(events)
    query, problems = read_dashboard.parse_live_query(
        outcome=outcome, reason=reason, status=status, egress=egress, cache=cache, client=client, endpoint=endpoint, q=q
    )
    if problems:
        raise validation_error(problems, "The stream parameters are not valid.")
    ctx = request.app.state.ctx
    if getattr(ctx, "live_tail", None) is None or not getattr(ctx, "ready", True):
        raise unavailable("The event stream is not running on this worker yet; try again shortly.")
    token = request.cookies.get(sessions.SESSION_COOKIE) or ""
    hub = hub_for(request)
    session_key = sessions.public_id(principal.session_id)
    if not hub.local_take(session_key):
        raise rate_limited("Too many live streams are open for this session; close a dashboard tab.", 5)
    holder = f"{ctx.worker_id}:{secrets.token_hex(4)}"
    try:
        slot, shared = await _take_slot(ctx, _slot_prefix(principal), holder)
        if shared and slot is None:
            raise rate_limited("Too many live streams are open for this session; close a dashboard tab.", 5)
        conn = Stream(
            request=request,
            ctx=ctx,
            hub=hub,
            principal=principal,
            token=token,
            kinds=kinds,
            query=query,
            after_id=parse_last_event_id(last_event_id_header, last_event_id),
            slot=slot,
            holder=holder,
            session_key=session_key,
        )
        try:
            await conn.start()
        except RuntimeError:
            if slot is not None:
                hub.later(_release_slot(ctx, slot, holder))
            raise unavailable("Too many live streams are open on this worker; try again shortly.") from None
    except BaseException:
        hub.local_give(session_key)
        raise
    disable_deadline(request.scope)  # a stream is meant to stay open (core/deadline.py)
    headers = {"Cache-Control": "no-store", "X-Accel-Buffering": "no"}
    return StreamingResponse(conn.run(), media_type="text/event-stream", headers=headers)


__all__ = [
    "EVENT_KINDS",
    "MAX_STREAMS_PER_SESSION",
    "TYPE_KINDS",
    "Stream",
    "StreamHub",
    "frame",
    "hub_for",
    "kpi_snapshot",
    "live_payload",
    "parse_kinds",
    "parse_last_event_id",
    "router",
    "tail_types",
]
