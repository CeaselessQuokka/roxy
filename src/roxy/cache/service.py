"""The cache service: how the proxy looks up, serves, refreshes and purges cached Roblox answers.

What this is
    `CacheService` (DESIGN 11.2), one per worker at `ctx.cache`. `peek(req)` reads the memory tier and cache.db
    (never upstream) so the throttle can tell cache hits apart (plan D10). `serve(req, peek)` returns a
    `ServeResult` for every `Roxy-Cache` state. `purge(scope, actor)` removes entries fleet-wide (plan 6.5, 6.8).
    `start()` adds the per-worker loops (generation watch, hit flush, eviction) and `close()` flushes.

Why it exists
    The cache is Roxy's strongest defense against Roblox rate limits: it is the only control that works however
    many different callers ask (plan 2.5 R5, R6). v1 served stale data only after a failed call, coalesced per
    worker, released every waiter on failure, and never cached errors or 429s (fixes F1, F5, F6, F10, F14).

How it works
    `serve` walks this table, top to bottom (plan 7.6, 7.7, 6.9):
    - No key (cache off, method not cacheable, a `cache_private` credential endpoint): upstream directly, `OFF`.
    - Fresh entry: `HIT` (a cached 400/403/404/410 replays its status, reason `cache_negative`).
    - A live per-key 429 marker: the stale entry (`STALE`, `cache_stale_cooldown`) or 429 with Retry-After
      (`upstream_cooldown`, `MISS`), without contacting Roblox.
    - Expired within the SWR window (`cache_swr_seconds`, or the rule's `stale_ttl`): served at once as
      `REVALIDATING` while one background refresh runs (fleet single-flight, background priority), unless the
      worker's refresh budget is full.
    - Expired within the stale window while the upstream reports the endpoint cooling down or its breaker
      open: `STALE` without contacting Roblox (`Roxy-Upstream-Cooldown`).
    - Otherwise one fleet single-flight fetch (interactive priority, or the shorter "stale available" class).
      The owner stores the answer (`store_decision`) and answers `MISS`; followers get `COALESCED` (the stored
      entry, or the owner's shared answer); a failure with a stale entry becomes `STALE` (`cache_stale_error`,
      `stale_after_failure`); a follower whose wait ends gets the stale entry or 503 `coalesce_timeout` with
      the owner's remaining deadline as Retry-After. Followers never call upstream after an owner failure.
    Every refetch of a key that had a body before feeds `change_observations` (identical body or not) for TTL
    tuning (F10). An answer fetched with the credential is never stored or shared under an anonymous key.

What to read next
    `roxy/cache/keys.py`, `roxy/cache/policy.py`, `roxy/cache/store.py`, `roxy/upstream/singleflight.py` and
    `roxy/cache/swr.py`; then `roxy/proxy/router.py` (the caller) and `roxy/proxy/respond.py` (the headers).
"""

from __future__ import annotations

import contextlib
import copy
import dataclasses
import inspect
import logging
import math
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final, Protocol

from roxy.cache.keys import MARKER_SUFFIX, VARY_HEADERS, CacheKey, assert_forward_list, build_key
from roxy.cache.policy import CacheSettings, RequestPolicy, StoreDecision, StoreKind, request_policy, store_decision
from roxy.cache.spread import DEFAULT_MAX_ROWS, SpreadGroup, compute_spread, rows_from_db, thresholds
from roxy.cache.store import CacheEntry, CacheStore, EvictionReport, PurgeScope
from roxy.cache.swr import SwrRefresher
from roxy.config.constants import CACHE_PAGE_MAX
from roxy.core.clock import Clock
from roxy.core.reasons import AuthClass, CacheState, Egress, Outcome, ReasonCode, Source
from roxy.rules.store import RulesSnapshot
from roxy.storage import leases
from roxy.storage.db import SharedStateUnavailable
from roxy.upstream.messages import BUSY_MESSAGE, MESSAGE_CONTENT_TYPE
from roxy.upstream.queue import Priority
from roxy.upstream.singleflight import (
    SHARE_BODY_MAX,
    FlightOutcome,
    FlightResult,
    FlightStart,
    OutcomeKind,
    Role,
    SingleFlight,
)

log = logging.getLogger(__name__)

GENERATION_POLL_S: Final = 0.25
"""How often each worker reads the purge generation row; a purge reaches every memory tier within this."""
MAINTENANCE_CHECK_S: Final = 15.0
"""How often each worker offers to run the eviction pass."""
MAINTENANCE_LEASE: Final = "cache_maintenance"
MAINTENANCE_PERIOD_MS: Final = 60_000
"""One eviction pass per minute fleet-wide: the lease is taken for this long and not released early."""
FOLLOWER_DEADLINE_HEADROOM_S: Final = 1.0
"""A follower stops waiting this long before its request deadline, to answer with stale or 503 itself."""
MAX_FLIGHT_ROUNDS: Final = 2
"""A stored entry that vanished before a follower read it (evicted or purged) earns one more flight."""
DETACHED_GRACE_S: Final = 5.0
PASS_HEADERS: Final = ("retry-after", "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset")
"""Upstream response headers kept in a `ServeResult` (the plan 9.13 outbound allowlist, `proxy/scrub.py`)."""


class RulesProvider(Protocol):
    """`rules/store.py: RulesStore` (anything with a current `snapshot`)."""

    @property
    def snapshot(self) -> RulesSnapshot: ...


@dataclass(slots=True)
class ServeResult:
    """What `serve` returns (DESIGN 11.2); `proxy/respond.py` turns it into the response and its headers."""

    status: int
    body: bytes
    content_type: str | None
    upstream_headers: dict[str, str]  # safe subset only
    cache_state: CacheState
    cache_age_s: int | None
    cache_ttl_s: int | None
    outcome: Outcome
    reason: ReasonCode
    source: Source
    egress: Egress
    auth_class: AuthClass
    upstream_status: int | None
    retry_after_s: int | None
    cooldown_s: int | None
    upstream_calls: int = 0
    upstream_bytes_in: int = 0
    upstream_bytes_out: int = 0
    queue_wait_ms: float = 0.0
    upstream_ms: float = 0.0
    trace: Any = None
    stale_after_failure: bool = False
    key_id: str | None = None
    """The cache key id (24 hex) when the request had a key, for request samples and the live feed."""


@dataclass(slots=True)
class CachePeek:
    """What `peek` found: the key, the plan for this request, and any fresh, stale or marker entry."""

    key: CacheKey | None
    policy: RequestPolicy
    fresh: CacheEntry | None = None
    stale: CacheEntry | None = None
    """Expired, but still inside the SWR or stale window: REVALIDATING or STALE material."""
    marker: CacheEntry | None = None
    """A live per-key Roblox 429 marker (plan 7.7)."""
    previous: CacheEntry | None = None
    """Whatever copy was found (fresh, stale or long expired): the baseline for change observations."""
    generation: int = 0
    """The purge-all generation seen at lookup; entries stored for this request carry it (plan 6.5)."""
    now: float = 0.0
    bypassed: bool = False

    @property
    def state(self) -> CacheState:
        """The state a serve would report if nothing changed (diagnostics only)."""
        if self.key is None:
            return CacheState.OFF
        if self.fresh is not None:
            return CacheState.HIT
        return CacheState.MISS


@dataclass(slots=True)
class CacheStats:
    """Per-worker counters for the System and Cache pages (the time series live in metrics rollups)."""

    hits: int = 0
    revalidating: int = 0
    stale: int = 0
    coalesced: int = 0
    misses: int = 0
    off: int = 0
    bypassed: int = 0
    stores: int = 0
    skipped: int = 0
    markers: int = 0
    cooldown_refusals: int = 0
    coalesce_timeouts: int = 0
    refreshes: int = 0
    refresh_failures: int = 0
    refresh_skipped: int = 0
    evictions: int = 0
    dead_removed: int = 0
    purges: int = 0


@dataclass(frozen=True, slots=True)
class PurgeReport:
    """The result of one purge, for the admin answer and the audit entry."""

    scope: str
    removed: int
    generation: int
    stamp: int
    fleet_invalidated: bool
    memory_cleared: int
    duration_ms: float
    actor: str


@dataclass(slots=True)
class _OwnerValue:
    """What the owner of a flight keeps for itself and its same-process followers."""

    result: Any | None
    entry: CacheEntry | None
    decision: StoreDecision | None = None
    extra: dict[str, Any] = field(default_factory=dict)


class _LazyUpstream:
    """Reads `ctx.upstream` at call time, so the cache can be built before the upstream service is wired."""

    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx

    async def fetch(self, req: Any, **kwargs: Any) -> Any:
        upstream = getattr(self._ctx, "upstream", None)
        if upstream is None:
            raise RuntimeError("the upstream service is not available")
        return await upstream.fetch(req, **kwargs)

    def availability(self, req: Any) -> Any:
        upstream = getattr(self._ctx, "upstream", None)
        check = getattr(upstream, "availability", None)
        return None if check is None else check(req)


def _scrub_forward_list() -> tuple[str, ...] | None:
    """`proxy/scrub.py: FORWARDED_REQUEST_HEADERS` when the proxy package is importable."""
    try:
        from roxy.proxy import scrub
    except ImportError:
        return None
    found = getattr(scrub, "FORWARDED_REQUEST_HEADERS", None)
    return tuple(found) if found is not None else None


def _seconds(value: Any) -> int | None:
    """Whole seconds, rounded up (Retry-After never undersells a wait); None stays None."""
    if value is None:
        return None
    try:
        return max(0, math.ceil(float(value)))
    except (TypeError, ValueError):
        return None


def _target_of(req: Any) -> str:
    target = getattr(req, "target", "") or ""
    if target:
        return str(target)
    path = str(getattr(req, "path", "") or "")
    return f"{str(req.host).lower()}/{path[1:] if path.startswith('/') else path}"


def _vary_of(req: Any) -> Mapping[str, str] | None:
    """The caller headers this request forwards (`ProxyRequest.forwarded_headers()`), the key's vary input."""
    forwarded = getattr(req, "forwarded_headers", None)
    if not callable(forwarded):
        return None
    headers = forwarded()
    return dict(headers) if headers else None


def _deadline_remaining(req: Any) -> float | None:
    deadline_at = getattr(req, "deadline_at", None)
    if not isinstance(deadline_at, int | float):
        return None
    return deadline_at - time.monotonic()  # the deadline middleware uses time.monotonic, so this does too


def _detached(req: Any, budget_s: float) -> Any:
    """A copy of `req` with its own deadline, for a background refresh that outlives the caller's request."""
    deadline = time.monotonic() + budget_s
    if dataclasses.is_dataclass(req) and not isinstance(req, type):
        with contextlib.suppress(TypeError, ValueError):  # a dataclass without a `deadline_at` field
            return dataclasses.replace(req, deadline_at=deadline)
    clone = copy.copy(req)
    with contextlib.suppress(AttributeError):  # an object that cannot take the attribute keeps its own
        clone.deadline_at = deadline
    return clone


def _safe_headers(headers: Any) -> dict[str, str]:
    if not headers:
        return {}
    items = headers.items() if hasattr(headers, "items") else headers
    kept: dict[str, str] = {}
    for name, value in items:
        lowered = str(name).lower()
        if lowered in PASS_HEADERS and lowered not in kept:
            kept[lowered] = str(value)
    return kept


class CacheService:
    """The response cache of one worker (module docstring)."""

    def __init__(
        self,
        *,
        dbs: Any,
        settings: Any,
        rules: RulesProvider | None,
        clock: Clock,
        upstream: Any,
        worker_id: str,
        tasks: Any = None,
        recorder: Any = None,
        forwarded_headers: tuple[str, ...] | None = None,
    ) -> None:
        cache_db = getattr(dbs, "cache", None) if dbs is not None else None
        self._hot = getattr(dbs, "hot", None) if dbs is not None else None
        self._settings = settings
        self._rules = rules
        self._clock = clock
        self._upstream = upstream
        self._worker_id = worker_id
        self._tasks = tasks
        self._recorder = recorder
        self.store = CacheStore(cache_db, clock)
        self.flights = SingleFlight(self._hot, clock, worker_id)
        self.swr = SwrRefresher(tasks, lambda: self._cs().swr_max_inflight)
        self.stats = CacheStats()
        self._cs_cache: tuple[Any, CacheSettings] | None = None
        # Plan 9.13: every forwarded caller header must vary the key. Checked once, at startup.
        forward = forwarded_headers if forwarded_headers is not None else _scrub_forward_list()
        if forward is not None:
            assert_forward_list(forward)
        self._cs()

    @classmethod
    def from_context(cls, ctx: Any) -> CacheService:
        """Build the worker's cache from its `AppContext` (lifespan hook), reading `ctx.upstream` lazily."""
        return cls(
            dbs=ctx.dbs,
            settings=ctx.settings,
            rules=ctx.rules,
            clock=ctx.clock,
            upstream=_LazyUpstream(ctx),
            worker_id=ctx.worker_id,
            tasks=ctx.tasks,
            recorder=getattr(ctx, "recorder", None),
        )

    # ---- lifecycle ----

    async def start(self) -> None:
        """Read the purge generation once, then start the per-worker loops on the task supervisor."""
        await self.store.sync_generation()
        if self._tasks is None:
            return
        self._tasks.start("cache_generation_watch", self.store.sync_generation, interval_s=GENERATION_POLL_S)
        self._tasks.start("cache_flush", self.flush, interval_s=self._cs().flush_interval_s)
        self._tasks.start("cache_maintenance", self.maintain, interval_s=MAINTENANCE_CHECK_S, run_immediately=False)

    async def close(self) -> None:
        """Flush buffered hits (shutdown) and stop any flight still running."""
        await self.flush()
        await self.flights.close()

    async def flush(self) -> int:
        return await self.store.flush()

    # ---- settings and rules ----

    def _cs(self) -> CacheSettings:
        version = getattr(self._settings, "version", None)
        cached = self._cs_cache
        if cached is not None and version is not None and cached[0] == version:
            return cached[1]
        cs = CacheSettings.read(self._settings)
        self._cs_cache = (version, cs)
        self.store.configure(memory_entries=cs.memory_entries, memory_bytes=cs.memory_bytes)
        return cs

    def _snapshot(self) -> RulesSnapshot:
        snapshot = getattr(self._rules, "snapshot", None) if self._rules is not None else None
        return snapshot if isinstance(snapshot, RulesSnapshot) else RulesSnapshot.empty()

    # ---- peek ----

    async def peek(self, req: Any) -> CachePeek:
        """Memory tier, then cache.db; never upstream (DESIGN 11.1 step 3). Sets `req.cache_key` and
        `req.fresh_cache_hit`. A broken cache.db read is a miss, never an error."""
        cs = self._cs()
        now = self._clock.now()
        snapshot = self._snapshot()
        headers = getattr(req, "headers", None) or {}
        policy = request_policy(req.method, _target_of(req), headers, cs, snapshot)
        if not policy.cacheable:
            self._mark(req, None, False)
            return CachePeek(key=None, policy=policy, now=now, generation=self.store.floor)
        key = build_key(
            req.method,
            req.host,
            req.path,
            list(getattr(req, "query", None) or ()),
            getattr(req, "body", None) or b"",
            policy.rule,
            ignored=snapshot.cache_ignored_params,
            auth_class=policy.auth_class,
            vary=_vary_of(req),
        )
        if policy.bypass_lookup:
            self.stats.bypassed += 1
            self._mark(req, key, False)
            return CachePeek(key=key, policy=policy, now=now, generation=self.store.floor, bypassed=True)
        found = await self.store.lookup(
            [key.id, key.marker_id], now=now, disk=cs.disk_enabled, fresh_short_circuit=key.id
        )
        entry = found.get(key.id)
        if entry is not None and (entry.auth_class != key.auth_class or entry.is_marker):
            entry = None  # defense in depth: ids already differ per auth class (plan 6.9)
        marker = found.get(key.marker_id)
        fresh = stale = None
        if entry is not None:
            if entry.is_fresh(now):
                fresh = entry
            elif not entry.negative and now < entry.expires_at + policy.stale_window_s:
                stale = entry
        active_marker = marker if marker is not None and marker.is_marker and marker.is_fresh(now) else None
        self._mark(req, key, fresh is not None)
        return CachePeek(
            key=key,
            policy=policy,
            fresh=fresh,
            stale=stale,
            marker=active_marker,
            previous=entry,
            generation=self.store.floor,
            now=now,
        )

    @staticmethod
    def _mark(req: Any, key: CacheKey | None, fresh: bool) -> None:
        try:
            req.cache_key = key
            req.fresh_cache_hit = fresh
        except AttributeError:  # a request object without these fields (tests, tools)
            pass

    # ---- serve ----

    async def serve(self, req: Any, peek: CachePeek | None = None) -> ServeResult:
        """Answer one request (module docstring has the decision table). Never raises for upstream problems."""
        if peek is None:
            peek = await self.peek(req)
        cs = self._cs()
        key = peek.key
        if key is None:
            self.stats.off += 1
            return await self._fetch_uncached(req)
        now = self._clock.now()
        policy = peek.policy
        fresh = peek.fresh
        if fresh is not None and fresh.is_fresh(now):
            self.stats.hits += 1
            reason = ReasonCode.CACHE_NEGATIVE if fresh.negative else ReasonCode.CACHE_HIT
            return self._from_entry(fresh, CacheState.HIT, reason, now)
        stale = peek.stale if peek.stale is not None and now < peek.stale.expires_at + policy.stale_window_s else None
        marker = peek.marker if peek.marker is not None and peek.marker.is_fresh(now) else None
        if marker is not None:
            remaining = max(1, math.ceil(marker.expires_at - now))
            if stale is not None:
                self.stats.stale += 1
                return self._from_entry(
                    stale, CacheState.STALE, ReasonCode.CACHE_STALE_COOLDOWN, now, cooldown_s=remaining
                )
            self.stats.cooldown_refusals += 1
            return self._cooldown_result(key, remaining)
        in_swr_window = stale is not None and policy.ttl_s > 0 and now < stale.expires_at + policy.swr_s
        current = peek
        if (
            stale is not None
            and in_swr_window
            and self.swr.schedule(key.flight_key, lambda: self._refresh(req, current))
        ):
            self.stats.revalidating += 1
            return self._from_entry(stale, CacheState.REVALIDATING, ReasonCode.CACHE_REVALIDATING, now)
        if stale is not None:
            cooling = await self._cooldown_remaining(req)
            if cooling is not None:
                self.stats.stale += 1
                return self._from_entry(
                    stale, CacheState.STALE, ReasonCode.CACHE_STALE_COOLDOWN, now, cooldown_s=cooling
                )
        return await self._fetch(req, peek, cs, stale)

    async def _fetch_uncached(self, req: Any) -> ServeResult:
        result = await self._upstream.fetch(req, priority=Priority.INTERACTIVE, stale_available=False, purpose="caller")
        return self._from_upstream(result, CacheState.OFF, None)

    async def _cooldown_remaining(self, req: Any) -> int | None:
        """Seconds until the endpoint can be asked again when the upstream says no egress is available now."""
        check = getattr(self._upstream, "availability", None)
        if not callable(check):
            return None
        try:
            info = check(req)
            if inspect.isawaitable(info):
                info = await info
        except Exception:
            log.exception("cache_availability_failed")
            return None
        if info is None or getattr(info, "any_egress_available", True):
            return None
        for name in ("cooldown_remaining_s", "soonest_s"):
            value = _seconds(getattr(info, name, None))
            if value:
                return value
        return 1

    async def _fetch(self, req: Any, peek: CachePeek, cs: CacheSettings, stale: CacheEntry | None) -> ServeResult:
        key = peek.key
        if key is None:  # serve() only calls this with a key
            raise RuntimeError("a cache fetch needs a cache key")
        priority = Priority.INTERACTIVE_STALE if stale is not None else Priority.INTERACTIVE
        wait_s = cs.follower_wait_s
        remaining = _deadline_remaining(req)
        if remaining is not None:
            wait_s = max(0.0, min(wait_s, remaining - FOLLOWER_DEADLINE_HEADROOM_S))

        async def fetch(start: FlightStart) -> tuple[_OwnerValue, FlightOutcome]:
            if start.takeover:
                # The previous owner may have stored the answer before it died or gave up: never call twice.
                now = self._clock.now()
                existing = await self.store.get(key.id, now=now, disk=cs.disk_enabled)
                if existing is not None and existing.is_fresh(now) and existing.auth_class == key.auth_class:
                    return _OwnerValue(None, existing), self._stored_outcome(existing)
            result = await self._upstream.fetch(
                req, priority=priority, stale_available=stale is not None, purpose="caller"
            )
            return await self._absorb(req, peek, result, cs)

        for _round in range(MAX_FLIGHT_ROUNDS):
            flight = await self.flights.run(
                key.flight_key,
                fetch,
                owner_deadline_s=cs.owner_deadline_s,
                wait_s=wait_s,
                enabled=peek.policy.coalesce,
            )
            served = await self._serve_flight(flight, key, stale)
            if served is not None:
                return served
        self.stats.coalesce_timeouts += 1
        return self._timeout_result(key, 1)

    async def _serve_flight(
        self, flight: FlightResult[_OwnerValue], key: CacheKey, stale: CacheEntry | None
    ) -> ServeResult | None:
        now = self._clock.now()
        value = flight.value
        if flight.role in (Role.OWNER, Role.SOLO):
            if value is None:
                return None
            if value.result is None and value.entry is not None:  # a takeover found the entry already stored
                self.stats.coalesced += 1
                return self._from_entry(value.entry, CacheState.COALESCED, ReasonCode.CACHE_COALESCED, now)
            return self._from_owner(value, stale, key, now)
        if flight.role is Role.TIMEOUT:
            if stale is not None:
                self.stats.stale += 1
                return self._from_entry(stale, CacheState.STALE, ReasonCode.CACHE_STALE_COOLDOWN, now)
            self.stats.coalesce_timeouts += 1
            return self._timeout_result(key, flight.retry_after_s or 1)
        outcome = flight.outcome
        if value is not None:  # a follower of an owner in this process: use its objects directly
            if value.entry is not None:
                self.stats.coalesced += 1
                return self._from_entry(value.entry, CacheState.COALESCED, ReasonCode.CACHE_COALESCED, now)
            if value.result is not None:
                result = value.result
                return self._from_shared(
                    key,
                    int(result.status),
                    bytes(result.body or b""),
                    result.content_type,
                    str(ReasonCode(result.reason).value),
                    result.upstream_status,
                    _seconds(result.retry_after_s),
                    _seconds(result.cooldown_s),
                    stale,
                    now,
                )
        if outcome is None:
            return None
        if outcome.kind is OutcomeKind.STORED and outcome.entry_id is not None:
            entry = await self.store.get(outcome.entry_id, now=now, disk=True)
            if entry is None or entry.auth_class != key.auth_class:
                return None  # vanished (evicted or purged) before we read it: one more flight
            self.stats.coalesced += 1
            return self._from_entry(entry, CacheState.COALESCED, ReasonCode.CACHE_COALESCED, now)
        if outcome.kind is OutcomeKind.SHARED and outcome.status is not None:
            return self._from_shared(
                key,
                outcome.status,
                outcome.body,
                outcome.content_type,
                outcome.reason or ReasonCode.UPSTREAM_OK.value,
                outcome.upstream_status,
                outcome.retry_after_s,
                outcome.cooldown_s,
                stale,
                now,
            )
        return None

    # ---- the owner's work ----

    async def _absorb(
        self, req: Any, peek: CachePeek, result: Any, cs: CacheSettings
    ) -> tuple[_OwnerValue, FlightOutcome]:
        """Store what should be stored (policy), record change observations, and say what followers get."""
        key = peek.key
        if key is None:  # owners always have a key
            raise RuntimeError("a cache owner needs a cache key")
        decision = store_decision(result, peek.policy, cs)
        now = self._clock.now()
        entry: CacheEntry | None = None
        stored = False
        if decision.kind is not StoreKind.NONE:
            entry = self._make_entry(key, peek.policy, result, decision, now, peek.generation)
            body = getattr(req, "body", None) or b""
            req_body = body if key.method == "POST" and body and decision.kind is StoreKind.ENTRY else None
            stored = await self.store.put(entry, disk=cs.shared_tier_on, compress=cs.compress, req_body=req_body)
            if decision.kind is StoreKind.MARKER:
                self.stats.markers += 1
            else:
                self.stats.stores += 1
                self._observe_change(req, peek, entry, now)
        elif decision.skipped:
            self.stats.skipped += 1
        content = entry if entry is not None and decision.kind is not StoreKind.MARKER else None
        return _OwnerValue(result, content, decision), self._outcome_for(result, key, content, stored)

    def _make_entry(
        self,
        key: CacheKey,
        policy: RequestPolicy,
        result: Any,
        decision: StoreDecision,
        now: float,
        generation: int,
    ) -> CacheEntry:
        stored_at = int(now)
        expires_at = stored_at + decision.ttl_s
        marker = decision.kind is StoreKind.MARKER
        content = decision.kind is StoreKind.ENTRY
        return CacheEntry(
            id=key.marker_id if marker else key.id,
            key=key.text + MARKER_SUFFIX if marker else key.text,
            auth_class=key.auth_class,
            method=key.method,
            host=key.host,
            path=key.path,
            status=429 if marker else int(result.upstream_status),
            body=b"" if marker else bytes(result.body or b""),
            content_type=None if marker else result.content_type,
            stored_at=stored_at,
            expires_at=expires_at,
            # Content stays until its stale window ends; negative entries and markers are never served stale.
            stale_until=expires_at + policy.stale_window_s if content else expires_at,
            ttl=decision.ttl_s,
            params=key.params,
            stripped=key.stripped,
            rule_id=policy.rule.id if policy.rule is not None else None,
            egress=str(getattr(result, "egress", "") or "") or None,
            negative=not content,
            generation=generation,
        )

    def _stored_outcome(self, entry: CacheEntry) -> FlightOutcome:
        return FlightOutcome(OutcomeKind.STORED, status=entry.status, entry_id=entry.id, stored_at=entry.stored_at)

    def _outcome_for(self, result: Any, key: CacheKey, entry: CacheEntry | None, stored: bool) -> FlightOutcome:
        if entry is not None and stored:
            return self._stored_outcome(entry)
        if AuthClass(result.auth_class) == AuthClass.CRED and key.auth_class != AuthClass.CRED:
            return FlightOutcome(OutcomeKind.NOSTORE)  # never hand a credential answer to anonymous followers
        body = bytes(result.body or b"")
        reason = ReasonCode(result.reason).value
        if len(body) > SHARE_BODY_MAX:
            return FlightOutcome(OutcomeKind.NOSTORE, status=int(result.status), reason=reason)
        return FlightOutcome(
            OutcomeKind.SHARED,
            status=int(result.status),
            reason=reason,
            body=body,
            content_type=result.content_type,
            upstream_status=result.upstream_status,
            retry_after_s=_seconds(result.retry_after_s),
            cooldown_s=_seconds(result.cooldown_s),
        )

    def _observe_change(self, req: Any, peek: CachePeek, entry: CacheEntry, now: float) -> None:
        """A refetch of a key that had a body: was the new body identical? (TTL tuning, plan F10)."""
        previous = peek.previous
        if previous is None or previous.negative or entry.negative:
            return
        template = str(getattr(req, "template", "") or entry.host + "/" + entry.path)
        day = int(now // 86_400) * 86_400
        self.store.observations.observe(template, day, previous.body == entry.body)

    # ---- stale-while-revalidate ----

    async def _refresh(self, req: Any, peek: CachePeek) -> None:
        """One background refresh: lead the fleet flight for this key or do nothing (someone else is on it)."""
        cs = self._cs()
        key = peek.key
        if key is None:
            return
        detached = _detached(req, cs.owner_deadline_s + DETACHED_GRACE_S)

        async def fetch(start: FlightStart) -> tuple[_OwnerValue, FlightOutcome]:
            result = await self._upstream.fetch(
                detached, priority=Priority.BACKGROUND, stale_available=True, purpose="swr_refresh"
            )
            return await self._absorb(detached, peek, result, cs)

        flight = await self.flights.try_lead(key.flight_key, fetch, owner_deadline_s=cs.owner_deadline_s)
        if flight is None:
            self.stats.refresh_skipped += 1
            return
        result = flight.value.result if flight.value is not None else None
        if result is not None and ReasonCode(result.reason).is_failure:
            self.stats.refresh_failures += 1
        else:
            self.stats.refreshes += 1
        if result is not None:
            self._record_refresh(detached, result)

    def _record_refresh(self, req: Any, result: Any) -> None:
        """Count the refresh's upstream calls in the metrics (upstream calls with no caller request, plan 7.6 and
        P6), so "avoided upstream calls" never forgets them. Metrics never fail the cache (C7)."""
        record = getattr(self._recorder, "record_background_fetch", None)
        if not callable(record):
            return
        try:
            record(
                endpoint_template=str(getattr(req, "template", "") or ""),
                host=str(getattr(req, "host", "") or ""),
                method=str(getattr(req, "method", "GET") or "GET"),
                egress=getattr(result, "egress", Egress.NONE),
                auth_class=getattr(result, "auth_class", AuthClass.ANON),
                status=int(getattr(result, "upstream_status", None) or getattr(result, "status", 0) or 0),
                calls=int(getattr(result, "calls", 0) or 0),
                bytes_in=int(getattr(result, "bytes_in", 0) or 0),
                bytes_out=int(getattr(result, "bytes_out", 0) or 0),
                ok=not ReasonCode(result.reason).is_failure,
            )
        except Exception:
            log.exception("cache_refresh_record_failed")

    # ---- result builders ----

    def _from_entry(
        self,
        entry: CacheEntry,
        state: CacheState,
        reason: ReasonCode,
        now: float,
        *,
        upstream: Any = None,
        cooldown_s: int | None = None,
        stale_after_failure: bool = False,
    ) -> ServeResult:
        self.store.record_hit(entry.id, now)
        return ServeResult(
            status=entry.status,
            body=entry.body,
            content_type=entry.content_type,
            upstream_headers={},
            cache_state=state,
            cache_age_s=entry.age(now),
            cache_ttl_s=entry.ttl,
            outcome=Outcome.SERVED_CACHE,
            reason=reason,
            source=Source.CACHE,
            egress=Egress(upstream.egress) if upstream is not None else Egress.NONE,
            auth_class=entry.auth_class,
            upstream_status=upstream.upstream_status if upstream is not None else None,
            retry_after_s=None,
            cooldown_s=cooldown_s,
            upstream_calls=int(upstream.calls) if upstream is not None else 0,
            upstream_bytes_in=int(upstream.bytes_in) if upstream is not None else 0,
            upstream_bytes_out=int(upstream.bytes_out) if upstream is not None else 0,
            queue_wait_ms=float(upstream.queue_wait_ms) if upstream is not None else 0.0,
            upstream_ms=float(upstream.upstream_ms) if upstream is not None else 0.0,
            trace=getattr(upstream, "trace", None) if upstream is not None else None,
            stale_after_failure=stale_after_failure,
            key_id=entry.id,
        )

    def _from_owner(self, value: _OwnerValue, stale: CacheEntry | None, key: CacheKey, now: float) -> ServeResult:
        result: Any = value.result
        if result is None:  # only a takeover that found a stored entry has no result, and it is served earlier
            raise RuntimeError("an owner value without an upstream result")
        reason = ReasonCode(result.reason)
        if reason.is_failure and stale is not None:
            made_call = int(getattr(result, "calls", 0) or 0) > 0
            self.stats.stale += 1
            return self._from_entry(
                stale,
                CacheState.STALE,
                ReasonCode.CACHE_STALE_ERROR if made_call else ReasonCode.CACHE_STALE_COOLDOWN,
                now,
                upstream=result,
                cooldown_s=_seconds(result.cooldown_s),
                stale_after_failure=made_call,
            )
        self.stats.misses += 1
        return self._from_upstream(result, CacheState.MISS, key.id)

    def _from_upstream(self, result: Any, state: CacheState, key_id: str | None) -> ServeResult:
        reason = ReasonCode(result.reason)
        if reason.is_served:
            outcome, source = Outcome.SERVED_UPSTREAM, Source.ROBLOX
        elif reason.is_refusal:
            outcome, source = Outcome.REFUSED, Source.ROXY
        else:
            outcome, source = Outcome.FAILED, Source.ROXY
        return ServeResult(
            status=int(result.status),
            body=bytes(result.body or b""),
            content_type=result.content_type,
            upstream_headers=_safe_headers(result.headers),
            cache_state=state,
            cache_age_s=None,
            cache_ttl_s=None,
            outcome=outcome,
            reason=reason,
            source=source,
            egress=Egress(result.egress),
            auth_class=AuthClass(result.auth_class),
            upstream_status=result.upstream_status,
            retry_after_s=_seconds(result.retry_after_s),
            cooldown_s=_seconds(result.cooldown_s),
            upstream_calls=int(result.calls),
            upstream_bytes_in=int(result.bytes_in),
            upstream_bytes_out=int(result.bytes_out),
            queue_wait_ms=float(result.queue_wait_ms),
            upstream_ms=float(result.upstream_ms),
            trace=getattr(result, "trace", None),
            key_id=key_id,
        )

    def _from_shared(
        self,
        key: CacheKey,
        status: int,
        body: bytes,
        content_type: str | None,
        reason_text: str,
        upstream_status: int | None,
        retry_after_s: int | None,
        cooldown_s: int | None,
        stale: CacheEntry | None,
        now: float,
    ) -> ServeResult:
        """A follower's answer from the owner's shared outcome (plan 6.9 step 4)."""
        try:
            reason = ReasonCode(reason_text)
        except ValueError:
            reason = ReasonCode.UPSTREAM_OK
        if not reason.is_served:
            if stale is not None:
                self.stats.stale += 1
                return self._from_entry(
                    stale,
                    CacheState.STALE,
                    ReasonCode.CACHE_STALE_ERROR,
                    now,
                    cooldown_s=cooldown_s,
                    stale_after_failure=True,
                )
            # The owner's failure, exactly: same status and Retry-After, and no call of our own (step 6).
            self.stats.misses += 1
            return ServeResult(
                status=status,
                body=body,
                content_type=content_type,
                upstream_headers={},
                cache_state=CacheState.MISS,
                cache_age_s=None,
                cache_ttl_s=None,
                outcome=Outcome.REFUSED if reason.is_refusal else Outcome.FAILED,
                reason=reason,
                source=Source.ROXY,
                egress=Egress.NONE,
                auth_class=key.auth_class,
                upstream_status=upstream_status,
                retry_after_s=retry_after_s,
                cooldown_s=cooldown_s,
                key_id=key.id,
            )
        self.stats.coalesced += 1
        return ServeResult(
            status=status,
            body=body,
            content_type=content_type,
            upstream_headers={},
            cache_state=CacheState.COALESCED,
            cache_age_s=0,
            cache_ttl_s=0,
            outcome=Outcome.SERVED_CACHE,
            reason=ReasonCode.CACHE_COALESCED,
            source=Source.CACHE,
            egress=Egress.NONE,
            auth_class=key.auth_class,
            upstream_status=None,
            retry_after_s=None,
            cooldown_s=None,
            key_id=key.id,
        )

    def _cooldown_result(self, key: CacheKey, remaining: int) -> ServeResult:
        """Plan 7.13 `cooldown_no_stale`: 429 with Retry-After, never contacting Roblox (plan 7.7)."""
        return ServeResult(
            status=429,
            body=BUSY_MESSAGE.encode("utf-8"),
            content_type=MESSAGE_CONTENT_TYPE,
            upstream_headers={},
            cache_state=CacheState.MISS,
            cache_age_s=None,
            cache_ttl_s=None,
            outcome=Outcome.FAILED,
            reason=ReasonCode.UPSTREAM_COOLDOWN,
            source=Source.ROXY,
            egress=Egress.NONE,
            auth_class=key.auth_class,
            upstream_status=None,
            retry_after_s=remaining,
            cooldown_s=remaining,
            key_id=key.id,
        )

    def _timeout_result(self, key: CacheKey, retry_after_s: int) -> ServeResult:
        """Plan 7.13 `coalesce_timeout`: 503 with the owner's remaining deadline as Retry-After (6.9 step 5)."""
        return ServeResult(
            status=503,
            body=BUSY_MESSAGE.encode("utf-8"),
            content_type=MESSAGE_CONTENT_TYPE,
            upstream_headers={},
            cache_state=CacheState.MISS,
            cache_age_s=None,
            cache_ttl_s=None,
            outcome=Outcome.FAILED,
            reason=ReasonCode.COALESCE_TIMEOUT,
            source=Source.ROXY,
            egress=Egress.NONE,
            auth_class=key.auth_class,
            upstream_status=None,
            retry_after_s=max(1, retry_after_s),
            cooldown_s=None,
            key_id=key.id,
        )

    # ---- purges and maintenance ----

    async def purge(self, scope: PurgeScope, actor: Any = None) -> PurgeReport:
        """Remove entries fleet-wide (plan 6.5, 6.8): the generation row moves first, then batched deletes.

        Raises ValueError (a bad scope, for example an invalid regex) and `SharedStateUnavailable`. The admin API
        writes the audit entry with the returned report.
        """
        started = time.perf_counter()
        result = await self.store.purge(scope, now=self._clock.now())
        self.stats.purges += 1
        name = str(getattr(actor, "name", actor) if actor is not None else "system")
        report = PurgeReport(
            scope=scope.label,
            removed=result.removed,
            generation=result.floor,
            stamp=result.stamp,
            fleet_invalidated=result.fleet_invalidated,
            memory_cleared=result.memory_cleared,
            duration_ms=round((time.perf_counter() - started) * 1000, 1),
            actor=name[:80],
        )
        log.info("cache_purged", extra={"fields": dataclasses.asdict(report)})
        self._event("cache_purge", "info", "cache_purge", dataclasses.asdict(report))
        return report

    async def maintain(self) -> EvictionReport | None:
        """The eviction pass, at most once a minute fleet-wide (a hot.db lease that is left to expire)."""
        cs = self._cs()
        if not cs.disk_enabled or self.store.shared is None:
            return None
        if self._hot is not None:
            holder, now_ms = self._worker_id, self._clock.now_ms()

            def take_turn(conn: Any) -> bool:
                # Only an expired (or missing) lease gives a turn; a valid one, ours included, is never extended,
                # so the pass runs at most once per MAINTENANCE_PERIOD_MS across the fleet.
                current = leases.holder_epoch(conn, MAINTENANCE_LEASE)
                if current is not None and current[2] > now_ms:
                    return False
                return leases.acquire(conn, MAINTENANCE_LEASE, holder, MAINTENANCE_PERIOD_MS, now_ms) is not None

            try:
                if not await self._hot.write(take_turn):
                    return None
            except SharedStateUnavailable:
                return None
        report = await self.store.maintain(
            max_entries=cs.max_entries, max_bytes=cs.max_bytes, policy=cs.eviction_policy, now=self._clock.now()
        )
        self.stats.evictions += report.evicted
        self.stats.dead_removed += report.dead
        if report.evicted or report.dead:
            fields = dataclasses.asdict(report)
            log.info("cache_maintenance", extra={"fields": fields})
            if report.evicted:
                self._event("cache_eviction", "info", "cache_pressure", fields)
        return report

    def _event(self, kind: str, severity: str, reason: str, detail: dict[str, Any]) -> None:
        record = getattr(self._recorder, "record_event", None)
        if record is None:
            return
        try:
            record(kind, severity, reason, detail)
        except Exception:
            log.exception("cache_event_failed", extra={"fields": {"type": kind}})

    # ---- diagnostics and admin views ----

    async def key_spread(self, limit: int = 25, max_rows: int = DEFAULT_MAX_ROWS) -> list[SpreadGroup]:
        """Evidence for CACHE-KEYSPLIT (parity row 65): groups whose keys split on a changing parameter."""
        await self.flush()
        if self.store.shared is None:
            return []
        raw = await self.store.shared.spread_rows(max_rows)
        limits = thresholds(self._settings)
        return compute_spread(
            rows_from_db(raw),
            min_entries=limits["min_entries"],
            distinct_pct=limits["distinct_pct"],
            max_hit_pct=limits["max_hit_pct"],
            limit=limit,
        )

    async def get_entry(self, entry_id: str) -> dict[str, Any] | None:
        """The inspector view of one entry (body included), or None (parity row 66)."""
        if self.store.shared is None:
            return None
        found = await self.store.shared.get_row(entry_id)
        if found is None:
            return None
        entry, req_body = found
        now = self._clock.now()
        return {
            "Id": entry.id,
            "Key": entry.key,
            "AuthClass": entry.auth_class.value,
            "Method": entry.method,
            "Path": f"{entry.host}/{entry.path}",
            "Params": [list(pair) for pair in entry.params],
            "Stripped": list(entry.stripped),
            "Status": entry.status,
            "ContentType": entry.content_type,
            "Body": entry.body.decode("utf-8", "replace"),
            "BodyLength": len(entry.body),
            "RequestBody": None if req_body is None else req_body.decode("utf-8", "replace"),
            "StoredAt": entry.stored_at,
            "ExpiresAt": entry.expires_at,
            "StaleUntil": entry.stale_until,
            "TTL": entry.ttl,
            "Age": entry.age(now),
            "Fresh": entry.is_fresh(now),
            "Negative": entry.negative,
            "Hits": entry.hits + self.store.hits.pending(entry.id),
            "LastHit": entry.last_hit_at,
            "Rule": entry.rule_id,
            "Egress": entry.egress,
            "Bytes": entry.size,
        }

    async def list_entries(
        self, query: str = "", offset: int = 0, limit: int = 25, sort: str = "hits", order: str = "desc"
    ) -> dict[str, Any]:
        """A page of the cache browser (v1 `list_entries` shape, paged in SQL)."""
        await self.flush()
        offset = max(0, int(offset))
        limit = max(1, min(int(limit or 50), CACHE_PAGE_MAX))
        if self.store.shared is None:
            return {"Total": 0, "Offset": offset, "Limit": limit, "Entries": [], "Query": query, "Sort": sort}
        total, rows = await self.store.shared.list_rows(query, offset, limit, sort, order != "asc")
        return {
            "Total": total,
            "Offset": offset,
            "Limit": limit,
            "Entries": rows,
            "Query": query,
            "Sort": sort,
            "Order": order,
        }

    def disk_status(self) -> dict[str, Any]:
        """Disk health for the health page (parity row 64), plus `MemoryOnly`."""
        cs = self._cs()
        if self.store.shared is None:
            return {"OK": False, "MemoryOnly": True}
        status = self.store.shared.disk_status()
        status["MemoryOnly"] = bool(cs.disk_enabled and not status["OK"])
        return status

    def state(self) -> dict[str, Any]:
        """This worker's cache state for the dashboard poll (v1 `get_state`, per worker)."""
        cs = self._cs()
        return {
            "Enabled": cs.enabled,
            "DiskEnabled": cs.disk_enabled,
            "Memory": {
                "Count": len(self.store.memory),
                "Bytes": self.store.memory.bytes,
                "MaxEntries": cs.memory_entries,
                "MaxBytes": cs.memory_bytes,
                "Evictions": self.store.memory.evictions,
                "Invalidations": self.store.memory_invalidations,
            },
            "Generation": self.store.floor,
            "Inflight": self.flights.inflight(),
            "Refreshing": self.swr.active(),
            "PendingHits": len(self.store.hits),
            "Stats": dataclasses.asdict(self.stats),
            "Flights": dataclasses.asdict(self.flights.stats),
            "VaryHeaders": list(VARY_HEADERS),
        }


__all__ = [
    "CachePeek",
    "CacheService",
    "CacheStats",
    "PurgeReport",
    "PurgeScope",
    "ServeResult",
]
