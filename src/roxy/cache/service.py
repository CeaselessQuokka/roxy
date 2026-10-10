"""The cache service: how the proxy looks up, serves, refreshes and purges cached Roblox answers.

What this is
    `CacheService` (DESIGN 11.2), one per worker at `ctx.cache`. `peek(req)` reads the memory tier and cache.db
    (never upstream) and marks `req.fresh_cache_hit`, which the abuse checks use only when an admin turned
    `throttle_count_cache_hits` off (cache hits count toward the per-IP limit by default: plan D10 as the Roxy
    owner reversed it on 2026-10-07) or `cache_serve_throttled` on. `serve(req, peek)` returns a `ServeResult`
    for every `Roxy-Cache` state. `purge(scope, actor)` removes entries fleet-wide (plan 6.5, 6.8). `start()`
    adds the per-worker loops (generation watch, hit flush, eviction) and `close()` lets pending stores land, then
    flushes.

Why it exists
    The cache is Roxy's strongest defense against Roblox rate limits: it is the only control that works however
    many different callers ask (plan 2.5 R5, R6). v1 served stale data only after a failed call, coalesced per
    worker, released every waiter on failure, and never cached errors or 429s (fixes F1, F5, F6, F10, F14).

How it works
    `serve` walks this table, top to bottom (plan 7.6, 7.7, 6.9):
    - No key (cache off, method not cacheable, a `cache_private` credential endpoint): upstream directly, `OFF`.
      A POST that is `OFF` only because of `cache_post_requests` still carries the key the cache would use on
      `req.cache_key` (`CachePeek.off_key`), as its identity for request samples and the dry run; nothing is
      looked up, served or stored under it.
    - Fresh entry: `HIT` (a cached 400/403/404/410 replays its status, reason `cache_negative`). Fresh means
      fresh when `peek` read it: the abuse verdict in between may have admitted the request only as a cache hit,
      so an entry that expired during the verdict is still served, never fetched (finding INGRESS-3).
    - A live per-key 429 marker: the stale entry (`STALE`, `cache_stale_cooldown`) or 429 with Retry-After
      (`upstream_cooldown`, `MISS`), without contacting Roblox.
    - Expired within the SWR window (`cache_swr_seconds`, or the rule's `stale_ttl`): served at once as
      `REVALIDATING` while one background refresh runs (fleet single-flight, background priority), unless the
      worker's refresh budget is full.
    - Expired within the stale window while the upstream reports the endpoint cooling down or its breaker
      open: `STALE` without contacting Roblox (`Roxy-Upstream-Cooldown`).
    - Otherwise one fleet single-flight fetch (interactive priority, or the shorter "stale available" class).
      The single-flight lease rides in the upstream's bucket reservation transaction (`lease=`, plan 6.3 and
      7.3); a lost lease (`SingleFlightLost`) makes this request a follower. The owner answers `MISS` as soon as
      Roblox answered: the entry goes into this worker's memory tier at once, and the cache.db write (bounded:
      at most `MAX_PENDING_WRITES` at a time, failures and skips counted) happens afterwards in the flight's
      background tail, so a locked cache.db never delays a caller (C7, the cache is disposable). Followers get
      `COALESCED` (the stored entry, or the owner's shared answer: inline in the lease row when small, else in a
      short-lived cache.db handoff row); a failure with a stale entry becomes `STALE` (`cache_stale_error`,
      `stale_after_failure`); a follower whose wait ends gets the stale entry or 503 `coalesce_timeout` with
      the owner's remaining deadline as Retry-After. Followers never call upstream after an owner failure.
      Followers in other workers also look in cache.db while the owner's outcome is late (`_stored_answer`,
      plan 6.9 step 4), so an owner that stored its answer but never published it still answers them.
    Every refetch of a key that had a body before feeds `change_observations` (identical body or not) for TTL
    tuning (F10). An answer fetched with the credential belongs to its own request alone (plan 6.9, C2) when the
    rules moved between the peek and the routing: the upstream used the credential for a key that is not a
    credential key, or fetched it under an allowlist row that is `cache_private` (`UpstreamResult.private`, or the
    row as it is when the answer arrives). Such an answer is never stored, never handed to a follower in this
    worker or another (they compete again and make their own call), and never served stale or by a refresh.
    Pattern matching runs under `roxy.rules.match.regex_budget` (plan 9.9): the policy lookup in `peek` (cache
    rules and the credential allowlist), the availability check and every upstream call made for a request, so a
    stored slow regex costs at most the budget, never one timeout per rule. Budgets nest: inside the router's
    request budget these blocks spend from it instead of starting their own.

What to read next
    `roxy/cache/keys.py`, `roxy/cache/policy.py`, `roxy/cache/store.py`, `roxy/upstream/singleflight.py` and
    `roxy/cache/swr.py`; then `roxy/proxy/router.py` (the caller) and `roxy/proxy/respond.py` (the headers).
"""

from __future__ import annotations

import contextlib
import copy
import dataclasses
import functools
import inspect
import logging
import math
import sqlite3
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final, Protocol

from roxy.cache.keys import (
    HANDOFF_SUFFIX,
    MARKER_SUFFIX,
    VARY_HEADERS,
    CacheKey,
    assert_forward_list,
    build_key,
    canonical_method,
)
from roxy.cache.policy import CacheSettings, RequestPolicy, StoreDecision, StoreKind, request_policy, store_decision
from roxy.cache.spread import DEFAULT_MAX_ROWS, SpreadGroup, compute_spread, rows_from_db, thresholds
from roxy.cache.store import CacheEntry, CacheStore, EvictionReport, PurgeScope
from roxy.cache.swr import SwrRefresher
from roxy.config.constants import CACHE_PAGE_MAX
from roxy.core.clock import Clock
from roxy.core.reasons import AuthClass, CacheState, Egress, Outcome, ReasonCode, Source
from roxy.metrics.recorder import note_cache_store, note_eviction_ages, note_eviction_pass
from roxy.rules.match import regex_budget
from roxy.rules.store import RulesSnapshot
from roxy.storage import leases
from roxy.storage.db import SharedStateUnavailable
from roxy.upstream.buckets import LeaseHook
from roxy.upstream.messages import BUSY_MESSAGE, MESSAGE_CONTENT_TYPE
from roxy.upstream.queue import Priority
from roxy.upstream.service import SingleFlightLost
from roxy.upstream.singleflight import (
    SHARE_BODY_MAX,
    Deferred,
    FlightOutcome,
    FlightResult,
    FlightStart,
    LeaseLost,
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
MAX_PENDING_WRITES: Final = 32
"""cache.db writes one worker keeps waiting at once (plan P9). They run after the caller was answered; beyond
this a store is skipped and counted (`store_skipped`), so a locked cache.db cannot pile up bodies in memory."""
HANDOFF_BODY_MAX: Final = 8 * 1024 * 1024
"""Largest answer passed to followers in other workers through a cache.db handoff row (the top of the
`cache_max_body` range). Bigger answers publish `nostore` and those followers compete again."""
HANDOFF_TTL_S: Final = 10
"""How long a handoff row is kept: followers read it within the outcome's one second linger; the maintenance
pass deletes it once this has passed."""
STORE_CHECK_MARGIN_S: Final = 1
"""A follower that looks in cache.db for its owner's answer (`_stored_answer`) accepts rows stored at most this
many whole seconds before its own request began (timestamps are whole seconds and the wall clock can step back a
little); anything older was not fetched for this request."""


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
    off_key: CacheKey | None = None
    """For a POST the cache has `OFF` only because of `cache_post_requests` (`RequestPolicy.key_when_off`): the key
    it would use. Never looked up, served or stored under (`key` stays None); `peek` puts it on `req.cache_key` as
    the request's identity, so request samples, the upstream's User-Agent arm and the retry hold treat the request
    exactly as a cached POST, and the dry run can replay a POST cache rule over it (finding insights-7)."""

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
    private: int = 0
    """Credential answers for a non-credential key, kept to their own request (plan 6.9)."""
    store_failures: int = 0
    """cache.db writes that failed after the caller was answered (the answer itself was never affected)."""
    store_skipped: int = 0
    """cache.db writes skipped because `MAX_PENDING_WRITES` were already waiting."""
    handoffs: int = 0
    """Answers too big for the lease row, passed to other workers through a cache.db handoff row."""


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
    private: bool = False
    """The answer belongs to the owner's own request (`_private_to`): never handed to a follower."""


def _private_to(result: Any, key: CacheKey) -> bool:
    """True when `result` was fetched with the credential and belongs to its own request alone (plan 6.9, C2):
    the key is not a credential key, or the upstream fetched it under a `cache_private` allowlist row (or none),
    which it reports as `result.private`.

    The upstream routes with its own read of the rules, so an allowlist row added, changed to `cache_private` (or a
    regex timing out differently) between `peek` and the fetch can send the request with the credential under a
    privacy the key does not show (findings F2 and cred-4). Such an answer is never stored, coalesced, revalidated
    or stale-served to anyone else.
    """
    if AuthClass(getattr(result, "auth_class", AuthClass.ANON)) is not AuthClass.CRED:
        return False
    return key.auth_class is not AuthClass.CRED or bool(getattr(result, "private", False))


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
        self._pending_writes = 0  # cache.db writes waiting right now (bounded by MAX_PENDING_WRITES)
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
        """Shutdown: give pending stores and outcome publishes a moment to land, stop any flight still running,
        then flush buffered hits (their rows now exist)."""
        await self.flights.close()
        await self.flush()

    async def flush(self) -> int:
        return await self.store.flush()

    async def settle(self, timeout_s: float = 10.0) -> None:
        """Wait (at most `timeout_s`) until every answered request's cache.db write and outcome publish are done.
        Requests never wait for this; tests and admin views that read cache.db right after a request do."""
        await self.flights.settle(timeout_s)

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
        `req.fresh_cache_hit`. A broken cache.db read is a miss, never an error.

        The router runs this before the abuse verdict only when a check reads `fresh_cache_hit`
        (`throttle_count_cache_hits` off or `cache_serve_throttled` on), else after an Allow. Either way the
        pattern matches share one `regex_budget` (plan 9.9; the router's request budget when it opened one). A
        cache rule or allowlist match cut off by the budget counts as no match (no rule, anonymous), which only
        ever grants less.

        A POST that `cache_post_requests` keeps `OFF` still gets the key the cache would use, as `CachePeek.off_key`
        and `req.cache_key` (its identity, plan 6.2: request samples feed the 11.3 dry run and TTL tuner), and no
        lookup: `serve` follows `CachePeek.key`, which stays None, so nothing is served or stored under it. Other
        `OFF` requests (the cache switched off, another method, a `cache_private` credential endpoint) get no key.
        """
        cs = self._cs()
        now = self._clock.now()
        snapshot = self._snapshot()
        headers = getattr(req, "headers", None) or {}
        with regex_budget():
            policy = request_policy(req.method, _target_of(req), headers, cs, snapshot)
        if not policy.cacheable:
            off_key = self._key_for(req, policy, snapshot) if policy.key_when_off else None
            self._mark(req, off_key, False)
            return CachePeek(key=None, policy=policy, now=now, generation=self.store.floor, off_key=off_key)
        key = self._key_for(req, policy, snapshot)
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
    def _key_for(req: Any, policy: RequestPolicy, snapshot: RulesSnapshot) -> CacheKey:
        """The request's cache key under `policy.rule` and today's ignored parameters (string work and one SHA-256
        of a POST body already held in memory; no lookup)."""
        return build_key(
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
        if fresh is not None:
            # Served even if it expired since the peek (finding INGRESS-3). The abuse verdict between the two may
            # have let this request through, uncounted, or answered a throttled caller, only because the peek saw
            # a fresh hit (`fresh_cache_hit`); a fresh check against the later clock would turn that request into
            # an upstream call the limiter never allowed. The overrun is the verdict's own budget (one hot.db write).
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
        result = await self._call_upstream(req, priority=Priority.INTERACTIVE, stale_available=False, purpose="caller")
        return self._from_upstream(result, CacheState.OFF, None)

    async def _call_upstream(
        self, req: Any, *, priority: Priority, stale_available: bool, purpose: str, lease: LeaseHook | None = None
    ) -> Any:
        """One upstream fetch. The single-flight lease hook (when this request competes for one) goes into the
        upstream's reservation transaction; a lost lease becomes `LeaseLost` for the flight to follow the winner.
        The upstream's allowlist and routing matches share one regex budget (plan 9.9)."""
        extra: dict[str, Any] = {"lease": lease} if lease is not None else {}
        try:
            with regex_budget():
                return await self._upstream.fetch(
                    req, priority=priority, stale_available=stale_available, purpose=purpose, **extra
                )
        except SingleFlightLost as exc:
            raise LeaseLost(str(exc)) from exc

    async def _cooldown_remaining(self, req: Any) -> int | None:
        """Seconds until the endpoint can be asked again when the upstream says no egress is available now."""
        check = getattr(self._upstream, "availability", None)
        if not callable(check):
            return None
        try:
            with regex_budget():  # availability matches the credential allowlist (plan 9.9)
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
        since = int(self._clock.now()) - STORE_CHECK_MARGIN_S

        async def stored(final: bool) -> FlightOutcome | None:
            return await self._stored_answer(key, cs, since, final=final)

        async def fetch(start: FlightStart) -> tuple[_OwnerValue, FlightOutcome | Deferred]:
            if start.takeover:
                # The previous owner may have stored the answer before it died or gave up: never call twice.
                now = self._clock.now()
                existing = await self.store.get(key.id, now=now, disk=cs.disk_enabled)
                if (
                    existing is not None
                    and existing.is_fresh(now)
                    and existing.auth_class == key.auth_class
                    and not existing.is_marker
                ):
                    return _OwnerValue(None, existing), self._existing_outcome(key, existing, cs)
            result = await self._call_upstream(
                req, priority=priority, stale_available=stale is not None, purpose="caller", lease=start.lease
            )
            return self._absorb(req, peek, result, cs)

        for _round in range(MAX_FLIGHT_ROUNDS):
            flight = await self.flights.run(
                key.flight_key,
                fetch,
                owner_deadline_s=cs.owner_deadline_s,
                wait_s=wait_s,
                enabled=peek.policy.coalesce,
                hooked=True,
                check=stored,
            )
            served = await self._serve_flight(flight, key, stale)
            if served is not None:
                return served
        self.stats.coalesce_timeouts += 1
        return self._timeout_result(key, 1)

    async def _stored_answer(
        self, key: CacheKey, cs: CacheSettings, since: int, *, final: bool
    ) -> FlightOutcome | None:
        """Where a follower looks when the owner's outcome is late (plan 6.9 step 4 polls cache.db; finding mp-12).

        The owner writes cache.db before it publishes, so an owner whose publish never landed (hot.db busy, then
        its worker stopped or was killed) has still left its answer here: the fresh entry, as a `stored` outcome,
        or on the last look before a timeout its handoff row (a big unstored answer), as a `shared` one. Only rows
        written since `since` (the request's start minus `STORE_CHECK_MARGIN_S`) count, so a caller that asked for
        a fresh copy (`Cache-Control: no-cache`) never gets an older entry this way. Read errors are a miss.
        """
        now = self._clock.now()
        entry = await self.store.get(key.id, now=now, disk=cs.disk_enabled)
        if (
            entry is not None
            and entry.is_fresh(now)
            and entry.auth_class == key.auth_class
            and not entry.is_marker
            and entry.stored_at >= since
        ):
            return self._stored_outcome(entry)
        if not final:
            return None  # handoff rows hold up to 8 MiB: read one only instead of answering 503
        handoff = await self.store.read_handoff(key.handoff_id)
        if (
            handoff is None
            or handoff.auth_class != key.auth_class
            or handoff.stored_at < since
            or now >= handoff.stale_until
        ):
            return None
        reason = ReasonCode.UPSTREAM_4XX if 400 <= handoff.status < 500 else ReasonCode.UPSTREAM_OK
        return FlightOutcome(
            OutcomeKind.SHARED,
            status=handoff.status,
            reason=reason.value,
            body=handoff.body,
            content_type=handoff.content_type,
            upstream_status=handoff.status,
        )

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
            if value.private or (value.result is not None and _private_to(value.result, key)):
                return None  # the owner's credential answer is its own (plan 6.9): compete again, fetch our own
            if value.entry is not None and value.entry.auth_class == key.auth_class:
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
            body = outcome.body
            if not body and outcome.entry_id is not None:  # too big for the lease row: read the handoff row
                handoff = await self.store.read_handoff(outcome.entry_id)
                if handoff is None or handoff.auth_class != key.auth_class or handoff.stored_at != outcome.stored_at:
                    return None  # gone (purged) or replaced by a newer flight: one more flight
                body = handoff.body
            return self._from_shared(
                key,
                outcome.status,
                body,
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

    def _absorb(
        self, req: Any, peek: CachePeek, result: Any, cs: CacheSettings
    ) -> tuple[_OwnerValue, FlightOutcome | Deferred]:
        """Decide what to keep (policy), put it in this worker's memory tier, record change observations, and
        hand the flight a `Deferred` outcome whose `finish` (run after the caller was answered) writes cache.db
        and says what followers in other workers get. No I/O here: the owner's answer never waits for cache.db."""
        key = peek.key
        if key is None:  # owners always have a key
            raise RuntimeError("a cache owner needs a cache key")
        if _private_to(result, key) or self._row_now_private(req, result):
            self.stats.private += 1
            return _OwnerValue(result, None, None, private=True), FlightOutcome(OutcomeKind.PRIVATE)
        decision = store_decision(result, peek.policy, cs)
        now = self._clock.now()
        entry: CacheEntry | None = None
        if decision.kind is not StoreKind.NONE:
            entry = self._make_entry(key, peek.policy, result, decision, now, peek.generation)
            self.store.memory.put(entry)  # this worker serves it at once; the cache.db row follows in the tail
            if decision.kind is StoreKind.MARKER:
                self.stats.markers += 1
            else:
                self.stats.stores += 1
                self._observe_change(req, peek, entry, now)
        elif decision.skipped:
            self.stats.skipped += 1
        content = entry if entry is not None and decision.kind is not StoreKind.MARKER else None
        body = getattr(req, "body", None) or b""
        req_body = body if key.method == "POST" and body and decision.kind is StoreKind.ENTRY else None
        finish = functools.partial(self._finish, key, result, entry, content is not None, req_body, cs, peek.generation)
        return _OwnerValue(result, content, decision), Deferred(finish)

    def _row_now_private(self, req: Any, result: Any) -> bool:
        """A credential answer whose allowlist row is `cache_private` (or gone) in the rules as they are now.

        Defense in depth for `_private_to` (finding cred-4): when an admin marks an endpoint private while a flight
        runs (the reason the switch exists), the answer is kept to its own request even if the upstream fetched it
        just before the change. A match cut off by the regex budget finds no row and counts as private, which only
        ever shares less. Anonymous answers are never private.
        """
        if AuthClass(getattr(result, "auth_class", AuthClass.ANON)) is not AuthClass.CRED:
            return False
        with regex_budget():  # the allowlist may hold regex rows (plan 9.9); nested in the request's budget
            row = self._snapshot().credential_rule_for(_target_of(req), canonical_method(str(req.method)))
        return row is None or bool(row.cache_private)

    async def _finish(
        self,
        key: CacheKey,
        result: Any,
        entry: CacheEntry | None,
        is_content: bool,
        req_body: bytes | None,
        cs: CacheSettings,
        generation: int,
    ) -> FlightOutcome:
        """The owner's tail: write the cache.db row, then say what followers in other workers get."""
        attempted = stored = False
        if entry is not None and cs.shared_tier_on:
            attempted = True
            stored = await self._write_shared(entry, cs.compress, req_body)
        if is_content and entry is not None and stored:
            return self._stored_outcome(entry)
        return await self._share(
            key,
            status=int(result.status),
            reason=ReasonCode(result.reason).value,
            body=bytes(result.body or b""),
            content_type=result.content_type,
            upstream_status=result.upstream_status,
            retry_after_s=_seconds(result.retry_after_s),
            cooldown_s=_seconds(result.cooldown_s),
            egress=str(getattr(result, "egress", "") or ""),
            generation=generation,
            cs=cs,
            handoff_ok=not (attempted and not stored),  # cache.db just refused a write: do not wait on it again
        )

    async def _share(
        self,
        key: CacheKey,
        *,
        status: int,
        reason: str,
        body: bytes,
        content_type: str | None,
        upstream_status: int | None,
        retry_after_s: int | None,
        cooldown_s: int | None,
        egress: str,
        generation: int,
        cs: CacheSettings,
        handoff_ok: bool,
    ) -> FlightOutcome:
        """An answer that is not (or not yet) a cache.db entry, as a `shared` outcome: the body inline when it
        fits the lease row, else in a handoff row (finding SF-NOSTORE: followers never compete again only because
        an answer was big or the disk tier is off). `nostore` only when even the handoff row cannot be written."""
        fields: dict[str, Any] = {
            "status": status,
            "reason": reason,
            "content_type": content_type,
            "upstream_status": upstream_status,
            "retry_after_s": retry_after_s,
            "cooldown_s": cooldown_s,
        }
        if len(body) <= SHARE_BODY_MAX:
            return FlightOutcome(OutcomeKind.SHARED, body=body, **fields)
        if handoff_ok and len(body) <= HANDOFF_BODY_MAX:
            handoff = self._handoff_entry(key, status, body, content_type, egress, generation)
            if await self._write_shared(handoff, cs.compress, None):
                self.stats.handoffs += 1
                return FlightOutcome(OutcomeKind.SHARED, entry_id=handoff.id, stored_at=handoff.stored_at, **fields)
        return FlightOutcome(OutcomeKind.NOSTORE, status=status, reason=reason)

    async def _write_shared(self, entry: CacheEntry, compress: bool, req_body: bytes | None) -> bool:
        """One cache.db write after the caller was answered, bounded by `MAX_PENDING_WRITES` per worker. A skip
        or a failure is counted; the answer was already served either way."""
        if self.store.shared is None:
            return False
        if self._pending_writes >= MAX_PENDING_WRITES:
            self.stats.store_skipped += 1
            return False
        self._pending_writes += 1
        try:
            written = await self.store.write_shared(entry, compress=compress, req_body=req_body)
        finally:
            self._pending_writes -= 1
        note_cache_store(self._recorder, written)  # stores per minute, the CACHE-PRESSURE denominator
        if not written:
            self.stats.store_failures += 1
        return written

    def _handoff_entry(
        self, key: CacheKey, status: int, body: bytes, content_type: str | None, egress: str, generation: int
    ) -> CacheEntry:
        """The short-lived row that carries a big answer to followers in other workers (never a lookup result:
        its id is `key.handoff_id`, it is already expired, and it is negative so nothing serves it as content)."""
        now = int(self._clock.now())
        return CacheEntry(
            id=key.handoff_id,
            key=key.text + HANDOFF_SUFFIX,
            auth_class=key.auth_class,
            method=key.method,
            host=key.host,
            path=key.path,
            status=status,
            body=body,
            content_type=content_type,
            stored_at=now,
            expires_at=now,
            stale_until=now + HANDOFF_TTL_S,
            ttl=0,
            params=key.params,
            stripped=key.stripped,
            egress=egress or None,
            negative=True,
            generation=generation,
        )

    def _existing_outcome(self, key: CacheKey, entry: CacheEntry, cs: CacheSettings) -> FlightOutcome | Deferred:
        """What followers get when a takeover found the answer already cached: the cache.db entry when the shared
        tier holds it, else the entry itself shared like a fresh answer (it may live only in this worker's memory)."""
        if cs.shared_tier_on:
            return self._stored_outcome(entry)
        reason = ReasonCode.UPSTREAM_4XX if 400 <= entry.status < 500 else ReasonCode.UPSTREAM_OK
        return Deferred(
            functools.partial(
                self._share,
                key,
                status=entry.status,
                reason=reason.value,
                body=entry.body,
                content_type=entry.content_type,
                upstream_status=entry.status,
                retry_after_s=None,
                cooldown_s=None,
                egress=entry.egress or "",
                generation=entry.generation,
                cs=cs,
                handoff_ok=True,
            )
        )

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

        async def fetch(start: FlightStart) -> tuple[_OwnerValue, FlightOutcome | Deferred]:
            # The refresh task copied the context of the request that started it: its own regex budget (plan
            # 9.9), never what is left of that request's, which may already be spent. `_absorb` matches the
            # credential allowlist again (`_row_now_private`), so it runs inside the same budget.
            with regex_budget(fresh=True):
                result = await self._call_upstream(
                    detached,
                    priority=Priority.BACKGROUND,
                    stale_available=True,
                    purpose="swr_refresh",
                    lease=start.lease,
                )
                return self._absorb(detached, peek, result, cs)

        flight = await self.flights.try_lead(key.flight_key, fetch, owner_deadline_s=cs.owner_deadline_s, hooked=True)
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
        """The eviction pass, at most once a minute fleet-wide (a hot.db lease that is left to expire). While the
        disk tier is off only dead rows are removed (single-flight handoff rows are still written then)."""
        cs = self._cs()
        if self.store.shared is None:
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
        if not cs.disk_enabled:
            try:
                dead = await self.store.remove_dead(self._clock.now())
            except (SharedStateUnavailable, sqlite3.Error):
                return None  # the disk tier is off, often because cache.db is failing: nothing to report
            self.stats.dead_removed += dead
            return EvictionReport(dead=dead)
        report = await self.store.maintain(
            max_entries=cs.max_entries, max_bytes=cs.max_bytes, policy=cs.eviction_policy, now=self._clock.now()
        )
        self.stats.evictions += report.evicted
        self.stats.dead_removed += report.dead
        note_eviction_pass(self._recorder, report)  # which cap forced evictions (CACHE-PRESSURE)
        note_eviction_ages(self._recorder, report)  # how many of them were still young (CACHE-PRESSURE)
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
            "Finishing": self.flights.tails(),
            "PendingWrites": self._pending_writes,
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
