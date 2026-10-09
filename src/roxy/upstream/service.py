"""UpstreamService: the one way any part of Roxy fetches something from Roblox.

What this is
    `UpstreamService.fetch(req, priority=..., stale_available=...)` makes the upstream call for a caller's cache
    miss (or a background refresh) and always returns an `UpstreamResult`, never an exception for an upstream
    problem: every failure becomes a row of the plan 7.13 table (`messages.py`). `internal_fetch` does the same for
    Roxy's own calls (probes, admin lookups) at internal priority. `availability`, `reset_state` and
    `bucket_snapshot` serve the cache layer and the Upstream page.

Why it exists
    It is the place where the fixes of plan 2.5 meet: routing that confines the credential (F11), pacing with
    shared GCRA buckets (F3), Retry-After and x-ratelimit honored for every worker (F2), adaptive rates (F4), a
    bounded priority queue (F7), circuit breakers (F8), jittered retries that never jump to another egress on a
    429 by default (F9), and honest statuses (F12). DESIGN.md 11.3 is the contract.

How it works (one fetch)
    1. Normalize the target (`host`, `/path`, endpoint template, URL with the caller's query in order) and read
       the settings and rules snapshots once. The credential allowlist (exact grants) and routing rule lookups
       run under `regex_budget` (plan 9.9); a match cut off by it never grants the credential.
    2. Route (`_route`): one hot.db READ gives every relevant cooldown, breaker and bucket TAT; `routing.decide`
       picks an egress; `buckets.reserve` takes the slot in ONE hot.db WRITE transaction that also inserts the
       single-flight lease (when the cache passed a hook), re-checks cooldowns, takes the half-open probe lease of
       a breaker, and (Tier 3) an AIMD slot. Nothing is committed when any of them says no.
    3. Wait for the slot in the per-worker `WaitQueue` (bounded; a canceled or evicted wait refunds the slot), and
       re-check cooldowns after a real wait, so a cooldown opened meanwhile by another worker is still honored.
    4. Send through the egress (which adds its API-shaped header profile; upstream adds only the body's
       Content-Type, a safe forwarded Accept and a cached CSRF token for write methods), with timeouts clipped to
       the request deadline. A CSRF 403 is retried once with the new token (a new bucket slot); a 3xx is followed
       here, not by the egress, so every hop takes a bucket slot, and only to a URL that passes the same checks as
       a caller's own path (`proxy/validate.py parse_redirect`: an allowed Roblox host, no encoded slash or
       dot segment) and, on the credential path, whose decoded path the allowlist grants; a Location that does
       not parse or pass is simply not followed. A CSRF retry is recorded for the Upstream page (`record_retry`,
       row 117).
    5. Classify (`status.py`), apply the side effects in at most one more hot.db transaction (`effects.py`, skipped
       for a plain success), then: log Roblox 429s (`record_upstream_429`), rotate a burned rotator session, lower
       the attributed bucket rate, set the credential cooldown, and decide by the 7.9 table whether to retry.
    6. Retry only 5xx, timeouts and connect errors, up to `upstream_max_attempts` in total, after a decorrelated
       jitter backoff, and only while the request deadline allows. A 429 is never retried at once; with
       `fallback_on_429=1` one retry on the OTHER anonymous egress is allowed, never onto the credential.
    C7: if hot.db cannot be used, the request is not sent unpaced and the credential is never used; the answer is
    the `degraded` row (503, Retry-After 10), or stale data from the cache layer. Once Roblox answered, the answer
    is Roblox's, whatever hot.db does: the writes after the call (its effects, a CSRF token, refunds) wait at most
    `HOT_SIDE_WRITE_BUDGET_MS` for another process's lock, a 429's cooldown that could not be written is kept in
    this worker's memory (`LocalCooldowns`), honored by every routing decision here and written to hot.db (for
    every worker) as soon as a write succeeds (`flush_local_cooldowns`, from the next fetch or the mirror loop),
    and a retry that hot.db cannot pace is not made: the caller gets Roblox's own 5xx, timeout or connect answer,
    never `degraded` (findings mp-7, mp-8). A request canceled while its reservation is being written gives back
    what that write granted (finding mp-9). A credential refused at send time answers with the wait the
    credential manager gave, not a fixed 300 s.

What to read next
    `roxy/upstream/routing.py`, `roxy/upstream/buckets.py`, `roxy/upstream/effects.py`, then the cache layer's
    `upstream/singleflight.py`, which calls `fetch`.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import importlib
import itertools
import logging
import random
import re
import sqlite3
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final, Literal, Protocol
from urllib.parse import parse_qsl, urlencode, urlsplit

import httpx

from roxy.core.clock import Clock
from roxy.core.ids import new_request_id
from roxy.core.reasons import AuthClass, Egress, ReasonCode
from roxy.metrics.recorder import note_attempts, note_reservation
from roxy.proxy.validate import parse_redirect
from roxy.rules.match import regex_budget
from roxy.storage.db import Database, SharedStateUnavailable
from roxy.upstream import aimd, breaker, buckets, cooldowns, csrf, deadlines, messages, routing
from roxy.upstream.adaptive import (
    AdaptiveController,
    AdaptivePolicy,
    LimitsWriter,
    RateChange,
    RulesLimitsWriter,
)
from roxy.upstream.adaptive import increase_job as adaptive_increase_job
from roxy.upstream.backoff import DecorrelatedJitter
from roxy.upstream.breaker import BreakerPolicy, BreakerRow
from roxy.upstream.buckets import BucketDefaults, BucketSpec, Grant, GuardDenial, LeaseHook, ReserveOutcome
from roxy.upstream.cooldowns import CooldownPolicy, CooldownRow
from roxy.upstream.effects import CallEffects, CallFacts, EffectsConfig, apply_call_outcome, should_record
from roxy.upstream.egress_port import (
    PURPOSE_CREDENTIAL_PROBE,
    OutboundRequest,
    call_optional,
    credential_view,
    egress_error,
    enabled,
    maybe_await,
)
from roxy.upstream.queue import Priority, WaitQueue
from roxy.upstream.routing import CredentialRule, EgressAvailability, RouteDecision, RouteRequest
from roxy.upstream.status import (
    NEGATIVE_CACHE_STATUSES,
    SUCCESS_LIKE,
    AttemptKind,
    RetryRule,
    classify_exception,
    classify_response,
    has_csrf_token,
    is_negative_cacheable,
    policy_for,
)
from roxy.upstream.trace import Trace, short_hash

log = logging.getLogger(__name__)

__all__ = [
    "Availability",
    "Priority",
    "ProbeResponse",
    "SingleFlightLost",
    "UpstreamRequest",
    "UpstreamResult",
    "UpstreamService",
]

HOT_BUSY_TIMEOUT_MS: Final = 2000
"""The reservation waits at most 2 s for hot.db's write lock before answering `degraded` (plan C7)."""

HOT_SIDE_WRITE_BUDGET_MS: Final = 500
"""Most a request-path hot.db write that has a fallback waits for another process's lock (finding mp-7): the call's
effects after Roblox answered (a cooldown it cannot write is kept in memory), sharing a CSRF token, refunding an
unused slot, releasing a reservation (it expires on its own), sharing cooldowns kept in memory. Roblox's answer is
already in hand or the request is going nowhere, so the caller never waits out SQLite's 5 s busy timeout; 0.5 s is
the abuse pipeline's own budget and covers ordinary contention between workers (each write takes milliseconds)."""

MAX_MIRROR_ENTRIES: Final = 5000
"""Per-worker bound on the availability mirror (active cooldowns are far fewer in practice)."""

MAX_REDIRECT_HOPS: Final = 3
MAX_ROUTE_ROUNDS: Final = 3
MAX_REROUTES: Final = 4
MIN_CALL_TIME_MS: Final = 1000.0
"""A slot is never reserved so late that less than this is left of the request deadline for the call itself."""

SAFE_RESPONSE_HEADERS: Final = frozenset(
    {
        "content-type",
        "cache-control",
        "retry-after",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
        "etag",
        "last-modified",
        "content-language",
    }
)
"""Upstream headers that may travel back toward a caller (plan 9.13); `respond.py` applies its own final list.
Never `set-cookie`, never `x-csrf-token`, never anything that could carry account data."""

FORWARDED_ACCEPT: Final = frozenset({"application/json", "*/*"})
"""Plan 9.13: a caller's `Accept` is forwarded only when it is one of these; otherwise Roxy's own is sent."""

_ROBLOX_HOST = re.compile(r"(?:[a-z0-9-]+\.)*roblox\.com")
CALLER: Final = "caller"
PROBE_TRIGGERS: Final[Mapping[str, str]] = {
    "liveness": "scheduled",
    "health": "health",
    "admin_check": "admin",
    "confirm_401": "upstream",
}
"""The trigger recorded with a credential probe of each `CredentialManager.probe` kind (CRED-PROBE-COST groups
the account's calls by it: `scheduled`, `health`, `admin`; a 401 confirmation is started by an upstream answer)."""


class SingleFlightLost(Exception):
    """The single-flight lease hook found the key owned by another worker: the caller becomes a follower.

    The only exception `fetch` raises on purpose, and only when the caller passed `lease=`.
    """


class UpstreamRequest(Protocol):
    """The fields of `proxy.context.ProxyRequest` that upstream reads (DESIGN.md section 7)."""

    request_id: str
    method: str
    host: str
    path: str
    query: Sequence[tuple[str, str]]
    body: bytes
    content_type: str | None
    headers: Mapping[str, str]
    template: str
    deadline_at: float


@dataclass(slots=True)
class UpstreamResult:
    """The outcome of a fetch (DESIGN.md 11.3). `reason` is always a 7.13 row; `status` is what callers get."""

    status: int
    headers: dict[str, str]
    body: bytes
    content_type: str | None
    egress: Egress
    auth_class: AuthClass
    upstream_status: int | None
    reason: ReasonCode
    retry_after_s: int | None
    cooldown_s: int | None
    attempts: int
    calls: int
    bytes_in: int
    bytes_out: int
    queue_wait_ms: float
    upstream_ms: float
    trace: Trace
    cacheable: bool = False
    negative_ttl_s: int | None = None
    cooldown_source: str = ""  # added: why a cooldown answer lasts as long as it does (Upstream page explainer)
    private: bool = False
    """Fetched with the credential under a `cache_private` allowlist row, or with no row (probes): the answer
    belongs to its own request and is never stored or handed to a follower (plan 6.9, 9.13; review finding cred-4).
    Only the upstream knows the row it actually routed under; the cache also re-reads the row when the answer
    arrives (`CacheService._row_now_private`)."""

    @property
    def ok(self) -> bool:
        """True when Roblox answered (any status the caller receives as Roblox's own)."""
        return self.reason in (ReasonCode.UPSTREAM_OK, ReasonCode.UPSTREAM_4XX)


@dataclass(frozen=True, slots=True)
class Availability:
    """Whether any egress could call this endpoint now (the cache uses it to serve STALE without asking)."""

    any_egress_available: bool
    cooldown_remaining_s: float  # 0 unless every usable egress is cooling down or its breaker is open
    soonest_s: float  # when the soonest egress frees up (0 = now)
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class UpstreamConfig:
    """Every setting a fetch uses, read once per settings version."""

    direct_enabled: bool
    rotator_enabled: bool
    credential_enabled: bool
    direct_weight: float
    rotator_weight: float
    shift_threshold_pct: float
    max_attempts: int
    fallback_on_429: bool
    backoff_base_ms: float
    backoff_cap_ms: float
    queue_max_length: int
    csrf_ttl_s: float
    error_ttl_s: int
    negative_429: bool
    allowed_hosts: frozenset[str]
    strict_hosts: bool
    max_url_length: int
    credential_probe_url: str
    defaults: BucketDefaults
    cooldown: CooldownPolicy
    breaker: BreakerPolicy
    adaptive: AdaptivePolicy
    aimd: aimd.AimdPolicy

    @classmethod
    def from_settings(cls, settings: Any) -> UpstreamConfig:
        get = settings.get
        return cls(
            direct_enabled=bool(get("direct_enabled")),
            rotator_enabled=bool(get("rotator_enabled")),
            credential_enabled=bool(get("credential_enabled")),
            direct_weight=float(get("direct_weight")),
            rotator_weight=float(get("rotator_weight")),
            shift_threshold_pct=float(get("direct_shift_threshold_pct")),
            max_attempts=max(1, int(get("upstream_max_attempts"))),
            fallback_on_429=bool(get("fallback_on_429")),
            backoff_base_ms=float(get("backoff_base_ms")),
            backoff_cap_ms=float(get("backoff_cap_ms")),
            queue_max_length=int(get("queue_max_length")),
            csrf_ttl_s=float(get("csrf_token_cache_s")),
            error_ttl_s=int(get("cache_error_ttl_seconds")),
            negative_429=bool(get("cache_negative_429")),
            allowed_hosts=frozenset(str(h).strip().lower().rstrip(".") for h in (get("allowed_roblox_hosts") or ())),
            strict_hosts=bool(get("strict_host_allowlist")),
            max_url_length=int(get("max_url_length")),
            credential_probe_url=str(get("credential_probe_url")),
            defaults=BucketDefaults.from_settings(settings),
            cooldown=CooldownPolicy.from_settings(settings),
            breaker=BreakerPolicy.from_settings(settings),
            adaptive=AdaptivePolicy.from_settings(settings),
            aimd=aimd.AimdPolicy.from_settings(settings),
        )


Mode = Literal["caller", "internal_anon", "internal_cred"]


@dataclass(slots=True)
class _Call:
    """The normalized request, shared by every attempt of one fetch."""

    req: Any
    method: str
    host: str
    path: str
    template: str
    url: str
    rules_target: str
    priority: Priority
    purpose: str
    mode: Mode
    credential_rule: CredentialRule | None
    routing_mode: str | None
    budget_ms: float
    cfg: UpstreamConfig
    rules: Any
    trace: Trace


@dataclass(slots=True)
class _RunState:
    lease: LeaseHook | None
    attempts: int = 0
    calls: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    queue_wait_ms: float = 0.0
    upstream_ms: float = 0.0
    exclude: set[Egress] = field(default_factory=set)
    last_failure: UpstreamResult | None = None
    reroutes: int = 0
    # Why the credential refused this request at send time and for how long (its `CredentialUnavailable`), so the
    # 503 carries the cooldown's real remaining time instead of the fixed 300 (wire report).
    credential_refusal: tuple[str, int | None] | None = None
    # hot.db refused the effects write of a call Roblox answered: a retry could not be paced either, so none is
    # made and Roblox's answer goes back (findings mp-7 and mp-8, plan C7).
    shared_unwritable: bool = False


@dataclass(slots=True)
class _Routed:
    """A reserved slot on one egress."""

    egress: Egress
    specs: tuple[BucketSpec, ...]
    grant: Grant
    holder: str
    probe_keys: tuple[str, ...] = ()
    aimd_key: str | None = None
    aimd_slot: str | None = None
    breakers_seen: dict[str, BreakerRow] = field(default_factory=dict)


@dataclass(slots=True)
class _Exchange:
    kind: AttemptKind
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    error: str = ""
    session_id: str | None = None


@dataclass(slots=True)
class _Snapshot:
    cooldowns: dict[str, CooldownRow]
    breakers: dict[str, BreakerRow]
    probe_leases: dict[str, float]  # breaker key -> remaining seconds of a probe lease someone holds
    tats: dict[str, float]


@dataclass(slots=True)
class _InternalRequest:
    """A request built for `internal_fetch` (same fields as `ProxyRequest` uses)."""

    request_id: str
    method: str
    host: str
    path: str
    query: list[tuple[str, str]]
    body: bytes
    content_type: str | None
    headers: dict[str, str]
    template: str
    deadline_at: float


@dataclass(slots=True)
class ProbeResponse:
    """An `EgressResponse`-shaped answer for the credential manager's probe (DESIGN.md 11.4 fields)."""

    status: int
    headers: httpx.Headers
    body: bytes
    elapsed_ms: float
    bytes_out: int
    bytes_in: int
    egress: Egress = Egress.CREDENTIAL
    session_id: str | None = None
    http_version: str = ""


def probe_response(result: UpstreamResult) -> ProbeResponse:
    """Turn an internal credential fetch back into the raw answer, or raise what the egress would have raised."""
    if result.reason in (ReasonCode.UPSTREAM_OK, ReasonCode.UPSTREAM_4XX, ReasonCode.UPSTREAM_5XX) or (
        result.reason is ReasonCode.UPSTREAM_COOLDOWN and result.upstream_status == 429
    ):
        headers = dict(result.headers)
        if result.upstream_status == 429 and result.retry_after_s is not None:
            headers["retry-after"] = str(result.retry_after_s)  # the cooldown Roxy already opened, for the manager
        return ProbeResponse(
            status=int(result.upstream_status or result.status),
            headers=httpx.Headers(headers),
            body=result.body,
            elapsed_ms=result.upstream_ms,
            bytes_out=result.bytes_out,
            bytes_in=result.bytes_in,
        )
    if result.reason is ReasonCode.UPSTREAM_TIMEOUT:
        raise egress_error("UpstreamTimeout", Egress.CREDENTIAL, "probe timed out")
    if result.reason is ReasonCode.UPSTREAM_CONNECT:
        raise egress_error("UpstreamConnectError", Egress.CREDENTIAL, "probe could not connect")
    why = "degraded" if result.reason is ReasonCode.DEGRADED else result.reason.value
    raise egress_error("CredentialUnavailable", why, result.retry_after_s)


_TEMPLATE_FN: list[Callable[[str, str], str] | None] = []


def template_for(host: str, path: str) -> str:
    """The metrics endpoint template (`metrics/templating.py` when it exists, else `host/path`)."""
    if not _TEMPLATE_FN:
        found: Callable[[str, str], str] | None = None
        with contextlib.suppress(ImportError):
            module = importlib.import_module("roxy.metrics.templating")
            candidate = getattr(module, "template_for", None)
            found = candidate if callable(candidate) else None
        _TEMPLATE_FN.append(found)
    fn = _TEMPLATE_FN[0]
    if fn is not None:
        with contextlib.suppress(Exception):
            return str(fn(host, path))
    return f"{host}{path}"


def is_roblox_https_url(url: str, allowed: frozenset[str] | None = None) -> bool:
    """https, port 443, no userinfo, a `*.roblox.com` host (and in `allowed` when given). Plan 9.10."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    host = (parts.hostname or "").lower()
    if host.endswith("."):
        host = host[:-1]
    if parts.scheme != "https" or parts.username is not None or parts.password is not None:
        return False
    if port not in (None, 443) or not _ROBLOX_HOST.fullmatch(host):
        return False
    return allowed is None or host in allowed


class UpstreamService:
    """One per worker (`ctx.upstream`). See the module docstring for the flow."""

    def __init__(
        self,
        ctx: Any,
        *,
        rng: random.Random | None = None,
        adaptive_writer: LimitsWriter | None = None,
        deadline_clock: Callable[[], float] | None = None,
    ) -> None:
        self._ctx = ctx
        self.clock: Clock = ctx.clock
        # `req.deadline_at` is in `time.monotonic()` seconds: the request deadline is enforced by `asyncio.timeout`
        # in core/deadline.py, which runs on real time, and the proxy, the cache and the tarpit read it that way
        # (DESIGN.md 11.3). Tests that step a fake clock through sleeps pass that clock's `monotonic` here.
        self.deadline_clock: Callable[[], float] = deadline_clock or time.monotonic
        self.hot: Database = ctx.dbs.hot
        self._rng = rng if rng is not None else random.Random()
        self.queue = WaitQueue(lambda: self.config().queue_max_length)
        self._holder_seq = itertools.count()
        self._cfg: tuple[Any, UpstreamConfig] | None = None
        self._mirror_cooldowns: dict[str, int] = {}  # key -> until_ms (active cooldowns, refreshed in the background)
        self._mirror_breakers: dict[str, float] = {}  # key -> reopen time in seconds (open breakers)
        # Cooldowns of 429s that arrived while hot.db could not be written (C7): honored here, written later.
        self.local_cooldowns = cooldowns.LocalCooldowns()
        self._background: set[asyncio.Task[Any]] = set()
        if adaptive_writer is None:
            from roxy.rules.service import RulesService  # local: keeps importing this module light

            adaptive_writer = RulesLimitsWriter(RulesService(ctx.dbs.control, clock=ctx.clock, store=ctx.rules))
        self.adaptive = AdaptiveController(adaptive_writer, event=self._record_event)

    # ------------------------------------------------------------------------------------------------- helpers

    def config(self) -> UpstreamConfig:
        """The settings snapshot, rebuilt only when the settings version changes."""
        settings = self._ctx.settings
        version = getattr(settings, "version", None)
        cached = self._cfg
        if cached is None or version is None or cached[0] != version:
            cached = (version, UpstreamConfig.from_settings(settings))
            self._cfg = cached
        return cached[1]

    @property
    def settings(self) -> Any:
        """The worker's live runtime settings (`ctx.settings`)."""
        return self._ctx.settings

    def _rules(self) -> Any:
        store = getattr(self._ctx, "rules", None)
        snapshot = getattr(store, "snapshot", None)
        return snapshot() if callable(snapshot) else snapshot

    @property
    def _egress(self) -> Any:
        return getattr(self._ctx, "egress", None)

    def _now_ms(self) -> int:
        return int(self.clock.now_ms())

    def _mono(self) -> float:
        return float(self.clock.monotonic())

    def _left_s(self, req: Any) -> float:
        """Seconds left before `req.deadline_at` (negative once it has passed), on `deadline_clock`."""
        return float(req.deadline_at) - float(self.deadline_clock())

    async def _sleep(self, seconds: float) -> None:
        """Sleep through the clock when it can (test clocks that run faster than real time), else asyncio."""
        sleeper = getattr(self.clock, "sleep", None)
        if callable(sleeper):
            await sleeper(max(0.0, seconds))
        else:
            await asyncio.sleep(max(0.0, seconds))

    def new_holder(self) -> str:
        """A unique lease holder id for one request in this worker."""
        return f"{getattr(self._ctx, 'worker_id', 'worker')}:{next(self._holder_seq)}"

    def _spawn(self, name: str, coro: Awaitable[Any]) -> None:
        """Run a small background job (bounded), never blocking the caller's answer."""
        tasks = getattr(self._ctx, "tasks", None)
        spawn = getattr(tasks, "spawn", None)
        if callable(spawn):
            spawn(name, coro, group="upstream", limit=16)
            return
        if len(self._background) >= 16:
            if asyncio.iscoroutine(coro):
                coro.close()
            return
        task = asyncio.ensure_future(coro)
        self._background.add(task)
        task.add_done_callback(self._background.discard)

    def _record_event(self, event_type: str, severity: str, reason: str, detail: dict[str, Any]) -> None:
        recorder = getattr(self._ctx, "recorder", None)
        if recorder is None:
            return
        try:
            recorder.record_event(event_type, severity, reason, detail)
        except Exception:  # metrics degrade open (plan C7)
            log.warning("upstream_event_record_failed", exc_info=True)

    def _alert_all_unavailable(self, call: _Call, states: Mapping[Egress, EgressAvailability]) -> None:
        """Parity rows 35 and 36, plan 17.7: every egress path is switched off, so callers cannot be served.

        Sent with v1's subject (`Roxy: all upstream methods unavailable`) through the notifier, which dedupes it
        fleet-wide (`all_unavailable`, 300 s). Only for "every path disabled": a cooldown on one endpoint is
        routine back pressure, shown on the Upstream page, and would make this alert cry wolf.
        """
        notifier = getattr(self._ctx, "alerts", None)
        notify = getattr(notifier, "notify", None)
        if not callable(notify):
            return
        try:
            alerts = importlib.import_module("roxy.notify.alerts")
            down = {egress.value: state.disabled_reason or "disabled" for egress, state in states.items()}
            alert = alerts.make_alert(
                "all_unavailable",
                summary=f"No egress path can reach Roblox for {call.host}{call.path}.",
                fields={"egresses": down, "endpoint": call.template},
            )
            notify(alert)
        except Exception:  # an alerting problem must never fail the caller's answer
            log.warning("all_unavailable_alert_failed", exc_info=True)

    def _record_retry(self, call: _Call, egress: Egress, status: int | None) -> None:
        """Row 117: one CSRF retry, under v1's own reason text (v1 counted only this retry, `log_retry`)."""
        recorder = getattr(self._ctx, "recorder", None)
        record = getattr(recorder, "record_retry", None)
        if not callable(record):
            return
        try:
            record(
                status=status,
                reason="CSRF token refresh",
                egress=egress.value,
                endpoint_template=call.template,
                at_ms=self._now_ms(),
            )
        except Exception:  # metrics degrade open (plan C7)
            log.warning("upstream_retry_record_failed", exc_info=True)

    def _record_429(self, call: _Call, egress: Egress, exchange: _Exchange, retry_after_s: float | None) -> None:
        recorder = getattr(self._ctx, "recorder", None)
        if recorder is None:
            return
        limits = cooldowns.parse_ratelimit_headers(exchange.headers, self.clock.now())
        try:
            recorder.record_upstream_429(
                at_ms=self._now_ms(),
                endpoint_template=call.template,
                host=call.host,
                egress=egress.value,
                retry_after_s=retry_after_s,
                ratelimit_headers=None if limits is None else limits.as_dict(),
                request_id=call.trace.request_id,
            )
        except Exception:
            log.warning("upstream_429_record_failed", exc_info=True)

    # ---------------------------------------------------------------------------------------------- public API

    async def fetch(
        self,
        req: UpstreamRequest,
        *,
        priority: Priority,
        stale_available: bool,
        purpose: str = CALLER,
        lease: LeaseHook | None = None,
    ) -> UpstreamResult:
        """Fetch `req` from Roblox. Never raises for upstream problems (only `SingleFlightLost`, see its doc).

        `stale_available=True` with interactive priority means the caller can fall back to a stale copy, so the
        request waits at most `queue_wait_stale_ms` (priority class 1). `lease` is the single-flight lease insert
        to run inside the first reservation transaction (plan 6.3).
        """
        effective = Priority(priority)
        if stale_available and effective is Priority.INTERACTIVE:
            effective = Priority.INTERACTIVE_STALE
        trace = Trace(request_id=str(getattr(req, "request_id", "")))
        return await self._guarded(req, effective, purpose, lease, trace, CALLER)

    async def internal_fetch(
        self,
        purpose: str,
        method: str,
        url: str,
        *,
        use_credential: bool = False,
        body: bytes | None = None,
        priority: Priority = Priority.INTERNAL,
        trigger: str = "",
    ) -> UpstreamResult:
        """Roxy's own call (a probe, a lookup) through the same buckets, cooldowns and breakers (rows 28, 29).

        Internal calls never pass the proxy pipeline (pause, blocks, throttles do not apply, v1 parity) but always
        pay their way in the buckets. `use_credential=True` sends through the credential path only (GET or HEAD,
        the reserved probe sub-bucket), never anonymously instead; otherwise the call is anonymous and never
        uses the credential. `trigger` (`scheduled`, `health`, `admin`, ...) is recorded with the call, so
        CRED-PROBE-COST can say which kind of probe spends the account's budget.
        """
        cfg = self.config()
        allowed = cfg.allowed_hosts if cfg.strict_hosts else None
        if not is_roblox_https_url(url, allowed):
            raise ValueError("internal_fetch needs an https URL on an allowed roblox.com host")
        upper = method.upper()
        if use_credential and upper not in routing.CREDENTIAL_METHODS:
            raise ValueError("the credential is only ever used for GET or HEAD (plan D1)")
        parts = urlsplit(url)
        host = (parts.hostname or "").lower().rstrip(".")
        path = parts.path or "/"
        settings = self._ctx.settings
        request = _InternalRequest(
            request_id=new_request_id(self.clock),
            method=upper,
            host=host,
            path=path,
            query=parse_qsl(parts.query, keep_blank_values=True),
            body=body or b"",
            content_type="application/json" if body else None,
            headers={},
            template=template_for(host, path),
            deadline_at=self.deadline_clock() + deadlines.internal_deadline_s(settings, Priority(priority)),
        )
        trace = Trace(request_id=request.request_id)
        mode: Mode = "internal_cred" if use_credential else "internal_anon"
        started = self._mono()
        result = await self._guarded(request, Priority(priority), purpose, None, trace, mode)
        self._record_internal(purpose, request, result, (self._mono() - started) * 1000, trigger=trigger)
        return result

    def availability(self, req: UpstreamRequest) -> Availability:
        """From this worker's mirror of active cooldowns and open breakers (refreshed every 500 ms by
        `run_mirror`, and by every fetch). `fetch` itself always reads hot.db; this is only a fast hint."""
        cfg = self.config()
        host, _path, template, _url, target = self._normalize(req)
        now_ms = self._now_ms()
        rules = self._rules()
        egresses = [Egress.DIRECT, Egress.ROTATOR]
        method = str(getattr(req, "method", "GET")).upper()
        if rules is not None and self._credential_row(rules, target, method) is not None:
            egresses = [Egress.CREDENTIAL]  # an allowlisted endpoint is only ever fetched with the credential
        enabled_list = [egress for egress in egresses if self._egress_enabled(egress, cfg)[0]]
        if not enabled_list:
            return Availability(False, 0.0, 60.0, ("all egress disabled",))
        waits: list[tuple[float, str]] = []
        for egress in enabled_list:
            cooldown = 0.0
            for key in self._ckeys(host, template, egress):
                cooldown = max(cooldown, (self._mirror_cooldowns.get(key, 0) - now_ms) / 1000)
            reopen = 0.0
            for key in breaker.breaker_keys(host, template, egress):
                reopen = max(reopen, self._mirror_breakers.get(key, 0.0) - now_ms / 1000)
            label = ""
            if cooldown > 0:
                label = f"{egress.value} cooling down"
            elif reopen > 0:
                label = f"{egress.value} breaker open"
            waits.append((max(cooldown, reopen, 0.0), label))
        soonest = min(wait for wait, _ in waits)
        reasons = tuple(text for _, text in waits if text)
        return Availability(soonest <= 0, soonest, soonest, reasons)

    def _note_cooldowns(self, rows: Mapping[str, int], now_ms: int) -> None:
        """Merge freshly seen cooldown ends into the mirror, keeping it bounded (plan P9)."""
        for key, until_ms in rows.items():
            self._mirror_cooldowns[key] = max(self._mirror_cooldowns.get(key, 0), until_ms)
        if len(self._mirror_cooldowns) > MAX_MIRROR_ENTRIES:
            self._mirror_cooldowns = {k: v for k, v in self._mirror_cooldowns.items() if v > now_ms}
            while len(self._mirror_cooldowns) > MAX_MIRROR_ENTRIES:
                self._mirror_cooldowns.pop(next(iter(self._mirror_cooldowns)))

    async def refresh_mirror(self) -> None:
        """Re-read active cooldowns and open breakers into this worker's mirror (one small read)."""
        now_ms = self._now_ms()

        def read(conn: sqlite3.Connection) -> tuple[dict[str, int], dict[str, float]]:
            cooling = {row.key: row.until_ms for row in cooldowns.active_rows(conn, now_ms, limit=5000)}
            open_rows = conn.execute(
                "SELECT key, half_open_at FROM breaker WHERE state = 'open' AND half_open_at > ? LIMIT 5000",
                (now_ms / 1000,),
            ).fetchall()
            return cooling, {str(key): float(at) for key, at in open_rows}

        self._mirror_cooldowns, self._mirror_breakers = await self.hot.read(read)
        local = self.local_cooldowns.pending(now_ms)
        self._note_cooldowns({row.key: row.until_ms for row in local}, now_ms)

    async def flush_local_cooldowns(self, *, budget_ms: int = HOT_BUSY_TIMEOUT_MS) -> int:
        """Write the cooldowns this worker kept in memory during a hot.db outage into hot.db (C7).

        Returns how many were written. Raises `SharedStateUnavailable` while hot.db still cannot be written (the
        cooldowns stay in memory and keep being honored by this worker). A fetch passes the short
        `HOT_SIDE_WRITE_BUDGET_MS` (the mirror loop shares them anyway); the loop waits the reservation's budget.
        """
        now_ms = self._now_ms()
        rows = self.local_cooldowns.pending(now_ms)
        if not rows:
            return 0
        written = await self.hot.write(
            functools.partial(cooldowns.write_local, rows=rows, now_ms=now_ms), busy_timeout_ms=budget_ms
        )
        self.local_cooldowns.forget(rows)
        log.info("upstream_local_cooldowns_shared", extra={"fields": {"written": written}})
        return int(written)

    async def run_mirror(self, stop: asyncio.Event, interval_s: float = 0.5) -> None:
        """Per-worker loop for the lifespan: keep the availability mirror fresh until `stop` is set, and share the
        cooldowns kept in memory during a hot.db outage as soon as hot.db can be written."""
        while not stop.is_set():
            with contextlib.suppress(SharedStateUnavailable):  # still unwritable: they stay in memory, honored here
                await self.flush_local_cooldowns()
            with contextlib.suppress(SharedStateUnavailable):  # keep the last mirror; fetch reads hot.db itself
                await self.refresh_mirror()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=interval_s)

    async def reset_state(self) -> dict[str, int]:
        """Clear every cooldown and breaker (parity row 34). Buckets are NEVER refilled (v1 bug B21)."""

        def clear(conn: sqlite3.Connection) -> dict[str, int]:
            return {"cooldowns": cooldowns.clear_all(conn), "breakers": breaker.reset_all(conn)}

        counts = await self.hot.write(clear)
        self._mirror_cooldowns.clear()
        self._mirror_breakers.clear()
        self.local_cooldowns = cooldowns.LocalCooldowns()
        return counts

    async def bucket_snapshot(self, limit: int = 500) -> list[buckets.BucketState]:
        """Bucket fill levels and next free slots for the Upstream page."""
        now_ms = self._now_ms()
        return await self.hot.read(lambda conn: buckets.bucket_states(conn, now_ms, limit))

    async def cooldown_snapshot(self, limit: int = 1000) -> list[CooldownRow]:
        """Active cooldowns for the Upstream page."""
        now_ms = self._now_ms()
        return await self.hot.read(lambda conn: cooldowns.active_rows(conn, now_ms, limit))

    async def run_adaptive_increase(self, now_s: float | None = None) -> list[RateChange]:
        """The hourly leader job body (plan 7.3 bounded upward probing); see `upstream/jobs.py`."""
        settings = self._ctx.settings
        return await adaptive_increase_job(
            self.adaptive,
            metrics_read=self._ctx.dbs.metrics.read,
            policy=AdaptivePolicy.from_settings(settings),
            limits=self._rules(),
            defaults=BucketDefaults.from_settings(settings),
            now_s=self.clock.now() if now_s is None else now_s,
        )

    async def breaker_snapshot(self, limit: int = 500) -> list[dict[str, Any]]:
        """Breakers that are open, half-open or counting failures."""
        now_s = self.clock.now()
        return await self.hot.read(lambda conn: breaker.snapshot(conn, now_s, limit))

    # --------------------------------------------------------------------------------------------- the fetch

    async def _guarded(
        self, req: Any, priority: Priority, purpose: str, lease: LeaseHook | None, trace: Trace, mode: Mode
    ) -> UpstreamResult:
        state = _RunState(lease=lease)
        try:
            result = await self._run(req, priority, purpose, trace, mode, state)
        except (asyncio.CancelledError, SingleFlightLost):
            raise
        except SharedStateUnavailable as exc:
            log.warning("upstream_degraded", extra={"fields": {"error": str(exc)[:200], "purpose": purpose}})
            if state.last_failure is not None:
                # Roblox already answered this request (a 5xx, a timeout, a 429 before a fallback) and only the
                # next attempt could not be paced: the caller gets Roblox's answer, never `degraded` (finding mp-8,
                # D4, the rule UP-COOLDOWN-LOST set for a 429).
                trace.note("hot.db unavailable for the next attempt: the last upstream answer goes back")
                result = state.last_failure
            else:
                result = self._failure(ReasonCode.DEGRADED, trace, state)
        except Exception:
            log.exception("upstream_fetch_failed", extra={"fields": {"purpose": purpose}})
            result = self._failure(ReasonCode.INTERNAL_ERROR, trace, state)
        trace.outcome = result.reason.value
        if mode == CALLER:  # calls by attempt for caller traffic and its refreshes (UP-429-AMPLIFY, UP-CSRF-LOOP)
            note_attempts(self._ctx, str(getattr(req, "template", "") or ""), trace)
        return result

    @staticmethod
    def _credential_row(rules: Any, target: str, method: str) -> Any:
        """The credential allowlist row for `target`, matched under the request's regex budget (plan 9.9).

        A match cut off by the timeout or a spent budget never grants the credential (fail closed, C1).
        """
        with regex_budget():
            return rules.credential_rule_for(target, method)

    @staticmethod
    def _routing_row(rules: Any, target: str) -> Any:
        """The routing rule for `target`, under the request's regex budget (a cut-off match means no rule)."""
        with regex_budget():
            return rules.routing_rule_for(target)

    def _normalize(self, req: Any) -> tuple[str, str, str, str, str]:
        host = str(req.host).strip().lower().rstrip(".")
        raw_path = str(req.path or "/")
        path = raw_path if raw_path.startswith("/") else "/" + raw_path
        template = str(getattr(req, "template", "") or "").strip() or template_for(host, path)
        if not template.startswith(host + "/") and template != host:
            template = f"{host}/{template.lstrip('/')}"
        query = list(getattr(req, "query", None) or ())
        url = f"https://{host}{path}" + (f"?{urlencode(query)}" if query else "")
        return host, path, template, url, f"{host}{path}"

    async def _run(
        self, req: Any, priority: Priority, purpose: str, trace: Trace, mode: Mode, state: _RunState
    ) -> UpstreamResult:
        cfg = self.config()
        rules = self._rules()
        host, path, template, url, target = self._normalize(req)
        method = str(req.method).upper()
        credential_rule: CredentialRule | None = None
        routing_row: Any = None
        with regex_budget():  # both lookups share one budget (and the request's, when the caller opened one)
            if mode == "internal_cred":
                # Roxy's own credential probe: the credential or nothing (never anonymous instead, never cached).
                credential_rule = CredentialRule(0, cache_private=True, identical_anonymous=False)
            elif mode == CALLER and rules is not None:
                row = self._credential_row(rules, target, method)
                credential_rule = CredentialRule.from_row(row) if row is not None else None
            if rules is not None and mode != "internal_cred":
                routing_row = self._routing_row(rules, target)
        call = _Call(
            req=req,
            method=method,
            host=host,
            path=path,
            template=template,
            url=url,
            rules_target=target,
            priority=priority,
            purpose=purpose,
            mode=mode,
            credential_rule=credential_rule,
            routing_mode=None if routing_row is None else str(routing_row.mode),
            budget_ms=deadlines.queue_budget_ms(self._ctx.settings, priority),
            cfg=cfg,
            rules=rules,
            trace=trace,
        )
        backoff = DecorrelatedJitter(cfg.backoff_base_ms, cfg.backoff_cap_ms, self._rng)
        while True:
            remaining = self._left_s(req)
            if remaining <= 0:
                return state.last_failure or self._failure(ReasonCode.DEADLINE, trace, state)
            if state.attempts >= cfg.max_attempts and state.last_failure is not None:
                return state.last_failure
            routed = await self._route(call, state)
            if isinstance(routed, UpstreamResult):
                return state.last_failure or routed
            outcome = await self._attempt(call, routed, state)
            if isinstance(outcome, UpstreamResult):
                return outcome
            kind, result, egress = outcome
            rule = policy_for(kind).retry
            if rule is RetryRule.REROUTE:
                state.attempts = max(0, state.attempts - 1)  # nothing reached Roblox: not an attempt
                state.exclude.add(egress)
                state.reroutes += 1
                if state.reroutes > MAX_REROUTES:
                    return result
                continue
            if rule is RetryRule.OPTIONAL_OTHER_ANONYMOUS:
                if not (cfg.fallback_on_429 and mode != "internal_cred" and state.attempts < cfg.max_attempts):
                    return result
                if egress is Egress.CREDENTIAL and not (credential_rule and credential_rule.identical_anonymous):
                    return result  # an allowlisted endpoint never falls back to anonymous (plan 6.9)
                if state.shared_unwritable:
                    return result  # the fallback could not be paced (C7): Roblox's 429 goes back as it is
                state.exclude.update({egress, Egress.CREDENTIAL})  # never onto the credential (plan 7.9)
                state.last_failure = result
                trace.note(f"429 on {egress.value}: one retry on another anonymous egress (fallback_on_429)")
                continue
            if rule is RetryRule.BACKOFF:
                state.last_failure = result
                if state.attempts >= cfg.max_attempts:
                    return result
                if state.shared_unwritable:
                    # hot.db refused this call's effects, so a retry could not take a bucket slot either (C7: never
                    # unpaced); waiting for the lock would only delay Roblox's answer (findings mp-7, mp-8).
                    trace.note(f"{kind.value} on {egress.value}: no retry while hot.db cannot be written")
                    return result
                delay_s = backoff.next_s()
                remaining = self._left_s(req)
                if not deadlines.can_retry_after(remaining, delay_s):
                    return result
                trace.note(f"{kind.value} on {egress.value}: retry after {delay_s * 1000:.0f} ms")
                await self._sleep(delay_s)
                continue
            return result  # pragma: no cover - every other rule ends inside _attempt

    # ------------------------------------------------------------------------------------------------ routing

    def _egress_enabled(self, egress: Egress, cfg: UpstreamConfig, purpose: str | None = None) -> tuple[bool, str]:
        if egress is Egress.DIRECT and not cfg.direct_enabled:
            return False, "direct_enabled is 0"
        if egress is Egress.ROTATOR and not cfg.rotator_enabled:
            return False, "rotator_enabled is 0"
        if egress is Egress.CREDENTIAL and not cfg.credential_enabled:
            return False, "credential_enabled is 0"
        return enabled(self._egress, egress, purpose)

    @staticmethod
    def _egress_purpose(call: _Call) -> str:
        """The purpose the egress sees: Roxy's own credential calls are probes; everything else keeps its name."""
        return PURPOSE_CREDENTIAL_PROBE if call.mode == "internal_cred" else call.purpose

    @staticmethod
    def _ckeys(host: str, template: str, egress: Egress) -> tuple[str, ...]:
        return cooldowns.keys_for(host, template, egress)

    def _specs(self, call: _Call, egress: Egress) -> tuple[BucketSpec, ...]:
        return buckets.specs_for(
            egress,
            call.host,
            call.template,
            call.cfg.defaults,
            call.rules,
            credential_probe=call.mode == "internal_cred",
        )

    def _candidates(self, call: _Call, state: _RunState) -> list[Egress]:
        if call.mode == "internal_cred":
            return [Egress.CREDENTIAL]
        pool = [Egress.DIRECT, Egress.ROTATOR]
        if call.credential_rule is not None and call.method in routing.CREDENTIAL_METHODS:
            pool.insert(0, Egress.CREDENTIAL)
        return [egress for egress in pool if egress not in state.exclude]

    @staticmethod
    def _read_snapshot(
        conn: sqlite3.Connection, ckeys: Sequence[str], bkeys: Sequence[str], tat_keys: Sequence[str], now_ms: int
    ) -> _Snapshot:
        rows = breaker.load(conn, bkeys)
        probes: dict[str, float] = {}
        for key, row in rows.items():
            if breaker.effective_state(row, now_ms / 1000) is breaker.BreakerState.HALF_OPEN:
                probes[key] = breaker.probe_lease_remaining_s(conn, key, now_ms)
        return _Snapshot(
            cooldowns=cooldowns.read_active(conn, ckeys, now_ms),
            breakers=rows,
            probe_leases=probes,
            tats=buckets.read_tats(conn, tat_keys),
        )

    def _merge_local(self, rows: dict[str, CooldownRow], keys: Sequence[str], now_ms: int) -> None:
        """Add this worker's in-memory cooldowns (C7) to `rows` read from hot.db; the later end wins."""
        for key, row in self.local_cooldowns.active(keys, now_ms).items():
            shared = rows.get(key)
            if shared is None or shared.until_ms < row.until_ms:
                rows[key] = row

    def _availability_of(
        self,
        call: _Call,
        egress: Egress,
        specs: Sequence[BucketSpec],
        snap: _Snapshot,
        now_ms: int,
    ) -> EgressAvailability:
        on, why = self._egress_enabled(egress, call.cfg, self._egress_purpose(call))
        cooling = [
            snap.cooldowns[key] for key in self._ckeys(call.host, call.template, egress) if key in snap.cooldowns
        ]
        longest = max(cooling, key=lambda row: row.until_ms, default=None)
        breaker_wait = 0.0
        for key in breaker.breaker_keys(call.host, call.template, egress):
            admission = breaker.admission(snap.breakers.get(key), now_ms / 1000)
            if not admission.allowed:
                breaker_wait = max(breaker_wait, admission.retry_in_s)
            elif admission.needs_probe_lease and snap.probe_leases.get(key, 0.0) > 0:
                breaker_wait = max(breaker_wait, snap.probe_leases[key])  # another worker is probing right now
        slot, _binding = buckets.earliest_slot_ms(snap.tats, specs, now_ms)
        own = specs[1]
        return EgressAvailability(
            egress=egress,
            enabled=on,
            disabled_reason=why,
            cooldown_s=0.0 if longest is None else longest.remaining_s(now_ms),
            cooldown_source="" if longest is None else longest.source,
            breaker_wait_s=breaker_wait,
            bucket_wait_s=max(0.0, (slot - now_ms) / 1000),
            fill=buckets.gcra_fill(snap.tats.get(own.key, 0.0), own, now_ms),
        )

    def _max_wait_ms(self, call: _Call, state: _RunState) -> float:
        budget = max(0.0, call.budget_ms - state.queue_wait_ms)
        left = self._left_s(call.req) * 1000 - MIN_CALL_TIME_MS
        return max(0.0, min(budget, left))

    async def _route(self, call: _Call, state: _RunState) -> _Routed | UpstreamResult:
        """Pick an egress and reserve its slot (plan 7.2 and 7.3). Retries a few times if the snapshot raced."""
        last_denial: tuple[float, str] | None = None
        if len(self.local_cooldowns):
            # Cooldowns kept in memory during a hot.db outage: share them first if hot.db takes writes again (a
            # short budget: they are honored here either way, and the mirror loop keeps trying).
            with contextlib.suppress(SharedStateUnavailable):
                await self.flush_local_cooldowns(budget_ms=HOT_SIDE_WRITE_BUDGET_MS)
        for _round in range(MAX_ROUTE_ROUNDS):
            candidates = self._candidates(call, state)
            specs = {egress: self._specs(call, egress) for egress in candidates}
            ckeys = [key for egress in candidates for key in self._ckeys(call.host, call.template, egress)]
            bkeys = [key for egress in candidates for key in breaker.breaker_keys(call.host, call.template, egress)]
            tat_keys = [spec.key for egress in candidates for spec in specs[egress]]
            now_ms = self._now_ms()
            snap = await self.hot.read(
                functools.partial(self._read_snapshot, ckeys=ckeys, bkeys=bkeys, tat_keys=tat_keys, now_ms=now_ms)
            )
            self._merge_local(snap.cooldowns, ckeys, now_ms)
            self._note_cooldowns({key: row.until_ms for key, row in snap.cooldowns.items()}, now_ms)
            states = {egress: self._availability_of(call, egress, specs[egress], snap, now_ms) for egress in candidates}
            max_wait_ms = self._max_wait_ms(call, state)
            route = await self._route_request(call, state, max_wait_ms)
            decision = routing.decide(route, states, self._rng)
            if decision.egress is None:
                if decision.reason is ReasonCode.EGRESS_DISABLED and call.mode == CALLER:
                    self._alert_all_unavailable(call, states)
                return self._refusal(decision, call, state)
            for egress in decision.candidates:
                routed = await self._reserve(call, state, egress, specs[egress], max_wait_ms, snap)
                if isinstance(routed, _Routed):
                    if routed.egress is not decision.egress:
                        call.trace.note(f"{decision.egress.value} raced, used {routed.egress.value}")
                    call.trace.bucket_key = routed.grant.binding_key
                    return routed
                last_denial = routed
        retry_ms, why = last_denial if last_denial is not None else (1000.0, "busy")
        reason = ReasonCode.UPSTREAM_COOLDOWN if why in {"cooldown", "breaker"} else ReasonCode.UPSTREAM_BUSY
        return self._failure(reason, call.trace, state, soonest_s=retry_ms / 1000, cooldown_s=retry_ms / 1000)

    async def _route_request(self, call: _Call, state: _RunState, max_wait_ms: float) -> RouteRequest:
        cfg = call.cfg
        usable = rejected = False
        cooldown_s = 0.0
        if call.credential_rule is not None and Egress.CREDENTIAL not in state.exclude:
            if call.mode == "internal_cred":
                on, _ = self._egress_enabled(Egress.CREDENTIAL, cfg, PURPOSE_CREDENTIAL_PROBE)
                remaining = await call_optional(
                    getattr(self._egress, "credential", None), "cooldown_remaining", default=0.0
                )
                cooldown_s = float(remaining or 0.0)
                usable = on and cooldown_s <= 0
            else:
                view = await credential_view(self._egress, setting_enabled=cfg.credential_enabled)
                usable, rejected, cooldown_s = view.usable, view.rejected, view.cooldown_s
        return RouteRequest(
            method=call.method,
            credential_rule=call.credential_rule,
            credential_usable=usable,
            credential_rejected=rejected,
            credential_cooldown_s=cooldown_s,
            routing_mode=call.routing_mode,
            direct_weight=cfg.direct_weight,
            rotator_weight=cfg.rotator_weight,
            shift_threshold_pct=cfg.shift_threshold_pct,
            max_wait_s=max_wait_ms / 1000,
            exclude=frozenset(state.exclude),
        )

    def _guards(
        self, call: _Call, egress: Egress, holder: str, probes: list[str], slots: list[str]
    ) -> list[buckets.Guard]:
        cfg = call.cfg
        ckeys = self._ckeys(call.host, call.template, egress)
        bkeys = breaker.breaker_keys(call.host, call.template, egress)
        # Copied here, on the event loop: the guards run on the database writer thread (C7 in-memory cooldowns).
        local = dict(self.local_cooldowns.active(ckeys, self._now_ms()))

        def cooldown_guard(conn: sqlite3.Connection, now_ms: int) -> GuardDenial | None:
            active = cooldowns.read_active(conn, ckeys, now_ms)
            active.update({key: row for key, row in local.items() if row.active(now_ms) and key not in active})
            if not active:
                return None
            row = max(active.values(), key=lambda item: item.until_ms)
            return GuardDenial("cooldown", row.key, row.until_ms - now_ms, row.source)

        def breaker_guard(conn: sqlite3.Connection, now_ms: int) -> GuardDenial | None:
            probes.clear()
            rows = breaker.load(conn, bkeys)
            for key in bkeys:
                admission = breaker.admission(rows.get(key), now_ms / 1000)
                if not admission.allowed:
                    return GuardDenial("breaker", key, admission.retry_in_s * 1000, "breaker")
                if admission.needs_probe_lease:
                    if not breaker.try_acquire_probe(conn, key, holder, now_ms, cfg.breaker.probe_ttl_s):
                        wait = breaker.probe_lease_remaining_s(conn, key, now_ms)
                        return GuardDenial("breaker", key, max(1000.0, wait * 1000), "breaker")
                    probes.append(key)
            return None

        guards: list[buckets.Guard] = [cooldown_guard, breaker_guard]
        if cfg.aimd.enabled:
            key = aimd.aimd_key(call.host, egress)

            def aimd_guard(conn: sqlite3.Connection, now_ms: int) -> GuardDenial | None:
                slots.clear()
                slot = aimd.acquire(conn, key, holder, cfg.aimd, now_ms)
                if slot is None:
                    return GuardDenial("aimd", key, aimd.RETRY_WHEN_FULL_MS)
                slots.append(slot)
                return None

            guards.append(aimd_guard)
        return guards

    async def _reserve(
        self,
        call: _Call,
        state: _RunState,
        egress: Egress,
        specs: tuple[BucketSpec, ...],
        max_wait_ms: float,
        snap: _Snapshot,
    ) -> _Routed | tuple[float, str]:
        holder = self.new_holder()
        probes: list[str] = []
        slots: list[str] = []
        background = buckets.BACKGROUND_GLOBAL_LIMIT if call.priority is Priority.BACKGROUND else None

        def routed_for(grant: Grant) -> _Routed:
            # `probes` and `slots` were filled by the guards inside the transaction that produced `grant`.
            return _Routed(
                egress=egress,
                specs=specs,
                grant=grant,
                holder=holder,
                probe_keys=tuple(probes),
                aimd_key=aimd.aimd_key(call.host, egress) if slots else None,
                aimd_slot=slots[0] if slots else None,
                breakers_seen=dict(snap.breakers),
            )

        outcome = await self._reserve_shielded(
            specs,
            max_wait_ms=max_wait_ms,
            background_global_limit=background,
            lease_hook=state.lease,
            guards=self._guards(call, egress, holder, probes, slots),
            routed_for=routed_for,
        )
        note_reservation(self._ctx, specs, outcome)  # bucket fill and rejection history (UP-BUCKET-TUNE, row 77)
        if outcome.lease_lost:
            raise SingleFlightLost(call.template)
        if outcome.grant is None:
            if outcome.guard is not None:
                if outcome.guard.reason == "cooldown":
                    call.trace.cooldown_source = outcome.guard.source
                return outcome.guard.retry_after_ms, outcome.guard.reason
            denial = outcome.denial
            return (denial.retry_after_ms, denial.reason) if denial is not None else (1000.0, "busy")
        state.lease = None  # the single-flight lease is in: never insert it again for this fetch
        return routed_for(outcome.grant)

    async def _reserve_shielded(
        self,
        specs: tuple[BucketSpec, ...],
        *,
        max_wait_ms: float,
        guards: Sequence[buckets.Guard],
        routed_for: Callable[[Grant], _Routed],
        background_global_limit: float | None = None,
        lease_hook: LeaseHook | None = None,
    ) -> ReserveOutcome:
        """`buckets.reserve` that never keeps what it took when the caller is canceled while it runs (finding mp-9).

        `Database.write` lets a job that already started run to its COMMIT when the waiting coroutine is canceled
        (a write is never half applied). A request canceled during its reservation (the deadline middleware's
        `asyncio.timeout`, a shutdown) therefore used to keep its bucket slots, a half-open breaker's fleet-wide
        probe lease, an AIMD slot and the single-flight lease, for a call it never made (plan 7.3: a canceled
        reservation is refunded). The write runs as its own task: on cancellation this waits for it (at most its
        `HOT_BUSY_TIMEOUT_MS` budget, a second cancellation included), gives back whatever it granted, and only
        then lets the cancellation go on, so the single-flight layer also sees the final `granted` state of its
        lease hook and abandons that lease (`singleflight._drive_hooked`).
        """
        task = asyncio.ensure_future(
            buckets.reserve(
                self.hot,
                specs,
                now_ms=self._now_ms,
                max_wait_ms=max_wait_ms,
                background_global_limit=background_global_limit,
                lease_hook=lease_hook,
                guards=guards,
                busy_timeout_ms=HOT_BUSY_TIMEOUT_MS,
            )
        )
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            while not task.done():
                try:
                    await asyncio.wait({task})
                except asyncio.CancelledError:
                    continue  # canceled again: the bookkeeping still comes first (bounded by the write budget)
            if not task.cancelled() and task.exception() is None:
                grant = task.result().grant
                if grant is not None:
                    await self._release_shielded(routed_for(grant), refund=True)
            raise

    async def _release(self, routed: _Routed, *, refund: bool) -> None:
        """Give back what a reservation holds when no call will use it (refund, probe lease, AIMD slot).

        Budgeted and never raising (finding mp-7): if hot.db stays locked, the slot simply stays taken until its
        time passes and a probe lease or AIMD slot expires on its own TTL, which is what C7 allows; the request
        must not wait out SQLite's 5 s busy timeout for bookkeeping.
        """
        aimd_policy = self.config().aimd

        def undo(conn: sqlite3.Connection) -> None:
            now_ms = self._now_ms()
            if refund:
                buckets.refund_in(conn, routed.grant, now_ms)
            for key in routed.probe_keys:
                breaker.release_probe(conn, key, routed.holder)
            if routed.aimd_slot is not None and routed.aimd_key is not None:
                aimd.release(conn, routed.aimd_key, routed.aimd_slot, routed.holder, None, aimd_policy, now_ms)

        try:
            await self.hot.write(undo, busy_timeout_ms=HOT_SIDE_WRITE_BUDGET_MS)
        except SharedStateUnavailable as exc:
            log.warning("upstream_release_not_shared", extra={"fields": {"error": str(exc)[:200]}})

    async def _release_shielded(self, routed: _Routed, *, refund: bool) -> None:
        """`_release` that completes even while the calling task is being canceled."""
        task = asyncio.ensure_future(self._release(routed, refund=refund))
        self._background.add(task)
        task.add_done_callback(self._background.discard)
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await asyncio.shield(task)

    # ------------------------------------------------------------------------------------------------ attempts

    async def _wait_for_slot(self, call: _Call, routed: _Routed, state: _RunState) -> str:
        """Sleep until the reserved slot. Returns "ok", "overflow", "evicted" or "blocked"."""
        wait_ms = routed.grant.slot_ms - self._now_ms()
        if wait_ms <= 1:
            return "ok"
        ticket = self.queue.enter(call.priority)
        if ticket is None:
            return "overflow"
        started = self._mono()
        try:
            arrived = await self.queue.wait(ticket, wait_ms / 1000, self._sleep)
        finally:
            state.queue_wait_ms += (self._mono() - started) * 1000
            call.trace.queue_wait_ms = state.queue_wait_ms
        if not arrived:
            return "evicted"
        # While this request slept, another worker may have opened a cooldown or a breaker: honor it.
        ckeys = self._ckeys(call.host, call.template, routed.egress)
        bkeys = [k for k in breaker.breaker_keys(call.host, call.template, routed.egress) if k not in routed.probe_keys]
        now_ms = self._now_ms()
        if self.local_cooldowns.active(ckeys, now_ms):
            return "blocked"  # a 429 seen by this worker during a hot.db outage (C7)

        def recheck(conn: sqlite3.Connection) -> bool:
            if cooldowns.read_active(conn, ckeys, now_ms):
                return True
            rows = breaker.load(conn, bkeys)
            return any(not breaker.admission(rows.get(key), now_ms / 1000).allowed for key in bkeys)

        return "blocked" if await self.hot.read(recheck) else "ok"

    async def _attempt(
        self, call: _Call, routed: _Routed, state: _RunState
    ) -> UpstreamResult | tuple[AttemptKind, UpstreamResult, Egress]:
        """One routed attempt: wait, send (with the CSRF retry and redirects), record, classify."""
        sent = False
        try:
            waited = await self._wait_for_slot(call, routed, state)
            if waited != "ok":
                await self._release(routed, refund=True)
                if waited == "blocked":
                    state.reroutes += 1
                    if state.reroutes > MAX_REROUTES:
                        return self._failure(ReasonCode.UPSTREAM_COOLDOWN, call.trace, state, soonest_s=1.0)
                    return await self._reroute_after_block(call, state)
                soonest = max(0.0, (routed.grant.slot_ms - self._now_ms()) / 1000)
                return self._failure(ReasonCode.QUEUE_OVERFLOW, call.trace, state, soonest_s=soonest)
            sent = True
            return await self._exchange_and_record(call, routed, state)
        except asyncio.CancelledError:
            await self._release_shielded(routed, refund=not sent)
            raise
        except BaseException:
            if not sent:
                await self._release_shielded(routed, refund=True)
            raise

    async def _reroute_after_block(
        self, call: _Call, state: _RunState
    ) -> UpstreamResult | tuple[AttemptKind, UpstreamResult, Egress]:
        routed = await self._route(call, state)
        if isinstance(routed, UpstreamResult):
            return state.last_failure or routed
        return await self._attempt(call, routed, state)

    def _outbound_headers(self, call: _Call) -> dict[str, str]:
        """The extra headers upstream adds (plan 9.13): the body's Content-Type, a forwarded `Accept` when it is one
        of the safe values. The egress adds its own API-shaped profile (Accept-Language, User-Agent) itself."""
        headers: dict[str, str] = {}
        caller_headers = getattr(call.req, "headers", None) or {}
        accept = str(caller_headers.get("accept", "")).strip().lower()
        if accept in FORWARDED_ACCEPT:
            headers["Accept"] = accept
        body = getattr(call.req, "body", b"") or b""
        if body:
            headers["Content-Type"] = str(getattr(call.req, "content_type", None) or "application/json")
        return headers

    @staticmethod
    def _identity(call: _Call) -> str:
        """The User-Agent experiment key (DESIGN 11.4 egress `identity`): the cache key id, else the template."""
        key = getattr(call.req, "cache_key", None)
        key_id = getattr(key, "id", None)
        return str(key_id) if key_id else call.template

    async def _send(
        self,
        call: _Call,
        egress: Egress,
        url: str,
        method: str,
        headers: dict[str, str],
        body: bytes | None,
        session_id: str | None,
        state: _RunState,
        *,
        csrf_retry: bool = False,
        hop: int = 0,
    ) -> _Exchange:
        remaining = self._left_s(call.req)
        out = OutboundRequest(
            method=method,
            url=url,
            headers=dict(headers),
            content=body or None,
            timeout=deadlines.attempt_timeout(self._ctx.settings, remaining),
            purpose=self._egress_purpose(call),
            session_id=session_id,
            follow_redirects=False,  # 3xx are followed here, so every hop takes a bucket slot
            identity=session_id if egress is Egress.ROTATOR else self._identity(call),
        )
        started = self._mono()
        port = self._egress
        try:
            if port is None:
                raise EgressDisabled("no egress clients")
            response = await port.send(egress, out)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            kind = classify_exception(exc)
            elapsed = (self._mono() - started) * 1000
            if kind is None:
                raise
            if egress is Egress.CREDENTIAL and kind is AttemptKind.EGRESS_DISABLED:
                retry_after = getattr(exc, "retry_after_s", None)
                state.credential_refusal = (
                    str(getattr(exc, "why", "") or "unavailable"),
                    int(retry_after) if isinstance(retry_after, int | float) else None,
                )
            if policy_for(kind).sent:
                state.calls += 1
                state.upstream_ms += elapsed
            call.trace.record_call(
                egress=egress.value,
                kind=kind.value,
                status=None,
                duration_ms=elapsed,
                error=f"{type(exc).__name__}: {exc}",
                csrf_retry=csrf_retry,
                redirect_hop=hop,
            )
            return _Exchange(kind, error=type(exc).__name__, session_id=session_id)
        elapsed = float(getattr(response, "elapsed_ms", 0.0) or (self._mono() - started) * 1000)
        status = int(response.status)
        lowered = {str(k).lower(): str(v) for k, v in response.headers.items()}
        kind = classify_response(status, lowered, csrf_retried=csrf_retry)
        state.calls += 1
        state.upstream_ms += elapsed
        state.bytes_in += int(getattr(response, "bytes_in", 0) or 0)
        state.bytes_out += int(getattr(response, "bytes_out", 0) or 0)
        call.trace.record_call(
            egress=egress.value,
            kind=kind.value,
            status=status,
            duration_ms=elapsed,
            headers=lowered,
            csrf_retry=csrf_retry,
            redirect_hop=hop,
            queue_wait_ms=state.queue_wait_ms,
        )
        returned_session = getattr(response, "session_id", None)
        return _Exchange(
            kind,
            status=status,
            headers=lowered,
            body=bytes(response.body or b""),
            session_id=str(returned_session) if returned_session else session_id,
        )

    async def _extra_slot(self, call: _Call, routed: _Routed, state: _RunState, host: str) -> bool:
        """Reserve (and wait for) one more slot on the same egress: a CSRF retry or a redirect hop is a real call."""
        specs = buckets.specs_for(
            routed.egress,
            host,
            call.template,
            call.cfg.defaults,
            call.rules,
            credential_probe=call.mode == "internal_cred",
        )
        holder = self.new_holder()
        try:
            outcome = await self._reserve_shielded(
                specs,
                max_wait_ms=self._max_wait_ms(call, state),
                guards=self._guards(call, routed.egress, holder, [], [])[:1],  # cooldowns only: the call is under way
                routed_for=lambda grant: _Routed(routed.egress, specs, grant, holder),
            )
        except SharedStateUnavailable:
            # No slot can be taken (C7: never unpaced): this extra call is not made, and Roblox's answer so far
            # (its 3xx, or the CSRF challenge) is what the caller gets, never `degraded`.
            call.trace.note("hot.db unavailable: no slot for the extra call")
            return False
        if outcome.grant is None:
            return False
        extra = _Routed(routed.egress, specs, outcome.grant, holder)
        try:
            waited = await self._wait_for_slot(call, extra, state)
        except BaseException:
            await self._release_shielded(extra, refund=True)
            raise
        if waited != "ok":
            await self._release(extra, refund=True)
            return False
        return True

    def _redirect_url(self, call: _Call, egress: Egress, current_url: str, exchange: _Exchange) -> str | None:
        """Where a 3xx may be followed: GET or HEAD only, and only a URL a caller could have asked for directly.

        Every hop is re-validated with the caller path's own checks (`proxy/validate.py parse_redirect`, which
        resolves the Location and runs `parse_upstream_url`; plan 9.10 "redirects are re-validated"): https on port
        443, an allowed Roblox host, and a path without encoded slashes, `%`, `?` or `#` in a segment and without
        `.` or `..` segments (v1 bug B4). The credential allowlist is matched on the hop's decoded, normalized
        target, exactly as a caller path is, and the URL followed is the one rebuilt from that parse, so what is
        fetched is what was checked (finding cred-3: the raw, still encoded path let a `*` or `(?:/.*)?` grant
        `.../%2E%2E/%2E%2E/v2/secret`, which a server that decodes before removing dot segments serves as an
        endpoint no row names). None means "do not follow", never an exception: a Location that does not even
        parse (`//[`) is the `unsafe_url` problem of `parse_redirect` (ingress review).
        """
        location = exchange.headers.get("location", "").strip()
        if not location or call.method not in routing.CREDENTIAL_METHODS:
            return None
        cfg = call.cfg
        parsed = parse_redirect(
            current_url,
            location,
            call.method,
            allowed_hosts=cfg.allowed_hosts,
            strict_host_allowlist=cfg.strict_hosts,
            max_url_length=cfg.max_url_length,
        )
        if not parsed.ok:
            return None
        target = parsed.upstream_url
        if egress is Egress.CREDENTIAL:
            new_target = parsed.target  # host plus the decoded, normalized path (what every rule matches)
            if call.mode != "internal_cred" and (
                call.rules is None or self._credential_row(call.rules, new_target, call.method) is None
            ):
                return None  # never carry the credential off the allowlist (plan C2 item 7)
            if call.mode == "internal_cred" and new_target != call.rules_target:
                return None
        return target

    async def _exchange_and_record(
        self, call: _Call, routed: _Routed, state: _RunState
    ) -> UpstreamResult | tuple[AttemptKind, UpstreamResult, Egress]:
        egress = routed.egress
        call.trace.start_attempt(egress.value)
        state.attempts += 1
        rotator = getattr(self._egress, "rotator", None)
        session_id = None
        if egress is Egress.ROTATOR:
            found = await call_optional(rotator, "session_for", call.req)
            session_id = str(found) if found else None
        identity = csrf.egress_identity(egress, session_id)
        call.trace.egress_identity = (
            f"rotator:{short_hash(session_id)}" if egress is Egress.ROTATOR and session_id else egress.value
        )
        headers = self._outbound_headers(call)
        body = getattr(call.req, "body", b"") or None
        if csrf.needs_token(call.method):
            now_s = self.clock.now()
            cached = await self.hot.read(lambda conn: csrf.read_token(conn, identity, now_s))
            if cached:
                headers["x-csrf-token"] = cached
        url = call.url
        exchange = await self._send(call, egress, url, call.method, headers, body, session_id, state)
        csrf_retried = False
        hops = 0
        while True:
            if exchange.kind is AttemptKind.CSRF_CHALLENGE and not csrf_retried:
                token = csrf.token_from(exchange.headers)
                if token is None:
                    exchange.kind = AttemptKind.DEFINITIVE
                    break
                ttl = call.cfg.csrf_ttl_s
                now_s = self.clock.now()
                await self._side_write(
                    functools.partial(csrf.store_token, identity=identity, token=token, ttl_s=ttl, now_s=now_s),
                    call,
                    "CSRF token not shared",
                )
                if not await self._extra_slot(call, routed, state, call.host):
                    await self._after_call(call, routed, exchange, state, AttemptKind.CSRF_CHALLENGE)
                    return self._failure(ReasonCode.UPSTREAM_BUSY, call.trace, state, soonest_s=1.0)
                headers["x-csrf-token"] = token
                csrf_retried = True
                self._record_retry(call, egress, exchange.status)  # row 117, like v1's log_retry(403, ...)
                exchange = await self._send(
                    call, egress, url, call.method, headers, body, exchange.session_id, state, csrf_retry=True
                )
                if exchange.status == 403 and has_csrf_token(exchange.headers):
                    await self._side_write(
                        functools.partial(csrf.forget_token, identity=identity), call, "CSRF token not forgotten"
                    )
                continue
            if exchange.kind is AttemptKind.REDIRECT and hops < MAX_REDIRECT_HOPS:
                target = self._redirect_url(call, egress, url, exchange)
                if target is None:
                    # Not followed (malformed, not an allowed Roblox host, off the allowlist): Roblox's own 3xx
                    # answer goes back like any other answer, after the normal bookkeeping below.
                    call.trace.note("redirect not followed")
                    break
                new_host = (urlsplit(target).hostname or call.host).lower()
                if not await self._extra_slot(call, routed, state, new_host):
                    break
                hops += 1
                url = target
                exchange = await self._send(
                    call, egress, url, call.method, headers, None, exchange.session_id, state, hop=hops
                )
                continue
            break
        if not policy_for(exchange.kind).sent and not csrf_retried and hops == 0:
            # Nothing reached Roblox (egress disabled, guard refusal): the slot was not used, give it back.
            await self._side_write(
                functools.partial(buckets.refund_in, grant=routed.grant, now_ms=self._now_ms()),
                call,
                "unused slot not refunded",
            )
        effects = await self._after_call(call, routed, exchange, state, exchange.kind)
        result = self._result(call, routed, exchange, effects, state)
        kind = exchange.kind
        retry = policy_for(kind).retry
        if retry in (RetryRule.NONE, RetryRule.FOLLOW_REDIRECT, RetryRule.CSRF_ONCE_SAME_EGRESS):
            return result
        return kind, result, egress

    async def _after_call(
        self, call: _Call, routed: _Routed, exchange: _Exchange, state: _RunState, kind: AttemptKind
    ) -> CallEffects | None:
        """Shared-state side effects (one hot.db write at most) and the side effects outside the database."""
        cfg = call.cfg
        now_s = self.clock.now()
        retry_after = cooldowns.parse_retry_after(exchange.headers.get("retry-after"), now_s)
        limits = cooldowns.parse_ratelimit_headers(exchange.headers, now_s) if exchange.headers else None
        facts = CallFacts(
            egress=routed.egress,
            host=call.host,
            template=call.template,
            kind=kind,
            status=exchange.status,
            retry_after_s=retry_after,
            ratelimit=limits,
            exit_id=exchange.session_id,
            probe_keys=routed.probe_keys,
            holder=routed.holder,
            aimd_key=routed.aimd_key,
            aimd_slot=routed.aimd_slot,
        )
        effects: CallEffects | None = None
        if should_record(facts, routed.breakers_seen, now_s):
            config = EffectsConfig(cooldown=cfg.cooldown, breaker=cfg.breaker, aimd=cfg.aimd)
            try:
                # Budgeted (finding mp-7): Roblox already answered, so the caller (and every follower of its flight)
                # never waits out SQLite's 5 s busy timeout for this bookkeeping; the fallback is just below.
                effects = await self.hot.write(
                    lambda conn: apply_call_outcome(conn, facts, config, self._now_ms(), self._rng),
                    busy_timeout_ms=HOT_SIDE_WRITE_BUDGET_MS,
                )
            except SharedStateUnavailable as exc:
                # C7: Roblox answered, but hot.db cannot be written. Breaker counts are lost and a held probe or
                # AIMD lease expires on its own; a 429's cooldown is NOT lost (finding UP-COOLDOWN-LOST), and no
                # retry is made, since it could not be paced either (finding mp-8).
                log.warning(
                    "upstream_effects_not_shared",
                    extra={"fields": {"error": str(exc)[:200], "kind": kind.value, "egress": routed.egress.value}},
                )
                state.shared_unwritable = True
                effects = self._local_effects(facts, cfg)
                await self._side_effects_outside(call, routed, exchange, kind, retry_after, effects)
                return effects
            now_ms = self._now_ms()
            seconds = effects.cooldown_s or 0.0
            self._note_cooldowns({key: now_ms + int(seconds * 1000) for key in effects.cooldown_keys}, now_ms)
            for transition in effects.transitions:
                self._record_event(
                    "breaker_" + transition.to_state.value,
                    "warning" if transition.to_state is not breaker.BreakerState.CLOSED else "info",
                    ReasonCode.UPSTREAM_COOLDOWN.value,
                    {
                        "key": transition.key,
                        "from": transition.from_state.value,
                        "reason": transition.reason,
                        "open_s": transition.open_s,
                    },
                )
            if effects.attribution is not None and effects.attribution.kind.value != "endpoint":
                self._record_event(
                    "upstream_429_attribution",
                    "warning",
                    ReasonCode.UPSTREAM_COOLDOWN.value,
                    effects.attribution.evidence() | {"egress": routed.egress.value, "template": call.template},
                )
        await self._side_effects_outside(call, routed, exchange, kind, retry_after, effects)
        return effects

    async def _side_write(self, fn: Callable[[sqlite3.Connection], Any], call: _Call, what: str) -> None:
        """A request-path hot.db write with a fallback (a CSRF token, a refund): budgeted, never raising.

        If hot.db stays locked past `HOT_SIDE_WRITE_BUDGET_MS`, the write is skipped (a token is not shared, a slot
        expires on its own) and the request goes on (finding mp-7).
        """
        try:
            await self.hot.write(fn, busy_timeout_ms=HOT_SIDE_WRITE_BUDGET_MS)
        except SharedStateUnavailable as exc:
            call.trace.note(f"{what} (hot.db unavailable)")
            log.warning("upstream_side_write_skipped", extra={"fields": {"what": what, "error": str(exc)[:200]}})

    def _local_effects(self, facts: CallFacts, cfg: UpstreamConfig) -> CallEffects | None:
        """The cooldown hot.db could not record, kept in this worker's memory (plan 7.5 and C7); None if none.

        A 429: same length rule as the shared path (Retry-After, x-ratelimit-reset, else the default), as a first
        429 (the streak lives in hot.db). Direct and credential 429s cool the endpoint down for that egress, and a
        credential 429 also the credential itself; a rotator 429 only rotates its session (the distinct-exit rule
        needs the shared exit records, plan 7.5). Host escalation and adaptive rates wait for hot.db.
        Any other answer that says `x-ratelimit-remaining: 0` cools the endpoint down until the reset, as
        `effects.apply_call_outcome` would have.
        """
        now_ms = self._now_ms()
        limit = facts.ratelimit
        if facts.kind is not AttemptKind.RATE_LIMITED:
            if facts.kind not in SUCCESS_LIKE or limit is None or not limit.exhausted or limit.reset_s is None:
                return None
            key = cooldowns.endpoint_key(facts.template, facts.egress)
            row = self.local_cooldowns.remember(
                key, cfg.cooldown.clamp(limit.reset_s), cooldowns.CooldownSource.RATELIMIT_RESET, now_ms
            )
            self._note_cooldowns({row.key: row.until_ms}, now_ms)
            return CallEffects(cooldown_s=row.remaining_s(now_ms), cooldown_source=row.source, cooldown_keys=[key])
        if facts.egress not in (Egress.DIRECT, Egress.CREDENTIAL):
            return None
        seconds, source = cooldowns.cooldown_duration(facts.retry_after_s, facts.ratelimit, 1, cfg.cooldown, self._rng)
        rows = [
            self.local_cooldowns.remember(cooldowns.endpoint_key(facts.template, facts.egress), seconds, source, now_ms)
        ]
        if facts.egress is Egress.CREDENTIAL:
            credential_s, credential_source = cooldowns.cooldown_duration(
                facts.retry_after_s, facts.ratelimit, 1, cfg.cooldown, self._rng, credential=True
            )
            rows.append(
                self.local_cooldowns.remember(cooldowns.CREDENTIAL_KEY, credential_s, credential_source, now_ms)
            )
        self._note_cooldowns({row.key: row.until_ms for row in rows}, now_ms)
        longest = max(rows, key=lambda row: row.until_ms)
        return CallEffects(
            cooldown_s=longest.remaining_s(now_ms),
            cooldown_source=longest.source,
            cooldown_keys=[row.key for row in rows],
        )

    async def _side_effects_outside(
        self,
        call: _Call,
        routed: _Routed,
        exchange: _Exchange,
        kind: AttemptKind,
        retry_after: float | None,
        effects: CallEffects | None,
    ) -> None:
        egress = routed.egress
        port = self._egress
        if kind is AttemptKind.RATE_LIMITED:
            self._record_429(call, egress, exchange, retry_after)
            if egress is Egress.ROTATOR and exchange.session_id:
                with contextlib.suppress(Exception):
                    await call_optional(getattr(port, "rotator", None), "rotate", exchange.session_id, "429")
            if effects is not None and effects.counted_429 and effects.attribution is not None:
                try:
                    await self.adaptive.on_rate_limited(
                        attribution=effects.attribution,
                        egress=egress,
                        first_in_episode=effects.first_in_episode,
                        policy=call.cfg.adaptive,
                        limits=call.rules,
                        defaults=call.cfg.defaults,
                        now_s=self.clock.now(),
                    )
                except Exception:  # an audit or control.db hiccup must not fail the caller's answer
                    log.warning("adaptive_decrease_failed", exc_info=True)
            if egress is Egress.CREDENTIAL and effects is not None:
                seconds = float(effects.cooldown_s or call.cfg.cooldown.credential_default_s)
                source = effects.cooldown_source or "default"
                with contextlib.suppress(Exception):
                    await call_optional(getattr(port, "credential", None), "set_cooldown", seconds, source)
        elif kind in (AttemptKind.TIMEOUT, AttemptKind.CONNECT_ERROR) and egress is Egress.ROTATOR:
            if exchange.session_id:
                with contextlib.suppress(Exception):
                    await call_optional(getattr(port, "rotator", None), "rotate", exchange.session_id, kind.value)
        elif kind is AttemptKind.DEFINITIVE and exchange.status == 401 and egress is Egress.CREDENTIAL:
            if call.mode == CALLER:
                self._spawn("credential_confirm", self._confirm_credential(call.template))

    async def _confirm_credential(self, template: str) -> None:
        """Plan 7.9: a 401 on the credential path marks the credential rejected only after one confirming probe.

        With the egress package's `CredentialManager.probe(kind, fetch=...)`, the manager runs the probe (one at a
        time fleet-wide), interprets it and marks the credential itself; `credential_probe_fetch` routes the call
        through the reserved probe sub-bucket. Without it, `internal.probe_credential` does the same steps here.
        """
        manager = getattr(self._egress, "credential", None)
        probe = getattr(manager, "probe", None)
        if callable(probe):
            await maybe_await(probe("confirm_401", fetch=self.probe_fetch_for("confirm_401")))
            return
        from roxy.upstream import internal  # local: internal.py imports this module

        verdict = await internal.probe_credential(self, purpose="credential_confirm")
        if verdict.verdict == "rejected":
            with contextlib.suppress(Exception):
                await call_optional(
                    manager, "mark_rejected", f"401 on {template[:120]} confirmed by a probe ({verdict.status})"
                )

    async def credential_probe_fetch(self, url: str, *, trigger: str = "") -> ProbeResponse:
        """The egress `ProbeFetch` hook: one credential probe call through the buckets (rows 25 and 28).

        Paced by the reserved `egress:credential:probe` sub-bucket at internal priority, honoring cooldowns and
        breakers. Returns the raw answer for the credential manager to interpret; raises the egress package's
        `CredentialUnavailable` when no slot is available, and `UpstreamTimeout` or `UpstreamConnectError` when
        Roblox could not be reached, exactly as a direct send would. `trigger` is recorded with the call (see
        `probe_fetch_for`, which callers use to name it).
        """
        result = await self.internal_fetch("credential_probe", "GET", url, use_credential=True, trigger=trigger)
        return probe_response(result)

    def probe_fetch_for(self, kind: str) -> Callable[[str], Awaitable[ProbeResponse]]:
        """`credential_probe_fetch` with the trigger of a probe `kind` (`PROBE_TRIGGERS`) bound, for
        `CredentialManager.probe(kind, fetch=...)`: the scheduled liveness probe records `scheduled`, the health
        check `health`, the dashboard's checks `admin`."""
        trigger = PROBE_TRIGGERS.get(kind, kind[:32])
        return functools.partial(self.credential_probe_fetch, trigger=trigger)

    # ------------------------------------------------------------------------------------------------- results

    def _result(
        self, call: _Call, routed: _Routed, exchange: _Exchange, effects: CallEffects | None, state: _RunState
    ) -> UpstreamResult:
        kind = exchange.kind
        egress = routed.egress
        auth = AuthClass.CRED if egress is Egress.CREDENTIAL else AuthClass.ANON
        private = egress is Egress.CREDENTIAL and (call.credential_rule is None or call.credential_rule.cache_private)
        now_s = self.clock.now()
        upstream_retry = cooldowns.parse_retry_after(exchange.headers.get("retry-after"), now_s)
        if kind is AttemptKind.RATE_LIMITED:
            cooldown_s = (
                effects.cooldown_s if effects is not None and effects.cooldown_s is not None else upstream_retry
            )
            source = effects.cooldown_source if effects is not None else ""
            call.trace.cooldown_source = source
            result = self._failure(
                ReasonCode.UPSTREAM_COOLDOWN,
                call.trace,
                state,
                egress=egress,
                upstream_status=429,
                cooldown_s=cooldown_s,
                cooldown_source=source,
            )
            result.auth_class = auth
            result.private = private
            if call.cfg.negative_429 and not private and result.cooldown_s:
                result.negative_ttl_s = result.cooldown_s
            return result
        if kind is AttemptKind.SERVER_ERROR:
            result = self._failure(
                ReasonCode.UPSTREAM_5XX,
                call.trace,
                state,
                egress=egress,
                upstream_status=exchange.status,
                upstream_retry_after_s=upstream_retry,
            )
            result.auth_class = auth
            result.private = private
            return result
        if kind in (
            AttemptKind.TIMEOUT,
            AttemptKind.CONNECT_ERROR,
            AttemptKind.LEAK_BLOCKED,
            AttemptKind.SMUGGLING_BLOCKED,
            AttemptKind.EGRESS_DISABLED,
            AttemptKind.TARGET_REFUSED,
        ):
            result = self._failure(policy_for(kind).reason, call.trace, state, egress=egress)
            result.auth_class = auth
            result.private = private
            return result
        # Roblox answered: pass the answer on with its real status (2xx, 3xx not followed, 4xx other than 429).
        status = int(exchange.status or 502)
        reason = ReasonCode.UPSTREAM_4XX if 400 <= status < 500 else ReasonCode.UPSTREAM_OK
        negative = None
        if reason is ReasonCode.UPSTREAM_4XX and not private and is_negative_cacheable(status, exchange.headers):
            negative = call.cfg.error_ttl_s if status in NEGATIVE_CACHE_STATUSES or status == 403 else None
        cooldown_s = None
        if effects is not None and effects.cooldown_s is not None and effects.cooldown_source == "ratelimit_reset":
            cooldown_s = messages.retry_after_seconds(ReasonCode.UPSTREAM_COOLDOWN, cooldown_s=effects.cooldown_s)
        return UpstreamResult(
            status=status,
            headers={k: v for k, v in exchange.headers.items() if k in SAFE_RESPONSE_HEADERS},
            body=exchange.body,
            content_type=exchange.headers.get("content-type"),
            egress=egress,
            auth_class=auth,
            upstream_status=status,
            reason=reason,
            retry_after_s=None,
            cooldown_s=cooldown_s,
            attempts=state.attempts,
            calls=state.calls,
            bytes_in=state.bytes_in,
            bytes_out=state.bytes_out,
            queue_wait_ms=state.queue_wait_ms,
            upstream_ms=state.upstream_ms,
            trace=call.trace,
            cacheable=200 <= status < 300 and not private,
            negative_ttl_s=negative,
            private=private,
        )

    def _failure(
        self,
        reason: ReasonCode,
        trace: Trace,
        state: _RunState | None,
        *,
        egress: Egress = Egress.NONE,
        upstream_status: int | None = None,
        cooldown_s: float | None = None,
        soonest_s: float | None = None,
        upstream_retry_after_s: float | None = None,
        credential_rejected: bool = False,
        cooldown_source: str = "",
    ) -> UpstreamResult:
        """An answer Roxy writes itself, from the reason's 7.13 row."""
        row = messages.caller_row(reason)
        status = messages.caller_status(reason, upstream_status) if row.status is not None or upstream_status else 502
        retry_after = messages.retry_after_seconds(
            reason,
            cooldown_s=cooldown_s,
            soonest_s=soonest_s,
            upstream_retry_after_s=upstream_retry_after_s,
            credential_rejected=credential_rejected,
        )
        cooldown_whole = None
        if reason in (ReasonCode.UPSTREAM_COOLDOWN, ReasonCode.CREDENTIAL_UNAVAILABLE) and (cooldown_s or 0) > 0:
            cooldown_whole = retry_after
        body = (row.body or "").encode("utf-8")
        trace.outcome = reason.value
        return UpstreamResult(
            status=status,
            headers={},
            body=body,
            content_type=messages.MESSAGE_CONTENT_TYPE,
            egress=egress,
            auth_class=AuthClass.CRED if egress is Egress.CREDENTIAL else AuthClass.ANON,
            upstream_status=upstream_status,
            reason=reason,
            retry_after_s=retry_after,
            cooldown_s=cooldown_whole,
            attempts=state.attempts if state is not None else 0,
            calls=state.calls if state is not None else 0,
            bytes_in=state.bytes_in if state is not None else 0,
            bytes_out=state.bytes_out if state is not None else 0,
            queue_wait_ms=state.queue_wait_ms if state is not None else 0.0,
            upstream_ms=state.upstream_ms if state is not None else 0.0,
            trace=trace,
            cacheable=False,
            negative_ttl_s=None,
            cooldown_source=cooldown_source,
        )

    def _refusal(self, decision: RouteDecision, call: _Call, state: _RunState) -> UpstreamResult:
        reason = decision.reason or ReasonCode.UPSTREAM_BUSY
        call.trace.note(decision.note)
        if decision.cooldown_source:
            call.trace.cooldown_source = decision.cooldown_source
        cooldown_s = decision.retry_after_s
        soonest_s = decision.retry_after_s
        rejected = reason is ReasonCode.CREDENTIAL_UNAVAILABLE and "rejected" in decision.note
        refusal = state.credential_refusal
        if reason is ReasonCode.CREDENTIAL_UNAVAILABLE and cooldown_s is None and refusal is not None:
            # Refused at send time: answer with what the credential manager said (a cooldown's real remaining
            # time, 10 s while shared state is unreadable), not the fixed 300 s meant for a rejected credential.
            why, hint = refusal
            rejected = rejected or why == "rejected"
            if why == "cooling_down":
                cooldown_s = None if hint is None else float(hint)
            soonest_s = None if hint is None else float(hint)
            call.trace.note(f"credential refused at send time: {why}")
        return self._failure(
            reason,
            call.trace,
            state,
            cooldown_s=cooldown_s,
            soonest_s=soonest_s,
            credential_rejected=rejected,
            cooldown_source=decision.cooldown_source,
        )

    def _record_internal(
        self, purpose: str, req: _InternalRequest, result: UpstreamResult, elapsed_ms: float, *, trigger: str = ""
    ) -> None:
        """Parity rows 28, 68, 72: Roxy's own calls are counted under the `internal` source, never as callers."""
        recorder = getattr(self._ctx, "recorder", None)
        if recorder is None:
            return
        try:
            recorder.record_internal_call(
                purpose,
                ok=result.reason is ReasonCode.UPSTREAM_OK and result.status < 300,
                status=result.upstream_status,
                duration_ms=elapsed_ms,
                endpoint_template=req.template,
                host=req.host,
                method=req.method,
                egress=result.egress.value,
                auth_class=result.auth_class.value,
                reason=result.reason,
                error="" if result.ok else result.reason.value,
                calls=result.calls,
                bytes_in=result.bytes_in,
                bytes_out=result.bytes_out,
                trigger=trigger,
            )
        except Exception:  # metrics degrade open (plan C7)
            log.warning("internal_call_record_failed", exc_info=True)


class EgressDisabled(Exception):
    """Raised here only when no egress clients exist at all; `status.classify_exception` maps it by name."""
