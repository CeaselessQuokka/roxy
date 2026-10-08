"""The metrics recorder: every number Roxy shows starts here, counted in memory and written in batches.

What this is
    `OutcomeEvent` (what the proxy reports once per request, DESIGN.md section 8) and `MetricsRecorder`, the one
    object per worker (`ctx.recorder`) that every package reports to: `record_outcome` for each proxy request,
    plus `record_event`, `record_upstream_429`, `record_internal_call`, `record_background_fetch`,
    `record_retry`, `record_egress_usage`, `record_error`, `record_fingerprint`, `record_capture`,
    `record_sample`, and the public-site and security helpers (`record_visit`, `record_probe`, `record_login`,
    `record_crawl`, `record_throttled`). Nothing here touches SQLite on the request path.

Why it exists
    Plan 6.3: writing a row per request would make every request wait for the disk and multiply write
    transactions by the request rate. Instead each worker adds numbers to a dict keyed by (minute, dimension
    hash), and the batch writer (`storage/batch.py`) upserts the dict every `metrics_flush_interval_ms`; two
    workers writing the same minute simply add up, so totals are exact with any number of workers (C6). Metrics
    fail open (C7): every `record_*` swallows its own errors and counts them, and never raises into a request.

How it works
    - Dimensions (plan 6.2) are bounded before they are hashed: hosts and templates through `VocabularyGate`s
      (64 hosts, 2,000 templates per worker; the rest become `other`), statuses outside the usual set become 0
      ("other"), unknown methods `OTHER`. `dim_hash` is the first 8 bytes of BLAKE2b over the dimension values,
      as a signed 64-bit integer (the `dims` primary key). A collision needs about 4 billion combinations.
    - Per (minute, dim_hash) the recorder keeps 7 counters and two 21-bucket histograms (latency, queue wait).
      Per (minute, client) it keeps requests, refused, served, bytes and a small endpoint counter for
      `top_endpoint`. Every in-memory map has a hard cap; overflow folds into `other` or is counted as dropped.
    - Queued kinds (events, 429 rows, captures, samples, live rows) go into the batch writer's bounded queues
      with priorities: rollups first, live rows and samples dropped first (`metrics_dropped` counts every drop).
    - Events are budgeted per worker (`EVENT_BURST` per type and reason, refilled at `EVENT_RATE` per second);
      beyond the budget they are summed into one row per minute with a `count`, so a flood of refusals costs a
      few rows a minute, and totals stay exact. `record_event(..., aggregate=True)` always sums per minute (for
      counters such as visits, retries, UA rule hits).
    - Honest numbers (P6): caller requests carry `upstream_calls`; background refreshes add upstream calls with
      zero requests (`record_background_fetch`); Roxy's own probes are rows with source `internal`
      (`record_internal_call`), reported separately. `metrics/catalog.py` has the exact definitions.
    - `run(stop)` flushes on the configured interval and refreshes the vocabulary gates hourly; `close()` flushes
      synchronously at shutdown (lifespan) so a recycle never loses buffered numbers.

What to read next
    `roxy/metrics/rollups.py` (what a flush writes and how the leader compacts it), `roxy/storage/batch.py`,
    then `roxy/metrics/catalog.py` (what each number means).
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import random
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any

from roxy.core.clock import SYSTEM_CLOCK, Clock
from roxy.core.iphash import ip_hash
from roxy.core.reasons import AuthClass, CacheState, Egress, Outcome, ReasonCode, Source
from roxy.core.redact import is_sensitive_key, redact_text
from roxy.metrics import histograms, security_events, visitors
from roxy.metrics.activity import ip_key, place_key
from roxy.metrics.capture import CaptureInput, CapturePolicy, CaptureRow, make_row, write_captures
from roxy.metrics.fingerprints import FingerprintAggregator, FingerprintItem, write_fingerprints
from roxy.metrics.live import LIVE_EVENT, LIVE_EVENTS_PER_SECOND, LiveRing, RateGate, live_entry
from roxy.metrics.rollups import ClientDelta, EgressDelta, RollupDelta, write_clients, write_egress_usage, write_rollups
from roxy.metrics.samples import SampleRow, should_sample, write_samples
from roxy.metrics.templating import MAX_HOSTS, MAX_TEMPLATES, OTHER, TEMPLATE_VERSION, VocabularyGate, template_for
from roxy.storage.batch import BatchWriter
from roxy.storage.db import Databases

log = logging.getLogger(__name__)

# --- bounds (plan P9) -------------------------------------------------------------------------------------------

KNOWN_STATUSES = frozenset(
    {200, 201, 204, 206, 301, 302, 304, 307, 308, 400, 401, 403, 404, 405, 408, 409, 410, 413, 414, 422, 429, 431,
     500, 502, 503, 504}
)  # fmt: skip
"""Statuses kept as themselves in `dims` (plan 6.2: about 25 seen in practice); any other is stored as 0."""

METHODS = frozenset({"GET", "HEAD", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"})
PROBLEM_TEMPLATES = frozenset(f"({code.value})" for code in ReasonCode)
"""Templates the proxy gives requests whose target is unusable (`proxy/context.py problem_template`)."""
MAX_PENDING_ROLLUP_KEYS = 20_000
"""(minute, dims) keys held between two flushes; beyond it the template folds into `other`."""
MAX_CLIENTS_PER_MINUTE = 5000
"""Distinct clients per type per minute held in memory; the rest are counted under `other`."""
MAX_ENDPOINTS_PER_CLIENT = 8
MAX_AGG_EVENT_KEYS = 1024
"""Distinct aggregated event keys held in memory (all minutes); overflow folds into one key per type."""
MAX_ERROR_SIGNATURES = 500
MAX_EVENT_BUDGETS = 512
EVENT_BURST = 30.0
"""Individual events of one (type, reason) one worker may write in a burst before summing per minute."""
EVENT_RATE = 0.5
"""Refill of that budget per second (30 a minute)."""
MAX_DETAIL_CHARS = 4000
MAX_SIGNATURE_CHARS = 200
VOCABULARY_REFRESH_S = 3600.0

# Batch kinds and their priorities (higher survives longer when the queue is full).
KIND_ROLLUPS = "metrics.rollups"
KIND_EGRESS = "metrics.egress_usage"
KIND_429 = "metrics.upstream_429"
KIND_CLIENTS = "metrics.clients"
KIND_ERRORS = "metrics.errors"
KIND_EVENTS = "metrics.events"
KIND_AGG_EVENTS = "metrics.events_aggregated"
KIND_FINGERPRINTS = "metrics.fingerprints"
KIND_CAPTURES = "metrics.captures"
KIND_SAMPLES = "metrics.samples"
KIND_LIVE = "metrics.live"
PRIORITIES: dict[str, int] = {
    KIND_ROLLUPS: 100,
    KIND_EGRESS: 95,
    KIND_429: 90,
    KIND_CLIENTS: 70,
    KIND_ERRORS: 65,
    KIND_EVENTS: 60,
    KIND_AGG_EVENTS: 55,
    KIND_FINGERPRINTS: 40,
    KIND_CAPTURES: 20,
    KIND_SAMPLES: 10,
    KIND_LIVE: 5,
}

# Event types written by this package (other packages may add their own through `record_event`).
REFUSAL_EVENT = "refusal"
FAILURE_EVENT = "failure"
INTERNAL_CALL_EVENT = "internal_call"
RETRY_EVENT = "upstream_retry"
CAPTURE_ERROR_EVENT = "capture_error"
BLOCKED_HEADER_EVENT = "blocked_header"
BLOCKED_UA_EVENT = "blocked_user_agent"


# --- the contract (DESIGN.md section 8) -------------------------------------------------------------------------


@dataclass(slots=True)
class OutcomeEvent:
    """One proxy request, reported exactly once by every exit path (DESIGN.md sections 7 and 8).

    The first block is the DESIGN.md section 8 contract. The fields after it were added by P7 with defaults, so
    callers written against the contract keep working: they feed the Live view (row 126), refusal message split
    (row 116), request samples and captures.
    """

    at_ms: int
    request_id: str
    endpoint_template: str
    host: str
    method: str
    egress: Egress
    outcome: Outcome
    reason: ReasonCode
    status: int
    source: Source
    cache_state: CacheState
    auth_class: AuthClass
    caller_bytes_in: int
    caller_bytes_out: int
    upstream_calls: int
    upstream_bytes_in: int
    upstream_bytes_out: int
    latency_ms: float
    queue_wait_ms: float
    upstream_ms: float
    client_ip: str
    place_id: str | None
    user_agent: str
    bypass: bool
    error: bool  # an upstream or internal error happened, whether or not the caller saw it (stale serves too)
    # --- added in P7 (optional) ---
    path: str = ""  # concrete host/path without the query (Live view)
    query: str = ""  # raw query string; redacted before it is stored
    upstream_status: int | None = None
    attempts: int = 0
    retries: int = 0  # CSRF and other retries inside the attempts
    cache_age_s: int | None = None
    upstream_error: str = ""
    message_source: str = ""  # refusals: "custom" or "default" (row 116)
    check: str = ""  # refusals: the abuse check that refused
    cache_key_id: str | None = None  # request samples (24 hex)
    body_hash: str | None = None  # request samples
    capture_id: str = ""


@dataclass(slots=True)
class EventRecord:
    """One `events` row. `count` > 1 means the row stands for that many occurrences (aggregated)."""

    at_ms: int
    type: str
    severity: str
    reason_code: str | None
    ip_hash: str | None
    place: str | None
    endpoint_template: str | None
    detail: dict[str, Any]
    count: int = 1


@dataclass(slots=True)
class Upstream429Row:
    at_ms: int
    endpoint_template: str
    host: str
    egress: str
    retry_after_s: float | None
    ratelimit_headers_json: str | None
    request_id: str | None


@dataclass(slots=True)
class ErrorDelta:
    signature: str
    count: int
    first_seen: int
    last_seen: int
    source: str
    last_detail: str
    module_line: str
    traceback: str


@dataclass(frozen=True, slots=True)
class RecorderConfig:
    """The settings the hot path reads, rebuilt only when the settings snapshot changes."""

    activity_tracking: bool = True
    live_tail_buffer: int = 500
    request_sample_pct: float = 100.0
    value_cap: int = 500
    flush_interval_s: float = 2.0
    capture: CapturePolicy = field(default_factory=CapturePolicy)

    @classmethod
    def from_settings(cls, get: Callable[[str], Any]) -> RecorderConfig:
        def value(key: str, fallback: Any) -> Any:
            try:
                found = get(key)
            except (KeyError, LookupError, AttributeError):
                return fallback
            return fallback if found is None else found

        return cls(
            activity_tracking=bool(int(value("activity_tracking", 1))),
            live_tail_buffer=max(0, int(value("live_tail_buffer", 500))),
            request_sample_pct=float(value("request_sample_pct", 100)),
            value_cap=max(1, int(value("max_header_value_records", 500))),
            flush_interval_s=max(0.25, int(value("metrics_flush_interval_ms", 2000)) / 1000.0),
            capture=CapturePolicy.from_settings(get),
        )


def dims_hash(dims: tuple[Any, ...]) -> int:
    """The `dims.dim_hash` of a dimension tuple: BLAKE2b-64 of the values joined by a unit separator."""
    text = "\x1f".join(str(v) for v in dims).encode("utf-8", "replace")
    return int.from_bytes(hashlib.blake2b(text, digest_size=8).digest(), "big", signed=True)


def _now_ms(clock: Clock) -> int:
    return clock.now_ms()


@dataclass(slots=True)
class _Agg:
    dims: tuple[Any, ...]
    requests: int = 0
    caller_bytes_in: int = 0
    caller_bytes_out: int = 0
    upstream_calls: int = 0
    upstream_bytes_in: int = 0
    upstream_bytes_out: int = 0
    errors: int = 0
    latency: list[int] | None = None
    queue_wait: list[int] | None = None


@dataclass(slots=True)
class _ClientAgg:
    requests: int = 0
    refused: int = 0
    served: int = 0
    bytes: int = 0
    endpoints: dict[str, int] = field(default_factory=dict)


class MetricsRecorder:
    """Per-worker metrics: in-memory aggregation flushed through a `BatchWriter` (see the module docstring)."""

    def __init__(
        self,
        dbs: Databases,
        settings: Any,
        clock: Clock | None = None,
        *,
        batch: BatchWriter | None = None,
        worker_id: str = "",
        ip_hash_key: bytes | None = None,
        rules: Any = None,
        rng: Callable[[], float] = random.random,
    ) -> None:
        self.dbs = dbs
        self.settings = settings
        self.clock: Clock = clock or SYSTEM_CLOCK
        self.worker_id = worker_id
        self.ip_hash_key = ip_hash_key
        self.rules = rules
        self._rng = rng
        self.batch = batch or BatchWriter(max_items=self._queue_max)
        self._config_version: object = object()
        self._config = RecorderConfig()
        self.reload_config()
        self.live = LiveRing(self._config.live_tail_buffer)
        self.fingerprints = FingerprintAggregator(ip_hash_key)
        self.templates = VocabularyGate(MAX_TEMPLATES)
        self.hosts = VocabularyGate(MAX_HOSTS)
        self._lock = threading.Lock()
        self._rollups: dict[tuple[int, int], _Agg] = {}
        self._clients: dict[tuple[int, str, str], _ClientAgg] = {}
        self._client_counts: dict[tuple[int, str], int] = {}
        self._egress: dict[tuple[int, str], list[int]] = {}
        self._agg_events: dict[tuple[Any, ...], int] = {}
        self._errors: dict[str, ErrorDelta] = {}
        self._budgets: dict[tuple[str, str], RateGate] = {}
        self._live_gate = RateGate(LIVE_EVENTS_PER_SECOND, LIVE_EVENTS_PER_SECOND, self.clock.monotonic)
        self._closing = False
        self._last_vocab_refresh: float | None = None
        # Counters for the System page (per worker; exact values are not critical).
        self.capture_errors = 0
        self.record_errors = 0
        self.events_aggregated = 0
        self.live_sampled_out = 0
        self.rollup_overflow = 0
        self.dims_last_minute = 0
        self._register_kinds()

    # ------------------------------------------------------------------------------------------- settings

    def _get(self, key: str) -> Any:
        return self.settings.get(key)

    def _queue_max(self) -> int:
        try:
            return int(self._get("metrics_queue_max"))
        except (KeyError, LookupError, AttributeError, TypeError, ValueError):
            return 50_000

    def reload_config(self) -> RecorderConfig:
        """Rebuild the cached settings now (also done automatically when the settings version changes)."""
        self._config = RecorderConfig.from_settings(self._get)
        self._config_version = getattr(self.settings, "version", None)
        live = getattr(self, "live", None)
        if live is not None:
            live.resize(self._config.live_tail_buffer)
        return self._config

    def config(self) -> RecorderConfig:
        version = getattr(self.settings, "version", None)
        if version is None or version != self._config_version:
            self.reload_config()
        return self._config

    # ----------------------------------------------------------------------------------------- batch kinds

    def _register_kinds(self) -> None:
        metrics = self.dbs.metrics
        b = self.batch
        b.register(KIND_ROLLUPS, metrics, write_rollups, priority=PRIORITIES[KIND_ROLLUPS], source=self._drain_rollups)
        b.register(
            KIND_EGRESS, metrics, write_egress_usage, priority=PRIORITIES[KIND_EGRESS], source=self._drain_egress
        )
        b.register(KIND_429, metrics, _write_429, priority=PRIORITIES[KIND_429])
        b.register(KIND_CLIENTS, metrics, write_clients, priority=PRIORITIES[KIND_CLIENTS], source=self._drain_clients)
        b.register(KIND_ERRORS, metrics, _write_errors, priority=PRIORITIES[KIND_ERRORS], source=self._drain_errors)
        b.register(KIND_EVENTS, metrics, write_events, priority=PRIORITIES[KIND_EVENTS])
        b.register(
            KIND_AGG_EVENTS, metrics, write_events, priority=PRIORITIES[KIND_AGG_EVENTS], source=self._drain_agg_events
        )
        b.register(
            KIND_FINGERPRINTS,
            metrics,
            self._write_fingerprints,
            priority=PRIORITIES[KIND_FINGERPRINTS],
            source=self.fingerprints.drain,
        )
        b.register(KIND_CAPTURES, metrics, self._write_captures, priority=PRIORITIES[KIND_CAPTURES])
        b.register(KIND_SAMPLES, metrics, write_samples, priority=PRIORITIES[KIND_SAMPLES])
        b.register(KIND_LIVE, metrics, write_events, priority=PRIORITIES[KIND_LIVE])

    def _write_fingerprints(self, conn: Any, items: list[FingerprintItem]) -> None:
        write_fingerprints(conn, items, value_cap=self._config.value_cap, hash_key=self.ip_hash_key)

    def _write_captures(self, conn: Any, rows: list[CaptureRow]) -> None:
        write_captures(conn, rows, self._config.capture, self.clock.now())

    # ------------------------------------------------------------------------------------- dimension bounds

    def _bounded_host(self, host: str) -> str:
        host = (host or "").strip().lower()
        if not host or len(host) > 64 or not (host == "roblox.com" or host.endswith(".roblox.com")):
            return OTHER  # not a Roblox host: attacker supplied, never its own dimension value
        return self.hosts.admit(host)

    def _bounded_template(self, template: str, host: str) -> str:
        if template in PROBLEM_TEMPLATES:
            return template  # "(not_roblox)" and friends: a fixed, bounded set chosen by the proxy (plan P9)
        if host == OTHER or not template:
            return OTHER
        return self.templates.admit(template)

    def _dims(
        self,
        *,
        template: str,
        host: str,
        method: str,
        egress: str,
        outcome: str,
        reason: str,
        status: int,
        source: str,
        cache_state: str,
        auth_class: str,
    ) -> tuple[Any, ...]:
        bounded_host = self._bounded_host(host)
        method = (method or "").upper()
        return (
            self._bounded_template(template, bounded_host),
            TEMPLATE_VERSION,
            bounded_host,
            method if method in METHODS else "OTHER",
            str(egress),
            str(outcome),
            str(reason),
            int(status) if int(status) in KNOWN_STATUSES else 0,
            str(source),
            str(cache_state),
            str(auth_class),
        )

    def _agg_for(self, minute: int, dims: tuple[Any, ...]) -> _Agg:
        """The (minute, dims) accumulator; caller holds `_lock`."""
        key = (minute, dims_hash(dims))
        agg = self._rollups.get(key)
        if agg is not None:
            return agg
        if len(self._rollups) >= MAX_PENDING_ROLLUP_KEYS:
            # Too many distinct combinations before a flush (an attack on the vocabulary): fold the template.
            self.rollup_overflow += 1
            dims = (OTHER, *dims[1:])
            key = (minute, dims_hash(dims))
            agg = self._rollups.get(key)
            if agg is not None:
                return agg
        agg = _Agg(dims)
        self._rollups[key] = agg
        return agg

    # --------------------------------------------------------------------------------------- record_outcome

    def record_outcome(self, ev: OutcomeEvent, capture: CaptureInput | None = None) -> str:
        """Count one proxy request (exactly once per request). Returns the capture id ("" when not captured).

        Never raises: a failure here is counted in `record_errors` and logged, and the request goes on.
        """
        capture_id = ""
        try:
            cfg = self.config()
            minute = int(ev.at_ms) // 60_000 * 60
            dims = self._dims(
                template=ev.endpoint_template,
                host=ev.host,
                method=ev.method,
                egress=ev.egress,
                outcome=ev.outcome,
                reason=ev.reason,
                status=ev.status,
                source=ev.source,
                cache_state=ev.cache_state,
                auth_class=ev.auth_class,
            )
            with self._lock:
                agg = self._agg_for(minute, dims)
                agg.requests += 1
                agg.caller_bytes_in += max(0, int(ev.caller_bytes_in))
                agg.caller_bytes_out += max(0, int(ev.caller_bytes_out))
                agg.upstream_calls += max(0, int(ev.upstream_calls))
                agg.upstream_bytes_in += max(0, int(ev.upstream_bytes_in))
                agg.upstream_bytes_out += max(0, int(ev.upstream_bytes_out))
                agg.errors += 1 if ev.error else 0
                if agg.latency is None:
                    agg.latency = histograms.empty()
                    agg.queue_wait = histograms.empty()
                histograms.observe(agg.latency, float(ev.latency_ms))
                if agg.queue_wait is not None:
                    histograms.observe(agg.queue_wait, float(ev.queue_wait_ms))
                if cfg.activity_tracking:
                    self._count_clients(minute, ev, dims[0])
            if capture is not None:
                capture_id = self.record_capture(_complete_capture(capture, ev), outcome=str(ev.outcome))
            self._record_live(ev, capture_id)
            if ev.outcome in (Outcome.REFUSED, Outcome.FAILED):
                self._record_refusal_event(ev, dims[0])
            if should_sample(str(ev.outcome), cfg.request_sample_pct, self._rng):
                self.batch.add(KIND_SAMPLES, self._sample_row(ev, dims[0]))
        except Exception:
            self._count_error("record_outcome")
        return capture_id

    def _count_clients(self, minute: int, ev: OutcomeEvent, template: str) -> None:
        """Client activity for one request; caller holds `_lock`."""
        refused = 1 if ev.outcome == Outcome.REFUSED else 0
        served = 1 if ev.outcome in (Outcome.SERVED_UPSTREAM, Outcome.SERVED_CACHE) else 0
        size = max(0, int(ev.caller_bytes_out))
        for ctype, key in (("ip", ip_key(ev.client_ip)), ("place", place_key(ev.place_id))):
            if not key:
                continue
            slot = (minute, ctype, key)
            agg = self._clients.get(slot)
            if agg is None:
                count_key = (minute, ctype)
                if self._client_counts.get(count_key, 0) >= MAX_CLIENTS_PER_MINUTE:
                    slot = (minute, ctype, OTHER)
                    agg = self._clients.get(slot)
                if agg is None:
                    agg = _ClientAgg()
                    self._clients[slot] = agg
                    self._client_counts[count_key] = self._client_counts.get(count_key, 0) + 1
            agg.requests += 1
            agg.refused += refused
            agg.served += served
            agg.bytes += size
            if template in agg.endpoints or len(agg.endpoints) < MAX_ENDPOINTS_PER_CLIENT:
                agg.endpoints[template] = agg.endpoints.get(template, 0) + 1

    def _record_live(self, ev: OutcomeEvent, capture_id: str) -> None:
        entry = live_entry(ev, capture_id)
        self.live.append(entry)
        if not self._live_gate.allow():
            self.live_sampled_out += 1
            return
        self.batch.add(
            KIND_LIVE,
            EventRecord(
                at_ms=int(ev.at_ms),
                type=LIVE_EVENT,
                severity="info",
                reason_code=str(ev.reason),
                ip_hash=None,  # live rows are deleted after 15 minutes; the raw IP is in the detail for the view
                place=ev.place_id,
                endpoint_template=ev.endpoint_template[:255],
                detail=entry,
            ),
        )

    def _record_refusal_event(self, ev: OutcomeEvent, template: str) -> None:
        event_type = REFUSAL_EVENT if ev.outcome == Outcome.REFUSED else FAILURE_EVENT
        severity = (
            "info"
            if event_type == REFUSAL_EVENT
            else ("critical" if ev.reason == ReasonCode.INTERNAL_ERROR else "warn")
        )
        detail: dict[str, Any] = {"status": int(ev.status), "method": ev.method[:12]}
        if ev.message_source:
            detail["message_source"] = ev.message_source[:16]
        if ev.check:
            detail["check"] = ev.check[:64]
        if ev.path:
            detail["path"] = ev.path.split("?", 1)[0][:200]
        if ev.upstream_status is not None:
            detail["upstream_status"] = int(ev.upstream_status)
        if ev.upstream_error:
            detail["upstream_error"] = ev.upstream_error[:300]
        if ev.egress != Egress.NONE:
            detail["egress"] = str(ev.egress)
        if ev.bypass:
            detail["bypass"] = True
        summary = (
            {"status": int(ev.status), "message_source": ev.message_source[:16]}
            if ev.message_source
            else {"status": int(ev.status)}
        )
        self._event(
            int(ev.at_ms),
            event_type,
            severity,
            str(ev.reason),
            detail,
            ip=ev.client_ip,
            place=ev.place_id,
            endpoint_template=template,
            summary_detail=summary,
        )

    def _sample_row(self, ev: OutcomeEvent, template: str) -> SampleRow:
        return SampleRow(
            at_ms=int(ev.at_ms),
            key_id=ev.cache_key_id,
            endpoint_template=template,
            method=ev.method[:12],
            client_hash=self._hash_ip(ev.client_ip),
            place=ev.place_id,
            cache_state=str(ev.cache_state),
            upstream_status=ev.upstream_status,
            egress=str(ev.egress),
            body_hash=ev.body_hash,
            bytes=max(0, int(ev.caller_bytes_out)),
            auth_class=str(ev.auth_class),
        )

    def _hash_ip(self, ip: str | None) -> str | None:
        if not ip or self.ip_hash_key is None:
            return None
        try:
            return ip_hash(ip, self.ip_hash_key)
        except ValueError:
            return None

    def _count_error(self, where: str) -> None:
        self.record_errors += 1
        # Log the first error and then every 1000th, so a broken producer cannot flood the journal.
        if self.record_errors == 1 or self.record_errors % 1000 == 0:
            log.exception("metrics_record_failed", extra={"fields": {"where": where, "errors": self.record_errors}})

    # --------------------------------------------------------------------------------------------- events

    def _event(
        self,
        at_ms: int,
        event_type: str,
        severity: str,
        reason: str | None,
        detail: Mapping[str, Any] | None,
        *,
        ip: str | None = None,
        place: str | None = None,
        endpoint_template: str | None = None,
        count: int = 1,
        aggregate: bool = False,
        summary_detail: Mapping[str, Any] | None = None,
    ) -> bool:
        """Queue one event row, or add it to the per-minute sums. Returns True when written individually."""
        reason_text = None if reason is None else str(reason)[:MAX_SIGNATURE_CHARS]
        template = endpoint_template[:255] if endpoint_template else None
        place_text = str(place)[:64] if place else None
        if not aggregate:
            budget_key = (event_type, reason_text or "")
            gate = self._budgets.get(budget_key)
            if gate is None:
                if len(self._budgets) >= MAX_EVENT_BUDGETS:
                    self._budgets.clear()  # bounded: forgetting budgets only grants a fresh burst
                gate = RateGate(EVENT_RATE, EVENT_BURST, self.clock.monotonic)
                self._budgets[budget_key] = gate
            if gate.allow():
                return self.batch.add(
                    KIND_EVENTS,
                    EventRecord(
                        at_ms=at_ms,
                        type=event_type,
                        severity=severity,
                        reason_code=reason_text,
                        ip_hash=self._hash_ip(ip),
                        place=place_text,
                        endpoint_template=template,
                        detail=dict(detail or {}),
                        count=count,
                    ),
                )
            self.events_aggregated += 1
            # Over budget: keep the count exact but drop the per-occurrence detail (bounded keys).
            detail = dict(summary_detail or {})
            detail["aggregated"] = True
            ip = None
        self._add_aggregate(at_ms, event_type, severity, reason_text, ip, place_text, template, detail, count)
        return False

    def _add_aggregate(
        self,
        at_ms: int,
        event_type: str,
        severity: str,
        reason: str | None,
        ip: str | None,
        place: str | None,
        template: str | None,
        detail: Mapping[str, Any] | None,
        count: int,
    ) -> None:
        detail_json = _detail_json(detail or {})
        minute_ms = int(at_ms) // 60_000 * 60_000
        key: tuple[Any, ...] = (
            minute_ms,
            event_type,
            severity,
            reason,
            self._hash_ip(ip),
            place,
            template,
            detail_json,
        )
        with self._lock:
            if key not in self._agg_events and len(self._agg_events) >= MAX_AGG_EVENT_KEYS:
                key = (minute_ms, event_type, severity, reason, None, None, None, _detail_json({"overflow": True}))
            self._agg_events[key] = self._agg_events.get(key, 0) + int(count)

    def record_event(
        self,
        type: str,
        severity: str = "info",
        reason: str | None = None,
        detail: Mapping[str, Any] | None = None,
        *,
        at_ms: int | None = None,
        ip: str | None = None,
        place: str | None = None,
        endpoint_template: str | None = None,
        count: int = 1,
        aggregate: bool = False,
    ) -> bool:
        """Record a notable event (`events` table): bans, breaker changes, credential changes, resets, CSP reports.

        `ip` is stored only as its keyed hash (`ip_hash` column); put the raw address in `detail` only where the
        admin needs it. `aggregate=True` sums occurrences per minute (use it for counters: retries, UA rule hits,
        cache stores). Returns True when the event was queued as its own row. Never raises.
        """
        try:
            return self._event(
                int(at_ms if at_ms is not None else _now_ms(self.clock)),
                str(type)[:64],
                str(severity)[:16],
                reason,
                detail,
                ip=ip,
                place=place,
                endpoint_template=endpoint_template,
                count=count,
                aggregate=aggregate,
                summary_detail={},
            )
        except Exception:
            self._count_error("record_event")
            return False

    def _drain_agg_events(self) -> list[EventRecord]:
        """Closed minutes of aggregated events (all of them when closing)."""
        current = _now_ms(self.clock) // 60_000 * 60_000
        out: list[EventRecord] = []
        with self._lock:
            ready = [k for k in self._agg_events if self._closing or k[0] < current]
            for key in ready:
                count = self._agg_events.pop(key)
                minute_ms, event_type, severity, reason, iph, place, template, detail_json = key
                detail = json.loads(detail_json) if detail_json else {}
                out.append(EventRecord(minute_ms, event_type, severity, reason, iph, place, template, detail, count))
        return out

    # ----------------------------------------------------------------------------------- other producers

    def record_upstream_429(
        self,
        *,
        endpoint_template: str,
        host: str,
        egress: Egress | str,
        retry_after_s: float | None = None,
        ratelimit_headers: Mapping[str, Any] | None = None,
        request_id: str | None = None,
        at_ms: int | None = None,
    ) -> None:
        """Every Roblox 429 (plan 6.2 `upstream_429`, capped 200,000 rows). Called by the upstream service."""
        try:
            # Raw `x-ratelimit-*` headers or the upstream service's parsed values (`limit`, `remaining`,
            # `reset_s`); bounded, and anything whose name says secret is dropped.
            headers: dict[str, Any] = {}
            for k, v in list((ratelimit_headers or {}).items())[:20]:
                name = str(k).lower()[:64]
                if is_sensitive_key(name):
                    continue
                headers[name] = v if v is None or isinstance(v, int | float) else str(v)[:200]
            bounded_host = self._bounded_host(host)
            self.batch.add(
                KIND_429,
                Upstream429Row(
                    at_ms=int(at_ms if at_ms is not None else _now_ms(self.clock)),
                    endpoint_template=self._bounded_template(endpoint_template, bounded_host),
                    host=bounded_host,
                    egress=str(egress),
                    retry_after_s=None if retry_after_s is None else float(retry_after_s),
                    ratelimit_headers_json=json.dumps(headers, sort_keys=True) if headers else None,
                    request_id=request_id,
                ),
            )
        except Exception:
            self._count_error("record_upstream_429")

    def _add_upstream_row(
        self,
        at_ms: int,
        dims: tuple[Any, ...],
        *,
        calls: int,
        bytes_in: int,
        bytes_out: int,
        error: bool,
    ) -> None:
        minute = int(at_ms) // 60_000 * 60
        with self._lock:
            agg = self._agg_for(minute, dims)
            agg.upstream_calls += max(0, int(calls))
            agg.upstream_bytes_in += max(0, int(bytes_in))
            agg.upstream_bytes_out += max(0, int(bytes_out))
            agg.errors += 1 if error else 0

    def record_internal_call(
        self,
        purpose: str,
        *,
        ok: bool,
        status: int | None = None,
        duration_ms: float = 0.0,
        endpoint_template: str = "",
        host: str = "",
        method: str = "GET",
        egress: Egress | str = Egress.DIRECT,
        auth_class: AuthClass | str = AuthClass.ANON,
        reason: ReasonCode | None = None,
        error: str = "",
        calls: int = 1,
        bytes_in: int = 0,
        bytes_out: int = 0,
        at_ms: int | None = None,
        elapsed_ms: float | None = None,
        endpoint: str = "",
    ) -> None:
        """One of Roxy's own upstream calls (probes, lookups): source `internal`, zero caller requests (P6).

        `elapsed_ms` is accepted as another name for `duration_ms`, and `endpoint` (a URL without its query, as
        the upstream service reports it) fills `host` and `endpoint_template` when those are not given.
        """
        try:
            if elapsed_ms is not None:
                duration_ms = elapsed_ms
            if endpoint and not (host and endpoint_template):
                target = endpoint.split("://", 1)[-1].split("?", 1)[0]
                url_host, _, url_path = target.partition("/")
                host = host or url_host
                endpoint_template = endpoint_template or template_for(url_host, url_path)
            when = int(at_ms if at_ms is not None else _now_ms(self.clock))
            if reason is None:
                if ok:
                    reason = ReasonCode.UPSTREAM_OK
                elif status is None:
                    reason = ReasonCode.UPSTREAM_CONNECT
                elif status >= 500:
                    reason = ReasonCode.UPSTREAM_5XX
                else:
                    reason = ReasonCode.UPSTREAM_4XX
            dims = self._dims(
                template=endpoint_template,
                host=host,
                method=method,
                egress=str(egress),
                outcome=Outcome.SERVED_UPSTREAM if ok else Outcome.FAILED,
                reason=reason,
                status=status or 0,
                source=Source.INTERNAL,
                cache_state=CacheState.NA,
                auth_class=str(auth_class),
            )
            self._add_upstream_row(when, dims, calls=calls, bytes_in=bytes_in, bytes_out=bytes_out, error=not ok)
            detail: dict[str, Any] = {
                "purpose": purpose[:60],
                "ok": bool(ok),
                "duration_ms": round(float(duration_ms), 3),
            }
            if status is not None:
                detail["status"] = int(status)
            if endpoint_template:
                detail["endpoint"] = endpoint_template[:200]
            if error:
                detail["error"] = redact_text(error)[:200]
            self._event(when, INTERNAL_CALL_EVENT, "info" if ok else "warn", purpose[:60], detail,
                        summary_detail={"ok": bool(ok)})  # fmt: skip
        except Exception:
            self._count_error("record_internal_call")

    def record_background_fetch(
        self,
        *,
        endpoint_template: str,
        host: str,
        method: str = "GET",
        egress: Egress | str = Egress.DIRECT,
        auth_class: AuthClass | str = AuthClass.ANON,
        status: int = 0,
        calls: int = 1,
        bytes_in: int = 0,
        bytes_out: int = 0,
        ok: bool = True,
        reason: ReasonCode = ReasonCode.CACHE_REVALIDATING,
        at_ms: int | None = None,
    ) -> None:
        """Upstream calls made for caller traffic without a caller waiting (stale-while-revalidate refreshes).

        Counted as upstream calls with zero requests, so "avoided upstream calls" never forgets them (P6).
        """
        try:
            dims = self._dims(
                template=endpoint_template,
                host=host,
                method=method,
                egress=str(egress),
                outcome=Outcome.SERVED_CACHE,
                reason=reason,
                status=status,
                source=Source.ROBLOX,
                cache_state=CacheState.REVALIDATING,
                auth_class=str(auth_class),
            )
            when = int(at_ms if at_ms is not None else _now_ms(self.clock))
            self._add_upstream_row(when, dims, calls=calls, bytes_in=bytes_in, bytes_out=bytes_out, error=not ok)
        except Exception:
            self._count_error("record_background_fetch")

    def record_retry(
        self,
        *,
        status: int | None,
        reason: str,
        egress: Egress | str = Egress.DIRECT,
        endpoint_template: str = "",
        at_ms: int | None = None,
    ) -> None:
        """One upstream retry (row 117: retries by status and by reason, per egress and per endpoint)."""
        detail = {"status": int(status) if status is not None else None, "reason": reason[:120], "egress": str(egress)}
        self.record_event(
            RETRY_EVENT, "info", None, detail, at_ms=at_ms, endpoint_template=endpoint_template or None, aggregate=True
        )

    def record_egress_usage(
        self,
        egress: Any,
        *,
        req_bytes: int | None = None,
        resp_bytes: int = 0,
        overhead_bytes: int = 0,
        requests: int = 1,
        at_ms: int | None = None,
    ) -> None:
        """Wire bytes per egress (plan 8.3): minute rows of `egress_usage`.

        Takes either the keyword form or one usage object with the same attribute names (`egress/accounting.py
        EgressUsage`: `egress`, `req_bytes`, `resp_bytes`, `overhead_bytes`, `requests`, `at_ms`). Never raises.
        """
        try:
            if req_bytes is None:
                usage = egress
                egress = usage.egress
                req_bytes = int(usage.req_bytes)
                resp_bytes = int(getattr(usage, "resp_bytes", 0) or 0)
                overhead_bytes = int(getattr(usage, "overhead_bytes", 0) or 0)
                requests = int(getattr(usage, "requests", 1) or 0)
                at_ms = getattr(usage, "at_ms", None)
            minute = int(at_ms if at_ms is not None else _now_ms(self.clock)) // 60_000 * 60
            key = (minute, str(egress)[:16])
            with self._lock:
                acc = self._egress.get(key)
                if acc is None:
                    acc = self._egress[key] = [0, 0, 0, 0]
                acc[0] += max(0, int(requests))
                acc[1] += max(0, int(req_bytes))
                acc[2] += max(0, int(resp_bytes))
                acc[3] += max(0, int(overhead_bytes))
        except Exception:
            self._count_error("record_egress_usage")

    def record_error(
        self,
        signature: str,
        *,
        detail: str = "",
        source: str = "roxy",
        module_line: str = "",
        traceback: str = "",
        at_s: int | None = None,
    ) -> None:
        """An internal error by signature (`errors` table, row 72). Detail and traceback are redacted."""
        try:
            now = int(at_s if at_s is not None else self.clock.now())
            sig = redact_text(signature or "Unknown error")[:MAX_SIGNATURE_CHARS]
            with self._lock:
                entry = self._errors.get(sig)
                if entry is None:
                    if len(self._errors) >= MAX_ERROR_SIGNATURES:
                        return
                    entry = self._errors[sig] = ErrorDelta(sig, 0, now, now, source[:16], "", "", "")
                entry.count += 1
                entry.last_seen = max(entry.last_seen, now)
                entry.source = source[:16]
                if detail:
                    entry.last_detail = detail
                if module_line:
                    entry.module_line = module_line[:200]
                if traceback:
                    entry.traceback = traceback
        except Exception:
            self._count_error("record_error")

    def record_fingerprint(
        self, header_pairs: Iterable[tuple[str, str]], user_agent: str | None, *, blocked: bool = False
    ) -> None:
        """Header names, values and User-Agent of one request that passed every check (row 79).

        `blocked=True` (a request-filter refusal, row 134) records the header names and the User-Agent as
        aggregated `blocked_header` and `blocked_user_agent` events instead.
        """
        try:
            now_ms = _now_ms(self.clock)
            if blocked:
                for name, _value in list(header_pairs)[:100]:
                    self._event(now_ms, BLOCKED_HEADER_EVENT, "info", str(name).lower()[:120], None, aggregate=True)
                ua = (user_agent or "(none)")[:400]
                self._event(now_ms, BLOCKED_UA_EVENT, "info", None, {"user_agent": redact_text(ua)}, aggregate=True)
                return
            ignored: frozenset[str] = frozenset()
            if self.rules is not None:
                with contextlib.suppress(Exception):
                    ignored = self.rules.snapshot().ignored_value_headers
            self.fingerprints.add(header_pairs, user_agent, now_ms // 1000, ignored)
        except Exception:
            self._count_error("record_fingerprint")

    def record_capture(self, inp: CaptureInput, *, outcome: str | None = None) -> str:
        """Capture one request's bodies if the policy wants it. Returns the capture id or "". Never raises (127)."""
        try:
            policy = self.config().capture
            if not policy.wants(outcome if outcome is not None else inp.outcome, self._rng):
                return ""
            row = make_row(inp, policy)
            self.batch.add(KIND_CAPTURES, row)
            return inp.request_id
        except Exception:
            self.capture_errors += 1
            with contextlib.suppress(Exception):
                self._event(_now_ms(self.clock), CAPTURE_ERROR_EVENT, "warn", None, None, aggregate=True)
            if self.capture_errors == 1 or self.capture_errors % 1000 == 0:
                log.warning("capture_failed", extra={"fields": {"capture_errors": self.capture_errors}}, exc_info=True)
            return ""

    def record_sample(self, row: SampleRow) -> None:
        """Queue one explicit `request_samples` row (record_outcome samples proxied requests by itself)."""
        try:
            self.batch.add(KIND_SAMPLES, row)
        except Exception:
            self._count_error("record_sample")

    # --- public site and security (rows 13, 19, 51, 80, 97, 130) ---

    def record_visit(self, page: str, user_agent: str | None, *, count: int = 1, at_ms: int | None = None) -> None:
        """A visit to a public page (`home`, `admin`, `robots`, `sitemap`), counted per minute (row 130)."""
        self.record_event(
            visitors.VISIT_EVENT, "info", None, visitors.visit_detail(page, user_agent), at_ms=at_ms, count=count,
            aggregate=True,
        )  # fmt: skip

    def record_admin_visit_discount(self, *, at_ms: int | None = None) -> None:
        """The owner's own admin visit, subtracted after a login without the seen cookie (v1 behavior)."""
        self.record_event(
            visitors.VISIT_EVENT, "info", None, visitors.admin_visit_discount(), at_ms=at_ms, count=-1, aggregate=True
        )

    def record_probe(self, ip: str, reason: str, user_agent: str | None = None, path: str | None = None) -> None:
        """An exploit or probe attempt (row 80; v1 reason strings kept, B19 fixed by `probe_signature`)."""
        try:
            signature, detail = security_events.probe_detail(ip, reason, user_agent, path)
            self._event(_now_ms(self.clock), security_events.PROBE, "warn", signature, detail, ip=ip,
                        summary_detail={})  # fmt: skip
        except Exception:
            self._count_error("record_probe")

    def record_login(self, ip: str, successful: bool, *, username: str | None = None, method: str = "") -> None:
        """An admin login attempt (row 97)."""
        detail = security_events.login_detail(ip, successful, username, method)
        self.record_event(security_events.LOGIN, "info" if successful else "warn",
                          "success" if successful else "failure", detail, ip=ip)  # fmt: skip

    def record_crawl(self, ip: str, path: str, user_agent: str | None = None) -> None:
        """A robots.txt or sitemap.xml fetch (row 13)."""
        self.record_event(security_events.CRAWL, "info", path[:64], security_events.crawl_detail(ip, path, user_agent),
                          ip=ip)  # fmt: skip

    def record_throttled(self, ip: str, *, tier: int | None = None, strikes: int | None = None) -> None:
        """A client that just became throttled (the v1 `throttled_ips` watch, row 80)."""
        self.record_event(security_events.THROTTLED, "info", None, security_events.throttled_detail(ip, tier, strikes),
                          ip=ip)  # fmt: skip

    # ------------------------------------------------------------------------------------------- draining

    def _drain_rollups(self) -> list[RollupDelta]:
        with self._lock:
            pending, self._rollups = self._rollups, {}
        out: list[RollupDelta] = []
        minutes: dict[int, int] = {}
        for (minute, dim_hash), agg in pending.items():
            minutes[minute] = minutes.get(minute, 0) + 1
            out.append(
                RollupDelta(
                    bucket_start=minute,
                    dim_hash=dim_hash,
                    dims=agg.dims,
                    requests=agg.requests,
                    caller_bytes_in=agg.caller_bytes_in,
                    caller_bytes_out=agg.caller_bytes_out,
                    upstream_calls=agg.upstream_calls,
                    upstream_bytes_in=agg.upstream_bytes_in,
                    upstream_bytes_out=agg.upstream_bytes_out,
                    errors=agg.errors,
                    latency_hist=histograms.encode(agg.latency) if agg.latency else None,
                    queue_wait_hist=histograms.encode(agg.queue_wait) if agg.queue_wait else None,
                )
            )
        if minutes:
            self.dims_last_minute = minutes[max(minutes)]
        return out

    def _drain_clients(self) -> list[ClientDelta]:
        with self._lock:
            pending, self._clients = self._clients, {}
            self._client_counts = {}
        out: list[ClientDelta] = []
        for (minute, ctype, key), agg in pending.items():
            top = max(agg.endpoints.items(), key=lambda kv: kv[1])[0] if agg.endpoints else None
            out.append(ClientDelta(minute, ctype, key, agg.requests, agg.refused, agg.served, agg.bytes, top))
        return out

    def _drain_egress(self) -> list[EgressDelta]:
        with self._lock:
            pending, self._egress = self._egress, {}
        return [EgressDelta(m, e, *values) for (m, e), values in pending.items()]

    def _drain_errors(self) -> list[ErrorDelta]:
        with self._lock:
            pending, self._errors = self._errors, {}
        return list(pending.values())

    # ------------------------------------------------------------------------------------------ lifecycle

    async def flush(self) -> Any:
        """Write everything collected so far (one transaction for metrics.db)."""
        return await self.batch.flush()

    def close(self) -> Any:
        """Shutdown: write everything, including the minute still open, synchronously (lifespan cleanup)."""
        self._closing = True
        return self.batch.flush_now()

    async def refresh_vocabulary(self) -> None:
        """Reset the template and host gates to the busiest values of the trailing 24 h (plan 6.2)."""
        from roxy.metrics import queries  # local import: queries imports this module's constants

        now = self.clock.now()
        templates, hosts = await self.dbs.metrics.read(
            lambda conn: (
                queries.top_values(conn, "endpoint_template", now - 86_400, now + 60, MAX_TEMPLATES),
                queries.top_values(conn, "host", now - 86_400, now + 60, MAX_HOSTS),
            )
        )
        self.templates.reset(templates)
        self.hosts.reset(hosts)
        self._last_vocab_refresh = self.clock.monotonic()

    async def run(self, stop: asyncio.Event) -> None:
        """Flush every `metrics_flush_interval_ms` and refresh the vocabulary hourly until `stop` is set."""
        while not stop.is_set():
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=self.config().flush_interval_s)
            try:
                await self.flush()
            except Exception:
                log.exception("metrics_flush_failed")
            due = self._last_vocab_refresh is None or self.clock.monotonic() - self._last_vocab_refresh >= (
                VOCABULARY_REFRESH_S
            )
            if due:
                try:
                    await self.refresh_vocabulary()
                except Exception as exc:
                    self._last_vocab_refresh = self.clock.monotonic()  # retry in an hour, not every flush
                    log.warning(
                        "vocabulary_refresh_failed", extra={"fields": {"error": f"{type(exc).__name__}: {exc}"}}
                    )

    def stats(self) -> dict[str, Any]:
        """The metrics pipeline card (System page): queue, drops, capture errors, dimension counts."""
        batch = self.batch.stats()
        with self._lock:
            pending = {
                "rollup_keys": len(self._rollups),
                "client_keys": len(self._clients),
                "aggregated_events": len(self._agg_events),
                "error_signatures": len(self._errors),
            }
        return {
            "worker_id": self.worker_id,
            "metrics_dropped": self.batch.dropped,
            "capture_errors": self.capture_errors,
            "record_errors": self.record_errors,
            "events_aggregated": self.events_aggregated,
            "live_sampled_out": self.live_sampled_out,
            "rollup_overflow": self.rollup_overflow,
            "dims_last_minute": self.dims_last_minute,
            "templates_known": len(self.templates),
            "templates_rejected": self.templates.rejected,
            "hosts_known": len(self.hosts),
            "fingerprints_dropped": self.fingerprints.dropped,
            "live_ring": len(self.live),
            "pending": pending,
            "batch": batch,
        }


def _complete_capture(capture: CaptureInput, ev: OutcomeEvent) -> CaptureInput:
    """Fill the summary fields a caller left empty from the outcome event (the event is the source of truth)."""
    return replace(
        capture,
        outcome=capture.outcome or str(ev.outcome),
        reason=capture.reason or str(ev.reason),
        status=capture.status or int(ev.status),
        method=capture.method or ev.method,
        url=capture.url or ev.path or ev.endpoint_template,
        query=capture.query or ev.query,
        ip=capture.ip or ev.client_ip,
        place_id=capture.place_id if capture.place_id is not None else ev.place_id,
        user_agent=capture.user_agent or ev.user_agent,
        upstream_status=capture.upstream_status if capture.upstream_status is not None else ev.upstream_status,
        egress=capture.egress or str(ev.egress),
    )


def build_recorder(ctx: Any) -> MetricsRecorder:
    """The worker's recorder from its `AppContext` (lifespan step "recorder", DESIGN.md section 1).

    Start `recorder.run(stop)` as a background loop and call `recorder.close()` at shutdown, after that loop has
    stopped, so the last seconds of numbers are written synchronously.
    """
    return MetricsRecorder(
        ctx.dbs,
        ctx.settings,
        ctx.clock,
        worker_id=getattr(ctx, "worker_id", ""),
        ip_hash_key=getattr(ctx, "ip_hash_key", None),
        rules=getattr(ctx, "rules", None),
    )


# ------------------------------------------------------------------------------------------- writers


def _detail_json(detail: Mapping[str, Any]) -> str:
    text = json.dumps(dict(detail), sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)
    return text


def _bounded_detail(record: EventRecord) -> str | None:
    detail = dict(record.detail)
    if record.count != 1:
        detail["count"] = int(record.count)
    if not detail:
        return None
    text = _detail_json(detail)
    # Event details may hold caller supplied text; scrub secrets and cap the size (plan P9).
    text = redact_text(text)
    if len(text) > MAX_DETAIL_CHARS:
        text = _detail_json({"truncated": True, "count": int(record.count), "text": text[:MAX_DETAIL_CHARS]})
    return text


def write_events(conn: Any, records: list[EventRecord]) -> None:
    """Batch writer handler for `events` (individual, aggregated and live rows)."""
    conn.executemany(
        "INSERT INTO events (at_ms, type, severity, reason_code, ip_hash, place, endpoint_template, detail_json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (r.at_ms, r.type, r.severity, r.reason_code, r.ip_hash, r.place, r.endpoint_template, _bounded_detail(r))
            for r in records
        ],
    )


def _write_429(conn: Any, rows: list[Upstream429Row]) -> None:
    conn.executemany(
        "INSERT INTO upstream_429 (at_ms, endpoint_template, host, egress, retry_after_s, ratelimit_headers_json, "
        "request_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
            (r.at_ms, r.endpoint_template, r.host, r.egress, r.retry_after_s, r.ratelimit_headers_json, r.request_id)
            for r in rows
        ],
    )


def _write_errors(conn: Any, rows: list[ErrorDelta]) -> None:
    conn.executemany(
        """
        INSERT INTO errors (signature, count, first_seen, last_seen, source, last_detail, module_line,
                            traceback_redacted)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (signature) DO UPDATE SET
            count = count + excluded.count, first_seen = min(first_seen, excluded.first_seen),
            last_seen = max(last_seen, excluded.last_seen), source = excluded.source,
            last_detail = CASE WHEN excluded.last_detail != '' THEN excluded.last_detail ELSE last_detail END,
            module_line = CASE WHEN excluded.module_line != '' THEN excluded.module_line ELSE module_line END,
            traceback_redacted = CASE WHEN excluded.traceback_redacted != '' THEN excluded.traceback_redacted
                                      ELSE traceback_redacted END
        """,
        [
            (
                r.signature,
                r.count,
                r.first_seen,
                r.last_seen,
                r.source,
                redact_text(r.last_detail)[:2000],
                r.module_line,
                redact_text(r.traceback)[:20_000],
            )
            for r in rows
        ],
    )
