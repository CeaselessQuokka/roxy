"""The metrics recorder: every number Roxy shows starts here, counted in memory and written in batches.

What this is
    `OutcomeEvent` (what the proxy reports once per request, DESIGN.md section 8) and `MetricsRecorder`, the one
    object per worker (`ctx.recorder`) that every package reports to: `record_outcome` for each proxy request,
    plus `record_event`, `record_upstream_429`, `record_internal_call`, `record_background_fetch`,
    `record_retry`, `record_egress_usage`, `record_error`, `record_fingerprint`, `record_capture`,
    `record_sample`, and the public-site and security helpers (`record_visit`, `record_probe`, `record_login`,
    `record_crawl`, `record_throttled`). Nothing here touches SQLite on the request path, and nothing heavier
    than a dict update runs there: capture rows are built on their own thread (`capture.CaptureEncoder`).

Why it exists
    Plan 6.3: writing a row per request would make every request wait for the disk and multiply write
    transactions by the request rate. Instead each worker adds numbers to a dict keyed by (minute, dimension
    hash), and the batch writer (`storage/batch.py`) upserts the dict every `metrics_flush_interval_ms`; two
    workers writing the same minute simply add up, so totals are exact with any number of workers (C6). Metrics
    fail open (C7): every `record_*` swallows its own errors and counts them, and never raises into a request.

How it works
    - Caller-supplied labels (template, host, place id, event reasons) are scrubbed like a log line before they
      become dimensions, event columns, samples or Live fields (`scrub_labels`, `core/redact.py redact_label`;
      plan C1 and 9.15): none of these passes the log filter. Ordinary values are unchanged.
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
    - Insight history (schema version 2, plan 11.1 and 11.5): bucket fill and rejections per minute
      (`record_reservation`, `record_bucket`), worker samples (`record_worker_sample`), shared cache stores,
      evictions and eviction passes (`record_cache_store`, `record_cache_eviction`, `record_eviction_pass`), rule
      hits (`record_rule_hit`), error occurrences per minute (inside `record_error`) and upstream calls by attempt
      (`record_attempts`, `record_attempt`). They are summed in bounded maps and written by one batch kind,
      `metrics.insight_history`, with upserts that add up across workers. The `note_*` module functions are the
      one-line producer hooks: they find the recorder and never raise.
    - `run(stop)` flushes on the configured interval and refreshes the vocabulary gates hourly. At shutdown the
      lifespan calls `aclose(budget_s=...)` after that loop stopped: one final flush, including the minute still
      open, so a recycle never loses buffered numbers. It never blocks the event loop and never outlives its
      budget, because every write of that flush carries what is left of the budget as its busy budget
      (`_ShutdownBudgetTarget`): a metrics.db locked by another process costs the budget, not SQLite's 5 s per
      write, and the numbers that could not be written are lost (metrics degrade open, C7; finding mp-6).
      `close()` is the synchronous form for scripts and tests.

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
import sqlite3
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any, TypeVar, cast

from roxy.core.clock import SYSTEM_CLOCK, Clock
from roxy.core.iphash import ip_hash
from roxy.core.reasons import AuthClass, CacheState, Egress, Outcome, ReasonCode, Source
from roxy.core.redact import MASK, is_secret_field, is_sensitive_key, redact_label, redact_text
from roxy.metrics import histograms, security_events, visitors
from roxy.metrics.activity import ip_key, place_key
from roxy.metrics.capture import (
    CaptureEncoder,
    CaptureInput,
    CapturePolicy,
    CaptureRow,
    make_row,
    trim_input,
    write_captures,
)
from roxy.metrics.fingerprints import FingerprintAggregator, FingerprintItem, write_fingerprints
from roxy.metrics.live import LIVE_EVENT, LIVE_EVENTS_PER_SECOND, LiveRing, RateGate, live_entry
from roxy.metrics.rollups import ClientDelta, EgressDelta, RollupDelta, write_clients, write_egress_usage, write_rollups
from roxy.metrics.samples import SampleRow, should_sample, write_samples
from roxy.metrics.templating import MAX_HOSTS, MAX_TEMPLATES, OTHER, TEMPLATE_VERSION, VocabularyGate, template_for
from roxy.storage.batch import BatchWriter
from roxy.storage.db import Database, Databases

log = logging.getLogger(__name__)

T = TypeVar("T")

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
FINAL_FLUSH_MAX_S = 4.0
"""Most the shutdown flush (`aclose`) may take: about half of the lifespan's 8 s shutdown budget, so the steps after
it (closing the egress clients, the notifier and the databases) keep time too."""
FINAL_FLUSH_GRACE_S = 0.5
"""How long `aclose` still waits for a write that started just before its budget ran out (that write's own busy
timeout is what was left of the budget, so it ends within moments)."""
ENCODER_SHUTDOWN_SHARE = 0.25
"""Part of the `aclose` budget queued captures may take to be built before the final write."""
MAX_HISTORY_KEYS = 20_000
"""Distinct keys held per insight history map between two flushes (plan P9); beyond it a sample is dropped and
counted in `history_dropped` (metrics degrade open, C7)."""
MAX_EVICTION_PASSES = 256
"""Eviction pass rows held between two flushes (one pass a minute fleet-wide, so this never fills in practice)."""
MAX_HISTORY_LABEL_CHARS = 255

# Batch kinds and their priorities (higher survives longer when the queue is full).
KIND_ROLLUPS = "metrics.rollups"
KIND_EGRESS = "metrics.egress_usage"
KIND_429 = "metrics.upstream_429"
KIND_CLIENTS = "metrics.clients"
KIND_HISTORY = "metrics.insight_history"
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
    KIND_HISTORY: 68,
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


@dataclass(slots=True)
class HistoryItem:
    """One row of an insight history table (schema version 2): `table` names it, `key` and `values` fill it.

    `write_history` turns it into an upsert: counts add up, peaks and maxima keep the larger value, so two workers
    writing the same minute end with the fleet total (C6).
    """

    table: str
    key: tuple[Any, ...]
    values: tuple[Any, ...]


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


class _ShutdownBudgetTarget:
    """metrics.db as the batch writer sees it: ordinary writes pass straight through; while `deadline` is set (the
    shutdown flush, `MetricsRecorder.aclose`) every write carries what is left until then as its busy budget.

    `Database.write(busy_timeout_ms=N)` treats N as one deadline from the call, queue wait and lock wait together,
    and a write still queued at it never runs (`storage/db.py`). Without it a metrics.db locked by another process
    (the other color's rollup, a backup) holds each write for SQLite's whole `busy_timeout` (5 s), past the lifespan
    shutdown budget (finding mp-6). Everything else (`name`, `read`, `write_sync`, ...) is the real database.
    """

    def __init__(self, db: Database) -> None:
        self.db = db
        self.name = db.name
        self.deadline: float | None = None  # time.monotonic() value; None outside the shutdown flush

    async def write(
        self,
        fn: Callable[[sqlite3.Connection], T],
        *,
        immediate: bool = True,
        busy_timeout_ms: int | None = None,
    ) -> T:
        deadline = self.deadline
        if busy_timeout_ms is None and deadline is not None:
            busy_timeout_ms = max(0, int((deadline - time.monotonic()) * 1000))
        return await self.db.write(fn, immediate=immediate, busy_timeout_ms=busy_timeout_ms)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.db, name)


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
        # Insight history (schema version 2), each map bounded by MAX_HISTORY_KEYS.
        self._bucket_minutes: dict[tuple[int, str], list[float]] = {}  # [attempts, rejections, fill_pct_peak]
        self._worker_minutes: dict[tuple[int, str], list[Any]] = {}  # [samples, cpu_sum, cpu_max, lag, conns, rss]
        self._cache_minutes: dict[int, list[float]] = {}  # [stores, evictions, young, age_sum, young_age_sum]
        self._eviction_passes: list[tuple[int, int, int, int, int]] = []
        self._rule_hits: dict[tuple[str, str], list[int]] = {}  # [hits, first_hit_at, last_hit_at]
        self._error_minutes: dict[tuple[str, int], int] = {}
        self._attempt_minutes: dict[tuple[Any, ...], int] = {}
        self.history_dropped = 0
        self._budgets: dict[tuple[str, str], RateGate] = {}
        self._live_gate = RateGate(LIVE_EVENTS_PER_SECOND, LIVE_EVENTS_PER_SECOND, self.clock.monotonic)
        self._closing = False
        self._last_vocab_refresh: float | None = None
        # Counters for the System page (per worker; exact values are not critical).
        self.capture_errors = 0
        self.capture_dropped = 0
        self.record_errors = 0
        self.events_aggregated = 0
        self.live_sampled_out = 0
        self.rollup_overflow = 0
        self.dims_last_minute = 0
        self._register_kinds()
        # Capture rows are built on the encoder's thread (LOOP-1). `make_row` is looked up when each capture is
        # built, so it stays this module's name for the function (tests wrap it to see which thread runs it).
        self.captures = CaptureEncoder(
            lambda row: self.batch.add(KIND_CAPTURES, row),
            encode=lambda inp, policy: make_row(inp, policy),
            on_error=self._capture_failed,
        )

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
        # Every kind writes through the shutdown budget wrapper (`aclose`); it is the real metrics.db otherwise.
        self._metrics_target = _ShutdownBudgetTarget(self.dbs.metrics)
        metrics = cast(Database, self._metrics_target)
        b = self.batch
        b.register(KIND_ROLLUPS, metrics, write_rollups, priority=PRIORITIES[KIND_ROLLUPS], source=self._drain_rollups)
        b.register(
            KIND_EGRESS, metrics, write_egress_usage, priority=PRIORITIES[KIND_EGRESS], source=self._drain_egress
        )
        b.register(KIND_429, metrics, _write_429, priority=PRIORITIES[KIND_429])
        b.register(KIND_CLIENTS, metrics, write_clients, priority=PRIORITIES[KIND_CLIENTS], source=self._drain_clients)
        b.register(KIND_HISTORY, metrics, write_history, priority=PRIORITIES[KIND_HISTORY], source=self._drain_history)
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
        # A label like "<credential piece>.roblox.com" is still a caller's text: scrub it like a log line (C1).
        return self.hosts.admit(redact_label(host))

    def _bounded_template(self, template: str, host: str) -> str:
        if template in PROBLEM_TEMPLATES:
            return template  # "(not_roblox)" and friends: a fixed, bounded set chosen by the proxy (plan P9)
        if host == OTHER or not template:
            return OTHER
        # Templates from `template_for` are already scrubbed; producers that pass their own are scrubbed here.
        return self.templates.admit(redact_label(template))

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
            ev = scrub_labels(ev)
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
            # A local OPTIONS answer never reached the cache or Roblox: not a proxied request to sample (spec-7).
            local = ev.reason == ReasonCode.OPTIONS_LOCAL
            if not local and should_sample(str(ev.outcome), cfg.request_sample_pct, self._rng):
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
        """Queue one event row, or add it to the per-minute sums. Returns True when written individually.

        The label columns (reason, place, template) may hold caller text (a header name, a crawled path, the
        `Roblox-Id` header), so they are scrubbed like a log line; `detail` is scrubbed when it is written.
        """
        reason_text = None if reason is None else redact_label(str(reason))[:MAX_SIGNATURE_CHARS]
        template = redact_label(endpoint_template)[:255] if endpoint_template else None
        place_text = redact_label(str(place))[:64] if place else None
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
        trigger: str = "",
    ) -> None:
        """One of Roxy's own upstream calls (probes, lookups): source `internal`, zero caller requests (P6).

        `elapsed_ms` is accepted as another name for `duration_ms`, and `endpoint` (a URL without its query, as
        the upstream service reports it) fills `host` and `endpoint_template` when those are not given. `trigger`
        says what started the call (`scheduled`, `health`, `admin`; CRED-PROBE-COST groups probes by it).
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
            if trigger:
                detail["trigger"] = str(trigger)[:32]
            if str(egress) == Egress.CREDENTIAL.value or str(auth_class) == AuthClass.CRED.value:
                detail["egress"] = Egress.CREDENTIAL.value
            summary: dict[str, Any] = {"ok": bool(ok)}
            if trigger:
                summary["trigger"] = detail["trigger"]
            if "egress" in detail:
                summary["egress"] = detail["egress"]
            self._event(when, INTERNAL_CALL_EVENT, "info" if ok else "warn", purpose[:60], detail,
                        summary_detail=summary)  # fmt: skip
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
                # When it happened, per minute (SYS-ERRORS compares the last hour with a 7-day hourly baseline).
                self._bump_locked(self._error_minutes, (sig, now // 60 * 60), 1)
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
        """Capture one request's bodies if the policy wants it. Returns the capture id or "". Never raises (127).

        Only the cheap part runs here, on the caller's thread: the policy decision and `trim_input`. Redaction,
        JSON and zstd run on the `CaptureEncoder` thread (LOOP-1); a full encoder queue drops the capture and
        counts it (`capture_dropped`) instead of making the request wait.
        """
        try:
            policy = self.config().capture
            if not policy.wants(outcome if outcome is not None else inp.outcome, self._rng):
                return ""
            if not self.captures.submit(trim_input(inp, policy), policy):
                self.capture_dropped += 1
                self._event(
                    _now_ms(self.clock), CAPTURE_ERROR_EVENT, "warn", None, {"reason": "encoder_queue_full"},
                    aggregate=True,
                )  # fmt: skip
                if self.capture_dropped == 1 or self.capture_dropped % 1000 == 0:
                    log.warning("capture_dropped", extra={"fields": {"capture_dropped": self.capture_dropped}})
                return ""
            return inp.request_id
        except Exception:
            self._capture_failed(None)
            return ""

    def _capture_failed(self, exc: BaseException | None) -> None:
        """A capture that could not be built (here or on the encoder thread): counted, logged, never raised."""
        self.capture_errors += 1
        with contextlib.suppress(Exception):
            self._event(_now_ms(self.clock), CAPTURE_ERROR_EVENT, "warn", None, None, aggregate=True)
        if self.capture_errors == 1 or self.capture_errors % 1000 == 0:
            info = exc if exc is not None else True
            log.warning("capture_failed", extra={"fields": {"capture_errors": self.capture_errors}}, exc_info=info)

    def record_sample(self, row: SampleRow) -> None:
        """Queue one explicit `request_samples` row (record_outcome samples proxied requests by itself)."""
        try:
            self.batch.add(KIND_SAMPLES, row)
        except Exception:
            self._count_error("record_sample")

    # --- insight history (schema version 2; plan 11.1, 11.5) ---

    def _bump_locked(self, table: dict[Any, int], key: Any, count: int) -> None:
        """Add `count` under `key` of a bounded counter map; caller holds `_lock`."""
        if key not in table and len(table) >= MAX_HISTORY_KEYS:
            self.history_dropped += 1
            return
        table[key] = table.get(key, 0) + int(count)

    def _minute_s(self, at_ms: int | None) -> int:
        when = int(at_ms if at_ms is not None else _now_ms(self.clock))
        return when // 60_000 * 60

    def record_bucket(
        self, bucket_key: str, *, attempts: int = 1, rejected: int = 0, fill_pct: float = 0.0, at_ms: int | None = None
    ) -> None:
        """One reservation against an upstream bucket (plan 7.3): attempts, rejections and the fill it saw."""
        try:
            key = (self._minute_s(at_ms), str(bucket_key)[:MAX_HISTORY_LABEL_CHARS])
            with self._lock:
                acc = self._bucket_minutes.get(key)
                if acc is None:
                    if len(self._bucket_minutes) >= MAX_HISTORY_KEYS:
                        self.history_dropped += 1
                        return
                    acc = self._bucket_minutes[key] = [0, 0, 0.0]
                acc[0] += max(0, int(attempts))
                acc[1] += max(0, int(rejected))
                acc[2] = max(acc[2], min(100.0, max(0.0, float(fill_pct))))
        except Exception:
            self._count_error("record_bucket")

    def record_reservation(self, specs: Iterable[Any], outcome: Any, *, now_ms: int | None = None) -> None:
        """A whole multi-bucket reservation (`upstream/buckets.py reserve`): one attempt on every bucket, the fill
        each bucket had after a grant, and a rejection on the bucket that bound a denial (its fill is 100%).

        A guard refusal (cooldown, breaker) or a lost lease asked no bucket, so it is not counted.
        """
        try:
            from roxy.upstream.buckets import gcra_fill  # local import: the upstream package imports metrics

            grant = getattr(outcome, "grant", None)
            denial = getattr(outcome, "denial", None)
            if grant is None and denial is None:
                return
            at = int(now_ms if now_ms is not None else getattr(grant, "now_ms", None) or _now_ms(self.clock))
            after = {key: tat for key, _interval, _before, tat in getattr(grant, "advanced", ())}
            binding = getattr(denial, "binding_key", "") if denial is not None else ""
            for spec in specs:
                if grant is not None:
                    fill = gcra_fill(after.get(spec.key, 0.0), spec, at) * 100.0
                    self.record_bucket(spec.key, fill_pct=fill, at_ms=at)
                else:
                    refused = spec.key == binding
                    self.record_bucket(spec.key, rejected=int(refused), fill_pct=100.0 if refused else 0.0, at_ms=at)
        except Exception:
            self._count_error("record_reservation")

    def record_worker_sample(
        self,
        *,
        worker_id: str | None = None,
        cpu_pct: float | None = None,
        loop_lag_ms_p99: float | None = None,
        open_conns: int | None = None,
        rss: int | None = None,
        at_ms: int | None = None,
    ) -> None:
        """One worker sample (SYS-WORKER-SAT, SYS-LOOP-LAG). Hook for the heartbeat; the minute keeps the mean CPU,
        the largest loop lag and connection count, and the last RSS."""
        try:
            key = (self._minute_s(at_ms), (worker_id or self.worker_id or "worker")[:MAX_HISTORY_LABEL_CHARS])
            with self._lock:
                acc = self._worker_minutes.get(key)
                if acc is None:
                    if len(self._worker_minutes) >= MAX_HISTORY_KEYS:
                        self.history_dropped += 1
                        return
                    acc = self._worker_minutes[key] = [0, 0.0, None, None, None, None]
                if cpu_pct is not None:
                    acc[0] += 1
                    acc[1] += float(cpu_pct)
                    acc[2] = float(cpu_pct) if acc[2] is None else max(acc[2], float(cpu_pct))
                if loop_lag_ms_p99 is not None:
                    acc[3] = float(loop_lag_ms_p99) if acc[3] is None else max(acc[3], float(loop_lag_ms_p99))
                if open_conns is not None:
                    acc[4] = int(open_conns) if acc[4] is None else max(acc[4], int(open_conns))
                if rss is not None:
                    acc[5] = int(rss)
        except Exception:
            self._count_error("record_worker_sample")

    def _cache_minute(self, at_ms: int | None) -> list[float] | None:
        """The accumulator of one cache minute; caller holds `_lock`."""
        minute = self._minute_s(at_ms)
        acc = self._cache_minutes.get(minute)
        if acc is None:
            if len(self._cache_minutes) >= MAX_HISTORY_KEYS:
                self.history_dropped += 1
                return None
            acc = self._cache_minutes[minute] = [0, 0, 0, 0.0, 0.0]
        return acc

    def record_cache_store(self, count: int = 1, *, at_ms: int | None = None) -> None:
        """Entries written to the shared cache tier (cache.db), the denominator of CACHE-PRESSURE."""
        try:
            with self._lock:
                acc = self._cache_minute(at_ms)
                if acc is not None:
                    acc[0] += max(0, int(count))
        except Exception:
            self._count_error("record_cache_store")

    def record_cache_eviction(self, *, age_s: float, ttl_s: float, count: int = 1, at_ms: int | None = None) -> None:
        """Entries evicted for space (not expiry); young ones (age below their TTL) mean the cache is too small."""
        try:
            n = max(0, int(count))
            young = float(age_s) < float(ttl_s)
            with self._lock:
                acc = self._cache_minute(at_ms)
                if acc is not None:
                    acc[1] += n
                    acc[3] += float(age_s) * n
                    if young:
                        acc[2] += n
                        acc[4] += float(age_s) * n
        except Exception:
            self._count_error("record_cache_eviction")

    def record_eviction_ages(
        self,
        *,
        evicted: int,
        young: int,
        age_s_total: float,
        young_age_s_total: float,
        at_ms: int | None = None,
    ) -> None:
        """The evicted entries of one eviction pass, summed (the same minute sums `record_cache_eviction` adds per
        entry): how many, how many were young (evicted before their TTL ran out), and their summed ages."""
        try:
            n = max(0, int(evicted))
            if n <= 0:
                return
            with self._lock:
                acc = self._cache_minute(at_ms)
                if acc is not None:
                    acc[1] += n
                    acc[2] += min(n, max(0, int(young)))
                    acc[3] += max(0.0, float(age_s_total))
                    acc[4] += max(0.0, float(young_age_s_total))
        except Exception:
            self._count_error("record_eviction_ages")

    def record_eviction_pass(self, report: Any, *, at_s: int | None = None) -> None:
        """One maintenance pass of the shared cache tier (`cache/store.py EvictionReport`), kept when it evicted."""
        try:
            evicted = int(getattr(report, "evicted", 0) or 0)
            if evicted <= 0:
                return
            row = (
                int(at_s if at_s is not None else self.clock.now()),
                int(getattr(report, "entries_before", 0) or 0),
                int(getattr(report, "bytes_before", 0) or 0),
                evicted,
                int(getattr(report, "freed_bytes", 0) or 0),
            )
            with self._lock:
                if len(self._eviction_passes) >= MAX_EVICTION_PASSES:
                    self.history_dropped += 1
                    return
                self._eviction_passes.append(row)
        except Exception:
            self._count_error("record_eviction_pass")

    def record_rule_hit(self, table: str, key: Any, *, count: int = 1, at_s: int | None = None) -> None:
        """A rule row matched a request (FILTER-REMOVE idle time, SEC-BYPASS-FOREVER last hit)."""
        try:
            now = int(at_s if at_s is not None else self.clock.now())
            slot = (str(table)[:64], str(key)[:MAX_HISTORY_LABEL_CHARS])
            with self._lock:
                acc = self._rule_hits.get(slot)
                if acc is None:
                    if len(self._rule_hits) >= MAX_HISTORY_KEYS:
                        self.history_dropped += 1
                        return
                    acc = self._rule_hits[slot] = [0, now, now]
                acc[0] += max(0, int(count))
                acc[1] = min(acc[1], now)
                acc[2] = max(acc[2], now)
        except Exception:
            self._count_error("record_rule_hit")

    def record_attempt(
        self,
        *,
        endpoint_template: str,
        egress: Egress | str,
        attempt: int,
        kind: str,
        status: int | None,
        challenge: bool = False,
        html_body: bool = False,
        exit_id: str = "",
        count: int = 1,
        at_ms: int | None = None,
    ) -> None:
        """One upstream HTTP call by attempt (first, csrf_retry, fallback_429, retry_5xx, redirect)."""
        try:
            template = redact_label(str(endpoint_template or OTHER))[:MAX_HISTORY_LABEL_CHARS]
            key = (
                self._minute_s(at_ms),
                template,
                str(egress)[:16],
                max(1, int(attempt)),
                str(kind)[:32],
                int(status) if status is not None else -1,
                1 if challenge else 0,
                1 if html_body else 0,
                str(exit_id or "")[:32],
            )
            with self._lock:
                self._bump_locked(self._attempt_minutes, key, max(0, int(count)))
        except Exception:
            self._count_error("record_attempt")

    def record_attempts(self, endpoint_template: str, trace: Any, *, at_ms: int | None = None) -> None:
        """Every call of one upstream trace (`upstream/trace.py Trace.calls`), classified by attempt kind.

        A CSRF retry repeats its attempt's number; a call after another attempt is `fallback_429` when the call
        before it was answered 429, otherwise `retry_5xx` (a 5xx, timeout or connect retry); a redirect hop is
        `redirect`. Rotator calls carry the session hash of the trace as `exit_id`.
        """
        try:
            calls = list(getattr(trace, "calls", ()) or ())
            identity = str(getattr(trace, "egress_identity", "") or "")
            exit_id = identity.split(":", 1)[1] if identity.startswith("rotator:") else ""
            previous: Any = None
            for call in calls:
                if getattr(call, "csrf_retry", False):
                    kind = "csrf_retry"
                elif getattr(call, "redirect_hop", 0):
                    kind = "redirect"
                elif int(getattr(call, "number", 1) or 1) <= 1 or previous is None:
                    kind = "first"
                elif getattr(previous, "status", None) == 429:
                    kind = "fallback_429"
                else:
                    kind = "retry_5xx"
                egress = str(getattr(call, "egress", "") or "none")
                self.record_attempt(
                    endpoint_template=endpoint_template,
                    egress=egress,
                    attempt=int(getattr(call, "number", 1) or 1),
                    kind=kind,
                    status=getattr(call, "status", None),
                    exit_id=exit_id if egress == Egress.ROTATOR.value else "",
                    at_ms=at_ms,
                )
                previous = call
        except Exception:
            self._count_error("record_attempts")

    def _drain_history(self) -> list[HistoryItem]:
        with self._lock:
            buckets, self._bucket_minutes = self._bucket_minutes, {}
            workers, self._worker_minutes = self._worker_minutes, {}
            caches, self._cache_minutes = self._cache_minutes, {}
            passes, self._eviction_passes = self._eviction_passes, []
            hits, self._rule_hits = self._rule_hits, {}
            errors, self._error_minutes = self._error_minutes, {}
            attempts, self._attempt_minutes = self._attempt_minutes, {}
        out: list[HistoryItem] = []
        out += [HistoryItem("bucket_minute", key, tuple(v)) for key, v in buckets.items()]
        out += [HistoryItem("worker_minute", key, tuple(v)) for key, v in workers.items()]
        out += [HistoryItem("cache_minute", (minute,), tuple(v)) for minute, v in caches.items()]
        out += [HistoryItem("cache_eviction_passes", (), row) for row in passes]
        out += [HistoryItem("rule_hits", key, tuple(v)) for key, v in hits.items()]
        out += [HistoryItem("error_minute", key, (n,)) for key, n in errors.items()]
        out += [HistoryItem("upstream_attempt_minute", key, (n,)) for key, n in attempts.items()]
        return out

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
        """Write everything collected so far (one transaction for metrics.db).

        Captures still on the encoder thread are waited for first (bounded, without blocking the loop), so a
        capture lands in the same flush as the numbers of its request.
        """
        await self.captures.drain()
        return await self.batch.flush()

    def close(self) -> Any:
        """Write everything, including the minute still open, synchronously (scripts and tests; the server's
        lifespan uses `aclose`, which never blocks the event loop)."""
        self._closing = True
        self.captures.close()
        return self.batch.flush_now()

    async def aclose(self, *, budget_s: float = FINAL_FLUSH_MAX_S) -> Any:
        """Shutdown (lifespan): the final flush, including the minute still open, within `budget_s` seconds.

        Captures still on the encoder thread get a part of the budget, then everything queued is written with
        every write's busy budget cut to what is left (`_ShutdownBudgetTarget`), so a locked metrics.db costs at most
        `budget_s` and the event loop never waits on SQLite. Numbers that cannot be written in time are lost and
        counted in `metrics_final_flush_incomplete` (metrics degrade open, C7). Returns the flush result, or None
        when even the backstop timeout ran out. Never raises.
        """
        self._closing = True
        budget = max(0.0, float(budget_s))
        deadline = time.monotonic() + budget
        try:
            await self.captures.drain(min(ENCODER_SHUTDOWN_SHARE * budget, budget))
            # The encoder thread may still be building one capture; joining it must not hold the loop.
            await asyncio.to_thread(self.captures.close, max(0.0, deadline - time.monotonic()) / 2)
        except Exception:
            log.exception("capture_encoder_close_failed")
        self._metrics_target.deadline = deadline
        result: Any = None
        try:
            # The busy budgets end the writes by the deadline; this timeout is only a backstop for a write that
            # had started just before it (its own busy timeout is what was left, so it ends at once).
            result = await asyncio.wait_for(
                self.batch.flush(), timeout=max(0.0, deadline - time.monotonic()) + FINAL_FLUSH_GRACE_S
            )
        except TimeoutError:
            log.warning("metrics_final_flush_timeout", extra={"fields": {"budget_s": round(budget, 3)}})
        except Exception:
            log.exception("metrics_final_flush_failed")
        finally:
            self._metrics_target.deadline = None
        left = self.batch.queued()
        if left or result is None or getattr(result, "failed_dbs", None):
            log.warning(
                "metrics_final_flush_incomplete",
                extra={"fields": {"items_not_written": left, "budget_s": round(budget, 3)}},
            )
        return result

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
        """Flush every `metrics_flush_interval_ms` and refresh the vocabulary hourly until `stop` is set.

        A stop request ends the loop without one more flush: the final flush is `aclose` (or `close`), which runs
        right after with the shutdown budget, so a locked metrics.db is not waited for twice (finding mp-6).
        """
        while not stop.is_set():
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=self.config().flush_interval_s)
            if stop.is_set():
                return
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
            "capture_dropped": self.capture_dropped,
            "capture_encoder": self.captures.stats(),
            "record_errors": self.record_errors,
            "events_aggregated": self.events_aggregated,
            "live_sampled_out": self.live_sampled_out,
            "rollup_overflow": self.rollup_overflow,
            "history_dropped": self.history_dropped,
            "dims_last_minute": self.dims_last_minute,
            "templates_known": len(self.templates),
            "templates_rejected": self.templates.rejected,
            "hosts_known": len(self.hosts),
            "fingerprints_dropped": self.fingerprints.dropped,
            "live_ring": len(self.live),
            "pending": pending,
            "batch": batch,
        }


def scrub_labels(ev: OutcomeEvent) -> OutcomeEvent:
    """`ev` with its caller-supplied labels (template, host, place id) scrubbed like a log line (plan C1, 9.15).

    These three become metric dimensions, client rows, event columns, request samples and Live fields, none of
    which passes the log filter, so a credential piece in a path segment or the `Roblox-Id` header must be removed
    here. Ordinary values come back unchanged (and the same event object is returned), so v1 templates and place
    ids are stored exactly as before.
    """
    template = redact_label(ev.endpoint_template) if ev.endpoint_template else ev.endpoint_template
    host = redact_label(ev.host) if ev.host else ev.host
    place = redact_label(ev.place_id) if ev.place_id else ev.place_id
    if template == ev.endpoint_template and host == ev.host and place == ev.place_id:
        return ev
    return replace(ev, endpoint_template=template, host=host, place_id=place)


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

    Start `recorder.run(stop)` as a background loop and await `recorder.aclose(budget_s=...)` at shutdown, after that
    loop has stopped, so the last seconds of numbers are written within the shutdown budget.
    """
    return MetricsRecorder(
        ctx.dbs,
        ctx.settings,
        ctx.clock,
        worker_id=getattr(ctx, "worker_id", ""),
        ip_hash_key=getattr(ctx, "ip_hash_key", None),
        rules=getattr(ctx, "rules", None),
    )


# ------------------------------------------------------------------------------- one-line producer hooks
#
# Producers call these with one line each (`note_reservation(self._ctx, specs, outcome)`): they find the recorder
# (an `AppContext`, a recorder, or None), call it, and never raise into the request (metrics degrade open, C7).


def _recorder_of(owner: Any) -> Any:
    if owner is None:
        return None
    if isinstance(owner, MetricsRecorder):
        return owner
    return getattr(owner, "recorder", None)


def note_reservation(owner: Any, specs: Iterable[Any], outcome: Any) -> None:
    """Upstream bucket reservation (`upstream/service.py _reserve`): attempts, rejections, fill per bucket."""
    record = getattr(_recorder_of(owner), "record_reservation", None)
    if record is not None:
        with contextlib.suppress(Exception):
            record(specs, outcome)


def note_attempts(owner: Any, endpoint_template: str, trace: Any) -> None:
    """Every call of one finished upstream fetch (`upstream/service.py _guarded`)."""
    record = getattr(_recorder_of(owner), "record_attempts", None)
    if record is not None:
        with contextlib.suppress(Exception):
            record(endpoint_template or OTHER, trace)


def note_cache_store(owner: Any, written: bool) -> None:
    """One entry written to cache.db (`cache/service.py _write_shared`)."""
    record = getattr(_recorder_of(owner), "record_cache_store", None)
    if record is not None and written:
        with contextlib.suppress(Exception):
            record(1)


def note_eviction_pass(owner: Any, report: Any) -> None:
    """One eviction pass of cache.db (`cache/service.py maintain`)."""
    record = getattr(_recorder_of(owner), "record_eviction_pass", None)
    if record is not None:
        with contextlib.suppress(Exception):
            record(report)


def note_eviction_ages(owner: Any, report: Any) -> None:
    """The ages of one pass's evicted entries (`cache/service.py maintain`; CACHE-PRESSURE "young evictions")."""
    record = getattr(_recorder_of(owner), "record_eviction_ages", None)
    if record is not None and int(getattr(report, "evicted", 0) or 0) > 0:
        with contextlib.suppress(Exception):
            record(
                evicted=int(report.evicted),
                young=int(getattr(report, "young", 0) or 0),
                age_s_total=float(getattr(report, "age_s_total", 0.0) or 0.0),
                young_age_s_total=float(getattr(report, "young_age_s_total", 0.0) or 0.0),
            )


def note_rule_hit(owner: Any, table: str, key: Any) -> None:
    """A rule row matched a request (abuse checks)."""
    record = getattr(_recorder_of(owner), "record_rule_hit", None)
    if record is not None:
        with contextlib.suppress(Exception):
            record(table, key)


# ------------------------------------------------------------------------------------------- writers

_HISTORY_SQL: dict[str, str] = {
    "bucket_minute": (
        "INSERT INTO bucket_minute (bucket_start, bucket_key, attempts, rejections, fill_pct_peak) "
        "VALUES (?, ?, ?, ?, ?) ON CONFLICT (bucket_start, bucket_key) DO UPDATE SET "
        "attempts = attempts + excluded.attempts, rejections = rejections + excluded.rejections, "
        "fill_pct_peak = max(fill_pct_peak, excluded.fill_pct_peak)"
    ),
    "worker_minute": (
        "INSERT INTO worker_minute (bucket_start, worker_id, samples, cpu_pct_sum, cpu_pct_max, loop_lag_ms_p99, "
        "open_conns, rss) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (bucket_start, worker_id) DO UPDATE SET "
        "samples = samples + excluded.samples, cpu_pct_sum = cpu_pct_sum + excluded.cpu_pct_sum, "
        "cpu_pct_max = max(coalesce(cpu_pct_max, excluded.cpu_pct_max), coalesce(excluded.cpu_pct_max, cpu_pct_max)), "
        "loop_lag_ms_p99 = max(coalesce(loop_lag_ms_p99, excluded.loop_lag_ms_p99), "
        "coalesce(excluded.loop_lag_ms_p99, loop_lag_ms_p99)), "
        "open_conns = max(coalesce(open_conns, excluded.open_conns), coalesce(excluded.open_conns, open_conns)), "
        "rss = coalesce(excluded.rss, rss)"
    ),
    "cache_minute": (
        "INSERT INTO cache_minute (bucket_start, stores, evictions, young_evictions, evicted_age_s_sum, "
        "young_age_s_sum) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (bucket_start) DO UPDATE SET "
        "stores = stores + excluded.stores, evictions = evictions + excluded.evictions, "
        "young_evictions = young_evictions + excluded.young_evictions, "
        "evicted_age_s_sum = evicted_age_s_sum + excluded.evicted_age_s_sum, "
        "young_age_s_sum = young_age_s_sum + excluded.young_age_s_sum"
    ),
    "cache_eviction_passes": (
        "INSERT INTO cache_eviction_passes (at, entries_before, bytes_before, evicted, freed_bytes) "
        "VALUES (?, ?, ?, ?, ?)"
    ),
    "rule_hits": (
        "INSERT INTO rule_hits (table_name, rule_key, hits, first_hit_at, last_hit_at) VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT (table_name, rule_key) DO UPDATE SET hits = hits + excluded.hits, "
        "first_hit_at = min(coalesce(first_hit_at, excluded.first_hit_at), excluded.first_hit_at), "
        "last_hit_at = max(coalesce(last_hit_at, excluded.last_hit_at), excluded.last_hit_at)"
    ),
    "error_minute": (
        "INSERT INTO error_minute (signature, bucket_start, count) VALUES (?, ?, ?) "
        "ON CONFLICT (signature, bucket_start) DO UPDATE SET count = count + excluded.count"
    ),
    "upstream_attempt_minute": (
        "INSERT INTO upstream_attempt_minute (bucket_start, endpoint_template, egress, attempt, kind, status, "
        "challenge, html_body, exit_id, count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (bucket_start, "
        "endpoint_template, egress, attempt, kind, status, challenge, html_body, exit_id) DO UPDATE SET "
        "count = count + excluded.count"
    ),
}


def write_history(conn: Any, items: list[HistoryItem]) -> None:
    """Batch writer handler for every insight history table (one statement per table, upserts add up)."""
    grouped: dict[str, list[tuple[Any, ...]]] = {}
    for item in items:
        if item.table in _HISTORY_SQL:
            grouped.setdefault(item.table, []).append((*item.key, *item.values))
    for table, rows in grouped.items():
        conn.executemany(_HISTORY_SQL[table], rows)


def _detail_json(detail: Mapping[str, Any]) -> str:
    text = json.dumps(dict(detail), sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)
    return text


_SCRUB_MAX_DEPTH = 8
"""How deep `_scrub_detail` walks a detail document; anything deeper is replaced (details are small and flat)."""


def _scrub_detail(value: Any, depth: int = 0) -> Any:
    """One detail value with every secret replaced, structure kept (the fallback of `_bounded_detail`).

    Strings go through `redact_text`, keys too, and a value under a secret-shaped field name (`is_secret_field`)
    becomes `[redacted]`, whatever its type, exactly what `redact_text` does to a `"name": value` pair in text.
    """
    if depth > _SCRUB_MAX_DEPTH:
        return MASK
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for key, item in value.items():
            name = str(key)
            secret = is_secret_field(name, item) and item not in (None, "")
            out[redact_text(name)] = MASK if secret else _scrub_detail(item, depth + 1)
        return out
    if isinstance(value, list | tuple):
        return [_scrub_detail(item, depth + 1) for item in value]
    return value


def _bounded_detail(record: EventRecord) -> str | None:
    detail = dict(record.detail)
    if record.count != 1:
        detail["count"] = int(record.count)
    if not detail:
        return None
    text = _detail_json(detail)
    # Event details may hold caller supplied text; scrub secrets and cap the size (plan P9).
    redacted = redact_text(text)
    if redacted != text:
        # Redacting the serialized text can cut through the JSON syntax: `{"pass": 6}` (a count under a key that
        # reads as a secret) became `{"pass": [redacted]}`, which the live tail and the SSE stream then read as
        # `{}`. When that happens the detail is scrubbed value by value instead, so the stored text is always JSON.
        try:
            json.loads(redacted)
        except ValueError:
            redacted = _detail_json(_scrub_detail(detail))
    text = redacted
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
