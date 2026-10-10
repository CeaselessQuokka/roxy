"""Data API (`/admin/api/v1/data`): storage use, retention, granular resets with preview, backups and VACUUM.

What this is
    The routes behind the Data page (plan 14.1, 6.6, 6.8, 6.10, 17.5; parity rows 83 and 133):
      * `GET /data/storage`: every database file (bytes, WAL) and every table with rows, bytes, oldest row and a
        30 day projection (`storage/read_sizes.py`), the disk budget and its use; `format=csv|json` downloads it.
      * `GET /data/retention`: every setting of the Data page's retention and record cap cards (plan 6.10: max
        ages, row caps, file limits; the catalog's `data#retention` and `data#record-caps` pages) with their values,
        and each table's state against its limits; edits go through the settings API.
      * `GET /data/resets`: every reset scope of plan 6.8, its families (narrower ones name their `parent`) and
        options, and `V1_CLEAR_TARGETS` (where each of v1's 27 clear targets went; `scope` None: nothing to reset).
        `POST /data/resets/preview` answers the exact rows per table and their date range, what is left alone,
        whether a snapshot will be taken, and the phrase to type for a destructive full reset. `POST /data/resets`
        runs it (with the preview's digest, a reason, and the typed phrase when one is asked for);
        `POST /data/resets/factory` runs the factory reset, which also needs a fresh second factor (plan 9.6) and a
        control.db snapshot.
      * `GET /data/backups` (the nightly backups recorded by `backup.sh`, the last "back up now" request it
        answered, and the snapshots on this server) and `POST /data/backups` ("back up now": a `VACUUM INTO`
        snapshot of control.db and metrics.db here, and a request file the root backup's path unit watches).
      * `GET /data/vacuum` (size, reclaimable space and an estimated time per database) and `POST /data/vacuum`.
      * `GET /data/operations/{id}`: the progress or result of a reset, a backup or a VACUUM.

Why it exists
    v1 had 27 "Clear data" targets that wiped in-memory dictionaries with a browser `confirm()`. Plan 6.8 replaces
    them with granular resets that show a preview first ("This will delete 48,211 rows from 3 tables covering
    2026-09-01 to 2026-09-30. Rules and settings are not affected."), ask to type the scope name for a destructive
    full reset, take a snapshot first where feasible so a reset can be undone, write an annotation (every chart
    shows a "data reset" marker) and audit the exact rows deleted per table.

How it works
    * A scope becomes a plan: SQL parts (`Part`: one table, a fixed WHERE clause with bound parameters, the row
      identity used for batched deletes, and `match`, the same rows as column values for the recorder's reset
      fence) plus service actions (a cache purge through `CacheService.purge`, the upstream reset through
      `UpstreamService.reset_state`, bans and the factory rule reset in one control.db transaction with an audit
      row and a `config_version` bump, the settings reset through `SettingsService.import_overrides`). Table names
      and clauses are constants of this module, never request text; request values are always parameters. Most
      parts delete; two rewrite rollup rows instead and keep their request counts: `clear_latency` (the latency
      family) empties the histograms, `clear_cache_state` (the cache statistics family, v1 "Clear stats") moves the
      requests of every cache lookup state to `recorder.CLEARED_CACHE_STATE`, merging rows that meet.
    * The preview counts each part (`count(*)`, `min` and `max` of its time column) and the actions' targets, and
      returns a digest of the normalized scope; running a reset requires that digest, so it can only run what was
      previewed. The intent audit row (`data.reset`, with the planned counts) is written before anything is
      deleted, and a refusal to write it (C7) means nothing is deleted (503).
    * The work runs as a background operation (`ctx.tasks.spawn`), so a reset of a large metrics.db is never cut off
      by the request deadline: snapshots first (`VACUUM INTO <state dir>/snapshots/reset-<time>-<db>.db` on a
      maintenance connection, only of a database that loses rows, and only while the snapshots folder stays within
      `snapshots_max_bytes`; cache.db and hot.db are never snapshotted, plan 17.5). Then the reset fence: a reset
      that touches metrics.db rows the recorder writes appends a fence to `service_state` (`recorder.RESET_FENCE_KEY`)
      and flushes this worker's recorder, so no worker's unflushed counts from before the reset are written back
      afterwards (finding parity-4, v1's `ClearEpochs`). Then the chart marker (`annotations`, kind `reset` when
      counters go, else `config_change`, P6), written BEFORE the first delete and linked to the intent row, so a
      reset that fails midway still marks what it deleted (finding mpjobs-4): on success it links to the
      `data.reset.done` row, on a failure that deleted something it is labeled incomplete and links to the
      `data.reset.failed` row, and when nothing was deleted it is removed. Then batches of 5,000 rows, each its
      own short write transaction with a yield between batches (the hot path keeps writing). The POST waits up to
      `INLINE_WAIT_S` and answers the result, or 202 with the operation id. One reset or backup runs at a time
      fleet-wide (the hot.db lease `ResetLease`, also taken by the internal socket's resets). Each worker's
      in-memory tarpit counters are cleared through `service_state` (`system.py`).
    * Back up now takes the same lease and, right after its audited intent, writes `<state dir>/backup-request`
      (`{requested_at, by, audit_id}`, mode 0640, renamed into place, as `scripts/ctl.py write_backup_request`
      does), which `roxy-backup-request.path` turns into a run of the root backup; `backup.sh` records what it did
      with the request under `last_request` in `audit/backup.json`. The request is written whatever the local plan
      says (finding secfix-4). The on-server copies count what the snapshots folder already holds against
      `snapshots_max_bytes` and make room by removing Back up now's own oldest copies (`manual-*`; reset and
      pre-migration snapshots are never removed here); a copy that still does not fit is skipped with its reason
      (finding apisec-5). 409 `not_feasible` only when neither the request nor any copy could be made.

    * The Data dashboard page (`roxy/admin/pages/data.py`) reads through the same functions as these routes
      (`reset_catalog`, `measure_storage` and `storage_rows`, `retention_answer`, `backups_answer`,
      `vacuum_answer`) and changes nothing itself: its forms post to these routes (P6, DESIGN.md 13).

What to read next
    `roxy/storage/read_sizes.py`, `roxy/metrics/recorder.py` (the reset fences), `roxy/metrics/annotate.py`,
    `roxy/cache/read_purge_counts.py`, `roxy/storage/retention.py`, `roxy/admin/api/system.py` (the per-worker
    watcher), `roxy/admin/api/common.py`.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import re
import secrets
import shutil
import sqlite3
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Final, Literal

from fastapi import Path as PathParam
from fastapi import Request
from pydantic import Field
from starlette.responses import JSONResponse

from roxy.admin.api import common
from roxy.admin.api.common import (
    AdminFreshMfa,
    AdminSession,
    ApiBody,
    Column,
    CsrfChecked,
    ExportFormatDep,
    TableQuery,
    TableSpec,
    actor_for,
    request_id_of,
)
from roxy.admin.api.settings import settings_service
from roxy.admin.api.system import MEMORY_FAMILIES, request_memory_reset
from roxy.cache.read_purge_counts import purge_preview
from roxy.cache.store import PurgeScope
from roxy.config import audit, catalog, read_audit
from roxy.config.audit import Actor
from roxy.config.constants import MAX_REASON_LENGTH
from roxy.config.defaults import SEED_MARKER_KEY, seed_defaults
from roxy.config.runtime import bump_config_version
from roxy.core.client_ip import limit_key, normalize_ip
from roxy.core.iphash import ip_hash
from roxy.core.reasons import Egress
from roxy.deps import get_ctx
from roxy.metrics.activity import ip_key, place_key
from roxy.metrics.annotate import delete_annotation, insert_annotation, update_annotation
from roxy.metrics.histograms import register_sql_functions
from roxy.metrics.recorder import (
    CACHE_LOOKUP_STATES,
    CLEARED_CACHE_STATE,
    FENCED_TABLES,
    MAX_FENCE_SELECTORS,
    MAX_RESET_FENCES,
    RESET_FENCE_KEY,
    dims_hash,
)
from roxy.metrics.rollups import DIM_COLUMNS, PAIR_CLIENT_TYPE, PAIR_SEPARATOR, ROLLUP_SUMS, zone
from roxy.rules.match import PatternValidationError
from roxy.rules.models import RULE_TABLES
from roxy.storage import leases, read_sizes, retention
from roxy.storage.db import Database, SharedStateUnavailable
from roxy.upstream import breaker, cooldowns

router = common.area_router("data")

# ================================================================================================ constants

DAY_S: Final = 86_400
BATCH_ROWS: Final = retention.BATCH_ROWS
"""Rows deleted per write transaction (the retention job and Purge All use the same size, plan 6.5)."""

BATCH_PAUSE_S: Final = 0.01
INLINE_WAIT_S: Final = 5.0
"""How long `POST /data/resets` (and backups, VACUUM) waits for its operation before answering 202."""

MAX_OPERATIONS: Final = 32
"""Operations each worker remembers for `GET /data/operations/{id}` (plan P9); older ones live in the audit log."""

STORAGE_CACHE_S: Final = 60.0
"""A storage measurement is reused this long (it scans every table on a maintenance connection)."""

STORAGE_MIN_REFRESH_S: Final = 10.0
"""A forced refresh (`refresh=true`) reuses a measurement younger than this."""

STORAGE_CACHE_ATTRIBUTE: Final = "_admin_data_storage_cache"

RESET_LEASE: Final = "data_reset"
RESET_LEASE_TTL_MS: Final = 30 * 60 * 1000
LEASE_RENEW_S: Final = 60.0
"""One reset or backup at a time fleet-wide: a hot.db lease, renewed while the operation runs."""

SNAPSHOT_DBS: Final = ("control", "metrics")
"""Databases worth a snapshot (cache.db is disposable and hot.db is short-lived state, plan 17.5)."""

SNAPSHOT_MIN_FREE_BYTES: Final = 64 * 1024 * 1024
MANUAL_SNAPSHOT_PREFIX: Final = "manual-"
"""Back up now's own copies: the only snapshots it removes to make room (oldest first)."""

BACKUP_REQUEST_NAME: Final = "backup-request"
"""`<state dir>/backup-request`, the file `roxy-backup-request.path` watches (same name as `scripts/ctl.py`)."""
BACKUP_REQUEST_MAX_BYTES: Final = 4096
"""Most of a pending request file that is read back (`backup.sh` reads the same at most)."""

NON_COUNTER_TABLES: Final = frozenset(
    {"recommendations", "recommendation_actions", "recommendation_watches", "health_runs", "health_results"}
)
"""metrics.db tables that hold no counters a KPI reads: a reset of only these marks charts as `config_change`."""
VACUUM_BYTES_PER_S: Final = 40 * 1024 * 1024
"""A conservative copy rate for the VACUUM time estimate (SSD on a 2 vCPU server); shown as an estimate."""

VACUUM_DBS: Final = ("control", "metrics", "cache")
"""hot.db is never vacuumed from the dashboard: its write lock would stall every proxied request."""

AUDIT_RESET: Final = "data.reset"
AUDIT_RESET_DONE: Final = "data.reset.done"
AUDIT_RESET_FAILED: Final = "data.reset.failed"
AUDIT_BACKUP: Final = "data.backup"
AUDIT_VACUUM: Final = "data.vacuum"
MAX_LABEL_CHARS: Final = 200
_ID_RE: Final = re.compile(r"[a-z0-9_]{1,40}")
_PLACEHOLDER_RE: Final = re.compile(r"\{[A-Za-z0-9_]{1,40}\}")
_PREFIX_END: Final = "\U0010ffff"

ROLLUPS: Final = ("rollup_minute", "rollup_hour", "rollup_day", "rollup_month")
ROLLUP_KEY: Final = "bucket_start, dim_hash"
CLIENTS: Final = ("client_minute", "client_hour", "client_day")
CLIENT_KEY: Final = "bucket_start, client_type, client_key"

PartAction = Literal["delete", "clear_latency", "clear_cache_state"]
CHANGE_WORDS: Final[dict[str, str]] = {
    "clear_latency": "the latency histograms",
    "clear_cache_state": "the cache state",
}
"""How the preview summary names what a rewriting part clears (`total_rows` counts them; `changed_rows` too)."""


# ================================================================================================ plan parts


@dataclass(frozen=True, slots=True)
class Part:
    """One table's share of a reset: rows of `table` in database `db` matching `where` (bound `params`).

    `key` is the row identity for batched deletes (`rowid`, or a WITHOUT ROWID table's primary key columns);
    `time_col` and `unit` let a date range apply (a part without one is skipped under a date range);
    `action` is `delete`, `clear_latency` (keep the rows, empty their latency and queue wait histograms) or
    `clear_cache_state` (keep the requests, move the rows of the cache lookup states to `CLEARED_CACHE_STATE`).
    `match` says which rows `where` selects as column values (`((column, (value, ...)), ...)`, every column must
    match), so the recorder can fence its unflushed items the same way (`fence_selectors`); None means "every row"
    when `where` is "1" and "no fence" otherwise (a test checks every part a fence needs has its `match`).
    """

    db: str
    table: str
    key: str
    where: str = "1"
    params: tuple[Any, ...] = ()
    time_col: str | None = None
    unit: Literal["s", "ms"] = "s"
    action: PartAction = "delete"
    match: tuple[tuple[str, tuple[Any, ...]], ...] | None = None


def _events(*types: str) -> Part:
    marks = ", ".join("?" for _ in types)
    return Part(
        "metrics", "events", "rowid", f"type IN ({marks})", tuple(types), "at_ms", "ms", match=(("type", types),)
    )


def _refusals(*reasons: str) -> Part:
    """Refusal events with one of `reasons` (the attempts tabs of the Protection page, v1's per-tab clears)."""
    marks = ", ".join("?" for _ in reasons)
    return Part(
        "metrics",
        "events",
        "rowid",
        f"type = 'refusal' AND reason_code IN ({marks})",
        tuple(reasons),
        "at_ms",
        "ms",
        match=(("type", ("refusal",)), ("reason_code", reasons)),
    )


def _rollups(
    where: str = "1",
    params: tuple[Any, ...] = (),
    action: PartAction = "delete",
    match: tuple[tuple[str, tuple[Any, ...]], ...] | None = None,
) -> tuple[Part, ...]:
    return tuple(Part("metrics", t, ROLLUP_KEY, where, params, "bucket_start", "s", action, match) for t in ROLLUPS)


_LOOKUP_STATES_SQL: Final = ", ".join(f"'{state}'" for state in CACHE_LOOKUP_STATES)
"""The cache lookup states as SQL literals (module constants of the recorder, never request text)."""


ATTEMPT_KEY: Final = "bucket_start, endpoint_template, egress, attempt, kind, status, challenge, html_body, exit_id"
"""The primary key of `upstream_attempt_minute` (a WITHOUT ROWID table)."""


def _dims(where: str) -> str:
    """Rollup rows whose dimensions match `where` (a constant of this module; values stay parameters)."""
    return f"dim_hash IN (SELECT dim_hash FROM dims WHERE {where})"  # noqa: S608 (module constants)


@dataclass(frozen=True, slots=True)
class Family:
    """A metric family of plan 6.8 and the card that shows it.

    `parent` names the family a narrower one is part of: v1 cleared each attempts tab, the throttled clients and the
    throttle rule hits on their own (parity-9, C3), so those clears map to part of the plan 6.8 family.
    """

    name: str
    label: str
    card: str
    parts: tuple[Part, ...]
    memory: tuple[str, ...] = ()
    note: str = ""
    parent: str | None = None


FAMILIES: Final[dict[str, Family]] = {
    f.name: f
    for f in (
        Family(
            "traffic",
            "Traffic",
            "traffic#requests",
            _rollups(),
            note=(
                "Traffic rows also hold the latency, cache and upstream numbers of the same requests; they go "
                "with them."
            ),
        ),
        Family(
            "latency",
            "Latency",
            "traffic#latency",
            _rollups("latency_hist IS NOT NULL OR queue_wait_hist IS NOT NULL", action="clear_latency", match=()),
            note="Request counts are kept; only the latency and queue wait histograms are emptied.",
        ),
        Family(
            "cache_stats",
            "Cache statistics",
            "cache#stats",
            (
                *_rollups(
                    _dims(f"cache_state IN ({_LOOKUP_STATES_SQL})"),
                    action="clear_cache_state",
                    match=(("cache_state", CACHE_LOOKUP_STATES),),
                ),
                Part("metrics", "cache_minute", "rowid", time_col="bucket_start"),
                Part("metrics", "cache_eviction_passes", "rowid", time_col="at"),
                Part("cache", "change_observations", "endpoint_template, day", time_col="day"),
            ),
            note=(
                "Hits, misses, stale and coalesced answers are cleared together, as v1's Clear stats did: hit ratios "
                "start again from the next lookup. The requests stay in every Traffic total (their cache state "
                "reads cleared). Cached entries are kept (use the cache scope to remove them)."
            ),
        ),
        Family(
            "upstream",
            "Upstream",
            "upstream#calls",
            (
                Part("metrics", "upstream_429", "rowid", time_col="at_ms", unit="ms"),
                Part("metrics", "upstream_attempt_minute", ATTEMPT_KEY, time_col="bucket_start"),
                Part("metrics", "bucket_minute", "bucket_start, bucket_key", time_col="bucket_start"),
                _events("failure", "upstream_retry"),
            ),
            note="Call counts inside the traffic rows are kept (they belong to the requests that made them).",
        ),
        Family(
            "egress_usage",
            "Egress usage",
            "egress#usage",
            (Part("metrics", "egress_usage", "bucket_start, egress, granularity", time_col="bucket_start"),),
            note="The rotator quota count of the current billing cycle starts again from what is left.",
        ),
        Family(
            "tarpit",
            "Tarpit",
            "protection#tarpit",
            (
                Part(
                    "hot",
                    "limiter",
                    "bucket_key",
                    "bucket_key >= ? AND bucket_key < ?",
                    ("tarpit_arrival:", "tarpit_arrival:" + _PREFIX_END),
                ),
                Part("metrics", "tarpit_minute", "bucket_start, category, kind", time_col="bucket_start"),
                Part("metrics", "tarpit_hold_minute", "bucket_start, category, bound_ms", time_col="bucket_start"),
            ),
            memory=("tarpit",),
            note="Each worker's tarpit counters (kept in memory) are cleared within a few seconds.",
        ),
        Family("throttle", "Throttle", "protection#throttle", (_events("throttle_tier", "ua_rule_hit", "throttled"),)),
        Family(
            "throttle_rule_hits",
            "Throttle rule hits",
            "protection#throttle",
            (_events("throttle_tier", "ua_rule_hit"),),
            parent="throttle",
            note="Ladder rung and User-Agent rule hit counts (v1 throttle_rules); the throttled clients list stays.",
        ),
        Family(
            "throttled_clients",
            "Throttled clients",
            "protection#throttle-history",
            (_events("throttled"),),
            parent="throttle",
            note="The clients that became throttled (v1 throttled); rung and rule hit counts stay.",
        ),
        Family(
            "fingerprints",
            "Fingerprints",
            "security#fingerprints",
            (
                Part("metrics", "fingerprint_headers", "name", time_col="last_seen"),
                Part("metrics", "fingerprint_values", "rowid", time_col="last_seen"),
                Part("metrics", "fingerprint_user_agents", "rowid", time_col="last_seen"),
                _events("blocked_header", "blocked_user_agent"),
            ),
            note="Covers the blocked variants too (v1 kept them apart).",
        ),
        Family(
            "activity",
            "Client activity",
            "clients#activity",
            (
                *(Part("metrics", t, CLIENT_KEY, time_col="bucket_start") for t in CLIENTS),
                Part("metrics", "client_score_hour", "bucket_start, client_key", time_col="bucket_start"),
            ),
            note="Bot scores per client and hour go too.",
        ),
        Family(
            "errors",
            "Errors",
            "system#errors",
            (
                Part("metrics", "errors", "rowid", time_col="last_seen"),
                Part("metrics", "error_minute", "signature, bucket_start", time_col="bucket_start"),
            ),
        ),
        Family("probes", "Probes", "security#probes", (_events("probe", "v1_probe_summary"),)),
        Family("logins", "Logins", "security#logins", (_events("login"),)),
        Family("crawls", "Crawls", "security#crawls", (_events("crawl"),)),
        Family("visits", "Visits", "overview#visitors", (_events("visit"),)),
        Family("refusals", "Refusals", "protection#refusals", (_events("refusal"),)),
        Family(
            "endpoint_block_attempts",
            "Endpoint block attempts",
            "protection#endpoint-blocks",
            (_refusals("endpoint_blocked"),),
            parent="refusals",
            note="Only refusals by an endpoint block (v1 blocked_attempts); they also leave the Refusals card.",
        ),
        Family(
            "endpoint_rule_attempts",
            "Endpoint rule attempts",
            "protection#endpoint-rules",
            (_refusals("endpoint_rule"),),
            parent="refusals",
            note="Only refusals by an endpoint rule (v1 rate_limited_attempts); they also leave the Refusals card.",
        ),
        Family(
            "header_rule_attempts",
            "Request filter attempts",
            "protection#header-rules",
            (_refusals("header_rule"),),
            parent="refusals",
            note="Only refusals by a request filter (v1 header_blocked_attempts); they also leave the Refusals card.",
        ),
        Family(
            "internal_calls",
            "Internal calls",
            "upstream#internal-calls",
            (*_rollups(_dims("source = 'internal'"), match=(("source", ("internal",)),)), _events("internal_call")),
        ),
        Family(
            "live",
            "Live feed and captures",
            "live#tail",
            (_events("live"), Part("metrics", "captures", "rowid", time_col="at")),
        ),
    )
}
"""Plan 6.8 "Metric family" resets: name -> family (tables, card, notes), plus the narrower families of v1's
separate clears (each names its `parent`)."""

STATISTICS_EXTRA: Final[tuple[Part, ...]] = (
    Part("metrics", "events", "rowid", time_col="at_ms", unit="ms"),
    Part("metrics", "request_samples", "rowid", time_col="at_ms", unit="ms"),
    Part("metrics", "refusal_samples", "rowid", time_col="at_ms", unit="ms"),
    Part("metrics", "anomalies", "rowid", time_col="at"),
    Part("metrics", "rule_hits", "table_name, rule_key"),
    Part("metrics", "rule_hit_minute", "bucket_start, table_name, rule_key", time_col="bucket_start"),
    Part("metrics", "metrics_pipeline_minute", "bucket_start, worker_id", time_col="bucket_start"),
    Part("metrics", "disk_samples", "at", time_col="at"),
    Part("metrics", "table_size_samples", "at, db, table_name", time_col="at"),
    Part("metrics", "worker_minute", "bucket_start, worker_id", time_col="bucket_start"),
    Part("metrics", "egress_provider_reports", "rowid", time_col="at"),
    Part("metrics", "recommendation_actions", "rowid", time_col="at"),
    Part("metrics", "recommendation_watches", "rowid"),
    Part("metrics", "recommendations", "rowid"),
    Part("metrics", "health_results", "rowid", "run_id IN (SELECT id FROM health_runs WHERE finished_at IS NOT NULL)"),
    Part("metrics", "health_runs", "rowid", "finished_at IS NOT NULL", (), "started_at"),
    Part("metrics", "legacy_totals", "key"),
    Part("metrics", "annotations", "rowid", time_col="at"),
)
""""Everything (statistics)": every metrics.db table no family covers. Kept: `dims` (the recorder relies on its
rows), `worker_heartbeat` and `health_job_status` (live fleet state, rewritten every few seconds)."""

LIMITER_PARTS: Final[tuple[Part, ...]] = (
    Part("hot", "strikes", "ip"),
    Part("hot", "limiter", "bucket_key"),
)
UPSTREAM_PARTS: Final[tuple[Part, ...]] = (Part("hot", "cooldown", "key"), Part("hot", "breaker", "key"))

ScopeName = Literal[
    "family",
    "date_range",
    "client",
    "endpoint",
    "cache",
    "bans",
    "limiter",
    "upstream",
    "recommendations",
    "health",
    "everything",
    "factory",
]
SCOPES: Final[dict[str, str]] = {
    "family": "One or more metric families, optionally limited to a date range.",
    "date_range": "Any selected families between two dates.",
    "client": "One client (IP address or place): activity rows, strikes, limiter state and events. Bans stay.",
    "endpoint": "One endpoint template: rollups, cache entries, breaker and cooldown state, 429 rows. Rules stay.",
    "cache": "Cache entries only (all, by host, by rule, by pattern, expired), memory tiers fleet-wide.",
    "bans": "Bans (all, automatic only, expired only, or one detector's). Hand-made deny list entries stay.",
    "limiter": "Strikes, limiter buckets and throttle-all buckets. Bans and rules stay.",
    "upstream": "Upstream cooldowns and breakers. Buckets are never refilled.",
    "recommendations": "Dismissed and expired recommendation history, or all. Applied settings stay.",
    "health": "Health check history (runs in progress stay).",
    "everything": "All statistics: metrics.db and cache.db. Settings, rules, users and the audit log stay.",
    "factory": "Everything, settings and rules too, after a snapshot. Admin users and the credential stay.",
}

V1_CLEAR_TARGETS: Final[dict[str, dict[str, Any]]] = {
    "probes": {"scope": "family", "families": ["probes"]},
    "requests": {
        "scope": "family",
        "families": ["traffic"],
        "note": "Request, status, retry and traffic chart counters are all traffic rows in v2.",
    },
    "refusals": {"scope": "family", "families": ["refusals"]},
    "ip_activity": {"scope": "family", "families": ["activity"], "note": "Covers places too (one family)."},
    "callers": {"scope": "family", "families": ["activity"], "note": "Covers IP addresses too (v1 bug B12 fixed)."},
    "internal_requests": {"scope": "family", "families": ["internal_calls"]},
    "proxy_timings": {"scope": "family", "families": ["latency"]},
    "request_failures": {"scope": "family", "families": ["upstream"], "note": "Failures are upstream events."},
    "rotate_ips": {
        "scope": "family",
        "families": ["egress_usage"],
        "note": "v2 never stores exit IPs (each worker keeps its last few in memory); egress usage is the stored "
        "rotator data.",
    },
    "endpoints": {
        "scope": "family",
        "families": ["traffic"],
        "note": "Endpoint popularity is read from traffic rows; the endpoint scope resets one template.",
    },
    "blocked_attempts": {
        "scope": "family",
        "families": ["endpoint_block_attempts"],
        "note": "Endpoint block refusals only; the other attempts tabs stay.",
    },
    "rate_limited_attempts": {
        "scope": "family",
        "families": ["endpoint_rule_attempts"],
        "note": "Endpoint rule refusals only; the other attempts tabs stay.",
    },
    "header_blocked_attempts": {
        "scope": "family",
        "families": ["header_rule_attempts"],
        "note": "Request filter refusals only; the other attempts tabs stay.",
    },
    "pause_drops": {
        "scope": None,
        "families": [],
        "note": "Nothing to reset: the pause banner counts from the moment the pause began (parity row 114).",
    },
    "throttle_drops": {
        "scope": None,
        "families": [],
        "note": "Nothing to reset: enabling throttle-all starts a new count by itself (parity row 115).",
    },
    "tarpit": {"scope": "family", "families": ["tarpit"]},
    "cache": {
        "scope": "family",
        "families": ["cache_stats"],
        "note": "Statistics only, as in v1: hits, misses, stale and coalesced together; requests and entries stay.",
    },
    "throttle_rules": {
        "scope": "family",
        "families": ["throttle_rule_hits"],
        "note": "Ladder rung and UA rule hit counts; the throttled clients list stays.",
    },
    "live": {"scope": "family", "families": ["live"], "note": "Captured bodies go too, as in v1."},
    "logins": {"scope": "family", "families": ["logins"]},
    "crawls": {"scope": "family", "families": ["crawls"]},
    "throttled": {"scope": "family", "families": ["throttled_clients"], "note": "The throttled clients list only."},
    "visits": {"scope": "family", "families": ["visits"]},
    "errors": {"scope": "family", "families": ["errors"]},
    "fingerprints": {"scope": "family", "families": ["fingerprints"]},
    "blocked_fingerprints": {"scope": "family", "families": ["fingerprints"], "note": "One family in v2."},
    "all": {"scope": "everything", "note": "Plus the worker request counts: System > Reset counts."},
}
"""Where every v1 `POST /admin/data/clear` target went (plan 6.8 last paragraph; v1 notes diagnostics.md 14).
`scope` None: v2 counts it from a moment that moves by itself, so there is nothing to reset (the note says why)."""


# ================================================================================================ bodies


class ResetBody(ApiBody):
    """A reset scope (plan 6.8). Which fields apply depends on `scope` (see `GET /data/resets`)."""

    scope: ScopeName
    families: list[Annotated[str, Field(max_length=32)]] | None = Field(default=None, max_length=len(FAMILIES))
    start: str | None = Field(default=None, alias="from", max_length=common.MAX_TIME_TEXT)
    end: str | None = Field(default=None, alias="to", max_length=common.MAX_TIME_TEXT)
    client_type: Literal["ip", "place"] | None = None
    client: str | None = Field(default=None, max_length=64)
    template: str | None = Field(default=None, max_length=300)
    cache: Literal["all", "host", "rule", "pattern", "expired"] | None = None
    value: str | None = Field(default=None, max_length=500)
    pattern_type: Literal["glob", "regex"] = "glob"
    include_stale: bool = False
    bans: Literal["all", "auto", "expired", "detector"] | None = None
    detector: str | None = Field(default=None, max_length=40)
    recommendations: Literal["history", "all"] | None = None


class RunResetBody(ResetBody):
    """`POST /data/resets`: the scope, the preview's digest, a reason and the typed phrase when one is asked for."""

    preview: str = Field(min_length=64, max_length=64)
    reason: str = Field(default="", max_length=MAX_REASON_LENGTH)
    confirm: str | None = Field(default=None, max_length=100)


class ReasonBody(ApiBody):
    reason: str = Field(default="", max_length=MAX_REASON_LENGTH)


class VacuumBody(ApiBody):
    database: Literal["control", "metrics", "cache"]
    reason: str = Field(default="", max_length=MAX_REASON_LENGTH)
    confirm: str = Field(max_length=100)


# ================================================================================================ the plan


@dataclass(slots=True)
class ResetPlan:
    """A normalized reset: what it deletes and how, what it leaves alone, and the phrase it needs."""

    scope: str
    label: str
    descriptor: dict[str, Any]
    parts: list[Part] = field(default_factory=list)
    cache_scope: PurgeScope | None = None
    upstream_reset: bool = False
    bans_where: tuple[str, tuple[Any, ...]] | None = None
    factory: bool = False
    memory: list[str] = field(default_factory=list)
    range: tuple[int, int] | None = None
    confirm_phrase: str | None = None
    leaves: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    snapshot_dbs: list[str] = field(default_factory=list)

    @property
    def digest(self) -> str:
        canonical = json.dumps(self.descriptor, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @property
    def counters(self) -> bool:
        """Whether this reset takes counters away (its chart marker is then a `reset`, which KPIs read as partial
        data; any other reset marks a `config_change`, P6 and DESIGN.md 14.2)."""
        return any(p.db == "metrics" and p.table not in NON_COUNTER_TABLES for p in self.parts)


def _fail(field_name: str, message: str) -> common.ApiError:
    return common.validation_error({field_name: message}, "The reset scope is not valid.", code="invalid_scope")


def _range(body: ResetBody, tz: str, *, required: bool) -> tuple[int, int] | None:
    if body.start is None and body.end is None:
        if required:
            raise _fail("from", "A date range reset needs both from and to.")
        return None
    if body.start is None or body.end is None:
        raise _fail("from" if body.start is None else "to", "Give both from and to.")
    try:
        start = int(common.parse_instant(body.start, tz=tz))
    except ValueError as exc:
        raise _fail("from", str(exc)) from None
    try:
        end = int(common.parse_instant(body.end, tz=tz))
    except ValueError as exc:
        raise _fail("to", str(exc)) from None
    if end <= start:
        raise _fail("to", "The end of the range must be after its start.")
    return start, end


def template_regex(template: str) -> str:
    """An anchored regex for the cache entries of an endpoint template (`{name}` matches one path segment)."""
    pieces = _PLACEHOLDER_RE.split(template.strip().lstrip("/"))
    return "^" + "[^/]+".join(re.escape(piece) for piece in pieces) + "$"


def _client_parts(kind: str, raw: str, ctx: Any) -> tuple[list[Part], dict[str, Any], list[str]]:
    notes: list[str] = []
    if kind == "ip":
        normalized = normalize_ip(raw)
        if normalized is None:
            raise _fail("client", "Give an IPv4 or IPv6 address.")
        key = ip_key(normalized)
        lk = limit_key(normalized, int(ctx.settings.get("ipv6_limit_prefix")))
        keys = sorted({key, lk})
        where_ip = "client_type = 'ip' AND client_key = ?"
        ip_match = (("client_type", ("ip",)), ("client_key", (key,)))
        parts = [Part("metrics", t, CLIENT_KEY, where_ip, (key,), "bucket_start", match=ip_match) for t in CLIENTS]
        # The pairs this address is part of (`<ip>|<place>` rows, finding parity-7): a key prefix range.
        where_pair = "client_type = 'pair' AND client_key >= ? AND client_key < ?"
        prefix = f"{key}{PAIR_SEPARATOR}"
        pair_match = (("client_type", (PAIR_CLIENT_TYPE,)), ("pair_ip", (key,)))
        parts.extend(
            Part("metrics", t, CLIENT_KEY, where_pair, (prefix, prefix + _PREFIX_END), "bucket_start", match=pair_match)
            for t in CLIENTS
        )
        # Bot scores are kept per address (the same `activity.ip_key` as the client tables).
        parts.append(
            Part(
                "metrics",
                "client_score_hour",
                "bucket_start, client_key",
                "client_key = ?",
                (key,),
                "bucket_start",
                match=(("client_key", (key,)),),
            )
        )
        parts.append(Part("hot", "strikes", "ip", "ip IN (?, ?)", (keys[0], keys[-1])))
        exact = (lk, f"flood:{lk}", f"tall:{lk}", f"tarpit_arrival:{key}")
        where = (
            "bucket_key IN (?, ?, ?, ?) OR (bucket_key >= ? AND bucket_key < ?) "
            "OR ((bucket_key >= 'ua:' AND bucket_key < 'ua;') AND substr(bucket_key, -?) = ?) "
            "OR ((bucket_key >= 'ep:' AND bucket_key < 'ep;') AND substr(bucket_key, -?) = ?)"
        )
        suffix = f"|{lk}"
        params: tuple[Any, ...] = (
            *exact,
            f"ucr:{key}|",
            f"ucr:{key}|{_PREFIX_END}",
            len(suffix),
            suffix,
            len(suffix),
            suffix,
        )
        parts.append(Part("hot", "limiter", "bucket_key", where, params))
        hash_key = getattr(ctx, "ip_hash_key", None)
        if hash_key:
            hashed = ip_hash(normalized, hash_key)
            parts.append(
                Part(
                    "metrics",
                    "events",
                    "rowid",
                    "ip_hash = ?",
                    (hashed,),
                    "at_ms",
                    "ms",
                    match=(("ip_hash", (hashed,)),),
                )
            )
        else:
            notes.append("Events cannot be matched to this address without the ip_hash_key credential; they stay.")
        notes.append("Live feed rows (kept 15 minutes) store the address only inside their detail; they stay.")
        return parts, {"client_type": "ip", "client": key, "limit_key": lk}, notes
    place = place_key(raw)
    if not place:
        raise _fail("client", "Give a place id (the Roblox-Id header value).")
    where_place = "client_type = 'place' AND client_key = ?"
    place_match = (("client_type", ("place",)), ("client_key", (place,)))
    parts = [Part("metrics", t, CLIENT_KEY, where_place, (place,), "bucket_start", match=place_match) for t in CLIENTS]
    # The pairs this place is part of: a pair key splits at its first separator (`rollups.split_pair`).
    where_pair = (
        "client_type = 'pair' AND instr(client_key, ?) > 0 AND substr(client_key, instr(client_key, ?) + 1) = ?"
    )
    pair_match = (("client_type", (PAIR_CLIENT_TYPE,)), ("pair_place", (place,)))
    parts.extend(
        Part(
            "metrics",
            t,
            CLIENT_KEY,
            where_pair,
            (PAIR_SEPARATOR, PAIR_SEPARATOR, place),
            "bucket_start",
            match=pair_match,
        )
        for t in CLIENTS
    )
    suffix = f"|place:{place}"
    where = (
        "bucket_key = ? OR (bucket_key >= ? AND bucket_key < ?) "
        "OR ((bucket_key >= 'ep:' AND bucket_key < 'ep;') AND substr(bucket_key, -?) = ?)"
    )
    params = (f"place:{place}", f"place:{place}|", f"place:{place}|{_PREFIX_END}", len(suffix), suffix)
    parts.append(Part("hot", "limiter", "bucket_key", where, params))
    parts.append(Part("metrics", "events", "rowid", "place = ?", (place,), "at_ms", "ms", match=(("place", (place,)),)))
    return parts, {"client_type": "place", "client": place}, notes


def build_plan(body: ResetBody, ctx: Any, now: float) -> ResetPlan:
    """Validate a scope and turn it into a plan (422 `invalid_scope` with the field at fault)."""
    tz = str(ctx.settings.get("ui_timezone") or "UTC")
    scope = body.scope
    descriptor: dict[str, Any] = {"scope": scope}
    if scope in ("family", "date_range"):
        names = list(dict.fromkeys(body.families or ()))
        if not names:
            raise _fail("families", f"Choose one or more of: {', '.join(FAMILIES)}.")
        unknown = [name for name in names if name not in FAMILIES]
        if unknown:
            raise _fail("families", f"Unknown families: {', '.join(unknown)}. Choose from: {', '.join(FAMILIES)}.")
        window = _range(body, tz, required=scope == "date_range")
        families = [FAMILIES[name] for name in names]
        plan = ResetPlan(scope, ", ".join(f.label for f in families), {**descriptor, "families": sorted(names)})
        seen: set[tuple[str, str, str, tuple[Any, ...], str]] = set()
        for family in families:
            for part in family.parts:
                identity = (part.db, part.table, part.where, part.params, part.action)
                if identity not in seen:
                    seen.add(identity)
                    plan.parts.append(part)
            plan.memory.extend(m for m in family.memory if m not in plan.memory)
            if family.note:
                plan.notes.append(f"{family.label}: {family.note}")
        plan.range = window
        if window is None:
            plan.confirm_phrase = f"reset {names[0]}" if len(names) == 1 else f"reset {len(names)} families"
        else:
            plan.descriptor["range"] = list(window)
        plan.leaves = ["Settings, rules, bans and users", "Other metric families"]
        plan.snapshot_dbs = sorted({p.db for p in plan.parts} & set(SNAPSHOT_DBS))
        return plan
    if (body.start is not None or body.end is not None) and scope != "health":
        raise _fail("from", "Only family, date range and health resets take a date range.")
    if scope == "client":
        if body.client_type is None or not body.client:
            raise _fail("client", "Give client_type (ip or place) and client.")
        parts, who, notes = _client_parts(body.client_type, body.client, ctx)
        plan = ResetPlan(scope, f"{who['client_type']} {who['client']}", {**descriptor, **who}, parts=parts)
        plan.notes = notes
        plan.leaves = ["Bans (a separate action)", "Rules and settings"]
        plan.snapshot_dbs = ["metrics"]
        return plan
    if scope == "endpoint":
        template = (body.template or "").strip()
        if not template or "/" not in template:
            raise _fail("template", "Give an endpoint template such as games.roblox.com/v1/games/{gameId}.")
        keys = tuple(cooldowns.endpoint_key(template, egress) for egress in Egress)
        marks = ", ".join("?" for _ in keys)
        plan = ResetPlan(scope, f"endpoint {template}", {**descriptor, "template": template})
        same_template = (("endpoint_template", (template,)),)
        plan.parts = [
            *_rollups(_dims("endpoint_template = ?"), (template,), match=same_template),
            Part(
                "metrics",
                "upstream_429",
                "rowid",
                "endpoint_template = ?",
                (template,),
                "at_ms",
                "ms",
                match=same_template,
            ),
            Part("hot", "cooldown", "key", f"key IN ({marks})", keys),
            Part("hot", "breaker", "key", f"key IN ({marks})", keys),
        ]
        try:
            plan.cache_scope = PurgeScope.pattern(template_regex(template), "regex").validated()
        except (PatternValidationError, ValueError) as exc:
            plan.notes.append(f"Cache entries cannot be matched to this template ({exc}); they stay.")
        plan.leaves = ["Rules (blocks, limits, cache rules)", "Other endpoints"]
        plan.snapshot_dbs = ["metrics"]
        return plan
    if scope == "cache":
        cache_kind = body.cache or "all"
        value = (body.value or "").strip()
        try:
            if cache_kind == "all":
                purge = PurgeScope.all()
            elif cache_kind == "expired":
                purge = PurgeScope.expired(include_stale=body.include_stale)
            elif cache_kind == "host":
                purge = PurgeScope.host(value)
            elif cache_kind == "rule":
                if not value.isdigit():
                    raise _fail("value", "Give the cache rule id.")
                purge = PurgeScope.rule(int(value))
            else:
                purge = PurgeScope.pattern(value, body.pattern_type)
            purge = purge.validated()
        except PatternValidationError as exc:
            raise _fail("value", exc.message) from None
        except ValueError as exc:
            raise _fail("value", str(exc)) from None
        plan = ResetPlan(scope, f"cache {purge.label}", {**descriptor, "purge": purge.label})
        plan.descriptor["pattern_type"] = purge.pattern_type
        plan.descriptor["include_stale"] = purge.include_stale
        plan.cache_scope = purge
        plan.confirm_phrase = "purge cache" if cache_kind == "all" else None
        plan.leaves = ["Cache statistics (the cache_stats family)", "Cache rules"]
        return plan
    if scope == "bans":
        ban_kind = body.bans or "all"
        if ban_kind == "auto":
            where: tuple[str, tuple[Any, ...]] = ("substr(created_by, 1, 5) = 'auto:'", ())
        elif ban_kind == "expired":
            where = ("expires_at IS NOT NULL AND expires_at <= ?", (int(now),))
        elif ban_kind == "detector":
            detector = (body.detector or "").strip()
            if not _ID_RE.fullmatch(detector):
                raise _fail("detector", "Give a detector name (lowercase letters, digits and _).")
            where = ("created_by = ?", (f"auto:{detector}",))
        else:
            where = ("1", ())
        descriptor.update(bans=ban_kind, detector=body.detector if ban_kind == "detector" else None)
        plan = ResetPlan(scope, f"bans ({ban_kind})", descriptor, bans_where=where)
        plan.confirm_phrase = "delete all bans" if ban_kind == "all" else None
        plan.leaves = ["The deny list, bypass and admin allowlist entries", "Rules and settings"]
        plan.snapshot_dbs = ["control"]
        return plan
    if scope == "limiter":
        plan = ResetPlan(scope, "limiter state", descriptor, parts=list(LIMITER_PARTS))
        plan.confirm_phrase = "reset limiters"
        plan.leaves = ["Bans and rules"]
        plan.notes.append("Every client starts with a full allowance again, penalties included.")
        return plan
    if scope == "upstream":
        plan = ResetPlan(scope, "upstream state", descriptor, upstream_reset=True)
        plan.leaves = ["Upstream buckets (never refilled, v1 bug B21)"]
        return plan
    if scope == "recommendations":
        rec_kind = body.recommendations or "history"
        descriptor["recommendations"] = rec_kind
        closed = "state NOT IN ('open', 'snoozed')"
        if rec_kind == "history":
            sub = f"recommendation_id IN (SELECT id FROM recommendations WHERE {closed})"  # noqa: S608 (constants)
            # Children first: their WHERE reads the parent table, which must still hold the closed rows.
            parts = [
                Part("metrics", "recommendation_actions", "rowid", sub),
                Part("metrics", "recommendation_watches", "rowid", sub),
                Part("metrics", "recommendations", "rowid", closed),
            ]
        else:
            parts = [
                Part("metrics", "recommendation_actions", "rowid"),
                Part("metrics", "recommendation_watches", "rowid"),
                Part("metrics", "recommendations", "rowid"),
            ]
        plan = ResetPlan(scope, f"recommendations ({rec_kind})", descriptor, parts=parts)
        plan.confirm_phrase = "delete recommendations" if rec_kind == "all" else None
        plan.leaves = ["Settings already applied"]
        plan.snapshot_dbs = ["metrics"]
        return plan
    if scope == "health":
        window = _range(body, tz, required=False)
        runs = "finished_at IS NOT NULL"
        params: tuple[Any, ...] = ()
        if window is not None:
            runs += " AND started_at >= ? AND started_at < ?"
            params = window
            descriptor["range"] = list(window)
        plan = ResetPlan(scope, "health history", descriptor, range=None)
        results = f"run_id IN (SELECT id FROM health_runs WHERE {runs})"  # noqa: S608 (constants)
        plan.parts = [
            Part("metrics", "health_results", "rowid", results, params),
            Part("metrics", "health_runs", "rowid", runs, params),
        ]
        plan.confirm_phrase = "delete health history" if window is None else None
        plan.leaves = ["Runs still in progress"]
        plan.snapshot_dbs = ["metrics"]
        return plan
    # everything and factory: whole tables (no family filters), each once.
    plan = ResetPlan(scope, "all statistics" if scope == "everything" else "factory reset", descriptor)
    plan.parts = list(_rollups())
    taken = {*ROLLUPS, *(p.table for p in STATISTICS_EXTRA)}
    for family in FAMILIES.values():
        plan.memory.extend(m for m in family.memory if m not in plan.memory)
        for part in family.parts:
            if part.db == "hot" or part.table in taken:
                continue  # hot.db state is the limiter scope's (factory only); whole tables come once
            taken.add(part.table)
            plan.parts.append(Part(part.db, part.table, part.key, time_col=part.time_col, unit=part.unit))
    plan.parts.extend(STATISTICS_EXTRA)
    plan.cache_scope = PurgeScope.all()
    plan.snapshot_dbs = ["control", "metrics"] if scope == "factory" else ["metrics"]
    if scope == "everything":
        plan.confirm_phrase = "everything"
        plan.leaves = ["Settings, rules, bans, users, sessions and the audit log (control.db)", "Limiter state"]
        return plan
    plan.parts.extend(p for p in LIMITER_PARTS if p not in plan.parts)
    plan.upstream_reset = True
    plan.factory = True
    plan.bans_where = ("1", ())
    plan.confirm_phrase = "factory reset"
    plan.leaves = [
        "Admin users, passkeys, sessions and trusted devices",
        "The credential and the rotator URL",
        "The admin allowlist (access list entries of kind allow_admin)",
        "The audit log and settings history",
        "The pause and throttle-all switches",
    ]
    plan.notes.append("Every setting goes back to its default and the rule tables to the shipped defaults.")
    return plan


# ================================================================================================ preview


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)).fetchone()
    return row is not None


def part_clause(part: Part, window: tuple[int, int] | None) -> tuple[str, tuple[Any, ...]] | None:
    """The WHERE clause of a part, limited to `window` when one is given (None: the part does not apply)."""
    if window is None:
        return part.where, part.params
    if part.time_col is None:
        return None
    scale = 1000 if part.unit == "ms" else 1
    clause = f"({part.where}) AND {part.time_col} >= ? AND {part.time_col} < ?"
    return clause, (*part.params, window[0] * scale, window[1] * scale)


def count_part(conn: sqlite3.Connection, part: Part, window: tuple[int, int] | None) -> dict[str, Any]:
    """Rows a part selects, with the oldest and newest time (in seconds) when it has a time column."""
    out: dict[str, Any] = {"db": part.db, "table": part.table, "action": part.action}
    clause = part_clause(part, window)
    if clause is None:
        return {**out, "rows": 0, "skipped": "not limited by dates: left alone for a date range"}
    if not _table_exists(conn, part.table):
        return {**out, "rows": 0, "skipped": "this table does not exist in this schema version"}
    where, params = clause
    time_sql = f"min({part.time_col}), max({part.time_col})" if part.time_col else "NULL, NULL"
    row = conn.execute(f"SELECT count(*), {time_sql} FROM {part.table} WHERE {where}", params).fetchone()  # noqa: S608 (module constants; values are parameters)
    scale = 1000 if part.unit == "ms" else 1
    return {
        **out,
        "rows": int(row[0]),
        "oldest": None if row[1] is None else int(row[1]) // scale,
        "newest": None if row[2] is None else int(row[2]) // scale,
    }


def _merge_counts(items: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in items:
        key = (item["db"], item["table"], item["action"])
        entry = merged.setdefault(key, {"db": item["db"], "table": item["table"], "action": item["action"], "rows": 0})
        entry["rows"] += int(item.get("rows") or 0)
        for name, pick in (("oldest", min), ("newest", max)):
            value = item.get(name)
            if value is not None:
                entry[name] = value if entry.get(name) is None else pick(entry[name], value)
        if item.get("skipped") and not entry["rows"]:
            entry["skipped"] = item["skipped"]
    return list(merged.values())


def snapshot_dir(ctx: Any) -> Path:
    return Path(ctx.env.state_dir) / "snapshots"


def _disk_free(state_dir: Path) -> int:
    """Free bytes on the state volume (0 when it cannot be read). A file system call: run it on a thread."""
    try:
        return int(shutil.disk_usage(state_dir).free)
    except OSError:
        return 0


def _snapshot_entries(folder: Path) -> list[tuple[float, int, Path]]:
    """`(mtime, bytes, path)` of every regular file in the snapshots folder, oldest first (links are not followed)."""
    found: list[tuple[float, int, Path]] = []
    if folder.is_dir():
        for entry in os.scandir(folder):
            if entry.is_file(follow_symlinks=False):
                info = entry.stat(follow_symlinks=False)
                found.append((info.st_mtime, info.st_size, Path(entry.path)))
    found.sort()
    return found


def _database_need(ctx: Any, name: str) -> int:
    """An upper bound of one `VACUUM INTO` copy: the file plus its WAL (the copy holds only the live pages)."""
    db = ctx.dbs.get(name)
    size = read_sizes.file_sizes([Path(db.path)])[Path(db.path).name]
    return int(size["bytes"] + size["wal_bytes"])


def snapshot_feasibility(
    ctx: Any, names: Sequence[str], *, held: int | None = None, room: int = 0
) -> list[dict[str, Any]]:
    """Whether a `VACUUM INTO` snapshot of each database can be taken now (plan 6.8 "where feasible").

    `snapshots_max_bytes` is the total all snapshots may use together (plan 6.10), so the copies count against it
    with what the folder already `held` (read from the folder when None) minus `room` (bytes the caller removes
    first), and each feasible copy counts against the next one; the free disk must keep `SNAPSHOT_MIN_FREE_BYTES`
    after all of them (finding apisec-5). It reads file and disk sizes: call it on a worker thread.
    """
    budget = int(ctx.settings.get("snapshots_max_bytes"))
    free = _disk_free(Path(ctx.env.state_dir)) + max(0, room)
    if held is None:
        held = sum(size for _mtime, size, _path in _snapshot_entries(snapshot_dir(ctx)))
    in_folder = max(0, held - max(0, room))
    planned = 0
    out = []
    for name in names:
        need = _database_need(ctx, name)
        if budget <= 0:
            reason, ok = "Snapshots are turned off (snapshots_max_bytes is 0).", False
        elif need > budget:
            reason, ok = f"The database ({need} bytes) is larger than snapshots_max_bytes ({budget}).", False
        elif in_folder + planned + need > budget:
            reason, ok = (
                f"The snapshots folder holds {in_folder} bytes; a copy of {need} bytes would pass snapshots_max_bytes "
                f"({budget}). Older snapshots leave after retention_snapshots_days, or raise the cap.",
                False,
            )
        elif free < planned + need + SNAPSHOT_MIN_FREE_BYTES:
            reason, ok = "Not enough free disk space for a copy.", False
        else:
            reason, ok = "", True
            planned += need
        out.append({"db": name, "bytes": need, "feasible": ok, "reason": reason})
    return out


def backup_plan(ctx: Any, names: Sequence[str]) -> tuple[list[dict[str, Any]], list[Path]]:
    """Back up now's feasibility, and the oldest manual copies to remove first so the new set fits the cap.

    Only `manual-*` snapshots are ever removed here (reset and pre-migration snapshots stay, whatever their age);
    when even removing every manual copy leaves no room, nothing is removed and the plan says why. A thread call.
    """
    entries = _snapshot_entries(snapshot_dir(ctx))
    held = sum(size for _mtime, size, _path in entries)
    budget = int(ctx.settings.get("snapshots_max_bytes"))
    need = sum(_database_need(ctx, name) for name in names)
    manual = [(size, path) for _mtime, size, path in entries if path.name.startswith(MANUAL_SNAPSHOT_PREFIX)]
    remove: list[Path] = []
    room = 0
    while manual and held - room + need > budget:
        size, path = manual.pop(0)
        remove.append(path)
        room += size
    plan = snapshot_feasibility(ctx, names, held=held, room=room)
    if not all(item["feasible"] for item in plan):
        return snapshot_feasibility(ctx, names, held=held), []
    return plan, remove


def _remove_snapshots(paths: Sequence[Path]) -> list[str]:
    """Delete the named snapshot files (never following a link); returns the names removed. A thread call."""
    removed: list[str] = []
    for path in paths:
        try:
            if path.is_symlink() or not path.is_file():
                continue
            path.unlink()
            removed.append(path.name)
        except FileNotFoundError:
            continue
    return removed


async def preview_plan(ctx: Any, plan: ResetPlan, now: float) -> dict[str, Any]:
    """Exact rows per table and their dates, the actions, what stays, the snapshot plan and the phrase."""
    counts: list[dict[str, Any]] = []
    for name in ("metrics", "hot", "cache", "control"):
        parts = [p for p in plan.parts if p.db == name]
        if not parts:
            continue
        window = plan.range

        def read(
            conn: sqlite3.Connection, parts: list[Part] = parts, window: tuple[int, int] | None = window
        ) -> list[dict[str, Any]]:
            return [count_part(conn, part, window) for part in parts]

        counts.extend(await ctx.dbs.get(name).read(read))
    actions: list[dict[str, Any]] = []
    if plan.bans_where is not None:
        where, params = plan.bans_where

        def bans(conn: sqlite3.Connection) -> int:
            return int(conn.execute(f"SELECT count(*) FROM bans WHERE {where}", params).fetchone()[0])  # noqa: S608 (constants)

        counts.append({"db": "control", "table": "bans", "action": "delete", "rows": await ctx.dbs.control.read(bans)})
    if plan.cache_scope is not None:
        purge = plan.cache_scope
        if getattr(ctx, "cache", None) is None:
            actions.append({"action": "cache_purge", "scope": purge.label, "skipped": "the cache is not running"})
        else:
            found = await ctx.dbs.cache.read(lambda conn: purge_preview(conn, purge, int(now)))
            counts.append({"db": "cache", "table": "entries", "action": "delete", **found})
            actions.append({"action": "cache_purge", "scope": purge.label, "fleet_wide": True})
    if plan.upstream_reset:

        def upstream(conn: sqlite3.Connection) -> dict[str, int]:
            return {
                part.table: int(conn.execute(f"SELECT count(*) FROM {part.table}").fetchone()[0])  # noqa: S608
                for part in UPSTREAM_PARTS
            }

        found = await ctx.dbs.hot.read(upstream)
        counts.extend({"db": "hot", "table": table, "action": "delete", "rows": rows} for table, rows in found.items())
        actions.append({"action": "upstream_reset", "note": "Cooldowns and breakers; buckets are never refilled."})
    if plan.factory:
        overrides = len(ctx.settings.snapshot().overrides)

        def rule_rows(conn: sqlite3.Connection) -> dict[str, int]:
            out: dict[str, int] = {}
            for name in RULE_TABLES:
                if name == "bans":
                    continue
                where = "kind != 'allow_admin'" if name == "access_list" else "1"
                out[name] = int(conn.execute(f"SELECT count(*) FROM {name} WHERE {where}").fetchone()[0])  # noqa: S608
            return out

        found = await ctx.dbs.control.read(rule_rows)
        counts.extend({"db": "control", "table": t, "action": "delete", "rows": n} for t, n in found.items())
        counts.append({"db": "control", "table": "settings", "action": "delete", "rows": overrides})
        actions.append({"action": "settings_reset", "overrides": overrides})
        actions.append({"action": "rules_reset", "note": "The shipped default rules are seeded again."})
    for name in plan.memory:
        actions.append({"action": "memory_reset", "family": name, "note": "Each worker clears its own counters."})
    tables = _merge_counts(counts)
    total = sum(int(t["rows"]) for t in tables)
    oldest = min((t["oldest"] for t in tables if t.get("oldest") is not None), default=None)
    newest = max((t["newest"] for t in tables if t.get("newest") is not None), default=None)
    deleted_tables = sum(1 for t in tables if t["rows"] and t["action"] == "delete")
    deleted_rows = sum(int(t["rows"]) for t in tables if t["action"] == "delete")
    changed = [t for t in tables if t["rows"] and t["action"] != "delete"]
    changed_rows = sum(int(t["rows"]) for t in changed)
    span = ""
    if plan.range is not None:
        span = f" between {_day(plan.range[0], ctx)} and {_day(plan.range[1], ctx)}"
    elif oldest is not None and newest is not None:
        span = f" covering {_day(oldest, ctx)} to {_day(newest, ctx)}"
    # A snapshot only where something will be deleted (a copy of an untouched database undoes nothing); a factory
    # reset always copies control.db first. File and disk sizes are read on a thread (a stalled disk must not hold
    # the event loop).
    rows_by_db: dict[str, int] = {}
    for table in tables:
        rows_by_db[table["db"]] = rows_by_db.get(table["db"], 0) + int(table["rows"])
    wanted = [name for name in plan.snapshot_dbs if rows_by_db.get(name, 0) > 0 or (plan.factory and name == "control")]
    snapshots = await asyncio.to_thread(snapshot_feasibility, ctx, wanted)
    steps = []
    if deleted_rows or not changed_rows:
        rows_word = "row" if deleted_rows == 1 else "rows"
        tables_word = "table" if deleted_tables == 1 else "tables"
        steps.append(f"delete {deleted_rows:,} {rows_word} from {deleted_tables} {tables_word}")
    if changed_rows:
        what = sorted({CHANGE_WORDS.get(str(t["action"]), "the values") for t in changed})
        rows_word = "row" if changed_rows == 1 else "rows"
        tables_word = "table" if len(changed) == 1 else "tables"
        steps.append(f"clear {' and '.join(what)} of {changed_rows:,} {rows_word} in {len(changed)} {tables_word}")
    summary = f"This will {' and '.join(steps)}{span}."
    if plan.leaves:
        summary += f" Not affected: {'; '.join(plan.leaves)}."
    return {
        "scope": plan.scope,
        "label": plan.label,
        "summary": summary,
        "total_rows": total,
        "changed_rows": changed_rows,
        "tables": tables,
        "actions": actions,
        "range": None if plan.range is None else {"from": plan.range[0], "to": plan.range[1]},
        "oldest": oldest,
        "newest": newest,
        "leaves": plan.leaves,
        "notes": plan.notes,
        "snapshots": snapshots,
        "confirm_phrase": plan.confirm_phrase,
        "fresh_mfa_required": plan.factory,
        "preview": plan.digest,
    }


def _day(at: int, ctx: Any) -> str:
    """A day in `ui_timezone` (the preview's date range text)."""
    tz = zone(str(ctx.settings.get("ui_timezone") or "UTC"))
    return datetime.fromtimestamp(max(0, int(at)), tz).strftime("%Y-%m-%d")


# ================================================================================================ operations


@dataclass(slots=True)
class Operation:
    """One background operation of this worker (a reset, a backup, a VACUUM)."""

    id: str
    kind: str
    label: str
    started_at: float
    status: str = "running"  # running, done, failed
    step: str = "starting"
    progress: dict[str, int] = field(default_factory=dict)
    result: dict[str, Any] | None = None
    error: str | None = None
    finished_at: float | None = None
    audit_id: int | None = None
    task: asyncio.Task[Any] | None = None

    def view(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "label": self.label,
            "status": self.status,
            "step": self.step,
            "progress": dict(self.progress),
            "result": self.result,
            "error": self.error,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "audit_id": self.audit_id,
            "url": f"{common.API_PREFIX}/data/operations/{self.id}",
        }


def _operations(request_or_app: Any) -> OrderedDict[str, Operation]:
    app = getattr(request_or_app, "app", request_or_app)
    ops: OrderedDict[str, Operation] | None = getattr(app.state, "roxy_data_operations", None)
    if ops is None:
        ops = OrderedDict()
        app.state.roxy_data_operations = ops
    return ops


def _remember(request: Request, op: Operation) -> None:
    ops = _operations(request)
    ops[op.id] = op
    while len(ops) > MAX_OPERATIONS:
        ops.popitem(last=False)


async def _start(
    request: Request,
    op: Operation,
    work: Callable[[], Any],
    *,
    on_refused: Callable[[], Any] | None = None,
) -> Any:
    """Run `work()` as a background operation; answer its result if it ends within `INLINE_WAIT_S`, else 202.

    `on_refused` runs when the worker cannot start one more operation (it gives back what the caller took).
    """
    ctx = get_ctx(request)

    async def runner() -> None:
        try:
            op.result = await work()
            op.status = "done"
        except Exception as exc:
            op.status = "failed"
            op.error = common.clean_message(f"{type(exc).__name__}: {exc}", 300)
            raise
        finally:
            op.finished_at = ctx.clock.now()

    task = ctx.tasks.spawn(op.id, runner(), group="admin_data", limit=4)
    if task is None:
        if on_refused is not None:
            await on_refused()
        raise common.unavailable("Too many data operations are running in this worker; try again shortly.")
    op.task = task
    _remember(request, op)
    done, _pending = await asyncio.wait({task}, timeout=INLINE_WAIT_S)
    if done and op.status == "done":
        return op.view()
    if done and op.status == "failed":
        raise common.ApiError(500, "operation_failed", op.error or "The operation failed.")
    return JSONResponse(op.view(), status_code=202, headers={"Cache-Control": common.NO_STORE})


def _new_id(kind: str) -> str:
    return f"{kind}_{secrets.token_hex(8)}"


async def _audit(
    ctx: Any, actor: Actor, action: str, target: str, after: Any, reason: str, request_id: str | None
) -> int:
    now = int(ctx.clock.now())

    def write(conn: sqlite3.Connection) -> int:
        return audit.record(conn, actor, action, target, None, after, reason or None, request_id, at=now)

    result: int = await common.run_mutation(ctx.dbs.control.write(write))
    return result


# ================================================================================================ running a reset


async def take_snapshot(ctx: Any, name: str, kind: str, now: float) -> dict[str, Any]:
    """`VACUUM INTO <state dir>/snapshots/<kind>-<time>-<db>.db` on a maintenance connection (a consistent copy)."""
    folder = snapshot_dir(ctx)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now))

    def run(conn: sqlite3.Connection) -> dict[str, Any]:
        folder.mkdir(mode=0o750, parents=True, exist_ok=True)
        target = folder / f"{kind}-{stamp}-{name}.db"
        counter = 1
        while target.exists():  # two operations in one second never overwrite each other
            target = folder / f"{kind}-{stamp}-{counter}-{name}.db"
            counter += 1
        started = time.perf_counter()
        conn.execute("VACUUM INTO ?", (str(target),))
        with contextlib.suppress(OSError):
            os.chmod(target, 0o640)
        return {
            "db": name,
            "file": target.name,
            "bytes": target.stat().st_size,
            "duration_ms": round((time.perf_counter() - started) * 1000, 1),
        }

    result: dict[str, Any] = await ctx.dbs.get(name).maintenance(run)
    return result


def _delete_batch(conn: sqlite3.Connection, part: Part, where: str, params: tuple[Any, ...], limit: int) -> int:
    if not _table_exists(conn, part.table):
        return 0
    if part.action == "clear_latency":
        target = f"({part.key})" if "," in part.key else part.key
        sql = (
            f"UPDATE {part.table} SET latency_hist = NULL, queue_wait_hist = NULL WHERE {target} IN "  # noqa: S608 (constants)
            f"(SELECT {part.key} FROM {part.table} WHERE ({where}) "
            "AND (latency_hist IS NOT NULL OR queue_wait_hist IS NOT NULL) LIMIT ?)"
        )
        return int(conn.execute(sql, (*params, limit)).rowcount)
    if part.action == "clear_cache_state":
        return _clear_cache_state_batch(conn, part, where, params, limit)
    return retention.delete_batch(conn, part.table, part.key, where, params, part.key, limit)


_DIM_SELECT: Final = f"SELECT {', '.join(DIM_COLUMNS)} FROM dims WHERE dim_hash = ?"  # noqa: S608 (module constants)
_DIM_INSERT: Final = (
    f"INSERT OR IGNORE INTO dims (dim_hash, {', '.join(DIM_COLUMNS)}) "  # noqa: S608 (module constants)
    f"VALUES ({', '.join('?' for _ in range(1 + len(DIM_COLUMNS)))})"
)
_CACHE_STATE_INDEX: Final = DIM_COLUMNS.index("cache_state")
_ZONED_ROLLUPS: Final = frozenset({"rollup_day", "rollup_month"})
"""Rollup levels whose rows carry the zone they were computed in (`tz`, plan 6.4); a moved row keeps it."""


def _clear_cache_state_batch(
    conn: sqlite3.Connection, part: Part, where: str, params: tuple[Any, ...], limit: int
) -> int:
    """Move at most `limit` rollup rows of a cache lookup state to `CLEARED_CACHE_STATE` (cache statistics reset).

    Each row goes to the same dimensions with the cache state cleared (its `dims` row added when new) and is added
    to a row already there (counters summed, histograms merged), exactly like two workers flushing one minute; the
    old row is deleted. Requests, bytes, calls and latency stay where they were in every total (parity-8).
    """
    register_sql_functions(conn)  # roxy_hist_merge, for rows that meet
    table = part.table  # a module constant (ROLLUPS)
    zoned = ", tz" if table in _ZONED_ROLLUPS else ""
    sums = ", ".join(ROLLUP_SUMS)
    rows = conn.execute(
        f"SELECT bucket_start, dim_hash FROM {table} WHERE ({where}) LIMIT ?",  # noqa: S608 (module constants)
        (*params, limit),
    ).fetchall()
    if not rows:
        return 0
    moved: dict[int, int] = {}
    for dim_hash in {int(row[1]) for row in rows}:
        found = conn.execute(_DIM_SELECT, (dim_hash,)).fetchone()
        if found is None:
            continue  # a rollup row without its dimensions: left alone (it cannot be told apart)
        dims = list(found)
        dims[_CACHE_STATE_INDEX] = CLEARED_CACHE_STATE
        cleared = tuple(dims)
        new_hash = dims_hash(cleared)
        conn.execute(_DIM_INSERT, (new_hash, *cleared))
        moved[dim_hash] = new_hash
    upsert = (
        f"INSERT INTO {table} (bucket_start, dim_hash, {sums}, latency_hist, queue_wait_hist{zoned}) "  # noqa: S608
        f"SELECT bucket_start, ?, {sums}, latency_hist, queue_wait_hist{zoned} FROM {table} "
        "WHERE bucket_start = ? AND dim_hash = ? "
        "ON CONFLICT (bucket_start, dim_hash) DO UPDATE SET "
        + ", ".join(f"{column} = {column} + excluded.{column}" for column in ROLLUP_SUMS)
        + ", latency_hist = roxy_hist_merge(latency_hist, excluded.latency_hist), "
        "queue_wait_hist = roxy_hist_merge(queue_wait_hist, excluded.queue_wait_hist)"
    )
    delete = f"DELETE FROM {table} WHERE bucket_start = ? AND dim_hash = ?"  # noqa: S608 (module constants)
    count = 0
    for bucket_start, dim_hash in rows:
        target = moved.get(int(dim_hash))
        if target is None:
            continue
        conn.execute(upsert, (target, bucket_start, dim_hash))
        conn.execute(delete, (bucket_start, dim_hash))
        count += 1
    return count


class ResetLease:
    """The fleet-wide lease (hot.db `RESET_LEASE`) one data reset or backup holds, renewed while it runs.

    Public because the internal socket's operator resets (`internal_app.py`) take the same lease: one reset or
    backup at a time, from the dashboard or from `scripts/ctl.py`."""

    def __init__(self, ctx: Any, holder: str) -> None:
        self.ctx = ctx
        self.holder = holder
        self.renewed = time.monotonic()

    async def acquire(self) -> bool:
        now_ms = self.ctx.clock.now_ms()

        def write(conn: sqlite3.Connection) -> bool:
            return leases.acquire(conn, RESET_LEASE, self.holder, RESET_LEASE_TTL_MS, now_ms) is not None

        result: bool = await self.ctx.dbs.hot.write(write)
        return result

    async def keep(self) -> None:
        if time.monotonic() - self.renewed < LEASE_RENEW_S:
            return
        self.renewed = time.monotonic()
        now_ms = self.ctx.clock.now_ms()
        with contextlib.suppress(SharedStateUnavailable):
            await self.ctx.dbs.hot.write(
                lambda conn: leases.renew(conn, RESET_LEASE, self.holder, RESET_LEASE_TTL_MS, now_ms)
            )

    async def release(self) -> None:
        with contextlib.suppress(SharedStateUnavailable):
            await self.ctx.dbs.hot.write(lambda conn: leases.release(conn, RESET_LEASE, self.holder))


async def _run_part(ctx: Any, op: Operation, lease: ResetLease, part: Part, window: tuple[int, int] | None) -> int:
    clause = part_clause(part, window)
    if clause is None:
        return 0
    where, params = clause
    db: Database = ctx.dbs.get(part.db)
    total = 0
    label = f"{part.db}.{part.table}"
    while True:
        changed = await db.write(lambda conn: _delete_batch(conn, part, where, params, BATCH_ROWS))
        total += changed
        op.progress[label] = op.progress.get(label, 0) + changed
        if changed < BATCH_ROWS:
            return total
        await lease.keep()
        await asyncio.sleep(BATCH_PAUSE_S)  # let the request path have the write lock between batches


def _control_reset(
    conn: sqlite3.Connection,
    plan: ResetPlan,
    actor: Actor,
    reason: str,
    request_id: str | None,
    target: str,
    now: int,
) -> dict[str, int]:
    """Bans and (factory) the rule tables, in one control.db transaction with an audit row and a version bump."""
    counts: dict[str, int] = {}
    if plan.bans_where is not None:
        where, params = plan.bans_where
        counts["bans"] = int(conn.execute(f"DELETE FROM bans WHERE {where}", params).rowcount)  # noqa: S608 (constants)
    if plan.factory:
        for name in RULE_TABLES:
            if name == "bans":
                continue
            where = "kind != 'allow_admin'" if name == "access_list" else "1"
            counts[name] = int(conn.execute(f"DELETE FROM {name} WHERE {where}").rowcount)  # noqa: S608 (registry names)
        conn.execute("DELETE FROM service_state WHERE key = ?", (SEED_MARKER_KEY,))
        seeded = seed_defaults(conn, now, actor)
        counts["seeded_defaults"] = seeded.total_inserted
    audit.record(conn, actor, "data.reset.rules", target, None, {"deleted": counts}, reason or None, request_id, at=now)
    bump_config_version(conn, now)
    return counts


def fence_selectors(plan: ResetPlan) -> list[dict[str, Any]]:
    """The reset fence of a plan: what every worker's recorder must drop or rewrite from its unflushed items.

    One selector per metrics.db part on a table the recorder writes (`recorder.FENCED_TABLES`; the four rollup
    levels are one, `rollup_minute`, the only level the recorder writes). A part whose `where` is not "1" needs its
    `match`, else it gets no selector (a test pins that every such part of every scope has one). Under a date range
    a part without a time column does not apply, as in `part_clause`.
    """
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for part in plan.parts:
        if part.db != "metrics":
            continue
        table = "rollup_minute" if part.table in ROLLUPS else part.table
        if table not in FENCED_TABLES:
            continue
        match = part.match
        if match is None:
            if part.where != "1":
                continue
            match = ()
        selector: dict[str, Any] = {
            "table": table,
            "action": part.action,
            "match": {column: list(values) for column, values in match},
        }
        if plan.range is not None:
            if part.time_col is None:
                continue
            selector["range"] = list(plan.range)
        identity = json.dumps(selector, sort_keys=True, default=str)
        if identity not in seen:
            seen.add(identity)
            out.append(selector)
    if len(out) > MAX_FENCE_SELECTORS:  # never in practice: then fence whole tables (more is dropped, never less)
        tables = sorted({str(s["table"]) for s in out})
        out = [{"table": t, "action": "delete", "match": {}} for t in tables][:MAX_FENCE_SELECTORS]
    return out


def _append_fence(conn: sqlite3.Connection, selectors: list[dict[str, Any]], now_ms: int) -> int:
    """Append one fence to `service_state[RESET_FENCE_KEY]` (the newest `MAX_RESET_FENCES` kept); returns its seq."""
    row = conn.execute("SELECT value_json FROM service_state WHERE key = ?", (RESET_FENCE_KEY,)).fetchone()
    document: Any = {}
    if row is not None:
        with contextlib.suppress(ValueError, TypeError):
            document = json.loads(row[0])
    if not isinstance(document, dict):
        document = {}
    fences = [f for f in document.get("fences") or [] if isinstance(f, dict)]
    try:
        seq = int(document.get("seq", 0)) + 1
    except (TypeError, ValueError):
        seq = 1
    seq = max([seq, *(int(f.get("seq", 0)) + 1 for f in fences if isinstance(f.get("seq"), int))])
    fences = [*fences[-(MAX_RESET_FENCES - 1) :], {"seq": seq, "at_ms": int(now_ms), "selectors": selectors}]
    conn.execute(
        "INSERT INTO service_state (key, value_json, updated_at) VALUES (?, ?, ?) "
        "ON CONFLICT (key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at",
        (RESET_FENCE_KEY, json.dumps({"seq": seq, "fences": fences}, separators=(",", ":")), int(now_ms) // 1000),
    )
    return seq


async def fence_pending_counts(ctx: Any, plan: ResetPlan) -> dict[str, Any] | None:
    """Keep every worker's unflushed counts from before this reset out of the tables it resets (finding parity-4).

    Writes the fence (control.db; a failure stops the reset before anything is deleted), tells this worker's
    recorder, and flushes it: what this worker gathered until now is either dropped by the fence or written now and
    deleted by the reset, and everything it counts afterwards is kept. Other workers see the fence inside their
    next flush transaction (`metrics/recorder.py ResetFences`). Raises `SharedStateUnavailable` when this worker's
    flush could not write metrics.db (its counts would come back after the reset).
    """
    selectors = fence_selectors(plan)
    if not selectors:
        return None
    now_ms = int(ctx.clock.now_ms())
    seq: int = await ctx.dbs.control.write(lambda conn: _append_fence(conn, selectors, now_ms))
    recorder = getattr(ctx, "recorder", None)
    flushed = False
    if recorder is not None and hasattr(recorder, "note_reset_fence"):
        recorder.note_reset_fence(seq)
        result = await recorder.flush()
        if "metrics" in (getattr(result, "failed_dbs", None) or ()):
            raise SharedStateUnavailable("metrics", "this worker's unflushed counts could not be written first")
        flushed = True
    return {"seq": seq, "selectors": len(selectors), "flushed_this_worker": flushed}


def marker_tables(plan: ResetPlan) -> list[str]:
    """What a reset's marker says it touched (`metrics/annotate.py` `tables`): `<db>.<table>` for deleted rows,
    `#latency` and `#cache_state` suffixes for rollup rows whose histograms or cache state were cleared."""
    suffix = {"clear_latency": "#latency", "clear_cache_state": "#cache_state"}
    names = [f"{p.db}.{p.table}{suffix.get(p.action, '')}" for p in plan.parts]
    if plan.cache_scope is not None:
        names.append("cache.entries")
    if plan.bans_where is not None:
        names.append("control.bans")
    if plan.upstream_reset:
        names.extend(f"hot.{p.table}" for p in UPSTREAM_PARTS)
    if plan.factory:
        names.extend(f"control.{name}" for name in RULE_TABLES)
        names.append("control.settings")
    return list(dict.fromkeys(names))


async def _write_marker(ctx: Any, plan: ResetPlan, audit_id: int | None) -> int:
    """The chart marker of a reset, before anything is deleted (finding mpjobs-4): at the start of a date range
    (with its end), else now; kind `reset` when counters go (KPIs then show the partial-data notice), naming what
    it touches so only the numbers of those tables get the notice (finding parity-12's `reset_tables`)."""
    at = plan.range[0] if plan.range is not None else int(ctx.clock.now())
    until = plan.range[1] if plan.range is not None else None  # a ranged reset marks the whole deleted range
    kind = "reset" if plan.counters else "config_change"
    label = f"Data reset: {plan.label}"[:MAX_LABEL_CHARS]
    tables = marker_tables(plan)

    def write(conn: sqlite3.Connection) -> int:
        return insert_annotation(conn, int(at), kind, label, audit_id, until=until, tables=tables)

    marker: int = await ctx.dbs.metrics.write(write)
    return marker


def _keep_marker(part: Part, marker: int | None) -> Part:
    """An `annotations` part that leaves this reset's own marker alone (the everything and factory resets)."""
    if marker is None or part.table != "annotations":
        return part
    return replace(part, where=f"({part.where}) AND id != ?", params=(*part.params, marker))


async def execute_reset(
    ctx: Any, op: Operation, plan: ResetPlan, actor: Actor, reason: str, request_id: str | None, lease: ResetLease
) -> dict[str, Any]:
    """Run a reset plan holding `lease` (released at the end). Returns the rows changed per table.

    Order: snapshots, the reset fence (`fence_pending_counts`), the chart marker, then the deletes; see the module
    docstring. `op.audit_id` is the intent row the marker links to until the reset ends.
    """
    target = f"operation:{op.id}"
    started = time.perf_counter()
    deleted: dict[str, int] = {}
    snapshots: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    fence: dict[str, Any] | None = None
    marker: int | None = None
    try:
        now = ctx.clock.now()
        op.step = "snapshot"
        for item in await asyncio.to_thread(snapshot_feasibility, ctx, plan.snapshot_dbs):
            if not item["feasible"]:
                if plan.factory and item["db"] == "control":
                    raise RuntimeError(f"a factory reset needs a control.db snapshot first: {item['reason']}")
                skipped.append({"db": item["db"], "reason": item["reason"]})
                continue
            snapshots.append(await take_snapshot(ctx, item["db"], "reset", now))
        op.step = "fence"
        fence = await fence_pending_counts(ctx, plan)
        op.step = "marker"
        marker = await _write_marker(ctx, plan, op.audit_id)  # metrics.db refusing it means nothing is deleted
        if plan.bans_where is not None or plan.factory:
            op.step = "rules"
            control = await ctx.dbs.control.write(
                lambda conn: _control_reset(conn, plan, actor, reason, request_id, target, int(ctx.clock.now()))
            )
            deleted.update({f"control.{name}": rows for name, rows in control.items()})
            if ctx.rules is not None:
                with contextlib.suppress(SharedStateUnavailable):
                    await ctx.rules.reload()
        if plan.factory:
            op.step = "settings"
            # Every override back to its default, atomically, with one history and audit row per key.
            result = await settings_service(ctx).import_overrides(
                {"overrides": {}},
                actor,
                f"Factory reset: {reason}"[:MAX_REASON_LENGTH],
                replace=True,
                request_id=request_id,
            )
            deleted["control.settings"] = len(result.changes)
        if plan.cache_scope is not None and getattr(ctx, "cache", None) is not None:
            op.step = "cache"
            report = await ctx.cache.purge(plan.cache_scope, actor)
            deleted["cache.entries"] = int(report.removed)
        if plan.upstream_reset:
            op.step = "upstream"
            if getattr(ctx, "upstream", None) is not None:
                counts = await ctx.upstream.reset_state()
            else:
                counts = await ctx.dbs.hot.write(
                    lambda conn: {"cooldowns": cooldowns.clear_all(conn), "breakers": breaker.reset_all(conn)}
                )
            deleted["hot.cooldown"] = int(counts.get("cooldowns", 0))
            deleted["hot.breaker"] = int(counts.get("breakers", 0))
        for part in plan.parts:
            op.step = f"{part.db}.{part.table}"
            rows = await _run_part(ctx, op, lease, _keep_marker(part, marker), plan.range)
            label = f"{part.db}.{part.table}"
            deleted[label] = deleted.get(label, 0) + rows
            await lease.keep()
        if plan.memory:
            op.step = "memory"
            await request_memory_reset(ctx, plan.memory)
        for name in sorted({p.db for p in plan.parts} & {"metrics", "cache"}):
            with contextlib.suppress(SharedStateUnavailable):  # give the freed pages back to the file system
                await ctx.dbs.get(name).maintenance(retention.incremental_vacuum)
    except Exception as exc:
        # What was deleted before the failure is still recorded (plan 9.7), best effort: control.db may be the
        # reason it failed.
        failure = {
            "deleted": deleted,
            "step": op.step,
            "error": common.clean_message(f"{type(exc).__name__}: {exc}", 300),
            "fence": fence,
        }
        failed_id: int | None = None
        with contextlib.suppress(Exception):
            failed_id = await _audit(ctx, actor, AUDIT_RESET_FAILED, target, failure, reason, request_id)
        if marker is not None:
            # Rows already gone keep their marker, so every chart and KPI over them still says "data reset"
            # (plan 6.8, finding mpjobs-4); a reset that changed nothing leaves no marker behind. Best effort.
            marker_id = marker
            changed = sum(deleted.values()) > 0
            incomplete = f"Data reset (incomplete): {plan.label}"[:MAX_LABEL_CHARS]

            def settle(conn: sqlite3.Connection) -> bool:
                if changed:
                    return update_annotation(conn, marker_id, audit_id=failed_id, label=incomplete)
                return delete_annotation(conn, marker_id)

            with contextlib.suppress(Exception):
                await ctx.dbs.metrics.write(settle)
        raise
    finally:
        await lease.release()
    op.step = "audit"
    duration_ms = round((time.perf_counter() - started) * 1000, 1)
    outcome = {
        "deleted": deleted,
        "total_rows": sum(deleted.values()),
        "snapshots": snapshots,
        "snapshots_skipped": skipped,
        "range": None if plan.range is None else {"from": plan.range[0], "to": plan.range[1]},
        "duration_ms": duration_ms,
        "intent_audit_id": op.audit_id,
        "fence": fence,
    }
    done_id = await _audit(ctx, actor, AUDIT_RESET_DONE, target, outcome, reason, request_id)
    if marker is not None:
        marker_id = marker
        with contextlib.suppress(SharedStateUnavailable):  # else the marker keeps linking to the intent row
            await ctx.dbs.metrics.write(lambda conn: update_annotation(conn, marker_id, audit_id=done_id))
    op.step = "done"
    return {**outcome, "audit_id": done_id, "annotation_id": marker}


# ================================================================================================ routes: resets


@router.get("/resets")
async def reset_scopes(_admin: AdminSession) -> dict[str, Any]:
    """Every reset scope of plan 6.8, the metric families, and where each v1 clear target went."""
    return reset_catalog()


def reset_catalog() -> dict[str, Any]:
    """The `GET /data/resets` answer (the Data page's reset form is built from the same data)."""
    return {
        "scopes": [{"scope": name, "description": text} for name, text in SCOPES.items()],
        "families": [
            {
                "name": f.name,
                "label": f.label,
                "card": f.card,
                "parent": f.parent,
                "tables": sorted({p.table for p in f.parts}),
                "actions": sorted({p.action for p in f.parts}),
                "note": f.note,
            }
            for f in FAMILIES.values()
        ],
        "cache_kinds": ["all", "host", "rule", "pattern", "expired"],
        "ban_kinds": ["all", "auto", "expired", "detector"],
        "recommendation_kinds": ["history", "all"],
        "v1_clear_targets": V1_CLEAR_TARGETS,
    }


@router.post("/resets/preview")
async def preview_reset(request: Request, body: ResetBody, _admin: AdminSession, _csrf: CsrfChecked) -> dict[str, Any]:
    """Exact rows per table, dates, what stays, the snapshot plan and the phrase to type (nothing is deleted)."""
    ctx = get_ctx(request)
    now = ctx.clock.now()
    plan = build_plan(body, ctx, now)
    return await common.run_mutation(preview_plan(ctx, plan, now))


async def _run_reset(request: Request, body: RunResetBody, admin: Any) -> Any:
    ctx = get_ctx(request)
    now = ctx.clock.now()
    plan = build_plan(body, ctx, now)
    if body.preview != plan.digest:
        raise common.conflict(
            "This scope was not previewed (or changed since the preview); preview it first.", code="preview_required"
        )
    if plan.confirm_phrase is not None and (body.confirm or "").strip().lower() != plan.confirm_phrase:
        message = f'Type "{plan.confirm_phrase}" to confirm this reset.'
        raise common.validation_error({"confirm": message}, message, code="confirmation_required")
    reason = common.require_reason(body.reason, required=plan.confirm_phrase is not None or plan.factory)
    preview = await common.run_mutation(preview_plan(ctx, plan, now))
    plan.snapshot_dbs = [item["db"] for item in preview["snapshots"]]  # run exactly the snapshot plan previewed
    if plan.factory:
        control = next((s for s in preview["snapshots"] if s["db"] == "control"), None)
        if control is None or not control["feasible"]:
            why = control["reason"] if control else "no snapshot plan"
            raise common.conflict(f"A factory reset needs a control.db snapshot first: {why}", code="not_feasible")
    actor = actor_for(admin)
    request_id = request_id_of(request)
    op = Operation(_new_id("reset"), "reset", plan.label, now)
    lease = ResetLease(ctx, f"{ctx.worker_id}:{op.id}")
    if not await common.run_mutation(lease.acquire()):
        raise common.conflict(
            "Another data reset or backup is running; wait for it to finish.", code="reset_in_progress"
        )
    intent = {
        "scope": plan.descriptor,
        "label": plan.label,
        "planned_rows": {f"{t['db']}.{t['table']}": t["rows"] for t in preview["tables"]},
        "total_rows": preview["total_rows"],
        "snapshots": preview["snapshots"],
        "operation": op.id,
    }
    try:
        # The intent row first (plan 9.7, C7): if control.db cannot take it, nothing is deleted.
        op.audit_id = await _audit(ctx, actor, AUDIT_RESET, f"operation:{op.id}", intent, reason, request_id)
    except BaseException:
        await lease.release()
        raise
    return await _start(
        request,
        op,
        lambda: execute_reset(ctx, op, plan, actor, reason, request_id, lease),
        on_refused=lease.release,
    )


@router.post("/resets", response_model=None)
async def run_reset(request: Request, body: RunResetBody, admin: AdminSession, _csrf: CsrfChecked) -> Any:
    """Run a previewed reset (see the module docstring); a factory reset goes through `/resets/factory`."""
    if body.scope == "factory":
        raise common.forbidden("A factory reset uses POST /data/resets/factory (it needs a fresh second factor).")
    return await _run_reset(request, body, admin)


@router.post("/resets/factory", response_model=None)
async def run_factory_reset(request: Request, body: RunResetBody, admin: AdminFreshMfa, _csrf: CsrfChecked) -> Any:
    """The factory reset (plan 6.8, 9.6): a fresh second factor, the typed phrase and a control.db snapshot."""
    if body.scope != "factory":
        raise common.validation_error({"scope": "This route runs the factory scope only."}, code="invalid_scope")
    return await _run_reset(request, body, admin)


@router.get("/operations/{op_id}")
async def get_operation(
    request: Request, op_id: Annotated[str, PathParam(pattern=r"^[a-z]{1,16}_[0-9a-f]{16}$")], _admin: AdminSession
) -> dict[str, Any]:
    """An operation's progress (from this worker) or its outcome (from the audit log, any worker)."""
    found = _operations(request).get(op_id)
    if found is not None:
        return found.view()
    ctx = get_ctx(request)

    def read(conn: sqlite3.Connection) -> list[dict[str, Any]]:
        rows, _total = read_audit.audit_page(conn, target=f"operation:{op_id}", limit=10)
        return rows

    rows = await ctx.dbs.control.read(read)
    if not rows:
        raise common.not_found("No operation has that id.")
    done = next((r for r in rows if r["action"].endswith(".done")), None)
    failed = next((r for r in rows if r["action"].endswith(".failed")), None)
    status = "done" if done else "failed" if failed else "started"
    return {
        "id": op_id,
        "status": status,
        "note": None if status != "started" else "Started on another worker; its end is not recorded (yet).",
        "audit": [{"id": r["id"], "action": r["action"], "at": r["at"]} for r in rows],
        "result_audit_id": done["id"] if done else None,
    }


# ================================================================================================ routes: storage


STORAGE_TABLE: Final = TableSpec(
    name="storage_tables",
    columns=(
        Column("db", "Database", "The SQLite file."),
        Column("table", "Table", "The table name."),
        Column("label", "What it holds", "Plain-English name of the table."),
        Column("rows", "Rows", "Rows in the table now.", "count"),
        Column("bytes", "Bytes", "Bytes on disk, indexes included (empty when SQLite cannot tell).", "bytes"),
        Column("oldest", "Oldest row", "When the oldest row was written (Unix seconds).", "s"),
        Column("rows_last_7d", "Rows in 7 days", "Rows written in the last 7 days.", "count"),
        Column("projected_rows", "Rows in 30 days", "Estimated rows 30 days from now (see the method).", "count"),
        Column("projected_bytes", "Bytes in 30 days", "Estimated bytes 30 days from now.", "bytes"),
        Column("retention_status", "Retention", "ok, pruning_due (older rows wait for the next prune) or over_cap."),
    ),
    default_sort="bytes",
)


def _limits(ctx: Any) -> dict[str, Any]:
    policy = retention.RetentionPolicy.from_settings(ctx.settings.get)
    return {name: getattr(policy, name) for name in policy.__dataclass_fields__}


async def measure_storage(ctx: Any, *, refresh: bool = False) -> dict[str, Any]:
    """Every database and table (cached `STORAGE_CACHE_S` per worker; one measurement at a time)."""
    state: dict[str, Any] | None = getattr(ctx, STORAGE_CACHE_ATTRIBUTE, None)
    if state is None:
        state = {"at": None, "value": None, "lock": asyncio.Lock()}
        setattr(ctx, STORAGE_CACHE_ATTRIBUTE, state)  # one cache per worker (per AppContext)
    async with state["lock"]:
        age = None if state["at"] is None else time.monotonic() - state["at"]
        # `refresh` measures again, but never twice within STORAGE_MIN_REFRESH_S (each pass scans every table).
        if age is not None and (age < STORAGE_MIN_REFRESH_S or (age < STORAGE_CACHE_S and not refresh)):
            return {**state["value"], "cached": True}
        now = ctx.clock.now()
        limits = _limits(ctx)
        databases = []
        for db in ctx.dbs.all():
            try:
                measured = await db.maintenance(
                    lambda conn, name=db.name: read_sizes.measure_database(conn, name, now, limits)
                )
            except SharedStateUnavailable as exc:
                measured = {"db": db.name, "error": f"unavailable: {exc}"[:200], "tables": []}
            databases.append(measured)
        paths = [Path(db.path) for db in ctx.dbs.all()]
        files = await asyncio.to_thread(read_sizes.file_sizes, paths)
        extra = await asyncio.to_thread(_folder_bytes, Path(ctx.env.state_dir))
        total = sum(f["bytes"] + f["wal_bytes"] + f["shm_bytes"] for f in files.values()) + sum(extra.values())
        budget = int(float(ctx.settings.get("storage_total_budget_gb")) * 1024**3)
        value = {
            "measured_at": int(now),
            "databases": databases,
            "files": files,
            "folders": extra,
            "total_bytes": total,
            "budget_bytes": budget,
            "used_pct": round(total * 100.0 / budget, 2) if budget else None,
            "projection_method": (
                "Rows added per day over the last 7 days x 30, added to today's rows, bounded by each table's max "
                "age and row cap; bytes follow today's bytes per row. An estimate."
            ),
        }
        state["at"], state["value"] = time.monotonic(), value
        return {**value, "cached": False}


def _folder_bytes(state_dir: Path) -> dict[str, int]:
    """Bytes in the snapshots and exports folders (plan 6.6 "Snapshots and exports")."""
    out: dict[str, int] = {}
    for name in ("snapshots", "exports"):
        total = 0
        folder = state_dir / name
        if folder.is_dir():
            for entry in os.scandir(folder):
                if entry.is_file(follow_symlinks=False):
                    total += entry.stat(follow_symlinks=False).st_size
        out[name] = total
    return out


@router.get("/storage", response_model=None)
async def storage(request: Request, admin: AdminSession, fmt: ExportFormatDep, refresh: bool = False) -> Any:
    """Storage sizes per database and table with a 30 day projection (plan 6.6; parity rows 85, 133)."""
    ctx = get_ctx(request)
    data = await common.run_mutation(measure_storage(ctx, refresh=refresh))
    if fmt is not None:
        rows = storage_rows(data)
        tq = TableQuery(sort="bytes")
        return await common.export_table(request, admin, STORAGE_TABLE, rows, fmt, total=len(rows), tq=tq)
    return data


def storage_rows(data: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Every table of a `measure_storage` answer as one `STORAGE_TABLE` row (the export and the Data page)."""
    rows = []
    for database in data.get("databases") or ():
        for table in database.get("tables", []):
            projection = table.get("projection_30d") or {}
            rows.append({**table, "projected_rows": projection.get("rows"), "projected_bytes": projection.get("bytes")})
    return rows


RETENTION_FILE_SETTINGS: Final = (
    "retention_exports_days",
    "retention_snapshots_days",
    "snapshots_max_bytes",
    "storage_total_budget_gb",
    "maintenance_hour",
)
RETENTION_CARDS: Final = ("data#retention", "data#record-caps")
"""The Data page cards whose settings the retention view lists (plan 6.10: every limit is shown there)."""


def retention_setting_keys() -> list[str]:
    """Every setting the retention view shows, in catalog order (finding parity-10): each catalog key whose pages
    name a `RETENTION_CARDS` card, then any other Data page setting a table's limit names, then the file limits."""
    keys = [key for key, spec in catalog.CATALOG.items() if any(page in RETENTION_CARDS for page in spec.pages)]
    for metas in read_sizes.TABLES.values():
        for meta in metas:
            for name in (meta.age, meta.cap):
                spec = catalog.CATALOG.get(name) if name else None
                if spec is not None and name not in keys and any(p.startswith("data#") for p in spec.pages):
                    keys.append(str(name))
    keys.extend(name for name in RETENTION_FILE_SETTINGS if name not in keys)
    return keys


@router.get("/retention")
async def retention_view(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """Every retention and record cap setting with its value, and each table's state against its limits."""
    return await retention_answer(get_ctx(request))


async def retention_answer(ctx: Any) -> dict[str, Any]:
    """The `GET /data/retention` answer (the Data page's retention and record cap cards read the same)."""
    data = await common.run_mutation(measure_storage(ctx))
    snapshot = ctx.settings.snapshot()
    settings = []
    for key in retention_setting_keys():
        spec = catalog.CATALOG.get(key)
        if spec is None:
            continue
        card = next((page.split("#", 1)[1] for page in spec.pages if page in RETENTION_CARDS), "retention")
        settings.append(
            {
                "key": key,
                "label": spec.label,
                "card": card,
                "value": snapshot[key],
                "default": catalog.DEFAULTS.get(key, spec.default),
                "unit": spec.unit,
                "min": spec.min,
                "max": spec.max,
                "overridden": snapshot.is_overridden(key),
                "description": spec.description,
            }
        )
    tables = [
        {
            "db": t["db"],
            "table": t["table"],
            "label": t["label"],
            "rows": t["rows"],
            "oldest": t["oldest"],
            "max_age_s": t["max_age_s"],
            "max_age_setting": t["max_age_setting"],
            "row_cap": t["row_cap"],
            "row_cap_setting": t["row_cap_setting"],
            "rule": t.get("retention_rule"),
            "status": t["retention_status"],
        }
        for database in data["databases"]
        for t in database.get("tables", [])
        if t.get("max_age_setting")
        or t.get("row_cap_setting")
        or t.get("max_age_s") is not None
        or t.get("row_cap") is not None
        or t.get("retention_rule")
    ]
    return {
        "settings": settings,
        "tables": tables,
        "edit_url": f"{common.API_PREFIX}/settings",
        "audit_min_days": retention.AUDIT_MIN_DAYS,
        "measured_at": data["measured_at"],
    }


# ================================================================================================ routes: backups


def _snapshot_files(folder: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if folder.is_dir():
        for entry in os.scandir(folder):
            if not entry.is_file(follow_symlinks=False) or not entry.name.endswith(".db"):
                continue
            info = entry.stat(follow_symlinks=False)
            kind = entry.name.split("-", 1)[0]
            out.append({"file": entry.name, "bytes": info.st_size, "at": int(info.st_mtime), "kind": kind})
    out.sort(key=lambda item: int(item["at"]), reverse=True)
    return out[:500]


def _backup_status(state_dir: Path) -> dict[str, Any]:
    """The nightly backup record (`backup.sh` writes `<state dir>/audit/backup.json`, plan 17.5)."""
    path = state_dir / "audit" / "backup.json"
    try:
        from roxy.health.facts import read_json_file
    except ImportError:  # pragma: no cover - the health package ships with this release
        return {"known": False}
    document = read_json_file(path)
    if not isinstance(document, dict):
        return {"known": False, "note": "No nightly backup has been recorded on this server yet."}
    success = document.get("last_success") if isinstance(document.get("last_success"), dict) else None
    files: dict[str, Any] = {}
    if success and isinstance(success.get("set"), dict) and isinstance(success["set"].get("files"), dict):
        files = {str(k): v for k, v in list(success["set"]["files"].items())[:50] if isinstance(v, int)}
    return {
        "known": True,
        "last_success": None
        if success is None
        else {
            "at": success.get("at"),
            "date": success.get("date"),
            "files": files,
            "encrypted": bool((success.get("set") or {}).get("encrypted")),
            "remote": bool((success.get("set") or {}).get("remote")),
        },
        "last_failure": document.get("last_failure") if isinstance(document.get("last_failure"), dict) else None,
        "restore_test": document.get("restore_test") if isinstance(document.get("restore_test"), dict) else None,
        # What backup.sh did with the last "back up now" request (ran, skipped_recent, skipped_no_database).
        "last_request": _request_view(document.get("last_request")),
    }


def _request_view(raw: Any) -> dict[str, Any] | None:
    """A request record (`backup.sh` or the pending file) with only its known, bounded, plain fields."""
    if not isinstance(raw, dict):
        return None
    view: dict[str, Any] = {}
    for key in ("at", "requested_at", "by", "outcome"):
        value = raw.get(key)
        if isinstance(value, str):
            view[key] = common.clean_message(value, 80)  # written by the roxy user: caller text, shown as text
        elif isinstance(value, int | float) and not isinstance(value, bool):
            view[key] = value
    audit_id = raw.get("audit_id")
    if isinstance(audit_id, int) and not isinstance(audit_id, bool):
        view["audit_id"] = audit_id
    return view


def _pending_request(state_dir: Path) -> dict[str, Any] | None:
    """The request file still waiting for the root backup, read without following a link (at most 4 KiB)."""
    path = state_dir / BACKUP_REQUEST_NAME
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        with os.fdopen(fd, "rb") as handle:
            raw = handle.read(BACKUP_REQUEST_MAX_BYTES)
    except OSError:
        return None
    try:
        return _request_view(json.loads(raw.decode("utf-8", "replace")))
    except ValueError:
        return {"unreadable": True}


def write_backup_request(state_dir: Path, by: str, audit_id: int | None, requested_at: float) -> dict[str, Any]:
    """Write `<state dir>/backup-request` for `roxy-backup-request.path` (as `scripts/ctl.py write_backup_request`).

    A new file (O_EXCL, never following a link, mode 0640) is renamed into place, so the path unit only ever sees
    a complete request. A thread call; never raises (the snapshot on this server is still taken).
    """
    target = state_dir / BACKUP_REQUEST_NAME
    tmp = state_dir / f".{BACKUP_REQUEST_NAME}.{secrets.token_hex(4)}.tmp"
    stamp = datetime.fromtimestamp(float(requested_at), UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    document = {"requested_at": stamp, "by": by, "audit_id": audit_id}
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(tmp, flags, 0o640)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(document, handle)
                handle.write("\n")
            os.replace(tmp, target)  # PathExists= sees the complete file only
        except BaseException:
            with contextlib.suppress(OSError):
                tmp.unlink()
            raise
    except OSError as exc:
        return {"written": False, "file": BACKUP_REQUEST_NAME, "error": type(exc).__name__}
    return {"written": True, "file": BACKUP_REQUEST_NAME, "requested_at": stamp}


@router.get("/backups")
async def backups(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """The nightly backups (as `backup.sh` recorded them, with its last answered request), a request still
    waiting for it, and the snapshots on this server."""
    return await backups_answer(get_ctx(request))


async def backups_answer(ctx: Any) -> dict[str, Any]:
    """The `GET /data/backups` answer (the Data page's backups card reads the same)."""
    state_dir = Path(ctx.env.state_dir)
    nightly = await asyncio.to_thread(_backup_status, state_dir)
    pending = await asyncio.to_thread(_pending_request, state_dir)
    snapshots = await asyncio.to_thread(_snapshot_files, state_dir / "snapshots")
    return {
        "nightly": nightly,
        "last_request": nightly.get("last_request"),
        "pending_request": pending,
        "snapshots": snapshots,
        "snapshots_bytes": sum(item["bytes"] for item in snapshots),
        "snapshots_max_bytes": int(ctx.settings.get("snapshots_max_bytes")),
        "snapshots_keep_days": int(ctx.settings.get("retention_snapshots_days")),
        "note": (
            "Back up now asks the nightly backup (roxy-backup.service) to run now; that one compresses, checks and "
            "optionally encrypts and copies the set, and skips a request within 10 minutes of its last good run. "
            "It also makes a snapshot on this server where one fits (VACUUM INTO, kept like reset snapshots; it "
            "replaces its own oldest copies when the folder would pass snapshots_max_bytes, and skips a copy that "
            "still does not fit, saying why)."
        ),
    }


@router.post("/backups", response_model=None)
async def back_up_now(request: Request, body: ReasonBody, admin: AdminSession, _csrf: CsrfChecked) -> Any:
    """Back up now: a request for the root backup, and `VACUUM INTO` snapshots of control.db and metrics.db where
    they fit `snapshots_max_bytes` and the free disk (audited; one backup or reset at a time fleet-wide).

    The request for the root backup (compressed, checked, optionally encrypted and copied off the server) is the
    backup; the on-server copies are a convenience. So the request is written whatever the local plan says, right
    after the audited intent, and a copy that does not fit is skipped with its reason in the result, as a reset
    skips its snapshot (finding secfix-4: with snapshots turned off, a folder full of reset snapshots or a nearly
    full disk, the button used to answer 409 before it asked the root backup). 409 `not_feasible` only when neither
    the request nor any copy could be made. The folder still never passes its cap (finding apisec-5)."""
    ctx = get_ctx(request)
    actor = actor_for(admin)
    reason = common.require_reason(body.reason, required=False)
    request_id = request_id_of(request)
    now = ctx.clock.now()
    op = Operation(_new_id("backup"), "backup", "back up now", now)
    lease = ResetLease(ctx, f"{ctx.worker_id}:{op.id}")
    if not await common.run_mutation(lease.acquire()):
        raise common.conflict("Another backup or data reset is running; wait for it to finish.", code="run_in_progress")
    state_dir = Path(ctx.env.state_dir)
    try:
        plan, replaced = await asyncio.to_thread(backup_plan, ctx, list(SNAPSHOT_DBS))
        copies = [str(item["db"]) for item in plan if item["feasible"]]
        skipped = [{"db": item["db"], "reason": item["reason"]} for item in plan if not item["feasible"]]
        intent = {
            "databases": copies,
            "skipped": skipped,
            "replaces": [path.name for path in replaced],
            "request_file": BACKUP_REQUEST_NAME,
        }
        op.audit_id = await _audit(ctx, actor, AUDIT_BACKUP, f"operation:{op.id}", intent, reason, request_id)
        op.step = "request"
        asked = await asyncio.to_thread(write_backup_request, state_dir, actor.label, op.audit_id, now)
        if not asked["written"] and not copies:
            why = " ".join(f"{item['db']}: {item['reason']}" for item in skipped)
            failed = {"request": asked, "skipped": skipped}
            await _audit(ctx, actor, f"{AUDIT_BACKUP}.failed", f"operation:{op.id}", failed, reason, request_id)
            raise common.conflict(
                f"No backup could be asked: the request for the root backup could not be written "
                f"({asked.get('error', 'unknown error')}) and no snapshot on this server fits. {why}",
                code="not_feasible",
            )
    except BaseException:
        await lease.release()
        raise

    async def work() -> dict[str, Any]:
        try:
            op.step = "room"
            removed = await asyncio.to_thread(_remove_snapshots, replaced)
            made = []
            for name in copies:
                op.step = name
                made.append(await take_snapshot(ctx, name, "manual", now))
                await lease.keep()
            outcome = {"snapshots": made, "skipped": skipped, "replaced": removed, "request": asked}
            done_id = await _audit(
                ctx, actor, f"{AUDIT_BACKUP}.done", f"operation:{op.id}", outcome, reason, request_id
            )
            return {**outcome, "audit_id": done_id}
        finally:
            await lease.release()

    return await _start(request, op, work, on_refused=lease.release)


# ================================================================================================ routes: vacuum


async def _vacuum_estimates(ctx: Any) -> list[dict[str, Any]]:
    out = []
    free = await asyncio.to_thread(_disk_free, Path(ctx.env.state_dir))
    for name in (*VACUUM_DBS, "hot"):
        db = ctx.dbs.get(name)
        sizes = await db.maintenance(retention.database_sizes)
        files = (await asyncio.to_thread(read_sizes.file_sizes, [Path(db.path)]))[Path(db.path).name]
        allowed = name in VACUUM_DBS
        out.append(
            {
                "db": name,
                "bytes": sizes["bytes"],
                "free_bytes": sizes["free_bytes"],
                "wal_bytes": files["wal_bytes"],
                "estimated_s": round(sizes["bytes"] / VACUUM_BYTES_PER_S, 1),
                "disk_free_bytes": free,
                "enough_disk": free > sizes["bytes"] * 2,
                "allowed": allowed,
                "note": (
                    "Writes to this database wait (or fail after 5 s) while VACUUM runs."
                    if allowed
                    else "hot.db is never vacuumed from the dashboard: it would stall every proxied request."
                ),
                "confirm_phrase": f"vacuum {name}" if allowed else None,
            }
        )
    return out


@router.get("/vacuum")
async def vacuum_estimate(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """Size, reclaimable space and an estimated time for a full VACUUM of each database (plan 6.5)."""
    return await vacuum_answer(get_ctx(request))


async def vacuum_answer(ctx: Any) -> dict[str, Any]:
    """The `GET /data/vacuum` answer (the Data page's vacuum card reads the same)."""
    return {"databases": await common.run_mutation(_vacuum_estimates(ctx)), "rate_bytes_per_s": VACUUM_BYTES_PER_S}


@router.post("/vacuum", response_model=None)
async def run_vacuum(request: Request, body: VacuumBody, admin: AdminSession, _csrf: CsrfChecked) -> Any:
    """A full VACUUM of one database after the typed confirmation (plan 6.5: never automatic)."""
    ctx = get_ctx(request)
    phrase = f"vacuum {body.database}"
    if body.confirm.strip().lower() != phrase:
        raise common.validation_error(
            {"confirm": f'Type "{phrase}".'}, f'Type "{phrase}".', code="confirmation_required"
        )
    estimates = {item["db"]: item for item in await common.run_mutation(_vacuum_estimates(ctx))}
    estimate = estimates[body.database]
    if not estimate["enough_disk"]:
        raise common.conflict(
            "Not enough free disk space for VACUUM (it needs about twice the file).", code="not_feasible"
        )
    actor = actor_for(admin)
    reason = common.require_reason(body.reason, required=False)
    request_id = request_id_of(request)
    op = Operation(_new_id("vacuum"), "vacuum", phrase, ctx.clock.now())
    op.audit_id = await _audit(
        ctx,
        actor,
        AUDIT_VACUUM,
        f"operation:{op.id}",
        {"database": body.database, "estimate": estimate},
        reason,
        request_id,
    )

    async def work() -> dict[str, Any]:
        db = ctx.dbs.get(body.database)
        before = await db.maintenance(retention.database_sizes)
        started = time.perf_counter()
        op.step = "vacuum"
        await db.maintenance(lambda conn: conn.execute("VACUUM"))
        after = await db.maintenance(retention.database_sizes)
        outcome = {
            "database": body.database,
            "bytes_before": before["bytes"],
            "bytes_after": after["bytes"],
            "reclaimed_bytes": max(0, before["bytes"] - after["bytes"]),
            "duration_ms": round((time.perf_counter() - started) * 1000, 1),
        }
        outcome["audit_id"] = await _audit(
            ctx, actor, f"{AUDIT_VACUUM}.done", f"operation:{op.id}", outcome, reason, request_id
        )
        return outcome

    return await _start(request, op, work)


__all__ = [
    "BACKUP_REQUEST_NAME",
    "FAMILIES",
    "MEMORY_FAMILIES",
    "RESET_LEASE",
    "SCOPES",
    "STORAGE_TABLE",
    "V1_CLEAR_TARGETS",
    "Family",
    "Operation",
    "Part",
    "ResetBody",
    "ResetLease",
    "ResetPlan",
    "backup_plan",
    "backups_answer",
    "build_plan",
    "count_part",
    "execute_reset",
    "fence_pending_counts",
    "fence_selectors",
    "marker_tables",
    "measure_storage",
    "part_clause",
    "preview_plan",
    "reset_catalog",
    "retention_answer",
    "retention_setting_keys",
    "router",
    "snapshot_feasibility",
    "storage_rows",
    "take_snapshot",
    "template_regex",
    "vacuum_answer",
    "write_backup_request",
]
