"""The LLM export (plan 12): one versioned JSON document an LLM can review without the database or the screens.

What this is
    `build_export(sources, window=..., detail=...)` gathers what Roxy knows about its own health into the plan 12.3
    document (`schema_version` `roxy.llm_export/1`): configuration, rules, recommendations, open issues, anomalies,
    rollups, top endpoints and clients, errors, Roblox 429 samples, egress usage, capacity, recent changes, the
    catalog entries that matter, the recommendation rule configuration, the latest health run, error samples, the
    parity checklist status, potential issues and a map of the code, plus the plan 12.5 instruction block.
    `LlmExport` and its parts are the Pydantic models; `schema_document()` is the JSON Schema generated from them
    and committed as `insights/schema/llm_export.v1.schema.json` (`python -m roxy.insights.llm_export --write-schema`
    rewrites it). `register_jobs(registry, ctx)` adds the leader job that writes `<state>/exports/roxy-llm-export.json`
    every hour, plus one dated copy per day kept for `retention_exports_days`.

Why it exists
    Plan 12.1: the owner hands one file to an LLM and gets grounded proposals back. Two things must never happen on
    the way. A secret must not leave (plan 9.15, C4): the export never reads the credential, the rotator password,
    the SMTP password, TOTP secrets, the webhook URL or session ids, and a last pass runs `redact_text` over every
    string anyway. And text written by strangers must not steer the LLM (plan 12.3 and 12.5 rule 0): a caller can
    put "do something bad" in a User-Agent, a path or a place id, and an LLM that reads it next to Roxy's own words
    may obey it.

How it works
    - The trust rule. Outside the `untrusted` key a string is only ever one of Roxy's own words (a catalog key, an
      enum value, a rule table column, a string constant of the insights, health, rules, abuse and upstream source,
      the catalog's own text) or a token that cannot carry words (a number, a lowercase hex hash, an ISO time, a
      ULID, a Roxy id). Every other string (paths, endpoint templates, User-Agents, place ids, error messages,
      tracebacks, rule patterns, admin notes, recommendation titles, health findings) is stored once in `untrusted`
      and referenced as `{"untrusted_ref": "u12"}`. Each untrusted entry is redacted, has its IP addresses hashed
      (unless raw addresses are allowed), holds at most 200 characters and has its control characters escaped
      (`roxy.health.report.escape_untrusted`, the same rule "Copy run for LLM" uses); a longer Roxy text that quotes
      outside strings (a recommendation's explanation) spans consecutive entries instead of being cut. Free-form
      values (evidence details, rule rows, change values) go through `Scrubber.value`, which applies the rule to
      every string and every dictionary key.
    - Secrets: the credential appears as `{present, status, set_at}`, the rotator as its host name only, sensitive
      settings as `[redacted]`; workers are named by pid (a host name can carry the server's address).
    - IP addresses are a keyed hash (`common.export_ip_policy`, plan 9.15) unless `export_include_ips` is 1; the
      API never shows raw addresses in the summary detail.
    - Bounds (plan P9): every list has a cap per detail level (`LIMITS`), the untrusted pool too; reads go through
      the read models on reader threads; the code scan (cached per release), the cleaning of the untrusted
      entries, the final validation and the serialization run on worker threads, off the event loop.

What to read next
    `roxy/admin/api/export_llm.py` (the route), `roxy/health/report.py` (Copy run for LLM), `roxy/core/redact.py`,
    `roxy/metrics/queries.py` (the rollup read models), `roxy/insights/engine.py` (recommendations).
"""

from __future__ import annotations

import argparse
import ast
import asyncio
import contextlib
import functools
import ipaddress
import json
import logging
import math
import os
import re
import secrets
import shutil
import threading
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field

import roxy
from roxy.abuse.bans import ua_hash
from roxy.abuse.pause import STATE_KEY as PAUSE_STATE_KEY
from roxy.abuse.pause import PauseState
from roxy.abuse.read_bans import detector_of
from roxy.abuse.throttle_all import STATE_KEY as THROTTLE_ALL_STATE_KEY
from roxy.abuse.throttle_all import ThrottleAllState
from roxy.cache.policy import select_rule
from roxy.config import catalog, read_changes
from roxy.config.audit import ACTOR_KINDS
from roxy.config.insight_params import INSIGHT_RULES
from roxy.config.runtime import thaw
from roxy.core import reasons
from roxy.core.clock import SYSTEM_CLOCK, Clock
from roxy.core.redact import masked_url, redact_text
from roxy.egress import read_credential
from roxy.egress import read_state as egress_state
from roxy.egress.rotator import DECIMAL_GB, day_start_for, usage_since
from roxy.health import checks as health_checks
from roxy.health import store as health_store
from roxy.health.report import LLM_INSTRUCTIONS, UNTRUSTED_MAX_CHARS, escape_untrusted
from roxy.insights import models
from roxy.metrics import queries, read_clients, read_history, read_security, read_upstream
from roxy.metrics.queries import Page
from roxy.rules.match import regex_budget
from roxy.rules.models import ACCESS_LIST_CAPS, RULE_TABLES
from roxy.rules.service import fetch_all
from roxy.scheduler.heartbeat import fleet_view
from roxy.storage.read_sizes import file_sizes
from roxy.upstream import breaker, cooldowns
from roxy.upstream.read_state import describe_key

log = logging.getLogger(__name__)

SCHEMA_VERSION: Final = "roxy.llm_export/1"
SCHEMA_MINOR: Final = 0
"""Additive changes bump this; a breaking change bumps the major version in `SCHEMA_VERSION` (plan 12.4)."""
SCHEMA_ID: Final = "urn:roxy:schema:llm_export:1"
SCHEMA_PATH: Final = Path(__file__).resolve().parent / "schema" / "llm_export.v1.schema.json"
INSTRUCTIONS: Final = LLM_INSTRUCTIONS
"""The plan 12.5 block, verbatim (one copy, shared with the health run's "Copy run for LLM")."""

WINDOWS: Final[tuple[str, ...]] = ("24h", "7d", "30d")
DETAILS: Final[tuple[str, ...]] = ("summary", "full")
WindowKey = Literal["24h", "7d", "30d"]
Detail = Literal["summary", "full"]
IpMode = Literal["raw", "hashed_stable", "hashed_one_time"]
GeneratedBy = Literal["api", "leader", "cli", "test"]
EgressName = Literal["none", "direct", "credential", "rotator"]
IpHasher = Callable[[str], str]

UNTRUSTED_REF_PATTERN: Final = r"^(u[0-9]{1,6}|omitted)$"
MAX_SOURCE_CHARS: Final = 8192
"""Longest outside text looked at before it is cut to 200 characters (bounds the redaction work)."""
MAX_TOKEN_CHARS: Final = 300
MAX_DEPTH: Final = 8
MAX_ITEMS: Final = 100
"""Free-form values: nesting depth and items per list or mapping kept (plan P9)."""
MAX_TEXT_CHUNKS: Final = 20
"""A longer text (a recommendation's explanation, at most 4000 characters) spans at most this many entries."""
MAX_TRACEBACK_FRAMES: Final = 20
MAX_TRACEBACK_LINES: Final = 60
MAX_CONCURRENT_BUILDS: Final = 2
"""Exports built at once per worker; the API answers 429 beyond it (an export reads every table)."""

FILE_NAME: Final = "roxy-llm-export.json"
DATED_PREFIX: Final = "roxy-llm-export-"
FILE_JOB: Final = "llm_export_file"
FILE_INTERVAL_S: Final = 3600.0
FILE_WINDOW: Final = "7d"
FILE_DETAIL: Final = "full"
FILE_MODE: Final = 0o640
DIR_MODE: Final = 0o750
MAX_FILE_BYTES: Final = 32 * 1024 * 1024
MAX_DIR_ENTRIES: Final = 5000
MAX_CHANGES_MD_BYTES: Final = 4 * 1024 * 1024
MAX_PARITY_ROWS: Final = 500
MAX_MODULES: Final = 1000
MAX_SYMBOLS_PER_MODULE: Final = 300
_DATED_RE: Final = re.compile(r"roxy-llm-export-([0-9]{4}-[0-9]{2}-[0-9]{2})\.json")
_TEMP_RE: Final = re.compile(r"\.roxy-llm-export.*\.tmp")

_BUILDS_IN_FLIGHT = 0


@dataclass(frozen=True, slots=True)
class Limits:
    """How much of each section one detail level carries (plan P9)."""

    all_settings: int
    rule_rows: int
    recommendations: int
    evidence_details: int
    top_endpoints: int
    top_clients: int
    user_agents: int
    errors: int
    samples_429: int
    changes: int
    anomalies: int
    all_health_results: int
    error_samples: int
    all_parity_rows: int
    code_symbols: int
    potential_issues: int
    untrusted: int


LIMITS: Final[dict[str, Limits]] = {
    "summary": Limits(0, 50, 50, 0, 10, 10, 10, 10, 10, 50, 50, 0, 0, 0, 0, 50, 1500),
    "full": Limits(1, 500, 200, 1, 50, 25, 25, 50, 50, 500, 200, 1, 20, 1, 1, 200, 8000),
}
"""Flags are 0 or 1. Page sizes for the client tables come from `queries.PAGE_SIZES` (10 and 25)."""


# ============================================================================================== the models


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class UntrustedRef(_Model):
    """A reference to one entry of `untrusted`: the outside text is never inlined next to Roxy's own words."""

    untrusted_ref: str = Field(pattern=UNTRUSTED_REF_PATTERN)


Tok = str | UntrustedRef
"""One of Roxy's own words or tokens inline, or a reference to outside text."""


class UntrustedItem(_Model):
    """One attacker-controllable string: redacted, IP addresses hashed, cut to 200 characters, controls escaped."""

    id: str = Field(pattern=r"^u[0-9]{1,6}$")
    kind: str = Field(pattern=r"^[a-z_]{1,40}$")
    untrusted_text: str
    length: int = Field(ge=0)
    truncated: bool


class WindowInfo(_Model):
    """The window the export covers (UTC times)."""

    key: WindowKey
    start: str
    end: str
    granularity: str
    rollup_unit: Literal["hour", "day"]


class FleetColor(_Model):
    color: str
    fresh_workers: int


class WorkerCount(_Model):
    expected_per_color: int
    fresh: int
    colors: list[FleetColor]


class Meta(_Model):
    """What this file is: schema, version, window, time zone, fleet, uptime and how IP addresses are shown."""

    schema_version: Literal["roxy.llm_export/1"]
    schema_minor: int
    generated_at: str
    generated_by: GeneratedBy
    roxy_version: str
    detail: Detail
    window: WindowInfo
    timezone: str
    worker_count: WorkerCount
    uptime_s: int | None
    fleet_uptime_s: int | None
    ip_addresses: IpMode
    config_version: int
    rules_version: int
    catalog_version: str
    limits: dict[str, int]
    notes: list[str]


class SettingEntry(_Model):
    """One runtime setting: value, default, when and by which kind of actor it last changed."""

    key: str
    group: str
    value: Any
    default: Any
    overridden: bool
    changed_at: str | None
    changed_by: str | None
    risk: str
    high_risk_reason: str | None
    apply: str


class CredentialInfo(_Model):
    """The one Roblox credential, as facts only (never a value, a masked suffix or a fingerprint)."""

    present: bool
    status: str
    set_at: str | None


class RotatorInfo(_Model):
    """The rotator gateway as its host name only (the URL carries a password)."""

    configured: bool | None
    host: str | None
    source: str | None


class ConfigSection(_Model):
    total: int
    overridden: int
    shown: Literal["all", "overridden"]
    invalid_overrides: int
    settings: list[SettingEntry]
    credential: CredentialInfo
    rotator: RotatorInfo


class RuleTableSection(_Model):
    """One rule table: its rows with outside text referenced, IP addresses hashed."""

    table: str
    label: str
    total: int
    cap: int | None
    truncated: bool
    withheld: int
    rows: list[dict[str, Any]]


class RulesSection(_Model):
    version: int
    tables: list[RuleTableSection]


class MetricItem(_Model):
    name: Tok
    value: Any
    unit: Tok | None


class EvidenceSection(_Model):
    window_from: str | None
    window_to: str | None
    metrics: list[MetricItem]
    sample_size: int
    links: list[UntrustedRef]
    details: Any


class ChangeItem(_Model):
    """One proposed change (plan 11.2): kind, what it touches, current and proposed values."""

    kind: str
    key: Tok | None
    table: Tok | None
    bucket_key: UntrustedRef | None
    category: Tok | None
    match: Any
    current: Any
    proposed: Any
    text: UntrustedRef | None


class RecommendationItem(_Model):
    """One recommendation (plan 11.2); its subject and texts can quote caller strings, so they are references."""

    id: Tok
    rule_id: Tok
    family: Tok
    fingerprint: Tok
    state: str
    severity: str
    computed_severity: str
    confidence: str
    risk: str
    safe_auto: bool
    dry_run_available: bool
    subject: UntrustedRef
    title: UntrustedRef
    explanation: list[UntrustedRef]
    expected_impact: list[UntrustedRef]
    evidence: EvidenceSection
    changes: list[ChangeItem]
    created_at: str | None
    updated_at: str | None
    expires_at: str | None
    snoozed_until: str | None
    dismissed_reason: Tok | None


class HealthIssue(_Model):
    check_id: Tok
    status: str
    critical: bool
    run_id: int


class StateIssue(_Model):
    """An open breaker or an active cooldown (`kind`, `egress` and `target` from `upstream/read_state.describe_key`)."""

    kind: str
    egress: str | None
    target: Tok
    state: str
    failures: int | None
    remaining_s: float | None
    hits: int | None
    source: Tok | None


class DegradedItem(_Model):
    subsystem: str
    state: Tok
    detail: Any


class Switches(_Model):
    paused: bool
    throttle_all: bool


class OpenIssues(_Model):
    health: list[HealthIssue]
    breakers: list[StateIssue]
    cooldowns: list[StateIssue]
    degraded: list[DegradedItem]
    switches: Switches


class AnomalyItem(_Model):
    at: str | None
    metric: Tok
    baseline: float | None
    observed: float | None
    zscore: float | None
    window: Tok


class RollupBucket(_Model):
    start: str
    requests: int
    avoided_upstream_calls: int
    upstream_calls: int
    roblox_429_by_egress: dict[EgressName, int]
    status_5xx: int
    timeouts: int
    p50_ms: float | None
    p95_ms: float | None
    p99_ms: float | None
    caller_bytes_in: int
    caller_bytes_out: int
    upstream_bytes_in: int
    upstream_bytes_out: int
    rotator_bytes: int


class Rollups(_Model):
    unit: Literal["hour", "day"]
    buckets: list[RollupBucket]


class EndpointRow(_Model):
    endpoint: UntrustedRef
    requests: int
    upstream_calls: int
    hit_ratio: float | None
    roblox_429: int | None
    p50_ms: float | None
    p95_ms: float | None
    p99_ms: float | None
    cache_rule_id: int | None
    cache_ttl_s: int | None
    cache_stale_ttl_s: int | None


class TopEndpoints(_Model):
    by_requests: list[EndpointRow]
    by_upstream_calls: list[EndpointRow]


class ClientRow(_Model):
    client: Tok
    requests: int
    refused: int
    served: int
    bytes: int
    refused_pct: float | None
    rate1: float | None
    rate5: float | None
    rate60: float | None
    top_endpoint: UntrustedRef | None
    user_agent: UntrustedRef | None
    bot_score: float | None


class UserAgentRow(_Model):
    user_agent: UntrustedRef
    ua_hash: str
    count: int
    first_seen: str | None
    last_seen: str | None


class TopClients(_Model):
    places: list[ClientRow]
    ips: list[ClientRow]
    user_agents: list[UserAgentRow]


class ErrorRow(_Model):
    signature: UntrustedRef
    count: int
    count_in_window: int
    first_seen: str | None
    last_seen: str | None
    source: Tok
    module_line: Tok | None
    sample: UntrustedRef | None


class HeaderItem(_Model):
    name: Tok
    value: Any


class Upstream429Row(_Model):
    at: str | None
    endpoint: UntrustedRef
    host: Tok
    egress: Tok
    retry_after_s: float | None
    ratelimit_headers: list[HeaderItem]
    request_id: Tok | None


class RotatorProjection(_Model):
    """`egress/read_state.project_cycle`: the end-of-cycle estimate with its 90 percent band when there is one."""

    used_bytes: int
    days_elapsed: float
    days_left: float
    trailing_days: int
    trailing_rate_bytes_per_day: float | None
    cycle_rate_bytes_per_day: float | None
    rate_bytes_per_day: float | None
    projected_bytes: int | None
    low_bytes: int | None
    high_bytes: int | None
    band: Tok | None
    band_reason: Tok | None


class RotatorBudget(_Model):
    """This billing cycle of the rotator (plan 8.4): used, projected with its band, quota and cost."""

    configured: bool | None
    usable: bool | None
    reason: Tok | None
    cycle_start: str | None
    cycle_end: str | None
    used_bytes: int
    today_bytes: int
    quota_bytes: int | None
    remaining_bytes: int | None
    projection: RotatorProjection
    projected_pct_of_quota: float | None
    cost_so_far_usd: float | None
    projected_cost_usd: float | None


class EgressSection(_Model):
    window_bytes: dict[EgressName, int]
    rotator: RotatorBudget


class WorkerRow(_Model):
    pid: int
    color: str
    is_leader: bool
    uptime_s: int | None
    rss_bytes: int | None
    loop_lag_ms_p99: float | None
    open_connections: int | None
    inflight_upstream: int | None
    requests: int
    proxied: int
    version: Tok | None


class SaturationRow(_Model):
    pid: int | None
    minutes: int
    cpu_pct_avg: float | None
    cpu_pct_max: float | None
    loop_lag_ms_p99_max: float | None
    rss_max: int | None


class DatabaseSize(_Model):
    name: str
    bytes: int
    wal_bytes: int
    shm_bytes: int


class Capacity(_Model):
    workers: list[WorkerRow]
    saturation: list[SaturationRow]
    databases: list[DatabaseSize]
    disk_total_bytes: int | None
    disk_free_bytes: int | None
    metrics_pipeline: dict[str, int]
    metrics_pipeline_scope: Literal["this_worker", "unavailable"]


class ChangeRow(_Model):
    kind: Literal["setting", "rule"]
    id: int
    at: str | None
    target: Tok
    action: Tok | None
    before: Any
    after: Any
    by: str
    reason: UntrustedRef | None
    source: Tok | None


class CatalogEntry(_Model):
    key: str
    reasons: list[Literal["changed", "recommendation", "potential_issue"]]
    spec: dict[str, Any]


class RuleParam(_Model):
    name: str
    key: str
    value: Any
    default: Any
    unit: str


class InsightRuleItem(_Model):
    rule_id: str
    family: str
    title: str
    enabled: bool
    severity: str
    changed: bool
    params: list[RuleParam]


class HealthResultItem(_Model):
    """One check of the latest run; Roxy's catalog text inline, what the check found as a reference."""

    check_id: Tok
    title: str | None
    status: str
    critical: bool
    measured: float | None
    unit: Tok | None
    threshold: Tok | None
    explanation: str | None
    finding: list[UntrustedRef]
    fix_link: Tok | None
    value: UntrustedRef | None
    detail: Any


class HealthLatest(_Model):
    run_id: int
    trigger: Tok
    state: Tok
    started_at: str | None
    finished_at: str | None
    version: Tok | None
    summary: Any
    shown: Literal["all", "not_passing"]
    results: list[HealthResultItem]


class ErrorSample(_Model):
    signature: UntrustedRef
    count: int
    module_line: Tok | None
    frames: int
    traceback: list[UntrustedRef]


class ParityRow(_Model):
    row: int
    title: str
    status: Literal["covered", "partial", "changed", "missing", "unknown"]
    note: str | None
    tests: list[str]


class ParityStatus(_Model):
    available: bool
    source: str | None
    counts: dict[str, int]
    shown: Literal["all", "not_covered"]
    rows: list[ParityRow]


class PotentialIssue(_Model):
    kind: Literal[
        "setting_high_risk",
        "setting_near_risky",
        "cap_over_80_pct",
        "rule_zero_hits",
        "health_config",
        "dismissed_not_accurate",
    ]
    subject: Tok
    message: str
    value: Any


class CodeSymbol(_Model):
    name: str
    kind: Literal["function", "class", "method"]
    line: int


class CodeModule(_Model):
    path: str
    doc: str | None
    symbols: list[CodeSymbol]


class CodeMap(_Model):
    """Modules with their first docstring line and public symbols at the running version (plan 12.3)."""

    version: str
    root: str
    symbols_included: bool
    truncated: bool
    modules: list[CodeModule]


class LlmExport(_Model):
    """The plan 12.3 document. Every string under `untrusted` came from outside Roxy; see `instructions` rule 0."""

    schema_version: Literal["roxy.llm_export/1"]
    schema_minor: int
    meta: Meta
    instructions: str
    config: ConfigSection
    rules: RulesSection
    recommendations: list[RecommendationItem]
    open_issues: OpenIssues
    anomalies: list[AnomalyItem]
    rollups: Rollups
    top_endpoints: TopEndpoints
    top_clients: TopClients
    errors: list[ErrorRow]
    upstream_429_samples: list[Upstream429Row]
    egress: EgressSection
    capacity: Capacity
    changes: list[ChangeRow]
    catalog: list[CatalogEntry]
    insight_rule_config: list[InsightRuleItem]
    health_latest: HealthLatest | None
    error_samples: list[ErrorSample]
    parity_status: ParityStatus
    potential_issues: list[PotentialIssue]
    code_map: CodeMap
    untrusted: list[UntrustedItem]


def schema_document() -> dict[str, Any]:
    """The JSON Schema (draft 2020-12) of the export, generated from `LlmExport` (plan 12.4)."""
    schema = LlmExport.model_json_schema()
    return {"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": SCHEMA_ID, **schema}


def schema_text() -> str:
    """`schema_document()` as the committed file holds it (sorted keys, two-space indent, final newline)."""
    return json.dumps(schema_document(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


@functools.cache
def schema_bytes() -> bytes:
    """`schema_text()` as UTF-8, built once per process (the "Open schema" route answers it)."""
    return schema_text().encode("utf-8")


# ======================================================================================= the trust rule


_TOKEN_PATTERNS: Final[tuple[re.Pattern[str], ...]] = tuple(
    re.compile(pattern)
    for pattern in (
        r"-?[0-9]{1,20}(?:\.[0-9]{1,12})?",  # a number written as text
        r"[0-9a-f]{8,64}",  # a hash or fingerprint (lowercase hex)
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",  # an ISO time
        r"[0-9A-HJKMNP-TV-Z]{26}",  # a ULID (request ids)
        r"[a-z]{2,8}_[0-9A-HJKMNP-TV-Z]{26}",  # a Roxy id such as rec_<ulid>
        r"[A-Z][A-Z0-9-]{1,40}:[0-9a-f]{16}",  # a recommendation fingerprint
        r"ip:[0-9a-f]{16}",  # a hashed IP address
    )
)
"""Tokens that cannot carry words, so they may stand outside `untrusted` whatever their source."""

_HARVEST: Final[tuple[str, ...]] = (
    "insights/",
    "health/",
    "rules/",
    "abuse/",
    "upstream/",
    "egress/read_state.py",
    "config/insight_params.py",
    "core/reasons.py",
    "metrics/catalog.py",
    "metrics/queries.py",
    "metrics/read_history.py",
)
"""Source whose string constants count as Roxy's own words (evidence names, units, detail keys, enum values)."""

_IPV4_RE: Final = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")
_IPV6_RUN_RE: Final = re.compile(r"[0-9A-Fa-f:]{2,39}")


def is_trusted(text: str, vocabulary: frozenset[str]) -> bool:
    """Whether `text` may stand outside `untrusted`: one of Roxy's own words, or a token that cannot carry words."""
    if text == "" or text in vocabulary:
        return True  # equal to one of Roxy's own words, so it is Roxy's text whoever sent it
    if len(text) > MAX_TOKEN_CHARS:
        return False
    return any(pattern.fullmatch(text) for pattern in _TOKEN_PATTERNS)


def mask_ips(text: str, hasher: IpHasher | None) -> str:
    """`text` with every IPv4 and IPv6 address replaced by `ip:<keyed hash>` (unchanged when `hasher` is None)."""
    if hasher is None or not text:
        return text

    def v4(match: re.Match[str]) -> str:
        candidate = match.group(0)
        try:
            ipaddress.IPv4Address(candidate)
        except ValueError:
            return candidate
        return f"ip:{hasher(candidate)}"

    def v6(match: re.Match[str]) -> str:
        candidate = match.group(0)
        if candidate.count(":") < 2:
            return candidate
        for core in (candidate, candidate.strip(":")):
            try:
                ipaddress.IPv6Address(core)
            except ValueError:
                continue
            return candidate.replace(core, f"ip:{hasher(core)}", 1)
        return candidate

    return _IPV6_RUN_RE.sub(v6, _IPV4_RE.sub(v4, text))


@dataclass(slots=True)
class _Entry:
    ident: str
    kind: str
    text: str  # raw (bounded) text, or text already cleaned when `cleaned`
    length: int
    cleaned: bool
    truncated: bool | None  # None: decided when the text is cleaned


class UntrustedPool:
    """Collects outside strings for `untrusted` and hands back references (equal texts share one entry).

    `ref` only reserves an id: the redaction, IP hashing and escaping of the text run in `materialize`, which the
    export calls on a worker thread, so thousands of entries never hold the event loop. `refs` cleans at once (it
    must split the cleaned text; it is used for a few long texts only).
    """

    def __init__(self, limit: int, ip_hasher: IpHasher | None) -> None:
        self.limit = max(0, int(limit))
        self.ip_hasher = ip_hasher
        self.omitted = 0
        self._entries: list[_Entry] = []
        self._index: dict[tuple[str, str, bool], str] = {}

    def __len__(self) -> int:
        return len(self._entries)

    def _clean(self, text: str) -> str:
        # Addresses are hashed and secrets removed BEFORE the text is cut, so a cut can never split one in half.
        return redact_text(mask_ips(text[:MAX_SOURCE_CHARS], self.ip_hasher))

    def _reserve(self, kind: str, text: str, length: int, cleaned: bool, truncated: bool | None) -> dict[str, str]:
        key = (kind, text, cleaned)
        found = self._index.get(key)
        if found is not None:
            return {"untrusted_ref": found}
        if len(self._entries) >= self.limit:
            self.omitted += 1
            return {"untrusted_ref": "omitted"}
        ident = f"u{len(self._entries) + 1}"
        self._index[key] = ident
        self._entries.append(_Entry(ident, kind, text, length, cleaned, truncated))
        return {"untrusted_ref": ident}

    def ref(self, value: Any, kind: str = "text") -> dict[str, str]:
        """One reference; the text is cut to 200 characters (plan 12.3)."""
        text = value if isinstance(value, str) else str(value)
        return self._reserve(kind, text[:MAX_SOURCE_CHARS], len(text), False, None)

    def refs(self, value: Any, kind: str = "text", max_chunks: int = 20) -> list[dict[str, str]]:
        """A longer Roxy text that quotes outside strings (a recommendation's explanation, a health finding), as
        consecutive entries of at most 200 characters each, so nothing is lost and no entry is longer."""
        text = value if isinstance(value, str) else str(value)
        clean = self._clean(text)
        if not clean:
            return []
        size = UNTRUSTED_MAX_CHARS
        pieces = [clean[start : start + size] for start in range(0, len(clean), size)]
        kept = pieces[: max(1, max_chunks)]
        cut = len(kept) < len(pieces) or len(text) > MAX_SOURCE_CHARS
        return [self._reserve(kind, piece, len(text), True, cut and i == len(kept) - 1) for i, piece in enumerate(kept)]

    def materialize(self) -> list[dict[str, Any]]:
        """The `untrusted` list: every entry redacted, IP addresses hashed, cut to 200 characters, escaped."""
        out: list[dict[str, Any]] = []
        for entry in self._entries:
            clean = entry.text if entry.cleaned else self._clean(entry.text)
            truncated = entry.truncated
            if truncated is None:
                truncated = len(clean) > UNTRUSTED_MAX_CHARS or entry.length > MAX_SOURCE_CHARS
            out.append(
                {
                    "id": entry.ident,
                    "kind": entry.kind,
                    "untrusted_text": escape_untrusted(clean),
                    "length": entry.length,
                    "truncated": truncated,
                }
            )
        return out

    @property
    def items(self) -> list[dict[str, Any]]:
        return self.materialize()


class Scrubber:
    """Applies the trust rule (module docstring) to single strings and to free-form values."""

    def __init__(self, pool: UntrustedPool, vocabulary: frozenset[str]) -> None:
        self.pool = pool
        self.vocabulary = vocabulary

    def trusted(self, text: str) -> bool:
        return is_trusted(text, self.vocabulary)

    def ref(self, value: Any, kind: str) -> dict[str, str]:
        return self.pool.ref(value, kind)

    def opt_ref(self, value: Any, kind: str) -> dict[str, str] | None:
        """A reference, or None for an empty value."""
        if value is None or value == "":
            return None
        return self.pool.ref(value, kind)

    def refs(self, value: Any, kind: str) -> list[dict[str, str]]:
        """Consecutive references of at most 200 characters each (an empty value gives an empty list)."""
        if value is None or value == "":
            return []
        return self.pool.refs(value, kind, MAX_TEXT_CHUNKS)

    def token(self, value: Any, kind: str = "text") -> Any:
        """A string inline when trusted, else a reference."""
        text = value if isinstance(value, str) else str(value)
        return text if self.trusted(text) else self.pool.ref(text, kind)

    def opt_token(self, value: Any, kind: str = "text") -> Any:
        if value is None:
            return None
        return self.token(value, kind)

    def value(self, value: Any, kind: str = "value", depth: int = 0) -> Any:
        """A JSON-shaped copy of `value` with every string (keys included) under the trust rule, bounded."""
        if value is None or isinstance(value, bool):
            return value
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return value if math.isfinite(value) else None
        if isinstance(value, str):
            return self.token(value, kind)
        if depth >= MAX_DEPTH:
            return None
        if isinstance(value, Mapping):
            pairs = list(value.items())[:MAX_ITEMS]
            if all(isinstance(key, str) and self.trusted(key) for key, _ in pairs):
                return {str(key): self.value(item, kind, depth + 1) for key, item in pairs}
            # A key that is not Roxy's word (a path, a parameter name) becomes a reference too.
            return {
                "entries": [
                    {"key": self.value(str(key), "key", depth + 1), "value": self.value(item, kind, depth + 1)}
                    for key, item in pairs
                ]
            }
        if isinstance(value, list | tuple | set | frozenset):
            return [self.value(item, kind, depth + 1) for item in list(value)[:MAX_ITEMS]]
        return self.pool.ref(str(value), kind)


# ================================================================================== the source code scan


@dataclass(frozen=True, slots=True)
class SourceScan:
    """The code map of one release and the words its source and catalog use (built once per process)."""

    root: str
    modules: tuple[dict[str, Any], ...]
    vocabulary: frozenset[str]
    truncated: bool


_SCAN_CACHE: dict[tuple[str, str], SourceScan] = {}
_SCAN_LOCK = threading.Lock()


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list | tuple):
        for item in value:
            yield from _strings(item)


def static_vocabulary() -> set[str]:
    """Roxy's own words that do not need the source: catalog keys, defaults and options, enums, rule ids, tables."""
    words: set[str] = {"", catalog.REDACTED}
    for key, spec in catalog.CATALOG.items():
        words.add(key)
        words.update(_strings(spec.default))
        words.update(option.value for option in spec.options)
        words.update((spec.group.value, spec.type.value, spec.risk.value, spec.apply.value))
    words.update(catalog.ALIASES)
    for enum_type in (
        reasons.ReasonCode,
        reasons.Outcome,
        reasons.Egress,
        reasons.Source,
        reasons.CacheState,
        reasons.AuthClass,
    ):
        words.update(str(member.value) for member in enum_type)
    words.update(models.SEVERITIES + models.CONFIDENCES + models.RISKS + models.STATES + models.CHANGE_KINDS)
    words.update(models.DISMISS_REASONS)
    words.update(models.SNOOZE_DURATIONS_S)
    for rule in INSIGHT_RULES.values():
        words.update((rule.rule_id, rule.family, rule.slug))
        words.update(param.name for param in rule.params)
        words.update(param.unit for param in rule.params)
    for name, table in RULE_TABLES.items():
        words.add(name)
        words.update(table.columns)
    words.update(ACTOR_KINDS)
    words.update(health_checks.CATALOG)
    return words


def _display_root(package: Path) -> str:
    return "src/roxy" if package.parent.name == "src" else package.name


def _symbols(tree: ast.Module) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and not node.name.startswith("_"):
            out.append({"name": node.name, "kind": "function", "line": node.lineno})
        elif isinstance(node, ast.ClassDef) and not node.name.startswith("_"):
            out.append({"name": node.name, "kind": "class", "line": node.lineno})
            for item in node.body:
                if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef) and not item.name.startswith("_"):
                    out.append({"name": f"{node.name}.{item.name}", "kind": "method", "line": item.lineno})
    return out[:MAX_SYMBOLS_PER_MODULE]


def _source_words(tree: ast.Module) -> Iterable[str]:
    """String constants, field names and keyword names of one module: the words its rows and payloads use."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and len(node.value) <= 300:
            yield node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            yield node.target.id  # dataclass and model fields (`asdict` keys)
        elif isinstance(node, ast.keyword) and node.arg is not None:
            yield node.arg  # `dict(key=...)` and constructor keywords


def _scan(package: Path) -> SourceScan:
    display = _display_root(package)
    paths = sorted(p for p in package.rglob("*.py") if "__pycache__" not in p.parts and "vendor" not in p.parts)
    truncated = len(paths) > MAX_MODULES
    words = static_vocabulary()
    modules: list[dict[str, Any]] = []
    for path in paths[:MAX_MODULES]:
        relative = path.relative_to(package).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
            tree = ast.parse(text)
        except (OSError, SyntaxError, ValueError):
            modules.append({"path": f"{display}/{relative}", "doc": None, "symbols": []})
            continue
        doc = ast.get_docstring(tree)
        first = doc.strip().splitlines()[0].strip()[:300] if doc and doc.strip() else None
        modules.append({"path": f"{display}/{relative}", "doc": first, "symbols": _symbols(tree)})
        if any(relative.startswith(prefix) for prefix in _HARVEST):
            words.update(_source_words(tree))
    return SourceScan(display, tuple(modules), frozenset(words), truncated)


def source_scan(package: Path | None = None, version: str = "") -> SourceScan:
    """The scan of `package` (default: the running `roxy` package), cached per path and release."""
    root = (package or Path(roxy.__file__).resolve().parent).resolve()
    key = (str(root), version)
    with _SCAN_LOCK:
        found = _SCAN_CACHE.get(key)
    if found is not None:
        return found
    scan = _scan(root)
    with _SCAN_LOCK:
        while len(_SCAN_CACHE) >= 2:
            _SCAN_CACHE.pop(next(iter(_SCAN_CACHE)))
        _SCAN_CACHE[key] = scan
    return scan


# =================================================================================== the parity checklist


_PARITY_CACHE: dict[str, tuple[tuple[int, int], list[dict[str, Any]]]] = {}
_PARITY_STATUSES: Final = ("covered", "partial", "changed", "missing")


def parse_parity(text: str) -> list[dict[str, Any]]:
    """The rows of the "Parity checklist" table of CHANGES.md: row number, title, status, note, test ids."""
    rows: list[dict[str, Any]] = []
    inside = False
    for line in text.splitlines():
        if line.startswith("## "):
            inside = line.strip().lower().startswith("## parity checklist")
            continue
        if not inside or not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 4 or not cells[0].isdigit():
            continue
        status_text = cells[2]
        lowered = status_text.lower()
        status = next((word for word in _PARITY_STATUSES if lowered.startswith(word)), "unknown")
        note = status_text
        if status != "unknown":
            note = status_text[len(status) :].strip()
            if note.startswith(":"):
                note = note[1:].strip()
            elif note.startswith("(") and note.endswith(")"):
                note = note[1:-1].strip()
        tests_cell = "|".join(cells[3:])
        tests = [test[:300] for test in re.findall(r"`([^`]+)`", tests_cell)][:30]
        rows.append(
            {
                "row": int(cells[0]),
                "title": cells[1][:300],
                "status": status,
                "note": note[:600] or None,
                "tests": tests,
            }
        )
        if len(rows) >= MAX_PARITY_ROWS:
            break
    return rows


def read_parity(path: Path) -> list[dict[str, Any]] | None:
    """`parse_parity` of a file, cached by its modification time and size; None when it cannot be read."""
    try:
        info = path.stat()
    except OSError:
        return None
    if info.st_size > MAX_CHANGES_MD_BYTES:
        return None
    stamp = (info.st_mtime_ns, info.st_size)
    cached = _PARITY_CACHE.get(str(path))
    if cached is not None and cached[0] == stamp:
        return cached[1]
    try:
        rows = parse_parity(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return None
    if len(_PARITY_CACHE) >= 4:
        _PARITY_CACHE.clear()
    _PARITY_CACHE[str(path)] = (stamp, rows)
    return rows


def default_changes_path(package: Path | None = None) -> Path:
    """CHANGES.md next to the source tree (`<repo>/src/roxy` gives `<repo>/CHANGES.md`)."""
    root = (package or Path(roxy.__file__).resolve().parent).resolve()
    base = root.parent.parent if root.parent.name == "src" else root.parent
    return base / "CHANGES.md"


# ========================================================================================= the sources


def _snapshot_of(source: Any) -> Any:
    snap = getattr(source, "snapshot", None)
    if snap is None:
        return source
    return snap() if callable(snap) else snap


@dataclass
class ExportSources:
    """Everything the export reads. `from_context(ctx)` in the app; tests build one over fixture databases."""

    dbs: Any
    settings: Any
    rules: Any
    clock: Clock = SYSTEM_CLOCK
    release: str = ""
    color: str = ""
    workers_expected: int = 1
    started_at: float | None = None
    state_dir: Path | None = None
    recorder: Any = None
    egress: Any = None
    cache: Any = None
    engine: Any = None
    providers: Any = None
    code_root: Path | None = None
    changes_path: Path | None = None

    @classmethod
    def from_context(cls, ctx: Any) -> ExportSources:
        env = getattr(ctx, "env", None)
        return cls(
            dbs=ctx.dbs,
            settings=ctx.settings,
            rules=ctx.rules,
            clock=ctx.clock,
            release=str(getattr(ctx, "release", "") or ""),
            color=str(getattr(ctx, "color", "") or ""),
            workers_expected=int(getattr(env, "workers", 1) or 1),
            started_at=getattr(ctx, "started_at", None),
            state_dir=getattr(env, "state_dir", None),
            recorder=getattr(ctx, "recorder", None),
            egress=getattr(ctx, "egress", None),
            cache=getattr(ctx, "cache", None),
            engine=getattr(ctx, "insights", None),
        )

    def insights_engine(self) -> Any:
        """The worker's engine, or one built for reading (the export only lists stored recommendations)."""
        if self.engine is None:
            from roxy.insights.engine import InsightsEngine

            self.engine = InsightsEngine(dbs=self.dbs, settings=self.settings, rules=self.rules, clock=self.clock)
        return self.engine


@dataclass
class ExportResult:
    """A built export: the JSON bytes, the validated document and a few facts for the audit row."""

    content: bytes
    document: dict[str, Any]
    untrusted: int
    omitted: int
    ip_mode: str


# ======================================================================================= small helpers


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number) or number < 0 or number > 32_503_680_000:
        return None
    return models.iso(number)


def _iso_ms(value: Any) -> str | None:
    return None if value is None else _iso(float(value) / 1000.0)


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _opt_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _opt_float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def actor_kind(label: Any) -> str | None:
    """`admin:alice` gives `admin`: the export names the kind of actor, never a person or an address."""
    if label is None:
        return None
    head = str(label).split(":", 1)[0]
    return head if head in ACTOR_KINDS or head == "auto" else "other"


def _host_name(url_text: str) -> str | None:
    """The host of a masked URL, or None (an IP literal is never shown: it can be a server address, plan C4)."""
    rest = url_text.split("://", 1)[-1]
    host = rest.split("/", 1)[0].rsplit("@", 1)[-1]
    if host.startswith("["):
        return None
    host = host.split(":", 1)[0].lower()
    if not re.fullmatch(r"[a-z0-9.-]{1,253}", host):
        return None
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    return None


def _safe_word(value: Any, pattern: str = r"[a-z0-9_]{1,40}", fallback: str = "other") -> str:
    text = str(value or "")
    return text if re.fullmatch(pattern, text) else fallback


def _list_column(value: Any) -> Any:
    """A list stored as JSON (`normalize_flags`) or as comma separated text (`methods`), as a list."""
    if isinstance(value, str):
        if value.startswith("["):
            with contextlib.suppress(ValueError):
                return json.loads(value)
        return [part for part in value.split(",") if part]
    return value


# ================================================================================== the builder itself


class _Build:
    """One export being built (see `build_export`)."""

    def __init__(
        self,
        sources: ExportSources,
        *,
        window: str,
        detail: str,
        ip_hasher: IpHasher | None,
        ip_mode: str,
        generated_by: str,
        scan: SourceScan,
    ) -> None:
        self.sources = sources
        self.window_key = window
        self.detail = detail
        self.limits = LIMITS[detail]
        self.ip_hasher = ip_hasher
        self.ip_mode = ip_mode
        self.generated_by = generated_by
        self.scan = scan
        self.dbs = sources.dbs
        self.now = float(sources.clock.now())
        self.now_ms = int(self.now * 1000)
        self.snap = _snapshot_of(sources.settings)
        self.rules_snap = _snapshot_of(sources.rules)
        self.tz = str(self.snap["ui_timezone"])
        self.win = queries.resolve_window(window, now=self.now, tz=self.tz)
        self.pool = UntrustedPool(self.limits.untrusted, ip_hasher)
        self.scrub = Scrubber(self.pool, scan.vocabulary)
        self.allowed_hosts = frozenset(
            f"{str(name).strip().lower().rstrip('.')}.roblox.com" for name in self.snap["allowed_roblox_hosts"] or ()
        )
        self.catalog_reasons: dict[str, set[str]] = {}
        self.fleet_rows: list[dict[str, Any]] = []
        self.health_run: dict[str, Any] | None = None
        self.rule_rows: dict[str, list[dict[str, Any]]] = {}
        self.dismissed: list[models.Recommendation] = []
        self.credential: dict[str, Any] = {}

    # ---- helpers ----

    def hash_ip(self, address: str) -> str:
        return self.ip_hasher(address) if self.ip_hasher is not None else address

    def hash_network(self, text: str) -> Any:
        """A CIDR or address as `<hash>/<prefix>` (or raw when addresses may be shown)."""
        if self.ip_hasher is None:
            return text
        address, _, prefix = str(text).partition("/")
        try:
            ipaddress.ip_address(address)
        except ValueError:
            return self.scrub.ref(text, "network")
        hashed = f"ip:{self.ip_hasher(address)}"
        return f"{hashed}/{prefix}" if prefix.isdigit() else hashed

    def host_token(self, host: Any) -> Any:
        text = str(host or "")
        return text if text in self.allowed_hosts else self.scrub.token(text, "host")

    def mention(self, key: str, why: str) -> None:
        if key in catalog.CATALOG:
            self.catalog_reasons.setdefault(key, set()).add(why)

    async def metrics(self, fn: Callable[[Any], Any]) -> Any:
        return await self.dbs.metrics.read(fn)

    # ---- sections ----

    async def meta(self) -> dict[str, Any]:
        rows = await self.metrics(lambda conn: fleet_view(conn, self.now))
        self.fleet_rows = [dict(row) for row in rows][:256]
        fresh = [row for row in self.fleet_rows if row.get("fresh")]
        colors = Counter(_safe_word(row.get("color"), r"[a-z]{1,16}") for row in fresh)
        uptimes = [_int(row.get("uptime_s")) for row in fresh]
        notes = [
            "Every string that came from outside Roxy (paths, endpoint templates, User-Agents, place ids, error "
            "messages, rule patterns, admin text, recommendation titles) is under untrusted and referenced by id.",
            "Counts in top_clients.user_agents and in errors.count are all time; every other table covers the window.",
            "top_clients.ips[].user_agent is the newest User-Agent of that address in the last 15 minutes (Live rows).",
            "capacity.metrics_pipeline holds the counters of the worker that built this export only.",
        ]
        if self.ip_mode == "raw":
            notes.append("IP addresses are shown raw because export_include_ips is 1.")
        else:
            notes.append("IP addresses are keyed hashes (ip:<hash>); raw addresses never appear in this file.")
        if self.detail == "summary":
            notes.append(
                "This is the summary detail: shorter lists, only overridden settings and changed recommendation "
                "rules, no evidence details, no error samples, no code symbols; ask for detail=full for everything."
            )
        return {
            "schema_version": SCHEMA_VERSION,
            "schema_minor": SCHEMA_MINOR,
            "generated_at": models.iso(self.now) or "",
            "generated_by": self.generated_by,
            "roxy_version": _safe_word(self.sources.release, r"[0-9A-Za-z._+-]{1,64}", "unknown"),
            "detail": self.detail,
            "window": {
                "key": self.window_key,
                "start": models.iso(self.win.start) or "",
                "end": models.iso(self.win.end) or "",
                "granularity": self.win.granularity,
                "rollup_unit": "hour" if self.win.span <= 86_400 else "day",
            },
            "timezone": _safe_word(self.tz, r"[A-Za-z0-9_+/-]{1,64}", "UTC"),
            "worker_count": {
                "expected_per_color": int(self.sources.workers_expected),
                "fresh": len(fresh),
                "colors": [{"color": color, "fresh_workers": n} for color, n in sorted(colors.items())],
            },
            "uptime_s": None if self.sources.started_at is None else max(0, int(self.now - self.sources.started_at)),
            "fleet_uptime_s": max(uptimes) if uptimes else None,
            "ip_addresses": self.ip_mode,
            "config_version": _int(getattr(self.snap, "version", 0)),
            "rules_version": _int(getattr(self.rules_snap, "version", 0)),
            "catalog_version": catalog.CATALOG_VERSION,
            "limits": {name: int(value) for name, value in asdict(self.limits).items()},
            "notes": notes,
        }

    async def config(self) -> dict[str, Any]:
        snap = self.snap
        overrides = getattr(snap, "overrides", {})
        meta = getattr(snap, "meta", {})
        entries: list[dict[str, Any]] = []
        overridden = 0
        for key, spec in catalog.CATALOG.items():
            is_set = key in overrides
            overridden += int(is_set)
            if is_set:
                self.mention(key, "changed")
            if not self.limits.all_settings and not is_set:
                continue
            value = snap[key]
            changed = meta.get(key)
            entries.append(
                {
                    "key": key,
                    "group": spec.group.value,
                    "value": catalog.REDACTED if spec.sensitive else self.scrub.value(thaw(value), "setting_value"),
                    "default": catalog.REDACTED if spec.sensitive else thaw(catalog.DEFAULTS.get(key, spec.default)),
                    "overridden": is_set,
                    "changed_at": _iso(changed[0]) if changed else None,
                    "changed_by": actor_kind(changed[1]) if changed else None,
                    "risk": spec.risk.value,
                    "high_risk_reason": None if spec.sensitive else spec.is_high_risk_value(value),
                    "apply": spec.apply.value,
                }
            )
        return {
            "total": len(catalog.CATALOG),
            "overridden": overridden,
            "shown": "all" if self.limits.all_settings else "overridden",
            "invalid_overrides": len(getattr(snap, "invalid", ()) or ()),
            "settings": entries,
            "credential": await self._credential(),
            "rotator": self._rotator(),
        }

    async def _credential(self) -> dict[str, Any]:
        egress = self.sources.egress
        present, status, set_at = False, "missing", None
        if egress is not None:
            info = egress.credential.status()
            present, status, set_at = bool(info.present), str(info.status), info.set_at
        else:
            found = await self.dbs.control.read(read_credential.credential_meta)
            if found is not None:
                present = found.get("fingerprint") is not None
                status = str(found.get("status") or ("unknown" if present else "missing"))
                set_at = found.get("set_at")
        self.credential = {"present": present, "status": _safe_word(status, r"[a-z_]{1,32}", "unknown")}
        return {"present": present, "status": self.credential["status"], "set_at": _iso(set_at)}

    def _rotator(self) -> dict[str, Any]:
        egress = self.sources.egress
        if egress is None:
            return {"configured": None, "host": None, "source": None}
        rotator = egress.rotator
        configured = bool(rotator.configured())
        host = _host_name(masked_url(rotator.masked_url())) if configured else None
        source = rotator.url_source()
        return {
            "configured": configured,
            "host": host,
            "source": None if source is None else _safe_word(source, r"[a-z_]{1,24}"),
        }

    # ---- rules ----

    _REF_COLUMNS: Final = {
        "pattern": "rule_pattern",
        "needle": "rule_pattern",
        "canonical_key": "rule_pattern",
        "message": "admin_text",
        "note": "admin_text",
        "reason_text": "admin_text",
        "header": "header_name",
        "name": "name",
    }
    _TIME_COLUMNS: Final = frozenset({"created_at", "updated_at", "expires_at", "last_hit_at"})
    _ACTOR_COLUMNS: Final = frozenset({"created_by", "updated_by"})
    _LIST_COLUMNS: Final = frozenset({"methods", "normalize_flags"})

    def _rule_row(self, table: str, row: Mapping[str, Any]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for column, value in row.items():
            if table == "bans" and column == "subject":
                continue  # `_ban_subject` below: hashed or referenced by its type
            if value is None:
                out[column] = None
            elif column in self._TIME_COLUMNS:
                out[column] = _iso(value)
            elif column in self._ACTOR_COLUMNS:
                out[column] = actor_kind(value)
            elif column in self._REF_COLUMNS:
                out[column] = "" if value == "" else self.scrub.ref(value, self._REF_COLUMNS[column])
            elif column == "cidr":
                out[column] = self.hash_network(str(value))
            elif column == "bucket_key":
                described = describe_key(str(value))
                out[column] = self.scrub.ref(value, "bucket_key")
                out["bucket_kind"] = _safe_word(described.get("kind"))
                out["bucket_egress"] = described.get("egress") if described.get("egress") in _EGRESSES else None
            elif column in self._LIST_COLUMNS:
                out[column] = self.scrub.value(_list_column(value), "rule_value")
            else:
                out[column] = self.scrub.value(value, "rule_value")
        if table == "bans":
            out["subject"] = self._ban_subject(str(row.get("subject_type")), str(row.get("subject")))
            out["detector"] = self.scrub.opt_token(detector_of(row.get("created_by")), "detector")
        return out

    def _ban_subject(self, subject_type: str, subject: str) -> Any:
        if subject_type in ("ip", "cidr"):
            return self.hash_network(subject)
        if subject_type == "ua_hash":
            return self.scrub.token(subject, "ua_hash")
        return self.scrub.ref(subject, "place" if subject_type == "place" else "ban_subject")

    async def rules(self) -> dict[str, Any]:
        names = tuple(RULE_EXPORT_TABLES)
        rows = await self.dbs.control.read(lambda conn: {name: fetch_all(conn, RULE_TABLES[name]) for name in names})
        tables: list[dict[str, Any]] = []
        now = int(self.now)
        for name in names:
            spec = RULE_TABLES[name]
            found = list(rows.get(name) or [])
            withheld = 0
            if name in ("bans", "access_list"):
                found = [r for r in found if r.get("expires_at") is None or int(r["expires_at"]) > now]
            if name == "access_list":
                # Admin allowlist entries are the admins' own addresses: counted, never listed.
                withheld = sum(1 for r in found if r.get("kind") == "allow_admin")
                found = [r for r in found if r.get("kind") != "allow_admin"]
            self.rule_rows[name] = found
            cap = sum(ACCESS_LIST_CAPS.values()) if name == "access_list" else spec.cap
            shown = found[: self.limits.rule_rows]
            tables.append(
                {
                    "table": name,
                    "label": spec.label,
                    "total": len(found),
                    "cap": cap or None,
                    "truncated": len(found) > len(shown),
                    "withheld": withheld,
                    "rows": [self._rule_row(name, row) for row in shown],
                }
            )
        return {"version": _int(getattr(self.rules_snap, "version", 0)), "tables": tables}

    # ---- recommendations ----

    def _recommendation(self, rec: models.Recommendation) -> dict[str, Any]:
        scrub = self.scrub
        evidence = rec.evidence
        changes: list[dict[str, Any]] = []
        for change in rec.changes:
            if change.kind in ("setting", "host_add") and change.key:
                self.mention(change.key, "recommendation")
            changes.append(
                {
                    "kind": change.kind,
                    "key": scrub.opt_token(change.key, "setting_key"),
                    "table": scrub.opt_token(change.table, "table"),
                    "bucket_key": scrub.opt_ref(change.bucket_key, "bucket_key"),
                    "category": scrub.opt_token(change.category, "category"),
                    "match": scrub.value(change.match, "rule_match"),
                    "current": scrub.value(change.current, "change_value"),
                    "proposed": scrub.value(change.proposed, "change_value"),
                    "text": scrub.opt_ref(change.text, "recommendation_text"),
                }
            )
        return {
            "id": scrub.token(rec.id, "id"),
            "rule_id": scrub.token(rec.rule_id, "rule_id"),
            "family": scrub.token(rec.family, "family"),
            "fingerprint": scrub.token(rec.fingerprint, "fingerprint"),
            "state": rec.state if rec.state in models.STATES else "unknown",
            "severity": rec.severity,
            "computed_severity": rec.computed_severity if rec.computed_severity in models.SEVERITIES else rec.severity,
            "confidence": rec.confidence,
            "risk": rec.risk,
            "safe_auto": bool(rec.safe_auto),
            "dry_run_available": bool(rec.dry_run_available),
            "subject": scrub.ref(rec.subject, "recommendation_subject"),
            "title": scrub.ref(rec.title, "recommendation_text"),
            "explanation": scrub.refs(rec.explanation, "recommendation_text"),
            "expected_impact": scrub.refs(rec.expected_impact, "recommendation_text"),
            "evidence": {
                "window_from": _iso(evidence.window_from),
                "window_to": _iso(evidence.window_to),
                "metrics": [
                    {
                        "name": scrub.token(metric.name, "metric_name"),
                        "value": scrub.value(metric.value, "metric_value"),
                        "unit": scrub.opt_token(metric.unit or None, "unit"),
                    }
                    for metric in evidence.metrics[: models.MAX_METRICS]
                ],
                "sample_size": int(evidence.sample_size),
                "links": [scrub.ref(link, "link") for link in evidence.links[: models.MAX_LINKS]]
                if self.limits.evidence_details
                else [],
                "details": scrub.value(evidence.details, "evidence") if self.limits.evidence_details else None,
            },
            "changes": changes,
            "created_at": _iso(rec.created_at),
            "updated_at": _iso(rec.updated_at),
            "expires_at": _iso(rec.expires_at),
            "snoozed_until": _iso(rec.snoozed_until),
            "dismissed_reason": scrub.opt_token(rec.dismissed_reason, "dismiss_reason"),
        }

    async def recommendations(self) -> list[dict[str, Any]]:
        engine = self.sources.insights_engine()
        closed = ("applied", "auto_applied", "dismissed", "rolled_back")
        states = ("open", "snoozed") if self.detail == "summary" else ("open", "snoozed", *closed)
        found: list[models.Recommendation] = await engine.list(states=states, limit=1000)
        self.dismissed = [
            rec for rec in await engine.list(states=("dismissed",), limit=500) if rec.dismissed_reason == "not_accurate"
        ]
        recent = [rec for rec in found if rec.state in ("open", "snoozed") or (rec.updated_at or 0) >= self.win.start]
        recent.sort(
            key=lambda r: (r.state not in ("open", "snoozed"), -models.severity_rank(r.severity), -(r.updated_at or 0))
        )
        return [self._recommendation(rec) for rec in recent[: self.limits.recommendations]]

    # ---- open issues ----

    def _state_issue(self, key: str, **fields: Any) -> dict[str, Any]:
        described = describe_key(key)
        kind = _safe_word(described.get("kind"))
        constant = kind in ("credential", "rotator_park", "rotator_streak", "global", "egress")
        target = described.get("target")
        return {
            "kind": kind,
            "egress": described.get("egress") if described.get("egress") in _EGRESSES else None,
            "target": self.scrub.token(target, "upstream_key") if constant else self.scrub.ref(target, "upstream_key"),
            "state": "active",
            "failures": None,
            "remaining_s": None,
            "hits": None,
            "source": None,
        } | fields

    async def open_issues(self) -> dict[str, Any]:
        def read_health(conn: Any) -> dict[str, Any] | None:
            run_id = health_store.latest_run_id(conn)
            return None if run_id is None else health_store.get_run(conn, run_id, now=self.now)

        self.health_run = await self.metrics(read_health)
        health: list[dict[str, Any]] = []
        for result in (self.health_run or {}).get("results") or []:
            if result.get("status") in ("warn", "fail"):
                health.append(
                    {
                        "check_id": self._check_id(str(result.get("check_id"))),
                        "status": str(result["status"]),
                        "critical": bool(result.get("critical")),
                        "run_id": int((self.health_run or {}).get("id") or 0),
                    }
                )
        breakers, active = await self.dbs.hot.read(
            lambda conn: (breaker.snapshot(conn, self.now, limit=200), cooldowns.active_rows(conn, self.now_ms, 200))
        )
        breaker_items = [
            self._state_issue(
                str(item["key"]),
                state=_safe_word(item.get("state")),
                failures=_opt_int(item.get("failures")),
                remaining_s=_opt_float(item.get("reopens_in_s")),
            )
            for item in breakers
            if item.get("state") != "closed"
        ]
        cooldown_items = [
            self._state_issue(
                row.key,
                remaining_s=round(row.remaining_s(self.now_ms), 3),
                hits=int(row.hits),
                source=self.scrub.token(row.source, "cooldown_source"),
            )
            for row in active
        ]
        degraded, switches = await self._degraded()
        return {
            "health": health,
            "breakers": breaker_items,
            "cooldowns": cooldown_items,
            "degraded": degraded,
            "switches": switches,
        }

    async def _degraded(self) -> tuple[list[dict[str, Any]], dict[str, bool]]:
        def read(conn: Any) -> tuple[dict[str, dict[str, Any]], Any, Any]:
            return (
                egress_state.leak_trips(conn),
                read_changes.service_state(conn, PAUSE_STATE_KEY),
                read_changes.service_state(conn, THROTTLE_ALL_STATE_KEY),
            )

        trips, pause, throttle_all = await self.dbs.control.read(read)
        items: list[dict[str, Any]] = []
        for egress, trip in sorted(trips.items()):
            items.append(
                {
                    "subsystem": "egress_leak_guard",
                    "state": self.scrub.token(egress, "egress"),
                    "detail": {
                        "since": _iso(trip.get("since")),
                        "reason": self.scrub.opt_token(trip.get("reason"), "trip_reason"),
                        "purpose": self.scrub.opt_token(trip.get("purpose"), "trip_purpose"),
                    },
                }
            )
        if self.credential.get("present") and self.credential.get("status") != "active":
            items.append({"subsystem": "credential", "state": self.credential["status"], "detail": None})
        egress = self.sources.egress
        if egress is not None and egress.rotator.configured():
            usable, reason, retry = egress.rotator.availability()
            if not usable:
                items.append(
                    {
                        "subsystem": "rotator",
                        "state": self.scrub.token(reason, "rotator_reason"),
                        "detail": {"retry_after_s": retry},
                    }
                )
        cache = self.sources.cache
        if cache is not None:
            with contextlib.suppress(Exception):
                disk = cache.disk_status()
                if not disk.get("OK"):
                    state = "memory_only" if disk.get("MemoryOnly") else "disk_off"
                    items.append({"subsystem": "cache_disk", "state": state, "detail": None})
        invalid_settings = len(getattr(self.snap, "invalid", ()) or ())
        invalid_rules = len(getattr(self.rules_snap, "invalid_rows", ()) or ())
        if invalid_settings or invalid_rules:
            items.append(
                {
                    "subsystem": "config",
                    "state": "invalid_rows",
                    "detail": {"settings": invalid_settings, "rules": invalid_rules},
                }
            )
        switches = {
            "paused": PauseState.from_json(pause).active(self.now),
            "throttle_all": ThrottleAllState.from_json(throttle_all).enabled,
        }
        return items, switches

    # ---- anomalies, rollups, endpoints, clients ----

    async def anomalies(self) -> list[dict[str, Any]]:
        rows = await self.metrics(
            lambda conn: read_history.anomalies_between(conn, self.win.start, self.win.end, self.limits.anomalies)
        )
        return [
            {
                "at": _iso(row.get("at")),
                "metric": self.scrub.token(row.get("metric"), "metric_name"),
                "baseline": _opt_float(row.get("baseline")),
                "observed": _opt_float(row.get("observed")),
                "zscore": _opt_float(row.get("zscore")),
                "window": self.scrub.token(row.get("window"), "window"),
            }
            for row in rows
        ]

    async def rollups(self) -> dict[str, Any]:
        rows = await self.metrics(lambda conn: queries.llm_rollup_summary(conn, self.win))
        buckets = []
        for row in rows:
            by_egress = {k: _int(v) for k, v in (row.get("roblox_429_by_egress") or {}).items() if k in _EGRESSES}
            buckets.append(
                {
                    "start": models.iso(row["start"]) or "",
                    "requests": _int(row.get("requests")),
                    "avoided_upstream_calls": _int(row.get("avoided_upstream_calls")),
                    "upstream_calls": _int(row.get("upstream_calls")),
                    "roblox_429_by_egress": by_egress,
                    "status_5xx": _int(row.get("status_5xx")),
                    "timeouts": _int(row.get("timeouts")),
                    "p50_ms": _opt_float(row.get("p50_ms")),
                    "p95_ms": _opt_float(row.get("p95_ms")),
                    "p99_ms": _opt_float(row.get("p99_ms")),
                    "caller_bytes_in": _int(row.get("caller_bytes_in")),
                    "caller_bytes_out": _int(row.get("caller_bytes_out")),
                    "upstream_bytes_in": _int(row.get("upstream_bytes_in")),
                    "upstream_bytes_out": _int(row.get("upstream_bytes_out")),
                    "rotator_bytes": _int(row.get("rotator_bytes")),
                }
            )
        return {"unit": "hour" if self.win.span <= 86_400 else "day", "buckets": buckets}

    def _endpoint(self, row: Mapping[str, Any]) -> dict[str, Any]:
        template = str(row.get("key") or "")
        rule = None
        with regex_budget(fresh=True), contextlib.suppress(Exception):
            rule = select_rule(self.rules_snap, template, "GET", bool(int(self.snap["cache_default_rules_enabled"])))
        return {
            "endpoint": self.scrub.ref(template, "endpoint"),
            "requests": _int(row.get("requests")),
            "upstream_calls": _int(row.get("upstream_calls")),
            "hit_ratio": _opt_float(row.get("hit_ratio")),
            "roblox_429": _opt_int(row.get("roblox_429")),
            "p50_ms": _opt_float(row.get("p50_ms")),
            "p95_ms": _opt_float(row.get("p95_ms")),
            "p99_ms": _opt_float(row.get("p99_ms")),
            "cache_rule_id": None if rule is None else int(rule.id),
            "cache_ttl_s": None if rule is None else int(rule.ttl),
            "cache_stale_ttl_s": None if rule is None else int(rule.stale_ttl),
        }

    async def top_endpoints(self) -> dict[str, Any]:
        limit = self.limits.top_endpoints
        data = await self.metrics(lambda conn: queries.llm_top_endpoints(conn, self.win, limit))
        return {
            "by_requests": [self._endpoint(row) for row in data["by_requests"]],
            "by_upstream_calls": [self._endpoint(row) for row in data["by_upstream_calls"]],
        }

    def _client(
        self,
        row: Mapping[str, Any],
        kind: str,
        scores: Mapping[str, float],
        agents: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> dict[str, Any]:
        key = str(row.get("key") or "")
        client: Any = self.hash_ip(key) if kind == "ip" else self.scrub.ref(key, "place")
        if kind == "ip" and self.ip_hasher is not None:
            client = f"ip:{client}"
        agent = (agents or {}).get(key) or {}
        return {
            "client": client,
            "requests": _int(row.get("requests")),
            "refused": _int(row.get("refused")),
            "served": _int(row.get("served")),
            "bytes": _int(row.get("bytes")),
            "refused_pct": _opt_float(row.get("refused_pct")),
            "rate1": _opt_float(row.get("rate1")),
            "rate5": _opt_float(row.get("rate5")),
            "rate60": _opt_float(row.get("rate60")),
            "top_endpoint": self.scrub.opt_ref(row.get("top_endpoint"), "endpoint"),
            "user_agent": self.scrub.opt_ref(agent.get("user_agent"), "user_agent"),
            "bot_score": _opt_float(scores.get(key)) if kind == "ip" else None,
        }

    async def top_clients(self) -> dict[str, Any]:
        size = self.limits.top_clients
        ua_limit = self.limits.user_agents

        def read(conn: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], Any]:
            page = Page(size=size, sort="requests")
            places = queries.client_table_sync(conn, self.win, "place", now=self.now, page=page)["rows"]
            ips = queries.client_table_sync(conn, self.win, "ip", now=self.now, page=page)["rows"]
            agents = read_security.user_agents(conn, limit=ua_limit)["rows"]
            # The newest User-Agent of each address, from the Live rows of the last 15 minutes.
            latest = read_clients.latest_user_agents(conn, [str(row.get("key") or "") for row in ips[:size]])
            return places, ips, agents, latest

        places, ips, agents, latest = await self.metrics(read)
        scores: Mapping[str, float] = {}
        providers = self.sources.providers or getattr(self.sources.engine, "providers", None)
        if providers is not None:
            with contextlib.suppress(Exception):
                scores = await providers.client_scores() or {}
        return {
            "places": [self._client(row, "place", scores) for row in places[:size]],
            "ips": [self._client(row, "ip", scores, latest) for row in ips[:size]],
            "user_agents": [
                {
                    "user_agent": self.scrub.ref(row["user_agent"], "user_agent"),
                    "ua_hash": ua_hash(str(row["user_agent"])),
                    "count": _int(row.get("count")),
                    "first_seen": _iso(row.get("first_seen")),
                    "last_seen": _iso(row.get("last_seen")),
                }
                for row in agents[:ua_limit]
            ],
        }

    # ---- errors ----

    def _module_line(self, value: Any) -> Any:
        if not value:
            return None
        text = str(value)
        return text if re.fullmatch(r"[A-Za-z0-9_./-]{1,200}:[0-9]{1,6}", text) else self.scrub.ref(text, "module_line")

    async def errors(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        def read(conn: Any) -> tuple[list[dict[str, Any]], dict[str, int]]:
            return (
                read_history.error_signatures(conn, limit=500),
                read_history.error_counts(conn, self.win.start, self.win.end),
            )

        rows, in_window = await self.metrics(read)
        rows.sort(key=lambda r: (-_int(r.get("count")), -_int(r.get("last_seen"))))
        errors = [
            {
                "signature": self.scrub.ref(row["signature"], "error_signature"),
                "count": _int(row.get("count")),
                "count_in_window": _int(in_window.get(str(row["signature"]))),
                "first_seen": _iso(row.get("first_seen")),
                "last_seen": _iso(row.get("last_seen")),
                "source": self.scrub.token(row.get("source") or "", "error_source"),
                "module_line": self._module_line(row.get("module_line")),
                "sample": self.scrub.opt_ref(row.get("last_detail"), "error_message"),
            }
            for row in rows[: self.limits.errors]
        ]
        samples: list[dict[str, Any]] = []
        for row in rows:
            if len(samples) >= self.limits.error_samples:
                break
            lines, frames = traceback_tail(str(row.get("traceback_redacted") or ""))
            if not lines:
                continue
            samples.append(
                {
                    "signature": self.scrub.ref(row["signature"], "error_signature"),
                    "count": _int(row.get("count")),
                    "module_line": self._module_line(row.get("module_line")),
                    "frames": frames,
                    "traceback": [self.scrub.ref(line, "traceback") for line in lines],
                }
            )
        return errors, samples

    async def upstream_429_samples(self) -> list[dict[str, Any]]:
        limit = self.limits.samples_429
        rows = await self.metrics(lambda conn: queries.recent_429s(conn, limit))
        out = []
        for row in rows:
            if _int(row.get("at_ms")) < self.win.start * 1000:
                continue
            headers = [
                {"name": self.scrub.token(name, "header_name"), "value": self._ratelimit_value(value)}
                for name, value in list((row.get("ratelimit_headers") or {}).items())[:20]
            ]
            out.append(
                {
                    "at": _iso_ms(row.get("at_ms")),
                    "endpoint": self.scrub.ref(row.get("endpoint_template") or "", "endpoint"),
                    "host": self.host_token(row.get("host")),
                    "egress": self.scrub.token(row.get("egress") or "", "egress"),
                    "retry_after_s": _opt_float(row.get("retry_after_s")),
                    "ratelimit_headers": headers,
                    "request_id": self.scrub.opt_token(row.get("request_id"), "request_id"),
                }
            )
        return out

    def _ratelimit_value(self, value: Any) -> Any:
        if value is None or isinstance(value, int | float):
            return self.scrub.value(value)
        text = str(value)
        # Roblox's rate limit values are numbers, commas, semicolons and `w=`: no room for words.
        return text if re.fullmatch(r"[0-9][0-9 ,;=.w]{0,79}", text) else self.scrub.ref(text, "header_value")

    # ---- egress and capacity ----

    async def egress(self) -> dict[str, Any]:
        billing_day = int(self.snap["rotator_billing_day"])
        start, end = egress_state.billing_cycle(self.now, billing_day)
        today = day_start_for(self.now)
        rotator = reasons.Egress.ROTATOR.value

        def read(conn: Any) -> tuple[int, list[int], int, dict[str, int]]:
            used = usage_since(conn, rotator, start)
            trailing = read_upstream.rotator_daily_bytes(conn, today - egress_state.TRAILING_DAYS * 86_400, today)
            return used, trailing, usage_since(conn, rotator, today), queries.egress_bytes(conn, self.win)

        used, trailing, today_bytes, window_bytes = await self.metrics(read)
        projection = egress_state.project_cycle(
            cycle_start=start, cycle_end=end, now_s=self.now, used_bytes=used, trailing=trailing
        )
        quota = int(float(self.snap["rotator_quota_gb_per_month"]) * DECIMAL_GB)
        price = float(self.snap["rotator_price_per_gb_usd"])
        configured: bool | None = None
        usable: bool | None = None
        reason: Any = None
        if self.sources.egress is not None:
            rotator_pool = self.sources.egress.rotator
            configured = bool(rotator_pool.configured())
            usable_now, why, _retry = rotator_pool.availability()
            usable = bool(usable_now)
            reason = self.scrub.token(why, "rotator_reason") if why else None
        return {
            "window_bytes": {k: _int(v) for k, v in window_bytes.items() if k in _EGRESSES},
            "rotator": {
                "configured": configured,
                "usable": usable,
                "reason": reason,
                "cycle_start": _iso(start),
                "cycle_end": _iso(end),
                "used_bytes": int(used),
                "today_bytes": int(today_bytes),
                "quota_bytes": quota or None,
                "remaining_bytes": max(0, quota - used) if quota > 0 else None,
                "projection": projection.as_dict()
                | {
                    "band": self.scrub.opt_token(projection.band, "projection"),
                    "band_reason": self.scrub.opt_token(projection.band_reason, "projection"),
                },
                "projected_pct_of_quota": egress_state.pct_of(projection.projected_bytes, quota),
                "cost_so_far_usd": egress_state.cost_usd(used, price),
                "projected_cost_usd": egress_state.cost_usd(projection.projected_bytes, price)
                if projection.projected_bytes is not None
                else None,
            },
        }

    async def capacity(self) -> dict[str, Any]:
        workers = [
            {
                "pid": _int(row.get("pid")),
                "color": _safe_word(row.get("color"), r"[a-z]{1,16}"),
                "is_leader": bool(row.get("is_leader")),
                "uptime_s": _opt_int(row.get("uptime_s")),
                "rss_bytes": _opt_int(row.get("rss")),
                "loop_lag_ms_p99": _opt_float(row.get("loop_lag_ms_p99")),
                "open_connections": _opt_int(row.get("open_conns")),
                "inflight_upstream": _opt_int(row.get("inflight_upstream")),
                "requests": _int(row.get("requests")),
                "proxied": _int(row.get("proxied")),
                "version": self.scrub.opt_token(row.get("version"), "version"),
            }
            for row in self.fleet_rows
            if row.get("fresh")
        ]
        history = await self.metrics(lambda conn: read_history.worker_history(conn, self.win.start, self.win.end))
        saturation = []
        for worker_id, samples in sorted(history.items())[:64]:
            parts = str(worker_id).split(":")
            pid = int(parts[-2]) if len(parts) >= 3 and parts[-2].isdigit() else None
            cpu = [s["cpu_pct"] for s in samples if s.get("cpu_pct") is not None]
            cpu_max = [s["cpu_pct_max"] for s in samples if s.get("cpu_pct_max") is not None]
            lag = [s["loop_lag_ms_p99"] for s in samples if s.get("loop_lag_ms_p99") is not None]
            rss = [s["rss"] for s in samples if s.get("rss") is not None]
            saturation.append(
                {
                    "pid": pid,
                    "minutes": len(samples),
                    "cpu_pct_avg": round(sum(cpu) / len(cpu), 2) if cpu else None,
                    "cpu_pct_max": _opt_float(max(cpu_max)) if cpu_max else None,
                    "loop_lag_ms_p99_max": _opt_float(max(lag)) if lag else None,
                    "rss_max": _opt_int(max(rss)) if rss else None,
                }
            )
        paths = [Path(db.path) for db in self.dbs.all()]
        sizes = await asyncio.to_thread(file_sizes, paths)
        databases = [
            {
                "name": _safe_word(name, r"[a-z_]{1,32}\.db", "database"),
                "bytes": _int(info.get("bytes")),
                "wal_bytes": _int(info.get("wal_bytes")),
                "shm_bytes": _int(info.get("shm_bytes")),
            }
            for name, info in sorted(sizes.items())
        ]
        total = free = None
        state_dir = self.sources.state_dir
        if state_dir is not None:
            with contextlib.suppress(OSError):
                usage = await asyncio.to_thread(shutil.disk_usage, state_dir)
                total, free = int(usage.total), int(usage.free)
        pipeline: dict[str, int] = {}
        recorder = self.sources.recorder
        if recorder is not None:
            with contextlib.suppress(Exception):
                stats = recorder.stats()
                pipeline = {key: _int(stats.get(key)) for key in _PIPELINE_KEYS if isinstance(stats.get(key), int)}
        return {
            "workers": workers,
            "saturation": saturation,
            "databases": databases,
            "disk_total_bytes": total,
            "disk_free_bytes": free,
            "metrics_pipeline": pipeline,
            "metrics_pipeline_scope": "this_worker" if recorder is not None else "unavailable",
        }

    # ---- changes, catalog, rule configuration ----

    def _change_target(self, item: Mapping[str, Any]) -> Any:
        if item.get("kind") == "setting":
            return self.scrub.token(item.get("key") or "", "setting_key")
        target = str(item.get("target") or "")
        table, _, ident = target.partition(":")
        if table in RULE_TABLES and re.fullmatch(r"[0-9a-f]{1,64}|[0-9]{1,20}", ident):
            return target
        return self.scrub.token(target, "rule_target")

    async def changes(self) -> list[dict[str, Any]]:
        limit = self.limits.changes
        # The read model returns the oldest changes first (bounded); read its whole bound and keep the newest.
        rows = await self.dbs.control.read(
            lambda conn: read_changes.recent_changes(conn, self.win.start, self.win.end + 1, read_changes.MAX_CHANGES)
        )
        out = []
        for item in rows[-limit:]:
            sensitive = False
            if item.get("kind") == "setting":
                spec = catalog.CATALOG.get(str(item.get("key")))
                sensitive = bool(spec is not None and spec.sensitive)
            else:
                # Admin allowlist entries are the admins' own addresses: withheld here as in `rules`.
                sensitive = str(item.get("target") or "").startswith("access_list:") and any(
                    isinstance(row, Mapping) and row.get("kind") == "allow_admin"
                    for row in (item.get("before"), item.get("after"))
                )
            action = item.get("action")
            out.append(
                {
                    "kind": "setting" if item.get("kind") == "setting" else "rule",
                    "id": _int(item.get("id")),
                    "at": _iso(item.get("at")),
                    "target": self._change_target(item),
                    "action": None
                    if action is None
                    else (action if re.fullmatch(r"[a-z_]{1,40}(\.[a-z_]{1,40}){0,3}", str(action)) else None),
                    "before": catalog.REDACTED if sensitive else self.scrub.value(item.get("before"), "change_value"),
                    "after": catalog.REDACTED if sensitive else self.scrub.value(item.get("after"), "change_value"),
                    "by": actor_kind(item.get("by")) or "unknown",
                    "reason": self.scrub.opt_ref(item.get("reason"), "admin_text"),
                    "source": self.scrub.opt_token(item.get("source"), "change_source"),
                }
            )
        return out

    def catalog_entries(self) -> list[dict[str, Any]]:
        out = []
        for key in sorted(self.catalog_reasons):
            spec = catalog.CATALOG[key]
            out.append({"key": key, "reasons": sorted(self.catalog_reasons[key]), "spec": catalog.spec_to_dict(spec)})
        return out

    def insight_rule_config(self) -> list[dict[str, Any]]:
        """Every rule (full) or the rules an admin changed (summary): switch, severity override, thresholds."""
        overrides = getattr(self.snap, "overrides", {})
        out = []
        for rule in INSIGHT_RULES.values():
            slug = rule.slug
            enabled_key, severity_key = f"insight_{slug}_enabled", f"insight_{slug}_severity"
            keys = [enabled_key, severity_key]
            params = []
            for param in rule.params:
                key = f"insight_{slug}_{param.name}"
                keys.append(key)
                params.append(
                    {
                        "name": param.name,
                        "key": key,
                        "value": thaw(self.snap[key]),
                        "default": thaw(catalog.DEFAULTS.get(key)),
                        "unit": param.unit,
                    }
                )
            out.append(
                {
                    "rule_id": rule.rule_id,
                    "family": rule.family,
                    "title": rule.title,
                    "enabled": bool(int(self.snap[enabled_key])),
                    "severity": str(self.snap[severity_key]),
                    "changed": any(key in overrides for key in keys),
                    "params": params,
                }
            )
        return out if self.limits.all_settings else [item for item in out if item["changed"]]

    # ---- health, parity, potential issues, code map ----

    def _check_id(self, check_id: str) -> Any:
        found = health_checks.spec_for(check_id)
        if found is not None:
            host = found[1].get("host")
            if host is None or host in self.allowed_hosts:
                return check_id
        return self.scrub.ref(check_id, "check_id")

    def health_latest(self) -> dict[str, Any] | None:
        run = self.health_run
        if run is None:
            return None
        results = []
        for item in run.get("results") or []:
            status = str(item.get("status") or "")
            if not self.limits.all_health_results and status not in ("warn", "fail"):
                continue
            check_id = str(item.get("check_id") or "")
            found = health_checks.spec_for(check_id)
            spec = found[0] if found is not None else None
            stored = str(item.get("explanation") or "")
            finding = stored
            if spec is not None and stored.startswith(spec.explanation):
                finding = stored[len(spec.explanation) :].strip()
            threshold = str(item.get("threshold") or "")
            fix_link = str(item.get("fix_link") or "")
            results.append(
                {
                    "check_id": self._check_id(check_id),
                    "title": spec.title if spec is not None else None,
                    "status": _safe_word(status, r"pass|warn|fail|n/a", "unknown"),
                    "critical": bool(item.get("critical")),
                    "measured": _opt_float(item.get("measured")),
                    "unit": self.scrub.opt_token(item.get("unit") or None, "unit"),
                    "threshold": (threshold if spec is not None and threshold == spec.thresholds else None)
                    or self.scrub.opt_token(threshold or None, "health_text"),
                    "explanation": spec.explanation if spec is not None else None,
                    "finding": self.scrub.refs(finding, "health_text"),
                    "fix_link": (fix_link if spec is not None and fix_link == spec.fix_link else None)
                    or self.scrub.opt_token(fix_link or None, "link"),
                    "value": self.scrub.opt_ref(item.get("value"), "health_value"),
                    "detail": self.scrub.value(item.get("detail") or {}, "health_detail"),
                }
            )
        return {
            "run_id": _int(run.get("id")),
            "trigger": self.scrub.token(run.get("trigger") or "", "trigger"),
            "state": self.scrub.token(run.get("state") or "", "state"),
            "started_at": _iso(run.get("started_at")),
            "finished_at": _iso(run.get("finished_at")),
            "version": self.scrub.opt_token(run.get("version"), "version"),
            "summary": self.scrub.value(run.get("summary") or {}, "health_summary"),
            "shown": "all" if self.limits.all_health_results else "not_passing",
            "results": results,
        }

    async def parity_status(self) -> dict[str, Any]:
        path = self.sources.changes_path or default_changes_path(self.sources.code_root)
        rows = await asyncio.to_thread(read_parity, path)
        if rows is None:
            return {"available": False, "source": None, "counts": {}, "shown": "all", "rows": []}
        counts = Counter(row["status"] for row in rows)
        shown = rows if self.limits.all_parity_rows else [row for row in rows if row["status"] != "covered"]
        return {
            "available": True,
            "source": "CHANGES.md",
            "counts": dict(sorted(counts.items())),
            "shown": "all" if self.limits.all_parity_rows else "not_covered",
            "rows": shown,
        }

    async def potential_issues(self) -> list[dict[str, Any]]:
        issues: list[dict[str, Any]] = []
        for key, spec in catalog.CATALOG.items():
            if spec.sensitive:
                continue
            value = self.snap[key]
            why = spec.is_high_risk_value(value)
            if why:
                issues.append({"kind": "setting_high_risk", "subject": key, "message": why, "value": thaw(value)})
                self.mention(key, "potential_issue")
                continue
            near = _near_risky(spec, value)
            if near is not None:
                issues.append(
                    {
                        "kind": "setting_near_risky",
                        "subject": key,
                        "message": f"{key} is {value}, within 10 percent of the risky value {near[0]}: {near[1]}",
                        "value": thaw(value),
                    }
                )
                self.mention(key, "potential_issue")
        for name, rows in self.rule_rows.items():
            caps: list[tuple[str, int, int]] = []
            if name == "access_list":
                # allow_admin rows were withheld from `rows`, so only bypass and deny are judged here.
                for kind, cap in ACCESS_LIST_CAPS.items():
                    if kind != "allow_admin":
                        caps.append((f"{name}:{kind}", sum(1 for r in rows if r.get("kind") == kind), cap))
            else:
                caps.append((name, len(rows), RULE_TABLES[name].cap))
            for subject, count, cap in caps:
                if cap and count >= 0.8 * cap:
                    issues.append(
                        {
                            "kind": "cap_over_80_pct",
                            "subject": subject if subject in RULE_TABLES else self.scrub.token(subject, "table"),
                            "message": f"{count} of {cap} rows are used ({round(count * 100.0 / cap, 1)} percent).",
                            "value": {"count": count, "cap": cap},
                        }
                    )
        issues += await self._zero_hit_rules()
        for result in (self.health_run or {}).get("results") or []:
            if str(result.get("check_id")) == "H-CONFIG" and result.get("status") in ("warn", "fail"):
                issues.append(
                    {
                        "kind": "health_config",
                        "subject": "H-CONFIG",
                        "message": f"The latest health run reports H-CONFIG as {result['status']}.",
                        "value": self.scrub.opt_ref(result.get("value"), "health_value"),
                    }
                )
        for rec in self.dismissed[:20]:
            issues.append(
                {
                    "kind": "dismissed_not_accurate",
                    "subject": self.scrub.token(rec.rule_id, "rule_id"),
                    "message": "An admin dismissed this recommendation as not accurate: the rule may have a bug.",
                    "value": {
                        "id": self.scrub.token(rec.id, "id"),
                        "subject": self.scrub.ref(rec.subject, "recommendation_subject"),
                    },
                }
            )
        return issues[: self.limits.potential_issues]

    async def _zero_hit_rules(self) -> list[dict[str, Any]]:
        hits = await self.metrics(lambda conn: read_history.rule_hits(conn))
        tracked = {table for table, _key in hits}
        out: list[dict[str, Any]] = []
        for table in sorted(tracked & set(self.rule_rows)):
            pk = RULE_TABLES[table].pk
            for row in self.rule_rows[table]:
                if not row.get("enabled", 1):
                    continue
                ident = str(row.get(pk))
                if (table, ident) in hits:
                    continue
                out.append(
                    {
                        "kind": "rule_zero_hits",
                        "subject": self.scrub.token(f"{table}:{ident}", "rule_target")
                        if not re.fullmatch(r"[0-9a-f]{1,64}|[0-9]{1,20}", ident)
                        else f"{table}:{ident}",
                        "message": "No hit is recorded for this enabled rule (hits are recorded for this table).",
                        "value": None,
                    }
                )
                if len(out) >= 50:
                    return out
        return out

    def code_map(self) -> dict[str, Any]:
        symbols = bool(self.limits.code_symbols)
        return {
            "version": _safe_word(self.sources.release, r"[0-9A-Za-z._+-]{1,64}", "unknown"),
            "root": self.scan.root,
            "symbols_included": symbols,
            "truncated": self.scan.truncated,
            "modules": [
                {"path": module["path"], "doc": module["doc"], "symbols": module["symbols"] if symbols else []}
                for module in self.scan.modules
            ],
        }

    # ---- the whole document ----

    async def document(self) -> dict[str, Any]:
        meta = await self.meta()
        config = await self.config()
        rules = await self.rules()
        recommendations = await self.recommendations()
        open_issues = await self.open_issues()
        anomalies = await self.anomalies()
        rollups = await self.rollups()
        top_endpoints = await self.top_endpoints()
        top_clients = await self.top_clients()
        errors, error_samples = await self.errors()
        samples_429 = await self.upstream_429_samples()
        egress = await self.egress()
        capacity = await self.capacity()
        changes = await self.changes()
        potential = await self.potential_issues()
        health = self.health_latest()
        parity = await self.parity_status()
        return {
            "schema_version": SCHEMA_VERSION,
            "schema_minor": SCHEMA_MINOR,
            "meta": meta,
            "instructions": INSTRUCTIONS,
            "config": config,
            "rules": rules,
            "recommendations": recommendations,
            "open_issues": open_issues,
            "anomalies": anomalies,
            "rollups": rollups,
            "top_endpoints": top_endpoints,
            "top_clients": top_clients,
            "errors": errors,
            "upstream_429_samples": samples_429,
            "egress": egress,
            "capacity": capacity,
            "changes": changes,
            "catalog": self.catalog_entries(),
            "insight_rule_config": self.insight_rule_config(),
            "health_latest": health,
            "error_samples": error_samples,
            "parity_status": parity,
            "potential_issues": potential,
            "code_map": self.code_map(),
            "untrusted": [],  # filled from the pool by `finalize`, on a worker thread
        }


RULE_EXPORT_TABLES: Final[tuple[str, ...]] = (
    "rules_cache",
    "rules_endpoint_limit",
    "rules_endpoint_block",
    "rules_user_agent",
    "rules_header",
    "rules_routing",
    "upstream_limits",
    "credential_allowlist",
    "throttle_tiers",
    "cache_ignored_params",
    "ignored_value_headers",
    "ignored_paths",
    "access_list",
    "bans",
)
"""Plan 12.3 `rules`: cache, endpoint, block, UA, header and routing rules, bucket overrides, the credential
allowlist, tiers, ignored parameters, headers and paths, bypass and deny entries, active bans."""

_EGRESSES: Final = frozenset(str(member.value) for member in reasons.Egress)
_PIPELINE_KEYS: Final[tuple[str, ...]] = (
    "metrics_dropped",
    "record_errors",
    "capture_errors",
    "capture_dropped",
    "history_dropped",
    "rollup_overflow",
    "dims_last_minute",
    "templates_known",
    "templates_rejected",
    "fingerprints_dropped",
    "events_aggregated",
    "live_sampled_out",
)


def _near_risky(spec: Any, value: Any) -> tuple[Any, str] | None:
    """`(threshold, why)` when a numeric value is within 10 percent of a numeric high-risk threshold."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    for condition in spec.high_risk_if:
        threshold = condition.value
        if isinstance(threshold, bool) or not isinstance(threshold, int | float) or threshold == 0:
            continue
        op = condition.op.value
        margin = abs(threshold) * 0.1
        if op in ("gt", "gte") and threshold - margin <= value < threshold:
            return threshold, condition.why
        if op in ("lt", "lte") and threshold < value <= threshold + margin:
            return threshold, condition.why
    return None


def traceback_tail(text: str) -> tuple[list[str], int]:
    """The last `MAX_TRACEBACK_FRAMES` frames of a traceback (and the final error line), as lines, plus the count."""
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return [], 0
    starts = [i for i, line in enumerate(lines) if line.lstrip().startswith('File "')]
    if starts:
        first = starts[-MAX_TRACEBACK_FRAMES] if len(starts) > MAX_TRACEBACK_FRAMES else starts[0]
        kept = lines[first:]
    else:
        kept = lines
    return kept[-MAX_TRACEBACK_LINES:], min(len(starts), MAX_TRACEBACK_FRAMES)


def _redact_strings(value: Any) -> Any:
    """Every string of a JSON value through `redact_text` (the last line of defense, plan 9.15)."""
    if isinstance(value, str):
        return redact_text(value) if value else value
    if isinstance(value, dict):
        return {key: _redact_strings(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_strings(item) for item in value]
    return value


def finalize(document: Mapping[str, Any], pool: UntrustedPool | None = None) -> tuple[dict[str, Any], bytes]:
    """Fill `untrusted` from `pool`, validate against the models (the schema), run the redaction pass, serialize.

    CPU work (thousands of strings): call it on a worker thread.
    """
    if pool is not None:
        document = {**document, "untrusted": pool.materialize()}
    model = LlmExport.model_validate(document)
    data = _redact_strings(model.model_dump(mode="json"))
    content = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return data, content


class ExportBusy(Exception):
    """`MAX_CONCURRENT_BUILDS` exports are being built in this worker already."""


async def build_export(
    sources: ExportSources,
    *,
    window: str = "24h",
    detail: str = "summary",
    ip_hasher: IpHasher | None = None,
    ip_mode: str = "hashed_one_time",
    generated_by: str = "api",
) -> ExportResult:
    """The plan 12.3 document over `window` (`24h`, `7d`, `30d`) at `detail` (`summary`, `full`).

    `ip_hasher` turns a client address into its keyed hash (`common.export_ip_policy`); None means raw addresses
    (only when `export_include_ips` is 1). Raises `ExportBusy` when too many builds run in this worker, and
    `SharedStateUnavailable` when a database cannot be read.
    """
    global _BUILDS_IN_FLIGHT
    if window not in WINDOWS:
        raise ValueError(f"window must be one of {WINDOWS}")
    if detail not in DETAILS:
        raise ValueError(f"detail must be one of {DETAILS}")
    if ip_hasher is None and ip_mode != "raw":
        raise ValueError("an IP hasher is needed unless ip_mode is raw")
    if _BUILDS_IN_FLIGHT >= MAX_CONCURRENT_BUILDS:
        raise ExportBusy
    _BUILDS_IN_FLIGHT += 1
    try:
        scan = await asyncio.to_thread(source_scan, sources.code_root, sources.release)
        build = _Build(
            sources,
            window=window,
            detail=detail,
            ip_hasher=ip_hasher,
            ip_mode=ip_mode,
            generated_by=generated_by,
            scan=scan,
        )
        document = await build.document()
        data, content = await asyncio.to_thread(finalize, document, build.pool)
        return ExportResult(content, data, len(build.pool), build.pool.omitted, ip_mode)
    finally:
        _BUILDS_IN_FLIGHT -= 1


def copy_text(content: bytes) -> str:
    """What "Copy for LLM" puts on the clipboard: the 12.5 instruction block, a blank line, then the JSON."""
    return INSTRUCTIONS + "\n\n" + content.decode("utf-8")


# =========================================================================================== the file job


def _atomic_write(path: Path, data: bytes) -> None:
    """Write `data` to `path` through a temporary file in the same directory (mode 0640), then rename it."""
    temp = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(temp, flags, FILE_MODE)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp, FILE_MODE)  # the umask may have narrowed it; plan 12.2 says 0640
        os.replace(temp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temp)
        raise


def write_files(directory: Path, content: bytes, now: float, keep_days: int) -> dict[str, Any]:
    """Write the latest file and today's dated copy, then delete dated copies older than `keep_days` (blocking)."""
    directory.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
    day = datetime.fromtimestamp(now, UTC).date()
    _atomic_write(directory / FILE_NAME, content)
    dated = f"{DATED_PREFIX}{day.isoformat()}.json"
    _atomic_write(directory / dated, content)
    cutoff = day - timedelta(days=max(1, int(keep_days)))
    pruned = 0
    with os.scandir(directory) as entries:
        for index, entry in enumerate(entries):
            if index >= MAX_DIR_ENTRIES:
                break
            if not entry.is_file(follow_symlinks=False):
                continue
            match = _DATED_RE.fullmatch(entry.name)
            stale = False
            if match is not None:
                with contextlib.suppress(ValueError):
                    stale = datetime.strptime(match.group(1), "%Y-%m-%d").date() < cutoff
            elif _TEMP_RE.fullmatch(entry.name):
                with contextlib.suppress(OSError):
                    stale = entry.stat(follow_symlinks=False).st_mtime < now - 3600
            if stale:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(entry.path)
                    pruned += 1
    return {"bytes": len(content), "latest": FILE_NAME, "dated": dated, "pruned": pruned}


async def write_export_files(ctx: Any, *, job: Any = None, directory: Path | None = None) -> dict[str, Any]:
    """The leader job body: build the full export over `FILE_WINDOW` and write it under `<state>/exports/`."""
    from roxy.admin.api.common import export_ip_policy  # the admin layer owns the export IP policy

    sources = ExportSources.from_context(ctx)
    now = float(sources.clock.now())
    hasher, mode = export_ip_policy(ctx, f"llm-file:{int(now)}")
    result = await build_export(
        sources, window=FILE_WINDOW, detail=FILE_DETAIL, ip_hasher=hasher, ip_mode=mode, generated_by="leader"
    )
    content = result.content
    if len(content) > MAX_FILE_BYTES:
        log.warning("llm_export_file_too_large", extra={"fields": {"bytes": len(content)}})
        result = await build_export(
            sources, window=FILE_WINDOW, detail="summary", ip_hasher=hasher, ip_mode=mode, generated_by="leader"
        )
        content = result.content
    if job is not None and getattr(job, "epoch", 0) > 0:
        await job.check()  # a worker that lost the leadership while building writes nothing
    target = directory or Path(ctx.env.state_dir) / "exports"
    keep = int(ctx.settings.get("retention_exports_days"))
    written = await asyncio.to_thread(write_files, target, content, now, keep)
    written["untrusted"] = result.untrusted
    return written


def register_jobs(registry: Any, ctx: Any) -> None:
    """Add the leader job `llm_export_file` (hourly; plan 12.2). The integrator calls this in the lifespan."""
    from roxy.scheduler.jobs import Job

    async def run(job: Any) -> dict[str, Any]:
        return await write_export_files(ctx, job=job)

    registry.add(
        Job(
            FILE_JOB,
            FILE_INTERVAL_S,
            run,
            leader_only=True,
            timeout_s=300.0,
            description="Write the LLM export to exports/roxy-llm-export.json with a dated copy per day (12.2).",
        )
    )


def main(argv: Sequence[str] | None = None) -> int:
    """`python -m roxy.insights.llm_export --write-schema [PATH]` rewrites the committed schema file."""
    parser = argparse.ArgumentParser(description="Roxy LLM export schema tool")
    parser.add_argument("--write-schema", nargs="?", const=str(SCHEMA_PATH), default=None, metavar="PATH")
    args = parser.parse_args(argv)
    if args.write_schema is None:
        parser.print_help()
        return 2
    path = Path(args.write_schema)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(schema_text(), encoding="utf-8")
    return 0


__all__ = [
    "DETAILS",
    "FILE_JOB",
    "FILE_NAME",
    "INSTRUCTIONS",
    "LIMITS",
    "RULE_EXPORT_TABLES",
    "SCHEMA_PATH",
    "SCHEMA_VERSION",
    "WINDOWS",
    "ExportBusy",
    "ExportResult",
    "ExportSources",
    "LlmExport",
    "Scrubber",
    "SourceScan",
    "UntrustedPool",
    "build_export",
    "copy_text",
    "default_changes_path",
    "finalize",
    "is_trusted",
    "mask_ips",
    "parse_parity",
    "read_parity",
    "register_jobs",
    "schema_bytes",
    "schema_document",
    "schema_text",
    "source_scan",
    "static_vocabulary",
    "traceback_tail",
    "write_export_files",
    "write_files",
]


if __name__ == "__main__":
    raise SystemExit(main())
