"""System API (`/admin/api/v1/system`): the fleet, the leader, jobs, the metrics pipeline, errors, versions.

What this is
    The routes behind the System page (plan 14.1; parity rows 84, 85, 121, 122):
      * `GET /system/fleet`: the worker fleet with every parity row 84 field (pid, color, this worker, start time
        and uptime, RSS, requests, proxied, the recycle threshold, `counters_reset_at`, loop lag p99, open
        connections, in-flight upstream calls), per color Expected (`ROXY_WORKERS`) against the Count of fresh
        heartbeats, the gunicorn master pids and service uptime of both colors during a deploy, host uptime, the time
        since the last deploy switch, and tarpit connection use against `tarpit_connection_budget`.
        `GET /system/workers` is the same list as a table (`format=csv|json` downloads it).
      * `POST /system/workers/reset-counts`: "Reset counts" (parity row 122): zero requests and proxied for every
        worker and set `counters_reset_at`.
      * `GET /system/leader`: who leads (fleet-wide, from the hot.db lease) and under which epoch.
      * `GET /system/jobs`: every job with its interval and last run, from this worker's runner and from what the
        leader publishes, plus the WAL checkpoint durations.
      * `GET /system/metrics-pipeline`: this worker's metrics queue, drops and flushes, and every database's writer
        statistics and pending operations, plus every worker's drops of the last hour; `GET /system/persistence`:
        file and WAL sizes (parity row 85), with the disk growth history and the newest table sizes.
      * `GET /system/errors` (signatures, paged, searchable, exportable) and `GET /system/errors/detail?signature=`
        (one signature with its redacted traceback).
      * `GET /system/versions` and `GET /system/environment` (the non-secret environment summary).
      * `POST /system/flush`: the forced flush (parity row 121, v1 `?flush=1`): bumps `flush_requested_at` in
        `service_state`; this worker flushes at once, every other worker within about a second.

Why it exists
    v1's Service Health and Tools sections (worker table, persistence card, refresh with flush) and the plan's
    System page. Every number is labeled with where it comes from: fleet facts from shared state, per-worker facts
    (metrics queue, writer statistics) from the worker answering, so nothing is presented as fleet-wide that is not.

How it works
    Reads use the existing read models: `scheduler/heartbeat.py fleet_view` (with `scheduler/read_fleet.py` for the
    header and `/proc` facts), `storage/leases.py holder_epoch`, `JobRunner.status()`, the leader's published job
    status (`health/store.py read_job_status`), `MetricsRecorder.stats()`, `metrics/read_errors.py`. Writes are
    audited: the intent row is written first and a refusal to write it (C7) is a 503 with nothing done.
    `register_jobs(registry, ctx)` adds the per-worker job `admin_requests_watch`, which polls two `service_state`
    keys every second: `flush_requested_at` (flush this worker's metrics) and `memory_reset_at` (clear per-worker
    counters a data reset named, such as the tarpit statistics). The lifespan wires it (integrator).
    Each read route delegates to a function the System page (`roxy/admin/pages/system.py`) calls too (`fleet`,
    `workers_table`, `leader_state`, `jobs_view`, `pipeline_view`, `persistence_view`, `errors_answer`,
    `error_detail_view`, `versions_view`, `environment_view`), so the page and the API show the same numbers.

What to read next
    `roxy/scheduler/heartbeat.py`, `roxy/scheduler/jobs.py`, `roxy/metrics/recorder.py`, `roxy/admin/api/data.py`.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib.metadata
import json
import logging
import os
import platform
import sqlite3
from pathlib import Path
from typing import Annotated, Any, Final

from fastapi import Depends, Query, Request
from pydantic import Field

import roxy
from roxy.admin.api import common
from roxy.admin.api.common import (
    AdminSession,
    ApiBody,
    Column,
    CsrfChecked,
    ExportFormatDep,
    TableQuery,
    TableSpec,
    actor_for,
    request_id_of,
    run_mutation,
    table_params,
)
from roxy.config import audit, catalog
from roxy.config.audit import Actor
from roxy.config.constants import MAX_REASON_LENGTH
from roxy.core.redact import masked_url
from roxy.deps import get_ctx
from roxy.metrics import queries, read_errors, read_producers
from roxy.metrics.templating import TEMPLATE_VERSION
from roxy.scheduler import heartbeat, read_fleet
from roxy.scheduler.jobs import Job, JobRegistry
from roxy.scheduler.leader import LEADER_LEASE, JobContext
from roxy.storage import leases, read_sizes
from roxy.storage.db import SharedStateUnavailable
from roxy.storage.migrate import REQUIRED_SCHEMA, applied_versions

log = logging.getLogger("roxy.admin.api.system")

router = common.area_router("system")

FLUSH_KEY: Final = "flush_requested_at"
"""`service_state` key bumped by the forced flush (plan 6.2, parity row 121)."""

MEMORY_RESET_KEY: Final = "memory_reset_at"
"""`service_state` key: `{family: unix seconds}` of the last data reset of per-worker in-memory counters."""

MEMORY_FAMILIES: Final = ("tarpit",)
"""Families whose counters live in each worker's memory (cleared by the watcher in every worker)."""

WATCH_JOB: Final = "admin_requests_watch"
WATCH_INTERVAL_S: Final = 1.0
FLUSH_TIMEOUT_S: Final = 5.0
JOB_STATUS_FRESH_S: Final = 180.0
"""Published leader job status older than this is ignored (the leader publishes every 30 s)."""
GROWTH_DAYS: Final = 30
"""Days of hourly disk samples the persistence card charts (SYS-DISK projects from the same 30 days)."""
MAX_GROWTH_SAMPLES: Final = GROWTH_DAYS * 24 + 24
"""Most samples one answer carries: one an hour over `GROWTH_DAYS`, plus a day of slack (plan P9)."""

LIBRARIES: Final = ("fastapi", "starlette", "uvicorn", "gunicorn", "httpx", "pydantic", "jinja2", "regex")
CREDENTIAL_NAMES: Final = (
    "rotator_url",
    "smtp_password",
    "alert_emails",
    "alert_webhook_url",
    "credential_encryption_key",
    "totp_encryption_key",
    "ip_hash_key",
)
"""The systemd credentials of plan 9.8 (names only: the environment summary says which exist, never a value).

The Roblox credential is not in this list: only `egress/credential.py` may name or read its file (plan C1, 19.5
item 7), so the summary asks the credential manager instead (`credential` in the answer: bootstrap file present,
a dashboard value present, a value in use)."""

DEPLOYED_VERSION_FILES: Final = (Path("/var/lib/roxy-deploy/deployed_version"), Path("/var/lib/roxy/deployed_version"))
"""Where `deploy.sh` records the deployed commit; its mtime is the last color switch (plan 17.4 step 9)."""

WORKERS_TABLE: Final = TableSpec(
    name="workers",
    columns=(
        Column("pid", "PID", "The worker's process id."),
        Column("color", "Color", "The deploy color (blue, green, dev)."),
        Column("is_this_worker", "Serving you", "Whether this worker answered this request.", sortable=False),
        Column("is_leader", "Leader", "Whether this worker runs the fleet's scheduled jobs."),
        Column("fresh", "Fresh", "A heartbeat in the last 20 s; a stale row is a stopped or frozen worker."),
        Column("uptime_s", "Uptime", "Seconds since the worker started.", "s"),
        Column("rss_bytes", "Memory", "Resident memory (RSS).", "bytes"),
        Column("requests", "All requests", "Every request this worker served since its counters were reset.", "count"),
        Column("proxied", "Proxy requests", "Requests aimed at the proxy, served or refused.", "count"),
        Column("max_requests", "Recycle after", "The request count at which gunicorn recycles the worker.", "count"),
        Column("counters_reset_at", "Counters reset", "When Reset counts last zeroed this worker.", "s"),
        Column("loop_lag_ms_p99", "Loop lag p99", "How late the event loop woke up (99th percentile, 1 min).", "ms"),
        Column("open_connections", "Connections", "Open connections.", "count"),
        Column("inflight_upstream", "In flight", "Upstream calls in progress.", "count"),
        Column("last_seen", "Last heartbeat", "When this worker last reported (Unix seconds).", "s"),
        Column("version", "Version", "The release the worker runs."),
    ),
    default_sort="pid",
    default_order="asc",
)

ERRORS_TABLE: Final = TableSpec(
    name="errors",
    columns=(
        Column("signature", "Signature", "The error's stable signature (type, place and message shape)."),
        Column("count", "Count", "How often it happened (kept since first seen).", "count"),
        Column("first_seen", "First seen", "When it first happened (Unix seconds).", "s"),
        Column("last_seen", "Last seen", "When it last happened (Unix seconds).", "s"),
        Column("source", "Source", "Where it was raised (request, job, startup, ...)."),
        Column("module_line", "Where", "The raising frame as module:line.", sortable=False),
        Column("last_detail", "Last detail", "The last message (redacted).", sortable=False, caller_text=True),
    ),
    default_sort="last_seen",
)


# ================================================================================================ the watcher


async def write_state(
    ctx: Any,
    key: str,
    value: Any,
    *,
    actor: Actor | None = None,
    action: str = "",
    reason: str = "",
    request_id: str | None = None,
) -> int | None:
    """Set one `service_state` value in control.db, with an audit row in the same transaction when `actor` is given."""
    now = int(ctx.clock.now())

    def write(conn: sqlite3.Connection) -> int | None:
        audit_id = None
        if actor is not None:
            audit_id = audit.record(
                conn, actor, action, f"service_state:{key}", None, {key: value}, reason or None, request_id, at=now
            )
        conn.execute(
            "INSERT INTO service_state (key, value_json, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT (key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at",
            (key, json.dumps(value), now),
        )
        return audit_id

    result: int | None = await run_mutation(ctx.dbs.control.write(write))
    return result


def _read_watched(conn: sqlite3.Connection) -> dict[str, Any]:
    rows = conn.execute(
        "SELECT key, value_json FROM service_state WHERE key IN (?, ?)", (FLUSH_KEY, MEMORY_RESET_KEY)
    ).fetchall()
    out: dict[str, Any] = {}
    for key, text in rows:
        with contextlib.suppress(ValueError, TypeError):
            out[str(key)] = json.loads(text)
    return out


def reset_local_memory(ctx: Any, family: str) -> bool:
    """Clear this worker's in-memory counters of one family. Returns True when something was cleared."""
    if family == "tarpit":
        tarpit = getattr(getattr(ctx, "abuse", None), "tarpit", None)
        if tarpit is None:
            return False
        from roxy.abuse.tarpit import TarpitStats

        tarpit.stats = TarpitStats()
        return True
    return False


async def request_memory_reset(ctx: Any, families: list[str]) -> dict[str, Any]:
    """Ask every worker to clear the in-memory counters of `families` (this worker clears them at once)."""
    now = int(ctx.clock.now())

    def write(conn: sqlite3.Connection) -> dict[str, Any]:
        current = _read_watched(conn).get(MEMORY_RESET_KEY)
        value = dict(current) if isinstance(current, dict) else {}
        for family in families:
            value[family] = now
        conn.execute(
            "INSERT INTO service_state (key, value_json, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT (key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at",
            (MEMORY_RESET_KEY, json.dumps(value), now),
        )
        return value

    value: dict[str, Any] = await ctx.dbs.control.write(write)
    for family in families:
        reset_local_memory(ctx, family)
    watcher = getattr(ctx, WATCHER_ATTRIBUTE, None)
    if isinstance(watcher, RequestsWatcher):
        watcher.seen_memory.update(dict.fromkeys(families, now))
    return value


WATCHER_ATTRIBUTE: Final = "_admin_requests_watcher"


class RequestsWatcher:
    """Per-worker state of `admin_requests_watch`: the request times this worker has already acted on."""

    def __init__(self, ctx: Any) -> None:
        self.ctx = ctx
        self.seen_flush: float | None = None
        self.seen_memory: dict[str, float] = {}
        self.started = False
        self.flushes = 0
        self.resets = 0

    async def run_once(self, _job: JobContext | None = None) -> dict[str, Any]:
        """Read the two keys; flush and reset what is newer than what this worker last saw."""
        values = await self.ctx.dbs.control.read(_read_watched)
        flush_at = values.get(FLUSH_KEY)
        memory = values.get(MEMORY_RESET_KEY)
        memory = memory if isinstance(memory, dict) else {}
        acted: dict[str, Any] = {"flushed": False, "reset": []}
        if not self.started:
            # The first look only records where things stand: a request older than this worker is not repeated.
            self.started = True
            self.seen_flush = float(flush_at) if isinstance(flush_at, int | float) else 0.0
            self.seen_memory = {str(k): float(v) for k, v in memory.items() if isinstance(v, int | float)}
            return acted
        if isinstance(flush_at, int | float) and float(flush_at) > (self.seen_flush or 0.0):
            self.seen_flush = float(flush_at)
            recorder = getattr(self.ctx, "recorder", None)
            if recorder is not None:
                async with asyncio.timeout(FLUSH_TIMEOUT_S):
                    await recorder.flush()
                self.flushes += 1
                acted["flushed"] = True
        for family, at in memory.items():
            if isinstance(at, int | float) and float(at) > self.seen_memory.get(str(family), 0.0):
                self.seen_memory[str(family)] = float(at)
                if reset_local_memory(self.ctx, str(family)):
                    self.resets += 1
                    acted["reset"].append(str(family))
        return acted


def register_jobs(registry: JobRegistry, ctx: Any) -> RequestsWatcher:
    """Add the per-worker job `admin_requests_watch` (every second; reads two `service_state` keys)."""
    watcher = RequestsWatcher(ctx)
    setattr(ctx, WATCHER_ATTRIBUTE, watcher)
    registry.add(
        Job(
            WATCH_JOB,
            WATCH_INTERVAL_S,
            watcher.run_once,
            leader_only=False,
            timeout_s=FLUSH_TIMEOUT_S + 5.0,
            description="Flush this worker's metrics, or clear its in-memory counters, when an admin asks (14.1).",
        )
    )
    return watcher


# ================================================================================================ bodies


class ReasonBody(ApiBody):
    reason: str = Field(default="", max_length=MAX_REASON_LENGTH)


# ================================================================================================ fleet


def _host_facts(pids: list[int]) -> dict[str, Any]:
    boot = read_fleet.boot_time_s()
    return {
        "uptime_s": read_fleet.host_uptime_s(),
        "boot_at": boot,
        "masters": {pid: read_fleet.process_started_at(pid, boot_s=boot) for pid in pids},
        "deploy_switched_at": read_fleet.file_mtime(DEPLOYED_VERSION_FILES),
    }


async def fleet(ctx: Any) -> dict[str, Any]:
    """The fleet header and workers (parity row 84) from shared heartbeats plus `/proc` facts."""
    now = ctx.clock.now()
    rows = await ctx.dbs.metrics.read(lambda conn: heartbeat.fleet_view(conn, now, this_pid=os.getpid()))
    masters = sorted({int(r["master_pid"]) for r in rows if r.get("fresh") and r.get("master_pid")})
    host = await asyncio.to_thread(_host_facts, masters)
    summary = read_fleet.fleet_summary(
        rows,
        now_s=now,
        expected_per_color=int(ctx.env.workers),
        this_color=str(ctx.color),
        master_started=host["masters"],
    )
    switched = host["deploy_switched_at"]
    tarpit: dict[str, Any] | None = None
    abuse = getattr(ctx, "abuse", None)
    if abuse is not None and getattr(abuse, "tarpit", None) is not None:
        state = await abuse.tarpit.state()
        tarpit = {
            key: state.get(key)
            for key in ("active_holds", "connection_budget", "max_concurrent", "capacity_used_pct", "slots_free")
        }
    return {
        "now": int(now),
        "this_worker": {"pid": os.getpid(), "worker_id": ctx.worker_id, "color": ctx.color},
        "host": {"uptime_s": host["uptime_s"], "booted_at": host["boot_at"]},
        "deploy": {
            "switched_at": switched,
            "since_switch_s": None if switched is None else max(0, int(now - switched)),
        },
        "tarpit_connections": tarpit,
        **summary,
    }


@router.get("/fleet")
async def get_fleet(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """The worker fleet, both colors during a deploy (parity row 84)."""
    return await run_mutation(fleet(get_ctx(request)))


@router.get("/workers", response_model=None)
async def workers(
    request: Request,
    admin: AdminSession,
    tq: Annotated[TableQuery, Depends(table_params(WORKERS_TABLE))],
    fmt: ExportFormatDep,
) -> Any:
    """The workers as a table (stale rows included; `fresh` tells them apart)."""
    data = await run_mutation(fleet(get_ctx(request)))
    rows = data["workers"]
    if fmt is not None:
        return await common.export_table(request, admin, WORKERS_TABLE, rows, fmt, total=len(rows), tq=tq)
    return workers_table(data, tq)


def workers_table(data: dict[str, Any], tq: TableQuery) -> dict[str, Any]:
    """One page of the workers of a `fleet` answer as the `GET /system/workers` table (the System page reads the
    fleet once and renders its header and this table from it)."""
    items, total = common.page_rows(data["workers"], tq, search_keys=("pid", "color", "worker_id", "version"))
    return common.table_answer(WORKERS_TABLE, tq, items, total)


@router.post("/workers/reset-counts")
async def reset_counts(request: Request, body: ReasonBody, admin: AdminSession, _csrf: CsrfChecked) -> dict[str, Any]:
    """Zero requests and proxied on every worker and set `counters_reset_at` (parity rows 84, 122)."""
    ctx = get_ctx(request)
    reason = common.require_reason(body.reason, required=False)
    at = int(ctx.clock.now())
    actor = actor_for(admin)
    request_id = request_id_of(request)

    def intent(conn: sqlite3.Connection) -> int:
        return audit.record(
            conn, actor, "system.reset_counts", "workers", None, {"reset_at": at}, reason or None, request_id, at=at
        )

    audit_id = await run_mutation(ctx.dbs.control.write(intent))
    changed = await run_mutation(ctx.dbs.metrics.write(lambda conn: heartbeat.reset_fleet_counters(conn, at)))
    reporter = getattr(ctx, "heartbeat", None)
    if reporter is not None:
        reporter.counters.reset(at)  # this worker adopts it now; the others on their next beat (5 s)
    return {"reset_at": at, "workers": int(changed), "audit_id": audit_id, "message": "Worker request counts reset"}


# ================================================================================================ leader and jobs


@router.get("/leader")
async def leader(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """Who leads the fleet (the hot.db lease), its epoch (fencing token), and this worker's view."""
    return await leader_state(get_ctx(request))


async def leader_state(ctx: Any) -> dict[str, Any]:
    """The answer of `GET /system/leader` (also the System page's leader card)."""
    lease = await run_mutation(ctx.dbs.hot.read(lambda conn: leases.holder_epoch(conn, LEADER_LEASE)))
    now_ms = ctx.clock.now_ms()
    elector = getattr(ctx, "leader", None)
    state = getattr(elector, "state", None)
    return {
        "holder": None if lease is None else lease[0],
        "epoch": None if lease is None else lease[1],
        "expires_in_s": None if lease is None else round(max(0, lease[2] - now_ms) / 1000, 1),
        "valid": lease is not None and lease[2] > now_ms,
        "this_worker": {
            "worker_id": ctx.worker_id,
            "is_leader": bool(getattr(elector, "is_leader", False)),
            "epoch": getattr(state, "epoch", None),
            "since": getattr(state, "since", None),
            "changes": getattr(state, "changes", None),
            "last_error": getattr(state, "last_error", None),
        },
    }


async def _published_jobs(ctx: Any) -> dict[str, dict[str, Any]]:
    """What the leader last published (`health_job_status`), name -> row; empty when nothing fresh is there."""
    try:
        from roxy.health import store
    except ImportError:  # pragma: no cover - the health package ships with this release
        return {}
    since = ctx.clock.now() - JOB_STATUS_FRESH_S
    try:
        facts = await ctx.dbs.metrics.read(lambda conn: store.read_job_status(conn, since))
    except (SharedStateUnavailable, sqlite3.Error):
        return {}
    return {
        fact.name: {
            "interval_s": fact.interval_s,
            "last_started_at": fact.last_started_at,
            "last_finished_at": fact.last_finished_at,
            "last_ok": fact.last_ok,
        }
        for fact in facts
    }


@router.get("/jobs")
async def jobs(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """Every scheduled job with its last run, and the WAL checkpoint durations (plan 6.5, 14.1)."""
    return await jobs_view(get_ctx(request))


async def jobs_view(ctx: Any) -> dict[str, Any]:
    """The answer of `GET /system/jobs` (also the System page's jobs card)."""
    runner = getattr(ctx, "jobs", None)
    elector = getattr(ctx, "leader", None)
    is_leader = bool(getattr(elector, "is_leader", False))
    local = {row["name"]: row for row in (runner.status() if runner is not None else [])}
    published = await _published_jobs(ctx)
    items = []
    for name in sorted(set(local) | set(published)):
        row = local.get(name)
        leader_only = bool(row["leader_only"]) if row is not None else True
        # A leader job's runs are known by the leader: this worker's own row when it leads, else what it published.
        use_local = row is not None and (is_leader or not leader_only)
        source = "this_worker" if use_local else ("leader" if name in published else "unknown")
        picked: dict[str, Any] = dict(row) if use_local and row is not None else dict(published.get(name, {}))
        description = ""
        if runner is not None and name in runner.registry:
            description = runner.registry.get(name).description
        items.append(
            {
                "name": name,
                "description": description,
                "leader_only": leader_only,
                "interval_s": picked.get("interval_s", row.get("interval_s") if row else None),
                "last_started_at": picked.get("last_started_at"),
                "last_finished_at": picked.get("last_finished_at"),
                "last_ok": picked.get("last_ok"),
                "last_duration_ms": picked.get("last_duration_ms"),
                "last_error": common.clean_message(picked["last_error"], 300) if picked.get("last_error") else None,
                "runs": picked.get("runs"),
                "failures": picked.get("failures"),
                "running": picked.get("running"),
                "next_due_in_s": picked.get("next_due_in_s"),
                "source": source,
            }
        )
    checkpoints = {}
    for name in ("wal_checkpoint_passive", "daily_maintenance"):
        row = local.get(name)
        if row is None:
            continue
        checkpoints[name] = {
            "last_duration_ms": row.get("last_duration_ms") if is_leader else None,
            "per_database_ms": row.get("last_result") if is_leader else None,
            "last_finished_at": row.get("last_finished_at") if is_leader else None,
        }
    return {
        "this_worker_is_leader": is_leader,
        "jobs": items,
        "checkpoints": checkpoints,
        "note": (
            "Leader jobs run on one worker; when another worker leads, their last runs come from the status it "
            "publishes every 30 s (failure details stay with the leader). Checkpoint durations are known by the "
            "leader only."
        ),
    }


# ================================================================================================ pipeline


def _db_stats(db: Any) -> dict[str, Any]:
    stats = db.stats
    return {
        "db": db.name,
        "writes": stats.writes,
        "reads": stats.reads,
        "write_errors": stats.write_errors,
        "unavailable": stats.unavailable,
        "busy_fast_failures": stats.fast_failures,
        "deadline_failures": stats.deadline_failures,
        "max_write_ms": round(stats.max_write_ms, 3),
        "last_write_ms": round(stats.last_write_ms, 3),
        "pending": db.pending(),
        # LOAD-3: the write lock's wait and hold percentiles since start, and how many hot-path writes shared a
        # transaction (group commit, storage/db.py).
        **stats.timing(),
        "groups": stats.groups,
        "grouped_writes": stats.grouped_writes,
        "largest_group": stats.largest_group,
    }


@router.get("/metrics-pipeline")
async def metrics_pipeline(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """This worker's metrics queue, drops and flushes, and every database writer's statistics (per worker), plus
    the items every worker dropped in the last hour (`fleet_drops_last_hour`, SYS-METRICS-DROP's reading)."""
    return await pipeline_view(get_ctx(request))


async def pipeline_view(ctx: Any) -> dict[str, Any]:
    """The answer of `GET /system/metrics-pipeline` (also the System page's metrics pipeline card)."""
    recorder = getattr(ctx, "recorder", None)
    stats = recorder.stats() if recorder is not None else None
    now = int(ctx.clock.now())
    dims = None
    fleet_drops = None
    with contextlib.suppress(SharedStateUnavailable):
        dims, fleet_drops = await ctx.dbs.metrics.read(
            lambda conn: (
                queries.dims_per_minute(conn, now - 3600, now),
                read_producers.pipeline_drops(conn, now - 3600, now + 1),
            )
        )
    watcher = getattr(ctx, WATCHER_ATTRIBUTE, None)
    return {
        "worker_id": ctx.worker_id,
        "scope": "this worker",
        "recorder": stats,
        "settings": {
            "metrics_flush_interval_ms": ctx.settings.get("metrics_flush_interval_ms"),
            "metrics_queue_max": ctx.settings.get("metrics_queue_max"),
        },
        "dims_per_minute_last_hour": dims,
        # Every worker's per-minute drop deltas (`metrics_pipeline_minute`), so a drop in another worker shows here.
        "fleet_drops_last_hour": fleet_drops,
        "fleet_drops_scope": "fleet",
        "databases": [_db_stats(db) for db in ctx.dbs.all()],
        "forced_flushes_here": watcher.flushes if isinstance(watcher, RequestsWatcher) else None,
    }


@router.get("/persistence")
async def persistence(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """Database and WAL file sizes, the schema versions and each writer's health (parity row 85), with the disk
    growth history: Roxy's storage and the free disk sampled hourly by the leader over the last
    `GROWTH_DAYS` days (`metrics/read_producers.py disk_growth`, the line SYS-DISK projects) and the newest table
    sizes (sampled every 6 hours)."""
    return await persistence_view(get_ctx(request))


async def persistence_view(ctx: Any) -> dict[str, Any]:
    """The answer of `GET /system/persistence` (also the System page's persistence card)."""
    files = await asyncio.to_thread(read_sizes.file_sizes, [Path(db.path) for db in ctx.dbs.all()])
    out = []
    for db in ctx.dbs.all():
        name = Path(db.path).name
        out.append({**_db_stats(db), "file": name, **files.get(name, {})})
    since = int(ctx.clock.now()) - GROWTH_DAYS * 86_400
    growth: list[dict[str, Any]] | None = None
    tables: dict[str, Any] | None = None
    with contextlib.suppress(SharedStateUnavailable):
        growth, tables = await ctx.dbs.metrics.read(
            lambda conn: (
                read_producers.disk_growth(conn, since, limit=MAX_GROWTH_SAMPLES),
                read_producers.latest_table_sizes(conn),
            )
        )
    return {
        "databases": out,
        "total_bytes": sum(f["bytes"] + f["wal_bytes"] + f["shm_bytes"] for f in files.values()),
        "growth": growth,
        "growth_days": GROWTH_DAYS,
        "growth_note": (
            "One sample an hour from the leader (the first an hour after it starts leading); None while metrics.db "
            "is busy."
        ),
        "table_sizes": tables,
        "storage_url": f"{common.API_PREFIX}/data/storage",
    }


# ================================================================================================ errors


@router.get("/errors", response_model=None)
async def errors(
    request: Request,
    admin: AdminSession,
    tq: Annotated[TableQuery, Depends(table_params(ERRORS_TABLE))],
    fmt: ExportFormatDep,
    source: Annotated[str | None, Query(max_length=64)] = None,
) -> Any:
    """Error signatures (plan 14.1 System > Errors; parity rows 16, 72): paged, searched, sorted on the server."""
    ctx = get_ctx(request)
    if fmt is not None:
        reader = _errors_reader(tq, source)

        async def fetch(page: int, size: int) -> tuple[list[dict[str, Any]], int]:
            rows, total = await ctx.dbs.metrics.read(reader(page, size))
            return list(rows), int(total)

        filters = {"source": source} if source else None
        return await common.export_pages(request, admin, ERRORS_TABLE, fetch, fmt, tq=tq, filters=filters)
    return await errors_answer(ctx, tq, source=source)


def _errors_reader(tq: TableQuery, source: str | None) -> Any:
    def reader(page: int, size: int) -> Any:
        def run(conn: sqlite3.Connection) -> tuple[list[dict[str, Any]], int]:
            return read_errors.errors_page(
                conn,
                q=tq.q,
                source=source,
                sort=tq.sort,
                descending=tq.descending,
                limit=size,
                offset=(page - 1) * size,
            )

        return run

    return reader


async def errors_answer(ctx: Any, tq: TableQuery, *, source: str | None = None) -> dict[str, Any]:
    """One page of error signatures as `GET /system/errors` answers it, with the `sources` of the source filter
    (also the System page's error log card)."""
    rows, total = await run_mutation(ctx.dbs.metrics.read(_errors_reader(tq, source)(tq.page, tq.page_size)))
    answer = common.table_answer(ERRORS_TABLE, tq, rows, total)
    answer["sources"] = await ctx.dbs.metrics.read(read_errors.error_sources)
    return answer


@router.get("/errors/detail")
async def error_detail(
    request: Request,
    _admin: AdminSession,
    signature: Annotated[str, Query(min_length=1, max_length=300)],
) -> dict[str, Any]:
    """One error signature with its redacted traceback and its hourly occurrences over the last day."""
    found = await error_detail_view(get_ctx(request), signature)
    if found is None:
        raise common.not_found("No error has that signature.")
    return found


async def error_detail_view(ctx: Any, signature: str) -> dict[str, Any] | None:
    """The answer of `GET /system/errors/detail` for `signature` (None when no error has it; the page's drawer)."""
    now = ctx.clock.now()
    found: dict[str, Any] | None = await run_mutation(
        ctx.dbs.metrics.read(lambda conn: read_errors.error_detail(conn, signature, now=now))
    )
    return found


# ================================================================================================ versions, env


def _library_versions() -> dict[str, str | None]:
    out: dict[str, str | None] = {}
    for name in LIBRARIES:
        try:
            out[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            out[name] = None
    return out


def _deployed_sha() -> str | None:
    for path in DEPLOYED_VERSION_FILES:
        try:
            with open(path, encoding="ascii", errors="replace") as handle:
                text = handle.readline(128).strip()
        except OSError:
            continue
        if text:
            return text[:64]
    return None


@router.get("/versions")
async def versions(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """What runs: release, package, Python, SQLite, libraries, catalog, schema and template versions, fleet mix."""
    return await versions_view(get_ctx(request))


async def versions_view(ctx: Any) -> dict[str, Any]:
    """The answer of `GET /system/versions` (also the System page's versions card)."""
    schema: dict[str, int] = {}
    for db in ctx.dbs.all():
        try:
            schema[db.name] = max(await db.read(applied_versions), default=0)
        except SharedStateUnavailable:
            schema[db.name] = -1
    now = ctx.clock.now()
    rows = await run_mutation(ctx.dbs.metrics.read(lambda conn: heartbeat.fleet_view(conn, now)))
    fleet_versions: dict[str, int] = {}
    for row in rows:
        if row.get("fresh"):
            label = str(row.get("version") or "unknown")
            fleet_versions[label] = fleet_versions.get(label, 0) + 1
    deployed, libraries = await asyncio.gather(asyncio.to_thread(_deployed_sha), asyncio.to_thread(_library_versions))
    return {
        "release": ctx.release or None,
        "deployed_sha": deployed,
        "package": roxy.__version__,
        "python": platform.python_version(),
        "sqlite": sqlite3.sqlite_version,
        "libraries": libraries,
        "catalog_version": catalog.CATALOG_VERSION,
        "settings": len(catalog.CATALOG),
        "config_version": ctx.settings.version,
        "schema": schema,
        "schema_required": dict(REQUIRED_SCHEMA),
        "template_version": TEMPLATE_VERSION,
        "fleet_versions": fleet_versions,
    }


def _credentials_present(directory: Path | None) -> dict[str, bool]:
    if directory is None:
        return dict.fromkeys(CREDENTIAL_NAMES, False)
    out: dict[str, bool] = {}
    for name in CREDENTIAL_NAMES:
        try:
            out[name] = (directory / name).stat().st_size > 0  # existence and size only, never the content
        except OSError:
            out[name] = False
    return out


@router.get("/environment")
async def environment(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """The non-secret environment summary: `ROXY_*` deployment facts, and which credentials exist (names only)."""
    return await environment_view(get_ctx(request))


async def environment_view(ctx: Any) -> dict[str, Any]:
    """The answer of `GET /system/environment` (also the System page's environment and alerts cards)."""
    env = ctx.env
    present = await asyncio.to_thread(_credentials_present, env.credentials_dir)
    manager = getattr(getattr(ctx, "egress", None), "credential", None)
    status = manager.status() if manager is not None else None
    credential = (
        None
        if status is None
        else {
            "bootstrap_file": bool(status.bootstrap_present),
            "dashboard_value": bool(status.ui_value_present),
            "in_use": bool(status.present),
        }
    )
    return {
        "env": env.env,
        "color": env.color,
        "workers": env.workers,
        "bind": env.bind,
        "max_requests": env.max_requests,
        "trusted_proxy_hops": env.trusted_proxy_hops,
        "trusted_proxy_cidrs": [str(network) for network in env.trusted_proxy_cidrs],
        "nginx_worker_processes": env.nginx_worker_processes,
        "nginx_worker_connections": env.nginx_worker_connections,
        "send_hsts": env.send_hsts,
        "log_level": env.log_level,
        "state_dir": str(env.state_dir),
        "databases": {db.name: str(db.path) for db in ctx.dbs.all()},
        "internal_socket": str(env.internal_socket),
        "rotator_ip_echo_url": masked_url(env.rotator_ip_echo_url),
        "backup_remote_configured": bool(env.backup_remote),
        "site_origin": env.site_origin,
        "auto_migrate": env.auto_migrate,
        "release_sha": env.release_sha,
        "credentials_directory_set": env.credentials_dir is not None,
        "credentials_present": present,
        "credential": credential,
        "note": "Secrets are systemd credentials (plan 9.8); this page shows which exist, never a value.",
    }


# ================================================================================================ forced flush


@router.post("/flush")
async def flush(request: Request, body: ReasonBody, admin: AdminSession, _csrf: CsrfChecked) -> dict[str, Any]:
    """Force every worker's metrics batch writer to flush (parity row 121) via `flush_requested_at`."""
    ctx = get_ctx(request)
    reason = common.require_reason(body.reason, required=False)
    at = ctx.clock.now()
    audit_id = await write_state(
        ctx,
        FLUSH_KEY,
        at,
        actor=actor_for(admin),
        action="system.flush",
        reason=reason,
        request_id=request_id_of(request),
    )
    flushed_here = False
    recorder = getattr(ctx, "recorder", None)
    if recorder is not None:
        try:
            async with asyncio.timeout(FLUSH_TIMEOUT_S):
                await recorder.flush()
            flushed_here = True
        except (TimeoutError, SharedStateUnavailable) as exc:
            log.warning("forced_flush_failed", extra={"fields": {"error": str(exc)[:200]}})
    watcher = getattr(ctx, WATCHER_ATTRIBUTE, None)
    if isinstance(watcher, RequestsWatcher) and flushed_here:
        watcher.seen_flush = max(watcher.seen_flush or 0.0, at)
    return {
        "requested_at": at,
        "flushed_here": flushed_here,
        "worker_id": ctx.worker_id,
        "others_within_s": WATCH_INTERVAL_S + 1.0,
        "audit_id": audit_id,
    }


__all__ = [
    "ERRORS_TABLE",
    "FLUSH_KEY",
    "MEMORY_FAMILIES",
    "MEMORY_RESET_KEY",
    "WATCH_JOB",
    "WORKERS_TABLE",
    "RequestsWatcher",
    "environment_view",
    "error_detail_view",
    "errors_answer",
    "fleet",
    "jobs_view",
    "leader_state",
    "persistence_view",
    "pipeline_view",
    "register_jobs",
    "request_memory_reset",
    "reset_local_memory",
    "router",
    "versions_view",
    "workers_table",
    "write_state",
]
