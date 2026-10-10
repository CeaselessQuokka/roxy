"""The job registry and runner: named background jobs on fixed intervals, leader-only or per worker.

What this is
    `Job` describes one scheduled job (name, interval, leader-only or not, timeout, idempotency). `JobRegistry`
    holds them; other packages register their own jobs (rollups, recommendation evaluation, probes, digests).
    `JobRunner` runs whichever jobs are due, at most one run per job at a time, and keeps a status record per job
    for the System page ("jobs and last run times"). `register_storage_jobs` adds the storage jobs this package
    owns: retention, hot.db pruning, PASSIVE checkpoints, daily maintenance and file pruning.

Why it exists
    Plan 5.6: every background task needs a name, an interval, exception logging, a timeout and a concurrency
    cap, and leader-only work must run on exactly one worker. v1 created unbounded timers; here every job is one
    entry in a table and runs through one loop.

How it works
    - Leader-only jobs run only while `elector.is_leader`, each with a `JobContext` carrying the epoch it started
      under (so its writes are fenced, see leader.py). A job that becomes due while this worker is a follower
      waits; when this worker becomes the leader, overdue jobs run on the next tick.
    - The schedule of leader jobs is fleet-wide (plan 5.6, C6). Every leader run first records its start in hot.db
      `job_runs` under the key `schedule:<name>` (a fenced write: a run that lost the lease records nothing and
      does not run). A worker that becomes the leader (a new epoch) reads those rows before it starts anything and
      runs each job no earlier than one interval after its last start anywhere in the fleet (that wait never more
      than one interval, in case a clock stepped), and no earlier than its own schedule says (`run_at_start=False`
      jobs still wait one interval after this worker started, so a deploy never starts the health run at once).
      Without that, each worker's own memory decided, so a leader change (every blue/green deploy, `max_requests`
      recycle or crash) reran every job at once: the hourly LLM export file twice in an hour (finding mpjobs-7). A
      job with no row (a fresh fleet, or a row older than the 7 day `job_runs` retention) keeps this worker's own
      schedule.
    - Jobs with `idempotent=False` get an idempotency key `job:<name>:<bucket>` recorded in hot.db `job_runs`
      before they run (the bucket is the interval number, or what `bucket_fn` returns). If the key exists the
      run is skipped, so a leadership change can never send the same alert or digest twice.
    - Each run gets `timeout_s` (default: the interval, at most 10 minutes); exceptions are logged and counted,
      never raised into the loop.

What to read next
    `roxy/scheduler/leader.py`, then `roxy/storage/retention.py` (what the storage jobs do).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import sqlite3
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from roxy.core.clock import SYSTEM_CLOCK, Clock
from roxy.scheduler.leader import JobContext, LeaderElector, LostLeadership
from roxy.storage import retention
from roxy.storage.db import Databases, SharedStateUnavailable

log = logging.getLogger(__name__)

JobFn = Callable[[JobContext], Awaitable[Any]]
MAX_JOB_TIMEOUT_S = 600.0
MAX_CONCURRENT_JOBS = 4
"""Jobs running at once per worker (plan 5.6: a cap on concurrency)."""

SCHEDULE_PREFIX = "schedule:"
"""`job_runs` key prefix of the fleet-wide schedule rows: `schedule:<job name>`, `started_at` = the job's last start
(wall seconds) anywhere in the fleet, `epoch` = the leader epoch it ran under (module docstring)."""

MAX_SCHEDULE_ROWS = 512
"""Schedule rows read when a worker becomes the leader (plan P9). One row per leader job name, a short code list;
rows of jobs a release no longer has go with the 7 day `job_runs` retention."""


def schedule_key(name: str) -> str:
    """The `job_runs` key of a leader job's schedule row."""
    return f"{SCHEDULE_PREFIX}{name}"


def record_start(conn: sqlite3.Connection, name: str, epoch: int, started_at: float) -> None:
    """Record that leader job `name` starts now (run it inside the run's fenced hot.db write)."""
    conn.execute(
        "INSERT INTO job_runs (idem_key, epoch, started_at, finished_at) VALUES (?, ?, ?, NULL) "
        "ON CONFLICT (idem_key) DO UPDATE SET epoch = excluded.epoch, started_at = excluded.started_at",
        (schedule_key(name), int(epoch), int(started_at)),
    )


def read_schedule(conn: sqlite3.Connection, *, limit: int = MAX_SCHEDULE_ROWS) -> dict[str, int]:
    """`{job name: last start (wall seconds)}` from the schedule rows, at most `limit` of them."""
    # A primary key range scan: every key from "schedule:" up to (not including) "schedule;" (":" + 1 is ";").
    rows = conn.execute(
        "SELECT idem_key, started_at FROM job_runs WHERE idem_key >= ? AND idem_key < ? LIMIT ?",
        (SCHEDULE_PREFIX, SCHEDULE_PREFIX[:-1] + chr(ord(SCHEDULE_PREFIX[-1]) + 1), int(limit)),
    ).fetchall()
    return {str(row[0])[len(SCHEDULE_PREFIX) :]: int(row[1]) for row in rows}


@dataclass(frozen=True, slots=True)
class Job:
    """One scheduled job.

    `interval_s` may be a number or a callable (read before every scheduling decision, so a live setting such as
    `health_auto_interval_h` applies without a restart). A non-positive interval disables the job.
    """

    name: str
    interval_s: float | Callable[[], float]
    fn: JobFn
    leader_only: bool = True
    timeout_s: float | None = None
    run_at_start: bool = True
    idempotent: bool = True
    bucket_fn: Callable[[JobContext], str | int] | None = None
    description: str = ""

    def interval(self) -> float:
        value = self.interval_s() if callable(self.interval_s) else self.interval_s
        return float(value)

    def timeout(self) -> float:
        if self.timeout_s is not None:
            return self.timeout_s
        interval = self.interval()
        return min(MAX_JOB_TIMEOUT_S, interval) if interval > 0 else MAX_JOB_TIMEOUT_S

    def bucket(self, ctx: JobContext) -> str | int:
        """The idempotency bucket of a run: `bucket_fn(ctx)` or the interval number of `ctx.now`."""
        if self.bucket_fn is not None:
            return self.bucket_fn(ctx)
        interval = max(1.0, self.interval())
        return int(ctx.now // interval)


class JobRegistry:
    """Named jobs. Names are unique; registering one twice is a bug and raises."""

    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}

    def add(self, job: Job) -> Job:
        if job.name in self._jobs:
            raise ValueError(f"job {job.name!r} already registered")
        self._jobs[job.name] = job
        return job

    def job(
        self,
        name: str,
        interval_s: float | Callable[[], float],
        *,
        leader_only: bool = True,
        timeout_s: float | None = None,
        run_at_start: bool = True,
        idempotent: bool = True,
        bucket_fn: Callable[[JobContext], str | int] | None = None,
        description: str = "",
    ) -> Callable[[JobFn], JobFn]:
        """Decorator form of `add`."""

        def register(fn: JobFn) -> JobFn:
            self.add(
                Job(
                    name,
                    interval_s,
                    fn,
                    leader_only=leader_only,
                    timeout_s=timeout_s,
                    run_at_start=run_at_start,
                    idempotent=idempotent,
                    bucket_fn=bucket_fn,
                    description=description,
                )
            )
            return fn

        return register

    def get(self, name: str) -> Job:
        return self._jobs[name]

    def all(self) -> list[Job]:
        return list(self._jobs.values())

    def __contains__(self, name: object) -> bool:
        return name in self._jobs

    def __len__(self) -> int:
        return len(self._jobs)


@dataclass(slots=True)
class JobStatus:
    """What the System page shows per job."""

    name: str
    leader_only: bool
    runs: int = 0
    failures: int = 0
    skipped: int = 0
    timeouts: int = 0
    running: bool = False
    last_started_at: float | None = None
    last_finished_at: float | None = None
    last_duration_ms: float | None = None
    last_ok: bool | None = None
    last_error: str | None = None
    last_result: Any = None
    next_due_mono: float = 0.0
    history: list[float] = field(default_factory=list)  # last durations in ms, bounded


_HISTORY = 20

MAX_RESULT_CHARS = 2000
"""`status()` shows a job's last result when its JSON form fits in this many characters (plan P9: the System page
and the published leader status stay small); a larger result is summarized as `{"truncated": true, "chars": n}`."""


def bounded_result(value: Any) -> Any:
    """A job's last result as plain JSON values, or a short summary when it is too large to show (`status()`)."""
    if value is None:
        return None
    try:
        text = json.dumps(value, default=str, sort_keys=True)
    except (TypeError, ValueError):
        return {"truncated": True, "chars": None}
    if len(text) > MAX_RESULT_CHARS:
        return {"truncated": True, "chars": len(text)}
    return json.loads(text)


class JobRunner:
    """Runs due jobs from a registry. Call `run(stop)` as one background task per worker."""

    def __init__(
        self,
        registry: JobRegistry,
        elector: LeaderElector | None,
        clock: Clock | None = None,
        *,
        worker_id: str = "",
        max_concurrent: int = MAX_CONCURRENT_JOBS,
    ) -> None:
        self.registry = registry
        self.elector = elector
        self.clock = clock or SYSTEM_CLOCK
        self.worker_id = worker_id
        self._limit = asyncio.Semaphore(max_concurrent)
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._status: dict[str, JobStatus] = {}
        self._synced_epoch: int | None = None  # the leader epoch whose fleet schedule this runner has read

    def _status_for(self, job: Job) -> JobStatus:
        status = self._status.get(job.name)
        if status is None:
            first = self.clock.monotonic() + (0.0 if job.run_at_start else max(0.0, job.interval()))
            status = JobStatus(job.name, job.leader_only, next_due_mono=first)
            self._status[job.name] = status
        return status

    def _context(self, job: Job) -> JobContext | None:
        if not job.leader_only:
            return JobContext(epoch=0, now=self.clock.now(), holder=self.worker_id, job_name=job.name)
        if self.elector is None or not self.elector.is_leader:
            return None
        return self.elector.job_context(job.name)

    def due(self) -> list[Job]:
        """Jobs whose time has come and that are allowed to run on this worker now."""
        now = self.clock.monotonic()
        ready: list[Job] = []
        for job in self.registry.all():
            status = self._status_for(job)
            if job.interval() <= 0 or status.running or now < status.next_due_mono:
                continue
            if job.leader_only and (self.elector is None or not self.elector.is_leader):
                continue
            ready.append(job)
        return ready

    async def sync_schedule(self) -> bool:
        """Once per leadership term: schedule every leader job from the fleet's record of its last start.

        Returns True when leader jobs may start (this worker is not the leader, the record was read for this
        epoch, or there is no hot.db to read it from), False when hot.db could not be read: leader jobs then wait
        for the next tick (they need hot.db for their fenced writes anyway).
        """
        elector = self.elector
        if elector is None or not elector.is_leader:
            return True
        epoch = elector.state.epoch
        if epoch == self._synced_epoch:
            return True
        hot = getattr(elector, "hot", None)
        if hot is None:
            self._synced_epoch = epoch
            return True
        try:
            starts = await hot.read(read_schedule)
        except SharedStateUnavailable as exc:
            log.warning("job_schedule_unavailable", extra={"fields": {"epoch": epoch, "error": str(exc)[:200]}})
            return False
        applied = self.apply_schedule(starts)
        self._synced_epoch = epoch
        log.info("job_schedule_synced", extra={"fields": {"epoch": epoch, "jobs": applied}})
        return True

    def apply_schedule(self, starts: dict[str, int]) -> int:
        """Move each leader job's next run to at least one interval after its last start in the fleet. Returns how
        many jobs had a row.

        The fleet's wait is cut to [0, interval] (a start stamped in the future, from a clock that stepped, can never
        push a job back by more than one interval), and the later of it and this worker's own schedule wins: a
        takeover never runs a job earlier than this worker would have, and never sooner than one interval after the
        fleet last ran it. An overdue job whose own schedule is due runs at once.
        """
        now, mono = self.clock.now(), self.clock.monotonic()
        applied = 0
        for job in self.registry.all():
            last = starts.get(job.name)
            if not job.leader_only or last is None:
                continue
            interval = job.interval()
            status = self._status_for(job)
            if interval <= 0 or status.running:
                continue
            wait = min(max(0.0, last + interval - now), interval)
            status.next_due_mono = max(status.next_due_mono, mono + wait)
            applied += 1
        return applied

    async def tick(self) -> list[str]:
        """Start every due job (each in its own task). Returns the names started."""
        started: list[str] = []
        leader_ready = await self.sync_schedule()
        for job in self.due():
            if job.leader_only and not leader_ready:
                continue
            ctx = self._context(job)
            if ctx is None:
                continue
            status = self._status_for(job)
            status.running = True
            status.next_due_mono = self.clock.monotonic() + job.interval()
            self._tasks[job.name] = asyncio.create_task(self._execute(job, ctx, status), name=f"job:{job.name}")
            started.append(job.name)
        return started

    async def run_job_now(self, name: str) -> JobStatus:
        """Run one job immediately and wait for it (admin "run now" buttons, tests). Respects leader_only."""
        job = self.registry.get(name)
        status = self._status_for(job)
        ctx = self._context(job)
        if ctx is None:
            raise LostLeadership(f"job {name} is leader-only and this worker is not the leader")
        if status.running:
            task = self._tasks.get(name)
            if task is not None:
                await asyncio.wait({task})
            return status
        status.running = True
        await self._execute(job, ctx, status)
        return status

    async def _execute(self, job: Job, ctx: JobContext, status: JobStatus) -> None:
        async with self._limit:
            started_wall = self.clock.now()
            started = time.perf_counter()
            status.last_started_at = started_wall
            bucket: str | int | None = None
            try:
                async with asyncio.timeout(job.timeout()):
                    if job.leader_only and ctx.hot is not None and ctx.epoch > 0:
                        # The fleet-wide schedule (module docstring); fenced, so a stale leader neither records nor
                        # runs. One small hot.db write per leader run, never on the request path.
                        await ctx.fenced_write(
                            ctx.hot, lambda conn: record_start(conn, job.name, ctx.epoch, started_wall)
                        )
                    if not job.idempotent:
                        bucket = job.bucket(ctx)
                        if not await ctx.claim(bucket):
                            status.skipped += 1
                            status.last_ok = True
                            status.last_error = None
                            return
                    status.last_result = await job.fn(ctx)
                    if bucket is not None:
                        await ctx.finish(bucket)
                status.runs += 1
                status.last_ok = True
                status.last_error = None
            except TimeoutError:
                status.timeouts += 1
                status.failures += 1
                status.last_ok = False
                status.last_error = f"timed out after {job.timeout():.0f} s"
                log.error("job_timeout", extra={"fields": {"job": job.name, "timeout_s": job.timeout()}})
            except LostLeadership as exc:
                status.skipped += 1
                status.last_ok = False
                status.last_error = f"lost leadership: {exc}"
                log.warning("job_lost_leadership", extra={"fields": {"job": job.name, "epoch": ctx.epoch}})
            except SharedStateUnavailable as exc:
                status.failures += 1
                status.last_ok = False
                status.last_error = str(exc)
                log.warning("job_shared_state_unavailable", extra={"fields": {"job": job.name, "error": str(exc)}})
            except Exception as exc:
                status.failures += 1
                status.last_ok = False
                status.last_error = f"{type(exc).__name__}: {exc}"
                log.exception("job_failed", extra={"fields": {"job": job.name}})
            finally:
                duration_ms = (time.perf_counter() - started) * 1000
                status.last_duration_ms = duration_ms
                status.last_finished_at = self.clock.now()
                status.history = [*status.history[-(_HISTORY - 1) :], duration_ms]
                status.running = False
                self._tasks.pop(job.name, None)

    async def run(self, stop: asyncio.Event, poll_s: float = 0.5) -> None:
        """Start due jobs every `poll_s` seconds until `stop` is set, then cancel what is still running."""
        try:
            while not stop.is_set():
                try:
                    await self.tick()
                except Exception:
                    log.exception("job_runner_tick_failed")
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(stop.wait(), timeout=poll_s)
        finally:
            await self.shutdown()

    async def shutdown(self) -> None:
        """Cancel running jobs and wait for them to finish canceling."""
        tasks = list(self._tasks.values())
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def status(self) -> list[dict[str, Any]]:
        """One dict per job for the System page and the LLM export."""
        rows: list[dict[str, Any]] = []
        mono = self.clock.monotonic()
        for job in self.registry.all():
            s = self._status_for(job)
            rows.append(
                {
                    "name": job.name,
                    "leader_only": job.leader_only,
                    "interval_s": job.interval(),
                    "runs": s.runs,
                    "failures": s.failures,
                    "skipped": s.skipped,
                    "timeouts": s.timeouts,
                    "running": s.running,
                    "last_started_at": s.last_started_at,
                    "last_finished_at": s.last_finished_at,
                    "last_duration_ms": s.last_duration_ms,
                    "last_ok": s.last_ok,
                    "last_error": s.last_error,
                    "last_result": bounded_result(s.last_result),
                    "next_due_in_s": max(0.0, s.next_due_mono - mono),
                }
            )
        return rows


# ------------------------------------------------------------------------------------------- storage jobs


RETENTION_INTERVAL_S = 600.0
HOT_PRUNE_INTERVAL_S = 60.0
CHECKPOINT_INTERVAL_S = 300.0
DAILY_CHECK_INTERVAL_S = 300.0
FILE_PRUNE_INTERVAL_S = 600.0
PASSIVE_CHECKPOINT_DBS = ("hot", "control", "metrics")
TRUNCATE_CHECKPOINT_DBS = ("cache", "metrics")
QUICK_CHECK_DBS = ("control", "hot")
DEFAULT_HOUR = 4
"""Fallback for the `maintenance_hour` setting when no settings getter is wired (catalog default)."""
DEFAULT_ZONE = "America/New_York"
"""Fallback for the `ui_timezone` setting when no settings getter is wired (catalog default)."""


def _fenced_writer(ctx: JobContext) -> retention.Writer:
    async def write(db: Any, fn: Any) -> int:
        result: int = await ctx.fenced_write(db, fn)
        return result

    return write


def register_storage_jobs(
    registry: JobRegistry,
    dbs: Databases,
    policy: Callable[[], retention.RetentionPolicy],
    *,
    state_dir: Path | None = None,
    setting: Callable[[str], Any] | None = None,
    maintenance_hour: Callable[[], int] | None = None,
    ui_timezone: Callable[[], str] | None = None,
    request_rates: Callable[[], Awaitable[tuple[float | None, float | None]]] | None = None,
    on_integrity_failure: Callable[[str, list[str]], Awaitable[None] | None] | None = None,
) -> None:
    """Register the storage-owned leader jobs (plan 5.6, 6.5, 6.10).

    `policy` returns the current retention values (for example `RetentionPolicy.from_settings(ctx.settings.get)`).
    `setting` is the runtime settings getter (`ctx.settings.get`); the daily job reads `maintenance_hour` and
    `ui_timezone` through it on every run, unless explicit `maintenance_hour` / `ui_timezone` callables are given
    (tests). `request_rates` returns (last minute rate, 24 h median rate) for the TRUNCATE gate, and
    `on_integrity_failure(db_name, problems)` is called when a daily `quick_check` fails (critical alert).
    """

    def live(key: str, fallback: Any) -> Any:
        if setting is None:
            return fallback
        try:
            value = setting(key)
        except (KeyError, LookupError, AttributeError, ValueError):
            return fallback
        return fallback if value is None else value

    def current_hour() -> int:
        return int(maintenance_hour() if maintenance_hour is not None else live("maintenance_hour", DEFAULT_HOUR))

    def current_zone() -> str:
        return str(ui_timezone() if ui_timezone is not None else live("ui_timezone", DEFAULT_ZONE))

    async def retention_job(ctx: JobContext) -> dict[str, int]:
        return await retention.run_retention(dbs, policy(), ctx.now, writer=_fenced_writer(ctx))

    async def hot_prune_job(ctx: JobContext) -> dict[str, int]:
        return await retention.run_hot_prune(dbs, policy(), ctx.now, writer=_fenced_writer(ctx))

    async def checkpoint_job(ctx: JobContext) -> dict[str, float]:
        durations: dict[str, float] = {}
        for name in PASSIVE_CHECKPOINT_DBS:
            await ctx.check()
            result = await dbs.get(name).maintenance(retention.checkpoint)
            durations[name] = round(result.duration_ms, 3)
            log.info(
                "wal_checkpoint",
                extra={
                    "fields": {
                        "db": name,
                        "mode": result.mode,
                        "busy": result.busy,
                        "frames": result.wal_frames,
                        "duration_ms": durations[name],
                    }
                },
            )
        return durations

    async def daily_job(ctx: JobContext) -> dict[str, Any]:
        last_rate, median = (await request_rates()) if request_rates is not None else (None, None)
        due, day = retention.daily_truncate_due(
            ctx.now,
            maintenance_hour=current_hour(),
            tz_name=current_zone(),
            last_run_day=None,
            last_minute_rate=last_rate,
            median_rate_24h=median,
        )
        if not due:
            return {"ran": False, "day": day}
        # Only now is this a real run: claim the day so a leadership change cannot repeat it.
        if not await ctx.claim(day):
            return {"ran": False, "day": day, "already_done": True}
        report: dict[str, Any] = {"ran": True, "day": day, "truncate_ms": {}, "integrity": {}}
        for name in TRUNCATE_CHECKPOINT_DBS:
            await ctx.check()
            result = await dbs.get(name).maintenance(retention.truncate_checkpoint)
            report["truncate_ms"][name] = round(result.duration_ms, 3)
        for db in dbs.all():
            await db.maintenance(retention.optimize)
        for name in QUICK_CHECK_DBS:
            problems = await dbs.get(name).maintenance(retention.quick_check)
            report["integrity"][name] = "ok" if not problems else problems[:5]
            if problems:
                log.critical("db_integrity_failed", extra={"fields": {"db": name, "problems": problems[:5]}})
                if on_integrity_failure is not None:
                    outcome = on_integrity_failure(name, problems)
                    if outcome is not None:
                        await outcome
        await ctx.finish(day)
        return report

    async def file_prune_job(ctx: JobContext) -> dict[str, int]:
        if state_dir is None:
            return {}
        current = policy()
        removed: dict[str, int] = {}
        for sub, days, files, size in (
            ("exports", current.retention_exports_days, current.exports_max_files, None),
            ("snapshots", current.retention_snapshots_days, None, current.snapshots_max_bytes),
        ):
            deleted = await asyncio.to_thread(
                retention.prune_directory, state_dir / sub, ctx.now, max_age_days=days, max_files=files, max_bytes=size
            )
            removed[sub] = len(deleted)
        return removed

    registry.add(
        Job(
            "retention",
            RETENTION_INTERVAL_S,
            retention_job,
            run_at_start=False,
            description="Prune every table to its max age and row cap, then incremental_vacuum (6.10).",
        )
    )
    registry.add(
        Job(
            "hot_prune",
            HOT_PRUNE_INTERVAL_S,
            hot_prune_job,
            description="Remove expired leases, cooldowns and idle limiter rows from hot.db (6.10).",
        )
    )
    registry.add(
        Job(
            "wal_checkpoint_passive",
            CHECKPOINT_INTERVAL_S,
            checkpoint_job,
            run_at_start=False,
            description="PASSIVE WAL checkpoints on hot, control and metrics (6.5).",
        )
    )
    # daily_maintenance claims its own idempotency key (the local day) only once it decides to run, so it is
    # registered as idempotent and polls every 5 minutes.
    registry.add(
        Job(
            "daily_maintenance",
            DAILY_CHECK_INTERVAL_S,
            daily_job,
            timeout_s=MAX_JOB_TIMEOUT_S,
            description="Once a day at maintenance_hour: TRUNCATE checkpoints, optimize, quick_check (6.5).",
        )
    )
    registry.add(
        Job(
            "file_retention",
            FILE_PRUNE_INTERVAL_S,
            file_prune_job,
            run_at_start=False,
            description="Prune exports/ and snapshots/ by age, count and size (6.10).",
        )
    )
