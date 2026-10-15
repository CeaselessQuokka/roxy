"""The health run engine: start a run, run its checks four at a time, store and stream every result.

What this is
    `HealthRunner`, one per worker (`runner_for(ctx)`): `start_run` (the dashboard button: returns the run id at
    once and runs in the background), `run_now` (the scheduled job and scripts: waits for the end),
    `run_checks` (the per-check entry point the fixture harness uses, the same path as a real run), and
    `run_check` (one check with its timeout and the credential rule). `register_jobs(registry, ctx)` adds the
    two leader jobs: the scheduled run every `health_auto_interval_h` hours with an alert on new failures, and
    the 30 s publish of the leader's job status for H-LEADER.

Why it exists
    Plan 13.1: "Checks run with bounded concurrency (4) and per-check timeouts; upstream checks use the internal
    probe priority and count against buckets (they never burst)". Results stream to the dashboard as each check
    finishes, runs are stored and compared, and scheduled runs skip the credential checks that call Roblox unless
    `health_auto_include_credential` is 1, to save the account's budget (13.3).

How it works
    - One run at a time in the whole fleet: a hot.db lease (`health:run`) is taken before the run row is written;
      a second request while one runs gets `RunBusy` with the running run's id (the dashboard follows that run's
      stream instead of starting a second probe wave).
    - The run row, each result and the final summary are metrics.db writes that also insert `events` rows
      (`health_run_started`, `health_result`, `health_run_finished`); the SSE tail delivers them to every worker.
    - Each check runs under `asyncio.timeout`: a check that does not finish is a `fail` ("did not finish within
      N s"); a check that raises is a `warn` that names the exception (a Roxy bug, never hidden as a pass).
    - A worker that stops mid-run marks the run interrupted on its way out; a run whose worker died is shown as
      interrupted by `store.run_state` after `RUN_STALE_S`.
    - Scheduled runs compare their results with the run before; new failures raise the `health_failures` alert
      (plan 17.7, cooldown key `health:<fingerprint of the failing set>`).

What to read next
    `roxy/health/checks.py` (the checks), `roxy/health/store.py` (the tables), `roxy/admin/api/health.py` (the
    routes), and `roxy/scheduler/jobs.py` (how leader jobs run).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
from collections.abc import Sequence
from typing import Any, Final

from roxy.health import checks, store
from roxy.health.checks import CheckEnv
from roxy.health.facts import LiveFacts, SystemFacts
from roxy.health.model import CheckKind, CheckResult, CheckSpec, RunOptions, Status, Trigger

log = logging.getLogger("roxy.health.runner")

CONCURRENCY: Final = 4
"""Checks one run executes at once (plan 13.1)."""

RUN_TIMEOUT_S: Final = 900.0
"""The longest a whole run may take; the fleet lease lives a minute longer."""

RUN_LEASE: Final = "health:run"
RUN_LEASE_TTL_MS: Final = int((RUN_TIMEOUT_S + 60) * 1000)

INTERNAL_MARGIN_S: Final = 10.0
"""Added to the internal call deadline for upstream checks (their queue wait plus attempts, plan 7.8)."""

FINISH_BUDGET_MS: Final = 1000
"""Busy budget of the "interrupted" write a stopping worker makes on its way out."""

SCHEDULE_JOB: Final = "health_scheduled_run"
SCHEDULE_POLL_S: Final = 300.0
"""The scheduled-run job wakes every 5 minutes and starts a run once `health_auto_interval_h` has passed since
the last scheduled run (so deploys and leader changes never postpone it indefinitely)."""

PUBLISH_JOB: Final = "health_publish_jobs"
PUBLISH_INTERVAL_S: Final = 30.0

MAX_TASKS: Final = 4
"""Background runs one worker keeps track of (the fleet lease allows one; this bounds the map regardless)."""


class RunBusy(Exception):
    """Another health run is still running somewhere in the fleet."""

    def __init__(self, running_run_id: int | None) -> None:
        self.running_run_id = running_run_id
        super().__init__("a health run is already running")


class NoChecks(ValueError):
    """The requested check list matched no check of the catalog."""


class HealthRunner:
    """Runs health checks for one worker (see the module docstring). Build with `runner_for(ctx)`."""

    def __init__(
        self,
        ctx: Any,
        *,
        facts: SystemFacts | None = None,
        concurrency: int = CONCURRENCY,
        run_timeout_s: float = RUN_TIMEOUT_S,
    ) -> None:
        self.ctx = ctx
        self.facts: SystemFacts = facts if facts is not None else LiveFacts(ctx)
        self.concurrency = max(1, int(concurrency))
        self.run_timeout_s = float(run_timeout_s)
        self._tasks: dict[int, asyncio.Task[Any]] = {}
        self.runs_started = 0
        self.checks_run = 0
        self.check_errors = 0

    # --- planning ----------------------------------------------------------------------------------------------

    def plan(self, options: RunOptions) -> list[tuple[CheckSpec, dict[str, str]]]:
        """The check instances a run with `options` executes (catalog order)."""
        planned = checks.expand(self.ctx, options.checks)
        if not planned:
            raise NoChecks("no check matches the requested ids")
        return planned

    def timeout_for(self, spec: CheckSpec) -> float:
        """A check's timeout: its catalog value, raised for upstream checks to cover the internal call deadline."""
        timeout = spec.timeout_s
        if spec.kind in (CheckKind.UPSTREAM, CheckKind.CREDENTIAL):
            with contextlib.suppress(Exception):
                from roxy.upstream.deadlines import internal_deadline_s
                from roxy.upstream.queue import Priority

                timeout = max(timeout, internal_deadline_s(self.ctx.settings, Priority.INTERNAL) + INTERNAL_MARGIN_S)
        return timeout

    # --- one check ---------------------------------------------------------------------------------------------

    async def run_check(
        self, spec: CheckSpec, params: dict[str, str], *, trigger: str, options: RunOptions
    ) -> CheckResult:
        """Run one check exactly as a run does: the credential rule, the timeout, and error capture."""
        env = CheckEnv(ctx=self.ctx, facts=self.facts, spec=spec, params=params, trigger=trigger, options=options)
        if spec.uses_credential and not options.include_credential:
            why = (
                "Scheduled runs skip the checks that call Roblox with the credential unless "
                "health_auto_include_credential is 1 (plan 13.1, 13.3)."
                if trigger == Trigger.SCHEDULE
                else "This run was started without the credential checks."
            )
            return env.result(Status.NA, "skipped", finding=why, detail={"skipped": True})
        timeout = self.timeout_for(spec)
        started = env.mono()
        try:
            async with asyncio.timeout(timeout):
                result = await spec.fn(env)
        except TimeoutError:
            result = env.result(
                Status.FAIL,
                f"did not finish within {timeout:g} s",
                finding="The check ran out of time; what it measures is too slow or stuck.",
            )
        except Exception as exc:
            self.check_errors += 1
            log.exception("health_check_failed", extra={"fields": {"check": env.check_id}})
            result = env.result(
                Status.WARN,
                f"check error ({type(exc).__name__})",
                finding="The check itself failed (a Roxy bug); the worker log has the traceback.",
            )
        result.duration_ms = max(0.0, (env.mono() - started) * 1000)
        self.checks_run += 1
        return result

    # --- runs --------------------------------------------------------------------------------------------------

    async def _take_lease(self, holder: str) -> bool:
        from roxy.storage import leases

        now_ms = int(self.ctx.clock.now_ms())
        grant = await self.ctx.dbs.hot.write(
            lambda conn: leases.acquire(conn, RUN_LEASE, holder, RUN_LEASE_TTL_MS, now_ms)
        )
        return grant is not None

    async def _release_lease(self, holder: str) -> None:
        from roxy.storage import leases

        with contextlib.suppress(Exception):
            await self.ctx.dbs.hot.write(lambda conn: leases.release(conn, RUN_LEASE, holder, delete=True))

    async def running_run_id(self) -> int | None:
        """The run that is running now (fleet-wide), if any."""
        now = float(self.ctx.clock.now())

        def read(conn: Any) -> int | None:
            row = conn.execute(
                "SELECT id FROM health_runs WHERE finished_at IS NULL AND started_at >= ? ORDER BY id DESC LIMIT 1",
                (int(now - store.RUN_STALE_S),),
            ).fetchone()
            return None if row is None else int(row[0])

        result: int | None = await self.ctx.dbs.metrics.read(read)
        return result

    async def _open(
        self, planned: list[tuple[CheckSpec, dict[str, str]]], *, trigger: str, actor: str, options: RunOptions
    ) -> tuple[int, str]:
        holder = f"{getattr(self.ctx, 'worker_id', 'worker')}#{secrets.token_hex(4)}"
        if not await self._take_lease(holder):
            raise RunBusy(await self.running_run_id())
        now = float(self.ctx.clock.now())
        at_ms = int(self.ctx.clock.now_ms())
        version = str(getattr(self.ctx, "release", "") or "")
        try:
            run_id: int = await self.ctx.dbs.metrics.write(
                lambda conn: store.insert_run(
                    conn,
                    started_at=int(now),
                    trigger=trigger,
                    version=version,
                    options=options.as_public_dict(),
                    actor=actor,
                    at_ms=at_ms,
                    planned=len(planned),
                )
            )
        except BaseException:
            await self._release_lease(holder)
            raise
        self.runs_started += 1
        log.info(
            "health_run_started",
            extra={"fields": {"run_id": run_id, "trigger": trigger, "checks": len(planned), "actor": actor}},
        )
        return run_id, holder

    async def _execute(
        self,
        run_id: int,
        holder: str,
        planned: list[tuple[CheckSpec, dict[str, str]]],
        *,
        trigger: str,
        options: RunOptions,
    ) -> list[CheckResult]:
        gate = asyncio.Semaphore(self.concurrency)
        results: list[CheckResult] = []
        finished = False

        async def one(spec: CheckSpec, params: dict[str, str]) -> None:
            async with gate:
                result = await self.run_check(spec, params, trigger=trigger, options=options)
            results.append(result)
            at_ms = int(self.ctx.clock.now_ms())
            try:
                await self.ctx.dbs.metrics.write(lambda conn: store.insert_result(conn, run_id, result, at_ms=at_ms))
            except Exception as exc:  # metrics degrade open (C7): the summary still counts it
                log.warning(
                    "health_result_not_stored",
                    extra={"fields": {"run_id": run_id, "check": result.check_id, "error": str(exc)[:200]}},
                )

        try:
            async with asyncio.timeout(self.run_timeout_s):
                await asyncio.gather(*(one(spec, params) for spec, params in planned))
            finished = True
        except TimeoutError:
            log.warning("health_run_timeout", extra={"fields": {"run_id": run_id, "done": len(results)}})
        finally:
            summary = store.summarize(results)
            if not finished:
                summary["interrupted"] = True
                summary["planned"] = len(planned)
            await self._finish(run_id, summary, trigger=trigger, shielded=not finished)
            await self._release_lease(holder)
        log.info("health_run_finished", extra={"fields": {"run_id": run_id, "summary": summary}})
        return results

    async def _finish(self, run_id: int, summary: dict[str, Any], *, trigger: str, shielded: bool) -> None:
        now = int(self.ctx.clock.now())
        at_ms = int(self.ctx.clock.now_ms())

        def write(conn: Any) -> None:
            store.finish_run(conn, run_id, finished_at=now, summary=summary, at_ms=at_ms, trigger=trigger)

        try:
            if shielded:
                # On the way out of a canceled run: never wait out a lock (the run shows as interrupted anyway).
                await asyncio.shield(self.ctx.dbs.metrics.write(write, busy_timeout_ms=FINISH_BUDGET_MS))
            else:
                await self.ctx.dbs.metrics.write(write)
        except Exception as exc:
            log.warning("health_run_not_finished", extra={"fields": {"run_id": run_id, "error": str(exc)[:200]}})

    async def run_checks(
        self,
        planned: Sequence[tuple[CheckSpec, dict[str, str]]],
        *,
        trigger: str = Trigger.MANUAL.value,
        actor: str = "system",
        options: RunOptions | None = None,
    ) -> int:
        """Run these check instances as one run and wait for the end. Returns the run id."""
        chosen = list(planned)
        if not chosen:
            raise NoChecks("no checks to run")
        opts = options or RunOptions()
        run_id, holder = await self._open(chosen, trigger=trigger, actor=actor, options=opts)
        results = await self._execute(run_id, holder, chosen, trigger=trigger, options=opts)
        if trigger == Trigger.SCHEDULE:
            await self.alert_new_failures(run_id, results)
        return run_id

    async def run_now(self, *, trigger: str, actor: str, options: RunOptions | None = None) -> int:
        """Plan and run a whole run, waiting for it (the scheduled job, scripts)."""
        opts = options or RunOptions()
        return await self.run_checks(self.plan(opts), trigger=trigger, actor=actor, options=opts)

    async def start_run(self, *, trigger: str, actor: str, options: RunOptions | None = None) -> int:
        """Start a run in the background and return its id at once (the Check Proxy Health button)."""
        opts = options or RunOptions()
        planned = self.plan(opts)
        self._tasks = {run_id: task for run_id, task in self._tasks.items() if not task.done()}
        if len(self._tasks) >= MAX_TASKS:
            raise RunBusy(next(iter(self._tasks)))
        run_id, holder = await self._open(planned, trigger=trigger, actor=actor, options=opts)
        coro = self._execute(run_id, holder, planned, trigger=trigger, options=opts)
        spawn = getattr(getattr(self.ctx, "tasks", None), "spawn", None)
        task: asyncio.Task[Any] | None
        if callable(spawn):
            task = spawn(f"health_run:{run_id}", coro, group="health", limit=MAX_TASKS)
        else:
            task = asyncio.get_running_loop().create_task(coro, name=f"roxy:health_run:{run_id}")
        if task is None:  # the supervisor refused (stopping): close the run instead of leaving it running
            summary = {**store.summarize([]), "interrupted": True, "planned": len(planned)}
            await self._finish(run_id, summary, trigger=trigger, shielded=True)
            await self._release_lease(holder)
            raise RunBusy(None)
        self._tasks[run_id] = task
        return run_id

    async def wait(self, run_id: int, timeout_s: float = RUN_TIMEOUT_S) -> None:
        """Wait for a background run of this worker to end (tests, scripts)."""
        task = self._tasks.get(run_id)
        if task is not None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(asyncio.shield(task), timeout=timeout_s)

    # --- alerts ------------------------------------------------------------------------------------------------

    async def alert_new_failures(self, run_id: int, results: Sequence[CheckResult]) -> list[str]:
        """Plan 17.7 "Health check new failures": compare with the scheduled run before and alert on what newly
        fails. The base is the previous SCHEDULED run, so a manual run in between (which the admin watched) never
        hides a failure from the alert, and a failure already alerted is not alerted again while it lasts."""
        now = float(self.ctx.clock.now())

        def read(conn: Any) -> dict[str, Any] | None:
            base = store.previous_run_id(conn, run_id, trigger=Trigger.SCHEDULE.value)
            if base is None:
                return {"new_failures": [r.check_id for r in results if r.status is Status.FAIL]}
            return store.compare_runs(conn, run_id, base, now=now)

        try:
            comparison = await self.ctx.dbs.metrics.read(read)
        except Exception as exc:
            log.warning("health_compare_failed", extra={"fields": {"run_id": run_id, "error": str(exc)[:200]}})
            return []
        if comparison is not None:
            new = list(comparison["new_failures"])
        else:
            new = [r.check_id for r in results if r.status is Status.FAIL]
        if not new:
            return []
        notifier = getattr(self.ctx, "alerts", None)
        notify = getattr(notifier, "notify", None)
        if callable(notify):
            try:
                from roxy.notify.alerts import make_alert

                origin = str(getattr(self.ctx.env, "site_origin", "")).rstrip("/")
                alert = make_alert(
                    "health_failures",
                    summary=f"The scheduled health check found {len(new)} new failure(s): {', '.join(new[:10])}.",
                    fields={"checks": new[:20], "run_id": run_id, "page": "health"},
                    link=f"{origin}/admin/health?run={run_id}",
                    n=len(new),
                    fingerprint=store.failures_fingerprint(new),
                )
                notify(alert)
            except Exception:
                log.warning("health_alert_failed", exc_info=True)
        return new


def default_options(ctx: Any, trigger: str, *, checks_wanted: Sequence[str] = ()) -> RunOptions:
    """The options a run of `trigger` uses: scheduled runs include credential checks only when
    `health_auto_include_credential` is 1 (13.1); every other trigger includes them."""
    include = True
    if trigger == Trigger.SCHEDULE:
        include = bool(ctx.settings.get("health_auto_include_credential"))
    return RunOptions(checks=tuple(checks_wanted), include_credential=include)


def runner_for(ctx: Any) -> HealthRunner:
    """This worker's `HealthRunner`, created on first use and kept on the context.

    `AppContext` has no `health` field yet (integrator request); a dataclass instance without slots accepts the
    attribute, and a test may put its own runner (with fixture facts) there first.
    """
    runner = getattr(ctx, "health", None)
    if isinstance(runner, HealthRunner) and runner.ctx is ctx:
        return runner
    runner = HealthRunner(ctx)
    ctx.health = runner
    return runner


# ------------------------------------------------------------------------------------------------- leader jobs


def register_jobs(registry: Any, ctx: Any) -> None:
    """Add the health leader jobs to the scheduler's registry (wired by the lifespan's jobs step).

    Wiring (integrator): in `lifespan._register_package_jobs`, `health_runner.register_jobs(registry, ctx)` when
    `roxy.health.runner` imports. Both jobs are leader-only.
    """
    from roxy.scheduler.jobs import Job

    def interval() -> float:
        # Read live before every scheduling decision; 0 turns scheduled runs off (the job then never runs).
        try:
            hours = float(ctx.settings.get("health_auto_interval_h") or 0)
        except (KeyError, LookupError, TypeError, ValueError):
            hours = 0.0
        return SCHEDULE_POLL_S if hours > 0 else 0.0

    async def scheduled(job_ctx: Any) -> dict[str, Any]:
        return await scheduled_run(ctx, job_ctx)

    async def publish(job_ctx: Any) -> dict[str, Any]:
        return await publish_job_status(ctx, job_ctx)

    registry.add(
        Job(
            SCHEDULE_JOB,
            interval,
            scheduled,
            leader_only=True,
            timeout_s=RUN_TIMEOUT_S + 60,
            # The first look comes one poll (5 minutes) after the job runner starts, not at boot: a deploy's own
            # smoke checks and the first callers get the buckets first, and a run never races the worker's startup.
            run_at_start=False,
            description="Run Check Proxy Health every health_auto_interval_h hours; alert on new failures (13.1).",
        )
    )
    registry.add(
        Job(
            PUBLISH_JOB,
            PUBLISH_INTERVAL_S,
            publish,
            leader_only=True,
            run_at_start=True,
            description="Publish the leader's job status for H-LEADER (health_job_status).",
        )
    )


async def scheduled_run(ctx: Any, job_ctx: Any) -> dict[str, Any]:
    """The scheduled run: due when `health_auto_interval_h` hours passed since the last scheduled run."""
    hours = float(ctx.settings.get("health_auto_interval_h") or 0)
    if hours <= 0:
        return {"ran": False, "reason": "off"}
    now = float(job_ctx.now)

    def last(conn: Any) -> tuple[int | None, int | None]:
        return (
            store.last_started_at(conn, Trigger.SCHEDULE.value),
            store.latest_run_id(conn, trigger=Trigger.SCHEDULE.value, finished=False),
        )

    last_started, last_id = await ctx.dbs.metrics.read(last)
    if last_started is not None and now - last_started < hours * 3600:
        return {"ran": False, "next_in_s": round(hours * 3600 - (now - last_started))}
    bucket = f"after-{last_id or 0}"
    # Idempotent per slot: a leadership change in the middle never starts the same scheduled run twice.
    if not await job_ctx.claim(bucket, retry_unfinished_after_s=RUN_TIMEOUT_S + 120):
        return {"ran": False, "reason": "claimed"}
    runner = runner_for(ctx)
    try:
        run_id = await runner.run_now(
            trigger=Trigger.SCHEDULE.value,
            actor="system:schedule",
            options=default_options(ctx, Trigger.SCHEDULE.value),
        )
    except RunBusy as busy:
        return {"ran": False, "reason": "busy", "running": busy.running_run_id}
    await job_ctx.finish(bucket)
    return {"ran": True, "run_id": run_id}


async def publish_job_status(ctx: Any, job_ctx: Any) -> dict[str, Any]:
    """Write the leader's `JobRunner.status()` to metrics.db (fenced: only the current leader writes)."""
    runner = getattr(ctx, "jobs", None)
    if runner is None:
        return {"published": 0}
    rows = [row for row in runner.status() if row.get("leader_only", True)]
    now = int(job_ctx.now)
    holder = str(getattr(job_ctx, "holder", "") or getattr(ctx, "worker_id", ""))
    written: int = await job_ctx.fenced_write(
        ctx.dbs.metrics, lambda conn: store.write_job_status(conn, rows, now=now, holder=holder)
    )
    return {"published": written}


def audit_run(ctx: Any, actor: Any, run_id: int, options: RunOptions, request_id: str | None) -> Any:
    """Record "health.run" in the audit log (a run may spend one credential call, 13.3). Returns the write."""
    from roxy.config import audit

    at = int(ctx.clock.now())
    after = {**options.as_public_dict(), "run_id": run_id}

    def write(conn: Any) -> int:
        return audit.record(conn, actor, "health.run", f"health_run:{run_id}", None, after, None, request_id, at=at)

    return ctx.dbs.control.write(write)


__all__ = [
    "CONCURRENCY",
    "PUBLISH_JOB",
    "RUN_LEASE",
    "RUN_TIMEOUT_S",
    "SCHEDULE_JOB",
    "HealthRunner",
    "NoChecks",
    "RunBusy",
    "audit_run",
    "default_options",
    "publish_job_status",
    "register_jobs",
    "runner_for",
    "scheduled_run",
]
