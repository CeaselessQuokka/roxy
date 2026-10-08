"""Lifespan: what one worker does when it starts and when it stops, in a fixed, documented order.

What this is
    `AppContext`, the one object per worker that holds everything long-lived (databases, settings, rules,
    clients, background tasks), and `build_lifespan(env)`, the FastAPI lifespan that builds it at startup, stores
    it at `app.state.ctx`, and takes it apart at shutdown.

Why it exists
    v1 created its state at import time, in module globals, in every worker, and lost up to 30 s of statistics on
    each worker recycle because nothing flushed on exit. A lifespan gives one place, run once per worker, where
    the startup order is explicit and every resource has a matching cleanup (plan 5.5). Tests build an app with
    temp databases and run the same code, so there is no separate "test mode" startup.

How it works
    Startup order (DESIGN.md section 1): env -> logging -> open databases -> schema check of control, hot and
    metrics (or development auto-migrate) -> cache.db quick check and rebuild, then its schema check -> settings
    -> rules -> alerts (the notifier) -> egress clients -> recorder and batch writer -> upstream service -> cache
    -> abuse pipeline -> error hooks -> heartbeat -> leader loop and jobs -> config watcher -> SSE tail. Each step
    is a small function; each step that acquires something registers its cleanup on an `AsyncExitStack`, so
    shutdown runs the cleanups in exactly the reverse order, and a failure halfway through startup still cleans
    up what was already opened.
    The request path packages come in dependency order: the notifier first (the egress reports leak trips to it),
    the egress before the recorder (whatever its accounting buffered meanwhile is handed over), the recorder
    before upstream, cache and abuse (each keeps a reference to it), upstream before the cache (the cache fetches
    through it), and the abuse pipeline last, because the proxy route answers 503 `degraded` until `ctx.abuse`
    exists, so a half-built worker never serves. Shutdown therefore stops the abuse loops first, flushes the
    cache, stops upstream, then flushes the recorder synchronously (after its loop has stopped, so the final
    write sees every number), closes the egress clients and finally the notifier.
    Stopping has a time limit from outside: gunicorn kills a worker `graceful_timeout` (30 s) after asking it to
    stop. Two things keep the shutdown inside it. First, `begin_drain` (called by `roxy.worker` as soon as uvicorn
    starts shutting down, before it waits for open requests) drops readiness and wakes every tarpit hold, so held
    refusals are answered at once instead of keeping uvicorn waiting for up to 55 s; uvicorn's own wait is capped
    below `graceful_timeout` too (`roxy.worker`). Second, every cleanup step shares `SHUTDOWN_BUDGET_S`
    (`shutdown_time_left`), so a loop stuck on a busy database cannot push the final flush past the kill.
    cache.db is checked before anything reads it: a damaged file must be rebuilt (plan 5.5), not reported as a
    schema problem, and it must not be open in this worker when it is renamed aside.
    A database below `REQUIRED_SCHEMA` stops the worker with a clear `schema_too_old` log line: the exception
    makes uvicorn report "Application startup failed", the worker exits with gunicorn's "failed to boot" status,
    and the master stops, which is what fails a bad deploy cleanly (plan 17.4 step 4). Workers never migrate in
    production.
    A database that is only busy or briefly unreachable (`SharedStateUnavailable`: another process holds a lock,
    a disk hiccup) is a different matter: stopping the whole master for it would take every healthy worker of
    the color down with this one. Startup steps retry it with backoff for up to `STARTUP_RETRY_S`; the cache.db
    check is skipped when hot.db stays busy (the cache is disposable). If a step still cannot read its database,
    the worker exits with an ordinary error status (`roxy.worker` maps it), so gunicorn simply starts a new one.
    Steps for packages built in later phases are marked "Hook (Pn)". Packages that exist are wired; until a
    package exists its step logs that it was skipped, so the skeleton app still starts.
    Error hooks (`core/errors.py`) live on the app, not the context, and an app can run its lifespan more than
    once (tests do): they are installed once per app and look up the current context when they run.

What to read next
    `roxy/main.py` (how the app is assembled), `roxy/storage/db.py` and `roxy/scheduler/leader.py`, then the
    request path: `roxy/proxy/router.py`.
"""

from __future__ import annotations

import asyncio
import builtins
import contextlib
import contextvars
import importlib
import logging
import os
import re
import secrets
import socket
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator, Mapping
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, Any, cast

from roxy import __version__
from roxy.config.env import EnvSettings, removed_env_vars_present
from roxy.core.clock import SYSTEM_CLOCK, Clock
from roxy.core.iphash import ip_hash, load_ip_hash_key
from roxy.core.logging import configure_logging, set_ip_hasher
from roxy.core.redact import SecretRegistry
from roxy.core.tasks import TaskSupervisor

if TYPE_CHECKING:
    from fastapi import FastAPI

    from roxy.abuse.pipeline import AbusePipeline
    from roxy.cache.service import CacheService
    from roxy.config.runtime import RuntimeSettings
    from roxy.egress.clients import EgressClients
    from roxy.metrics.live import EventTail
    from roxy.metrics.recorder import MetricsRecorder
    from roxy.notify.notifier import Notifier
    from roxy.rules.store import RulesStore
    from roxy.scheduler.heartbeat import HeartbeatReporter
    from roxy.scheduler.jobs import JobRegistry, JobRunner
    from roxy.scheduler.leader import LeaderElector
    from roxy.storage.db import Databases
    from roxy.upstream.service import UpstreamService

log = logging.getLogger("roxy.lifespan")

LOOP_STOP_TIMEOUT_S = 10.0
"""How long shutdown waits for a background loop to finish its own cleanup (release a lease, delete a row), at
most; the whole shutdown is also held to `SHUTDOWN_BUDGET_S`."""

TASK_DRAIN_TIMEOUT_S = 25.0
"""How long shutdown lets one-shot jobs (stale-while-revalidate refreshes) finish, at most; in practice what is left
of `SHUTDOWN_BUDGET_S` (those jobs already ran during uvicorn's graceful wait for open requests)."""

SHUTDOWN_BUDGET_S = 8.0
"""Every cleanup step of the lifespan shutdown together (final metrics flush, leader lease release, closing the
clients and databases) must fit in this. `roxy.worker` sets uvicorn's graceful wait for open requests to gunicorn's
`graceful_timeout` minus this budget and a margin, so gunicorn never kills a worker before its shutdown ran."""

SHUTDOWN_MIN_STEP_S = 0.1
"""A step still gets this long when the budget is spent (a healthy loop stops in milliseconds)."""

_shutdown_deadline: contextvars.ContextVar[float | None] = contextvars.ContextVar(
    "roxy_shutdown_deadline", default=None
)
# Set by the lifespan when its shutdown starts. A ContextVar, not a global: the exit stack's cleanups run in the
# lifespan's own task, so they see the deadline of their app (tests run several apps in one process).


def shutdown_time_left(cap_s: float) -> float:
    """How long the next shutdown step may take: `cap_s`, cut to what is left of `SHUTDOWN_BUDGET_S`."""
    deadline = _shutdown_deadline.get()
    if deadline is None:
        return cap_s
    return max(SHUTDOWN_MIN_STEP_S, min(cap_s, deadline - time.monotonic()))


def begin_drain(app: Any) -> None:
    """The server began to shut down: let go of every connection held open on purpose, then let uvicorn wait.

    Called by `roxy.worker` before uvicorn waits for open requests (and before the lifespan shutdown runs). A
    tarpit hold may last up to 55 s, longer than gunicorn's `graceful_timeout` (30 s): without this, uvicorn would
    wait for it until gunicorn killed the worker, and the lifespan shutdown (final metrics flush, leader lease
    release) would never run. So readiness drops at once and the tarpit answers every held refusal now
    (`Tarpit.wake_all`; a context without an abuse pipeline is simply skipped). Never raises.
    """
    public = getattr(app, "public", app)  # roxy.asgi serves a ListenerDispatcher that wraps the public app
    ctx = getattr(getattr(public, "state", None), "ctx", None)
    if ctx is None:
        return
    try:
        ctx.ready = False  # the deploy gate stops sending work here
        tarpit = getattr(getattr(ctx, "abuse", None), "tarpit", None)
        wake = getattr(tarpit, "wake_all", None)
        if callable(wake):
            wake()
        log.info("worker_draining", extra={"fields": {"worker_id": ctx.worker_id, "tarpit_woken": callable(wake)}})
    except Exception:
        log.exception("worker_drain_failed")


async def _stop_tasks(tasks: TaskSupervisor) -> None:
    """Shutdown step: drain one-shot jobs within what is left of the budget, then cancel every task."""
    await tasks.stop(drain_timeout_s=shutdown_time_left(TASK_DRAIN_TIMEOUT_S))


CACHE_INIT_LEASE = "cache_init"
CACHE_INIT_TTL_MS = 60_000
CACHE_INIT_WAIT_S = 15.0

STARTUP_RETRY_S = 20.0
"""How long a startup step retries a busy or unreachable database before the worker gives up (below gunicorn's
30 s worker timeout, which would otherwise kill a worker still starting)."""

STARTUP_RETRY_MAX_DELAY_S = 2.0

SCHEMA_CHECKED_FIRST = ("control", "hot", "metrics")
"""Databases checked in the schema step; cache.db follows its own quick check (see the module docstring)."""


class StartupUnavailable(RuntimeError):
    """A shared database stayed unavailable through every startup retry. Transient: a new worker may succeed."""


_transient_startup_failure = False


def transient_startup_failure() -> bool:
    """True when this process's startup failed only because shared state was unavailable (read by roxy.worker)."""
    return _transient_startup_failure


def _unavailable_error() -> tuple[type[Exception], ...]:
    """`(SharedStateUnavailable,)` for `except`, or an empty tuple (catches nothing) while storage is not built."""
    db_module = optional_import("roxy.storage.db")
    found = getattr(db_module, "SharedStateUnavailable", None) if db_module is not None else None
    return (found,) if isinstance(found, type) and issubclass(found, Exception) else ()


async def _retry_unavailable[R](step: str, attempt: Callable[[], Awaitable[R]], budget_s: float | None = None) -> R:
    """Run `attempt()`, retrying `SharedStateUnavailable` with backoff for up to `STARTUP_RETRY_S`.

    Any other exception (a schema that is too old, a bug) is raised at once. After the budget the last error is
    raised as `StartupUnavailable`.
    """
    unavailable = _unavailable_error()
    deadline = time.monotonic() + (STARTUP_RETRY_S if budget_s is None else budget_s)
    delay = 0.2
    while True:
        try:
            return await attempt()
        except unavailable as exc:
            if time.monotonic() + delay >= deadline:
                raise StartupUnavailable(f"{step}: {exc}") from exc
            log.warning(
                "startup_step_retry",
                extra={"fields": {"step": step, "error": str(exc)[:200], "retry_in_s": delay}},
            )
            await asyncio.sleep(delay)
            delay = min(delay * 2, STARTUP_RETRY_MAX_DELAY_S)


@dataclass
class AppContext:
    """Everything one worker keeps for its lifetime (DESIGN.md section 1). Add fields; never rename them."""

    env: EnvSettings
    clock: Clock
    dbs: Databases
    settings: RuntimeSettings
    rules: RulesStore
    worker_id: str  # f"{hostname}:{pid}:{random8}"
    color: str  # ROXY_COLOR: "blue", "green" or "dev"
    started_at: float
    tasks: TaskSupervisor
    # Filled by later phases (None until then):
    recorder: MetricsRecorder | None = None
    egress: EgressClients | None = None
    upstream: UpstreamService | None = None
    cache: CacheService | None = None
    abuse: AbusePipeline | None = None
    alerts: Notifier | None = None
    # Added by P0:
    release: str = ""  # commit or version this worker runs (reported by /internal/version)
    leader: LeaderElector | None = None
    heartbeat: HeartbeatReporter | None = None
    jobs: JobRunner | None = None
    ip_hash_key: bytes | None = None  # the `ip_hash_key` credential (plan 12.3), None when not configured
    ready: bool = False  # True once startup finished; False again as soon as shutdown begins
    startup_steps: list[str] = field(default_factory=list)  # step names in the order they ran (tests, /internal)
    # Added by the wave 2 wiring:
    live_tail: EventTail | None = None  # the per-worker `events` tail the SSE endpoints subscribe to (plan 14.11)


class CatalogDefaultsSettings:
    """Read-only stand-in for `RuntimeSettings` until `config/runtime.py` exists: every key at its catalog default.

    Implements the read side of the DESIGN.md section 4 API, so code written against `ctx.settings` works in
    the skeleton. It never changes (`version` stays 0) because there is nothing to reload from yet.
    """

    # The method names shadow the built-in types inside this class body, so annotations say `builtins.int`.
    version = 0

    def __init__(self, values: Mapping[builtins.str, Any]) -> None:
        self._values = dict(values)

    def snapshot(self) -> Mapping[builtins.str, Any]:
        return dict(self._values)

    def get(self, key: builtins.str) -> Any:
        return self._values[key]

    def int(self, key: builtins.str) -> builtins.int:
        return builtins.int(self._values[key])

    def float(self, key: builtins.str) -> builtins.float:
        return builtins.float(self._values[key])

    def bool(self, key: builtins.str) -> builtins.bool:
        return builtins.bool(self._values[key])

    def str(self, key: builtins.str) -> builtins.str:
        return builtins.str(self._values[key])

    def list(self, key: builtins.str) -> builtins.list[Any]:
        return builtins.list(self._values[key])

    async def refresh_if_changed(self) -> builtins.bool:
        return False

    def subscribe(self, callback: Callable[..., Any]) -> None:
        """Nothing ever changes here, so callbacks are never called."""


# --- helpers -------------------------------------------------------------------------------------------------------


def optional_import(name: str) -> ModuleType | None:
    """Import `name`, or return None when that module (or its package) has not been written yet.

    Only "this module does not exist" is tolerated. A module that exists but fails to import (a syntax error, a
    missing dependency) raises, because silently starting without it would hide a real bug.
    """
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError as exc:
        missing = exc.name or ""
        if missing and (name == missing or name.startswith(missing + ".")):
            return None
        raise


_RELEASE_DIR = re.compile(r"/releases/([0-9a-f]{7,40})(?:/|$)")


def detect_release(env: EnvSettings) -> str:
    """The release this worker runs: ROXY_RELEASE_SHA, else the `/opt/roxy/releases/<sha>` directory, else the
    package version (development)."""
    if env.release_sha:
        return env.release_sha
    for candidate in (Path(__file__).resolve(), Path.cwd().resolve()):
        match = _RELEASE_DIR.search(candidate.as_posix())
        if match:
            return match.group(1)
    return __version__


def new_worker_id() -> str:
    """`<hostname>:<pid>:<8 random hex>` (DESIGN.md section 1). The random part tells a recycled pid apart."""
    return f"{socket.gethostname()}:{os.getpid()}:{secrets.token_hex(4)}"


@contextlib.contextmanager
def _step(steps: list[str], name: str) -> Iterator[None]:
    """Time one startup step and record its name, so the order is visible in logs and tests."""
    started = time.perf_counter()
    steps.append(name)
    yield
    log.info("startup_step", extra={"fields": {"step": name, "ms": round((time.perf_counter() - started) * 1000, 1)}})


def _start_loop(
    ctx: AppContext,
    stack: AsyncExitStack,
    name: str,
    run: Callable[[asyncio.Event], Awaitable[Any]],
) -> None:
    """Start a background loop that takes a stop event, and register its graceful stop on the exit stack.

    Shutdown sets the event (so the loop runs its own cleanup: release a lease, delete a heartbeat row), waits up
    to `LOOP_STOP_TIMEOUT_S`, then cancels it if it is still running.
    """
    stop = asyncio.Event()
    task = ctx.tasks.start(name, lambda: run(stop))

    async def stop_loop() -> None:
        stop.set()
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=shutdown_time_left(LOOP_STOP_TIMEOUT_S))
        except TimeoutError:
            log.warning("loop_stop_timeout", extra={"fields": {"task": name}})
            await ctx.tasks.cancel(name)
        except Exception:
            log.exception("loop_stop_failed", extra={"fields": {"task": name}})

    stack.push_async_callback(stop_loop)


# --- startup steps -------------------------------------------------------------------------------------------------


async def _open_databases(env: EnvSettings, stack: AsyncExitStack) -> Databases | None:
    """Step: open the four databases (P1 `storage/db.py`)."""
    db_module = optional_import("roxy.storage.db")
    if db_module is None:
        log.warning("storage_not_built", extra={"fields": {"step": "databases"}})
        return None
    dbs = cast("Databases", db_module.open_databases(env))
    stack.push_async_callback(dbs.close_all)
    return dbs


async def _check_schema(
    env: EnvSettings, dbs: Databases, clock: Clock, names: tuple[str, ...] = SCHEMA_CHECKED_FIRST
) -> None:
    """Step: refuse to start below REQUIRED_SCHEMA; in development with ROXY_AUTO_MIGRATE=1, migrate first.

    The development migration also seeds the built-in default rows (plan 15.5) once, exactly like the deploy's
    migration step does (`python -m roxy.config.defaults --seed`). Production workers never migrate or seed.
    """
    migrate = optional_import("roxy.storage.migrate")
    if migrate is None:
        log.warning("storage_not_built", extra={"fields": {"step": "schema"}})
        return
    ran = False
    if env.migrate_on_start:
        # Development only (DESIGN.md section 0). Run off the event loop: migrations are synchronous SQLite.
        ran = bool(await asyncio.to_thread(migrate.auto_migrate, dbs, env, names=names))
        log.info("auto_migrate", extra={"fields": {"ran": ran, "databases": list(names)}})
    schema_too_old = getattr(migrate, "SchemaTooOld", RuntimeError)
    try:
        versions = await _retry_unavailable("schema", lambda: asyncio.to_thread(migrate.check_schema, dbs, names=names))
    except schema_too_old:
        log.critical(
            "startup_refused_schema_too_old",
            extra={"fields": {"fix": "run `python -m roxy.storage.migrate --expand` (deploy.sh step 3)"}},
        )
        raise
    log.info("schema_ok", extra={"fields": {"versions": versions}})
    if ran and "control" in names:
        await _retry_unavailable("seed_defaults", lambda: _seed_defaults(dbs, clock))


async def _seed_defaults(dbs: Databases, clock: Clock) -> None:
    """Development auto-migrate only: insert the plan 15.5 default rows once (`config/defaults.py`).

    Safe with several workers starting at once: seeding runs in one control.db write transaction and stops at the
    `defaults_seeded` marker, so the second worker finds the marker and inserts nothing.
    """
    defaults = optional_import("roxy.config.defaults")
    seed = getattr(defaults, "seed_control_defaults", None) if defaults is not None else None
    if seed is None:
        return
    report = await seed(dbs.control, clock)
    log.info("defaults_seeded", extra={"fields": report.as_dict()})


async def _check_cache_db(env: EnvSettings, dbs: Databases, worker_id: str, clock: Clock) -> None:
    """Step: `PRAGMA quick_check` on the disposable cache.db under the `cache_init` lease (plan 5.5), then the
    cache.db schema check (development: migrate it first).

    One worker checks (and rebuilds a damaged file); the others wait for it to finish, up to a bound. The check
    runs before anything in this worker opens cache.db. If hot.db stays busy the check is skipped: the cache is
    disposable and serving matters more than this check (MP review F1).
    """
    migrate = optional_import("roxy.storage.migrate")
    leases = optional_import("roxy.storage.leases")
    if migrate is None or leases is None or not hasattr(migrate, "recover_cache_db"):
        return
    await _recover_cache_db_under_lease(env, dbs, worker_id, clock, migrate, leases)
    await _check_schema(env, dbs, clock, names=("cache",))


async def _recover_cache_db_under_lease(
    env: EnvSettings, dbs: Databases, worker_id: str, clock: Clock, migrate: ModuleType, leases: ModuleType
) -> None:
    cache_path = dbs.paths.get("cache", env.cache_db) if hasattr(dbs, "paths") else env.cache_db
    unavailable = _unavailable_error()

    def try_acquire(conn: Any) -> Any:
        return leases.acquire(conn, CACHE_INIT_LEASE, worker_id, CACHE_INIT_TTL_MS, clock.now_ms())

    def holder(conn: Any) -> Any:
        return leases.holder_epoch(conn, CACHE_INIT_LEASE)

    deadline = time.monotonic() + CACHE_INIT_WAIT_S
    while True:
        try:
            grant = await dbs.hot.write(try_acquire)
        except unavailable as exc:
            if time.monotonic() >= deadline:
                log.warning(
                    "cache_db_check_skipped",
                    extra={"fields": {"reason": "hot.db unavailable", "error": str(exc)[:200]}},
                )
                return
            await asyncio.sleep(0.5)
            continue
        if grant is not None:
            try:
                moved = await asyncio.to_thread(migrate.recover_cache_db, cache_path)
                if moved is not None:
                    log.warning("cache_db_rebuilt", extra={"fields": {"moved_to": str(moved)}})
            finally:
                # A one-off lease (no fencing needed), so the row is deleted rather than kept for its epoch. If
                # hot.db is busy right now the row simply expires after CACHE_INIT_TTL_MS.
                with contextlib.suppress(*unavailable):
                    await dbs.hot.write(lambda conn: leases.release(conn, CACHE_INIT_LEASE, worker_id, delete=True))
            return
        if time.monotonic() >= deadline:
            return  # another worker is taking too long; serving matters more than waiting
        try:
            current = await dbs.hot.read(holder)
        except unavailable:
            await asyncio.sleep(0.5)  # cannot tell who holds it right now; keep waiting until the deadline
            continue
        if current is None or current[2] <= clock.now_ms():
            return  # another worker checked it (its lease is gone)
        await asyncio.sleep(0.2)


async def _load_settings(dbs: Databases | None, clock: Clock) -> RuntimeSettings:
    """Step: warm the runtime settings snapshot. Hook (P2): `config/runtime.py` provides
    `async load_runtime_settings(dbs, clock) -> RuntimeSettings`; until then, catalog defaults."""
    runtime = optional_import("roxy.config.runtime")
    loader = getattr(runtime, "load_runtime_settings", None) if runtime is not None else None
    if loader is not None and dbs is not None:
        return cast("RuntimeSettings", await loader(dbs, clock))
    catalog = optional_import("roxy.config.catalog")
    values: Mapping[str, Any] = catalog.defaults() if catalog is not None else {}
    log.info("settings_from_catalog_defaults", extra={"fields": {"keys": len(values)}})
    return cast("RuntimeSettings", CatalogDefaultsSettings(values))


async def _load_rules(dbs: Databases | None, settings: RuntimeSettings, clock: Clock) -> RulesStore:
    """Step: load the compiled rules snapshot. Hook (P2): `rules/store.py` provides
    `async load_rules_store(dbs, clock) -> RulesStore`; until then there are no rules (None)."""
    store = optional_import("roxy.rules.store")
    loader = getattr(store, "load_rules_store", None) if store is not None else None
    if loader is not None and dbs is not None:
        return cast("RulesStore", await loader(dbs, clock))
    log.info("rules_not_built")
    return cast("RulesStore", None)


def _setup_ip_hashing(ctx: AppContext) -> None:
    """Load the `ip_hash_key` credential and apply `log_hash_client_ips` (plan 9.15) now and on every change."""
    key = load_ip_hash_key(ctx.env.credentials_dir)
    ctx.ip_hash_key = key
    if key is not None:
        SecretRegistry.register("ip_hash_key", key.hex())

    def apply(*_args: Any) -> None:
        try:
            enabled = bool(ctx.settings.get("log_hash_client_ips"))
        except (KeyError, LookupError, AttributeError, TypeError):
            enabled = False
        if enabled and key is None:
            log.warning("ip_hashing_unavailable", extra={"fields": {"reason": "ip_hash_key credential missing"}})
        set_ip_hasher((lambda ip: ip_hash(ip, key)) if enabled and key is not None else None)

    apply()
    subscribe = getattr(ctx.settings, "subscribe", None)
    if callable(subscribe):
        subscribe(apply)


async def _start_heartbeat_and_leader(ctx: AppContext, stack: AsyncExitStack) -> None:
    """Steps: heartbeat, then leader election, then the job runner (P1 `scheduler/`)."""
    heartbeat_mod = optional_import("roxy.scheduler.heartbeat")
    leader_mod = optional_import("roxy.scheduler.leader")
    jobs_mod = optional_import("roxy.scheduler.jobs")
    if heartbeat_mod is None or leader_mod is None or ctx.dbs is None:
        log.info("scheduler_not_built")
        return
    elector = leader_mod.LeaderElector(ctx.dbs.hot, ctx.worker_id, ctx.clock)
    ctx.leader = elector
    with _step(ctx.startup_steps, "heartbeat"):
        info = heartbeat_mod.WorkerInfo.current(
            ctx.worker_id, ctx.color, ctx.started_at, max_requests=ctx.env.max_requests, version=ctx.release
        )
        reporter = heartbeat_mod.HeartbeatReporter(
            ctx.dbs.metrics, info, ctx.clock, is_leader=lambda: elector.is_leader
        )
        ctx.heartbeat = reporter
        _start_loop(ctx, stack, "heartbeat", reporter.run)
    with _step(ctx.startup_steps, "leader"):
        _start_loop(ctx, stack, "leader", elector.run)
    if jobs_mod is None:
        return
    with _step(ctx.startup_steps, "jobs"):
        registry = jobs_mod.JobRegistry()
        retention = optional_import("roxy.storage.retention")
        register = getattr(jobs_mod, "register_storage_jobs", None)
        if register is not None and retention is not None:
            settings = ctx.settings

            def policy() -> Any:
                return retention.RetentionPolicy.from_settings(settings.get)

            # `setting` lets the daily job read `maintenance_hour` and `ui_timezone` live on every run.
            register(registry, ctx.dbs, policy, state_dir=ctx.env.state_dir, setting=settings.get)
        _register_package_jobs(ctx, registry)
        # Hook (P10, P2): insights, health check auto-runs and alert digests register their jobs here.
        runner = jobs_mod.JobRunner(registry, elector, ctx.clock, worker_id=ctx.worker_id)
        ctx.jobs = runner
        _start_loop(ctx, stack, "jobs", runner.run)


CREDENTIAL_LIVENESS_JOB = "credential_liveness"


def _register_package_jobs(ctx: AppContext, registry: JobRegistry) -> None:
    """Leader jobs of the request path packages: metrics compaction and caps, the adaptive rate increase, and
    the scheduled credential liveness probe (plan 5.6). Each is skipped while its package is not wired."""
    metrics_jobs = optional_import("roxy.metrics.jobs")
    if metrics_jobs is not None and ctx.recorder is not None:
        rules = ctx.rules
        metrics_jobs.register_metrics_jobs(
            registry,
            ctx.dbs,
            ctx.settings.get,
            ignore_header=metrics_jobs.rules_ignore_header(ctx.dbs.control, clock=ctx.clock, store=rules),
            # `RulesStore.snapshot` is a property (the compiled rules of the current config_version).
            ignored_headers=lambda: rules.snapshot.ignored_value_headers if rules is not None else (),
        )
    upstream_jobs = optional_import("roxy.upstream.jobs")
    if upstream_jobs is not None and ctx.upstream is not None:
        upstream_jobs.register_upstream_jobs(registry, ctx.upstream)
    jobs_mod = optional_import("roxy.scheduler.jobs")
    if jobs_mod is None or ctx.egress is None or ctx.upstream is None:
        return
    egress, upstream, settings = ctx.egress, ctx.upstream, ctx.settings

    def liveness_interval_s() -> float:
        # Read live before every scheduling decision; 0 turns the scheduled probe off.
        return float(settings.get("credential_probe_interval_min")) * 60.0

    async def liveness(job_ctx: Any) -> dict[str, Any]:
        # Paced by the reserved probe sub-bucket (row 28): the upstream layer's fetcher, never the bare client.
        result = await egress.credential.probe("liveness", fetch=upstream.credential_probe_fetch)
        return {"outcome": result.outcome, "status_code": result.status_code}

    registry.add(
        jobs_mod.Job(
            CREDENTIAL_LIVENESS_JOB,
            liveness_interval_s,
            liveness,
            leader_only=True,
            run_at_start=False,
            description="Check that the Roblox credential still works (one account call, plan 5.6 and 13.2).",
        )
    )


async def _start_alerts(ctx: AppContext, stack: AsyncExitStack) -> None:
    """Step: the notifier (`notify/notifier.py`), closed last among the request path packages."""
    notifier_mod = optional_import("roxy.notify.notifier")
    if notifier_mod is None or ctx.dbs is None:
        log.info("notifier_not_built")
        return
    ctx.alerts = notifier_mod.build_notifier(ctx)
    stack.push_async_callback(ctx.alerts.aclose)


async def _start_egress(ctx: AppContext, stack: AsyncExitStack) -> None:
    """Step "clients": the three egress clients (P3, `egress/clients.py`) and their per-worker refresh loop."""
    egress_mod = optional_import("roxy.egress.clients")
    if egress_mod is None or ctx.dbs is None:
        log.info("egress_not_built")
        return
    ctx.egress = await egress_mod.build_egress_clients(ctx)
    stack.push_async_callback(ctx.egress.aclose)
    _start_loop(ctx, stack, "egress_refresh", ctx.egress.run)


def _start_recorder(ctx: AppContext, stack: AsyncExitStack) -> None:
    """Step "recorder": the metrics recorder and its flush loop (P7, `metrics/recorder.py`).

    `close` (a synchronous final flush) is registered BEFORE the loop, so on shutdown the loop stops first and the
    final write then contains every number, including the minute still open.
    """
    recorder_mod = optional_import("roxy.metrics.recorder")
    if recorder_mod is None or ctx.dbs is None:
        log.info("recorder_not_built")
        return
    recorder = recorder_mod.build_recorder(ctx)
    ctx.recorder = recorder
    stack.callback(recorder.close)
    _start_loop(ctx, stack, "metrics_flush", recorder.run)
    accounting = getattr(ctx.egress, "accounting", None)
    if accounting is not None:
        # Usage the egress measured before the recorder existed (its own startup self-tests) is not lost.
        for usage in accounting.drain():
            recorder.record_egress_usage(usage)


def _start_upstream(ctx: AppContext, stack: AsyncExitStack) -> None:
    """Step "upstream": the `UpstreamService` (P4) and its availability mirror loop."""
    service_mod = optional_import("roxy.upstream.service")
    if service_mod is None or ctx.dbs is None or ctx.egress is None:
        log.info("upstream_not_built")
        return
    ctx.upstream = service_mod.UpstreamService(ctx)
    _start_loop(ctx, stack, "upstream_mirror", ctx.upstream.run_mirror)


async def _start_cache(ctx: AppContext, stack: AsyncExitStack) -> None:
    """Step "cache": the `CacheService` (P5); `close` flushes buffered hit counts at shutdown."""
    cache_mod = optional_import("roxy.cache.service")
    if cache_mod is None or ctx.dbs is None:
        log.info("cache_not_built")
        return
    cache = cache_mod.CacheService.from_context(ctx)
    await _retry_unavailable("cache", cache.start)
    ctx.cache = cache
    stack.push_async_callback(cache.close)


async def _start_abuse(ctx: AppContext, stack: AsyncExitStack) -> None:
    """Step "abuse": `abuse.pipeline.install` builds `ctx.abuse`, loads the switches and starts its loops (P6)."""
    pipeline_mod = optional_import("roxy.abuse.pipeline")
    if pipeline_mod is None or ctx.dbs is None:
        log.info("abuse_not_built")
        return
    await pipeline_mod.install(ctx, stack)


def _install_error_hooks(app: FastAPI) -> None:
    """Attach the metrics and alert sides of `core/errors.py` hooks, once per app (see the module docstring).

    The hooks read `app.state.ctx` when an error happens, so a second lifespan run on the same app (a test) reaches
    the new recorder and notifier instead of the closed ones.
    """
    hooks = getattr(app.state, "error_hooks", None)
    if hooks is None or getattr(app.state, "error_hooks_wired", False):
        return
    app.state.error_hooks_wired = True

    def current(name: str) -> Any:
        return getattr(getattr(app.state, "ctx", None), name, None)

    events_mod = optional_import("roxy.metrics.security_events")
    if events_mod is not None:
        events_mod.install_error_hooks(hooks, lambda: current("recorder"))
    notifier_mod = optional_import("roxy.notify.notifier")
    if notifier_mod is not None:

        def alert_on_error(event: Any) -> None:
            notifier = current("alerts")
            if notifier is None:
                return
            alert = notifier_mod.error_alert(event, str(getattr(notifier, "site_origin", "")))
            if alert is not None:
                notifier.notify(alert)  # fire and forget: the error answer has already been sent

        hooks.add("server_error", alert_on_error)


def _start_live_tail(ctx: AppContext, stack: AsyncExitStack) -> None:
    """Step "sse_tail": one `events` tail per worker for the SSE endpoints (plan 5.6, 14.11)."""
    live_mod = optional_import("roxy.metrics.live")
    if live_mod is None or ctx.dbs is None:
        log.info("live_tail_not_built")
        return
    ctx.live_tail = live_mod.EventTail(ctx.dbs.metrics)
    _start_loop(ctx, stack, "sse_tail", ctx.live_tail.run)


def _start_config_watcher(ctx: AppContext, stack: AsyncExitStack) -> None:
    """Step: poll `config_version` every second and reload settings and rules when it moved (plan 5.6, 5.7).

    Every worker runs its own watcher, so an edit made in one worker reaches the whole fleet within about a
    second. Only stores that can reload are watched (the catalog-defaults stand-in never changes).
    """
    runtime = optional_import("roxy.config.runtime")
    watch = getattr(runtime, "watch_config", None) if runtime is not None else None
    if watch is None or ctx.dbs is None:
        log.info("config_watcher_not_built")
        return
    targets = [
        target
        for target in (ctx.settings, ctx.rules)
        if target is not None and not isinstance(target, CatalogDefaultsSettings)
    ]
    if not targets:
        return
    _start_loop(ctx, stack, "config_watcher", lambda stop: watch(stop, *targets))


# --- the lifespan --------------------------------------------------------------------------------------------------


async def startup(app: FastAPI, env: EnvSettings, clock: Clock, stack: AsyncExitStack) -> AppContext:
    """Run every startup step in order and return the finished context (also stored at `app.state.ctx`).

    A `StartupUnavailable` (shared state stayed unreachable through the retries) is remembered for
    `roxy.worker`, which then exits with an ordinary error status instead of gunicorn's "failed to boot".
    """
    global _transient_startup_failure
    _transient_startup_failure = False
    try:
        return await _startup(app, env, clock, stack)
    except StartupUnavailable as exc:
        _transient_startup_failure = True
        log.critical("startup_failed_shared_state_unavailable", extra={"fields": {"error": str(exc)[:300]}})
        raise


async def _startup(app: FastAPI, env: EnvSettings, clock: Clock, stack: AsyncExitStack) -> AppContext:
    steps: list[str] = []
    worker_id = new_worker_id()
    started_at = clock.now()
    with _step(steps, "env"):
        removed = removed_env_vars_present()
    with _step(steps, "logging"):
        configure_logging(env.log_level, static_fields={"color": env.color, "pid": os.getpid()})
        log.info(
            "worker_starting",
            extra={"fields": {"worker_id": worker_id, "env": env.env, "color": env.color, "version": __version__}},
        )
        if removed:
            # Names only: ROXY_ROTATE_PROXY's value embeds a password.
            log.warning("removed_env_vars_ignored", extra={"fields": {"names": removed}})
    with _step(steps, "databases"):
        dbs = await _open_databases(env, stack)
    if dbs is not None:
        with _step(steps, "schema"):
            await _check_schema(env, dbs, clock)
        with _step(steps, "cache_db_check"):
            await _check_cache_db(env, dbs, worker_id, clock)
    with _step(steps, "settings"):
        settings = await _retry_unavailable("settings", lambda: _load_settings(dbs, clock))
    with _step(steps, "rules"):
        rules = await _retry_unavailable("rules", lambda: _load_rules(dbs, settings, clock))

    tasks = TaskSupervisor(clock=clock)
    # Registered early, so it unwinds LATE: after every loop below has been stopped gracefully, it drains one-shot
    # jobs and cancels anything left, before the databases close.
    stack.push_async_callback(_stop_tasks, tasks)
    ctx = AppContext(
        env=env,
        clock=clock,
        dbs=cast("Databases", dbs),  # None only while storage is not built (skeleton)
        settings=settings,
        rules=rules,
        worker_id=worker_id,
        color=env.color,
        started_at=started_at,
        tasks=tasks,
        release=detect_release(env),
        startup_steps=steps,
    )
    app.state.ctx = ctx
    _setup_ip_hashing(ctx)

    with _step(steps, "alerts"):
        await _start_alerts(ctx, stack)
    with _step(steps, "clients"):
        await _retry_unavailable("clients", lambda: _start_egress(ctx, stack))
    with _step(steps, "recorder"):
        _start_recorder(ctx, stack)
    with _step(steps, "upstream"):
        _start_upstream(ctx, stack)
    with _step(steps, "cache"):
        await _start_cache(ctx, stack)
    with _step(steps, "abuse"):
        await _start_abuse(ctx, stack)
    with _step(steps, "error_hooks"):
        _install_error_hooks(app)
    if dbs is not None:
        await _start_heartbeat_and_leader(ctx, stack)
    with _step(steps, "config_watcher"):
        _start_config_watcher(ctx, stack)
    with _step(steps, "sse_tail"):
        _start_live_tail(ctx, stack)
    ctx.ready = True
    log.info("worker_ready", extra={"fields": {"worker_id": worker_id, "steps": steps, "release": ctx.release}})
    return ctx


def build_lifespan(
    env: EnvSettings, clock: Clock | None = None
) -> Callable[[FastAPI], contextlib.AbstractAsyncContextManager[None]]:
    """The FastAPI `lifespan` for one worker: run `startup`, serve, then unwind every step in reverse."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        _shutdown_deadline.set(None)  # a lifespan run again in the same task starts without an old deadline
        async with AsyncExitStack() as stack:
            ctx = await startup(app, env, clock or SYSTEM_CLOCK, stack)
            try:
                yield
            finally:
                ctx.ready = False  # readiness drops first, so the deploy gate stops sending work here
                # Every cleanup below shares one budget, so the whole shutdown fits in gunicorn's graceful_timeout.
                _shutdown_deadline.set(time.monotonic() + SHUTDOWN_BUDGET_S)
                log.info("worker_stopping", extra={"fields": {"worker_id": ctx.worker_id}})
        log.info("worker_stopped", extra={"fields": {"worker_id": ctx.worker_id}})

    return lifespan
