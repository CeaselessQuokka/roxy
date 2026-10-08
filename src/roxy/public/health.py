"""The public monitor endpoint: `GET /health` with v1's keys plus a `Degraded` list (parity rows 14 and 129).

What this is
    `router` with `GET|HEAD /health`, answering
    `{"DataBytes":..,"DataLimitBytes":..,"Degraded":[..],"Paused":..,"PersistenceOK":..,"Status":"ok"}` plus a
    newline, and `POST|PUT|PATCH|DELETE /health`, answering v1's 404 `"Not a Roblox URL"`. `health_body(ctx)`
    builds the JSON so other code (the admin health view) can reuse it.

Why it exists
    External monitors (UptimeRobot style checks, the owner's curl) already parse v1's keys, so they stay, with
    v1's wire form (Flask `jsonify`: sorted keys, compact separators, a trailing newline, `application/json`).
    v2 adds `Degraded`, the short list of reasons the service is running in a reduced mode, so a monitor can
    alarm on "serving, but without shared state" instead of only on "down". The release SHA is NOT here: it tells
    an attacker which build runs, so it lives on the internal socket only (plan 5.8).
    In v1 a `POST /health` fell through to the proxy route: it was refused with 404 `"Not a Roblox URL"`, but it
    also passed pause, throttles and the 8 to 20 s probe tarpit (v1 bug B18). Row 129 keeps the 404 and drops
    the rest, so the non-GET methods are answered here directly.

How it works
    - `DataBytes`: the bytes the four SQLite databases use on disk (main file plus WAL), `DataLimitBytes`: the
      `storage_total_budget_gb` setting in bytes. v1 measured its single JSON data file against 24 MiB; the
      meaning ("how full is the store that predicts trouble") is the same. Measuring means a `stat` per file,
      and on a stalled disk (the C7 situation) a `stat` can block for seconds, which on the event loop would
      freeze every request of the worker. So the sizes are measured on a daemon thread, reused for
      `SIZE_FRESH_S`, and awaited for at most `SIZE_WAIT_S`: when the disk is slow, `/health` answers at once
      with the last size it knows (`cached_data_bytes`), and the late measurement is used by a later call.
    - `PersistenceOK`: every database answers a trivial read within 2 s and the store is within its budget.
    - `Paused`: the pause switch as the abuse pipeline sees it (refreshed every second from control.db).
    - `Degraded` codes: `starting` (the worker has no finished context), `shared_state` (a database did not
      answer), `storage_budget` (over the budget), `memory_rate_limits` (the abuse pipeline fell back to
      per-worker limits, plan C7), `egress_direct_disabled` and `egress_rotator_disabled` (a credential leak
      guard trip switched that egress off until an admin re-enables it).
    Always 200, no Roxy headers beyond the request id, nothing recorded (the monitor polls every 30 s and v1
    kept it out of every log).

What to read next
    `roxy/internal_app.py` (the readiness check the deploy gate uses), `roxy/public/pages.py` (the other public
    routes) and `roxy/abuse/state.py` (where the pause switch comes from).
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import json
import logging
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from fastapi import APIRouter, Request
from fastapi.responses import Response

from roxy.core.reasons import REFUSAL_HEADER, Egress, ReasonCode
from roxy.core.scope import catalog_default

log = logging.getLogger("roxy.public.health")

router = APIRouter()

JSON_TYPE: Final = "application/json"  # v1 jsonify: no charset parameter
PING_TIMEOUT_S: Final = 2.0
GIB: Final = 1024**3
NOT_ROBLOX_BODY: Final = b'"Not a Roblox URL"\n'
"""v1's refusal for a non-GET /health (the proxy's not_roblox text, JSON string plus newline)."""

DB_SUFFIXES: Final = ("", "-wal")


def _setting(ctx: Any, key: str) -> Any:
    settings = getattr(ctx, "settings", None)
    if settings is not None:
        with contextlib.suppress(KeyError, LookupError, AttributeError):
            return settings.get(key)
    return catalog_default(key)


def _database_paths(ctx: Any) -> tuple[str, ...]:
    dbs = getattr(ctx, "dbs", None)
    if dbs is None:
        return ()
    return tuple(str(db.path) for db in dbs.all())


def measure_bytes(paths: tuple[str, ...]) -> int:
    """Bytes the database files use on disk (main files and write-ahead logs); 0 for files that do not exist.

    Blocking file system calls: run on a measurement thread (`_start_measurement`), never on the event loop.
    """
    total = 0
    for name in paths:
        path = Path(name)
        for suffix in DB_SUFFIXES:
            with contextlib.suppress(OSError):
                total += (path.with_name(path.name + suffix)).stat().st_size
    return total


def data_bytes(ctx: Any) -> int:
    """Bytes the databases use on disk, measured now (blocking: for threads and scripts, not the event loop)."""
    return measure_bytes(_database_paths(ctx))


@dataclass
class _Sizes:
    """What this process last measured for one set of database files, and the measurement in flight."""

    value: int = 0
    measured_at: float | None = None  # time.monotonic() of the last finished measurement
    pending: concurrent.futures.Future[int] | None = None


SIZE_FRESH_S: Final = 10.0
"""A measured size is reused for this long (the monitor polls every 30 s; the budget changes slowly)."""

SIZE_WAIT_S: Final = 0.25
"""How long `/health` waits for a new measurement before answering with the last known size."""

MAX_SIZE_ENTRIES: Final = 8
"""Database sets remembered (one per app in this process: one in production, a few in tests); plan P9."""

_SIZES: dict[tuple[str, ...], _Sizes] = {}


def _start_measurement(paths: tuple[str, ...]) -> concurrent.futures.Future[int]:
    """Measure on a new daemon thread. Each set of files has at most one measurement in flight, so a stalled disk
    holds at most `MAX_SIZE_ENTRIES` threads, never the event loop. Daemon (not a ThreadPoolExecutor, whose threads
    are joined at interpreter exit): a `stat` stuck on a dead disk must not keep a stopping worker alive."""
    future: concurrent.futures.Future[int] = concurrent.futures.Future()

    def run() -> None:
        if not future.set_running_or_notify_cancel():
            return
        try:
            future.set_result(measure_bytes(paths))
        except BaseException as exc:  # handed to the waiting side, which keeps the last known size
            future.set_exception(exc)

    threading.Thread(target=run, name="roxy-health-size", daemon=True).start()
    return future


def _sizes_for(paths: tuple[str, ...]) -> _Sizes:
    state = _SIZES.get(paths)
    if state is None:
        while len(_SIZES) >= MAX_SIZE_ENTRIES:
            _SIZES.pop(next(iter(_SIZES)))  # the oldest set (dicts keep insertion order)
        state = _SIZES[paths] = _Sizes()
    return state


def _adopt(state: _Sizes, now: float) -> None:
    """Take the finished measurement's result, if there is one."""
    future = state.pending
    if future is None or not future.done():
        return
    state.pending = None
    with contextlib.suppress(Exception):
        state.value = int(future.result())
        state.measured_at = now


async def cached_data_bytes(ctx: Any, *, wait_s: float = SIZE_WAIT_S) -> int:
    """`DataBytes` without touching the disk on the event loop (finding LOOP-2).

    A size measured in the last `SIZE_FRESH_S` is returned as is. Otherwise one measurement is started on the
    size thread (never two at once for the same files) and awaited for at most `wait_s`, polling so the loop keeps
    serving; if it is not done by then (a stalled disk), the last known size is returned and the measurement is
    picked up by a later call when it finishes. Before the first measurement ever finishes the answer is 0.
    """
    paths = _database_paths(ctx)
    if not paths:
        return 0
    state = _sizes_for(paths)
    now = time.monotonic()
    _adopt(state, now)
    if state.measured_at is not None and now - state.measured_at < SIZE_FRESH_S:
        return state.value
    if state.pending is None:
        try:
            state.pending = _start_measurement(paths)
        except RuntimeError:  # no new thread (interpreter shutting down): answer with what we know
            return state.value
    deadline = now + max(0.0, wait_s)
    # Polling on purpose: the result comes from another thread, and a wake-up callback per waiting request would
    # pile up on a measurement that never finishes (a dead disk); a short poll costs nothing and holds nothing.
    while state.pending is not None and not state.pending.done() and time.monotonic() < deadline:  # noqa: ASYNC110
        await asyncio.sleep(0.005)
    _adopt(state, time.monotonic())
    return state.value


async def databases_answer(ctx: Any) -> bool:
    """True when every database answers `SELECT 1` within `PING_TIMEOUT_S`."""
    dbs = getattr(ctx, "dbs", None)
    if dbs is None:
        return False

    def ping(conn: sqlite3.Connection) -> int:
        return int(conn.execute("SELECT 1").fetchone()[0])

    try:
        async with asyncio.timeout(PING_TIMEOUT_S):
            for db in dbs.all():
                await db.read(ping)
    except Exception as exc:  # any failure means "not persisting"; the reason goes to the log, not the body
        log.warning("health_database_check_failed", extra={"fields": {"error": f"{type(exc).__name__}"}})
        return False
    return True


def paused(ctx: Any) -> bool:
    """The pause switch as the abuse pipeline holds it (False before the pipeline exists)."""
    switches = getattr(getattr(ctx, "abuse", None), "switches", None)
    state = getattr(switches, "pause", None)
    clock = getattr(ctx, "clock", None)
    if state is None or clock is None:
        return False
    try:
        return bool(state.active(clock.now()))
    except Exception:
        return False


def _egress_tripped(ctx: Any, egress: Egress) -> bool:
    tripped = getattr(getattr(ctx, "egress", None), "tripped", None)
    if not callable(tripped):
        return False
    try:
        return bool(tripped(egress))
    except Exception:
        return False


async def health_body(ctx: Any) -> dict[str, Any]:
    """The `/health` document for this worker (see the module docstring for every key)."""
    started = ctx is not None and bool(getattr(ctx, "ready", False))
    answers = await databases_answer(ctx) if started else False
    used = await cached_data_bytes(ctx) if started else 0
    try:
        limit = int(float(_setting(ctx, "storage_total_budget_gb") or 0) * GIB)
    except (TypeError, ValueError):
        limit = 0
    within_budget = limit <= 0 or used <= limit
    degraded: list[str] = []
    if not started:
        degraded.append("starting")
    elif not answers:
        degraded.append("shared_state")
    if not within_budget:
        degraded.append("storage_budget")
    if bool(getattr(getattr(ctx, "abuse", None), "degraded", False)):
        degraded.append("memory_rate_limits")
    if _egress_tripped(ctx, Egress.DIRECT):
        degraded.append("egress_direct_disabled")
    if _egress_tripped(ctx, Egress.ROTATOR):
        degraded.append("egress_rotator_disabled")
    return {
        "Status": "ok",
        "Paused": paused(ctx),
        "DataBytes": used,
        "DataLimitBytes": limit,
        "PersistenceOK": answers and within_budget,
        "Degraded": degraded,
    }


def jsonify_bytes(value: Any) -> bytes:
    """Flask `jsonify` wire form: sorted keys, compact separators, ASCII escapes, one trailing newline."""
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


@router.api_route("/health", methods=["GET", "HEAD"], include_in_schema=False)
async def health(request: Request) -> Response:
    """The monitor JSON (always 200; the server drops the body of a HEAD answer)."""
    ctx = getattr(request.app.state, "ctx", None)
    return Response(content=jsonify_bytes(await health_body(ctx)), media_type=JSON_TYPE)


@router.api_route("/health", methods=["POST", "PUT", "PATCH", "DELETE"], include_in_schema=False)
async def health_other_methods() -> Response:
    """v1's 404 for anything but GET and HEAD (row 129), without v1's proxy pipeline and tarpit hold (B18)."""
    return Response(
        content=NOT_ROBLOX_BODY,
        status_code=404,
        media_type=JSON_TYPE,
        headers={REFUSAL_HEADER: ReasonCode.NOT_ROBLOX.value},
    )


__all__ = [
    "cached_data_bytes",
    "data_bytes",
    "databases_answer",
    "health_body",
    "jsonify_bytes",
    "measure_bytes",
    "paused",
    "router",
]
