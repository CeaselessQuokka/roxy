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
      meaning ("how full is the store that predicts trouble") is the same.
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
import contextlib
import json
import logging
import sqlite3
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


def data_bytes(ctx: Any) -> int:
    """Bytes the databases use on disk (main files and write-ahead logs); 0 for files that do not exist."""
    dbs = getattr(ctx, "dbs", None)
    total = 0
    if dbs is None:
        return 0
    for db in dbs.all():
        path = Path(db.path)
        for suffix in DB_SUFFIXES:
            with contextlib.suppress(OSError):
                total += (path.with_name(path.name + suffix)).stat().st_size
    return total


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
    used = data_bytes(ctx) if started else 0
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


__all__ = ["data_bytes", "databases_answer", "health_body", "jsonify_bytes", "paused", "router"]
