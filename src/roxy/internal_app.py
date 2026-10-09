"""The internal app: version, readiness, flush and the operator CLI routes, reachable ONLY on the color's Unix socket.

What this is
    `create_internal_app(public_app)` builds a small Starlette app with these routes:
        GET  /internal/version   -> {"Version", "PackageVersion", "Color", "WorkerId", "Env", "ConfigVersion"}
        GET  /internal/ready     -> 200 when this worker is ready and its databases answer, else 503
        POST /internal/flush     -> flush this worker's buffered metrics now
      and four routes for `scripts/ctl.py`, the operator CLI (plan 9.14 list, 12.2, 17.8), each audited with an
      actor of kind `cli`:
        GET  /internal/export/llm           -> the plan 12 LLM export (`window`, `detail`, `format`)
        POST /internal/health/run           -> run Check Proxy Health and wait for the result (trigger `cli`)
        POST /internal/data/resets/preview  -> what a reset scope would delete (plan 6.8; nothing is deleted)
        POST /internal/data/resets          -> run a previewed reset (its digest, a reason, the typed phrase)
    `ListenerDispatcher` is the top-level ASGI app gunicorn serves (`roxy.asgi:app`): it sends each connection
    to the public app or to the internal app depending on WHICH SOCKET it arrived on.
    `PublicInternalNotFound` is the one `/internal` route of the PUBLIC app: a fixed 404 for `/internal` and
    everything under it, whatever the method.

Why it exists
    Plan 5.8: nginx connects from 127.0.0.1, so "the peer is loopback" is true for every internet request nginx
    forwards, and must never authorize anything. The deploy still needs to ask a color "are you ready, which
    version are you?" before switching traffic to it (plan 17.4 step 5). The answer is a second listener that
    nginx never proxies: a Unix socket in `/run/roxy-<color>/` (mode 0660, group roxy). The public app serves no
    internal endpoint, so there is nothing to reach on the TCP port even by mistake.
    The operator CLI needs the same door for the actions that only a running worker can do, because they use the
    worker's live context (the LLM export reads its settings and rule snapshots, a health run uses its upstream
    clients and leases, a reset purges its cache tiers and resets its upstream state). Everything else the CLI does
    straight on the databases, so it also works while every color is stopped.
    Without its own `/internal` route the public app would hand `/internal/version` to the proxy catch-all,
    which refuses it as "Not a Roblox URL" only after the abuse pipeline and the probe tarpit (8 to 20 s), and
    the deploy's own check that the endpoint is hidden (`scripts/smoke_remote.py internal_hidden`) would wait
    that long on every deploy. So the public app answers at once, as nginx does for `location /internal/` in
    production: 404 with v1's JSON body `"Not Found"` and a newline, no proxy pipeline, no tarpit, and no probe
    record (only the deploy tools on the server itself can reach a color's TCP port directly).

How it works
    Every worker serves both listeners (`deploy/gunicorn.conf.py`): each opens its own TCP listener on
    `ROXY_BIND` (`reuse_port`), and the master creates the internal Unix socket `ROXY_INTERNAL_SOCKET` once and
    hands it to every worker. The ASGI scope says which listener a request came in on. Verified by experiment
    with gunicorn 26.2, uvicorn-worker 0.4 and uvicorn 0.54 (P0 report):
        TCP listener:   scope["server"] == ("127.0.0.1", 18931),            scope["client"] == ("127.0.0.1", 57846)
        Unix listener:  scope["server"] == ("/tmp/.../internal.sock", None), scope["client"] is None
    (uvicorn's `get_local_addr` returns `(path, None)` for a Unix socket; plain `uvicorn --uds` behaves the same.)
    The dispatcher routes to the internal app only when the server address has no port AND its path is the
    configured `ROXY_INTERNAL_SOCKET`. Anything else, including a future public Unix socket, goes to the public
    app, so the default is the safe side. Lifespan events go to the public app, which owns the `AppContext`;
    the internal app reads that context through the public app's state.
    Who may do what (no CSRF, no session: there are no browsers or cookies on this socket):
      * Opening the socket at all needs the `roxy` group (mode 0660): the service account and the deploy user.
        That is enough for version, readiness, flush, a summary LLM export, a health run without the credential
        check and a reset preview: none of them changes data or reveals a raw address.
      * A reset, a full-detail export (every rule row, raw addresses when `export_include_ips` is 1) and a health
        run that spends a credential call (13.3) also need a proof that the caller can write the state directory,
        the same right as writing the databases directly. The CLI writes a random secret to a new 0600 file in
        `<state dir>/ctl-proofs/` and sends `Roxy-Ctl-Proof: <file name>:<secret>`; this app reads the file
        without following links, checks that this service's user owns it and its directory, that it is younger
        than `PROOF_MAX_AGE_S` and that the secret matches (constant time), then deletes it (one use). The deploy
        user is in the `roxy` group but cannot write the 0750 state directory, so it can never destroy data or
        export raw addresses through the socket. The dashboard asks a fresh second factor for the same actions.
      * `Roxy-Actor: <name>` names the operator (`scripts/ctl.py` sends the login name behind sudo); the audit
        rows say `cli:<name>`. It is a label, never an authorization.
    Errors use the admin API's section 13 shape (`{"error": {"code", "message", "fields"}}`) with the same codes,
    so the CLI prints what the dashboard would say. `/internal/flush` and the others are POSTs without CSRF on
    purpose (see above). Each request reaches ONE worker; `scripts/ctl.py flush-metrics` uses the fleet-wide
    `service_state` request instead.
    `PublicInternalNotFound` is a plain Starlette route that `roxy/main.py` puts FIRST in the public app, so no
    other route (the proxy catch-all above all) ever sees an `/internal` path there. It matches every method and
    answers with `core/errors.py: not_found_response`; the middleware stack still adds the request id and the
    security headers.

What to read next
    `roxy/asgi.py` (the object gunicorn imports), `deploy/gunicorn.conf.py`, `scripts/ctl.py` (the caller of the
    operator routes), then `scripts/smoke_remote.py`.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import stat
import time
from collections.abc import Awaitable, Callable, Mapping
from pathlib import Path
from typing import Any, Final

from starlette.applications import Starlette
from starlette.datastructures import URLPath
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import BaseRoute, Match, NoMatchFound, Route
from starlette.types import ASGIApp, Receive, Scope, Send

from roxy import __version__
from roxy.core.errors import not_found_response

READY_CHECK_TIMEOUT_S = 2.0
FLUSH_TIMEOUT_S = 10.0

INTERNAL_PREFIX = "/internal"

ACTOR_HEADER: Final = "Roxy-Actor"
"""The operator's name for the audit rows (a label, never an authorization)."""

PROOF_HEADER: Final = "Roxy-Ctl-Proof"
"""`<16 hex file name>:<64 hex secret>`: proof that the caller can write the state directory (module docstring)."""

PROOF_DIR_NAME: Final = "ctl-proofs"
"""The directory under the state directory where `scripts/ctl.py` writes its one-use proofs."""

PROOF_MAX_AGE_S: Final = 120.0
"""A proof older than this is refused (the CLI writes it right before the request)."""

PROOF_FUTURE_SKEW_S: Final = 5.0
"""A proof may carry an mtime this far in the future (the wall clock can step back a little, WSL and NTP)."""

MAX_BODY_BYTES: Final = 64 * 1024
"""The largest JSON body an operator route reads (plan P9); a bigger one is a 413."""

HEALTH_WAIT_MARGIN_S: Final = 30.0
"""Waited past the health run timeout before answering with the run still marked running."""

EXPORT_WINDOWS: Final = ("24h", "7d", "30d")
EXPORT_DETAILS: Final = ("summary", "full")
EXPORT_FORMATS: Final = ("json", "text")
MAX_HEALTH_CHECKS: Final = 200
"""Check ids one CLI health run may name (the admin API has the same bound)."""

_ACTOR_RE: Final = re.compile(r"[A-Za-z0-9_.@-]{1,64}")
_PROOF_RE: Final = re.compile(r"([0-9a-f]{16}):([0-9a-f]{64})")
_JSON_TYPE: Final = "application/json"


def is_internal_path(path: str) -> bool:
    """True for `/internal` and everything under `/internal/` (but not `/internals`)."""
    return path == INTERNAL_PREFIX or path.startswith(INTERNAL_PREFIX + "/")


class PublicInternalNotFound(BaseRoute):
    """The public app's only `/internal` route: an immediate 404 for every method (see the module docstring)."""

    path = INTERNAL_PREFIX  # for route listings; matching uses `is_internal_path`, not a path pattern

    def matches(self, scope: Scope) -> tuple[Match, Scope]:
        if scope.get("type") == "http" and is_internal_path(str(scope.get("path", ""))):
            return Match.FULL, {}
        return Match.NONE, {}

    def url_path_for(self, name: str, /, **path_params: Any) -> URLPath:
        raise NoMatchFound(name, path_params)  # nothing links to it

    async def handle(self, scope: Scope, receive: Receive, send: Send) -> None:
        await not_found_response(str(scope.get("path", "")))(scope, receive, send)


def listener_kind(scope: Scope, internal_socket: str | os.PathLike[str] | None) -> str:
    """Return "internal" when the request arrived on the configured Unix socket, else "public" (the safe default)."""
    server = scope.get("server")
    if internal_socket is None or not isinstance(server, tuple | list) or len(server) != 2:
        return "public"
    host, port = server
    if port is not None or not isinstance(host, str):
        return "public"  # a TCP listener always has a port
    try:
        same = os.path.abspath(host) == os.path.abspath(os.fspath(internal_socket))
    except (TypeError, ValueError):
        return "public"
    return "internal" if same else "public"


class ListenerDispatcher:
    """Top-level ASGI app: one public app for TCP, one internal app for the internal Unix socket."""

    def __init__(self, *, public: ASGIApp, internal: ASGIApp, internal_socket: str | os.PathLike[str] | None) -> None:
        self.public = public
        self.internal = internal
        self.internal_socket = internal_socket
        # gunicorn's worker and some tools look for the app's state; expose the public app's.
        self.state = getattr(public, "state", None)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self.public(scope, receive, send)  # the public app owns startup and shutdown
            return
        if listener_kind(scope, self.internal_socket) == "internal":
            await self.internal(scope, receive, send)
        else:
            await self.public(scope, receive, send)


def _ctx(request: Request) -> Any:
    public = request.app.state.public_app
    return getattr(public.state, "ctx", None)


async def _databases_answer(ctx: Any) -> bool:
    """True when every database answers a trivial read within the timeout (PersistenceOK)."""
    dbs = getattr(ctx, "dbs", None)
    if dbs is None:
        return False

    def ping(conn: sqlite3.Connection) -> int:
        return int(conn.execute("SELECT 1").fetchone()[0])

    try:
        async with asyncio.timeout(READY_CHECK_TIMEOUT_S):
            for db in dbs.all():
                await db.read(ping)
    except Exception:
        return False
    return True


async def version(request: Request) -> JSONResponse:
    ctx = _ctx(request)
    env = getattr(request.app.state, "env", None)
    return JSONResponse(
        {
            "Version": getattr(ctx, "release", None) or __version__,
            "PackageVersion": __version__,
            "Color": getattr(ctx, "color", None) or getattr(env, "color", None),
            "WorkerId": getattr(ctx, "worker_id", None),
            "Env": getattr(env, "env", None),
            # The `config_version` this worker's settings and rules snapshots were built from: lets the deploy
            # tools and the multi-process tests see that a change reached every worker (plan 5.7, within 2 s).
            "ConfigVersion": getattr(getattr(ctx, "settings", None), "version", None),
        }
    )


async def ready(request: Request) -> JSONResponse:
    ctx = _ctx(request)
    started = bool(getattr(ctx, "ready", False))
    persistence_ok = await _databases_answer(ctx) if started else False
    leader = getattr(ctx, "leader", None)
    body = {
        "Ready": started and persistence_ok,
        "Started": started,
        "PersistenceOK": persistence_ok,
        "Version": getattr(ctx, "release", None) or __version__,
        "WorkerId": getattr(ctx, "worker_id", None),
        "IsLeader": bool(getattr(leader, "is_leader", False)),
    }
    return JSONResponse(body, status_code=200 if body["Ready"] else 503)


async def flush(request: Request) -> JSONResponse:
    ctx = _ctx(request)
    recorder = getattr(ctx, "recorder", None)
    flush_now = getattr(recorder, "flush", None) or getattr(recorder, "flush_now", None)
    if flush_now is None:
        return JSONResponse({"Flushed": False, "Reason": "no metrics recorder in this build"}, status_code=200)
    async with asyncio.timeout(FLUSH_TIMEOUT_S):
        result = flush_now()
        if asyncio.iscoroutine(result):
            result = await result
    return JSONResponse({"Flushed": True, "WorkerId": getattr(ctx, "worker_id", None)})


# ================================================================================ operator routes (scripts/ctl.py)


class OperatorError(Exception):
    """A refusal of an operator route, answered in the section 13 shape."""

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        *,
        fields: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.fields = dict(fields or {})
        self.headers = dict(headers or {})


def _error_response(
    status: int, code: str, message: str, fields: Mapping[str, str], headers: Mapping[str, str]
) -> Response:
    from roxy.admin.api import common  # the admin API's error shape and message cleaning (lazy: no import cycle)

    return common.error_response(status, code, message, fields, headers)


def operator_actor(request: Request) -> Any:
    """`Actor("cli", <name>)` from `Roxy-Actor` (letters, digits, `_ . @ -`; anything else is `ctl`)."""
    from roxy.config.audit import Actor

    raw = request.headers.get(ACTOR_HEADER, "").strip()
    return Actor("cli", raw if _ACTOR_RE.fullmatch(raw) else "ctl")


def check_proof(state_dir: Path | str | None, header: str | None, *, now: float | None = None) -> bool:
    """True when `header` names a fresh proof file this service's user wrote in `<state_dir>/ctl-proofs/`.

    Blocking file work: call it on a thread. The file is deleted once it has been opened, whatever the answer, so
    a proof is good for one request only. Nothing here follows a symbolic link.
    """
    if state_dir is None or not header:
        return False
    found = _PROOF_RE.fullmatch(header.strip())
    if found is None:
        return False
    name, secret = found.groups()
    moment = time.time() if now is None else now
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        dir_fd = os.open(Path(state_dir) / PROOF_DIR_NAME, flags | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return False
    try:
        info = os.fstat(dir_fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o022:
            return False  # a directory someone else controls proves nothing
        try:
            fd = os.open(name, flags, dir_fd=dir_fd)
        except OSError:
            return False
        try:
            file_info = os.fstat(fd)
            data = os.read(fd, 130)
        finally:
            os.close(fd)
        with contextlib.suppress(OSError):
            os.unlink(name, dir_fd=dir_fd)  # one use
        if not stat.S_ISREG(file_info.st_mode) or file_info.st_uid != os.geteuid() or file_info.st_mode & 0o077:
            return False
        age = moment - file_info.st_mtime
        if age > PROOF_MAX_AGE_S or age < -PROOF_FUTURE_SKEW_S:
            return False
        return hmac.compare_digest(data.strip(), secret.encode("ascii"))
    finally:
        os.close(dir_fd)


async def _require_proof(request: Request, ctx: Any, what: str) -> None:
    state_dir = getattr(getattr(ctx, "env", None), "state_dir", None)
    if not await asyncio.to_thread(check_proof, state_dir, request.headers.get(PROOF_HEADER)):
        raise OperatorError(
            403,
            "forbidden",
            f"{what} needs the roxy user: run scripts/ctl.py as roxy (sudo -u roxy ...), so it can prove it may "
            "write the state directory.",
        )


async def _json_body(request: Request) -> dict[str, Any]:
    raw = bytearray()
    async for chunk in request.stream():
        raw += chunk
        if len(raw) > MAX_BODY_BYTES:
            raise OperatorError(413, "bad_request", f"The request body is larger than {MAX_BODY_BYTES} bytes.")
    if not raw:
        raise OperatorError(400, "missing_body", "This request needs a JSON object as its body.")
    try:
        value = json.loads(bytes(raw))
    except ValueError:
        raise OperatorError(400, "invalid_json", "The request body is not valid JSON.") from None
    if not isinstance(value, dict):
        raise OperatorError(400, "invalid_body", "The request body must be a JSON object.")
    return value


def _live_ctx(request: Request) -> Any:
    ctx = _ctx(request)
    if ctx is None or not getattr(ctx, "ready", False):
        raise OperatorError(503, "unavailable", "This worker has not finished starting; try again shortly.")
    return ctx


def _request_id(ctx: Any) -> str:
    from roxy.core.ids import new_request_id

    return new_request_id(getattr(ctx, "clock", None))


async def _operator(request: Request, work: Callable[[Request], Awaitable[Response]]) -> Response:
    """Run an operator route: its own refusals, the admin API's errors and service refusals become section 13
    answers with `Cache-Control: no-store`; anything else is a real bug and propagates (a 500 from the server)."""
    from pydantic import ValidationError

    from roxy.admin.api import common

    try:
        response = await work(request)
    except OperatorError as exc:
        return _error_response(exc.status, exc.code, exc.message, exc.fields, exc.headers)
    except ValidationError as exc:
        fields = {
            ".".join(str(part) for part in err.get("loc") or ()) or "body": str(err.get("msg")) for err in exc.errors()
        }
        return _error_response(422, "validation_failed", "Some fields are not valid.", fields, {})
    except Exception as exc:
        mapped = common.service_error(exc)
        if mapped is None:
            raise
        return _error_response(
            mapped.status_code, mapped.error_code, mapped.error_message, mapped.error_fields, mapped.headers or {}
        )
    response.headers["Cache-Control"] = common.NO_STORE
    return response


# --- the LLM export (plan 12.2: "scripts/ctl.py export-llm ... talks to the internal socket, audited as cli") ---


class _NoRawAddresses:
    """`ctx` as `export_ip_policy` sees it, with `export_include_ips` read as 0 (a summary never shows them)."""

    def __init__(self, ctx: Any) -> None:
        self.ip_hash_key = getattr(ctx, "ip_hash_key", None)
        self._settings = ctx.settings
        self.settings = self

    def bool(self, key: str) -> bool:
        return False if key == "export_include_ips" else bool(self._settings.bool(key))


def _choice(request: Request, name: str, allowed: tuple[str, ...], default: str) -> str:
    value = request.query_params.get(name, default)
    if value not in allowed:
        raise OperatorError(
            422, "validation_failed", f"{name} must be one of {', '.join(allowed)}.", fields={name: value[:40]}
        )
    return value


async def _export_llm(request: Request) -> Response:
    from roxy.admin.api import common
    from roxy.config import audit
    from roxy.insights import llm_export

    window = _choice(request, "window", EXPORT_WINDOWS, "24h")
    detail = _choice(request, "detail", EXPORT_DETAILS, "summary")
    fmt = _choice(request, "format", EXPORT_FORMATS, "json")
    ctx = _live_ctx(request)
    if detail == "full":
        await _require_proof(request, ctx, "The full-detail export")
    actor = operator_actor(request)
    request_id = _request_id(ctx)
    policy_ctx: Any = ctx if detail == "full" else _NoRawAddresses(ctx)
    hasher, ip_mode = common.export_ip_policy(policy_ctx, request_id)
    try:
        result = await llm_export.build_export(
            llm_export.ExportSources.from_context(ctx),
            window=window,
            detail=detail,
            ip_hasher=hasher,
            ip_mode=ip_mode,
            generated_by="cli",
        )
    except llm_export.ExportBusy:
        raise OperatorError(
            429,
            "rate_limited",
            "Another LLM export is being built in this worker; try again shortly.",
            headers={"Retry-After": "5"},
        ) from None
    if fmt == "text":
        content = llm_export.copy_text(result.content).encode("utf-8")
        media_type = "text/plain; charset=utf-8"
    else:
        content = result.content
        media_type = _JSON_TYPE
    at = int(ctx.clock.now())
    details = {
        "window": window,
        "detail": detail,
        "format": fmt,
        "bytes": len(content),
        "ip_addresses": ip_mode,
        "untrusted": result.untrusted,
        "via": "internal_socket",
    }

    def write(conn: sqlite3.Connection) -> int:
        target = f"llm_export:{detail}"
        return audit.record(conn, actor, common.EXPORT_AUDIT_ACTION, target, None, details, None, request_id, at=at)

    audit_id = await ctx.dbs.control.write(write)  # the audit row is written before the bytes leave (plan 9.7)
    return Response(
        content=content,
        media_type=media_type,
        headers={"Roxy-Export-Untrusted": str(result.untrusted), "Roxy-Audit-Id": str(audit_id)},
    )


async def export_llm(request: Request) -> Response:
    return await _operator(request, _export_llm)


# --- Check Proxy Health (plan 13; trigger "cli") ------------------------------------------------------------------


async def _health_run(request: Request) -> Response:
    from roxy.health import checks, store
    from roxy.health.model import RunOptions, Trigger
    from roxy.health.runner import RUN_TIMEOUT_S, NoChecks, RunBusy, audit_run, runner_for

    body = await _json_body(request)
    unknown_keys = sorted(set(body) - {"checks", "include_credential", "wait"})
    if unknown_keys:
        raise OperatorError(422, "validation_failed", "Unknown field.", fields={unknown_keys[0][:40]: "Not allowed."})
    wanted = body.get("checks", [])
    if not isinstance(wanted, list) or len(wanted) > MAX_HEALTH_CHECKS or not all(isinstance(c, str) for c in wanted):
        raise OperatorError(
            422, "validation_failed", "checks must be a list of check ids.", fields={"checks": "Not valid."}
        )
    ids = tuple(c.strip()[:120] for c in wanted if c.strip())
    unknown = [c for c in ids if not checks.known_check_id(c)]
    if unknown:
        raise OperatorError(422, "unknown_check", f"Unknown check id: {unknown[0]}.", fields={"checks": unknown[0]})
    include_credential = bool(body.get("include_credential", False))
    wait = bool(body.get("wait", True))
    ctx = _live_ctx(request)
    options = RunOptions(checks=ids, include_credential=include_credential, admin_ip=None)
    runner = runner_for(ctx)
    try:
        planned = runner.plan(options)
    except NoChecks:
        raise OperatorError(
            422, "unknown_check", "No check matches these ids.", fields={"checks": "No match."}
        ) from None
    uses_credential = include_credential and any(spec.uses_credential for spec, _ in planned)
    if uses_credential:
        await _require_proof(request, ctx, "A health run with the credential check (one Roblox call, plan 13.3)")
    actor = operator_actor(request)
    try:
        run_id = await runner.start_run(trigger=Trigger.CLI.value, actor=actor.label, options=options)
    except RunBusy as busy:
        headers = {"Roxy-Health-Run": str(busy.running_run_id)} if busy.running_run_id else {}
        raise OperatorError(
            409, "run_in_progress", "A health run is already running; wait for it.", headers=headers
        ) from None
    with contextlib.suppress(Exception):  # the run is recorded in health_runs with its actor either way
        await audit_run(ctx, actor, run_id, options, _request_id(ctx))
    if wait:
        await runner.wait(run_id, timeout_s=RUN_TIMEOUT_S + HEALTH_WAIT_MARGIN_S)
    now = float(ctx.clock.now())
    run = await ctx.dbs.metrics.read(lambda conn: store.get_run(conn, run_id, now=now))
    return JSONResponse(
        {"run_id": run_id, "checks": len(planned), "include_credential": uses_credential, "run": run},
        status_code=200 if run is not None and run.get("finished_at") is not None else 202,
    )


async def health_run(request: Request) -> Response:
    return await _operator(request, _health_run)


# --- resets (plan 6.8, the Data page's flow: preview, then run exactly what was previewed) -----------------------


async def _reset_plan(request: Request, *, running: bool) -> tuple[Any, Any, Any, float]:
    from roxy.admin.api import data

    body_model = data.RunResetBody if running else data.ResetBody
    body = body_model.model_validate(await _json_body(request))
    if body.scope == "factory":
        raise OperatorError(
            403, "forbidden", "A factory reset is only possible from the dashboard, with a fresh second factor (9.6)."
        )
    ctx = _live_ctx(request)
    now = ctx.clock.now()
    return body, ctx, data.build_plan(body, ctx, now), now


async def _reset_preview(request: Request) -> Response:
    from roxy.admin.api import common, data

    _body, ctx, plan, now = await _reset_plan(request, running=False)
    return JSONResponse(await common.run_mutation(data.preview_plan(ctx, plan, now)))


async def reset_preview(request: Request) -> Response:
    return await _operator(request, _reset_preview)


async def _reset_run(request: Request) -> Response:
    from roxy.admin.api import common, data
    from roxy.config import audit

    body, ctx, plan, now = await _reset_plan(request, running=True)
    if body.preview != plan.digest:
        raise OperatorError(
            409, "preview_required", "This scope was not previewed (or changed since); preview it first."
        )
    if plan.confirm_phrase is not None and (body.confirm or "").strip().lower() != plan.confirm_phrase:
        message = f'Type "{plan.confirm_phrase}" to confirm this reset.'
        raise OperatorError(422, "confirmation_required", message, fields={"confirm": message})
    await _require_proof(request, ctx, "A data reset")
    reason = common.require_reason(body.reason, required=plan.confirm_phrase is not None)
    preview = await common.run_mutation(data.preview_plan(ctx, plan, now))
    plan.snapshot_dbs = [item["db"] for item in preview["snapshots"]]  # run exactly the snapshot plan previewed
    actor = operator_actor(request)
    request_id = _request_id(ctx)
    op = data.Operation(f"reset_{secrets.token_hex(8)}", "reset", plan.label, now)
    # The data API's fleet-wide reset lease: one reset at a time, from the dashboard or from here. (`_Lease` is
    # private to data.py today; the integrator is asked to give it a public name.)
    lease = data._Lease(ctx, f"{ctx.worker_id}:{op.id}")
    if not await common.run_mutation(lease.acquire()):
        raise OperatorError(409, "reset_in_progress", "Another data reset is running; wait for it to finish.")
    intent = {
        "scope": plan.descriptor,
        "label": plan.label,
        "planned_rows": {f"{t['db']}.{t['table']}": t["rows"] for t in preview["tables"]},
        "total_rows": preview["total_rows"],
        "snapshots": preview["snapshots"],
        "operation": op.id,
        "via": "internal_socket",
    }
    at = int(ctx.clock.now())

    def write_intent(conn: sqlite3.Connection) -> int:
        return audit.record(
            conn, actor, data.AUDIT_RESET, f"operation:{op.id}", None, intent, reason or None, request_id, at=at
        )

    try:
        # The intent row first (plan 9.7, C7): if control.db cannot take it, nothing is deleted.
        op.audit_id = await common.run_mutation(ctx.dbs.control.write(write_intent))
    except BaseException:
        await lease.release()
        raise
    outcome = await data.execute_reset(ctx, op, plan, actor, reason, request_id, lease)
    return JSONResponse({"operation": op.id, "label": plan.label, "status": "done", **outcome})


async def reset_run(request: Request) -> Response:
    return await _operator(request, _reset_run)


def create_internal_app(public_app: Any) -> Starlette:
    """The internal app for the Unix socket. It shares the public app's `AppContext` (and has no lifespan)."""
    app = Starlette(
        routes=[
            Route("/internal/version", version, methods=["GET"]),
            Route("/internal/ready", ready, methods=["GET"]),
            Route("/internal/flush", flush, methods=["POST"]),
            Route("/internal/export/llm", export_llm, methods=["GET"]),
            Route("/internal/health/run", health_run, methods=["POST"]),
            Route("/internal/data/resets/preview", reset_preview, methods=["POST"]),
            Route("/internal/data/resets", reset_run, methods=["POST"]),
        ]
    )
    app.state.public_app = public_app
    app.state.env = getattr(public_app.state, "env", None)
    return app


OPERATOR_ROUTES: Final = (
    ("GET", "/internal/export/llm"),
    ("POST", "/internal/health/run"),
    ("POST", "/internal/data/resets/preview"),
    ("POST", "/internal/data/resets"),
)
"""The routes `scripts/ctl.py` calls (tests check each is audited as `cli` and none is reachable on TCP)."""


__all__ = [
    "ACTOR_HEADER",
    "INTERNAL_PREFIX",
    "OPERATOR_ROUTES",
    "PROOF_DIR_NAME",
    "PROOF_HEADER",
    "PROOF_MAX_AGE_S",
    "ListenerDispatcher",
    "OperatorError",
    "PublicInternalNotFound",
    "check_proof",
    "create_internal_app",
    "is_internal_path",
    "listener_kind",
    "operator_actor",
]
