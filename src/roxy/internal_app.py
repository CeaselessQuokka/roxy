"""The internal app: version, readiness and flush endpoints, reachable ONLY on the color's Unix socket.

What this is
    `create_internal_app(public_app)` builds a tiny Starlette app with three routes:
        GET  /internal/version  -> {"Version", "PackageVersion", "Color", "WorkerId", "Env", "ConfigVersion"}
        GET  /internal/ready    -> 200 when this worker is ready and its databases answer, else 503
        POST /internal/flush    -> flush this worker's buffered metrics now
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
    `/internal/flush` is a POST with no CSRF token on purpose: only processes in the `roxy` group can open the
    socket, and there are no browsers or cookies on it. Each request reaches ONE worker; `scripts/ctl.py`
    repeats the call to reach the others.
    `PublicInternalNotFound` is a plain Starlette route that `roxy/main.py` puts FIRST in the public app, so no
    other route (the proxy catch-all above all) ever sees an `/internal` path there. It matches every method and
    answers with `core/errors.py: not_found_response`; the middleware stack still adds the request id and the
    security headers.

What to read next
    `roxy/asgi.py` (the object gunicorn imports), `deploy/gunicorn.conf.py`, then `scripts/smoke_remote.py`.
"""

from __future__ import annotations

import asyncio
import os
import sqlite3
from typing import Any

from starlette.applications import Starlette
from starlette.datastructures import URLPath
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import BaseRoute, Match, NoMatchFound, Route
from starlette.types import ASGIApp, Receive, Scope, Send

from roxy import __version__
from roxy.core.errors import not_found_response

READY_CHECK_TIMEOUT_S = 2.0
FLUSH_TIMEOUT_S = 10.0

INTERNAL_PREFIX = "/internal"


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


def create_internal_app(public_app: Any) -> Starlette:
    """The internal app for the Unix socket. It shares the public app's `AppContext` (and has no lifespan)."""
    app = Starlette(
        routes=[
            Route("/internal/version", version, methods=["GET"]),
            Route("/internal/ready", ready, methods=["GET"]),
            Route("/internal/flush", flush, methods=["POST"]),
        ]
    )
    app.state.public_app = public_app
    app.state.env = getattr(public_app.state, "env", None)
    return app
