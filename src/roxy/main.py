"""The app factory: `create_app(env)` assembles the public FastAPI application.

What this is
    `create_app(env)` returns the FastAPI app that serves the public port: middleware in the plan 5.3 order,
    exception handlers, the templates, the static files, and the routers. `create_asgi_app(env)` wraps it with the
    internal app for the Unix socket; that is what gunicorn loads (`roxy.asgi:app`).

Why it exists
    A factory instead of a module-level app means every test gets a fresh app with its own temp databases and
    settings, and nothing happens at import time (v1 opened files and read secrets on import). It is also the one
    place that shows, top to bottom, everything a request passes through.

How it works
    1. Settings from the environment (`EnvSettings`), unless a test passes its own.
    2. Middleware, outermost first: request id, unhandled errors, real client IP, deadline, security headers,
       size limits, timing (`core/middleware.py` explains each).
    3. FastAPI's built-in docs are OFF: `/docs` is the public user guide (plan 16.1), and the admin API schema
       must not be public.
    4. The first route is `internal_app.PublicInternalNotFound`: `/internal` and everything under it answer an
       immediate 404 (v1's `"Not Found"` body) on the public port, as nginx does in production, so the proxy
       catch-all never treats an internal path as a target to refuse and tarpit (plan 5.8).
    5. Routers are included in a fixed order, the proxy catch-all last so it never shadows a real page. A
       router module exposes `router` (an `APIRouter`, or a Starlette `Router` for the plain proxy endpoint).
       Modules not written yet are skipped; until the public pages exist a placeholder answers `/`.
    6. `create_asgi_app` (the server's app) prepares every route before the worker serves (`warm_routes`), so the
       first proxy request of a new worker does not stop the event loop while FastAPI builds the routes in front
       of the catch-all. This is the one startup warm-up: gunicorn's worker (`roxy/worker.py`), plain uvicorn and
       the tests all get it from here, and the worker then freezes the app as built, route tables included.

What to read next
    `roxy/core/middleware.py` (the stack), `roxy/lifespan.py` (startup), `roxy/internal_app.py` (the socket app).
"""

from __future__ import annotations

import html
import logging
import time
from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.routing import iter_route_contexts
from starlette.routing import Router
from starlette.types import ASGIApp

from roxy import __version__
from roxy.config.env import EnvSettings
from roxy.core.clock import Clock
from roxy.core.errors import install_exception_handlers
from roxy.core.middleware import build_middleware
from roxy.core.security_headers import get_nonce
from roxy.core.templating import STATIC_DIR, STATIC_URL_PREFIX, AssetHasher, HashedStaticFiles, Templates
from roxy.internal_app import ListenerDispatcher, PublicInternalNotFound, create_internal_app
from roxy.lifespan import build_lifespan, optional_import

log = logging.getLogger("roxy.main")

ROUTER_MODULES: tuple[str, ...] = (
    "roxy.public.health",  # /health (P12)
    "roxy.public.csp_report",  # POST /csp-report (P12, plan 9.2)
    "roxy.public.pages",  # /, /docs, /status, robots, sitemap, favicon (P12)
    "roxy.admin.router",  # /admin and /admin/api/v1 (P8, P9, P11)
    "roxy.proxy.router",  # /{host}.roblox.com/{path:path}: the catch-all, always LAST (P6)
)
"""Router modules in inclusion order. Each exposes `router`."""

placeholder_router = APIRouter()


@placeholder_router.get("/", response_class=HTMLResponse, include_in_schema=False)
async def placeholder_home(request: Request) -> HTMLResponse:
    """Stands in for the public home page until `roxy/public/pages.py` exists (P12)."""
    nonce = html.escape(get_nonce(request.scope), quote=True)
    body = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Roxy</title>'
        f'<style nonce="{nonce}">body{{font-family:system-ui,sans-serif;margin:3rem}}</style></head>'
        f"<body><h1>Roxy</h1><p>Roxy v{html.escape(__version__)} is starting up. The public pages arrive in a "
        "later build.</p></body></html>"
    )
    return HTMLResponse(body)


def include_routers(app: FastAPI, modules: tuple[str, ...] = ROUTER_MODULES) -> list[str]:
    """Include every router module that exists, in order. Returns the names that were included."""
    included: list[str] = []
    for name in modules:
        module = optional_import(name)
        if module is None:
            if name == "roxy.public.pages":
                app.include_router(placeholder_router)
            continue
        router: Any = getattr(module, "router", None)
        if isinstance(router, APIRouter):
            app.include_router(router)
        elif isinstance(router, Router):
            app.router.routes.extend(router.routes)  # a plain Starlette router (the proxy hot path)
        else:
            raise TypeError(f"{name} must expose `router` (an APIRouter or a Starlette Router)")
        included.append(name)
    return included


@dataclass(frozen=True, slots=True)
class RouteWarmup:
    """What `warm_routes` did, kept on `app.state.route_warmup` and logged by the worker once it started."""

    routes: int | None
    """Route contexts walked (about 390); None when the walk failed and the routes are built on first use."""
    ms: float
    """How long the walk took, in milliseconds (about 250 to 350 on the development machine)."""


def warm_routes(app: FastAPI) -> RouteWarmup:
    """Prepare every route's request handling state now, before the worker serves (docs/PERFORMANCE.md, "Startup
    warm-up (2026-10-14)").

    FastAPI (0.142 here) prepares the routes of an included router lazily: the first request matched through the
    router builds each route's dependency model (its signature, a pydantic adapter per parameter) and keeps it
    until the routes change. The admin router holds several hundred page and API routes, all in front of the proxy
    catch-all, so the first proxy request of every new worker built them on the event loop: about 390 routes,
    48,000 objects and 250 to 370 ms, during which every other request of that worker waited. They then left
    together: in the plan 19.4 cooldown scenario seven calls to the endpoint Roblox was refusing went out before
    its first 429 came back (all inside the endpoint's burst of 10), and in the replays it was the largest stall
    behind the worst heartbeat.
    FastAPI's public `iter_route_contexts` walks the same per-router lists that matching uses, built the same way
    and cached on the same router objects, so after it no request builds any. Nothing is served and no state
    changes beyond FastAPI's own cache. It is an optimization only: if a FastAPI version walks differently, the
    failure is logged and the routes are built on first use, as before.
    """
    started = time.perf_counter()
    routes: int | None
    try:
        routes = sum(1 for _ in iter_route_contexts(app.router.routes))
    except Exception:  # never stop a worker from booting over a cache warm-up
        log.warning("route_warmup_failed", exc_info=True)
        routes = None
    warmup = RouteWarmup(routes=routes, ms=round((time.perf_counter() - started) * 1000, 1))
    app.state.route_warmup = warmup
    return warmup


def create_app(env: EnvSettings | None = None, *, clock: Clock | None = None) -> FastAPI:
    """Build the public application. `env` defaults to the process environment; tests pass their own."""
    env = env or EnvSettings()
    app = FastAPI(
        title="Roxy",
        version=__version__,
        docs_url=None,  # /docs is the public user guide, not Swagger
        redoc_url=None,
        openapi_url=None,  # the admin API schema is not published
        lifespan=build_lifespan(env, clock),
        middleware=build_middleware(
            trusted_cidrs=env.trusted_proxy_cidrs,
            hops=env.trusted_proxy_hops,
            send_hsts=env.send_hsts,
            clock=clock,
        ),
    )
    app.state.env = env
    install_exception_handlers(app)
    # Before every other route: an internal path on the public port is a fixed 404, never a proxy target.
    app.router.routes.append(PublicInternalNotFound())
    hasher = AssetHasher(STATIC_DIR)
    app.state.templates = Templates(hasher=hasher)
    # nginx serves /static/ in production (plan 17.2); this mount gives development and tests the same URLs.
    # Only once the directory exists (P11 adds it): Starlette answers 500 for a mount whose directory is missing.
    if STATIC_DIR.is_dir():
        app.mount(STATIC_URL_PREFIX, HashedStaticFiles(directory=STATIC_DIR, hasher=hasher), name="static")
    app.state.routers = include_routers(app)
    return app


def create_asgi_app(env: EnvSettings | None = None, *, clock: Clock | None = None) -> ASGIApp:
    """The object gunicorn serves: the public app on TCP, the internal app on the Unix socket (plan 5.8).

    The public app's routes are prepared here (`warm_routes`): gunicorn's worker, plain uvicorn and an in-process
    client all build this before they serve, so a new worker's first request is as fast as the next one. The
    internal app's plain Starlette routes are compiled when they are made. Tests that build `create_app` directly
    keep FastAPI's lazy preparation (it would add about 0.3 s to every test app)."""
    env = env or EnvSettings()
    public = create_app(env, clock=clock)
    warm_routes(public)
    return ListenerDispatcher(public=public, internal=create_internal_app(public), internal_socket=env.internal_socket)
