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
    4. Routers are included in a fixed order, the proxy catch-all last so it never shadows a real page. A
       router module exposes `router` (an `APIRouter`, or a Starlette `Router` for the plain proxy endpoint).
       Modules not written yet are skipped; until the public pages exist a placeholder answers `/`.

What to read next
    `roxy/core/middleware.py` (the stack), `roxy/lifespan.py` (startup), `roxy/internal_app.py` (the socket app).
"""

from __future__ import annotations

import html
import logging
from typing import Any

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import HTMLResponse
from starlette.routing import Router
from starlette.types import ASGIApp

from roxy import __version__
from roxy.config.env import EnvSettings
from roxy.core.clock import Clock
from roxy.core.errors import install_exception_handlers
from roxy.core.middleware import build_middleware
from roxy.core.security_headers import get_nonce
from roxy.core.templating import STATIC_DIR, STATIC_URL_PREFIX, AssetHasher, HashedStaticFiles, Templates
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
    hasher = AssetHasher(STATIC_DIR)
    app.state.templates = Templates(hasher=hasher)
    # nginx serves /static/ in production (plan 17.2); this mount gives development and tests the same URLs.
    # Only once the directory exists (P11 adds it): Starlette answers 500 for a mount whose directory is missing.
    if STATIC_DIR.is_dir():
        app.mount(STATIC_URL_PREFIX, HashedStaticFiles(directory=STATIC_DIR, hasher=hasher), name="static")
    app.state.routers = include_routers(app)
    return app


def create_asgi_app(env: EnvSettings | None = None, *, clock: Clock | None = None) -> ASGIApp:
    """The object gunicorn serves: the public app on TCP, the internal app on the Unix socket (plan 5.8)."""
    from roxy.internal_app import ListenerDispatcher, create_internal_app

    env = env or EnvSettings()
    public = create_app(env, clock=clock)
    return ListenerDispatcher(public=public, internal=create_internal_app(public), internal_socket=env.internal_socket)
