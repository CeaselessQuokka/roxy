"""FastAPI dependencies: how routes ask for the context, settings, a database, the client IP, or an admin.

What this is
    Small functions FastAPI calls before a route runs, declared in the route signature, for example
    `async def page(ctx: AppContext = Depends(get_ctx))`. `get_db("metrics")` returns a dependency for one
    database. `require_admin(scope)` and `require_csrf` are the admin guards (plan 5.5, D22).

Why it exists
    Dependency injection keeps routes free of globals: a route says what it needs, and tests swap any piece with
    `app.dependency_overrides[get_ctx] = ...` instead of monkeypatching modules. The admin guards are
    dependencies so the security test suite can discover every admin route and check it declares them (19.7).
    The proxy hot path does NOT use these: it reads `request.app.state.ctx` directly, because FastAPI's
    dependency resolution and Pydantic validation cost microseconds per request that the busiest route does not
    need to pay (DESIGN.md section 1).

How it works
    Everything comes from `request.app.state.ctx` (built by the lifespan) or `request.state` (filled by the
    middleware). A request that arrives while the context does not exist (during startup or shutdown) gets 503.
    Until the admin auth package exists (P8), `require_admin` and `require_csrf` FAIL CLOSED: every admin route
    answers 404, exactly like a non-allowlisted IP will, so nothing is ever exposed by a missing piece.

What to read next
    `roxy/admin/auth/deps.py` (the real guards, P8, re-exported here per DESIGN.md 11.7), then
    `roxy/admin/auth/sessions.py` and `roxy/admin/auth/csrf.py`.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, Literal

from fastapi import HTTPException, Request

from roxy.config.env import DATABASE_NAMES
from roxy.core.client_ip import UNKNOWN_IP
from roxy.lifespan import AppContext, optional_import

if TYPE_CHECKING:
    from roxy.config.runtime import RuntimeSettings
    from roxy.storage.db import Database

AdminScope = Literal["session", "fresh_mfa"]


def get_ctx(request: Request) -> AppContext:
    """The worker's `AppContext`. 503 while the worker is starting or stopping."""
    ctx = getattr(request.app.state, "ctx", None)
    if not isinstance(ctx, AppContext):
        raise HTTPException(status_code=503, detail="Service is starting; please try again shortly.")
    return ctx


def get_settings(request: Request) -> RuntimeSettings:
    """The live runtime settings (an in-memory snapshot; reading it never touches the database)."""
    return get_ctx(request).settings


def get_db(name: str) -> Callable[[Request], Database]:
    """A dependency returning one database by name: `Depends(get_db("metrics"))`."""
    if name not in DATABASE_NAMES:
        raise ValueError(f"unknown database {name!r}; expected one of {DATABASE_NAMES}")

    def dependency(request: Request) -> Database:
        dbs = get_ctx(request).dbs
        if dbs is None:
            raise HTTPException(status_code=503, detail="Storage is not available.")
        database: Database = getattr(dbs, name)
        return database

    dependency.__name__ = f"get_db_{name}"
    return dependency


def get_client_ip(request: Request) -> str:
    """The caller's IP as resolved by `ClientIPMiddleware` (never read X-Forwarded-For anywhere else)."""
    ip = getattr(request.state, "client_ip", None)
    if isinstance(ip, str) and ip:
        return ip
    return request.client.host if request.client else UNKNOWN_IP


def get_request_id(request: Request) -> str:
    """This request's id (also sent as `Roxy-Request-Id`)."""
    return str(getattr(request.state, "request_id", ""))


def get_trace(request: Request) -> Any | None:
    """The per-request upstream trace (`upstream/trace.py`) when the route has created one, else None."""
    return getattr(request.state, "trace", None)


def require_admin(scope: AdminScope = "session") -> Callable[[Request], Awaitable[Any]]:
    """A dependency that admits only a signed-in admin (`"session"`) or one with fresh MFA (`"fresh_mfa"`).

    Delegates to `roxy.admin.auth.deps.require_admin(scope)` once P8 provides it; until then it fails
    closed with the uniform 404.
    """
    if scope not in ("session", "fresh_mfa"):
        raise ValueError(f"unknown admin scope {scope!r}")
    auth = optional_import("roxy.admin.auth.deps")
    real = getattr(auth, "require_admin", None) if auth is not None else None
    if real is not None:
        dependency: Callable[[Request], Awaitable[Any]] = real(scope)
        return dependency

    async def closed(request: Request) -> Any:
        raise HTTPException(status_code=404, detail="Not Found")

    closed.__name__ = f"require_admin_{scope}"
    return closed


async def require_csrf(request: Request) -> None:
    """A dependency that checks the CSRF token and same-origin headers on state-changing admin requests.

    Delegates to `roxy.admin.auth.deps.require_csrf` once P8 provides it; until then it fails closed.
    """
    auth = optional_import("roxy.admin.auth.deps")
    real = getattr(auth, "require_csrf", None) if auth is not None else None
    if real is not None:
        await real(request)
        return
    raise HTTPException(status_code=403, detail="Forbidden")
