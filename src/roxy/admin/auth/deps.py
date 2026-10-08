"""The admin guards: `require_admin(scope)` and `require_csrf`, used by every admin route (DESIGN.md 11.7).

What this is
    FastAPI dependencies, re-exported by `roxy/deps.py`:
      * `require_admin("session")` admits a request with a live admin session; `require_admin("fresh_mfa")` also
        needs a second factor entered within `admin_reauth_window_s` (sensitive actions, plan 9.6). Both return an
        `AdminPrincipal`.
      * `require_csrf` checks the CSRF token and the same-origin headers on every state-changing request.
    Plus `get_auth(request)` (this worker's `AuthService`), `request_info(request)` and `masked_csrf(request)`
    (the per-response masked token for pages and JSON).

Why it exists
    Declaring the guards as dependencies keeps every admin route honest in one line, and lets the security tests
    discover every admin route and check it declares them (plan 19.7). Owner decision D22: one role, so the only
    distinction is "signed in" versus "signed in with a fresh second factor".

How it works
    `require_admin`, in order:
      1. No worker context yet (starting or stopping): plain 404, fail closed (the same answer as before P8).
      2. Admin allowlist (D6) on and the caller not on it: plain 404 (`allowlist.py`).
      3. An `Origin` header that is not `ROXY_SITE_ORIGIN`: 403 (plan 9.4).
      4. Session cookie -> live session (`AuthService.load_session`). None: API paths get 401 JSON
         `Session expired` (v1 text), pages a 302 to `/admin`; the dead cookie is cleared either way.
      5. A bootstrap session (D5 first login) may only enroll: elsewhere API paths get 403 and pages a 302 to
         `/admin/enroll`.
      6. `fresh_mfa` without a recent second factor: 403 `Re-authentication required` with `Roxy-Reauth:
         required`, so the dashboard can ask for the code and retry.
      7. Activity: only real use extends the session (plan 9.6). A state-changing request is use; a page load is
         use only when the browser says a person started it (`Sec-Fetch-Mode: navigate` with `Sec-Fetch-User:
         ?1`). Polling, HTMX refreshes and the live tail are not, so an unattended tab still expires. The
         heartbeat endpoint makes its own decision from the client's report of recent input.
    Shared state problems (C7) answer 503 with a clear message instead of guessing.

What to read next
    `roxy/admin/auth/sessions.py` and `roxy/admin/auth/csrf.py`, then `roxy/admin/auth/routes.py`.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Literal

from fastapi import HTTPException, Request

from roxy.admin.auth import csrf, sessions
from roxy.admin.auth.allowlist import admin_ip_allowed, not_found
from roxy.admin.auth.flow import AuthError, AuthService, RequestInfo
from roxy.admin.auth.responses import session_cookie_clear_header
from roxy.admin.auth.trusted_devices import TRUSTED_COOKIE
from roxy.core.client_ip import UNKNOWN_IP

log = logging.getLogger("roxy.admin.auth.deps")

AdminScope = Literal["session", "fresh_mfa"]
Activity = Literal["auto", "never"]

STATE_PRINCIPAL = "admin"
STATE_SESSION = "admin_session"
STATE_COOKIE = "admin_session_cookie"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
SESSION_EXPIRED_TEXT = "Session expired"
REAUTH_TEXT = "Re-authentication required"
ENROLL_TEXT = "Finish enrolling your authenticator app first."
FORBIDDEN_TEXT = "Forbidden"
ENROLL_PATHS = frozenset(
    {
        "/admin/enroll",
        "/admin/api/v1/auth/totp/enroll/start",
        "/admin/api/v1/auth/totp/enroll/confirm",
        "/admin/api/v1/auth/session",
        "/admin/api/v1/auth/logout",
        "/admin/api/v1/auth/heartbeat",
    }
)
"""The only paths a bootstrap session may use (D5: enroll an authenticator, nothing else)."""


@dataclass(frozen=True, slots=True)
class AdminPrincipal:
    """The signed-in admin of a request (DESIGN.md 11.7). `session_id` is the stored hash, never the cookie."""

    user_id: int
    username: str
    session_id: str
    mfa_level: str
    mfa_at: int
    ip: str
    ua: str


def get_ctx_or_none(request: Request) -> Any | None:
    return getattr(request.app.state, "ctx", None)


def get_auth(request: Request) -> AuthService:
    """This worker's `AuthService` (created on first use; rebuilt if the worker context was replaced)."""
    ctx = get_ctx_or_none(request)
    if ctx is None:
        raise not_found()
    service = getattr(request.app.state, "auth_service", None)
    if not isinstance(service, AuthService) or service.ctx is not ctx:
        service = AuthService(
            ctx,
            hasher=getattr(request.app.state, "auth_hasher", None),
            notifier=getattr(request.app.state, "auth_notifier", None),
        )
        request.app.state.auth_service = service
    return service


def client_ip(request: Request) -> str:
    ip = getattr(request.state, "client_ip", None)
    if isinstance(ip, str) and ip:
        return ip
    return request.client.host if request.client else UNKNOWN_IP


def request_info(request: Request) -> RequestInfo:
    """The parts of the request the login flow needs (cookies included, User-Agent bounded)."""
    return RequestInfo(
        ip=client_ip(request),
        ua=request.headers.get("user-agent", "")[:400],
        request_id=getattr(request.state, "request_id", None),
        path=request.url.path[:200],
        session_cookie=request.cookies.get(sessions.SESSION_COOKIE),
        trusted_cookie=request.cookies.get(TRUSTED_COOKIE),
    )


def is_api_path(path: str) -> bool:
    return path.startswith("/admin/api/")


def is_user_activity(request: Request) -> bool:
    """Whether this request is real use that should keep the session alive (see the module docstring)."""
    if request.method not in SAFE_METHODS:
        return True
    if request.headers.get("hx-request"):
        return False  # HTMX GETs are refreshes and polls
    mode = request.headers.get("sec-fetch-mode", "").lower()
    user = request.headers.get("sec-fetch-user", "")
    return mode == "navigate" and user == "?1"


def _reject_unauthenticated(request: Request) -> HTTPException:
    clear = {"Set-Cookie": session_cookie_clear_header()}
    if is_api_path(request.url.path):
        return HTTPException(status_code=401, detail=SESSION_EXPIRED_TEXT, headers=clear)
    return HTTPException(status_code=302, detail="Login required", headers={**clear, "Location": "/admin"})


def _unavailable(error: AuthError) -> HTTPException:
    return HTTPException(status_code=error.status, detail=error.body, headers=error.headers or None)


async def load_request_session(request: Request) -> tuple[sessions.SessionRecord, str] | None:
    """The live session of this request and its cookie token, cached on `request.state`."""
    cached = getattr(request.state, STATE_SESSION, None)
    token = getattr(request.state, STATE_COOKIE, None)
    if isinstance(cached, sessions.SessionRecord) and isinstance(token, str):
        return cached, token
    token = request.cookies.get(sessions.SESSION_COOKIE)
    if not token:
        return None
    try:
        record = await get_auth(request).load_session(token)
    except AuthError as error:
        raise _unavailable(error) from None
    if record is None:
        return None
    setattr(request.state, STATE_SESSION, record)
    setattr(request.state, STATE_COOKIE, token)
    return record, token


def require_admin(
    scope: AdminScope = "session", *, allow_bootstrap: bool = False, activity: Activity = "auto"
) -> Callable[[Request], Awaitable[AdminPrincipal]]:
    """A dependency admitting a signed-in admin (`session`) or one with a fresh second factor (`fresh_mfa`)."""
    if scope not in ("session", "fresh_mfa"):
        raise ValueError(f"unknown admin scope {scope!r}")

    async def dependency(request: Request) -> AdminPrincipal:
        ctx = get_ctx_or_none(request)
        if ctx is None:
            raise not_found()
        ip = client_ip(request)
        if not admin_ip_allowed(ctx, ip):
            raise not_found()
        if csrf.foreign_origin(request, str(ctx.env.site_origin)):
            raise HTTPException(status_code=403, detail=FORBIDDEN_TEXT)
        found = await load_request_session(request)
        if found is None:
            raise _reject_unauthenticated(request)
        record, _ = found
        if record.mfa_level == "bootstrap" and not (allow_bootstrap or request.url.path in ENROLL_PATHS):
            if is_api_path(request.url.path):
                raise HTTPException(status_code=403, detail=ENROLL_TEXT, headers={"Roxy-Enroll": "required"})
            raise HTTPException(status_code=302, detail=ENROLL_TEXT, headers={"Location": "/admin/enroll"})
        auth = get_auth(request)
        if scope == "fresh_mfa" and not record.is_fresh(ctx.clock.now(), ctx.settings.int("admin_reauth_window_s")):
            raise HTTPException(status_code=403, detail=REAUTH_TEXT, headers={"Roxy-Reauth": "required"})
        if activity == "auto" and is_user_activity(request):
            try:
                await auth.touch_session(record)
            except AuthError as error:
                raise _unavailable(error) from None
        principal = AdminPrincipal(
            user_id=record.user_id,
            username=record.username,
            session_id=record.id_hash,
            mfa_level=record.mfa_level,
            mfa_at=record.created_at,
            ip=ip,
            ua=request.headers.get("user-agent", "")[:400],
        )
        setattr(request.state, STATE_PRINCIPAL, principal)
        return principal

    dependency.__name__ = f"require_admin_{scope}"
    return dependency


async def require_csrf(request: Request) -> None:
    """403 unless a state-changing request carries this session's CSRF token from Roxy's own origin."""
    if request.method in SAFE_METHODS:
        return
    ctx = get_ctx_or_none(request)
    if ctx is None:
        raise HTTPException(status_code=403, detail=FORBIDDEN_TEXT)
    found = await load_request_session(request)
    if found is None:
        raise HTTPException(status_code=403, detail=FORBIDDEN_TEXT)
    record, token = found
    secret = sessions.csrf_secret(token)
    if hashlib.sha256(secret).hexdigest() != record.csrf_secret_hash:
        raise HTTPException(status_code=403, detail=FORBIDDEN_TEXT)
    problem = csrf.check(request, secret, str(ctx.env.site_origin))
    if problem is not None:
        log.info(
            "csrf_rejected",
            extra={"fields": {"reason": problem, "path": request.url.path, "client_ip": client_ip(request)}},
        )
        raise HTTPException(status_code=403, detail=FORBIDDEN_TEXT)


def masked_csrf_for_token(token: str) -> str:
    """A fresh masked CSRF token for a session cookie value (a new string on every call, BREACH)."""
    return csrf.mask(sessions.csrf_secret(token))


def masked_csrf(request: Request) -> str | None:
    """A fresh masked CSRF token for this request's session, for a page's meta tag or a JSON field."""
    token = getattr(request.state, STATE_COOKIE, None)
    if not isinstance(token, str):
        return None
    return masked_csrf_for_token(token)


__all__ = [
    "AdminPrincipal",
    "AdminScope",
    "get_auth",
    "masked_csrf",
    "request_info",
    "require_admin",
    "require_csrf",
]
