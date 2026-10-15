"""HTTP helpers for the auth routes: v1-shaped JSON answers, strict body parsing, and the auth cookies.

What this is
    `v1_json(value, status)` (the wire form v1's `jsonify` produced), `error_response(AuthError)`,
    `read_json_body(request, Model)`, and setters for the session, trusted device, `roxy_admin_seen` and
    `roxy_admin_counted` cookies.

Why it exists
    Callers and the v1 login page logic depend on the exact bodies: `"Not Found"`, `"Invalid credentials"`,
    `"Too many attempts; try again in N seconds."` are JSON strings followed by a newline, keys sorted, compact
    separators (lead decision 2). Plan 9.6 and 9.9: a request body that is missing, not JSON, not an object, too
    large, or has unexpected fields is rejected with 400, never treated as `{}`. Cookie flags live in one place
    so a test can pin them.

How it works
    - `read_json_body` requires `Content-Type: application/json`, reads at most `MAX_BODY_BYTES`, parses, and
      validates with a Pydantic model whose config forbids extra fields; any problem raises
      `AuthError(400, "Invalid request")`.
    - Cookies: `__Host-roxy_session` (session, no Max-Age) and `__Host-roxy_trusted` (Max-Age = trust lifetime)
      are both `Secure; HttpOnly; SameSite=Strict; Path=/` with no Domain, as the `__Host-` prefix requires.
      `roxy_admin_seen` (v1 visitor-count marker, not security relevant) keeps v1's flags. `roxy_admin_counted`
      (a day, `Path=/admin`, `Secure; HttpOnly; SameSite=Strict`) marks a browser whose login page visit was
      counted, so the login that follows takes exactly that visit back (finding parity-3).

What to read next
    `roxy/admin/auth/routes.py` (the callers), then `roxy/admin/auth/sessions.py`.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, ValidationError
from starlette.requests import Request
from starlette.responses import Response

from roxy.admin.auth.flow import INVALID_REQUEST_TEXT, AuthError
from roxy.admin.auth.sessions import SESSION_COOKIE
from roxy.admin.auth.trusted_devices import DAY_S, TRUSTED_COOKIE
from roxy.config.constants import ADMIN_SEEN_COOKIE, ADMIN_SEEN_COOKIE_MAX_AGE_S

MAX_BODY_BYTES = 64 * 1024
"""Largest auth request body (a passkey answer is a few KiB)."""


def v1_json(value: Any, status: int = 200, headers: dict[str, str] | None = None) -> Response:
    """JSON exactly as v1's `jsonify` wrote it: sorted keys, compact, trailing newline."""
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    return Response(content=text, status_code=status, media_type="application/json", headers=headers)


def error_response(error: AuthError) -> Response:
    return v1_json(error.body, error.status, headers=error.headers or None)


def bad_request() -> AuthError:
    return AuthError(400, INVALID_REQUEST_TEXT)


async def read_json_body[M: BaseModel](request: Request, model: type[M]) -> M:
    """Parse and validate a JSON object body, or raise `AuthError(400, "Invalid request")`."""
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        raise bad_request()
    # The size limit middleware already caps every body at `max_body_bytes`; this is the tighter auth cap.
    raw = await request.body()
    if len(raw) > MAX_BODY_BYTES or not raw.strip():
        raise bad_request()
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise bad_request() from None
    if not isinstance(data, dict):
        raise bad_request()
    try:
        return model.model_validate(data)
    except ValidationError:
        raise bad_request() from None


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(SESSION_COOKIE, token, path="/", secure=True, httponly=True, samesite="strict")


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="strict")


def session_cookie_clear_header() -> str:
    """A raw `Set-Cookie` value that deletes the session cookie (for responses raised as exceptions)."""
    return f"{SESSION_COOKIE}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict"


def set_trusted_cookie(response: Response, token: str, days: int) -> None:
    response.set_cookie(
        TRUSTED_COOKIE, token, max_age=max(1, days) * DAY_S, path="/", secure=True, httponly=True, samesite="strict"
    )


def clear_trusted_cookie(response: Response) -> None:
    response.delete_cookie(TRUSTED_COOKIE, path="/", secure=True, httponly=True, samesite="strict")


ADMIN_COUNTED_COOKIE = "roxy_admin_counted"
"""Marks a browser whose visit of the login page was counted as an Admin Page Visit (finding parity-3). A login from
that browser takes the visit back once (it was the owner); a login without it takes nothing back, so a script or a
browser that signs in without loading the page never cancels a real visitor's visit."""
ADMIN_COUNTED_COOKIE_MAX_AGE_S = 86_400
"""A day: the login that follows a page load comes within minutes; a visit older than that stays counted."""
ADMIN_COOKIE_PATH = "/admin"
"""Only the login page and the auth API under `/admin` ever read it."""


def set_admin_counted_cookie(response: Response) -> None:
    """`roxy_admin_counted=1` on a login page whose visit was counted (a visitor-count marker, not security relevant;
    flags as strict as the auth cookies anyway)."""
    response.set_cookie(
        ADMIN_COUNTED_COOKIE,
        "1",
        max_age=ADMIN_COUNTED_COOKIE_MAX_AGE_S,
        path=ADMIN_COOKIE_PATH,
        secure=True,
        httponly=True,
        samesite="strict",
    )


def clear_admin_counted_cookie(response: Response) -> None:
    response.delete_cookie(ADMIN_COUNTED_COOKIE, path=ADMIN_COOKIE_PATH, secure=True, httponly=True, samesite="strict")


def set_admin_seen_cookie(response: Response) -> None:
    """v1's `roxy_admin_seen=1` (180 days): the visitor counters skip admins (parity row 19)."""
    response.set_cookie(
        ADMIN_SEEN_COOKIE,
        "1",
        max_age=ADMIN_SEEN_COOKIE_MAX_AGE_S,
        path="/",
        secure=True,
        httponly=True,
        samesite="lax",
    )
