"""Error handling: one clean 500 for every unhandled exception, and hooks so errors are counted and alerted.

What this is
    `UnhandledErrorMiddleware` turns any exception that escapes a route into the plan 7.13 answer (500,
    `Internal Server Error`, `Retry-After: 5`, with the request id and security headers). `ErrorHooks` is the
    list of callbacks later phases attach to: probe logging for client errors (status below 500), the errors
    table and alert emails for server errors, and the fallback outcome record. `install_exception_handlers`
    registers FastAPI handlers so `HTTPException` 4xx (404 for unknown paths, 405, 422) reach the probe hook.
    `send_plain_response` and `send_response` are the small helpers every middleware uses to answer on its own.
    `v1_json_body` is v1's `jsonify(text)` wire form, and `not_found_response` is the one "nothing here" answer
    for the admin area and for `/internal` on the public port.

Why it exists
    v1's `@app.errorhandler(Exception)` did two jobs: record client errors as probes, and email the admin about
    real failures. Starlette's built-in handler runs OUTSIDE every user middleware, so its 500 would carry no
    `Roxy-Request-Id` and no security headers. Catching here, just inside the request id middleware, keeps both,
    and the hooks keep this module free of imports from metrics and notify (which are built later and depend on
    core, not the other way round).
    The 500 body keeps v1's wire form: v1 answered `jsonify("Internal Server Error")`, a JSON string plus a
    newline labeled `application/json` (plan 7.13 asks for the text "as v1"; LEAD_NOTES decision 2 keeps every
    `jsonify` answer in that form).
    A 404 under `/admin` has exactly one wire form per area, whoever writes it: v1's `"Not Found"` plus a newline
    for pages (parity row 15), and the DESIGN.md section 13 error object under `/admin/api/v1`. The admin
    network allowlist (D6) hides real routes with a plain 404 that must be byte for byte the answer for a path
    that does not exist, or the hiding would be detectable; rendering both here makes that true by construction.

How it works
    The middleware watches whether the response has started. If an exception arrives before that, it sends the
    500 and then runs the server error hooks (after the caller has the answer, so a slow alert never delays it).
    If the response had already started, the status line is gone and cannot be changed: it logs and re-raises
    so the server closes the connection rather than pretend the truncated response was complete. Hooks may be
    plain functions or coroutines; each runs with a short timeout and its own exceptions are logged, never
    raised, because error handling must not fail in a new way while handling an error.
    The `HTTPException` handler answers as FastAPI would, except a plain 404 (`detail` "Not Found") on an admin
    path, which gets `not_found_response(path)`, and the section 13 shapes (`section13_exception_body`): an
    exception carrying `error_code` on an admin path, and the admin guards' 401, 403 and 503 on `/admin/api/v1`
    (DESIGN.md 13, so one admin API speaks one error format). Client errors still reach the probe hook: an
    allowlist refusal is worth recording. The admin catch-all route (`roxy/admin/router.py`) and the public
    `/internal` guard (`roxy/internal_app.py`) answer with `not_found_response` directly and run no hook: v1 never
    logged a typo in an admin URL as a probe, and the deploy's own checks of `/internal` are not attacks.

What to read next
    `roxy/core/deadline.py` and `roxy/core/middleware.py` (the other answers Roxy writes itself), then
    `roxy/metrics/security_events.py` and `roxy/notify/gate.py`, which register hooks, and `roxy/admin/router.py`.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from starlette.background import BackgroundTask
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from roxy.core.reasons import REFUSAL_HEADER, ReasonCode
from roxy.core.redact import redact_path
from roxy.core.security_headers import baseline_headers, is_admin_path, standalone_headers

_log = logging.getLogger("roxy.core.errors")

INTERNAL_ERROR_BODY = "Internal Server Error"
INTERNAL_ERROR_RETRY_AFTER_S = 5
HOOK_TIMEOUT_S = 2.0
_MAX_HOOKS_PER_KIND = 16
MAX_EVENT_PATH_CHARS = 2048
"""How much of a path (and detail) an error event keeps, cut BEFORE redaction so the work per event is bounded.

A 414 is answered before every rate limit, so its full decoded path (up to nginx's request line limit) must not
cost more scrubbing than a page view (review findings INGRESS-1 and public-4). Cutting first is safe: a credential
piece cut short of the 24 character window is not a leak, and a longer one before the cut is still found."""

PLAIN_TEXT = "text/plain; charset=utf-8"
JSON_TYPE = "application/json"  # what v1's jsonify sent: no charset parameter

NOT_FOUND_TEXT = "Not Found"
"""v1's 404 text (`jsonify("Not Found")`), also Starlette's default `HTTPException(404)` detail."""

ADMIN_API_PREFIX = "/admin/api/v1"
"""The versioned admin API (plan D9, DESIGN.md section 13): its errors use the section 13 error object."""

ADMIN_API_NOT_FOUND_CODE = "not_found"
ADMIN_API_NOT_FOUND_MESSAGE = "Not found."


def v1_json_body(text: str) -> bytes:
    """v1 `jsonify(text)`: the JSON string (ASCII, non-ASCII as \\uXXXX escapes) followed by a newline."""
    return (json.dumps(str(text)) + "\n").encode("ascii")


def is_admin_api_path(path: str) -> bool:
    """True for `/admin/api/v1` and everything under `/admin/api/v1/`."""
    return path == ADMIN_API_PREFIX or path.startswith(ADMIN_API_PREFIX + "/")


def admin_api_error_body(code: str, message: str, fields: Mapping[str, str] | None = None) -> bytes:
    """The DESIGN.md section 13 error object: `{"error": {"code", "message", "fields"}}`, compact JSON."""
    error = {"code": code, "message": message, "fields": dict(fields or {})}
    return json.dumps({"error": error}, separators=(",", ":")).encode("ascii")


def not_found_payload(path: str) -> bytes:
    """The 404 body for `path`: the section 13 error object under `/admin/api/v1`, else v1's `"Not Found"`."""
    if is_admin_api_path(path):
        return admin_api_error_body(ADMIN_API_NOT_FOUND_CODE, ADMIN_API_NOT_FOUND_MESSAGE)
    return v1_json_body(NOT_FOUND_TEXT)


def not_found_response(path: str, headers: Mapping[str, str] | None = None) -> Response:
    """The one "nothing here" answer for `path` (see the module docstring): 404, `application/json`."""
    return Response(content=not_found_payload(path), status_code=404, media_type=JSON_TYPE, headers=headers)


@dataclass(frozen=True, slots=True)
class ErrorEvent:
    """What a hook learns about one error response."""

    status: int
    reason: ReasonCode | None
    detail: str
    request_id: str | None
    client_ip: str | None
    method: str
    path: str
    user_agent: str
    exc: BaseException | None = None


ErrorHook = Callable[[ErrorEvent], Awaitable[None] | None]


@dataclass(slots=True)
class ErrorHooks:
    """Callbacks run after Roxy answers with an error. Stored at `app.state.error_hooks`.

    - `client_error`: status below 500 (404, 405, 413, 414, 422, 431...); v1 logged these as probes.
    - `server_error`: unhandled exceptions; the errors table and the alert email attach here.
    - `deadline`: the request deadline expired (504).
    """

    client_error: list[ErrorHook] = field(default_factory=list)
    server_error: list[ErrorHook] = field(default_factory=list)
    deadline: list[ErrorHook] = field(default_factory=list)

    def add(self, kind: str, hook: ErrorHook) -> None:
        """Attach `hook` to `kind` ("client_error", "server_error" or "deadline")."""
        hooks: list[ErrorHook] = getattr(self, kind)
        if len(hooks) >= _MAX_HOOKS_PER_KIND:
            raise RuntimeError(f"too many {kind} hooks")
        hooks.append(hook)


_FALLBACK_HOOKS = ErrorHooks()


def get_error_hooks(scope: Scope) -> ErrorHooks:
    """The hooks of the app serving this request (an empty set when the app has none, for example in tests)."""
    app = scope.get("app")
    hooks = getattr(getattr(app, "state", None), "error_hooks", None)
    return hooks if isinstance(hooks, ErrorHooks) else _FALLBACK_HOOKS


def _header(scope: Scope, name: bytes) -> str:
    for key, value in scope.get("headers", []):
        if key.lower() == name:
            return bytes(value).decode("latin-1")
    return ""


def event_from_scope(
    scope: Scope,
    status: int,
    *,
    reason: ReasonCode | None = None,
    detail: str = "",
    exc: BaseException | None = None,
) -> ErrorEvent:
    """Build an `ErrorEvent` from what the middleware stack stored in `scope["state"]`.

    The path (and the detail, which usually repeats it) is redacted here, so no hook, log line or errors table row
    ever holds a secret path segment such as the kill-switch token of `/admin/invalidate/<token>` (plan D9). Both
    are cut to `MAX_EVENT_PATH_CHARS` first, so the scrubbing work per event is bounded.
    """
    state = scope.get("state") or {}
    return ErrorEvent(
        status=status,
        reason=reason,
        detail=redact_path(detail[:MAX_EVENT_PATH_CHARS]),
        request_id=state.get("request_id"),
        client_ip=state.get("client_ip"),
        method=str(scope.get("method", "")),
        path=redact_path(str(scope.get("path", ""))[:MAX_EVENT_PATH_CHARS]),
        user_agent=_header(scope, b"user-agent")[:512],
        exc=exc,
    )


async def run_hooks(hooks: Sequence[ErrorHook], event: ErrorEvent) -> None:
    """Run each hook with a timeout; log (never raise) anything that goes wrong."""
    for hook in list(hooks):
        try:
            result = hook(event)
            if inspect.isawaitable(result):
                async with asyncio.timeout(HOOK_TIMEOUT_S):
                    await result
        except Exception:
            _log.exception("error_hook_failed", extra={"fields": {"hook": getattr(hook, "__name__", repr(hook))}})


async def emit_client_error(scope: Scope, event: ErrorEvent) -> None:
    """Log a client error (a possible probe) and run the client error hooks."""
    _log.info(
        "http_client_error",
        extra={
            "fields": {
                "status": event.status,
                "reason": event.reason,
                "method": event.method,
                "path": event.path,
                "client_ip": event.client_ip,
                "user_agent": event.user_agent,
                "detail": event.detail,
            }
        },
    )
    await run_hooks(get_error_hooks(scope).client_error, event)


async def emit_server_error(scope: Scope, event: ErrorEvent) -> None:
    """Log an unhandled exception with its traceback and run the server error hooks."""
    exc = event.exc
    _log.error(
        "unhandled_exception",
        exc_info=(type(exc), exc, exc.__traceback__) if exc is not None else None,
        extra={"fields": {"method": event.method, "path": event.path, "client_ip": event.client_ip, "status": 500}},
    )
    await run_hooks(get_error_hooks(scope).server_error, event)


async def emit_deadline(scope: Scope, event: ErrorEvent) -> None:
    """Log a request that ran out of time and run the deadline hooks."""
    _log.warning(
        "request_deadline_exceeded",
        extra={"fields": {"method": event.method, "path": event.path, "client_ip": event.client_ip}},
    )
    await run_hooks(get_error_hooks(scope).deadline, event)


async def send_plain_response(
    send: Send,
    status: int,
    body: str,
    *,
    headers: Sequence[tuple[str, str]] = (),
    reason: ReasonCode | None = None,
    scope: Scope | None = None,
) -> None:
    """Send a complete plain text response with security headers (and `Roxy-Refusal` if given).

    Pass `scope` from middleware that wraps `SecurityHeadersMiddleware` (the unhandled error 500, the deadline
    504): the response then gets the full set, CSP and the `/admin` headers included (`standalone_headers`).
    Without it only the baseline is added, which suits answers sent inside that middleware (it adds the rest).
    """
    await send_response(
        send, status, body.encode("utf-8"), content_type=PLAIN_TEXT, headers=headers, reason=reason, scope=scope
    )


async def send_response(
    send: Send,
    status: int,
    payload: bytes,
    *,
    content_type: str,
    headers: Sequence[tuple[str, str]] = (),
    reason: ReasonCode | None = None,
    scope: Scope | None = None,
) -> None:
    """Send a complete response of `content_type` with security headers (see `send_plain_response`)."""
    raw: list[tuple[bytes, bytes]] = [
        (b"content-type", content_type.encode("latin-1")),
        (b"content-length", str(len(payload)).encode("latin-1")),
    ]
    security = standalone_headers(scope) if scope is not None else baseline_headers()
    raw.extend((name.encode("latin-1"), value.encode("latin-1")) for name, value in security)
    # Caller-facing names keep their canonical casing (`Retry-After`, `Roxy-Refusal`), as v1 sent them: HTTP says
    # names are case-insensitive, but a Luau script indexing a headers table by exact name may not be.
    raw.extend((name.encode("latin-1"), value.encode("latin-1")) for name, value in headers)
    if reason is not None:
        raw.append((REFUSAL_HEADER.encode("latin-1"), reason.value.encode("latin-1")))
    await send({"type": "http.response.start", "status": status, "headers": raw})
    await send({"type": "http.response.body", "body": payload, "more_body": False})


class UnhandledErrorMiddleware:
    """Pure ASGI middleware: any exception before the response starts becomes the 7.13 500 answer."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = False

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, receive, tracking_send)
        except Exception as exc:
            if started:
                # Too late for a clean 500: the status line is already on the wire. Let the server drop the
                # connection so the caller sees a broken response, not a complete-looking one.
                await emit_server_error(scope, event_from_scope(scope, 500, reason=ReasonCode.INTERNAL_ERROR, exc=exc))
                raise
            await send_response(
                send,
                500,
                v1_json_body(INTERNAL_ERROR_BODY),  # v1 `jsonify("Internal Server Error")`, plan 7.13
                content_type=JSON_TYPE,
                headers=[("Retry-After", str(INTERNAL_ERROR_RETRY_AFTER_S))],
                scope=scope,  # this answer is built outside SecurityHeadersMiddleware
            )
            await emit_server_error(scope, event_from_scope(scope, 500, reason=ReasonCode.INTERNAL_ERROR, exc=exc))


GUARD_ERROR_CODES: Mapping[int, str] = {401: "unauthorized", 403: "forbidden", 503: "unavailable"}
"""Section 13 codes of the admin guards' own answers on `/admin/api/v1` (DESIGN.md 13): not signed in (401), a
CSRF or origin refusal (403) and shared state that cannot be read (503). The allowlist 404 already has its form."""

ENROLL_HEADER = "Roxy-Enroll"
ENROLL_CODE = "enrollment_required"
"""The 403 that asks a bootstrap session to finish enrolling its authenticator (it carries `Roxy-Enroll`)."""

MAX_GUARD_MESSAGE_CHARS = 500
"""A section 13 message built here is Roxy's own text; the cut only bounds an unexpected long detail."""


def _plain_text(value: Any) -> str:
    """A message for a section 13 body: Roxy's own text as a string, bounded."""
    return ("" if value is None else str(value))[:MAX_GUARD_MESSAGE_CHARS]


def section13_exception_body(exc: StarletteHTTPException, path: str) -> bytes | None:
    """The section 13 body for an `HTTPException` on an admin path, or None to answer as FastAPI does.

    - An exception that carries a string `error_code` (an API `ApiError`, the guards' `ReauthRequired`) on any
      `/admin` path: `{"error": {code, error_message, error_fields}}`. The auth routes' fresh-MFA 403 gets
      `reauth_required` here, the same as the area routes (common's request 1).
    - The guards' own 401, 403 and 503 on `/admin/api/v1` (DESIGN.md 13): codes from `GUARD_ERROR_CODES`
      (`enrollment_required` for the 403 that asks to finish enrolling), message the guard's own text, for
      example `{"error": {"code": "unauthorized", "message": "Session expired", "fields": {}}}`.
    Headers (the cleared session cookie, `Roxy-Reauth`, `Retry-After`) are kept by the caller.
    """
    code = getattr(exc, "error_code", None)
    if isinstance(code, str) and code and is_admin_path(path):
        fields = getattr(exc, "error_fields", None)
        clean = {str(k)[:120]: _plain_text(v) for k, v in dict(fields or {}).items()} if fields else None
        return admin_api_error_body(code, _plain_text(getattr(exc, "error_message", exc.detail)), clean)
    if is_admin_api_path(path) and exc.status_code in GUARD_ERROR_CODES:
        headers = {name.lower() for name in (exc.headers or {})}
        guard_code = ENROLL_CODE if ENROLL_HEADER.lower() in headers else GUARD_ERROR_CODES[exc.status_code]
        return admin_api_error_body(guard_code, _plain_text(exc.detail))
    return None


async def _http_exception_handler(request: Request, exc: Exception) -> Response:
    """FastAPI handler for `HTTPException`: probe-log client errors, then answer as FastAPI would.

    Two exceptions: a plain 404 under `/admin` (an allowlist refusal, a guard without a context, a route not
    found) is answered with `not_found_response`, byte for byte the answer for an admin path that does not exist;
    and an exception with a section 13 shape (`section13_exception_body`: one carrying `error_code`, or a guard's
    401, 403 or 503 on `/admin/api/v1`) is answered with the DESIGN.md section 13 error object.
    """
    from fastapi.exception_handlers import http_exception_handler  # local import: core stays usable without it

    assert isinstance(exc, StarletteHTTPException)
    path = str(request.scope.get("path", ""))
    body = section13_exception_body(exc, path)
    if body is None and exc.status_code == 404 and exc.detail == NOT_FOUND_TEXT and is_admin_path(path):
        response = not_found_response(path, headers=exc.headers)
    elif body is not None:
        response = Response(content=body, status_code=exc.status_code, media_type=JSON_TYPE, headers=exc.headers)
    else:
        response = await http_exception_handler(request, exc)
    if exc.status_code < 500:
        detail = f"HTTP {exc.status_code} via {request.method} {request.url.path}"[:200]
        reason = ReasonCode.METHOD_NOT_ALLOWED if exc.status_code == 405 else None
        event = event_from_scope(request.scope, exc.status_code, reason=reason, detail=detail)
        # Runs after the response is sent, so probe logging never delays the answer.
        response.background = BackgroundTask(emit_client_error, request.scope, event)
    return response


async def _validation_exception_handler(request: Request, exc: Exception) -> Response:
    """FastAPI handler for request validation errors (422): probe-log, then FastAPI's normal answer."""
    from fastapi.exception_handlers import request_validation_exception_handler
    from fastapi.exceptions import RequestValidationError

    assert isinstance(exc, RequestValidationError)
    response = await request_validation_exception_handler(request, exc)
    detail = f"HTTP 422 via {request.method} {request.url.path}"[:200]
    event = event_from_scope(request.scope, 422, detail=detail)
    response.background = BackgroundTask(emit_client_error, request.scope, event)
    return response


def install_exception_handlers(app: Any) -> None:
    """Register the client error handlers on a FastAPI app and give it an `ErrorHooks` at `app.state.error_hooks`."""
    from fastapi.exceptions import RequestValidationError

    if not isinstance(getattr(app.state, "error_hooks", None), ErrorHooks):
        app.state.error_hooks = ErrorHooks()
    app.add_exception_handler(StarletteHTTPException, _http_exception_handler)
    app.add_exception_handler(RequestValidationError, _validation_exception_handler)
