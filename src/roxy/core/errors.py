"""Error handling: one clean 500 for every unhandled exception, and hooks so errors are counted and alerted.

What this is
    `UnhandledErrorMiddleware` turns any exception that escapes a route into the plan 7.13 answer (500,
    `Internal Server Error`, `Retry-After: 5`, with the request id and security headers). `ErrorHooks` is the
    list of callbacks later phases attach to: probe logging for client errors (status below 500), the errors
    table and alert emails for server errors, and the fallback outcome record. `install_exception_handlers`
    registers FastAPI handlers so `HTTPException` 4xx (404 for unknown paths, 405, 422) reach the probe hook.
    `send_plain_response` is the small helper every middleware uses to answer on its own.

Why it exists
    v1's `@app.errorhandler(Exception)` did two jobs: record client errors as probes, and email the admin about
    real failures. Starlette's built-in handler runs OUTSIDE every user middleware, so its 500 would carry no
    `Roxy-Request-Id` and no security headers. Catching here, just inside the request id middleware, keeps both,
    and the hooks keep this module free of imports from metrics and notify (which are built later and depend on
    core, not the other way round).

How it works
    The middleware watches whether the response has started. If an exception arrives before that, it sends the
    500 and then runs the server error hooks (after the caller has the answer, so a slow alert never delays it).
    If the response had already started, the status line is gone and cannot be changed: it logs and re-raises
    so the server closes the connection rather than pretend the truncated response was complete. Hooks may be
    plain functions or coroutines; each runs with a short timeout and its own exceptions are logged, never
    raised, because error handling must not fail in a new way while handling an error.

What to read next
    `roxy/core/deadline.py` and `roxy/core/middleware.py` (the other answers Roxy writes itself), then
    `roxy/metrics/security_events.py` and `roxy/notify/gate.py`, which register hooks.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from starlette.background import BackgroundTask
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from roxy.core.reasons import REFUSAL_HEADER, ReasonCode
from roxy.core.redact import redact_path
from roxy.core.security_headers import baseline_headers, standalone_headers

_log = logging.getLogger("roxy.core.errors")

INTERNAL_ERROR_BODY = "Internal Server Error"
INTERNAL_ERROR_RETRY_AFTER_S = 5
HOOK_TIMEOUT_S = 2.0
_MAX_HOOKS_PER_KIND = 16

PLAIN_TEXT = "text/plain; charset=utf-8"


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
    ever holds a secret path segment such as the kill-switch token of `/admin/invalidate/<token>` (plan D9).
    """
    state = scope.get("state") or {}
    return ErrorEvent(
        status=status,
        reason=reason,
        detail=redact_path(detail),
        request_id=state.get("request_id"),
        client_ip=state.get("client_ip"),
        method=str(scope.get("method", "")),
        path=redact_path(str(scope.get("path", ""))),
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
    payload = body.encode("utf-8")
    raw: list[tuple[bytes, bytes]] = [
        (b"content-type", PLAIN_TEXT.encode("latin-1")),
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
            await send_plain_response(
                send,
                500,
                INTERNAL_ERROR_BODY,
                headers=[("Retry-After", str(INTERNAL_ERROR_RETRY_AFTER_S))],
                scope=scope,  # this answer is built outside SecurityHeadersMiddleware
            )
            await emit_server_error(scope, event_from_scope(scope, 500, reason=ReasonCode.INTERNAL_ERROR, exc=exc))


async def _http_exception_handler(request: Request, exc: Exception) -> Response:
    """FastAPI handler for `HTTPException`: probe-log client errors, then answer exactly as FastAPI would."""
    from fastapi.exception_handlers import http_exception_handler  # local import: core stays usable without it

    assert isinstance(exc, StarletteHTTPException)
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
