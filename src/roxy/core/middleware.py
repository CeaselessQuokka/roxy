"""The HTTP middleware stack: what happens to every request before a router sees it, and to every response after.

What this is
    The pure ASGI middleware classes, plus `build_middleware()` that returns them in the plan 5.3 order:
        request id -> unhandled errors -> real client IP -> deadline -> security headers -> size limits -> timing
    (outermost first). `RequestIdMiddleware`, `ClientIPMiddleware`, `SizeLimitMiddleware` and `TimingMiddleware`
    live here; the others have their own modules (`errors.py`, `deadline.py`, `security_headers.py`).

Why it exists
    Every one of these is a cross-cutting rule that must hold for EVERY response, including error responses that
    the routers never produce: a request id on every answer (plan 7.13), the real client IP computed exactly once
    and from the right end of `X-Forwarded-For` (9.11), size limits before a body is buffered (9.12), and a
    timing record. The order matters: the request id is outermost so even the deadline 504 and the unhandled
    error 500 carry it; the deadline wraps everything that can wait; size limits run inside security headers so a
    413 still gets the headers.

How it works
    Each class is an ASGI callable `(scope, receive, send)`. They pass the request down by calling the next app,
    and change responses by wrapping `send` (to add headers to the `http.response.start` message) or `receive`
    (to count body bytes as they arrive, so a 2 GiB upload is refused after 2 MiB instead of being buffered).
    Facts they learn are stored in `scope["state"]` (`request.state` in a route): `request_id`, `received_ms`,
    `peer_ip`, `client_ip`, `csp_nonce`, `deadline_at`, `app_ms`.
    Pure ASGI is used instead of Starlette's `BaseHTTPMiddleware`, which runs the app in a separate task and
    buffers through a memory stream: more overhead per request, and it breaks context variables and streaming.

What to read next
    `roxy/main.py` (where `build_middleware` is used), then `roxy/proxy/router.py` (what runs after the stack).
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Sequence
from typing import Any

from starlette.middleware import Middleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from roxy.core.client_ip import IPNetwork, is_trusted, parse_ip, resolve_client_ip
from roxy.core.clock import SYSTEM_CLOCK, Clock
from roxy.core.deadline import DeadlineMiddleware
from roxy.core.errors import UnhandledErrorMiddleware, emit_client_error, event_from_scope, send_plain_response
from roxy.core.ids import new_request_id
from roxy.core.logging import request_id_var
from roxy.core.reasons import ReasonCode
from roxy.core.redact import redact_query
from roxy.core.scope import get_app_context, get_state, setting_int
from roxy.core.security_headers import SecurityHeadersMiddleware

_log = logging.getLogger("roxy.core.middleware")

REQUEST_ID_HEADER = "Roxy-Request-Id"
_REQUEST_ID_HEADER_LOWER = REQUEST_ID_HEADER.lower().encode("latin-1")

# Size limit settings (plan 9.12) and the fallbacks used only when neither live settings nor the catalog exist.
MAX_BODY_BYTES_DEFAULT = 2 * 1024 * 1024
MAX_HEADER_COUNT_DEFAULT = 100
MAX_HEADER_BYTES_DEFAULT = 8 * 1024
MAX_URL_LENGTH_DEFAULT = 4096

BODY_TOO_LARGE_TEXT = "Request body is too large."
URL_TOO_LONG_TEXT = "Request URL is too long."
HEADERS_TOO_LARGE_TEXT = "Request header fields are too large."

SLOW_REQUEST_MS = 10_000.0
"""Requests slower than this are logged at INFO; normal ones at DEBUG (journald volume, plan 17.6)."""

_NGINX_REQUEST_ID = re.compile(rb"[0-9a-f]{32}")


# --- request id ----------------------------------------------------------------------------------------------------


class RequestIdMiddleware:
    """Gives every request a ULID, stores it in the state and the log context, and sends `Roxy-Request-Id`."""

    def __init__(self, app: ASGIApp, *, clock: Clock | None = None) -> None:
        self.app = app
        self.clock = clock

    def _clock(self, scope: Scope) -> Clock:
        if self.clock is not None:
            return self.clock
        ctx_clock = getattr(get_app_context(scope), "clock", None)
        return ctx_clock if ctx_clock is not None else SYSTEM_CLOCK

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        clock = self._clock(scope)
        request_id = new_request_id(clock)
        state = get_state(scope)
        state["request_id"] = request_id
        state["received_ms"] = clock.now_ms()
        state["received_monotonic"] = time.monotonic()
        header_value = request_id.encode("latin-1")

        async def send_with_id(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = [(k, v) for k, v in message.get("headers", []) if k.lower() != _REQUEST_ID_HEADER_LOWER]
                headers.append((REQUEST_ID_HEADER.encode("latin-1"), header_value))
                message = {**message, "headers": headers}
            await send(message)

        # A context variable, so every log line written while serving this request carries its id.
        token = request_id_var.set(request_id)
        try:
            await self.app(scope, receive, send_with_id)
        finally:
            request_id_var.reset(token)


# --- real client IP ------------------------------------------------------------------------------------------------


class ClientIPMiddleware:
    """Resolves the caller's IP once (plan 9.11) and makes it the request's client address.

    `scope["state"]["client_ip"]` and `request.client.host` both become the resolved address; the socket peer
    (nginx) is kept as `scope["state"]["peer_ip"]`. uvicorn's own proxy header handling is OFF
    (`RoxyUvicornWorker`), so this is the only place `X-Forwarded-For` is read.
    """

    def __init__(self, app: ASGIApp, *, trusted_cidrs: Sequence[IPNetwork], hops: int) -> None:
        self.app = app
        self.trusted_cidrs = tuple(trusted_cidrs)
        self.hops = hops

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        client = scope.get("client")
        peer = str(client[0]) if client else None
        forwarded: list[str] = []
        nginx_request_id: bytes | None = None
        for name, value in scope.get("headers", []):
            lowered = name.lower()
            if lowered == b"x-forwarded-for":
                forwarded.append(value.decode("latin-1"))
            elif lowered == b"x-request-id":
                nginx_request_id = value
        # Several X-Forwarded-For lines are one list in order (RFC 9110 field combination).
        xff = ",".join(forwarded) if forwarded else None
        client_ip = resolve_client_ip(peer, xff, self.trusted_cidrs, self.hops)
        state = get_state(scope)
        state["peer_ip"] = peer
        state["client_ip"] = client_ip
        peer_address = parse_ip(peer)
        if (
            nginx_request_id is not None
            and peer_address is not None
            and is_trusted(peer_address, self.trusted_cidrs)
            and _NGINX_REQUEST_ID.fullmatch(nginx_request_id)
        ):
            # nginx's own id ($request_id), kept to correlate its access log with ours. Trusted peers only.
            state["nginx_request_id"] = nginx_request_id.decode("latin-1")
        if client and parse_ip(client_ip) is not None:
            scope["client"] = (client_ip, client[1])
        await self.app(scope, receive, send)


# --- size limits ---------------------------------------------------------------------------------------------------


class BodyTooLarge(Exception):
    """Raised from `receive` when the body passes `max_body_bytes`; turned into a 413 by `SizeLimitMiddleware`."""


def _url_length(scope: Scope) -> int:
    raw_path = scope.get("raw_path")
    if isinstance(raw_path, bytes | bytearray):
        # Some servers (and httpx's test transport) include the query in raw_path; count it once.
        path_length = len(bytes(raw_path).split(b"?", 1)[0])
    else:
        path_length = len(str(scope.get("path", "")).encode("utf-8"))
    query = scope.get("query_string") or b""
    return path_length + (1 + len(query) if query else 0)


class SizeLimitMiddleware:
    """Refuses oversized URLs (414), headers (431) and bodies (413) before the app buffers them (plan 9.12).

    Limits are the live settings `max_url_length`, `max_header_count`, `max_header_bytes` (per header line) and
    `max_body_bytes`. Every refusal is logged as a probe through the client error hooks.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def _refuse(self, scope: Scope, send: Send, status: int, text: str, reason: ReasonCode) -> None:
        await send_plain_response(send, status, text, reason=reason)
        detail = f"HTTP {status} via {scope.get('method')} {scope.get('path')}"[:200]
        await emit_client_error(scope, event_from_scope(scope, status, reason=reason, detail=detail))

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        max_url = setting_int(scope, "max_url_length", MAX_URL_LENGTH_DEFAULT)
        if _url_length(scope) > max_url:
            await self._refuse(scope, send, 414, URL_TOO_LONG_TEXT, ReasonCode.URL_TOO_LONG)
            return
        headers: list[tuple[bytes, bytes]] = list(scope.get("headers", []))
        max_count = setting_int(scope, "max_header_count", MAX_HEADER_COUNT_DEFAULT)
        max_header_bytes = setting_int(scope, "max_header_bytes", MAX_HEADER_BYTES_DEFAULT)
        if len(headers) > max_count or any(len(name) + len(value) > max_header_bytes for name, value in headers):
            await self._refuse(scope, send, 431, HEADERS_TOO_LARGE_TEXT, ReasonCode.HEADERS_TOO_LARGE)
            return
        max_body = setting_int(scope, "max_body_bytes", MAX_BODY_BYTES_DEFAULT)
        for name, value in headers:
            if name.lower() == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    declared = 0  # the HTTP server already rejects malformed lengths; count the bytes instead
                if declared > max_body:
                    # Refused from the header alone: the body is never read.
                    await self._refuse(scope, send, 413, BODY_TOO_LARGE_TEXT, ReasonCode.BODY_TOO_LARGE)
                    return

        received = 0
        exceeded = False
        response_started = False
        refused = False

        async def limited_receive() -> Message:
            nonlocal received, exceeded
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > max_body:
                    exceeded = True
                    raise BodyTooLarge()
            return message

        async def guarded_send(message: Message) -> None:
            nonlocal response_started, refused
            if refused:
                return  # the app kept sending after we answered 413 for it; drop the rest
            if message["type"] == "http.response.start":
                if exceeded:
                    # The app swallowed BodyTooLarge and tried to answer itself; the 413 wins.
                    refused = True
                    await send_plain_response(send, 413, BODY_TOO_LARGE_TEXT, reason=ReasonCode.BODY_TOO_LARGE)
                    return
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, guarded_send)
        except BodyTooLarge:
            if response_started:
                raise
            if not refused:
                await send_plain_response(send, 413, BODY_TOO_LARGE_TEXT, reason=ReasonCode.BODY_TOO_LARGE)
                refused = True
        if refused:
            await emit_client_error(
                scope,
                event_from_scope(scope, 413, reason=ReasonCode.BODY_TOO_LARGE, detail="body over max_body_bytes"),
            )


# --- timing --------------------------------------------------------------------------------------------------------


class TimingMiddleware:
    """Innermost: measures how long the app took and logs one structured line per request.

    Normal requests log at DEBUG (one line per request would flood journald at INFO), slow ones at INFO, server
    errors at WARNING. The time is also stored as `scope["state"]["app_ms"]`.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = time.perf_counter()
        first_byte: float | None = None
        status = 0
        bytes_out = 0

        async def timed_send(message: Message) -> None:
            nonlocal first_byte, status, bytes_out
            if message["type"] == "http.response.start":
                first_byte = time.perf_counter()
                status = int(message["status"])
            elif message["type"] == "http.response.body":
                bytes_out += len(message.get("body", b""))
            await send(message)

        try:
            await self.app(scope, receive, timed_send)
        finally:
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            state = get_state(scope)
            state["app_ms"] = elapsed_ms
            if status >= 500:
                level = logging.WARNING
            elif elapsed_ms >= SLOW_REQUEST_MS:
                level = logging.INFO
            else:
                level = logging.DEBUG
            if _log.isEnabledFor(level):
                query = (scope.get("query_string") or b"").decode("latin-1")
                fields: dict[str, Any] = {
                    "method": scope.get("method"),
                    "path": scope.get("path"),
                    "query": redact_query(query),
                    "status": status,
                    "ms": round(elapsed_ms, 2),
                    "ttfb_ms": None if first_byte is None else round((first_byte - started) * 1000.0, 2),
                    "bytes_out": bytes_out,
                    "client_ip": state.get("client_ip"),
                }
                _log.log(level, "http_request", extra={"fields": fields})


# --- assembly ------------------------------------------------------------------------------------------------------


def build_middleware(
    *,
    trusted_cidrs: Sequence[IPNetwork],
    hops: int,
    send_hsts: bool = False,
    clock: Clock | None = None,
) -> list[Middleware]:
    """The public app's middleware in plan 5.3 order, outermost first (pass to `FastAPI(middleware=...)`)."""
    return [
        Middleware(RequestIdMiddleware, clock=clock),
        Middleware(UnhandledErrorMiddleware),
        Middleware(ClientIPMiddleware, trusted_cidrs=trusted_cidrs, hops=hops),
        Middleware(DeadlineMiddleware),
        Middleware(SecurityHeadersMiddleware, send_hsts=send_hsts),
        Middleware(SizeLimitMiddleware),
        Middleware(TimingMiddleware),
    ]
