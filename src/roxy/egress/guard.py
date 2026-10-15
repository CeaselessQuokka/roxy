"""The leak guard: a transport under the anonymous clients that refuses any request carrying the credential.

What this is
    `GuardTransport`, an `httpx.AsyncBaseTransport` that wraps the real transport of the direct client and of every
    rotator client. Before a request is handed down, it inspects the final request (every header name and value,
    `Cookie` and `Authorization` included, the whole URL, and the body) and refuses it when it finds:
      * the Roblox credential, or any run of 24 or more of its characters: `CredentialLeakBlocked`. The request is
        not sent, a critical audit entry and alert fire, and that egress is disabled fleet-wide until an admin
        re-enables it (plan C2 item 4, 7.9 row "leak guard tripped");
      * a public auth marker (`TOKEN_PREFIX`, the `.ROBLOSECURITY` cookie name) or a body larger than
        `max_body_bytes`: `AuthSmugglingBlocked`. Refused and counted, but the egress stays enabled, so a caller
        who types a public string cannot switch an egress off (C2 item 5).
    `NoStoreCookieJar` is the cookie jar of every egress client: it never stores and never sends a cookie (C2 item 6).

Why it exists
    The credential must never leave through the rotator, and must not leave through the direct path either (an
    anonymous response fetched with the credential would be cached and served to everyone). The guard is a
    transport, not an httpx event hook, because hooks are a mutable list that later code can clear; a transport is
    fixed when the client is built and sees the request after every hook has run (test 2c).

How it works
    The credential module hands over an opaque `LeakMatcher` (it holds only keyed hashes of short pieces of the
    secret, never the secret). Each part of the request is checked as sent, ASCII case folded, and again after
    percent-decoding when it contains `%`. The leak check runs first, on everything, because a real credential is
    the serious case; then the markers; then the body size. Locations name where something was found
    (`header:cookie`, `url`, `body`), never what. The purpose of the call travels in a context variable set by
    `EgressClients.send`, so the alert can say which code path tried it. A typical request costs about 50
    microseconds to inspect; a body over 64 KiB is inspected on a worker thread (two at most) so a large upload
    never stalls the event loop.

What to read next
    `roxy/egress/credential.py` (`LeakMatcher`, the only holder of the secret), then `roxy/egress/clients.py`
    (where the guard is installed and the trip handler disables the egress).
"""

from __future__ import annotations

import contextlib
import functools
import http.cookiejar
import logging
from collections.abc import Awaitable, Callable, Iterator
from contextvars import ContextVar
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote_to_bytes

import anyio
import anyio.to_thread
import httpx

from roxy.core.logging import request_id_var
from roxy.core.reasons import Egress
from roxy.core.redact import ROBLOX_COOKIE_NAME, TOKEN_PREFIX, redact_text
from roxy.egress.errors import AuthSmugglingBlocked, CredentialLeakBlocked

if TYPE_CHECKING:
    from roxy.egress.credential import LeakMatcher

log = logging.getLogger("roxy.egress.guard")

_MARKERS: tuple[tuple[bytes, str], ...] = (
    (ROBLOX_COOKIE_NAME.lower().encode("ascii"), "cookie_name"),
    (TOKEN_PREFIX.lower().encode("ascii"), "token_prefix"),
)
_DECODE_ROUNDS = 2

OFFLOAD_BODY_BYTES = 64 * 1024
"""Bodies larger than this are inspected on a worker thread (at most `_INSPECTION_THREADS` at a time)."""

_INSPECTION_THREADS = 2
_limiter: anyio.CapacityLimiter | None = None


def _inspection_limiter() -> anyio.CapacityLimiter:
    global _limiter
    if _limiter is None:
        _limiter = anyio.CapacityLimiter(_INSPECTION_THREADS)
    return _limiter


class Verdict(StrEnum):
    """What the inspection found."""

    CLEAN = "clean"
    LEAK = "leak"
    MARKER = "marker"
    OVERSIZE = "oversize"


@dataclass(frozen=True, slots=True)
class Inspection:
    """The result of inspecting one request. `location` and `marker` never contain request content."""

    verdict: Verdict
    location: str = ""
    marker: str = ""


@dataclass(frozen=True, slots=True)
class GuardContext:
    """Who is sending: the call's purpose and the caller's request id (for the alert's code path hint)."""

    purpose: str
    request_id: str | None


_CONTEXT: ContextVar[GuardContext | None] = ContextVar("roxy_egress_guard_context", default=None)


@contextlib.contextmanager
def guard_context(purpose: str) -> Iterator[GuardContext]:
    """Label every guarded request sent by the current task inside the block with `purpose`."""
    context = GuardContext(purpose=purpose, request_id=request_id_var.get())
    token = _CONTEXT.set(context)
    try:
        yield context
    finally:
        _CONTEXT.reset(token)


@dataclass(frozen=True, slots=True)
class LeakTrip:
    """What the trip handler learns: which egress, where in the request, and which code path. Never the value."""

    egress: Egress
    location: str
    purpose: str
    request_id: str | None


@dataclass(slots=True)
class GuardStats:
    """Counters shown on the Egress page and in the health check."""

    inspected: int = 0
    leak_trips: int = 0
    smuggling_refusals: int = 0
    oversize_refusals: int = 0


def _variants(data: bytes) -> list[bytes]:
    """`data` and up to two rounds of percent-decoding of it (an encoded secret is still the secret)."""
    out = [data]
    current = data
    for _ in range(_DECODE_ROUNDS):
        if b"%" not in current:
            break
        decoded = unquote_to_bytes(current)
        if decoded == current:
            break
        out.append(decoded)
        current = decoded
    return out


def _safe_header_name(name: bytes) -> str:
    text = name.decode("latin-1", "replace").lower()
    return redact_text(text)[:40]


def request_parts(request: httpx.Request, body: bytes) -> list[tuple[str, bytes]]:
    """Every inspectable part of the final request with a content-free location label."""
    parts: list[tuple[str, bytes]] = [("url", str(request.url).encode("utf-8", "replace"))]
    parts.append(("url", request.url.raw_path))
    for name, value in request.headers.raw:
        parts.append((f"header:{_safe_header_name(name)}", name + b": " + value))
    if body:
        parts.append(("body", body))
    return parts


def inspect_parts(
    parts: list[tuple[str, bytes]], matcher: LeakMatcher, *, body_size: int, max_body_bytes: int
) -> Inspection:
    """Apply the three checks in order (leak, markers, body size) to already collected parts."""
    expanded = [(location, variant) for location, data in parts for variant in _variants(data)]
    for location, data in expanded:
        if matcher.matches(data):
            return Inspection(Verdict.LEAK, location)
    for location, data in expanded:
        folded = data.lower()  # ASCII-only lowercasing; changing case must not get around a public marker
        for marker, name in _MARKERS:
            if marker in folded:
                return Inspection(Verdict.MARKER, location, name)
    if body_size > max_body_bytes:
        return Inspection(Verdict.OVERSIZE, "body", "oversize_body")
    return Inspection(Verdict.CLEAN)


def inspect_request(request: httpx.Request, body: bytes, matcher: LeakMatcher, max_body_bytes: int) -> Inspection:
    """Inspect a final httpx request whose body has been read (see `GuardTransport`)."""
    return inspect_parts(request_parts(request, body), matcher, body_size=len(body), max_body_bytes=max_body_bytes)


async def _request_body(request: httpx.Request) -> bytes:
    try:
        return request.content
    except httpx.RequestNotRead:
        # A streamed body: read it (httpx keeps it for the actual send). Roxy's own clients always pass bytes.
        return await request.aread()


class GuardTransport(httpx.AsyncBaseTransport):
    """Wraps the real transport of an anonymous client and refuses credential-bearing requests (module docstring)."""

    def __init__(
        self,
        inner: httpx.AsyncBaseTransport,
        *,
        egress: Egress,
        matcher: Callable[[], LeakMatcher],
        max_body_bytes: Callable[[], int],
        on_leak: Callable[[LeakTrip], Awaitable[None]] | None = None,
        on_marker: Callable[[Egress, Inspection], None] | None = None,
        stats: GuardStats | None = None,
    ) -> None:
        if egress is Egress.CREDENTIAL:
            raise ValueError("the leak guard protects the anonymous egresses; the credential client is not one")
        self._inner = inner
        self.egress = egress
        self._matcher = matcher
        self._max_body_bytes = max_body_bytes
        self._on_leak = on_leak
        self._on_marker = on_marker
        self.stats = stats if stats is not None else GuardStats()

    @property
    def inner(self) -> httpx.AsyncBaseTransport:
        """The wrapped transport (read only: the guard cannot be unwrapped)."""
        return self._inner

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        body = await _request_body(request)
        self.stats.inspected += 1
        matcher, max_body = self._matcher(), self._max_body_bytes()
        if len(body) > OFFLOAD_BODY_BYTES:
            # A large body takes a while to scan (about 170 ms for 2 MiB); a worker thread keeps the event loop free.
            inspection = await anyio.to_thread.run_sync(
                functools.partial(inspect_request, request, body, matcher, max_body), limiter=_inspection_limiter()
            )
        else:
            inspection = inspect_request(request, body, matcher, max_body)
        if inspection.verdict is Verdict.LEAK:
            self.stats.leak_trips += 1
            context = _CONTEXT.get()
            trip = LeakTrip(
                egress=self.egress,
                location=inspection.location,
                purpose=context.purpose if context else "unknown",
                request_id=context.request_id if context else request_id_var.get(),
            )
            log.critical(
                "credential_leak_blocked",
                extra={"fields": {"egress": self.egress.value, "location": trip.location, "purpose": trip.purpose}},
            )
            if self._on_leak is not None:
                try:
                    await self._on_leak(trip)
                except Exception:
                    # The request is refused whatever happens here; the handler logs its own details.
                    log.exception("leak_trip_handler_failed", extra={"fields": {"egress": self.egress.value}})
            raise CredentialLeakBlocked(self.egress, inspection.location)
        if inspection.verdict in (Verdict.MARKER, Verdict.OVERSIZE):
            if inspection.verdict is Verdict.MARKER:
                self.stats.smuggling_refusals += 1
            else:
                self.stats.oversize_refusals += 1
            log.warning(
                "auth_marker_blocked",
                extra={
                    "fields": {
                        "egress": self.egress.value,
                        "marker": inspection.marker,
                        "location": inspection.location,
                    }
                },
            )
            if self._on_marker is not None:
                try:
                    self._on_marker(self.egress, inspection)
                except Exception:
                    log.exception("marker_handler_failed")
            raise AuthSmugglingBlocked(self.egress, inspection.marker, inspection.location)
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()


class NoStoreCookieJar(http.cookiejar.CookieJar):
    """A cookie jar that never stores a cookie and never adds one to a request (plan C2 item 6).

    httpx extracts every `Set-Cookie` into the client's jar and sends jar cookies on later requests. With this
    jar both are no-ops, so no response can plant a cookie that a later anonymous request would carry.
    """

    def set_cookie(self, cookie: http.cookiejar.Cookie) -> None:
        return None

    def set_cookie_if_ok(self, cookie: http.cookiejar.Cookie, request: Any) -> None:
        return None

    def extract_cookies(self, response: Any, request: Any) -> None:
        return None

    def make_cookies(self, response: Any, request: Any) -> list[http.cookiejar.Cookie]:
        return []

    def add_cookie_header(self, request: Any) -> None:
        return None


__all__ = [
    "GuardContext",
    "GuardStats",
    "GuardTransport",
    "Inspection",
    "LeakTrip",
    "NoStoreCookieJar",
    "Verdict",
    "guard_context",
    "inspect_parts",
    "inspect_request",
    "request_parts",
]
