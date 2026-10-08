"""Request deadline: every request finishes within `request_deadline_s`, with a meaningful answer if it cannot.

What this is
    `DeadlineMiddleware` runs the rest of the app inside `asyncio.timeout(request_deadline_s)` (default 60 s).
    `deadline_remaining(scope)` tells inner code how much of the budget is left, and `disable_deadline(scope)`
    lets a deliberately long-lived response (the admin live stream) opt out.

Why it exists
    Plan 5.2. With async workers nothing else bounds a request: gunicorn's `timeout` only notices a frozen event
    loop, not a coroutine waiting on a slow upstream. Without a deadline a stuck upstream holds a socket until
    nginx gives up at 100 s and the caller sees nginx's bare 504. With it, Roxy answers first (60 s is below
    nginx's `proxy_read_timeout` of 100 s), with a status, a body and `Retry-After` the caller can act on, and
    every inner budget (queue wait, upstream attempts, tarpit hold) is derived from this one number so they can
    never add up past it.

How it works
    `asyncio.timeout` cancels the inner work when the time is up and turns that cancellation into `TimeoutError`
    at the `async with`. The middleware checks that it was THIS timeout that expired (`expired()`), not some inner
    timeout an endpoint forgot to handle (that is an ordinary bug and becomes a 500). If the response has not
    started, it sends the 7.13 row: 504, `Upstream request failed; please try again later.`, `Retry-After: 5` and
    `Roxy-Refusal: deadline`. If the response had started (a slow stream), nothing can be sent any more; the
    middleware logs and ends the response, and the server closes the connection.
    The value is read per request from the live settings, so a change applies to the next request.

What to read next
    `roxy/upstream/queue.py` and `roxy/upstream/singleflight.py`, which use `deadline_remaining`.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import MutableMapping
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from roxy.core.errors import emit_deadline, event_from_scope, send_plain_response
from roxy.core.reasons import ReasonCode
from roxy.core.scope import get_state, setting_float

_log = logging.getLogger("roxy.core.deadline")

DEADLINE_SETTING = "request_deadline_s"
DEFAULT_DEADLINE_S = 60.0
DEADLINE_BODY = "Upstream request failed; please try again later."
DEADLINE_RETRY_AFTER_S = 5

STATE_DEADLINE_AT = "deadline_at"
"""`scope["state"]` key: when the deadline expires, in `time.monotonic()` seconds (None when disabled)."""
STATE_DEADLINE_TIMEOUT = "deadline_timeout"
"""`scope["state"]` key: the `asyncio.Timeout` object, so the deadline can be disabled for streams."""


def deadline_remaining(scope: MutableMapping[str, Any]) -> float | None:
    """Seconds left before this request's deadline (never negative), or None when there is no deadline."""
    deadline_at = get_state(scope).get(STATE_DEADLINE_AT)
    if deadline_at is None:
        return None
    return max(0.0, float(deadline_at) - time.monotonic())


def disable_deadline(scope: MutableMapping[str, Any]) -> None:
    """Remove the deadline for this request (only for responses meant to stay open, like Server-Sent Events)."""
    state = get_state(scope)
    timeout = state.get(STATE_DEADLINE_TIMEOUT)
    if isinstance(timeout, asyncio.Timeout):
        timeout.reschedule(None)
    state[STATE_DEADLINE_AT] = None


class DeadlineMiddleware:
    """Pure ASGI middleware enforcing `request_deadline_s` (plan 5.2 and 7.13 row "deadline")."""

    def __init__(self, app: ASGIApp, *, default_s: float = DEFAULT_DEADLINE_S) -> None:
        self.app = app
        self.default_s = default_s

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        budget = setting_float(scope, DEADLINE_SETTING, self.default_s)
        state = get_state(scope)
        state[STATE_DEADLINE_AT] = time.monotonic() + budget
        started = False

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        timeout = asyncio.timeout(budget)
        state[STATE_DEADLINE_TIMEOUT] = timeout
        try:
            async with timeout:
                await self.app(scope, receive, tracking_send)
        except TimeoutError:
            if not timeout.expired():
                raise  # an inner timeout nobody handled: a bug, reported as a 500 by UnhandledErrorMiddleware
            if started:
                _log.warning(
                    "deadline_after_response_start",
                    extra={"fields": {"path": scope.get("path"), "deadline_s": budget}},
                )
                return
            await send_plain_response(
                send,
                504,
                DEADLINE_BODY,
                headers=[("Retry-After", str(DEADLINE_RETRY_AFTER_S))],
                reason=ReasonCode.DEADLINE,
                scope=scope,  # this answer is built outside SecurityHeadersMiddleware
            )
            await emit_deadline(
                scope,
                event_from_scope(scope, 504, reason=ReasonCode.DEADLINE, detail=f"deadline {budget:g} s exceeded"),
            )
