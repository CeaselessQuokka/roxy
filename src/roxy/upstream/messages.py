"""Caller-facing upstream messages and the plan 7.13 outcome table, in one place.

What this is
    The exact texts callers see when Roxy could not get an answer from Roblox (parity row 36), and `CALLER_ROWS`,
    one entry per upstream or failure reason code saying which status, body and `Retry-After` the caller gets
    (plan 7.13). `retry_after_seconds` turns a row's rule into a number.

Why it exists
    v1 answered every failure with HTTP 500 and no `Retry-After`, so game scripts retried at once and fed more
    429s (plan 2.5, R8). v2 sends honest statuses with a wait hint. The texts are part of the v1 contract (callers
    match on them), so they live here once and are golden-tested; `proxy/respond.py` builds the final response
    from these rows, and `upstream/service.py` uses the same rows to fill `UpstreamResult`.

How it works
    Each `CallerRow` says: a fixed status or "the real upstream status", a fixed body or "the upstream body", how
    `Retry-After` is computed (`RetryAfterRule`), and whether the `Roxy-Refusal` header names the reason. Bodies
    are plain text: v1 sent these strings raw under an `application/json` label (invalid JSON); v2 sends the same
    bytes as `text/plain; charset=utf-8` (lead decision 2, recorded in CHANGES.md).

What to read next
    `roxy/upstream/status.py` (which attempt outcome leads to which reason) and `roxy/upstream/service.py`.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final

from roxy.core.reasons import ReasonCode

BUSY_MESSAGE: Final = "All request methods are busy right now; please try again shortly."
"""v1 proxy.py:264: no egress could take the call (busy, cooling down, disabled)."""

FAILED_MESSAGE: Final = "Upstream request failed; please try again later."
"""v1 proxy.py:283: Roblox failed (5xx), timed out, or could not be reached after the allowed retries."""

INTERNAL_ERROR_MESSAGE: Final = "Internal Server Error"
"""v1 index.py:2179: an unexpected exception inside Roxy."""

AUTH_SMUGGLING_MESSAGE: Final = "Requests requiring authentication are not allowed with this proxy."
"""v1 index.py:1414: the guard saw a public credential marker on an anonymous request (plan C2 item 5)."""

NOT_ROBLOX_MESSAGE: Final = "Not a Roblox URL"
"""v1 parity row 7: the egress host check refused the target (only reachable if validation and egress disagree)."""

MESSAGE_CONTENT_TYPE: Final = "text/plain; charset=utf-8"
"""Content type of every body above (lead decision 2: same bytes as v1, honest label)."""

DEFAULT_FAILURE_RETRY_AFTER_S: Final = 5
REJECTED_CREDENTIAL_RETRY_AFTER_S: Final = 300


class RetryAfterRule(StrEnum):
    """How the `Retry-After` value of a 7.13 row is computed."""

    NONE = "none"  # Roxy adds none (an upstream Retry-After may still be relayed by respond.py)
    FIXED = "fixed"  # the row's fixed number of seconds
    COOLDOWN = "cooldown"  # the remaining cooldown of the endpoint and egress
    SOONEST = "soonest"  # when the soonest egress can take a call again
    SOONEST_MIN_1 = "soonest_min_1"  # the same, never below 1 second
    UPSTREAM_OR_DEFAULT = "upstream_or_default"  # Roblox's own Retry-After, else 5
    OWNER_DEADLINE = "owner_deadline"  # the single-flight owner's remaining deadline
    CREDENTIAL = "credential"  # the credential's remaining cooldown, or 300 when it was rejected


@dataclass(frozen=True, slots=True)
class CallerRow:
    """What the caller receives for one internal outcome (one row of plan 7.13)."""

    reason: ReasonCode
    status: int | None  # None: the real upstream status
    body: str | None  # None: the upstream body
    retry_after: RetryAfterRule
    retry_after_fixed: int | None = None
    refusal_header: bool = True  # sends `Roxy-Refusal: <reason>`
    upstream_status_header: bool = True  # sends `Roxy-Upstream-Status` whenever an upstream status is known


def _row(
    reason: ReasonCode,
    status: int | None,
    body: str | None,
    retry_after: RetryAfterRule,
    fixed: int | None = None,
    *,
    refusal: bool = True,
) -> tuple[ReasonCode, CallerRow]:
    return reason, CallerRow(reason, status, body, retry_after, fixed, refusal)


CALLER_ROWS: Final[Mapping[ReasonCode, CallerRow]] = MappingProxyType(
    dict(
        [
            # Roblox answered and Roxy passes the answer on (2xx, 3xx not followed, 4xx other than 429).
            _row(ReasonCode.UPSTREAM_OK, None, None, RetryAfterRule.NONE, refusal=False),
            _row(ReasonCode.UPSTREAM_4XX, None, None, RetryAfterRule.NONE, refusal=False),
            # Roblox 429 or an active cooldown, and no stale copy to serve (`cooldown_no_stale`).
            _row(ReasonCode.UPSTREAM_COOLDOWN, 429, BUSY_MESSAGE, RetryAfterRule.COOLDOWN),
            # No egress can grant a slot within the queue deadline: honest back pressure.
            _row(ReasonCode.UPSTREAM_BUSY, 429, BUSY_MESSAGE, RetryAfterRule.SOONEST),
            _row(ReasonCode.QUEUE_OVERFLOW, 429, BUSY_MESSAGE, RetryAfterRule.SOONEST_MIN_1),
            # Roblox 5xx after the allowed retries: the real status (500, 502, 503, 504), no Roxy-Refusal header.
            _row(ReasonCode.UPSTREAM_5XX, None, FAILED_MESSAGE, RetryAfterRule.UPSTREAM_OR_DEFAULT, refusal=False),
            _row(ReasonCode.UPSTREAM_TIMEOUT, 504, FAILED_MESSAGE, RetryAfterRule.FIXED, DEFAULT_FAILURE_RETRY_AFTER_S),
            _row(ReasonCode.UPSTREAM_CONNECT, 502, FAILED_MESSAGE, RetryAfterRule.FIXED, DEFAULT_FAILURE_RETRY_AFTER_S),
            _row(ReasonCode.DEADLINE, 504, FAILED_MESSAGE, RetryAfterRule.FIXED, DEFAULT_FAILURE_RETRY_AFTER_S),
            _row(ReasonCode.COALESCE_TIMEOUT, 503, BUSY_MESSAGE, RetryAfterRule.OWNER_DEADLINE),
            _row(ReasonCode.EGRESS_DISABLED, 503, BUSY_MESSAGE, RetryAfterRule.FIXED, 60),
            _row(ReasonCode.CREDENTIAL_UNAVAILABLE, 503, BUSY_MESSAGE, RetryAfterRule.CREDENTIAL),
            _row(ReasonCode.DEGRADED, 503, BUSY_MESSAGE, RetryAfterRule.FIXED, 10),
            _row(
                ReasonCode.INTERNAL_ERROR,
                500,
                INTERNAL_ERROR_MESSAGE,
                RetryAfterRule.FIXED,
                DEFAULT_FAILURE_RETRY_AFTER_S,
                refusal=False,
            ),
            # Not rows of 7.13 (the plan gives only the side effects, 7.9); chosen here and recorded in the report:
            # a real credential leak trip disables that egress, so the caller sees the egress_disabled answer with
            # its own reason; a public marker at the guard is an auth smuggling refusal with the v1 400 text.
            _row(ReasonCode.LEAK_BLOCKED, 503, BUSY_MESSAGE, RetryAfterRule.FIXED, 60),
            _row(ReasonCode.AUTH_SMUGGLING, 400, AUTH_SMUGGLING_MESSAGE, RetryAfterRule.NONE),
            _row(ReasonCode.HOST_NOT_ALLOWED, 404, NOT_ROBLOX_MESSAGE, RetryAfterRule.NONE),
        ]
    )
)


def caller_row(reason: ReasonCode) -> CallerRow:
    """The 7.13 row for `reason`. Raises KeyError for reasons this package never produces (abuse refusals)."""
    return CALLER_ROWS[reason]


def caller_status(reason: ReasonCode, upstream_status: int | None) -> int:
    """The status the caller receives: the row's fixed status, or the real upstream status."""
    row = CALLER_ROWS[reason]
    if row.status is not None:
        return row.status
    if upstream_status is None:  # pragma: no cover - only rows with a fixed status reach here without one
        raise ValueError(f"{reason} needs the upstream status")
    return upstream_status


def _whole_seconds(value: float | None, *, minimum: int = 1) -> int | None:
    """Round a wait up to whole seconds (Retry-After is an integer, and rounding down would invite a retry
    that is still too early)."""
    if value is None:
        return None
    return max(minimum, math.ceil(max(0.0, value) - 1e-9))


def retry_after_seconds(
    reason: ReasonCode,
    *,
    cooldown_s: float | None = None,
    soonest_s: float | None = None,
    upstream_retry_after_s: float | None = None,
    owner_remaining_s: float | None = None,
    credential_rejected: bool = False,
) -> int | None:
    """The `Retry-After` seconds for `reason` per its 7.13 row, or None when the row adds none."""
    row = CALLER_ROWS[reason]
    match row.retry_after:
        case RetryAfterRule.NONE:
            return None
        case RetryAfterRule.FIXED:
            return row.retry_after_fixed
        case RetryAfterRule.COOLDOWN:
            return _whole_seconds(cooldown_s if cooldown_s is not None else soonest_s) or 1
        case RetryAfterRule.SOONEST:
            return _whole_seconds(soonest_s, minimum=1) or 1
        case RetryAfterRule.SOONEST_MIN_1:
            return _whole_seconds(soonest_s, minimum=1) or 1
        case RetryAfterRule.UPSTREAM_OR_DEFAULT:
            relayed = _whole_seconds(upstream_retry_after_s, minimum=0)
            return relayed if relayed is not None else DEFAULT_FAILURE_RETRY_AFTER_S
        case RetryAfterRule.OWNER_DEADLINE:
            return _whole_seconds(owner_remaining_s) or 1
        case RetryAfterRule.CREDENTIAL:
            if credential_rejected:
                return REJECTED_CREDENTIAL_RETRY_AFTER_S
            # The cooldown's remaining time, else when the credential manager said it could be tried again
            # (`soonest_s`, for example 10 s while shared state is unreadable), else 300.
            return _whole_seconds(cooldown_s) or _whole_seconds(soonest_s) or REJECTED_CREDENTIAL_RETRY_AFTER_S
    return None  # pragma: no cover - the match above is exhaustive


__all__ = [
    "AUTH_SMUGGLING_MESSAGE",
    "BUSY_MESSAGE",
    "CALLER_ROWS",
    "DEFAULT_FAILURE_RETRY_AFTER_S",
    "FAILED_MESSAGE",
    "INTERNAL_ERROR_MESSAGE",
    "MESSAGE_CONTENT_TYPE",
    "NOT_ROBLOX_MESSAGE",
    "REJECTED_CREDENTIAL_RETRY_AFTER_S",
    "CallerRow",
    "RetryAfterRule",
    "caller_row",
    "caller_status",
    "retry_after_seconds",
]
