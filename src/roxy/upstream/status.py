"""Status classification and the outcome policy table (plan 7.9): what one upstream answer means.

What this is
    `classify_response` and `classify_exception` turn one HTTP exchange into an `AttemptKind` (success, CSRF
    challenge, rate limited, server error, timeout, ...). `POLICY_TABLE` says, for each kind, whether Roxy may
    retry and where, which side effects follow (cooldown, breaker failure, negative caching, ...), and which 7.13
    reason the caller gets if the request ends there. Also the v1 failure labels (`failure_reason_text`).

Why it exists
    v1 treated only HTTP 200 as success (201 and 204 writes were reported as failures, bug B4), and answered a 429
    by immediately trying the other method, which is how one rate limit became four calls (plan 2.5, R3). The
    replacement is an explicit table (plan 7.9 "replaces fall through to the other method"), so the decision for
    each outcome is data that is golden-tested row by row instead of control flow spread over a loop.

How it works
    - Any 2xx is success. 304 is "not modified". Other 3xx are redirects (followed manually by the service only
      within the host allowlist, at most 3 hops, never carrying the credential off the allowlist).
    - 403 with an `x-csrf-token` response header is Roblox's CSRF handshake (once per attempt; a second one is
      definitive). Other 4xx except 429 are definitive answers. 429 is rate limiting. 5xx is a server error.
    - Exceptions are recognized by class name, so this module does not import the egress package: the egress
      contract (DESIGN 11.4) names `CredentialLeakBlocked`, `AuthSmugglingBlocked`, `EgressDisabled`,
      `UpstreamTimeout` and `UpstreamConnectError`. Raw `httpx` timeouts and transport errors map the same way.
    - The policy says nothing about HOW a side effect is done; `upstream/effects.py` and `service.py` do that.

What to read next
    `roxy/upstream/effects.py` (side effects in hot.db) and `roxy/upstream/service.py` (the retry loop).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final

import httpx

from roxy.core.reasons import ReasonCode

CSRF_HEADER: Final = "x-csrf-token"


class AttemptKind(StrEnum):
    """What one upstream exchange turned out to be."""

    SUCCESS = "success"  # any 2xx
    NOT_MODIFIED = "not_modified"  # 304
    REDIRECT = "redirect"  # other 3xx
    CSRF_CHALLENGE = "csrf_challenge"  # 403 + x-csrf-token, first time in this attempt
    DEFINITIVE = "definitive"  # 4xx other than 429 (and a repeated CSRF 403), or an odd 1xx
    RATE_LIMITED = "rate_limited"  # 429
    SERVER_ERROR = "server_error"  # 5xx
    TIMEOUT = "timeout"
    CONNECT_ERROR = "connect_error"  # connect, TLS or protocol failure
    LEAK_BLOCKED = "leak_blocked"  # the guard found the real credential on an anonymous request (never sent)
    SMUGGLING_BLOCKED = "smuggling_blocked"  # the guard found only a public marker (never sent)
    EGRESS_DISABLED = "egress_disabled"  # the egress refused before sending (admin switch, quota, leak trip)
    TARGET_REFUSED = "target_refused"  # the egress host check refused the URL (never sent)


class RetryRule(StrEnum):
    """Where (if anywhere) an attempt may be repeated."""

    NONE = "none"
    CSRF_ONCE_SAME_EGRESS = "csrf_once_same_egress"  # with the token, counted against the buckets
    FOLLOW_REDIRECT = "follow_redirect"  # allowlisted host only, max 3 hops
    OPTIONAL_OTHER_ANONYMOUS = "optional_other_anonymous"  # 429: only with fallback_on_429=1, never the credential
    BACKOFF = "backoff"  # 5xx, timeout, connect: same or other anonymous egress, jittered backoff, deadline allowing
    REROUTE = "reroute"  # nothing was sent: route again without that egress (not counted as an attempt)


class SideEffect(StrEnum):
    """Side effects named by the 7.9 table."""

    RECORD_SUCCESS = "record_success"
    AIMD_SUCCESS = "aimd_success"
    REFRESH_TTL = "refresh_ttl"
    NEGATIVE_CACHE = "negative_cache"
    CREDENTIAL_REJECT_CHECK = "credential_reject_check"  # 401 on the credential path: one confirming probe
    COOLDOWN = "cooldown"
    ROTATE_SESSION = "rotate_session"
    BREAKER_FAILURE = "breaker_failure"
    ADAPTIVE_DECREASE = "adaptive_decrease"
    LOG_429 = "log_429"
    ROTATOR_HEALTH_FAILURE = "rotator_health_failure"
    AIMD_FAILURE = "aimd_failure"
    CRITICAL_ALERT = "critical_alert"
    DISABLE_EGRESS = "disable_egress"
    COUNT_SMUGGLING = "count_smuggling"


@dataclass(frozen=True, slots=True)
class OutcomePolicy:
    """One row of the plan 7.9 table."""

    kind: AttemptKind
    retry: RetryRule
    side_effects: frozenset[SideEffect]
    reason: ReasonCode  # the 7.13 reason when the request ends with this outcome
    breaker_failure: bool  # counts as a breaker failure (a rotator 429 only under the distinct-exit rule)
    rotator_health_failure: bool  # counts toward the rotator failure streak (row 31)
    sent: bool  # an HTTP call reached Roblox (it counts in `calls` and in the buckets)


def _p(
    kind: AttemptKind,
    retry: RetryRule,
    effects: tuple[SideEffect, ...],
    reason: ReasonCode,
    *,
    breaker: bool = False,
    rotator: bool = False,
    sent: bool = True,
) -> tuple[AttemptKind, OutcomePolicy]:
    return kind, OutcomePolicy(kind, retry, frozenset(effects), reason, breaker, rotator, sent)


S = SideEffect
POLICY_TABLE: Final[Mapping[AttemptKind, OutcomePolicy]] = MappingProxyType(
    dict(
        [
            _p(AttemptKind.SUCCESS, RetryRule.NONE, (S.RECORD_SUCCESS, S.AIMD_SUCCESS), ReasonCode.UPSTREAM_OK),
            _p(AttemptKind.NOT_MODIFIED, RetryRule.NONE, (S.RECORD_SUCCESS, S.REFRESH_TTL), ReasonCode.UPSTREAM_OK),
            _p(AttemptKind.REDIRECT, RetryRule.FOLLOW_REDIRECT, (S.RECORD_SUCCESS,), ReasonCode.UPSTREAM_OK),
            _p(AttemptKind.CSRF_CHALLENGE, RetryRule.CSRF_ONCE_SAME_EGRESS, (), ReasonCode.UPSTREAM_4XX),
            _p(
                AttemptKind.DEFINITIVE,
                RetryRule.NONE,
                (S.RECORD_SUCCESS, S.NEGATIVE_CACHE, S.CREDENTIAL_REJECT_CHECK),
                ReasonCode.UPSTREAM_4XX,
            ),
            _p(
                AttemptKind.RATE_LIMITED,
                RetryRule.OPTIONAL_OTHER_ANONYMOUS,
                (
                    S.COOLDOWN,
                    S.ROTATE_SESSION,
                    S.BREAKER_FAILURE,
                    S.ADAPTIVE_DECREASE,
                    S.LOG_429,
                    S.ROTATOR_HEALTH_FAILURE,
                    S.AIMD_FAILURE,
                ),
                ReasonCode.UPSTREAM_COOLDOWN,
                breaker=True,
                rotator=True,
            ),
            _p(
                AttemptKind.SERVER_ERROR,
                RetryRule.BACKOFF,
                (S.BREAKER_FAILURE, S.ROTATOR_HEALTH_FAILURE, S.AIMD_FAILURE),
                ReasonCode.UPSTREAM_5XX,
                breaker=True,
                rotator=True,
            ),
            _p(
                AttemptKind.TIMEOUT,
                RetryRule.BACKOFF,
                (S.BREAKER_FAILURE, S.ROTATOR_HEALTH_FAILURE, S.ROTATE_SESSION, S.AIMD_FAILURE),
                ReasonCode.UPSTREAM_TIMEOUT,
                breaker=True,
                rotator=True,
            ),
            _p(
                AttemptKind.CONNECT_ERROR,
                RetryRule.BACKOFF,
                (S.BREAKER_FAILURE, S.ROTATOR_HEALTH_FAILURE, S.ROTATE_SESSION, S.AIMD_FAILURE),
                ReasonCode.UPSTREAM_CONNECT,
                breaker=True,
                rotator=True,
            ),
            _p(
                AttemptKind.LEAK_BLOCKED,
                RetryRule.NONE,
                (S.CRITICAL_ALERT, S.DISABLE_EGRESS),
                ReasonCode.LEAK_BLOCKED,
                sent=False,
            ),
            _p(
                AttemptKind.SMUGGLING_BLOCKED,
                RetryRule.NONE,
                (S.COUNT_SMUGGLING,),
                ReasonCode.AUTH_SMUGGLING,
                sent=False,
            ),
            _p(AttemptKind.EGRESS_DISABLED, RetryRule.REROUTE, (), ReasonCode.EGRESS_DISABLED, sent=False),
            _p(AttemptKind.TARGET_REFUSED, RetryRule.NONE, (), ReasonCode.HOST_NOT_ALLOWED, sent=False),
        ]
    )
)
del S

SUCCESS_LIKE: Final = frozenset(
    {AttemptKind.SUCCESS, AttemptKind.NOT_MODIFIED, AttemptKind.REDIRECT, AttemptKind.DEFINITIVE}
)
"""Outcomes where Roblox answered normally: they close a half-open breaker and reset the rotator failure streak."""

FAILURE_KINDS: Final = frozenset(
    {AttemptKind.RATE_LIMITED, AttemptKind.SERVER_ERROR, AttemptKind.TIMEOUT, AttemptKind.CONNECT_ERROR}
)

NEGATIVE_CACHE_STATUSES: Final = frozenset({400, 404, 410})
"""Roblox answers that are cached briefly (plan 7.7); a 403 joins them only when it is not a CSRF challenge."""

_EXCEPTION_KINDS: Final[Mapping[str, AttemptKind]] = MappingProxyType(
    {
        "CredentialLeakBlocked": AttemptKind.LEAK_BLOCKED,
        "AuthSmugglingBlocked": AttemptKind.SMUGGLING_BLOCKED,
        "EgressDisabled": AttemptKind.EGRESS_DISABLED,
        "UpstreamTimeout": AttemptKind.TIMEOUT,
        "UpstreamConnectError": AttemptKind.CONNECT_ERROR,
        "TargetNotAllowed": AttemptKind.TARGET_REFUSED,
    }
)


def has_csrf_token(headers: Mapping[str, str]) -> bool:
    """Whether a response carries a non-empty `x-csrf-token` header (any case)."""
    return any(name.lower() == CSRF_HEADER and bool(value.strip()) for name, value in headers.items())


def classify_response(status: int, headers: Mapping[str, str], *, csrf_retried: bool = False) -> AttemptKind:
    """The kind of an HTTP answer (plan 7.9 and parity row 24)."""
    if 200 <= status < 300:
        return AttemptKind.SUCCESS
    if status == 304:
        return AttemptKind.NOT_MODIFIED
    if 300 <= status < 400:
        return AttemptKind.REDIRECT
    if status == 429:
        return AttemptKind.RATE_LIMITED
    if status == 403 and not csrf_retried and has_csrf_token(headers):
        return AttemptKind.CSRF_CHALLENGE
    if status >= 500:
        return AttemptKind.SERVER_ERROR
    return AttemptKind.DEFINITIVE  # 4xx (and anything odd below 200, which httpx never surfaces)


def classify_exception(exc: BaseException) -> AttemptKind | None:
    """The kind of an exception raised while sending, or None when it is not an upstream problem (a bug)."""
    for cls in type(exc).__mro__:
        kind = _EXCEPTION_KINDS.get(cls.__name__)
        if kind is not None:
            return kind
    if isinstance(exc, httpx.TimeoutException):
        return AttemptKind.TIMEOUT
    if isinstance(exc, httpx.TransportError):
        return AttemptKind.CONNECT_ERROR  # connect, TLS, proxy and protocol errors: Roblox was not reached cleanly
    return None


def policy_for(kind: AttemptKind) -> OutcomePolicy:
    """The 7.9 row for `kind`."""
    return POLICY_TABLE[kind]


def is_negative_cacheable(status: int, headers: Mapping[str, str]) -> bool:
    """Plan 7.7: Roblox 404, 400, 410, and a 403 that is not a CSRF challenge, are cached briefly."""
    if status in NEGATIVE_CACHE_STATUSES:
        return True
    return status == 403 and not has_csrf_token(headers)


def failure_reason_text(status: int) -> str:
    """v1 `_failure_reason` labels (proxy.py:319-330), kept for the failures log (parity rows 72, 117)."""
    if status == 429:
        return "Rate limited (429)"
    if 500 <= status < 600:
        return f"Upstream error ({status})"
    if status == 403:
        return "Forbidden (403)"
    if status == 404:
        return "Not found (404)"
    if 400 <= status < 500:
        return f"Client error ({status})"
    return f"HTTP {status}"


__all__ = [
    "CSRF_HEADER",
    "FAILURE_KINDS",
    "NEGATIVE_CACHE_STATUSES",
    "POLICY_TABLE",
    "SUCCESS_LIKE",
    "AttemptKind",
    "OutcomePolicy",
    "RetryRule",
    "SideEffect",
    "classify_exception",
    "classify_response",
    "failure_reason_text",
    "has_csrf_token",
    "is_negative_cacheable",
    "policy_for",
]
