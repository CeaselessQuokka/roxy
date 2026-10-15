"""Egress exceptions: the closed set of ways an outgoing request can fail before or instead of reaching Roblox.

What this is
    `EgressError` and its subclasses. `EgressClients.send` raises exactly these (DESIGN.md 11.4):
    `CredentialLeakBlocked`, `AuthSmugglingBlocked`, `EgressDisabled` (and its subclass `CredentialUnavailable`),
    `UpstreamTimeout`, `UpstreamConnectError`, plus `TargetNotAllowed` for a URL that fails the egress host check.
    `EgressConfigError` is a startup problem (for example a test-only variable set in production).

Why it exists
    The upstream layer maps every failure to one row of the plan 7.13 table. Typed exceptions that each carry
    their `ReasonCode` make that mapping a lookup instead of string matching, and keep library exceptions
    (httpx, httpcore, anyio) from leaking past the egress boundary.

How it works
    Every exception stores the egress it happened on and a short, secret-free `detail`. None of them ever holds
    request content: a leak exception names WHERE the credential was found (`header:cookie`, `url`, `body`),
    never what was found. `reason` gives the `ReasonCode` for metrics and the `Roxy-Refusal` header.

What to read next
    `roxy/egress/guard.py` (raises the two blocked exceptions) and `roxy/egress/clients.py` (maps httpx errors).
"""

from __future__ import annotations

from roxy.core.reasons import Egress, ReasonCode


class EgressConfigError(RuntimeError):
    """The egress layer cannot start safely (a startup error, never a per-request one)."""


class EgressError(Exception):
    """Base class for every per-request egress failure."""

    reason: ReasonCode = ReasonCode.INTERNAL_ERROR

    def __init__(self, egress: Egress, detail: str = "") -> None:
        self.egress = egress
        self.detail = detail[:200]
        super().__init__(f"{type(self).__name__} on {egress.value}" + (f": {self.detail}" if self.detail else ""))


class CredentialLeakBlocked(EgressError):
    """An anonymous request carried the credential (or a 24+ character piece of it). It was not sent.

    `location` says where it was found (`url`, `header:<name>`, `body`); the matched text is never kept.
    """

    reason = ReasonCode.LEAK_BLOCKED

    def __init__(self, egress: Egress, location: str) -> None:
        self.location = location[:80]
        super().__init__(egress, f"credential found in {self.location}; request not sent")


class AuthSmugglingBlocked(EgressError):
    """An anonymous request carried a public auth marker (`TOKEN_PREFIX`, `.ROBLOSECURITY`) or an uninspectable
    body. It was not sent; the egress stays enabled (plan C2 item 5)."""

    reason = ReasonCode.AUTH_SMUGGLING

    def __init__(self, egress: Egress, marker: str, location: str) -> None:
        self.marker = marker
        self.location = location[:80]
        super().__init__(egress, f"{marker} in {self.location}; request not sent")


class EgressDisabled(EgressError):
    """The egress is switched off (admin setting, leak guard trip, quota stop, rotator parked, not configured)."""

    reason = ReasonCode.EGRESS_DISABLED

    def __init__(self, egress: Egress, why: str, retry_after_s: int | None = None) -> None:
        self.why = why
        self.retry_after_s = retry_after_s
        super().__init__(egress, why)


class CredentialUnavailable(EgressDisabled):
    """The credential may not be used right now: absent, disabled, rejected, cooling down, not yet confirmed, or
    shared state is unreadable (plan C7: then it is never used). A subclass of `EgressDisabled` so callers that
    catch the contract's exception also catch this one."""

    reason = ReasonCode.CREDENTIAL_UNAVAILABLE

    def __init__(self, why: str, retry_after_s: int | None = None) -> None:
        super().__init__(Egress.CREDENTIAL, why, retry_after_s)
        if why == "degraded":
            self.reason = ReasonCode.DEGRADED


class TargetNotAllowed(EgressError):
    """The URL failed the egress host check (not https, not an allowed Roblox host, userinfo, odd port)."""

    reason = ReasonCode.HOST_NOT_ALLOWED


class UpstreamTimeout(EgressError):
    """Roblox (or the rotator) did not answer within the read, write or pool timeout."""

    reason = ReasonCode.UPSTREAM_TIMEOUT


class UpstreamConnectError(EgressError):
    """The connection could not be made or broke (DNS, TCP, TLS, proxy refusal, protocol error, oversize body)."""

    reason = ReasonCode.UPSTREAM_CONNECT


__all__ = [
    "AuthSmugglingBlocked",
    "CredentialLeakBlocked",
    "CredentialUnavailable",
    "EgressConfigError",
    "EgressDisabled",
    "EgressError",
    "TargetNotAllowed",
    "UpstreamConnectError",
    "UpstreamTimeout",
]
