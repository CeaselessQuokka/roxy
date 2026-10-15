"""Egress data shapes: what the upstream layer hands to `EgressClients.send` and what it gets back.

What this is
    `OutboundRequest` (one upstream call to make), `EgressResponse` (what came back, with byte counts), the
    purpose names Roxy uses for its own calls, and `SelfTestResult` (the shape of the H-CRED-GUARD and
    H-ENV-PROXY health check answers).

Why it exists
    DESIGN.md 11.4 pins these two dataclasses as the contract between the upstream agent and the egress agent.
    Keeping them in their own small module lets every egress submodule import them without import cycles.

How it works
    Plain dataclasses. Fields after the DESIGN.md ones have defaults, so code written against the contract keeps
    working: `follow_redirects` (plan 7.9: 3xx followed manually within the allowlist, on by default) and
    `identity` (the stable key the User-Agent experiment splits direct traffic by, usually the cache key id).

What to read next
    `roxy/egress/clients.py` (`EgressClients.send`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

import httpx

from roxy.core.reasons import Egress

PURPOSE_CALLER = "caller"
"""A caller's proxied request (the default purpose)."""

PURPOSE_CREDENTIAL_PROBE = "credential_probe"
"""Roxy's own liveness or health probe of the credential (uses the reserved probe sub-bucket, plan 7.3)."""

PURPOSE_EXIT_IP_PROBE = "exit_ip_probe"
"""The rotator exit IP check (the only call allowed to a non-Roblox host: the configured IP echo service)."""

CREDENTIAL_PROBE_PURPOSES = frozenset(
    {PURPOSE_CREDENTIAL_PROBE, "health_check_credential", "token_validate", "token_check"}
)
"""Purposes that count as a credential probe: allowed while the credential status is still `unknown` (a probe is
how it becomes `active`), never while it is cooling down."""


@dataclass(slots=True)
class OutboundRequest:
    """One upstream call to make through an egress (DESIGN.md 11.4).

    `headers` are the extra headers the upstream layer wants on top of the egress header profile (for example
    `Content-Type` for a body, or `x-csrf-token` on a CSRF retry). `Cookie`, `Authorization`, `Host` and
    hop-by-hop headers are always dropped: only `egress/credential.py` may add a cookie.
    """

    method: str
    url: str
    headers: dict[str, str]
    content: bytes | None
    timeout: httpx.Timeout
    purpose: str = PURPOSE_CALLER
    session_id: str | None = None
    follow_redirects: bool = True
    identity: str | None = None


@dataclass(slots=True)
class EgressResponse:
    """What one `EgressClients.send` returned (DESIGN.md 11.4), after any followed redirects.

    `body` is decoded (gzip, deflate, br). `bytes_out` and `bytes_in` are wire bytes (TLS and the proxy CONNECT
    included) when socket metering is active, otherwise the fallback estimate (`metering` says which).
    `Set-Cookie` headers are never included.
    """

    status: int
    headers: httpx.Headers
    body: bytes
    elapsed_ms: float
    bytes_out: int
    bytes_in: int
    egress: Egress
    session_id: str | None
    http_version: str
    url: str = ""
    redirects: int = 0
    metering: str = "socket"
    new_connections: int = 0


SelfTestStatus = Literal["pass", "warn", "fail"]


@dataclass(frozen=True, slots=True)
class SelfTestResult:
    """The answer of an egress self-test, in the shape the health check (plan 13.2) stores."""

    check_id: str
    status: SelfTestStatus
    value: str
    detail: str
    facts: dict[str, object] = field(default_factory=dict)


__all__ = [
    "CREDENTIAL_PROBE_PURPOSES",
    "PURPOSE_CALLER",
    "PURPOSE_CREDENTIAL_PROBE",
    "PURPOSE_EXIT_IP_PROBE",
    "EgressResponse",
    "OutboundRequest",
    "SelfTestResult",
]
