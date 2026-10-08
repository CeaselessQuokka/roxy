"""The egress contract as the upstream package sees it (DESIGN.md 11.4), plus small adapters.

What this is
    `OutboundRequest` (the request upstream hands to an egress client), the `EgressPort` protocol (what upstream
    calls on `ctx.egress`), and helpers that read the credential manager and rotator pool defensively, since parts
    of their API may be sync or async.

Why it exists
    The egress package (three clients, the leak guard, the rotator pool, the credential slot) is built by another
    specialist at the same time. Coding against a protocol keeps the two packages independent: tests use a fake
    that satisfies it, and production passes `EgressClients`. `OutboundRequest` mirrors the contract's fields
    exactly; if the egress package exports its own class with those fields, either works (egress reads the
    attributes, never the class).

How it works
    - `send(egress, out)` returns an object with `status`, `headers` (an `httpx.Headers` or any mapping), `body`,
      `elapsed_ms`, `bytes_out`, `bytes_in`, `session_id`; it raises `CredentialLeakBlocked`,
      `AuthSmugglingBlocked`, `EgressDisabled`, `UpstreamTimeout` or `UpstreamConnectError` (`status.py` maps them
      by class name, so subclasses such as the egress package's `CredentialUnavailable` work too).
    - The egress adds its API-shaped header profile per identity itself; `out.headers` carries only upstream's
      extras. `follow_redirects` is False: upstream follows 3xx itself so every hop takes a bucket slot.
    - `is_enabled(egress, purpose=...)` gives `(enabled, reason)`: the admin switch, a leak-guard trip, the rotator
      park and quota stop, the credential status. Rotator health (the failure streak that parks it, parity row 31)
      is the egress package's job, because it sees every rotator call.
    - `maybe_await` lets the same code call a method whether the implementation made it a coroutine or not.

What to read next
    `roxy/egress/clients.py` (the real implementation) and `roxy/upstream/service.py` (the caller).
"""

from __future__ import annotations

import importlib
import inspect
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from roxy.core.reasons import Egress

PURPOSE_CREDENTIAL_PROBE = "credential_probe"
"""The egress purpose of Roxy's own credential calls: the egress lets a probe through while the credential status
is still `unknown` (a probe is how it becomes `active`), never while it is cooling down."""


@dataclass(slots=True)
class OutboundRequest:
    """One HTTP call for an egress client (DESIGN.md 11.4, field for field, plus the egress package's two optional
    fields). `headers` are only the extras upstream wants (Content-Type for a body, a forwarded Accept, the CSRF
    token): the egress adds its own header profile for the identity."""

    method: str
    url: str
    headers: dict[str, str]
    content: bytes | None
    timeout: httpx.Timeout
    purpose: str
    session_id: str | None = None
    follow_redirects: bool = False  # upstream follows 3xx itself, so every hop takes a bucket slot (plan 7.3)
    identity: str | None = None  # the stable key the User-Agent experiment splits direct traffic by


class EgressResponseLike(Protocol):
    """The fields of `EgressResponse` that upstream reads."""

    status: int
    headers: Mapping[str, str]
    body: bytes
    elapsed_ms: float
    bytes_out: int
    bytes_in: int


class EgressPort(Protocol):
    """What `ctx.egress` must provide (DESIGN.md 11.4)."""

    credential: Any
    rotator: Any
    headers: Any

    async def send(self, egress: Egress, out: OutboundRequest) -> Any: ...

    def is_enabled(self, egress: Egress) -> tuple[bool, str]: ...


async def maybe_await(value: Any) -> Any:
    """`await value` if it is awaitable, else return it as is."""
    if inspect.isawaitable(value):
        return await value
    return value


async def call_optional(target: Any, name: str, *args: Any, default: Any = None) -> Any:
    """Call `target.name(*args)` (sync or async) if it exists; `default` when it does not or `target` is None."""
    method = getattr(target, name, None) if target is not None else None
    if method is None or not callable(method):
        return default
    return await maybe_await(method(*args))


def enabled(egress_port: Any, egress: Egress, purpose: str | None = None) -> tuple[bool, str]:
    """`is_enabled(egress)` (with the call's purpose when the egress accepts one), safe when there is no egress."""
    if egress_port is None:
        return False, "egress clients are not configured"
    try:
        if purpose is None:
            result = egress_port.is_enabled(egress)
        else:
            try:
                result = egress_port.is_enabled(egress, purpose=purpose)
            except TypeError:  # an implementation of the bare contract takes no purpose
                result = egress_port.is_enabled(egress)
    except Exception as exc:  # an egress bug must not take the request path down with it
        return False, f"is_enabled failed: {type(exc).__name__}"
    if isinstance(result, tuple) and result:
        return bool(result[0]), str(result[1]) if len(result) > 1 else ""
    return bool(result), ""


@dataclass(frozen=True, slots=True)
class CredentialView:
    """What routing needs to know about the one credential (plan C1)."""

    usable: bool  # enabled, configured, not rejected, not cooling down
    rejected: bool
    cooldown_s: float


async def credential_view(egress_port: Any, *, setting_enabled: bool) -> CredentialView:
    """Ask the credential manager whether the credential may be used now. Any doubt means "no" (C7)."""
    if not setting_enabled or egress_port is None:
        return CredentialView(False, False, 0.0)
    manager = getattr(egress_port, "credential", None)
    try:
        status = await call_optional(manager, "status")
        text = str(getattr(status, "status", status) or "").lower()
        rejected = text == "rejected"
        available = await call_optional(manager, "available", default=False)
        cooldown = await call_optional(manager, "cooldown_remaining", default=0.0)
        cooldown_s = float(cooldown or 0.0)
    except Exception:
        return CredentialView(False, False, 0.0)
    on, _reason = enabled(egress_port, Egress.CREDENTIAL)
    return CredentialView(bool(available) and on and not rejected and cooldown_s <= 0, rejected, max(0.0, cooldown_s))


def egress_error(name: str, *args: Any) -> Exception:
    """An instance of the egress package's exception `name` (for `ProbeFetch` callers that catch them), or a
    plain RuntimeError when the egress package is not installed."""
    try:
        module = importlib.import_module("roxy.egress.errors")
        cls = getattr(module, name)
        error = cls(*args)
    except (ImportError, AttributeError, TypeError):
        return RuntimeError(f"{name}: {args}")
    return error if isinstance(error, Exception) else RuntimeError(name)


__all__ = [
    "PURPOSE_CREDENTIAL_PROBE",
    "CredentialView",
    "EgressPort",
    "EgressResponseLike",
    "OutboundRequest",
    "call_optional",
    "credential_view",
    "egress_error",
    "enabled",
    "maybe_await",
]
