"""Check 15, auth smuggling: refuse requests that carry the caller's own Roblox login or API key (plan 4.1 row 9).

What this is
    `AuthSmugglingCheck`, `inspect_auth_attempt` (what was sent, where, and whether it looks like a real cookie)
    and `detect_auth_attempt` (the v1 style reason string only). It looks for the public markers of a Roblox login
    (the `TOKEN_PREFIX` warning text every `.ROBLOSECURITY` value starts with, the `.ROBLOSECURITY` and `.RBXID`
    cookie names) and for the headers that carry an Open Cloud API key or an OAuth or bearer token.

Why it exists
    Roxy sends requests with its OWN Roblox account (D1 revised 2026-10-16) and never with a caller's. A caller who
    sends their own cookie or key is either confused about the service or trying to make Roxy act as them, and
    their answer could be cached for everyone. Either way the request is refused, and recorded on the Endpoint
    policy page (Caller sign-in attempts) so the owner can see who leaks their own secrets by mistake. v1 refused an
    `X-Roblox-Token` header or a header value containing the prefix; v2 also scans the query string, cookie names
    and the body (up to `max_body_bytes`) (plan C2 item 5), and refuses `Authorization`, `Proxy-Authorization`,
    `X-Api-Key`, `X-Api-Token` and `Api-Key`. These are refusals, never leak-guard trips: anyone can type the
    public markers, so they must never be able to switch an egress off.

How it works
    In order: an `X-Roblox-Token` header (any value); an API key or authorization header (any value); a header
    value containing either login marker (`"<Name>" header carried a ROBLOSECURITY-shaped value`, v1 text); a
    cookie named `.ROBLOSECURITY` or `.RBXID`; the markers in a query name or value; the markers in the body (raw,
    and percent-decoded when it has `%` or `+`). Matching is case-insensitive. 400 with
    `messages.AUTH_SMUGGLING`, tarpit category `auth_attempt`, counted by SPAM-AUTH. Bypass does not skip it.
    `AuthAttempt.value` is the secret itself, kept only in memory for the keyed fingerprint the recorder computes
    (`metrics/recorder.py record_auth_attempt`); it is never logged, stored or returned.

What to read next
    `roxy/core/redact.py` (`TOKEN_PREFIX`), `roxy/abuse/checks/endpoint_policy.py`, then
    `roxy/abuse/checks/header_rules.py`.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Final
from urllib.parse import unquote_plus

from roxy.abuse.checks.base import Check, Facts, LimitSpec, refusal_headers
from roxy.abuse.messages import (
    AUTH_SMUGGLING,
    REASON_AUTH_API_KEY,
    REASON_AUTH_BODY,
    REASON_AUTH_COOKIE_NAME,
    REASON_AUTH_HEADER_VALUE,
    REASON_AUTH_QUERY,
    REASON_AUTH_TOKEN_HEADER,
)
from roxy.abuse.verdict import Refuse, title_case_header
from roxy.core.reasons import ReasonCode
from roxy.core.redact import ROBLOX_COOKIE_NAME, TOKEN_PREFIX
from roxy.core.scope import catalog_default

_PREFIX: Final = TOKEN_PREFIX.lower()
_COOKIE: Final = ROBLOX_COOKIE_NAME.lower()
_COOKIE_ASSIGN: Final = _COOKIE + "="
SIGN_IN_COOKIES: Final = frozenset({_COOKIE, ".rbxid"})
"""Cookie names that carry a Roblox sign-in: the session cookie and Roblox's other sign-in cookie."""
KEY_HEADERS: Final = frozenset({"authorization", "proxy-authorization", "x-api-key", "x-api-token", "api-key"})
"""Headers that carry an Open Cloud API key or an OAuth or bearer token (any value is refused)."""
MIN_REAL_COOKIE_CHARS: Final = 100
"""A value with the warning prefix and at least this many characters after it looks like a real session cookie."""


@dataclass(frozen=True, slots=True)
class AuthAttempt:
    """What a caller sent. `value` is the secret itself: memory only, for the fingerprint, never stored."""

    reason: str  # the v1 style reason (Refuse.detail)
    kind: str  # roblosecurity, api_key, bearer, x_roblox_token
    where: str  # "header", "cookie", "query" or "body"
    name: str = ""  # the header, cookie or query parameter name ("" for the body)
    looks_real: bool = False
    value: str = field(default="", repr=False)


def _has_marker(text: str) -> bool:
    lowered = text.lower()
    return _PREFIX in lowered or _COOKIE_ASSIGN in lowered


def _looks_real(text: str) -> bool:
    lowered = text.lower()
    at = lowered.find(_PREFIX)
    if at < 0:
        return False
    tail = text[at + len(_PREFIX) :]
    for stop in ";&\"' \t\r\n,":
        tail = tail.split(stop, 1)[0]
    return len(tail) >= MIN_REAL_COOKIE_CHARS


def _cookies(cookie_header: str) -> Iterable[tuple[str, str]]:
    for part in cookie_header.split(";"):
        name, _, value = part.partition("=")
        if name.strip():
            yield name.strip(), value.strip()


def _key_kind(name: str, value: str) -> str:
    if name in ("authorization", "proxy-authorization") and value.strip().lower().startswith("bearer"):
        return "bearer"
    return "api_key"


def inspect_auth_attempt(req: Any, max_body_bytes: int | None = None) -> AuthAttempt | None:
    """What sign-in the request carries, or None (module docstring for the order).

    `max_body_bytes` bounds the body scan; None reads the catalog default of the `max_body_bytes` setting (the
    check passes the live value).
    """
    if max_body_bytes is None:
        max_body_bytes = int(catalog_default("max_body_bytes") or 0)
    headers: dict[str, str] = getattr(req, "headers", {}) or {}
    names = list(getattr(req, "header_names_in_order", None) or headers)
    for name in names:
        lower = name.lower()
        value = str(headers.get(lower, headers.get(name, "")) or "")
        if lower == "x-roblox-token":
            return AuthAttempt(REASON_AUTH_TOKEN_HEADER, "x_roblox_token", "header", lower, _looks_real(value), value)
        if lower in KEY_HEADERS:
            reason = REASON_AUTH_API_KEY.format(name=title_case_header(name))
            return AuthAttempt(reason, _key_kind(lower, value), "header", lower, _looks_real(value), value)
    for name in names:
        lower = name.lower()
        value = str(headers.get(lower, headers.get(name, "")) or "")
        if value and _has_marker(value):
            reason = REASON_AUTH_HEADER_VALUE.format(name=title_case_header(name))
            where = "cookie" if lower == "cookie" else "header"
            return AuthAttempt(reason, "roblosecurity", where, lower, _looks_real(value), value)
    for cookie, value in _cookies(str(headers.get("cookie", "") or "")):
        if cookie.lower() in SIGN_IN_COOKIES:
            real = _looks_real(value) or (cookie.lower() == _COOKIE and len(value) >= MIN_REAL_COOKIE_CHARS)
            return AuthAttempt(REASON_AUTH_COOKIE_NAME, "roblosecurity", "cookie", cookie.lower()[:64], real, value)
    for key, value in getattr(req, "query", None) or ():
        if key.lower() in SIGN_IN_COOKIES or _has_marker(key) or _has_marker(value):
            return AuthAttempt(REASON_AUTH_QUERY, "roblosecurity", "query", key.lower()[:64], _looks_real(value), value)
    body: bytes = getattr(req, "body", b"") or b""
    if body:
        text = body[: max(0, int(max_body_bytes))].decode("latin-1")
        candidates = [text]
        if "%" in text or "+" in text:
            candidates.append(unquote_plus(text, encoding="latin-1"))
        for candidate in candidates:
            lowered = candidate.lower()
            if _PREFIX in lowered or _COOKIE in lowered:
                return AuthAttempt(REASON_AUTH_BODY, "roblosecurity", "body", "", _looks_real(candidate), candidate)
    return None


def detect_auth_attempt(req: Any, max_body_bytes: int | None = None) -> str | None:
    """The v1 style reason string when the request carries a sign-in, else None (see `inspect_auth_attempt`)."""
    attempt = inspect_auth_attempt(req, max_body_bytes)
    return None if attempt is None else attempt.reason


class AuthSmugglingCheck(Check):
    name = "auth_smuggling"
    position = 140
    label = "Auth smuggling"
    tarpit_category = "auth_attempt"

    def prepare(self, req: Any, facts: Facts) -> Refuse | LimitSpec | None:
        reason = detect_auth_attempt(req, facts.int("max_body_bytes"))
        if reason is None:
            return None
        return Refuse(
            status=400,
            body=AUTH_SMUGGLING,
            reason=ReasonCode.AUTH_SMUGGLING,
            check=self.name,
            headers=refusal_headers(ReasonCode.AUTH_SMUGGLING),
            tarpit_category=self.tarpit_category,
            detail=reason,
        )


__all__ = [
    "KEY_HEADERS",
    "SIGN_IN_COOKIES",
    "AuthAttempt",
    "AuthSmugglingCheck",
    "detect_auth_attempt",
    "inspect_auth_attempt",
]
