"""Check 15, auth smuggling: refuse requests that try to carry a Roblox login through the proxy (plan 4.1 row 9).

What this is
    `AuthSmugglingCheck` and `detect_auth_attempt`, which looks for the two public markers of a Roblox login: the
    `TOKEN_PREFIX` warning text every `.ROBLOSECURITY` value starts with, and the `.ROBLOSECURITY` cookie name.

Why it exists
    Roxy is an anonymous proxy. A caller who sends their own cookie would make Roxy perform authenticated actions
    as them, and their answer could be cached for everyone. v1 refused an `X-Roblox-Token` header or a header value
    containing the prefix; v2 also scans the query string, cookie names and the body (up to `max_body_bytes`)
    (plan C2 item 5). These are refusals, never leak-guard trips: anyone can type the public markers, so they must
    never be able to switch an egress off.

How it works
    In order: any `X-Roblox-Token` header (any value) -> `X-Roblox-Token header`; a header value containing either
    marker -> `"<Name>" header carried a ROBLOSECURITY-shaped value` (v1 texts); a cookie named `.ROBLOSECURITY`;
    the markers in a query name or value; the markers in the body (raw, and percent-decoded when it has `%`).
    Matching is case-insensitive. 400 with v1's text, tarpit category `auth_attempt`, counted by SPAM-AUTH. Bypass
    does not skip it.

What to read next
    `roxy/core/redact.py` (`TOKEN_PREFIX`), then `roxy/abuse/checks/header_rules.py`.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Final
from urllib.parse import unquote_plus

from roxy.abuse.checks.base import Check, Facts, LimitSpec, refusal_headers
from roxy.abuse.messages import (
    AUTH_SMUGGLING,
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


def _has_marker(text: str) -> bool:
    lowered = text.lower()
    return _PREFIX in lowered or _COOKIE_ASSIGN in lowered


def _cookie_names(cookie_header: str) -> Iterable[str]:
    for part in cookie_header.split(";"):
        name = part.split("=", 1)[0].strip()
        if name:
            yield name


def detect_auth_attempt(req: Any, max_body_bytes: int | None = None) -> str | None:
    """The v1 style reason string when the request carries a Roblox login marker, else None.

    `max_body_bytes` bounds the body scan; None reads the catalog default of the `max_body_bytes` setting (the
    check passes the live value).
    """
    if max_body_bytes is None:
        max_body_bytes = int(catalog_default("max_body_bytes") or 0)
    headers: dict[str, str] = getattr(req, "headers", {}) or {}
    names = list(getattr(req, "header_names_in_order", None) or headers)
    for name in names:
        lower = name.lower()
        if lower == "x-roblox-token":
            return REASON_AUTH_TOKEN_HEADER
        value = str(headers.get(lower, headers.get(name, "")) or "")
        if value and _has_marker(value):
            return REASON_AUTH_HEADER_VALUE.format(name=title_case_header(name))
    for cookie in _cookie_names(str(headers.get("cookie", "") or "")):
        if cookie.lower() == _COOKIE:
            return REASON_AUTH_COOKIE_NAME
    for key, value in getattr(req, "query", None) or ():
        if key.lower() == _COOKIE or _has_marker(key) or _has_marker(value):
            return REASON_AUTH_QUERY
    body: bytes = getattr(req, "body", b"") or b""
    if body:
        text = body[: max(0, int(max_body_bytes))].decode("latin-1")
        if _PREFIX in text.lower() or _COOKIE in text.lower():
            return REASON_AUTH_BODY
        if "%" in text or "+" in text:
            decoded = unquote_plus(text, encoding="latin-1").lower()
            if _PREFIX in decoded or _COOKIE in decoded:
                return REASON_AUTH_BODY
    return None


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


__all__ = ["AuthSmugglingCheck", "detect_auth_attempt"]
