"""Header sanitization both ways: which caller headers may reach Roblox, and which Roblox headers reach callers.

What this is
    Two allowlists (plan 9.13). Inbound: `forwarded_request_headers(method, headers, body)` returns the only caller
    headers Roxy passes upstream, and `cache_vary_items(...)` returns the same values in the fixed order the cache
    key uses. Outbound: `safe_response_headers(upstream_headers)` returns the only Roblox response headers a caller
    may see.

Why it exists
    v1 used a denylist: every caller header not on a list of 20 names went to Roblox, including `Authorization`,
    `X-Api-Key`, `X-Csrf-Token` and `Accept-Language` (bug B5). None of those were part of the cache key, so one
    caller's header-dependent answer (a localized game name, a token-authorized response) was cached and served
    to everyone. An allowlist cannot grow by accident. The rule that keeps the cache honest: ANY header that is
    forwarded must also vary the cache key, so `FORWARDED_REQUEST_HEADERS` is the single list both use, and
    `cache/keys.py` asserts its vary list equals it. Outbound, `Set-Cookie` and `x-csrf-token` from Roblox could
    carry account state, so they never reach a caller.

How it works
    Inbound, from the caller's lowercased header dict:
    - `accept` only when it is exactly `application/json` or `*/*` (case and surrounding spaces ignored);
      otherwise nothing, and the egress layer sends Roxy's own `Accept`.
    - `content-type` and `content-length` only for methods that carry a body (POST, PUT, PATCH, DELETE).
      Content-Length is computed from the body actually read, never copied from the caller.
    - nothing else: not `Accept-Language` (Roxy always sends `en-US`, so localized text cannot mix in the shared
      cache), not cookies, not authorization, not forwarding headers.
    Outbound: only `Retry-After` and the three `x-ratelimit-*` headers, with printable ASCII values of at most
    256 characters, under their canonical names. `Content-Type` is replayed separately by `respond.py`, and
    `Cache-Control` is always Roxy's own.

What to read next
    `roxy/proxy/respond.py` (where the outbound list is applied), then `roxy/cache/keys.py` (the vary list) and
    `roxy/egress/headers.py` (Roxy's own API-shaped request headers).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

FORWARDED_REQUEST_HEADERS: tuple[str, ...] = ("accept", "content-type", "content-length")
"""Every caller header that may reach Roblox (lowercase). Adding a name here requires adding it to the cache key
in the same change (`cache/keys.py` asserts the two lists are equal)."""

FORWARDABLE_ACCEPT: frozenset[str] = frozenset({"application/json", "*/*"})
BODY_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})
"""Methods whose body (and its Content-Type and Content-Length) is forwarded, as v1 did."""

MAX_HEADER_VALUE = 256
"""Forwarded or relayed header values longer than this are dropped (Roblox never needs longer ones)."""

SAFE_RESPONSE_HEADERS: dict[str, str] = {
    "retry-after": "Retry-After",
    "x-ratelimit-limit": "x-ratelimit-limit",
    "x-ratelimit-remaining": "x-ratelimit-remaining",
    "x-ratelimit-reset": "x-ratelimit-reset",
}
"""Upstream response headers a caller may receive: lowercase name to the name sent (plan 9.13 outbound)."""

NEVER_RELAYED: frozenset[str] = frozenset({"set-cookie", "set-cookie2", "x-csrf-token", "cookie", "authorization"})
"""Named for the tests and the reader: these are dropped like every other unlisted header."""


def is_safe_value(value: str) -> bool:
    """Printable ASCII only (no CR, LF or other control characters) and at most `MAX_HEADER_VALUE` long."""
    return len(value) <= MAX_HEADER_VALUE and all(0x20 <= ord(ch) <= 0x7E for ch in value)


def normalized_accept(value: str | None) -> str | None:
    """The caller's Accept when Roxy forwards it (`application/json` or `*/*`), else None."""
    if value is None:
        return None
    candidate = value.strip().lower()
    return candidate if candidate in FORWARDABLE_ACCEPT else None


def forwarded_request_headers(method: str, headers: Mapping[str, str], body: bytes) -> dict[str, str]:
    """The caller headers Roxy forwards to Roblox (lowercase names), per the plan 9.13 allowlist.

    `headers` is the caller's header dict with lowercase names (`ProxyRequest.headers`).
    """
    forwarded: dict[str, str] = {}
    accept = normalized_accept(headers.get("accept"))
    if accept is not None:
        forwarded["accept"] = accept
    if method.upper() in BODY_METHODS:
        content_type = (headers.get("content-type") or "").strip()
        if content_type and is_safe_value(content_type):
            forwarded["content-type"] = content_type
        forwarded["content-length"] = str(len(body))  # what is actually sent, never the caller's claim
    return forwarded


def cache_vary_items(method: str, headers: Mapping[str, str], body: bytes) -> tuple[tuple[str, str], ...]:
    """The forwarded header values in `FORWARDED_REQUEST_HEADERS` order: the cache key's vary input.

    Built from `forwarded_request_headers`, so a header that is forwarded always varies the key, and a header
    that varies the key is always one that was forwarded.
    """
    forwarded = forwarded_request_headers(method, headers, body)
    return tuple((name, forwarded[name]) for name in FORWARDED_REQUEST_HEADERS if name in forwarded)


def safe_response_headers(
    upstream_headers: Mapping[str, str] | Iterable[tuple[str, str]] | None,
) -> list[tuple[str, str]]:
    """The upstream response headers a caller may see, under canonical names, in the order received.

    Accepts a mapping (including `httpx.Headers`) or (name, value) pairs. Only the first copy of each name is
    kept; values that are not printable ASCII are dropped.
    """
    if upstream_headers is None:
        return []
    items: Iterable[tuple[str, str]]
    if isinstance(upstream_headers, Mapping):
        items = upstream_headers.items()
    else:
        items = upstream_headers
    kept: list[tuple[str, str]] = []
    seen: set[str] = set()
    for name, value in items:
        lowered = str(name).lower()
        canonical = SAFE_RESPONSE_HEADERS.get(lowered)
        if canonical is None or lowered in seen:
            continue
        text = str(value).strip()
        if not text or not is_safe_value(text):
            continue
        seen.add(lowered)
        kept.append((canonical, text))
    return kept
