"""CSRF protection: a per-session synchronizer token, XOR-masked per response (BREACH), plus same-origin checks.

What this is
    `mask(secret)` and `unmask(text)` for the token, `same_origin_problem(request, site_origin)` for the
    `Origin` and `Sec-Fetch-Site` headers, and `check(request, secret, site_origin)` which combines them. The
    FastAPI dependency `require_csrf` (in `deps.py`) calls `check` on every state-changing admin request.

Why it exists
    CSRF (cross-site request forgery): another site makes the admin's browser send a request to Roxy, and the
    browser attaches the admin's cookie. v1 had no CSRF token at all (dashboard notes bug 32). Plan 9.6 adds two
    independent defenses:
      * A synchronizer token: a secret tied to the session that the dashboard sends back in the `X-CSRF-Token`
        header. Another site can make the browser send the cookie, but cannot read Roxy's pages, so it cannot
        know the token.
      * Same-origin headers: browsers add `Origin` and `Sec-Fetch-Site` to requests and scripts cannot forge
        them. A state-changing request must come from Roxy's own origin.
    BREACH is an attack on compressed HTTPS pages: if a page contains both a secret and text the attacker can
    choose (a search term reflected in the page), the compressed SIZE leaks whether the attacker's guess matches
    part of the secret, one character at a time. The defense is to never send the same token bytes twice: every
    response embeds `pad + (token XOR pad)` with a fresh random pad, so the bytes differ every time and nothing
    repeats for compression to find, while the server can still recover the token (`unmask`). nginx also turns
    gzip off under `/admin` (defense in depth, plan 9.6).

How it works
    - The secret itself is `sessions.csrf_secret(session id)`, 32 bytes.
    - `mask` returns URL-safe base64 of 64 bytes: a random 32-byte pad followed by the XOR.
    - `check` fails (HTTP 403) when the header is missing or malformed, when the unmasked value differs from the
      session's secret (constant-time comparison), when `Origin` is present and is not `ROXY_SITE_ORIGIN`, when
      `Sec-Fetch-Site` is present and is not `same-origin`, or when NEITHER header is present (a browser always
      sends at least one of them on a state-changing request).

What to read next
    `roxy/admin/auth/deps.py` (`require_csrf`), then `roxy/admin/auth/sessions.py` (`csrf_secret`).
"""

from __future__ import annotations

import base64
import binascii
import hmac
import secrets

from starlette.requests import Request

CSRF_HEADER = "X-CSRF-Token"
SECRET_BYTES = 32
_MAX_HEADER_CHARS = 200


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(text: str) -> bytes | None:
    if not text or len(text) > _MAX_HEADER_CHARS or not text.isascii():
        return None
    padded = text + "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError):
        return None


def mask(secret: bytes) -> str:
    """A fresh masked form of `secret`: `base64url(pad + (secret XOR pad))` with a new random pad."""
    pad = secrets.token_bytes(len(secret))
    return _b64encode(pad + bytes(a ^ b for a, b in zip(secret, pad, strict=True)))


def unmask(text: str) -> bytes | None:
    """The secret inside a masked token, or None when the text is not a well-formed masked token."""
    raw = _b64decode(text.strip()) if isinstance(text, str) else None
    if raw is None or len(raw) != 2 * SECRET_BYTES:
        return None
    pad, masked = raw[:SECRET_BYTES], raw[SECRET_BYTES:]
    return bytes(a ^ b for a, b in zip(masked, pad, strict=True))


def same_origin_problem(request: Request, site_origin: str) -> str | None:
    """Why the request does not look same-origin, or None when it does (plan 9.4, 9.6)."""
    origin = request.headers.get("origin")
    fetch_site = request.headers.get("sec-fetch-site")
    if origin is not None and origin.rstrip("/") != site_origin.rstrip("/"):
        return "origin_mismatch"
    if fetch_site is not None and fetch_site.strip().lower() != "same-origin":
        return "cross_site_fetch"
    if origin is None and fetch_site is None:
        return "no_origin_headers"
    return None


def foreign_origin(request: Request, site_origin: str) -> bool:
    """True when an `Origin` header is present and is not Roxy's (plan 9.4: rejected on every admin API call)."""
    origin = request.headers.get("origin")
    return origin is not None and origin.rstrip("/") != site_origin.rstrip("/")


def check(request: Request, secret: bytes, site_origin: str) -> str | None:
    """None when the request passes every CSRF rule, else a short reason (the caller answers 403)."""
    problem = same_origin_problem(request, site_origin)
    if problem is not None:
        return problem
    header = request.headers.get(CSRF_HEADER)
    if header is None:
        return "missing_token"
    candidate = unmask(header)
    if candidate is None:
        return "malformed_token"
    if not hmac.compare_digest(candidate, secret):
        return "wrong_token"
    return None
