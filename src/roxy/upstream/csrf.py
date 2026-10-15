"""The Roblox CSRF handshake, with tokens cached per egress identity in hot.db.

What this is
    Helpers for Roblox's CSRF protection: which requests need a token, how to read one from a 403 response, and a
    small shared cache (`csrf_cache` in hot.db) keyed by egress identity (`direct`, `credential`, or a rotator
    session), so a known token is sent up front instead of paying a 403 round trip on every write call.

Why it exists
    Roblox answers a state-changing call (POST, PATCH, PUT, DELETE) without a valid `x-csrf-token` header with
    403 plus a fresh token in the `x-csrf-token` response header; the client must repeat the call with that token.
    v1 did the dance on every call and did not count the retry against its budget (plan 2.5: CSRF retries are real
    calls). Parity row 23: v2 keeps exactly one CSRF retry per attempt, counts it against the buckets, and caches
    the token for `csrf_token_cache_s` (600 s; 0 disables the cache).

How it works
    - `needs_token(method)` is true for the write methods. Only those ever carry a cached token.
    - A token is identity-scoped: the credential's token belongs to the account session and must never be sent on
      an anonymous path, and each rotator session is its own client as far as Roblox can tell.
    - Rows carry `expires_at` (wall clock seconds). Every store prunes expired rows and keeps the table under
      `MAX_CACHED_TOKENS` rows (oldest expiry first), so it stays bounded (plan P9) even in the rotator's
      per-request session mode, where identities are many and short-lived.
    - Tokens are secrets of a kind (they authorize writes for the session), so they are never logged, never put in
      a trace (redaction drops the header), and never relayed to callers (the safe response header list).

What to read next
    `roxy/upstream/status.py` (`CSRF_CHALLENGE`), `roxy/upstream/service.py` (`_exchange`, where the retry happens).
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Mapping
from typing import Final

from roxy.core.reasons import Egress
from roxy.upstream.status import CSRF_HEADER

WRITE_METHODS: Final = frozenset({"POST", "PUT", "PATCH", "DELETE"})
MAX_CACHED_TOKENS: Final = 256
MAX_TOKEN_LENGTH: Final = 256
_TOKEN_RE = re.compile(r"[\x21-\x7e]{1,256}")  # printable ASCII, no spaces: what a header value token looks like


def needs_token(method: str) -> bool:
    """Whether Roblox expects a CSRF token on this method."""
    return method.upper() in WRITE_METHODS


def egress_identity(egress: Egress, session_id: str | None = None) -> str:
    """The cache key: `direct`, `credential`, or `rotator:<session>` (`rotator` without a session)."""
    if egress is Egress.ROTATOR and session_id:
        return f"rotator:{session_id}"[:200]
    return egress.value


def token_from(headers: Mapping[str, str]) -> str | None:
    """The `x-csrf-token` value of a response, if it looks like a token."""
    for name, value in headers.items():
        if name.lower() == CSRF_HEADER:
            token = value.strip()
            return token if _TOKEN_RE.fullmatch(token) else None
    return None


def read_token(conn: sqlite3.Connection, identity: str, now_s: float) -> str | None:
    """The cached token for `identity`, if one exists and has not expired."""
    row = conn.execute(
        "SELECT token FROM csrf_cache WHERE egress_identity = ? AND expires_at > ?", (identity, now_s)
    ).fetchone()
    return None if row is None else str(row[0])


def store_token(conn: sqlite3.Connection, identity: str, token: str, ttl_s: float, now_s: float) -> None:
    """Cache `token` for `identity` for `ttl_s` seconds, pruning expired rows and keeping the table bounded."""
    if ttl_s <= 0 or not _TOKEN_RE.fullmatch(token):
        return
    conn.execute(
        "INSERT INTO csrf_cache (egress_identity, token, expires_at) VALUES (?, ?, ?) "
        "ON CONFLICT(egress_identity) DO UPDATE SET token = excluded.token, expires_at = excluded.expires_at",
        (identity, token, now_s + ttl_s),
    )
    conn.execute(
        "DELETE FROM csrf_cache WHERE egress_identity IN "
        "(SELECT egress_identity FROM csrf_cache WHERE expires_at <= ? LIMIT 64)",
        (now_s,),
    )
    count = int(conn.execute("SELECT count(*) FROM csrf_cache").fetchone()[0])
    if count > MAX_CACHED_TOKENS:
        conn.execute(
            "DELETE FROM csrf_cache WHERE egress_identity IN "
            "(SELECT egress_identity FROM csrf_cache ORDER BY expires_at ASC LIMIT ?)",
            (count - MAX_CACHED_TOKENS,),
        )


def forget_token(conn: sqlite3.Connection, identity: str) -> None:
    """Drop the cached token (Roblox rejected it: the retry got a CSRF 403 again)."""
    conn.execute("DELETE FROM csrf_cache WHERE egress_identity = ?", (identity,))


__all__ = [
    "MAX_CACHED_TOKENS",
    "WRITE_METHODS",
    "egress_identity",
    "forget_token",
    "needs_token",
    "read_token",
    "store_token",
    "token_from",
]
