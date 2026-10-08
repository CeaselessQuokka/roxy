"""The emailed kill switch: a one-time link that signs out admin sessions and can revoke trusted devices.

What this is
    `mint` makes the token for the login alert email's link (`<ROXY_SITE_ORIGIN>/admin/invalidate/<token>`),
    `is_valid` checks one without using it, and `kill_switch` uses one: in a single control.db transaction it
    marks the token used, ends sessions, optionally revokes trusted devices, and writes the audit row.

Why it exists
    Parity row 99: every successful login emails the admin, and the email carries a link to end all sessions if
    the login was not theirs. v1 stored the tokens in clear and the link did not touch trusted devices, so an
    attacker who had ticked "trust this device" got straight back in (bug B10). v2 stores only a SHA-256 of each
    token and offers, on the confirmation page, to revoke trusted devices and to end every session (both checked
    by default; unchecking the second ends only the sessions that were not opened with a passkey).
    GET only shows the confirmation page and never uses the token: mail scanners and link previewers open links
    on their own, and v1 learned that consuming on GET burned the link before the admin clicked it.

How it works
    - Tokens are 256-bit random, valid `invalidation_link_ttl_s` (default 24 h), single use (`used_at`).
    - "End every session" bumps `service_state.session_epoch` and deletes every session row (the epoch kill
      switch of v1, plus real deletion).
    - Bounded: at most `MAX_TOKENS_PER_USER` unused tokens per admin (oldest dropped); expired rows are pruned by
      the leader.

What to read next
    `roxy/admin/auth/routes.py` (`/admin/invalidate/<token>`), then `roxy/admin/auth/sessions.py`.
"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
from dataclasses import dataclass

from roxy.admin.auth import sessions, trusted_devices
from roxy.admin.auth.events import audit_auth

MAX_TOKENS_PER_USER = 50
_MAX_TOKEN_CHARS = 100


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def link(site_origin: str, token: str) -> str:
    """The URL put in the login alert email (the only Roxy link that ever carries a token, plan 17.7)."""
    return f"{site_origin.rstrip('/')}/admin/invalidate/{token}"


def _well_formed(token: str) -> bool:
    return 0 < len(token) <= _MAX_TOKEN_CHARS and all(c.isalnum() or c in "-_" for c in token)


def mint(conn: sqlite3.Connection, *, user_id: int, now: int, ttl_s: int) -> str:
    """A new kill-switch token for `user_id`, stored hashed, valid `ttl_s` seconds."""
    token = secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO invalidation_tokens (token_hash, user_id, expires_at, used_at) VALUES (?, ?, ?, NULL)",
        (hash_token(token), user_id, now + ttl_s),
    )
    conn.execute(
        "DELETE FROM invalidation_tokens WHERE user_id = ? AND (expires_at <= ? OR token_hash NOT IN "
        "(SELECT token_hash FROM invalidation_tokens WHERE user_id = ? ORDER BY expires_at DESC LIMIT ?))",
        (user_id, now, user_id, MAX_TOKENS_PER_USER),
    )
    return token


def is_valid(conn: sqlite3.Connection, token: str, now: int) -> bool:
    """Whether `token` is unused and unexpired (read only; used only where the allowlist hides the page)."""
    if not _well_formed(token):
        return False
    row = conn.execute(
        "SELECT 1 FROM invalidation_tokens WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?",
        (hash_token(token), now),
    ).fetchone()
    return row is not None


@dataclass(frozen=True, slots=True)
class KillSwitchResult:
    """What one use of the link did."""

    user_id: int
    sessions_ended: int
    trusted_devices_revoked: int
    all_sessions: bool


def kill_switch(
    conn: sqlite3.Connection,
    *,
    token: str,
    now: int,
    revoke_trusted: bool,
    all_sessions: bool,
    ip: str | None,
    request_id: str | None,
) -> KillSwitchResult | None:
    """Use the token (single use) and apply the chosen options, all in the caller's write transaction.

    Returns None when the token is unknown, used or expired (nothing is changed then).
    """
    if not _well_formed(token):
        return None
    row = conn.execute(
        "UPDATE invalidation_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL AND expires_at > ? "
        "RETURNING user_id",
        (now, hash_token(token), now),
    ).fetchone()
    if row is None:
        return None
    user_id = int(row[0])
    if all_sessions:
        ended, epoch = sessions.revoke_all(conn, now)
    else:
        ended, epoch = sessions.revoke_non_passkey_sessions(conn), sessions.read_epoch(conn)
    revoked = trusted_devices.revoke_all(conn) if revoke_trusted else 0
    audit_auth(
        conn,
        "auth.kill_switch",
        user_id=user_id,
        username=None,
        ip=ip,
        request_id=request_id,
        reason="kill-switch link from the login alert email",
        after={
            "sessions_ended": ended,
            "all_sessions": all_sessions,
            "trusted_devices_revoked": revoked,
            "session_epoch": epoch,
        },
        at=now,
        actor_kind="system",
    )
    return KillSwitchResult(user_id, ended, revoked, all_sessions)
