"""Server-side admin sessions: the `__Host-roxy_session` cookie, idle and absolute expiry, rotation, kill switch.

What this is
    Functions over control.db `admin_sessions` (run inside the caller's `db.write`/`db.read`): `create`, `load`,
    `touch`, `rotate`, `revoke`, `revoke_user`, `revoke_all`, `kill_switch_sessions`, plus the cookie helpers and
    `csrf_secret(token)` (the per-session CSRF secret, `csrf.py`).

Why it exists
    v1 kept the whole session inside a signed (not encrypted) cookie: logout only deleted the browser's copy, a
    copied cookie stayed valid while it was used (bug B11), and there was no way to end one session. Plan 9.6:
    sessions live on the server, the cookie holds only a 256-bit random id, and the database holds only the
    SHA-256 of that id, so a copied database cannot be replayed as a login. Logout, revoke and the kill switch
    delete rows, which ends the session everywhere at once.

How it works
    - Cookie: `__Host-roxy_session=<id>; Path=/; Secure; HttpOnly; SameSite=Strict`, no Domain, no Max-Age (it
      ends with the browser). The `__Host-` prefix makes browsers refuse the cookie unless it is Secure, has
      Path=/ and no Domain, so a sibling subdomain cannot plant or overwrite it (session fixation).
    - A session is live while ALL of these hold: its row exists; its `epoch` equals `service_state.session_epoch`
      (the kill switch bumps the epoch); `now < expires_at` (absolute lifetime, `admin_session_max_age_s`, kept
      across rotations); and `now - last_seen_at <= admin_session_idle_timeout_s`. Only real use moves
      `last_seen_at` (`deps.py` decides what counts as use; plan 9.6).
    - `created_at` doubles as "when the second factor was last entered": a re-authentication rotates the session,
      and the new row starts at that moment. The fresh-MFA window (`admin_reauth_window_s`) is measured from it.
    - Rotation (login, enrollment, re-authentication) inserts a new row with a new id and deletes the old one in
      the same transaction; the old cookie value stops working immediately.
    - The CSRF secret is HMAC-SHA256(session id, label): it needs no storage, changes with every rotation, and
      cannot be turned back into the session id. Its hash is stored (`csrf_secret_hash`) as a cross-check.
    - Bounded (plan P9): at most `MAX_SESSIONS_PER_USER` rows per admin (oldest dropped); expired rows are pruned
      by the leader (`storage/retention.py`).

What to read next
    `roxy/admin/auth/deps.py` (where sessions are checked on every admin request), then `roxy/admin/auth/csrf.py`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
from dataclasses import dataclass

SESSION_COOKIE = "__Host-roxy_session"
MAX_SESSIONS_PER_USER = 20
BOOTSTRAP_MAX_AGE_S = 1800
"""A first-login (bootstrap) session may only enroll the authenticator, and only for 30 minutes."""

FULL_MFA_LEVELS = frozenset({"totp", "recovery", "passkey", "email"})
"""Levels reached by actually entering a second factor (these can be fresh, plan 9.6)."""

MFA_LEVELS = FULL_MFA_LEVELS | {"trusted_device", "bootstrap"}

_CSRF_LABEL = b"roxy-csrf-v1"
_MAX_UA = 400
_MAX_IP = 64


def new_token() -> str:
    """A fresh 256-bit session id for the cookie."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """SHA-256 hex of a session id: the only form stored (`admin_sessions.id_hash`)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def csrf_secret(token: str) -> bytes:
    """The session's CSRF secret (32 bytes), derived from the session id with HMAC-SHA256."""
    return hmac.new(token.encode("utf-8"), _CSRF_LABEL, hashlib.sha256).digest()


def csrf_secret_hash(token: str) -> str:
    return hashlib.sha256(csrf_secret(token)).hexdigest()


def public_id(id_hash: str) -> str:
    """A short public handle for one session (dashboards list and revoke sessions by it)."""
    return id_hash[:16]


@dataclass(frozen=True, slots=True)
class SessionRecord:
    """One `admin_sessions` row joined with its user's name."""

    id_hash: str
    user_id: int
    username: str
    created_at: int
    last_seen_at: int
    expires_at: int
    ip: str | None
    ua: str | None
    epoch: int
    csrf_secret_hash: str
    mfa_level: str

    def is_fresh(self, now: float, window_s: int) -> bool:
        """True when a real second factor was entered within `window_s` seconds (plan 9.6)."""
        return self.mfa_level in FULL_MFA_LEVELS and now - self.created_at <= window_s

    def idle_expires_at(self, idle_timeout_s: int) -> int:
        return min(self.last_seen_at + idle_timeout_s, self.expires_at)


def read_epoch(conn: sqlite3.Connection) -> int:
    """The current kill-switch epoch (`service_state.session_epoch`)."""
    row = conn.execute("SELECT value_json FROM service_state WHERE key = 'session_epoch'").fetchone()
    if row is None:
        return 0
    try:
        return int(json.loads(row[0]))
    except (TypeError, ValueError):
        return 0


def bump_epoch(conn: sqlite3.Connection, now: int) -> int:
    """Increase the epoch (the kill switch); every session created before it stops being valid."""
    current = read_epoch(conn)
    conn.execute(
        "INSERT INTO service_state (key, value_json, updated_at) VALUES ('session_epoch', ?, ?) "
        "ON CONFLICT (key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at",
        (json.dumps(current + 1), now),
    )
    return current + 1


def create(
    conn: sqlite3.Connection,
    *,
    user_id: int,
    ip: str | None,
    ua: str | None,
    mfa_level: str,
    now: int,
    max_age_s: int,
    expires_at: int | None = None,
) -> tuple[str, str]:
    """Insert a new session inside the caller's write transaction. Returns (cookie token, id hash)."""
    if mfa_level not in MFA_LEVELS:
        raise ValueError(f"unknown mfa level {mfa_level!r}")
    token = new_token()
    id_hash = hash_token(token)
    lifetime = min(max_age_s, BOOTSTRAP_MAX_AGE_S) if mfa_level == "bootstrap" else max_age_s
    absolute = now + lifetime if expires_at is None else min(expires_at, now + lifetime)
    conn.execute(
        "INSERT INTO admin_sessions (id_hash, user_id, created_at, last_seen_at, expires_at, ip, ua, epoch, "
        "csrf_secret_hash, mfa_level) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            id_hash,
            user_id,
            now,
            now,
            absolute,
            (ip or "")[:_MAX_IP] or None,
            (ua or "")[:_MAX_UA] or None,
            read_epoch(conn),
            csrf_secret_hash(token),
            mfa_level,
        ),
    )
    _cap_user(conn, user_id)
    return token, id_hash


def _cap_user(conn: sqlite3.Connection, user_id: int) -> None:
    conn.execute(
        "DELETE FROM admin_sessions WHERE user_id = ? AND id_hash NOT IN (SELECT id_hash FROM admin_sessions "
        "WHERE user_id = ? ORDER BY created_at DESC, id_hash LIMIT ?)",
        (user_id, user_id, MAX_SESSIONS_PER_USER),
    )


def load(conn: sqlite3.Connection, id_hash: str) -> tuple[SessionRecord, int] | None:
    """The session row and the current epoch, or None when the row does not exist."""
    row = conn.execute(
        "SELECT s.id_hash, s.user_id, u.username, s.created_at, s.last_seen_at, s.expires_at, s.ip, s.ua, s.epoch, "
        "s.csrf_secret_hash, s.mfa_level FROM admin_sessions AS s JOIN admin_users AS u ON u.id = s.user_id "
        "WHERE s.id_hash = ?",
        (id_hash,),
    ).fetchone()
    if row is None:
        return None
    record = SessionRecord(
        id_hash=str(row[0]),
        user_id=int(row[1]),
        username=str(row[2]),
        created_at=int(row[3]),
        last_seen_at=int(row[4]),
        expires_at=int(row[5]),
        ip=row[6],
        ua=row[7],
        epoch=int(row[8]),
        csrf_secret_hash=str(row[9]),
        mfa_level=str(row[10]),
    )
    return record, read_epoch(conn)


def is_live(record: SessionRecord, epoch: int, now: float, idle_timeout_s: int) -> bool:
    """All four liveness rules of the module docstring."""
    return record.epoch == epoch and now < record.expires_at and now - record.last_seen_at <= idle_timeout_s


def touch(conn: sqlite3.Connection, id_hash: str, now: int) -> None:
    """Record real use: moves the idle deadline forward (never past the absolute expiry)."""
    conn.execute(
        "UPDATE admin_sessions SET last_seen_at = ? WHERE id_hash = ? AND last_seen_at < ?", (now, id_hash, now)
    )


def rotate(
    conn: sqlite3.Connection,
    old: SessionRecord,
    *,
    mfa_level: str,
    now: int,
    ip: str | None,
    ua: str | None,
    max_age_s: int,
) -> tuple[str, str]:
    """Replace `old` with a new session id (privilege change); keeps the absolute expiry of the first login."""
    keep_until = old.expires_at if old.mfa_level != "bootstrap" else None
    conn.execute("DELETE FROM admin_sessions WHERE id_hash = ?", (old.id_hash,))
    return create(
        conn,
        user_id=old.user_id,
        ip=ip,
        ua=ua,
        mfa_level=mfa_level,
        now=now,
        max_age_s=max_age_s,
        expires_at=keep_until,
    )


def revoke(conn: sqlite3.Connection, id_hash: str) -> bool:
    """End one session."""
    return conn.execute("DELETE FROM admin_sessions WHERE id_hash = ?", (id_hash,)).rowcount > 0


def revoke_public(conn: sqlite3.Connection, user_id: int, short_id: str) -> bool:
    """End one of `user_id`'s sessions by its public id."""
    if not short_id or len(short_id) != 16 or not all(c in "0123456789abcdef" for c in short_id):
        return False
    return (
        conn.execute(
            "DELETE FROM admin_sessions WHERE user_id = ? AND substr(id_hash, 1, 16) = ?", (user_id, short_id)
        ).rowcount
        > 0
    )


def revoke_user(conn: sqlite3.Connection, user_id: int, *, keep: str | None = None) -> int:
    """End every session of one admin (except `keep`, the caller's own)."""
    return conn.execute("DELETE FROM admin_sessions WHERE user_id = ? AND id_hash != ?", (user_id, keep or "")).rowcount


def revoke_all(conn: sqlite3.Connection, now: int) -> tuple[int, int]:
    """The epoch kill switch: bump the epoch and delete every session. Returns (sessions deleted, new epoch)."""
    epoch = bump_epoch(conn, now)
    deleted = conn.execute("DELETE FROM admin_sessions").rowcount
    return deleted, epoch


def revoke_non_passkey_sessions(conn: sqlite3.Connection) -> int:
    """End every session that was not opened with a passkey (the kill switch's narrower option, row 99)."""
    return conn.execute("DELETE FROM admin_sessions WHERE mfa_level != 'passkey'").rowcount


def list_for_user(conn: sqlite3.Connection, user_id: int, now: int) -> list[dict[str, object]]:
    """The admin's unexpired sessions, newest first (for the Security page)."""
    rows = conn.execute(
        "SELECT id_hash, created_at, last_seen_at, expires_at, ip, ua, mfa_level FROM admin_sessions "
        "WHERE user_id = ? AND expires_at > ? ORDER BY created_at DESC",
        (user_id, now),
    ).fetchall()
    return [
        {
            "Id": public_id(str(row[0])),
            "CreatedAt": int(row[1]),
            "LastSeenAt": int(row[2]),
            "ExpiresAt": int(row[3]),
            "IP": row[4],
            "UserAgent": row[5],
            "MfaLevel": row[6],
        }
        for row in rows
    ]
