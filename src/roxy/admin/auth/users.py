"""Admin accounts: reading and writing `admin_users` rows (all full admins, owner decision D22).

What this is
    `AdminUser` and the functions the login flow, enrollment and `scripts/create_admin.py` use on control.db:
    `get_by_username`, `get_by_id`, `insert_user`, `set_password_hash`, `store_totp`, `set_recovery_codes`,
    `reset_mfa`, `mark_login`, and `email_for`.

Why it exists
    One place that knows the column names keeps the flow readable, and lets the console script create the first
    admin with exactly the same code the server uses to check it (plan 9.5: no "first visitor becomes admin").

How it works
    Every function takes a connection already inside a transaction. Usernames compare case-insensitively (the
    column is `COLLATE NOCASE`). The TOTP secret is encrypted before it reaches this module (`totp.TotpCipher`);
    storing one clears `mfa_bootstrap_pending`, which ends the one-time emailed-code login of the v1 upgrade (D5).
    `reset_mfa` (console only) removes the TOTP secret, recovery codes, passkeys, trusted devices and sessions.

What to read next
    `roxy/admin/auth/flow.py`, then `scripts/create_admin.py`.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from typing import Any

USERNAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}")
"""Allowed admin usernames: 1 to 64 letters, digits and `_ . @ -`, starting with a letter or digit."""

_COLUMNS = (
    "id, username, password_hash, totp_secret_enc, recovery_codes_hash_json, created_at, last_login_at, "
    "mfa_bootstrap_pending, email"
)


@dataclass(frozen=True, slots=True)
class AdminUser:
    id: int
    username: str
    password_hash: str
    totp_secret_enc: bytes | None
    recovery_codes_hash_json: str | None
    created_at: int
    last_login_at: int | None
    mfa_bootstrap_pending: bool
    email: str | None

    @property
    def has_totp(self) -> bool:
        return bool(self.totp_secret_enc)


def _row_to_user(row: Any) -> AdminUser | None:
    if row is None:
        return None
    secret = row[3]
    return AdminUser(
        id=int(row[0]),
        username=str(row[1]),
        password_hash=str(row[2]),
        totp_secret_enc=bytes(secret) if secret is not None else None,
        recovery_codes_hash_json=row[4] if isinstance(row[4], str) else None,
        created_at=int(row[5]),
        last_login_at=int(row[6]) if row[6] is not None else None,
        mfa_bootstrap_pending=bool(row[7]),
        email=row[8] if isinstance(row[8], str) else None,
    )


def valid_username(username: str) -> bool:
    return bool(USERNAME_RE.fullmatch(username))


def get_by_username(conn: sqlite3.Connection, username: str) -> AdminUser | None:
    if not username or len(username) > 64:
        return None
    row = conn.execute(f"SELECT {_COLUMNS} FROM admin_users WHERE username = ?", (username,)).fetchone()  # noqa: S608 (column list is a module constant)
    return _row_to_user(row)


def get_by_id(conn: sqlite3.Connection, user_id: int) -> AdminUser | None:
    row = conn.execute(f"SELECT {_COLUMNS} FROM admin_users WHERE id = ?", (user_id,)).fetchone()  # noqa: S608 (column list is a module constant)
    return _row_to_user(row)


def count_users(conn: sqlite3.Connection) -> int:
    return int(conn.execute("SELECT count(*) FROM admin_users").fetchone()[0])


def insert_user(
    conn: sqlite3.Connection, *, username: str, password_hash: str, now: int, email: str | None = None
) -> int:
    """Create an admin (no second factor yet; the caller stores TOTP in the same transaction)."""
    if not valid_username(username):
        raise ValueError("username must be 1 to 64 letters, digits, '_', '.', '@' or '-'")
    cursor = conn.execute(
        "INSERT INTO admin_users (username, password_hash, created_at, mfa_bootstrap_pending, email) "
        "VALUES (?, ?, ?, 0, ?)",
        (username, password_hash, now, email),
    )
    if cursor.lastrowid is None:  # pragma: no cover - sqlite3 always sets it after an INSERT
        raise RuntimeError("admin insert returned no id")
    return int(cursor.lastrowid)


def set_password_hash(conn: sqlite3.Connection, user_id: int, password_hash: str) -> None:
    conn.execute("UPDATE admin_users SET password_hash = ? WHERE id = ?", (password_hash, user_id))


def store_totp(conn: sqlite3.Connection, user_id: int, secret_enc: bytes, recovery_json: str) -> None:
    """Store an enrolled authenticator and its recovery codes; ends the D5 bootstrap state."""
    conn.execute(
        "UPDATE admin_users SET totp_secret_enc = ?, recovery_codes_hash_json = ?, mfa_bootstrap_pending = 0 "
        "WHERE id = ?",
        (secret_enc, recovery_json, user_id),
    )


def set_recovery_codes(conn: sqlite3.Connection, user_id: int, recovery_json: str) -> None:
    conn.execute("UPDATE admin_users SET recovery_codes_hash_json = ? WHERE id = ?", (recovery_json, user_id))


def mark_login(conn: sqlite3.Connection, user_id: int, now: int) -> None:
    conn.execute("UPDATE admin_users SET last_login_at = ? WHERE id = ?", (now, user_id))


def reset_mfa(conn: sqlite3.Connection, user_id: int) -> dict[str, int]:
    """Remove every second factor and every login of one admin (console recovery, `--reset-mfa`)."""
    conn.execute(
        "UPDATE admin_users SET totp_secret_enc = NULL, recovery_codes_hash_json = NULL WHERE id = ?", (user_id,)
    )
    return {
        "passkeys": conn.execute("DELETE FROM admin_passkeys WHERE user_id = ?", (user_id,)).rowcount,
        "trusted_devices": conn.execute("DELETE FROM trusted_devices WHERE user_id = ?", (user_id,)).rowcount,
        "sessions": conn.execute("DELETE FROM admin_sessions WHERE user_id = ?", (user_id,)).rowcount,
    }


def email_for(user: AdminUser, fallback: str | None) -> str | None:
    """Where an emailed code for `user` goes: the account's address, else the main alert address."""
    return user.email or fallback
