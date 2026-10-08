"""Short-lived server-side auth records in hot.db: login transactions, the TOTP replay guard, pending enrollments.

What this is
    A tiny keyed store with expiry, built on hot.db's `lease (name, holder, expires_ms, epoch, payload_json)`
    rows: `put`, `get`, `take` (read and delete in one step), `delete`, `cap`, plus the TOTP replay guard
    `accept_totp_step`. Every function is plain SQL on a connection, so callers run it inside their own
    `db.write`/`db.read` and can combine it with a lockout update in the same transaction.

Why it exists
    The password step and the second factor step of a login are separate requests that may land on different
    worker processes, so "this login is half done, for this IP and browser, until 120 s from now" must live in
    shared storage (plan 9.5, C6), not in a worker's memory or a client-side cookie (v1's signed session cookie
    carried the challenge). A lease row already is exactly that shape: a named record with an owner, an expiry and
    a small JSON payload; expired rows are deleted by the leader's hot.db pruning (`prune_expired_leases`), so
    nothing here can grow without bound. The names use their own prefixes and never collide with the leader,
    single-flight or tarpit leases.
    The TOTP replay guard needs "the newest step this user already used" for 90 seconds at most: after a step
    and the one after it have passed, no code of that step is accepted anyway, so the row may then expire.

How it works
    - Names: `auth_tx:<sha256 of the transaction token>` (login transactions; the token itself is never stored),
      `auth_totp:<user id>` (replay guard; `epoch` holds the last accepted step), `auth_enroll:<session hash>`
      (a TOTP secret waiting for its first code, encrypted), `auth_webauthn:<purpose>:<session hash>` (a passkey
      challenge outside a login transaction).
    - `take` is `DELETE ... RETURNING`: of two parallel requests finishing the same transaction exactly one gets
      the row, which is what makes every one-time thing here one-time.
    - `cap(prefix, limit)` drops the rows of one prefix that expire soonest beyond `limit`
      (`MAX_EXPIRABLES_PER_STORE`, plan P9).

What to read next
    `roxy/admin/auth/flow.py` (the login transaction's payload fields), then `roxy/storage/leases.py` (the same
    table used for real leases).
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from typing import Any

from roxy.admin.auth.totp import TOTP_STEP_S
from roxy.config.constants import MAX_EXPIRABLES_PER_STORE

LOGIN_TX = "auth_tx:"
TOTP_GUARD = "auth_totp:"
ENROLL = "auth_enroll:"
WEBAUTHN = "auth_webauthn:"
HOLDER = "roxy-auth"
_PREFIX_END = "\U0010ffff"
_MAX_PAYLOAD_BYTES = 16 * 1024


def new_token() -> str:
    """A fresh 256-bit token for the client (URL safe base64)."""
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    """SHA-256 hex of a client token: what is stored and looked up."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def put(conn: sqlite3.Connection, name: str, payload: dict[str, Any], expires_ms: int, *, holder: str = HOLDER) -> None:
    """Create or replace record `name` with `payload`, valid until `expires_ms`."""
    text = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    if len(text) > _MAX_PAYLOAD_BYTES:
        raise ValueError("auth record payload too large")
    conn.execute(
        "INSERT INTO lease (name, holder, expires_ms, epoch, payload_json) VALUES (?, ?, ?, 0, ?) "
        "ON CONFLICT (name) DO UPDATE SET holder = excluded.holder, expires_ms = excluded.expires_ms, "
        "payload_json = excluded.payload_json",
        (name, holder, int(expires_ms), text),
    )


def _decode(text: str | None) -> dict[str, Any] | None:
    if not text:
        return None
    try:
        value = json.loads(text)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def get(conn: sqlite3.Connection, name: str, now_ms: int) -> dict[str, Any] | None:
    """The payload of an unexpired record, or None."""
    row = conn.execute("SELECT payload_json, expires_ms FROM lease WHERE name = ?", (name,)).fetchone()
    if row is None or int(row[1]) <= now_ms:
        return None
    return _decode(row[0])


def get_any(conn: sqlite3.Connection, name: str) -> tuple[dict[str, Any] | None, int] | None:
    """The payload and expiry of a record whether or not it expired (None when there is no row)."""
    row = conn.execute("SELECT payload_json, expires_ms FROM lease WHERE name = ?", (name,)).fetchone()
    if row is None:
        return None
    return _decode(row[0]), int(row[1])


def take(conn: sqlite3.Connection, name: str, now_ms: int, *, expect: str | None = None) -> dict[str, Any] | None:
    """Delete record `name` and return its payload, only if it is unexpired (and, with `expect`, unchanged).

    `expect` is the exact payload JSON the caller verified against; if a concurrent request changed the record
    (a resent email code, a new passkey challenge), nothing is taken.
    """
    if expect is None:
        row = conn.execute(
            "DELETE FROM lease WHERE name = ? AND expires_ms > ? RETURNING payload_json", (name, now_ms)
        ).fetchone()
    else:
        row = conn.execute(
            "DELETE FROM lease WHERE name = ? AND expires_ms > ? AND payload_json = ? RETURNING payload_json",
            (name, now_ms, expect),
        ).fetchone()
    return None if row is None else _decode(row[0])


def raw_payload(conn: sqlite3.Connection, name: str) -> str | None:
    """The stored payload JSON text exactly (for `take(..., expect=...)`)."""
    row = conn.execute("SELECT payload_json FROM lease WHERE name = ?", (name,)).fetchone()
    return None if row is None else str(row[0])


def delete(conn: sqlite3.Connection, name: str) -> None:
    conn.execute("DELETE FROM lease WHERE name = ?", (name,))


def delete_prefix(conn: sqlite3.Connection, prefix: str) -> int:
    """Delete every record whose name starts with `prefix`."""
    return conn.execute("DELETE FROM lease WHERE name >= ? AND name < ?", (prefix, prefix + _PREFIX_END)).rowcount


def cap(conn: sqlite3.Connection, prefix: str, now_ms: int, limit: int = MAX_EXPIRABLES_PER_STORE) -> int:
    """Delete expired records of `prefix`, then the soonest-expiring ones beyond `limit`. Returns rows deleted."""
    high = prefix + _PREFIX_END
    deleted = conn.execute(
        "DELETE FROM lease WHERE name >= ? AND name < ? AND expires_ms <= ?", (prefix, high, now_ms)
    ).rowcount
    count = int(conn.execute("SELECT count(*) FROM lease WHERE name >= ? AND name < ?", (prefix, high)).fetchone()[0])
    if count > limit:
        deleted += conn.execute(
            "DELETE FROM lease WHERE name IN (SELECT name FROM lease WHERE name >= ? AND name < ? "
            "ORDER BY expires_ms LIMIT ?)",
            (prefix, high, count - limit),
        ).rowcount
    return deleted


def accept_totp_step(conn: sqlite3.Connection, user_id: int, step: int, now_ms: int) -> bool:
    """The replay guard: record `step` as used for `user_id` unless it is not newer than the last used step.

    Returns False for a replay (same or older step while the previous one is still in its acceptance window).
    """
    name = f"{TOTP_GUARD}{user_id}"
    row = conn.execute("SELECT epoch, expires_ms FROM lease WHERE name = ?", (name,)).fetchone()
    if row is not None and int(row[1]) > now_ms and int(row[0]) >= step:
        return False
    # Keep the row until no code of `step` can be accepted any more: the end of step + 1, plus one step of margin.
    expires_ms = (step + 3) * TOTP_STEP_S * 1000
    conn.execute(
        "INSERT INTO lease (name, holder, expires_ms, epoch, payload_json) VALUES (?, ?, ?, ?, NULL) "
        "ON CONFLICT (name) DO UPDATE SET epoch = excluded.epoch, expires_ms = excluded.expires_ms",
        (name, HOLDER, expires_ms, step),
    )
    return True
