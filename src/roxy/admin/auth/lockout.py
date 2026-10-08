"""Login lockout: failures counted per (username, network) BEFORE checking, plus a global slow-down guard.

What this is
    Pure functions over a hot.db connection, meant to run inside one `db.write` transaction:
    `reserve` (count this attempt, or refuse it when the key is locked), `release` (this attempt turned out not to
    be a failure), `clear` (a full login succeeded), and `global_tick` (the fleet-wide attempts-per-minute guard).
    `ip_prefix` and `lockout_key` build the key.

Why it exists
    v1 counted failures per IP in each worker's memory, AFTER checking the password, in a fixed window. With
    several workers, or several parallel requests, an attacker got far more than 5 guesses: every request read
    "4 failures so far", then every one checked a password. Plan 9.5 fixes all three:
      * Counted before verifying, atomically: the attempt takes a slot in the same transaction that counts the
        slots, so the 6th parallel guess is refused before any password is hashed, whatever the worker.
      * Keyed by (username, network): the network is the IPv4 /24 or IPv6 /64, so an attacker cannot reset the
        count by changing the last part of the address; the username keeps one network from locking out a
        different account.
      * Sliding window: each failure is its own row with its own time, so a failure stops counting exactly
        `admin_login_window_s` after it happened (v1's fixed window let 10 guesses through around a boundary).
    The global guard stops guessing spread over many networks without letting an attacker lock the owner out:
    beyond `admin_login_global_max_per_min` attempts per minute, attempts are slowed, never refused, and the
    admin allowlist and trusted devices are exempt (they are not even counted).

How it works
    - Rows live in hot.db `login_failures (subject, count, window_start)`. A failure slot is the row
      `authfail:<key>:<random>` with `window_start` = the attempt time in seconds. All slots of one key share a
      prefix, so they are read with one primary key range scan. At most `max_failures` slots exist per key.
    - The global guard is the single row `global`: a one-minute window start and the attempts counted in it.
    - Bounded (plan P9): rows older than an hour are pruned by the leader (`storage/retention.py`), and when the
      table passes `MAX_TRACKED_LOGIN_IPS` rows the oldest slots are dropped at insert time.

What to read next
    `roxy/admin/auth/flow.py` (when each function is called), then `roxy/storage/retention.py`
    (`prune_login_failures`).
"""

from __future__ import annotations

import hashlib
import ipaddress
import secrets
import sqlite3
from dataclasses import dataclass

from roxy.config.constants import MAX_TRACKED_LOGIN_IPS
from roxy.core.client_ip import parse_ip

FAIL_PREFIX = "authfail:"
GLOBAL_SUBJECT = "global"
GLOBAL_WINDOW_S = 60
_PREFIX_END = "\U0010ffff"  # largest code point: `subject < prefix + this` is a primary key range scan
_TRIM_BATCH = 100

LOCKOUT_TEXT = "Too many attempts; try again in {seconds} seconds."
"""v1 429 body, kept exactly (plan 9.5)."""


def ip_prefix(ip: str) -> str:
    """The network an address belongs to for lockouts: IPv4 /24, IPv6 /64 (plan 9.5)."""
    address = parse_ip(ip)
    if address is None:
        return ip[:64] or "unknown"
    prefix = 24 if address.version == 4 else 64
    return str(ipaddress.ip_network((address, prefix), strict=False))


def lockout_key(username: str, ip: str) -> str:
    """`<network>|<16 hex of SHA-256(username)>`: the username is hashed so guesses are not stored in clear."""
    digest = hashlib.sha256(username.strip().casefold().encode("utf-8")).hexdigest()[:16]
    return f"{ip_prefix(ip)}|{digest}"


def _range(key: str) -> tuple[str, str]:
    low = f"{FAIL_PREFIX}{key}:"
    return low, low + _PREFIX_END


@dataclass(frozen=True, slots=True)
class Reservation:
    """The result of `reserve`.

    `allowed` False means locked: refuse with 429 and `retry_after_s`. When allowed, `subject` is this attempt's
    slot (pass it to `release` if the attempt turns out not to be a failure). `failures_before` counts the
    failures already in the window; `last_chance` is True when this attempt fills the last slot.
    """

    allowed: bool
    subject: str | None
    retry_after_s: int
    failures_before: int
    last_chance: bool


def reserve(conn: sqlite3.Connection, key: str, now_s: int, max_failures: int, window_s: int) -> Reservation:
    """Count one attempt for `key`, or refuse it when `max_failures` are already in the sliding window."""
    low, high = _range(key)
    conn.execute(
        "DELETE FROM login_failures WHERE subject >= ? AND subject < ? AND window_start <= ?",
        (low, high, now_s - window_s),
    )
    times = [
        int(row[0])
        for row in conn.execute(
            "SELECT window_start FROM login_failures WHERE subject >= ? AND subject < ? ORDER BY window_start",
            (low, high),
        )
    ]
    limit = max(1, int(max_failures))
    if len(times) >= limit:
        # The window has room again once enough of the oldest failures age out (see the module docstring).
        unlock_at = times[len(times) - limit] + window_s
        return Reservation(False, None, max(1, unlock_at - now_s), len(times), False)
    subject = f"{low}{secrets.token_hex(6)}"
    conn.execute("INSERT INTO login_failures (subject, count, window_start) VALUES (?, 1, ?)", (subject, now_s))
    _trim(conn)
    return Reservation(True, subject, 0, len(times), len(times) + 1 >= limit)


def _trim(conn: sqlite3.Connection) -> None:
    """Keep the table bounded (plan P9): drop the oldest failure slots beyond `MAX_TRACKED_LOGIN_IPS` rows."""
    total = int(conn.execute("SELECT count(*) FROM login_failures").fetchone()[0])
    if total <= MAX_TRACKED_LOGIN_IPS:
        return
    conn.execute(
        "DELETE FROM login_failures WHERE subject IN (SELECT subject FROM login_failures WHERE subject >= ? AND "
        "subject < ? ORDER BY window_start LIMIT ?)",
        (FAIL_PREFIX, FAIL_PREFIX + _PREFIX_END, total - MAX_TRACKED_LOGIN_IPS + _TRIM_BATCH),
    )


def release(conn: sqlite3.Connection, subject: str | None) -> None:
    """Give back one slot (the attempt succeeded, or was refused before it could be checked)."""
    if subject:
        conn.execute("DELETE FROM login_failures WHERE subject = ?", (subject,))


def clear(conn: sqlite3.Connection, key: str) -> int:
    """Forget every failure of `key` (a full login succeeded, like v1's reset on success)."""
    low, high = _range(key)
    return conn.execute("DELETE FROM login_failures WHERE subject >= ? AND subject < ?", (low, high)).rowcount


def failures(conn: sqlite3.Connection, key: str, now_s: int, window_s: int) -> int:
    """Failures of `key` still inside the window (read only)."""
    low, high = _range(key)
    row = conn.execute(
        "SELECT count(*) FROM login_failures WHERE subject >= ? AND subject < ? AND window_start > ?",
        (low, high, now_s - window_s),
    ).fetchone()
    return int(row[0])


@dataclass(frozen=True, slots=True)
class GlobalTick:
    """The global guard after counting one attempt: `engaged` means this attempt is slowed."""

    count: int
    engaged: bool
    just_engaged: bool


def global_tick(conn: sqlite3.Connection, now_s: int, cap: int) -> GlobalTick:
    """Count one non-exempt attempt in the current one-minute window of the fleet-wide guard."""
    row = conn.execute("SELECT count, window_start FROM login_failures WHERE subject = ?", (GLOBAL_SUBJECT,)).fetchone()
    # A clock that stepped back a little (now before the window start) still counts in the current window.
    if row is None or now_s - int(row[1]) >= GLOBAL_WINDOW_S:
        count = 1
        conn.execute(
            "INSERT INTO login_failures (subject, count, window_start) VALUES (?, 1, ?) "
            "ON CONFLICT (subject) DO UPDATE SET count = 1, window_start = excluded.window_start",
            (GLOBAL_SUBJECT, now_s),
        )
    else:
        count = int(row[0]) + 1
        conn.execute("UPDATE login_failures SET count = ? WHERE subject = ?", (count, GLOBAL_SUBJECT))
    limit = max(1, int(cap))
    return GlobalTick(count, count > limit, count == limit + 1)


def top_prefixes(conn: sqlite3.Connection, now_s: int, since_s: int, limit: int = 5) -> list[tuple[str, int]]:
    """Networks with the most failure slots in the last `since_s` seconds (for the global guard alert)."""
    counts: dict[str, int] = {}
    for (subject,) in conn.execute(
        "SELECT subject FROM login_failures WHERE subject >= ? AND subject < ? AND window_start > ? LIMIT 5000",
        (FAIL_PREFIX, FAIL_PREFIX + _PREFIX_END, now_s - since_s),
    ):
        network = str(subject)[len(FAIL_PREFIX) :].split("|", 1)[0]
        counts[network] = counts.get(network, 0) + 1
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]
