"""Trusted devices: a browser the admin marked as trusted skips ONLY the second factor prompt, for a while.

What this is
    Functions over control.db `trusted_devices` (inside the caller's transaction): `issue`, `find_valid`, `touch`,
    `list_for_user`, `revoke`, `revoke_all`, plus `ua_family` and `device_name`, and the cookie name.

Why it exists
    Parity row 100: v1 let a browser skip the emailed code for 30 days. Plan 9.5 and 4.6 keep the convenience with
    tighter rules: the password is still required every time; trust applies only while
    `admin_trusted_devices_enabled` is on; a device is bound to its browser family and operating system (a cookie
    copied into a different browser does not work); devices are listed individually (name, browser, last use)
    and can be revoked one by one or all at once; and the kill switch can revoke them too (v1 bug B10).

How it works
    - The cookie `__Host-roxy_trusted` holds a 256-bit random token; the table holds only its SHA-256.
    - `ua_family` reduces a User-Agent to `<browser>/<os>` (for example `firefox/linux`). It survives browser
      updates (the version is ignored) but not a move to another browser or operating system.
    - Lifetime is `trusted_device_days` from issue; using a device does not extend it (as in v1).
    - Bounded (plan P9): at most `MAX_DEVICES_PER_USER` per admin, oldest dropped; expired rows are pruned by the
      leader.

What to read next
    `roxy/admin/auth/flow.py` (where a trusted device skips the second factor), then
    `roxy/admin/auth/invalidation.py` (the kill switch that can revoke them).
"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
from dataclasses import dataclass

TRUSTED_COOKIE = "__Host-roxy_trusted"
MAX_DEVICES_PER_USER = 20
DAY_S = 86_400

_BROWSERS: tuple[tuple[str, str, str], ...] = (
    # (needle in the lowercased UA, family id, display name), checked in order: Edge and Opera also say "chrome".
    ("edg/", "edge", "Edge"),
    ("edga/", "edge", "Edge"),
    ("edgios/", "edge", "Edge"),
    ("opr/", "opera", "Opera"),
    ("firefox/", "firefox", "Firefox"),
    ("fxios/", "firefox", "Firefox"),
    ("crios/", "chrome", "Chrome"),
    ("chrome/", "chrome", "Chrome"),
    ("safari/", "safari", "Safari"),
)
_SYSTEMS: tuple[tuple[str, str, str], ...] = (
    # Android says "linux" and iOS says "mac os x", so both are checked before those.
    ("android", "android", "Android"),
    ("iphone", "ios", "iOS"),
    ("ipad", "ios", "iOS"),
    ("windows", "windows", "Windows"),
    ("cros", "chromeos", "ChromeOS"),
    ("mac os x", "macos", "macOS"),
    ("macintosh", "macos", "macOS"),
    ("linux", "linux", "Linux"),
)


def _classify(ua: str | None) -> tuple[str, str, str, str]:
    text = (ua or "").lower()
    browser = next(((fam, name) for needle, fam, name in _BROWSERS if needle in text), ("other", "Another browser"))
    system = next(((fam, name) for needle, fam, name in _SYSTEMS if needle in text), ("other", "another system"))
    return browser[0], system[0], browser[1], system[1]


def ua_family(ua: str | None) -> str:
    """`<browser>/<os>` of a User-Agent, versions ignored (for example `chrome/windows`)."""
    browser, system, _, _ = _classify(ua)
    return f"{browser}/{system}"


def device_name(ua: str | None) -> str:
    """A readable name for the device list, for example `Firefox on Linux`."""
    _, _, browser, system = _classify(ua)
    return f"{browser} on {system}"


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class TrustedDevice:
    id: int
    user_id: int
    name: str | None
    ua_family: str | None
    created_at: int
    last_used_at: int | None
    expires_at: int


def issue(conn: sqlite3.Connection, *, user_id: int, ua: str | None, now: int, days: int) -> str:
    """Trust this browser for `days` days. Returns the cookie token (stored only as a hash)."""
    token = secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO trusted_devices (token_hash, user_id, name, ua_family, created_at, last_used_at, expires_at) "
        "VALUES (?, ?, ?, ?, ?, NULL, ?)",
        (hash_token(token), user_id, device_name(ua), ua_family(ua), now, now + max(1, days) * DAY_S),
    )
    conn.execute(
        "DELETE FROM trusted_devices WHERE user_id = ? AND id NOT IN (SELECT id FROM trusted_devices "
        "WHERE user_id = ? ORDER BY created_at DESC, id DESC LIMIT ?)",
        (user_id, user_id, MAX_DEVICES_PER_USER),
    )
    return token


def find_valid(conn: sqlite3.Connection, token: str | None, ua: str | None, now: int) -> TrustedDevice | None:
    """The device for `token` when it exists, has not expired, and matches this browser family."""
    if not token or len(token) > 100:
        return None
    row = conn.execute(
        "SELECT id, user_id, name, ua_family, created_at, last_used_at, expires_at FROM trusted_devices "
        "WHERE token_hash = ?",
        (hash_token(token),),
    ).fetchone()
    if row is None or int(row[6]) <= now or row[3] != ua_family(ua):
        return None
    return TrustedDevice(int(row[0]), int(row[1]), row[2], row[3], int(row[4]), row[5], int(row[6]))


def touch(conn: sqlite3.Connection, device_id: int, now: int) -> None:
    conn.execute("UPDATE trusted_devices SET last_used_at = ? WHERE id = ?", (now, device_id))


def list_for_user(conn: sqlite3.Connection, user_id: int, now: int) -> list[dict[str, object]]:
    rows = conn.execute(
        "SELECT id, name, ua_family, created_at, last_used_at, expires_at FROM trusted_devices "
        "WHERE user_id = ? AND expires_at > ? ORDER BY created_at DESC",
        (user_id, now),
    ).fetchall()
    return [
        {
            "Id": int(row[0]),
            "Name": row[1],
            "Family": row[2],
            "CreatedAt": int(row[3]),
            "LastUsedAt": row[4],
            "ExpiresAt": int(row[5]),
        }
        for row in rows
    ]


def revoke(conn: sqlite3.Connection, user_id: int, device_id: int) -> bool:
    return conn.execute("DELETE FROM trusted_devices WHERE id = ? AND user_id = ?", (device_id, user_id)).rowcount > 0


def revoke_all(conn: sqlite3.Connection, user_id: int | None = None) -> int:
    """Revoke every trusted device of one admin, or of every admin when `user_id` is None (kill switch)."""
    if user_id is None:
        return conn.execute("DELETE FROM trusted_devices").rowcount
    return conn.execute("DELETE FROM trusted_devices WHERE user_id = ?", (user_id,)).rowcount
