"""Adversarial review (lens auth): the per (username, network) login lockout window versus hot.db retention.

What this is
    A reviewer probe. Plan 9.5 and 15.3 G make `admin_login_window_s` a live setting an admin may raise up to
    86400 seconds (24 hours) to count login failures over a longer sliding window. `lockout.reserve` honors that
    window in its own query, but the leader pruned `login_failures` on a FIXED idle of
    `RetentionPolicy.login_failures_idle_s` (3600 s). When the configured window was longer than an hour, the prune
    deleted failure rows still inside the window, so the lockout count silently reset after an hour.

Why it exists
    An owner who lengthens the window to make brute force harder got the opposite: the effective lockout window was
    capped at one hour by retention, so an attacker got `admin_login_max_failures` guesses per hour instead of per
    configured window (C6 and plan 9.5 broken under a realistic setting). Fixed in `storage/retention.py`: the idle
    is the largest window the catalog accepts (`LOGIN_WINDOW_MAX_S`, 86400 s) and never less than the live window.

How it works
    Fill the lockout key with `max_failures` failure slots at time T with a two hour window, advance the fake clock
    to T + 4000 s (inside the two hour window, past the old one hour prune idle), run `prune_login_failures` with
    the default policy, then try one more `reserve`. The key must still be locked.

What to read next
    `roxy/admin/auth/lockout.py` (`reserve`), `roxy/storage/retention.py` (`prune_login_failures`,
    `RetentionPolicy.login_failures_idle_s`).
"""

from __future__ import annotations

from typing import Any

from roxy.admin.auth import lockout
from roxy.storage.retention import RetentionPolicy, prune_login_failures

WINDOW_S = 7200  # the admin raised admin_login_window_s to two hours (range allows up to 86400)
MAX_FAILURES = 5
ADVANCE_S = 4000  # inside the two hour window, but past RetentionPolicy.login_failures_idle_s (3600)


async def test_lockout_window_longer_than_an_hour_survives_retention(dbs: Any) -> None:
    key = lockout.lockout_key("owner", "203.0.113.7")
    now = 1_760_000_000

    def fill(conn: Any) -> None:
        for _ in range(MAX_FAILURES):
            reservation = lockout.reserve(conn, key, now, MAX_FAILURES, WINDOW_S)
            assert reservation.allowed, "each of the first max_failures attempts takes a slot"

    await dbs.hot.write(fill)

    # The sixth attempt, still at T, is locked out: the configured window has no room left.
    locked = await dbs.hot.write(lambda conn: lockout.reserve(conn, key, now, MAX_FAILURES, WINDOW_S))
    assert not locked.allowed, "the key is locked once max_failures slots are in the window"

    # The leader runs retention while the attacker waits less than the configured window (but more than an hour).
    later = now + ADVANCE_S
    await dbs.hot.write(lambda conn: prune_login_failures(conn, later, RetentionPolicy(), 10_000))

    # Still inside admin_login_window_s, so the lockout must still hold.
    after = await dbs.hot.write(lambda conn: lockout.reserve(conn, key, later, MAX_FAILURES, WINDOW_S))
    assert not after.allowed, (
        "the lockout must hold for the full admin_login_window_s; retention must not prune failures still inside it"
    )
