"""The optional admin network allowlist (owner decision D6): every other network gets a plain 404.

What this is
    `admin_ip_allowed(ctx, ip)` answers "may this address see /admin at all?", and `in_admin_allowlist(ctx, ip)`
    answers "is this address on the list?" (used for the global login slow-down exemption, plan 9.5).

Why it exists
    D6: when the owner always logs in from the same networks, hiding /admin from everyone else removes it from
    attackers' view entirely (no login page to guess against). It is off by default
    (`admin_allowlist_enabled=0`) because a changing network would lock the owner out until the setting is changed
    from the server console. Non-listed addresses get the same plain 404 as a path that does not exist, so a
    scanner cannot even tell the dashboard is there.

How it works
    - The list is the `access_list` rows of kind `allow_admin` (CIDR ranges, optional expiry), compiled into the
      in-memory rules snapshot (`rules/store.py`), so the check is a dictionary lookup per request, no database.
    - Turned on with an empty list, it hides /admin from every network, exactly as the setting's help text warns.
      The dashboard should refuse to enable it with an empty list; the console can always turn it off.
    - The kill-switch link is the one exception, decided in `routes.py`: a non-listed network may use a VALID
      link (an invalid one gets the same 404), so the owner can still stop an attacker from a phone on mobile data.

What to read next
    `roxy/admin/auth/deps.py` (where the check runs first on every admin route), then `roxy/rules/store.py`
    (`CidrSet`).
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException


def in_admin_allowlist(ctx: Any, ip: str) -> bool:
    """True when `ip` is inside an active `allow_admin` range (whether or not the allowlist is switched on)."""
    try:
        return bool(ctx.rules.snapshot.access.allow_admin.contains(ip, ctx.clock.now()))
    except AttributeError:
        return False


def allowlist_enabled(ctx: Any) -> bool:
    try:
        return bool(ctx.settings.bool("admin_allowlist_enabled"))
    except (KeyError, AttributeError):
        return False


def admin_ip_allowed(ctx: Any, ip: str) -> bool:
    """True when the allowlist is off, or `ip` is on it."""
    return not allowlist_enabled(ctx) or in_admin_allowlist(ctx, ip)


def not_found() -> HTTPException:
    """The plain 404 every hidden admin route answers with (the same as an unknown path)."""
    return HTTPException(status_code=404, detail="Not Found")
