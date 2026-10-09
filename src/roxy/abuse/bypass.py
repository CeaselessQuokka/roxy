"""Bypass: trusted clients that skip the rate limits (v1 "Throttle bypass", now CIDR aware and expiring).

What this is
    `is_bypassed` (the per-request lookup against the `access_list` bypass entries in the rules snapshot), and
    `add_bypass` / `bypass_my_ip`, the audited writers behind the Protection > Bypass card and the "Bypass my IP"
    button (plan 4.1 row 6, rows 111 and 113).

Why it exists
    The owner load-tests Roxy and sometimes runs trusted tools that must not be throttled. v1 kept an exact-IP list
    whose entries never expired unless the admin typed a lifetime, so forgotten load-test entries lingered forever.
    v2 matches CIDR ranges (lead decision 4) and gives every new entry a default expiry (`bypass_default_expiry_h`,
    24 h); "never" needs an explicit confirmation.

How it works
    - A bypassed request skips throttle-all, the per-IP throttle (and is never counted), place limits, User-Agent
      rules, endpoint rate rules and every tarpit hold (v1 semantics), and also the flood limit, the spam
      detectors, the browser challenge and the bot score block (v2 decision: an absolute ceiling, a heuristic block
      or an automatic ban on an address the owner explicitly trusts would defeat the entry). It never skips pause,
      bans, the deny list, ignored paths, probes, auth smuggling checks, header filters or endpoint blocks.
    - The lookup is the snapshot's CIDR index with the expiry checked at lookup time, so an entry stops working the
      second it expires, not at the next reload. `bypass_entry` returns the matching row itself, so every request
      it covers counts as a hit of that row (recorded by the pipeline, in memory).
    - Writes go through `rules/service.py` (one audited control.db transaction plus a `config_version` bump).

What to read next
    `roxy/rules/store.py` (`AccessLists`, `CidrSet`), then `roxy/abuse/checks/bypass.py`.
"""

from __future__ import annotations

from typing import Any, Final

from roxy.config.audit import Actor
from roxy.rules.service import RuleChange, RulesService
from roxy.rules.store import RulesSnapshot

SECONDS_PER_HOUR: Final = 3600


class BypassNeedsConfirmation(ValueError):
    """A bypass entry that never expires was requested without the explicit confirmation."""


def is_bypassed(snapshot: RulesSnapshot, ip: str, now: float) -> bool:
    """Whether an active (unexpired) bypass entry covers `ip`."""
    return bool(ip) and snapshot.access.bypass.contains(ip, now)


def bypass_entry(snapshot: RulesSnapshot, ip: str, now: float) -> Any:
    """The active bypass entry (`AccessListRow`) that covers `ip`, or None: the row whose hits the pipeline records
    (SEC-BYPASS-FOREVER "last hit", FILTER-REMOVE "bypass entry unused")."""
    if not ip:
        return None
    return snapshot.access.bypass.match(ip, now)


def bypass_expires_at(now: float, default_expiry_h: float, expires_in_h: float | None = None) -> int | None:
    """The expiry for a new entry: `expires_in_h` hours if given, else the default; 0 hours means never (None)."""
    hours = default_expiry_h if expires_in_h is None else expires_in_h
    if hours is None or float(hours) <= 0:
        return None
    return int(now + float(hours) * SECONDS_PER_HOUR)


async def add_bypass(
    service: RulesService,
    cidr: str,
    actor: Actor,
    *,
    now: float,
    default_expiry_h: float,
    expires_in_h: float | None = None,
    never: bool = False,
    confirm_never: bool = False,
    note: str = "",
    reason: str = "",
    request_id: str | None = None,
) -> RuleChange:
    """Add a bypass entry. `never=True` requires `confirm_never=True` (plan 4.1 row 6)."""
    if never and not confirm_never:
        raise BypassNeedsConfirmation("A bypass that never expires needs confirmation")
    expires_at = None if never else bypass_expires_at(now, default_expiry_h, expires_in_h)
    row: dict[str, Any] = {"kind": "bypass", "cidr": cidr, "note": note, "expires_at": expires_at}
    return await service.create("access_list", row, actor, reason, request_id=request_id)


async def bypass_my_ip(
    service: RulesService,
    ip: str,
    actor: Actor,
    *,
    now: float,
    default_expiry_h: float,
    request_id: str | None = None,
) -> RuleChange:
    """Row 113: bypass the admin's own address as Roxy resolved it (9.11), with the default expiry."""
    return await add_bypass(
        service,
        ip,
        actor,
        now=now,
        default_expiry_h=default_expiry_h,
        note="Bypass my IP",
        reason="Bypass my IP",
        request_id=request_id,
    )


def never_expiring_entries(snapshot: RulesSnapshot) -> list[Any]:
    """Bypass entries without an expiry (input for the "never-expiring bypass" recommendation)."""
    return [row for row in snapshot.access.rows if row.kind == "bypass" and row.expires_at is None]


__all__ = [
    "BypassNeedsConfirmation",
    "add_bypass",
    "bypass_entry",
    "bypass_expires_at",
    "bypass_my_ip",
    "is_bypassed",
    "never_expiring_entries",
]
