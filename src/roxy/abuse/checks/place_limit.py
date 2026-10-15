"""Check 8, place limit: an optional budget per Roblox experience (`Roblox-Id` header), off by default (D11).

What this is
    `PlaceLimitCheck` (plan 10.1, D11): a GCRA limit of `place_limit_per_minute` per 60 s per place, enforced only
    when `place_limit_enabled` is on and the request names a place.

Why it exists
    One experience can run on hundreds of game-server IPs, so per-IP limits cannot bound it. A per-place budget can,
    but `Roblox-Id` is a claim anyone can forge: with `place_limit_key = place_prefix` (default) the budget is per
    place AND caller network (/24 for IPv4, /48 for IPv6), so a forger only spends their own network's share.

How it works
    Limiter row `place:<id>` or `place:<id>|<network>`, evaluated in the single hot.db transaction. Refusal 429 with
    `Retry-After`; tarpit category `throttle`. Bypass entries skip it.

What to read next
    `roxy/abuse/limiter.py`, then `roxy/abuse/checks/challenge.py`.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from roxy.abuse.checks.base import Check, Facts, LimitSpec, TxState, refusal_headers, with_trio
from roxy.abuse.messages import PLACE_LIMIT_DEFAULT, REASON_PLACE
from roxy.abuse.verdict import TRUE, Refuse
from roxy.core.reasons import ReasonCode


def caller_network(ip: str, fallback: str) -> str:
    """The caller's /24 (IPv4) or /48 (IPv6) network, or `fallback` when `ip` is not an address."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return fallback
    prefix = 24 if address.version == 4 else 48
    return str(ipaddress.ip_network((address, prefix), strict=False))


class PlaceLimitCheck(Check):
    name = "place_limit"
    position = 80
    label = "Place limit"
    kind = "limiter"
    skipped_by_bypass = True
    tarpit_category = "throttle"

    def prepare(self, req: Any, facts: Facts) -> Refuse | LimitSpec | None:
        place = getattr(req, "place_id", None)
        if not place or not facts.bool("place_limit_enabled"):
            return None
        key = f"place:{place}"
        if facts.str("place_limit_key") == "place_prefix":
            key += "|" + caller_network(facts.ip, facts.limit_key)
        limit = max(1, facts.int("place_limit_per_minute"))
        return LimitSpec(self.name, key, "gcra", limit=limit, window_s=60)

    async def check(self, req: Any, tx: TxState) -> Refuse | None:
        outcome = tx.outcomes.get(self.name)
        if outcome is None or outcome.admitted:
            return None
        retry = outcome.retry_after_s
        refusal = Refuse(
            status=429,
            body=PLACE_LIMIT_DEFAULT.format(retry=retry),
            reason=ReasonCode.PLACE_LIMIT,
            check=self.name,
            headers=refusal_headers(
                ReasonCode.PLACE_LIMIT, Retry_After=retry, Roxy_Throttle_Reset=retry, Roxy_Throttled=TRUE
            ),
            tarpit_category=self.tarpit_category,
            detail=REASON_PLACE.format(limit=outcome.spec.limit),
        )
        return with_trio(refusal, tx)


__all__ = ["PlaceLimitCheck", "caller_network"]
