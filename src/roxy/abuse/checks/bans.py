"""Check 2, bans and the deny list: known bad actors are refused right after the pause check.

What this is
    `BansCheck` (plan 4.1 row 5: "bans and deny list right after pause"). It refuses a request whose IP, CIDR,
    `Roblox-Id` place or User-Agent hash has an active ban, or whose IP is on the deny list (`access_list`, kind
    `deny`).

Why it exists
    Plan 10.5: once an abuser is identified, refuse them before any other work. Bypass does not skip this check
    (an admin's ban always wins over an old bypass entry).

How it works
    - Lookups are in the rules snapshot (CIDR index, dictionaries), checked against the expiry at lookup time.
    - With `ban_disguise_as_throttle` (default on) the refusal is byte-identical to an ordinary throttle refusal
      (`Roxy-Refusal: throttle`), so the abuser does not learn they are banned; otherwise 403 `Access denied.` with
      `Roxy-Refusal: banned` (or `deny_list`). The deny list follows the same switch (a v2 decision: the list is a
      permanent ban by network). The disguise is rendered after the transaction with the client's real strikes and
      penalty (`checks/base.py redisguise`): a client on rung 3 keeps getting the rung 3 text once banned, exactly
      what a genuine throttle refusal would say at that moment.
    - Every ban hit is counted in memory and flushed to `bans.hits` in batches. Tarpit category `ban`, never for a
      caller on the bypass list (the pipeline marks bypass before any check, so the router knows it whichever check
      refuses).

What to read next
    `roxy/abuse/bans.py`, then `roxy/abuse/checks/bypass.py` (the next check).
"""

from __future__ import annotations

from typing import Any

from roxy.abuse.bans import find_ban
from roxy.abuse.checks.base import Check, Facts, LimitSpec, disguised_throttle, refusal_headers
from roxy.abuse.messages import ACCESS_DENIED, REASON_BAN, REASON_DENY
from roxy.abuse.verdict import Refuse
from roxy.core.reasons import ReasonCode


class BansCheck(Check):
    name = "bans"
    position = 20
    label = "Bans and deny list"
    tarpit_category = "ban"

    def prepare(self, req: Any, facts: Facts) -> Refuse | LimitSpec | None:
        ban = find_ban(
            facts.rules, ip=facts.ip, place=getattr(req, "place_id", None), user_agent=req.user_agent, now=facts.now
        )
        if ban is not None:
            facts.services.ban_hits.record(ban.id, int(facts.now))
            return self._refuse(
                facts, ReasonCode.BANNED, REASON_BAN.format(subject_type=ban.subject_type, subject=ban.subject)
            )
        deny = facts.rules.access.deny.match(facts.ip, facts.now) if facts.ip else None
        if deny is not None:
            return self._refuse(facts, ReasonCode.DENY_LIST, REASON_DENY.format(cidr=deny.cidr))
        return None

    def _refuse(self, facts: Facts, reason: ReasonCode, detail: str) -> Refuse:
        if facts.bool("ban_disguise_as_throttle"):
            return disguised_throttle(
                facts, reason=reason, check=self.name, tarpit_category=self.tarpit_category, detail=detail
            )
        return Refuse(
            status=403,
            body=ACCESS_DENIED,
            reason=reason,
            check=self.name,
            headers=refusal_headers(reason),
            tarpit_category=self.tarpit_category,
            detail=detail,
        )


__all__ = ["BansCheck"]
