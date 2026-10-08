"""Check 16, header filters: refuse requests whose headers match an admin filter (plan 4.3 row 45).

What this is
    `HeaderRuleCheck`. Matching lives in `roxy/abuse/header_rules.py`.

Why it exists
    v1 parity: the first filter that hits refuses the request with 429. Without a custom message the refusal is
    disguised as an ordinary throttle (the rung message for the client's current strikes, `Retry-After` and
    `Roxy-Throttle-Reset` equal to `throttle_reset_duration`), so the tool author cannot tell a filter caught them.

How it works
    The rule is found before the transaction (no I/O), but only once the cheap limiters admitted the request when
    regex rules exist (`uses_patterns`, see `roxy/abuse/pipeline.py`); the disguised body is rendered after the
    transaction (`checks/base.py redisguise`), because it depends on the client's strikes and penalty, which the
    transaction read. A custom message is sent as is with `Roxy-Refusal:
    header_rule` (v2 adds `Retry-After`, v1 bug B8). Neither form counts toward the per-IP limit or adds a strike
    (v1). Tarpit category `header_rule` (on by default) with v1's reason `Filter <id> (matched <Header>)`. Bypass
    does not skip it.

What to read next
    `roxy/abuse/header_rules.py`, then `roxy/abuse/checks/blocks.py`.
"""

from __future__ import annotations

from typing import Any

from roxy.abuse.checks.base import Check, Facts, LimitSpec, disguised_throttle, refusal_headers
from roxy.abuse.header_rules import header_pairs, header_rule_message, match_header_rule
from roxy.abuse.messages import REASON_HEADER_RULE
from roxy.abuse.verdict import TRUE, Refuse, title_case_header
from roxy.core.reasons import ReasonCode


class HeaderRuleCheck(Check):
    name = "header_rule"
    position = 150
    label = "Request filters (header rules)"
    tarpit_category = "header_rule"
    uses_patterns = True

    def prepare(self, req: Any, facts: Facts) -> Refuse | LimitSpec | None:
        if not facts.rules.enabled_header_rules:
            return None
        if facts.pairs_cache is None:
            facts.pairs_cache = header_pairs(req)
        hit = match_header_rule(facts.rules, facts.pairs_cache)
        if hit is None:
            return None
        detail = REASON_HEADER_RULE.format(rule_id=hit.rule_id, header=title_case_header(hit.header))
        message = header_rule_message(hit.rule)
        if not message:
            return disguised_throttle(
                facts,
                reason=ReasonCode.HEADER_RULE,
                check=self.name,
                tarpit_category=self.tarpit_category,
                detail=detail,
            )
        window = max(1, facts.int("throttle_reset_duration", 50))
        return Refuse(
            status=429,
            body=message,
            reason=ReasonCode.HEADER_RULE,
            check=self.name,
            headers=refusal_headers(
                ReasonCode.HEADER_RULE, Retry_After=window, Roxy_Throttle_Reset=window, Roxy_Throttled=TRUE
            ),
            tarpit_category=self.tarpit_category,
            message_source="custom",
            detail=detail,
        )

    # `check` is the base class's: a disguised refusal is rendered again with the client's real strikes and
    # penalty (read by the transaction), exactly like v1's disguise; a custom message gets the per-IP trio.


__all__ = ["HeaderRuleCheck"]
