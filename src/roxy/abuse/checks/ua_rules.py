"""Check 11, User-Agent rules: limits for clients whose User-Agent matches an admin rule.

What this is
    `UaRuleCheck` (plan 4.3 row 44). The matching and messages live in `roxy/abuse/ua_rules.py`; the budget is a
    limiter row evaluated in the pipeline's single hot.db transaction.

Why it exists
    v1 parity, with two fixes: the tarpit switch `tarpit_on_user_agent_rule` finally exists (v1 bug B1), and a UA
    rule budget is no longer spent by a request that a later check refuses anyway (plan 6.3).

How it works
    First matching enabled rule (master switch `user_agent_rules_enabled`). Burst: fixed window of `limit` per
    `period`; cooldown: one request per `cooldown` seconds (a refused retry does not move the clock). Refusal 429:
    the rule's message or v1's default text; `Retry-After`, `Roxy-Throttle-Reset` (the same seconds),
    `Roxy-Throttled: True`, `Roxy-Client-Limited: True`. Tarpit category `user_agent_rule`. Bypass entries skip it.
    The pipeline counts every evaluated rule as a hit, allowed or refused (row 76), also as an aggregated
    `ua_rule_hit` event for the metrics; the matching rule row is also reported as a rule hit (`facts.note_match`)
    for the per-minute hit history, even when an earlier limiter refused the request first. Matching can run admin
    regexes (`uses_patterns`), so while regex rules exist it runs only for a request the cheaper limiters before it
    admitted (`roxy/abuse/pipeline.py`).

What to read next
    `roxy/abuse/ua_rules.py`, then `roxy/abuse/checks/ignored_paths.py`.
"""

from __future__ import annotations

from typing import Any

from roxy.abuse.checks.base import (
    TABLE_UA_RULE,
    Algo,
    Check,
    Facts,
    LimitSpec,
    TxState,
    refusal_headers,
    with_trio,
)
from roxy.abuse.messages import REASON_UA_RULE
from roxy.abuse.ua_rules import match_ua_rule, ua_limit, ua_message
from roxy.abuse.verdict import TRUE, Refuse
from roxy.core.reasons import ReasonCode


class UaRuleCheck(Check):
    name = "user_agent_rule"
    position = 100
    label = "User-Agent rules"
    kind = "limiter"
    skipped_by_bypass = True
    tarpit_category = "user_agent_rule"
    uses_patterns = True

    def prepare(self, req: Any, facts: Facts) -> Refuse | LimitSpec | None:
        rule = match_ua_rule(facts.rules, req.user_agent, enabled=facts.bool("user_agent_rules_enabled"))
        if rule is None:
            return None
        facts.note_match(TABLE_UA_RULE, rule.id)  # matched, whether its budget admits or refuses
        limit = ua_limit(rule, facts.limit_key)
        algo: Algo = "cooldown" if limit.kind == "cooldown" else "fixed"
        return LimitSpec(
            self.name,
            limit.key,
            algo,
            limit=limit.limit,
            window_s=limit.period,
            cooldown_s=limit.cooldown_s,
            payload=rule,
        )

    async def check(self, req: Any, tx: TxState) -> Refuse | None:
        outcome = tx.outcomes.get(self.name)
        if outcome is None or outcome.admitted:
            return None
        rule = outcome.spec.payload
        retry = outcome.retry_after_s
        text, source = ua_message(rule, retry)
        refusal = Refuse(
            status=429,
            body=text,
            reason=ReasonCode.USER_AGENT_RULE,
            check=self.name,
            headers=refusal_headers(
                ReasonCode.USER_AGENT_RULE,
                Retry_After=retry,
                Roxy_Throttle_Reset=retry,
                Roxy_Throttled=TRUE,
                Roxy_Client_Limited=TRUE,
            ),
            tarpit_category=self.tarpit_category,
            message_source=source,
            detail=REASON_UA_RULE.format(needle=rule.needle),
        )
        return with_trio(refusal, tx)


__all__ = ["UaRuleCheck"]
