"""Check 18, endpoint rate rules: per-endpoint limits per IP, per place or for everyone (plan 4.3 row 43).

What this is
    `EndpointRuleCheck`, the last check. The rule matching, keys and texts live in `roxy/abuse/endpoint_rules.py`.

Why it exists
    v1 parity plus the `place` and `global` scopes. The budget is a limiter row evaluated in the single hot.db
    transaction, so it holds exactly across workers.

How it works
    Refusal 429: the rule's message or `This endpoint is rate-limited for you; try again in N seconds.`. Headers as
    v1 (which built them directly): `Roxy-Requests-Left` (the per-IP value), `Roxy-Throttle-Reset` (the rule window's
    remaining seconds), `Roxy-Throttled: True`, `Roxy-Endpoint-Limited: True`; v2 adds `Retry-After` (v1 bug B16:
    none, and "try again in 0 seconds" was possible). Tarpit category `endpoint_rule` with v1's reason
    `Rate rule: <pattern>`. Bypass entries skip it. A rule can be an admin regex (`uses_patterns`), so while regex
    rules exist it is matched only for a request the cheap limiters admitted.

What to read next
    `roxy/abuse/endpoint_rules.py`, then `roxy/abuse/pipeline.py`.
"""

from __future__ import annotations

from typing import Any

from roxy.abuse.checks.base import Check, Facts, LimitSpec, TxState, refusal_headers, with_trio
from roxy.abuse.endpoint_rules import endpoint_limit, endpoint_rule_message, match_endpoint_rule
from roxy.abuse.messages import REASON_RATE_RULE
from roxy.abuse.verdict import TRUE, Refuse
from roxy.core.reasons import ReasonCode


class EndpointRuleCheck(Check):
    name = "endpoint_rule"
    position = 170
    label = "Endpoint rate rules"
    kind = "limiter"
    skipped_by_bypass = True
    tarpit_category = "endpoint_rule"
    uses_patterns = True

    def prepare(self, req: Any, facts: Facts) -> Refuse | LimitSpec | None:
        if not facts.rules.endpoint_limits:
            return None
        rule = match_endpoint_rule(facts.rules, facts.target)
        if rule is None:
            return None
        key, limit, period = endpoint_limit(
            rule,
            limit_key=facts.limit_key,
            place_id=getattr(req, "place_id", None),
            allowed_per_ip=facts.int("allowed_requests_per_minute", 10),
        )
        return LimitSpec(self.name, key, "fixed", limit=limit, window_s=period, payload=rule)

    async def check(self, req: Any, tx: TxState) -> Refuse | None:
        outcome = tx.outcomes.get(self.name)
        if outcome is None or outcome.admitted:
            return None
        rule = outcome.spec.payload
        retry = outcome.retry_after_s
        text, source = endpoint_rule_message(rule, retry)
        refusal = Refuse(
            status=429,
            body=text,
            reason=ReasonCode.ENDPOINT_RULE,
            check=self.name,
            headers=refusal_headers(
                ReasonCode.ENDPOINT_RULE,
                Retry_After=retry,
                Roxy_Throttle_Reset=retry,
                Roxy_Throttled=TRUE,
                Roxy_Endpoint_Limited=TRUE,
            ),
            tarpit_category=self.tarpit_category,
            message_source=source,
            detail=REASON_RATE_RULE.format(pattern=rule.pattern),
        )
        return with_trio(refusal, tx)


__all__ = ["EndpointRuleCheck"]
