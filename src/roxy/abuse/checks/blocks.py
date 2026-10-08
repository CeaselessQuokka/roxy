"""Check 17, endpoint blocks: 403 for endpoints the admin blocked (plan 4.3 row 46).

What this is
    `BlockCheck`. Matching and texts live in `roxy/abuse/blocks.py`.

Why it exists
    v1 parity: the most specific enabled block covering the request target refuses it with 403, the block's public
    message or `This endpoint is currently blocked.`, and `Roxy-Blocked: True`.

How it works
    Matched against `host/path` (normalized like v1). Tarpit category `blocked_endpoint` with v1's reason
    `Block rule: <pattern>`. Applies to bypass entries too (only their tarpit hold is skipped). A block can be an
    admin regex (`uses_patterns`), so while regex rules exist it runs only for a request the cheap limiters admitted.

What to read next
    `roxy/abuse/blocks.py`, then `roxy/abuse/checks/endpoint_rules.py`.
"""

from __future__ import annotations

from typing import Any

from roxy.abuse.blocks import block_message, match_block
from roxy.abuse.checks.base import Check, Facts, LimitSpec, refusal_headers
from roxy.abuse.messages import REASON_BLOCK_RULE
from roxy.abuse.verdict import TRUE, Refuse
from roxy.core.reasons import ReasonCode


class BlockCheck(Check):
    name = "endpoint_blocked"
    position = 160
    label = "Endpoint blocks"
    tarpit_category = "blocked_endpoint"
    uses_patterns = True

    def prepare(self, req: Any, facts: Facts) -> Refuse | LimitSpec | None:
        if not facts.rules.endpoint_blocks:
            return None
        rule = match_block(facts.rules, facts.target)
        if rule is None:
            return None
        text, source = block_message(rule)
        return Refuse(
            status=403,
            body=text,
            reason=ReasonCode.ENDPOINT_BLOCKED,
            check=self.name,
            headers=refusal_headers(ReasonCode.ENDPOINT_BLOCKED, Roxy_Blocked=TRUE),
            tarpit_category=self.tarpit_category,
            message_source=source,
            detail=REASON_BLOCK_RULE.format(pattern=rule.pattern),
        )


__all__ = ["BlockCheck"]
