"""Check 15b, the endpoint policy: refuse Roblox endpoints that act on an account or read its private data.

What this is
    `EndpointPolicyCheck`, position 145: after auth smuggling (140), before request filters (150) and the admin's
    own endpoint blocks (160).

Why it exists
    D1 revised (2026-10-16): Roxy sends its own Roblox account with caller requests, so every endpoint that could
    act on that account, read its private data, or touch sign-in and security flows must never reach Roblox at all
    (`docs/endpoint_policy/BRIEF.md`). The verdicts come from `RulesSnapshot.endpoint_policy`
    (`roxy/policy/engine.py`): the shipped seed plus the admin's overrides and category switches.

How it works
    A BLOCK verdict refuses with the status `endpoint_policy_block_status` (403 by default) and the body
    `endpoint_policy_block_message`, the headers `Roxy-Blocked: policy` and `Roxy-Refusal: endpoint_policy`, and
    no tarpit (most of these are honest mistakes). `detail` names the operation and where the verdict came from, for
    the dashboard only. With `endpoint_policy_enforce` off (shadow mode) a BLOCK is not refused; the request goes
    on without the account (the credential is only ever granted for ALLOW_TOKEN) and the pipeline records a
    `policy_would_block` event, and every real refusal a `policy_blocked` counter event (refusals per operation
    for the page). Every decision for an operation Roblox does not document is recorded as a
    `policy_unknown` counter event, so the Endpoint policy page can list what callers ask for that has no review
    yet. Bypass entries are refused too. The matching is the seed's own template index (no admin regex), so it is
    not deferred like the pattern checks.

What to read next
    `roxy/policy/engine.py`, then `roxy/abuse/checks/header_rules.py`.
"""

from __future__ import annotations

from typing import Any, Final

from roxy.abuse.checks.base import Check, Facts, LimitSpec, refusal_headers
from roxy.abuse.verdict import Refuse
from roxy.core.reasons import ReasonCode
from roxy.policy.engine import PolicyDecision

POLICY_UNKNOWN_EVENT: Final = "policy_unknown"
POLICY_WOULD_BLOCK_EVENT: Final = "policy_would_block"
POLICY_BLOCKED_EVENT: Final = "policy_blocked"
BLOCK_STATUSES: Final = frozenset({403, 404, 500})


def decision_for(req: Any, facts: Facts) -> PolicyDecision:
    """The endpoint policy's decision for this request (also kept on `facts` for the pipeline's records)."""
    host = str(getattr(req, "host", "") or "")
    path = str(getattr(req, "path", "") or "/")
    method = str(getattr(req, "method", "GET") or "GET")
    query = list(getattr(req, "query", None) or ())
    template = str(getattr(req, "template", "") or "") or None
    return facts.rules.endpoint_policy.decide(host, method, path, query, template)


def detail_of(decision: PolicyDecision) -> str:
    """Roxy's own words for the records: the operation and where its verdict came from (never caller text)."""
    return f"{decision.endpoint_id} ({decision.source}, {decision.category})"[:300]


class EndpointPolicyCheck(Check):
    name = "endpoint_policy"
    position = 145
    label = "Endpoint policy"
    tarpit_category = None

    def prepare(self, req: Any, facts: Facts) -> Refuse | LimitSpec | None:
        if getattr(req, "target_problem", None) is not None:
            return None  # an invalid target was refused earlier (unsafe URL, not Roblox)
        decision = decision_for(req, facts)
        facts.policy = decision
        if not decision.blocked or not facts.flag("endpoint_policy_enforce"):
            return None
        status = int(facts.setting("endpoint_policy_block_status") or 403)
        return Refuse(
            status=status if status in BLOCK_STATUSES else 403,
            body=facts.str("endpoint_policy_block_message").strip() or "This Roblox endpoint is blocked by Roxy.",
            reason=ReasonCode.ENDPOINT_POLICY,
            check=self.name,
            headers=refusal_headers(ReasonCode.ENDPOINT_POLICY, Roxy_Blocked="policy"),
            tarpit_category=None,
            message_source="custom",
            detail=detail_of(decision),
        )


__all__ = [
    "POLICY_BLOCKED_EVENT",
    "POLICY_UNKNOWN_EVENT",
    "POLICY_WOULD_BLOCK_EVENT",
    "EndpointPolicyCheck",
    "decision_for",
    "detail_of",
]
