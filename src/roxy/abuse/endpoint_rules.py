"""Endpoint rate rules: "at most N requests per P seconds to this pattern", per IP, per place, or for everyone.

What this is
    `match_endpoint_rule` (the most specific enabled rule for a target), `endpoint_limit` (the limiter key and the
    effective limit for one request) and `endpoint_rule_message` (the rule's message or v1's default text). Plan 4.3
    row 43.

Why it exists
    Some endpoints are expensive for Roblox or popular with scrapers. A per-endpoint limit protects them without
    lowering every client's general allowance. v1 counted per IP and pattern; v2 adds the `place` scope (one budget
    per claimed experience) and `global` (one budget for everyone).

How it works
    - Matching is the shared matcher (row 111): most specific wins, ties to the lowest id; a timed out regex counts
      as a match (fail closed).
    - Scope `ip`: key `ep:<rule id>|<limit key>`, and the limit is clamped to `allowed_requests_per_minute` (v1: a
      rule can only make an endpoint stricter than the general per-IP allowance, never looser; only the count is
      clamped, the rule keeps its own period). Scope `place`: key `ep:<id>|place:<place id>` (a request without a
      `Roblox-Id` falls back to its IP budget). Scope `global`: key `ep:<id>|*`. The non-IP scopes are not clamped,
      because a fleet-wide budget is naturally larger than one client's.
    - The window is v1's fixed window (`limiter.fixed`), evaluated in the pipeline's single hot.db transaction.
      `Retry-After` and the "try again in N seconds" text use a true ceiling of at least 1 (v1 could say 0, B16).

What to read next
    `roxy/abuse/limiter.py` (`fixed`), then `roxy/abuse/checks/endpoint_rules.py`.
"""

from __future__ import annotations

from roxy.abuse.messages import ENDPOINT_RULE_DEFAULT, clean_admin_message
from roxy.abuse.verdict import MessageSource
from roxy.rules.models import EndpointLimitRow
from roxy.rules.store import RulesSnapshot

KEY_PREFIX = "ep:"


def match_endpoint_rule(snapshot: RulesSnapshot, target: str) -> EndpointLimitRow | None:
    """The rule that covers `target` (`host/path`), or None (v1 `match_endpoint_rule`)."""
    return snapshot.endpoint_limit_for(target)


def endpoint_limit(
    rule: EndpointLimitRow, *, limit_key: str, place_id: str | None, allowed_per_ip: int
) -> tuple[str, int, int]:
    """`(limiter key, effective limit, period seconds)` for one request under `rule`."""
    period = max(1, int(rule.period or 60))
    limit = max(1, int(rule.limit or 1))
    scope = (rule.scope or "ip").lower()
    if scope == "global":
        return f"{KEY_PREFIX}{rule.id}|*", limit, period
    if scope == "place" and place_id:
        return f"{KEY_PREFIX}{rule.id}|place:{place_id}", limit, period
    if allowed_per_ip:
        limit = min(limit, int(allowed_per_ip))  # v1 clamp: never looser than the general per-IP allowance
    return f"{KEY_PREFIX}{rule.id}|{limit_key}", max(1, limit), period


def endpoint_rule_message(rule: EndpointLimitRow, retry: int) -> tuple[str, MessageSource]:
    """`(text, message_source)`: the rule's message, or the v1 default with the retry seconds."""
    text = clean_admin_message(rule.message)
    return (text, "custom") if text else (ENDPOINT_RULE_DEFAULT.format(retry=retry), "default")


__all__ = ["KEY_PREFIX", "endpoint_limit", "endpoint_rule_message", "match_endpoint_rule"]
