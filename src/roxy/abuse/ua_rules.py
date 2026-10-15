"""User-Agent rules: limits for clients whose User-Agent matches a needle (burst or cooldown, per IP or global).

What this is
    `match_ua_rule` (the FIRST enabled rule whose needle matches, v1 order), `ua_limit` (the limiter key and kind for
    one request), `ua_message` (the rule's message or v1's default text), and `explain_user_agent_rules`, the dry-run
    tester behind the Protection > User-Agent rules card (plan 4.3 row 44).

Why it exists
    Scrapers often announce themselves (`python-requests`, a bot name) while sharing IPs with legitimate traffic. A
    UA rule slows exactly those clients: `burst` allows N requests per period, `cooldown` one request per N seconds,
    either per calling IP or shared by every IP sending that UA (`global`).

How it works
    - Needles match with v1 semantics (`rules/match.py text_matches`: contains, exact, or a case-insensitive regex
      search with a timeout). A regex cut off by its timeout counts as a match (fail closed).
    - First match wins, in the stored order (position, then creation). The master switch
      `user_agent_rules_enabled` turns every rule off at once.
    - Keys: `ua:<rule id>|<limit key>` (scope ip) or `ua:<rule id>|*` (global). Not clamped to the per-IP allowance
      (v1). Burst rules use the v1 fixed window; cooldown rules `limiter.cooldown`.
    - The tester shows every rule's result and reflects the master switch (v1 bug B13 ignored it).

What to read next
    `roxy/abuse/limiter.py` (`fixed`, `cooldown`), then `roxy/abuse/checks/ua_rules.py`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from roxy.abuse.messages import clean_admin_message, ua_default
from roxy.abuse.verdict import MessageSource
from roxy.config.constants import DEFAULT_USER_AGENT_RULE_COOLDOWN
from roxy.rules.match import text_matches
from roxy.rules.models import UserAgentRuleIn, UserAgentRuleRow
from roxy.rules.store import RulesSnapshot

KEY_PREFIX = "ua:"


@dataclass(frozen=True, slots=True)
class UaLimit:
    """How one request is limited by a matched rule."""

    key: str
    kind: str  # "burst" or "cooldown"
    limit: int
    period: int
    cooldown_s: float


def ua_matches(rule: Any, user_agent: str) -> bool:
    """v1 `_user_agent_matches` (an empty needle never matches; a timed out regex counts as a match)."""
    return text_matches(str(rule.mode or "contains"), str(rule.needle or ""), user_agent or "", on_timeout=True)


def match_ua_rule(snapshot: RulesSnapshot, user_agent: str, *, enabled: bool = True) -> UserAgentRuleRow | None:
    """The first enabled rule whose needle matches `user_agent`, or None (v1 `match_user_agent_rule`)."""
    if not enabled:
        return None
    for rule in snapshot.enabled_ua_rules:
        if ua_matches(rule, user_agent):
            return rule
    return None


def ua_limit(rule: UserAgentRuleRow, limit_key: str) -> UaLimit:
    """The limiter key and parameters for one request (v1 `check_user_agent_rule`)."""
    who = limit_key if (rule.scope or "ip") == "ip" else "*"
    cooldown = float(rule.cooldown if rule.cooldown is not None else DEFAULT_USER_AGENT_RULE_COOLDOWN)
    return UaLimit(
        key=f"{KEY_PREFIX}{rule.id}|{who}",
        kind="cooldown" if rule.kind == "cooldown" else "burst",
        limit=max(1, int(rule.limit or 10)),
        period=max(1, int(rule.period or 60)),
        cooldown_s=cooldown,
    )


def ua_message(rule: UserAgentRuleRow, retry: int) -> tuple[str, MessageSource]:
    """`(text, message_source)`: the rule's message, or the v1 burst or cooldown default text."""
    text = clean_admin_message(rule.message)
    if text:
        return text, "custom"
    return ua_default(rule.kind, rule.limit, rule.period, rule.cooldown, retry), "default"


def explain_user_agent_rules(
    snapshot: RulesSnapshot, user_agent: str, *, enabled: bool, draft: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """The tester: which rules match `user_agent`, which one would limit it, and how a draft rule would behave."""
    rules = []
    first: str | None = None
    for rule in snapshot.ua_rules:
        matched = ua_matches(rule, user_agent)
        is_first = bool(enabled and rule.enabled and matched and first is None)
        if is_first:
            first = rule.id
        rules.append(
            {
                "id": rule.id,
                "needle": rule.needle,
                "mode": rule.mode,
                "kind": rule.kind,
                "scope": rule.scope,
                "enabled": rule.enabled,
                "matched": matched,
                "is_first_match": is_first,
            }
        )
    result: dict[str, Any] = {
        "user_agent": user_agent,
        "rules_enabled": enabled,
        "limited": first is not None,
        "limited_by": first,
        "rules": rules,
        "draft": None,
    }
    if draft is not None:
        try:
            model = UserAgentRuleIn.model_validate(dict(draft))
        except ValidationError as exc:
            message = exc.errors()[0].get("msg", "Invalid rule") if exc.errors() else "Invalid rule"
            result["draft"] = {"valid": False, "error": str(message)}
        else:
            matched = text_matches(model.mode, model.needle, user_agent, on_timeout=True)
            result["draft"] = {
                "valid": True,
                "error": "",
                **model.model_dump(),
                "matched": matched,
                "already_matched": first is not None,
            }
    return result


__all__ = ["KEY_PREFIX", "UaLimit", "explain_user_agent_rules", "match_ua_rule", "ua_limit", "ua_matches", "ua_message"]
