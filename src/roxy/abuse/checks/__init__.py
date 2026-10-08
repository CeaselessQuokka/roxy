"""The abuse checks, one module each, and their binding order (DESIGN.md 11.1 step 4, plan 4.1 row 5).

What this is
    `default_checks()` returns a fresh, position-ordered list of every check object:
    pause -> bans and deny list -> bypass -> flood -> spam -> throttle-all -> per-IP throttle -> place limit ->
    challenge -> bot score -> User-Agent rules -> ignored path -> unsafe URL -> not Roblox / host allowlist ->
    auth smuggling -> header filters -> endpoint blocks -> endpoint rate rules.

Why it exists
    The order is part of the contract: it decides which refusal a caller sees when several apply (a throttled
    client probing a non-Roblox URL gets 429, not 404, exactly as in v1) and which checks a bypass entry skips. Keeping
    it in one list with explicit positions makes it testable and lets the Protection page draw the pipeline.

How it works
    Each check is a small object (`checks/base.py Check`) with a `name`, a `position` (gaps of 10 leave room for new
    checks at documented places), `skipped_by_bypass`, a tarpit category, `prepare` and `check`. The pipeline sorts
    by position, so the list order here is only for reading.

What to read next
    `roxy/abuse/checks/base.py`, then each check in order starting with `roxy/abuse/checks/pause.py`.
"""

from __future__ import annotations

from roxy.abuse.checks.auth_smuggling import AuthSmugglingCheck
from roxy.abuse.checks.bans import BansCheck
from roxy.abuse.checks.base import Check
from roxy.abuse.checks.blocks import BlockCheck
from roxy.abuse.checks.bypass import BypassCheck
from roxy.abuse.checks.challenge import BotScoreCheck, ChallengeCheck
from roxy.abuse.checks.endpoint_rules import EndpointRuleCheck
from roxy.abuse.checks.flood import FloodCheck
from roxy.abuse.checks.header_rules import HeaderRuleCheck
from roxy.abuse.checks.ignored_paths import IgnoredPathCheck
from roxy.abuse.checks.pause import PauseCheck
from roxy.abuse.checks.place_limit import PlaceLimitCheck
from roxy.abuse.checks.probe import NotRobloxCheck, UnsafeUrlCheck
from roxy.abuse.checks.spam import SpamCheck
from roxy.abuse.checks.throttle import ThrottleCheck
from roxy.abuse.checks.throttle_all import ThrottleAllCheck
from roxy.abuse.checks.ua_rules import UaRuleCheck

PIPELINE_ORDER: tuple[str, ...] = (
    "pause",
    "bans",
    "bypass",
    "flood",
    "spam",
    "throttle_all",
    "throttle",
    "place_limit",
    "challenge",
    "bot_score",
    "user_agent_rule",
    "ignored_path",
    "unsafe_url",
    "not_roblox",
    "auth_smuggling",
    "header_rule",
    "endpoint_blocked",
    "endpoint_rule",
)
"""The binding order (names), asserted by the tests against `default_checks()`."""


def default_checks() -> list[Check]:
    """A fresh list of every check, sorted by position."""
    checks: list[Check] = [
        PauseCheck(),
        BansCheck(),
        BypassCheck(),
        FloodCheck(),
        SpamCheck(),
        ThrottleAllCheck(),
        ThrottleCheck(),
        PlaceLimitCheck(),
        ChallengeCheck(),
        BotScoreCheck(),
        UaRuleCheck(),
        IgnoredPathCheck(),
        UnsafeUrlCheck(),
        NotRobloxCheck(),
        AuthSmugglingCheck(),
        HeaderRuleCheck(),
        BlockCheck(),
        EndpointRuleCheck(),
    ]
    return sorted(checks, key=lambda check: check.position)


__all__ = ["PIPELINE_ORDER", "Check", "default_checks"]
