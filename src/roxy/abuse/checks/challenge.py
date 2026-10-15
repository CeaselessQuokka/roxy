"""Checks 9 and 10, challenge and bot score (Tier 3, both off by default).

What this is
    `ChallengeCheck` serves the proof-of-work page to browser clients whose bot score reaches
    `challenge_trigger_score` and who have no valid solved cookie; `BotScoreCheck` refuses any client whose score
    reaches `bot_score_block_threshold` (0 = off). Plus `bot_score(req, facts)`, the score both use.

Why it exists
    Plan 10.7 and 10.8: the bot score is mainly an explanation shown in drill-downs and used by recommendations. It
    can act on its own only when the admin opts in, because heuristics misjudge some legitimate clients.

How it works
    - The score comes from `roxy/abuse/bot.py` (this worker's view of the client plus the current request), computed
      at most once per request and only when one of the two features is on.
    - The challenge applies only to browser requests (`is_browser`: Roblox game servers cannot run JavaScript) and
      needs the `ip_hash_key` credential (the puzzle's signing key); without it the challenge stays off. The page is
      HTML (403) and is never tarpitted.
    - The block is 403 `Access denied.` with `Roxy-Refusal: bot_score`, tarpit category `ban`.
    - Bypass entries skip both.

What to read next
    `roxy/abuse/bot.py`, `roxy/abuse/challenge.py`, then `roxy/abuse/checks/ua_rules.py`.
"""

from __future__ import annotations

from typing import Any

from roxy.abuse.bot import SIGNALS, score
from roxy.abuse.challenge import (
    challenge_page,
    cookie_from_header,
    make_challenge,
    verify_cookie,
)
from roxy.abuse.checks.base import Check, Facts, LimitSpec, refusal_headers
from roxy.abuse.messages import ACCESS_DENIED
from roxy.abuse.verdict import HTML_CONTENT_TYPE, Refuse
from roxy.core.reasons import ReasonCode


def bot_score(req: Any, facts: Facts) -> int:
    """The client's bot score for this request (cached on `facts`)."""
    if facts.score_cache is None:
        signals = facts.services.bot.signals(
            facts.limit_key,
            now=facts.now,
            user_agent=req.user_agent,
            game_server=facts.game_server,
            header_names=list(getattr(req, "header_names_in_order", ()) or ()),
        )
        weights = {name: facts.float(f"bot_weight_{name}") for name in SIGNALS}
        facts.score_cache = score(signals, weights)
    return facts.score_cache


class ChallengeCheck(Check):
    name = "challenge"
    position = 90
    label = "Browser challenge"
    skipped_by_bypass = True

    def prepare(self, req: Any, facts: Facts) -> Refuse | LimitSpec | None:
        key = facts.services.challenge_key
        if not facts.bool("challenge_enabled") or key is None or not getattr(req, "is_browser", False):
            return None
        if bot_score(req, facts) < facts.int("challenge_trigger_score"):
            return None
        headers = getattr(req, "headers", {}) or {}
        bits = facts.int("challenge_difficulty_bits")
        max_age = facts.int("challenge_cookie_minutes") * 60
        solved = verify_cookie(
            key,
            cookie_from_header(headers.get("cookie")),
            client_ip=facts.ip,
            user_agent=req.user_agent,
            now=facts.now,
            max_age_s=max_age,
            min_bits=bits,
        )
        if solved:
            return None
        puzzle = make_challenge(key, client_ip=facts.ip, user_agent=req.user_agent, now=facts.now, bits=bits)
        return Refuse(
            status=403,
            body=challenge_page(puzzle, bits, max_age_s=max_age, nonce=getattr(req, "csp_nonce", None)),
            reason=ReasonCode.CHALLENGE,
            check=self.name,
            headers=refusal_headers(ReasonCode.CHALLENGE, Cache_Control="no-store"),
            tarpit_category=None,
            detail=f"Bot score {bot_score(req, facts)}",
            content_type=HTML_CONTENT_TYPE,
        )


class BotScoreCheck(Check):
    name = "bot_score"
    position = 95
    label = "Bot score block"
    skipped_by_bypass = True
    tarpit_category = "ban"

    def prepare(self, req: Any, facts: Facts) -> Refuse | LimitSpec | None:
        threshold = facts.int("bot_score_block_threshold")
        if threshold <= 0:
            return None
        value = bot_score(req, facts)
        if value < threshold:
            return None
        return Refuse(
            status=403,
            body=ACCESS_DENIED,
            reason=ReasonCode.BOT_SCORE,
            check=self.name,
            headers=refusal_headers(ReasonCode.BOT_SCORE),
            tarpit_category=self.tarpit_category,
            detail=f"Bot score {value}",
        )


__all__ = ["BotScoreCheck", "ChallengeCheck", "bot_score"]
