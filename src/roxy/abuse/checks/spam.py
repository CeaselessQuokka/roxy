"""Check 5, spam: refuses clients a spam detector flagged with the `strike` or `tarpit` action.

What this is
    `SpamCheck` (plan 4.1 row 5: "flood limit and spam detector after bypass"). The detectors themselves run every
    second in the background (`roxy/abuse/spam.py`); this check only reads the worker's copy of the active flags.

Why it exists
    A detector that decides "this client keeps hammering while refused" must have a way to act besides banning:
    refuse the offending requests (with a strike, or held by the tarpit) for as long as the behavior continues.

How it works
    A flag lasts 10 s and is refreshed each second the detector still fires, so the refusals stop shortly after the
    client calms down. The refusal is disguised as an ordinary throttle (a detector is a heuristic; telling an
    abuser which heuristic caught them helps them evade it); the true reason `spam` is recorded. Tarpit category
    `spam` (on by default). Bypass entries skip it.

What to read next
    `roxy/abuse/spam.py` (the detectors and their actions), then `roxy/abuse/checks/throttle_all.py`.
"""

from __future__ import annotations

from typing import Any

from roxy.abuse.checks.base import Check, Facts, LimitSpec, disguised_throttle
from roxy.abuse.messages import REASON_SPAM
from roxy.abuse.verdict import Refuse
from roxy.core.reasons import ReasonCode


class SpamCheck(Check):
    name = "spam"
    position = 50
    label = "Spam detectors"
    skipped_by_bypass = True
    tarpit_category = "spam"

    def prepare(self, req: Any, facts: Facts) -> Refuse | LimitSpec | None:
        flag = facts.services.spam.flagged(facts.limit_key, facts.now)
        if flag is None:
            return None
        return disguised_throttle(
            facts,
            reason=ReasonCode.SPAM,
            check=self.name,
            tarpit_category=self.tarpit_category,
            detail=REASON_SPAM.format(detector=f"SPAM-{flag.detector.upper()}"),
        )


__all__ = ["SpamCheck"]
