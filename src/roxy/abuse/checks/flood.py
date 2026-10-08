"""Check 4, flood limit: an absolute per-client ceiling that counts every request, cache hits included.

What this is
    `FloodCheck` (plan 10.1: `flood_limit_per_minute`, default 300). A GCRA limit of N per 60 s per client key.

Why it exists
    The per-IP throttle is the fairness limit, and an admin can tune it per deployment (for example
    `throttle_count_cache_hits` = 0 stops counting cache hits there; the default 1 counts them, because a cache hit
    still costs Roxy resources). The flood limit is the absolute ceiling under all of that: a client hammering one
    URL can never use all of a worker's capacity whatever the per-IP settings say, and legitimate clients never come
    near it. A client it refuses runs none of the costly pattern checks (admin regexes) after it.

How it works
    One limiter row `flood:<limit_key>` evaluated in the pipeline's single hot.db transaction. Unlike the other
    limiters it is committed even when a later check refuses the request: it counts every request it sees, probes
    and refused requests included. Bypass entries skip it (see `roxy/abuse/bypass.py`). The refusal is a plain 429
    with `Retry-After`; tarpit category `throttle`.

What to read next
    `roxy/abuse/limiter.py` (`gcra`), then `roxy/abuse/checks/spam.py`.
"""

from __future__ import annotations

from typing import Any

from roxy.abuse.checks.base import Check, Facts, LimitSpec, TxState, refusal_headers, with_trio
from roxy.abuse.messages import FLOOD_DEFAULT, REASON_FLOOD
from roxy.abuse.verdict import TRUE, Refuse
from roxy.core.reasons import ReasonCode


class FloodCheck(Check):
    name = "flood"
    position = 40
    label = "Flood limit"
    kind = "limiter"
    skipped_by_bypass = True
    tarpit_category = "throttle"

    def prepare(self, req: Any, facts: Facts) -> Refuse | LimitSpec | None:
        limit = facts.int("flood_limit_per_minute", 300)
        return LimitSpec(self.name, f"flood:{facts.limit_key}", "gcra", limit=limit, window_s=60, always_commit=True)

    async def check(self, req: Any, tx: TxState) -> Refuse | None:
        outcome = tx.outcomes.get(self.name)
        if outcome is None or outcome.admitted:
            return None
        retry = outcome.retry_after_s
        refusal = Refuse(
            status=429,
            body=FLOOD_DEFAULT.format(retry=retry),
            reason=ReasonCode.FLOOD,
            check=self.name,
            headers=refusal_headers(
                ReasonCode.FLOOD, Retry_After=retry, Roxy_Throttle_Reset=retry, Roxy_Throttled=TRUE
            ),
            tarpit_category=self.tarpit_category,
            detail=REASON_FLOOD.format(limit=outcome.spec.limit),
        )
        return with_trio(refusal, tx)


__all__ = ["FloodCheck"]
