"""Check 7, the per-IP throttle: the normal fairness limit (10 requests per 50 s by default) and its strike ladder.

What this is
    `ThrottleCheck` (plan 4.3 rows 39 and 40, plan 10.2 and 10.4). The decision itself is `roxy/abuse/throttle.py`
    `evaluate_per_ip`, run inside the pipeline's single hot.db transaction.

Why it exists
    This is the limit most callers meet. It must be exact across workers (C6), never let the crossing request through
    (v1 B8), and tell the caller precisely when to come back.

How it works
    - Skipped for bypass entries, and for fresh cache hits while `throttle_count_cache_hits` is 0 (D10): such a
      request is neither counted nor refused.
    - Refusal: 429 with the ladder rung's message for the client's strikes, or v1's fallback text when the ladder is
      empty or the rung has no message; `Retry-After` (the GCRA wait or the rung's penalty, whichever is longer),
      `Roxy-Throttle-Reset`, `Roxy-Throttled: True`, `Roxy-Requests-Left: 0`. Tarpit category `throttle`.
    - With `cache_serve_throttled` the refusal carries `allow_fresh_cache_serve`, and the router answers from a fresh
      cached copy instead (row 60).

What to read next
    `roxy/abuse/throttle.py`, then `roxy/abuse/checks/place_limit.py`.
"""

from __future__ import annotations

from typing import Any

from roxy.abuse.checks.base import Check, Facts, LimitSpec, TxState, refusal_headers, with_trio
from roxy.abuse.messages import REASON_PER_IP, throttle_fallback
from roxy.abuse.verdict import TRUE, MessageSource, Refuse
from roxy.core.reasons import ReasonCode


class ThrottleCheck(Check):
    name = "throttle"
    position = 70
    label = "Per-IP throttle"
    kind = "limiter"
    skipped_by_bypass = True
    tarpit_category = "throttle"

    def prepare(self, req: Any, facts: Facts) -> Refuse | LimitSpec | None:
        policy = facts.per_ip
        if policy is None:
            return None
        if getattr(req, "fresh_cache_hit", False) and not facts.bool("throttle_count_cache_hits", False):
            return None  # D10: a fresh cache hit costs Roblox nothing, so it is neither counted nor refused
        payload = {
            "serve_from_cache": facts.bool("cache_serve_throttled", False)
            and bool(getattr(req, "fresh_cache_hit", False))
        }
        return LimitSpec(
            self.name,
            policy.key,
            "per_ip",
            limit=policy.limit,
            window_s=policy.window_s,
            per_ip=policy,
            payload=payload,
        )

    async def check(self, req: Any, tx: TxState) -> Refuse | None:
        outcome = tx.outcomes.get(self.name)
        if outcome is None or outcome.admitted or outcome.per_ip is None:
            return None
        result = outcome.per_ip
        text = result.rung.message.strip()
        source: MessageSource = "custom" if text else "default"
        if not text:
            text = throttle_fallback(result.reset_s, outcome.spec.limit)
        refusal = Refuse(
            status=429,
            body=text,
            reason=ReasonCode.THROTTLE,
            check=self.name,
            headers=refusal_headers(
                ReasonCode.THROTTLE,
                Retry_After=result.retry_after_s,
                Roxy_Requests_Left=0,
                Roxy_Throttle_Reset=result.reset_s,
                Roxy_Throttled=TRUE,
            ),
            tarpit_category=self.tarpit_category,
            message_source=source,
            allow_fresh_cache_serve=bool(outcome.spec.payload and outcome.spec.payload.get("serve_from_cache")),
            penalty_retry_after_s=result.penalty_s or None,
            detail=REASON_PER_IP.format(limit=outcome.spec.limit, window=int(outcome.spec.window_s)),
        )
        return with_trio(refusal, tx)


__all__ = ["ThrottleCheck"]
