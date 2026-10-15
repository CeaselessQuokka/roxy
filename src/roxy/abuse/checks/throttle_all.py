"""Check 6, throttle-all: while the emergency switch is on, every client gets a tiny fixed allowance.

What this is
    `ThrottleAllCheck` (plan 4.3 row 42). Active only while the throttle-all switch is on.

Why it exists
    During an attack the owner flips one switch and every client is limited to `global_throttle_limit` requests per
    `global_throttle_period` (1 per 60 s by default) without editing any rule.

How it works
    A v1 fixed window per client key (`tall:<limit_key>`) evaluated in the single hot.db transaction; a refusal counts
    nothing. Body: the switch's reason or the pause default, the live `pause_message_default` setting (v1 used its
    one downtime constant for both, B6/B13; the catalog default is that constant). Headers as v1: the per-IP trio, then
    `Roxy-Throttle-Reset` set to the emergency window's remaining seconds and `Roxy-Global-Throttled: True`
    (`Roxy-Throttled` stays the per-IP value, v1 B7). v2 adds `Retry-After` (v1 bug B8). Tarpit category
    `throttle_all`. Bypass entries skip it.

What to read next
    `roxy/abuse/throttle_all.py` (the switch), then `roxy/abuse/checks/throttle.py` (the per-IP throttle).
"""

from __future__ import annotations

from typing import Any

from roxy.abuse.checks.base import Check, Facts, LimitSpec, TxState, refusal_headers, with_trio
from roxy.abuse.messages import DEFAULT_DOWNTIME_MESSAGE, REASON_GLOBAL
from roxy.abuse.throttle_all import KEY_PREFIX
from roxy.abuse.verdict import TRUE, Refuse
from roxy.core.reasons import ReasonCode


class ThrottleAllCheck(Check):
    name = "throttle_all"
    position = 60
    label = "Throttle-all (emergency limit)"
    kind = "limiter"
    skipped_by_bypass = True
    tarpit_category = "throttle_all"

    def prepare(self, req: Any, facts: Facts) -> Refuse | LimitSpec | None:
        state = facts.services.switches.throttle_all
        if not state.enabled:
            return None
        limit = max(1, facts.int("global_throttle_limit"))
        period = max(1, facts.int("global_throttle_period"))
        return LimitSpec(
            self.name, f"{KEY_PREFIX}{facts.limit_key}", "fixed", limit=limit, window_s=period, payload=state
        )

    async def check(self, req: Any, tx: TxState) -> Refuse | None:
        outcome = tx.outcomes.get(self.name)
        if outcome is None or outcome.admitted:
            return None
        text, source = outcome.spec.payload.message(
            tx.facts.setting("pause_message_default") if tx.facts is not None else DEFAULT_DOWNTIME_MESSAGE
        )
        refusal = Refuse(
            status=429,
            body=text,
            reason=ReasonCode.THROTTLE_ALL,
            check=self.name,
            headers=refusal_headers(
                ReasonCode.THROTTLE_ALL,
                Retry_After=outcome.retry_after_s,
                Roxy_Throttle_Reset=outcome.reset_s,
                Roxy_Global_Throttled=TRUE,
            ),
            tarpit_category=self.tarpit_category,
            message_source=source,
            detail=REASON_GLOBAL.format(limit=outcome.spec.limit, period=int(outcome.spec.window_s)),
        )
        return with_trio(refusal, tx)


__all__ = ["ThrottleAllCheck"]
