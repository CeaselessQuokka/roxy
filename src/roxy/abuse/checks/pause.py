"""Check 1, pause: while Roxy is paused (manually or in a scheduled window) every proxy request gets 503.

What this is
    `PauseCheck`, the first check of the pipeline (plan 4.1 row 5). Nothing skips it, not even bypass.

Why it exists
    Maintenance needs a switch that stops all proxying at once with an honest answer: v1's 503 with the admin's
    reason or `Service down for maintenance.`, plus `Roxy-Paused: True`. v2 adds `Retry-After` (plan 7.13: the time
    to the scheduled end, or 60 s) so well-behaved clients know when to come back.

How it works
    Reads the worker's cached pause state (`roxy/abuse/state.py`), so a paused request costs no database write.
    Never tarpitted (v1). The header value stays v1's `True` (plan row 8 "same names and values"; plan 7.13 shows
    `1`, recorded as a plan conflict).

What to read next
    `roxy/abuse/pause.py` (the state and its writers), then `roxy/abuse/checks/bans.py` (the next check).
"""

from __future__ import annotations

from typing import Any

from roxy.abuse.checks.base import Check, Facts, LimitSpec, refusal_headers
from roxy.abuse.verdict import TRUE, Refuse
from roxy.core.reasons import ReasonCode


class PauseCheck(Check):
    name = "pause"
    position = 10
    label = "Pause"

    def prepare(self, req: Any, facts: Facts) -> Refuse | LimitSpec | None:
        state = facts.services.switches.pause
        if not state.active(facts.now):
            return None
        text, source = state.message(facts.now)
        return Refuse(
            status=503,
            body=text,
            reason=ReasonCode.PAUSED,
            check=self.name,
            headers=refusal_headers(ReasonCode.PAUSED, Roxy_Paused=TRUE, Retry_After=state.retry_after(facts.now)),
            tarpit_category=None,
            message_source=source,
            detail="Paused",
        )


__all__ = ["PauseCheck"]
