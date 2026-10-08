"""Check 3, bypass: marks requests from trusted networks so the rate-limit checks after it skip them.

What this is
    `BypassCheck`, a marker check: it never refuses; it sets `req.bypass = True` when an active bypass entry covers
    the caller's IP (plan 4.1 row 6).

Why it exists
    v1 resolved bypass right after pause and every later rate check tested the flag. Keeping the marker as a check
    at its documented position makes the order visible on the Protection page and keeps the skip rule in one place:
    each check declares `skipped_by_bypass`.

How it works
    Looks the IP up in the snapshot's bypass CIDR index (expiry checked at lookup time). The live feed shows
    `Bypass: true` from the same flag.

What to read next
    `roxy/abuse/bypass.py` (what bypass skips and why), then `roxy/abuse/checks/flood.py`.
"""

from __future__ import annotations

from typing import Any

from roxy.abuse.bypass import is_bypassed
from roxy.abuse.checks.base import Check, Facts, LimitSpec
from roxy.abuse.verdict import Refuse


class BypassCheck(Check):
    name = "bypass"
    position = 30
    label = "Bypass"
    kind = "marker"

    def prepare(self, req: Any, facts: Facts) -> Refuse | LimitSpec | None:
        if is_bypassed(facts.rules, facts.ip, facts.now):
            req.bypass = True
        return None


__all__ = ["BypassCheck"]
