"""Check 12, ignored paths: paths answered 404 `Not Found` without logging them as probes (plan 4.3 row 50).

What this is
    `IgnoredPathCheck`: requests whose path matches an entry of the editable `ignored_paths` table (seeded with v1's
    two entries, Chrome DevTools' `.well-known/appspecific/com.chrome.devtools.json` and `favicon.ico`).

Why it exists
    Browsers ask every site for a few files. Logging them as probes would bury real probes in noise and could feed
    the spam detectors, so they get a quiet 404.

How it works
    Matched with the shared glob matcher (lead decision 4: a literal entry still matches itself exactly, and now also
    its subpaths) against the request path without its leading slash (v1 `dst`). 404 `Not Found`, never tarpitted,
    never counted as a probe. It applies to bypass entries too.

What to read next
    `roxy/rules/store.py` (`is_ignored_path`), then `roxy/abuse/checks/probe.py`.
"""

from __future__ import annotations

from typing import Any

from roxy.abuse.checks.base import Check, Facts, LimitSpec, refusal_headers
from roxy.abuse.messages import NOT_FOUND
from roxy.abuse.verdict import Refuse
from roxy.core.reasons import ReasonCode


class IgnoredPathCheck(Check):
    name = "ignored_path"
    position = 110
    label = "Ignored paths"

    def prepare(self, req: Any, facts: Facts) -> Refuse | LimitSpec | None:
        if not facts.path or not facts.rules.is_ignored_path(facts.path):
            return None
        return Refuse(
            status=404,
            body=NOT_FOUND,
            reason=ReasonCode.IGNORED_PATH,
            check=self.name,
            headers=refusal_headers(ReasonCode.IGNORED_PATH),
            tarpit_category=None,
            detail="Ignored path",
        )


__all__ = ["IgnoredPathCheck"]
