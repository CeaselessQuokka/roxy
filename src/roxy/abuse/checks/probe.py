"""Checks 13 and 14, probes: unsafe URLs (404 `Invalid URL`) and non-Roblox or disallowed hosts (404).

What this is
    `UnsafeUrlCheck` and `NotRobloxCheck` (plan 4.3 row 51), plus `probe_signature`, which recognizes the paths
    scanners try everywhere (`wp-login.php`, `.env`, `.git/config`, ...) for the bot score and the SPAM-PROBE
    detector.

Why it exists
    Requests for anything but a Roblox API URL are scanners looking for weaknesses. v1 answered them with 404 and
    held them in the tarpit; v2 keeps the texts and the tarpit, and counts them per client so a persistent scanner
    is banned (SPAM-PROBE) instead of merely slowed.

How it works
    The URL is parsed once by `proxy/validate.py` (DESIGN.md 11.1 step 2), which sets `req.target_problem` to
    `unsafe_url`, `not_roblox` or `host_not_allowed`; these checks only turn that into the v1 refusal. A host that
    looks like Roblox but is outside the host allowlist (SSRF guard, plan 9.10) gets the same `Not a Roblox URL`
    text with reason `host_not_allowed`. Tarpit category `probe` (on by default), reason strings as v1
    (`Invalid URL (unsafe characters)`, `Non-Roblox URL: <first segment>`). Bypass does not skip them.

What to read next
    `roxy/abuse/spam.py` (SPAM-PROBE), then `roxy/abuse/checks/auth_smuggling.py`.
"""

from __future__ import annotations

from typing import Any, Final

from roxy.abuse.checks.base import Check, Facts, LimitSpec, refusal_headers
from roxy.abuse.messages import (
    INVALID_URL,
    NOT_A_ROBLOX_URL,
    REASON_PROBE_HOST,
    REASON_PROBE_NOT_ROBLOX,
    REASON_PROBE_UNSAFE,
)
from roxy.abuse.verdict import Refuse
from roxy.core.reasons import ReasonCode

PROBE_SIGNATURES: Final[tuple[str, ...]] = (
    "wp-admin",
    "wp-login",
    "wp-content",
    "wp-includes",
    "xmlrpc.php",
    ".env",
    ".git/",
    ".svn/",
    ".htaccess",
    ".aws/",
    ".ssh/",
    "phpmyadmin",
    "phpinfo",
    "cgi-bin/",
    "server-status",
    "actuator/",
    "vendor/phpunit",
    "etc/passwd",
    "../",
    "..%2f",
    "%2e%2e",
    "boaform",
    "owa/auth",
    "autodiscover",
)
"""Lowercase substrings of paths that scanners request on every site (plan 4.3 row 51)."""


def probe_signature(path: str) -> str | None:
    """The first scanner signature found in `path`, or None."""
    lowered = (path or "").lower()
    for signature in PROBE_SIGNATURES:
        if signature in lowered:
            return signature
    return None


class UnsafeUrlCheck(Check):
    name = "unsafe_url"
    position = 120
    label = "Unsafe URL"
    tarpit_category = "probe"

    def prepare(self, req: Any, facts: Facts) -> Refuse | LimitSpec | None:
        if getattr(req, "target_problem", None) != ReasonCode.UNSAFE_URL:
            return None
        return Refuse(
            status=404,
            body=INVALID_URL,
            reason=ReasonCode.UNSAFE_URL,
            check=self.name,
            headers=refusal_headers(ReasonCode.UNSAFE_URL),
            tarpit_category=self.tarpit_category,
            detail=REASON_PROBE_UNSAFE,
        )


class NotRobloxCheck(Check):
    name = "not_roblox"
    position = 130
    label = "Not a Roblox URL / host allowlist"
    tarpit_category = "probe"

    def prepare(self, req: Any, facts: Facts) -> Refuse | LimitSpec | None:
        problem = getattr(req, "target_problem", None)
        if problem not in (ReasonCode.NOT_ROBLOX, ReasonCode.HOST_NOT_ALLOWED):
            return None
        first = facts.path.split("/", 1)[0][:60]
        reason = ReasonCode(problem)
        template = REASON_PROBE_NOT_ROBLOX if reason is ReasonCode.NOT_ROBLOX else REASON_PROBE_HOST
        return Refuse(
            status=404,
            body=NOT_A_ROBLOX_URL,
            reason=reason,
            check=self.name,
            headers=refusal_headers(reason),
            tarpit_category=self.tarpit_category,
            detail=template.format(host=first),
        )


__all__ = ["PROBE_SIGNATURES", "NotRobloxCheck", "UnsafeUrlCheck", "probe_signature"]
