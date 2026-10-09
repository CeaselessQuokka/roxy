"""Every caller-facing text the abuse layer can send, and the v1 tarpit reason strings.

What this is
    The refusal bodies of plan 4.1 row 7 exactly as v1 sent them (golden tests compare against these strings), the
    v2 texts for the new checks (flood, place limit, ban, challenge), the C5 dash replacement for the default rung 1
    message, and the per-hold reason strings of the tarpit (row 123).

Why it exists
    Callers (Roblox game scripts) sometimes match refusal text, so parity is byte for byte. Keeping every string in
    one module makes the golden tests trivial to read and stops two checks from drifting apart (v1 had the ladder in
    two places, one with a dash).

How it works
    Plain constants plus small formatting helpers. Admin-authored messages (rule messages, pause and throttle-all
    reasons, ladder rungs) are used as stored after `clean_admin_message` (v1 `_clean_message`: trimmed, at most 400
    characters; reasons 300); an empty result falls back to the default text, exactly as v1 did at refusal time.
    Pause and throttle-all reasons are also checked when they are written (`checked_state_reason`: no em or en
    dash, plan C5), like every other admin text a caller can receive.

What to read next
    `roxy/abuse/verdict.py` (how a text becomes a response body), then `roxy/abuse/checks/` (who uses which text).
"""

from __future__ import annotations

from typing import Final

from roxy.config.constants import MAX_RULE_MESSAGE
from roxy.rules.models import check_admin_text

MAX_STATE_REASON: Final = 300
"""v1 cut pause and throttle-all reasons to 300 characters (runtime.py:526, 565)."""

# --- v1 texts (pipeline.md section 18, abuse.md section 5) ------------------------------------------------------------

DEFAULT_DOWNTIME_MESSAGE: Final = "Service down for maintenance."
"""The catalog default of the live setting `pause_message_default`, which is the pause AND the throttle-all default
(v1 bug B6/B13 kept for parity: throttle-all without a reason says the pause text too). Only a fallback: the checks
pass the live setting."""

THROTTLE_FALLBACK: Final = (
    "You have been throttled; try again in {reset_in} seconds (you get ~{allowed} requests per ~minute)."
)
UA_BURST_DEFAULT: Final = "This client is limited to {limit} requests per {period}s. Try again in {retry} seconds."
UA_COOLDOWN_DEFAULT: Final = "This client is limited to one request every {cooldown}s. Try again in {retry} seconds."
NOT_FOUND: Final = "Not Found"
INVALID_URL: Final = "Invalid URL"
NOT_A_ROBLOX_URL: Final = "Not a Roblox URL"
AUTH_SMUGGLING: Final = "Requests requiring authentication are not allowed with this proxy."
ENDPOINT_BLOCKED: Final = "This endpoint is currently blocked."
ENDPOINT_RULE_DEFAULT: Final = "This endpoint is rate-limited for you; try again in {retry} seconds."

# The default ladder (rung 1 with the C5 replacement) lives in `roxy.config.defaults.THROTTLE_TIERS`, the one copy.

# --- v2 texts for checks v1 did not have (CHANGES.md lists them) -----------------------------------------------------

ACCESS_DENIED: Final = "Access denied."
"""Plan 10.5: a ban (or the deny list) that is not disguised as a throttle."""
FLOOD_DEFAULT: Final = "You are sending requests too fast; try again in {retry} seconds."
PLACE_LIMIT_DEFAULT: Final = "This experience is over its request limit; try again in {retry} seconds."
CHALLENGE_TITLE: Final = "Checking your browser"

# --- tarpit and live-feed reason strings (v1 index.py; plan row 123) -------------------------------------------------

REASON_PROBE_UNSAFE: Final = "Invalid URL (unsafe characters)"
REASON_PROBE_NOT_ROBLOX: Final = "Non-Roblox URL: {host}"
REASON_PROBE_HOST: Final = "Host not allowed: {host}"
REASON_PER_IP: Final = "Per-IP limit {limit} per {window}s"
REASON_GLOBAL: Final = "Global limit {limit} per {period}s"
REASON_RATE_RULE: Final = "Rate rule: {pattern}"
REASON_BLOCK_RULE: Final = "Block rule: {pattern}"
REASON_UA_RULE: Final = "User-Agent rule: {needle}"
REASON_HEADER_RULE: Final = "Filter {rule_id} (matched {header})"
REASON_AUTH_TOKEN_HEADER: Final = "X-Roblox-Token header"  # noqa: S105 (a v1 reason string, not a secret)
REASON_AUTH_HEADER_VALUE: Final = '"{name}" header carried a ROBLOSECURITY-shaped value'
REASON_AUTH_COOKIE_NAME: Final = "cookie named .ROBLOSECURITY"
REASON_AUTH_QUERY: Final = "query string carried a ROBLOSECURITY-shaped value"
REASON_AUTH_BODY: Final = "request body carried a ROBLOSECURITY-shaped value"
REASON_FLOOD: Final = "Flood limit {limit} per 60s"
REASON_PLACE: Final = "Place limit {limit} per 60s"
REASON_BAN: Final = "Ban {subject_type}:{subject}"
REASON_DENY: Final = "Deny list {cidr}"
REASON_SPAM: Final = "Spam detector {detector}"


def clean_admin_message(value: object, limit: int = MAX_RULE_MESSAGE) -> str:
    """v1 `_clean_message` plus the refusal-time `.strip()`: trimmed text, at most `limit` characters."""
    return str(value or "").strip()[:limit].strip()


def checked_state_reason(value: object) -> str:
    """A pause or throttle-all reason as the switch writers store it: cut like v1, then checked like rule messages.

    The reason becomes every caller's 503 or 429 body, so plan C5 applies: `rules/models.py check_admin_text`
    refuses an em or en dash and control characters with a ValueError (the admin API answers it as a 400, like a
    rule message). Length is not refused: v1 cut reasons to 300 characters, and so does this.
    """
    return check_admin_text(clean_admin_message(value, MAX_STATE_REASON), MAX_STATE_REASON, "The reason")


def downtime_default(setting_value: object) -> str:
    """The live `pause_message_default` cleaned like an admin message; an empty value falls back to the catalog's."""
    return clean_admin_message(setting_value, MAX_STATE_REASON) or DEFAULT_DOWNTIME_MESSAGE


def throttle_fallback(reset_in: int, allowed: int) -> str:
    """The per-IP text used when the ladder is empty or the rung has no message."""
    return THROTTLE_FALLBACK.format(reset_in=reset_in, allowed=allowed)


def ua_default(kind: str, limit: int | None, period: int | None, cooldown: float | None, retry: int) -> str:
    """The v1 User-Agent rule default text. `cooldown` prints as a float (`2.0s`, `0.5s`) exactly like v1."""
    if kind == "cooldown":
        return UA_COOLDOWN_DEFAULT.format(cooldown=float(cooldown if cooldown is not None else 2.0), retry=retry)
    return UA_BURST_DEFAULT.format(limit=limit if limit is not None else 10, period=period or 60, retry=retry)


__all__ = [
    "ACCESS_DENIED",
    "AUTH_SMUGGLING",
    "CHALLENGE_TITLE",
    "DEFAULT_DOWNTIME_MESSAGE",
    "ENDPOINT_BLOCKED",
    "ENDPOINT_RULE_DEFAULT",
    "FLOOD_DEFAULT",
    "INVALID_URL",
    "MAX_STATE_REASON",
    "NOT_A_ROBLOX_URL",
    "NOT_FOUND",
    "PLACE_LIMIT_DEFAULT",
    "THROTTLE_FALLBACK",
    "UA_BURST_DEFAULT",
    "UA_COOLDOWN_DEFAULT",
    "checked_state_reason",
    "clean_admin_message",
    "downtime_default",
    "throttle_fallback",
    "ua_default",
]
