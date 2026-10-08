"""Reason codes and outcome vocabularies: the closed set of words Roxy uses to explain every response.

What this is
    `ReasonCode` names why a request ended the way it did (a refusal, an upstream failure, or how it was served).
    `Outcome`, `Egress`, `Source`, `CacheState` and `AuthClass` are the other small enums every outcome event
    carries (plan 7.13, DESIGN section 6 and 8).

Why it exists
    v1 wrote free-form strings ("upstream failure", "methods_exhausted") into its stats, so the dashboard could not
    group or explain them reliably. A closed enum means every reason has one spelling, can be counted, documented,
    filtered on, and sent to callers in the `Roxy-Refusal` header without typos. New codes are added here only
    (DESIGN section 6 lists the set; change both together).

How it works
    Each enum is a `StrEnum`, so a member is also a plain string: `ReasonCode.DEADLINE == "deadline"` is True and
    `json.dumps` writes the value. Member names are the uppercase form of the value. `ReasonCode.category` says
    which family a code belongs to, so code can ask "is this a refusal?" without its own list.

What to read next
    `roxy/core/deadline.py` (the first code that sends a reason to a caller), then `roxy/proxy/respond.py` and
    `roxy/metrics/recorder.py` (where every reason ends up).
"""

from __future__ import annotations

from enum import StrEnum

REFUSAL_HEADER = "Roxy-Refusal"
"""Response header that names the reason code when Roxy itself refused or failed a request (plan 7.13)."""


class ReasonCategory(StrEnum):
    """The three families of reason codes."""

    REFUSAL = "refusal"  # Roxy decided not to serve the request (abuse checks, validation, limits)
    FAILURE = "failure"  # Roxy tried, but upstream or Roxy itself could not produce an answer
    SERVED = "served"  # The caller got an answer (from Roblox, from the cache, or answered locally)


class ReasonCode(StrEnum):
    """Why a request ended the way it did. Closed set: add new codes here and in DESIGN.md section 6 only."""

    # Refusals: Roxy chose not to serve the request.
    PAUSED = "paused"
    BANNED = "banned"
    DENY_LIST = "deny_list"
    FLOOD = "flood"
    SPAM = "spam"
    THROTTLE_ALL = "throttle_all"
    THROTTLE = "throttle"
    PLACE_LIMIT = "place_limit"
    USER_AGENT_RULE = "user_agent_rule"
    IGNORED_PATH = "ignored_path"
    UNSAFE_URL = "unsafe_url"
    NOT_ROBLOX = "not_roblox"
    HOST_NOT_ALLOWED = "host_not_allowed"
    AUTH_SMUGGLING = "auth_smuggling"
    HEADER_RULE = "header_rule"
    ENDPOINT_BLOCKED = "endpoint_blocked"
    ENDPOINT_RULE = "endpoint_rule"
    BODY_TOO_LARGE = "body_too_large"
    HEADERS_TOO_LARGE = "headers_too_large"
    URL_TOO_LONG = "url_too_long"
    METHOD_NOT_ALLOWED = "method_not_allowed"
    CHALLENGE = "challenge"
    BOT_SCORE = "bot_score"

    # Upstream and internal failures: Roxy tried but could not produce an answer.
    UPSTREAM_COOLDOWN = "upstream_cooldown"
    UPSTREAM_BUSY = "upstream_busy"
    QUEUE_OVERFLOW = "queue_overflow"
    UPSTREAM_5XX = "upstream_5xx"
    UPSTREAM_TIMEOUT = "upstream_timeout"
    UPSTREAM_CONNECT = "upstream_connect"
    DEADLINE = "deadline"
    COALESCE_TIMEOUT = "coalesce_timeout"
    EGRESS_DISABLED = "egress_disabled"
    CREDENTIAL_UNAVAILABLE = "credential_unavailable"
    DEGRADED = "degraded"
    LEAK_BLOCKED = "leak_blocked"
    INTERNAL_ERROR = "internal_error"

    # Served: the caller received an answer.
    UPSTREAM_OK = "upstream_ok"
    UPSTREAM_4XX = "upstream_4xx"
    CACHE_HIT = "cache_hit"
    CACHE_REVALIDATING = "cache_revalidating"
    CACHE_STALE_COOLDOWN = "cache_stale_cooldown"
    CACHE_STALE_ERROR = "cache_stale_error"
    CACHE_COALESCED = "cache_coalesced"
    CACHE_NEGATIVE = "cache_negative"
    THROTTLED_CACHE = "throttled_cache"
    OPTIONS_LOCAL = "options_local"

    @property
    def category(self) -> ReasonCategory:
        """Which family this code belongs to (refusal, failure or served)."""
        return _CATEGORY[self]

    @property
    def is_refusal(self) -> bool:
        return _CATEGORY[self] is ReasonCategory.REFUSAL

    @property
    def is_failure(self) -> bool:
        return _CATEGORY[self] is ReasonCategory.FAILURE

    @property
    def is_served(self) -> bool:
        return _CATEGORY[self] is ReasonCategory.SERVED


_REFUSALS = frozenset(
    {
        ReasonCode.PAUSED,
        ReasonCode.BANNED,
        ReasonCode.DENY_LIST,
        ReasonCode.FLOOD,
        ReasonCode.SPAM,
        ReasonCode.THROTTLE_ALL,
        ReasonCode.THROTTLE,
        ReasonCode.PLACE_LIMIT,
        ReasonCode.USER_AGENT_RULE,
        ReasonCode.IGNORED_PATH,
        ReasonCode.UNSAFE_URL,
        ReasonCode.NOT_ROBLOX,
        ReasonCode.HOST_NOT_ALLOWED,
        ReasonCode.AUTH_SMUGGLING,
        ReasonCode.HEADER_RULE,
        ReasonCode.ENDPOINT_BLOCKED,
        ReasonCode.ENDPOINT_RULE,
        ReasonCode.BODY_TOO_LARGE,
        ReasonCode.HEADERS_TOO_LARGE,
        ReasonCode.URL_TOO_LONG,
        ReasonCode.METHOD_NOT_ALLOWED,
        ReasonCode.CHALLENGE,
        ReasonCode.BOT_SCORE,
    }
)
_FAILURES = frozenset(
    {
        ReasonCode.UPSTREAM_COOLDOWN,
        ReasonCode.UPSTREAM_BUSY,
        ReasonCode.QUEUE_OVERFLOW,
        ReasonCode.UPSTREAM_5XX,
        ReasonCode.UPSTREAM_TIMEOUT,
        ReasonCode.UPSTREAM_CONNECT,
        ReasonCode.DEADLINE,
        ReasonCode.COALESCE_TIMEOUT,
        ReasonCode.EGRESS_DISABLED,
        ReasonCode.CREDENTIAL_UNAVAILABLE,
        ReasonCode.DEGRADED,
        ReasonCode.LEAK_BLOCKED,
        ReasonCode.INTERNAL_ERROR,
    }
)

# Every code maps to exactly one category; anything not a refusal or a failure is a served outcome. The import-time
# check below makes a forgotten code fail loudly instead of being silently counted as "served".
_CATEGORY: dict[ReasonCode, ReasonCategory] = {
    code: (
        ReasonCategory.REFUSAL
        if code in _REFUSALS
        else ReasonCategory.FAILURE
        if code in _FAILURES
        else ReasonCategory.SERVED
    )
    for code in ReasonCode
}

REFUSAL_REASONS: frozenset[ReasonCode] = _REFUSALS
FAILURE_REASONS: frozenset[ReasonCode] = _FAILURES
SERVED_REASONS: frozenset[ReasonCode] = frozenset(c for c in ReasonCode if _CATEGORY[c] is ReasonCategory.SERVED)

_EXPECTED_SERVED = {
    "upstream_ok",
    "upstream_4xx",
    "cache_hit",
    "cache_revalidating",
    "cache_stale_cooldown",
    "cache_stale_error",
    "cache_coalesced",
    "cache_negative",
    "throttled_cache",
    "options_local",
}
if {c.value for c in SERVED_REASONS} != _EXPECTED_SERVED:  # pragma: no cover - guards future edits
    raise RuntimeError("ReasonCode categories are out of date: put every new code in exactly one family")


class Outcome(StrEnum):
    """The four ways a request can end, counted on the Overview page."""

    SERVED_UPSTREAM = "served_upstream"
    SERVED_CACHE = "served_cache"
    REFUSED = "refused"
    FAILED = "failed"


class Egress(StrEnum):
    """Which network path an upstream call used (plan 7.1). `none` means no upstream call was made."""

    NONE = "none"
    DIRECT = "direct"
    CREDENTIAL = "credential"
    ROTATOR = "rotator"


class Source(StrEnum):
    """Who produced the response body the caller received."""

    ROBLOX = "roblox"  # Roblox's own answer, passed through
    ROXY = "roxy"  # Roxy wrote the body (refusals, failures)
    RELAY = "relay"  # Roblox's answer relayed after Roxy processing (prettyprint, browser HTML)
    INTERNAL = "internal"  # Roxy's own upstream calls (probes, lookups), not caller traffic
    CACHE = "cache"  # served from the response cache


class CacheState(StrEnum):
    """The value of the `Roxy-Cache` response header. `str(state)` is exactly the header text.

    `NA` is used when the cache does not apply (a refusal, an admin page) and renders as "n/a", never as a dash
    (plan C5). `CacheState("NA")` is also accepted, so a value written by its name parses back.
    """

    HIT = "HIT"
    REVALIDATING = "REVALIDATING"
    STALE = "STALE"
    COALESCED = "COALESCED"
    MISS = "MISS"
    OFF = "OFF"
    NA = "n/a"

    @property
    def header_text(self) -> str:
        """The text sent in the `Roxy-Cache` header (the value itself)."""
        return self.value

    @classmethod
    def _missing_(cls, value: object) -> CacheState | None:
        # Accept the member name ("NA") and lowercase spellings ("hit") as well as the header text.
        if isinstance(value, str):
            upper = value.upper()
            if upper in cls.__members__:
                return cls.__members__[upper]
            for member in cls:
                if member.value.upper() == upper:
                    return member
        return None


class AuthClass(StrEnum):
    """Whether a response was fetched anonymously or with the credential (plan 6.9). Never mixed in the cache."""

    ANON = "anon"
    CRED = "cred"
