"""The "Why did this request wait?" explainer of the Upstream page (plan 7.12): facts in, plain sentences out.

What this is
    `explain_wait(facts)` turns what Roxy kept about one request id (its Live row, the Roblox 429s it met, the 429
    that opened the cooldown it ran into, how full its buckets were in that minute, and how many calls to its
    endpoint Roblox answered with a challenge or an HTML page in that minute) into an ordered list of sentences an
    admin can act on, plus the numbers behind them. `request_bucket_keys(row)` names the buckets one
    request needed (plan 7.3). `REASON_TEXT` is the sentence for every outcome reason (`core/reasons.py`).

Why it exists
    v1 could only show a request's trace fields. v2's question is "why did this wait (or fail)": a cooldown opened
    by an earlier 429, a full bucket, a queue that overflowed, a retry after a 5xx, a CSRF round trip, a single
    flight it followed. The live trace object (`upstream/trace.py`) is not stored per request, so the explainer
    works from the rows that are stored, across every worker, and says which facts it lacks instead of guessing
    (P6): for example, which bucket bound a wait is inferred from that minute's bucket history, and labeled so.

How it works
    Pure functions: no I/O, no clock. The API gathers the facts (`metrics/read_upstream.py`,
    `metrics/read_history.py`) and passes a `WaitFacts`; the answer is JSON-ready.

What to read next
    `roxy/admin/api/upstream.py` (the route), `roxy/metrics/read_upstream.py` (`live_row`, `request_429_rows`).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from roxy.core.reasons import ReasonCode

FULL_PCT: Final = 99.5
"""A bucket whose peak fill reached this (percent of its burst) in a minute was full in that minute."""

REASON_TEXT: Final[dict[str, str]] = {
    ReasonCode.UPSTREAM_OK.value: "Roblox answered.",
    ReasonCode.UPSTREAM_4XX.value: "Roblox answered with an error status, and that answer was passed on.",
    ReasonCode.CACHE_HIT.value: "It was served from Roxy's cache; Roblox was not called.",
    ReasonCode.CACHE_REVALIDATING.value: (
        "It was served from the cache at once while one background refresh updated the entry."
    ),
    ReasonCode.CACHE_STALE_COOLDOWN.value: (
        "It was served a stale copy from the cache because the endpoint was cooling down; Roblox was not called."
    ),
    ReasonCode.CACHE_STALE_ERROR.value: "Roblox failed, so a stale copy from the cache was served instead.",
    ReasonCode.CACHE_COALESCED.value: (
        "An identical request was already fetching this, so this one waited for that answer instead of calling "
        "Roblox (single flight)."
    ),
    ReasonCode.CACHE_NEGATIVE.value: "It was served a cached error answer that Roblox gave a moment earlier.",
    ReasonCode.THROTTLED_CACHE.value: "The caller was over its limit and was served from a fresh cache entry.",
    ReasonCode.OPTIONS_LOCAL.value: "Roxy answered the OPTIONS request itself.",
    ReasonCode.UPSTREAM_COOLDOWN.value: (
        "A cooldown was open for this endpoint (or its host or egress), so Roxy did not call Roblox and answered "
        "429 with Retry-After."
    ),
    ReasonCode.UPSTREAM_BUSY.value: (
        "No egress could get a bucket slot within the request's queue budget, so Roxy answered 429 with the time "
        "of the soonest free slot instead of waiting longer."
    ),
    ReasonCode.QUEUE_OVERFLOW.value: "The worker's wait queue was full, so the request was not queued.",
    ReasonCode.UPSTREAM_5XX.value: "Roblox answered 5xx on every allowed attempt.",
    ReasonCode.UPSTREAM_TIMEOUT.value: "Roblox did not answer in time on every allowed attempt.",
    ReasonCode.UPSTREAM_CONNECT.value: "Roxy could not connect to Roblox on every allowed attempt.",
    ReasonCode.DEADLINE.value: "The request used up its whole deadline (request_deadline_s).",
    ReasonCode.COALESCE_TIMEOUT.value: (
        "It waited for another worker fetching the same thing, and that fetch did not finish in time."
    ),
    ReasonCode.EGRESS_DISABLED.value: (
        "Every egress path was off (an admin switch, a leak guard trip or the rotator budget)."
    ),
    ReasonCode.CREDENTIAL_UNAVAILABLE.value: (
        "The endpoint may only use the credential, and the credential was cooling down, rejected or not confirmed."
    ),
    ReasonCode.DEGRADED.value: (
        "Roxy's shared state could not be used, so the call was not made without pacing (plan C7)."
    ),
    ReasonCode.LEAK_BLOCKED.value: "The leak guard refused the call because it carried the credential.",
    ReasonCode.INTERNAL_ERROR.value: "Roxy failed with an internal error (see System > Errors).",
}

_CACHE_SERVES: Final = frozenset({"HIT", "STALE", "COALESCED", "REVALIDATING"})


@dataclass(slots=True)
class WaitFacts:
    """What is known about one request id (gathered by the API from metrics.db)."""

    request_id: str
    minted_at_ms: int | None
    live: Mapping[str, Any] | None
    roblox_429s: Sequence[Mapping[str, Any]] = ()
    prior_429s: Sequence[Mapping[str, Any]] = ()
    buckets: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    queue_budget_ms: float | None = None
    capture_available: bool = False
    flagged_calls: Mapping[str, int] = field(default_factory=dict)
    """`{calls, challenges, html_bodies}` of the request's endpoint and egress in its minute
    (`upstream_attempt_minute`, flagged by `upstream/pages.py`); empty when unknown."""


def request_bucket_keys(row: Mapping[str, Any]) -> list[str]:
    """The upstream buckets one request needed (plan 7.3): global, its egress, its host and its endpoint."""
    keys = ["global"]
    egress = str(row.get("egress") or "")
    if egress in ("direct", "rotator", "credential"):
        keys.append(f"egress:{egress}")
    host = str(row.get("host") or "")
    if host:
        keys.append(f"host:{host}")
    template = str(row.get("template") or "")
    if template:
        keys.append(f"endpoint:{template}")
    return keys


def _ms(value: Any) -> float:
    try:
        return max(0.0, float(value or 0))
    except (TypeError, ValueError):
        return 0.0


def _full_buckets(buckets: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    found: list[tuple[int, float, str]] = []
    for key, item in buckets.items():
        peak = float(item.get("fill_pct_peak") or 0.0)
        rejections = int(item.get("rejections") or 0)
        if peak >= FULL_PCT or rejections > 0:
            found.append((rejections, round(peak, 1), str(key)))
    found.sort(key=lambda entry: (-entry[0], -entry[1], entry[2]))
    return [{"key": key, "fill_pct_peak": peak, "rejections": rejections} for rejections, peak, key in found]


def explain_wait(facts: WaitFacts) -> dict[str, Any]:
    """`{found, reasons: [sentence], full_buckets, waited_ms, ...}` for one request (see the module docstring)."""
    row = facts.live
    reasons: list[str] = []
    full = _full_buckets(facts.buckets)
    if row is None:
        if facts.roblox_429s:
            reasons.append(
                "The Live record of this request is no longer kept (15 minutes), but Roxy's 429 log has it: "
                f"Roblox answered it with 429 {len(facts.roblox_429s)} time(s)."
            )
        else:
            reasons.append(
                "Nothing is kept for this request id: Live records last 15 minutes (and are sampled above 50 "
                "requests per second per worker); Roblox 429s are kept 90 days."
            )
        return {
            "found": bool(facts.roblox_429s),
            "reasons": reasons,
            "full_buckets": full,
            "waited_ms": None,
            "roblox_429s": [dict(item) for item in facts.roblox_429s],
            "prior_429s": [dict(item) for item in facts.prior_429s],
            "flagged_calls": {},
            "capture_available": facts.capture_available,
        }
    reason = str(row.get("reason") or "")
    outcome = str(row.get("outcome") or "")
    cache = str(row.get("cache") or "")
    waited = _ms(row.get("queue_wait_ms"))
    if outcome == "refused":
        reasons.append(f"Roxy's protection refused it ({reason}) before any upstream call; see the Protection page.")
    else:
        reasons.append(REASON_TEXT.get(reason, f"It ended with reason {reason}."))
    if reason == ReasonCode.UPSTREAM_COOLDOWN.value or reason == ReasonCode.CACHE_STALE_COOLDOWN.value:
        if facts.prior_429s:
            first = facts.prior_429s[0]
            retry = first.get("retry_after_s")
            wait = f" with Retry-After {round(float(retry))} s" if retry is not None else ""
            reasons.append(
                f"The cooldown came from Roblox: a 429 on {first.get('endpoint_template')} through "
                f"{first.get('egress')} at {first.get('at_ms')} ms{wait}."
            )
        else:
            reasons.append(
                "No 429 for this endpoint was logged shortly before it, so the cooldown was on its host or egress, "
                "or came from a circuit breaker or the x-ratelimit headers."
            )
    if waited > 0:
        sentence = f"It waited {round(waited, 1)} ms for a bucket slot"
        if facts.queue_budget_ms:
            sentence += f" (its queue budget was {round(facts.queue_budget_ms)} ms)"
        reasons.append(sentence + ".")
    if full and (waited > 0 or reason in (ReasonCode.UPSTREAM_BUSY.value, ReasonCode.QUEUE_OVERFLOW.value)):
        top = full[0]
        reasons.append(
            f"In that minute {top['key']} was the fullest of its buckets ({top['fill_pct_peak']} percent of its burst, "
            f"{top['rejections']} reservations refused); this is inferred from the minute's bucket history, "
            "because the binding bucket of each request is not stored."
        )
    attempts = int(row.get("attempts") or 0)
    if attempts > 1:
        reasons.append(
            f"It took {attempts} attempts: earlier ones failed (5xx, timeout or connect error) and were retried "
            "after a jittered backoff, each in a new bucket slot."
        )
    if int(row.get("retries") or 0) > 0:
        reasons.append(
            "Roblox asked for a CSRF token, so the call was repeated once with the new token (one more bucket slot)."
        )
    if facts.roblox_429s and reason != ReasonCode.UPSTREAM_COOLDOWN.value:
        reasons.append(f"Roblox answered 429 to {len(facts.roblox_429s)} of its calls.")
    challenges = int(facts.flagged_calls.get("challenges") or 0)
    html_bodies = int(facts.flagged_calls.get("html_bodies") or 0)
    if challenges or html_bodies:
        reasons.append(
            f"In that minute {challenges} call(s) to this endpoint through {row.get('egress')} were answered with a "
            f"challenge and {html_bodies} with an HTML page instead of JSON: Roblox or its CDN may be blocking this "
            "path. This is inferred from the minute's attempt history, because the flags of one request's calls are "
            "not stored."
        )
    if cache in _CACHE_SERVES and outcome != "refused" and waited == 0:
        reasons.append("A cache serve does not wait for Roblox.")
    return {
        "found": True,
        "reasons": reasons,
        "full_buckets": full,
        "waited_ms": round(waited, 3),
        "roblox_429s": [dict(item) for item in facts.roblox_429s],
        "prior_429s": [dict(item) for item in facts.prior_429s],
        "flagged_calls": dict(facts.flagged_calls),
        "capture_available": facts.capture_available,
    }


__all__ = ["FULL_PCT", "REASON_TEXT", "WaitFacts", "explain_wait", "request_bucket_keys"]
