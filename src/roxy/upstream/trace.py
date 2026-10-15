"""The per-request upstream trace: what happened on the way to Roblox, for the live feed and "why did this wait?".

What this is
    `Trace`, a small mutable record filled while one fetch runs (attempts, egress paths tried, the last upstream
    status and redacted headers, errors, queue wait, the cooldown or bucket that held the request back), with one
    `AttemptRecord` per HTTP call. `to_dict()` renders the v1 field names plus the v2 additions.

Why it exists
    Parity row 37: v1's trace carried Attempts, Methods, Method, Outcome, UpstreamStatus, UpstreamHeaders,
    UpstreamError, Duration and Retries, and the live feed, captures and the endpoint log read them. v2 adds
    QueueWaitMs, CooldownSource, BucketKey, EgressIdentity and CacheDecision so the Upstream page can answer
    "why did this request wait?" (plan 7.12). Two v1 problems are fixed: headers were stored unredacted (B28) and
    fields leaked from one attempt into the next (B32, an old timeout error survived a later success).

How it works
    Every call appends an `AttemptRecord` (bounded at `MAX_ATTEMPT_RECORDS`) and overwrites the top-level "last
    call" fields, clearing the error of a successful call. A call Roblox answered with a challenge or with an HTML
    page on a JSON endpoint (`upstream/pages.py`) carries the `challenge` and `html_body` flags, which the metrics
    recorder counts per minute for UP-CHALLENGE; a rotator call carries the short hash of the exit it used (a
    retry after a rotation uses another exit). Upstream headers pass through `core.redact
    .redact_headers` before they are stored, so cookies, CSRF tokens and anything credential-shaped never reach a
    trace. Session ids of the rotator are shown as a short hash (they select an exit IP).

What to read next
    `roxy/upstream/service.py` (who fills it) and `roxy/metrics/live.py` (who shows it).
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from roxy.core.redact import redact_headers, redact_text

MAX_ATTEMPT_RECORDS: Final = 16
"""Calls kept per trace (attempts, CSRF retries and redirect hops; the real number is far lower)."""

MAX_ERROR_LENGTH: Final = 300
"""v1 truncated `UpstreamError` to 300 characters."""

MAX_HEADER_VALUE_LENGTH: Final = 500


def short_hash(value: str) -> str:
    """A short, stable label for an identifier that should not be shown verbatim (rotator session ids)."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:10]


@dataclass(slots=True)
class AttemptRecord:
    """One HTTP call made for this request."""

    number: int  # 1-based attempt number (a CSRF retry or redirect hop shares its attempt's number)
    egress: str
    kind: str  # an `AttemptKind` value
    status: int | None
    duration_ms: float
    error: str = ""
    csrf_retry: bool = False
    redirect_hop: int = 0
    queue_wait_ms: float = 0.0
    challenge: bool = False  # the answer carried a challenge header (`upstream/pages.py`)
    html_body: bool = False  # the answer was an HTML page on a JSON endpoint
    exit_id: str = ""  # rotator calls: the short hash of the session (exit) this call used

    def to_dict(self) -> dict[str, Any]:
        return {
            "Attempt": self.number,
            "Egress": self.egress,
            "Kind": self.kind,
            "Status": self.status,
            "DurationMs": round(self.duration_ms, 1),
            "Error": self.error,
            "CsrfRetry": self.csrf_retry,
            "RedirectHop": self.redirect_hop,
            "QueueWaitMs": round(self.queue_wait_ms, 1),
            "Challenge": self.challenge,
            "HtmlBody": self.html_body,
        }


@dataclass(slots=True)
class Trace:
    """Everything worth knowing about one fetch. Mutable while the fetch runs, read-only afterwards."""

    request_id: str = ""
    attempts: int = 0  # routed attempts (CSRF retries and redirect hops are not attempts, v1 semantics)
    retries: int = 0  # CSRF retries (v1 `Retries`)
    egresses: list[str] = field(default_factory=list)  # v1 `Methods`: egress per attempt, in order
    egress: str = "none"  # v1 `Method`: the egress of the last call
    outcome: str = ""  # the final reason code
    upstream_status: int | None = None
    upstream_headers: dict[str, str] = field(default_factory=dict)
    upstream_error: str = ""
    duration_ms: float = 0.0  # the last call only (v1 `Duration`)
    queue_wait_ms: float = 0.0  # total time spent waiting for bucket slots
    cooldown_source: str = ""  # retry_after, ratelimit_reset, breaker or default, when a cooldown decided the outcome
    bucket_key: str = ""  # the bucket that bound the reservation (the one with the latest slot)
    egress_identity: str = ""  # direct, credential, or rotator:<session hash>
    cache_decision: str = ""  # filled by the cache layer (HIT, MISS, ...); upstream leaves it empty
    calls: list[AttemptRecord] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)  # short routing notes ("direct cooling down, used rotator")

    def start_attempt(self, egress: str) -> int:
        """Count a routed attempt on `egress` and return its number."""
        self.attempts += 1
        self.egresses.append(egress)
        self.egress = egress
        return self.attempts

    def record_call(
        self,
        *,
        egress: str,
        kind: str,
        status: int | None,
        duration_ms: float,
        headers: Mapping[str, str] | None = None,
        error: str = "",
        csrf_retry: bool = False,
        redirect_hop: int = 0,
        queue_wait_ms: float = 0.0,
        challenge: bool = False,
        html_body: bool = False,
        exit_id: str = "",
    ) -> None:
        """Record one HTTP call (or a call that failed before an answer) and make it the "last call"."""
        clean_error = redact_text(error)[:MAX_ERROR_LENGTH] if error else ""
        self.egress = egress
        self.upstream_status = status
        self.upstream_error = clean_error  # cleared on success: no leak from earlier attempts (v1 bug B32)
        self.duration_ms = duration_ms
        self.upstream_headers = (
            redact_headers(headers, max_value_length=MAX_HEADER_VALUE_LENGTH) if headers is not None else {}
        )
        if csrf_retry:
            self.retries += 1
        if len(self.calls) < MAX_ATTEMPT_RECORDS:
            self.calls.append(
                AttemptRecord(
                    number=max(1, self.attempts),
                    egress=egress,
                    kind=kind,
                    status=status,
                    duration_ms=duration_ms,
                    error=clean_error,
                    csrf_retry=csrf_retry,
                    redirect_hop=redirect_hop,
                    queue_wait_ms=queue_wait_ms,
                    challenge=challenge,
                    html_body=html_body,
                    exit_id=exit_id,
                )
            )

    def note(self, text: str) -> None:
        """Add a short routing note (bounded)."""
        if len(self.notes) < MAX_ATTEMPT_RECORDS:
            self.notes.append(text[:200])

    def to_dict(self) -> dict[str, Any]:
        """The v1 trace fields (row 37) plus the v2 additions, ready for JSON."""
        return {
            "Attempts": self.attempts,
            "Methods": list(self.egresses),
            "Method": self.egress,
            "Outcome": self.outcome,
            "UpstreamStatus": self.upstream_status,
            "UpstreamHeaders": dict(self.upstream_headers),
            "UpstreamError": self.upstream_error,
            "Duration": round(self.duration_ms / 1000, 3),
            "Retries": self.retries,
            "QueueWaitMs": round(self.queue_wait_ms, 1),
            "CooldownSource": self.cooldown_source,
            "BucketKey": self.bucket_key,
            "EgressIdentity": self.egress_identity,
            "CacheDecision": self.cache_decision,
            "Calls": [call.to_dict() for call in self.calls],
            "Notes": list(self.notes),
        }


__all__ = ["MAX_ATTEMPT_RECORDS", "AttemptRecord", "Trace", "short_hash"]
