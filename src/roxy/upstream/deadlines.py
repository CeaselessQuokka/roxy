"""Deadline math: every inner time budget of an upstream fetch, derived from the one request deadline.

What this is
    Small pure functions over the runtime settings: the single-flight owner deadline (plan 5.2 and 6.9), a class's
    queue budget, the per-attempt httpx timeout clipped to what is left of the request deadline, and whether a
    retry still fits after its backoff.

Why it exists
    Plan 5.2: the request deadline (`request_deadline_s`, 60 s) is enforced by middleware, and every inner budget
    is derived from it so they can never add up past it. The single-flight owner deadline is
    `queue_wait_interactive_ms + request_timeout x upstream_max_attempts + backoff_cap_ms` (4 s + 15 s x 2 + 2 s =
    36 s with defaults); followers wait up to that long and the lease expires after it. The catalog's cross rule
    keeps it below `request_deadline_s` minus 2 s. Keeping the formula in one function (the catalog's own
    `owner_deadline_s`) means the validation and the code can never disagree.

How it works
    Settings are read through the small `SettingsReader` protocol (`ctx.settings` satisfies it), so tests can
    pass a plain stand-in. Times are seconds as floats unless a name ends in `_ms`.

What to read next
    `roxy/config/catalog.py` (`owner_deadline_s` and the `owner_deadline` cross rule), then
    `roxy/upstream/service.py`, which calls these for every attempt.
"""

from __future__ import annotations

from typing import Any, Final, Protocol

import httpx

from roxy.config import catalog
from roxy.upstream.queue import QUEUE_WAIT_SETTING, Priority

WRITE_TIMEOUT_S: Final = 10.0
"""httpx write timeout per attempt (plan 7.11: write 10 s). A constant: request bodies are at most 2 MiB."""

POOL_TIMEOUT_S: Final = 5.0
"""httpx pool timeout per attempt (plan 7.11: pool 5 s): how long to wait for a free pooled connection."""

MIN_ATTEMPT_S: Final = 1.0
"""A retry is only worth starting when at least this much of the request deadline is left after its backoff."""

OWNER_DEADLINE_KEYS: Final = ("queue_wait_interactive_ms", "request_timeout", "upstream_max_attempts", "backoff_cap_ms")


class SettingsReader(Protocol):
    """The read side of `config.runtime.RuntimeSettings` that this package uses."""

    def get(self, key: str) -> Any: ...


def owner_deadline_s(settings: SettingsReader) -> float:
    """Plan 5.2: queue_wait_interactive_ms + request_timeout x upstream_max_attempts + backoff_cap_ms (seconds)."""
    value = catalog.owner_deadline_s({key: settings.get(key) for key in OWNER_DEADLINE_KEYS})
    if value is None:  # pragma: no cover - the catalog always has these keys with numeric values
        raise ValueError("owner deadline settings are missing")
    return value


def owner_deadline_ms(settings: SettingsReader) -> int:
    """`owner_deadline_s` in whole milliseconds, for lease expiry (`expires_ms = now + owner_deadline`)."""
    return round(owner_deadline_s(settings) * 1000)


def queue_budget_ms(settings: SettingsReader, priority: Priority) -> float:
    """The longest a request of `priority` may wait for a bucket slot (plan 7.8)."""
    return max(0.0, float(settings.get(QUEUE_WAIT_SETTING[priority])))


def attempt_timeout(settings: SettingsReader, remaining_s: float) -> httpx.Timeout:
    """httpx timeouts for one attempt: connect and read from the settings, both clipped to the deadline left.

    `request_timeout` is a per-read timeout in httpx (not a total), so the clip to `remaining_s` is what keeps a
    slowly dripping upstream from outliving the request deadline (v1 bug B30). The middleware's deadline still
    cuts anything that slips through.
    """
    left = max(0.05, remaining_s)
    read = min(float(settings.get("request_timeout")), left)
    connect = min(float(settings.get("upstream_connect_timeout_s")), left)
    return httpx.Timeout(connect=connect, read=read, write=min(WRITE_TIMEOUT_S, left), pool=min(POOL_TIMEOUT_S, left))


def can_retry_after(remaining_s: float, backoff_s: float, min_attempt_s: float = MIN_ATTEMPT_S) -> bool:
    """Whether a retry that first sleeps `backoff_s` still leaves `min_attempt_s` of the deadline for the call."""
    return remaining_s - backoff_s >= min_attempt_s


def internal_deadline_s(settings: SettingsReader, priority: Priority) -> float:
    """The deadline of an internal call (a probe or lookup has no middleware deadline): its class's queue wait
    plus every allowed attempt plus the backoff cap, never more than `request_deadline_s`."""
    budget = (
        queue_budget_ms(settings, priority) / 1000
        + float(settings.get("request_timeout")) * int(settings.get("upstream_max_attempts"))
        + float(settings.get("backoff_cap_ms")) / 1000
    )
    return min(budget, float(settings.get("request_deadline_s")))


__all__ = [
    "MIN_ATTEMPT_S",
    "OWNER_DEADLINE_KEYS",
    "POOL_TIMEOUT_S",
    "WRITE_TIMEOUT_S",
    "SettingsReader",
    "attempt_timeout",
    "can_retry_after",
    "internal_deadline_s",
    "owner_deadline_ms",
    "owner_deadline_s",
    "queue_budget_ms",
]
