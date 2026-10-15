"""Decorrelated jitter backoff: how long to wait before retrying a failed upstream call.

What this is
    `DecorrelatedJitter`, a tiny stateful generator of retry delays, and the pure step function behind it.

Why it exists
    Plan 2.5 F9 and 7.9: a 5xx, timeout or connect error may be retried (up to `upstream_max_attempts`), but never
    immediately. If every worker retried after the same fixed delay, their retries would arrive at Roblox in
    lockstep (a "thundering herd"); plain exponential backoff with full jitter spreads them but can produce very
    short waits. "Decorrelated jitter" (Marc Brooker, AWS Architecture Blog, 2015) keeps waits growing on average
    while each one is random: `next = min(cap, uniform(base, previous x 3))`.

How it works
    Start at `previous = base`. Each call draws uniformly between `base` and three times the previous delay and
    clips to `cap` (`backoff_base_ms` 200, `backoff_cap_ms` 2000). Every delay therefore lies in `[base, cap]`, the
    property the unit tests check. The random source is injectable so tests are deterministic.

What to read next
    `roxy/upstream/deadlines.py` (`can_retry_after`: a retry only happens if it still fits the deadline), then
    `roxy/upstream/service.py`.
"""

from __future__ import annotations

import random
from typing import Protocol


class UniformSource(Protocol):
    """Anything with `uniform(a, b)` (`random.Random` and the module `random` both qualify)."""

    def uniform(self, a: float, b: float) -> float: ...


def decorrelated_jitter_ms(previous_ms: float, base_ms: float, cap_ms: float, rng: UniformSource) -> float:
    """One step: `min(cap, uniform(base, previous x 3))`, always within `[base, cap]`."""
    base = max(0.0, float(base_ms))
    cap = max(base, float(cap_ms))
    upper = max(base, float(previous_ms) * 3)
    return min(cap, max(base, rng.uniform(base, upper)))


class DecorrelatedJitter:
    """Successive retry delays for one request. Not shared between requests (each has its own history)."""

    def __init__(self, base_ms: float, cap_ms: float, rng: UniformSource | None = None) -> None:
        self.base_ms = max(0.0, float(base_ms))
        self.cap_ms = max(self.base_ms, float(cap_ms))
        self._rng: UniformSource = rng if rng is not None else random.Random()
        self._previous = self.base_ms

    def next_ms(self) -> float:
        """The next delay in milliseconds."""
        delay = decorrelated_jitter_ms(self._previous, self.base_ms, self.cap_ms, self._rng)
        self._previous = delay
        return delay

    def next_s(self) -> float:
        """The next delay in seconds."""
        return self.next_ms() / 1000

    def reset(self) -> None:
        """Start over from `base` (after a success)."""
        self._previous = self.base_ms


__all__ = ["DecorrelatedJitter", "UniformSource", "decorrelated_jitter_ms"]
