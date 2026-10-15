"""Clocks: one place that answers "what time is it?", so tests can control time.

What this is
    A tiny `Clock` protocol with two implementations: `SystemClock` (the real time) and `FakeClock` (a clock tests
    move forward by hand).

Why it exists
    Rate limiters, cooldowns, TTLs and leases are all time math. If every module called `time.time()` directly,
    a test of "the ban expires after 60 minutes" would have to sleep for an hour, or monkeypatch the standard
    library. v1 shortened its constants in a DEBUG mode instead, which tested different numbers than production
    ran (plan 15.4, "Retired"). Passing a clock around fixes both problems.

How it works
    `now()` is wall clock seconds (for timestamps that are stored or shown), `now_ms()` the same in integer
    milliseconds (GCRA and leases store milliseconds), and `monotonic()` is a clock that never jumps backwards
    (for measuring durations and deadlines inside one process; it is meaningless across processes, so it is
    never stored in a database).

What to read next
    `roxy/core/ids.py` (time-sortable ids built from the clock), then `roxy/storage/leases.py` (leases are
    expiry times in milliseconds).
"""

from __future__ import annotations

import threading
import time
from typing import Protocol


class Clock(Protocol):
    """Anything that can tell the time. Code depends on this protocol, never on a concrete clock."""

    def now(self) -> float:
        """Wall clock time in seconds since the Unix epoch (UTC)."""
        ...

    def now_ms(self) -> int:
        """Wall clock time in integer milliseconds since the Unix epoch (UTC)."""
        ...

    def monotonic(self) -> float:
        """Seconds from an arbitrary start point that never goes backwards (durations, deadlines)."""
        ...


class SystemClock:
    """The real clock."""

    def now(self) -> float:
        return time.time()

    def now_ms(self) -> int:
        # time_ns avoids the float rounding that int(time.time() * 1000) can introduce.
        return time.time_ns() // 1_000_000

    def monotonic(self) -> float:
        return time.monotonic()


class FakeClock:
    """A clock that only moves when a test calls `advance()` or `set()`.

    Thread safe, because storage writer threads read the clock while the test thread advances it.
    """

    def __init__(self, start: float = 1_760_000_000.0) -> None:
        self._now = float(start)
        self._mono = 1000.0
        self._lock = threading.Lock()

    def now(self) -> float:
        with self._lock:
            return self._now

    def now_ms(self) -> int:
        with self._lock:
            # round() with no ndigits already returns an int (round half to even).
            return round(self._now * 1000)

    def monotonic(self) -> float:
        with self._lock:
            return self._mono

    def advance(self, seconds: float) -> None:
        """Move both clocks forward by `seconds` (must not be negative: time never runs backwards here)."""
        if seconds < 0:
            raise ValueError("FakeClock cannot move backwards")
        with self._lock:
            self._now += seconds
            self._mono += seconds

    def set(self, wall_seconds: float) -> None:
        """Jump the wall clock to an absolute time (the monotonic clock moves by the same amount if forward)."""
        with self._lock:
            delta = wall_seconds - self._now
            self._now = float(wall_seconds)
            if delta > 0:
                self._mono += delta


SYSTEM_CLOCK: Clock = SystemClock()
"""The shared real clock. Production code receives it through `AppContext.clock`."""
