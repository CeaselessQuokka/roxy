"""The harness clock: one time line for the load client, the mock Roblox and Roxy's own rate decisions.

What this is
    `now()`: seconds on the wall clock (CLOCK_REALTIME, the clock Roxy's GCRA buckets, cache TTLs and cooldowns
    read through `roxy.core.clock.SystemClock`), made steady: within one process it never goes back. Two things
    use it: the client's schedule ("send request 812 at 81.2 s") and the mock's per-endpoint windows ("60 calls in
    any 60 s"). Durations (latency, timeouts) keep using `time.monotonic()`.

Why it exists
    A load test compares three parties' sense of time: callers send N requests a minute, Roxy paces M calls a
    minute, and the mock refuses above L calls a minute. If one of them measures a minute differently, the test
    measures the clocks, not Roxy. That happens on WSL 2: there CLOCK_MONOTONIC runs about 9.5 percent fast
    against the host (90 s of `time.monotonic()` took 82 s on a Windows stopwatch), while the wall clock is
    stepped back about 2.8 s every 32 s to stay on the host's time (the step size varies from day to day; it was
    0.9 s per 31 s earlier). An earlier version of this harness ran the client and the mock on CLOCK_MONOTONIC,
    so on WSL the callers sent 9.5 percent more than planned and the mock's "minute" was 55 real seconds, while
    Roxy's buckets and TTLs ran on real time: the mock was effectively 9.5 percent more generous to Roxy than a
    machine with honest clocks would be. On a normal Linux server (NTP slews, never steps) the two clocks agree
    and this module changes nothing.

How it works
    `now()` returns `max(last value returned, time.time())`. After a step back the harness clock holds still
    until the wall clock catches up, exactly what Roxy's GCRA does with `max(TAT, now)` and what the abuse
    pipeline's `steady_now_ms` does: during those seconds the client sends nothing new, the mock's windows do not
    age, and Roxy's buckets do not refill. Every process of the harness reads the same system wall clock, so
    times taken in the client processes and in the mock's thread line up without any exchange of offsets; the
    mock's loop and each client's loop run `tick_forever` so that every process holds still at the same instant.
    `sleep_until(t)` sleeps on `asyncio` (which uses CLOCK_MONOTONIC for the length of a sleep) and checks the
    harness clock again when it wakes, so a request never leaves before its planned instant.

What to read next
    `client.py` (the schedule), `mock_roblox.py` (the windows), `roxy/core/clock.py` (Roxy's side).
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Callable
from typing import Final

_lock: Final = threading.Lock()
_last = 0.0
_wall: Callable[[], float] = time.time
"""The wall clock read by `now()` (a test replaces it to play a step back)."""

MIN_SLEEP_S: Final = 0.0005
"""Shortest sleep `sleep_until` makes while the harness clock is behind its target (it re-checks after it)."""


TICK_S: Final = 0.005
"""How often `tick_forever` reads the clock."""


def now() -> float:
    """Wall clock seconds that never step back within this process (see the module docstring)."""
    global _last
    value = _wall()
    with _lock:
        if value > _last:
            _last = value
        return _last


async def tick_forever() -> None:
    """Read the clock every `TICK_S` until canceled (run it as a task on the loop of the mock and of each client).

    `now()` remembers the last value it returned, so after a step back it holds still at the newest instant this
    process has seen. A process that reads the clock rarely (the mock reads it once per call) would hold still at
    an older instant than a busy one, and the two would disagree for a few seconds after each step. Ticking keeps
    every process's last value within a few milliseconds of the instant of the step.
    """
    while True:
        now()
        await asyncio.sleep(TICK_S)


async def sleep_until(target: float) -> None:
    """Sleep until the harness clock reaches `target`; returns at once when it already has."""
    while True:
        remaining = target - now()
        if remaining <= 0:
            return
        await asyncio.sleep(max(remaining, MIN_SLEEP_S))


def wait_until(target: float) -> None:
    """The blocking form of `sleep_until`, for threads and plain functions."""
    while True:
        remaining = target - now()
        if remaining <= 0:
            return
        time.sleep(max(remaining, MIN_SLEEP_S))


__all__ = ["MIN_SLEEP_S", "TICK_S", "now", "sleep_until", "tick_forever", "wait_until"]
