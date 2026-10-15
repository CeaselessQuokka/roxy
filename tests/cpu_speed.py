"""How much slower this machine runs the regex engine than the machine the timing bounds were set on.

What this is
    `slowdown()`: this machine's time for a fixed `regex` workload divided by the time the same workload takes on
    the development machine the ReDoS cost model and the regex timing tests were calibrated on (an AMD Ryzen 9
    9950X3D under WSL2), never less than 1. `scaled(seconds)` is a wall-time bound multiplied by it.

Why it exists
    A few tests bound one regex run in wall time, for example "every accepted pattern fails a worst-case 8 KiB
    input in under half of the 50 ms per-match timeout". `rules/regex_cost.py` calibrated its 3 million step
    budget on the development machine (about 5 to 25 ms there), so those bounds hold there with a margin. A
    GitHub-hosted runner is about twice as slow per core, which puts the slowest accepted patterns (13 to 14 ms on
    the development machine) past 25 ms, as the development machine slowed to half speed showed: CI failed while
    nothing had changed. A bound multiplied by `slowdown()` keeps its meaning on any machine (the
    same margin against the model's calibration, and a pattern that gets slower still fails); on the development
    machine, and on anything faster, the bound is exactly what the test says.

How it works
    The workload runs in the engine Roxy matches with (`regex`): a backtracking search for a chain of seven
    optional characters followed by a digit over 8 KiB of text that never matches (`REFERENCE_S` on the
    development machine). It is not one of the patterns any test measures.
    The best of `RUNS` runs is taken (a scheduler hiccup is not the machine's speed), once per process.

What to read next
    `src/roxy/rules/regex_cost.py` (the calibration), tests/unit/rules/test_regex_cost.py and
    tests/security/test_ingress_redos.py (the bounds that use it).
"""

from __future__ import annotations

import time
from functools import cache

import regex

REFERENCE_PATTERN = "[c-y]?" * 7 + "[0-9]"
REFERENCE_TEXT = "m" * 8192
REFERENCE_S = 0.008
"""The workload's best time on the development machine: 7.3 to 7.9 ms on each of its idle cores (2026-10-15)."""
RUNS = 5


@cache
def slowdown() -> float:
    """This machine's regex speed relative to the development machine: 1.0 there or faster, 2.0 when twice as slow."""
    compiled = regex.compile(REFERENCE_PATTERN)
    best = float("inf")
    for _ in range(RUNS):
        started = time.perf_counter()
        compiled.search(REFERENCE_TEXT)
        best = min(best, time.perf_counter() - started)
    return max(1.0, best / REFERENCE_S)


def scaled(seconds: float) -> float:
    """A wall-time bound set on the development machine, for this machine."""
    return seconds * slowdown()
