"""Plausible v1 times and counts: one rule for every number the migrator reads from v1's JSON files.

What this is
    `plausible_epoch(value, now=...)` turns a v1 time (seconds since 1970, as v1 stored it) into whole seconds,
    or None when it is not a time v1 could have written; `bounded_count(value)` turns a v1 counter into a whole
    number SQLite and JSON both hold exactly; `finite_json(value)` replaces NaN and infinity anywhere in a
    structure with None, so `json.dumps(..., allow_nan=False)` can write it.

Why it exists
    v1's data file can hold damaged numbers (the v1 dashboard fix of 2026-10-09, MIGRATION.md): NaN and
    infinity, which Python's `json.load` accepts; zero and negative
    times; a huge finite value, which v1's cross-worker merge of the cache timestamps grew without bound before it
    reached infinity; and a time far in the future from a wrong clock. Lead decision (4) of the final review:
    a time more than one day ahead is damage, like a negative one (the patched v1 drops such values to 0 itself,
    `_plausible_time`), and NaN or infinity anywhere must never stop the import. Before this module a huge time
    became a 301 digit integer, and the SQLite insert raised OverflowError: the whole statistics step, or a whole
    rule table, rolled back on every run (finding ops-5). A time ten years ahead sorted first in the Clients and
    Protection tables for ten years and was never aged out by retention.

How it works
    A time must be a number (an int, a float, or text holding one; never a bool), finite, above 0 and at most
    `now + FUTURE_SLACK_S`; anything else is None, which every caller reads as "missing" (the import then uses
    the other time of the record, or the time of the run). A count is clamped to [0, MAX_COUNT]. JSON reports go
    through `finite_json` and are written with `allow_nan=False`, so a bare `NaN` (invalid JSON) never reaches a
    report file.

What to read next
    `roxy/migration/stats_import.py` and `roxy/migration/rules_import.py` (the callers), then `report.py`.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any, Final

FUTURE_SLACK_S: Final = 86400
"""How far ahead of the migrator's clock a v1 time may be (one day: clocks drift, time zones confuse; a time
further ahead is damage, lead decision 4)."""

MAX_COUNT: Final = 2**53
"""The largest count imported (exact in a JSON number and well inside SQLite's 64-bit INTEGER)."""

MAX_EXPIRY_S: Final = 253_402_300_799
"""The last second of the year 9999: the latest expiry time imported (an expiry lies in the future by nature)."""


def plausible_epoch(value: Any, *, now: int) -> int | None:
    """`value` as whole Unix seconds when it is a plausible v1 time at `now`, else None (read as missing)."""
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):  # OverflowError: an int too large for a float
        return None
    if not math.isfinite(number) or number <= 0 or number > now + FUTURE_SLACK_S:
        return None
    return int(number)


def plausible_expiry(value: Any) -> int | None:
    """`value` as whole Unix seconds when it is a usable expiry time (finite, positive, at most MAX_EXPIRY_S), else
    None. Unlike a "seen" time, an expiry may lie far ahead; it only has to fit a date and an SQLite INTEGER."""
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(number) or number <= 0 or number > MAX_EXPIRY_S:
        return None
    return int(number)


def bounded_count(value: Any) -> int:
    """A non-negative whole number from a v1 counter, at most MAX_COUNT (anything that is not a number is 0)."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return min(max(0, value), MAX_COUNT)
    if isinstance(value, float) and math.isfinite(value):
        return min(max(0, int(value)), MAX_COUNT)
    return 0


def finite_json(value: Any) -> Any:
    """`value` with every NaN or infinite float (in lists, tuples and dict values, at any depth) replaced by None."""
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, Mapping):
        return {key: finite_json(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [finite_json(item) for item in value]
    return value


__all__ = [
    "FUTURE_SLACK_S",
    "MAX_COUNT",
    "MAX_EXPIRY_S",
    "bounded_count",
    "finite_json",
    "plausible_epoch",
    "plausible_expiry",
]
