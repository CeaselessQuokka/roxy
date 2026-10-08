"""Latency histograms with fixed buckets: mergeable by addition, stored as small varint-packed blobs.

What this is
    The 21 fixed latency buckets of plan 6.4 (upper bounds 5, 10, 20, 35, 50, 75, 100, 150, 200, 300, 500, 750,
    1000, 1500, 2000, 3000, 5000, 8000, 12000, 20000 ms, plus an overflow bucket), the functions that put a
    duration in a bucket, pack a histogram into a blob and back, merge blobs, and read percentiles (p50, p95,
    p99) out of a histogram. Plus the two SQL functions the rollup tables use: `roxy_hist_merge(a, b)` (scalar,
    for `ON CONFLICT` upserts) and `roxy_hist_sum(blob)` (aggregate, for compaction and queries).

Why it exists
    A percentile cannot be averaged: the p95 of two minutes is not the mean of their two p95s. Counting requests
    per fixed bucket instead makes histograms of any two minutes, endpoints or workers add up element by element,
    so p50, p95 and p99 can be computed for any time range and any filter straight from the rollups (parity row
    70). The price is precision: a percentile is only known to within its bucket, which `percentile` reports as
    an interpolated value and `BUCKET_ERROR_NOTE` explains in the UI tooltip.

How it works
    - In memory a histogram is a plain `list[int]` of 21 counts (dense; cheap to add to).
    - On disk it is sparse: only non-empty buckets, as pairs of varints `(bucket index, count)` with strictly
      increasing indexes (a varint stores 7 bits per byte, so small numbers take one byte). An empty histogram
      is stored as NULL. A minute with 40 requests spread over 4 buckets costs 8 bytes instead of 21 integers.
    - `percentile(counts, q)` finds the bucket holding the q-th request and interpolates linearly between the
      bucket's lower and upper bound. The overflow bucket has no upper bound, so a percentile that lands there
      reports the last bound (20000 ms) and `is_overflow` says so.
    - SQLite cannot call Python by itself: `register_sql_functions(conn)` attaches the two functions to one
      connection. It is cheap and idempotent, so the write handlers and readers call it at the start of every
      transaction (sqlite3 connections do not support weak references, so "already registered" cannot be
      tracked reliably).

What to read next
    `roxy/metrics/recorder.py` (where histograms are filled), `roxy/metrics/rollups.py` (where they are merged in
    SQL), `roxy/metrics/queries.py` (where percentiles are read back).
"""

from __future__ import annotations

import bisect
import sqlite3
from collections.abc import Iterable, Sequence

BOUNDS_MS: tuple[int, ...] = (
    5,
    10,
    20,
    35,
    50,
    75,
    100,
    150,
    200,
    300,
    500,
    750,
    1000,
    1500,
    2000,
    3000,
    5000,
    8000,
    12000,
    20000,
)
"""Inclusive upper bounds of the first 20 buckets in milliseconds (plan 6.4). Bucket 20 is the overflow."""

BUCKETS = len(BOUNDS_MS) + 1
OVERFLOW = BUCKETS - 1

BUCKET_ERROR_NOTE = (
    "Percentiles are computed from fixed latency buckets, so each value is accurate to within its bucket: for "
    "example a p95 shown as 180 ms lies somewhere between 150 and 200 ms. Values at or above 20000 ms are only "
    "known to be at least that long."
)
"""Tooltip text for every percentile on the dashboard (plan 6.4: error bounded by bucket width, documented)."""

SQL_MERGE = "roxy_hist_merge"
SQL_SUM = "roxy_hist_sum"


def empty() -> list[int]:
    """A new histogram with every bucket at zero."""
    return [0] * BUCKETS


def bucket_index(ms: float) -> int:
    """The bucket for a duration: the first bucket whose upper bound is at least `ms` (negative counts as 0)."""
    value = ms if ms > 0 else 0.0
    # bisect_left on the inclusive bounds: 5.0 lands in bucket 0, 5.01 in bucket 1, 20000.5 in the overflow.
    return bisect.bisect_left(BOUNDS_MS, value)


def observe(counts: list[int], ms: float, n: int = 1) -> None:
    """Add `n` observations of `ms` milliseconds to `counts` in place."""
    counts[bucket_index(ms)] += n


def add_into(target: list[int], other: Sequence[int]) -> None:
    """Element-wise `target += other` (the merge that makes histograms of any slices add up)."""
    for i, value in enumerate(other):
        if value:
            target[i] += value


def total(counts: Sequence[int]) -> int:
    return sum(counts)


# ------------------------------------------------------------------------------------------------ encoding


def _put_varint(out: bytearray, value: int) -> None:
    if value < 0:
        raise ValueError("varint values must not be negative")
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)


def _get_varint(data: bytes, pos: int) -> tuple[int, int]:
    shift = 0
    value = 0
    while True:
        if pos >= len(data):
            raise ValueError("truncated histogram blob")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7
        if shift > 63:
            raise ValueError("histogram varint too long")


def encode(counts: Sequence[int]) -> bytes | None:
    """Pack a histogram as sparse `(index, count)` varint pairs; None (SQL NULL) when it is empty."""
    out = bytearray()
    for index, count in enumerate(counts):
        if count:
            _put_varint(out, index)
            _put_varint(out, count)
    return bytes(out) if out else None


def decode(blob: bytes | None) -> list[int]:
    """Unpack a blob from `encode` (None or empty means an empty histogram). Raises ValueError if malformed."""
    counts = empty()
    if not blob:
        return counts
    data = bytes(blob)
    pos = 0
    previous = -1
    while pos < len(data):
        index, pos = _get_varint(data, pos)
        count, pos = _get_varint(data, pos)
        if index <= previous or index >= BUCKETS:
            raise ValueError("histogram blob has an out of order or unknown bucket index")
        counts[index] = count
        previous = index
    return counts


def merge_blobs(a: bytes | None, b: bytes | None) -> bytes | None:
    """`encode(decode(a) + decode(b))`, the scalar SQL function `roxy_hist_merge` (NULL-safe)."""
    if not a:
        return bytes(b) if b else None
    if not b:
        return bytes(a)
    counts = decode(a)
    add_into(counts, decode(b))
    return encode(counts)


def sum_blobs(blobs: Iterable[bytes | None]) -> list[int]:
    """Decode and add many blobs (Python side of `roxy_hist_sum`)."""
    counts = empty()
    for blob in blobs:
        if blob:
            add_into(counts, decode(blob))
    return counts


class _HistSum:
    """The `roxy_hist_sum(blob)` aggregate: element-wise sum of every blob in a group."""

    def __init__(self) -> None:
        self.counts = empty()
        self.seen = False

    def step(self, blob: bytes | None) -> None:
        if blob:
            add_into(self.counts, decode(blob))
            self.seen = True

    def finalize(self) -> bytes | None:
        return encode(self.counts) if self.seen else None


def register_sql_functions(conn: sqlite3.Connection) -> None:
    """Attach `roxy_hist_merge` and `roxy_hist_sum` to `conn` (idempotent; call inside each transaction)."""
    # deterministic=True lets SQLite use the function in more query plans; it is a pure function of its inputs.
    conn.create_function(SQL_MERGE, 2, merge_blobs, deterministic=True)
    conn.create_aggregate(SQL_SUM, 1, _HistSum)  # type: ignore[arg-type]


# --------------------------------------------------------------------------------------------- percentiles


def lower_bound(index: int) -> float:
    return 0.0 if index == 0 else float(BOUNDS_MS[index - 1])


def upper_bound(index: int) -> float:
    return float(BOUNDS_MS[index]) if index < OVERFLOW else float(BOUNDS_MS[-1])


def percentile(counts: Sequence[int], q: float) -> float | None:
    """The q-th percentile (0 < q <= 1) in ms, interpolated inside its bucket; None for an empty histogram.

    The rank is `q * total`; the bucket holding that rank is found by walking the cumulative counts, and the
    value is placed proportionally between the bucket's bounds (requests are assumed spread evenly inside a
    bucket). A rank in the overflow bucket returns 20000 ms (the last known bound).
    """
    if not 0 < q <= 1:
        raise ValueError("q must be in (0, 1]")
    n = sum(counts)
    if n <= 0:
        return None
    rank = q * n
    cumulative = 0
    for index, count in enumerate(counts):
        if not count:
            continue
        if cumulative + count >= rank:
            if index == OVERFLOW:
                return float(BOUNDS_MS[-1])
            low, high = lower_bound(index), upper_bound(index)
            fraction = (rank - cumulative) / count
            return round(low + (high - low) * fraction, 3)
        cumulative += count
    return float(BOUNDS_MS[-1])  # pragma: no cover (rank <= n always lands above)


def is_overflow(counts: Sequence[int], q: float) -> bool:
    """True when the q-th percentile falls in the overflow bucket (only known to be at least 20000 ms)."""
    n = sum(counts)
    if n <= 0:
        return False
    return sum(counts[:OVERFLOW]) < q * n


def percentiles(counts: Sequence[int], qs: Iterable[float] = (0.5, 0.95, 0.99)) -> dict[str, float | None]:
    """`{"p50": ..., "p95": ..., "p99": ...}` for the given quantiles."""
    return {f"p{round(q * 100):d}": percentile(counts, q) for q in qs}


def mean_estimate(counts: Sequence[int]) -> float | None:
    """Mean from bucket midpoints (overflow counted at its lower bound). An estimate, like every bucket value."""
    n = sum(counts)
    if n <= 0:
        return None
    acc = 0.0
    for index, count in enumerate(counts):
        if count:
            mid = lower_bound(index) if index == OVERFLOW else (lower_bound(index) + upper_bound(index)) / 2
            acc += mid * count
    return round(acc / n, 3)
