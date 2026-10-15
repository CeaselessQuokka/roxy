"""Histogram buckets, the blob format, the SQL merge functions and percentile math (plan 6.4, parity row 70)."""

from __future__ import annotations

import sqlite3

import pytest
from hypothesis import given
from hypothesis import strategies as st

from roxy.metrics import histograms as h

counts_strategy = st.lists(st.integers(min_value=0, max_value=10**9), min_size=h.BUCKETS, max_size=h.BUCKETS)


def test_bounds_are_the_plan_values() -> None:
    assert h.BOUNDS_MS == (
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
    assert h.BUCKETS == 21


@pytest.mark.parametrize(
    ("ms", "index"),
    [(-3, 0), (0, 0), (5, 0), (5.01, 1), (10, 1), (35, 3), (36, 4), (19999.9, 19), (20000, 19), (20000.1, 20)],
)
def test_bucket_index_uses_inclusive_upper_bounds(ms: float, index: int) -> None:
    assert h.bucket_index(ms) == index


def test_encode_is_sparse_varint_pairs_and_empty_is_null() -> None:
    counts = h.empty()
    assert h.encode(counts) is None
    counts[2] = 3
    counts[20] = 300
    blob = h.encode(counts)
    assert blob == bytes([2, 3, 20, 0xAC, 0x02])  # 300 = 0b10_0101100 -> 0xAC 0x02
    assert h.decode(blob) == counts
    assert h.decode(None) == h.empty()


@given(counts_strategy, counts_strategy)
def test_merge_is_element_wise_addition(a: list[int], b: list[int]) -> None:
    merged = h.merge_blobs(h.encode(a), h.encode(b))
    assert h.decode(merged) == [x + y for x, y in zip(a, b, strict=True)]


@given(counts_strategy)
def test_round_trip(counts: list[int]) -> None:
    assert h.decode(h.encode(counts)) == counts


@pytest.mark.parametrize("blob", [bytes([3, 1, 2, 1]), bytes([21, 1]), bytes([1]), bytes([0x80])])
def test_malformed_blobs_are_rejected(blob: bytes) -> None:
    with pytest.raises(ValueError):
        h.decode(blob)


def test_sql_functions_merge_and_sum() -> None:
    conn = sqlite3.connect(":memory:")
    h.register_sql_functions(conn)
    a, b = h.empty(), h.empty()
    a[1], b[1], b[5] = 2, 3, 7
    row = conn.execute(
        "SELECT roxy_hist_merge(?, ?), roxy_hist_merge(NULL, ?), roxy_hist_merge(?, NULL)",
        (h.encode(a), h.encode(b), h.encode(b), h.encode(a)),
    ).fetchone()
    assert h.decode(row[0])[1] == 5
    assert h.decode(row[1]) == b
    assert h.decode(row[2]) == a
    conn.execute("CREATE TABLE t (g INTEGER, x BLOB)")
    conn.executemany("INSERT INTO t VALUES (?, ?)", [(1, h.encode(a)), (1, h.encode(b)), (1, None), (2, None)])
    rows = dict(conn.execute("SELECT g, roxy_hist_sum(x) FROM t GROUP BY g").fetchall())
    assert h.decode(rows[1])[5] == 7
    assert h.decode(rows[1])[1] == 5
    assert rows[2] is None  # a group of empty histograms stays NULL


def test_percentile_interpolates_inside_the_bucket() -> None:
    counts = h.empty()
    counts[h.bucket_index(150)] = 100  # every request between 100 and 150 ms
    assert h.percentile(counts, 0.5) == pytest.approx(125.0)
    assert h.percentile(counts, 0.99) == pytest.approx(149.5)
    assert h.percentile(counts, 1.0) == pytest.approx(150.0)


def test_percentile_across_buckets() -> None:
    counts = h.empty()
    counts[0] = 50  # 0..5 ms
    counts[10] = 45  # 300..500 ms
    counts[20] = 5  # over 20 s
    assert h.percentile(counts, 0.5) == pytest.approx(5.0)
    assert h.percentile(counts, 0.95) == pytest.approx(500.0)
    assert h.percentile(counts, 0.99) == 20000.0
    assert h.is_overflow(counts, 0.99)
    assert not h.is_overflow(counts, 0.95)
    assert h.percentiles(counts) == {"p50": pytest.approx(5.0), "p95": pytest.approx(500.0), "p99": 20000.0}


def test_percentile_of_empty_histogram_is_none_and_q_is_checked() -> None:
    assert h.percentile(h.empty(), 0.5) is None
    with pytest.raises(ValueError):
        h.percentile([1] * h.BUCKETS, 0)


@given(counts_strategy)
def test_percentiles_are_monotone_and_within_bounds(counts: list[int]) -> None:
    values = [h.percentile(counts, q) for q in (0.1, 0.5, 0.9, 0.95, 0.99, 1.0)]
    if sum(counts) == 0:
        assert all(v is None for v in values)
        return
    numbers = [v for v in values if v is not None]
    assert numbers == sorted(numbers)
    assert all(0 <= v <= 20000 for v in numbers)


def test_percentile_error_is_bounded_by_the_bucket_width() -> None:
    durations = [7.0] * 30 + [180.0] * 60 + [900.0] * 10
    counts = h.empty()
    for ms in durations:
        h.observe(counts, ms)
    exact_p95 = sorted(durations)[94]
    estimate = h.percentile(counts, 0.95)
    assert estimate is not None
    index = h.bucket_index(exact_p95)
    assert h.lower_bound(index) <= estimate <= h.upper_bound(index)


def test_mean_estimate() -> None:
    counts = h.empty()
    counts[0] = 2  # midpoint 2.5
    counts[1] = 2  # midpoint 7.5
    assert h.mean_estimate(counts) == pytest.approx(5.0)
    assert h.mean_estimate(h.empty()) is None
