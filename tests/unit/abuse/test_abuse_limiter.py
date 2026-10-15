"""GCRA, fixed window and cooldown math (plan 10.2), plus the degraded-mode helpers (plan C7)."""

from __future__ import annotations

import pytest

from roxy.abuse.limiter import (
    DegradedEntry,
    LimiterRow,
    MemoryRowStore,
    cooldown,
    degraded_limit,
    fixed,
    fixed_peek,
    gcra,
    gcra_peek,
    merge_limiter_row,
    unshared,
)

T0 = 1_760_000_000_000  # milliseconds


def run_gcra(times_ms: list[int], limit: int, window_s: float) -> list[bool]:
    row = LimiterRow("k")
    admitted = []
    for now in times_ms:
        decision = gcra(row, limit, window_s, now)
        admitted.append(decision.admitted)
        if decision.admitted:
            row = decision.row
    return admitted


def test_fresh_client_gets_limit_minus_one_after_first_request() -> None:
    decision = gcra(LimiterRow("k"), 10, 50, T0)
    assert decision.admitted
    assert decision.remaining == 9  # plan 10.2 example
    assert decision.reset_s == 5
    assert decision.retry_after_s == 0


def test_gcra_burst() -> None:
    """Plan 10.2: a fresh client may send L at once; request L + 1 of the burst is refused."""
    results = run_gcra([T0] * 11, 10, 50)
    assert results == [True] * 10 + [False]


def test_gcra_burst_refusal_headers() -> None:
    row = LimiterRow("k")
    for _ in range(10):
        row = gcra(row, 10, 50, T0).row
    refused = gcra(row, 10, 50, T0)
    assert not refused.admitted
    assert refused.remaining == 0
    assert refused.retry_after_s == 5  # one interval until one more request fits
    assert refused.reset_s == 50  # the full allowance is back after W
    assert refused.row == row  # a refusal does not move TAT


@pytest.mark.parametrize(("limit", "window_s"), [(10, 50), (7, 60), (1, 5), (3, 7), (100, 60)])
def test_gcra_exact_rate_for_ten_minutes_is_never_refused(limit: int, window_s: float) -> None:
    interval_ms = window_s * 1000 / limit
    count = int(600_000 / interval_ms) + 1
    times = [T0 + round(i * interval_ms) for i in range(count)]
    assert all(run_gcra(times, limit, window_s))


def test_gcra_slightly_faster_than_the_rate_is_eventually_refused() -> None:
    times = [T0 + i * 3000 for i in range(200)]  # 600 s at one request every 3 s, the limit allows one per 5 s
    results = run_gcra(times, 10, 50)
    assert False in results
    assert sum(results) <= 10 + 600 // 5 + 1  # the burst plus one per interval, never more


def test_gcra_survives_a_clock_step_back() -> None:
    row = gcra(LimiterRow("k"), 10, 50, T0).row
    stepped = gcra(row, 10, 50, T0 - 900)  # WSL steps the wall clock back about 0.9 s
    assert stepped.admitted
    assert stepped.row.tat_ms == T0 + 10_000


def test_gcra_peek() -> None:
    assert gcra_peek(LimiterRow("k"), 10, 50, T0) == (10, 0)
    row = gcra(LimiterRow("k"), 10, 50, T0).row
    assert gcra_peek(row, 10, 50, T0) == (9, 5)
    assert gcra_peek(row, 10, 50, T0 + 5000) == (10, 0)


def test_fixed_window_v1_semantics() -> None:
    row = LimiterRow("k")
    results = []
    for _ in range(4):
        decision = fixed(row, 3, 50, T0)
        results.append(decision.admitted)
        if decision.admitted:
            row = decision.row
    assert results == [True, True, True, False]  # atomic: exactly the limit, no limit + 1
    refused = fixed(row, 3, 50, T0 + 1500)
    assert refused.retry_after_s == 49  # ceil(48.5)
    assert refused.reset_s == 48  # floor, as v1 reported Roxy-Throttle-Reset
    assert fixed_peek(row, 3, T0 + 1500) == (0, 48)
    # v1: a new window starts only when now > end (strict).
    assert not fixed(row, 3, 50, T0 + 50_000).admitted
    fresh = fixed(row, 3, 50, T0 + 50_001)
    assert fresh.admitted
    assert fresh.remaining == 2


def test_fixed_row_keeps_the_window_end_in_tat_ms_for_retention() -> None:
    decision = fixed(LimiterRow("k"), 3, 50, T0)
    assert decision.row.tat_ms == T0 + 50_000
    assert decision.row.window_start == T0


def test_cooldown_does_not_move_the_clock_on_refusal() -> None:
    first = cooldown(LimiterRow("k"), 2.0, T0)
    assert first.admitted
    early = cooldown(first.row, 2.0, T0 + 500)
    assert not early.admitted
    assert early.retry_after_s == 2  # ceil(1.5), v1 bug B12 fixed
    assert early.row == first.row
    assert cooldown(early.row, 2.0, T0 + 2000).admitted


def test_cooldown_retry_uses_a_true_ceiling() -> None:
    first = cooldown(LimiterRow("k"), 2.0, T0)
    assert cooldown(first.row, 2.0, T0 + 999).retry_after_s == 2
    assert cooldown(first.row, 2.0, T0 + 1000).retry_after_s == 1


def test_degraded_limit_is_limit_floor_divided_by_workers() -> None:
    """C6 and C7 (finding mp-2): the shares of all workers add up to at most the limit, so a share may be 0."""
    assert degraded_limit(10, 2) == 5
    assert degraded_limit(10, 4) == 2
    assert degraded_limit(3, 2) == 1
    assert degraded_limit(1, 2) == 0  # a limit smaller than the fleet: this worker refuses (fail closed)
    assert degraded_limit(1, 4) == 0
    assert degraded_limit(10, 0) == 10
    for limit in range(1, 12):
        for workers in (1, 2, 3, 4, 8):
            assert degraded_limit(limit, workers) * workers <= limit


def test_unshared_refuses_without_counting_and_names_the_configured_pace() -> None:
    row = LimiterRow("k", tat_ms=T0, exists=True)
    decision = unshared(row, 1, 60)
    assert not decision.admitted
    assert decision.row is row  # nothing counted
    assert (decision.retry_after_s, decision.reset_s, decision.remaining) == (60, 60, 0)
    assert unshared(row, 10, 50).retry_after_s == 5
    assert unshared(row, 7, 60).retry_after_s == 9  # a true ceiling, at least 1
    assert unshared(row, 1000, 1).retry_after_s == 1


# --- merging degraded rows back into hot.db (finding mp-1) -----------------------------------------------------------


def test_degraded_gcra_merge_keeps_the_later_tat() -> None:
    seed = LimiterRow("k", tat_ms=T0 + 1_000, exists=True)
    memory = LimiterRow("k", tat_ms=T0 + 300_000, exists=True)
    entry = DegradedEntry(memory, seed, "gcra")
    assert entry.changed
    assert merge_limiter_row(LimiterRow("k"), entry, T0).tat_ms == T0 + 300_000  # hot.db lost the row: memory
    assert merge_limiter_row(seed, entry, T0).tat_ms == T0 + 300_000
    later = LimiterRow("k", tat_ms=T0 + 400_000, exists=True)
    assert merge_limiter_row(later, entry, T0) == later  # hot.db moved further: nothing to add
    unchanged = DegradedEntry(seed, seed, "gcra")
    assert not unchanged.changed


def test_degraded_gcra_merge_never_admits_more_than_the_fleet_limit() -> None:
    """Two workers each spend their share (5 of 10 per 300 s) from the same seed; after both merges the shared
    row admits nothing more until the pace allows it, exactly like one shared row that saw all 10."""
    limit, window = 10, 300
    seed = LimiterRow("k")
    shared = seed
    for _ in range(2):  # two workers, each on its own memory row at the degraded share
        row = seed
        for _ in range(degraded_limit(limit, 2)):
            decision = gcra(row, degraded_limit(limit, 2), window, T0)
            assert decision.admitted
            row = decision.row
        assert not gcra(row, degraded_limit(limit, 2), window, T0).admitted
        shared = merge_limiter_row(shared, DegradedEntry(row, seed, "gcra"), T0)
    assert not gcra(shared, limit, window, T0).admitted
    one_row = seed
    for _ in range(limit):
        one_row = gcra(one_row, limit, window, T0).row
    assert shared.tat_ms >= one_row.tat_ms


def test_degraded_fixed_merge_adds_what_each_worker_counted() -> None:
    end = T0 + 60_000
    seed = LimiterRow("k", window_start=T0, count=3, tat_ms=end, exists=True)
    worker_a = DegradedEntry(LimiterRow("k", window_start=T0, count=5, tat_ms=end, exists=True), seed, "fixed")
    worker_b = DegradedEntry(LimiterRow("k", window_start=T0, count=4, tat_ms=end, exists=True), seed, "fixed")
    shared = merge_limiter_row(seed, worker_a, T0 + 1_000)
    shared = merge_limiter_row(shared, worker_b, T0 + 1_000)
    assert (shared.count, shared.window_start, shared.tat_ms) == (3 + 2 + 1, T0, end)
    # A window that is over counts nothing any more.
    assert merge_limiter_row(seed, worker_a, end + 1) == seed
    # No running shared window: the worker's own window (started in degraded mode) is the whole story.
    fresh = DegradedEntry(LimiterRow("k", window_start=T0, count=2, tat_ms=end, exists=True), LimiterRow("k"), "fixed")
    assert merge_limiter_row(LimiterRow("k"), fresh, T0) == fresh.row
    # Two different running windows: the counts add up over the longer window.
    other = LimiterRow("k", window_start=T0 - 30_000, count=4, tat_ms=T0 + 30_000, exists=True)
    merged = merge_limiter_row(other, fresh, T0)
    assert (merged.count, merged.window_start, merged.tat_ms) == (6, T0, end)


def test_degraded_cooldown_merge_keeps_the_latest_request() -> None:
    first = cooldown(LimiterRow("k"), 2.0, T0).row
    later = cooldown(LimiterRow("k"), 2.0, T0 + 5_000).row
    merged = merge_limiter_row(first, DegradedEntry(later, LimiterRow("k"), "cooldown"), T0 + 5_000)
    assert (merged.window_start, merged.tat_ms) == (later.window_start, later.tat_ms)
    assert not cooldown(merged, 2.0, T0 + 5_500).admitted


def test_memory_row_store_discard_and_items() -> None:
    store: MemoryRowStore[list[int]] = MemoryRowStore(max_rows=4)
    first, second = [1], [2]
    store.put("a", first)
    store.put("b", second)
    assert store.items() == [("a", first), ("b", second)]
    store.discard("a", [1])  # an equal but different object: kept
    assert store.get("a") is first
    store.put("b", [3])
    store.discard("b", second)  # replaced meanwhile: the newer row is kept
    assert store.get("b") == [3]
    store.discard("a", first)
    assert store.get("a") is None
    assert len(store) == 1


def test_memory_row_store_is_bounded_lru() -> None:
    store: MemoryRowStore[int] = MemoryRowStore(max_rows=3)
    for i in range(3):
        store.put(f"k{i}", i)
    assert store.get("k0") == 0  # touch k0, so k1 is the oldest
    store.put("k3", 3)
    assert len(store) == 3
    assert store.get("k1") is None
    assert store.get("k0") == 0
