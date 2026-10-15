"""Live tail: the row fields (row 126), the per-worker ring, filters, rate gate, and the events-table tail (14.11)."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

from roxy.core.clock import FakeClock
from roxy.core.reasons import CacheState, Outcome, ReasonCode
from roxy.metrics.live import (
    LIVE_EVENT,
    EventTail,
    LiveFilter,
    LiveRing,
    RateGate,
    live_entry,
    prune_live_events,
)
from roxy.metrics.recorder import EventRecord, MetricsRecorder, OutcomeEvent, write_events

ROW_126 = (
    "outcome",
    "reason",
    "upstream_status",
    "egress",
    "attempts",
    "retries",
    "duration_ms",
    "bypass",
    "capture_id",
    "cache",
    "cache_age_s",
    "request_id",
    "queue_wait_ms",
    "place",
)


def test_live_entry_has_every_row_126_field(make_event: Callable[..., OutcomeEvent]) -> None:
    ev = make_event(
        upstream_status=200,
        attempts=2,
        retries=1,
        cache_age_s=None,
        bypass=True,
        path="a/b",
        upstream_error="Timeout after 10.0s",
        user_agent="x" * 1000,
    )
    entry = live_entry(ev, "CAP1")
    for field in ROW_126:
        assert field in entry, field
    assert entry["capture_id"] == "CAP1"
    assert entry["cache"] == "MISS"
    assert entry["attempts"] == 2
    assert len(entry["user_agent"]) == 400
    assert live_entry(make_event(cache_state=CacheState.NA))["cache"] == "n/a"


def test_ring_is_bounded_newest_first_and_resizable() -> None:
    ring = LiveRing(3)
    for i in range(5):
        ring.append({"i": i, "outcome": "refused" if i % 2 else "served_upstream"})
    assert [e["i"] for e in ring.snapshot()] == [4, 3, 2]
    assert [e["i"] for e in ring.snapshot(LiveFilter(outcomes=frozenset({"refused"})))] == [3]
    ring.resize(1)
    assert [e["i"] for e in ring.snapshot()] == [4]
    ring.resize(0)
    ring.append({"i": 9})
    assert len(ring) == 0


def test_filter_covers_every_field(make_event: Callable[..., OutcomeEvent]) -> None:
    entry = live_entry(
        make_event(
            outcome=Outcome.REFUSED,
            reason=ReasonCode.USER_AGENT_RULE,
            status=429,
            path="games.roblox.com/v1/games/9/votes",
        )
    )
    assert LiveFilter(reasons=frozenset({"user_agent_rule"})).matches(entry)
    assert LiveFilter(reasons=frozenset({"ignored_path"})).matches(entry) is False
    assert LiveFilter(statuses=frozenset({429})).matches(entry)
    assert LiveFilter(egress=frozenset({"rotator"})).matches(entry) is False
    assert LiveFilter(cache=frozenset({"MISS"})).matches(entry)
    assert LiveFilter(client="12345").matches(entry)  # place id
    assert LiveFilter(client="203.0.113.5").matches(entry)
    assert LiveFilter(endpoint="{gameId}").matches(entry)
    assert LiveFilter(text="roblox/wininet").matches(entry)
    assert LiveFilter(text="nothing like it").matches(entry) is False


def test_rate_gate_tolerates_a_clock_stepping_back() -> None:
    now = [100.0]
    gate = RateGate(rate=1.0, burst=2.0, clock=lambda: now[0])
    assert [gate.allow(), gate.allow(), gate.allow()] == [True, True, False]
    now[0] = 99.0  # WSL steps the clock back about a second now and then
    assert gate.allow() is False
    now[0] = 101.5
    assert gate.allow() is True


def _event(i: int, event_type: str = LIVE_EVENT, at_ms: int = 1_760_000_000_000) -> EventRecord:
    return EventRecord(at_ms, event_type, "info", "upstream_ok", None, None, "t", {"i": i, "outcome": "refused"})


async def test_tail_delivers_rows_from_any_writer(dbs: Any) -> None:
    tail = EventTail(dbs.metrics, poll_s=0.01)
    sub_all = tail.subscribe()
    sub_bans = tail.subscribe(types=["ban"])
    sub_filtered = tail.subscribe(types=[LIVE_EVENT], live_filter=LiveFilter(outcomes=frozenset({"served_upstream"})))
    dbs.metrics.write_sync(lambda c: write_events(c, [_event(0)]))  # before the tail starts: not replayed
    assert await tail.poll_once() == 0
    dbs.metrics.write_sync(lambda c: write_events(c, [_event(1), _event(2, "ban")]))
    assert await tail.poll_once() == 2
    got = [sub_all.queue.get_nowait().detail["i"] for _ in range(sub_all.queue.qsize())]
    assert got == [1, 2]
    assert sub_bans.queue.qsize() == 1
    assert sub_filtered.queue.qsize() == 0
    tail.unsubscribe(sub_all)
    assert tail.subscribers == 2


async def test_slow_subscriber_loses_oldest_and_counts(dbs: Any) -> None:
    tail = EventTail(dbs.metrics, batch=5000)
    sub = tail.subscribe()
    sub.queue = asyncio.Queue(3)
    await tail.poll_once()
    dbs.metrics.write_sync(lambda c: write_events(c, [_event(i) for i in range(10)]))
    await tail.poll_once()
    assert sub.lost == 7
    assert [sub.queue.get_nowait().detail["i"] for _ in range(3)] == [7, 8, 9]


async def test_backfill_for_last_event_id(dbs: Any) -> None:
    tail = EventTail(dbs.metrics)
    await tail.poll_once()
    dbs.metrics.write_sync(lambda c: write_events(c, [_event(i) for i in range(4)]))
    await tail.poll_once()
    ids = list(range(1, 5))
    sub = tail.subscribe()
    sent = await tail.backfill(sub, after_id=ids[1])
    assert sent == 2
    assert [sub.queue.get_nowait().id for _ in range(2)] == ids[2:]


async def test_tail_run_stops(dbs: Any) -> None:
    tail = EventTail(dbs.metrics, poll_s=0.01)
    stop = asyncio.Event()
    task = asyncio.create_task(tail.run(stop))
    await asyncio.sleep(0.05)
    stop.set()
    await asyncio.wait_for(task, 2)
    assert tail.polls >= 1


def test_live_rows_are_pruned_after_fifteen_minutes(dbs: Any) -> None:
    old = 1_760_000_000_000
    dbs.metrics.write_sync(
        lambda c: write_events(c, [_event(1, at_ms=old), _event(2, "ban", at_ms=old), _event(3, at_ms=old + 1_000_000)])
    )
    deleted = dbs.metrics.write_sync(lambda c: prune_live_events(c, old / 1000 + 901))
    assert deleted == 1
    left = dbs.metrics.read_sync(lambda c: sorted(r[0] for r in c.execute("SELECT type FROM events")))
    assert left == ["ban", "live"]


async def test_recorder_samples_live_rows_above_the_rate(
    recorder: MetricsRecorder, make_event: Callable[..., OutcomeEvent], fake_clock: FakeClock
) -> None:
    for _ in range(80):
        recorder.record_outcome(make_event())
    assert recorder.live_sampled_out == 30  # 50 per second per worker, then sampled (plan 14.11)
    assert len(recorder.live) == 80  # the ring still has every request
