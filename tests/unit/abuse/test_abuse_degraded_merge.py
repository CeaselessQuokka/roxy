"""C7 degraded mode at its two edges: leaving it never refills an allowance, and a share is never rounded up.

What this is
    Unit tests of `AbusePipeline` over the test's temporary databases, with hot.db writes failing on demand the way
    a write-locked hot.db fails them (`SharedStateUnavailable`; reads keep working, as WAL allows). Two pipelines
    over the same files play two workers of one fleet (`ROXY_WORKERS=2`).

Why it exists
    Review findings mp-1 and mp-2 (plan C6, C7, DESIGN.md 11.9 "C7 degraded mode"):
    - mp-1: memory rows used to be dropped on recovery, so every admit, strike and penalty decided while hot.db
      could not be written was forgotten and the client got its allowance again inside the same window. Now the
      first successful transaction that touches a key merges that key's memory rows into hot.db before it decides,
      and a background task merges the rest.
    - mp-2: `degraded_limit` rounded `limit // workers` up to 1, so a limit smaller than the fleet multiplied. Now
      the share may be 0, which refuses (fail closed) without a strike; and the divisor is the live fleet from the
      heartbeats when it is larger than `ROXY_WORKERS` (both colors during a deploy).

How it works
    `locked_hot(dbs)` swaps `dbs.hot.write` for one that raises, and restores it. Times come from `FakeClock`, so
    every window is exact. The multi-process versions of the same checks (real processes, a real lock) are in
    tests/multiprocess/test_rr_mp_degraded.py.

What to read next
    `roxy/abuse/pipeline.py` (`_degraded_walk`, `_claim`, `merge_pending`, `refresh_fleet_size`),
    `roxy/abuse/limiter.py` (`merge_limiter_row`, `degraded_limit`, `unshared`), `roxy/abuse/throttle.py`
    (`merge_strike_row`, `refuse_unshared`).
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

import pytest
from abuse_support import CLIENT_IP, FakeReq

from roxy.abuse.checks.base import LimitSpec
from roxy.abuse.limiter import LimiterRow
from roxy.abuse.pipeline import AbusePipeline, walk_limiters
from roxy.abuse.verdict import Allow, Refuse
from roxy.core.clock import FakeClock
from roxy.core.reasons import ReasonCode
from roxy.scheduler.heartbeat import HeartbeatReporter, WorkerInfo
from roxy.storage.db import SharedStateUnavailable

LIMIT_10 = {"allowed_requests_per_minute": 10, "throttle_reset_duration": 300, "flood_limit_per_minute": 100_000}


@contextmanager
def locked_hot(dbs: Any) -> Iterator[None]:
    """hot.db refuses every write (another process holds the write lock); reads still work."""
    real_write = dbs.hot.write

    async def locked(*_args: Any, **_kwargs: Any) -> Any:
        raise SharedStateUnavailable("hot", "database is locked")

    dbs.hot.write = locked
    try:
        yield
    finally:
        dbs.hot.write = real_write


async def admitted(pipeline: AbusePipeline, count: int, req: FakeReq | None = None) -> int:
    return sum([isinstance(await pipeline.evaluate(req or FakeReq()), Allow) for _ in range(count)])


def strike_row(dbs: Any, key: str = CLIENT_IP) -> tuple[int, int] | None:
    row = dbs.hot.read_sync(
        lambda conn: conn.execute("SELECT strikes, throttled_until FROM strikes WHERE ip = ?", (key,)).fetchone()
    )
    return None if row is None else (int(row[0]), int(row[1]))


def limiter_row(dbs: Any, key: str) -> tuple[int, int, int] | None:
    row = dbs.hot.read_sync(
        lambda conn: conn.execute(
            "SELECT tat_ms, window_start, count FROM limiter WHERE bucket_key = ?", (key,)
        ).fetchone()
    )
    return None if row is None else (int(row[0]), int(row[1]), int(row[2]))


# --- mp-1: leaving degraded mode -------------------------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["gcra", "fixed"])
async def test_two_degraded_workers_never_admit_more_than_the_limit_in_one_window(
    make_pipeline: Callable[..., AbusePipeline], dbs: Any, fake_clock: FakeClock, mode: str
) -> None:
    """Each worker admits its share (5 of 10) while hot.db is locked; after the lock, nothing more in the window."""
    settings = {**LIMIT_10, "throttle_window_mode": mode}
    worker_a = make_pipeline(settings, workers=2)
    worker_b = make_pipeline(settings, workers=2)
    with locked_hot(dbs):
        during = await admitted(worker_a, 6) + await admitted(worker_b, 6)
    assert during == 10
    assert worker_a.degraded
    assert worker_b.degraded
    fake_clock.advance(1.0)
    after = 0
    for _ in range(5):
        after += await admitted(worker_a, 1) + await admitted(worker_b, 1)
    assert not worker_a.degraded
    assert not worker_b.degraded
    assert after == 0, f"{after} more requests got through in the same window after the outage"
    # The strike and penalty each worker gave the client while degraded reached hot.db.
    strikes = strike_row(dbs)
    assert strikes is not None
    assert strikes[0] >= 1
    assert strikes[1] > fake_clock.now()


async def test_the_first_successful_transaction_merges_the_clients_rows_before_it_decides(
    make_pipeline: Callable[..., AbusePipeline], dbs: Any, fake_clock: FakeClock
) -> None:
    """One worker, a short lock: what it admitted from memory counts in the very next shared decision."""
    pipeline = make_pipeline({**LIMIT_10, "throttle_escalation_enabled": 0}, workers=1)
    assert await admitted(pipeline, 4) == 4
    with locked_hot(dbs):
        assert await admitted(pipeline, 4) == 4  # 1 worker: the share is the whole limit
    assert pipeline.degraded
    assert await admitted(pipeline, 5) == 2  # 4 + 4 counted already: 2 left of 10
    assert pipeline.stats.degraded_merged >= 1
    tat = limiter_row(dbs, CLIENT_IP)
    assert tat is not None
    assert tat[0] - fake_clock.now_ms() == 300_000  # 10 cells of 30 s: the whole window is spent


async def test_a_failed_merge_keeps_the_rows_and_a_later_one_writes_them(
    make_pipeline: Callable[..., AbusePipeline], dbs: Any
) -> None:
    pipeline = make_pipeline(LIMIT_10, workers=2)
    with locked_hot(dbs):
        assert await admitted(pipeline, 3) == 3
    other = FakeReq(client_ip="198.51.100.4", limit_key="198.51.100.4")
    assert await admitted(pipeline, 1, other) == 1  # recovery; the client's rows are not touched by this request
    assert pipeline._merge_task is not None
    with locked_hot(dbs):
        merged = await pipeline._merge_task  # the background merge meets a locked hot.db again
    assert merged == 0
    assert len(pipeline._memory_rows) >= 1  # nothing lost
    assert await pipeline.merge_pending() >= 1
    assert len(pipeline._memory_rows) == 0
    row = limiter_row(dbs, CLIENT_IP)
    assert row is not None  # the 3 degraded admits are in hot.db


async def test_rows_left_from_an_earlier_outage_are_rebased_on_hot_db(
    make_pipeline: Callable[..., AbusePipeline], dbs: Any
) -> None:
    """A second outage before the merge: the old memory row keeps its admits on top of what hot.db has now.

    Fixed windows make the three possible starting points visible: the rebased row (3 + 4 = 7 counted) leaves A's
    share of 5 nothing; A's stale copy alone (3) would leave 2, and hot.db alone (4) would leave 1.
    """
    settings = {**LIMIT_10, "throttle_window_mode": "fixed", "throttle_escalation_enabled": 0}
    worker_a = make_pipeline(settings, workers=2)
    worker_b = make_pipeline(settings, workers=2)
    with locked_hot(dbs):
        assert await admitted(worker_a, 3) == 3  # worker A's memory: 3 of its share of 5
    worker_a._merge_not_before = float("inf")  # keep A's background merge from running (test control)
    worker_a._recovered()  # A saw a write work (another key), but the client's row is not merged yet
    assert await admitted(worker_b, 4) == 4  # worker B, healthy: hot.db now holds 4
    with locked_hot(dbs):
        assert await admitted(worker_a, 3) == 0
    assert worker_a.degraded
    assert await worker_a.merge_pending(even_if_degraded=True) >= 1  # (what aclose does at shutdown)
    row = limiter_row(dbs, CLIENT_IP)
    assert row is not None
    assert row[2] == 7  # hot.db ends with both workers' counts, once each


async def test_aclose_merges_what_a_worker_counted_during_an_outage(
    make_pipeline: Callable[..., AbusePipeline], dbs: Any
) -> None:
    pipeline = make_pipeline(LIMIT_10, workers=2)
    with locked_hot(dbs):
        assert await admitted(pipeline, 2) == 2
    await pipeline.aclose()  # hot.db works again by shutdown time: the rows outlive the worker
    assert len(pipeline._memory_rows) == 0
    assert limiter_row(dbs, CLIENT_IP) is not None


async def test_a_refusal_before_any_limiter_shows_the_merged_trio(
    make_pipeline: Callable[..., AbusePipeline], dbs: Any, fake_clock: FakeClock
) -> None:
    """The header trio of a pause or ban refusal (no limiter ran) counts rows that are not merged yet."""
    pipeline = make_pipeline({**LIMIT_10, "throttle_escalation_enabled": 0}, workers=1)
    with locked_hot(dbs):
        assert await admitted(pipeline, 6) == 6
    pipeline._merge_not_before = float("inf")
    pipeline._recovered()
    facts = pipeline._facts(
        FakeReq(), pipeline._values(), pipeline._rules_snapshot(), fake_clock.now(), fake_clock.now_ms()
    )
    state = await pipeline._peek(facts.per_ip, fake_clock.now_ms())
    assert state.trio[0] == 4  # 6 of 10 spent, though hot.db alone would say 10


# --- mp-2: the share is never rounded up -----------------------------------------------------------------------------


@pytest.mark.parametrize("workers", [2, 4])
async def test_a_limit_below_the_fleet_size_fails_closed_without_a_strike(
    make_pipeline: Callable[..., AbusePipeline], dbs: Any, workers: int
) -> None:
    pipeline = make_pipeline({"allowed_requests_per_minute": 1, "throttle_reset_duration": 60}, workers=workers)
    with locked_hot(dbs):
        verdicts = [await pipeline.evaluate(FakeReq()) for _ in range(3)]
    assert all(isinstance(v, Refuse) for v in verdicts)
    refusal = verdicts[0]
    assert isinstance(refusal, Refuse)
    assert refusal.reason is ReasonCode.THROTTLE
    assert refusal.headers["Retry-After"] == "60"  # the configured pace: 1 request per 60 s
    assert refusal.headers["Roxy-Requests-Left"] == "0"
    assert len(pipeline._memory_strikes) == 0  # Roxy's outage is not the client's fault: no strike, no penalty
    assert pipeline.degraded
    assert pipeline.stats.snapshot()["degraded_requests"] == 3


async def test_with_one_worker_a_limit_of_one_still_admits_while_degraded(
    make_pipeline: Callable[..., AbusePipeline], dbs: Any
) -> None:
    pipeline = make_pipeline({"allowed_requests_per_minute": 1, "throttle_reset_duration": 60}, workers=1)
    with locked_hot(dbs):
        assert await admitted(pipeline, 3) == 1


def test_a_cooldown_has_no_share_when_the_fleet_is_larger_than_one() -> None:
    """A cooldown is one request per period: with 2 or more workers its degraded share is 0 (refused)."""
    spec = LimitSpec("user_agent_rule", "uar:1|x", "cooldown", cooldown_s=2.0)
    shared = walk_limiters([spec], {}, {}, None, 1_000_000)
    assert shared.state.stopped_at is None
    split = walk_limiters([spec], {}, {}, None, 1_000_000, divisor=2)
    assert split.state.stopped_at == "user_agent_rule"
    assert split.limiter_writes == []
    assert split.state.outcomes["user_agent_rule"].retry_after_s == 2


def test_a_global_rule_below_the_fleet_size_refuses_and_counts_nothing() -> None:
    spec = LimitSpec("endpoint_rule", "er:1|global", "fixed", limit=1, window_s=30)
    walk = walk_limiters([spec], {"er:1|global": LimiterRow("er:1|global")}, {}, None, 5_000, divisor=2)
    assert walk.state.stopped_at == "endpoint_rule"
    assert walk.limiter_writes == []
    assert walk.state.outcomes["endpoint_rule"].retry_after_s == 30


async def test_the_divisor_is_the_live_fleet_when_heartbeats_show_more_workers(
    make_pipeline: Callable[..., AbusePipeline], dbs: Any, fake_clock: FakeClock
) -> None:
    """A blue/green deploy runs both colors: 4 live workers with ROXY_WORKERS=2 make the share 10 // 4 = 2."""
    for pid, color in [(101, "blue"), (102, "blue"), (201, "green"), (202, "green")]:
        info = WorkerInfo(worker_id=f"w{pid}", color=color, pid=pid, started_at=int(fake_clock.now()))
        HeartbeatReporter(dbs.metrics, info, fake_clock, rss=lambda: None).beat_sync()
    pipeline = make_pipeline({"allowed_requests_per_minute": 10}, workers=2, metrics_db=dbs.metrics)
    await pipeline.refresh_fleet_size()
    assert pipeline.fleet_size == 4
    with locked_hot(dbs):
        assert await admitted(pipeline, 5) == 2
    fake_clock.advance(60.0)  # every heartbeat is stale now: back to ROXY_WORKERS
    await pipeline.refresh_fleet_size()
    assert pipeline.fleet_size is None
    assert pipeline._divisor() == 2


async def test_the_fleet_size_loop_is_started(make_pipeline: Callable[..., AbusePipeline]) -> None:
    started: list[str] = []

    class Tasks:
        def start(self, name: str, *_args: Any, **_kwargs: Any) -> None:
            started.append(name)

    make_pipeline().start(Tasks())
    assert "abuse_fleet_size" in started
