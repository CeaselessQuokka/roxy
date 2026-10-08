"""Unit tests for roxy.scheduler.leader (election, renewal, takeover, fencing, idempotency keys)."""

from __future__ import annotations

import asyncio
import sqlite3
from typing import Any

import pytest

from roxy.core.clock import FakeClock
from roxy.scheduler.leader import JobContext, LeaderElector, LeaderState, LostLeadership
from roxy.storage import leases
from roxy.storage.db import SharedStateUnavailable


def _insert_hot(conn: sqlite3.Connection, tag: str) -> None:
    conn.execute("INSERT INTO email_gate (key, last_sent_at) VALUES (?, 0)", (tag,))


def _insert_metrics(conn: sqlite3.Connection, tag: str) -> None:
    conn.execute("INSERT INTO legacy_totals (key, value_json) VALUES (?, '1')", (tag,))


async def test_first_worker_leads_and_others_follow(dbs, fake_clock: FakeClock) -> None:
    a = LeaderElector(dbs.hot, "a", fake_clock)
    b = LeaderElector(dbs.hot, "b", fake_clock)
    assert await a.tick() == 5.0
    assert a.is_leader
    assert a.state.epoch == 1
    wait = await b.tick()
    assert not b.is_leader
    assert 0.05 <= wait <= 5.0
    fake_clock.advance(5)
    assert await a.tick() == 5.0  # renewed
    fake_clock.advance(14)
    await b.tick()
    assert not b.is_leader  # the renewal moved the expiry, so 19 s after the first grant b still follows


async def test_takeover_after_the_leader_stops_renewing(dbs, fake_clock: FakeClock) -> None:
    a = LeaderElector(dbs.hot, "a", fake_clock)
    b = LeaderElector(dbs.hot, "b", fake_clock)
    await a.tick()
    fake_clock.advance(14.9)
    await b.tick()
    assert not b.is_leader
    fake_clock.advance(0.2)  # 15.1 s after the last renewal: expired
    await b.tick()
    assert b.is_leader
    assert b.state.epoch == 2
    # a resumes after its stall: its renewal is refused and it steps down.
    await a.tick()
    assert not a.is_leader
    assert dbs.hot.read_sync(lambda c: leases.holder_epoch(c, "leader"))[:2] == ("b", 2)


async def test_follower_wakes_up_right_after_expiry(dbs, fake_clock: FakeClock) -> None:
    a = LeaderElector(dbs.hot, "a", fake_clock)
    b = LeaderElector(dbs.hot, "b", fake_clock, jitter_s=0.0)
    await a.tick()
    fake_clock.advance(12)
    wait = await b.tick()
    assert wait == pytest.approx(3.0, abs=0.01)  # sleeps exactly until the lease would expire


async def test_stalled_leader_cannot_write_after_takeover(dbs, fake_clock: FakeClock) -> None:
    a = LeaderElector(dbs.hot, "a", fake_clock)
    b = LeaderElector(dbs.hot, "b", fake_clock)
    await a.tick()
    ctx_a = a.job_context("rollups")
    await ctx_a.fenced_write(dbs.hot, lambda c: _insert_hot(c, "a-before"))
    await ctx_a.fenced_write(dbs.metrics, lambda c: _insert_metrics(c, "a-before"))
    fake_clock.advance(16)  # a stalls past its lease
    await b.tick()
    assert b.is_leader
    # a still believes it leads (it has not ticked), but every fenced write is refused and rolled back.
    assert a.is_leader
    with pytest.raises(LostLeadership):
        await ctx_a.fenced_write(dbs.hot, lambda c: _insert_hot(c, "a-after"))
    with pytest.raises(LostLeadership):
        await ctx_a.fenced_write(dbs.metrics, lambda c: _insert_metrics(c, "a-after"))
    with pytest.raises(LostLeadership):
        await ctx_a.check()
    hot_keys = dbs.hot.read_sync(lambda c: [r[0] for r in c.execute("SELECT key FROM email_gate")])
    metric_keys = dbs.metrics.read_sync(lambda c: [r[0] for r in c.execute("SELECT key FROM legacy_totals")])
    assert hot_keys == ["a-before"]
    assert metric_keys == ["a-before"]
    ctx_b = b.job_context("rollups")
    await ctx_b.fenced_write(dbs.metrics, lambda c: _insert_metrics(c, "b"))
    assert ctx_b.epoch == ctx_a.epoch + 1


async def test_fencing_also_catches_a_takeover_during_the_job(dbs, fake_clock: FakeClock) -> None:
    a = LeaderElector(dbs.hot, "a", fake_clock)
    await a.tick()
    ctx = a.job_context("j")

    def takeover_then_write(conn: sqlite3.Connection) -> None:
        _insert_metrics(conn, "during")

        # Another worker takes the lease while this job's metrics transaction is still open.
        def steal(hot: sqlite3.Connection) -> None:
            hot.execute("UPDATE lease SET holder = 'z', epoch = epoch + 1 WHERE name = 'leader'")

        dbs.hot.write_sync(steal)

    with pytest.raises(LostLeadership):
        await ctx.fenced_write(dbs.metrics, takeover_then_write)
    assert dbs.metrics.read_sync(lambda c: c.execute("SELECT count(*) FROM legacy_totals").fetchone()[0]) == 0


async def test_fenced_write_outside_hot_needs_a_lease_margin(dbs, fake_clock: FakeClock) -> None:
    """MP review F3: a check outside a hot.db transaction can be overtaken, so it needs lease time in hand."""
    a = LeaderElector(dbs.hot, "a", fake_clock)
    await a.tick()  # lease until 15 s
    ctx = a.job_context("retention")
    fake_clock.advance(11)  # two renewals missed: 4 s left, below the 5 s margin
    with pytest.raises(LostLeadership, match="margin"):
        await ctx.fenced_write(dbs.metrics, lambda c: _insert_metrics(c, "late"))
    assert ctx.fence_margin_ms == 5000
    assert dbs.metrics.read_sync(lambda c: c.execute("SELECT count(*) FROM legacy_totals").fetchone()[0]) == 0
    # On hot.db the check shares the transaction (and its lock) with the write, so no margin is needed.
    await ctx.fenced_write(dbs.hot, lambda c: _insert_hot(c, "hot-ok"))
    await a.tick()  # renewed: 15 s left again
    await ctx.fenced_write(dbs.metrics, lambda c: _insert_metrics(c, "renewed"))
    assert dbs.metrics.read_sync(lambda c: [r[0] for r in c.execute("SELECT key FROM legacy_totals")]) == ["renewed"]


async def test_job_context_requires_leadership(dbs, fake_clock: FakeClock) -> None:
    a = LeaderElector(dbs.hot, "a", fake_clock)
    with pytest.raises(LostLeadership):
        a.job_context("x")
    per_worker = JobContext(epoch=0, now=fake_clock.now(), holder="a", job_name="flush")
    with pytest.raises(LostLeadership):
        await per_worker.check()


async def test_idempotency_keys(dbs, fake_clock: FakeClock) -> None:
    a = LeaderElector(dbs.hot, "a", fake_clock)
    await a.tick()
    ctx = a.job_context("digest")
    assert ctx.idem_key(42) == "job:digest:42"
    assert await ctx.claim(42)
    assert not await ctx.claim(42)
    await ctx.finish(42)
    row = dbs.hot.read_sync(
        lambda c: tuple(
            c.execute("SELECT epoch, started_at, finished_at FROM job_runs WHERE idem_key = 'job:digest:42'").fetchone()
        )
    )
    assert row[0] == 1
    assert row[2] is not None
    # An unfinished claim from a crashed run can be retried after a while, if the job asks for it.
    assert await ctx.claim(43)
    fake_clock.advance(120)
    await a.tick()  # the lease expired meanwhile: a takes it again under a new epoch
    later = a.job_context("digest")
    assert not await later.claim(43)
    assert await later.claim(43, retry_unfinished_after_s=60)


async def test_claim_is_fenced(dbs, fake_clock: FakeClock) -> None:
    a = LeaderElector(dbs.hot, "a", fake_clock)
    b = LeaderElector(dbs.hot, "b", fake_clock)
    await a.tick()
    ctx_a = a.job_context("alert")
    fake_clock.advance(16)
    await b.tick()
    with pytest.raises(LostLeadership):
        await ctx_a.claim(1)
    assert await b.job_context("alert").claim(1)


async def test_release_lets_another_worker_lead(dbs, fake_clock: FakeClock) -> None:
    events: list[tuple[str, str, int]] = []

    def record(event: str, state: LeaderState) -> None:
        events.append((event, state.holder, state.epoch))

    a = LeaderElector(dbs.hot, "a", fake_clock, on_change=record)
    b = LeaderElector(dbs.hot, "b", fake_clock, on_change=record)
    await a.tick()
    await a.release()
    assert not a.is_leader
    await b.tick()
    assert b.is_leader
    assert b.state.epoch == 2
    assert events == [("acquired", "a", 1), ("released", "a", 1), ("acquired", "b", 2)]


async def test_async_callback_and_callback_errors_are_contained(dbs, fake_clock: FakeClock) -> None:
    seen: list[str] = []

    async def record(event: str, state: LeaderState) -> None:
        seen.append(event)
        raise RuntimeError("callback bug")

    a = LeaderElector(dbs.hot, "a", fake_clock, on_change=record)
    await a.tick()
    assert a.is_leader
    assert seen == ["acquired"]


class _FlakyHot:
    """A hot database stand-in whose writes fail with SharedStateUnavailable when told to."""

    def __init__(self, real: Any) -> None:
        self.real = real
        self.path = real.path
        self.fail = False

    async def write(self, fn: Any, *, immediate: bool = True) -> Any:
        if self.fail:
            raise SharedStateUnavailable("hot", "database is locked")
        return await self.real.write(fn, immediate=immediate)


async def test_unavailable_hot_db_steps_down_before_the_lease_expires(dbs, fake_clock: FakeClock) -> None:
    hot = _FlakyHot(dbs.hot)
    a = LeaderElector(hot, "a", fake_clock)  # type: ignore[arg-type]
    await a.tick()
    hot.fail = True
    fake_clock.advance(5)
    assert await a.tick() == 1.0
    assert a.is_leader  # the lease is surely valid for 10 more seconds
    fake_clock.advance(5.5)
    await a.tick()
    assert not a.is_leader  # cannot confirm it any more: step down before it could expire
    assert a.state.last_error is not None


async def test_run_loop_and_release_on_stop(dbs) -> None:
    a = LeaderElector(dbs.hot, "a", ttl_s=2.0, renew_s=0.5)
    stop = asyncio.Event()
    task = asyncio.create_task(a.run(stop))
    for _ in range(100):
        if a.is_leader:
            break
        await asyncio.sleep(0.01)
    assert a.is_leader
    stop.set()
    await asyncio.wait_for(task, 5)
    assert not a.is_leader
    assert dbs.hot.read_sync(lambda c: leases.holder_epoch(c, "leader"))[2] == 0  # released


def test_renew_interval_must_leave_room() -> None:
    with pytest.raises(ValueError):
        LeaderElector(None, "a", ttl_s=15, renew_s=10)  # type: ignore[arg-type]
