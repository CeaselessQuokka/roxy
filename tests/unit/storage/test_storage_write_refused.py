"""A write function's deliberate refusal is not a database write error (gap G10).

What this is
    `storage.db.WriteRefused` and its one subclass, `scheduler.leader.LostLeadership`: raised inside a write, the
    transaction is rolled back and the caller gets the exception, and `DbStats.refused` counts it, not
    `write_errors`. A fenced leader write that finds the lease moved is the case that made the System page say
    "Writing failed recently" right after startup (`tests/integration/pages/test_page_system.py
    test_an_empty_history_explains_itself` failed alone 5 of 5 runs).

What to read next
    `roxy/storage/db.py` (`_count_error`), `roxy/scheduler/leader.py` (`JobContext.fenced_write`).
"""

from __future__ import annotations

import sqlite3
from typing import Any

import pytest

from roxy.core.clock import FakeClock
from roxy.scheduler.leader import LeaderElector, LostLeadership
from roxy.storage.db import WriteRefused


def _insert_then(error: BaseException) -> Any:
    def write(conn: sqlite3.Connection) -> None:
        conn.execute("INSERT INTO annotations (at, kind, label) VALUES (1, 'config_change', 'x')")
        raise error

    return write


async def test_a_refusal_rolls_back_and_counts_as_refused(dbs: Any) -> None:
    metrics = dbs.metrics
    before = (metrics.stats.write_errors, metrics.stats.refused)
    with pytest.raises(WriteRefused):
        await metrics.write(_insert_then(WriteRefused("precondition false")))
    with pytest.raises(LostLeadership):
        await metrics.write(_insert_then(LostLeadership("lease moved")))
    assert (metrics.stats.write_errors, metrics.stats.refused) == (before[0], before[1] + 2)
    count = metrics.read_sync(lambda conn: conn.execute("SELECT count(*) FROM annotations").fetchone()[0])
    assert count == 0  # rolled back
    with pytest.raises(ValueError, match="a bug"):
        await metrics.write(_insert_then(ValueError("a bug")))
    assert metrics.stats.write_errors == before[0] + 1  # anything else is still a write error


async def test_a_fenced_write_after_the_lease_moved_is_refused_not_failed(dbs: Any, fake_clock: FakeClock) -> None:
    leader = LeaderElector(dbs.hot, "worker-a", fake_clock)
    await leader.tick()
    assert leader.is_leader
    ctx = leader.job_context("fingerprint_auto_ignore")
    fake_clock.advance(16)  # worker-a stalled past its lease; worker-b takes over
    other = LeaderElector(dbs.hot, "worker-b", fake_clock)
    await other.tick()
    assert other.is_leader
    errors = dbs.metrics.stats.write_errors
    with pytest.raises(LostLeadership):
        await ctx.fenced_write(dbs.metrics, lambda conn: conn.execute("DELETE FROM fingerprint_values"))
    assert dbs.metrics.stats.write_errors == errors
    assert dbs.metrics.stats.refused >= 1
