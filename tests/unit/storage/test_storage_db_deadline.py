"""Unit tests for the hot-path write budget of `roxy.storage.db`: a deadline measured from enqueue time (HOT-HOL).

What this is
    Tests of `Database.write(..., busy_timeout_ms=...)` while another connection holds the write lock or a long job
    holds the writer thread: how long each caller waits, whether a job that ran out of time ever runs, and that a
    caller is never told "unavailable" about a write that commits.

Why it exists
    Finding HOT-HOL (multi-process review): a short budget used to be spent per job on the single writer thread,
    so N concurrent hot-path writes waited about N x the budget before the C7 fallback answered. The budget is now a
    deadline from the moment the job is queued (plan C7: degrade promptly), for every database.

How it works
    Real SQLite files in a temporary directory; a second plain `sqlite3` connection takes `BEGIN IMMEDIATE` the way
    another process would; time is measured with `time.monotonic()` and bounds are several times wider than a
    correct implementation needs.

What to read next
    `roxy/storage/db.py` (module docstring, the busy circuit and the budget), `tests/unit/storage/test_storage_db.py`.
"""

from __future__ import annotations

import asyncio
import sqlite3
import threading
import time
from pathlib import Path

import pytest

from roxy.storage.db import Database, SharedStateUnavailable


def _scratch(db: Database) -> None:
    db.write_sync(lambda c: c.execute("CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY, v TEXT)"))


def _count(db: Database) -> int:
    return int(db.read_sync(lambda c: c.execute("SELECT count(*) FROM t").fetchone()[0]))


async def test_budgeted_writes_queued_behind_each_other_finish_within_their_budget(tmp_path: Path) -> None:
    """Eight hot-path writes queued at once while another process holds the lock: each answers within about one
    budget, not 8 x 0.3 s, and none of them commits later."""
    db = Database("hot", tmp_path / "hot.db")
    _scratch(db)
    blocker = sqlite3.connect(str(db.path), isolation_level=None)
    blocker.execute("BEGIN IMMEDIATE")

    async def timed(index: int) -> float:
        def insert(conn: sqlite3.Connection) -> None:
            conn.execute("INSERT INTO t (v) VALUES (?)", (str(index),))

        started = time.monotonic()
        with pytest.raises(SharedStateUnavailable):
            await db.write(insert, busy_timeout_ms=300)
        return time.monotonic() - started

    try:
        waits = await asyncio.gather(*(timed(i) for i in range(8)))
        assert max(waits) < 0.9, waits  # the old behavior: about 2.4 s for the last one
        assert db.stats.deadline_failures >= 6
        assert db.stats.fast_failures == 0  # a short budget still never opens the busy circuit
    finally:
        blocker.execute("ROLLBACK")
        blocker.close()
    await asyncio.sleep(0.2)
    await db.write(lambda c: None)  # the writer thread drained every canceled job
    assert _count(db) == 0  # nothing was written after its caller was told "unavailable"
    await db.close()


async def test_budgeted_write_behind_a_long_job_gives_up_at_its_deadline_and_never_runs(tmp_path: Path) -> None:
    """Head of line blocking inside one process: a 1 s job holds the writer thread; a 200 ms hot-path write queued
    behind it answers at its deadline, and its function never runs."""
    db = Database("hot", tmp_path / "hot.db")
    _scratch(db)
    release = threading.Event()
    ran: list[str] = []

    def long_job(conn: sqlite3.Connection) -> None:
        release.wait(5)

    long_task = asyncio.create_task(db.write(long_job))
    await asyncio.sleep(0.05)  # the long job is running on the writer thread
    started = time.monotonic()
    with pytest.raises(SharedStateUnavailable):
        await db.write(lambda c: ran.append("hot"), busy_timeout_ms=200)
    waited = time.monotonic() - started
    release.set()
    await long_task
    await db.write(lambda c: None)
    assert waited < 0.7, waited
    assert ran == []  # canceled before it started: it never runs
    await db.close()


async def test_a_budgeted_write_that_started_is_never_reported_unavailable(tmp_path: Path) -> None:
    """A job already running when its deadline passes finishes (its busy timeout is what was left of the budget),
    and the caller gets its result: "unavailable" only ever means "did not happen"."""
    db = Database("hot", tmp_path / "hot.db")
    _scratch(db)

    def slow_insert(conn: sqlite3.Connection) -> str:
        conn.execute("INSERT INTO t (v) VALUES ('slow')")
        time.sleep(0.4)  # longer than the budget, but the job is already running
        return "committed"

    assert await db.write(slow_insert, busy_timeout_ms=100) == "committed"
    assert _count(db) == 1
    await db.close()


async def test_a_canceled_budgeted_caller_never_runs_its_job(tmp_path: Path) -> None:
    db = Database("hot", tmp_path / "hot.db")
    _scratch(db)
    release = threading.Event()
    ran: list[str] = []
    long_task = asyncio.create_task(db.write(lambda c: release.wait(5)))
    await asyncio.sleep(0.05)
    waiter = asyncio.create_task(db.write(lambda c: ran.append("x"), busy_timeout_ms=2000))
    await asyncio.sleep(0.05)
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    release.set()
    await long_task
    await db.write(lambda c: None)
    assert ran == []
    await db.close()


async def test_writes_without_a_budget_still_wait_their_turn(tmp_path: Path) -> None:
    """Only `busy_timeout_ms` callers have a deadline: an ordinary write queued behind a long job simply runs."""
    db = Database("hot", tmp_path / "hot.db")
    _scratch(db)
    release = threading.Event()
    long_task = asyncio.create_task(db.write(lambda c: release.wait(5)))
    await asyncio.sleep(0.05)
    ordinary = asyncio.create_task(db.write(lambda c: c.execute("INSERT INTO t (v) VALUES ('later')")))
    await asyncio.sleep(0.6)
    assert not ordinary.done()
    release.set()
    await long_task
    await ordinary
    assert _count(db) == 1
    await db.close()
