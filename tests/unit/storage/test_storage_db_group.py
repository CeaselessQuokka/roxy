"""Unit tests for group commit in `roxy.storage.db` (finding LOAD-3): hot-path writes queued together share one
transaction, and each one still behaves exactly like a write of its own.

What this is
    Tests of the writer thread of a database whose profile sets `group_writes` (hot.db): which writes join a group,
    that each write stays atomic (a failing one undoes only itself), ordered (each sees the writes before it),
    budgeted (a write whose deadline passed never runs), and that a caller only ever receives a committed result.

Why it exists
    Under load the two workers' hot.db transactions queued behind one write lock (p99 30 to 135 ms, about 205
    requests a second). Group commit lets one lock acquisition and one commit serve every write already waiting in a
    worker; these tests pin the contract that makes that safe (plan 6.3, C6, C7).

How it works
    A long ordinary write (no budget, so it never joins a group) holds the writer thread while the test queues
    budgeted writes behind it; releasing it lets the queued writes run as one group. Real SQLite files in a temporary
    directory; a second plain `sqlite3` connection stands in for another worker process.

What to read next
    `roxy/storage/db.py` (module docstring, `_ConnectionThread._run_group`), `tests/unit/storage/test_storage_db.py`
    and `test_storage_db_deadline.py`, `tests/multiprocess/test_storage_mp.py`.
"""

from __future__ import annotations

import asyncio
import dataclasses
import sqlite3
import threading
import time
from collections.abc import Callable, Coroutine
from pathlib import Path
from typing import Any

import pytest

from roxy.storage import db as dbmod
from roxy.storage.db import PROFILES, Database, SharedStateUnavailable

BUDGET_MS = 5000  # a budget long enough that it never runs out in these tests unless a test wants it to


@pytest.fixture(autouse=True)
def _patient_groups(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests that count group sizes must not depend on the machine's speed: no time bound unless a test sets one,
    and a group forms whatever the backlog (the backlog rule has its own test)."""
    monkeypatch.setattr(dbmod, "GROUP_MAX_MS", 60_000.0)
    monkeypatch.setattr(dbmod, "GROUP_MIN_QUEUE", 0)


async def test_groups_form_only_in_a_backlog(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Below `GROUP_MIN_QUEUE` queued writes every write keeps a transaction of its own (the shortest lock holds);
    from it on, the writes waiting together share one."""
    monkeypatch.setattr(dbmod, "GROUP_MIN_QUEUE", 8)
    db = Database("hot", tmp_path / "hot.db")
    _setup(db)

    def queue(count: int, tag: str) -> Callable[[], Coroutine[Any, Any, Any]]:
        async def jobs() -> list[str]:
            calls = (db.write(_insert(f"{tag}{i}"), busy_timeout_ms=BUDGET_MS) for i in range(count))
            return list(await asyncio.gather(*calls))

        return jobs

    try:
        assert len(await _behind_a_long_write(db, queue(5, "few"))) == 5  # 4 queued behind the first: no group
        assert db.stats.groups == 0
        assert len(await _behind_a_long_write(db, queue(12, "many"))) == 12  # 11 behind the first: a backlog
        assert db.stats.groups == 1
        assert db.stats.largest_group == 12
    finally:
        await db.close()


def _script(db: Database, sql: str) -> None:
    """Run DDL on a plain connection of its own (not through the writer under test), in WAL mode like every Roxy
    database (a file in rollback journal mode would need an exclusive lock to switch, which a blocker prevents)."""
    conn = sqlite3.connect(str(db.path))
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(sql)
    finally:
        conn.close()


def _setup(db: Database) -> None:
    _script(
        db,
        "CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY, v TEXT);"
        "CREATE TABLE IF NOT EXISTS counter (id INTEGER PRIMARY KEY, n INTEGER NOT NULL);"
        "INSERT OR IGNORE INTO counter (id, n) VALUES (1, 0);",
    )


def _values(db: Database) -> list[str]:
    return [str(r[0]) for r in db.read_sync(lambda c: c.execute("SELECT v FROM t ORDER BY id").fetchall())]


def _insert(value: str) -> Callable[[sqlite3.Connection], str]:
    def run(conn: sqlite3.Connection) -> str:
        conn.execute("INSERT INTO t (v) VALUES (?)", (value,))
        return value

    return run


async def _behind_a_long_write(db: Database, queue_jobs: Callable[[], Coroutine[Any, Any, Any]]) -> Any:
    """Hold the writer thread with an ordinary write, let `queue_jobs` queue its writes, then release it."""
    release = threading.Event()
    started = threading.Event()

    def hold(conn: sqlite3.Connection) -> None:
        started.set()
        release.wait(10)

    holder = asyncio.create_task(db.write(hold))
    await asyncio.to_thread(started.wait, 10)
    waiting: asyncio.Task[Any] = asyncio.create_task(queue_jobs())
    await asyncio.sleep(0.05)  # every write is queued behind the long one
    release.set()
    await holder
    return await waiting


async def test_queued_hot_path_writes_share_one_transaction(tmp_path: Path) -> None:
    db = Database("hot", tmp_path / "hot.db")
    _setup(db)

    async def queue_jobs() -> list[str]:
        return list(await asyncio.gather(*(db.write(_insert(f"v{i}"), busy_timeout_ms=BUDGET_MS) for i in range(10))))

    try:
        results = await _behind_a_long_write(db, queue_jobs)
        assert results == [f"v{i}" for i in range(10)]
        assert _values(db) == [f"v{i}" for i in range(10)]  # all committed, in queue order
        assert db.stats.groups == 1
        assert db.stats.largest_group == 10
        assert db.stats.grouped_writes == 10
        assert db.stats.writes == 11  # the ten grouped writes and the long one
    finally:
        await db.close()


async def test_each_grouped_write_sees_the_writes_before_it(tmp_path: Path) -> None:
    """A read-then-write job (the shape of every limiter, plan 6.3) loses no update inside a group."""
    db = Database("hot", tmp_path / "hot.db")
    _setup(db)

    def increment(conn: sqlite3.Connection) -> int:
        n = int(conn.execute("SELECT n FROM counter WHERE id = 1").fetchone()[0]) + 1
        conn.execute("UPDATE counter SET n = ? WHERE id = 1", (n,))
        return n

    async def queue_jobs() -> list[int]:
        return list(await asyncio.gather(*(db.write(increment, busy_timeout_ms=BUDGET_MS) for _ in range(40))))

    try:
        results = await _behind_a_long_write(db, queue_jobs)
        assert results == list(range(1, 41))
        assert db.read_sync(lambda c: c.execute("SELECT n FROM counter").fetchone()[0]) == 40
        assert db.stats.largest_group == 40
    finally:
        await db.close()


async def test_a_failing_grouped_write_undoes_only_itself(tmp_path: Path) -> None:
    db = Database("hot", tmp_path / "hot.db")
    _setup(db)

    def bad(conn: sqlite3.Connection) -> None:
        conn.execute("INSERT INTO t (v) VALUES ('bad')")
        raise ValueError("refused by its own check")

    async def queue_jobs() -> list[Any]:
        jobs = [_insert("a"), _insert("b"), bad, _insert("c")]
        return list(
            await asyncio.gather(*(db.write(job, busy_timeout_ms=BUDGET_MS) for job in jobs), return_exceptions=True)
        )

    try:
        results = await _behind_a_long_write(db, queue_jobs)
        assert results[:2] == ["a", "b"]
        assert isinstance(results[2], ValueError)
        assert results[3] == "c"
        assert _values(db) == ["a", "b", "c"]  # the failing write's row is gone, every other row stayed
        assert db.stats.largest_group == 4
        assert db.stats.write_errors == 1
    finally:
        await db.close()


async def test_a_failing_first_write_leaves_the_rest_to_a_new_transaction(tmp_path: Path) -> None:
    db = Database("hot", tmp_path / "hot.db")
    _setup(db)

    def bad(conn: sqlite3.Connection) -> None:
        conn.execute("INSERT INTO t (v) VALUES ('bad')")
        raise ValueError("first")

    async def queue_jobs() -> list[Any]:
        jobs = [bad, _insert("x"), _insert("y")]
        return list(
            await asyncio.gather(*(db.write(job, busy_timeout_ms=BUDGET_MS) for job in jobs), return_exceptions=True)
        )

    try:
        results = await _behind_a_long_write(db, queue_jobs)
        assert isinstance(results[0], ValueError)
        assert results[1:] == ["x", "y"]
        assert _values(db) == ["x", "y"]
    finally:
        await db.close()


async def test_ordinary_writes_never_join_a_group_and_keep_their_order(tmp_path: Path) -> None:
    """Writes without a budget (admin changes, leader jobs) run alone; the queue order is kept around them."""
    db = Database("hot", tmp_path / "hot.db")
    _setup(db)

    async def queue_jobs() -> list[str]:
        calls = [
            db.write(_insert("a"), busy_timeout_ms=BUDGET_MS),
            db.write(_insert("b"), busy_timeout_ms=BUDGET_MS),
            db.write(_insert("plain")),
            db.write(_insert("c"), busy_timeout_ms=BUDGET_MS),
        ]
        return list(await asyncio.gather(*calls))

    try:
        assert await _behind_a_long_write(db, queue_jobs) == ["a", "b", "plain", "c"]
        assert _values(db) == ["a", "b", "plain", "c"]
        assert db.stats.groups == 1  # a and b; the plain write ended the group, c ran on its own
        assert db.stats.largest_group == 2
        assert db.stats.grouped_writes == 2
    finally:
        await db.close()


async def test_other_databases_never_group(tmp_path: Path) -> None:
    db = Database("cache", tmp_path / "cache.db")  # group_writes is off for every profile but hot.db
    _setup(db)

    async def queue_jobs() -> list[str]:
        return list(await asyncio.gather(*(db.write(_insert(f"v{i}"), busy_timeout_ms=BUDGET_MS) for i in range(5))))

    try:
        assert not PROFILES["cache"].group_writes
        assert [p.name for p in PROFILES.values() if p.group_writes] == ["hot"]
        assert len(await _behind_a_long_write(db, queue_jobs)) == 5
        assert db.stats.groups == 0
    finally:
        await db.close()


async def test_a_grouped_write_whose_budget_ran_out_never_runs(tmp_path: Path) -> None:
    """Another process holds the lock past one write's budget: that write is answered "unavailable" at its
    deadline and never runs; the patient write queued with it commits once the lock is free."""
    db = Database("hot", tmp_path / "hot.db")
    _setup(db)
    blocker = sqlite3.connect(str(db.path), isolation_level=None)
    blocker.execute("BEGIN IMMEDIATE")
    ran: list[str] = []

    def short(conn: sqlite3.Connection) -> None:
        ran.append("short")

    try:
        patient = asyncio.create_task(db.write(_insert("patient"), busy_timeout_ms=3000))
        started = time.monotonic()
        with pytest.raises(SharedStateUnavailable):
            await db.write(short, busy_timeout_ms=150)
        assert time.monotonic() - started < 1.0
        await asyncio.sleep(0.2)
        blocker.execute("ROLLBACK")
        assert await patient == "patient"
        assert ran == []
        assert _values(db) == ["patient"]
    finally:
        if blocker.in_transaction:
            blocker.execute("ROLLBACK")
        blocker.close()
        await db.close()


async def test_a_lost_group_transaction_fails_what_had_succeeded_and_reruns_the_rest(tmp_path: Path) -> None:
    """An I/O error inside a grouped write means SQLite may have dropped the whole transaction: the writes that had
    returned did not happen ("unavailable", plan C7), and the writes not reached yet run in a new transaction."""
    db = Database("hot", tmp_path / "hot.db")
    _setup(db)

    def io_error(conn: sqlite3.Connection) -> None:
        conn.execute("INSERT INTO t (v) VALUES ('io')")
        exc = sqlite3.OperationalError("disk I/O error")
        exc.sqlite_errorcode = 10  # SQLITE_IOERR
        raise exc

    async def queue_jobs() -> list[Any]:
        jobs = [_insert("first"), io_error, _insert("later")]
        return list(
            await asyncio.gather(*(db.write(job, busy_timeout_ms=BUDGET_MS) for job in jobs), return_exceptions=True)
        )

    try:
        results = await _behind_a_long_write(db, queue_jobs)
        assert isinstance(results[0], SharedStateUnavailable)  # it had returned, but its transaction is gone
        assert isinstance(results[1], SharedStateUnavailable)
        assert results[2] == "later"
        assert _values(db) == ["later"]
        assert db.stats.reconnects == 1  # an I/O error reopens the connection
    finally:
        await db.close()


async def test_no_caller_receives_a_result_its_commit_did_not_keep(tmp_path: Path) -> None:
    """A failing COMMIT (here a deferred foreign key) undoes the whole group, so every write of it is answered
    "unavailable", never with the value its function returned."""
    profile = dataclasses.replace(PROFILES["hot"], foreign_keys=True)
    db = Database("hot", tmp_path / "hot.db", profile)
    _setup(db)
    _script(
        db,
        "CREATE TABLE parent (id INTEGER PRIMARY KEY);"
        "CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER "
        "REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED);",
    )

    def orphan(conn: sqlite3.Connection) -> str:
        conn.execute("INSERT INTO child (parent_id) VALUES (999)")  # checked only at COMMIT
        return "orphan"

    async def queue_jobs() -> list[Any]:
        jobs = [_insert("innocent"), orphan]
        return list(
            await asyncio.gather(*(db.write(job, busy_timeout_ms=BUDGET_MS) for job in jobs), return_exceptions=True)
        )

    try:
        results = await _behind_a_long_write(db, queue_jobs)
        assert all(isinstance(r, SharedStateUnavailable) for r in results), results
        assert _values(db) == []
    finally:
        await db.close()


async def test_a_group_stops_taking_writes_at_its_size_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dbmod, "GROUP_MAX_JOBS", 4)
    db = Database("hot", tmp_path / "hot.db")
    _setup(db)

    async def queue_jobs() -> list[str]:
        return list(await asyncio.gather(*(db.write(_insert(f"v{i}"), busy_timeout_ms=BUDGET_MS) for i in range(10))))

    try:
        assert len(await _behind_a_long_write(db, queue_jobs)) == 10
        assert _values(db) == [f"v{i}" for i in range(10)]
        assert db.stats.largest_group == 4
        assert db.stats.groups == 3  # 4 + 4 + 2
    finally:
        await db.close()


async def test_a_group_that_held_the_lock_long_enough_leaves_the_rest_to_the_next(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`GROUP_MAX_MS` bounds how long one transaction holds the lock: past it, what ran commits and the writes not
    started yet run in the next transaction (the other workers get the lock in between)."""
    monkeypatch.setattr(dbmod, "GROUP_MAX_MS", 50.0)
    db = Database("hot", tmp_path / "hot.db")
    _setup(db)

    def slow(value: str) -> Callable[[sqlite3.Connection], str]:
        def run(conn: sqlite3.Connection) -> str:
            conn.execute("INSERT INTO t (v) VALUES (?)", (value,))
            time.sleep(0.03)
            return value

        return run

    async def queue_jobs() -> list[str]:
        return list(await asyncio.gather(*(db.write(slow(f"v{i}"), busy_timeout_ms=BUDGET_MS) for i in range(6))))

    try:
        assert await _behind_a_long_write(db, queue_jobs) == [f"v{i}" for i in range(6)]
        assert _values(db) == [f"v{i}" for i in range(6)]  # every write ran once, in order
        assert db.stats.largest_group == 2  # 30 ms, 60 ms: past 50 ms the third waits for the next transaction
        assert db.stats.groups == 3
    finally:
        await db.close()


async def test_every_immediate_write_waits_for_the_lock_in_short_polls(tmp_path: Path) -> None:
    """Grouped or not, a write on the writer thread waits for another process's lock `LOCK_POLL_MS` at a time and
    tries again (`_begin_polling`), instead of SQLite's own backoff that sleeps 10 to 100 ms between tries; a deferred
    write keeps SQLite's handler with its full budget."""
    db = Database("hot", tmp_path / "hot.db")
    _setup(db)
    try:
        polled = await db.write(lambda c: c.execute("PRAGMA busy_timeout").fetchone()[0])
        assert polled == dbmod.LOCK_POLL_MS
        polled = await db.write(lambda c: c.execute("PRAGMA busy_timeout").fetchone()[0], busy_timeout_ms=BUDGET_MS)
        assert polled == dbmod.LOCK_POLL_MS
        deferred = await db.write(lambda c: c.execute("PRAGMA busy_timeout").fetchone()[0], immediate=False)
        assert deferred == PROFILES["hot"].busy_timeout_ms
    finally:
        await db.close()


def test_begin_polling_waits_tries_again_and_gives_up(tmp_path: Path) -> None:
    db = Database("hot", tmp_path / "hot.db")
    _setup(db)
    conn = dbmod.connect(db.path, db.profile)
    conn.execute(f"PRAGMA busy_timeout={dbmod.LOCK_POLL_MS}")
    blocker = sqlite3.connect(str(db.path), isolation_level=None, check_same_thread=False)
    try:
        blocker.execute("BEGIN IMMEDIATE")
        started = time.monotonic()
        with pytest.raises(sqlite3.OperationalError):
            dbmod._begin_polling(conn, "BEGIN IMMEDIATE", lambda: started + 0.1)
        assert 0.09 <= time.monotonic() - started < 1.0  # it kept trying until the deadline
        later = time.monotonic() + 5
        assert dbmod._begin_polling(conn, "BEGIN IMMEDIATE", lambda: later, lambda: False) is False
        timer = threading.Timer(0.15, lambda: blocker.execute("ROLLBACK"))
        timer.start()
        assert dbmod._begin_polling(conn, "BEGIN IMMEDIATE", lambda: later) is True
        timer.join()
        conn.execute("ROLLBACK")
    finally:
        if blocker.in_transaction:
            blocker.execute("ROLLBACK")
        blocker.close()
        conn.close()


def test_lock_wait_and_hold_are_counted_per_transaction(tmp_path: Path) -> None:
    stats = dbmod.DbStats()
    stats.note_transaction(0.05, 0.3)
    stats.note_transaction(150.0, 0.3)
    stats.note_transaction(9000.0, 12.0)
    timing = stats.timing()
    assert timing["lock_wait_ms"] == {"n": 3, "p50": 200, "p95": None, "p99": None, "max": None}
    assert timing["hold_ms"]["p50"] == 0.5
    assert timing["hold_ms"]["max"] == 20
    assert dbmod.histogram_summary(dbmod._empty_hist()) == {"n": 0, "p50": None, "p95": None, "p99": None, "max": None}


async def test_close_runs_every_queued_grouped_write_first(tmp_path: Path) -> None:
    db = Database("hot", tmp_path / "hot.db")
    _setup(db)
    release = threading.Event()
    started = threading.Event()

    def hold(conn: sqlite3.Connection) -> None:
        started.set()
        release.wait(10)

    holder = asyncio.create_task(db.write(hold))
    await asyncio.to_thread(started.wait, 10)
    writes = [asyncio.create_task(db.write(_insert(f"v{i}"), busy_timeout_ms=BUDGET_MS)) for i in range(5)]
    await asyncio.sleep(0.05)
    closing = asyncio.create_task(db.close())  # the stop marker queues behind the five writes
    await asyncio.sleep(0.05)
    release.set()
    await holder
    assert [await w for w in writes] == [f"v{i}" for i in range(5)]
    await closing
    reopened = Database("hot", tmp_path / "hot.db")
    try:
        assert _values(reopened) == [f"v{i}" for i in range(5)]
    finally:
        await reopened.close()
