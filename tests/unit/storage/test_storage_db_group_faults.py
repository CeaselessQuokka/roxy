"""Group commit under faults (finding LOAD-3): every grouped write behaves exactly as a write of its own would.

What this is
    The proof obligations of `roxy.storage.db` group commit, one test each: a failing member never commits, loses or
    rolls back another member's write; a savepoint that cannot open, roll back or release, a failed COMMIT, a busy
    database, lease and fence checks, a bug in the group code and a member that ends the transaction behave as the
    single-transaction writer does (or, where the state cannot be known, never report a write as done); callers see
    the same exceptions; queue order and read-your-writes hold.

Why it exists
    Group commit answers many callers from one transaction. A mistake there would tell a caller its limiter row,
    lease or bucket slot was written when it was not (or the reverse), which breaks plan C6 (exact limits across
    workers) and C7 (fail closed). DESIGN.md section 2 is the contract these tests pin.

How it works
    A long ordinary write holds the writer thread while a test queues budgeted writes behind it, so they run as one
    group (`GROUP_MIN_QUEUE` is 0 here). Faults are injected with `FaultyConnection`, a real SQLite connection whose
    `execute` fails on chosen statements, installed by replacing `roxy.storage.db.connect` for the writer. A second
    plain connection stands in for another worker process.

What to read next
    `roxy/storage/db.py` (`_ConnectionThread._run_group`), `test_storage_db_group.py` (the happy paths),
    `test_storage_txn_contract.py` (no write function ends its transaction), `tests/multiprocess/test_storage_mp.py`.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import sqlite3
import threading
import time
from collections.abc import Callable, Coroutine
from pathlib import Path
from typing import Any

import pytest

from roxy.storage import db as dbmod
from roxy.storage import leases
from roxy.storage.db import PROFILES, Database, DbProfile, SharedStateUnavailable

BUDGET_MS = 5000  # long enough that it never runs out unless a test wants it to


@pytest.fixture(autouse=True)
def _patient_groups(monkeypatch: pytest.MonkeyPatch) -> None:
    """A group forms whatever the backlog, and no time bound cuts it (tests that need either set them)."""
    monkeypatch.setattr(dbmod, "GROUP_MAX_MS", 60_000.0)
    monkeypatch.setattr(dbmod, "GROUP_MIN_QUEUE", 0)


# ---------------------------------------------------------------------------------------------------- helpers


class FaultyConnection:
    """A real connection whose `execute` raises for statements that start with a chosen prefix (fault injection).

    `faults` maps a statement prefix to a list: each matching statement pops the next entry and raises it, or runs
    normally when the entry is None (to let earlier statements of the same kind through); an empty list lets every
    statement run. Everything else is the real connection's.
    """

    def __init__(self, real: sqlite3.Connection) -> None:
        self.real = real
        self.faults: dict[str, list[BaseException | None]] = {}

    def execute(self, sql: str, *args: Any) -> Any:
        for prefix, pending in self.faults.items():
            if sql.startswith(prefix) and pending:
                fault = pending.pop(0)
                if fault is not None:
                    raise fault
        return self.real.execute(sql, *args)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.real, name)


def _error(cls: type[sqlite3.Error], text: str, code: int) -> sqlite3.Error:
    exc = cls(text)
    exc.sqlite_errorcode = code  # what SQLite sets on a real error
    return exc


def _faulty_writer(monkeypatch: pytest.MonkeyPatch) -> list[FaultyConnection]:
    """Make every writer connection a `FaultyConnection`; returns the list they are added to."""
    made: list[FaultyConnection] = []
    real_connect = dbmod.connect

    def connect(path: Any, profile: DbProfile, role: dbmod.ConnRole = "writer") -> Any:
        conn = real_connect(path, profile, role)
        if role != "writer":
            return conn
        faulty = FaultyConnection(conn)
        made.append(faulty)
        return faulty

    monkeypatch.setattr(dbmod, "connect", connect)
    return made


def _script(path: Path, sql: str) -> None:
    conn = sqlite3.connect(str(path))
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(sql)
    finally:
        conn.close()


def _hot(tmp_path: Path, profile: DbProfile | None = None) -> Database:
    db = Database("hot", tmp_path / "hot.db", profile)
    _script(
        db.path,
        "CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY, v TEXT UNIQUE);"
        "CREATE TABLE IF NOT EXISTS lease (name TEXT PRIMARY KEY, holder TEXT NOT NULL, expires_ms INTEGER NOT NULL,"
        " epoch INTEGER NOT NULL, payload_json TEXT);",
    )
    return db


def _values(db: Database) -> list[str]:
    return [str(r[0]) for r in db.read_sync(lambda c: c.execute("SELECT v FROM t ORDER BY id").fetchall())]


def _insert(value: str, ran: list[str] | None = None) -> Callable[[Any], str]:
    def run(conn: Any) -> str:
        if ran is not None:
            ran.append(value)
        conn.execute("INSERT INTO t (v) VALUES (?)", (value,))
        return value

    return run


async def _behind_a_long_write(db: Database, queue_jobs: Callable[[], Coroutine[Any, Any, Any]]) -> Any:
    """Hold the writer thread with an ordinary write, let `queue_jobs` queue its writes, then release it."""
    release = threading.Event()
    started = threading.Event()

    def hold(conn: Any) -> None:
        started.set()
        release.wait(10)

    holder = asyncio.create_task(db.write(hold))
    await asyncio.to_thread(started.wait, 10)
    waiting: asyncio.Task[Any] = asyncio.create_task(queue_jobs())
    await asyncio.sleep(0.05)  # every write is queued behind the long one
    release.set()
    await holder
    return await waiting


async def _group_of(db: Database, jobs: list[Callable[[Any], Any]], budget_ms: int = BUDGET_MS) -> list[Any]:
    """Queue `jobs` behind a long write so they run as one group; their results or exceptions, in order."""

    async def queue_jobs() -> list[Any]:
        calls = (db.write(job, busy_timeout_ms=budget_ms) for job in jobs)
        return list(await asyncio.gather(*calls, return_exceptions=True))

    return list(await _behind_a_long_write(db, queue_jobs))


# ---------------------------------------------------------------------- savepoint, release and commit failures


async def test_a_savepoint_that_cannot_open_fails_only_its_own_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Its job never runs (as when BEGIN fails for a write of its own); the jobs before it commit, the ones after it
    run in the next transaction."""
    made = _faulty_writer(monkeypatch)
    db = _hot(tmp_path)
    ran: list[str] = []
    try:
        await db.write(lambda c: None)  # the writer connection exists
        full = _error(sqlite3.OperationalError, "database or disk is full", 13)
        made[0].faults["SAVEPOINT"] = [full]  # the second job's savepoint (the first job runs without one)
        results = await _group_of(db, [_insert("a", ran), _insert("b", ran), _insert("c", ran)])
        assert results[0] == "a"
        assert isinstance(results[1], SharedStateUnavailable)
        assert results[1].__cause__ is full
        assert results[2] == "c"
        assert ran == ["a", "c"]  # b never ran
        assert _values(db) == ["a", "c"]
    finally:
        await db.close()


async def test_a_savepoint_that_cannot_be_rolled_back_gives_up_the_whole_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A job raised and its savepoint could not be undone: the transaction's state is not known, so nothing of it is
    reported as done. The failing job gets its own exception, the one before it "unavailable", none of their rows
    stay, and the job after it runs in a new transaction."""
    made = _faulty_writer(monkeypatch)
    db = _hot(tmp_path)

    def bad(conn: Any) -> None:
        conn.execute("INSERT INTO t (v) VALUES ('bad')")
        raise ValueError("refused by its own check")

    try:
        await db.write(lambda c: None)
        made[0].faults["ROLLBACK TO"] = [_error(sqlite3.OperationalError, "out of memory", 7)]
        results = await _group_of(db, [_insert("a"), bad, _insert("c")])
        assert isinstance(results[0], SharedStateUnavailable)
        assert isinstance(results[1], ValueError)
        assert results[2] == "c"
        assert _values(db) == ["c"]
    finally:
        await db.close()


async def test_a_release_that_fails_gives_up_the_whole_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    made = _faulty_writer(monkeypatch)
    db = _hot(tmp_path)
    try:
        await db.write(lambda c: None)
        made[0].faults["RELEASE"] = [_error(sqlite3.OperationalError, "out of memory", 7)]
        results = await _group_of(db, [_insert("a"), _insert("b"), _insert("c")])
        assert isinstance(results[0], SharedStateUnavailable)
        assert isinstance(results[1], SharedStateUnavailable)
        assert results[2] == "c"
        assert _values(db) == ["c"]
    finally:
        await db.close()


async def test_a_failed_commit_answers_every_write_of_the_group_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No caller receives a value its COMMIT did not keep; a failing job still gets its own exception."""
    made = _faulty_writer(monkeypatch)
    db = _hot(tmp_path)

    def bad(conn: Any) -> None:
        raise KeyError("its own")

    try:
        await db.write(lambda c: None)
        io = _error(sqlite3.OperationalError, "disk I/O error", 10)
        made[0].faults["COMMIT"] = [None, io]  # the long write's COMMIT goes through, the group's fails
        results = await _group_of(db, [_insert("a"), bad, _insert("b")])
        assert isinstance(results[0], SharedStateUnavailable)
        assert results[0].__cause__ is io
        assert isinstance(results[1], KeyError)
        assert isinstance(results[2], SharedStateUnavailable)
        assert _values(db) == []
        assert db.stats.reconnects == 1  # an I/O error reopens the connection
        assert await db.write(_insert("after"), busy_timeout_ms=BUDGET_MS) == "after"
        assert _values(db) == ["after"]
    finally:
        await db.close()


async def test_with_foreign_keys_on_writes_never_group_and_keep_their_own_fate(tmp_path: Path) -> None:
    """A deferred foreign key fails at COMMIT, which would fail every job of a group for one job's mistake. So a
    profile with foreign keys on never groups (`group_safe`): the innocent write commits, the orphan alone fails with
    its own error, as with transactions of their own."""
    profile = dataclasses.replace(PROFILES["hot"], foreign_keys=True)
    assert not dbmod.group_safe(profile)
    assert dbmod.group_safe(PROFILES["hot"])
    db = _hot(tmp_path, profile)
    _script(
        db.path,
        "CREATE TABLE parent (id INTEGER PRIMARY KEY);"
        "CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER "
        "REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED);",
    )

    def orphan(conn: Any) -> str:
        conn.execute("INSERT INTO child (parent_id) VALUES (999)")  # checked only at COMMIT
        return "orphan"

    try:
        results = await _group_of(db, [_insert("innocent"), orphan, _insert("later")])
        assert results[0] == "innocent"
        assert isinstance(results[1], sqlite3.IntegrityError)
        assert results[2] == "later"
        assert _values(db) == ["innocent", "later"]
        assert db.stats.groups == 0
    finally:
        await db.close()


# ------------------------------------------------------------------- environmental loss and broken contracts


async def test_a_write_whose_transaction_sqlite_dropped_reports_nothing_as_done(tmp_path: Path) -> None:
    """Some errors (a full disk, no memory) make SQLite roll the whole transaction back under the job. The jobs that
    had run are answered "unavailable" (true: their rows are gone), the failing job its own error, and the rest run
    in a new transaction."""
    db = _hot(tmp_path)

    def full(conn: Any) -> None:
        conn.execute("INSERT INTO t (v) VALUES ('full')")
        conn.execute("ROLLBACK")  # what SQLite itself does for some errors
        raise _error(sqlite3.OperationalError, "database or disk is full", 13)

    try:
        results = await _group_of(db, [_insert("a"), full, _insert("c")])
        assert isinstance(results[0], SharedStateUnavailable)
        assert isinstance(results[1], SharedStateUnavailable)
        assert results[2] == "c"
        assert _values(db) == ["c"]
    finally:
        await db.close()


@pytest.mark.parametrize("statement", ["ROLLBACK", "COMMIT"])
async def test_a_write_that_ends_its_transaction_is_never_reported_done(
    tmp_path: Path, statement: str, caplog: pytest.LogCaptureFixture
) -> None:
    """A function passed to `write` must never end the transaction it runs in (`test_storage_txn_contract.py` checks
    that none in Roxy does). If one did, no job of its group is answered with a value: after a ROLLBACK nothing of
    them exists; after a COMMIT they were written but are still answered "unavailable" (a false failure, never a
    false success), and the writer logs `db_job_ended_transaction`."""
    db = _hot(tmp_path)

    def rogue(value: str) -> Callable[[Any], str]:
        def run(conn: Any) -> str:
            conn.execute("INSERT INTO t (v) VALUES (?)", (value,))
            conn.execute(statement)
            return value

        return run

    committed = statement == "COMMIT"
    try:
        with caplog.at_level(logging.ERROR, logger="roxy.storage.db"):
            results = await _group_of(db, [_insert("a"), rogue("rogue"), _insert("c")])
        assert isinstance(results[0], SharedStateUnavailable)
        assert isinstance(results[1], SharedStateUnavailable)
        assert isinstance(results[1].__cause__, dbmod.JobEndedTransaction)
        assert results[2] == "c"
        assert any(r.getMessage() == "db_job_ended_transaction" for r in caplog.records)
        assert _values(db) == (["a", "rogue", "c"] if committed else ["c"])
        # The first job of a group can end it too: it alone is answered "unavailable", the next runs on its own.
        results = await _group_of(db, [rogue("first"), _insert("d")])
        assert isinstance(results[0], SharedStateUnavailable)
        assert isinstance(results[0].__cause__, dbmod.JobEndedTransaction)
        assert results[1] == "d"
        assert _values(db) == (["a", "rogue", "c", "first", "d"] if committed else ["c", "d"])
    finally:
        await db.close()


async def test_a_bug_before_commit_answers_every_caller_and_keeps_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = _hot(tmp_path)
    original = dbmod._ConnectionThread._start_grouped
    calls = {"n": 0}

    def flaky(self: Any, job: Any) -> bool:
        calls["n"] += 1
        if calls["n"] == 3:
            raise RuntimeError("a bug in the group code")
        return original(self, job)

    monkeypatch.setattr(dbmod._ConnectionThread, "_start_grouped", flaky)
    try:
        results = await _group_of(db, [_insert(v) for v in "abcd"])
        assert all(isinstance(r, SharedStateUnavailable) for r in results), results
        assert _values(db) == []
        monkeypatch.setattr(dbmod._ConnectionThread, "_start_grouped", original)
        assert await db.write(_insert("after"), busy_timeout_ms=BUDGET_MS) == "after"  # the writer thread lives on
    finally:
        await db.close()


async def test_a_bug_after_commit_still_delivers_every_committed_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No caller of a committed write is ever told "unavailable": results are delivered right after COMMIT, and a
    failure in the bookkeeping after it delivers them anyway."""
    db = _hot(tmp_path)
    original = dbmod.DbStats.note_transaction
    calls = {"n": 0}

    def broken(self: Any, lock_wait_ms: float, hold_ms: float) -> None:
        calls["n"] += 1
        if calls["n"] == 2:  # the first call is the long write's, the second the group's
            raise RuntimeError("a bug in the statistics")
        original(self, lock_wait_ms, hold_ms)

    monkeypatch.setattr(dbmod.DbStats, "note_transaction", broken)
    try:
        assert await _group_of(db, [_insert(v) for v in "abc"]) == ["a", "b", "c"]
        assert calls["n"] == 2
        assert _values(db) == ["a", "b", "c"]
    finally:
        await db.close()


# --------------------------------------------------------------------------------------- exception parity


def _parity_jobs() -> list[Callable[[Any], Any]]:
    def plain_bug(conn: Any) -> None:
        raise ValueError("a bug")

    def duplicate(conn: Any) -> None:
        conn.execute("INSERT INTO t (v) VALUES ('dup')")  # UNIQUE: 'dup' was inserted by the first job

    def unavailable(conn: Any) -> None:
        raise _error(sqlite3.OperationalError, "database or disk is full", 13)

    return [_insert("dup"), plain_bug, duplicate, unavailable, _insert("last")]


def _shape(result: Any) -> tuple[str, str, str | None]:
    if not isinstance(result, BaseException):
        return ("value", repr(result), None)
    cause = type(result.__cause__).__name__ if result.__cause__ is not None else None
    return (type(result).__name__, str(result), cause)


async def test_grouped_and_single_writes_raise_the_same_exceptions(tmp_path: Path) -> None:
    """The same jobs, queued the same way, once on hot.db (grouped) and once on a profile that never groups: every
    caller gets the same value or the same exception (type, message and cause), and the same rows stay."""
    shapes: dict[str, list[tuple[str, str, str | None]]] = {}
    rows: dict[str, list[str]] = {}
    for mode, profile in (
        ("grouped", PROFILES["hot"]),
        ("single", dataclasses.replace(PROFILES["hot"], group_writes=False)),
    ):
        directory = tmp_path / mode
        directory.mkdir()
        db = _hot(directory, profile)
        try:
            shapes[mode] = [_shape(r) for r in await _group_of(db, _parity_jobs())]
            rows[mode] = _values(db)
            assert (db.stats.groups > 0) == (mode == "grouped")
        finally:
            await db.close()
    assert shapes["grouped"] == shapes["single"]
    assert rows["grouped"] == rows["single"] == ["dup", "last"]
    assert shapes["grouped"][2][0] == "IntegrityError"
    assert shapes["grouped"][3] == (
        "SharedStateUnavailable",
        "shared state unavailable in hot.db: database or disk is full",
        "OperationalError",
    )


# ---------------------------------------------------------------------------------- budgets and a busy database


@pytest.mark.parametrize("grouped", [True, False])
async def test_a_busy_database_fails_every_write_at_its_own_deadline(tmp_path: Path, grouped: bool) -> None:
    """Another process holds the lock past every budget: each write is answered "unavailable" at its own deadline,
    none of them ever runs, and short budgets never open the busy circuit; once the lock is free a write goes through
    at once. Grouped or not, the same."""
    profile = PROFILES["hot"] if grouped else dataclasses.replace(PROFILES["hot"], group_writes=False)
    db = _hot(tmp_path, profile)
    await db.write(lambda c: None)
    blocker = sqlite3.connect(str(db.path), isolation_level=None)
    blocker.execute("BEGIN IMMEDIATE")
    ran: list[str] = []
    budgets = [150, 300, 450, 600]

    async def timed(value: str, budget: int) -> tuple[Any, float]:
        began = time.monotonic()
        try:
            result: Any = await db.write(_insert(value, ran), busy_timeout_ms=budget)
        except SharedStateUnavailable as exc:
            result = exc
        return result, (time.monotonic() - began) * 1000

    try:
        answers = await asyncio.gather(*(timed(f"v{b}", b) for b in budgets))
        for (result, waited_ms), budget in zip(answers, budgets, strict=True):
            assert isinstance(result, SharedStateUnavailable)
            assert budget - 20 <= waited_ms < budget + 400, (budget, waited_ms)
        assert ran == []
        assert db._busy_until == 0.0  # a hot path's short budget never opens the busy circuit
        blocker.execute("ROLLBACK")
        assert await db.write(_insert("free"), busy_timeout_ms=1000) == "free"
        assert _values(db) == ["free"]
    finally:
        if blocker.in_transaction:
            blocker.execute("ROLLBACK")
        blocker.close()
        await db.close()


@pytest.mark.parametrize("grouped", [True, False])
async def test_a_write_that_waited_the_full_timeout_opens_the_busy_circuit(tmp_path: Path, grouped: bool) -> None:
    """A budget as long as the profile's busy timeout is a full wait: when it runs out the circuit opens and the next
    write fails at once ("database is busy"), grouped or not."""
    profile = dataclasses.replace(PROFILES["hot"], busy_timeout_ms=300, group_writes=grouped)
    db = _hot(tmp_path, profile)
    await db.write(lambda c: None)
    blocker = sqlite3.connect(str(db.path), isolation_level=None)
    blocker.execute("BEGIN IMMEDIATE")
    try:
        calls = (db.write(_insert(v), busy_timeout_ms=300) for v in "ab")
        results = await asyncio.gather(*calls, return_exceptions=True)
        assert all(isinstance(r, SharedStateUnavailable) for r in results)
        assert db.stats.groups == 0  # nothing committed, grouped or not
        began = time.monotonic()
        with pytest.raises(SharedStateUnavailable, match="database is busy"):
            await db.write(_insert("c"), busy_timeout_ms=300)
        assert time.monotonic() - began < 0.1
    finally:
        blocker.execute("ROLLBACK")
        blocker.close()
        await db.close()


async def test_a_caller_that_gives_up_before_its_grouped_write_starts_never_runs(tmp_path: Path) -> None:
    db = _hot(tmp_path)
    ran: list[str] = []
    release = threading.Event()
    started = threading.Event()

    def hold(conn: Any) -> None:
        started.set()
        release.wait(10)

    try:
        holder = asyncio.create_task(db.write(hold))
        await asyncio.to_thread(started.wait, 10)
        tasks = [asyncio.create_task(db.write(_insert(v, ran), busy_timeout_ms=BUDGET_MS)) for v in "abc"]
        await asyncio.sleep(0.05)
        tasks[1].cancel()
        release.set()
        await holder
        assert await tasks[0] == "a"
        assert await tasks[2] == "c"
        with pytest.raises(asyncio.CancelledError):
            await tasks[1]
        assert ran == ["a", "c"]
        assert _values(db) == ["a", "c"]
    finally:
        await db.close()


async def test_a_write_whose_budget_runs_out_while_the_group_runs_never_runs(tmp_path: Path) -> None:
    """The deadline is checked when each job starts: a job whose budget ran out while the jobs ahead of it in the same
    transaction ran is refused ("unavailable") and never runs; the rest commit."""
    db = _hot(tmp_path)
    ran: list[str] = []

    def slow(conn: Any) -> str:
        conn.execute("INSERT INTO t (v) VALUES ('slow')")
        time.sleep(0.4)
        return "slow"

    async def queue_jobs() -> list[Any]:
        calls = [
            db.write(slow, busy_timeout_ms=BUDGET_MS),
            db.write(_insert("short", ran), busy_timeout_ms=300),
            db.write(_insert("patient", ran), busy_timeout_ms=BUDGET_MS),
        ]
        return list(await asyncio.gather(*calls, return_exceptions=True))

    try:
        results = await _behind_a_long_write(db, queue_jobs)
        assert results[0] == "slow"
        assert isinstance(results[1], SharedStateUnavailable)
        assert results[2] == "patient"
        assert ran == ["patient"]
        assert _values(db) == ["slow", "patient"]
    finally:
        await db.close()


# ---------------------------------------------------------------------------------------- leases and fences


class LostFence(Exception):
    """A fenced write found that its epoch is no longer the lease's (the shape of `LostLeadership`)."""


def _fenced_insert(value: str, name: str, epoch: int) -> Callable[[Any], str]:
    def run(conn: Any) -> str:
        found = leases.holder_epoch(conn, name)
        if found is None or found[1] != epoch:
            raise LostFence(f"{name} is at epoch {found[1] if found else None}, not {epoch}")
        conn.execute("INSERT INTO t (v) VALUES (?)", (value,))
        return value

    return run


async def test_lease_and_fence_checks_inside_a_group_see_the_writes_before_them(tmp_path: Path) -> None:
    """Leases are read-then-write functions composed into a write (DESIGN.md section 2). Inside one group each sees
    the jobs before it, exactly as separate transactions in that order would: the second acquirer is refused, a
    fenced write checks the epoch the first granted, a takeover after expiry bumps the epoch, and the fenced write
    holding the old epoch then fails alone."""
    db = _hot(tmp_path)

    def acquire(holder: str, now_ms: int) -> Callable[[Any], Any]:
        return lambda conn: leases.acquire(conn, "job", holder, 1000, now_ms)

    jobs = [
        acquire("a", 10_000),
        acquire("b", 10_500),  # still a's: refused
        _fenced_insert("by-a", "job", 1),
        acquire("b", 11_001),  # a's lease expired at 11,000: b takes over, epoch 2
        _fenced_insert("late-a", "job", 1),  # fenced off
        _fenced_insert("by-b", "job", 2),
    ]
    try:
        results = await _group_of(db, jobs)
        assert db.stats.largest_group == 6
        assert results[0].holder == "a"
        assert results[0].epoch == 1
        assert results[1] is None
        assert results[2] == "by-a"
        assert results[3].holder == "b"
        assert results[3].epoch == 2
        assert isinstance(results[4], LostFence)
        assert results[5] == "by-b"
        assert _values(db) == ["by-a", "by-b"]
        assert db.read_sync(lambda c: leases.holder_epoch(c, "job")) == ("b", 2, 12_001)
    finally:
        await db.close()


# ------------------------------------------------------------------------------- order and read-your-writes


async def test_writes_commit_in_queue_order_and_each_caller_reads_its_own_write(tmp_path: Path) -> None:
    """Many tasks write at once (budgeted writes that group, and ordinary ones that never do): rows commit in the
    order the writes were queued, and a task that read right after its write returned always found its row."""
    db = _hot(tmp_path)

    async def one(index: int) -> bool:
        value = f"v{index:04d}"
        budget = None if index % 7 == 0 else BUDGET_MS
        await db.write(_insert(value), busy_timeout_ms=budget)
        found = await db.read(lambda c: c.execute("SELECT count(*) FROM t WHERE v = ?", (value,)).fetchone()[0])
        return bool(found == 1)

    try:
        seen = await asyncio.gather(*(one(i) for i in range(300)))
        assert all(seen)
        assert _values(db) == [f"v{i:04d}" for i in range(300)]
        assert db.stats.groups > 0
    finally:
        await db.close()
