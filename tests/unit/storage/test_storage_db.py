"""Unit tests for roxy.storage.db: threads, transactions, PRAGMAs, error mapping and bounds."""

from __future__ import annotations

import asyncio
import dataclasses
import sqlite3
import stat
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from roxy.storage import db as dbmod
from roxy.storage.db import (
    PROFILES,
    Database,
    SharedStateUnavailable,
    connect,
    ensure_state_dir,
    is_unavailable_error,
    open_databases,
    resolve_db_paths,
)
from roxy.storage.migrate import migrate_all


def _scratch(db: Database) -> None:
    db.write_sync(lambda c: c.execute("CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY, v TEXT)"))


def test_open_databases_uses_env_paths(env, state_dir: Path) -> None:
    dbs = open_databases(env)
    try:
        assert [d.name for d in dbs.all()] == ["control", "hot", "metrics", "cache"]
        for d in dbs.all():
            assert d.path == state_dir / f"{d.name}.db"
            assert d.profile is PROFILES[d.name]
        assert dbs.get("hot") is dbs.hot
        with pytest.raises(KeyError):
            dbs.get("nope")
    finally:
        dbs.close_all_sync()


def test_resolve_db_paths_accepts_raw_env_names(tmp_path: Path) -> None:
    mapping = {"ROXY_STATE_DIR": str(tmp_path / "s"), "ROXY_HOT_DB": str(tmp_path / "elsewhere" / "h.db")}
    state, paths = resolve_db_paths(mapping)
    assert state == tmp_path / "s"
    assert paths["hot"] == tmp_path / "elsewhere" / "h.db"
    assert paths["control"] == tmp_path / "s" / "control.db"
    obj = SimpleNamespace(state_dir=str(tmp_path / "x"), cache_db=None)
    assert resolve_db_paths(obj)[1]["cache"] == tmp_path / "x" / "cache.db"
    assert resolve_db_paths(SimpleNamespace())[0] == dbmod.DEFAULT_STATE_DIR


def test_state_dir_created_0750_and_db_files_0640(tmp_path: Path) -> None:
    target = tmp_path / "new" / "state"
    ensure_state_dir(target)
    assert stat.S_IMODE(target.stat().st_mode) == 0o750
    conn = connect(target / "hot.db", PROFILES["hot"])
    conn.execute("CREATE TABLE x (a)")
    conn.close()
    assert stat.S_IMODE((target / "hot.db").stat().st_mode) == 0o640


@pytest.mark.parametrize("name", ["control", "hot", "metrics", "cache"])
def test_pragmas_follow_design_section_0(tmp_path: Path, name: str) -> None:
    profile = PROFILES[name]
    writer = connect(tmp_path / f"{name}.db", profile, "writer")
    reader = connect(tmp_path / f"{name}.db", profile, "reader")
    try:
        assert writer.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert writer.execute("PRAGMA busy_timeout").fetchone()[0] == 5000
        assert writer.execute("PRAGMA synchronous").fetchone()[0] == (2 if name == "control" else 1)
        assert writer.execute("PRAGMA foreign_keys").fetchone()[0] == (1 if name == "control" else 0)
        assert writer.execute("PRAGMA wal_autocheckpoint").fetchone()[0] == 1000
        assert writer.execute("PRAGMA journal_size_limit").fetchone()[0] == 64 * 1024 * 1024
        assert writer.execute("PRAGMA cache_size").fetchone()[0] == -profile.writer_cache_kib
        assert reader.execute("PRAGMA cache_size").fetchone()[0] == -profile.reader_cache_kib
        assert writer.execute("PRAGMA mmap_size").fetchone()[0] == (32 * 1024 * 1024 if name == "cache" else 0)
        assert writer.execute("PRAGMA temp_store").fetchone()[0] == (2 if name == "hot" else 0)
        assert reader.execute("PRAGMA query_only").fetchone()[0] == 1
        assert writer.execute("PRAGMA query_only").fetchone()[0] == 0
        assert writer.execute("PRAGMA auto_vacuum").fetchone()[0] == 2  # incremental, set before WAL on a new file
    finally:
        writer.close()
        reader.close()
    expected = {
        "control": (2048, 1024),
        "hot": (4096, 1024),
        "metrics": (8192, 2048),
        "cache": (4096, 2048),
    }
    assert (profile.writer_cache_kib, profile.reader_cache_kib) == expected[name]


def test_migrated_databases_use_incremental_auto_vacuum(dbs) -> None:
    for d in dbs.all():
        assert d.read_sync(lambda c: c.execute("PRAGMA auto_vacuum").fetchone()[0]) == 2


async def test_write_commits_and_returns_value(tmp_path: Path) -> None:
    db = Database("hot", tmp_path / "hot.db")
    _scratch(db)
    try:
        new_id = await db.write(lambda c: c.execute("INSERT INTO t (v) VALUES ('a')").lastrowid)
        assert new_id == 1
        assert await db.read(lambda c: c.execute("SELECT v FROM t").fetchall()[0][0]) == "a"
        assert db.stats.writes >= 1
        assert db.stats.reads >= 1
    finally:
        await db.close()


async def test_write_rolls_back_and_reraises(tmp_path: Path) -> None:
    db = Database("hot", tmp_path / "hot.db")
    _scratch(db)

    def boom(conn: sqlite3.Connection) -> None:
        conn.execute("INSERT INTO t (v) VALUES ('lost')")
        raise ValueError("nope")

    try:
        with pytest.raises(ValueError, match="nope"):
            await db.write(boom)
        assert await db.read(lambda c: c.execute("SELECT count(*) FROM t").fetchone()[0]) == 0
        # The writer connection is still usable after the rollback.
        await db.write(lambda c: c.execute("INSERT INTO t (v) VALUES ('ok')"))
        assert await db.read(lambda c: c.execute("SELECT count(*) FROM t").fetchone()[0]) == 1
    finally:
        await db.close()


async def test_sql_mistakes_are_not_disguised_as_unavailable(tmp_path: Path) -> None:
    db = Database("hot", tmp_path / "hot.db")
    try:
        with pytest.raises(sqlite3.OperationalError, match="no such table"):
            await db.write(lambda c: c.execute("SELECT * FROM missing"))
        # A write sent to a reader fails loudly as a programming error, not as SharedStateUnavailable.
        _scratch(db)
        with pytest.raises(sqlite3.OperationalError):
            await db.read(lambda c: c.execute("INSERT INTO t (v) VALUES ('x')"))
    finally:
        await db.close()


async def test_read_sees_one_snapshot(tmp_path: Path) -> None:
    db = Database("hot", tmp_path / "hot.db")
    _scratch(db)
    db.write_sync(lambda c: c.execute("INSERT INTO t (v) VALUES ('first')"))

    def two_selects(conn: sqlite3.Connection) -> tuple[int, int]:
        before = conn.execute("SELECT count(*) FROM t").fetchone()[0]
        other = sqlite3.connect(str(db.path), isolation_level=None)  # another writer commits in between
        other.execute("INSERT INTO t (v) VALUES ('second')")
        other.close()
        after = conn.execute("SELECT count(*) FROM t").fetchone()[0]
        return before, after

    try:
        assert await db.read(two_selects) == (1, 1)
        assert await db.read(lambda c: c.execute("SELECT count(*) FROM t").fetchone()[0]) == 2
    finally:
        await db.close()


async def test_busy_database_raises_shared_state_unavailable(tmp_path: Path) -> None:
    profile = dataclasses.replace(PROFILES["hot"], busy_timeout_ms=100)
    db = Database("hot", tmp_path / "hot.db", profile)
    _scratch(db)
    blocker = sqlite3.connect(str(db.path), isolation_level=None)
    blocker.execute("BEGIN IMMEDIATE")
    try:
        with pytest.raises(SharedStateUnavailable) as info:
            await db.write(lambda c: c.execute("INSERT INTO t (v) VALUES ('x')"))
        assert info.value.db_name == "hot"
        assert isinstance(info.value.cause, sqlite3.OperationalError)
        assert db.stats.unavailable >= 1
        with pytest.raises(SharedStateUnavailable):
            db.write_sync(lambda c: c.execute("INSERT INTO t (v) VALUES ('x')"))
    finally:
        blocker.execute("ROLLBACK")
        blocker.close()
        await db.close()


def test_is_unavailable_error_classification() -> None:
    busy = sqlite3.OperationalError("database is locked")
    busy.sqlite_errorcode = 5  # type: ignore[attr-defined]
    ioerr = sqlite3.OperationalError("disk I/O error")
    ioerr.sqlite_errorcode = 10 | (4 << 8)  # type: ignore[attr-defined]  # an extended SQLITE_IOERR code
    syntax = sqlite3.OperationalError("near x: syntax error")
    syntax.sqlite_errorcode = 1  # type: ignore[attr-defined]
    assert is_unavailable_error(busy)
    assert is_unavailable_error(ioerr)
    assert not is_unavailable_error(syntax)
    assert not is_unavailable_error(ValueError("database is locked"))
    assert is_unavailable_error(sqlite3.DatabaseError("database disk image is malformed"))


async def test_queue_is_bounded(tmp_path: Path) -> None:
    db = Database("hot", tmp_path / "hot.db", max_pending=1)
    _scratch(db)
    started = threading.Event()
    release = threading.Event()

    def slow(conn: sqlite3.Connection) -> None:
        started.set()
        release.wait(5)

    try:
        first = asyncio.create_task(db.write(slow))
        await asyncio.to_thread(started.wait, 5)
        second = asyncio.create_task(db.write(lambda c: None))  # fills the one queue slot
        await asyncio.sleep(0.05)
        with pytest.raises(SharedStateUnavailable, match="too many pending"):
            await db.write(lambda c: None)
        release.set()
        await first
        await second
    finally:
        release.set()
        await db.close()


async def test_canceled_job_never_runs(tmp_path: Path) -> None:
    db = Database("hot", tmp_path / "hot.db")
    _scratch(db)
    started = threading.Event()
    release = threading.Event()

    def slow(conn: sqlite3.Connection) -> None:
        started.set()
        release.wait(5)

    try:
        first = asyncio.create_task(db.write(slow))
        await asyncio.to_thread(started.wait, 5)
        queued = asyncio.create_task(db.write(lambda c: c.execute("INSERT INTO t (v) VALUES ('ghost')")))
        await asyncio.sleep(0.05)
        queued.cancel()
        with pytest.raises(asyncio.CancelledError):
            await queued
        release.set()
        await first
        assert await db.read(lambda c: c.execute("SELECT count(*) FROM t").fetchone()[0]) == 0
    finally:
        release.set()
        await db.close()


async def test_readers_not_blocked_by_long_write_in_process(tmp_path: Path) -> None:
    db = Database("hot", tmp_path / "hot.db")
    _scratch(db)
    db.write_sync(lambda c: c.execute("INSERT INTO t (v) VALUES ('a')"))
    in_write = threading.Event()

    def long_write(conn: sqlite3.Connection) -> None:
        conn.execute("INSERT INTO t (v) VALUES ('b')")
        in_write.set()
        time.sleep(1.0)

    try:
        writing = asyncio.create_task(db.write(long_write))
        await asyncio.to_thread(in_write.wait, 5)
        latencies = []
        for _ in range(10):
            t0 = time.perf_counter()
            count = await db.read(lambda c: c.execute("SELECT count(*) FROM t").fetchone()[0])
            latencies.append(time.perf_counter() - t0)
            assert count == 1  # the uncommitted row is invisible
        assert not writing.done()
        assert max(latencies) < 0.25
        await writing
        assert await db.read(lambda c: c.execute("SELECT count(*) FROM t").fetchone()[0]) == 2
    finally:
        await db.close()


async def test_close_stops_threads_and_refuses_new_work(tmp_path: Path) -> None:
    db = Database("hot", tmp_path / "hot.db")
    _scratch(db)
    await db.write(lambda c: None)
    await db.read(lambda c: None)
    assert any(t.name.startswith("roxy-db-hot-") for t in threading.enumerate())
    await db.close()
    assert not any(t.name.startswith("roxy-db-hot-") and t.is_alive() for t in threading.enumerate())
    with pytest.raises(SharedStateUnavailable, match="closed"):
        await db.write(lambda c: None)
    with pytest.raises(SharedStateUnavailable, match="closed"):
        db.read_sync(lambda c: None)


async def test_maintenance_runs_without_transaction(tmp_path: Path) -> None:
    db = Database("metrics", tmp_path / "metrics.db")
    _scratch(db)
    try:
        in_tx = await db.maintenance(lambda c: c.in_transaction)
        assert in_tx is False
        row = await db.maintenance(lambda c: tuple(c.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()))
        assert row[0] == 0
    finally:
        await db.close()


def test_sync_variants_round_trip(dbs) -> None:
    dbs.hot.write_sync(lambda c: c.execute("INSERT INTO lease (name, holder, expires_ms, epoch) VALUES ('x','h',1,1)"))
    assert dbs.hot.read_sync(lambda c: c.execute("SELECT holder FROM lease").fetchone()[0]) == "h"
    with pytest.raises(sqlite3.IntegrityError):
        dbs.hot.write_sync(lambda c: c.execute("INSERT INTO lease (name, holder, expires_ms) VALUES ('x','h',1)"))


async def test_databases_close_all(env) -> None:
    dbs = open_databases(env)
    migrate_all(dbs)
    for d in dbs.all():
        await d.read(lambda c: None)
    await dbs.close_all()
    for d in dbs.all():
        with pytest.raises(SharedStateUnavailable):
            await d.read(lambda c: None)


# --- fix pass: multi-process review F2 and F9 ---------------------------------------------------------------------


async def test_queued_writes_fail_fast_while_another_process_holds_the_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MP review F2: the Nth queued write must not wait N x busy_timeout before learning the file is locked."""
    monkeypatch.setattr(dbmod, "BUSY_CIRCUIT_COOLDOWN_S", 0.3)
    busy_s = 0.6
    profile = dataclasses.replace(PROFILES["hot"], busy_timeout_ms=int(busy_s * 1000))
    db = Database("hot", tmp_path / "hot.db", profile)
    _scratch(db)
    blocker = sqlite3.connect(str(db.path), isolation_level=None)
    blocker.execute("BEGIN IMMEDIATE")  # another process stalled inside a write transaction

    async def timed_write(index: int) -> float:
        started = time.monotonic()
        with pytest.raises(SharedStateUnavailable):
            await db.write(lambda c, i=index: c.execute("INSERT INTO t (v) VALUES (?)", (str(i),)))
        return time.monotonic() - started

    try:
        waits = await asyncio.gather(*(timed_write(i) for i in range(6)))
        # Without the busy circuit the last of six writes waits about 6 x 0.6 s = 3.6 s.
        assert max(waits) < 2 * busy_s, waits
        assert db.stats.fast_failures >= 5
        blocker.execute("ROLLBACK")
        await asyncio.sleep(0.4)  # past the cooldown: the next write probes the lock and succeeds
        await db.write(lambda c: c.execute("INSERT INTO t (v) VALUES ('after')"))
        assert await db.read(lambda c: c.execute("SELECT count(*) FROM t").fetchone()[0]) == 1
    finally:
        if blocker.in_transaction:
            blocker.execute("ROLLBACK")
        blocker.close()
        await db.close()


async def test_short_busy_timeout_per_write_does_not_open_the_circuit(tmp_path: Path) -> None:
    db = Database("hot", tmp_path / "hot.db")  # the profile waits 5 s
    _scratch(db)
    blocker = sqlite3.connect(str(db.path), isolation_level=None)
    blocker.execute("BEGIN IMMEDIATE")
    try:
        started = time.monotonic()
        with pytest.raises(SharedStateUnavailable):
            await db.write(lambda c: c.execute("INSERT INTO t (v) VALUES ('x')"), busy_timeout_ms=100)
        assert time.monotonic() - started < 2.0
        with pytest.raises(SharedStateUnavailable):
            await db.write(lambda c: c.execute("INSERT INTO t (v) VALUES ('y')"), busy_timeout_ms=100)
        assert db.stats.fast_failures == 0  # a short budget running out says little about the lock
        blocker.execute("ROLLBACK")
        await db.write(lambda c: c.execute("INSERT INTO t (v) VALUES ('z')"))  # back to the profile's timeout
        assert await db.read(lambda c: c.execute("SELECT v FROM t").fetchall()[0][0]) == "z"
        with pytest.raises(ValueError):
            await db.write(lambda c: None, busy_timeout_ms=-1)
    finally:
        if blocker.in_transaction:
            blocker.execute("ROLLBACK")
        blocker.close()
        await db.close()


async def test_close_racing_a_submit_never_strands_the_job(tmp_path: Path) -> None:
    """MP review F9: close() slipping its stop marker in between the closed check and the enqueue."""
    db = Database("hot", tmp_path / "hot.db")
    _scratch(db)
    await db.write(lambda c: None)  # threads running
    original_put = db._write_q.put_nowait
    closers: list[threading.Thread] = []

    def racing_put(item: object) -> None:
        closer = threading.Thread(target=db.stop_threads, kwargs={"timeout_s": 5.0})
        closers.append(closer)
        closer.start()
        closer.join(0.3)  # give close() every chance to run in between
        original_put(item)  # type: ignore[arg-type]

    db._write_q.put_nowait = racing_put  # type: ignore[method-assign]
    try:
        result = await asyncio.wait_for(db.write(lambda c: c.execute("INSERT INTO t (v) VALUES ('raced')")), 5)
        assert result is not None
    finally:
        for closer in closers:
            await asyncio.to_thread(closer.join, 5)
        await db.close()


def test_leftover_jobs_are_failed_after_the_threads_stop(tmp_path: Path) -> None:
    import concurrent.futures

    db = Database("hot", tmp_path / "hot.db")
    db.stop_threads()
    future: concurrent.futures.Future[object] = concurrent.futures.Future()
    db._write_q.put_nowait(dbmod._Job(lambda c: None, future, "BEGIN IMMEDIATE"))
    db.stop_threads()
    with pytest.raises(SharedStateUnavailable, match="closed"):
        future.result(timeout=1)


@pytest.mark.skipif(not hasattr(dbmod.os, "geteuid") or dbmod.os.geteuid() == 0, reason="root ignores modes")
async def test_unsearchable_state_dir_raises_shared_state_unavailable(tmp_path: Path) -> None:
    """MP review F9: EACCES on the directory is "unavailable" (C7), never a raw PermissionError."""
    locked = tmp_path / "locked"
    locked.mkdir()
    db = Database("hot", locked / "hot.db")
    locked.chmod(0)
    try:
        with pytest.raises(SharedStateUnavailable):
            await db.write(lambda c: None)
        with pytest.raises(SharedStateUnavailable):
            await db.read(lambda c: None)
        with pytest.raises(SharedStateUnavailable):
            await db.maintenance(lambda c: None)
        with pytest.raises(SharedStateUnavailable):
            db.write_sync(lambda c: None)
        with pytest.raises(SharedStateUnavailable):
            db.read_sync(lambda c: None)
    finally:
        locked.chmod(0o700)
        await db.close()
