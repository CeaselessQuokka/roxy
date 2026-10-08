"""Unit tests for roxy.storage.batch.BatchWriter (bounded queues, drops, flushes, retries)."""

from __future__ import annotations

import asyncio
import sqlite3
from typing import Any

import pytest

from roxy.storage import db as dbmod
from roxy.storage.batch import BatchWriter
from roxy.storage.db import SharedStateUnavailable


def _events_handler(conn: sqlite3.Connection, items: list[Any]) -> None:
    conn.executemany("INSERT INTO events (at_ms, type, severity) VALUES (?, ?, 'info')", [(i, f"e{i}") for i in items])


def _gate_handler(conn: sqlite3.Connection, items: list[Any]) -> None:
    conn.executemany(
        "INSERT INTO email_gate (key, last_sent_at) VALUES (?, 0) ON CONFLICT (key) DO NOTHING",
        [(str(i),) for i in items],
    )


def _count(db, table: str) -> int:
    return int(db.read_sync(lambda c: c.execute(f"SELECT count(*) FROM {table}").fetchone()[0]))


async def test_flush_writes_each_database_in_one_transaction(dbs) -> None:
    writer = BatchWriter()
    writer.register("event", dbs.metrics, _events_handler)
    writer.register("gate", dbs.hot, _gate_handler)
    for i in range(10):
        writer.add("event", i)
    writer.add_many("gate", ["a", "b"])
    assert writer.queued() == 12
    writes_before = dbs.metrics.stats.writes
    result = await writer.flush()
    assert result.written == {"event": 10, "gate": 2}
    assert result.failed_dbs == []
    assert dbs.metrics.stats.writes == writes_before + 1  # one transaction for all ten events
    assert _count(dbs.metrics, "events") == 10
    assert _count(dbs.hot, "email_gate") == 2
    assert writer.queued() == 0
    assert (await writer.flush()).written == {}


def test_overflow_drops_oldest_low_priority_first(dbs) -> None:
    writer = BatchWriter(max_items=3)
    writer.register("low", dbs.metrics, _events_handler, priority=0)
    writer.register("high", dbs.metrics, _events_handler, priority=10)
    assert writer.add("low", 1)
    assert writer.add("low", 2)
    assert writer.add("high", 100)
    assert writer.add("high", 101)  # drops low 1 (oldest of the lowest priority)
    assert writer.add("low", 3)  # drops low 2
    stats = writer.stats()
    assert stats["queued"] == 3
    assert stats["dropped"] == 2
    assert stats["kinds"]["low"]["dropped"] == 2
    assert writer.add("high", 102)  # drops low 3
    assert not writer.add("low", 4)  # only higher priority items queued: the new low item is the one dropped
    assert writer.dropped == 4
    writer.flush_now()
    rows = dbs.metrics.read_sync(lambda c: [r[0] for r in c.execute("SELECT at_ms FROM events ORDER BY at_ms")])
    assert rows == [100, 101, 102]


def test_max_items_can_follow_a_live_setting(dbs) -> None:
    limit = {"value": 2}
    writer = BatchWriter(max_items=lambda: limit["value"])
    writer.register("event", dbs.metrics, _events_handler)
    writer.add_many("event", [1, 2, 3])
    assert writer.queued() == 2
    assert writer.dropped == 1
    limit["value"] = 10
    writer.add_many("event", [4, 5, 6])
    assert writer.queued() == 5


async def test_failed_flush_requeues_and_retries(dbs, monkeypatch: pytest.MonkeyPatch) -> None:
    # The fake "database is locked" opens the database's busy circuit (storage/db.py); with no cooldown the very
    # next flush probes again, as it would once the cooldown passed in production.
    monkeypatch.setattr(dbmod, "BUSY_CIRCUIT_COOLDOWN_S", 0.0)
    calls = {"n": 0}

    def flaky(conn: sqlite3.Connection, items: list[Any]) -> None:
        calls["n"] += 1
        if calls["n"] == 1:
            err = sqlite3.OperationalError("database is locked")
            err.sqlite_errorcode = 5  # type: ignore[attr-defined]
            raise err
        _events_handler(conn, items)

    writer = BatchWriter()
    writer.register("event", dbs.metrics, flaky)
    writer.add_many("event", [1, 2, 3])
    first = await writer.flush()
    assert first.failed_dbs == ["metrics"]
    assert writer.flush_failures == 1
    assert writer.queued() == 3  # nothing lost
    writer.add("event", 4)
    second = await writer.flush()
    assert second.written == {"event": 4}
    rows = dbs.metrics.read_sync(lambda c: [r[0] for r in c.execute("SELECT at_ms FROM events ORDER BY id")])
    assert rows == [1, 2, 3, 4]  # order kept across the retry


async def test_requeue_respects_the_bound(dbs) -> None:
    def unavailable(conn: sqlite3.Connection, items: list[Any]) -> None:
        raise SharedStateUnavailable("metrics", "down for the test")

    writer = BatchWriter(max_items=3)
    writer.register("event", dbs.metrics, unavailable)
    writer.add_many("event", [1, 2, 3])
    await writer.flush()  # fails; while it was failing nothing new arrived, so all three fit back
    assert writer.queued() == 3
    writer._requeue_kinds(["event"], {"event": [7, 8]})  # no room left: both dropped and counted
    assert writer.queued() == 3
    assert writer.dropped == 2


# --- fix pass: multi-process review F4, F7 and F8 -------------------------------------------------------------------


def _rows(dbs: Any) -> list[int]:
    return dbs.metrics.read_sync(lambda c: [r[0] for r in c.execute("SELECT at_ms FROM events ORDER BY at_ms")])


@pytest.mark.parametrize("bad_kind", ["high", "low"])
async def test_one_unwritable_item_never_blocks_the_database(dbs, bad_kind: str) -> None:
    """MP review F4: a handler error that is not "database unavailable" isolates the bad item instead of
    retrying the whole database forever."""

    def picky(conn: sqlite3.Connection, items: list[Any]) -> None:
        if 13 in items:
            raise ValueError("cannot store item 13")
        _events_handler(conn, items)

    writer = BatchWriter()
    writer.register("high", dbs.metrics, picky if bad_kind == "high" else _events_handler, priority=10)
    writer.register("low", dbs.metrics, picky if bad_kind == "low" else _events_handler, priority=0)
    writer.add_many("high", [10, 11, 12, 13, 14, 15] if bad_kind == "high" else [10, 11, 12, 14, 15])
    writer.add_many("low", [1, 2, 13, 3] if bad_kind == "low" else [1, 2, 3])
    result = await writer.flush()
    assert result.written == {"high": 5, "low": 3}
    assert writer.dropped == 1
    assert writer.stats()["kinds"][bad_kind]["dropped"] == 1
    assert writer.queued() == 0
    assert 13 not in _rows(dbs)
    assert len(_rows(dbs)) == 8
    writer.add("low", 4)
    assert (await writer.flush()).failed_dbs == []  # nothing is stuck
    writer.add_many("high", [20, 13])
    sync_result = writer.flush_now()  # the shutdown flush isolates too
    assert sync_result.written.get("high", 0) == (1 if bad_kind == "high" else 2)


async def test_canceled_flush_puts_the_unwritten_items_back(dbs) -> None:
    """MP review F7: a flush canceled while its write waits in the queue must not lose the drained items."""
    import threading

    writer = BatchWriter()
    writer.register("event", dbs.metrics, _events_handler)
    busy, release = threading.Event(), threading.Event()

    def hold_writer(conn: sqlite3.Connection) -> None:
        busy.set()
        release.wait(5)

    holder = asyncio.create_task(dbs.metrics.write(hold_writer))
    await asyncio.to_thread(busy.wait, 5)
    writer.add_many("event", list(range(10)))
    flushing = asyncio.create_task(writer.flush())
    await asyncio.sleep(0.05)  # the flush drained the queue and its write waits behind hold_writer
    flushing.cancel()
    with pytest.raises(asyncio.CancelledError):
        await flushing
    release.set()
    await holder
    assert writer.queued() == 10
    assert writer.flush_now().written == {"event": 10}
    assert _rows(dbs) == list(range(10))


async def test_canceled_flush_never_doubles_a_write_that_started(dbs) -> None:
    import threading

    started, release = threading.Event(), threading.Event()

    def slow(conn: sqlite3.Connection, items: list[Any]) -> None:
        started.set()
        release.wait(5)
        _events_handler(conn, items)

    writer = BatchWriter()
    writer.register("event", dbs.metrics, slow)
    writer.add_many("event", [1, 2, 3])
    flushing = asyncio.create_task(writer.flush())
    await asyncio.to_thread(started.wait, 5)
    flushing.cancel()
    with pytest.raises(asyncio.CancelledError):
        await flushing
    release.set()
    for _ in range(100):  # the started write finishes on the writer thread
        if len(_rows(dbs)) == 3:
            break
        await asyncio.sleep(0.02)
    assert _rows(dbs) == [1, 2, 3]
    assert writer.queued() == 0  # not put back, so never written twice


async def test_requeue_keeps_higher_priority_items(dbs) -> None:
    """MP review F8: putting items back follows the same priorities as add()."""
    writer = BatchWriter(max_items=10)

    def failing_rollups(conn: sqlite3.Connection, items: list[Any]) -> None:
        for i in range(10):
            writer.add("low", 100 + i)  # low priority events arrive while the flush is failing
        raise SharedStateUnavailable("metrics", "locked for the test")

    writer.register("high", dbs.metrics, failing_rollups, priority=10)
    writer.register("low", dbs.hot, _gate_handler, priority=0)
    writer.add_many("high", list(range(10)))
    result = await writer.flush()
    assert result.failed_dbs == ["metrics"]
    kinds = writer.stats()["kinds"]
    assert kinds["high"]["queued"] == 10  # the rollups survive
    assert kinds["low"]["queued"] == 0  # the newer, lower priority events made room
    assert kinds["low"]["dropped"] == 10
    assert kinds["high"]["dropped"] == 0


async def test_sources_are_drained_at_flush(dbs) -> None:
    pending = {"items": [10, 11]}

    def source() -> list[Any]:
        items, pending["items"] = pending["items"], []
        return items

    writer = BatchWriter()
    writer.register("event", dbs.metrics, _events_handler, source=source)
    assert (await writer.flush()).written == {"event": 2}
    assert (await writer.flush()).written == {}
    assert _count(dbs.metrics, "events") == 2


async def test_run_loop_flushes_periodically_and_on_stop(dbs) -> None:
    writer = BatchWriter()
    writer.register("event", dbs.metrics, _events_handler)
    stop = asyncio.Event()
    task = asyncio.create_task(writer.run(lambda: 0.05, stop))
    writer.add("event", 1)
    for _ in range(100):
        if _count(dbs.metrics, "events") == 1:
            break
        await asyncio.sleep(0.02)
    assert _count(dbs.metrics, "events") == 1
    writer.add("event", 2)
    stop.set()
    await asyncio.wait_for(task, 5)
    assert _count(dbs.metrics, "events") == 2
    assert writer.flushes >= 2


def test_duplicate_kind_is_rejected(dbs) -> None:
    writer = BatchWriter()
    writer.register("event", dbs.metrics, _events_handler)
    with pytest.raises(ValueError):
        writer.register("event", dbs.metrics, _events_handler)
    assert writer.kinds() == ["event"]
