"""Multi-process correctness of the storage layer and leader election (plan 19.3, C6).

Every test starts real operating system processes (multiprocessing with the `spawn` start method, like separate
gunicorn workers) that share temporary SQLite files, and checks a property that must hold across processes:

1. N processes x M read-modify-write increments through `db.write` lose no update (with 1, 2 and 4 processes).
2. Exactly one leader among 4 processes, and among two groups of 2 simulating blue and green; when the leader is
   killed (SIGKILL), another process leads within the 15 s lease TTL, under the next epoch.
3. A leader that stalls (SIGSTOP) past its lease and then resumes cannot write: epoch fencing.
4. Counted slot leases (the tarpit cap) never exceed the cap under contention from 16 holders in 4 processes.
5. Readers in another process are never blocked by a long write.
6. Group commit (LOAD-3): hot-path writes that share a transaction lose no update with 1, 2 and 4 processes.
Plus measurements of p50/p99 latency of a small hot.db write transaction under 4-process contention, and of write
throughput with and without group commit under 2-process contention, printed for docs/PERFORMANCE.md.
"""

from __future__ import annotations

import asyncio
import multiprocessing as mp
import os
import random
import signal
import sqlite3
import statistics
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from roxy.scheduler.leader import LEADER_RENEW_S, LEADER_TTL_S, LeaderElector, LostLeadership
from roxy.storage import leases
from roxy.storage.db import DB_NAMES, Database, SharedStateUnavailable
from roxy.storage.migrate import migrate_paths

pytestmark = [
    pytest.mark.multiprocess,
    pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX signals (SIGSTOP, SIGKILL)"),
]

CTX = mp.get_context("spawn")

SCRATCH_DDL = """
CREATE TABLE IF NOT EXISTS mp_counter (id INTEGER PRIMARY KEY, n INTEGER NOT NULL);
INSERT OR IGNORE INTO mp_counter (id, n) VALUES (1, 0);
CREATE TABLE IF NOT EXISTS mp_leader_log (id INTEGER PRIMARY KEY, holder TEXT, epoch INTEGER, at_ms INTEGER);
CREATE TABLE IF NOT EXISTS mp_slot_obs (id INTEGER PRIMARY KEY, holders INTEGER);
"""


@pytest.fixture
def hot_path(tmp_path: Path) -> Path:
    """Migrated databases in a temp dir, plus scratch tables in hot.db for the tests. Returns hot.db's path."""
    paths = {name: tmp_path / f"{name}.db" for name in DB_NAMES}
    migrate_paths(paths)
    conn = sqlite3.connect(str(paths["hot"]))
    conn.executescript(SCRATCH_DDL)
    conn.close()
    return paths["hot"]


@pytest.fixture
def procs() -> Iterator[list[Any]]:
    """Processes started by a test; any still alive at the end are resumed and killed."""
    started: list[Any] = []
    yield started
    for proc in started:
        if proc.is_alive():
            if proc.pid:
                os.kill(proc.pid, signal.SIGCONT)
            proc.kill()
        proc.join(5)


def _start(procs: list[Any], target: Any, *args: Any) -> Any:
    proc = CTX.Process(target=target, args=args, daemon=True)
    proc.start()
    procs.append(proc)
    return proc


def _join_all(procs: list[Any], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    for proc in procs:
        proc.join(max(0.1, deadline - time.monotonic()))
    stuck = [p for p in procs if p.is_alive()]
    assert not stuck, f"processes did not finish: {stuck}"
    assert all(p.exitcode == 0 for p in procs), [p.exitcode for p in procs]


def _query(path: Path, sql: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    conn = sqlite3.connect(str(path), timeout=10)
    try:
        return [tuple(r) for r in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


# ------------------------------------------------------------------------------------- 1. no lost updates


def _child_increment(path: str, increments: int, concurrency: int) -> None:
    asyncio.run(_increment(path, increments, concurrency))


async def _increment(path: str, increments: int, concurrency: int) -> None:
    db = Database("hot", path)

    def read_modify_write(conn: sqlite3.Connection) -> None:
        # Read, decide in Python, write back: only correct if no other process can write in between, which is
        # exactly what BEGIN IMMEDIATE guarantees.
        n = conn.execute("SELECT n FROM mp_counter WHERE id = 1").fetchone()[0]
        conn.execute("UPDATE mp_counter SET n = ? WHERE id = 1", (n + 1,))

    gate = asyncio.Semaphore(concurrency)

    async def one() -> None:
        async with gate:
            await db.write(read_modify_write)

    await asyncio.gather(*(one() for _ in range(increments)))
    await db.close()


@pytest.mark.parametrize("workers", [1, 2, 4])
def test_no_lost_updates_across_processes(hot_path: Path, procs: list[Any], workers: int) -> None:
    increments = 300
    for _ in range(workers):
        _start(procs, _child_increment, str(hot_path), increments, 8)
    _join_all(procs, 90)
    assert _query(hot_path, "SELECT n FROM mp_counter WHERE id = 1") == [(workers * increments,)]


# ------------------------------------------------------------------------------------- 2. one leader


def _child_leader(path: str, holder: str, ttl_s: float, renew_s: float, flags: Any, index: int, stop: Any) -> None:
    asyncio.run(_leader_main(path, holder, ttl_s, renew_s, flags, index, stop))


async def _leader_main(path: str, holder: str, ttl_s: float, renew_s: float, flags: Any, index: int, stop: Any) -> None:
    hot = Database("hot", path)
    elector = LeaderElector(hot, holder, ttl_s=ttl_s, renew_s=renew_s)
    local_stop = asyncio.Event()
    election = asyncio.create_task(elector.run(local_stop))
    try:
        while not stop.is_set():
            flags[index] = 1 if elector.is_leader else 0
            if elector.is_leader:
                try:
                    ctx = elector.job_context("mp")
                    await ctx.fenced_write(
                        hot,
                        lambda c, e=ctx.epoch: c.execute(
                            "INSERT INTO mp_leader_log (holder, epoch, at_ms) VALUES (?, ?, ?)", (holder, e, _now_ms())
                        ),
                    )
                except (LostLeadership, SharedStateUnavailable):
                    pass
            await asyncio.sleep(0.02)
    finally:
        flags[index] = 0
        local_stop.set()
        await election
        await hot.close()


def _wait_for(predicate: Any, timeout: float, interval: float = 0.02) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return bool(predicate())


def _sample_leaders(flags: Any, seconds: float, ignore: frozenset[int] = frozenset()) -> list[int]:
    counts = []
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        counts.append(sum(v for i, v in enumerate(flags[:]) if i not in ignore))
        time.sleep(0.01)
    return counts


def test_exactly_one_leader_among_four_processes(hot_path: Path, procs: list[Any]) -> None:
    flags = CTX.Array("i", 4)
    stop = CTX.Event()
    for i in range(4):
        _start(procs, _child_leader, str(hot_path), f"w{i}", 2.0, 0.5, flags, i, stop)
    assert _wait_for(lambda: sum(flags[:]) == 1, 20), "no leader was elected"
    counts = _sample_leaders(flags, 2.0)
    stop.set()
    _join_all(procs, 30)
    assert max(counts) == 1, "two processes believed they were the leader at the same time"
    assert min(counts) == 1
    pairs = _query(hot_path, "SELECT DISTINCT holder, epoch FROM mp_leader_log")
    assert len(pairs) == 1, pairs  # one leader, one epoch, nobody else ever wrote


def test_one_leader_across_blue_and_green_and_fast_takeover(
    hot_path: Path, procs: list[Any], capsys: pytest.CaptureFixture[str]
) -> None:
    holders = ["blue-0", "blue-1", "green-0", "green-1"]
    flags = CTX.Array("i", len(holders))
    stop = CTX.Event()
    # The real production timings: TTL 15 s, renew every 5 s (plan 5.6).
    for i, holder in enumerate(holders):
        _start(procs, _child_leader, str(hot_path), holder, LEADER_TTL_S, LEADER_RENEW_S, flags, i, stop)
    assert _wait_for(lambda: sum(flags[:]) == 1, 20), "no leader was elected"
    counts = _sample_leaders(flags, 1.5)
    assert max(counts) == 1
    assert min(counts) == 1

    leader_index = flags[:].index(1)
    old_holder, old_epoch, _ = _query(hot_path, "SELECT holder, epoch, expires_ms FROM lease WHERE name = 'leader'")[0]
    assert old_holder == holders[leader_index]
    killed_at = time.monotonic()
    procs[leader_index].kill()  # SIGKILL: no lease release, exactly like a crash

    def taken_over() -> bool:
        rows = _query(hot_path, "SELECT holder, expires_ms FROM lease WHERE name = 'leader'")
        return bool(rows) and rows[0][0] != old_holder and rows[0][1] > _now_ms()

    assert _wait_for(taken_over, LEADER_TTL_S + 5, interval=0.05), "nobody took over"
    takeover_s = time.monotonic() - killed_at
    new_holder, new_epoch = _query(hot_path, "SELECT holder, epoch FROM lease WHERE name = 'leader'")[0]
    alive = {i for i in range(len(holders)) if i != leader_index}
    assert _wait_for(lambda: sum(flags[i] for i in alive) == 1, 5)
    after = _sample_leaders(flags, 1.0, ignore=frozenset({leader_index}))
    stop.set()
    _join_all([p for i, p in enumerate(procs) if i != leader_index], 30)
    with capsys.disabled():
        print(
            f"\n[leader takeover] {old_holder} killed, {new_holder} leads after {takeover_s:.2f} s "
            f"(TTL {LEADER_TTL_S:.0f} s, epoch {old_epoch} -> {new_epoch})"
        )
    assert takeover_s <= LEADER_TTL_S + 1.0
    assert new_epoch == old_epoch + 1
    assert max(after) == 1
    # Per epoch, exactly one holder ever wrote.
    per_epoch = _query(hot_path, "SELECT epoch, count(DISTINCT holder) FROM mp_leader_log GROUP BY epoch")
    assert all(n == 1 for _, n in per_epoch)


# ------------------------------------------------------------------------------------- 3. epoch fencing


def _child_stalled_leader(
    path: str, holder: str, ttl_s: float, renew_s: float, ready: Any, results: Any, stop: Any
) -> None:
    asyncio.run(_stalled_main(path, holder, ttl_s, renew_s, ready, results, stop))


async def _stalled_main(
    path: str, holder: str, ttl_s: float, renew_s: float, ready: Any, results: Any, stop: Any
) -> None:
    hot = Database("hot", path)
    elector = LeaderElector(hot, holder, ttl_s=ttl_s, renew_s=renew_s)
    local_stop = asyncio.Event()
    election = asyncio.create_task(elector.run(local_stop))
    while not elector.is_leader:  # noqa: ASYNC110 (polls another task's state; there is no event to wait on)
        await asyncio.sleep(0.01)
    ctx = elector.job_context("mp")  # a long job: the epoch is captured once, when it starts
    ready.put((holder, ctx.epoch))
    writes = lost = 0
    while not stop.is_set():
        try:
            await ctx.fenced_write(
                hot,
                lambda c: c.execute(
                    "INSERT INTO mp_leader_log (holder, epoch, at_ms) VALUES (?, ?, ?)", (holder, ctx.epoch, _now_ms())
                ),
            )
            writes += 1
        except LostLeadership:
            lost += 1
        except SharedStateUnavailable:
            pass
        await asyncio.sleep(0.01)
    results.put((holder, writes, lost))
    local_stop.set()
    await election
    await hot.close()


def _stop_outside_write(path: Path, pid: int) -> None:
    """SIGSTOP `pid` at a moment when it does not hold hot.db's write lock (else nobody could take over)."""
    for _ in range(50):
        os.kill(pid, signal.SIGSTOP)
        probe = sqlite3.connect(str(path), timeout=0.2, isolation_level=None)
        try:
            probe.execute("BEGIN IMMEDIATE")
            probe.execute("ROLLBACK")
            return
        except sqlite3.OperationalError:
            os.kill(pid, signal.SIGCONT)
            time.sleep(0.02)
        finally:
            probe.close()
    raise AssertionError("could not stop the leader outside a write transaction")


def test_stalled_leader_cannot_write_after_losing_its_lease(hot_path: Path, procs: list[Any]) -> None:
    ttl_s, renew_s = 1.5, 0.3
    ready = CTX.Queue()
    results = CTX.Queue()
    stop = CTX.Event()
    stalled = _start(procs, _child_stalled_leader, str(hot_path), "stalled", ttl_s, renew_s, ready, results, stop)
    holder_a, epoch_a = ready.get(timeout=30)
    assert _wait_for(lambda: _query(hot_path, "SELECT count(*) FROM mp_leader_log")[0][0] >= 5, 10)

    _stop_outside_write(hot_path, stalled.pid)  # the leader freezes (GC pause, VM stall, SIGSTOP)
    flags = CTX.Array("i", 1)
    _start(procs, _child_leader, str(hot_path), "successor", ttl_s, renew_s, flags, 0, stop)
    assert _wait_for(
        lambda: _query(hot_path, "SELECT count(*) FROM mp_leader_log WHERE holder = 'successor'")[0][0] >= 3, 20
    ), "the successor never took over"
    os.kill(stalled.pid, signal.SIGCONT)  # the old leader wakes up and carries on with its job
    time.sleep(1.0)
    stop.set()
    _join_all(procs, 30)

    holder, writes, lost = results.get(timeout=10)
    assert holder == holder_a
    assert writes >= 5
    assert lost >= 1, "the resumed leader was never refused"
    rows = _query(hot_path, "SELECT id, holder, epoch FROM mp_leader_log ORDER BY id")
    first_successor = next(i for i, (_, h, _) in enumerate(rows) if h == "successor")
    successor_epoch = rows[first_successor][2]
    assert successor_epoch == epoch_a + 1
    late = [r for r in rows[first_successor:] if r[1] == holder_a]
    assert late == [], f"the stalled leader wrote after the takeover: {late[:3]}"


# ------------------------------------------------------------------------------------- 4. slot cap


def _child_slots(path: str, name: str, holders: int, cap: int, seconds: float, results: Any) -> None:
    asyncio.run(_slots_main(path, name, holders, cap, seconds, results))


async def _slots_main(path: str, name: str, holders: int, cap: int, seconds: float, results: Any) -> None:
    hot = Database("hot", path)
    stats = {"max": 0, "acquired": 0, "refused": 0}
    end = time.monotonic() + seconds

    async def holder_loop(holder: str) -> None:
        while time.monotonic() < end:

            def take(conn: sqlite3.Connection) -> tuple[str | None, int]:
                now = _now_ms()
                slot = leases.acquire_slot(conn, "tarpit:", holder, cap, 5000, now)
                count = leases.count_slots(conn, "tarpit:", now)
                if slot is not None:
                    conn.execute("INSERT INTO mp_slot_obs (holders) VALUES (?)", (count,))
                return slot, count

            slot, count = await hot.write(take)
            stats["max"] = max(stats["max"], count)
            if slot is None:
                stats["refused"] += 1
                await asyncio.sleep(0.002)
                continue
            stats["acquired"] += 1
            await asyncio.sleep(random.uniform(0.0, 0.01))  # hold the slot (a tarpit hold) for a moment
            await hot.write(lambda c, s=slot: leases.release(c, s, holder))

    await asyncio.gather(*(holder_loop(f"{name}-{k}") for k in range(holders)))
    results.put((name, stats["max"], stats["acquired"], stats["refused"]))
    await hot.close()


def test_slot_leases_never_exceed_the_cap(hot_path: Path, procs: list[Any]) -> None:
    cap = 3
    results = CTX.Queue()
    for i in range(4):
        _start(procs, _child_slots, str(hot_path), f"p{i}", 4, cap, 3.0, results)  # 16 holders, cap 3
    sampled = []
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        sampled.append(
            _query(hot_path, "SELECT count(*) FROM lease WHERE name LIKE 'tarpit:%' AND expires_ms > ?", (_now_ms(),))[
                0
            ][0]
        )
        time.sleep(0.01)
    _join_all(procs, 60)
    reports = [results.get(timeout=10) for _ in range(4)]
    assert max(r[1] for r in reports) <= cap
    assert max(sampled) <= cap
    observed_max, observations = _query(hot_path, "SELECT max(holders), count(*) FROM mp_slot_obs")[0]
    assert observed_max == cap  # contention was real: the cap was reached
    assert observations == sum(r[2] for r in reports)
    assert sum(r[3] for r in reports) > 0  # and holders were refused
    assert _query(hot_path, "SELECT count(*) FROM lease WHERE name LIKE 'tarpit:%'")[0][0] <= cap  # bounded rows


# ------------------------------------------------------------------------------------- 5. readers not blocked


def _child_long_writer(path: str, hold_s: float, in_write: Any, results: Any) -> None:
    async def main() -> None:
        db = Database("hot", path)

        def long_write(conn: sqlite3.Connection) -> None:
            conn.execute("INSERT INTO mp_counter (id, n) VALUES (2, 0)")
            in_write.set()
            time.sleep(hold_s)  # holds hot.db's write lock the whole time

        started = time.monotonic()
        await db.write(long_write)
        results.put(("writer", time.monotonic() - started))
        await db.close()

    asyncio.run(main())


def _child_reader(path: str, in_write: Any, reads: int, results: Any) -> None:
    async def main() -> None:
        db = Database("hot", path)
        in_write.wait(30)
        latencies = []
        counts = []
        for _ in range(reads):
            t0 = time.monotonic()
            counts.append(await db.read(lambda c: c.execute("SELECT count(*) FROM mp_counter").fetchone()[0]))
            latencies.append(time.monotonic() - t0)
            await asyncio.sleep(0.02)
        results.put(("reader", max(latencies), counts))
        await db.close()

    asyncio.run(main())


def test_readers_are_never_blocked_by_a_long_write(hot_path: Path, procs: list[Any]) -> None:
    in_write = CTX.Event()
    results = CTX.Queue()
    _start(procs, _child_long_writer, str(hot_path), 2.0, in_write, results)
    _start(procs, _child_reader, str(hot_path), in_write, 30, results)
    _join_all(procs, 60)
    report = {r[0]: r[1:] for r in (results.get(timeout=10), results.get(timeout=10))}
    writer_seconds = report["writer"][0]
    max_read_s, counts = report["reader"]
    assert writer_seconds >= 2.0
    assert max_read_s < 0.25, f"a read waited {max_read_s:.3f} s behind the writer"
    assert counts[0] == 1  # reads during the write see the last committed snapshot, not the pending row
    assert set(counts) <= {1, 2}


# ------------------------------------------------------------------------------------- latency measurement


def _child_latency(path: str, name: str, operations: int, results: Any, start: Any, rate_per_s: float) -> None:
    async def main() -> None:
        db = Database("hot", path)
        rng = random.Random(name)
        start.wait(30)
        next_at = time.perf_counter()
        latencies = []
        for _ in range(operations):
            key = f"ip:198.51.100.{rng.randrange(256)}"

            def admit(conn: sqlite3.Connection, k: str = key) -> None:
                # The shape of a per-IP limiter admit (plan 6.3, abuse transaction): one upsert by primary key.
                now = _now_ms()
                conn.execute(
                    "INSERT INTO limiter (bucket_key, tat_ms, window_start, count, updated_at) VALUES (?, ?, ?, 1, ?)"
                    " ON CONFLICT (bucket_key) DO UPDATE SET count = count + 1,"
                    " tat_ms = max(tat_ms, excluded.tat_ms), updated_at = excluded.updated_at",
                    (k, now + 5000, now // 1000, now // 1000),
                )

            t0 = time.perf_counter()
            await db.write(admit)
            latencies.append((time.perf_counter() - t0) * 1000)
            if rate_per_s > 0:
                # Paced mode: random (Poisson) arrivals averaging rate_per_s, like independent callers.
                # Evenly spaced arrivals would make the processes collide in lockstep every time.
                next_at += rng.expovariate(rate_per_s)
                await asyncio.sleep(max(0.0, next_at - time.perf_counter()))
        results.put(latencies)
        await db.close()

    asyncio.run(main())


def _percentile(values: list[float], pct: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, round(pct / 100 * (len(ordered) - 1)))]


def test_hot_write_latency_under_four_process_contention(
    hot_path: Path, procs: list[Any], capsys: pytest.CaptureFixture[str]
) -> None:
    # (label, processes, writes per process, writes per second per process; 0 = as fast as possible)
    scenarios = [
        ("1 process, saturated", 1, 1000, 0.0),
        ("4 processes, saturated", 4, 1000, 0.0),
        ("4 processes, Poisson arrivals 4 x 50/s = 200/s (plan 6.7 load)", 4, 500, 50.0),
    ]
    measured: dict[str, tuple[float, float, float, int]] = {}
    for label, workers, operations, rate in scenarios:
        procs.clear()
        start = CTX.Event()
        results = CTX.Queue()
        for i in range(workers):
            _start(procs, _child_latency, str(hot_path), f"{label}-{i}", operations, results, start, rate)
        time.sleep(1.0)  # let every process import and open its connection before the clock starts
        start.set()
        samples: list[float] = []
        for _ in range(workers):
            samples.extend(results.get(timeout=60))
        _join_all(procs, 30)
        measured[label] = (
            _percentile(samples, 50),
            _percentile(samples, 99),
            statistics.fmean(samples),
            len(samples),
        )
    with capsys.disabled():
        print(f"\n[hot.db write latency] SQLite {sqlite3.sqlite_version}, {os.cpu_count()} CPUs (dev machine, WSL)")
        for label, (p50, p99, mean, n) in measured.items():
            print(f"[hot.db write latency] {label}: {n} writes, p50 {p50:.3f} ms, p99 {p99:.3f} ms, mean {mean:.3f} ms")
    p50, p99, _, _ = measured["4 processes, saturated"]
    assert p50 < 50
    assert p99 < 1000


# ------------------------------------------------------------------------------------- 6. group commit (LOAD-3)


def _child_grouped(
    path: str, increments: int, concurrency: int, budget_ms: int | None, results: Any, start: Any
) -> None:
    asyncio.run(_grouped_main(path, increments, concurrency, budget_ms, results, start))


async def _grouped_main(
    path: str, increments: int, concurrency: int, budget_ms: int | None, results: Any, start: Any
) -> None:
    db = Database("hot", path)
    await db.write(lambda c: None)  # threads and connection ready before the clock starts
    start.wait(30)

    def read_modify_write(conn: sqlite3.Connection) -> None:
        # The shape of a limiter (plan 6.3): read a row, decide in Python, write it back.
        n = conn.execute("SELECT n FROM mp_counter WHERE id = 1").fetchone()[0]
        conn.execute("UPDATE mp_counter SET n = ? WHERE id = 1", (n + 1,))

    gate = asyncio.Semaphore(concurrency)
    latencies: list[float] = []
    failed = 0

    async def one() -> None:
        nonlocal failed
        async with gate:
            t0 = time.perf_counter()
            try:
                await db.write(read_modify_write, busy_timeout_ms=budget_ms)
            except SharedStateUnavailable:
                failed += 1
            latencies.append((time.perf_counter() - t0) * 1000)

    began = time.perf_counter()
    await asyncio.gather(*(one() for _ in range(increments)))
    seconds = time.perf_counter() - began
    results.put((db.stats.writes - 1, db.stats.grouped_writes, db.stats.largest_group, failed, seconds, latencies))
    await db.close()


@pytest.mark.parametrize("workers", [1, 2, 4])
def test_grouped_hot_path_writes_lose_no_update_across_processes(
    hot_path: Path, procs: list[Any], workers: int
) -> None:
    """LOAD-3: hot-path writes (a busy budget) queued together share one transaction (group commit). A read, decide,
    write job inside a group still sees every write before it, of its own group and of the other processes', so no
    update is lost with 1, 2 or 4 processes (plan C6), and the writes really were grouped."""
    increments = 400
    results = CTX.Queue()
    start = CTX.Event()
    for _ in range(workers):
        _start(procs, _child_grouped, str(hot_path), increments, 64, 10_000, results, start)
    time.sleep(1.0)
    start.set()
    _join_all(procs, 120)
    reports = [results.get(timeout=10) for _ in range(workers)]
    assert sum(r[3] for r in reports) == 0  # nothing ran out of its 10 s budget
    assert sum(r[0] for r in reports) == workers * increments
    assert _query(hot_path, "SELECT n FROM mp_counter WHERE id = 1") == [(workers * increments,)]
    assert max(r[2] for r in reports) > 1  # transactions carried several writes
    assert sum(r[1] for r in reports) > 0


def test_group_commit_throughput_under_two_process_contention(
    hot_path: Path, procs: list[Any], capsys: pytest.CaptureFixture[str]
) -> None:
    """Measurement for docs/PERFORMANCE.md (LOAD-3): two processes, 32 concurrent read, decide, write jobs each, as
    ordinary writes (one transaction each) and as hot-path writes (grouped). Prints writes a second and latency; the
    assertion is only that both lose nothing."""
    measured: dict[str, tuple[float, float, float, int]] = {}
    total = 0
    for label, budget in (("one transaction per write", None), ("group commit (budgeted writes)", 10_000)):
        procs.clear()
        results = CTX.Queue()
        start = CTX.Event()
        for _ in range(2):
            _start(procs, _child_grouped, str(hot_path), 1500, 32, budget, results, start)
        time.sleep(1.0)
        start.set()
        _join_all(procs, 180)
        reports = [results.get(timeout=10) for _ in range(2)]
        assert sum(r[3] for r in reports) == 0
        total += sum(r[0] for r in reports)
        samples = [ms for r in reports for ms in r[5]]
        rate = sum(r[0] for r in reports) / max(r[4] for r in reports)
        largest = max(r[2] for r in reports) or 1  # 0 means no transaction ever carried more than one write
        measured[label] = (rate, _percentile(samples, 50), _percentile(samples, 99), largest)
    assert _query(hot_path, "SELECT n FROM mp_counter WHERE id = 1") == [(total,)]
    with capsys.disabled():
        for label, (rate, p50, p99, largest) in measured.items():
            print(
                f"\n[hot.db group commit] 2 processes x 32 concurrent jobs, {label}: {rate:,.0f} writes/s, "
                f"p50 {p50:.2f} ms, p99 {p99:.2f} ms, largest transaction {largest} writes"
            )
