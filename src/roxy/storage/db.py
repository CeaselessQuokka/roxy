"""SQLite access for every worker: one writer thread and two reader threads per database file.

What this is
    `Database` wraps one SQLite file (control, hot, metrics or cache). Async code calls `await db.write(fn)` or
    `await db.read(fn)` with a small function that receives a `sqlite3.Connection`; the function runs on a
    background thread inside a transaction and its return value comes back to the caller. `Databases` holds the
    four files and `open_databases(env)` builds them from the `ROXY_STATE_DIR` and `ROXY_*_DB` settings.

Why it exists
    SQLite calls block. Running one on the asyncio event loop freezes every request in that worker for as long
    as the call takes (and gunicorn's watchdog kills a loop frozen for 30 s, plan 5.2). Moving each call to a
    thread keeps the loop free. A single writer thread per database per process also means this process never
    competes with itself for SQLite's one write lock; it only waits for other processes, which `busy_timeout`
    handles.

How it works
    - Writes go to one thread with its own connection. Each write runs inside `BEGIN IMMEDIATE ... COMMIT`.
      IMMEDIATE takes the database write lock at the start, so a read-then-write function (read a counter,
      decide, update it) can never interleave with another process's write: this is what makes limits exact
      across workers (plan C6). On an exception the transaction is rolled back and the exception re-raised.
    - Reads go to two reader threads, each with its own (thread local) connection, inside a deferred
      `BEGIN ... COMMIT`, so a function that runs several SELECTs sees one consistent snapshot. In WAL mode
      readers never wait for the writer and the writer never waits for readers.
    - If SQLite reports that the file is locked for longer than `busy_timeout` (5 s), or an I/O, disk full or
      corruption error (or the operating system refuses to open the file at all), the caller gets
      `SharedStateUnavailable`. Callers use it to fail closed (plan C7): no credential use, no tarpit hold, no
      admin login, conservative per-worker limits.
    - A busy circuit stops one long lock from turning into a queue of long waits. Jobs run one after another on
      the writer thread, so without it the Nth queued write would only learn that the file is locked after
      N x 5 s. When a write gives up after the full `busy_timeout`, the database is marked busy for
      `BUSY_CIRCUIT_COOLDOWN_S`: jobs that reach the writer during that time fail at once, and the first job
      after it is the probe that waits the full timeout again. So no caller waits much longer than one
      `busy_timeout`.
    - A caller on a hot path passes a shorter `busy_timeout_ms` to `write`, and that budget is a DEADLINE measured
      from the moment the job is queued, not a wait that starts when the writer thread reaches the job. Head of
      line blocking is the reason: a short budget that restarted per job would make the Nth of N queued hot-path
      writes wait N x the budget while another process holds the lock (and a 5 s job ahead of it would add 5 s
      more). So the writer gives a job only what is left of its budget as SQLite's busy timeout, fails a job whose
      deadline already passed without running it, and the waiting coroutine stops waiting at its deadline: if the
      job has not started it is canceled (it never runs) and the caller gets `SharedStateUnavailable`; if it is
      already running, its own busy timeout (the remaining budget) ends it within moments, commit or rollback,
      so a caller is never told "unavailable" about a write that later commits.
    - Every queue is bounded (plan P9): when more than `MAX_PENDING_JOBS` operations are waiting, new ones fail
      fast with `SharedStateUnavailable` instead of piling up memory.
    - `write_sync` and `read_sync` do the same work on the calling thread, for scripts, migrations and tests.
      Never call them from the event loop thread of a running server.
    - PRAGMAs per plan 6.1 with the memory sizes from DESIGN.md section 0 (the production box has 909 MB).

What to read next
    `roxy/storage/migrate.py` (the schema), `roxy/storage/leases.py` (functions you pass to `write`), and
    `roxy/storage/batch.py` (how metrics are written in batches instead of per request).
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import logging
import os
import queue
import sqlite3
import stat
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, TypeVar

log = logging.getLogger(__name__)

T = TypeVar("T")

DB_NAMES: tuple[str, ...] = ("control", "hot", "metrics", "cache")
"""The four database files, in the order they are opened and migrated."""

BUSY_TIMEOUT_MS = 5000
"""How long SQLite retries a locked database before giving up (plan 6.1). Then `SharedStateUnavailable`."""

WAL_AUTOCHECKPOINT_PAGES = 1000
"""Copy the WAL back into the database file after about 1000 pages (4 MiB) of new writes (plan 6.5)."""

JOURNAL_SIZE_LIMIT_BYTES = 64 * 1024 * 1024
"""Shrink the WAL file back to at most 64 MiB after a checkpoint, so it cannot grow forever (plan 6.1)."""

READER_THREADS = 2
"""Reader threads (and connections) per database per worker (plan 6.1 sizes the page caches for two)."""

MAX_PENDING_JOBS = 10_000
"""Bound on queued operations per database per worker (plan P9). Beyond it, callers fail fast."""

BUSY_CIRCUIT_COOLDOWN_S = 2.0
"""After a write gave up on a locked database, writes fail at once for this long (see the module docstring)."""

DEFAULT_STATE_DIR = Path("/var/lib/roxy")
"""Where systemd's `StateDirectory=roxy` puts state in production (plan 17.1)."""

STATE_DIR_MODE = 0o750
"""Owner can do everything, the `roxy` group can read, nobody else can even list it (plan 17.1)."""

DB_FILE_MODE = 0o640
"""New database files: owner read/write, group read, others nothing (matches systemd `UMask=0027`)."""

ConnRole = Literal["writer", "reader", "maintenance"]


@dataclass(frozen=True, slots=True)
class DbProfile:
    """The PRAGMA settings for one database file.

    Cache sizes are per connection, in KiB, from DESIGN.md section 0 (the plan's sizes scaled down for the
    909 MB production box). Each worker has one writer connection and two reader connections per file.
    """

    name: str
    synchronous: Literal["FULL", "NORMAL"]
    writer_cache_kib: int
    reader_cache_kib: int
    mmap_bytes: int
    foreign_keys: bool = False
    temp_store_memory: bool = False
    busy_timeout_ms: int = BUSY_TIMEOUT_MS  # tests lower it with dataclasses.replace() to see busy errors fast


PROFILES: dict[str, DbProfile] = {
    # control.db holds settings, rules, users and the audit log: every commit must survive a power cut, so
    # synchronous=FULL (an fsync on every commit; admin writes are rare, so the cost does not matter).
    "control": DbProfile(
        "control", "FULL", writer_cache_kib=2048, reader_cache_kib=1024, mmap_bytes=0, foreign_keys=True
    ),
    # hot.db is written on every request. NORMAL in WAL mode cannot corrupt the file; a power cut can only lose
    # the last moments of limiter state, which is acceptable. temp_store=MEMORY keeps sort scratch off disk.
    "hot": DbProfile(
        "hot", "NORMAL", writer_cache_kib=4096, reader_cache_kib=1024, mmap_bytes=0, temp_store_memory=True
    ),
    "metrics": DbProfile("metrics", "NORMAL", writer_cache_kib=8192, reader_cache_kib=2048, mmap_bytes=0),
    # cache.db reads large bodies; memory mapping 32 MiB of it lets reads skip a copy (DESIGN.md section 0).
    "cache": DbProfile("cache", "NORMAL", writer_cache_kib=4096, reader_cache_kib=2048, mmap_bytes=32 * 1024 * 1024),
}


class SharedStateUnavailable(Exception):
    """Shared state in a database could not be read or written (plan C7 trigger).

    Raised when SQLite stays locked past `busy_timeout`, on I/O, disk full or corruption errors, when the
    per-database queue is full, or after the database was closed. Callers decide what failing closed means for
    them (no credential use, no tarpit hold, refuse admin login, conservative per-worker limits).
    """

    def __init__(self, db_name: str, cause: BaseException | str) -> None:
        self.db_name = db_name
        self.cause = cause
        super().__init__(f"shared state unavailable in {db_name}.db: {cause}")


# SQLite primary result codes that mean "the shared file cannot be used right now" rather than "your SQL is
# wrong". Extended codes (for example SQLITE_IOERR_FSYNC) keep the primary code in their low 8 bits.
_SQLITE_BUSY = 5
_SQLITE_LOCKED = 6
_SQLITE_NOMEM = 7
_SQLITE_READONLY = 8
_SQLITE_IOERR = 10
_SQLITE_CORRUPT = 11
_SQLITE_FULL = 13
_SQLITE_CANTOPEN = 14
_SQLITE_PROTOCOL = 15
_SQLITE_NOTADB = 26
_UNAVAILABLE_CODES = frozenset(
    {
        _SQLITE_BUSY,
        _SQLITE_LOCKED,
        _SQLITE_NOMEM,
        _SQLITE_READONLY,
        _SQLITE_IOERR,
        _SQLITE_CORRUPT,
        _SQLITE_FULL,
        _SQLITE_CANTOPEN,
        _SQLITE_PROTOCOL,
        _SQLITE_NOTADB,
    }
)
# After these the connection itself may be unusable, so the thread drops it and opens a fresh one next time.
_BROKEN_CODES = frozenset({_SQLITE_IOERR, _SQLITE_CORRUPT, _SQLITE_CANTOPEN, _SQLITE_NOTADB, _SQLITE_NOMEM})
_UNAVAILABLE_TEXT = (
    "database is locked",
    "database table is locked",
    "disk i/o error",
    "unable to open",
    "malformed",
    "not a database",
    "database or disk is full",
    "readonly database",
)


def _primary_code(exc: sqlite3.Error) -> int | None:
    code = getattr(exc, "sqlite_errorcode", None)
    return None if code is None else int(code) & 0xFF


def is_unavailable_error(exc: BaseException) -> bool:
    """True when `exc` means the database file is busy, locked, broken or unreachable (not a SQL mistake)."""
    if not isinstance(exc, sqlite3.Error):
        return False
    code = _primary_code(exc)
    if code is not None:
        return code in _UNAVAILABLE_CODES
    text = str(exc).lower()
    return any(fragment in text for fragment in _UNAVAILABLE_TEXT)


def _is_broken_error(exc: BaseException) -> bool:
    if not isinstance(exc, sqlite3.Error):
        return False
    code = _primary_code(exc)
    return code in _BROKEN_CODES if code is not None else "malformed" in str(exc).lower()


def _is_lock_timeout(exc: BaseException) -> bool:
    """True when `exc` says another connection held the lock until `busy_timeout` ran out (BUSY or LOCKED)."""
    if not isinstance(exc, sqlite3.Error):
        return False
    code = _primary_code(exc)
    if code is not None:
        return code in (_SQLITE_BUSY, _SQLITE_LOCKED)
    text = str(exc).lower()
    return "database is locked" in text or "database table is locked" in text


def connect(path: Path | str, profile: DbProfile, role: ConnRole = "writer") -> sqlite3.Connection:
    """Open one connection to `path` with the PRAGMAs for `profile` and `role`.

    `isolation_level=None` turns off the sqlite3 module's own guessing about when to open transactions: this
    module always says BEGIN and COMMIT itself, so what runs is exactly what you read.
    `check_same_thread=False` is safe because each connection is used by one thread at a time; the flag only
    lets `close()` run from the thread that shuts the database down.
    """
    target = Path(path)
    try:
        existed = target.exists()
    except OSError as exc:
        # For example a state directory this process may not search (EACCES). Reported as SQLite's own "unable to
        # open" error, so every caller turns it into SharedStateUnavailable like any other unreachable file.
        raise sqlite3.OperationalError(f"unable to open database file: {exc.strerror or exc}") from exc
    busy_ms = profile.busy_timeout_ms
    conn = sqlite3.connect(str(target), timeout=busy_ms / 1000, isolation_level=None, check_same_thread=False)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout={int(busy_ms)}")
        if role != "reader":
            # auto_vacuum can only be switched on before the first page is written (plan 6.5), and switching
            # the file to WAL writes the first page, so a brand new file gets it here, before journal_mode.
            if conn.execute("PRAGMA page_count").fetchone()[0] == 0:
                conn.execute("PRAGMA auto_vacuum=INCREMENTAL")
            mode = conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if str(mode).lower() != "wal":
                log.warning("sqlite_wal_unavailable", extra={"fields": {"db": profile.name, "mode": mode}})
        conn.execute(f"PRAGMA synchronous={profile.synchronous}")
        conn.execute(f"PRAGMA foreign_keys={'ON' if profile.foreign_keys else 'OFF'}")
        conn.execute(f"PRAGMA wal_autocheckpoint={WAL_AUTOCHECKPOINT_PAGES}")
        conn.execute(f"PRAGMA journal_size_limit={JOURNAL_SIZE_LIMIT_BYTES}")
        cache_kib = profile.reader_cache_kib if role == "reader" else profile.writer_cache_kib
        if role == "maintenance":
            cache_kib = min(cache_kib, 1024)  # short-lived connection: a small cache is plenty
        # A negative cache_size means KiB instead of pages, so the budget does not depend on the page size.
        conn.execute(f"PRAGMA cache_size={-cache_kib}")
        conn.execute(f"PRAGMA mmap_size={profile.mmap_bytes}")
        if profile.temp_store_memory:
            conn.execute("PRAGMA temp_store=MEMORY")
        if role == "reader":
            # A reader connection refuses to change anything, so a write sent to `read()` by mistake fails loudly
            # instead of slipping past the single-writer design.
            conn.execute("PRAGMA query_only=1")
    except BaseException:
        conn.close()
        raise
    if not existed and target.exists():
        _restrict_file_mode(target)
    return conn


def _restrict_file_mode(path: Path) -> None:
    """Make a newly created database file owner read/write and group read only (best effort)."""
    try:
        os.chmod(path, DB_FILE_MODE)
    except OSError as exc:  # for example a filesystem that does not support modes
        log.warning("db_file_mode_unchanged", extra={"fields": {"path": str(path), "error": str(exc)}})


def ensure_state_dir(path: Path | str) -> Path:
    """Create the state directory with mode 0750 if it is missing, and warn if others can access it.

    In production systemd creates `/var/lib/roxy` (`StateDirectory=roxy`, `StateDirectoryMode=0750`, plan
    17.1), so this only creates directories in development and tests.
    """
    directory = Path(path)
    if not directory.exists():
        directory.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):  # best effort, for example on filesystems without modes
            os.chmod(directory, STATE_DIR_MODE)  # mkdir's mode is reduced by the umask; set it exactly
    else:
        mode = stat.S_IMODE(directory.stat().st_mode)
        if mode & 0o007:
            log.warning(
                "state_dir_too_open",
                extra={"fields": {"path": str(directory), "mode": oct(mode), "expected": oct(STATE_DIR_MODE)}},
            )
    return directory


@dataclass(slots=True)
class _Job:
    fn: Callable[[sqlite3.Connection], Any]
    future: concurrent.futures.Future[Any]
    begin: str
    busy_ms: int | None = None  # a shorter busy_timeout for this one job (writer only), None for the profile's
    deadline: float | None = None  # monotonic time by which a `busy_ms` job must be done waiting (queue included)


@dataclass(slots=True)
class DbStats:
    """Counters for the System page. Updated from worker threads; exact values are not critical."""

    writes: int = 0
    reads: int = 0
    write_errors: int = 0
    unavailable: int = 0
    max_write_ms: float = 0.0
    last_write_ms: float = 0.0
    reconnects: int = 0
    fast_failures: int = 0  # writes refused at once by the busy circuit
    deadline_failures: int = 0  # hot-path writes whose budget ran out while they waited in the queue


class _ConnectionThread(threading.Thread):
    """A thread that owns one connection and runs jobs from a shared queue until it receives `None`."""

    def __init__(self, db: Database, role: ConnRole, jobs: queue.Queue[_Job | None], index: int) -> None:
        # daemon=True: a database someone forgot to close never keeps the interpreter from exiting.
        super().__init__(name=f"roxy-db-{db.name}-{role}-{index}", daemon=True)
        self._db = db
        self.role: ConnRole = role
        self._jobs = jobs
        self._conn: sqlite3.Connection | None = None
        self._busy_ms = db.profile.busy_timeout_ms  # the busy_timeout currently set on self._conn

    def run(self) -> None:
        while True:
            job = self._jobs.get()
            if job is None:
                break
            # A caller that was canceled before its job started gets nothing run on its behalf.
            if not job.future.set_running_or_notify_cancel():
                continue
            try:
                result = self._run(job)
            except BaseException as exc:  # handed to the waiting coroutine, which re-raises it
                job.future.set_exception(exc)
            else:
                job.future.set_result(result)
        self._close()

    def _run(self, job: _Job) -> Any:
        db = self._db
        if self.role == "writer":
            remaining = db._busy_until - time.monotonic()
            if remaining > 0:
                # The busy circuit is open: the last write waited the whole busy_timeout for another process's
                # lock. Failing now (instead of waiting another 5 s behind every queued job) lets the caller fall
                # back at once (plan C7); the first job after the cooldown probes the lock again.
                db.stats.fast_failures += 1
                db.stats.unavailable += 1
                raise SharedStateUnavailable(db.name, f"database is busy (retrying in {remaining:.1f} s)")
        busy_ms = job.busy_ms
        if self.role == "writer" and job.deadline is not None and busy_ms is not None:
            # The budget counts from enqueue time (module docstring): the queue wait is already spent.
            left_ms = (job.deadline - time.monotonic()) * 1000
            if left_ms <= 0:
                db.stats.deadline_failures += 1
                db.stats.unavailable += 1
                raise SharedStateUnavailable(db.name, f"write budget of {busy_ms} ms ran out in the queue")
            # Rounded up to 10 ms, so an uncontended queue (a fraction of a millisecond) keeps the same PRAGMA value.
            busy_ms = max(1, min(busy_ms, -(-int(left_ms) // 10) * 10))
        if self._conn is None:
            try:
                self._conn = connect(db.path, db.profile, self.role)
            except (sqlite3.Error, OSError) as exc:
                raise db._translate(exc) from exc
            self._busy_ms = db.profile.busy_timeout_ms
        full_wait = job.busy_ms is None or job.busy_ms >= db.profile.busy_timeout_ms
        if self.role == "writer":
            self._set_busy_timeout(db.profile.busy_timeout_ms if busy_ms is None else busy_ms)
        try:
            result = db._transact(self._conn, job.fn, job.begin, self.role)
        except SharedStateUnavailable as exc:
            cause = exc.cause if isinstance(exc.cause, BaseException) else None
            if cause is not None and _is_broken_error(cause):
                self._close()  # reopen on the next job
                db.stats.reconnects += 1
            elif self.role == "writer" and full_wait and cause is not None and _is_lock_timeout(cause):
                # Only a write that waited the full timeout opens the circuit: a hot path's short budget running
                # out says little about how long the lock will last.
                db._busy_until = time.monotonic() + BUSY_CIRCUIT_COOLDOWN_S
            raise
        if self.role == "writer":
            db._busy_until = 0.0
        return result

    def _set_busy_timeout(self, busy_ms: int) -> None:
        if self._conn is None or busy_ms == self._busy_ms:
            return
        self._conn.execute(f"PRAGMA busy_timeout={int(busy_ms)}")
        self._busy_ms = busy_ms

    def _close(self) -> None:
        conn, self._conn = self._conn, None
        if conn is None:
            return
        try:
            if self.role == "writer":
                conn.execute("PRAGMA optimize")  # plan 6.5: refresh query planner statistics on close
        except sqlite3.Error:
            pass
        finally:
            conn.close()


class Database:
    """One SQLite file shared by every worker process. See the module docstring for the threading model."""

    def __init__(
        self,
        name: str,
        path: Path | str,
        profile: DbProfile | None = None,
        *,
        readers: int = READER_THREADS,
        max_pending: int = MAX_PENDING_JOBS,
    ) -> None:
        self.name = name
        self.path = Path(path)
        self.profile = profile or PROFILES[name]
        self.stats = DbStats()
        self._readers = readers
        self._write_q: queue.Queue[_Job | None] = queue.Queue(maxsize=max_pending)
        self._read_q: queue.Queue[_Job | None] = queue.Queue(maxsize=max_pending)
        self._threads: list[_ConnectionThread] = []
        # Guards starting the threads, `_closed`, and putting a job in a queue: holding it while checking
        # `_closed` and enqueuing means close() can never slip its stop marker in between (a job queued behind
        # the marker would never run, and its caller would wait forever).
        self._start_lock = threading.Lock()
        self._started = False
        self._closed = False
        self._busy_until = 0.0  # monotonic time until which the busy circuit fails writes at once
        # Connections used by write_sync/read_sync, one per calling thread and role, closed by close().
        self._local = threading.local()
        self._sync_conns: list[sqlite3.Connection] = []
        self._sync_lock = threading.Lock()

    def __repr__(self) -> str:
        return f"Database({self.name!r}, {str(self.path)!r})"

    # ----------------------------------------------------------------------------------------------- async API

    async def write(
        self,
        fn: Callable[[sqlite3.Connection], T],
        *,
        immediate: bool = True,
        busy_timeout_ms: int | None = None,
    ) -> T:
        """Run `fn(conn)` on this database's writer thread inside `BEGIN IMMEDIATE ... COMMIT`.

        `fn` must be quick and must not touch the event loop; return plain values (call `fetchall()` inside
        `fn`, never return a cursor). Exceptions roll the transaction back and are re-raised here. Busy, locked
        and I/O errors become `SharedStateUnavailable`. If the awaiting coroutine is canceled before the job
        starts, it never runs; once it started it finishes (commit or rollback), so it is never half applied.
        `busy_timeout_ms` is a total budget for a hot path that has a better fallback than waiting: measured from
        this call, it covers the wait in this process's queue AND the wait for another process's lock (instead of
        the profile's 5 s per job). When it runs out before the job started, the job is canceled and this raises
        `SharedStateUnavailable` (see the module docstring). A short budget never opens the busy circuit.
        """
        if busy_timeout_ms is not None and busy_timeout_ms < 0:
            raise ValueError("busy_timeout_ms must not be negative")
        deadline = None if busy_timeout_ms is None else time.monotonic() + busy_timeout_ms / 1000
        return await self._submit(
            self._write_q, fn, "BEGIN IMMEDIATE" if immediate else "BEGIN", busy_timeout_ms, deadline
        )

    async def read(self, fn: Callable[[sqlite3.Connection], T]) -> T:
        """Run `fn(conn)` on a reader thread inside one read transaction (one consistent snapshot)."""
        return await self._submit(self._read_q, fn, "BEGIN")

    async def maintenance(self, fn: Callable[[sqlite3.Connection], T]) -> T:
        """Run `fn(conn)` on a short-lived connection with no surrounding transaction, in a worker thread.

        For statements that cannot run inside a transaction or should not hold up the writer thread:
        checkpoints, `incremental_vacuum`, `quick_check`, `optimize`, migrations.
        """
        return await asyncio.to_thread(self.maintenance_sync, fn)

    async def close(self) -> None:
        """Finish queued jobs, stop the threads and close every connection."""
        await asyncio.to_thread(self.close_sync)

    async def _submit(
        self,
        jobs: queue.Queue[_Job | None],
        fn: Callable[[sqlite3.Connection], T],
        begin: str,
        busy_ms: int | None = None,
        deadline: float | None = None,
    ) -> T:
        future: concurrent.futures.Future[T] = concurrent.futures.Future()
        # Checking `_closed` and enqueuing happen under one lock that close() also takes (see __init__). The lock
        # is held only for a non-blocking put, so the event loop never waits on it for long.
        with self._start_lock:
            if self._closed:
                raise SharedStateUnavailable(self.name, "database is closed")
            self._start_threads_locked()
            try:
                jobs.put_nowait(_Job(fn, future, begin, busy_ms, deadline))
            except queue.Full:
                self.stats.unavailable += 1
                raise SharedStateUnavailable(self.name, "too many pending operations") from None
        # wrap_future moves the result from the worker thread back onto this event loop safely. Canceling the
        # awaiting coroutine cancels the wrapper, which cancels a job that has not started (it never runs).
        waiter = asyncio.wrap_future(future)
        if deadline is None:
            return await waiter
        return await self._await_until(waiter, future, deadline, busy_ms)

    async def _await_until(
        self,
        waiter: asyncio.Future[T],
        future: concurrent.futures.Future[T],
        deadline: float,
        busy_ms: int | None,
    ) -> T:
        """Wait for a budgeted job; at its deadline cancel it if it has not started (module docstring)."""
        try:
            # asyncio.wait (unlike wait_for) does not cancel the job when the time is up: we decide below.
            await asyncio.wait({waiter}, timeout=max(0.0, deadline - time.monotonic()))
        except asyncio.CancelledError:
            waiter.cancel()  # the caller went away: a job that has not started must never run
            raise
        if not waiter.done() and future.cancel():
            # Still queued behind other jobs: it never runs, so "unavailable" is exactly what happened.
            self.stats.deadline_failures += 1
            self.stats.unavailable += 1
            raise SharedStateUnavailable(self.name, f"write budget of {busy_ms} ms ran out in the queue")
        # Done, or already running with only what was left of the budget as its busy timeout: it ends promptly.
        return await waiter

    def _start_threads_locked(self) -> None:
        """Start the writer and reader threads on first use. The caller holds `_start_lock`."""
        if self._started:
            return
        threads = [_ConnectionThread(self, "writer", self._write_q, 0)]
        threads += [_ConnectionThread(self, "reader", self._read_q, i) for i in range(self._readers)]
        for thread in threads:
            thread.start()
        self._threads = threads
        self._started = True

    # ------------------------------------------------------------------------------------------------ sync API

    def write_sync(self, fn: Callable[[sqlite3.Connection], T], *, immediate: bool = True) -> T:
        """Same as `write`, on the calling thread. For scripts, migrations and tests only.

        Never call it from inside a function passed to `write` on the same database: the inner call would wait
        for the write lock the outer call holds, until `busy_timeout` gives up.
        """
        conn = self._sync_conn("writer")
        return self._transact(conn, fn, "BEGIN IMMEDIATE" if immediate else "BEGIN", "writer")

    def read_sync(self, fn: Callable[[sqlite3.Connection], T]) -> T:
        """Same as `read`, on the calling thread (one consistent snapshot)."""
        conn = self._sync_conn("reader")
        return self._transact(conn, fn, "BEGIN", "reader")

    def maintenance_sync(self, fn: Callable[[sqlite3.Connection], T]) -> T:
        """Run `fn(conn)` on a fresh connection in autocommit mode (no BEGIN), then close it."""
        if self._closed:
            raise SharedStateUnavailable(self.name, "database is closed")
        try:
            conn = connect(self.path, self.profile, "maintenance")
        except (sqlite3.Error, OSError) as exc:
            raise self._translate(exc) from exc
        try:
            return fn(conn)
        except sqlite3.Error as exc:
            if conn.in_transaction:
                _rollback_quietly(conn)
            raise self._translate(exc) from exc
        finally:
            conn.close()

    def close_sync(self) -> None:
        """Stop accepting work, drain queued jobs, stop threads and close all connections."""
        self.stop_threads()
        self.close_connections()

    def stop_threads(self, timeout_s: float = 30.0) -> None:
        """First half of `close_sync`: let queued jobs finish and stop the threads."""
        with self._start_lock:
            # From here on `_submit` refuses new jobs, so every job already queued sits ahead of the stop markers.
            self._closed = True
            threads, self._threads = self._threads, []
            self._started = False
        for thread in threads:
            target = self._write_q if thread.role == "writer" else self._read_q
            try:
                target.put(None, timeout=timeout_s)
            except queue.Full:
                log.error("db_close_queue_full", extra={"fields": {"db": self.name}})
        deadline = time.monotonic() + timeout_s
        for thread in threads:
            thread.join(max(0.0, deadline - time.monotonic()))
            if thread.is_alive():
                log.error("db_thread_did_not_stop", extra={"fields": {"db": self.name, "thread": thread.name}})
        if not any(thread.is_alive() for thread in threads):
            self._fail_leftover_jobs()

    def _fail_leftover_jobs(self) -> None:
        """Answer every job still queued after the threads stopped, so no caller waits forever."""
        for jobs in (self._write_q, self._read_q):
            while True:
                try:
                    job = jobs.get_nowait()
                except queue.Empty:
                    break
                if job is not None and job.future.set_running_or_notify_cancel():
                    job.future.set_exception(SharedStateUnavailable(self.name, "database is closed"))

    def close_connections(self) -> None:
        """Second half of `close_sync`: close the connections opened by `write_sync` and `read_sync`."""
        self._closed = True
        with self._sync_lock:
            conns, self._sync_conns = self._sync_conns, []
        for conn in conns:
            with contextlib.suppress(sqlite3.Error):
                conn.close()

    def _sync_conn(self, role: ConnRole) -> sqlite3.Connection:
        if self._closed:
            raise SharedStateUnavailable(self.name, "database is closed")
        conn: sqlite3.Connection | None = getattr(self._local, role, None)
        if conn is None:
            try:
                conn = connect(self.path, self.profile, role)
            except (sqlite3.Error, OSError) as exc:
                raise self._translate(exc) from exc
            setattr(self._local, role, conn)
            with self._sync_lock:
                self._sync_conns.append(conn)
        return conn

    # ----------------------------------------------------------------------------------------------- internals

    def _transact(
        self, conn: sqlite3.Connection, fn: Callable[[sqlite3.Connection], T], begin: str, role: ConnRole
    ) -> T:
        """Run `fn` between `begin` and COMMIT on `conn`; roll back and re-raise on any exception."""
        started = time.perf_counter()
        try:
            conn.execute(begin)
        except sqlite3.Error as exc:
            self._count_error(role)
            raise self._translate(exc) from exc
        try:
            result = fn(conn)
            conn.execute("COMMIT")
        except BaseException as exc:
            _rollback_quietly(conn)
            self._count_error(role)
            # On a reader, "readonly" means a write was sent to read() (query_only refused it): a bug in the
            # caller, so it is raised as is instead of being disguised as an unavailable database.
            misuse = role == "reader" and isinstance(exc, sqlite3.Error) and _primary_code(exc) == _SQLITE_READONLY
            if is_unavailable_error(exc) and not misuse:
                self.stats.unavailable += 1
                raise SharedStateUnavailable(self.name, exc) from exc
            raise
        elapsed_ms = (time.perf_counter() - started) * 1000
        if role == "reader":
            self.stats.reads += 1
        else:
            self.stats.writes += 1
            self.stats.last_write_ms = elapsed_ms
            if elapsed_ms > self.stats.max_write_ms:
                self.stats.max_write_ms = elapsed_ms
        return result

    def _count_error(self, role: ConnRole) -> None:
        if role != "reader":
            self.stats.write_errors += 1

    def _translate(self, exc: sqlite3.Error | OSError) -> BaseException:
        # An OSError while opening (permission denied, a missing mount, too many open files) means the shared
        # file cannot be used right now, exactly like SQLite's own "unable to open".
        if isinstance(exc, OSError) or is_unavailable_error(exc):
            self.stats.unavailable += 1
            return SharedStateUnavailable(self.name, exc)
        return exc

    def pending(self) -> dict[str, int]:
        """Queued (not yet started) operations, for the System page."""
        return {"write": self._write_q.qsize(), "read": self._read_q.qsize()}


def _rollback_quietly(conn: sqlite3.Connection) -> None:
    if not conn.in_transaction:
        return
    try:
        conn.execute("ROLLBACK")
    except sqlite3.Error as exc:
        log.warning("db_rollback_failed", extra={"fields": {"error": str(exc)}})


@dataclass
class Databases:
    """The four shared databases of one worker process (`ctx.dbs`)."""

    control: Database
    hot: Database
    metrics: Database
    cache: Database
    paths: dict[str, Path] = field(default_factory=dict)

    def all(self) -> list[Database]:
        """The databases in a fixed order: control, hot, metrics, cache."""
        return [self.control, self.hot, self.metrics, self.cache]

    def get(self, name: str) -> Database:
        """Look a database up by name (`"control"`, `"hot"`, `"metrics"` or `"cache"`)."""
        if name not in DB_NAMES:
            raise KeyError(name)
        db: Database = getattr(self, name)
        return db

    async def close_all(self) -> None:
        """Close every database (queued work finishes first)."""
        await asyncio.to_thread(self.close_all_sync)

    def close_all_sync(self) -> None:
        """Synchronous `close_all`. Stops every thread before closing any connection, because a writer thread of
        one database may hold a read connection to another (leader fencing reads hot.db from other writers)."""
        for db in self.all():
            db.stop_threads()
        for db in self.all():
            db.close_connections()


def _env_value(env: object, *names: str) -> Any:
    """Read the first non-empty value among `names` from an EnvSettings object, any object, or a mapping."""
    for key in names:
        if isinstance(env, Mapping):
            value = env.get(key)
        else:
            value = getattr(env, key, None)
        if value not in (None, ""):
            return value
    return None


def resolve_db_paths(env: object) -> tuple[Path, dict[str, Path]]:
    """Return `(state_dir, {db name: path})` from the environment settings.

    Each database lives at `ROXY_<NAME>_DB` when set, otherwise `<ROXY_STATE_DIR>/<name>.db` (plan 15.3 L).
    Works with `config/env.py`'s `EnvSettings` (lowercase fields) and with any object or mapping that has the
    raw `ROXY_*` names, so tools and tests do not depend on the settings class.
    """
    state_raw = _env_value(env, "state_dir", "roxy_state_dir", "ROXY_STATE_DIR")
    state_dir = Path(state_raw) if state_raw is not None else DEFAULT_STATE_DIR
    paths: dict[str, Path] = {}
    for name in DB_NAMES:
        explicit = _env_value(env, f"{name}_db", f"roxy_{name}_db", f"ROXY_{name.upper()}_DB")
        paths[name] = Path(explicit) if explicit is not None else state_dir / f"{name}.db"
    return state_dir, paths


def open_databases(env: object) -> Databases:
    """Build the four `Database` objects for this worker.

    Creates the state directory (and any custom database directory) with mode 0750 if needed. Connections and
    threads start lazily on first use, so building this is cheap; PRAGMAs are applied as each connection opens.
    """
    state_dir, paths = resolve_db_paths(env)
    ensure_state_dir(state_dir)
    for path in paths.values():
        if path.parent != state_dir:
            ensure_state_dir(path.parent)
    dbs = {name: Database(name, paths[name]) for name in DB_NAMES}
    return Databases(control=dbs["control"], hot=dbs["hot"], metrics=dbs["metrics"], cache=dbs["cache"], paths=paths)
