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
    - Waiting for the lock (finding LOAD-3). Every request writes hot.db at least once and every worker process
      competes for its ONE write lock. SQLite's own busy handler sleeps longer and longer between tries (1, 2, 5,
      10 ... 100 ms), so a worker that found the lock taken a few times slept through most of the moments it was
      free while the other worker took it again and again: writes queued up (p99 30 to 135 ms, about 205 requests
      a second at most on the development machine). The writer thread therefore waits in short polls: SQLite
      waits at most `LOCK_POLL_MS` per try, and the thread tries again until the job's budget (or the profile's
      `busy_timeout`) runs out (`_begin_polling`). Every worker waits the same way, so none falls behind for long.
    - Group commit on hot.db, only in a backlog (finding LOAD-3). A transaction holds the lock for much longer than
      its SQL takes: the writer thread gives up the GIL inside every SQLite call and may wait for the event loop to
      hand it back. When at least `GROUP_MIN_QUEUE` writes wait behind the one it takes, the writer of a database
      whose profile says `group_writes` takes the hot-path writes already queued (a write with a busy budget; up
      to `GROUP_MAX_JOBS`, while the group has held the lock less than `GROUP_MAX_MS`) and runs them in ONE
      `BEGIN IMMEDIATE ... COMMIT`, one after another. Each write keeps its own atomicity (every write after the
      first runs inside a savepoint, so a failing one undoes only its own changes and gets its own exception), its
      own order (a read-then-write job sees every earlier job's rows, so limits stay exact, plan C6), its own
      budget (a job whose deadline passed while the group waited is refused, never run), and its own result, which
      its caller receives only after COMMIT: if the transaction is lost, every job of it gets
      `SharedStateUnavailable` (it did not happen, plan C7). One lock acquisition and one commit then serve many
      requests instead of one each. Below the backlog every write keeps a transaction of its own (the shortest
      lock holds), and writes without a budget (admin changes, leader jobs, migrations) always do.
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
from collections import deque
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
    group_writes: bool = False  # hot-path writes queued together share one transaction (group commit)


PROFILES: dict[str, DbProfile] = {
    # control.db holds settings, rules, users and the audit log: every commit must survive a power cut, so
    # synchronous=FULL (an fsync on every commit; admin writes are rare, so the cost does not matter).
    "control": DbProfile(
        "control", "FULL", writer_cache_kib=2048, reader_cache_kib=1024, mmap_bytes=0, foreign_keys=True
    ),
    # hot.db is written on every request. NORMAL in WAL mode cannot corrupt the file; a power cut can only lose
    # the last moments of limiter state, which is acceptable. temp_store=MEMORY keeps sort scratch off disk. Its
    # hot-path writes (the abuse transaction, bucket reservations, leases) are grouped: every worker writes it per
    # request and the workers share its one write lock (LOAD-3, module docstring).
    "hot": DbProfile(
        "hot",
        "NORMAL",
        writer_cache_kib=4096,
        reader_cache_kib=1024,
        mmap_bytes=0,
        temp_store_memory=True,
        group_writes=True,
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


GROUP_MAX_JOBS = 64
"""Most hot-path writes that share one transaction (group commit, see the module docstring)."""

GROUP_MAX_MS = 10.0
"""A group neither takes nor starts more writes once it has held the write lock this long (the rest wait for the
next transaction), so the other workers get the lock back quickly. Without this bound a group that grew to 64
writes while it waited for the lock held it for up to a second when this worker's event loop kept the GIL busy."""

GROUP_MIN_QUEUE = 8
"""Group commit starts only when at least this many writes wait in the queue behind the one the writer takes (a
backlog). Measured in the load harness: below the ceiling, single transactions keep the shortest lock holds (cache
hit p99 24 ms against 70 ms with groups at 200 requests a second); in a backlog, groups answer more (about 310
requests a second against 270 at 450 and 600 offered) with far shorter waits (p95 inside Roxy 93 to 150 ms against
305 to 543 ms)."""

LOCK_POLL_MS = 2
"""While a writer waits for another worker's write lock, SQLite's busy handler waits at most this long at a time
before the writer thread tries again (`_begin_polling`), so the wait never stretches into SQLite's 10 to 100 ms
sleeps while the lock is free."""

_GROUP_SAVEPOINT = "roxy_group_write"
"""The savepoint around each grouped write after the first, so one write's failure undoes only that write."""


def _groupable(job: _Job) -> bool:
    """A hot-path write: it carries a busy budget (it is small and has a fallback) and takes the write lock."""
    return job.deadline is not None and job.begin == "BEGIN IMMEDIATE"


@dataclass(slots=True)
class _Outcome:
    """What one grouped job did, held until the group's COMMIT decides whether it happened."""

    job: _Job
    ok: bool  # its function returned (`value` is the result) or raised (`value` is what its caller gets)
    value: Any
    lost: bool = False  # the group's transaction is gone with it (or its state is unknown)
    broken: bool = False  # the connection must be reopened


TIMING_BOUNDS_MS: tuple[float, ...] = (0.1, 0.25, 0.5, 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000)
"""Upper bounds of the write timing histograms (`DbStats.lock_wait_hist`, `hold_hist`); one more bucket above."""


def _bucket(ms: float) -> int:
    """The histogram bucket of a duration (the last bucket holds everything above the last bound)."""
    for index, bound in enumerate(TIMING_BOUNDS_MS):
        if ms <= bound:
            return index
    return len(TIMING_BOUNDS_MS)


def histogram_summary(counts: list[int]) -> dict[str, float | int | None]:
    """`{n, p50, p95, p99}` of a timing histogram, each percentile the upper bound of its bucket (None above the
    last bound, or when empty). Coarse on purpose: it is cheap to keep on every write and says what matters (is
    the lock wait a fraction of a millisecond, a few milliseconds, or a hundred?)."""
    total = sum(counts)
    out: dict[str, float | int | None] = {"n": total}
    for name, share in (("p50", 0.5), ("p95", 0.95), ("p99", 0.99)):
        if not total:
            out[name] = None
            continue
        rank, seen = share * total, 0
        for index, count in enumerate(counts):
            seen += count
            if seen >= rank:
                out[name] = TIMING_BOUNDS_MS[index] if index < len(TIMING_BOUNDS_MS) else None
                break
    top = max((index for index, count in enumerate(counts) if count), default=None)
    # The bucket of the slowest transaction (its upper bound; None above the last bound or when empty).
    out["max"] = None if top is None or top >= len(TIMING_BOUNDS_MS) else TIMING_BOUNDS_MS[top]
    return out


def _empty_hist() -> list[int]:
    return [0] * (len(TIMING_BOUNDS_MS) + 1)


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
    groups: int = 0  # transactions that carried more than one hot-path write (group commit)
    grouped_writes: int = 0  # hot-path writes that shared their transaction with others
    largest_group: int = 0  # the most hot-path writes one transaction carried
    # Per write transaction of the writer thread: how long BEGIN IMMEDIATE waited for the write lock (another
    # worker held it), and how long this worker then held it (until COMMIT or ROLLBACK). Fixed buckets
    # (`TIMING_BOUNDS_MS`), so the p99 of every transaction since start is known, not only the last one.
    lock_wait_hist: list[int] = field(default_factory=_empty_hist)
    hold_hist: list[int] = field(default_factory=_empty_hist)

    def note_transaction(self, lock_wait_ms: float, hold_ms: float) -> None:
        self.lock_wait_hist[_bucket(lock_wait_ms)] += 1
        self.hold_hist[_bucket(hold_ms)] += 1

    def timing(self) -> dict[str, dict[str, float | int | None]]:
        """Lock wait and lock hold percentiles of the writer's transactions (the System page, LOAD-3)."""
        return {"lock_wait_ms": histogram_summary(self.lock_wait_hist), "hold_ms": histogram_summary(self.hold_hist)}


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
        # Jobs taken from the queue by a group that must run after it (an ordinary write, the stop marker, or the
        # rest of a group whose transaction was lost). Taken before the queue, in order. Bounded by GROUP_MAX_JOBS.
        self._carry: deque[_Job | None] = deque()
        self._grouping = role == "writer" and db.profile.group_writes

    def run(self) -> None:
        while True:
            job = self._carry.popleft() if self._carry else self._jobs.get()
            if job is None:
                break
            if self._grouping and _groupable(job) and len(self._carry) + self._jobs.qsize() >= GROUP_MIN_QUEUE:
                self._run_group(job)  # a backlog of hot-path writes: one transaction for many (GROUP_MIN_QUEUE)
                continue
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
        lock_deadline: float | None = None
        if self.role == "writer":
            wait_ms = db.profile.busy_timeout_ms if busy_ms is None else busy_ms
            if job.begin == "BEGIN IMMEDIATE":
                # Wait for the write lock in short polls (`_begin_polling`), like a group does: every writer of every
                # worker then waits the same way, so none sleeps through SQLite's long backoff while the others
                # take turns (an ordinary write starved behind grouped ones held up its whole queue).
                self._set_busy_timeout(LOCK_POLL_MS)
                lock_deadline = time.monotonic() + wait_ms / 1000
            else:
                self._set_busy_timeout(wait_ms)  # a deferred write waits inside its statements: SQLite's handler
        try:
            result = db._transact(self._conn, job.fn, job.begin, self.role, lock_deadline=lock_deadline)
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

    # ---- group commit (hot-path writes; the module docstring explains why) ----

    def _take_more(self, group: list[_Job]) -> None:
        """Move hot-path writes that are already waiting (carried first, then queued) into `group`, without waiting
        for new ones. An ordinary write or the stop marker ends the group and runs right after it, in order."""
        while len(group) < GROUP_MAX_JOBS:
            if self._carry:
                carried = self._carry[0]
                if carried is None or not _groupable(carried):
                    return
                self._carry.popleft()
                group.append(carried)
                continue
            try:
                job = self._jobs.get_nowait()
            except queue.Empty:
                return
            if job is None or not _groupable(job):
                self._carry.append(job)
                return
            group.append(job)

    def _start_grouped(self, job: _Job) -> bool:
        """Mark a grouped job running just before its function runs; False when it must not run (its caller went
        away, or its budget ran out while it waited for the lock or for the writes ahead of it)."""
        if not job.future.set_running_or_notify_cancel():
            return False
        if job.deadline is not None and time.monotonic() >= job.deadline:
            db = self._db
            db.stats.deadline_failures += 1
            db.stats.unavailable += 1
            job.future.set_exception(SharedStateUnavailable(db.name, f"write budget of {job.busy_ms} ms ran out"))
            return False
        return True

    def _fail_unstarted(self, jobs: list[_Job], error: Callable[[], BaseException]) -> int:
        """Answer every job whose caller still waits with `error()` (a fresh exception each); how many there were."""
        failed = 0
        for job in jobs:
            if job.future.set_running_or_notify_cancel():
                job.future.set_exception(error())
                failed += 1
        return failed

    def _job_error(self, exc: BaseException) -> BaseException:
        """How a job's own exception reaches its caller (the mapping of `Database._transact`)."""
        db = self._db
        db._count_error("writer")
        if is_unavailable_error(exc):
            db.stats.unavailable += 1
            return SharedStateUnavailable(db.name, exc)
        return exc

    def _run_group(self, first: _Job) -> None:
        """Run `first` and the hot-path writes queued with it in ONE `BEGIN IMMEDIATE ... COMMIT` (group commit).

        Each job is still atomic on its own: every job after the first runs inside a savepoint, so a failing job
        undoes only its own changes and gets its own exception. Jobs run one after another on this thread, exactly as
        separate transactions would, so a read-then-write job sees every earlier job's rows (limits stay exact,
        plan C6). Results are handed out only after COMMIT: a caller never sees a value that was not committed, and
        when the transaction is lost every job of it gets `SharedStateUnavailable` ("did not happen").
        """
        group = [first]
        try:
            self._group(group)
        except BaseException as exc:  # a bug here must never stop the writer thread or strand a caller
            log.exception("db_group_failed", extra={"fields": {"db": self._db.name}})
            if self._conn is not None:
                _rollback_quietly(self._conn)
            for job in group:
                if job.future.done() or any(job is carried for carried in self._carry):
                    continue  # answered already, or handed on to run in the next transaction
                if job.future.running() or job.future.set_running_or_notify_cancel():
                    job.future.set_exception(SharedStateUnavailable(self._db.name, exc))

    def _group(self, group: list[_Job]) -> None:
        """The body of `_run_group` (`group` holds the first job and grows as jobs are taken)."""
        db = self._db
        self._take_more(group)
        remaining = db._busy_until - time.monotonic()
        if remaining > 0:
            # The busy circuit is open (see `_run`): every job of the group fails at once.
            for job in group:
                if job.future.set_running_or_notify_cancel():
                    db.stats.fast_failures += 1
                    db.stats.unavailable += 1
                    job.future.set_exception(
                        SharedStateUnavailable(db.name, f"database is busy (retrying in {remaining:.1f} s)")
                    )
            return
        if self._conn is None:
            try:
                self._conn = connect(db.path, db.profile, self.role)
            except (sqlite3.Error, OSError) as exc:
                cause = exc
                self._fail_unstarted(group, lambda: db._translate(cause))
                return
            self._busy_ms = db.profile.busy_timeout_ms
        conn = self._conn
        full_wait = any((job.busy_ms or 0) >= db.profile.busy_timeout_ms for job in group)
        started = time.perf_counter()
        try:
            if not self._begin_group(conn, group):
                return  # every caller of the group gave up while it waited for the lock: nothing to run
        except sqlite3.Error as exc:
            db._count_error("writer")
            failure = exc
            now = time.monotonic()
            # Jobs past their deadline ran out of budget waiting for another worker's lock (counted like the ones
            # their callers gave up on); `_fail_unstarted` skips jobs already answered.
            late = sum(1 for job in group if job.deadline is not None and job.deadline <= now and not job.future.done())
            if self._fail_unstarted(group, lambda: db._translate(failure)):
                db.stats.deadline_failures += late
            if _is_broken_error(exc):
                self._close()
                db.stats.reconnects += 1
            elif full_wait and _is_lock_timeout(exc):
                db._busy_until = time.monotonic() + BUSY_CIRCUIT_COOLDOWN_S
            return
        locked = time.perf_counter()
        done: list[_Outcome] = []
        index = 0
        while True:
            held_ms = (time.perf_counter() - locked) * 1000
            if index >= len(group) and held_ms < GROUP_MAX_MS:
                self._take_more(group)  # writes queued while this group waited for the lock or ran
            if index >= len(group):
                break
            if done and held_ms >= GROUP_MAX_MS:
                # The group held the lock long enough (a slow job, or the GIL busy elsewhere in this worker): commit
                # what ran and leave the rest for the next transaction, so the other workers get the lock now.
                self._carry.extendleft(reversed(group[index:]))
                break
            job = group[index]
            index += 1
            if not self._start_grouped(job):
                continue
            # The first job of the transaction needs no savepoint: if it fails, nothing else is lost.
            outcome = self._run_in_savepoint(conn, job) if done else self._run_first(conn, job)
            done.append(outcome)
            if outcome.lost or not conn.in_transaction:
                # The first job failed (rolled back; nothing else had run), or SQLite rolled the whole transaction
                # back under a later one (an I/O error, a full disk, out of memory): what had succeeded did not
                # happen. The jobs not reached yet run in a new transaction.
                _rollback_quietly(conn)
                self._finish_lost(done, outcome.value)
                if outcome.broken:
                    self._close()
                    db.stats.reconnects += 1
                self._carry.extendleft(reversed(group[index:]))
                return
        if not done:
            _rollback_quietly(conn)  # every job was canceled or out of time: nothing to commit
            return
        try:
            conn.execute("COMMIT")
        except BaseException as exc:
            _rollback_quietly(conn)
            db._count_error("writer")
            self._finish_lost(done, exc)
            if _is_broken_error(exc):
                self._close()
                db.stats.reconnects += 1
            return
        finished = time.perf_counter()
        db.stats.note_transaction((locked - started) * 1000, (finished - locked) * 1000)
        elapsed_ms = (finished - started) * 1000
        db.stats.last_write_ms = elapsed_ms
        db.stats.max_write_ms = max(db.stats.max_write_ms, elapsed_ms)
        if len(done) > 1:
            db.stats.groups += 1
            db.stats.grouped_writes += len(done)
            db.stats.largest_group = max(db.stats.largest_group, len(done))
        db._busy_until = 0.0
        for outcome in done:
            if outcome.ok:
                db.stats.writes += 1
                outcome.job.future.set_result(outcome.value)
            else:
                outcome.job.future.set_exception(outcome.value)

    def _begin_group(self, conn: sqlite3.Connection, group: list[_Job]) -> bool:
        """`BEGIN IMMEDIATE` for a group, waiting for the write lock in short polls until the most patient job's
        deadline. False (no transaction) when every caller of the group gave up meanwhile; raises the last
        `sqlite3.Error` when the lock stayed taken (or anything else went wrong).

        SQLite's own busy handler sleeps longer and longer between tries (1, 2, 5, 10 ... 100 ms), so while another
        worker takes and frees the lock many times a second, a waiting worker sleeps through most of the moments
        it was free and falls further behind. Here SQLite waits at most `LOCK_POLL_MS` at a time (it sleeps 1 ms,
        then 1 ms more) and this loop tries again, so the wait never escalates. Each try needs the GIL back, which
        is why the poll is not shorter.
        """
        self._set_busy_timeout(LOCK_POLL_MS)

        def still_wanted() -> bool:
            if all(job.future.cancelled() for job in group):
                return False
            self._take_more(group)  # writes queued meanwhile wait for the same lock
            return True

        return _begin_polling(conn, "BEGIN IMMEDIATE", lambda: max(job.deadline or 0.0 for job in group), still_wanted)

    def _run_first(self, conn: sqlite3.Connection, job: _Job) -> _Outcome:
        """The first job of a group's transaction, run as a plain write: on failure the whole (one job) transaction
        is rolled back, exactly as `Database._transact` does."""
        try:
            return _Outcome(job, True, job.fn(conn))
        except BaseException as exc:
            _rollback_quietly(conn)
            return _Outcome(job, False, self._job_error(exc), lost=True, broken=_is_broken_error(exc))

    def _run_in_savepoint(self, conn: sqlite3.Connection, job: _Job) -> _Outcome:
        """A later job of a group, inside a savepoint: its failure undoes its own changes and nothing else."""
        try:
            conn.execute(f"SAVEPOINT {_GROUP_SAVEPOINT}")
        except sqlite3.Error as exc:  # the transaction is in an unknown state: treat it as lost
            return _Outcome(job, False, self._job_error(exc), lost=True, broken=_is_broken_error(exc))
        try:
            value = job.fn(conn)
        except BaseException as exc:
            lost = _is_broken_error(exc)
            try:
                if conn.in_transaction:
                    conn.execute(f"ROLLBACK TO {_GROUP_SAVEPOINT}")
                    conn.execute(f"RELEASE {_GROUP_SAVEPOINT}")
            except sqlite3.Error:
                lost = True
            return _Outcome(job, False, self._job_error(exc), lost=lost, broken=_is_broken_error(exc))
        try:
            conn.execute(f"RELEASE {_GROUP_SAVEPOINT}")
        except sqlite3.Error as exc:
            return _Outcome(job, False, self._job_error(exc), lost=True, broken=_is_broken_error(exc))
        return _Outcome(job, True, value)

    def _finish_lost(self, done: list[_Outcome], cause: BaseException) -> None:
        """The group's transaction is gone: jobs whose function had returned did not happen after all."""
        db = self._db
        for outcome in done:
            if outcome.ok:
                db.stats.unavailable += 1
                outcome.job.future.set_exception(SharedStateUnavailable(db.name, cause))
            else:
                outcome.job.future.set_exception(outcome.value)

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
        self,
        conn: sqlite3.Connection,
        fn: Callable[[sqlite3.Connection], T],
        begin: str,
        role: ConnRole,
        *,
        lock_deadline: float | None = None,
    ) -> T:
        """Run `fn` between `begin` and COMMIT on `conn`; roll back and re-raise on any exception. With
        `lock_deadline` (the writer thread), `begin` waits for the lock in short polls until then (`_begin_polling`;
        the caller set the connection's busy timeout to `LOCK_POLL_MS`)."""
        started = time.perf_counter()
        try:
            if lock_deadline is None:
                conn.execute(begin)
            else:
                _begin_polling(conn, begin, lambda: lock_deadline)
        except sqlite3.Error as exc:
            self._count_error(role)
            raise self._translate(exc) from exc
        locked = time.perf_counter()
        try:
            result = fn(conn)
            conn.execute("COMMIT")
            if role != "reader":
                self.stats.note_transaction((locked - started) * 1000, (time.perf_counter() - locked) * 1000)
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


def _begin_polling(
    conn: sqlite3.Connection,
    begin: str,
    deadline: Callable[[], float],
    still_wanted: Callable[[], bool] | None = None,
) -> bool:
    """Run `begin` on a connection whose busy timeout is `LOCK_POLL_MS`, trying again until `deadline()` (monotonic).

    True once the transaction began; False when `still_wanted()` says nobody waits for it any more; the last
    `sqlite3.Error` when the lock stayed taken past the deadline (or any other error, at once).
    """
    while True:
        try:
            conn.execute(begin)
            return True
        except sqlite3.Error as exc:
            if not _is_lock_timeout(exc) or time.monotonic() >= deadline():
                raise
        if still_wanted is not None and not still_wanted():
            return False


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
