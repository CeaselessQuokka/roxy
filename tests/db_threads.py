"""The database thread guard of the test suite: every test module closes the databases it opened (gaps_insights G8).

What this is
    The helpers behind the root `tests/conftest.py` guard: `alive()` lists the running `roxy-db-*` threads (the
    writer and reader threads `roxy.storage.db.Database` starts on first use), `share(databases, owner)` and
    `unshare(databases)` mark databases a broader fixture keeps open on purpose (the e2e session's dashboard),
    `describe(thread)` names a thread's database, whether it is closed and which test started it. Imported as
    `db_threads` (the root conftest puts `tests/` on `sys.path`, like `pages_harness`).

Why it exists
    A database someone forgot to close keeps its threads (daemon threads, so the process still exits) and its file
    handles until the test process ends, and a test that counts database threads then fails far from the cause:
    `tests/unit/storage/test_storage_db.py::test_close_stops_threads_and_refuses_new_work` failed in the full run
    because the e2e session's dashboard server kept its hot.db open until the session ended (finding G8). The guard
    fails the module that leaves a database open, naming the test that opened it.

How it works
    The root conftest notes, after each test, the database threads that test left running (`note_started`), and at
    the end of each module fails when a thread started in it is still alive after a short grace (a lifespan shutdown
    may still be closing), unless its database is shared (`share`) by a fixture that outlives the module and
    `unshare`s it when it closes them. At the end of the session any database thread still alive is reported.

What to read next
    `tests/conftest.py` (the fixtures), `tests/e2e/conftest.py` (the one shared dashboard), `roxy/storage/db.py`.
"""

from __future__ import annotations

import threading
import time
import weakref
from collections.abc import Iterable
from typing import Any, Final

THREAD_PREFIX: Final = "roxy-db-"
"""`roxy.storage.db._ConnectionThread` names: `roxy-db-<database>-<role>-<index>`."""
GRACE_S: Final = 5.0
"""How long the guard waits for threads of databases that are still closing (a lifespan's shutdown runs on its
own thread in the page harness)."""

_shared: weakref.WeakKeyDictionary[Any, str] = weakref.WeakKeyDictionary()
_started_by: weakref.WeakKeyDictionary[threading.Thread, str] = weakref.WeakKeyDictionary()


def alive() -> set[threading.Thread]:
    """The running database threads of this process."""
    return {t for t in threading.enumerate() if t.name.startswith(THREAD_PREFIX) and t.is_alive()}


def _database_of(thread: threading.Thread) -> Any:
    return getattr(thread, "_db", None)


def share(databases: Any, owner: str) -> None:
    """Mark every database of a `Databases` set (or one `Database`) as kept open on purpose by `owner`."""
    for db in _each(databases):
        _shared[db] = owner


def unshare(databases: Any) -> None:
    """The owner closed them (or is about to): the guard checks their threads again."""
    for db in _each(databases):
        _shared.pop(db, None)


def _each(databases: Any) -> Iterable[Any]:
    every = getattr(databases, "all", None)
    return list(every()) if callable(every) else [databases]


def is_shared(thread: threading.Thread) -> bool:
    db = _database_of(thread)
    return db is not None and db in _shared


def note_started(threads: Iterable[threading.Thread], nodeid: str) -> None:
    """Remember which test left these threads running (the first test that did)."""
    for thread in threads:
        _started_by.setdefault(thread, nodeid)


def still_running(threads: Iterable[threading.Thread], grace_s: float = GRACE_S) -> list[threading.Thread]:
    """The threads (not shared) still alive after waiting up to `grace_s` in total for them to end."""
    deadline = time.monotonic() + grace_s
    left = []
    for thread in sorted(threads, key=lambda t: t.name):
        if is_shared(thread):
            continue
        thread.join(max(0.0, deadline - time.monotonic()))
        if thread.is_alive():
            left.append(thread)
    return left


def describe(thread: threading.Thread) -> str:
    """`<thread> (<database path>, never closed | closed but still running), started by <test>`."""
    db = _database_of(thread)
    state = "closed but still running" if getattr(db, "_closed", False) else "never closed"
    where = getattr(db, "path", "?")
    return f"{thread.name} ({where}, {state}), started by {_started_by.get(thread, 'an earlier fixture')}"


__all__ = [
    "GRACE_S",
    "THREAD_PREFIX",
    "alive",
    "describe",
    "is_shared",
    "note_started",
    "share",
    "still_running",
    "unshare",
]
