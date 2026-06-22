"""Cross-process shared JSON state, guarded by an flock.

Small, high-frequency state that MUST be shared across all gunicorn workers — the
per-IP request throttle counters, cross-worker coordination (e.g. email
de-duplication) — lives in a tiny dedicated file, one per concern, separate from
the big diagnostics data file so a per-request read-modify-write stays cheap.

Every mutation goes through `update()`, which holds BOTH:
  - an in-process `threading.Lock` (so threads in one worker can't race), and
  - an inter-process `fcntl.flock` (so the 4 workers can't race),
then writes atomically via `os.replace` (a reader can never observe a torn file).

`read()` returns a lock-free snapshot: because writers always swap the file in
atomically, a reader sees either the whole old file or the whole new one. That
makes hot read paths (e.g. building response headers) cheap while keeping the
authoritative read-modify-writes correct.

This is the same mechanism `storage.py` and `routing.py` use; it's factored here
so every cross-worker counter shares one audited implementation.
"""

import fcntl
import json
import os
import tempfile
from contextlib import contextmanager
from threading import Lock


class LockedJSON:
    def __init__(self, path_getter):
        # A callable so the path is resolved at call time: tests point config at a
        # sandbox, and a getter avoids capturing a stale value at import.
        self._path_getter = path_getter if callable(path_getter) else (lambda: path_getter)
        self._io_lock = Lock()

    @property
    def path(self) -> str:
        return self._path_getter()

    @contextmanager
    def _interprocess_lock(self):
        directory = os.path.dirname(self.path) or "."
        os.makedirs(directory, exist_ok=True)
        lock_file = open(self.path + ".lock", "a+")
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            finally:
                lock_file.close()

    def _load(self) -> dict:
        try:
            with open(self.path, "r", encoding="utf-8") as file:
                data = json.load(file)
                return data if isinstance(data, dict) else {}
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return {}

    def _write(self, data: dict):
        directory = os.path.dirname(self.path) or "."
        os.makedirs(directory, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".roxy_lf_", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as file:
                json.dump(data, file, separators=(",", ":"))
            os.replace(tmp_path, self.path)
        finally:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

    def update(self, mutator):
        """Atomic read-modify-write across threads AND processes.

        `mutator(data)` edits `data` in place and may return a value (forwarded to
        the caller). On a disk failure the change is applied to an in-memory dict so
        the request still flows (rare; the worst case is a single uncoordinated
        decision until the disk recovers)."""
        with self._io_lock:
            try:
                with self._interprocess_lock():
                    data = self._load()
                    result = mutator(data)
                    self._write(data)
                    return result
            except OSError:
                return mutator({})

    def read(self) -> dict:
        """A lock-free snapshot. Atomic os.replace writes can't be read half-written."""
        return self._load()

    def clear(self):
        self.update(lambda data: data.clear())
