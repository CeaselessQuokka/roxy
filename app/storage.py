import config
import fcntl
import json
import os
import shutil
import tempfile
import time
from contextlib import contextmanager
from threading import Lock, Thread

# Guards this process's writers. The fcntl lock below guards across processes
# (e.g. multiple gunicorn workers) so the shared data file is never corrupted.
_io_lock = Lock()

# Persistence health, surfaced on the admin dashboard so a broken data file
# (permissions, full disk...) is visible instead of silently eating stats.
_status_lock = Lock()
_last_write_ok = 0.0
_last_error = ""
_last_error_at = 0.0
_write_count = 0
BACKUP_EVERY = 50  # Copy the data file to .bak every N successful writes.


def _record_write_ok():
    global _last_write_ok, _write_count
    with _status_lock:
        _last_write_ok = time.time()
        _write_count += 1
        return _write_count


def _record_write_error(error: Exception):
    global _last_error, _last_error_at
    with _status_lock:
        _last_error = f"{type(error).__name__}: {error}"
        _last_error_at = time.time()


def get_status() -> dict:
    """Persistence health for the dashboard."""
    directory = os.path.dirname(config.DATA_FILE) or "."
    try:
        writable = os.access(directory, os.W_OK) and (
            not os.path.exists(config.DATA_FILE) or os.access(config.DATA_FILE, os.W_OK)
        )
    except OSError:
        writable = False
    with _status_lock:
        return {
            "DataFile": config.DATA_FILE,
            "Writable": writable,
            "LastWriteOK": _last_write_ok,
            "LastError": _last_error,
            "LastErrorAt": _last_error_at,
        }


def _lock_path() -> str:
    return config.DATA_FILE + ".lock"


def _backup_path() -> str:
    return config.DATA_FILE + ".bak"


@contextmanager
def _interprocess_lock():
    """Exclusive lock shared across all processes touching the data file."""
    directory = os.path.dirname(config.DATA_FILE) or "."
    os.makedirs(directory, exist_ok=True)
    lock_file = open(_lock_path(), "a+")
    try:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        finally:
            lock_file.close()


def load_data() -> dict:
    """Load the persisted state file, falling back to the rolling backup.

    A corrupt main file is quarantined (renamed aside) instead of being
    silently overwritten, so stats are never lost without a trace.
    """
    try:
        with open(config.DATA_FILE, "r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        pass
    except json.JSONDecodeError:
        try:
            os.replace(config.DATA_FILE, config.DATA_FILE + f".corrupt-{int(time.time())}")
        except OSError:
            pass
    except OSError:
        pass
    try:
        with open(_backup_path(), "r", encoding="utf-8") as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def get_mtime() -> float:
    """Last-modified time of the data file (0.0 if it doesn't exist yet)."""
    try:
        return os.path.getmtime(config.DATA_FILE)
    except OSError:
        return 0.0


def _write_atomic(data: dict):
    directory = os.path.dirname(config.DATA_FILE) or "."
    os.makedirs(directory, exist_ok=True)
    # Write to a temp file in the same directory, then atomically replace.
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".roxy_data_", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(data, file, separators=(",", ":"))  # Minified.
        os.replace(tmp_path, config.DATA_FILE)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def _after_successful_write():
    """Bookkeeping + rolling backup. Called while holding the write locks."""
    count = _record_write_ok()
    if count % BACKUP_EVERY == 0:
        try:
            shutil.copy2(config.DATA_FILE, _backup_path())
        except OSError:
            pass  # Backups are best-effort.


def save_data(data: dict) -> bool:
    """Atomically write minified JSON to disk. Returns True on success."""
    with _io_lock:
        try:
            with _interprocess_lock():
                _write_atomic(data)
                _after_successful_write()
            return True
        except OSError as error:
            _record_write_error(error)
            return False


def update_data(mutator) -> dict:
    """Locked read-modify-write of the whole data file.

    `mutator(data)` may edit `data` in place and/or return a replacement dict.
    The whole operation is atomic across threads AND processes, so concurrent
    gunicorn workers can each update their own sub-keys without clobbering.
    Returns the final data dict that was written.
    """
    with _io_lock:
        try:
            with _interprocess_lock():
                data = load_data()
                result = mutator(data)
                if result is not None:
                    data = result
                _write_atomic(data)
                _after_successful_write()
                return data
        except OSError as error:
            _record_write_error(error)
            raise


def start_autosave(flush):
    """Start a background thread that periodically calls `flush()`.

    The interval is read from runtime settings each cycle so it can be tuned live.
    """

    def loop():
        while True:
            try:
                import runtime

                interval = runtime.get_setting("autosave_interval") or config.AUTOSAVE_INTERVAL
            except Exception:
                interval = config.AUTOSAVE_INTERVAL
            time.sleep(max(1, int(interval)))
            try:
                flush()
            except Exception:
                # Persistence must never crash the app; ignore and retry next cycle.
                pass

    thread = Thread(target=loop, daemon=True)
    thread.start()
    return thread
