import config
import json
import os
import tempfile
import time
from threading import Lock, Thread

_io_lock = Lock()


def load_data() -> dict:
    """Load the persisted state file. Returns an empty dict if missing or unreadable."""
    try:
        with open(config.DATA_FILE, "r", encoding="utf-8") as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def save_data(data: dict) -> bool:
    """Atomically write minified JSON to disk. Returns True on success."""
    with _io_lock:
        try:
            directory = os.path.dirname(config.DATA_FILE) or "."
            os.makedirs(directory, exist_ok=True)
            # Write to a temp file in the same directory, then atomically replace.
            fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".roxy_data_", suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as file:
                    json.dump(data, file, separators=(",", ":"))  # Minified.
                os.replace(tmp_path, config.DATA_FILE)
                return True
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
        except OSError:
            return False


def start_autosave(provider):
    """Start a background thread that periodically saves provider() to disk.

    `provider` is a zero-argument callable returning a JSON-serializable dict.
    """

    def loop():
        while True:
            time.sleep(config.AUTOSAVE_INTERVAL)
            try:
                save_data(provider())
            except Exception:
                # Persistence must never crash the app; ignore and retry next cycle.
                pass

    thread = Thread(target=loop, daemon=True)
    thread.start()
    return thread
