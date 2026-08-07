"""Full request/response payloads for the live feed.

The live feed in diagnostics.py records what every request WAS — who, where,
which rule answered it, what came back. This module holds the part that is
expensive to keep: the actual bytes. Request bodies and upstream response bodies
are attacker-controlled and arbitrarily large, which makes them exactly the kind
of data that filled the stats file and got the workers OOM-killed before.

So they are kept somewhere else, under rules the stats file does not have:

  Its own file.  Never merged into DATA_FILE, never part of the cross-worker
      stat merge, never persisted across a restart in any meaningful sense. It
      can be deleted at any moment and the only thing lost is the ability to
      inspect the last few minutes of traffic.

  Three independent ceilings.  A record count, a total byte budget, and a TTL.
      Each one alone has a hole: a count cap says nothing about size (60 records
      of 5 MB is 300 MB), a byte cap alone lets one quiet hour pin stale
      payloads indefinitely, and a TTL alone is unbounded under a flood. Applied
      together, the store's worst case is a known, small number.

  Shared, not per-worker.  Four workers each holding their own ring would mean
      the dashboard could only ever show the bodies of requests that happened to
      land on whichever worker answered the poll — i.e. roughly a quarter of
      them, unpredictably. One flock'd file makes the capture the admin is
      looking at the same capture regardless of who serves the page.

  Buffered, not written per request.  The shared file is rewritten WHOLE under
      an exclusive flock, so doing that once per request would put a
      several-hundred-kilobyte serialize plus cross-worker lock contention on
      the hot path — worst exactly during the flood this exists to diagnose,
      where it would slow the proxy down more than the attacker does. So a
      capture costs a dict insert under a thread lock, and the file is merged on
      an interval. The price is that a body captured on another worker can take
      up to that interval to appear, which is invisible next to a dashboard that
      polls on a similar cadence.

Capturing is a debugging aid, not an audit log: it is admin-toggleable, it drops
oldest-first without complaint, and every path through it is best-effort. It
must never be able to fail a request it is only observing.
"""

import config
import itertools
import json
import os
import secrets
import threading
import time

import runtime
from lockfile import LockedJSON

_store = LockedJSON(lambda: config.CAPTURE_FILE)

# Captures taken by THIS worker since its last flush. Guarded by a plain thread
# lock — no file I/O — so the per-request cost is a dict write.
_pending_lock = threading.Lock()
_pending = {}
_last_flush = 0.0
FLUSH_INTERVAL = 3.0  # Seconds between merges into the shared file.

# Unique per (process, capture) so two workers can never mint the same id.
_id_prefix = f"{os.getpid():x}{secrets.token_hex(2)}"
_id_counter = itertools.count(1)

# Header names whose values must never be written here, matching the redaction
# the rest of the app applies. Capture holds bodies; it is not a way around the
# rule that secrets stay out of anything the dashboard can render.
SENSITIVE_HEADERS = {"x-roblox-token", "cookie", "authorization", "x-csrf-token", "set-cookie"}


def capture_id() -> str:
    return f"{_id_prefix}-{next(_id_counter)}"


def _setting(name: str, default):
    return runtime.get_setting(name, default)


def is_enabled() -> bool:
    return bool(_setting("capture_enabled", 1))


def _limits() -> tuple[int, int, int, int]:
    return (
        max(0, int(_setting("capture_max_records", config.CAPTURE_MAX_RECORDS))),
        max(0, int(_setting("capture_max_bytes", config.CAPTURE_MAX_BYTES))),
        max(0, int(_setting("capture_max_body", config.CAPTURE_MAX_BODY))),
        max(0, int(_setting("capture_ttl_seconds", config.CAPTURE_TTL_SECONDS))),
    )


def truncate(text, limit: int) -> tuple[str, bool, int]:
    """Clip a body to `limit` characters. Returns (text, was_truncated, original_length)."""
    if text is None:
        return "", False, 0
    if isinstance(text, (bytes, bytearray)):
        text = text.decode("utf-8", "replace")
    elif not isinstance(text, str):
        text = str(text)
    original = len(text)
    if limit and original > limit:
        return text[:limit], True, original
    return text, False, original


def redact_headers(headers) -> dict:
    """A plain dict of headers with secret values replaced. Accepts any mapping
    or (name, value) iterable, so it works for both request and response sides."""
    pairs = headers.items() if hasattr(headers, "items") else (headers or [])
    out = {}
    for name, value in pairs:
        name = str(name)
        out[name] = "[redacted]" if name.lower() in SENSITIVE_HEADERS else str(value)[:2000]
    return out


def _entry_bytes(entry: dict) -> int:
    """Roughly what this record costs on disk. Measured rather than assumed: the
    byte budget is the ceiling that actually matters and it has to be enforced
    against real serialized size, not against a character count of the body."""
    try:
        return len(json.dumps(entry, separators=(",", ":"), default=str).encode("utf-8", "replace"))
    except (TypeError, ValueError):
        return config.CAPTURE_MAX_BODY


def _prune(records: dict, now: float, max_records: int, max_bytes: int, ttl: int):
    """Apply all three ceilings, oldest-first, in place."""
    if ttl:
        for key in [k for k, r in records.items() if now - float(r.get("Date", 0) or 0) > ttl]:
            records.pop(key, None)
    ordered = sorted(records.items(), key=lambda kv: float(kv[1].get("Date", 0) or 0))
    while len(ordered) > max_records:
        key, _ = ordered.pop(0)
        records.pop(key, None)
    total = sum(int(r.get("Bytes", 0) or 0) for _, r in ordered)
    while ordered and total > max_bytes:
        key, record = ordered.pop(0)
        total -= int(record.get("Bytes", 0) or 0)
        records.pop(key, None)


def record(entry: dict) -> str:
    """Buffer one captured request/response pair. Returns its id ("" if not stored).

    Costs a dict insert; the shared file is merged on an interval by _flush.
    Never raises: a capture failure must cost the request nothing.
    """
    if not is_enabled():
        return ""
    max_records, max_bytes, max_body, _ = _limits()
    if not max_records or not max_bytes:
        return ""
    try:
        entry = dict(entry)
        key = str(entry.get("Id") or capture_id())
        entry["Id"] = key
        entry.setdefault("Date", time.time())
        for field in ("RequestBody", "ResponseBody"):
            text, truncated, original = truncate(entry.get(field), max_body)
            entry[field] = text
            entry[f"{field}Truncated"] = truncated
            entry[f"{field}Length"] = original
        entry["Bytes"] = _entry_bytes(entry)
        with _pending_lock:
            _pending[key] = entry
            # The buffer is capped exactly like the file: a burst between two
            # flushes must not be able to grow it without limit either.
            _prune(_pending, entry["Date"], max_records, max_bytes, 0)
            due = time.time() - _last_flush >= FLUSH_INTERVAL
        if due:
            _flush()
        return key
    except Exception:
        return ""


def _flush():
    """Merge this worker's buffered captures into the shared file, then prune it."""
    global _last_flush, _pending
    max_records, max_bytes, _, ttl = _limits()
    with _pending_lock:
        batch, _pending = _pending, {}
        _last_flush = time.time()
    if not batch:
        return
    now = time.time()

    def mutate(data):
        records = data.setdefault("Records", {})
        if not isinstance(records, dict):
            records = data["Records"] = {}
        records.update(batch)
        _prune(records, now, max_records, max_bytes, ttl)

    try:
        _store.update(mutate)
    except Exception:
        pass  # The captures are lost; the request they describe was served regardless.


def flush():
    """Force a merge (used before the dashboard reads, and by tests)."""
    try:
        _flush()
    except Exception:
        pass


def get(capture_id_value: str) -> dict | None:
    """One captured pair by id, or None if it expired or was evicted.

    Checks this worker's unflushed buffer first: a body captured moments ago on
    THIS worker is exactly the one an admin is most likely to click, and making
    them wait for the next flush to see it would be a strange kind of lag.
    """
    if not capture_id_value:
        return None
    key = str(capture_id_value)
    _, _, _, ttl = _limits()
    with _pending_lock:
        entry = _pending.get(key)
    if entry is None:
        records = _store.read().get("Records")
        if not isinstance(records, dict):
            return None
        entry = records.get(key)
    if not isinstance(entry, dict):
        return None
    if ttl and time.time() - float(entry.get("Date", 0) or 0) > ttl:
        return None  # Expired but not yet swept; treat it as gone rather than serving stale.
    return entry


def get_state() -> dict:
    """Capture-store health for the dashboard: what it is holding and against
    which ceilings, so the admin can size it instead of guessing."""
    _flush()  # The dashboard should describe the store as it will be read, not one interval behind.
    max_records, max_bytes, max_body, ttl = _limits()
    records = _store.read().get("Records")
    records = records if isinstance(records, dict) else {}
    now = time.time()
    live = [r for r in records.values() if isinstance(r, dict) and (not ttl or now - float(r.get("Date", 0) or 0) <= ttl)]
    used = sum(int(r.get("Bytes", 0) or 0) for r in live)
    oldest = min((float(r.get("Date", 0) or 0) for r in live), default=0.0)
    return {
        "Enabled": is_enabled(),
        "Count": len(live),
        "MaxRecords": max_records,
        "Bytes": used,
        "MaxBytes": max_bytes,
        "MaxBody": max_body,
        "TTL": ttl,
        "OldestAt": oldest,
        # How far back the capture window actually reaches right now. Under a
        # flood this collapses to seconds, which is itself worth seeing: it says
        # the store is being churned, not that nothing is being captured.
        "WindowSeconds": max(0.0, now - oldest) if oldest else 0.0,
        "File": config.CAPTURE_FILE,
    }


def reset():
    """Drop every capture (admin clear), buffered ones included."""
    global _last_flush
    with _pending_lock:
        _pending.clear()
        _last_flush = time.time()  # Nothing pending, so don't flush the batch we just dropped.
    try:
        _store.update(lambda data: data.clear())
    except Exception:
        pass
