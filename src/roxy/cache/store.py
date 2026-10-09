"""Cache storage: each worker's memory tier in front of the shared cache.db tier, plus hits, purges and eviction.

What this is
    `CacheEntry` (one stored answer), `MemoryTier` (a per-worker LRU with an entry cap and a byte cap),
    `SharedTier` (the `entries` table of cache.db: zstd bodies, the purge generation row, batched hit counts,
    change observations, purges and LRU/LFU eviction) and `CacheStore`, which puts them together the way the
    cache service uses them. `PurgeScope` names what a purge removes (plan 6.8).

Why it exists
    v1 kept the shared tier in 16 JSON shard files rewritten whole under a lock, evicted first in, first out (so
    the hottest long-lived keys went first), lost purges in every other worker's memory, and counted hits by
    rewriting shards on a request thread (v1 bugs B5, B6, B8, B24; plan 2.4). SQLite gives O(1) point reads and
    writes shared by every worker, and one counter row tells every worker when to drop its memory tier.

How it works
    - Bodies are stored with a one-byte format tag: `z` plus a zstd frame (when `cache_compress` is on and
      compression helps) or `r` plus the raw bytes. Compression and decompression run inside the database
      functions, on the writer and reader threads, so a 1 MiB body never blocks the event loop.
    - The `generation` row holds two counters. `value` is the purge-all generation: rows written under an older
      value are misses at once (every read checks `generation >= value`), so Purge All takes effect before its
      batched deletes finish (plan 6.5). `updated_at` is a change stamp moved by EVERY purge; each worker polls
      both a few times a second (and sees them on every disk read) and drops its whole memory tier when either
      moved. Scoped purges therefore reach every worker's memory without invalidating unrelated disk rows.
      Purges move the stamp before deleting and again after, so a memory copy loaded mid-purge is dropped too.
    - Reads of an id that is fresh in memory never touch disk. An expired memory copy is checked against disk,
      because another worker may already have refreshed it (fixes v1 bug B5).
    - Hits are counted in memory (`HitBuffer`, bounded) and written every `metrics_flush_interval_ms` in one
      transaction, together with the TTL tuner's change observations (plan F10). `last_hit_at` starts at the
      store time, so "least recently used" is an index scan.
    - Eviction runs from a maintenance loop (one worker at a time, under a hot.db lease). Rows whose stale
      window has ended are deleted first (plan 15.3 D), then, while the table is over `cache_max_entries` or
      `cache_max_bytes`, victims are chosen from the least recently used end: `lru` takes them in order, `hybrid`
      (the default) scores that tail by hits with an hourly half-life so popular entries survive, `lfu` adds a
      random sample and evicts the fewest hits. Totals are counted with `length()`, which reads only each row's
      header, never the body pages.
    - Disk health counts writes and failures per worker (parity row 64); `ok` turns true again after a later
      successful write, like v1.
    - The service puts an entry in the memory tier before its caller is answered and writes the cache.db row
      afterwards (`write_shared`, from the single-flight tail), so a locked cache.db never delays an answer.
    - Single-flight handoff rows (key text ending in ` !flight`) carry an answer too big for the hot.db lease row
      to followers in other workers. They are read by id without entering the memory tier (`read_handoff`),
      are never a lookup result, live a few seconds, and are deleted with the other dead rows (`remove_dead`,
      which also runs while the disk tier is switched off).

What to read next
    `roxy/cache/service.py` (who calls what, and when), then `roxy/storage/db.py` (the threads behind
    `db.read` and `db.write`).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import sqlite3
import threading
from collections import OrderedDict
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

import zstandard

from roxy.cache.keys import HANDOFF_SUFFIX
from roxy.core.clock import Clock
from roxy.core.reasons import AuthClass
from roxy.rules.match import compile_pattern, kind_of, normalize_glob, normalize_regex, validate_pattern
from roxy.storage.db import Database, SharedStateUnavailable

log = logging.getLogger(__name__)

FORMAT_RAW: Final = b"r"
FORMAT_ZSTD: Final = b"z"
ZSTD_LEVEL: Final = 3
"""zstd level 3: about 4x on Roblox JSON at a few hundred MB/s, the library's own default trade-off."""
MIN_COMPRESS_BYTES: Final = 64
"""Bodies shorter than this are stored raw: the frame header would make them bigger."""

ROW_OVERHEAD_BYTES: Final = 64
"""Fixed per-row allowance in the byte budget (row header, ids, integers, index entries)."""
MEMORY_ENTRY_OVERHEAD: Final = 256
"""Fixed per-entry allowance in the memory budget (the Python objects around the body)."""

MAX_PENDING_HITS: Final = 5000
"""Distinct entry ids with unflushed hits per worker (v1 MAX_PENDING_HITS). Beyond it new ids are dropped."""
MAX_PENDING_OBSERVATIONS: Final = 2000
"""Distinct (endpoint template, day) pairs with unflushed change observations per worker."""

DELETE_BATCH: Final = 5000
"""Rows per delete transaction in purges and cleanup (plan 6.5), so no single transaction holds the lock long."""
PURGE_PAUSE_S: Final = 0.01
"""Pause between delete batches, so request writes interleave with a long purge."""
EVICT_DELETE_CHUNK: Final = 500
MAX_EVICT_CANDIDATES: Final = 4000
"""Rows read per eviction round to choose victims from (bounds the round's cost)."""
MAX_EVICT_ROUNDS: Final = 50
EVICT_TARGET_RATIO: Final = 0.95
"""Once over a cap, evict down to 95% of it, so the next store does not immediately trigger another round."""
HYBRID_HALF_LIFE_S: Final = 3600.0
"""In the hybrid policy a hit counts half as much after an hour, a quarter after two (recency decay)."""
WRITE_BUSY_TIMEOUT_MS: Final = 2000
"""How long a store waits for another process's cache.db write lock before giving up (the answer is still served)."""

SIZE_SQL: Final = (
    "(coalesce(length(body), 0) + coalesce(length(key), 0) + coalesce(length(params_json), 0)"
    f" + coalesce(length(headers_json), 0) + coalesce(length(req_body), 0) + {ROW_OVERHEAD_BYTES})"
)
"""The bytes one row counts against `cache_max_bytes`. `length()` of a BLOB is read from the row header, so this
never reads body pages (the columns after `body` would)."""

_LIST_COLUMNS: Final = (
    "id, key, auth_class, method, host, path, status, content_type, body_len, stored_at, expires_at, stale_until, "
    "ttl, rule_id, egress, hits, last_hit_at, negative"
)
"""Cache browser columns: everything but the bodies."""

_COLUMNS: Final = (
    "id, key, auth_class, method, host, path, params_json, status, content_type, headers_json, body, body_len, "
    "stored_at, expires_at, stale_until, ttl, rule_id, egress, hits, last_hit_at, bytes, negative, generation"
)

_UPSERT: Final = """
INSERT INTO entries (id, key, auth_class, method, host, path, params_json, req_body, status, content_type,
    headers_json, body, body_len, stored_at, expires_at, stale_until, ttl, rule_id, egress, hits, last_hit_at,
    bytes, negative, generation)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET
    key = excluded.key, auth_class = excluded.auth_class, method = excluded.method, host = excluded.host,
    path = excluded.path, params_json = excluded.params_json, req_body = excluded.req_body,
    status = excluded.status, content_type = excluded.content_type, headers_json = excluded.headers_json,
    body = excluded.body, body_len = excluded.body_len, stored_at = excluded.stored_at,
    expires_at = excluded.expires_at, stale_until = excluded.stale_until, ttl = excluded.ttl,
    rule_id = excluded.rule_id, egress = excluded.egress,
    hits = CASE WHEN entries.generation >= excluded.generation THEN entries.hits ELSE 0 END,
    last_hit_at = max(coalesce(entries.last_hit_at, 0), excluded.last_hit_at),
    bytes = excluded.bytes, negative = excluded.negative, generation = excluded.generation
WHERE excluded.generation >= entries.generation
"""
"""Insert or refresh one entry. A refresh keeps the key's hit count (its popularity, for eviction), and a row
written under an older purge generation never replaces a newer one."""

_local = threading.local()


# --- bodies ----------------------------------------------------------------------------------------------------------


def _compressor() -> zstandard.ZstdCompressor:
    # zstd (de)compressor objects must not be shared between threads; one per database thread is plenty.
    found = getattr(_local, "compressor", None)
    if found is None:
        found = _local.compressor = zstandard.ZstdCompressor(level=ZSTD_LEVEL)
    return found


def _decompressor() -> zstandard.ZstdDecompressor:
    found = getattr(_local, "decompressor", None)
    if found is None:
        found = _local.decompressor = zstandard.ZstdDecompressor()
    return found


def encode_body(body: bytes, compress: bool) -> bytes:
    """The stored form of a body: a format tag plus zstd (when it helps) or the raw bytes."""
    if compress and len(body) >= MIN_COMPRESS_BYTES:
        packed = _compressor().compress(body)
        if len(packed) < len(body):
            return FORMAT_ZSTD + packed
    return FORMAT_RAW + body


def decode_body(blob: bytes | None) -> bytes:
    """The body back from its stored form. Raises ValueError for an unknown format tag (a damaged row)."""
    if not blob:
        return b""
    tag, data = blob[:1], blob[1:]
    if tag == FORMAT_ZSTD:
        return bytes(_decompressor().decompress(data))
    if tag == FORMAT_RAW:
        return bytes(data)
    raise ValueError("unknown cached body format")


def stored_size(
    body_blob: bytes, key: str, params_json: str | None, headers_json: str | None, req_blob: bytes | None
) -> int:
    """The bytes a row counts against the budget: exactly what `SIZE_SQL` computes for the same row."""
    return (
        len(body_blob)
        + len(key)
        + len(params_json or "")
        + len(headers_json or "")
        + len(req_blob or b"")
        + ROW_OVERHEAD_BYTES
    )


# --- entries ---------------------------------------------------------------------------------------------------------


@dataclass(slots=True)
class CacheEntry:
    """One stored answer, in memory and as a cache.db row. Timestamps are whole Unix seconds (plan 6.2)."""

    id: str
    key: str
    auth_class: AuthClass
    method: str
    host: str
    path: str
    status: int
    body: bytes
    content_type: str | None
    stored_at: int
    expires_at: int
    stale_until: int
    ttl: int
    headers: dict[str, str] = field(default_factory=dict)
    params: tuple[tuple[str, str], ...] = ()
    stripped: tuple[str, ...] = ()
    rule_id: int | None = None
    egress: str | None = None
    hits: int = 0
    last_hit_at: int | None = None
    negative: bool = False
    generation: int = 0
    size: int = 0
    """Bytes counted against `cache_max_bytes` (set when written to cache.db)."""

    def is_fresh(self, now: float) -> bool:
        """v1 `is_fresh`: strictly before `expires_at`."""
        return self.expires_at > now

    def age(self, now: float) -> int:
        """Whole seconds since it was stored, never negative (v1 `Roxy-Cache-Age`)."""
        return max(0, int(now - self.stored_at))

    @property
    def is_marker(self) -> bool:
        """A per-key Roblox 429 marker (plan 7.7): never served as content."""
        return self.negative and self.status == 429

    @property
    def memory_size(self) -> int:
        return len(self.body) + len(self.key) + MEMORY_ENTRY_OVERHEAD

    def params_json(self) -> str:
        """The stored `params_json`: the parameters a refresh resends plus the ignored names that were dropped."""
        return json.dumps(
            {"params": [list(pair) for pair in self.params], "stripped": list(self.stripped)},
            separators=(",", ":"),
            ensure_ascii=False,
        )


def _entry_from_row(row: sqlite3.Row) -> CacheEntry:
    params_doc = json.loads(row["params_json"]) if row["params_json"] else {}
    headers_doc = json.loads(row["headers_json"]) if row["headers_json"] else {}
    return CacheEntry(
        id=str(row["id"]),
        key=str(row["key"]),
        auth_class=AuthClass(row["auth_class"]),
        method=str(row["method"]),
        host=str(row["host"]),
        path=str(row["path"]),
        status=int(row["status"]),
        body=decode_body(row["body"]),
        content_type=row["content_type"],
        stored_at=int(row["stored_at"]),
        expires_at=int(row["expires_at"]),
        stale_until=int(row["stale_until"]),
        ttl=int(row["ttl"]),
        headers={str(k): str(v) for k, v in dict(headers_doc).items()},
        params=tuple((str(n), str(v)) for n, v in params_doc.get("params", ())),
        stripped=tuple(str(n) for n in params_doc.get("stripped", ())),
        rule_id=None if row["rule_id"] is None else int(row["rule_id"]),
        egress=row["egress"],
        hits=int(row["hits"] or 0),
        last_hit_at=None if row["last_hit_at"] is None else int(row["last_hit_at"]),
        negative=bool(row["negative"]),
        generation=int(row["generation"]),
        size=int(row["bytes"] or 0),
    )


# --- the memory tier -------------------------------------------------------------------------------------------------


class MemoryTier:
    """A per-worker LRU of entries with an entry cap and a byte cap (parity row 52). Event loop thread only.

    A cap of 0 turns the tier off. Expired entries are kept (they may still be served stale); the caller decides.
    `floor` is the purge-all generation this worker has seen: older entries are refused and dropped.
    """

    def __init__(self, max_entries: int = 0, max_bytes: int = 0) -> None:
        self._items: OrderedDict[str, CacheEntry] = OrderedDict()
        self._bytes = 0
        self.max_entries = max_entries
        self.max_bytes = max_bytes
        self.floor = 0
        self.evictions = 0

    def configure(self, max_entries: int, max_bytes: int) -> None:
        """Apply new caps (a live settings change) and trim at once."""
        self.max_entries, self.max_bytes = max(0, max_entries), max(0, max_bytes)
        if self.max_entries == 0 or self.max_bytes == 0:
            self.clear()
        self._trim()

    def get(self, entry_id: str) -> CacheEntry | None:
        entry = self._items.get(entry_id)
        if entry is None:
            return None
        if entry.generation < self.floor:
            self.drop(entry_id)
            return None
        self._items.move_to_end(entry_id)  # most recently used goes to the end
        return entry

    def put(self, entry: CacheEntry) -> bool:
        """Insert or replace; False when the tier is off, the entry is too big, or it predates a purge-all."""
        self.drop(entry.id)
        size = entry.memory_size
        if self.max_entries <= 0 or self.max_bytes <= 0 or size > self.max_bytes or entry.generation < self.floor:
            return False
        self._items[entry.id] = entry
        self._bytes += size
        self._trim()
        return entry.id in self._items

    def drop(self, entry_id: str) -> None:
        old = self._items.pop(entry_id, None)
        if old is not None:
            self._bytes = max(0, self._bytes - old.memory_size)

    def clear(self) -> int:
        count = len(self._items)
        self._items.clear()
        self._bytes = 0
        return count

    def _trim(self) -> None:
        while self._items and (len(self._items) > self.max_entries or self._bytes > self.max_bytes):
            _id, old = self._items.popitem(last=False)  # least recently used is at the front
            self._bytes = max(0, self._bytes - old.memory_size)
            self.evictions += 1

    def __len__(self) -> int:
        return len(self._items)

    def __contains__(self, entry_id: object) -> bool:
        return entry_id in self._items

    @property
    def bytes(self) -> int:
        return self._bytes


# --- buffers ---------------------------------------------------------------------------------------------------------


class HitBuffer:
    """Hits per entry id waiting for the next flush (parity row 63). Bounded: new ids beyond the cap are dropped."""

    def __init__(self, max_ids: int = MAX_PENDING_HITS) -> None:
        self._pending: dict[str, list[int]] = {}
        self._max = max_ids
        self.dropped = 0

    def record(self, entry_id: str, at: int) -> None:
        item = self._pending.get(entry_id)
        if item is None:
            if len(self._pending) >= self._max:
                self.dropped += 1
                return
            self._pending[entry_id] = [1, at]
        else:
            item[0] += 1
            item[1] = max(item[1], at)

    def pending(self, entry_id: str) -> int:
        item = self._pending.get(entry_id)
        return 0 if item is None else item[0]

    def drain(self) -> list[tuple[str, int, int]]:
        items = [(entry_id, count, at) for entry_id, (count, at) in self._pending.items()]
        self._pending = {}
        return items

    def restore(self, items: Sequence[tuple[str, int, int]]) -> None:
        """Put back hits a failed flush could not write (still bounded)."""
        for entry_id, count, at in items:
            item = self._pending.get(entry_id)
            if item is None:
                if len(self._pending) >= self._max:
                    self.dropped += 1
                    continue
                self._pending[entry_id] = [count, at]
            else:
                item[0] += count
                item[1] = max(item[1], at)

    def __len__(self) -> int:
        return len(self._pending)


class ObservationBuffer:
    """Refetch observations for TTL tuning (plan F10, `change_observations`), per (endpoint template, UTC day)."""

    def __init__(self, max_keys: int = MAX_PENDING_OBSERVATIONS) -> None:
        self._pending: dict[tuple[str, int], list[int]] = {}
        self._max = max_keys
        self.dropped = 0

    def observe(self, template: str, day: int, identical: bool) -> None:
        key = (template, day)
        item = self._pending.get(key)
        if item is None:
            if len(self._pending) >= self._max:
                self.dropped += 1
                return
            item = self._pending[key] = [0, 0]
        item[0] += 1
        item[1] += 1 if identical else 0

    def drain(self) -> list[tuple[str, int, int, int]]:
        items = [(template, day, refetches, same) for (template, day), (refetches, same) in self._pending.items()]
        self._pending = {}
        return items

    def restore(self, items: Sequence[tuple[str, int, int, int]]) -> None:
        for template, day, refetches, same in items:
            key = (template, day)
            item = self._pending.get(key)
            if item is None:
                if len(self._pending) >= self._max:
                    self.dropped += 1
                    continue
                item = self._pending[key] = [0, 0]
            item[0] += refetches
            item[1] += same

    def __len__(self) -> int:
        return len(self._pending)


# --- disk health -----------------------------------------------------------------------------------------------------


@dataclass(slots=True)
class DiskHealth:
    """Per-worker write and read results for cache.db (parity row 64, v1 `_health`)."""

    writes: int = 0
    failures: int = 0
    read_failures: int = 0
    last_write_at: float = 0.0
    last_error: str = ""
    last_error_at: float = 0.0

    @property
    def ok(self) -> bool:
        """v1: healthy when nothing failed, or when a write succeeded after the last failure."""
        return self.failures == 0 or self.last_write_at >= self.last_error_at

    def wrote(self, now: float) -> None:
        self.writes += 1
        self.last_write_at = now

    def failed(self, error: str, now: float, *, read: bool = False) -> None:
        if read:
            self.read_failures += 1
        else:
            self.failures += 1
        self.last_error = error[:300]
        self.last_error_at = now


# --- purge scopes ----------------------------------------------------------------------------------------------------


class PurgeKind(StrEnum):
    """What a purge removes (plan 6.8 "Cache only", parity row 66)."""

    ALL = "all"
    ID = "id"
    HOST = "host"
    RULE = "rule"
    PATTERN = "pattern"
    EXPIRED = "expired"
    PARAM = "param"


@dataclass(frozen=True, slots=True)
class PurgeScope:
    """One purge request. Build it with the class methods; `validated()` normalizes and checks it."""

    kind: PurgeKind
    value: str | int | None = None
    pattern_type: str = "glob"
    include_stale: bool = False
    """For EXPIRED: also remove entries that are past their lifetime but still inside their stale window."""

    @classmethod
    def all(cls) -> PurgeScope:
        return cls(PurgeKind.ALL)

    @classmethod
    def entry(cls, entry_id: str) -> PurgeScope:
        return cls(PurgeKind.ID, entry_id)

    @classmethod
    def host(cls, host: str) -> PurgeScope:
        return cls(PurgeKind.HOST, host)

    @classmethod
    def rule(cls, rule_id: int) -> PurgeScope:
        return cls(PurgeKind.RULE, int(rule_id))

    @classmethod
    def pattern(cls, pattern: str, pattern_type: str = "glob") -> PurgeScope:
        return cls(PurgeKind.PATTERN, pattern, pattern_type=pattern_type)

    @classmethod
    def expired(cls, include_stale: bool = False) -> PurgeScope:
        return cls(PurgeKind.EXPIRED, include_stale=include_stale)

    @classmethod
    def param(cls, name: str) -> PurgeScope:
        """Entries affected by adding or removing ignored query parameter `name` (scoped, parity row 54)."""
        return cls(PurgeKind.PARAM, name)

    def validated(self) -> PurgeScope:
        """Normalized copy. Raises ValueError (a `PatternValidationError` for patterns) when it cannot run."""
        kind = PurgeKind(self.kind)
        if kind in (PurgeKind.ALL, PurgeKind.EXPIRED):
            return PurgeScope(kind, None, include_stale=self.include_stale)
        if kind == PurgeKind.RULE:
            return PurgeScope(kind, int(self.value or 0))
        text = str(self.value or "").strip()
        if not text:
            raise ValueError("Nothing to purge: pass an id, a pattern, expired or all")
        if kind == PurgeKind.HOST:
            return PurgeScope(kind, text.lower().rstrip("."))
        if kind == PurgeKind.PATTERN:
            pattern_type = kind_of(self.pattern_type)
            return PurgeScope(kind, validate_pattern(text, pattern_type), pattern_type=pattern_type)
        return PurgeScope(kind, text)

    @property
    def label(self) -> str:
        return self.kind.value if self.value is None else f"{self.kind.value}:{self.value}"


def target_matches(pattern: str, pattern_type: str, target: str) -> bool:
    """v1 `path_matches` for purges: globs see the normalized (lowercased) target, regexes the trimmed target."""
    kind = kind_of(pattern_type)
    normalized = normalize_regex(target) if kind == "regex" else normalize_glob(target)
    return compile_pattern(pattern, kind).matches(normalized)


def _params_mention(params_json: str | None, name: str) -> bool:
    if not params_json:
        return False
    try:
        doc = json.loads(params_json)
    except ValueError:
        return False
    if name in doc.get("stripped", ()):
        return True
    return any(pair and pair[0] == name for pair in doc.get("params", ()))


# --- the shared tier -------------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ReadResult:
    entries: dict[str, CacheEntry]
    floor: int
    stamp: int


@dataclass(slots=True)
class EvictionReport:
    """What one maintenance pass did, for logs, the System page and the CACHE-PRESSURE rule."""

    dead: int = 0
    evicted: int = 0
    freed_bytes: int = 0
    entries_before: int = 0
    bytes_before: int = 0
    entries_after: int = 0
    bytes_after: int = 0
    young: int = 0  # evicted before their TTL ran out: the cache is too small for what it is asked to keep
    age_s_total: float = 0.0  # summed age (now minus stored_at) of every evicted entry
    young_age_s_total: float = 0.0  # the same for the young ones


@dataclass(frozen=True, slots=True)
class Victim:
    """One entry an eviction round chose: its id, size, age (seconds since it was stored) and whether it was young
    (evicted before its TTL ran out)."""

    id: str
    size: int
    age_s: float
    young: bool


def _generation(conn: sqlite3.Connection) -> tuple[int, int]:
    row = conn.execute("SELECT value, updated_at FROM generation WHERE id = 1").fetchone()
    return (int(row[0]), int(row[1])) if row is not None else (0, 0)


class SharedTier:
    """The cache.db `entries` table, shared by every worker (plan 6.2, 6.5). Every method may raise
    `SharedStateUnavailable` except `write`, which records the failure in `health` and returns False."""

    def __init__(self, db: Database, clock: Clock) -> None:
        self.db = db
        self._clock = clock
        self.health = DiskHealth()

    # ---- reads ----

    async def read(self, ids: Sequence[str]) -> ReadResult:
        """The valid rows among `ids` (bodies decoded on the reader thread) plus the generation counters."""
        wanted = tuple(dict.fromkeys(ids))

        def run(conn: sqlite3.Connection) -> ReadResult:
            floor, stamp = _generation(conn)
            marks = ", ".join("?" for _ in wanted)
            sql = f"SELECT {_COLUMNS} FROM entries WHERE id IN ({marks}) AND generation >= ?"  # noqa: S608  # only placeholders are interpolated
            found: dict[str, CacheEntry] = {}
            for row in conn.execute(sql, (*wanted, floor)).fetchall():
                try:
                    entry = _entry_from_row(row)
                except (ValueError, TypeError, KeyError, zstandard.ZstdError):
                    log.warning("cache_row_unreadable", extra={"fields": {"id": str(row["id"])[:32]}})
                    continue
                found[entry.id] = entry
            return ReadResult(found, floor, stamp)

        return await self.db.read(run)

    async def read_generation(self) -> tuple[int, int]:
        """`(purge-all generation, change stamp)` from the generation row."""
        return await self.db.read(_generation)

    # ---- writes ----

    async def write(self, entry: CacheEntry, *, compress: bool, req_body: bytes | None = None) -> bool:
        """Insert or refresh one entry. Never raises: a failure is recorded in `health` and returns False."""

        def run(conn: sqlite3.Connection) -> int:
            blob = encode_body(entry.body, compress)
            req_blob = encode_body(req_body, compress) if req_body else None
            params_json = entry.params_json()
            headers_json = json.dumps(entry.headers, sort_keys=True, separators=(",", ":")) if entry.headers else None
            size = stored_size(blob, entry.key, params_json, headers_json, req_blob)
            conn.execute(
                _UPSERT,
                (
                    entry.id,
                    entry.key,
                    entry.auth_class.value,
                    entry.method,
                    entry.host,
                    entry.path,
                    params_json,
                    req_blob,
                    entry.status,
                    entry.content_type,
                    headers_json,
                    blob,
                    len(entry.body),
                    entry.stored_at,
                    entry.expires_at,
                    entry.stale_until,
                    entry.ttl,
                    entry.rule_id,
                    entry.egress,
                    entry.stored_at if entry.last_hit_at is None else entry.last_hit_at,
                    size,
                    1 if entry.negative else 0,
                    entry.generation,
                ),
            )
            return size

        now = self._clock.now()
        try:
            entry.size = await self.db.write(run, busy_timeout_ms=WRITE_BUSY_TIMEOUT_MS)
        except (SharedStateUnavailable, sqlite3.Error, OSError) as exc:
            self.health.failed(f"{type(exc).__name__}: {exc}", now)
            log.warning("cache_write_failed", extra={"fields": {"error": str(exc)[:200]}})
            return False
        self.health.wrote(now)
        return True

    async def flush(
        self, hits: Sequence[tuple[str, int, int]], observations: Sequence[tuple[str, int, int, int]]
    ) -> int:
        """Write buffered hit counts and change observations in one transaction; returns rows touched."""

        def run(conn: sqlite3.Connection) -> int:
            touched = 0
            if hits:
                cur = conn.executemany(
                    "UPDATE entries SET hits = hits + ?, last_hit_at = max(coalesce(last_hit_at, 0), ?) WHERE id = ?",
                    [(count, at, entry_id) for entry_id, count, at in hits],
                )
                touched += max(0, cur.rowcount)
            if observations:
                conn.executemany(
                    "INSERT INTO change_observations (endpoint_template, day, refetches, identical_bodies) "
                    "VALUES (?, ?, ?, ?) ON CONFLICT (endpoint_template, day) DO UPDATE SET "
                    "refetches = refetches + excluded.refetches, "
                    "identical_bodies = identical_bodies + excluded.identical_bodies",
                    list(observations),
                )
                touched += len(observations)
            return touched

        return await self.db.write(run)

    async def bump_generation(self, *, purge_all: bool, now_s: int) -> tuple[int, int]:
        """Move the change stamp (and, for Purge All, the purge-all generation); returns the new pair."""

        def run(conn: sqlite3.Connection) -> tuple[int, int]:
            conn.execute("INSERT OR IGNORE INTO generation (id, value, updated_at) VALUES (1, 0, 0)")
            if purge_all:
                conn.execute(
                    "UPDATE generation SET value = value + 1, updated_at = max(updated_at + 1, ?) WHERE id = 1",
                    (now_s,),
                )
            else:
                conn.execute("UPDATE generation SET updated_at = max(updated_at + 1, ?) WHERE id = 1", (now_s,))
            return _generation(conn)

        return await self.db.write(run)

    # ---- deletes ----

    async def delete_where(
        self, where: str, params: tuple[Any, ...], *, batch: int = DELETE_BATCH, pause_s: float = PURGE_PAUSE_S
    ) -> int:
        """Delete rows matching `where` in batches of `batch` (plan 6.5). `where` is module code, never input."""
        sql = f"DELETE FROM entries WHERE rowid IN (SELECT rowid FROM entries WHERE {where} LIMIT ?)"  # noqa: S608  # `where` comes from this module's constants; values are bound
        total = 0
        while True:
            removed = await self.db.write(lambda conn: conn.execute(sql, (*params, batch)).rowcount)
            total += max(0, removed)
            if removed < batch:
                return total
            await asyncio.sleep(pause_s)

    async def delete_ids(self, ids: Sequence[str]) -> int:
        """Delete exact ids; returns how many rows really existed (fixes v1 bug B7)."""
        total = 0
        for start in range(0, len(ids), EVICT_DELETE_CHUNK):
            chunk = tuple(ids[start : start + EVICT_DELETE_CHUNK])
            marks = ", ".join("?" for _ in chunk)
            sql = f"DELETE FROM entries WHERE id IN ({marks})"  # noqa: S608  # only placeholders are interpolated

            def run(conn: sqlite3.Connection, sql: str = sql, chunk: tuple[str, ...] = chunk) -> int:
                return conn.execute(sql, chunk).rowcount

            total += max(0, await self.db.write(run))
        return total

    async def delete_matching(
        self,
        columns: str,
        predicate: Callable[[sqlite3.Row], bool],
        *,
        batch: int = DELETE_BATCH,
        pause_s: float = PURGE_PAUSE_S,
    ) -> int:
        """Scan the table in rowid order, test each row with `predicate` on a reader thread, delete the matches."""
        after = 0
        total = 0
        select = f"SELECT rowid, {columns} FROM entries WHERE rowid > ? ORDER BY rowid LIMIT ?"  # noqa: S608  # `columns` comes from this module

        while True:

            def find(conn: sqlite3.Connection, after: int = after) -> tuple[list[int], int | None, int]:
                rows = conn.execute(select, (after, batch)).fetchall()
                last = int(rows[-1][0]) if rows else None
                return [int(row[0]) for row in rows if predicate(row)], last, len(rows)

            matched, last, seen = await self.db.read(find)
            for start in range(0, len(matched), EVICT_DELETE_CHUNK):
                chunk = tuple(matched[start : start + EVICT_DELETE_CHUNK])
                marks = ", ".join("?" for _ in chunk)
                sql = f"DELETE FROM entries WHERE rowid IN ({marks})"  # noqa: S608  # only placeholders

                def remove(conn: sqlite3.Connection, sql: str = sql, chunk: tuple[int, ...] = chunk) -> int:
                    return conn.execute(sql, chunk).rowcount

                total += max(0, await self.db.write(remove))
            if last is None or seen < batch:
                return total
            after = last
            await asyncio.sleep(pause_s)

    # ---- budgets and eviction ----

    async def totals(self) -> tuple[int, int]:
        """`(rows, bytes)` of the whole table, counted from row headers only (see `SIZE_SQL`)."""
        sql = f"SELECT count(*), total({SIZE_SQL}) FROM entries"  # noqa: S608  # SIZE_SQL is a module constant
        row = await self.db.read(lambda conn: conn.execute(sql).fetchone())
        return int(row[0]), int(row[1] or 0)

    async def evict(self, *, max_entries: int, max_bytes: int, policy: str, now: float) -> EvictionReport:
        """Bring the table under both caps (to 95% of a cap that was exceeded); see the module docstring."""
        count, size = await self.totals()
        report = EvictionReport(entries_before=count, bytes_before=size)
        goal_entries = int(max_entries * EVICT_TARGET_RATIO) if count > max_entries else max_entries
        goal_bytes = int(max_bytes * EVICT_TARGET_RATIO) if size > max_bytes else max_bytes
        rounds = 0
        while (count > goal_entries or size > goal_bytes) and rounds < MAX_EVICT_ROUNDS:
            rounds += 1
            victims = await self._victims(policy, max(0, count - goal_entries), max(0, size - goal_bytes), now)
            if not victims:
                break
            removed = await self.delete_ids([victim.id for victim in victims])
            freed = sum(victim.size for victim in victims)
            count = max(0, count - removed)
            size = max(0, size - freed)
            report.evicted += removed
            report.freed_bytes += freed
            # Ages for CACHE-PRESSURE (plan 11.5): an entry evicted before its TTL ran out was still wanted.
            for victim in victims:
                report.age_s_total += victim.age_s
                if victim.young:
                    report.young += 1
                    report.young_age_s_total += victim.age_s
            await asyncio.sleep(0)  # let requests run between rounds
        report.entries_after, report.bytes_after = count, size
        return report

    async def _victims(self, policy: str, need_entries: int, need_bytes: int, now: float) -> list[Victim]:
        want = max(need_entries, 1)
        lru_only = policy == "lru"
        limit = min(MAX_EVICT_CANDIDATES, max(want, 64) if lru_only else max(want * 4, 256))
        select = f"SELECT id, {SIZE_SQL}, hits, last_hit_at, stored_at, ttl FROM entries"  # noqa: S608  # constants

        def run(conn: sqlite3.Connection) -> list[tuple[str, int, int, int, int, int]]:
            # The last_hit_at index gives the least recently used rows without sorting the table.
            rows = conn.execute(f"{select} ORDER BY last_hit_at LIMIT ?", (limit,)).fetchall()
            if policy == "lfu":
                low, high = conn.execute("SELECT min(rowid), max(rowid) FROM entries").fetchone()
                if low is not None:
                    start = random.randint(int(low), int(high))  # a random window: an LFU sample
                    rows += conn.execute(f"{select} WHERE rowid >= ? ORDER BY rowid LIMIT ?", (start, limit)).fetchall()
            return [
                (str(r[0]), int(r[1] or 0), int(r[2] or 0), int(r[3] or 0), int(r[4] or 0), int(r[5] or 0))
                for r in rows
            ]

        rows = await self.db.read(run)
        unique = list({row[0]: row for row in rows}.values())
        if policy == "lfu":
            unique.sort(key=lambda row: (row[2], row[3]))
        elif not lru_only:  # hybrid: hits that fade with an hourly half-life, least valuable first
            unique.sort(key=lambda row: (row[2] * 0.5 ** (max(0.0, now - row[3]) / HYBRID_HALF_LIFE_S), row[3]))
        chosen: list[Victim] = []
        freed = 0
        for entry_id, entry_size, _hits, _last, stored_at, ttl in unique:
            if len(chosen) >= need_entries and freed >= need_bytes:
                break
            age = max(0.0, now - stored_at)
            chosen.append(Victim(entry_id, entry_size, age, ttl > 0 and age < ttl))
            freed += entry_size
        return chosen

    # ---- admin views ----

    async def get_row(self, entry_id: str) -> tuple[CacheEntry, bytes | None] | None:
        """One entry with its stored request body (for the inspector and POST refresh), or None."""

        def run(conn: sqlite3.Connection) -> tuple[CacheEntry, bytes | None] | None:
            floor, _stamp = _generation(conn)
            sql = f"SELECT {_COLUMNS}, req_body FROM entries WHERE id = ? AND generation >= ?"  # noqa: S608  # constants
            row = conn.execute(sql, (entry_id, floor)).fetchone()
            if row is None:
                return None
            return _entry_from_row(row), (decode_body(row["req_body"]) if row["req_body"] else None)

        return await self.db.read(run)

    async def list_rows(
        self, query: str, offset: int, limit: int, sort: str, descending: bool
    ) -> tuple[int, list[dict[str, Any]]]:
        """A page of the cache browser (parity row 66): `(total matching, rows without bodies)`."""
        order = _SORTS.get(sort, _SORTS["hits"])
        direction = "DESC" if descending else "ASC"
        needle = query.strip().lower()
        like = "%" + needle.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        where = "generation >= ? AND (? = '' OR lower(key) LIKE ? ESCAPE '\\')"
        select = f"SELECT {_LIST_COLUMNS}, {SIZE_SQL} AS size FROM entries"  # noqa: S608  # module constants
        # `order` comes from the `_SORTS` whitelist and `direction` is one of two literals; values are bound.
        page_sql = f"{select} WHERE {where} ORDER BY {order} {direction}, id LIMIT ? OFFSET ?"
        count_sql = f"SELECT count(*) FROM entries WHERE {where}"  # noqa: S608  # constant text

        def run(conn: sqlite3.Connection) -> tuple[int, list[dict[str, Any]]]:
            floor, _stamp = _generation(conn)
            total = int(conn.execute(count_sql, (floor, needle, like)).fetchone()[0])
            rows = conn.execute(page_sql, (floor, needle, like, limit, offset)).fetchall()
            return total, [dict(row) for row in rows]

        return await self.db.read(run)

    async def spread_rows(self, max_rows: int) -> list[tuple[str, str, str, str | None, int, int]]:
        """`(method, host, path, params_json, hits, bytes)` of up to `max_rows` content entries (no markers, no
        single-flight handoff rows: both repeat an entry's parameters and would count one key twice)."""
        sql = (
            f"SELECT method, host, path, params_json, hits, {SIZE_SQL} FROM entries "  # noqa: S608  # constants
            "WHERE generation >= ? AND NOT (negative = 1 AND status = 429) AND substr(key, -?) != ? "
            "ORDER BY rowid DESC LIMIT ?"
        )

        def run(conn: sqlite3.Connection) -> list[tuple[str, str, str, str | None, int, int]]:
            floor, _stamp = _generation(conn)
            params = (floor, len(HANDOFF_SUFFIX), HANDOFF_SUFFIX, max_rows)
            return [
                (str(r[0]), str(r[1]), str(r[2]), r[3], int(r[4] or 0), int(r[5] or 0))
                for r in conn.execute(sql, params).fetchall()
            ]

        return await self.db.read(run)

    def disk_status(self) -> dict[str, Any]:
        """v1 `disk_status()` shape (parity row 64), for this worker."""
        directory = Path(self.db.path).parent
        exists = directory.is_dir()
        try:
            writable = os.access(directory, os.W_OK | os.X_OK) if exists else False
            error = ""
        except OSError as exc:
            writable, error = False, f"{type(exc).__name__}: {exc}"
        health = self.health
        return {
            "Dir": str(directory),
            "File": str(self.db.path),
            "Exists": exists,
            "Writable": writable,
            "Error": error or health.last_error,
            "LastErrorAt": health.last_error_at,
            "LastWriteAt": health.last_write_at,
            "Writes": health.writes,
            "Failures": health.failures,
            "ReadFailures": health.read_failures,
            "OK": bool(writable and health.ok),
        }


_SORTS: Final[dict[str, str]] = {
    "hits": "hits",
    "bytes": SIZE_SQL,
    "stored": "stored_at",
    "expires": "expires_at",
    "key": "lower(key)",
    "last_hit": "last_hit_at",
}
"""Cache browser sort columns (v1 SORT_FIELDS plus `last_hit`); anything else sorts by hits, like v1."""


# --- the store -------------------------------------------------------------------------------------------------------


@dataclass(slots=True)
class PurgeResult:
    removed: int
    floor: int
    stamp: int
    fleet_invalidated: bool
    memory_cleared: int


class CacheStore:
    """The memory tier, the shared tier and the buffers of one worker, used together by the cache service."""

    def __init__(self, db: Database | None, clock: Clock) -> None:
        self._clock = clock
        self.memory = MemoryTier()
        self.shared = SharedTier(db, clock) if db is not None else None
        self.hits = HitBuffer()
        self.observations = ObservationBuffer()
        self.floor = 0
        self.stamp: int | None = None
        self.memory_invalidations = 0

    def configure(self, *, memory_entries: int, memory_bytes: int) -> None:
        self.memory.configure(memory_entries, memory_bytes)

    # ---- generation ----

    def observe_generation(self, floor: int, stamp: int) -> bool:
        """Remember the generation counters; True (and the memory tier is emptied) when they moved."""
        if self.stamp is None:
            self.floor, self.stamp = floor, stamp
            self.memory.floor = floor
            return False
        if floor == self.floor and stamp == self.stamp:
            return False
        self.floor, self.stamp = floor, stamp
        self.memory.floor = floor
        self.memory.clear()
        self.memory_invalidations += 1
        return True

    async def sync_generation(self) -> bool:
        """Poll the generation row (the per-worker watch loop); True when the memory tier was dropped."""
        if self.shared is None:
            return False
        try:
            floor, stamp = await self.shared.read_generation()
        except (SharedStateUnavailable, sqlite3.Error):
            return False
        return self.observe_generation(floor, stamp)

    # ---- lookups and stores ----

    async def lookup(
        self, ids: Sequence[str], *, now: float, disk: bool, fresh_short_circuit: str | None = None
    ) -> dict[str, CacheEntry]:
        """Entries for `ids` (fresh or not; the caller decides), memory first, then cache.db.

        When `fresh_short_circuit` names an id that is fresh in memory, disk is not read at all.
        """
        from_memory: dict[str, CacheEntry] = {}
        need_disk: list[str] = []
        for entry_id in ids:
            entry = self.memory.get(entry_id)
            if entry is not None:
                from_memory[entry_id] = entry
            if entry is None or not entry.is_fresh(now):
                need_disk.append(entry_id)
        if fresh_short_circuit is not None:
            hit = from_memory.get(fresh_short_circuit)
            if hit is not None and hit.is_fresh(now):
                return from_memory
        if not disk or self.shared is None or not need_disk:
            return from_memory
        try:
            result = await self.shared.read(need_disk)
        except (SharedStateUnavailable, sqlite3.Error) as exc:
            self.shared.health.failed(f"{type(exc).__name__}: {exc}", self._clock.now(), read=True)
            return from_memory
        if self.observe_generation(result.floor, result.stamp):
            from_memory = {}  # a purge happened: memory copies are no longer trustworthy
        found = dict(from_memory)
        for entry_id, entry in result.entries.items():
            current = found.get(entry_id)
            if current is None or entry.stored_at >= current.stored_at:
                found[entry_id] = entry
                self.memory.put(entry)  # promote, so the next lookup is served from memory
        return found

    async def get(self, entry_id: str, *, now: float, disk: bool) -> CacheEntry | None:
        return (await self.lookup([entry_id], now=now, disk=disk)).get(entry_id)

    async def put(self, entry: CacheEntry, *, disk: bool, compress: bool, req_body: bytes | None = None) -> bool:
        """Store in memory, and in cache.db when `disk`; True only when the cache.db write landed."""
        self.memory.put(entry)
        if not disk:
            return False
        return await self.write_shared(entry, compress=compress, req_body=req_body)

    async def write_shared(self, entry: CacheEntry, *, compress: bool, req_body: bytes | None = None) -> bool:
        """Write one row to cache.db only (the service already put the entry in memory before answering).
        Never raises; False when there is no shared tier or the write failed (recorded in disk health)."""
        if self.shared is None:
            return False
        return await self.shared.write(entry, compress=compress, req_body=req_body)

    async def read_handoff(self, entry_id: str) -> CacheEntry | None:
        """A single-flight handoff row straight from cache.db, never promoted into the memory tier (a big body
        read once by followers must not push the hot entries out). None when missing or unreadable."""
        if self.shared is None:
            return None
        try:
            result = await self.shared.read([entry_id])
        except (SharedStateUnavailable, sqlite3.Error) as exc:
            self.shared.health.failed(f"{type(exc).__name__}: {exc}", self._clock.now(), read=True)
            return None
        return result.entries.get(entry_id)

    def record_hit(self, entry_id: str, now: float) -> None:
        self.hits.record(entry_id, int(now))

    async def flush(self) -> int:
        """Write buffered hits and change observations (every `metrics_flush_interval_ms`, and on shutdown)."""
        hits = self.hits.drain()
        observations = self.observations.drain()
        if self.shared is None or (not hits and not observations):
            return 0
        try:
            return await self.shared.flush(hits, observations)
        except (SharedStateUnavailable, sqlite3.Error) as exc:
            self.hits.restore(hits)
            self.observations.restore(observations)
            log.warning("cache_flush_failed", extra={"fields": {"error": str(exc)[:200]}})
            return 0

    # ---- purges ----

    async def purge(self, scope: PurgeScope, *, now: float) -> PurgeResult:
        """Run one purge (plan 6.5, 6.8): stamp first, batched deletes, stamp again. Raises ValueError for a bad
        scope and `SharedStateUnavailable` when cache.db cannot be written (the caller reports it)."""
        scope = scope.validated()
        cleared = self.memory.clear()
        if self.shared is None:
            return PurgeResult(cleared, self.floor, self.stamp or 0, False, cleared)
        shared = self.shared
        now_s = int(now)
        floor, stamp = await shared.bump_generation(purge_all=scope.kind == PurgeKind.ALL, now_s=now_s)
        self.observe_generation(floor, stamp)
        removed = await self._purge_rows(shared, scope, floor, now_s)
        # Second stamp: any worker that loaded a soon-deleted row into memory during the deletes drops it now.
        floor, stamp = await shared.bump_generation(purge_all=False, now_s=now_s)
        self.observe_generation(floor, stamp)
        self.memory.clear()
        if scope.kind == PurgeKind.ALL:
            await self._incremental_vacuum()
        return PurgeResult(removed, floor, stamp, True, cleared)

    @staticmethod
    async def _purge_rows(shared: SharedTier, scope: PurgeScope, floor: int, now_s: int) -> int:
        kind = scope.kind
        if kind == PurgeKind.ALL:
            return await shared.delete_where("generation < ?", (floor,))
        if kind == PurgeKind.ID:
            return await shared.delete_ids([str(scope.value)])
        if kind == PurgeKind.HOST:
            return await shared.delete_where("host = ?", (scope.value,))
        if kind == PurgeKind.RULE:
            return await shared.delete_where("rule_id = ?", (scope.value,))
        if kind == PurgeKind.EXPIRED:
            column = "expires_at" if scope.include_stale else "stale_until"
            return await shared.delete_where(f"{column} <= ?", (now_s,))
        if kind == PurgeKind.PATTERN:
            pattern, pattern_type = str(scope.value), scope.pattern_type

            def matches(row: sqlite3.Row) -> bool:
                return target_matches(pattern, pattern_type, f"{row['host']}/{row['path']}")

            return await shared.delete_matching("host, path", matches)
        name = str(scope.value)
        return await shared.delete_matching("params_json", lambda row: _params_mention(row["params_json"], name))

    async def _incremental_vacuum(self) -> None:
        if self.shared is None:
            return
        try:
            await self.shared.db.maintenance(lambda conn: conn.execute("PRAGMA incremental_vacuum(2000)").fetchall())
        except (SharedStateUnavailable, sqlite3.Error) as exc:
            log.warning("cache_vacuum_failed", extra={"fields": {"error": str(exc)[:200]}})

    # ---- maintenance ----

    async def maintain(self, *, max_entries: int, max_bytes: int, policy: str, now: float) -> EvictionReport:
        """Delete rows whose stale window ended, then evict down to the budgets (one worker at a time)."""
        if self.shared is None:
            return EvictionReport()
        dead = await self.remove_dead(now)
        report = await self.shared.evict(max_entries=max_entries, max_bytes=max_bytes, policy=policy, now=now)
        report.dead = dead
        return report

    async def remove_dead(self, now: float) -> int:
        """Delete rows whose stale window ended (expired entries, markers and single-flight handoff rows). Also run
        while the disk tier is switched off, because handoff rows are still written then."""
        if self.shared is None:
            return 0
        return await self.shared.delete_where("stale_until <= ?", (int(now),))


__all__ = [
    "SIZE_SQL",
    "CacheEntry",
    "CacheStore",
    "DiskHealth",
    "EvictionReport",
    "HitBuffer",
    "MemoryTier",
    "ObservationBuffer",
    "PurgeKind",
    "PurgeResult",
    "PurgeScope",
    "ReadResult",
    "SharedTier",
    "decode_body",
    "encode_body",
    "stored_size",
    "target_matches",
]
