"""Request fingerprints: which header names, header values and User-Agents callers send (parity rows 79, 134).

What this is
    `FingerprintAggregator` collects, per worker and in memory, counts of header names, header values and
    User-Agents for the requests that passed every refusal check, and hands them to the batch writer every flush;
    `write_fingerprints` upserts them into `fingerprint_headers`, `fingerprint_values` and
    `fingerprint_user_agents`. `value_for_storage` decides what is stored for a value (sensitive values only as a
    hash), and `auto_ignore_candidates` finds headers whose values are unique on almost every request (request
    ids, timestamps) so the leader can stop listing them.

Why it exists
    Unusual header names and User-Agents are the quickest way to recognize a client or an exploit tool, and the
    header drill-down shows which values a header carries. v1 stored non-sensitive values raw (bug B21: custom
    API key headers and `X-Forwarded-For` chains in clear text) and decided auto-ignore per worker, counting the
    same value once per worker (bug B22). v2 hashes every value whose header name says secret (the shared
    `is_sensitive_key` rule: cookies, authorization, CSRF and API keys, tokens) and every header that carries
    client addresses, scrubs the rest with `redact_text`, and decides auto-ignore centrally from the shared table.

How it works
    - Per header pair: the name is lowercased and cut to 120 characters (v1). Values of ignored headers (the
      `ignored_value_headers` table, through the rules snapshot) are not recorded; the name still is.
    - Stored value: `(empty)` for an empty value; `fp:` plus 12 hex characters of a keyed hash for sensitive
      headers (HMAC with the `ip_hash_key` credential when present, else SHA-256 like v1); otherwise the first
      200 characters, run through `redact_text` once per distinct value at flush time (a value that redaction
      changes is stored as its hash instead).
    - The aggregator is bounded: past `MAX_PENDING_*` distinct keys per flush new keys are dropped and counted.
    - `write_fingerprints` adds counts with `ON CONFLICT DO UPDATE`, keeps `first_seen` and `last_seen`, and keeps
      at most `max_header_value_records` values per header by deleting the least seen ones (v1 evicted the
      smallest count too).
    - Auto-ignore (central, a leader job): a header seen on at least 500 requests whose stored values are at the
      per-header cap and were seen about once each (stored values / their total count >= 0.9) is added to the
      ignore list as an `auto` entry, and its stored values are deleted.

What to read next
    `roxy/metrics/recorder.py` (`record_fingerprint`), `roxy/metrics/jobs.py` (the auto-ignore job), and
    `roxy/core/redact.py` (`is_sensitive_key`).
"""

from __future__ import annotations

import hashlib
import hmac
import sqlite3
import threading
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from roxy.core.redact import is_sensitive_key, redact_text

MAX_NAME_CHARS = 120
MAX_VALUE_CHARS = 200
MAX_UA_CHARS = 400
EMPTY_VALUE = "(empty)"
NO_USER_AGENT = "(none)"

AUTO_IGNORE_MIN_REQUESTS = 500
"""v1 `config.AUTO_IGNORE_MIN_REQUESTS`: a header must be seen this often before auto-ignore is considered."""

AUTO_IGNORE_UNIQUE_RATIO = 0.9
"""v1 `config.AUTO_IGNORE_UNIQUE_RATIO`: share of distinct values at which a header counts as unique per request."""

MAX_PENDING_NAMES = 2000
MAX_PENDING_VALUES = 5000
MAX_PENDING_USER_AGENTS = 2000

ADDRESS_HEADERS = frozenset(
    {"x-forwarded-for", "x-real-ip", "forwarded", "cf-connecting-ip", "true-client-ip", "x-client-ip", "via"}
)
"""Headers that carry client addresses: stored hashed, like secrets (fix for v1 bug B21)."""

V1_SENSITIVE = frozenset({"x-roblox-token", "cookie", "authorization", "x-csrf-token"})
"""v1 `_value_for_storage` hashed exactly these; v2 hashes them and every `is_sensitive_key` name."""


def hashes_value(name_lower: str) -> bool:
    """True when values of this header are only ever stored as a hash."""
    return name_lower in V1_SENSITIVE or name_lower in ADDRESS_HEADERS or is_sensitive_key(name_lower)


def value_hash_text(value: str, key: bytes | None) -> str:
    """`fp:` plus 12 hex characters: keyed (HMAC-SHA256) when a key is configured, plain SHA-256 like v1."""
    data = value.encode("utf-8", "replace")
    digest = hmac.new(key, data, hashlib.sha256).hexdigest() if key else hashlib.sha256(data).hexdigest()
    return "fp:" + digest[:12]


def value_for_storage(name_lower: str, value: str, key: bytes | None = None) -> str:
    """What is stored for one header value (before the flush-time `redact_text` pass for plain values)."""
    if not value:
        return EMPTY_VALUE
    if hashes_value(name_lower):
        return value_hash_text(value, key)
    return value[:MAX_VALUE_CHARS]


def row_hash(*parts: str) -> str:
    """Primary key of a value or UA row: SHA-256 of the parts joined by NUL, first 32 hex characters."""
    return hashlib.sha256("\x00".join(parts).encode("utf-8", "replace")).hexdigest()[:32]


@dataclass(slots=True)
class FingerprintItem:
    """One aggregated delta for the batch writer. `kind` is `h` (header name), `v` (value) or `u` (UA)."""

    kind: str
    key: str  # header name, (name, stored value) joined by NUL, or the User-Agent text
    count: int
    first_seen: int
    last_seen: int


class FingerprintAggregator:
    """Per-worker, in-memory fingerprint counts between two flushes (bounded)."""

    def __init__(self, hash_key: bytes | None = None) -> None:
        self.hash_key = hash_key
        self._lock = threading.Lock()
        self._names: dict[str, list[int]] = {}
        self._values: dict[tuple[str, str], list[int]] = {}
        self._uas: dict[str, list[int]] = {}
        self.dropped = 0

    def add(
        self,
        pairs: Iterable[tuple[str, str]],
        user_agent: str | None,
        now_s: int,
        ignored: frozenset[str] | set[str] = frozenset(),
    ) -> None:
        """Count one request's headers and User-Agent."""
        with self._lock:
            for raw_name, raw_value in pairs:
                name = str(raw_name).lower()[:MAX_NAME_CHARS]
                if not name:
                    continue
                self._bump(self._names, name, now_s, MAX_PENDING_NAMES)
                if name in ignored:
                    continue
                stored = value_for_storage(name, str(raw_value), self.hash_key)
                self._bump(self._values, (name, stored), now_s, MAX_PENDING_VALUES)
            ua = (user_agent or NO_USER_AGENT)[:MAX_UA_CHARS]
            self._bump(self._uas, ua, now_s, MAX_PENDING_USER_AGENTS)

    def _bump(self, store: dict[Any, list[int]], key: Any, now_s: int, cap: int) -> None:
        entry = store.get(key)
        if entry is None:
            if len(store) >= cap:
                self.dropped += 1
                return
            store[key] = [1, now_s, now_s]
            return
        entry[0] += 1
        entry[2] = now_s

    def drain(self) -> list[FingerprintItem]:
        """Hand over (and forget) everything counted since the last call."""
        with self._lock:
            names, self._names = self._names, {}
            values, self._values = self._values, {}
            uas, self._uas = self._uas, {}
        items = [FingerprintItem("h", n, c, f, last) for n, (c, f, last) in names.items()]
        items += [FingerprintItem("v", f"{n}\x00{v}", c, f, last) for (n, v), (c, f, last) in values.items()]
        items += [FingerprintItem("u", ua, c, f, last) for ua, (c, f, last) in uas.items()]
        return items

    def pending(self) -> int:
        with self._lock:
            return len(self._names) + len(self._values) + len(self._uas)


def _display(name: str, stored: str, key: bytes | None) -> str:
    """Scrub a plain stored value once per distinct value; a value that redaction changes is stored hashed."""
    if stored == EMPTY_VALUE or stored.startswith("fp:"):
        return stored
    cleaned = redact_text(stored)
    return stored if cleaned == stored else value_hash_text(stored, key)


def write_fingerprints(
    conn: sqlite3.Connection, items: list[FingerprintItem], *, value_cap: int, hash_key: bytes | None = None
) -> None:
    """Batch writer handler: upsert names, values and User-Agents, then keep at most `value_cap` values per name."""
    names = [(i.key, i.count, i.first_seen, i.last_seen) for i in items if i.kind == "h"]
    conn.executemany(
        """
        INSERT INTO fingerprint_headers (name, count, first_seen, last_seen) VALUES (?, ?, ?, ?)
        ON CONFLICT (name) DO UPDATE SET count = count + excluded.count,
            first_seen = min(first_seen, excluded.first_seen), last_seen = max(last_seen, excluded.last_seen)
        """,
        names,
    )
    value_rows = []
    touched: set[str] = set()
    for item in items:
        if item.kind != "v":
            continue
        name, _, stored = item.key.partition("\x00")
        display = _display(name, stored, hash_key)
        value_rows.append((row_hash(name, display), name, display, item.count, item.first_seen, item.last_seen))
        touched.add(name)
    conn.executemany(
        """
        INSERT INTO fingerprint_values (value_hash, name, value, count, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT (value_hash) DO UPDATE SET count = count + excluded.count,
            first_seen = min(first_seen, excluded.first_seen), last_seen = max(last_seen, excluded.last_seen)
        """,
        value_rows,
    )
    ua_rows = []
    for item in items:
        if item.kind != "u":
            continue
        ua = item.key if item.key == NO_USER_AGENT else redact_text(item.key)[:MAX_UA_CHARS]
        ua_rows.append((row_hash(ua), ua, item.count, item.first_seen, item.last_seen))
    conn.executemany(
        """
        INSERT INTO fingerprint_user_agents (ua_hash, user_agent, count, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)
        ON CONFLICT (ua_hash) DO UPDATE SET count = count + excluded.count,
            first_seen = min(first_seen, excluded.first_seen), last_seen = max(last_seen, excluded.last_seen)
        """,
        ua_rows,
    )
    cap = max(1, int(value_cap))
    for name in touched:
        have = int(conn.execute("SELECT count(*) FROM fingerprint_values WHERE name = ?", (name,)).fetchone()[0])
        if have > cap:
            # Least seen first, then oldest: the values worth keeping for the drill-down survive (v1 by Count).
            conn.execute(
                """
                DELETE FROM fingerprint_values WHERE value_hash IN (
                    SELECT value_hash FROM fingerprint_values WHERE name = ?
                    ORDER BY count ASC, last_seen ASC LIMIT ?)
                """,
                (name, have - cap),
            )


@dataclass(frozen=True, slots=True)
class AutoIgnoreCandidate:
    name: str
    requests: int
    distinct_values: int
    value_hits: int

    @property
    def note(self) -> str:
        """The ignore list note, worded like v1's (`auto: N distinct values in M requests`)."""
        return f"auto: {self.distinct_values} distinct values in {self.requests} requests"


def auto_ignore_candidates(
    conn: sqlite3.Connection,
    *,
    value_cap: int,
    ignored: Iterable[str] = (),
    min_requests: int = AUTO_IGNORE_MIN_REQUESTS,
    ratio: float = AUTO_IGNORE_UNIQUE_RATIO,
) -> list[AutoIgnoreCandidate]:
    """Headers whose values are unique on almost every request, computed from the shared tables (fixes B22)."""
    skip = {name.lower() for name in ignored}
    rows = conn.execute(
        """
        SELECT h.name AS name, h.count AS requests, count(v.value_hash) AS distinct_values,
               coalesce(sum(v.count), 0) AS value_hits
        FROM fingerprint_headers h JOIN fingerprint_values v ON v.name = h.name
        WHERE h.count >= ?
        GROUP BY h.name HAVING count(v.value_hash) >= ?
        """,
        (int(min_requests), max(1, int(value_cap))),
    ).fetchall()
    found = []
    for row in rows:
        name = str(row["name"])
        hits = int(row["value_hits"])
        distinct = int(row["distinct_values"])
        if name in skip or hits <= 0:
            continue
        if distinct / hits >= ratio:
            found.append(AutoIgnoreCandidate(name, int(row["requests"]), distinct, hits))
    return found


def clear_values(conn: sqlite3.Connection, name: str) -> int:
    """Delete every stored value of one header (after it was added to the ignore list)."""
    return conn.execute("DELETE FROM fingerprint_values WHERE name = ?", (name.lower(),)).rowcount
