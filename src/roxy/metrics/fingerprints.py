"""Request fingerprints: which header names, header values and User-Agents callers send (parity rows 79, 134).

What this is
    `FingerprintAggregator` collects, per worker and in memory, counts of header names, header values and
    User-Agents for the requests that passed every refusal check, and hands them to the batch writer every flush;
    `write_fingerprints` upserts them into `fingerprint_headers`, `fingerprint_values` and
    `fingerprint_user_agents`. `value_for_storage` decides what is stored for a value (sensitive values only as a
    hash), and `auto_ignore_candidates` finds headers whose values are unique on almost every request (request
    ids, timestamps) so the leader can stop listing them. Each User-Agent row also keeps what its newest request
    looked like (v1's User-Agent drill-down, metrics.db schema 8): `RequestDetail`.

Why it exists
    Unusual header names and User-Agents are the quickest way to recognize a client or an exploit tool, and the
    header drill-down shows which values a header carries. v1 stored non-sensitive values raw (bug B21: custom
    API key headers and `X-Forwarded-For` chains in clear text) and decided auto-ignore per worker, counting the
    same value once per worker (bug B22). v2 hashes every value whose header name says secret (the shared
    `is_sensitive_key` rule: cookies, authorization, CSRF and API keys, tokens), never keeps a value of a header
    that carries client addresses (`ADDRESS_HEADERS`: their names are still counted), scrubs the rest with
    `redact_text`, and decides auto-ignore centrally from the shared table.

How it works
    - Per header pair: the name is lowercased and cut to 120 characters (v1). A header name is caller text too
      (any HTTP token, so 40 characters of the credential make a valid name, and caller headers are never
      forwarded, so the leak guard never sees them): a name that `redact_label` changes is stored as `fp:` plus
      the keyed hash of the whole name, and its values only as hashes (finding cred-7, plan 9.15). Values of
      ignored headers (the `ignored_value_headers` table, through the rules snapshot) are not recorded; the name
      still is. Values of `ADDRESS_HEADERS` are never recorded, whatever the ignore list says: they are shipped
      as default ignored headers (`config/defaults.py`, so the dashboard lists why), the aggregator and the writer
      skip them, and the leader's fingerprint job deletes any a previous release stored (`clear_address_values`).
    - Header values and User-Agents are recorded as the caller wrote them (`core/header_text.py`: UTF-8, invalid
      bytes as `\\xNN`), not as the Latin-1 text the checks match.
    - Stored value: `(empty)` for an empty value; `fp:` plus 12 hex characters of a keyed hash for sensitive
      headers (HMAC with the `ip_hash_key` credential when present, else SHA-256 like v1); otherwise the first
      200 characters, run through `redact_text` once per distinct value at flush time (a value that redaction
      changes is stored as its hash instead).
    - The User-Agent drill-down: per User-Agent the aggregator keeps only the detail of the newest request it saw
      (a reference to the request's own path, address and header name list: no copy, no work on the request
      path); `write_fingerprints` turns it into `last_path` (scrubbed, 300 characters), `last_caller` (the client
      address, as the Endpoints page's last caller), `last_header_names` (a JSON array of at most 64 names, each
      stored as above) and `last_detail_at`, and the upsert keeps the newest detail across workers.
    - The aggregator is bounded: past `MAX_PENDING_*` distinct keys per flush new keys are dropped and counted.
    - `write_fingerprints` adds counts with `ON CONFLICT DO UPDATE`, keeps `first_seen` and `last_seen`, and keeps
      at most `max_header_value_records` values per header by deleting the least seen ones (v1 evicted the
      smallest count too).
    - Auto-ignore (central, a leader job): a header seen on at least 500 requests whose stored values are at the
      per-header cap and were seen about once each (stored values / their total count >= 0.9) is added to the
      ignore list as an `auto` entry, and its stored values are deleted.

What to read next
    `roxy/metrics/recorder.py` (`record_fingerprint`), `roxy/metrics/jobs.py` (the auto-ignore job),
    `roxy/metrics/read_security.py` (`user_agent_detail`) and `roxy/core/redact.py` (`is_sensitive_key`).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Final

from roxy.config.constants import CLIENT_ADDRESS_HEADERS
from roxy.core.header_text import header_text
from roxy.core.redact import is_sensitive_key, redact_label, redact_text

MAX_NAME_CHARS = 120
MAX_VALUE_CHARS = 200
MAX_UA_CHARS = 400
EMPTY_VALUE = "(empty)"
NO_USER_AGENT = "(none)"

MAX_LAST_PATH_CHARS: Final = 300
"""The User-Agent drill-down keeps this much of the newest request's target (v1 `LastPath` kept 300)."""
MAX_LAST_CALLER_CHARS: Final = 64
"""The newest request's client address, cut like the Live row's `ip` (v1 `LastIP` kept 64)."""
MAX_LAST_HEADER_NAMES: Final = 64
"""Header names kept for the newest request of a User-Agent (in the order sent; plan P9)."""

AUTO_IGNORE_MIN_REQUESTS = 500
"""v1 `config.AUTO_IGNORE_MIN_REQUESTS`: a header must be seen this often before auto-ignore is considered."""

AUTO_IGNORE_UNIQUE_RATIO = 0.9
"""v1 `config.AUTO_IGNORE_UNIQUE_RATIO`: share of distinct values at which a header counts as unique per request."""

MAX_PENDING_NAMES = 2000
MAX_PENDING_VALUES = 5000
MAX_PENDING_USER_AGENTS = 2000

ADDRESS_HEADERS: Final[frozenset[str]] = frozenset(CLIENT_ADDRESS_HEADERS)
"""Headers that carry client (or proxy) addresses (`config/constants.py CLIENT_ADDRESS_HEADERS`): their values are
never kept, not even hashed (fix for v1 bug B21; a hash of an address still tells one client from another). Their
names are counted like any header. Shipped as default ignored headers (`config/defaults.py`) so the dashboard lists
them and says why."""

V1_SENSITIVE = frozenset({"x-roblox-token", "cookie", "authorization", "x-csrf-token"})
"""v1 `_value_for_storage` hashed exactly these; v2 hashes them and every `is_sensitive_key` name."""


def keeps_no_values(name_lower: str) -> bool:
    """True for a header whose values are never stored at all (`ADDRESS_HEADERS`), whatever the ignore list says."""
    return name_lower in ADDRESS_HEADERS


def hashes_value(name_lower: str) -> bool:
    """True when values of this header are never stored as they were sent: only as a hash, or (an address
    header) not at all. The v1 migrator imports no value of such a header."""
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


def name_for_storage(raw_name: str, key: bytes | None = None) -> tuple[str, bool]:
    """`(stored name, hidden)` for one header name: lowercased and cut to `MAX_NAME_CHARS` (v1), or, when the name
    holds something secret-shaped, `fp:` plus the keyed hash of the whole lowercased name (`hidden` True).

    Judged before the cut, so a credential piece that straddles character 120 is still found.
    """
    name = str(raw_name).lower()
    if name and redact_label(name) != name:
        return value_hash_text(name, key), True
    return name[:MAX_NAME_CHARS], False


def row_hash(*parts: str) -> str:
    """Primary key of a value or UA row: SHA-256 of the parts joined by NUL, first 32 hex characters."""
    return hashlib.sha256("\x00".join(parts).encode("utf-8", "replace")).hexdigest()[:32]


@dataclass(frozen=True, slots=True)
class RequestDetail:
    """What one request looked like, for its User-Agent's drill-down (v1 `LastPath`, `LastIP`, `LastHeaders`).

    Raw and uncopied: `path` is the request's target (host and path, no query), `caller` its client address and
    `header_names` the request's own list of header names in the order sent. `write_fingerprints` scrubs, cuts and
    hashes them once per User-Agent per flush, on the writer thread.
    """

    path: str
    caller: str
    header_names: Sequence[str]


@dataclass(slots=True)
class FingerprintItem:
    """One aggregated delta for the batch writer. `kind` is `h` (header name), `v` (value) or `u` (UA); a `u` item
    may carry the `detail` of the newest request of that User-Agent this worker saw."""

    kind: str
    key: str  # header name, (name, stored value) joined by NUL, or the User-Agent text
    count: int
    first_seen: int
    last_seen: int
    detail: RequestDetail | None = None


class FingerprintAggregator:
    """Per-worker, in-memory fingerprint counts between two flushes (bounded)."""

    def __init__(self, hash_key: bytes | None = None) -> None:
        self.hash_key = hash_key
        self._lock = threading.Lock()
        self._names: dict[str, list[int]] = {}
        self._values: dict[tuple[str, str], list[int]] = {}
        self._uas: dict[str, list[int]] = {}
        self._details: dict[str, RequestDetail] = {}  # keys are always keys of `_uas` (bounded with it)
        self.dropped = 0

    def add(
        self,
        pairs: Iterable[tuple[str, str]],
        user_agent: str | None,
        now_s: int,
        ignored: frozenset[str] | set[str] = frozenset(),
        detail: RequestDetail | None = None,
    ) -> None:
        """Count one request's headers and User-Agent (and keep `detail` as its User-Agent's newest request)."""
        with self._lock:
            for raw_name, raw_value in pairs:
                name, hidden = name_for_storage(raw_name, self.hash_key)
                if not name:
                    continue
                self._bump(self._names, name, now_s, MAX_PENDING_NAMES)
                if name in ignored or keeps_no_values(name):
                    continue  # the name is counted; its value is not kept (an ignored or an address header)
                value = header_text(str(raw_value))
                # A secret-shaped name makes its value suspect too: store it only as a hash.
                stored = (
                    value_hash_text(value, self.hash_key)
                    if hidden and value
                    else value_for_storage(name, value, self.hash_key)
                )
                self._bump(self._values, (name, stored), now_s, MAX_PENDING_VALUES)
            ua = header_text(user_agent or NO_USER_AGENT)[:MAX_UA_CHARS]
            if self._bump(self._uas, ua, now_s, MAX_PENDING_USER_AGENTS) and detail is not None:
                self._details[ua] = detail  # the newest request of this User-Agent seen by this worker

    def _bump(self, store: dict[Any, list[int]], key: Any, now_s: int, cap: int) -> bool:
        """Count one occurrence of `key`; False when the store is full and the key is new (dropped, counted)."""
        entry = store.get(key)
        if entry is None:
            if len(store) >= cap:
                self.dropped += 1
                return False
            store[key] = [1, now_s, now_s]
            return True
        entry[0] += 1
        entry[2] = now_s
        return True

    def drain(self) -> list[FingerprintItem]:
        """Hand over (and forget) everything counted since the last call."""
        with self._lock:
            names, self._names = self._names, {}
            values, self._values = self._values, {}
            uas, self._uas = self._uas, {}
            details, self._details = self._details, {}
        items = [FingerprintItem("h", n, c, f, last) for n, (c, f, last) in names.items()]
        items += [FingerprintItem("v", f"{n}\x00{v}", c, f, last) for (n, v), (c, f, last) in values.items()]
        items += [FingerprintItem("u", ua, c, f, last, details.get(ua)) for ua, (c, f, last) in uas.items()]
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


_NEWER_DETAIL: Final = (
    "excluded.last_detail_at IS NOT NULL AND (last_detail_at IS NULL OR excluded.last_detail_at >= last_detail_at)"
)
"""The upsert keeps the newest request detail of a User-Agent across workers and flushes (a flush without one, or
with an older one, leaves the stored detail as it is). In an UPSERT every SET expression sees the old row."""


def stored_detail(detail: RequestDetail | None, hash_key: bytes | None = None) -> tuple[str | None, ...]:
    """`(last_path, last_caller, last_header_names)` as stored for one request detail (all None without one).

    The path is scrubbed like a Live row's URL (`redact_text`) and cut to `MAX_LAST_PATH_CHARS`; the caller is the
    client address cut to `MAX_LAST_CALLER_CHARS`; the header names are the first `MAX_LAST_HEADER_NAMES` names in
    the order sent, each as `name_for_storage` stores it (a secret-shaped name as `fp:<keyed hash>`), repeats kept,
    as a JSON array. Names only: no header value is ever part of the drill-down.
    """
    if detail is None:
        return None, None, None
    path = redact_text(str(detail.path or ""))[:MAX_LAST_PATH_CHARS]
    caller = str(detail.caller or "")[:MAX_LAST_CALLER_CHARS]
    names: list[str] = []
    for raw in list(detail.header_names)[:MAX_LAST_HEADER_NAMES]:
        name, _hidden = name_for_storage(str(raw), hash_key)
        if name:
            names.append(name)
    return path or None, caller or None, json.dumps(names, ensure_ascii=False, separators=(",", ":"))


def clear_address_values(conn: sqlite3.Connection) -> int:
    """Delete every stored value of an `ADDRESS_HEADERS` header (the leader's fingerprint job): values a previous
    release stored (hashed) before this one stopped keeping them, or that an older color wrote during a deploy."""
    marks = ", ".join("?" for _ in ADDRESS_HEADERS)
    return int(
        conn.execute(
            f"DELETE FROM fingerprint_values WHERE name IN ({marks})",  # noqa: S608 (placeholders only)
            sorted(ADDRESS_HEADERS),
        ).rowcount
    )


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
        if keeps_no_values(name):
            continue  # defense in depth: an address header's value is never written (the aggregator skips it too)
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
        path, caller, sent = stored_detail(item.detail, hash_key)
        at = item.last_seen if item.detail is not None else None
        ua_rows.append((row_hash(ua), ua, item.count, item.first_seen, item.last_seen, path, caller, sent, at))
    conn.executemany(
        f"""
        INSERT INTO fingerprint_user_agents (ua_hash, user_agent, count, first_seen, last_seen, last_path,
            last_caller, last_header_names, last_detail_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (ua_hash) DO UPDATE SET count = count + excluded.count,
            first_seen = min(first_seen, excluded.first_seen), last_seen = max(last_seen, excluded.last_seen),
            last_path = CASE WHEN {_NEWER_DETAIL} THEN excluded.last_path ELSE last_path END,
            last_caller = CASE WHEN {_NEWER_DETAIL} THEN excluded.last_caller ELSE last_caller END,
            last_header_names = CASE WHEN {_NEWER_DETAIL} THEN excluded.last_header_names ELSE last_header_names END,
            last_detail_at = CASE WHEN {_NEWER_DETAIL} THEN excluded.last_detail_at ELSE last_detail_at END
        """,  # noqa: S608 (a fixed SQL condition, no caller text)
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
