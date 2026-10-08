"""Request and response capture: the bodies behind a row of the Live view, redacted, sampled and short-lived.

What this is
    `CaptureInput` (what the proxy hands over for one request), `CapturePolicy` (the capture settings of plan
    15.3 I, read live), `build_record` (the redacted capture), `encode_record` / `decode_record` (zstd-compressed
    JSON in `captures.compressed_blob`), the batch writer handler `write_captures` (insert, then enforce the
    count, byte and age caps at once), and `get_capture` for `GET /admin/api/v1/live/{request_id}`.

Why it exists
    Seeing exactly what a game sent and what came back is the fastest way to debug a failing request (parity
    rows 81, 82, 127, 128). It is also caller data on disk, so v2 is stricter than v1: every secret-named header
    and query parameter is masked, bodies and URLs are scrubbed with `redact_text` (v1 redacted five header
    names and nothing else), served requests are sampled (`capture_sample_served_pct`, default 20; refusals are
    always captured), and captures expire after `capture_ttl_seconds` (default 15 minutes).

How it works
    - `CapturePolicy.wants(outcome)` decides per request; the recorder calls it and, when it says yes, builds
      the record, queues it for the batch writer and returns the capture id (the request id), which the Live
      row carries as `capture_id`. Capture never fails a request: the recorder wraps all of it, swallows any
      exception and counts it in `capture_errors` (row 127).
    - Bodies are cut to `capture_max_body` BYTES (0 keeps no body text) and decoded as UTF-8 with replacement
      characters; the original length is kept so the UI can say "truncated from N bytes".
    - `write_captures` inserts the batch and immediately prunes oldest-first beyond `capture_max_records` and
      `capture_max_bytes` and older than the TTL, so the caps hold within one flush, not only when the leader's
      retention job runs. `bytes` is the stored (compressed) size, which is what the disk cap is about.
    - A lookup of an expired or evicted capture returns None; the API answers 404 with
      `CAPTURE_EXPIRED_MESSAGE`, v1's exact text (row 128).

What to read next
    `roxy/metrics/recorder.py` (`record_capture`), `roxy/core/redact.py` (the redaction rules), then
    `roxy/storage/retention.py` (`prune_captures`, reused here).
"""

from __future__ import annotations

import json
import random
import sqlite3
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

import zstandard

from roxy.core.redact import redact_headers, redact_query, redact_text
from roxy.storage import retention

CAPTURE_EXPIRED_MESSAGE = "That capture has expired or was evicted."
"""v1 `/admin/live/detail` 404 text (index.py:615-627), kept verbatim (row 128; it contains no dash)."""

CAPTURE_OFF_MESSAGE = "Response capture was off for this request (Settings → capture_enabled)."
"""v1 dashboard text for a live row without a capture (the arrow is U+2192, not a dash)."""

MAX_HEADER_VALUE_CHARS = 2000
"""v1 clipped captured header values at 2000 characters."""

MAX_QUERY_CHARS = 2000
MAX_URL_CHARS = 2000
MAX_UA_CHARS = 400
ZSTD_LEVEL = 3
"""zstd level 3: fast (well under a millisecond for 16 KiB) and typically 3 to 5 times smaller for JSON."""

_COMPRESSOR = zstandard.ZstdCompressor(level=ZSTD_LEVEL)
_DECOMPRESSOR = zstandard.ZstdDecompressor()
MAX_DECODED_BYTES = 4 * 1024 * 1024
"""Upper bound when decompressing one capture (two bodies of at most 512 KiB plus headers fit easily)."""

SERVED_OUTCOMES = frozenset({"served_upstream", "served_cache"})


@dataclass(slots=True)
class CaptureInput:
    """Everything one capture may hold. Fields are raw; `build_record` redacts and truncates them."""

    request_id: str
    at_ms: int
    method: str = ""
    url: str = ""  # host/path, without the query
    query: str = ""
    ip: str = ""
    place_id: str | None = None
    user_agent: str = ""
    outcome: str = ""
    reason: str = ""
    status: int = 0
    upstream_status: int | None = None
    egress: str = ""
    request_headers: Mapping[str, str] | Iterable[tuple[str, str]] = field(default_factory=dict)
    request_body: bytes | str | None = None
    response_headers: Mapping[str, str] | Iterable[tuple[str, str]] = field(default_factory=dict)
    response_body: bytes | str | None = None


@dataclass(frozen=True, slots=True)
class CapturePolicy:
    """The capture settings (plan 15.3 I) as one immutable value."""

    enabled: bool = True
    max_records: int = 2000
    max_bytes: int = 64 * 1024 * 1024
    max_body: int = 16 * 1024
    ttl_s: int = 900
    sample_served_pct: float = 20.0

    @classmethod
    def from_settings(cls, get: Callable[[str], Any]) -> CapturePolicy:
        def value(key: str, fallback: Any) -> Any:
            try:
                found = get(key)
            except (KeyError, LookupError, AttributeError):
                return fallback
            return fallback if found is None else found

        return cls(
            enabled=bool(int(value("capture_enabled", 1))),
            max_records=max(0, int(value("capture_max_records", 2000))),
            max_bytes=max(0, int(value("capture_max_bytes", 64 * 1024 * 1024))),
            max_body=max(0, int(value("capture_max_body", 16 * 1024))),
            ttl_s=max(0, int(value("capture_ttl_seconds", 900))),
            sample_served_pct=min(100.0, max(0.0, float(value("capture_sample_served_pct", 20)))),
        )

    @property
    def active(self) -> bool:
        """Capture is on and every cap leaves room for at least one capture (0 means "keep none" in v2)."""
        return self.enabled and self.max_records > 0 and self.max_bytes > 0 and self.ttl_s > 0

    def wants(self, outcome: str, rnd: Callable[[], float] = random.random) -> bool:
        """Capture this request? Refusals and failures always; served requests at `sample_served_pct`."""
        if not self.active:
            return False
        if outcome not in SERVED_OUTCOMES:
            return True
        return self.sample_served_pct >= 100.0 or rnd() * 100.0 < self.sample_served_pct

    def retention_policy(self) -> retention.RetentionPolicy:
        return retention.RetentionPolicy(
            capture_ttl_seconds=self.ttl_s, capture_max_records=self.max_records, capture_max_bytes=self.max_bytes
        )


def truncate_body(value: bytes | str | None, max_body: int) -> tuple[str, bool, int]:
    """`(text, truncated, original length in bytes)`. Cut at `max_body` bytes; 0 keeps no body text."""
    if value is None:
        return "", False, 0
    raw = value if isinstance(value, bytes) else str(value).encode("utf-8", "replace")
    length = len(raw)
    if length == 0:
        return "", False, 0
    kept = raw[:max_body] if max_body > 0 else b""
    # errors="replace" keeps a partial multi-byte character at the cut visible as U+FFFD instead of failing.
    return kept.decode("utf-8", "replace"), len(kept) < length, length


def _headers(headers: Mapping[str, str] | Iterable[tuple[str, str]]) -> dict[str, str]:
    return redact_headers(headers, max_value_length=MAX_HEADER_VALUE_CHARS)


def build_record(inp: CaptureInput, policy: CapturePolicy) -> dict[str, Any]:
    """The redacted capture of one request (plan row 82: broader redaction than v1)."""
    request_body, request_cut, request_len = truncate_body(inp.request_body, policy.max_body)
    response_body, response_cut, response_len = truncate_body(inp.response_body, policy.max_body)
    return {
        "request_id": inp.request_id,
        "at_ms": int(inp.at_ms),
        "ip": inp.ip[:64],
        "method": inp.method[:12],
        "url": redact_text(inp.url)[:MAX_URL_CHARS],
        "query": redact_query(inp.query)[:MAX_QUERY_CHARS],
        "place_id": inp.place_id,
        "user_agent": redact_text(inp.user_agent)[:MAX_UA_CHARS],
        "outcome": inp.outcome,
        "reason": inp.reason,
        "status": int(inp.status),
        "upstream_status": inp.upstream_status,
        "egress": inp.egress,
        "request_headers": _headers(inp.request_headers),
        "request_body": redact_text(request_body),
        "request_body_truncated": request_cut,
        "request_body_length": request_len,
        "response_headers": _headers(inp.response_headers),
        "response_body": redact_text(response_body),
        "response_body_truncated": response_cut,
        "response_body_length": response_len,
    }


def encode_record(record: Mapping[str, Any]) -> bytes:
    data = json.dumps(record, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
    return _COMPRESSOR.compress(data)


def decode_record(blob: bytes) -> dict[str, Any]:
    data = _DECOMPRESSOR.decompress(bytes(blob), max_output_size=MAX_DECODED_BYTES)
    value = json.loads(data.decode("utf-8"))
    return value if isinstance(value, dict) else {}


@dataclass(slots=True)
class CaptureRow:
    """One queued capture for the batch writer."""

    at_s: int
    request_id: str
    outcome: str
    status: int
    blob: bytes


def make_row(inp: CaptureInput, policy: CapturePolicy) -> CaptureRow:
    record = build_record(inp, policy)
    return CaptureRow(int(inp.at_ms // 1000), inp.request_id, inp.outcome, int(inp.status), encode_record(record))


def write_captures(conn: sqlite3.Connection, rows: list[CaptureRow], policy: CapturePolicy, now_s: float) -> int:
    """Batch writer handler: insert the captures, then prune to the caps at once. Returns rows pruned."""
    conn.executemany(
        "INSERT INTO captures (at, request_id, outcome, status, compressed_blob, bytes) VALUES (?, ?, ?, ?, ?, ?)",
        [(r.at_s, r.request_id, r.outcome, r.status, r.blob, len(r.blob)) for r in rows],
    )
    pruned = 0
    keep = policy.retention_policy()
    while True:
        # retention.prune_captures handles TTL, count and bytes in one call, at most `limit` rows per call.
        step = retention.prune_captures(conn, now_s, keep, retention.BATCH_ROWS)
        pruned += step
        if step < retention.BATCH_ROWS:
            return pruned


def get_capture(conn: sqlite3.Connection, request_id: str, now_s: float, ttl_s: int) -> dict[str, Any] | None:
    """The newest capture for `request_id`, or None when there is none or it is older than the TTL (row 128)."""
    if not request_id:
        return None
    row = conn.execute(
        "SELECT at, compressed_blob FROM captures WHERE request_id = ? ORDER BY id DESC LIMIT 1", (request_id,)
    ).fetchone()
    if row is None or row["compressed_blob"] is None:
        return None
    if ttl_s <= 0 or now_s - int(row["at"]) > ttl_s:
        return None  # expired but not swept yet: same answer as evicted
    try:
        return decode_record(row["compressed_blob"])
    except (zstandard.ZstdError, ValueError):
        return None


def capture_state(conn: sqlite3.Connection, policy: CapturePolicy, now_s: float) -> dict[str, Any]:
    """v1 `capture.get_state()` fields, counting only captures inside the TTL (System and Live pages)."""
    cutoff = int(now_s - policy.ttl_s)
    row = conn.execute(
        "SELECT count(*) AS n, coalesce(sum(bytes), 0) AS b, min(at) AS oldest FROM captures WHERE at >= ?",
        (cutoff,),
    ).fetchone()
    oldest = int(row["oldest"]) if row["oldest"] is not None else None
    return {
        "enabled": policy.enabled,
        "count": int(row["n"]),
        "max_records": policy.max_records,
        "bytes": int(row["b"]),
        "max_bytes": policy.max_bytes,
        "max_body": policy.max_body,
        "ttl_s": policy.ttl_s,
        "sample_served_pct": policy.sample_served_pct,
        "oldest_at": oldest,
        "window_s": int(now_s - oldest) if oldest is not None else 0,
    }
