"""Request samples: one small row per proxied request, the raw material for dry-run replay and TTL tuning.

What this is
    `SampleRow` (one `request_samples` row), `should_sample` (the `request_sample_pct` coin flip), `sample_from`
    (build a row from an outcome event) and `write_samples` (the batch writer handler).

Why it exists
    Plan 6.2 and 11.3: before a recommendation changes a cache TTL or a bucket, Roxy replays the last day of
    requests against the proposed settings ("this TTL would have saved 3,200 upstream calls"), and the TTL tuner
    looks at how often the same cache key was fetched and whether the body changed. Rollups are too coarse for
    that (they do not know cache keys), so each proxied request leaves one compact row: the cache key id, the
    template, how it was served, a hash of the body and its size. No client address is stored, only its keyed
    hash.

How it works
    - Only requests that reached the cache or upstream stage are sampled (outcome `served_upstream`,
      `served_cache` or `failed`); refusals are not "proxied requests".
    - `request_sample_pct` (default 100) is a per-request coin flip, so the sample stays unbiased.
    - Rows go through the batch writer at the lowest priority: under memory pressure samples are the first
      thing dropped (counted in `metrics_dropped`). Age (`request_sample_hours`, 24) and the row cap
      (`request_sample_max_rows`, 3,000,000) are enforced by the storage retention job.

What to read next
    `roxy/metrics/recorder.py` (where samples are taken), `roxy/storage/retention.py` (`prune_request_samples`).
"""

from __future__ import annotations

import random
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass

SAMPLED_OUTCOMES = frozenset({"served_upstream", "served_cache", "failed"})


@dataclass(slots=True)
class SampleRow:
    """One `request_samples` row."""

    at_ms: int
    key_id: str | None
    endpoint_template: str
    method: str
    client_hash: str | None
    place: str | None
    cache_state: str | None
    upstream_status: int | None
    egress: str | None
    body_hash: str | None
    bytes: int
    auth_class: str | None


def should_sample(outcome: str, pct: float, rnd: Callable[[], float] = random.random) -> bool:
    """True for a proxied request that wins the `request_sample_pct` coin flip."""
    if outcome not in SAMPLED_OUTCOMES or pct <= 0:
        return False
    return pct >= 100 or rnd() * 100.0 < pct


def write_samples(conn: sqlite3.Connection, rows: list[SampleRow]) -> None:
    """Batch writer handler."""
    conn.executemany(
        """
        INSERT INTO request_samples (at_ms, key_id, endpoint_template, method, client_hash, place, cache_state,
                                     upstream_status, egress, body_hash, bytes, auth_class)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                r.at_ms,
                r.key_id,
                r.endpoint_template,
                r.method,
                r.client_hash,
                r.place,
                r.cache_state,
                r.upstream_status,
                r.egress,
                r.body_hash,
                r.bytes,
                r.auth_class,
            )
            for r in rows
        ],
    )
