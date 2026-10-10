"""Request samples: one small row per proxied request, the raw material for dry-run replay and TTL tuning.

What this is
    `SampleRow` (one `request_samples` row), `should_sample` (the `request_sample_pct` coin flip) and `write_samples`
    (the batch writer handler); `RefusalSample`, `should_sample_refusal` and `write_refusal_samples` for the
    requests a limiter refused (`refusal_samples`, metrics.db schema 7).

Why it exists
    Plan 6.2 and 11.3: before a recommendation changes a cache TTL or a bucket, Roxy replays the last day of
    requests against the proposed settings ("this TTL would have saved 3,200 upstream calls"), and the TTL tuner
    looks at how often the same cache key was fetched and whether the body changed. Rollups are too coarse for
    that (they do not know cache keys), so each proxied request leaves one compact row: the cache key id, the
    template, how it was served, a hash of the body and its size. No client address is stored, only its keyed
    hash. A limit change (THROTTLE-TUNE, the place limit, an endpoint rule) is replayed over the requests the limiter
    SAW, admitted and refused; the refused ones are not proxied requests, so they get their own small table (review
    round 4, finding LOGICFIX-5: without them the replay of a raised limit previewed about zero refusals).

How it works
    - Only requests that reached the cache or upstream stage are request samples (outcome `served_upstream`,
      `served_cache` or `failed`); refusals are not "proxied requests".
    - A refusal by the per-IP throttle or by a check after it in the abuse pipeline (`LIMIT_STREAM_REASONS`: those
      requests reached the per-IP limiter) is a refusal sample, with the same coin flip. A worker keeps at most
      `MAX_REFUSAL_SAMPLES_PER_MINUTE` a minute, so a flood the limiter refuses never multiplies metrics writes; the
      rest are counted (`refusal_samples_capped` in the recorder stats) and the replay is then a lower bound.
    - `request_sample_pct` (default 100) is a per-request coin flip, so the sample stays unbiased; each row keeps
      the rate it was taken at (`sample_pct`), so a dry run counts it for 100 / its own rate even after the rate
      changed (finding LOGICFIX-6).
    - Rows go through the batch writer at the lowest priority: under memory pressure samples are the first
      thing dropped (counted in `metrics_dropped`). Age (`request_sample_hours`, 24) and the row cap
      (`request_sample_max_rows`, 3,000,000) are enforced by the storage retention job, for both tables.

What to read next
    `roxy/metrics/recorder.py` (where samples are taken), `roxy/storage/retention.py` (`prune_request_samples`),
    `roxy/insights/simulate.py` (`dry_run`, `_limit_replays`).
"""

from __future__ import annotations

import random
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

SAMPLED_OUTCOMES = frozenset({"served_upstream", "served_cache", "failed"})

LIMIT_STREAM_ORDER: Final[tuple[str, ...]] = (
    "throttle",
    "place_limit",
    "challenge",
    "bot_score",
    "user_agent_rule",
    "ignored_path",
    "unsafe_url",
    "not_roblox",
    "host_not_allowed",
    "auth_smuggling",
    "header_rule",
    "endpoint_blocked",
    "endpoint_rule",
)
"""Refusal reasons of the per-IP throttle and of every check after it, in the abuse pipeline's order (DESIGN 11.1
step 4): each of these requests reached the per-IP limiter, and the ones after a check reached that check too."""
LIMIT_STREAM_REASONS: Final[frozenset[str]] = frozenset(LIMIT_STREAM_ORDER)
"""Refusals kept as refusal samples (see `LIMIT_STREAM_ORDER`)."""
MAX_REFUSAL_SAMPLES_PER_MINUTE: Final = 6000
"""Refusal samples one worker keeps per minute (100 a second): a flood the limiter refuses never multiplies metrics
writes (plan P9); a module constant (a safety bound, not a tuning knob)."""


def reasons_from(check: str) -> frozenset[str]:
    """The refusal reasons of `check` and of every check after it (`LIMIT_STREAM_ORDER`): the refused part of the
    stream that reached `check`."""
    if check not in LIMIT_STREAM_ORDER:
        return frozenset()
    return frozenset(LIMIT_STREAM_ORDER[LIMIT_STREAM_ORDER.index(check) :])


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
    sample_pct: float | None = None


@dataclass(slots=True)
class RefusalSample:
    """One `refusal_samples` row: a request a limiter check refused (`LIMIT_STREAM_REASONS`)."""

    at_ms: int
    reason: str
    endpoint_template: str
    method: str
    client_hash: str | None
    place: str | None
    sample_pct: float | None = None


def _coin(pct: float, rnd: Callable[[], float]) -> bool:
    if pct <= 0:
        return False
    return pct >= 100 or rnd() * 100.0 < pct


def should_sample(outcome: str, pct: float, rnd: Callable[[], float] = random.random) -> bool:
    """True for a proxied request that wins the `request_sample_pct` coin flip."""
    if outcome not in SAMPLED_OUTCOMES:
        return False
    return _coin(pct, rnd)


def should_sample_refusal(reason: str, pct: float, rnd: Callable[[], float] = random.random) -> bool:
    """True for a refusal of `LIMIT_STREAM_REASONS` that wins the same coin flip."""
    if reason not in LIMIT_STREAM_REASONS:
        return False
    return _coin(pct, rnd)


def write_samples(conn: sqlite3.Connection, rows: list[SampleRow]) -> None:
    """Batch writer handler."""
    conn.executemany(
        """
        INSERT INTO request_samples (at_ms, key_id, endpoint_template, method, client_hash, place, cache_state,
                                     upstream_status, egress, body_hash, bytes, auth_class, sample_pct)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                r.sample_pct,
            )
            for r in rows
        ],
    )


def write_refusal_samples(conn: sqlite3.Connection, rows: list[RefusalSample]) -> None:
    """Batch writer handler of `refusal_samples`."""
    conn.executemany(
        "INSERT INTO refusal_samples (at_ms, reason, endpoint_template, method, client_hash, place, sample_pct) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        [(r.at_ms, r.reason, r.endpoint_template, r.method, r.client_hash, r.place, r.sample_pct) for r in rows],
    )


__all__ = [
    "LIMIT_STREAM_ORDER",
    "LIMIT_STREAM_REASONS",
    "MAX_REFUSAL_SAMPLES_PER_MINUTE",
    "SAMPLED_OUTCOMES",
    "RefusalSample",
    "SampleRow",
    "reasons_from",
    "should_sample",
    "should_sample_refusal",
    "write_refusal_samples",
    "write_samples",
]
