"""Producer history: rule hits per minute, tarpit holds, bot scores and metrics drops, summed in memory per worker.

What this is
    `ProducerHistory`, the part of the metrics recorder that fills the schema version 5 tables
    (`storage/migrations/metrics/0005_producer_history.sql`): `rule_hit` (one rule row matched a request),
    `tarpit` (one tarpit-eligible refusal, held or skipped, with its hold time and the client's arrival gap),
    `client_score` (a client's bot score) and, at every flush, the metrics items this worker dropped since the last
    flush. `write_producers(conn, items)` is the batch writer's handler for all of them, `HOLD_BOUNDS_MS` the hold
    histogram, and `prune_producers(conn, now_s, keep_days)` the retention step the leader job runs (it also bounds
    the two disk tables the leader writes, `metrics/disk_history.py`).

Why it exists
    Several recommendation rules waited on facts nothing recorded (integrate.md "Open issues"): which filter or bypass
    entry matched requests (FILTER-REMOVE, SEC-BYPASS-FOREVER), how the tarpit holds and whether holding slows
    clients down (TARPIT-TUNE, parity row 78), bot scores (ABUSE-BOT, THROTTLE-TUNE, ABUSE-DIST), and a metrics
    drop count that is fleet-wide and windowed (SYS-METRICS-DROP used one worker's lifetime counter, so it kept
    firing until that worker restarted). The request path must stay cheap (plan 6.3): no write per request, so each
    fact is added to a bounded dict here and written by the recorder's batch writer every flush.

How it works
    - Every map is keyed by minute (hour for scores) plus labels and bounded by `MAX_PRODUCER_KEYS`; a key that
      does not fit is counted in `dropped` (reported as `history_dropped`), never an exception (metrics degrade open,
      C7). Labels are cut to fixed lengths (P9).
    - The batch writer calls `drain()` at every flush (a "source", so these items never compete for the bounded
      queue and are never evicted by a burst of events). Each item becomes one upsert: counts add up, maxima keep
      the larger value, so two workers writing the same minute end with the fleet total (C6).
    - Drops: `drain()` asks the recorder for its cumulative counters (batch queue overflow, history map overflow,
      capture queue overflow) and writes the growth since the previous flush into this worker's row of the current
      minute. Summing those rows over a window answers "items dropped by every worker in the last hour".
    - Hold times go into a fixed-bucket histogram (`HOLD_BOUNDS_MS`, up to the 55 s hard cap of plan 10.6), so a
      p95 can be read for any range.

What to read next
    `roxy/metrics/recorder.py` (the `record_*` methods that call this), `roxy/metrics/read_producers.py` (the read
    models), `roxy/abuse/tarpit.py` and `roxy/abuse/pipeline.py` (the producers).
"""

from __future__ import annotations

import bisect
import sqlite3
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Final

from roxy.core.clock import SYSTEM_CLOCK, Clock

MAX_PRODUCER_KEYS: Final = 20_000
"""Keys each in-memory map holds between two flushes (a flush runs every 2 s; normal traffic fills a few hundred)."""
MAX_LABEL_CHARS: Final = 255
MAX_CATEGORY_CHARS: Final = 64
MAX_KIND_CHARS: Final = 16
MAX_CLIENT_KEY_CHARS: Final = 64
MAX_SCORE: Final = 100

HOLD_BOUNDS_MS: Final[tuple[int, ...]] = (
    250,
    500,
    1000,
    2000,
    3000,
    5000,
    8000,
    10000,
    12000,
    15000,
    20000,
    25000,
    30000,
    40000,
    55000,
)
"""Upper bounds (inclusive, ms) of the hold histogram: jitter holds (0.5 to 3 s by default) and holds (8 to 20 s)
both get several buckets, and 55 s is the hard cap of plan 10.6. A longer value lands in the overflow bucket."""
OVERFLOW_BOUND: Final = -1
"""`tarpit_hold_minute.bound_ms` of the overflow bucket."""

TABLE_RULE_HITS: Final = "rule_hit_minute"
TABLE_TARPIT: Final = "tarpit_minute"
TABLE_TARPIT_HOLDS: Final = "tarpit_hold_minute"
TABLE_SCORES: Final = "client_score_hour"
TABLE_PIPELINE: Final = "metrics_pipeline_minute"
TABLE_DISK: Final = "disk_samples"
TABLE_SIZES: Final = "table_size_samples"

DropCounters = Callable[[], tuple[int, int, int]]
"""`() -> (batch queue drops, history map drops, capture drops)`, each cumulative since the worker started."""


def hold_bound(held_s: float) -> int:
    """The histogram bucket (its upper bound in ms, or `OVERFLOW_BOUND`) of one hold."""
    ms = max(0.0, float(held_s)) * 1000.0
    index = bisect.bisect_left(HOLD_BOUNDS_MS, ms)
    return HOLD_BOUNDS_MS[index] if index < len(HOLD_BOUNDS_MS) else OVERFLOW_BOUND


@dataclass(slots=True)
class ProducerItem:
    """One upsert into a schema version 5 table (`table` names it; `key` and `values` fill its columns in order)."""

    table: str
    key: tuple[Any, ...]
    values: tuple[Any, ...]


class ProducerHistory:
    """Bounded in-memory sums of the producer facts of one worker (see the module docstring)."""

    def __init__(
        self, *, clock: Clock | None = None, worker_id: str = "", counters: DropCounters | None = None
    ) -> None:
        self.clock: Clock = clock or SYSTEM_CLOCK
        self.worker_id = worker_id or "worker"
        self.counters = counters
        self._lock = threading.Lock()  # producers run on the event loop; `flush_now` may drain from another thread
        self._rule_hits: dict[tuple[int, str, str], int] = {}
        # [holds, skipped, held_s_sum, held_s_max, gaps_after_hold, gap_after_hold_s, gaps_after_instant, gap_s]
        self._tarpit: dict[tuple[int, str, str], list[float]] = {}
        self._holds: dict[tuple[int, str, int], int] = {}
        self._scores: dict[tuple[int, str], list[int]] = {}  # [score_max, score_last, last_at, samples]
        self._reported = (0, 0, 0)  # the drop counters already written
        self.dropped = 0  # keys that did not fit a map (reported in `history_dropped`)
        self.errors = 0

    # ------------------------------------------------------------------------------------------- producers

    def _minute(self, at_s: float | None) -> int:
        when = float(at_s) if at_s is not None else self.clock.now()
        return int(when) // 60 * 60

    def _room(self, table: dict[Any, Any], key: Any) -> bool:
        """Whether `key` is in `table` or fits; counts a drop otherwise. Caller holds `_lock`."""
        if key in table or len(table) < MAX_PRODUCER_KEYS:
            return True
        self.dropped += 1
        return False

    def rule_hit(self, table: str, key: Any, count: int = 1, at_s: float | None = None) -> None:
        """`count` requests matched rule row `key` of control.db table `table` (summed per minute)."""
        slot = (self._minute(at_s), str(table)[:MAX_CATEGORY_CHARS], str(key)[:MAX_LABEL_CHARS])
        with self._lock:
            if self._room(self._rule_hits, slot):
                self._rule_hits[slot] = self._rule_hits.get(slot, 0) + max(0, int(count))

    def tarpit(
        self,
        *,
        category: str,
        kind: str,
        held_s: float = 0.0,
        skipped: bool = False,
        gap_s: float = 0.0,
        after_hold: bool | None = None,
        at_s: float | None = None,
    ) -> None:
        """One tarpit-eligible refusal: held for `held_s` seconds, or skipped. `gap_s` is the time since the client's
        previous eligible refusal (0: unknown or the first one) and `after_hold` whether that one was held."""
        minute = self._minute(at_s)
        name = str(category or "unknown")[:MAX_CATEGORY_CHARS]
        slot = (minute, name, str(kind or "hold")[:MAX_KIND_CHARS])
        held = max(0.0, float(held_s))
        gap = max(0.0, float(gap_s))
        with self._lock:
            if not self._room(self._tarpit, slot):
                return
            acc = self._tarpit.get(slot)
            if acc is None:
                acc = self._tarpit[slot] = [0, 0, 0.0, 0.0, 0, 0.0, 0, 0.0]
            if skipped:
                acc[1] += 1
            else:
                acc[0] += 1
                acc[2] += held
                acc[3] = max(acc[3], held)
                bucket = (minute, name, hold_bound(held))
                if self._room(self._holds, bucket):
                    self._holds[bucket] = self._holds.get(bucket, 0) + 1
            if gap > 0 and after_hold is not None:
                if after_hold:
                    acc[4] += 1
                    acc[5] += gap
                else:
                    acc[6] += 1
                    acc[7] += gap

    def client_score(self, client_key: str, score: int, at_s: float | None = None) -> None:
        """A bot score (0 to 100) one worker computed for a client address (summed per hour: max and latest)."""
        key = str(client_key or "")[:MAX_CLIENT_KEY_CHARS]
        if not key:
            return
        when = int(float(at_s) if at_s is not None else self.clock.now())
        value = max(0, min(MAX_SCORE, int(score)))
        slot = (when // 3600 * 3600, key)
        with self._lock:
            if not self._room(self._scores, slot):
                return
            acc = self._scores.get(slot)
            if acc is None:
                self._scores[slot] = [value, value, when, 1]
                return
            acc[0] = max(acc[0], value)
            if when >= acc[2]:
                acc[1], acc[2] = value, when
            acc[3] += 1

    # --------------------------------------------------------------------------------------------- draining

    def _drop_deltas(self) -> tuple[int, int, int] | None:
        """Growth of the recorder's drop counters since the last drain (None when nothing new was dropped)."""
        if self.counters is None:
            return None
        current = tuple(max(0, int(v)) for v in self.counters())
        previous = self._reported
        deltas = tuple(max(0, now - before) for now, before in zip(current, previous, strict=True))
        self._reported = (int(current[0]), int(current[1]), int(current[2]))
        return (deltas[0], deltas[1], deltas[2]) if any(deltas) else None

    def drain(self) -> list[ProducerItem]:
        """Everything summed since the last call, as upserts (the batch writer's source for `metrics.producers`)."""
        try:
            deltas = self._drop_deltas()
        except Exception:
            self.errors += 1
            deltas = None
        with self._lock:
            hits, self._rule_hits = self._rule_hits, {}
            tarpit, self._tarpit = self._tarpit, {}
            holds, self._holds = self._holds, {}
            scores, self._scores = self._scores, {}
        out = [ProducerItem(TABLE_RULE_HITS, key, (n,)) for key, n in hits.items() if n > 0]
        for key, acc in tarpit.items():
            values = (int(acc[0]), int(acc[1]), float(acc[2]), float(acc[3]), int(acc[4]), float(acc[5]))
            out.append(ProducerItem(TABLE_TARPIT, key, (*values, int(acc[6]), float(acc[7]))))
        out += [ProducerItem(TABLE_TARPIT_HOLDS, key, (n,)) for key, n in holds.items() if n > 0]
        out += [ProducerItem(TABLE_SCORES, key, tuple(acc)) for key, acc in scores.items()]
        if deltas is not None:
            out.append(ProducerItem(TABLE_PIPELINE, (self._minute(None), self.worker_id[:MAX_LABEL_CHARS]), deltas))
        return out

    def stats(self) -> dict[str, int]:
        with self._lock:
            pending = len(self._rule_hits) + len(self._tarpit) + len(self._holds) + len(self._scores)
        return {"pending_keys": pending, "dropped": self.dropped, "errors": self.errors}


# ------------------------------------------------------------------------------------------------- writer

_SQL: Final[dict[str, str]] = {
    TABLE_RULE_HITS: (
        "INSERT INTO rule_hit_minute (bucket_start, table_name, rule_key, hits) VALUES (?, ?, ?, ?) "
        "ON CONFLICT (bucket_start, table_name, rule_key) DO UPDATE SET hits = hits + excluded.hits"
    ),
    TABLE_TARPIT: (
        "INSERT INTO tarpit_minute (bucket_start, category, kind, holds, skipped, held_s_sum, held_s_max, "
        "gaps_after_hold, gap_after_hold_s_sum, gaps_after_instant, gap_after_instant_s_sum) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (bucket_start, category, kind) DO UPDATE SET "
        "holds = holds + excluded.holds, skipped = skipped + excluded.skipped, "
        "held_s_sum = held_s_sum + excluded.held_s_sum, held_s_max = max(held_s_max, excluded.held_s_max), "
        "gaps_after_hold = gaps_after_hold + excluded.gaps_after_hold, "
        "gap_after_hold_s_sum = gap_after_hold_s_sum + excluded.gap_after_hold_s_sum, "
        "gaps_after_instant = gaps_after_instant + excluded.gaps_after_instant, "
        "gap_after_instant_s_sum = gap_after_instant_s_sum + excluded.gap_after_instant_s_sum"
    ),
    TABLE_TARPIT_HOLDS: (
        "INSERT INTO tarpit_hold_minute (bucket_start, category, bound_ms, holds) VALUES (?, ?, ?, ?) "
        "ON CONFLICT (bucket_start, category, bound_ms) DO UPDATE SET holds = holds + excluded.holds"
    ),
    TABLE_SCORES: (
        "INSERT INTO client_score_hour (bucket_start, client_key, score_max, score_last, last_at, samples) "
        "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (bucket_start, client_key) DO UPDATE SET "
        "score_max = max(score_max, excluded.score_max), "
        "score_last = CASE WHEN excluded.last_at >= last_at THEN excluded.score_last ELSE score_last END, "
        "last_at = max(last_at, excluded.last_at), samples = samples + excluded.samples"
    ),
    TABLE_PIPELINE: (
        "INSERT INTO metrics_pipeline_minute (bucket_start, worker_id, dropped, history_dropped, capture_dropped) "
        "VALUES (?, ?, ?, ?, ?) ON CONFLICT (bucket_start, worker_id) DO UPDATE SET "
        "dropped = dropped + excluded.dropped, history_dropped = history_dropped + excluded.history_dropped, "
        "capture_dropped = capture_dropped + excluded.capture_dropped"
    ),
}


def write_producers(conn: sqlite3.Connection, items: list[ProducerItem]) -> None:
    """Batch writer handler: one `executemany` per table, upserts that add up across workers and flushes."""
    grouped: dict[str, list[tuple[Any, ...]]] = {}
    for item in items:
        if item.table in _SQL:
            grouped.setdefault(item.table, []).append((*item.key, *item.values))
    for table, rows in grouped.items():
        conn.executemany(_SQL[table], rows)


# ---------------------------------------------------------------------------------------------- retention

MINUTE_TABLES: Final[tuple[str, ...]] = (TABLE_RULE_HITS, TABLE_TARPIT, TABLE_TARPIT_HOLDS, TABLE_PIPELINE)
"""Tables keyed by `bucket_start` minutes; they follow `retention_minute_days` like the other minute tables."""
ROW_CAPS: Final[dict[str, int]] = {
    TABLE_SCORES: 300_000,
    TABLE_DISK: 5_000,
    TABLE_SIZES: 60_000,
}
"""Hard row caps (plan P9), a backstop behind the age limits: about 12,500 scored clients an hour for a day, more
than five months of hourly disk samples, and 6-hourly table sizes of 100 tables for five months."""
TIME_COLUMNS: Final[dict[str, str]] = {
    **dict.fromkeys(MINUTE_TABLES, "bucket_start"),
    TABLE_SCORES: "bucket_start",
    TABLE_DISK: "at",
    TABLE_SIZES: "at",
}
DELETE_BATCH: Final = 20_000
"""Most time buckets one prune step deletes per table (short transactions on a live metrics.db, plan 6.3)."""


def prune_producers(
    conn: sqlite3.Connection, now_s: float, keep_days: Mapping[str, float], *, limit: int = DELETE_BATCH
) -> dict[str, int]:
    """Delete rows older than each table's `keep_days` entry, then trim each capped table to its row cap (oldest
    time buckets first). A table without a positive `keep_days` entry is only trimmed. Returns rows deleted."""
    deleted: dict[str, int] = {}
    for table, column in TIME_COLUMNS.items():  # both names are module constants (never caller text)
        removed = 0
        days = keep_days.get(table)
        if days is not None and days > 0:
            cutoff = int(now_s - float(days) * 86_400)
            removed += conn.execute(
                f"DELETE FROM {table} WHERE {column} IN "  # noqa: S608 (constant names)
                f"(SELECT DISTINCT {column} FROM {table} WHERE {column} < ? ORDER BY {column} LIMIT ?)",
                (cutoff, int(limit)),
            ).rowcount
        cap = ROW_CAPS.get(table)
        if cap is not None:
            count = int(conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0])  # noqa: S608 (constant)
            if count > cap:
                # Delete whole oldest time buckets until the table is under its cap (never a partial bucket).
                row = conn.execute(
                    f"SELECT {column} FROM {table} ORDER BY {column} DESC LIMIT 1 OFFSET ?",  # noqa: S608 (constant)
                    (cap,),
                ).fetchone()
                if row is not None:
                    removed += conn.execute(
                        f"DELETE FROM {table} WHERE {column} <= ?",  # noqa: S608 (constant)
                        (row[0],),
                    ).rowcount
        deleted[table] = int(removed)
    return deleted


__all__ = [
    "DELETE_BATCH",
    "HOLD_BOUNDS_MS",
    "MAX_PRODUCER_KEYS",
    "MINUTE_TABLES",
    "OVERFLOW_BOUND",
    "ROW_CAPS",
    "TABLE_DISK",
    "TABLE_PIPELINE",
    "TABLE_RULE_HITS",
    "TABLE_SCORES",
    "TABLE_SIZES",
    "TABLE_TARPIT",
    "TABLE_TARPIT_HOLDS",
    "DropCounters",
    "ProducerHistory",
    "ProducerItem",
    "hold_bound",
    "prune_producers",
    "write_producers",
]
