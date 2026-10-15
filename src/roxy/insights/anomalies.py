"""Anomaly detection: is the last quarter hour unusual next to the day before it? (the `anomalies` table).

What this is
    `detect(ctx)` compares, for a few headline metrics (caller requests, Roblox 429s, Roxy's failures, upstream
    calls, p95 latency), the last `WINDOW_MIN` minutes with the same-length blocks of the previous `BASELINE_H`
    hours, and returns an `Anomaly` for each metric whose z-score is at least `Z_THRESHOLD`. `record(conn, ...)`
    writes them to metrics.db `anomalies` (plan 6.2), once per metric and window. `run(engine, job)` is the leader
    job body.

Why it exists
    Plan 11.1 lists "recent anomalies" among what rules can read, and plan 6.2 keeps them as input for
    recommendations (SYS-CHANGE-REGRESSION, for example, can tell a regression from a traffic spike). A z-score
    against the recent past flags "this is not normal for this server" without a hand-set threshold per metric.

How it works
    One rollup read of the baseline span at minute granularity (`metrics/queries.py collect`), summed into blocks;
    the mean and standard deviation of the blocks are the baseline, and `z = (observed - mean) / stdev`. A flat
    baseline (stdev 0) cannot score, a baseline with fewer than `MIN_BLOCKS` blocks is too short, and an
    observation below `MIN_OBSERVED` events is too small to call unusual. These are detector constants, not
    recommendation thresholds: no rule fires on them directly.

What to read next
    `roxy/insights/context.py` (`anomalies(window)` for rules), `roxy/metrics/queries.py`.
"""

from __future__ import annotations

import math
import sqlite3
import statistics
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Final

from roxy.insights.context import InsightContext
from roxy.metrics import histograms, queries, read_history

WINDOW_MIN: Final = 15
"""Length of the observed block (the "last quarter hour")."""
BASELINE_H: Final = 24
"""How far back the baseline blocks reach."""
Z_THRESHOLD: Final = 4.0
"""How many standard deviations from the baseline mean make a block anomalous (about 1 in 15,000 for normal data)."""
MIN_BLOCKS: Final = 8
"""Fewest baseline blocks (2 hours) before a score means anything."""
MIN_OBSERVED: Final = 20
"""Fewest events in the observed block before a count can be called unusual."""
METRICS: Final[tuple[str, ...]] = ("requests", "roblox_429", "failed", "upstream_calls", "p95_ms")


@dataclass(frozen=True, slots=True)
class Anomaly:
    """One anomalous metric in one window."""

    at: int
    metric: str
    baseline: float
    observed: float
    zscore: float
    window: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "at": self.at,
            "metric": self.metric,
            "baseline": self.baseline,
            "observed": self.observed,
            "zscore": self.zscore,
            "window": self.window,
        }


def _blocks(conn: sqlite3.Connection, start: int, end: int) -> dict[str, list[float]]:
    """Every metric summed per `WINDOW_MIN` block over `[start, end)` (the last block is the observed one)."""
    window = queries.Window(start, end, "minute", "UTC")
    data = queries.collect(conn, window)
    per_minute_429 = read_history.roblox_429_counts(conn, start, end, group_by=(), per_minute=True)
    counts_429 = {int(key[0]): n for key, n in per_minute_429.items()}
    size = WINDOW_MIN * 60
    blocks = (end - start) // size
    sums: dict[str, list[float]] = {name: [0.0] * blocks for name in METRICS}
    hists = [histograms.empty() for _ in range(blocks)]
    for (bucket, _group), totals in data.items():
        index = (int(bucket or 0) - start) // size
        if not 0 <= index < blocks:
            continue
        for name in ("requests", "failed", "upstream_calls"):
            sums[name][index] += totals.values[name]
        histograms.add_into(hists[index], totals.latency)
    for minute, n in counts_429.items():
        index = (minute - start) // size
        if 0 <= index < blocks:
            sums["roblox_429"][index] += n
    sums["p95_ms"] = [float(histograms.percentile(h, 0.95) or 0.0) for h in hists]
    return sums


def score(series: Sequence[float]) -> tuple[float, float, float] | None:
    """`(mean, observed, z)` for a block series whose last value is the observed one, or None."""
    baseline, observed = list(series[:-1]), float(series[-1])
    if len(baseline) < MIN_BLOCKS:
        return None
    mean = statistics.fmean(baseline)
    deviation = statistics.pstdev(baseline)
    if deviation == 0 or math.isnan(deviation):
        return None
    return mean, observed, (observed - mean) / deviation


async def detect(ctx: InsightContext) -> list[Anomaly]:
    """Anomalies of the last `WINDOW_MIN` minutes against the previous `BASELINE_H` hours."""
    size = WINDOW_MIN * 60
    end = int(ctx.now) - int(ctx.now) % size
    start = end - BASELINE_H * 3600 - size
    sums = await ctx.dbs.metrics.read(lambda conn: _blocks(conn, start, end))
    found: list[Anomaly] = []
    label = f"{WINDOW_MIN}m"
    for metric, series in sums.items():
        result = score(series)
        if result is None:
            continue
        mean, observed, z = result
        if abs(z) < Z_THRESHOLD or (metric != "p95_ms" and observed < MIN_OBSERVED and mean < MIN_OBSERVED):
            continue
        found.append(Anomaly(end, metric, round(mean, 3), round(observed, 3), round(z, 2), label))
    return found


def record(conn: sqlite3.Connection, anomalies: Sequence[Anomaly]) -> int:
    """Insert anomalies not recorded yet for the same metric and window end (idempotent by data)."""
    written = 0
    for item in anomalies:
        exists = conn.execute(
            "SELECT 1 FROM anomalies WHERE at = ? AND metric = ? AND window = ?", (item.at, item.metric, item.window)
        ).fetchone()
        if exists:
            continue
        conn.execute(
            "INSERT INTO anomalies (at, metric, baseline, observed, zscore, window) VALUES (?, ?, ?, ?, ?, ?)",
            (item.at, item.metric, item.baseline, item.observed, item.zscore, item.window),
        )
        written += 1
    return written


async def run(engine: Any, job: Any = None) -> dict[str, Any]:
    """Leader job body: detect and record (fenced by the leader lease when `job` has one)."""
    ctx = engine.context(None if job is None else job.now)
    found = await detect(ctx)
    if not found:
        return {"anomalies": 0}
    if job is not None and getattr(job, "epoch", 0) > 0:
        written = await job.fenced_write(engine.dbs.metrics, lambda conn: record(conn, found))
    else:
        written = await engine.dbs.metrics.write(lambda conn: record(conn, found))
    return {"anomalies": len(found), "written": written, "metrics": [a.metric for a in found]}


__all__ = ["BASELINE_H", "METRICS", "WINDOW_MIN", "Z_THRESHOLD", "Anomaly", "detect", "record", "run", "score"]
