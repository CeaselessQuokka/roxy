"""Metrics: counting, storing and explaining everything Roxy does (plan sections 6.2 to 6.4, 14.3, P4 and P6).

What this is
    The package behind every chart, KPI tile and table: `recorder.py` (per-worker counting, the
    `ctx.recorder` object), `histograms.py`, `templating.py`, `rollups.py` (writes and compaction), `queries.py`
    (read models), `catalog.py` (what each number means), and the smaller stores: `live.py`, `capture.py`,
    `samples.py`, `fingerprints.py`, `visitors.py`, `security_events.py`, `activity.py`, plus `jobs.py` (leader
    jobs).

Why it exists
    v1 kept 47 in-memory dictionaries per worker and merged them into one JSON file under a lock, which lost
    data, double counted across workers, and blocked requests while it wrote. v2 counts in memory, writes in
    batches to SQLite, compacts on one leader, and reads any time range from rollups.

How it works
    Producers call `ctx.recorder.record_*`; the recorder hands batches to `storage/batch.py`; the leader runs
    `jobs.register_metrics_jobs`; the admin API and the LLM export read through `queries.py`.

What to read next
    `roxy/metrics/recorder.py`, then `roxy/metrics/rollups.py` and `roxy/metrics/queries.py`.
"""
