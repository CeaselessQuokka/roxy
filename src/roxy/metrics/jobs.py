"""The metrics leader jobs: compaction, the live-row prune, security event caps and header auto-ignore.

What this is
    `register_metrics_jobs(registry, dbs, setting, ...)` adds this package's jobs to the scheduler's
    `JobRegistry` (the lifespan calls it next to `register_storage_jobs`; the scheduler itself is not changed):
    - `metrics_compaction` (every minute): cap closed client minutes to the top N plus `other`, then compact
      minutes into hours, hours into local days and days into local months, for `rollup_*`, `egress_usage` and
      the client tables (`rollups.compact_all`).
    - `metrics_live_prune` (every minute): delete `live` event rows older than 15 minutes.
    - `metrics_security_caps` (every minute): keep each security event type within its `max_*_records` cap.
    - `fingerprint_auto_ignore` (every 5 minutes): add headers whose values are unique per request to the
      ignored value headers list and delete their stored values (central decision, fixes v1 bug B22).
    `rules_ignore_header(...)` builds the default callback that writes the ignore entry through the audited
    rules service.
    `register_producer_jobs(registry, dbs, setting, state_dir=...)` adds the jobs of the producer history
    (schema version 5, `metrics/producers.py`, `metrics/disk_history.py`):
    - `metrics_disk_history` (hourly): one disk sample (files every time, table sizes every 6 hours) for SYS-DISK
      and the Data page projection.
    - `metrics_producer_prune` (every 10 minutes): bound every schema version 5 table: the minute tables by
      `retention_minute_days`, bot scores by `retention_client_minute_days` (at least 2 days: THROTTLE-TUNE reads
      24 h), disk samples by `disk_history.DISK_KEEP_DAYS`, each capped tables to its row cap.

Why it exists
    Plan 5.6: compaction and pruning must run on exactly one worker of the fleet. Every write here goes through
    the job context's fenced write, so a leader that lost its lease while stalled cannot write anything (the
    write rolls back with `LostLeadership`).

How it works
    Each job reads its settings live through `setting(key)` at the start of every run (`ui_timezone`,
    `metrics_flush_interval_ms`, retention days, client caps, `activity_tracking`,
    `auto_ignore_high_cardinality`, `max_header_value_records`). Compaction is idempotent (whole buckets are
    recomputed), so a run cut short or repeated after a leadership change does no harm.

What to read next
    `roxy/metrics/rollups.py` (`compact_all`), `roxy/scheduler/jobs.py` (the registry and runner),
    `roxy/scheduler/leader.py` (fenced writes).
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Awaitable, Callable, Iterable
from pathlib import Path
from typing import Any, Final

from roxy.metrics import disk_history, fingerprints, producers, security_events
from roxy.metrics.live import LIVE_KEEP_S, prune_live_events
from roxy.metrics.rollups import DEFAULT_ZONE, ClientCaps, CompactionConfig, compact_all
from roxy.scheduler.jobs import Job, JobRegistry
from roxy.scheduler.leader import JobContext
from roxy.storage.db import Database, Databases

log = logging.getLogger(__name__)

COMPACTION_INTERVAL_S = 60.0
LIVE_PRUNE_INTERVAL_S = 60.0
SECURITY_CAPS_INTERVAL_S = 60.0
AUTO_IGNORE_INTERVAL_S = 300.0
AUTO_IGNORE_MAX_PER_RUN = 10
DISK_HISTORY_JOB: Final = "metrics_disk_history"
PRODUCER_PRUNE_JOB: Final = "metrics_producer_prune"
PRODUCER_PRUNE_INTERVAL_S: Final = 600.0
DISK_HISTORY_TIMEOUT_S: Final = 300.0
"""A table size walk of a large metrics.db takes seconds; five minutes bounds a stalled disk."""
MIN_SCORE_KEEP_DAYS: Final = 2
"""Bot scores are kept at least two days: THROTTLE-TUNE reads the last 24 hours."""

IgnoreHeader = Callable[[str, str], Awaitable[bool]]
"""`ignore(name, note) -> added`: put one header on the ignored value headers list (audited)."""


def _live(setting: Callable[[str], Any], key: str, fallback: Any) -> Any:
    try:
        value = setting(key)
    except (KeyError, LookupError, AttributeError, TypeError, ValueError):
        return fallback
    return fallback if value is None else value


def compaction_config(setting: Callable[[str], Any]) -> CompactionConfig:
    """The compaction settings, read live. The grace covers two flush intervals plus a margin, so a bucket is
    compacted only after every worker has flushed it."""
    flush_s = int(_live(setting, "metrics_flush_interval_ms", 2000)) / 1000.0
    return CompactionConfig(
        tz_name=str(_live(setting, "ui_timezone", DEFAULT_ZONE)),
        grace_s=max(120, int(2 * flush_s + 30)),
        minute_retention_days=int(_live(setting, "retention_minute_days", 14)),
        client_minute_retention_days=int(_live(setting, "retention_client_minute_days", 3)),
        caps=ClientCaps(
            ips=max(1, int(_live(setting, "max_ip_activity_records", 500))),
            places=max(1, int(_live(setting, "max_caller_records", 500))),
        ),
        activity_tracking=bool(int(_live(setting, "activity_tracking", 1))),
    )


def register_metrics_jobs(
    registry: JobRegistry,
    dbs: Databases,
    setting: Callable[[str], Any],
    *,
    ignore_header: IgnoreHeader | None = None,
    ignored_headers: Callable[[], Iterable[str]] | None = None,
) -> None:
    """Add the metrics leader jobs to `registry` (call once per worker, before the runner starts)."""
    metrics = dbs.metrics

    def fenced(ctx: JobContext) -> Callable[[Callable[[sqlite3.Connection], Any]], Awaitable[Any]]:
        async def write(fn: Callable[[sqlite3.Connection], Any]) -> Any:
            return await ctx.fenced_write(metrics, fn)

        return write

    async def compaction_job(ctx: JobContext) -> dict[str, int]:
        report = await compact_all(fenced(ctx), ctx.now, compaction_config(setting))
        return {level: len(buckets) for level, buckets in report.items()}

    async def live_prune_job(ctx: JobContext) -> int:
        return int(await ctx.fenced_write(metrics, lambda conn: prune_live_events(conn, ctx.now, LIVE_KEEP_S)))

    async def security_caps_job(ctx: JobContext) -> dict[str, int]:
        result: dict[str, int] = await ctx.fenced_write(
            metrics, lambda conn: security_events.enforce_caps(conn, setting)
        )
        return result

    async def auto_ignore_job(ctx: JobContext) -> list[str]:
        if ignore_header is None or not bool(int(_live(setting, "auto_ignore_high_cardinality", 1))):
            return []
        cap = int(_live(setting, "max_header_value_records", 500))
        already = list(ignored_headers()) if ignored_headers is not None else []
        candidates = await metrics.read(
            lambda conn: fingerprints.auto_ignore_candidates(conn, value_cap=cap, ignored=already)
        )
        added: list[str] = []
        for candidate in candidates[:AUTO_IGNORE_MAX_PER_RUN]:
            await ctx.check()
            if await ignore_header(candidate.name, candidate.note):
                name = candidate.name

                def clear(conn: sqlite3.Connection, header: str = name) -> int:
                    return fingerprints.clear_values(conn, header)

                await ctx.fenced_write(metrics, clear)
                added.append(name)
                log.info("fingerprint_auto_ignored", extra={"fields": {"header": name, "note": candidate.note}})
        return added

    registry.add(
        Job(
            "metrics_compaction",
            COMPACTION_INTERVAL_S,
            compaction_job,
            description="Compact metrics: client top N, minutes to hours, days and months in ui_timezone (6.4).",
        )
    )
    registry.add(
        Job(
            "metrics_live_prune",
            LIVE_PRUNE_INTERVAL_S,
            live_prune_job,
            description="Delete live tail rows older than 15 minutes from the events table (14.11).",
        )
    )
    registry.add(
        Job(
            "metrics_security_caps",
            SECURITY_CAPS_INTERVAL_S,
            security_caps_job,
            description="Keep probe, login, crawl and throttled events within their record caps (15.3 I).",
        )
    )
    registry.add(
        Job(
            "fingerprint_auto_ignore",
            AUTO_IGNORE_INTERVAL_S,
            auto_ignore_job,
            run_at_start=False,
            description="Stop listing header values that are unique per request (row 79, auto-ignore).",
        )
    )


def producer_keep_days(setting: Callable[[str], Any]) -> dict[str, float]:
    """How many days each schema version 5 table keeps (read live on every prune run)."""
    minute_days = float(_live(setting, "retention_minute_days", 14))
    keep: dict[str, float] = dict.fromkeys(producers.MINUTE_TABLES, minute_days)
    client_days = float(_live(setting, "retention_client_minute_days", 3))
    keep[producers.TABLE_SCORES] = max(float(MIN_SCORE_KEEP_DAYS), client_days)
    keep[producers.TABLE_DISK] = float(disk_history.DISK_KEEP_DAYS)
    keep[producers.TABLE_SIZES] = float(disk_history.DISK_KEEP_DAYS)
    return keep


def register_producer_jobs(
    registry: JobRegistry,
    dbs: Databases,
    setting: Callable[[str], Any],
    *,
    state_dir: Path | None = None,
) -> None:
    """Add the producer history leader jobs (the module docstring) to `registry`.

    `state_dir` is the worker's `ROXY_STATE_DIR` (the volume measured, and where `exports` and `snapshots` live);
    without it the directory of metrics.db is used. Both jobs write through the run's fenced write, so a leader that
    lost its lease writes nothing.
    """
    metrics = dbs.metrics

    async def disk_history_job(ctx: JobContext) -> dict[str, Any]:
        async def write(fn: Callable[[sqlite3.Connection], Any]) -> Any:
            return await ctx.fenced_write(metrics, fn)

        return await disk_history.take_sample(dbs, now=ctx.now, state_dir=state_dir, write=write)

    async def prune_job(ctx: JobContext) -> dict[str, int]:
        keep = producer_keep_days(setting)
        result: dict[str, int] = await ctx.fenced_write(
            metrics, lambda conn: producers.prune_producers(conn, ctx.now, keep)
        )
        return result

    registry.add(
        Job(
            DISK_HISTORY_JOB,
            disk_history.DISK_SAMPLE_INTERVAL_S,
            disk_history_job,
            timeout_s=DISK_HISTORY_TIMEOUT_S,
            run_at_start=False,
            description="Sample Roxy's storage hourly and table sizes every 6 hours (SYS-DISK growth, 6.6).",
        )
    )
    registry.add(
        Job(
            PRODUCER_PRUNE_JOB,
            PRODUCER_PRUNE_INTERVAL_S,
            prune_job,
            run_at_start=False,
            description="Bound the rule hit, tarpit, bot score, metrics drop and disk history tables (6.10).",
        )
    )


def rules_ignore_header(control: Database, *, clock: Any = None, store: Any = None) -> IgnoreHeader:
    """The default `ignore_header`: an audited `ignored_value_headers` row with `auto = 1` (rules service)."""
    from roxy.config.audit import Actor
    from roxy.rules.service import RuleConflict, RulesError, RulesService

    service = RulesService(control, clock=clock, store=store)
    actor = Actor("system", "auto:fingerprints")

    async def ignore(name: str, note: str) -> bool:
        try:
            await service.create("ignored_value_headers", {"name": name, "note": note[:200], "auto": True}, actor, note)
        except RuleConflict:
            return True  # already on the list (added by an admin or an earlier run)
        except RulesError as exc:
            log.warning("fingerprint_auto_ignore_refused", extra={"fields": {"header": name, "error": exc.message}})
            return False
        return True

    return ignore
