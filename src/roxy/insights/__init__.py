"""The recommendations engine (plan 11): rules that read Roxy's numbers and propose precise, reversible changes.

What this is
    The package behind the Recommendations page. `rules/` holds one class per plan 11.5 rule; `engine.py` evaluates
    them on the leader and keeps each recommendation's lifecycle; `context.py` is everything a rule may read;
    `models.py` is the 11.2 object; `simulate.py` is the 11.3 dry run; `actions.py` applies, undoes, snoozes and
    dismisses; `autoapply.py` is the D7 auto-apply mode with its watch window and automatic rollback; `anomalies.py`
    detects metric anomalies the rules can read. `register_jobs(registry, ...)` adds the package's leader jobs.

Why it exists
    v1 showed one lifetime banner ("Roblox has rate-limited us 579 time(s)") with no window, no endpoint and no
    button (plan 11.6). v2 names the endpoint, shows the evidence, proposes the exact change with its current value,
    previews it on real samples, applies it atomically with an audit trail, and can undo it.

How it works
    The leader runs `insights_evaluate` every `insights_interval_s` (30 s) and `insights_triggers` every few seconds
    (an early run after a 429 burst, a breaker opening, a credential or settings change, a ban or a failed health
    check). `insights_watch` closes auto-apply watch windows (rolling back a change that made a guard metric worse),
    `insights_auto_apply` applies safe low-risk recommendations when `insights_auto_apply` is 1,
    `insights_anomalies` records metric anomalies every 5 minutes, and `insights_history_prune` bounds the schema
    version 2 history tables. Every job is idempotent by data, so a leadership change never applies or rolls back
    twice.

What to read next
    `roxy/insights/rules/base.py` (how to write a rule), `roxy/insights/engine.py`, `roxy/insights/actions.py`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from roxy.insights.engine import InsightsEngine

EVALUATE_JOB: Final = "insights_evaluate"
TRIGGER_JOB: Final = "insights_triggers"
WATCH_JOB: Final = "insights_watch"
AUTO_APPLY_JOB: Final = "insights_auto_apply"
PRUNE_JOB: Final = "insights_history_prune"
ANOMALY_JOB: Final = "insights_anomalies"
WATCH_INTERVAL_S: Final = 60.0
PRUNE_INTERVAL_S: Final = 600.0
ANOMALY_INTERVAL_S: Final = 300.0
HISTORY_KEEP_DAYS: Final[dict[str, float]] = {
    "error_minute": 8,  # SYS-ERRORS needs 7 days of baseline plus the last hour
    "cache_eviction_passes": 14,
    "egress_provider_reports": 400,
}
"""Retention of the history tables not tied to a catalog setting; the minute tables follow `retention_minute_days`
and `rule_hits` keeps a rule's last hit for `retention_hour_days` (an idle rule reads as never hit after that)."""


def register_jobs(registry: Any, engine: InsightsEngine, *, actions: Any = None, auto: Any = None) -> None:
    """Add the insights leader jobs to the scheduler's registry (the integrator calls this in the lifespan).

    `engine` is `InsightsEngine.from_context(ctx)`; `actions` a `RecommendationActions` and `auto` an `AutoApplier`
    (both optional: without them only evaluation, triggers and pruning run).
    """
    from roxy.insights.engine import TRIGGER_POLL_S
    from roxy.metrics import read_history
    from roxy.scheduler.jobs import Job

    async def evaluate(job: Any) -> dict[str, Any]:
        report = await engine.run_once(now=job.now, job=job)
        return report.to_dict()

    async def triggers(job: Any) -> dict[str, Any] | None:
        report = await engine.check_triggers(job=job, now=job.now)
        return None if report is None else report.to_dict()

    async def prune(job: Any) -> dict[str, int]:
        snap = engine._settings_snapshot()
        keep = dict(HISTORY_KEEP_DAYS)
        minute_days = float(snap["retention_minute_days"])
        for table in ("bucket_minute", "worker_minute", "cache_minute", "upstream_attempt_minute"):
            keep[table] = minute_days
        keep["rule_hits"] = float(snap["retention_hour_days"])
        deleted: dict[str, int] = await job.fenced_write(
            engine.dbs.metrics, lambda conn: read_history.prune_history(conn, job.now, keep)
        )
        return deleted

    registry.add(
        Job(
            EVALUATE_JOB,
            engine.interval_s,
            evaluate,
            leader_only=True,
            description="Evaluate the recommendation rules and keep their lifecycle (plan 11.1)",
        )
    )
    registry.add(
        Job(
            TRIGGER_JOB,
            TRIGGER_POLL_S,
            triggers,
            leader_only=True,
            run_at_start=False,
            description="Evaluate early after a trigger event: 429 burst, breaker, credential, settings, ban, health",
        )
    )
    registry.add(
        Job(
            PRUNE_JOB,
            PRUNE_INTERVAL_S,
            prune,
            leader_only=True,
            description="Bound the insight history tables (bucket, worker, cache, error and attempt minutes)",
        )
    )

    async def detect(job: Any) -> dict[str, Any]:
        from roxy.insights import anomalies

        return await anomalies.run(engine, job)

    registry.add(
        Job(
            ANOMALY_JOB,
            ANOMALY_INTERVAL_S,
            detect,
            leader_only=True,
            run_at_start=False,
            description="Record metric anomalies of the last quarter hour against the previous day",
        )
    )
    if auto is not None:

        async def watch(job: Any) -> dict[str, Any]:
            return await auto.watch(now=job.now, job=job)  # type: ignore[no-any-return]

        async def auto_apply(job: Any) -> dict[str, Any]:
            return await auto.run(now=job.now, job=job)  # type: ignore[no-any-return]

        registry.add(
            Job(
                WATCH_JOB,
                WATCH_INTERVAL_S,
                watch,
                leader_only=True,
                description="Close watch windows of applied recommendations; roll back on a worse guard metric (11.4)",
            )
        )
        registry.add(
            Job(
                AUTO_APPLY_JOB,
                engine.interval_s,
                auto_apply,
                leader_only=True,
                run_at_start=False,
                description="Auto-apply safe low-risk recommendations within the D7 guardrails (11.4)",
            )
        )
    del actions  # the jobs reach the actions through `auto`; kept in the signature for the integrator's wiring


__all__ = [
    "ANOMALY_JOB",
    "AUTO_APPLY_JOB",
    "EVALUATE_JOB",
    "HISTORY_KEEP_DAYS",
    "PRUNE_JOB",
    "TRIGGER_JOB",
    "WATCH_JOB",
    "register_jobs",
]
