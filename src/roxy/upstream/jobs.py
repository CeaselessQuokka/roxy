"""The upstream package's scheduled work: the hourly adaptive rate increase, and the per-worker mirror loop.

What this is
    `register_upstream_jobs(registry, service)` adds the leader job `adaptive_rate_increase` (hourly) to the
    scheduler's job registry, and `start_upstream_loops(tasks, service)` starts the per-worker loop that keeps the
    availability mirror fresh. The lifespan calls both once the `UpstreamService` exists.

Why it exists
    Plan 7.3: the bounded upward probing of adaptive rates must run on exactly one worker (C6: N workers raising
    a rate N times would multiply it), so it is a leader job; plan 5.6 lists every leader job in one registry.
    `availability()` is synchronous (the cache asks it for every stale decision), so it reads a per-worker mirror
    of active cooldowns and open breakers that a small loop refreshes twice a second.

How it works
    The job reads the evidence from metrics.db (`adaptive.collect_stats`) and writes raised rates through the
    audited rules service. It is idempotent by data: a key whose rate changed within the probe window is never
    raised again, so a second run after a leadership change does nothing. Its writes go to control.db, which the
    leader fencing of hot.db does not cover; the idempotency is what keeps a stale leader harmless here.

What to read next
    `roxy/upstream/adaptive.py` (the rules), `roxy/scheduler/jobs.py` (the registry), `roxy/lifespan.py`.
"""

from __future__ import annotations

from typing import Any, Final

from roxy.scheduler.jobs import Job, JobRegistry
from roxy.scheduler.leader import JobContext

ADAPTIVE_JOB: Final = "adaptive_rate_increase"
ADAPTIVE_INTERVAL_S: Final = 3600.0
MIRROR_LOOP: Final = "upstream_mirror"
MIRROR_INTERVAL_S: Final = 0.5


def register_upstream_jobs(registry: JobRegistry, service: Any) -> None:
    """Add the hourly, leader-only adaptive rate increase job."""

    async def increase(ctx: JobContext) -> dict[str, Any]:
        changes = await service.run_adaptive_increase(ctx.now)
        return {"raised": [change.bucket_key for change in changes][:50]}

    registry.add(
        Job(
            ADAPTIVE_JOB,
            ADAPTIVE_INTERVAL_S,
            increase,
            leader_only=True,
            run_at_start=False,
            description="Raise upstream bucket rates that rejected real demand for a full clean probe window (7.3)",
        )
    )


def start_upstream_loops(tasks: Any, service: Any) -> None:
    """Start the per-worker availability mirror (`TaskSupervisor.start` restarts it after any failure)."""
    tasks.start(MIRROR_LOOP, service.refresh_mirror, interval_s=MIRROR_INTERVAL_S)


__all__ = ["ADAPTIVE_JOB", "MIRROR_LOOP", "register_upstream_jobs", "start_upstream_loops"]
