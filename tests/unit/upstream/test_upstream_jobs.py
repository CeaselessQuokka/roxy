"""The upstream scheduled work: the adaptive increase leader job and the availability mirror loop."""

from __future__ import annotations

import asyncio
from typing import Any

from upstream_fakes import answer

from roxy.core.tasks import TaskSupervisor
from roxy.scheduler.jobs import JobRegistry
from roxy.scheduler.leader import JobContext
from roxy.upstream import jobs
from roxy.upstream.queue import Priority
from roxy.upstream.service import UpstreamService


def test_adaptive_job_is_hourly_and_leader_only(service: UpstreamService) -> None:
    registry = JobRegistry()
    jobs.register_upstream_jobs(registry, service)
    job = registry.get(jobs.ADAPTIVE_JOB)
    assert job.interval() == 3600
    assert job.leader_only is True
    assert job.run_at_start is False


async def test_adaptive_job_runs_against_empty_metrics(service: UpstreamService, clock: Any) -> None:
    registry = JobRegistry()
    jobs.register_upstream_jobs(registry, service)
    result = await registry.get(jobs.ADAPTIVE_JOB).fn(JobContext(epoch=1, now=clock.now()))
    assert result == {"raised": []}


async def test_mirror_loop_sees_other_workers_cooldowns(service: UpstreamService, ctx: Any, egress: Any) -> None:
    from upstream_fakes import request

    req = request(service)
    now_ms = ctx.clock.now_ms()
    for key in (
        "endpoint:games.roblox.com/v1/games:direct",
        "endpoint:games.roblox.com/v1/games:rotator",
    ):
        ctx.dbs.hot.write_sync(
            lambda c, k=key: c.execute(
                "INSERT INTO cooldown (key, until_ms, source, set_at, hits) VALUES (?, ?, 'retry_after', ?, 1)",
                (k, now_ms + 20_000, now_ms / 1000),
            )
        )
    assert service.availability(req).any_egress_available is True  # this worker has not looked yet
    tasks = TaskSupervisor()
    jobs.start_upstream_loops(tasks, service)
    for _ in range(100):
        if not service.availability(req).any_egress_available:
            break
        await asyncio.sleep(0.01)
    view = service.availability(req)
    assert view.any_egress_available is False
    assert view.cooldown_remaining_s == 20
    await tasks.stop()
    egress.handler = lambda e, out: answer(200)
    result = await service.fetch(req, priority=Priority.INTERACTIVE, stale_available=False)
    assert result.status == 429  # fetch itself always reads hot.db
