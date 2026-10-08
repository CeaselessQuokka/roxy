"""Unit tests for roxy.scheduler.jobs (registry, runner, idempotency, storage jobs)."""

from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from roxy.core.clock import FakeClock
from roxy.scheduler.jobs import Job, JobRegistry, JobRunner, register_storage_jobs
from roxy.scheduler.leader import JobContext, LeaderElector, LostLeadership
from roxy.storage.retention import RetentionPolicy


async def _settle(runner: JobRunner) -> None:
    """Wait until every job started by the last tick has finished."""
    while runner._tasks:
        await asyncio.gather(*list(runner._tasks.values()), return_exceptions=True)


def _counter_job(name: str, interval: float, calls: list[str], **kwargs: Any) -> Job:
    async def fn(ctx: JobContext) -> str:
        calls.append(f"{name}:{ctx.epoch}")
        return "done"

    return Job(name, interval, fn, **kwargs)


def test_registry_rejects_duplicates_and_supports_decorator() -> None:
    registry = JobRegistry()

    @registry.job("rollups", 60, description="minute to hour rollups")
    async def rollups(ctx: JobContext) -> None:
        return None

    assert "rollups" in registry
    assert len(registry) == 1
    assert registry.get("rollups").fn is rollups
    with pytest.raises(ValueError):
        registry.add(Job("rollups", 60, rollups))


async def test_leader_only_jobs_run_only_on_the_leader(dbs, fake_clock: FakeClock) -> None:
    calls: list[str] = []
    registry = JobRegistry()
    registry.add(_counter_job("leader_job", 60, calls))
    registry.add(_counter_job("worker_job", 60, calls, leader_only=False))
    elector = LeaderElector(dbs.hot, "a", fake_clock)
    runner = JobRunner(registry, elector, fake_clock, worker_id="a")
    assert await runner.tick() == ["worker_job"]
    await _settle(runner)
    await elector.tick()
    assert await runner.tick() == ["leader_job"]  # overdue leader job runs as soon as this worker leads
    await _settle(runner)
    assert sorted(calls) == ["leader_job:1", "worker_job:0"]


async def test_jobs_run_on_their_interval(dbs, fake_clock: FakeClock) -> None:
    calls: list[str] = []
    registry = JobRegistry()
    registry.add(_counter_job("now", 30, calls, leader_only=False))
    registry.add(_counter_job("later", 30, calls, leader_only=False, run_at_start=False))
    registry.add(_counter_job("disabled", 0, calls, leader_only=False))
    runner = JobRunner(registry, None, fake_clock)
    await runner.tick()
    await _settle(runner)
    assert calls == ["now:0"]
    fake_clock.advance(29)
    assert await runner.tick() == []
    fake_clock.advance(1)
    assert sorted(await runner.tick()) == ["later", "now"]
    await _settle(runner)
    assert len(calls) == 3
    status = {row["name"]: row for row in runner.status()}
    assert status["now"]["runs"] == 2
    assert status["now"]["last_ok"] is True
    assert status["disabled"]["runs"] == 0
    assert 0 <= status["now"]["next_due_in_s"] <= 30


async def test_non_idempotent_job_runs_once_per_bucket_across_leaders(dbs, fake_clock: FakeClock) -> None:
    sent: list[int] = []

    async def send_digest(ctx: JobContext) -> None:
        sent.append(ctx.epoch)

    registry = JobRegistry()
    registry.add(Job("digest", 60, send_digest, idempotent=False))
    a = LeaderElector(dbs.hot, "a", fake_clock)
    b = LeaderElector(dbs.hot, "b", fake_clock)
    runner_a = JobRunner(registry, a, fake_clock)
    runner_b = JobRunner(registry, b, fake_clock)
    await a.tick()
    await runner_a.tick()
    await _settle(runner_a)
    fake_clock.advance(16)  # a dies; b takes over within the same minute bucket
    await b.tick()
    assert b.is_leader
    await runner_b.tick()
    await _settle(runner_b)
    assert sent == [1]  # b's run of the same bucket was a no-op
    assert runner_b.status()[0]["skipped"] == 1
    keys = dbs.hot.read_sync(lambda c: [tuple(r) for r in c.execute("SELECT idem_key, epoch FROM job_runs")])
    assert len(keys) == 1
    assert keys[0][0].startswith("job:digest:")
    assert keys[0][1] == 1


async def test_failures_timeouts_and_lost_leadership_are_recorded(dbs, fake_clock: FakeClock) -> None:
    async def broken(ctx: JobContext) -> None:
        raise RuntimeError("bug")

    async def slow(ctx: JobContext) -> None:
        await asyncio.sleep(5)

    async def fenced(ctx: JobContext) -> None:
        raise LostLeadership("taken over")

    registry = JobRegistry()
    registry.add(Job("broken", 10, broken, leader_only=False))
    registry.add(Job("slow", 10, slow, leader_only=False, timeout_s=0.05))
    registry.add(Job("fenced", 10, fenced, leader_only=False))
    runner = JobRunner(registry, None, fake_clock)
    await runner.tick()
    await _settle(runner)
    status = {row["name"]: row for row in runner.status()}
    assert status["broken"]["failures"] == 1
    assert "RuntimeError" in status["broken"]["last_error"]
    assert status["slow"]["timeouts"] == 1
    assert status["slow"]["last_ok"] is False
    assert status["fenced"]["skipped"] == 1
    assert "lost leadership" in status["fenced"]["last_error"]
    assert not any(row["running"] for row in status.values())


async def test_run_job_now_respects_leader_only(dbs, fake_clock: FakeClock) -> None:
    calls: list[str] = []
    registry = JobRegistry()
    registry.add(_counter_job("leader_job", 60, calls))
    elector = LeaderElector(dbs.hot, "a", fake_clock)
    runner = JobRunner(registry, elector, fake_clock)
    with pytest.raises(LostLeadership):
        await runner.run_job_now("leader_job")
    await elector.tick()
    status = await runner.run_job_now("leader_job")
    assert status.runs == 1
    assert calls == ["leader_job:1"]


async def test_run_loop_and_shutdown() -> None:
    calls: list[str] = []
    registry = JobRegistry()
    registry.add(_counter_job("fast", 0.02, calls, leader_only=False))

    async def forever(ctx: JobContext) -> None:
        await asyncio.sleep(60)

    registry.add(Job("forever", 100, forever, leader_only=False))
    runner = JobRunner(registry, None)
    stop = asyncio.Event()
    task = asyncio.create_task(runner.run(stop, poll_s=0.01))
    await asyncio.sleep(0.2)
    stop.set()
    await asyncio.wait_for(task, 5)
    assert len(calls) >= 2
    assert not runner._tasks  # the long job was canceled on shutdown


async def test_storage_jobs(dbs, fake_clock: FakeClock, state_dir: Path) -> None:
    exports = state_dir / "exports"
    exports.mkdir()
    old = exports / "old.json"
    old.write_text("{}")
    os.utime(old, (fake_clock.now() - 30 * 86400, fake_clock.now() - 30 * 86400))
    local_hour = datetime.fromtimestamp(fake_clock.now(), UTC).hour
    integrity_calls: list[str] = []

    registry = JobRegistry()
    register_storage_jobs(
        registry,
        dbs,
        RetentionPolicy,
        state_dir=state_dir,
        maintenance_hour=lambda: local_hour,
        ui_timezone=lambda: "UTC",
        on_integrity_failure=lambda name, problems: integrity_calls.append(name),
    )
    names = {job.name for job in registry.all()}
    assert names == {"retention", "hot_prune", "wal_checkpoint_passive", "daily_maintenance", "file_retention"}
    elector = LeaderElector(dbs.hot, "leader-1", fake_clock)
    runner = JobRunner(registry, elector, fake_clock)
    await elector.tick()
    for name in sorted(names):
        status = await runner.run_job_now(name)
        assert status.last_ok, (name, status.last_error)
    results = {row["name"]: row for row in runner.status()}
    assert results["file_retention"]["runs"] == 1
    assert not old.exists()
    daily = runner._status["daily_maintenance"].last_result
    assert daily["ran"] is True
    assert daily["integrity"] == {"control": "ok", "hot": "ok"}
    assert set(daily["truncate_ms"]) == {"cache", "metrics"}
    again = await runner.run_job_now("daily_maintenance")
    assert again.last_result == {"ran": False, "day": daily["day"], "already_done": True}
    assert set(runner._status["wal_checkpoint_passive"].last_result) == {"hot", "control", "metrics"}
    assert integrity_calls == []


async def test_daily_job_reads_maintenance_settings_live(dbs, fake_clock: FakeClock) -> None:
    hour = datetime.fromtimestamp(fake_clock.now(), UTC).hour
    values: dict[str, Any] = {"maintenance_hour": (hour + 1) % 24, "ui_timezone": "UTC"}

    def setting(key: str) -> Any:
        return values[key]

    registry = JobRegistry()
    register_storage_jobs(registry, dbs, RetentionPolicy, setting=setting)
    elector = LeaderElector(dbs.hot, "leader-1", fake_clock)
    runner = JobRunner(registry, elector, fake_clock)
    await elector.tick()
    first = await runner.run_job_now("daily_maintenance")
    assert first.last_result["ran"] is False  # not the maintenance hour yet
    values["maintenance_hour"] = hour  # an admin changes the setting; the next run sees it
    second = await runner.run_job_now("daily_maintenance")
    assert second.last_result["ran"] is True
