"""Unit tests for roxy.scheduler.jobs (registry, runner, idempotency, storage jobs)."""

from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from roxy.core.clock import FakeClock
from roxy.scheduler.jobs import (
    SCHEDULE_PREFIX,
    Job,
    JobRegistry,
    JobRunner,
    read_schedule,
    record_start,
    register_storage_jobs,
    schedule_key,
)
from roxy.scheduler.leader import JobContext, LeaderElector, LostLeadership
from roxy.storage.db import SharedStateUnavailable
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
    assert await runner_b.tick() == []  # the fleet schedule: a ran it 16 s ago (finding mpjobs-7)
    await runner_b.run_job_now("digest")  # forced anyway: the idempotency key still stops a second send
    assert sent == [1]  # b's run of the same bucket was a no-op
    assert runner_b.status()[0]["skipped"] == 1
    keys = dbs.hot.read_sync(
        lambda c: [tuple(r) for r in c.execute("SELECT idem_key, epoch FROM job_runs WHERE idem_key LIKE 'job:%'")]
    )
    assert len(keys) == 1
    assert keys[0][0].startswith("job:digest:")
    assert keys[0][1] == 1


def _schedule_rows(dbs: Any) -> dict[str, tuple[int, int]]:
    """`{job name: (epoch, started_at)}` of the fleet schedule rows in hot.db `job_runs`."""
    rows = dbs.hot.read_sync(
        lambda c: c.execute(
            "SELECT idem_key, epoch, started_at FROM job_runs WHERE idem_key LIKE 'schedule:%'"
        ).fetchall()
    )
    return {str(r[0]).removeprefix(SCHEDULE_PREFIX): (int(r[1]), int(r[2])) for r in rows}


async def test_a_new_leader_follows_the_fleet_schedule_instead_of_its_own(dbs, fake_clock: FakeClock) -> None:
    """mpjobs-7: a takeover reruns nothing early. Each job runs one interval after its last start anywhere in the
    fleet (overdue ones at once); a job no leader ever ran keeps the new leader's own schedule."""
    calls: list[str] = []
    registry = JobRegistry()
    registry.add(_counter_job("hourly", 3600, calls))  # run_at_start: the hourly LLM export shape
    registry.add(_counter_job("often", 5, calls))
    registry.add(_counter_job("later", 300, calls, run_at_start=False))
    a = LeaderElector(dbs.hot, "a", fake_clock)
    b = LeaderElector(dbs.hot, "b", fake_clock)
    runner_a = JobRunner(registry, a, fake_clock, worker_id="a")
    runner_b = JobRunner(registry, b, fake_clock, worker_id="b")
    started_at = int(fake_clock.now())
    await a.tick()
    assert sorted(await runner_a.tick()) == ["hourly", "often"]
    await _settle(runner_a)
    assert _schedule_rows(dbs) == {"hourly": (1, started_at), "often": (1, started_at)}
    assert await runner_b.tick() == []  # a follower runs no leader job
    fake_clock.advance(16)  # a stops renewing; b takes the lease over (a new epoch)
    await b.tick()
    assert b.is_leader
    assert b.state.epoch == 2
    assert await runner_b.tick() == ["often"]  # overdue in the fleet; the hourly one ran 16 s ago
    await _settle(runner_b)
    status = {row["name"]: row for row in runner_b.status()}
    assert 3584 - 1 <= status["hourly"]["next_due_in_s"] <= 3584
    assert 284 - 1 <= status["later"]["next_due_in_s"] <= 300  # no row: one interval after b first looked
    assert _schedule_rows(dbs)["often"] == (2, started_at + 16)
    fake_clock.advance(3584)
    assert sorted(await runner_b.tick()) == ["hourly", "later", "often"]
    await _settle(runner_b)
    assert calls.count("hourly:1") == 1
    assert calls.count("hourly:2") == 1  # once per interval across the fleet


async def test_a_new_leader_never_runs_a_job_earlier_than_its_own_schedule(dbs, fake_clock: FakeClock) -> None:
    """A job that is overdue in the fleet but not yet due here (`run_at_start=False`: one interval after this worker
    started, the health poll's "never at boot or deploy") waits for this worker's own schedule."""
    calls: list[str] = []
    registry = JobRegistry()
    registry.add(_counter_job("poll", 300, calls, run_at_start=False))
    a = LeaderElector(dbs.hot, "a", fake_clock)
    b = LeaderElector(dbs.hot, "b", fake_clock)
    runner_a = JobRunner(registry, a, fake_clock, worker_id="a")
    await a.tick()
    await runner_a.run_job_now("poll")  # the fleet ran it at T0
    fake_clock.advance(250)
    await a.tick()  # a leads again for now (a takeover of its own expired lease: a new epoch)
    runner_b = JobRunner(registry, b, fake_clock, worker_id="b")
    assert await runner_b.tick() == []  # b starts at T0 + 250: its own first run is due at T0 + 550
    fake_clock.advance(150)  # T0 + 400: a is gone (its lease ran out at T0 + 265), b takes over
    await b.tick()
    assert b.is_leader
    assert await runner_b.tick() == []  # overdue in the fleet since T0 + 300, but not before b's own T0 + 550
    fake_clock.advance(150)
    assert await runner_b.tick() == ["poll"]
    await _settle(runner_b)
    assert calls == ["poll:1", f"poll:{b.state.epoch}"]


async def test_a_stale_leader_neither_records_nor_runs(dbs, fake_clock: FakeClock) -> None:
    """The schedule row is a fenced write: a worker that still believes it leads after a takeover runs nothing."""
    calls: list[str] = []
    registry = JobRegistry()
    registry.add(_counter_job("hourly", 3600, calls))
    registry.add(_counter_job("often", 5, calls))
    a = LeaderElector(dbs.hot, "a", fake_clock)
    b = LeaderElector(dbs.hot, "b", fake_clock)
    runner_a = JobRunner(registry, a, fake_clock, worker_id="a")
    await a.tick()
    await runner_a.tick()
    await _settle(runner_a)
    fake_clock.advance(16)
    await b.tick()  # b took over; a has not noticed yet (it did not tick)
    assert a.is_leader
    assert b.is_leader
    assert await runner_a.tick() == ["often"]  # started, then refused by the fence before its function ran
    await _settle(runner_a)
    assert calls == ["hourly:1", "often:1"]
    status = {row["name"]: row for row in runner_a.status()}
    assert status["often"]["skipped"] == 1
    assert "lost leadership" in status["often"]["last_error"]
    assert _schedule_rows(dbs)["often"][0] == 1  # nothing recorded under the stale epoch's later attempt


async def test_a_start_stamped_in_the_future_never_delays_a_job_by_more_than_one_interval(
    dbs, fake_clock: FakeClock
) -> None:
    calls: list[str] = []
    registry = JobRegistry()
    registry.add(_counter_job("hourly", 3600, calls))
    future = int(fake_clock.now()) + 10 * 3600  # a row written while some clock ran ahead
    dbs.hot.write_sync(lambda conn: record_start(conn, "hourly", 1, future))
    elector = LeaderElector(dbs.hot, "a", fake_clock)
    runner = JobRunner(registry, elector, fake_clock, worker_id="a")
    await elector.tick()
    assert await runner.tick() == []
    assert runner.status()[0]["next_due_in_s"] == 3600
    fake_clock.advance(3600)
    assert await runner.tick() == ["hourly"]
    await _settle(runner)


async def test_leader_jobs_wait_while_the_fleet_schedule_cannot_be_read(dbs, fake_clock: FakeClock) -> None:
    """hot.db unreadable when this worker becomes the leader: per-worker jobs go on, leader jobs wait one tick and
    read the schedule again (they need hot.db for their fenced writes anyway)."""
    calls: list[str] = []
    registry = JobRegistry()
    registry.add(_counter_job("leader_job", 60, calls))
    registry.add(_counter_job("worker_job", 60, calls, leader_only=False))
    elector = LeaderElector(dbs.hot, "a", fake_clock)
    runner = JobRunner(registry, elector, fake_clock, worker_id="a")
    await elector.tick()
    real_read = dbs.hot.read

    async def broken_read(*_args: Any, **_kwargs: Any) -> Any:
        raise SharedStateUnavailable("hot", "disk I/O error")

    dbs.hot.read = broken_read
    try:
        assert await runner.tick() == ["worker_job"]
    finally:
        dbs.hot.read = real_read
    await _settle(runner)
    assert await runner.tick() == ["leader_job"]
    await _settle(runner)
    assert sorted(calls) == ["leader_job:1", "worker_job:0"]


def test_schedule_rows_are_one_per_job_and_read_back_bounded(dbs) -> None:
    def fill(conn: Any) -> None:
        for i in range(5):
            record_start(conn, f"job_{i}", 3, 1_000 + i)
        record_start(conn, "job_0", 4, 2_000)  # a later start replaces the row (one row per job name)
        conn.execute("INSERT INTO job_runs (idem_key, epoch, started_at) VALUES ('job:digest:1', 3, 5)")

    dbs.hot.write_sync(fill)
    assert dbs.hot.read_sync(read_schedule) == {
        "job_0": 2_000,
        "job_1": 1_001,
        "job_2": 1_002,
        "job_3": 1_003,
        "job_4": 1_004,
    }
    assert len(dbs.hot.read_sync(lambda c: read_schedule(c, limit=2))) == 2
    assert schedule_key("llm_export_file") == "schedule:llm_export_file"


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
