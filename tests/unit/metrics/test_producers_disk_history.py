"""Disk growth history: the leader job samples Roxy's storage hourly and table sizes every 6 hours, fenced and bounded.

Covers the wave 3b producers lane, item 6 (SYS-DISK growth and projection, the Data page): `measure_files`,
`table_bytes` (the `dbstat` catalog), `rollup_rows_per_minute`, `take_sample`, and the two jobs of
`register_producer_jobs` run by the real `JobRunner` on the leader (fenced writes), plus the read models.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from roxy.core.clock import FakeClock
from roxy.metrics import disk_history, read_producers
from roxy.metrics.jobs import (
    DISK_HISTORY_JOB,
    PRODUCER_PRUNE_JOB,
    producer_keep_days,
    register_metrics_jobs,
    register_producer_jobs,
)
from roxy.scheduler.jobs import JobRegistry, JobRunner
from roxy.scheduler.leader import LeaderElector, LostLeadership


def test_measure_files_counts_databases_wal_and_state_folders(tmp_path: Path) -> None:
    (tmp_path / "metrics.db").write_bytes(b"x" * 1000)
    (tmp_path / "metrics.db-wal").write_bytes(b"w" * 200)
    (tmp_path / "exports").mkdir()
    (tmp_path / "exports" / "a.json").write_bytes(b"e" * 50)
    (tmp_path / "exports" / "nested").mkdir()
    (tmp_path / "exports" / "nested" / "b.json").write_bytes(b"e" * 25)
    measure = disk_history.measure_files(tmp_path, {"metrics": tmp_path / "metrics.db", "hot": tmp_path / "hot.db"})
    assert measure.files["metrics.db"] == {"bytes": 1000, "wal_bytes": 200}
    assert measure.files["hot.db"] == {"bytes": 0, "wal_bytes": 0}  # a missing file counts 0
    assert measure.files["exports"] == {"bytes": 75, "wal_bytes": 0}
    assert "snapshots" not in measure.files
    assert measure.storage_bytes == 1275
    assert measure.total_bytes > 0
    assert 0 <= measure.free_bytes <= measure.total_bytes


def test_table_bytes_and_rollup_rows(dbs: Any, fake_clock: FakeClock) -> None:
    sizes = dbs.metrics.maintenance_sync(disk_history.table_bytes)
    assert sizes is not None
    assert {"rollup_minute", "events", "disk_samples"} <= set(sizes)
    assert not any(name.startswith("sqlite_") for name in sizes)
    hour = int(fake_clock.now()) // 3600 * 3600

    def fill(conn: Any) -> None:
        for minute in range(60):
            for dim in range(3):
                conn.execute(
                    "INSERT INTO rollup_minute (bucket_start, dim_hash, requests) VALUES (?, ?, 1)",
                    (hour - 3600 + minute * 60, dim),
                )

    dbs.metrics.write_sync(fill)
    assert dbs.metrics.read_sync(lambda conn: disk_history.rollup_rows_per_minute(conn, hour + 10)) == 3.0


async def leader_runner(dbs: Any, clock: FakeClock, registry: JobRegistry) -> tuple[LeaderElector, JobRunner]:
    elector = LeaderElector(dbs.hot, "leader-1", clock)
    await elector.tick()
    assert elector.is_leader
    return elector, JobRunner(registry, elector, clock, worker_id="leader-1")


async def test_the_jobs_sample_on_the_leader_and_tables_every_six_hours(
    dbs: Any, fake_clock: FakeClock, settings: Any, tmp_path: Path
) -> None:
    registry = JobRegistry()
    register_producer_jobs(registry, dbs, settings.get, state_dir=tmp_path)
    jobs = {job.name: job for job in registry.all()}
    assert set(jobs) == {DISK_HISTORY_JOB, PRODUCER_PRUNE_JOB}
    assert all(job.leader_only and not job.run_at_start for job in jobs.values())
    assert jobs[DISK_HISTORY_JOB].interval() == disk_history.DISK_SAMPLE_INTERVAL_S
    elector, runner = await leader_runner(dbs, fake_clock, registry)

    first = await runner.run_job_now(DISK_HISTORY_JOB)
    assert first.last_ok, first.last_error
    assert first.last_result["tables_sampled"] == ["control", "hot", "metrics"]
    fake_clock.advance(3600)
    await elector.tick()  # hours pass: the lease is renewed (taken again) before the next run
    second = await runner.run_job_now(DISK_HISTORY_JOB)
    assert second.last_result["tables_sampled"] == []  # table sizes only every 6 hours
    fake_clock.advance(6 * 3600)
    await elector.tick()
    third = await runner.run_job_now(DISK_HISTORY_JOB)
    assert third.last_result["tables_sampled"] == ["control", "hot", "metrics"]

    now = int(fake_clock.now())
    growth = dbs.metrics.read_sync(lambda conn: read_producers.disk_growth(conn, now - 86_400))
    assert len(growth) == 3
    assert all(point["total_bytes"] > 0 for point in growth)  # the database files are not empty
    latest = dbs.metrics.read_sync(read_producers.latest_disk_sample)
    assert latest is not None
    assert set(latest["files"]) >= {"control.db", "hot.db", "metrics.db", "cache.db"}
    tables = dbs.metrics.read_sync(read_producers.latest_table_sizes)
    assert tables["at"] == now
    assert "metrics.rollup_minute" in tables["tables"]
    assert not any(key.startswith("cache.") for key in tables["tables"])  # cache.db counts by its file only
    assert dbs.metrics.read_sync(lambda conn: read_producers.rollup_rows_avg(conn, now - 86_400)) == 0.0

    prune = await runner.run_job_now(PRODUCER_PRUNE_JOB)
    assert prune.last_ok, prune.last_error
    assert set(prune.last_result) == set(producer_keep_days(settings.get))


async def test_a_worker_that_is_not_the_leader_samples_nothing(
    dbs: Any, fake_clock: FakeClock, settings: Any, tmp_path: Path
) -> None:
    registry = JobRegistry()
    register_producer_jobs(registry, dbs, settings.get, state_dir=tmp_path)
    leader = LeaderElector(dbs.hot, "leader-1", fake_clock)
    await leader.tick()
    follower = LeaderElector(dbs.hot, "follower-2", fake_clock)
    await follower.tick()
    assert not follower.is_leader
    runner = JobRunner(registry, follower, fake_clock, worker_id="follower-2")
    with pytest.raises(LostLeadership):
        await runner.run_job_now(DISK_HISTORY_JOB)
    assert dbs.metrics.read_sync(read_producers.latest_disk_sample) is None


def test_keep_days_follow_the_settings(settings: Any) -> None:
    keep = producer_keep_days(settings.get)
    assert keep["rule_hit_minute"] == float(settings.get("retention_minute_days"))
    assert keep["client_score_hour"] >= 2.0  # THROTTLE-TUNE reads a day of scores
    assert keep["disk_samples"] == float(disk_history.DISK_KEEP_DAYS)


def test_the_metrics_jobs_are_unchanged(dbs: Any, settings: Any) -> None:
    registry = JobRegistry()
    register_metrics_jobs(registry, dbs, settings.get)
    assert DISK_HISTORY_JOB not in {job.name for job in registry.all()}  # separate registration (integrator wiring)
