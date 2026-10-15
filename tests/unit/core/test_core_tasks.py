"""TaskSupervisor tests: loops run, failures are logged and restarted, bounds hold, shutdown is clean."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

import pytest

from roxy.core.tasks import TaskSupervisor


async def wait_until(predicate: Callable[[], bool], limit_s: float = 2.0) -> None:
    deadline = asyncio.get_running_loop().time() + limit_s
    while not predicate():
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError("condition not reached in time")
        await asyncio.sleep(0.005)


async def test_interval_loop_runs_repeatedly() -> None:
    supervisor = TaskSupervisor()
    calls: list[int] = []

    async def job() -> None:
        calls.append(1)

    supervisor.start("tick", job, interval_s=0.01)
    await wait_until(lambda: len(calls) >= 3)
    [status] = supervisor.status()
    assert status.name == "tick"
    assert status.runs >= 3
    assert status.running
    await supervisor.stop()
    assert not supervisor.is_running("tick")


async def test_failing_loop_is_logged_and_restarted(caplog: pytest.LogCaptureFixture) -> None:
    supervisor = TaskSupervisor(backoff_initial_s=0.01, backoff_max_s=0.02)
    attempts: list[int] = []

    async def flaky() -> None:
        attempts.append(1)
        if len(attempts) < 3:
            raise RuntimeError("database is locked")

    with caplog.at_level("ERROR", logger="roxy.core.tasks"):
        supervisor.start("flaky", flaky)
        await wait_until(lambda: not supervisor.is_running("flaky"))
    [status] = supervisor.status()
    assert len(attempts) == 3  # failed twice, then a clean run ended the long-running loop
    assert status.failures == 2
    assert status.last_error == "RuntimeError: database is locked"
    assert sum(1 for r in caplog.records if r.getMessage() == "task_failed") == 2
    await supervisor.stop()


async def test_backoff_never_faster_than_interval() -> None:
    supervisor = TaskSupervisor(backoff_initial_s=0.001, backoff_max_s=60)
    assert supervisor._backoff(1, 5.0) == 5.0
    assert supervisor._backoff(30, None) == 60
    assert supervisor._backoff(3, None) == pytest.approx(0.004)


async def test_per_run_timeout() -> None:
    supervisor = TaskSupervisor(backoff_initial_s=0.01, backoff_max_s=0.01)

    async def stuck() -> None:
        await asyncio.sleep(10)

    supervisor.start("stuck", stuck, interval_s=0.01, timeout_s=0.02)
    await wait_until(lambda: supervisor.status()[0].failures >= 1)
    assert "TimeoutError" in (supervisor.status()[0].last_error or "")
    await supervisor.stop()


async def test_duplicate_running_name_rejected() -> None:
    supervisor = TaskSupervisor()

    async def forever() -> None:
        await asyncio.sleep(10)

    supervisor.start("one", forever)
    with pytest.raises(ValueError):
        supervisor.start("one", forever)
    await supervisor.stop()


async def test_spawn_respects_group_limit_and_drains_on_stop() -> None:
    supervisor = TaskSupervisor()
    release = asyncio.Event()
    finished: list[int] = []

    async def refresh(n: int) -> None:
        await release.wait()
        finished.append(n)

    accepted = [supervisor.spawn(f"r{n}", refresh(n), group="swr", limit=2) for n in range(4)]
    assert [task is not None for task in accepted] == [True, True, False, False]
    assert supervisor.group_size("swr") == 2
    release.set()
    await supervisor.stop(drain_timeout_s=1.0)
    assert sorted(finished) == [0, 1]  # in-flight one-shot jobs finished during shutdown
    assert supervisor.group_size("swr") == 0


async def test_stop_cancels_jobs_that_overrun_the_drain() -> None:
    supervisor = TaskSupervisor()
    was_canceled = asyncio.Event()

    async def slow() -> None:
        try:
            await asyncio.sleep(10)
        except asyncio.CancelledError:
            was_canceled.set()
            raise

    supervisor.spawn("slow", slow(), group="swr", limit=1)
    await asyncio.sleep(0)
    await supervisor.stop(drain_timeout_s=0.01)
    assert was_canceled.is_set()


async def test_no_new_work_after_stop() -> None:
    supervisor = TaskSupervisor()
    await supervisor.stop()

    async def job() -> None:
        return None

    assert supervisor.spawn("late", job()) is None
    with pytest.raises(RuntimeError):
        supervisor.start("late", job)
