"""The plan 17.7 alert producers in the running app: their leader jobs are scheduled and the daily quick_check alerts.

What this is
    Integration tests on `create_app(env)` with its lifespan (the `app` and `client` fixtures of tests/conftest.py):
    the jobs step registers `alerts_rates`, `alerts_storage`, `alerts_backup` and `alerts_digest` as leader jobs, the
    leader runs each of them cleanly on an empty state, and the storage jobs get the `db_integrity` hook.

Why it exists
    The producers are only useful when something schedules them (lane_docs request 3: seven alerts were defined and
    never sent). The unit tests in `tests/unit/notify/test_notify_producers.py` pin what each producer sends; this
    file pins that the app actually wires them, on one leader (C6), and never at start.

How it works
    `register_storage_jobs` is wrapped before the app starts so the test sees the `on_integrity_failure` the lifespan
    passes. The jobs run through `JobRunner.run_job_now` once this worker holds the leader lease.

What to read next
    `roxy/lifespan.py` (`_register_wave3_jobs`, the storage jobs), `roxy/notify/producers.py`.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from roxy.notify import producers
from roxy.scheduler import jobs as jobs_mod

ALERT_JOBS = (producers.JOB_RATES, producers.JOB_STORAGE, producers.JOB_BACKUP, producers.JOB_DIGEST)


@pytest.fixture
def storage_hooks(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    seen: list[Any] = []
    original = jobs_mod.register_storage_jobs

    def wrapped(*args: Any, **kwargs: Any) -> Any:
        seen.append(kwargs.get("on_integrity_failure"))
        return original(*args, **kwargs)

    monkeypatch.setattr(jobs_mod, "register_storage_jobs", wrapped)
    return seen


async def _leader(ctx: Any) -> None:
    for _ in range(100):
        if ctx.leader is not None and ctx.leader.is_leader:
            return
        await asyncio.sleep(0.05)
    raise AssertionError("this worker never became the leader")


async def test_the_alert_jobs_run_on_the_leader_and_the_quick_check_alerts(
    storage_hooks: list[Any], app: Any, client: Any
) -> None:
    ctx = app.state.ctx
    assert storage_hooks  # the daily quick_check sends `db_integrity`
    assert callable(storage_hooks[0])
    runner = ctx.jobs
    for name in ALERT_JOBS:
        job = runner.registry.get(name)
        assert job.leader_only, name
        assert not job.run_at_start, name
    await _leader(ctx)
    for name in ALERT_JOBS:
        status = await runner.run_job_now(name)
        assert status.last_ok is True, (name, status.last_error)
    found = {row["name"]: row for row in runner.status()}
    assert found[producers.JOB_RATES]["last_result"]["roblox_429"]["roblox_429"] == 0
    assert found[producers.JOB_BACKUP]["last_result"] == {"backup": "no record"}
