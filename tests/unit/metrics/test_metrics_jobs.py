"""The metrics leader jobs: registration, fenced writes after a takeover, auto-ignore through the rules service."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from roxy.core.clock import FakeClock
from roxy.metrics import fingerprints as fp
from roxy.metrics.jobs import compaction_config, register_metrics_jobs, rules_ignore_header
from roxy.metrics.recorder import MetricsRecorder, OutcomeEvent
from roxy.scheduler.jobs import JobRegistry, JobRunner
from roxy.scheduler.leader import LeaderElector

Rows = Callable[..., list[tuple[Any, ...]]]


def test_compaction_config_reads_settings(settings: Any) -> None:
    settings.set(
        ui_timezone="Europe/Berlin", metrics_flush_interval_ms=60000, max_caller_records=7, activity_tracking=0
    )
    config = compaction_config(settings.get)
    assert config.tz_name == "Europe/Berlin"
    assert config.grace_s == 150  # two 60 s flush intervals plus 30 s
    assert config.caps.places == 7
    assert config.activity_tracking is False
    nothing: dict[str, Any] = {}
    assert compaction_config(nothing.__getitem__).grace_s == 120


async def test_jobs_run_on_the_leader_and_are_fenced(
    dbs: Any,
    settings: Any,
    fake_clock: FakeClock,
    recorder: MetricsRecorder,
    make_event: Callable[..., OutcomeEvent],
    metrics_rows: Rows,
) -> None:
    registry = JobRegistry()
    register_metrics_jobs(registry, dbs, settings.get)
    assert {job.name for job in registry.all()} == {
        "metrics_compaction",
        "metrics_live_prune",
        "metrics_security_caps",
        "fingerprint_auto_ignore",
    }
    for _ in range(5):
        recorder.record_outcome(make_event())
    recorder.close()
    fake_clock.advance(2 * 3600)

    leader = LeaderElector(dbs.hot, "worker-a", fake_clock)
    await leader.tick()
    assert leader.is_leader
    runner = JobRunner(registry, leader, fake_clock, worker_id="worker-a")
    status = await runner.run_job_now("metrics_compaction")
    assert status.last_ok is True
    assert metrics_rows("SELECT sum(requests) FROM rollup_hour") == [(5,)]

    # worker-a stalls past its lease; worker-b takes over. worker-a still believes it leads, but cannot write.
    fake_clock.advance(16)
    other = LeaderElector(dbs.hot, "worker-b", fake_clock)
    await other.tick()
    assert other.is_leader
    assert leader.is_leader  # stale belief: only the fencing check can stop it
    dbs.metrics.write_sync(lambda c: c.execute("DELETE FROM rollup_hour"))
    status = await runner.run_job_now("metrics_compaction")
    assert status.last_ok is False
    assert "lost leadership" in (status.last_error or "")
    assert metrics_rows("SELECT count(*) FROM rollup_hour") == [(0,)]


async def test_auto_ignore_job_calls_back_and_clears_values(
    dbs: Any, settings: Any, fake_clock: FakeClock, metrics_rows: Rows
) -> None:
    agg = fp.FingerprintAggregator()
    for i in range(600):
        agg.add([("X-Request-Id", f"id-{i}")], "UA", int(fake_clock.now()))
    items = agg.drain()
    dbs.metrics.write_sync(lambda c: fp.write_fingerprints(c, items, value_cap=500))
    calls: list[tuple[str, str]] = []

    async def ignore(name: str, note: str) -> bool:
        calls.append((name, note))
        return True

    registry = JobRegistry()
    register_metrics_jobs(registry, dbs, settings.get, ignore_header=ignore, ignored_headers=lambda: ["traceparent"])
    leader = LeaderElector(dbs.hot, "worker-a", fake_clock)
    await leader.tick()
    runner = JobRunner(registry, leader, fake_clock)
    status = await runner.run_job_now("fingerprint_auto_ignore")
    assert status.last_result == ["x-request-id"]
    assert calls == [("x-request-id", "auto: 500 distinct values in 600 requests")]
    assert metrics_rows("SELECT count(*) FROM fingerprint_values") == [(0,)]
    settings.set(auto_ignore_high_cardinality=0)
    status = await runner.run_job_now("fingerprint_auto_ignore")
    assert status.last_result == []


async def test_rules_ignore_header_writes_an_audited_auto_entry(dbs: Any, fake_clock: FakeClock) -> None:
    ignore = rules_ignore_header(dbs.control, clock=fake_clock)
    assert await ignore("x-request-id", "auto: 500 distinct values in 600 requests") is True
    assert await ignore("x-request-id", "again") is True  # already there
    row = dbs.control.read_sync(lambda c: tuple(c.execute("SELECT name, auto FROM ignored_value_headers").fetchone()))
    assert row == ("x-request-id", 1)
    audit = dbs.control.read_sync(
        lambda c: c.execute("SELECT count(*) FROM audit_log WHERE target LIKE '%ignored_value_headers%'").fetchone()[0]
    )
    assert audit == 1
    assert await ignore("bad header name!", "x") is False


async def test_live_prune_and_security_caps_jobs(
    dbs: Any,
    settings: Any,
    fake_clock: FakeClock,
    recorder: MetricsRecorder,
    make_event: Callable[..., OutcomeEvent],
    metrics_rows: Rows,
) -> None:
    recorder.record_outcome(make_event())
    for i in range(4):
        recorder.record_probe(f"198.51.100.{i}", "Invalid 2FA code")
    recorder.close()
    settings.set(max_exploit_records=2)
    fake_clock.advance(1000)
    registry = JobRegistry()
    register_metrics_jobs(registry, dbs, settings.get)
    leader = LeaderElector(dbs.hot, "w", fake_clock)
    await leader.tick()
    runner = JobRunner(registry, leader, fake_clock)
    assert (await runner.run_job_now("metrics_live_prune")).last_result == 1
    assert (await runner.run_job_now("metrics_security_caps")).last_result == {"probe": 2}
    assert metrics_rows("SELECT type, count(*) FROM events GROUP BY type") == [("probe", 2)]
