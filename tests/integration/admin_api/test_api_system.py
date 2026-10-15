"""The System page API in the real app (plan 14.1; parity rows 84, 85, 121, 122): the fleet with both colors,
reset counts, the leader, jobs, the metrics pipeline, persistence, errors with redacted tracebacks, versions, the
non-secret environment, the forced flush and the per-worker watcher that carries it to every worker."""

from __future__ import annotations

import csv
import io
import json
import os
from typing import Any

from roxy.admin.api import system
from roxy.scheduler.jobs import JobRegistry


async def _metrics(api_app: Any, sql: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    return await api_app.ctx.dbs.metrics.read(lambda conn: [tuple(r) for r in conn.execute(sql, params).fetchall()])


async def _control(api_app: Any, sql: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    return await api_app.ctx.dbs.control.read(lambda conn: [tuple(r) for r in conn.execute(sql, params).fetchall()])


async def _beat(api_app: Any) -> None:
    reporter = api_app.ctx.heartbeat
    await reporter.beat()


async def _other_color(api_app: Any, *, pid: int = 4_000_001, fresh: bool = True) -> None:
    now = int(api_app.clock.now())
    seen = now if fresh else now - 120

    def write(conn: Any) -> None:
        conn.execute(
            "INSERT INTO worker_heartbeat (pid, started_at, last_seen, rss, requests, proxied, loop_lag_ms_p99, "
            "open_conns, inflight_upstream, worker_id, hostname, color, master_pid, max_requests, version, is_leader) "
            "VALUES (?, ?, ?, 1000, 7, 3, 1.5, 2, 1, ?, 'host', 'green', ?, 20000, '2.0.1', 0)",
            (pid, now - 50, seen, f"host:{pid}:x", os.getppid()),
        )

    await api_app.ctx.dbs.metrics.write(write)


# ================================================================================================ fleet


async def test_fleet_has_the_parity_row_84_fields_and_both_colors(api: Any, api_app: Any, api_json: Any) -> None:
    await _beat(api_app)
    await _other_color(api_app)
    await _other_color(api_app, pid=4_000_002, fresh=False)
    body = api_json(await api.get("system/fleet"))
    me = next(w for w in body["workers"] if w["is_this_worker"])
    assert me["pid"] == os.getpid()
    assert me["color"] == "dev"
    assert me["fresh"] is True
    for name in (
        "started_at",
        "uptime_s",
        "rss_bytes",
        "requests",
        "proxied",
        "max_requests",
        "counters_reset_at",
        "loop_lag_ms_p99",
        "open_connections",
        "inflight_upstream",
        "master_pid",
    ):
        assert name in me
    colors = {entry["color"]: entry for entry in body["colors"]}
    assert set(colors) == {"dev", "green"}
    assert colors["dev"]["expected"] == api_app.ctx.env.workers
    assert colors["dev"]["count"] == 1
    assert colors["dev"]["is_this_color"] is True
    assert body["colors"][0]["color"] == "dev"
    green = colors["green"]
    assert green["count"] == 1
    assert green["stale"] == 1
    assert green["master_pids"] == [os.getppid()]
    assert green["service_uptime_s"] is not None
    assert green["service_uptime_s"] >= 0
    assert body["deploying"] is True
    assert body["totals"]["fresh"] == 2
    assert body["totals"]["stale"] == 1
    assert body["host"]["uptime_s"] is not None
    assert body["this_worker"]["worker_id"] == api_app.ctx.worker_id
    assert body["tarpit_connections"]["connection_budget"] is not None
    assert "since_switch_s" in body["deploy"]


async def test_workers_table_and_export(api: Any, api_app: Any, api_json: Any) -> None:
    await _beat(api_app)
    await _other_color(api_app)
    page = api_json(await api.get("system/workers", params={"sort": "requests", "order": "desc"}))
    assert page["total"] == 2
    assert page["items"][0]["pid"] == 4_000_001
    assert [c["key"] for c in page["columns"]][:2] == ["pid", "color"]
    response = await api.get("system/workers", params={"format": "csv"})
    rows = list(csv.reader(io.StringIO(response.text)))
    assert rows[0][0] == "PID"
    assert len(rows) == 3


async def test_reset_counts_zeroes_every_worker_and_is_audited(api: Any, api_app: Any, api_json: Any) -> None:
    api_app.ctx.heartbeat.counters.requests = 42
    await _beat(api_app)
    await _other_color(api_app)
    api_app.clock.advance(5)
    body = api_json(await api.post("system/workers/reset-counts", json={"reason": "fresh start"}))
    at = int(api_app.clock.now())
    assert body["reset_at"] == at
    assert body["workers"] == 2
    assert body["message"] == "Worker request counts reset"
    rows = await _metrics(api_app, "SELECT requests, proxied, counters_reset_at FROM worker_heartbeat ORDER BY pid")
    assert rows == [(0, 0, at), (0, 0, at)]
    assert api_app.ctx.heartbeat.counters.requests == 0
    assert api_app.ctx.heartbeat.counters.reset_at == at
    audit_rows = await _control(
        api_app, "SELECT action, target, reason FROM audit_log WHERE id = ?", (body["audit_id"],)
    )
    assert audit_rows == [("system.reset_counts", "workers", "fresh start")]


# ================================================================================================ leader, jobs


async def test_leader_and_jobs(api: Any, api_app: Any, api_json: Any) -> None:
    leader = api_json(await api.get("system/leader"))
    # The lease times follow the fake clock, which the login moved; holder and epoch are what matter here.
    assert leader["holder"] == api_app.ctx.worker_id
    assert leader["epoch"] >= 1
    assert isinstance(leader["valid"], bool)
    assert leader["this_worker"]["is_leader"] is True
    await api_app.ctx.jobs.run_job_now("wal_checkpoint_passive")
    now = int(api_app.clock.now())
    await api_app.ctx.dbs.metrics.write(
        lambda conn: conn.execute(
            "INSERT INTO health_job_status (name, interval_s, last_started_at, last_finished_at, last_ok, holder, "
            "published_at) VALUES ('published_only_job', 60, ?, ?, 1, 'other', ?)",
            (now - 5, now - 4, now),
        )
    )
    body = api_json(await api.get("system/jobs"))
    jobs = {item["name"]: item for item in body["jobs"]}
    assert body["this_worker_is_leader"] is True
    assert {"retention", "hot_prune", "wal_checkpoint_passive", "daily_maintenance"} <= set(jobs)
    checkpoint = jobs["wal_checkpoint_passive"]
    assert checkpoint["source"] == "this_worker"
    assert checkpoint["runs"] == 1
    assert checkpoint["last_ok"] is True
    assert checkpoint["description"]
    assert jobs["published_only_job"]["source"] == "leader"
    assert jobs["published_only_job"]["last_ok"] is True
    assert body["checkpoints"]["wal_checkpoint_passive"]["last_duration_ms"] is not None


# ================================================================================================ pipeline


async def test_metrics_pipeline_and_persistence(api: Any, api_app: Any, api_json: Any) -> None:
    body = api_json(await api.get("system/metrics-pipeline"))
    assert body["scope"] == "this worker"
    assert body["worker_id"] == api_app.ctx.worker_id
    assert "metrics_dropped" in body["recorder"]
    assert "batch" in body["recorder"]
    assert [db["db"] for db in body["databases"]] == ["control", "hot", "metrics", "cache"]
    assert body["settings"]["metrics_queue_max"] == api_app.ctx.settings.get("metrics_queue_max")
    persistence = api_json(await api.get("system/persistence"))
    files = {db["db"]: db for db in persistence["databases"]}
    assert files["metrics"]["file"] == "metrics.db"
    assert files["metrics"]["bytes"] > 0
    assert persistence["total_bytes"] >= sum(db["bytes"] for db in persistence["databases"])


# ================================================================================================ errors


async def test_errors_are_searchable_and_tracebacks_redacted(
    api: Any, api_app: Any, api_json: Any, section13: Any
) -> None:
    now = int(api_app.clock.now())
    secret_trace = "Traceback\n  url https://user:hunter2secret@example.invalid/x\nValueError: boom"

    def write(conn: Any) -> None:
        conn.execute(
            "INSERT INTO errors (signature, count, first_seen, last_seen, source, last_detail, module_line, "
            "traceback_redacted) VALUES ('ValueError@proxy/router.py', 5, ?, ?, 'request', 'boom', "
            "'roxy.proxy.router:120', ?)",
            (now - 100, now - 10, secret_trace),
        )
        conn.execute(
            "INSERT INTO errors (signature, count, first_seen, last_seen, source, last_detail, module_line) "
            "VALUES ('KeyError@jobs', 50, ?, ?, 'job', 'missing', 'roxy.scheduler.jobs:9')",
            (now - 1000, now - 500),
        )

    await api_app.ctx.dbs.metrics.write(write)
    page = api_json(await api.get("system/errors"))
    assert [item["signature"] for item in page["items"]] == ["ValueError@proxy/router.py", "KeyError@jobs"]
    assert page["items"][0]["has_traceback"] is True
    assert set(page["sources"]) == {"job", "request"}
    by_count = api_json(await api.get("system/errors", params={"sort": "count"}))
    assert by_count["items"][0]["signature"] == "KeyError@jobs"
    found = api_json(await api.get("system/errors", params={"q": "scheduler"}))
    assert [item["signature"] for item in found["items"]] == ["KeyError@jobs"]
    only_jobs = api_json(await api.get("system/errors", params={"source": "job"}))
    assert only_jobs["total"] == 1
    detail = api_json(await api.get("system/errors/detail", params={"signature": "ValueError@proxy/router.py"}))
    assert "hunter2secret" not in detail["traceback"]
    assert "[redacted]" in detail["traceback"]
    assert detail["count"] == 5
    assert detail["hourly"] == []
    section13(await api.get("system/errors/detail", params={"signature": "nope"}), 404, "not_found")
    exported = await api.get("system/errors", params={"format": "json"})
    assert exported.json()["total"] == 2


# ================================================================================================ versions, env


async def test_versions_and_environment_never_show_a_secret(
    api: Any, api_app: Any, api_json: Any, fake_secrets: dict[str, str]
) -> None:
    await _beat(api_app)
    versions = api_json(await api.get("system/versions"))
    assert versions["package"] == "2.0.0"
    assert versions["template_version"] == 1
    assert set(versions["schema"]) == {"control", "hot", "metrics", "cache"}
    assert versions["schema"]["metrics"] >= versions["schema_required"]["metrics"]
    assert versions["libraries"]["fastapi"]
    assert versions["sqlite"]
    assert sum(versions["fleet_versions"].values()) == 1
    response = await api.get("system/environment")
    env = api_json(response)
    assert env["env"] == "development"
    assert env["workers"] == api_app.ctx.env.workers
    assert env["credentials_present"]["ip_hash_key"] is True
    assert all(isinstance(value, bool) for value in env["credentials_present"].values())
    # The Roblox credential is described by its manager (only egress/credential.py names its file, plan C1).
    assert set(env["credential"]) == {"bootstrap_file", "dashboard_value", "in_use"}
    assert all(isinstance(value, bool) for value in env["credential"].values())
    for value in fake_secrets.values():
        for line in value.splitlines():
            if len(line.strip()) >= 8:
                assert line.strip() not in response.text


# ================================================================================================ flush and watcher


async def test_forced_flush_writes_this_workers_metrics_and_asks_every_worker(
    api: Any, api_app: Any, api_json: Any, metrics_seed: Any
) -> None:
    metrics_seed.record(3)
    body = api_json(await api.post("system/flush", json={"reason": "refresh"}))
    assert body["flushed_here"] is True
    assert body["worker_id"] == api_app.ctx.worker_id
    rows = await _metrics(api_app, "SELECT sum(requests) FROM rollup_minute")
    assert rows == [(3,)]
    state = await _control(api_app, "SELECT value_json FROM service_state WHERE key = 'flush_requested_at'")
    assert json.loads(state[0][0]) == body["requested_at"]
    audit_rows = await _control(api_app, "SELECT action, target FROM audit_log WHERE id = ?", (body["audit_id"],))
    assert audit_rows == [("system.flush", "service_state:flush_requested_at")]


async def test_watcher_flushes_and_clears_memory_when_another_worker_asks(api_app: Any, metrics_seed: Any) -> None:
    ctx = api_app.ctx
    registry = JobRegistry()
    watcher = system.register_jobs(registry, ctx)
    assert system.WATCH_JOB in registry
    assert registry.get(system.WATCH_JOB).leader_only is False
    assert await watcher.run_once() == {"flushed": False, "reset": []}  # the first look only records
    metrics_seed.record(2)
    ctx.abuse.tarpit.stats.record(
        category="flood", reason="r", ip="203.0.113.1", held_s=2.0, skipped=False, gap_s=0.0, at=ctx.clock.now()
    )
    assert ctx.abuse.tarpit.stats.snapshot()["held"] == 1
    api_app.clock.advance(3)
    await system.write_state(ctx, system.FLUSH_KEY, ctx.clock.now())
    await system.write_state(ctx, system.MEMORY_RESET_KEY, {"tarpit": int(ctx.clock.now())})
    acted = await watcher.run_once()
    assert acted == {"flushed": True, "reset": ["tarpit"]}
    assert (await _metrics(api_app, "SELECT sum(requests) FROM rollup_minute")) == [(2,)]
    assert ctx.abuse.tarpit.stats.snapshot()["held"] == 0
    assert await watcher.run_once() == {"flushed": False, "reset": []}  # each request is acted on once


async def test_guards(anon_api: Any, api: Any, section13: Any) -> None:
    for path in ("system/fleet", "system/jobs", "system/errors", "system/environment"):
        assert (await anon_api.get(path)).status_code == 401
    assert (await anon_api.post("system/flush", json={})).status_code == 401
    assert (await api.post("system/flush", json={}, csrf=False)).status_code == 403
    section13(await api.post("system/flush"), 400, "missing_body")
    section13(await api.post("system/workers/reset-counts", json={"reason": 5}), 422, "validation_failed")
