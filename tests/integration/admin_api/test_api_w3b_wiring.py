"""Wave 3b integration on the real app: the lifespan wiring and the integrator's fixes to the specialists' requests.

What this is
    Integration tests over one running app (`api_app`: the real lifespan, temporary databases, Roblox played by
    respx) for what the wave 3b integration connected: the recommendations engine, its actions, the auto-applier,
    the health runner and the loop lag monitor on the context; their jobs in the scheduler with intervals that
    follow the catalog settings live; the heartbeat feeding the worker history; request fingerprints (parity rows
    79 and 134) and the fetched body hash in request samples; event details that stay JSON after redaction; the
    eviction ages in the cache minute; the credential probe trigger; the section 13 shape of the guards' answers;
    the settings editor refusing to arm the spam detectors; one action at a time per recommendation; one place
    lookup cache per worker; the LLM export link; and the bounded job result on the System page.

Why it exists
    Each specialist tested their own package; these tests prove the pieces are connected in a running worker, the
    way production builds them (DESIGN.md section 14, "Wave 3b as built").

How it works
    The fixtures of `tests/integration/admin_api/conftest.py`. Proxied requests go through the app's own client with
    a Roblox User-Agent and a documentation-range address; the recorder is flushed before metrics.db is read.

What to read next
    `roxy/lifespan.py` (`_start_insights`, `_register_wave3_jobs`), `roxy/proxy/router.py` (`note_fingerprint`,
    `fetched_body_hash`), `roxy/core/errors.py` (`section13_exception_body`), `roxy/admin/api/settings.py`
    (`refuse_arming`), `roxy/insights/actions.py` (`_exclusive`).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any

import httpx
import pytest

from roxy.admin.api import clients as clients_api
from roxy.admin.api import lookup as lookup_api
from roxy.cache.store import EvictionReport
from roxy.config.audit import Actor
from roxy.config.settings_service import FINGERPRINT_CONTEXT
from roxy.core.ids import new_id
from roxy.core.iphash import derived_key
from roxy.health.runner import HealthRunner
from roxy.insights.actions import ACTION_LEASE_PREFIX, RecommendationActions
from roxy.insights.autoapply import AutoApplier
from roxy.insights.engine import InsightsEngine, write_recommendation
from roxy.insights.models import Evidence, ProposedChange, Recommendation, make_fingerprint
from roxy.metrics.recorder import note_eviction_ages, note_eviction_pass
from roxy.rules.service import RulesService
from roxy.scheduler.heartbeat import LoopLagMonitor
from roxy.scheduler.jobs import MAX_RESULT_CHARS, Job, JobRegistry, JobRunner
from roxy.storage import leases
from roxy.upstream.internal import place_lookup_for

GAMES = "games.roblox.com"
LEADER_JOBS = {
    "insights_evaluate",
    "insights_triggers",
    "insights_history_prune",
    "insights_anomalies",
    "insights_watch",
    "insights_auto_apply",
    "health_scheduled_run",
    "health_publish_jobs",
    "llm_export_file",
}
PROBE_URL = "https://users.roblox.com/v1/users/authenticated"


async def proxy(api_app: Any, path: str, *, n: int = 1, headers: dict[str, str] | None = None) -> httpx.Response:
    sent = {"User-Agent": "Roblox/Linux", "X-Forwarded-For": f"198.51.100.{n}", **(headers or {})}
    response: httpx.Response = await api_app.harness.http.get(path, headers=sent)
    await api_app.ctx.cache.settle()
    return response


def games_route(api_app: Any, body: bytes = b'{"data":[1]}') -> Any:
    return api_app.roblox.route(host=GAMES, path="/v1/games").mock(
        return_value=httpx.Response(200, content=body, headers={"Content-Type": "application/json"})
    )


async def metrics_rows(api_app: Any, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    await api_app.ctx.recorder.flush()

    def read(conn: sqlite3.Connection) -> list[dict[str, Any]]:
        return [dict(row) for row in conn.execute(sql, params).fetchall()]

    rows: list[dict[str, Any]] = await api_app.ctx.dbs.metrics.read(read)
    return rows


# ================================================================================================ the wiring


async def test_lifespan_builds_the_wave3_services_and_registers_their_jobs(api_app: Any) -> None:
    ctx = api_app.ctx
    assert "insights" in ctx.startup_steps
    assert ctx.startup_steps.index("insights") < ctx.startup_steps.index("jobs")
    assert isinstance(ctx.insights, InsightsEngine)
    assert ctx.insights.rules, "the rule modules were loaded"
    assert isinstance(ctx.insight_actions, RecommendationActions)
    assert ctx.insight_actions.engine is ctx.insights
    assert isinstance(ctx.auto_apply, AutoApplier)
    assert isinstance(ctx.health, HealthRunner)
    assert ctx.health.ctx is ctx
    assert isinstance(ctx.loop_lag, LoopLagMonitor)
    assert ctx.heartbeat.lag is ctx.loop_lag
    running = {status.name for status in ctx.tasks.status() if status.running}
    assert {"loop_lag", "heartbeat", "jobs"} <= running
    jobs = {job.name: job for job in ctx.jobs.registry.all()}
    assert set(jobs) >= LEADER_JOBS
    assert all(jobs[name].leader_only for name in LEADER_JOBS)
    assert jobs["admin_requests_watch"].leader_only is False  # every worker carries out a forced flush
    assert jobs["admin_requests_watch"].interval() == 1.0
    assert jobs["insights_evaluate"].interval() == float(ctx.settings.int("insights_interval_s"))
    assert jobs["health_scheduled_run"].interval() == 300.0
    assert jobs["health_publish_jobs"].interval() == 30.0
    assert jobs["llm_export_file"].interval() == 3600.0


async def test_job_intervals_follow_their_settings_without_a_restart(api_app: Any) -> None:
    jobs = {job.name: job for job in api_app.ctx.jobs.registry.all()}
    await api_app.settings(insights_enabled=0, health_auto_interval_h=0)
    assert jobs["insights_evaluate"].interval() == 0.0  # 0 turns a job off
    assert jobs["insights_auto_apply"].interval() == 0.0
    assert jobs["health_scheduled_run"].interval() == 0.0
    await api_app.settings(insights_enabled=1, insights_interval_s=120, health_auto_interval_h=12)
    assert jobs["insights_evaluate"].interval() == 120.0
    assert jobs["health_scheduled_run"].interval() == 300.0


async def test_recommendation_actions_fingerprint_like_the_settings_editor(api_app: Any) -> None:
    ctx = api_app.ctx
    assert ctx.ip_hash_key is not None
    expected = derived_key(ctx.ip_hash_key, FINGERPRINT_CONTEXT)
    assert ctx.insight_actions.settings_service._fingerprint_key == expected


async def test_job_status_shows_a_bounded_last_result() -> None:
    registry = JobRegistry()

    async def small(_ctx: Any) -> dict[str, Any]:
        return {"ran": True, "rows": 3}

    async def large(_ctx: Any) -> dict[str, Any]:
        return {"text": "x" * (MAX_RESULT_CHARS + 10)}

    registry.add(Job("small", 60.0, small, leader_only=False))
    registry.add(Job("large", 60.0, large, leader_only=False))
    runner = JobRunner(registry, None)
    await runner.run_job_now("small")
    await runner.run_job_now("large")
    rows = {row["name"]: row for row in runner.status()}
    assert rows["small"]["last_result"] == {"ran": True, "rows": 3}
    assert rows["large"]["last_result"]["truncated"] is True
    assert rows["large"]["last_result"]["chars"] > MAX_RESULT_CHARS


# ================================================================================================ history hooks


async def test_the_heartbeat_feeds_the_worker_minute_history(api_app: Any) -> None:
    ctx = api_app.ctx
    await ctx.heartbeat.beat()
    await ctx.heartbeat.beat()  # the CPU share needs two readings
    rows = await metrics_rows(
        api_app, "SELECT worker_id, samples, cpu_pct_sum, rss FROM worker_minute WHERE worker_id = ?", (ctx.worker_id,)
    )
    assert rows, "no worker history was written"
    assert sum(int(row["samples"]) for row in rows) >= 1
    assert all(float(row["cpu_pct_sum"]) >= 0 for row in rows)


async def test_eviction_passes_carry_their_young_evictions_into_the_cache_minute(api_app: Any) -> None:
    report = EvictionReport(evicted=3, young=2, age_s_total=30.0, young_age_s_total=8.0, entries_before=10)
    note_eviction_pass(api_app.ctx.recorder, report)  # the pass row only: its evictions are not counted twice
    note_eviction_ages(api_app.ctx.recorder, report)
    rows = await metrics_rows(
        api_app, "SELECT evictions, young_evictions, evicted_age_s_sum, young_age_s_sum FROM cache_minute"
    )
    assert [(r["evictions"], r["young_evictions"]) for r in rows] == [(3, 2)]
    assert rows[0]["evicted_age_s_sum"] == pytest.approx(30.0)
    assert rows[0]["young_age_s_sum"] == pytest.approx(8.0)


async def test_event_details_stay_json_when_redaction_meets_a_secret_shaped_key(api_app: Any) -> None:
    """`{"pass": 6}` used to become invalid JSON (`"pass": [redacted]`); the live tail then read `{}`."""
    api_app.ctx.recorder.record_event("w3b_detail_check", "info", None, {"pass": 6, "failed": 1, "note": "plain"})
    rows = await metrics_rows(api_app, "SELECT detail_json FROM events WHERE type = 'w3b_detail_check'")
    detail = json.loads(rows[0]["detail_json"])
    assert detail == {"pass": "[redacted]", "failed": 1, "note": "plain"}


# ================================================================================================ the proxy path


async def test_passing_requests_are_fingerprinted_and_filtered_ones_count_as_blocked(api_app: Any) -> None:
    games_route(api_app)
    allowed = await proxy(api_app, f"/{GAMES}/v1/games?universeIds=1", headers={"X-W3b-Probe": "alpha"})
    assert allowed.status_code == 200, allowed.text
    names = await metrics_rows(api_app, "SELECT name, count FROM fingerprint_headers")
    assert {"x-w3b-probe", "user-agent"} <= {row["name"] for row in names}
    agents = await metrics_rows(api_app, "SELECT user_agent FROM fingerprint_user_agents")
    assert [row["user_agent"] for row in agents] == ["Roblox/Linux"]

    service = RulesService(api_app.ctx.dbs.control, clock=api_app.clock, store=api_app.ctx.rules)
    await service.create("rules_header", {"needle": "w3bfiltered", "scope": "either"}, Actor("cli", "test"), "test")
    refused = await proxy(api_app, f"/{GAMES}/v1/games?universeIds=2", n=2, headers={"X-Tool": "w3bfiltered"})
    assert refused.status_code >= 400
    api_app.clock.advance(61)  # blocked fingerprints are per-minute sums, written once their minute closed
    blocked = await metrics_rows(api_app, "SELECT type, reason_code FROM events WHERE type LIKE 'blocked_%'")
    assert {row["type"] for row in blocked} == {"blocked_header", "blocked_user_agent"}
    assert "x-tool" in {row["reason_code"] for row in blocked}
    # The refused request did not add to the passing fingerprints.
    names_after = await metrics_rows(api_app, "SELECT name FROM fingerprint_headers WHERE name = 'x-tool'")
    assert names_after == []


async def test_request_samples_carry_the_hash_of_the_body_fetched_from_roblox(api_app: Any) -> None:
    body = b'{"data":[{"id":1,"name":"w3b"}]}'
    games_route(api_app, body)
    first = await proxy(api_app, f"/{GAMES}/v1/games?universeIds=7")
    second = await proxy(api_app, f"/{GAMES}/v1/games?universeIds=7", n=2)
    assert first.status_code == second.status_code == 200
    assert second.headers.get("roxy-cache") == "HIT"
    rows = await metrics_rows(api_app, "SELECT cache_state, body_hash FROM request_samples ORDER BY at_ms, rowid")
    assert [row["body_hash"] for row in rows] == [hashlib.sha256(body).hexdigest()[:16], None]


async def test_credential_probes_record_what_started_them(
    api_app: Any, api: Any, api_json: Any, fake_secrets: dict[str, str]
) -> None:
    bootstrap = fake_secrets["roblox_credential"]

    def answer(request: httpx.Request) -> httpx.Response:
        if request.headers.get("cookie", "") == f".ROBLOSECURITY={bootstrap}":
            return httpx.Response(200, json={"id": 1, "name": "user1"})
        return httpx.Response(401, json={"errors": [{"message": "Authorization has been denied"}]})

    api_app.roblox.get(PROBE_URL).mock(side_effect=answer)
    checked = api_json(await api.post("credential/check"))
    assert checked["probe"]["ok"] is True
    rows = await metrics_rows(api_app, "SELECT detail_json FROM events WHERE type = 'internal_call'")
    triggers = {json.loads(row["detail_json"]).get("trigger") for row in rows}
    assert "admin" in triggers
    assert api_app.ctx.upstream.probe_fetch_for("liveness").keywords == {"trigger": "scheduled"}
    assert api_app.ctx.upstream.probe_fetch_for("health").keywords == {"trigger": "health"}


# ================================================================================================ admin API


async def test_guard_answers_on_the_api_use_the_section13_object(api: Any, anon_api: Any, section13: Any) -> None:
    section13(await anon_api.get("settings"), 401, "unauthorized")
    section13(await anon_api.get("/admin/api/v1/auth/sessions"), 401, "unauthorized")
    section13(await api.patch("settings", json={"changes": {"cache_ttl_seconds": 61}}, csrf=False), 403, "forbidden")
    missing = await anon_api.get("no-such-area")
    assert missing.status_code == 404
    assert missing.json() == {"error": {"code": "not_found", "message": "Not found.", "fields": {}}}


async def test_the_settings_editor_cannot_arm_the_spam_detectors(
    api_app: Any, api: Any, api_json: Any, section13: Any
) -> None:
    assert api_app.ctx.settings.bool("spam_dry_run") is True
    for response in (
        await api.patch("settings", json={"changes": {"spam_dry_run": 0}, "reason": "x", "confirm_high_risk": True}),
        await api.put("settings/spam_dry_run", json={"value": 0, "reason": "x", "confirm_high_risk": True}),
        await api.post(
            "settings/import",
            json={"document": {"spam_dry_run": 0}, "reason": "restore", "confirm_high_risk": True},
        ),
    ):
        fields = section13(response, 422, "confirmation_required")
        assert "protection/spam/arm" in fields["spam_dry_run"]
    assert api_app.ctx.settings.bool("spam_dry_run") is True
    # Leaving the dry run on, or turning it back on, is never refused.
    api_json(await api.put("settings/spam_dry_run", json={"value": 1}))


async def test_one_action_at_a_time_per_recommendation(api_app: Any, api: Any, api_json: Any, section13: Any) -> None:
    ctx, clock = api_app.ctx, api_app.clock
    rec = Recommendation(
        rule_id="CACHE-LOW-HIT",
        family="cache",
        subject="w3b",
        title="A longer cache lifetime",
        evidence=Evidence(sample_size=1),
        changes=[ProposedChange("setting", key="cache_ttl_seconds", current=60, proposed=90)],
    )
    rec.id, rec.fingerprint, rec.state = new_id("rec", clock), make_fingerprint(rec.rule_id, rec.subject), "open"
    rec.created_at = rec.updated_at = clock.now()
    await ctx.dbs.metrics.write(lambda conn: write_recommendation(conn, rec))
    name = f"{ACTION_LEASE_PREFIX}{rec.id}"
    await ctx.dbs.hot.write(lambda conn: leases.acquire(conn, name, "another-worker", 60_000, clock.now_ms()))
    busy = section13(await api.post(f"recommendations/{rec.id}/snooze", json={"duration": "1h"}), 409, "wrong_state")
    assert busy == {}
    await ctx.dbs.hot.write(lambda conn: leases.release(conn, name, "another-worker", delete=True))
    snoozed = api_json(await api.post(f"recommendations/{rec.id}/snooze", json={"duration": "1h"}))
    assert snoozed["recommendation"]["state"] == "snoozed"
    held = await ctx.dbs.hot.read(lambda conn: leases.holder_epoch(conn, name))
    assert held is None  # released after the action


async def test_the_place_lookup_cache_is_shared_by_every_route(api_app: Any) -> None:
    upstream = api_app.ctx.upstream
    one = place_lookup_for(upstream)
    assert lookup_api.lookup_for(upstream) is one
    assert clients_api.CachedPlaceLookup is type(one)
    assert one.peek("1818") is None


async def test_the_llm_export_link_points_at_the_export_area(api: Any, api_json: Any) -> None:
    datasets = api_json(await api.get("export/datasets"))
    assert datasets["llm_export"] == "/admin/api/v1/export/llm"
    exported = await api.get(datasets["llm_export"], params={"detail": "summary"})
    assert exported.status_code == 200, exported.text[:200]
