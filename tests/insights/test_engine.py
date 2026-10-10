"""The insights engine, its actions and auto-apply, the simulator, anomalies and the recorder's history hooks.

What this is
    Tests on real temporary databases (the `dbs` fixture) with a fake clock and a test rule whose results each test
    sets: the per-rule pipeline (switches, severity override, evidence minimum, fingerprints, `safe_auto` from the
    change kinds), the lifecycle (open, update, resolve, expire, snooze, dismiss cooldown, re-open on a severity
    rise), SSE publication, trigger detection, apply and undo through the audited services (with compensation and
    supersede checks), the D7 guardrails, watch window and automatic rollback, the 11.3 simulation algorithms,
    anomaly scoring, the schema version 2 history hooks of the metrics recorder, and `register_jobs`.

Why it exists
    Plan 11.1 to 11.4 behaviors that no single rule fixture exercises, and that the three rule families written on
    this framework rely on.

What to read next
    `roxy/insights/engine.py`, `roxy/insights/actions.py`, `roxy/insights/autoapply.py`.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from typing import Any

import pytest

from roxy.config.audit import Actor
from roxy.config.runtime import RuntimeSettings, load_runtime_settings
from roxy.config.settings_service import SettingsService
from roxy.core.clock import FakeClock
from roxy.core.reasons import AuthClass, CacheState, Egress, Outcome, ReasonCode, Source
from roxy.insights import anomalies, register_jobs, simulate
from roxy.insights.actions import ActionError, RecommendationActions
from roxy.insights.autoapply import AutoApplier, guardrail_problem, worse
from roxy.insights.context import InsightContext, InsightProviders
from roxy.insights.engine import RECOMMENDATION_EVENT, InsightsEngine
from roxy.insights.models import Evidence, ProposedChange, Recommendation, make_fingerprint
from roxy.insights.rules.base import Rule
from roxy.metrics import read_history
from roxy.metrics.recorder import MetricsRecorder, OutcomeEvent
from roxy.rules.service import RuleConflict, RulesService
from roxy.rules.store import RulesStore
from roxy.scheduler.jobs import JobRegistry
from roxy.scheduler.leader import JobContext
from roxy.upstream.buckets import BucketSpec, Denial, Grant, ReserveOutcome
from roxy.upstream.trace import Trace

NOW = 1_791_385_200.0  # 2026-10-07T15:00:00Z, a whole minute
ADMIN = Actor("admin", "tester", "203.0.113.5")
TEMPLATE = "games.roblox.com/v1/games"


class FakeRule(Rule):
    """A test rule (catalog id UP-5XX) whose recommendations each test sets."""

    id = "UP-5XX"
    safe_auto = True

    def __init__(self) -> None:
        self.results: list[Recommendation] = []
        self.error: Exception | None = None
        self.minimum = 1

    def minimum_evidence(self, ctx: InsightContext) -> int:
        return self.minimum

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        if self.error is not None:
            raise self.error
        return [copy.deepcopy(rec) for rec in self.results]


def rec(
    subject: str = TEMPLATE,
    *,
    severity: str = "warn",
    changes: list[ProposedChange] | None = None,
    sample: int = 5,
    safe_auto: bool = True,
    risk: str = "low",
) -> Recommendation:
    return Recommendation(
        rule_id="UP-5XX",
        family="upstream",
        subject=subject,
        title=f"Test recommendation for {subject}",
        severity=severity,
        evidence=Evidence(sample_size=sample).add("calls", sample),
        changes=list(changes if changes is not None else [bucket(90)]),
        safe_auto=safe_auto,
        risk=risk,
    )


def bucket(per_min: float, current: float = 120.0) -> ProposedChange:
    return ProposedChange(
        "bucket_override",
        bucket_key=f"endpoint:{TEMPLATE}",
        current={"per_min": current, "burst": 10},
        proposed={"per_min": per_min, "burst": 10},
    )


@dataclass
class World:
    dbs: Any
    clock: FakeClock
    runtime: RuntimeSettings
    store: RulesStore
    rule: FakeRule
    engine: InsightsEngine
    settings: SettingsService
    rules: RulesService
    actions: RecommendationActions

    async def set(self, **values: Any) -> None:
        await self.settings.update(values, ADMIN, "test setup")

    def events(self, action: str | None = None) -> list[dict[str, Any]]:
        rows = self.dbs.metrics.read_sync(
            lambda c: c.execute(
                "SELECT detail_json FROM events WHERE type = ? ORDER BY id", (RECOMMENDATION_EVENT,)
            ).fetchall()
        )
        details = [json.loads(r[0]) for r in rows]
        return [d for d in details if action is None or d["action"] == action]

    def rows(self) -> list[tuple[str, str, str]]:
        found: list[tuple[str, str, str]] = self.dbs.metrics.read_sync(
            lambda c: [
                (str(r[0]), str(r[1]), str(r[2]))
                for r in c.execute("SELECT id, state, severity FROM recommendations ORDER BY rowid")
            ]
        )
        return found


@pytest.fixture
async def world(dbs: Any) -> World:
    clock = FakeClock(NOW)
    runtime = await load_runtime_settings(dbs, clock)
    store = RulesStore(dbs.control, clock=clock)
    await store.reload()
    rule = FakeRule()
    engine = InsightsEngine(dbs=dbs, settings=runtime, rules=store, clock=clock, rule_set={rule.id: rule})
    settings = SettingsService(dbs.control, runtime=runtime, clock=clock)
    rules = RulesService(dbs.control, clock=clock, store=store)
    actions = RecommendationActions(engine=engine, settings_service=settings, rules_service=rules, clock=clock)
    return World(dbs, clock, runtime, store, rule, engine, settings, rules, actions)


# ------------------------------------------------------------------------------------------ the rule pipeline


async def test_evaluate_rule_applies_the_engine_pipeline(world: World) -> None:
    world.rule.results = [
        rec("a", changes=[bucket(90)]),
        rec("a", severity="info"),  # same subject: one fingerprint, the higher severity wins
        rec("b", changes=[ProposedChange("setting", key="cache_ttl_seconds", current=120, proposed=150)]),
        rec("c", sample=0),  # below the evidence minimum
    ]
    outcome = await world.engine.evaluate_rule("UP-5XX")
    assert outcome.ran
    assert [r.subject for r in outcome.recommendations] == ["a", "b"]
    by_subject = {r.subject: r for r in outcome.recommendations}
    assert by_subject["a"].severity == "warn"
    assert by_subject["a"].safe_auto is True
    assert by_subject["b"].safe_auto is False  # a global setting is never safe_auto (11.2)
    assert by_subject["a"].fingerprint == make_fingerprint("UP-5XX", "a")
    assert by_subject["a"].dry_run_available is True
    world.rule.minimum = 6
    assert (await world.engine.evaluate_rule("UP-5XX")).recommendations == []
    world.rule.minimum = 1
    await world.set(insight_up_5xx_severity="critical")
    forced = (await world.engine.evaluate_rule("UP-5XX")).recommendations
    assert {r.severity for r in forced} == {"critical"}
    assert forced[0].computed_severity == "warn"
    await world.set(insight_up_5xx_enabled=0)
    assert (await world.engine.evaluate_rule("UP-5XX")).skipped == "rule_disabled"
    await world.set(insight_up_5xx_enabled=1, insights_enabled=0)
    assert (await world.engine.evaluate_rule("UP-5XX")).skipped == "insights_disabled"
    assert (await world.engine.evaluate_rule("SYS-DISK")).skipped == "unknown_rule"
    await world.set(insights_enabled=1)
    world.rule.error = RuntimeError("boom")
    failed = await world.engine.evaluate_rule("UP-5XX")
    assert failed.error
    assert "boom" in failed.error
    assert not failed.ran


async def test_lifecycle_open_update_resolve_reopen(world: World) -> None:
    world.rule.results = [rec("a")]
    report = await world.engine.run_once()
    assert report.opened == 1
    assert report.evaluated == 1
    ((first_id, state, _sev),) = world.rows()
    assert state == "open"
    assert first_id.startswith("rec_")
    assert [e["action"] for e in world.events()] == ["opened"]
    world.rule.results = [rec("a", severity="critical")]
    report = await world.engine.run_once()
    assert report.updated == 1
    assert world.rows() == [(first_id, "open", "critical")]
    assert world.events()[-1]["action"] == "updated"
    report = await world.engine.run_once()  # nothing changed: updated silently
    assert report.updated == 1
    assert len(world.events()) == 2
    world.rule.results = []
    report = await world.engine.run_once()
    assert report.resolved == 1
    assert world.rows()[0][1] == "resolved"
    world.rule.results = [rec("a")]
    await world.engine.run_once()
    rows = world.rows()
    assert len(rows) == 2
    assert rows[1][1] == "open"
    assert rows[1][0] != first_id
    stored = await world.engine.get(rows[1][0])
    assert stored is not None
    assert stored.subject == "a"
    assert stored.changes[0].kind == "bucket_override"
    assert [r.id for r in await world.engine.list()] == [rows[1][0]]


async def test_expiry_and_failed_rules(world: World) -> None:
    world.rule.results = [rec("a")]
    await world.engine.run_once()
    world.rule.error = RuntimeError("data source down")
    report = await world.engine.run_once()
    assert report.failed == ["UP-5XX"]
    assert world.rows()[0][1] == "open"
    world.rule.error = None
    world.clock.advance(7 * 86_400 + 1)
    report = await world.engine.run_once()
    assert report.expired == 1
    assert report.opened == 1
    assert [r[1] for r in world.rows()] == ["expired", "open"]


async def test_snooze_and_dismiss_with_cooldown(world: World) -> None:
    world.rule.results = [rec("a")]
    await world.engine.run_once()
    rec_id = world.rows()[0][0]
    snoozed = await world.actions.snooze(rec_id, ADMIN, duration="1h")
    assert snoozed.state == "snoozed"
    await world.engine.run_once()
    assert world.rows()[0][1] == "snoozed"
    world.clock.advance(3601)
    report = await world.engine.run_once()
    assert report.unsnoozed == 1
    assert world.rows()[0][1] == "open"
    with pytest.raises(ActionError) as bad:
        await world.actions.dismiss(rec_id, ADMIN, "other")
    assert bad.value.code == "invalid"
    with pytest.raises(ActionError):
        await world.actions.dismiss(rec_id, ADMIN, "because")
    with pytest.raises(ActionError):
        await world.actions.dismiss(rec_id, ADMIN, "other", "dash " + chr(0x2014) + " here")
    dismissed = await world.actions.dismiss(rec_id, ADMIN, "intended_behavior", "seasonal traffic")
    assert dismissed.dismissed_reason == "intended_behavior: seasonal traffic"
    report = await world.engine.run_once()
    assert report.quiet == 1
    assert len(world.rows()) == 1
    world.rule.results = [rec("a", severity="critical")]
    report = await world.engine.run_once()
    assert report.reopened == 1
    assert [r[1] for r in world.rows()] == ["dismissed", "open"]
    actions = world.dbs.metrics.read_sync(
        lambda c: [r[0] for r in c.execute("SELECT action FROM recommendation_actions ORDER BY id")]
    )
    assert actions == ["snooze", "dismiss"]


async def test_triggers_start_an_early_run(world: World) -> None:
    world.rule.results = [rec("a")]
    assert await world.engine.check_triggers() is None  # the first poll only sets the cursors
    world.dbs.metrics.write_sync(
        lambda c: c.execute(
            "INSERT INTO events (at_ms, type, severity, detail_json) VALUES (?, 'breaker_open', 'warning', '{}')",
            (int(NOW * 1000),),
        )
    )
    world.clock.advance(10)
    report = await world.engine.check_triggers()
    assert report is not None
    assert report.trigger == "breaker_open"
    assert report.opened == 1
    await world.set(cache_ttl_seconds=150)
    assert await world.engine.check_triggers() is None  # too soon after the last triggered run
    world.clock.advance(10)
    report = await world.engine.check_triggers()
    assert report is not None
    assert "settings_change" in report.trigger
    rows = [(int((NOW + 21) * 1000), TEMPLATE, "games.roblox.com", "direct")] * 20
    world.dbs.metrics.write_sync(
        lambda c: c.executemany(
            "INSERT INTO upstream_429 (at_ms, endpoint_template, host, egress) VALUES (?, ?, ?, ?)", rows
        )
    )
    world.clock.advance(10)
    report = await world.engine.check_triggers()
    assert report is not None
    assert report.trigger == "roblox_429_burst"


# --------------------------------------------------------------------------------------------- apply and undo


def three_changes() -> list[ProposedChange]:
    return [
        ProposedChange("setting", key="cache_ttl_seconds", current=120, proposed=150),
        bucket(90),
        ProposedChange(
            "rule_upsert",
            table="rules_cache",
            match={"pattern": TEMPLATE, "type": "glob"},
            current=None,
            proposed={"pattern": TEMPLATE, "type": "glob", "ttl": 300, "stale_ttl": 60, "origin": "recommendation"},
        ),
    ]


async def open_recommendation(world: World, changes: list[ProposedChange], **kw: Any) -> str:
    world.rule.results = [rec(changes=changes, **kw)]
    await world.engine.run_once()
    return next(r[0] for r in reversed(world.rows()) if r[1] == "open")


async def test_apply_and_undo_through_the_audited_services(world: World) -> None:
    rec_id = await open_recommendation(world, three_changes())
    preview = await world.actions.preview(rec_id)
    assert [item.valid for item in preview] == [True, True, True]
    result = await world.actions.apply(rec_id, ADMIN, "fewer calls")
    assert result.recommendation.state == "applied"
    assert len(result.changes) == 3
    assert world.runtime.int("cache_ttl_seconds") == 150
    history = await world.settings.history("cache_ttl_seconds", limit=1)
    assert history[0].source == f"recommendation:{rec_id}"
    limit = await world.rules.get_row("upstream_limits", f"endpoint:{TEMPLATE}")
    assert limit is not None
    assert limit["per_min"] == 90
    assert limit["origin"] == "recommendation"
    rows = await world.rules.list_rows("rules_cache")
    assert [(r["pattern"], r["ttl"], r["origin"]) for r in rows] == [(TEMPLATE, 300, "recommendation")]
    audit = world.dbs.control.read_sync(
        lambda c: [r[0] for r in c.execute("SELECT reason FROM audit_log WHERE reason LIKE 'recommendation:%'")]
    )
    assert len(audit) == 3
    assert all(rec_id in reason for reason in audit)
    watch = world.dbs.metrics.read_sync(lambda c: c.execute("SELECT state FROM recommendation_watches").fetchone())
    assert watch[0] == "watching"
    assert world.events()[-1]["action"] == "apply"
    with pytest.raises(ActionError) as twice:
        await world.actions.apply(rec_id, ADMIN)
    assert twice.value.code == "conflict"
    undone = await world.actions.undo(rec_id, ADMIN, "testing undo")
    assert undone.recommendation.state == "rolled_back"
    assert world.runtime.int("cache_ttl_seconds") == 120
    assert await world.rules.get_row("upstream_limits", f"endpoint:{TEMPLATE}") is None
    assert await world.rules.list_rows("rules_cache") == []
    watch = world.dbs.metrics.read_sync(lambda c: c.execute("SELECT state FROM recommendation_watches").fetchone())
    assert watch[0] == "canceled"


async def test_undo_refuses_when_a_key_was_changed_since(world: World) -> None:
    rec_id = await open_recommendation(world, three_changes())
    await world.actions.apply(rec_id, ADMIN)
    await world.set(cache_ttl_seconds=200)
    with pytest.raises(ActionError) as superseded:
        await world.actions.undo(rec_id, ADMIN)
    assert superseded.value.code == "superseded"
    assert "cache_ttl_seconds" in superseded.value.message
    assert world.runtime.int("cache_ttl_seconds") == 200
    assert await world.rules.get_row("upstream_limits", f"endpoint:{TEMPLATE}") is not None  # nothing reverted


async def test_a_failed_change_rolls_the_others_back(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    rec_id = await open_recommendation(world, three_changes())

    async def refuse(*args: Any, **kwargs: Any) -> Any:
        raise RuleConflict("rules_cache", "That cache rule already exists")

    monkeypatch.setattr(world.rules, "create", refuse)
    with pytest.raises(ActionError) as failed:
        await world.actions.apply(rec_id, ADMIN)
    assert failed.value.code == "invalid"
    assert world.runtime.int("cache_ttl_seconds") == 120
    assert await world.rules.get_row("upstream_limits", f"endpoint:{TEMPLATE}") is None
    assert world.rows()[-1][1] == "open"


async def test_preview_marks_invalid_and_manual_changes(world: World) -> None:
    rec_id = await open_recommendation(
        world, [ProposedChange("setting", key="cache_ttl_seconds", current=120, proposed=-5)]
    )
    (item,) = await world.actions.preview(rec_id)
    assert item.valid is False
    with pytest.raises(ActionError) as invalid:
        await world.actions.apply(rec_id, ADMIN)
    assert invalid.value.code == "invalid"
    manual_id = await open_recommendation(world, [ProposedChange("manual", text="Fix the code")])
    with pytest.raises(ActionError) as manual:
        await world.actions.apply(manual_id, ADMIN)
    assert manual.value.code == "manual"


# ------------------------------------------------------------------------------------------------ auto-apply


def test_guardrails() -> None:
    settings = {"auto_apply_max_step_pct": 50, "cache_error_ttl_seconds": 60, "cache_ttl_seconds": 120}
    assert guardrail_problem(rec(changes=[bucket(90)]), settings) is None
    assert "moves" in str(guardrail_problem(rec(changes=[bucket(30)]), settings))  # a 75% step
    assert "risk" in str(guardrail_problem(rec(risk="medium"), settings))
    assert "not safe" in str(guardrail_problem(rec(safe_auto=False), settings))
    assert "not safe" in str(guardrail_problem(rec(), settings, rule_allows=False))
    wide_ban = ProposedChange(
        "ban_add", table="bans", current=None, proposed={"subject_type": "cidr", "subject": "203.0.113.0/24"}
    )
    assert "more than one address" in str(guardrail_problem(rec(changes=[wide_ban]), settings))
    one_ip = ProposedChange(
        "ban_add", table="bans", current=None, proposed={"subject_type": "cidr", "subject": "203.0.113.7/32"}
    )
    assert guardrail_problem(rec(changes=[one_ip]), settings) is None
    bypass = ProposedChange("bypass_add", table="access_list", proposed={"kind": "bypass", "cidr": "203.0.113.7/32"})
    assert "never" in str(guardrail_problem(rec(changes=[bypass]), settings))
    bounded = ProposedChange("setting", key="cache_error_ttl_seconds", current=60, proposed=80)
    assert guardrail_problem(rec(changes=[bounded]), settings) is None
    too_far = ProposedChange("setting", key="cache_error_ttl_seconds", current=60, proposed=700)
    assert "bounds" in str(guardrail_problem(rec(changes=[too_far]), settings))
    big_step = ProposedChange("setting", key="cache_error_ttl_seconds", current=60, proposed=120)
    assert "moves 100%" in str(guardrail_problem(rec(changes=[big_step]), settings))
    unbounded = ProposedChange("setting", key="cache_ttl_seconds", current=120, proposed=130)
    assert "no auto-apply bounds" in str(guardrail_problem(rec(changes=[unbounded]), settings))
    secret = ProposedChange("setting", key="admin_session_idle_timeout_s", current=1800, proposed=2000)
    assert "never" in str(guardrail_problem(rec(changes=[secret]), settings))
    assert worse({"error_rate": 0.0, "p95_ms": 100}, {"error_rate": 0.2, "p95_ms": 110}, 20) == {
        "error_rate": {"before": 0.0, "after": 0.2, "change_pct": None}
    }
    assert worse({"p95_ms": 100}, {"p95_ms": 130}, 20)["p95_ms"]["change_pct"] == 30.0
    assert worse({"p95_ms": 100}, {"p95_ms": 115}, 20) == {}


def outcome_event(at_ms: int, *, error: bool) -> OutcomeEvent:
    return OutcomeEvent(
        at_ms=at_ms,
        request_id="r",
        endpoint_template=TEMPLATE,
        host="games.roblox.com",
        method="GET",
        egress=Egress.NONE,
        outcome=Outcome.SERVED_CACHE,
        reason=ReasonCode.CACHE_HIT,
        status=200,
        source=Source.CACHE,
        cache_state=CacheState.HIT,
        auth_class=AuthClass.ANON,
        caller_bytes_in=0,
        caller_bytes_out=100,
        upstream_calls=0,
        upstream_bytes_in=0,
        upstream_bytes_out=0,
        latency_ms=5.0,
        queue_wait_ms=0.0,
        upstream_ms=0.0,
        client_ip="203.0.113.9",
        place_id=None,
        user_agent="Roblox/Linux",
        bypass=False,
        error=error,
    )


async def record_traffic(world: World, start: float, minutes: int, *, error_every: int = 0) -> None:
    recorder = MetricsRecorder(world.dbs, world.runtime, world.clock)
    for minute in range(minutes):
        for n in range(20):
            at = int((start + minute * 60) * 1000) + n * 1000
            recorder.record_outcome(outcome_event(at, error=bool(error_every) and n % error_every == 0))
    await recorder.aclose()


class FakeNotifier:
    def __init__(self) -> None:
        self.alerts: list[Any] = []

    def notify(self, alert: Any) -> None:
        self.alerts.append(alert)


async def test_auto_apply_watch_and_rollback(world: World) -> None:
    notifier = FakeNotifier()
    auto = AutoApplier(engine=world.engine, actions=world.actions, notifier=notifier)
    rec_id = await open_recommendation(world, [bucket(90)])
    assert await auto.run() == {"skipped": "auto_apply_off"}
    await world.set(insights_auto_apply=1)
    await record_traffic(world, NOW - 1800, 30)  # the baseline: no errors
    done = await auto.run()
    assert done["applied"] == [rec_id]
    assert done["used_this_hour"] == 1
    assert world.rows()[-1][1] == "auto_applied"
    history = await world.dbs.metrics.read(
        lambda c: [r[0] for r in c.execute("SELECT actor FROM recommendation_actions")]
    )
    assert history == ["auto_apply:insights"]
    await record_traffic(world, NOW, 30, error_every=2)  # half the requests fail after the change
    world.clock.advance(1801)
    report = await auto.watch()
    assert report == {"kept": [], "rolled_back": [rec_id], "rollback_refused": [], "rollback_pending": []}
    assert world.rows()[-1][1] == "rolled_back"
    assert await world.rules.get_row("upstream_limits", f"endpoint:{TEMPLATE}") is None
    assert [a.type for a in notifier.alerts] == ["auto_apply_rollback"]


async def test_auto_apply_keeps_a_harmless_change_and_respects_the_budget(world: World) -> None:
    auto = AutoApplier(engine=world.engine, actions=world.actions)
    await world.set(insights_auto_apply=1, auto_apply_max_per_hour=1)
    await record_traffic(world, NOW - 1800, 30)
    world.rule.results = [rec("a", changes=[bucket(90)]), rec("b", changes=[bucket(100)])]
    await world.engine.run_once()
    done = await auto.run()
    assert len(done["applied"]) == 1
    assert "budget" in next(iter(done["refused"].values()))
    await record_traffic(world, NOW, 30)
    world.clock.advance(1801)
    report = await auto.watch()
    assert report["kept"] == done["applied"]
    assert report["rolled_back"] == []


# ------------------------------------------------------------------------------------------------- simulate


def sample(at_s: float, key: str, body: str | None, method: str = "GET", i: int = 0) -> dict[str, Any]:
    return {
        "id": i,
        "at_ms": int(at_s * 1000),
        "key_id": key,
        "endpoint_template": TEMPLATE,
        "method": method,
        "body_hash": body,
        "egress": "direct",
        "client_hash": "c1",
        "place": "p1",
    }


def test_cache_replay_counts_hits_refreshes_and_staleness() -> None:
    rows = [
        sample(0, "k", "h1"),
        sample(10, "k", "h1"),
        sample(70, "k", "h2"),
        sample(75, "k", "h2"),
        sample(200, "k", "h2"),
    ]
    replay = simulate.cache_replay(rows, ttl_s=60, swr_s=30)
    assert (replay.hits, replay.revalidating, replay.misses) == (2, 1, 2)
    assert replay.upstream_calls == 3
    assert replay.avoided_calls == 2
    assert replay.compared_hits == 3
    assert replay.stale_hits == 1
    uncacheable = simulate.cache_replay(rows, ttl_s=60, cacheable=lambda s: False)
    assert uncacheable.upstream_calls == 5
    assert uncacheable.simulated_hit_ratio is None


def test_ttl_tuner_estimates_and_caps() -> None:
    rows = [sample(t, "k", f"h{int(t // 600)}", i=t) for t in range(0, 3600, 100)]
    estimate = simulate.estimate_change_interval(rows)
    assert estimate.change_interval_s == pytest.approx(600)
    assert simulate.proposed_ttl(estimate, cap_s=3600) == 600
    assert simulate.proposed_ttl(estimate, cap_s=300) == 300
    never = simulate.estimate_change_interval([sample(t, "k", "same", i=t) for t in range(0, 600, 60)])
    assert never.never_changed
    assert simulate.proposed_ttl(never, cap_s=3600) == 3600
    assert simulate.proposed_ttl(simulate.estimate_change_interval([]), cap_s=3600) is None


def test_limit_and_bucket_replay_reuse_the_production_algorithms() -> None:
    arrivals = [(i * 100, "client-a") for i in range(30)] + [(i * 1000, "client-b") for i in range(5)]
    limited = simulate.limit_replay(arrivals, limit=10, window_s=60)
    assert limited.refused == 20
    assert limited.refused_by_key == {"client-a": 20}
    paced = simulate.bucket_replay([0] * 15, per_min=60, burst=10, max_wait_ms=2500)
    assert paced.refused == 3
    assert paced.percentile(1.0) == 2000
    assert (
        simulate.template_pattern("groups.roblox.com/v1/groups/{groupId}/roles")
        == "groups.roblox.com/v1/groups/*/roles"
    )


# ------------------------------------------------------------------------------------------------ anomalies


def test_anomaly_score() -> None:
    steady = [100.0, 102, 98, 101, 99, 100, 103, 97, 100]
    assert anomalies.score([*steady, 101]) is not None
    mean, observed, z = anomalies.score([*steady, 400]) or (0, 0, 0)
    assert observed == 400
    assert z > anomalies.Z_THRESHOLD
    assert mean == pytest.approx(100, abs=1)
    assert anomalies.score([100.0] * 9 + [400]) is None  # a flat baseline cannot score
    assert anomalies.score([1.0, 2.0, 3.0]) is None  # too short


async def test_anomalies_are_detected_and_recorded_once(world: World) -> None:
    await record_traffic(world, NOW - 6 * 3600, 6 * 60 - 15)
    recorder = MetricsRecorder(world.dbs, world.runtime, world.clock)
    for minute in range(15):  # ten times the usual traffic in the last quarter hour
        for n in range(200):
            recorder.record_outcome(outcome_event(int((NOW - 900 + minute * 60) * 1000) + n * 250, error=False))
    await recorder.aclose()
    first = await anomalies.run(world.engine)
    assert "requests" in first["metrics"]
    assert first["written"] >= 1
    again = await anomalies.run(world.engine)
    assert again["written"] == 0
    ctx = world.engine.context()
    assert any(a["metric"] == "requests" for a in await ctx.anomalies(ctx.window(minutes=30, end=NOW + 60)))


# ------------------------------------------------------------------------------------ recorder history hooks


async def test_recorder_history_hooks_and_read_models(world: World) -> None:
    recorder = MetricsRecorder(world.dbs, world.runtime, world.clock)
    now_ms = int(NOW * 1000)
    specs = (BucketSpec("global", 600, 20), BucketSpec(f"endpoint:{TEMPLATE}", 120, 10))
    grant = Grant(now_ms, now_ms, "", ((specs[1].key, 500.0, 0.0, now_ms + 2500.0),))
    recorder.record_reservation(specs, ReserveOutcome(grant=grant))
    recorder.record_reservation(specs, ReserveOutcome(denial=Denial(9000, specs[1].key, "busy")))
    trace = Trace(egress_identity="rotator:abc123")
    trace.start_attempt("direct")
    trace.record_call(egress="direct", kind="rate_limited", status=429, duration_ms=5)
    trace.start_attempt("rotator")
    trace.record_call(egress="rotator", kind="csrf_challenge", status=403, duration_ms=5)
    trace.record_call(egress="rotator", kind="success", status=200, duration_ms=5, csrf_retry=True)
    recorder.record_attempts(TEMPLATE, trace)
    recorder.record_error("KeyError at keys.py:212", module_line="keys.py:212")
    recorder.record_error("KeyError at keys.py:212")
    recorder.record_rule_hit("rules_endpoint_block", 7)
    recorder.record_cache_store(3)
    recorder.record_cache_eviction(age_s=50, ttl_s=300, count=2)
    recorder.record_cache_eviction(age_s=900, ttl_s=300)
    recorder.record_eviction_pass(
        type("Report", (), {"evicted": 3, "entries_before": 10, "bytes_before": 99, "freed_bytes": 9})()
    )
    recorder.record_worker_sample(worker_id="w1", cpu_pct=80, loop_lag_ms_p99=12, open_conns=4, rss=1000)
    recorder.record_worker_sample(worker_id="w1", cpu_pct=90, loop_lag_ms_p99=30)
    recorder.record_internal_call(
        "credential_probe",
        ok=True,
        status=200,
        egress=Egress.CREDENTIAL,
        endpoint_template="users.roblox.com/v1/users/authenticated",
        trigger="scheduled",
    )
    await recorder.aclose()
    start, end = int(NOW) - 60, int(NOW) + 60
    read = world.dbs.metrics.read_sync
    buckets = read(lambda c: read_history.bucket_summary(c, start, end))
    assert buckets[specs[1].key] == {"attempts": 2, "rejections": 1, "fill_pct_peak": 100.0, "minutes": 1}
    assert buckets["global"]["rejections"] == 0
    kinds = sorted(
        (a["kind"], a["status"], a["exit_id"]) for a in read(lambda c: read_history.attempt_rows(c, start, end))
    )
    assert kinds == [("csrf_retry", 200, "abc123"), ("fallback_429", 403, "abc123"), ("first", 429, "")]
    assert read(lambda c: read_history.error_counts(c, start, end)) == {"KeyError at keys.py:212": 2}
    hits = read(lambda c: read_history.rule_hits(c, "rules_endpoint_block"))
    assert hits[("rules_endpoint_block", "7")]["hits"] == 1
    cache = read(lambda c: read_history.cache_summary(c, start, end))
    assert (cache["stores"], cache["evictions"], cache["young_evictions"]) == (3, 3, 2)
    assert read(lambda c: read_history.eviction_passes(c, start, end))[0]["evicted"] == 3
    worker = read(lambda c: read_history.worker_history(c, start, end))["w1"][0]
    assert worker["cpu_pct"] == 85
    assert worker["loop_lag_ms_p99"] == 30
    assert worker["open_conns"] == 4
    (probe,) = read(lambda c: read_history.events_between(c, ["internal_call"], start, end))
    assert probe["detail"]["trigger"] == "scheduled"
    assert probe["detail"]["egress"] == "credential"
    deleted = world.dbs.metrics.write_sync(
        lambda c: read_history.prune_history(c, NOW + 30 * 86_400, {"bucket_minute": 14, "error_minute": 8})
    )
    assert deleted["bucket_minute"] == 2
    assert deleted["error_minute"] == 1


# --------------------------------------------------------------------------------------------- the context


async def test_context_reads_limits_rules_and_settings(world: World) -> None:
    ctx = world.engine.context()
    assert ctx.bucket_limit(f"endpoint:{TEMPLATE}") == {
        "per_min": 120.0,
        "burst": 10,
        "overridden": False,
        "origin": "default",
    }
    await world.rules.upsert(
        "upstream_limits", {"bucket_key": f"endpoint:{TEMPLATE}", "per_min": 60, "burst": 5}, ADMIN
    )
    await world.rules.create("rules_cache", {"pattern": TEMPLATE, "ttl": 300, "methods": ["GET"]}, ADMIN)
    ctx = world.engine.context()
    assert ctx.bucket_limit(f"endpoint:{TEMPLATE}")["per_min"] == 60
    assert ctx.cache_rule_for(TEMPLATE) is not None
    assert ctx.cache_rule_for(TEMPLATE, "POST") is None
    window = ctx.window(minutes=60)
    assert (window.start, window.end) == (int(NOW) - 3600, int(NOW))
    with pytest.raises(KeyError):
        ctx.setting("no_such_setting")
    changes = await ctx.recent_changes(NOW - 60)
    assert {c["kind"] for c in changes} == {"rule"}
    assert await ctx.providers.disk() is None
    assert InsightProviders().classify_address("10.0.0.1") == "private"


def test_models_round_trip_and_validate() -> None:
    original = rec("a", changes=three_changes())
    original.id, original.fingerprint = "rec_1", make_fingerprint("UP-5XX", "a")
    copy_back = Recommendation.from_payload(json.loads(json.dumps(original.to_payload())))
    assert copy_back.to_payload() == original.to_payload()
    with pytest.raises(ValueError):
        ProposedChange("delete_everything")
    with pytest.raises(ValueError):
        Recommendation(rule_id="X", family="f", subject="s", title="t", severity="loud")


async def test_register_jobs_wires_the_leader_jobs(world: World) -> None:
    registry = JobRegistry()
    auto = AutoApplier(engine=world.engine, actions=world.actions)
    register_jobs(registry, world.engine, actions=world.actions, auto=auto)
    names = {job.name for job in registry.all()}
    assert names == {
        "insights_evaluate",
        "insights_triggers",
        "insights_history_prune",
        "insights_anomalies",
        "insights_watch",
        "insights_auto_apply",
    }
    assert registry.get("insights_evaluate").interval() == 30
    world.rule.results = [rec("a")]
    result = await registry.get("insights_evaluate").fn(JobContext(epoch=0, now=NOW))
    assert result["opened"] == 1
    await world.set(insights_enabled=0)
    assert registry.get("insights_evaluate").interval() == 0  # a non-positive interval turns the job off
