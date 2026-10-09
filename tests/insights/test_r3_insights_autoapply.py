"""Review round 3, lens insights: apply on stale data, the D7 auto-apply guardrails and the automatic rollback.

What this is
    Adversarial tests (strict xfails, one per finding) of `roxy/insights/autoapply.py` and
    `roxy/insights/actions.py` over real temporary databases, a fake clock and a test rule whose output each test
    sets (the same setup as `tests/insights/test_engine.py`): auto-apply after the admin switched the rule off,
    auto-apply of a recommendation whose stored `current` is stale, an automatic rollback that cannot happen, and
    a manual apply of a `host_add` card after the admin edited the host list.

Why it exists
    Plan 11.4 (D7): auto-apply moves a value at most `auto_apply_max_step_pct` per change, and a change that makes a
    guard metric worse is rolled back and the admin is notified. Plan 11.1: `insight_<rule_id>_enabled` is the
    rule's off switch. Plan 11.2: `host_add` "adds to `allowed_roblox_hosts`". An unattended 3 a.m. change, or a
    one-click one, must never be bigger, or less visible, than these promise.

How it works
    Each test opens a recommendation through the engine's real `run_once`, changes the world the way an admin or
    the passing time would (a setting, a bucket override row edited through `RulesService`, guard metrics recorded
    through `MetricsRecorder`), then runs `AutoApplier.run` or `AutoApplier.watch` and checks what was written.

What to read next
    `roxy/insights/autoapply.py`, `roxy/insights/actions.py`, `tests/insights/test_engine.py`.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

import pytest

from roxy.config.audit import Actor
from roxy.config.runtime import RuntimeSettings, load_runtime_settings
from roxy.config.settings_service import SettingsService
from roxy.core.clock import FakeClock
from roxy.core.reasons import AuthClass, CacheState, Egress, Outcome, ReasonCode, Source
from roxy.insights.actions import RecommendationActions
from roxy.insights.autoapply import AutoApplier
from roxy.insights.context import InsightContext
from roxy.insights.engine import InsightsEngine
from roxy.insights.models import Evidence, ProposedChange, Recommendation
from roxy.insights.rules.base import Rule
from roxy.metrics.recorder import MetricsRecorder, OutcomeEvent
from roxy.rules.service import RulesService
from roxy.rules.store import RulesStore

NOW = 1_791_385_200.0  # 2026-10-07T15:00:00Z
ADMIN = Actor("admin", "tester", "203.0.113.5")
TEMPLATE = "games.roblox.com/v1/games"
BUCKET_KEY = f"endpoint:{TEMPLATE}"


class SafeRule(Rule):
    """A test rule (catalog id UP-5XX, so its switch is `insight_up_5xx_enabled`) that allows auto-apply."""

    id = "UP-5XX"
    safe_auto = True

    def __init__(self) -> None:
        self.results: list[Recommendation] = []

    def minimum_evidence(self, ctx: InsightContext) -> int:
        return 1

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        return [copy.deepcopy(rec) for rec in self.results]


def bucket(per_min: float, current: float = 120.0) -> ProposedChange:
    return ProposedChange(
        "bucket_override",
        bucket_key=BUCKET_KEY,
        current={"per_min": current, "burst": 10},
        proposed={"per_min": per_min, "burst": 10},
    )


def rec(changes: list[ProposedChange]) -> Recommendation:
    return Recommendation(
        rule_id="UP-5XX",
        family="upstream",
        subject=TEMPLATE,
        title=f"Test recommendation for {TEMPLATE}",
        severity="warn",
        evidence=Evidence(sample_size=5).add("calls", 5),
        changes=changes,
        safe_auto=True,
        risk="low",
    )


class FakeNotifier:
    def __init__(self) -> None:
        self.alerts: list[Any] = []

    def notify(self, alert: Any) -> None:
        self.alerts.append(alert)


@dataclass
class World:
    dbs: Any
    clock: FakeClock
    runtime: RuntimeSettings
    rule: SafeRule
    engine: InsightsEngine
    settings: SettingsService
    rules: RulesService
    actions: RecommendationActions
    notifier: FakeNotifier
    auto: AutoApplier

    async def set(self, **values: Any) -> None:
        await self.settings.update(values, ADMIN, "test setup")

    async def open(self, changes: list[ProposedChange]) -> str:
        self.rule.results = [rec(changes)]
        await self.engine.run_once()
        found = await self.engine.list(states=("open",))
        assert len(found) == 1
        return found[0].id

    def state_of(self, rec_id: str) -> str:
        row = self.dbs.metrics.read_sync(
            lambda c: c.execute("SELECT state FROM recommendations WHERE id = ?", (rec_id,)).fetchone()
        )
        return str(row[0])


@pytest.fixture
async def world(dbs: Any) -> World:
    clock = FakeClock(NOW)
    runtime = await load_runtime_settings(dbs, clock)
    store = RulesStore(dbs.control, clock=clock)
    await store.reload()
    rule = SafeRule()
    engine = InsightsEngine(dbs=dbs, settings=runtime, rules=store, clock=clock, rule_set={rule.id: rule})
    settings = SettingsService(dbs.control, runtime=runtime, clock=clock)
    rules = RulesService(dbs.control, clock=clock, store=store)
    actions = RecommendationActions(engine=engine, settings_service=settings, rules_service=rules, clock=clock)
    notifier = FakeNotifier()
    auto = AutoApplier(engine=engine, actions=actions, notifier=notifier, clock=clock)
    return World(dbs, clock, runtime, rule, engine, settings, rules, actions, notifier, auto)


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


# --------------------------------------------------------------------------------------------- the findings


@pytest.mark.xfail(
    strict=True,
    reason="finding insights-3: auto-apply applies open recommendations of a rule the admin switched off",
)
async def test_r3_insights_auto_apply_respects_the_rules_off_switch(world: World) -> None:
    rec_id = await world.open([bucket(100)])
    # The admin distrusts this rule and switches it off; its open card stays listed until it expires (engine
    # lifecycle), but nothing may act on its behalf any more.
    await world.set(insights_auto_apply=1, insight_up_5xx_enabled=0)
    done = await world.auto.run()
    assert done.get("applied") == [], f"auto-applied a switched-off rule's recommendation: {done}"
    assert await world.rules.get_row("upstream_limits", BUCKET_KEY) is None
    assert world.state_of(rec_id) == "open"


@pytest.mark.xfail(
    strict=True,
    reason="finding insights-4: the auto-apply step guardrail judges a bucket against the card's stale current",
)
async def test_r3_insights_auto_apply_step_limit_uses_the_live_value(world: World) -> None:
    await world.open([bucket(100, current=120)])  # 120 -> 100 is a 17% step: allowed at 50%
    await world.set(insights_auto_apply=1)
    # Between the leader's evaluation and the auto-apply job, an admin tightens this bucket by hand.
    await world.rules.create(
        "upstream_limits",
        {"bucket_key": BUCKET_KEY, "per_min": 40, "burst": 10, "origin": "admin"},
        ADMIN,
        "tighten it during an incident",
    )
    done = await world.auto.run()
    row = await world.rules.get_row("upstream_limits", BUCKET_KEY)
    assert row is not None
    # 40 -> 100 is a 150% move, three times auto_apply_max_step_pct (50): D7 forbids it.
    assert row["per_min"] == 40, f"auto-apply moved the live bucket 40 -> {row['per_min']} ({done})"


@pytest.mark.xfail(
    strict=True,
    reason="finding insights-5: a guard regression whose automatic rollback is refused is closed as kept, no alert",
)
async def test_r3_insights_failed_automatic_rollback_reaches_the_admin(world: World) -> None:
    rec_id = await world.open([bucket(90)])
    await world.set(insights_auto_apply=1)
    await record_traffic(world, NOW - 1800, 30)  # the baseline: no errors
    done = await world.auto.run()
    assert done["applied"] == [rec_id]
    # During the watch window an admin adjusts the auto-applied row (here only its burst), so the stored
    # after-row no longer matches and the undo is refused as superseded.
    await world.rules.update("upstream_limits", BUCKET_KEY, {"burst": 12}, ADMIN, "a little more burst")
    await record_traffic(world, NOW, 30, error_every=2)  # half the requests fail after the change
    world.clock.advance(1801)
    report = await world.auto.watch()
    assert report == {"kept": [rec_id], "rolled_back": []}  # the precondition: the rollback was refused
    watch = world.dbs.metrics.read_sync(
        lambda c: c.execute("SELECT state, result_json FROM recommendation_watches").fetchone()
    )
    assert "rollback_refused" in str(watch[1])
    assert world.notifier.alerts, (
        "an auto-applied change made a guard metric worse and could not be rolled back, yet no alert was sent "
        f"(watch closed as {watch[0]!r})"
    )


# ------------------------------------------------------------------------------------------- checked clean


async def test_r3_insights_double_apply_and_undo_are_refused(world: World) -> None:
    """Checked clean: a second apply of an applied card and a second undo are both refused, and the undo puts
    back exactly the before value (no override row left behind)."""
    rec_id = await world.open([bucket(90)])
    await world.actions.apply(rec_id, ADMIN, "first")
    from roxy.insights.actions import ActionError

    with pytest.raises(ActionError):
        await world.actions.apply(rec_id, ADMIN, "second")
    await world.actions.undo(rec_id, ADMIN, "back")
    with pytest.raises(ActionError):
        await world.actions.undo(rec_id, ADMIN, "again")
    assert await world.rules.get_row("upstream_limits", BUCKET_KEY) is None


async def test_r3_insights_undo_works_from_stored_details_after_a_restart(world: World) -> None:
    """Checked clean: a fresh `RecommendationActions` (a restarted worker) undoes from the stored action row,
    including an existing admin row that the apply had updated (restored column for column)."""
    await world.rules.create(
        "upstream_limits", {"bucket_key": BUCKET_KEY, "per_min": 120, "burst": 7, "origin": "admin"}, ADMIN, "mine"
    )
    before = await world.rules.get_row("upstream_limits", BUCKET_KEY)
    rec_id = await world.open([bucket(90)])
    await world.actions.apply(rec_id, ADMIN, "apply")
    fresh = RecommendationActions(
        engine=world.engine, settings_service=world.settings, rules_service=world.rules, clock=world.clock
    )
    await fresh.undo(rec_id, ADMIN, "after a restart")
    after = await world.rules.get_row("upstream_limits", BUCKET_KEY)
    skip = {"updated_at", "updated_by", "created_at", "created_by"}
    assert after is not None
    assert before is not None
    assert {k: v for k, v in after.items() if k not in skip} == {k: v for k, v in before.items() if k not in skip}


@pytest.mark.xfail(
    strict=True,
    reason="finding insights-13: applying a host_add card writes its stale full host list over the admin's edit",
)
async def test_r3_insights_host_add_adds_one_host_to_the_live_list(world: World) -> None:
    hosts = list(world.runtime.list("allowed_roblox_hosts"))
    assert "develop.roblox.com" in hosts
    # HOST-ADD's card: `current` and `proposed` are the whole list as it was when the leader evaluated.
    card = ProposedChange("host_add", key="allowed_roblox_hosts", current=hosts, proposed=[*hosts, "new.roblox.com"])
    rec_id = await world.open([card])
    # Before the next evaluation the admin removes a host (it was being abused) ...
    await world.set(allowed_roblox_hosts=[h for h in hosts if h != "develop.roblox.com"])
    # ... and then clicks Apply on the "add new.roblox.com" card.
    await world.actions.apply(rec_id, ADMIN, "add the missing host")
    live = list(world.runtime.list("allowed_roblox_hosts"))
    assert "new.roblox.com" in live
    assert "develop.roblox.com" not in live, "the apply put back a host the admin had removed"
