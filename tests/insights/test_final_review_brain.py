"""Final review, brain fixer: regression tests of the insights side of findings brain-1 to brain-4 and data-2.

What this is
    Unit and small integration tests of the pieces the fixes added: the bucket change gate of UP-BUCKET-TUNE's "too
    loose" branch (brain-1; the "too tight" branch is pinned by the reproduction in `tests/review_final/`), the undo's
    high-risk confirmation and the caller's check and guard (brain-2), the step measured for a NEW cache rule from
    the lifetime in force (brain-3), the watch window verdict (brain-4) and the data reset markers a rule reads
    (data-2: `InsightContext.data_reset_at`).

Why it exists
    The reproductions in `tests/review_final/` drive whole flows (the D7 auto-applier over a fixture, the admin API);
    these pin the contracts underneath them, so a later change to one helper fails here with a precise message.

How it works
    The same worlds as the neighboring suites: `test_r3_insights_autoapply.py`'s engine, actions and auto-applier over
    the root conftest's temporary databases and a `FakeClock`, and a committed insights fixture loaded through
    `tests/insights/harness.py` (closed by the test itself).

What to read next
    `roxy/insights/autoapply.py`, `roxy/insights/actions.py`, `roxy/insights/models.py` (`watch_verdict`),
    `roxy/insights/context.py` (`data_reset_at`), `roxy/insights/rules/upstream.py` (`bucket_changed_at`).
"""

# ruff: noqa: F811  (the imported pytest fixture is the tests' parameter)

from __future__ import annotations

from typing import Any

import pytest

from insights.test_r3_insights_autoapply import (  # noqa: F401  (the `world` fixture)
    ADMIN,
    NOW,
    TEMPLATE,
    World,
    rec,
    record_traffic,
    world,
)
from roxy.config.settings_service import SettingsService
from roxy.insights import simulate
from roxy.insights.actions import (
    GUARD_METRICS,
    UNDO_CONFIRM_MESSAGE,
    ActionError,
    AppliedChange,
    RecommendationActions,
    high_risk_restores,
    setting_restores,
)
from roxy.insights.autoapply import AutoApplier, guardrail_problem, in_force_values
from roxy.insights.engine import InsightsEngine
from roxy.insights.models import WATCH_VERDICTS, ProposedChange, watch_verdict
from roxy.insights.read_recommendations import GUARD_ORDER, watch_of
from roxy.insights.rules import load_rules
from roxy.insights.rules.cache import new_rule
from roxy.metrics.annotate import insert_annotation
from roxy.rules.service import RulesService
from roxy.rules.store import RulesStore


def _setting_change(key: str, current: Any, proposed: Any) -> ProposedChange:
    return ProposedChange("setting", key=key, current=current, proposed=proposed)


# ------------------------------------------------------------------------------------------------ brain-1


async def test_up_bucket_tune_never_cuts_twice_on_the_429s_of_one_episode() -> None:
    """The "too loose" branch counts only the 429s drawn at the bucket's current rate: once a cut is applied, the
    429s that justified it are still in the hour the rule reads when a short watch window ends, and must not cut
    the bucket again (200 -> 140, never -> 98 on the same six 429s)."""
    from insights import harness as insight_harness

    state = await insight_harness.load("up_bucket_tune__too_loose_endpoint")
    try:
        store = RulesStore(state.dbs.control, clock=state.clock)
        await store.reload()
        engine = InsightsEngine(
            dbs=state.dbs,
            settings=state.runtime,
            rules=store,
            clock=state.clock,
            providers=state.providers,
            rule_set={"UP-BUCKET-TUNE": load_rules()["UP-BUCKET-TUNE"]},
        )
        settings = SettingsService(state.dbs.control, runtime=state.runtime, clock=state.clock)
        rules = RulesService(state.dbs.control, clock=state.clock, store=store)
        actions = RecommendationActions(
            engine=engine, settings_service=settings, rules_service=rules, clock=state.clock
        )
        await settings.update({"insights_auto_apply": 1, "auto_apply_watch_minutes": 5}, ADMIN, "D7 on, short watch")
        auto = AutoApplier(engine=engine, actions=actions, notifier=None, clock=state.clock)
        key = "endpoint:users.roblox.com/v1/usernames/users"

        await engine.run_once(now=state.now)
        first = await auto.run(now=state.now)
        assert len(first["applied"]) == 1, first
        assert (await rules.get_row("upstream_limits", key))["per_min"] == 140  # the fixture's 200 cut by 30%

        later = state.now + 6 * 60  # the 429s (30 to 40 minutes before the cut) are still inside the hour
        state.clock.set(later)
        await engine.run_once(now=later)
        await auto.run(now=later)
        open_cards = [r for r in await engine.list(states=("open",)) if r.subject == key]
        assert (await rules.get_row("upstream_limits", key))["per_min"] == 140, "cut again on the same 429s"
        assert open_cards == [], [(r.title, r.state) for r in open_cards]
    finally:
        state.close()


# ------------------------------------------------------------------------------------------------ brain-2


def test_setting_restores_name_what_an_undo_writes_back() -> None:
    applied = [
        AppliedChange("setting", "setting:spam_dry_run", None, "spam_dry_run", 0, 1, 7),
        AppliedChange("setting", "setting:cache_error_ttl_seconds", None, "cache_error_ttl_seconds", 60, 60, None),
        AppliedChange("bucket_override", "upstream_limits:endpoint:x", "upstream_limits", "endpoint:x", None, {}),
    ]
    # The second apply found its value already in place (no history row): its undo writes nothing.
    assert setting_restores(applied) == {"spam_dry_run": 0}
    assert high_risk_restores(applied) == ["spam_dry_run"]  # a Risk.HIGH setting; 0 also arms the detectors


async def test_an_undo_that_puts_back_a_high_risk_value_needs_a_confirmation_and_a_reason(world: World) -> None:
    await world.set(spam_dry_run=0)  # armed earlier (through the arm route, in the real app)
    rec_id = await world.open([_setting_change("spam_dry_run", 0, 1)])
    await world.actions.apply(rec_id, ADMIN, "back to dry run")
    await world.runtime.reload()
    assert world.runtime.int("spam_dry_run") == 1
    for confirmed, reason in ((False, ""), (True, ""), (False, "why")):
        with pytest.raises(ActionError) as refused:
            await world.actions.undo(rec_id, ADMIN, reason, confirm_high_risk=confirmed)
        assert refused.value.code == "confirm"
        assert refused.value.message == UNDO_CONFIRM_MESSAGE
        assert set(refused.value.fields) == {"spam_dry_run"}
    await world.runtime.reload()
    assert world.runtime.int("spam_dry_run") == 1  # nothing was written
    assert world.state_of(rec_id) == "applied"
    # Confirmed with a reason, the actions put the value back (refusing to arm is the settings API's guard).
    await world.actions.undo(rec_id, ADMIN, "confirmed by the owner", confirm_high_risk=True)
    await world.runtime.reload()
    assert world.runtime.int("spam_dry_run") == 0
    assert world.state_of(rec_id) == "rolled_back"


async def test_an_undo_runs_the_callers_check_first_and_its_guard_in_the_write(world: World) -> None:
    rec_id = await world.open([_setting_change("cache_error_ttl_seconds", 60, 80)])
    await world.actions.apply(rec_id, ADMIN, "longer error lifetime")
    seen: list[dict[str, Any]] = []

    def refuse(applied: Any) -> None:
        seen.append(setting_restores(applied))
        raise RuntimeError("the caller refuses this undo")

    with pytest.raises(RuntimeError):
        await world.actions.undo(rec_id, ADMIN, "", check=refuse)
    assert seen == [{"cache_error_ttl_seconds": 60}]
    await world.runtime.reload()
    assert world.runtime.int("cache_error_ttl_seconds") == 80  # the check ran before any write
    assert world.state_of(rec_id) == "applied"

    judged: list[dict[str, Any]] = []
    await world.actions.undo(rec_id, ADMIN, "", guard=lambda pending: judged.append(dict(pending.dirty)))
    assert judged == [{"cache_error_ttl_seconds": (80, 60)}]
    await world.runtime.reload()
    assert world.runtime.int("cache_error_ttl_seconds") == 60


# ------------------------------------------------------------------------------------------------ brain-3


def test_a_new_rule_row_is_stepped_from_the_value_in_force() -> None:
    settings = {"auto_apply_max_step_pct": 50}
    card = rec([new_rule(TEMPLATE, {"ttl": 150})])
    # No idea what is in force: refused rather than judged with no step at all.
    assert "cannot be compared with the value in force" in str(guardrail_problem(card, settings))
    assert guardrail_problem(card, settings, in_force=lambda r, c: {"ttl": 120}) is None  # +25%
    far = rec([new_rule(TEMPLATE, {"ttl": 3600})])
    assert "moves 2900%" in str(guardrail_problem(far, settings, in_force=lambda r, c: {"ttl": 120}))
    uncached = guardrail_problem(card, settings, in_force=lambda r, c: {"ttl": 0})
    assert "moves from 0" in str(uncached)


async def test_the_value_in_force_is_the_lifetime_the_cache_gives_the_endpoint(world: World) -> None:
    ctx = world.engine.context(NOW)
    card = rec([new_rule(TEMPLATE, {"ttl": 150})])
    covering = ctx.cache_rule_for(TEMPLATE, "GET")
    expected = int(covering.ttl) if covering is not None else int(ctx.setting("cache_ttl_seconds"))
    assert in_force_values(ctx, card, card.changes[0]) == {"ttl": expected}
    # A v1 glob that names the card's own template reads the same lifetime; a pattern naming no endpoint, nothing.
    glob = ProposedChange(
        "rule_upsert",
        table="rules_cache",
        match={"pattern": simulate.template_pattern(TEMPLATE), "type": "glob"},
        proposed={"pattern": simulate.template_pattern(TEMPLATE), "type": "glob", "ttl": 150},
    )
    assert in_force_values(ctx, card, glob) == {"ttl": expected}
    wide = ProposedChange("rule_upsert", table="rules_cache", match={"pattern": "games.roblox.com/*", "type": "glob"})
    assert in_force_values(ctx, card, wide) is None
    # An update of an existing row and other tables are judged from the change's own `current`.
    update = ProposedChange("rule_upsert", table="rules_cache", match={"pattern": "x", "type": "glob"}, current={})
    assert in_force_values(ctx, card, update) is None
    await world.set(cache_enabled=0)
    await world.runtime.reload()
    assert in_force_values(world.engine.context(NOW), card, card.changes[0]) == {"ttl": 0}


def test_template_of_match_reads_back_an_exact_pattern_only() -> None:
    template = "games.roblox.com/v1/games/{universeId}/votes"
    match = simulate.template_match(template)
    found = simulate.template_of_match(match)
    assert found is not None
    assert simulate.exact_template_pattern(found) == match["pattern"]
    assert simulate.template_of_match({"pattern": "games.roblox.com/v1/games/*", "type": "glob"}) is None
    assert simulate.template_of_match({"pattern": "^games\\.roblox\\.com/.*$", "type": "regex"}) is None


# ------------------------------------------------------------------------------------------------ brain-4


def test_watch_verdicts_never_read_a_regression_as_within_bounds() -> None:
    worse = {"worse": {"error_rate": {"before": 0.0, "after": 0.5, "change_pct": None}}}
    assert watch_verdict("kept", {"worse": {}}) == "within_bounds"
    assert watch_verdict("kept", worse, "applied") == "worse_applied_by_hand"
    assert watch_verdict("kept", worse, "rolled_back") == "worse_kept"
    assert watch_verdict("kept", {**worse, "rollback_refused": "changed again"}) == "worse_rollback_refused"
    assert watch_verdict("kept", {**worse, "verdict": "worse_applied_by_hand"}) == "worse_applied_by_hand"
    for state in ("watching", "rolled_back", "canceled"):
        assert watch_verdict(state, worse) == state
    assert set(WATCH_VERDICTS) >= {"within_bounds", "worse_applied_by_hand", "worse_rollback_refused"}
    assert list(GUARD_ORDER) == list(GUARD_METRICS)  # the read model lists the guard metrics in their order


@pytest.mark.parametrize(("error_every", "verdict"), [(0, "within_bounds"), (2, "worse_applied_by_hand")])
async def test_a_watch_of_a_change_applied_by_hand_records_what_it_found(
    world: World, error_every: int, verdict: str
) -> None:
    await record_traffic(world, NOW - 1800, 30)  # the baseline: no errors
    rec_id = await world.open([_setting_change("cache_error_ttl_seconds", 60, 80)])
    await world.actions.apply(rec_id, ADMIN, "by hand")
    await record_traffic(world, NOW, 30, error_every=error_every)
    world.clock.advance(1801)
    report = await world.auto.watch()
    assert report["kept"] == [rec_id]  # plan 11.4: a change applied by hand is never rolled back automatically
    found = world.dbs.metrics.read_sync(lambda c: watch_of(c, rec_id))
    assert found is not None
    assert found["state"] == "kept"
    assert found["verdict"] == verdict
    if error_every:
        assert [row["metric"] for row in found["worse"]] == ["error_rate"]
        assert found["worse"][0]["before"] == 0.0
    else:
        assert found["worse"] == []


# ------------------------------------------------------------------------------------------------ data-2


async def test_data_reset_at_reads_the_newest_reset_of_the_named_tables(world: World) -> None:
    def write(conn: Any) -> None:
        insert_annotation(conn, int(NOW - 7200), "reset", "statistics", None, tables=["metrics.rule_hits"])
        insert_annotation(conn, int(NOW - 600), "reset", "cache", None, tables=["metrics.cache_minute"])
        insert_annotation(
            conn, int(NOW - 9000), "reset", "range", None, until=int(NOW - 3600), tables=["metrics.rollup_hour"]
        )
        insert_annotation(conn, int(NOW - 300), "config_change", "a setting", None)

    await world.dbs.metrics.write(write)
    ctx = world.engine.context(NOW)
    assert await ctx.data_reset_at(("metrics.rule_hits",), NOW - 86_400) == NOW - 7200
    assert await ctx.data_reset_at(("metrics.rule_hits",), NOW - 3600) is None  # older than `since`
    assert await ctx.data_reset_at(("metrics.rollup_hour",), NOW - 86_400) == NOW - 3600  # a range ends at until
    assert await ctx.data_reset_at(("metrics.rollup_day",), NOW - 86_400) is None  # another family's reset
