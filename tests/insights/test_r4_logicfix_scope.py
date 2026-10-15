"""Review round 4, lens logicfix: "scoped to one endpoint" (plan 11.2 `safe_auto`) for a template's own legacy rule.

What this is
    An adversarial test of the insights-8 fix (`simulate.endpoint_scoped`, `template_match`, `own_template_row`). The
    fix makes a NEW rule for one template an anchored regex, but a change that UPDATES the template's own row still
    counted as scoped whatever that row covers. The own row is found by `names_template`, which also accepts the v1
    glob of the template, and a v1 glob covers every path below it (`rules/match.py`). This was a strict xfail for
    finding LOGICFIX-2; `simulate.endpoint_scoped` now judges every change to a pattern rule row (new, updated or
    deleted) by whether the row names exactly one template, and the engine says on the card why it is not
    auto-applied (`simulate.WIDE_PATTERN_NOTE`).

Why it exists
    Plan 11.2: `safe_auto` means "scoped to one endpoint", and D7 applies such a card unattended. Every cache rule the
    migrator imports from v1 is a glob, so on the first day after cutover the template's own row of a v1 rule is a
    subtree rule: CACHE-TTL-TUNE (safe_auto, risk low) then proposes a longer TTL for that row from the refetches of
    ONE template, and the change also lengthens the TTL of every sibling endpoint below it, which the evidence never
    looked at (the defect insights-8 described, through the update path).

How it works
    A v1 style glob row for `users.roblox.com/v1/users` is stored through the real `RulesService`. The real
    `CacheTtlTune._change` builds the TTL change for that template (an update of its own row), the engine's own
    `_finalize` judges `safe_auto`, and `autoapply.guardrail_problem` judges it auto-appliable. The cache's own
    `select_rule` shows the same row answers a sibling endpoint.

What to read next
    `roxy/insights/simulate.py` (`endpoint_scoped`, `names_template`), `roxy/insights/rules/core.py`
    (`own_cache_rule`, `CacheTtlTune._change`), `roxy/insights/engine.py` (`_finalize`).
"""

from __future__ import annotations

from typing import Any

from roxy.cache.policy import select_rule
from roxy.config.audit import Actor
from roxy.config.runtime import load_runtime_settings
from roxy.core.clock import FakeClock
from roxy.insights import simulate
from roxy.insights.autoapply import guardrail_problem
from roxy.insights.engine import InsightsEngine
from roxy.insights.models import Evidence, Recommendation
from roxy.insights.rules.core import CacheTtlTune
from roxy.rules.service import RulesService
from roxy.rules.store import RulesStore, build_rules_snapshot

ADMIN = Actor("admin", "r4-logicfix")
NOW = 1_791_385_200.0  # 2026-10-07T15:00:00Z
TEMPLATE = "users.roblox.com/v1/users"
SIBLING = "users.roblox.com/v1/users/156/username-history"


async def test_r4_logicfix_a_ttl_card_for_a_legacy_glob_row_is_not_scoped_to_one_endpoint(dbs: Any) -> None:
    clock = FakeClock(NOW)
    store = RulesStore(dbs.control, clock=clock)
    await store.reload()
    service = RulesService(dbs.control, clock=clock, store=store)
    # The row the migrator writes for a v1 cache rule (v1 rules are globs; scripts/migrate_from_v1.py).
    await service.create(
        "rules_cache", {"pattern": TEMPLATE, "type": "glob", "ttl": 300, "methods": "GET"}, ADMIN, "v1 import"
    )
    await store.reload()
    runtime = await load_runtime_settings(dbs, clock)
    rule = CacheTtlTune()
    engine = InsightsEngine(dbs=dbs, settings=runtime, rules=store, clock=clock, rule_set={rule.id: rule})
    ctx = engine.context(NOW)
    change = rule._change(ctx, TEMPLATE, 400)  # the refetches of TEMPLATE say its bodies last longer than 300 s
    assert change.current is not None, change  # an update of the template's own row
    assert change.match == {"pattern": TEMPLATE, "type": "glob"}, change
    # The card exactly as `CacheTtlTune._raise` builds it (through the rule's own `recommendation` helper).
    card: Recommendation = rule.recommendation(
        ctx,
        subject=TEMPLATE,
        title=f"Cache {TEMPLATE} longer: 300 s to 400 s",
        severity="info",
        confidence="high",
        explanation="Most refetches returned the same body.",
        evidence=Evidence(sample_size=10_000),
        changes=[change],
        expected_impact=f"Fewer refetches of {TEMPLATE}.",
        risk="low",
    )
    [judged], _held = engine._finalize(rule, ctx, [card])
    snapshot = dbs.control.read_sync(lambda conn: build_rules_snapshot(conn, NOW))
    sibling_rule = select_rule(snapshot, SIBLING, "GET", False)
    # The precondition: the row the change updates is the rule the cache uses for the sibling endpoint too.
    assert sibling_rule is not None
    assert sibling_rule.pattern == TEMPLATE, sibling_rule
    judged.updated_at = NOW  # `persist` stamps the card at the evaluation that produced it
    auto = guardrail_problem(judged, ctx.settings, rule_allows=rule.safe_auto, rule_enabled=True, now=NOW)
    # Plan 11.2: a change that also retimes SIBLING is not "scoped to one endpoint", so it is never safe_auto.
    assert not simulate.endpoint_scoped(change), (
        f"the TTL change of the {TEMPLATE} glob row reads as scoped to one endpoint, yet it also sets the TTL of "
        f"{SIBLING}; safe_auto={judged.safe_auto}, auto-apply guardrail problem: {auto!r}"
    )
    assert not judged.safe_auto
    assert auto is not None  # D7 never applies it
    assert simulate.WIDE_PATTERN_NOTE in judged.explanation  # and the card says why
    # The template's own EXACT row (what a recommendation writes since insights-8) stays scoped.
    exact = simulate.template_match(TEMPLATE)
    await service.create("rules_cache", {**exact, "ttl": 300, "methods": "GET"}, ADMIN, "exact rule")
    await store.reload()
    exact_change = rule._change(engine.context(NOW), TEMPLATE, 400)
    assert exact_change.match == exact, exact_change
    assert simulate.endpoint_scoped(exact_change)
