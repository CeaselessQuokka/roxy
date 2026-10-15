"""Wave 2 high fixes AUTH-1 and AUTH-2, new variants (review round 3, lens w2highs): other retention jobs and windows.

What this is
    Variants of findings AUTH-1 (login failure slots pruned before the lockout window ended) and AUTH-2 (alert
    dedupe rows pruned before their cooldown ended), fixed in `storage/retention.py` under the rule the review round
    wrote into CHANGES.md: "rows that enforce a limit outlive its longest period". The fix covered two tables. Here
    the same rule is tried on the lockout with a lowered idle, on the 40 day rotator alert key, and on two more
    tables whose rows carry a window the leader's retention job can cut short:
      * `strikes` (hot.db): the per-IP escalation ladder. A strike fades one at a time, one per
        `throttle_strike_decay_seconds` since the last strike (0: never), but `prune_strikes` deletes the whole row
        once the last strike is one decay period old (or at once when the decay is 0).
      * `recommendations` (metrics.db): a dismissed or rolled back recommendation stays quiet for
        `dismiss_cooldown_days` (up to 365), but `prune_recommendations` deletes closed rows after
        `retention_recommendations_days` (as low as 1), and the engine then opens the same recommendation again
        (with auto-apply on, a change the admin rolled back can be applied again).

Why it exists
    v1 kept an idle throttle entry while it still carried strikes ("sweeping those away would quietly undo
    escalation for any caller patient enough to pause between bursts", `app/throttle.py _prune_once`). The ladder is
    the abuse defense against a client that pauses between bursts (plan 10.2, parity C3), and `dismiss_cooldown_days`
    is the admin's promise from the engine (plan 11.1 lifecycle).

How it works
    Real temporary databases (`dbs`). The retention policy is built the way the leader job builds it,
    `RetentionPolicy.from_settings(getter)`, then the pruner runs and the state is read back through the code that
    decides: `throttle.effective_strikes` over `load_strike_rows` for the ladder, and `InsightsEngine.run_once` with
    a test rule for the recommendation lifecycle.

What to read next
    `src/roxy/storage/retention.py` (`prune_strikes`, `prune_recommendations`, `prune_login_failures`,
    `prune_email_gate`), `src/roxy/abuse/throttle.py` (`effective_strikes`), `src/roxy/insights/engine.py`
    (`persist`, `_apply_result`), `tests/security/test_rr_auth_lockout_retention.py`.
"""

from __future__ import annotations

import copy
from collections.abc import Callable, Mapping
from typing import Any

import pytest

from roxy.abuse.throttle import StrikeRow, effective_strikes, load_strike_rows, save_strike_rows
from roxy.config.audit import Actor
from roxy.config.runtime import load_runtime_settings
from roxy.config.settings_service import SettingsService
from roxy.core.clock import FakeClock
from roxy.insights.actions import RecommendationActions
from roxy.insights.context import InsightContext
from roxy.insights.engine import InsightsEngine
from roxy.insights.models import Evidence, ProposedChange, Recommendation
from roxy.insights.rules.base import Rule
from roxy.rules.service import RulesService
from roxy.rules.store import RulesStore
from roxy.storage.retention import (
    DAY_S,
    RetentionPolicy,
    prune_email_gate,
    prune_login_failures,
    prune_recommendations,
    prune_strikes,
)

NOW = 1_791_385_200  # 2026-10-07T15:00:00Z
ADMIN = Actor("admin", "w2highs", "203.0.113.5")


def settings_getter(values: Mapping[str, Any]) -> Callable[[str], Any]:
    """A settings `get` that knows only `values` (every other policy field keeps its default)."""

    def get(key: str) -> Any:
        return values[key]

    return get


# ---------------------------------------------------------------------------------- AUTH-1 and AUTH-2 variants


def test_auth1_variant_a_lowered_idle_never_shortens_the_live_lockout_window(dbs: Any) -> None:
    """AUTH-1 variant (holds): a policy whose `login_failures_idle_s` is shorter than the live window still keeps a
    slot the window counts."""
    policy = RetentionPolicy(login_failures_idle_s=600, admin_login_window_s=86_400)
    slot_at = NOW - 80_000  # inside the 86,400 s window
    dbs.hot.write_sync(
        lambda conn: conn.execute(
            "INSERT INTO login_failures (subject, count, window_start) VALUES (?, 1, ?)",
            ("authfail:198.51.100.0/24|0123456789abcdef:aaaaaaaaaaaa", slot_at),
        )
    )
    dbs.hot.write_sync(lambda conn: prune_login_failures(conn, NOW, policy, 5000))
    left = dbs.hot.read_sync(lambda conn: conn.execute("SELECT count(*) FROM login_failures").fetchone()[0])
    assert left == 1


def test_auth2_variant_the_rotator_quota_key_outlives_its_40_day_cooldown_and_cap_rows_go(dbs: Any) -> None:
    """AUTH-2 variant (holds): the rotator's literal 40 day cooldown key is kept on day 39, while the hourly
    `capmem:` reservation row (added by the mp-10 fix after AUTH-2) is pruned after a day idle."""
    rows = [
        ("alert:rotator_quota:cycle", NOW - 39 * DAY_S),
        ("capmem:email", NOW - 2 * DAY_S),
        ("capdrop:email", NOW - 2 * DAY_S),
    ]
    dbs.hot.write_sync(
        lambda conn: conn.executemany("INSERT INTO email_gate (key, last_sent_at, suppressed) VALUES (?, ?, 0)", rows)
    )
    dbs.hot.write_sync(lambda conn: prune_email_gate(conn, NOW, RetentionPolicy(), 5000))
    left = dbs.hot.read_sync(lambda conn: [r[0] for r in conn.execute("SELECT key FROM email_gate ORDER BY key")])
    assert left == ["alert:rotator_quota:cycle"]


# ------------------------------------------------------------------------------------------ the strike ladder


@pytest.mark.parametrize(("decay_s", "idle_s"), [(1800, 1860), (0, 600)], ids=["default_decay", "never_decay"])
def test_w2h2_retention_never_forgives_strikes_the_decay_still_counts(dbs: Any, decay_s: int, idle_s: int) -> None:
    """A client on rung 5 whose penalty ended and who paused `idle_s` seconds: the ladder says 4 strikes are left
    (one faded) with the default decay, or all 5 with a decay of 0. The leader's prune must leave them."""
    key = "203.0.113.9"
    row = StrikeRow(key, strikes=5, last_strike_at=NOW - idle_s, tier=5, throttled_until=NOW - 30, exists=True)
    dbs.hot.write_sync(lambda conn: save_strike_rows(conn, [row]))
    before = effective_strikes(row.strikes, row.last_strike_at, NOW, decay_s)
    policy = RetentionPolicy.from_settings(settings_getter({"throttle_strike_decay_seconds": decay_s}))
    assert policy.strike_idle_s == decay_s  # the job reads the live decay
    dbs.hot.write_sync(lambda conn: prune_strikes(conn, NOW, policy, 5000))
    stored = dbs.hot.read_sync(lambda conn: load_strike_rows(conn, [key]))[key]
    after = effective_strikes(stored.strikes, stored.last_strike_at, NOW, decay_s) if stored.exists else 0
    assert (before, after) == (before, before)


# ------------------------------------------------------------------------------- the recommendation quiet period


class QuietRule(Rule):
    """A test rule (catalog id UP-5XX) that keeps finding the same problem."""

    id = "UP-5XX"
    safe_auto = True

    def __init__(self) -> None:
        self.results: list[Recommendation] = []

    def minimum_evidence(self, ctx: InsightContext) -> int:
        return 1

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        return [copy.deepcopy(rec) for rec in self.results]


def _recommendation() -> Recommendation:
    return Recommendation(
        rule_id="UP-5XX",
        family="upstream",
        subject="games.roblox.com/v1/games",
        title="Test recommendation",
        severity="warn",
        evidence=Evidence(sample_size=5).add("calls", 5),
        changes=[
            ProposedChange(
                "bucket_override",
                bucket_key="endpoint:games.roblox.com/v1/games",
                current={"per_min": 120.0, "burst": 10},
                proposed={"per_min": 90.0, "burst": 10},
            )
        ],
        safe_auto=True,
        risk="low",
    )


@pytest.mark.parametrize("closed_state", ["dismissed", "rolled_back"])
async def test_w2h3_retention_keeps_a_recommendation_quiet_for_its_whole_quiet_period(
    dbs: Any, closed_state: str
) -> None:
    clock = FakeClock(float(NOW))
    runtime = await load_runtime_settings(dbs, clock)
    store = RulesStore(dbs.control, clock=clock)
    await store.reload()
    rule = QuietRule()
    engine = InsightsEngine(dbs=dbs, settings=runtime, rules=store, clock=clock, rule_set={rule.id: rule})
    settings = SettingsService(dbs.control, runtime=runtime, clock=clock)
    actions = RecommendationActions(
        engine=engine,
        settings_service=settings,
        rules_service=RulesService(dbs.control, clock=clock, store=store),
        clock=clock,
    )
    # Both values are inside their catalog ranges: keep closed items a month, stay quiet a quarter after a dismiss.
    await settings.update({"retention_recommendations_days": 30, "dismiss_cooldown_days": 90}, ADMIN, "w2highs")
    rule.results = [_recommendation()]
    assert (await engine.run_once()).opened == 1
    rec_id = dbs.metrics.read_sync(lambda conn: conn.execute("SELECT id FROM recommendations").fetchone()[0])
    if closed_state == "dismissed":
        await actions.dismiss(rec_id, ADMIN, "intended_behavior", "seasonal traffic")
    else:  # what an undo of an applied change (or the watch window's automatic rollback) leaves behind
        dbs.metrics.write_sync(
            lambda conn: conn.execute(
                "UPDATE recommendations SET state = 'rolled_back', updated_at = ? WHERE id = ?", (NOW, rec_id)
            )
        )
    clock.advance(40 * DAY_S)  # inside the 90 day quiet period, past the 30 day retention
    policy = RetentionPolicy.from_settings(runtime.get)
    assert policy.retention_recommendations_days == 30
    dbs.metrics.write_sync(lambda conn: prune_recommendations(conn, clock.now(), policy, 5000))
    report = await engine.run_once()
    states = dbs.metrics.read_sync(lambda conn: [r[0] for r in conn.execute("SELECT state FROM recommendations")])
    assert (report.quiet, report.opened, states) == (1, 0, [closed_state])
