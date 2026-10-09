"""Review round 3, lens mpjobs: recommendation actions and leader jobs under concurrency and failure.

What this is
    Adversarial tests (strict xfails, one per finding) against the running app (`api_app`): a deposed leader that
    keeps running the D7 auto-apply job, an apply that races the leader's evaluation between the API's digest
    check and the action lease, and a busy hot.db during a recommendation action.

Why it exists
    Plan 5.6 (a leader whose loop stalled past its lease cannot write; auto-apply is a non-idempotent job), plan 11.3
    and P4 (a recommendation is applied exactly as previewed), C6 (every limit holds with any number of workers) and
    C7 with DESIGN.md section 13 (shared state that cannot be written answers 503 `unavailable`, never a misleading
    conflict). Each test fails today for the reason in its xfail marker.

How it works
    The deposed leader is made the way `LeaderElector._try_acquire` makes one: another holder takes the expired
    `leader` lease (a new epoch) while this worker still holds a `JobContext` from before, and the registered job
    body is run with that old context. The race with the leader's evaluation is injected exactly between the API's
    check and the action: the stored recommendation is rewritten (same id, new proposed value) the way
    `engine.persist` updates an open recommendation every `insights_interval_s`. The busy hot.db is a real SQLite
    write lock held by another connection, the way another worker's long transaction holds it.

What to read next
    `roxy/insights/autoapply.py`, `roxy/insights/actions.py` (`_exclusive`), `roxy/admin/api/recommendations.py`
    (`apply`), `roxy/scheduler/leader.py` (fencing).
"""

from __future__ import annotations

import asyncio
import contextlib
import sqlite3
from typing import Any

import pytest

from roxy.config.insight_params import INSIGHT_RULES
from roxy.core.ids import new_id
from roxy.core.reasons import CacheState, Egress, Outcome, ReasonCode, Source
from roxy.insights import AUTO_APPLY_JOB, simulate
from roxy.insights.actions import ACTION_LEASE_PREFIX, ACTION_LEASE_TTL_MS
from roxy.insights.autoapply import AUTO_ACTOR
from roxy.insights.engine import write_recommendation
from roxy.insights.models import Evidence, ProposedChange, Recommendation, changes_digest, make_fingerprint
from roxy.scheduler.leader import LEADER_LEASE, LostLeadership
from roxy.storage import leases

BASE = "recommendations"
TEMPLATE = "games.roblox.com/v1/games"


async def _seed(
    api_app: Any,
    *,
    rule_id: str,
    subject: str,
    changes: list[ProposedChange],
    safe_auto: bool = False,
    risk: str = "low",
) -> Recommendation:
    """One open recommendation, written with the engine's own writer."""
    now = api_app.clock.now()
    spec = INSIGHT_RULES[rule_id]
    rec = Recommendation(
        rule_id=rule_id,
        family=spec.family,
        subject=subject,
        title=f"{rule_id} on {subject}",
        severity="warn",
        confidence="high",
        explanation="Plain-English explanation.",
        evidence=Evidence(window_from=now - 3600, window_to=now, sample_size=50).add("requests", 50, "requests"),
        changes=list(changes),
        expected_impact="Fewer upstream calls.",
        risk=risk,
        safe_auto=safe_auto,
    )
    rec.id = new_id("rec", api_app.clock)
    rec.fingerprint = make_fingerprint(rule_id, subject)
    rec.computed_severity = "warn"
    rec.state = "open"
    rec.created_at = rec.updated_at = now
    rec.expires_at = now + 7 * 86_400
    rec.dry_run_available = simulate.can_simulate(rec)
    await api_app.ctx.dbs.metrics.write(lambda conn: write_recommendation(conn, rec))
    return rec


def _cache_rule(pattern: str, ttl: int = 300) -> ProposedChange:
    return ProposedChange(
        "rule_upsert",
        table="rules_cache",
        match={"pattern": pattern, "type": "glob"},
        current=None,
        proposed={"pattern": pattern, "type": "glob", "ttl": ttl, "stale_ttl": 60},
    )


async def _wait_leader(api_app: Any) -> Any:
    elector = api_app.ctx.leader
    for _ in range(200):
        if elector is not None and elector.is_leader:
            return elector
        await asyncio.sleep(0.02)
    pytest.fail("the test app never became the leader")


def _cache_rule_rows(api_app: Any, pattern: str) -> int:
    count: int = api_app.ctx.dbs.control.read_sync(
        lambda c: c.execute("SELECT count(*) FROM rules_cache WHERE pattern = ?", (pattern,)).fetchone()[0]
    )
    return count


# ============================================================================== mpjobs-1: deposed leader


@pytest.mark.xfail(
    strict=True,
    reason="finding mpjobs-1: insights_auto_apply ignores its JobContext (`del job`), so a deposed leader "
    "still applies",
)
async def test_r3_mpjobs_deposed_leader_auto_apply_writes_nothing(api_app: Any) -> None:
    await api_app.settings(insights_auto_apply=1)
    rec = await _seed(
        api_app, rule_id="HOT-ENDPOINT", subject=TEMPLATE, changes=[_cache_rule(TEMPLATE)], safe_auto=True
    )
    elector = await _wait_leader(api_app)
    old_job = elector.job_context(AUTO_APPLY_JOB)  # this worker starts its run as the leader...

    def takeover(conn: sqlite3.Connection) -> Any:
        # ...then stalls past its lease; another worker takes the expired lease over (a new epoch, plan 5.6).
        conn.execute("UPDATE lease SET expires_ms = 0 WHERE name = ?", (LEADER_LEASE,))
        return leases.acquire(conn, LEADER_LEASE, "other-worker:4242:feedface", 15_000, api_app.clock.now_ms())

    grant = await api_app.ctx.dbs.hot.write(takeover)
    assert grant is not None
    assert grant.epoch > old_job.epoch

    job = api_app.ctx.jobs.registry.get(AUTO_APPLY_JOB)
    with contextlib.suppress(LostLeadership):  # the fenced outcome: the old run is refused before it writes
        await job.fn(old_job)

    stored = await api_app.ctx.insights.get(rec.id)
    assert stored is not None
    # Plan 5.6: "a leader whose loop stalled past its lease and then resumed cannot write". The new leader runs its
    # own auto-apply pass (with its own hourly budget read), so a deposed one that still applies doubles the D7
    # budget `auto_apply_max_per_hour` (C6) and races the new leader's watch windows.
    assert stored.state == "open", stored.state
    assert _cache_rule_rows(api_app, TEMPLATE) == 0


# ============================================================================== mpjobs-2: digest race


@pytest.mark.xfail(
    strict=True,
    reason="finding mpjobs-2: apply checks the previewed digest and the high-risk confirmation before the action "
    "lease, then applies whatever the leader's evaluation stored in between",
)
async def test_r3_mpjobs_apply_never_writes_an_unpreviewed_high_risk_value(
    api: Any, api_app: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    previewed = ProposedChange("setting", key="rotator_hard_stop_pct", current=100, proposed=90)
    rec = await _seed(api_app, rule_id="EGR-BURN", subject="rotator", changes=[previewed])
    preview = (await api.get(f"{BASE}/{rec.id}/preview")).json()
    assert preview["requires"]["confirm_high_risk"] is False  # 90 is not a high-risk value
    digest = preview["changes_digest"]
    assert digest == changes_digest([previewed])

    actions = api_app.ctx.insight_actions
    original = actions.apply

    async def leader_evaluation_lands_first(rec_id: str, *args: Any, **kwargs: Any) -> Any:
        # The leader's `insights_evaluate` (engine.persist, every 30 s) updates the open recommendation in place:
        # same id and fingerprint, a new proposed value. It takes no action lease, so it can land right here.
        stored = await api_app.ctx.insights.get(rec_id)
        stored.changes = [ProposedChange("setting", key="rotator_hard_stop_pct", current=100, proposed=150)]
        await api_app.ctx.dbs.metrics.write(lambda conn: write_recommendation(conn, stored))
        return await original(rec_id, *args, **kwargs)

    monkeypatch.setattr(actions, "apply", leader_evaluation_lands_first)
    answer = await api.post(f"{BASE}/{rec.id}/apply", json={"changes_digest": digest})
    applied = api_app.ctx.settings.int("rotator_hard_stop_pct")
    # Plan 11.3 and P4: applied exactly as previewed, or refused (409 changed_since_preview). Today the admin's
    # click applies 150 (overage charges, a high-risk value) with no preview, no confirmation and no reason.
    assert applied in (90, 100), (answer.status_code, answer.text, applied)
    if answer.status_code != 200:
        assert answer.status_code == 409, answer.text


# ============================================================================== mpjobs-3: busy hot.db


@pytest.mark.xfail(
    strict=True,
    reason="finding mpjobs-3: a busy hot.db during a recommendation action answers 409 wrong_state "
    "('another request is changing this recommendation') instead of 503 unavailable",
)
async def test_r3_mpjobs_busy_hot_db_during_an_action_is_503(api: Any, api_app: Any, section13: Any) -> None:
    rec = await _seed(api_app, rule_id="HOT-ENDPOINT", subject=TEMPLATE, changes=[_cache_rule(TEMPLATE)])
    hot_path = str(api_app.ctx.dbs.hot.path)
    locker = sqlite3.connect(hot_path, timeout=0.1, isolation_level=None, check_same_thread=False)
    try:
        locker.execute("BEGIN IMMEDIATE")  # another worker's long hot.db transaction holds the write lock
        answer = await api.post(f"{BASE}/{rec.id}/snooze", json={"duration": "1h"})
    finally:
        with contextlib.suppress(sqlite3.Error):
            locker.execute("ROLLBACK")
        locker.close()
    # DESIGN.md 13.1 and C7: shared state that cannot be written is 503 `unavailable` with Retry-After; a 409
    # `wrong_state` tells the admin another admin is acting on it, so they reload and retry into the same lock.
    section13(answer, 503, "unavailable")
    stored = await api_app.ctx.insights.get(rec.id)
    assert stored is not None
    assert stored.state == "open"


# ============================================================================== mpjobs-8: watch window


@pytest.mark.xfail(
    strict=True,
    reason="finding mpjobs-8: when the D7 rollback cannot take the action lease, insights_watch closes the regressed "
    "watch as kept, so the automatic rollback never happens",
)
async def test_r3_mpjobs_a_regressed_watch_is_rolled_back_once_the_lease_frees(api_app: Any, metrics_seed: Any) -> None:
    rec = await _seed(
        api_app, rule_id="HOT-ENDPOINT", subject=TEMPLATE, changes=[_cache_rule(TEMPLATE)], safe_auto=True
    )
    auto = api_app.ctx.auto_apply
    await api_app.ctx.insight_actions.apply(rec.id, AUTO_ACTOR, "auto-apply (D7)", auto=True)
    assert _cache_rule_rows(api_app, TEMPLATE) == 1
    started = int(api_app.clock.now())

    def zero_baseline(conn: sqlite3.Connection) -> None:  # nothing was refused before the change
        conn.execute(
            "UPDATE recommendation_watches SET baseline_json = ? WHERE recommendation_id = ?",
            ('{"error_rate": 0.0, "roblox_429_rate": null, "p95_ms": null, "refused_rate": 0.0}', rec.id),
        )

    await api_app.ctx.dbs.metrics.write(zero_baseline)
    refused = {
        "outcome": Outcome.REFUSED,
        "reason": ReasonCode.THROTTLE,
        "status": 429,
        "source": Source.ROXY,
        "cache_state": CacheState.NA,
        "upstream_calls": 0,
        "egress": Egress.NONE,
    }
    metrics_seed.record(40, at_ms=(started + 120) * 1000, **refused)  # the change made callers get refused
    metrics_seed.record(10, at_ms=(started + 120) * 1000)
    await metrics_seed.flush()
    watch_s = int(api_app.ctx.settings.int("auto_apply_watch_minutes")) * 60
    api_app.clock.advance(watch_s + 30)  # the watch window is over

    # A worker died in the middle of an action on this recommendation (its lease lives on for up to 120 s), or a
    # busy hot.db refuses the lease (mpjobs-3): the rollback cannot take the lease right now.
    lease = f"{ACTION_LEASE_PREFIX}{rec.id}"
    now_ms = api_app.clock.now_ms()
    await api_app.ctx.dbs.hot.write(
        lambda conn: leases.acquire(conn, lease, "dead-worker:1:deadbeef", ACTION_LEASE_TTL_MS, now_ms)
    )
    first = await auto.watch()
    assert first["rolled_back"] == [], first  # it could not act now; fine, as long as it tries again later

    await api_app.ctx.dbs.hot.write(lambda conn: conn.execute("DELETE FROM lease WHERE name = ?", (lease,)))
    api_app.clock.advance(60)  # the next insights_watch pass
    await auto.watch()
    stored = await api_app.ctx.insights.get(rec.id)
    assert stored is not None
    # Plan 11.4: a guard metric that got worse rolls the change back automatically and notifies the admin.
    assert stored.state == "rolled_back", stored.state
    assert _cache_rule_rows(api_app, TEMPLATE) == 0
