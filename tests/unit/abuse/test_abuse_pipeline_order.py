"""Pipeline order, the single-transaction commit rule (plan 6.3) and degraded mode (plan C7)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from abuse_support import ADMIN, FakeReq

from roxy.abuse.checks import PIPELINE_ORDER, default_checks
from roxy.abuse.checks.base import LimitSpec
from roxy.abuse.limiter import LimiterRow
from roxy.abuse.pipeline import AbusePipeline, walk_limiters
from roxy.abuse.verdict import Allow, Refuse
from roxy.core.clock import FakeClock
from roxy.core.reasons import ReasonCode
from roxy.rules.service import RulesService
from roxy.storage.db import SharedStateUnavailable

BYPASS_SKIPS = {
    "flood",
    "spam",
    "throttle_all",
    "throttle",
    "place_limit",
    "challenge",
    "bot_score",
    "user_agent_rule",
    "endpoint_rule",
}


def limiter_rows(dbs: Any) -> dict[str, tuple[int, int]]:
    rows = dbs.hot.read_sync(lambda conn: conn.execute("SELECT bucket_key, count, tat_ms FROM limiter").fetchall())
    return {str(r[0]): (int(r[1]), int(r[2])) for r in rows}


def test_pipeline_order_is_the_design_order() -> None:
    checks = default_checks()
    assert tuple(check.name for check in checks) == PIPELINE_ORDER
    positions = [check.position for check in checks]
    assert positions == sorted(positions)
    assert len(set(positions)) == len(positions)
    assert {check.name for check in checks if check.skipped_by_bypass} == BYPASS_SKIPS
    # Never skipped by bypass (DESIGN.md 11.1): pause, bans, filters, smuggling, blocks.
    never = {
        "pause",
        "bans",
        "ignored_path",
        "unsafe_url",
        "not_roblox",
        "auth_smuggling",
        "header_rule",
        "endpoint_blocked",
    }
    assert never.isdisjoint(BYPASS_SKIPS)


def test_describe_lists_every_check(make_pipeline: Callable[..., AbusePipeline]) -> None:
    described = make_pipeline().describe()
    assert [d["name"] for d in described] == list(PIPELINE_ORDER)
    assert described[0] == {
        "name": "pause",
        "position": 10,
        "label": "Pause",
        "kind": "static",
        "skipped_by_bypass": False,
        "tarpit_category": None,
    }


async def test_a_request_refused_later_spends_no_rate_budget(
    make_pipeline: Callable[..., AbusePipeline], rules_service: RulesService, snapshot_of: Callable[[], Any], dbs: Any
) -> None:
    """Plan 6.3: only the flood counter (every request) is committed when a later check refuses."""
    await rules_service.create("rules_user_agent", {"needle": "tool", "kind": "burst", "limit": 1, "period": 60}, ADMIN)
    await rules_service.create("rules_endpoint_block", {"pattern": "games.roblox.com/v1/blocked"}, ADMIN)
    pipeline = make_pipeline(rules=snapshot_of())

    def blocked() -> FakeReq:
        return FakeReq(path="/v1/blocked").with_headers([("User-Agent", "tool")])

    for _ in range(5):
        verdict = await pipeline.evaluate(blocked())
        assert isinstance(verdict, Refuse)
        assert verdict.reason is ReasonCode.ENDPOINT_BLOCKED
    rows = limiter_rows(dbs)
    assert set(rows) == {"flood:203.0.113.7"}  # no per-IP count, no UA budget spent
    # The UA rule budget is intact: the first real request passes, the second hits the rule.
    assert isinstance(await pipeline.evaluate(FakeReq().with_headers([("User-Agent", "tool")])), Allow)
    assert (await pipeline.evaluate(FakeReq().with_headers([("User-Agent", "tool")]))).reason is (  # type: ignore[union-attr]
        ReasonCode.USER_AGENT_RULE
    )


async def test_flood_counts_probes(make_pipeline: Callable[..., AbusePipeline]) -> None:
    pipeline = make_pipeline({"flood_limit_per_minute": 10})
    for _ in range(10):
        verdict = await pipeline.evaluate(FakeReq(target_problem=ReasonCode.NOT_ROBLOX))
        assert isinstance(verdict, Refuse)
        assert verdict.reason is ReasonCode.NOT_ROBLOX
    verdict = await pipeline.evaluate(FakeReq(target_problem=ReasonCode.NOT_ROBLOX))
    assert isinstance(verdict, Refuse)
    assert verdict.reason is ReasonCode.FLOOD


async def test_endpoint_rule_refusal_is_not_counted_per_ip(
    make_pipeline: Callable[..., AbusePipeline], rules_service: RulesService, snapshot_of: Callable[[], Any]
) -> None:
    await rules_service.create("rules_endpoint_limit", {"pattern": "games.roblox.com", "limit": 1, "period": 60}, ADMIN)
    pipeline = make_pipeline(rules=snapshot_of())
    first = await pipeline.evaluate(FakeReq())
    assert isinstance(first, Allow)
    for _ in range(5):
        refused = await pipeline.evaluate(FakeReq())
        assert isinstance(refused, Refuse)
        assert refused.headers["Roxy-Requests-Left"] == "9"  # only the admitted request was counted


def test_walk_commits_flood_even_when_a_later_limiter_refuses() -> None:
    now = 1_760_000_000_000
    specs = [
        LimitSpec("flood", "flood:k", "gcra", limit=300, window_s=60, always_commit=True),
        LimitSpec("ua", "ua:1|k", "fixed", limit=1, window_s=60),
    ]
    rows = {"ua:1|k": LimiterRow("ua:1|k", tat_ms=now + 60_000, window_start=now, count=1, exists=True)}
    walk = walk_limiters(specs, rows, {}, None, now)
    assert walk.state.stopped_at == "ua"
    assert [row.key for row in walk.limiter_writes] == ["flood:k"]


async def test_degraded_mode_uses_limit_over_workers(make_pipeline: Callable[..., AbusePipeline], dbs: Any) -> None:
    """Plan C7: hot.db unavailable -> per-worker memory at limit / workers, logged as degraded."""
    events: list[tuple[Any, ...]] = []

    class Recorder:
        def record_event(self, *args: Any) -> None:
            events.append(args)

    pipeline = make_pipeline(workers=2, recorder=Recorder())

    async def broken_write(*_args: Any, **_kwargs: Any) -> Any:
        raise SharedStateUnavailable("hot", "disk I/O error")

    async def broken_read(*_args: Any, **_kwargs: Any) -> Any:
        raise SharedStateUnavailable("hot", "disk I/O error")

    real_write, real_read = dbs.hot.write, dbs.hot.read
    dbs.hot.write, dbs.hot.read = broken_write, broken_read
    try:
        results = [await pipeline.evaluate(FakeReq()) for _ in range(6)]
    finally:
        dbs.hot.write, dbs.hot.read = real_write, real_read
    assert [isinstance(v, Allow) for v in results] == [True] * 5 + [False]  # 10 per 50 s over 2 workers
    assert pipeline.degraded
    assert events
    assert events[0][0] == "abuse_degraded"
    refused = results[-1]
    assert isinstance(refused, Refuse)
    assert refused.reason is ReasonCode.THROTTLE
    # Recovery: the next successful transaction leaves degraded mode.
    assert isinstance(await pipeline.evaluate(FakeReq(client_ip="198.51.100.4", limit_key="198.51.100.4")), Allow)
    assert not pipeline.degraded


async def test_degraded_mode_tarpit_never_holds(make_pipeline: Callable[..., AbusePipeline], dbs: Any) -> None:
    pipeline = make_pipeline()

    async def broken_write(*_args: Any, **_kwargs: Any) -> Any:
        raise SharedStateUnavailable("hot", "database is locked")

    real = dbs.hot.write
    dbs.hot.write = broken_write
    try:
        refusal = await pipeline.evaluate(FakeReq(target_problem=ReasonCode.UNSAFE_URL))
        assert isinstance(refusal, Refuse)
        assert await pipeline.tarpit.plan("probe", FakeReq(), reason="x") is None
    finally:
        dbs.hot.write = real
    assert pipeline.tarpit.stats.total.skipped == 1


async def test_bypass_marker_sets_the_request_flag(
    make_pipeline: Callable[..., AbusePipeline], rules_service: RulesService, snapshot_of: Callable[[], Any]
) -> None:
    await rules_service.create("access_list", {"kind": "bypass", "cidr": "203.0.113.7"}, ADMIN)
    pipeline = make_pipeline(rules=snapshot_of())
    req = FakeReq()
    await pipeline.evaluate(req)
    assert req.bypass


async def test_expired_bypass_no_longer_applies(
    make_pipeline: Callable[..., AbusePipeline],
    rules_service: RulesService,
    snapshot_of: Callable[[], Any],
    fake_clock: FakeClock,
) -> None:
    await rules_service.create(
        "access_list", {"kind": "bypass", "cidr": "203.0.113.7", "expires_at": int(fake_clock.now()) + 60}, ADMIN
    )
    pipeline = make_pipeline(rules=snapshot_of())
    fake_clock.advance(61)
    req = FakeReq()
    await pipeline.evaluate(req)
    assert not req.bypass


@pytest.mark.parametrize("reason", [ReasonCode.PAUSED])
async def test_stats_count_refusals_by_check(
    make_pipeline: Callable[..., AbusePipeline], dbs: Any, fake_clock: FakeClock, reason: ReasonCode
) -> None:
    from roxy.abuse.pause import set_pause

    await set_pause(dbs.control, fake_clock, ADMIN, paused=True)
    pipeline = make_pipeline()
    pipeline.switches.reload_sync()
    await pipeline.evaluate(FakeReq())
    assert pipeline.stats.snapshot()["refusals"] == {"pause": 1}
    # A paused service must never feed SPAM-REFUSED.
    assert "ref|ip:203.0.113.7" not in pipeline.spam._pending
