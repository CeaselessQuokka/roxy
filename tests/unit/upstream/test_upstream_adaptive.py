"""Adaptive rate (plan 7.3, F4): attribution, the decrease and increase rules, and the audited write."""

from __future__ import annotations

from typing import Any

import pytest
from upstream_fakes import FakeRules, FakeSettings, MemoryLimitsWriter, read_rows

from roxy.config.audit import Actor
from roxy.core.reasons import Egress
from roxy.upstream import adaptive, cooldowns
from roxy.upstream.adaptive import (
    AdaptiveController,
    AdaptivePolicy,
    Attribution,
    AttributionKind,
    KeyStats,
    decreased_rate,
    increased_rate,
    should_increase,
)
from roxy.upstream.buckets import BucketDefaults

POLICY = AdaptivePolicy.from_settings(FakeSettings())
DEFAULTS = BucketDefaults.from_settings(FakeSettings())
NOW_S = 1_760_000_000.0
EP = "endpoint:games.roblox.com/v1/games"


def endpoint_attr(key: str = EP) -> Attribution:
    return Attribution(AttributionKind.ENDPOINT, key, 1, 1, 60)


def test_policy_defaults() -> None:
    assert POLICY.enabled is True
    assert (POLICY.decrease_pct, POLICY.increase_pct, POLICY.probe_after_h) == (30, 10, 24)
    assert (POLICY.min_per_min, POLICY.max_per_min) == (6, 600)


@pytest.mark.parametrize(("current", "expected"), [(120, 84), (10, 7), (8, 6), (6, 6), (3, 3)])
def test_decrease_floors_and_never_raises(current: float, expected: float) -> None:
    assert decreased_rate(current, 30, 6) == expected


@pytest.mark.parametrize(("current", "expected"), [(120, 132), (590, 600), (600, 600), (900, 900)])
def test_increase_caps_and_never_lowers(current: float, expected: float) -> None:
    assert increased_rate(current, 10, 600) == expected


def test_attribution_from_cooldown_evidence(dbs: Any) -> None:
    def cool(template: str, at_ms: int) -> None:
        key = cooldowns.endpoint_key(template, Egress.DIRECT)
        dbs.hot.write_sync(lambda c: cooldowns.open_cooldown(c, key, 30, "retry_after", at_ms, 1))

    now_ms = int(NOW_S * 1000)
    cool("games.roblox.com/v1/a", now_ms)

    def attr(template: str) -> Attribution:
        return dbs.hot.read_sync(
            lambda c: adaptive.attribute(c, "games.roblox.com", template, Egress.DIRECT, NOW_S, 60, 3)
        )

    assert attr("games.roblox.com/v1/a").kind is AttributionKind.ENDPOINT
    cool("games.roblox.com/v1/b", now_ms)
    cool("games.roblox.com/v1/c", now_ms)
    host = attr("games.roblox.com/v1/c")
    assert (host.kind, host.bucket_key, host.templates_429) == (AttributionKind.HOST, "host:games.roblox.com", 3)
    cool("users.roblox.com/v1/x", now_ms)
    assert attr("games.roblox.com/v1/c").kind is AttributionKind.EGRESS


async def test_decrease_once_per_episode() -> None:
    rules = FakeRules()
    writer = MemoryLimitsWriter(rules)
    controller = AdaptiveController(writer)

    async def hit(first: bool, now: float, attribution: Attribution | None = None) -> Any:
        return await controller.on_rate_limited(
            attribution=attribution or endpoint_attr(),
            egress=Egress.DIRECT,
            first_in_episode=first,
            policy=POLICY,
            limits=rules.snapshot,
            defaults=DEFAULTS,
            now_s=now,
        )

    change = await hit(True, NOW_S)
    assert change is not None
    assert (change.bucket_key, change.old_per_min, change.new_per_min, change.burst) == (EP, 120, 84, 10)
    assert writer.writes == [(EP, 84, 10, writer.writes[0][3])]
    assert await hit(False, NOW_S + 1) is None  # an in-flight request's 429: same episode
    assert await hit(True, NOW_S + 30) is None  # this worker lowered it moments ago
    later = await hit(True, NOW_S + 120)
    assert later is not None
    assert later.new_per_min == pytest.approx(58.8)


async def test_decrease_respects_another_workers_recent_change() -> None:
    rules = FakeRules()
    rules.limit(EP, 50, 4, origin="adaptive", updated_at=int(NOW_S) - 10)
    controller = AdaptiveController(MemoryLimitsWriter(rules))
    result = await controller.on_rate_limited(
        attribution=endpoint_attr(),
        egress=Egress.DIRECT,
        first_in_episode=True,
        policy=POLICY,
        limits=rules.snapshot,
        defaults=DEFAULTS,
        now_s=NOW_S,
    )
    assert result is None


@pytest.mark.parametrize(
    ("egress", "kind", "enabled"),
    [
        (Egress.ROTATOR, AttributionKind.ENDPOINT, True),
        (Egress.DIRECT, AttributionKind.EGRESS, True),
        (Egress.DIRECT, AttributionKind.ENDPOINT, False),
    ],
)
async def test_no_decrease_for_rotator_egress_attribution_or_when_off(
    egress: Egress, kind: AttributionKind, enabled: bool
) -> None:
    rules = FakeRules()
    writer = MemoryLimitsWriter(rules)
    controller = AdaptiveController(writer)
    policy = AdaptivePolicy.from_settings(FakeSettings(adaptive_rate_enabled=int(enabled)))
    key = None if kind is AttributionKind.EGRESS else EP
    result = await controller.on_rate_limited(
        attribution=Attribution(kind, key, 1, 2, 60),
        egress=egress,
        first_in_episode=True,
        policy=policy,
        limits=rules.snapshot,
        defaults=DEFAULTS,
        now_s=NOW_S,
    )
    assert result is None
    assert writer.writes == []


async def test_host_attribution_lowers_the_host_bucket() -> None:
    rules = FakeRules()
    writer = MemoryLimitsWriter(rules)
    controller = AdaptiveController(writer)
    result = await controller.on_rate_limited(
        attribution=Attribution(AttributionKind.HOST, "host:games.roblox.com", 3, 1, 60),
        egress=Egress.CREDENTIAL,
        first_in_episode=False,
        policy=POLICY,
        limits=rules.snapshot,
        defaults=DEFAULTS,
        now_s=NOW_S,
    )
    assert result is not None
    assert (result.bucket_key, result.old_per_min, result.new_per_min, result.burst) == (
        "host:games.roblox.com",
        240,
        168,
        15,
    )


def test_should_increase_rules() -> None:
    window = POLICY.probe_after_h * 3600
    demand = KeyStats(EP, attempts=1000, rejections=50)
    assert should_increase(demand, None, NOW_S, POLICY) is True
    assert should_increase(KeyStats(EP, attempts=1000, rejections=10), None, NOW_S, POLICY) is False  # exactly 1 %
    assert should_increase(KeyStats(EP, attempts=0), None, NOW_S, POLICY) is False  # no evidence
    limited = KeyStats(EP, attempts=1000, rejections=50, rate_limited=1)
    assert should_increase(limited, None, NOW_S, POLICY) is False
    assert should_increase(demand, NOW_S - window + 60, NOW_S, POLICY) is False  # changed less than 24 h ago


async def test_increase_job_reads_metrics_and_raises(dbs: Any) -> None:
    def seed(conn: Any) -> None:
        dims = [
            (1, "games.roblox.com/v1/games", "games.roblox.com", "upstream_ok"),
            (2, "games.roblox.com/v1/games", "games.roblox.com", "upstream_busy"),
            (3, "users.roblox.com/v1/users", "users.roblox.com", "upstream_ok"),
            (4, "users.roblox.com/v1/users", "users.roblox.com", "queue_overflow"),
        ]
        for dim_hash, template, host, reason in dims:
            conn.execute(
                "INSERT INTO dims (dim_hash, endpoint_template, template_version, host, method, egress, outcome, "
                "reason_code, status, source, cache_state, auth_class) VALUES (?, ?, 1, ?, 'GET', 'direct', "
                "'served_upstream', ?, 200, 'roblox', 'MISS', 'anon')",
                (dim_hash, template, host, reason),
            )
        hour = int(NOW_S) - 3600
        for dim_hash, requests, calls in [(1, 900, 900), (2, 100, 0), (3, 900, 900), (4, 100, 0)]:
            conn.execute(
                "INSERT INTO rollup_hour (bucket_start, dim_hash, requests, upstream_calls) VALUES (?, ?, ?, ?)",
                (hour, dim_hash, requests, calls),
            )
        conn.execute(
            "INSERT INTO upstream_429 (at_ms, endpoint_template, host, egress) VALUES (?, ?, ?, 'direct')",
            (int(NOW_S * 1000) - 3600_000, "users.roblox.com/v1/users", "users.roblox.com"),
        )

    dbs.metrics.write_sync(seed)
    rules = FakeRules()
    writer = MemoryLimitsWriter(rules)
    controller = AdaptiveController(writer)
    changes = await adaptive.increase_job(
        controller, metrics_read=dbs.metrics.read, policy=POLICY, limits=rules.snapshot, defaults=DEFAULTS, now_s=NOW_S
    )
    # games: 10 % of attempts rejected and no 429 -> raised; users: had a 429 -> untouched; hosts: never at default.
    assert [(c.bucket_key, c.old_per_min, c.new_per_min) for c in changes] == [(EP, 120, 132)]
    assert writer.writes[0][:3] == (EP, 132, 10)


async def test_increase_never_overrides_an_admin_rate() -> None:
    rules = FakeRules()
    rules.limit(EP, 50, 5, origin="admin")
    controller = AdaptiveController(MemoryLimitsWriter(rules))
    stats = {EP: KeyStats(EP, attempts=1000, rejections=500)}
    assert (
        await controller.run_increases(stats, policy=POLICY, limits=rules.snapshot, defaults=DEFAULTS, now_s=NOW_S)
        == []
    )


async def test_rules_writer_audits_an_adaptive_row(dbs: Any, fake_clock: Any) -> None:
    from roxy.rules.service import RulesService
    from roxy.rules.store import RulesStore

    store = RulesStore(dbs.control, clock=fake_clock)
    writer = adaptive.RulesLimitsWriter(RulesService(dbs.control, clock=fake_clock, store=store))
    await writer.write_limit(EP, 84.0, 10, "Roblox 429 attributed to endpoint: 120 -> 84 per minute")
    rows = read_rows(dbs.control, "SELECT bucket_key, per_min, burst, origin, updated_by FROM upstream_limits")
    assert rows == [(EP, 84.0, 10, "adaptive", Actor("system", "adaptive").label)]
    audit = read_rows(dbs.control, "SELECT actor, action FROM audit_log")
    assert len(audit) == 1
    assert store.snapshot.upstream_limit(EP) is not None
