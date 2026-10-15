"""Rule hits: every abuse check that matched an admin rule row reports it, and the recorder keeps it per minute.

Covers the wave 3b producers lane, item 1: blocks, endpoint rules, header rules, User-Agent rules, bypass, deny and
ban entries report their matched row id for every decision (`Facts.note_match`, `Allow.matches`,
`Refuse.matches`), the pipeline hands them to the metrics recorder in memory (no new hot.db or metrics.db write on
the request), and the recorder writes them per rule per minute (`rule_hit_minute`) and per rule (`rule_hits`), so
FILTER-REMOVE and SEC-BYPASS-FOREVER see real hit history. Two workers' hits add up (C6).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from abuse_support import ADMIN, FakeReq, FakeSettings

from roxy.abuse.checks.base import (
    TABLE_ACCESS_LIST,
    TABLE_BANS,
    TABLE_ENDPOINT_BLOCK,
    TABLE_ENDPOINT_LIMIT,
    TABLE_HEADER_RULE,
    TABLE_UA_RULE,
)
from roxy.abuse.pipeline import AbusePipeline
from roxy.abuse.verdict import Allow, Refuse
from roxy.core.clock import FakeClock
from roxy.core.reasons import ReasonCode
from roxy.metrics import read_history, read_producers
from roxy.metrics.recorder import MetricsRecorder
from roxy.rules.service import RulesService
from roxy.rules.store import RulesSnapshot


def recorder_for(dbs: Any, clock: FakeClock, worker: str = "w1") -> MetricsRecorder:
    return MetricsRecorder(dbs, FakeSettings(), clock, worker_id=worker)


def hits_by_rule(dbs: Any, clock: FakeClock) -> dict[tuple[str, str], int]:
    now = int(clock.now())
    return dbs.metrics.read_sync(lambda conn: read_producers.rule_hit_counts(conn, now - 3600, now + 60))


def req(ip: str = "203.0.113.7", **fields: Any) -> FakeReq:
    return FakeReq(client_ip=ip, limit_key=ip, **fields)


async def test_every_matched_rule_row_is_on_the_verdict_and_recorded(
    dbs: Any,
    fake_clock: FakeClock,
    rules_service: RulesService,
    snapshot_of: Callable[[], RulesSnapshot],
    make_pipeline: Callable[..., AbusePipeline],
) -> None:
    block = await rules_service.create("rules_endpoint_block", {"pattern": "games.roblox.com/v1/blocked"}, ADMIN)
    limit = await rules_service.create(
        "rules_endpoint_limit", {"pattern": "games.roblox.com/v1/limited", "limit": 100, "period": 60}, ADMIN
    )
    header = await rules_service.create("rules_header", {"needle": "executor"}, ADMIN)
    agent = await rules_service.create(
        "rules_user_agent", {"needle": "friendlybot", "kind": "burst", "limit": 50, "period": 60}, ADMIN
    )
    bypass = await rules_service.create("access_list", {"kind": "bypass", "cidr": "198.51.100.0/24"}, ADMIN)
    deny = await rules_service.create("access_list", {"kind": "deny", "cidr": "192.0.2.128/25"}, ADMIN)
    ban = await rules_service.create("bans", {"subject_type": "ip", "subject": "192.0.2.66"}, ADMIN)
    recorder = recorder_for(dbs, fake_clock)
    pipeline = make_pipeline(rules=snapshot_of(), recorder=recorder)

    blocked = await pipeline.evaluate(req(path="/v1/blocked", template="games.roblox.com/v1/blocked"))
    assert isinstance(blocked, Refuse)
    assert blocked.reason is ReasonCode.ENDPOINT_BLOCKED
    assert blocked.matches == {TABLE_ENDPOINT_BLOCK: str(block.key)}

    limited = await pipeline.evaluate(req("203.0.113.8", path="/v1/limited", template="games.roblox.com/v1/limited"))
    assert isinstance(limited, Allow)  # the rule matched and its budget admitted: still a hit
    assert limited.matches == {TABLE_ENDPOINT_LIMIT: str(limit.key)}

    filtered = await pipeline.evaluate(
        req("203.0.113.9").with_headers([("User-Agent", "Roblox/Linux"), ("X-Executor", "1")])
    )
    assert isinstance(filtered, Refuse)
    assert filtered.matches == {TABLE_HEADER_RULE: str(header.key)}  # the row id, not the canonical key

    friendly = await pipeline.evaluate(req("203.0.113.10").with_headers([("User-Agent", "FriendlyBot/2")]))
    assert isinstance(friendly, Allow)
    assert friendly.matches == {TABLE_UA_RULE: str(agent.key)}

    trusted = await pipeline.evaluate(req("198.51.100.20"))
    assert isinstance(trusted, Allow)
    assert trusted.matches == {TABLE_ACCESS_LIST: str(bypass.key)}

    denied = await pipeline.evaluate(req("192.0.2.200"))
    assert isinstance(denied, Refuse)
    assert denied.reason is ReasonCode.DENY_LIST
    assert denied.matches == {TABLE_ACCESS_LIST: str(deny.key)}

    banned = await pipeline.evaluate(req("192.0.2.66"))
    assert isinstance(banned, Refuse)
    assert banned.matches == {TABLE_BANS: str(ban.key)}

    plain = await pipeline.evaluate(req("203.0.113.11"))
    assert isinstance(plain, Allow)
    assert plain.matches == {}

    recorder.close()
    assert hits_by_rule(dbs, fake_clock) == {
        (TABLE_ENDPOINT_BLOCK, str(block.key)): 1,
        (TABLE_ENDPOINT_LIMIT, str(limit.key)): 1,
        (TABLE_HEADER_RULE, str(header.key)): 1,
        (TABLE_UA_RULE, str(agent.key)): 1,
        (TABLE_ACCESS_LIST, str(bypass.key)): 1,
        (TABLE_ACCESS_LIST, str(deny.key)): 1,
        (TABLE_BANS, str(ban.key)): 1,
    }
    lifetime = dbs.metrics.read_sync(lambda conn: read_history.rule_hits(conn, TABLE_ACCESS_LIST))
    assert lifetime[(TABLE_ACCESS_LIST, str(bypass.key))]["last_hit_at"] == int(fake_clock.now())


async def test_hits_are_summed_per_rule_and_minute(
    dbs: Any,
    fake_clock: FakeClock,
    rules_service: RulesService,
    snapshot_of: Callable[[], RulesSnapshot],
    make_pipeline: Callable[..., AbusePipeline],
) -> None:
    block = await rules_service.create("rules_endpoint_block", {"pattern": "games.roblox.com/v1/blocked"}, ADMIN)
    recorder = recorder_for(dbs, fake_clock)
    pipeline = make_pipeline(rules=snapshot_of(), recorder=recorder)
    for n in range(3):
        await pipeline.evaluate(req(f"203.0.113.{20 + n}", path="/v1/blocked"))
    fake_clock.advance(60)
    for n in range(2):
        await pipeline.evaluate(req(f"203.0.113.{30 + n}", path="/v1/blocked"))
    await recorder.flush()
    start = int(fake_clock.now()) - 3600
    series = dbs.metrics.read_sync(
        lambda conn: read_producers.rule_hit_series(conn, TABLE_ENDPOINT_BLOCK, block.key, start, start + 7200)
    )
    assert [hits for _minute, hits in series] == [3, 2]
    assert series[1][0] - series[0][0] == 60


async def test_two_workers_add_up_in_the_same_minute(
    dbs: Any,
    fake_clock: FakeClock,
    rules_service: RulesService,
    snapshot_of: Callable[[], RulesSnapshot],
    make_pipeline: Callable[..., AbusePipeline],
) -> None:
    bypass = await rules_service.create("access_list", {"kind": "bypass", "cidr": "198.51.100.0/24"}, ADMIN)
    rules = snapshot_of()
    first, second = recorder_for(dbs, fake_clock, "w1"), recorder_for(dbs, fake_clock, "w2")
    worker_a = make_pipeline(rules=rules, recorder=first)
    worker_b = make_pipeline(rules=rules, recorder=second)
    for n in range(4):
        await worker_a.evaluate(req(f"198.51.100.{n + 1}"))
    for n in range(3):
        await worker_b.evaluate(req(f"198.51.100.{n + 50}"))
    first.close()
    second.close()
    assert hits_by_rule(dbs, fake_clock) == {(TABLE_ACCESS_LIST, str(bypass.key)): 7}
    lifetime = dbs.metrics.read_sync(lambda conn: read_history.rule_hits(conn, TABLE_ACCESS_LIST))
    assert lifetime[(TABLE_ACCESS_LIST, str(bypass.key))]["hits"] == 7


async def test_reporting_hits_adds_no_database_write_to_the_request(
    dbs: Any,
    fake_clock: FakeClock,
    rules_service: RulesService,
    snapshot_of: Callable[[], RulesSnapshot],
    make_pipeline: Callable[..., AbusePipeline],
) -> None:
    await rules_service.create(
        "rules_endpoint_limit", {"pattern": "games.roblox.com/v1/limited", "limit": 100, "period": 60}, ADMIN
    )
    recorder = recorder_for(dbs, fake_clock)
    pipeline = make_pipeline(rules=snapshot_of(), recorder=recorder)
    writes = {"hot": 0, "metrics": 0}
    real_hot, real_metrics = dbs.hot.write, dbs.metrics.write

    async def hot_write(fn: Any, **kwargs: Any) -> Any:
        writes["hot"] += 1
        return await real_hot(fn, **kwargs)

    async def metrics_write(fn: Any, **kwargs: Any) -> Any:
        writes["metrics"] += 1
        return await real_metrics(fn, **kwargs)

    dbs.hot.write, dbs.metrics.write = hot_write, metrics_write
    try:
        verdict = await pipeline.evaluate(req(path="/v1/limited", template="games.roblox.com/v1/limited"))
    finally:
        dbs.hot.write, dbs.metrics.write = real_hot, real_metrics
    assert isinstance(verdict, Allow)
    assert verdict.matches  # reported...
    assert writes == {"hot": 1, "metrics": 0}  # ...inside the single abuse transaction, nothing written for it
    assert recorder.producers.stats()["pending_keys"] == 1  # in memory until the recorder's next flush


async def test_a_cheap_refusal_runs_no_pattern_and_reports_no_pattern_hit(
    dbs: Any,
    fake_clock: FakeClock,
    rules_service: RulesService,
    snapshot_of: Callable[[], RulesSnapshot],
    make_pipeline: Callable[..., AbusePipeline],
) -> None:
    # A regex rule defers the pattern checks until the cheap limiters admitted the request (plan 9.9).
    await rules_service.create(
        "rules_user_agent", {"needle": "^Bot", "mode": "regex", "kind": "burst", "limit": 50, "period": 60}, ADMIN
    )
    recorder = recorder_for(dbs, fake_clock)
    pipeline = make_pipeline({"allowed_requests_per_minute": 1}, rules=snapshot_of(), recorder=recorder)
    first = await pipeline.evaluate(req().with_headers([("User-Agent", "Bot/1")]))
    assert isinstance(first, Allow)
    assert set(first.matches) == {TABLE_UA_RULE}
    second = await pipeline.evaluate(req().with_headers([("User-Agent", "Bot/1")]))
    assert isinstance(second, Refuse)
    assert second.reason is ReasonCode.THROTTLE
    assert second.matches == {}  # the regex never ran, so nothing can claim it matched
    assert pipeline.stats.pattern_checks_skipped == 1


async def test_a_bypass_caller_refused_by_a_ban_reports_both_rows(
    dbs: Any,
    fake_clock: FakeClock,
    rules_service: RulesService,
    snapshot_of: Callable[[], RulesSnapshot],
    make_pipeline: Callable[..., AbusePipeline],
) -> None:
    bypass = await rules_service.create("access_list", {"kind": "bypass", "cidr": "203.0.113.7"}, ADMIN)
    ban = await rules_service.create("bans", {"subject_type": "ip", "subject": "203.0.113.7"}, ADMIN)
    pipeline = make_pipeline(rules=snapshot_of(), recorder=recorder_for(dbs, fake_clock))
    verdict = await pipeline.evaluate(req())
    assert isinstance(verdict, Refuse)
    assert verdict.reason is ReasonCode.BANNED  # a ban beats an old bypass entry (plan 10.5)
    assert verdict.matches == {TABLE_ACCESS_LIST: str(bypass.key), TABLE_BANS: str(ban.key)}


async def test_a_deny_entry_that_refuses_counts_over_a_bypass_entry(
    dbs: Any,
    fake_clock: FakeClock,
    rules_service: RulesService,
    snapshot_of: Callable[[], RulesSnapshot],
    make_pipeline: Callable[..., AbusePipeline],
) -> None:
    await rules_service.create("access_list", {"kind": "bypass", "cidr": "203.0.113.0/24"}, ADMIN)
    deny = await rules_service.create("access_list", {"kind": "deny", "cidr": "203.0.113.7"}, ADMIN)
    pipeline = make_pipeline(rules=snapshot_of(), recorder=recorder_for(dbs, fake_clock))
    verdict = await pipeline.evaluate(req())
    assert isinstance(verdict, Refuse)
    assert verdict.reason is ReasonCode.DENY_LIST
    assert verdict.matches == {TABLE_ACCESS_LIST: str(deny.key)}  # the row that decided is the one counted


async def test_without_a_recorder_hits_stay_on_the_verdict_only(
    dbs: Any,
    fake_clock: FakeClock,
    rules_service: RulesService,
    snapshot_of: Callable[[], RulesSnapshot],
    make_pipeline: Callable[..., AbusePipeline],
) -> None:
    block = await rules_service.create("rules_endpoint_block", {"pattern": "games.roblox.com/v1/blocked"}, ADMIN)
    pipeline = make_pipeline(rules=snapshot_of())  # no recorder: metrics degrade open, the verdict is unchanged
    verdict = await pipeline.evaluate(req(path="/v1/blocked"))
    assert isinstance(verdict, Refuse)
    assert verdict.matches == {TABLE_ENDPOINT_BLOCK: str(block.key)}
