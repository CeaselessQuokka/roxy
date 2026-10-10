"""Review round 3, lens insights: the engine's trigger detection and dedupe across workers, attacked.

What this is
    Adversarial tests of `roxy/insights/engine.py` over real temporary databases and a fake clock: a Roblox 429
    burst that the per-worker batch writer flushes after the leader's trigger poll (finding insights-10, fixed),
    the 50 per rule cap against the resolve step (finding insights-11, fixed), and two workers' engines persisting
    the same evaluation at the same time (checked clean).

Why it exists
    Plan 11.1: the leader evaluates "immediately on trigger events (Roblox 429 burst, ...)", and re-evaluation
    "updates the existing recommendation's evidence instead of creating a new one". The 429 rows reach metrics.db
    through each worker's `BatchWriter`, which flushes every `metrics_flush_interval_ms` (2 s) with the event's own
    time, so a row routinely lands after a poll that already moved past its time.

How it works
    The burst is recorded through the production `MetricsRecorder.record_upstream_429` with the time it happened,
    and flushed (`aclose`) only after the leader's next poll, exactly the order a 2 s flush and a 5 s poll produce.
    The dedupe test runs `run_once` of two engines (two workers after a leader change) concurrently.

What to read next
    `roxy/insights/engine.py` (`check_triggers`, `_trigger_kinds`, `persist`), `roxy/storage/batch.py`.
"""

from __future__ import annotations

import asyncio
import copy
from typing import Any

from roxy.config.runtime import load_runtime_settings
from roxy.core.clock import FakeClock
from roxy.insights.context import InsightContext
from roxy.insights.engine import InsightsEngine
from roxy.insights.models import Evidence, Recommendation
from roxy.insights.rules.base import Rule
from roxy.metrics.recorder import MetricsRecorder
from roxy.rules.store import RulesStore

NOW = 1_791_385_200.0  # 2026-10-07T15:00:00Z
TEMPLATE = "games.roblox.com/v1/games"


class BurstRule(Rule):
    """A test rule (catalog id UP-429-ENDPOINT) that runs on the `roblox_429_burst` trigger only."""

    id = "UP-429-ENDPOINT"
    triggers = frozenset({"roblox_429_burst"})

    def __init__(self) -> None:
        self.results: list[Recommendation] = []

    def minimum_evidence(self, ctx: InsightContext) -> int:
        return 1

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        return [copy.deepcopy(rec) for rec in self.results]


def card() -> Recommendation:
    return Recommendation(
        rule_id="UP-429-ENDPOINT",
        family="upstream",
        subject=TEMPLATE,
        title=f"Roblox is rate-limiting {TEMPLATE}",
        evidence=Evidence(sample_size=25).add("roblox_429", 25),
    )


async def engine_over(dbs: Any, clock: FakeClock, rule: Rule) -> InsightsEngine:
    runtime = await load_runtime_settings(dbs, clock)
    store = RulesStore(dbs.control, clock=clock)
    await store.reload()
    return InsightsEngine(dbs=dbs, settings=runtime, rules=store, clock=clock, rule_set={rule.id: rule})


async def test_r3_insights_a_late_flushed_429_burst_still_triggers(dbs: Any) -> None:
    """insights-10 (fixed): the poll counts `upstream_429` rows by id since the last poll, whatever their time."""
    clock = FakeClock(NOW)
    rule = BurstRule()
    rule.results = [card()]
    engine = await engine_over(dbs, clock, rule)
    recorder = MetricsRecorder(dbs, engine.settings, clock)
    assert await engine.check_triggers() is None  # the first poll sets the cursors
    clock.advance(4)
    for n in range(25):  # 25 >= insight_up_429_endpoint_min_429s (20): a burst, recorded at t+4 s
        recorder.record_upstream_429(
            endpoint_template=TEMPLATE,
            host="games.roblox.com",
            egress="direct",
            retry_after_s=30,
            ratelimit_headers={},
            request_id=f"01J{n:023d}",
            at_ms=int(clock.now() * 1000),
        )
    clock.advance(1)
    assert await engine.check_triggers() is None  # the poll at t+5 s: the batch writer has not flushed yet
    await recorder.aclose(budget_s=10.0)  # its 2 s flush lands at t+6 s with the rows' own time (t+4 s)
    stored = dbs.metrics.read_sync(lambda c: c.execute("SELECT count(*) FROM upstream_429").fetchone()[0])
    assert stored == 25  # the precondition: the burst is in metrics.db before the next poll
    clock.advance(5)
    report = await engine.check_triggers()  # the poll at t+10 s
    assert report is not None, (
        "25 Roblox 429s reached metrics.db, yet no early evaluation started: the poll compares the rows' own "
        "time with the previous poll's time instead of what it has read so far"
    )
    assert "roblox_429_burst" in report.trigger
    assert report.opened == 1
    # The rows are counted once: the next poll (nothing new flushed) starts nothing.
    clock.advance(10)
    assert await engine.check_triggers() is None


async def test_r3_insights_a_small_late_flush_is_not_a_burst(dbs: Any) -> None:
    """insights-10 (fixed), the other side: fewer new rows than `insight_up_429_endpoint_min_429s` start no run,
    and rows already in metrics.db before the first poll never count (the first poll only sets the cursor)."""
    clock = FakeClock(NOW)
    rule = BurstRule()
    rule.results = [card()]
    engine = await engine_over(dbs, clock, rule)
    recorder = MetricsRecorder(dbs, engine.settings, clock)

    def record(n: int) -> None:
        for i in range(n):
            recorder.record_upstream_429(
                endpoint_template=TEMPLATE,
                host="games.roblox.com",
                egress="direct",
                retry_after_s=30,
                ratelimit_headers={},
                request_id=f"01K{i:023d}",
                at_ms=int(clock.now() * 1000),
            )

    record(30)
    await recorder.aclose(budget_s=10.0)
    assert await engine.check_triggers() is None  # history before the first poll is not a burst
    recorder = MetricsRecorder(dbs, engine.settings, clock)
    clock.advance(10)
    record(5)
    await recorder.aclose(budget_s=10.0)
    assert await engine.check_triggers() is None  # 5 < 20


async def test_r3_insights_the_per_rule_cap_never_resolves_a_card_that_still_holds(dbs: Any) -> None:
    """insights-11 (fixed): a card the 50 per rule cap leaves out keeps its state (it is still true); a card whose
    condition is really gone is still resolved."""
    clock = FakeClock(NOW)
    rule = BurstRule()

    def subject_card(subject: str) -> Recommendation:
        found = card()
        found.subject = subject
        found.title = f"Roblox is rate-limiting {subject}"
        return found

    # 50 endpoints (the MAX_PER_RULE bound) with the condition, all opened.
    rule.results = [subject_card(f"games.roblox.com/v1/e{n:02d}") for n in range(50)]
    engine = await engine_over(dbs, clock, rule)
    assert (await engine.run_once()).opened == 50
    # A 51st endpoint appears (its subject sorts first); the other 50 still have the condition.
    rule.results = [subject_card("games.roblox.com/v1/a-new"), *rule.results]
    clock.advance(30)
    report = await engine.run_once()
    resolved = dbs.metrics.read_sync(
        lambda c: [str(r[0]) for r in c.execute("SELECT json_extract(payload_json, '$.subject') FROM recommendations "
                                                "WHERE state = 'resolved'")]
    )  # fmt: skip
    assert report.resolved == 0, f"resolved although the rule still reports them: {resolved}"
    assert report.opened == 1
    open_count = dbs.metrics.read_sync(
        lambda c: c.execute("SELECT count(*) FROM recommendations WHERE state = 'open'").fetchone()[0]
    )
    assert open_count == 51
    # One endpoint's condition clears for real: that card (and only it) is resolved.
    rule.results = [r for r in rule.results if r.subject != "games.roblox.com/v1/e10"]
    clock.advance(30)
    report = await engine.run_once()
    assert report.resolved == 1


async def test_r3_insights_two_workers_persisting_at_once_keep_one_open_card(dbs: Any) -> None:
    """Checked clean: two engines (the old and the new leader around a lease change) persist the same evaluation
    concurrently; SQLite serializes the two write transactions and the second one updates, never duplicates."""
    clock = FakeClock(NOW)
    first_rule, second_rule = BurstRule(), BurstRule()
    first_rule.results = [card()]
    second_rule.results = [card()]
    first = await engine_over(dbs, clock, first_rule)
    second = await engine_over(dbs, clock, second_rule)
    await asyncio.gather(first.run_once(), second.run_once())
    rows = dbs.metrics.read_sync(
        lambda c: c.execute("SELECT state, count(*) FROM recommendations GROUP BY state").fetchall()
    )
    assert [tuple(r) for r in rows] == [("open", 1)]
