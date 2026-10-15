"""Review round 4, lens logicfix: the engine's Roblox 429 burst trigger after a data reset, attacked.

What this is
    An adversarial test of the insights-10 fix (`engine._trigger_kinds`: an id cursor on `upstream_429`, rows with
    `id > cursor` count). It was a strict xfail for finding LOGICFIX-3; the poll now also remembers the cursor row's
    time and request id, and when that row is gone (or another row holds its id) it counts by time for that poll.

Why it exists
    `upstream_429.id` is `INTEGER PRIMARY KEY` without AUTOINCREMENT (metrics `0001_initial.sql`), so SQLite gives a
    new row `max(rowid) + 1`: after a data reset deletes the newest rows (the `upstream` family, or the per-endpoint
    reset of the very template that is being rate-limited), the next rows REUSE ids at or below the cursor. The fix's
    own comment says "A table emptied by a data reset gives a lower top id: the cursor follows it, so the next rows
    count again", which holds only when a poll runs between the reset and the next rows. A burst that the batch
    writer flushes after the reset but before the leader's next poll (5 s apart) is counted as nothing, exactly the
    "late flush" shape of finding insights-10.

How it works
    The engine and the production `MetricsRecorder` over temporary databases and a fake clock, as
    `test_r3_insights_engine.py` does: a first burst triggers (the control), the rows are deleted as the reset does
    (`DELETE` of the table's rows, `admin/api/data.py` family `upstream`), a second burst is flushed, and the next
    poll is checked.

What to read next
    `roxy/insights/engine.py` (`_trigger_kinds`), `roxy/admin/api/data.py` (`FAMILIES`, the `endpoint` scope).
"""

from __future__ import annotations

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


async def _burst(dbs: Any, settings: Any, clock: FakeClock, count: int, tag: str) -> None:
    """`count` Roblox 429s recorded and flushed by a worker's recorder (as the batch writer does every 2 s)."""
    recorder = MetricsRecorder(dbs, settings, clock)
    for n in range(count):
        recorder.record_upstream_429(
            endpoint_template=TEMPLATE,
            host="games.roblox.com",
            egress="direct",
            retry_after_s=30,
            ratelimit_headers={},
            request_id=f"01{tag}{n:023d}",
            at_ms=int(clock.now() * 1000),
        )
    await recorder.aclose(budget_s=10.0)


async def test_r4_logicfix_a_burst_after_a_reset_still_triggers(dbs: Any) -> None:
    clock = FakeClock(NOW)
    rule = BurstRule()
    rule.results = [card()]
    runtime = await load_runtime_settings(dbs, clock)
    store = RulesStore(dbs.control, clock=clock)
    await store.reload()
    engine = InsightsEngine(dbs=dbs, settings=runtime, rules=store, clock=clock, rule_set={rule.id: rule})
    assert await engine.check_triggers() is None  # the first poll sets the cursors
    clock.advance(5)
    await _burst(dbs, runtime, clock, 30, "A")
    first = await engine.check_triggers()
    assert first is not None  # the control: a burst triggers
    assert "roblox_429_burst" in first.trigger
    # The admin resets the upstream data (or this endpoint's data) right after: the 30 rows go.
    dbs.metrics.write_sync(lambda conn: conn.execute("DELETE FROM upstream_429"))
    clock.advance(65)  # past TRIGGER_MIN_GAP_S, so a second trigger may start a run
    await _burst(dbs, runtime, clock, 25, "B")  # flushed before the leader's next poll (polls are 5 s apart)
    ids = dbs.metrics.read_sync(lambda c: c.execute("SELECT min(id), max(id) FROM upstream_429").fetchone())
    assert tuple(ids) == (1, 25)  # the precondition: SQLite reused the ids the reset freed
    report = await engine.check_triggers()
    assert report is not None, (
        "25 Roblox 429s reached metrics.db after the reset, yet no early evaluation started: their ids (1 to 25) are "
        "at or below the cursor the first burst left (30)"
    )
    assert "roblox_429_burst" in report.trigger


async def test_r4_logicfix_a_reset_alone_starts_no_run_and_the_id_cursor_resumes(dbs: Any) -> None:
    """The time fallback is for one poll only: a reset of the newest rows with nothing new after it starts no early
    run (the older rows left were counted already, and their time is before the cursor row's), and the next burst is
    counted by id again. (A reset that leaves rows of the cursor row's own instant may count those again: one extra
    early run at worst, never a missed burst.)"""
    clock = FakeClock(NOW)
    rule = BurstRule()
    rule.results = [card()]
    runtime = await load_runtime_settings(dbs, clock)
    store = RulesStore(dbs.control, clock=clock)
    await store.reload()
    engine = InsightsEngine(dbs=dbs, settings=runtime, rules=store, clock=clock, rule_set={rule.id: rule})
    assert await engine.check_triggers() is None
    clock.advance(5)
    await _burst(dbs, runtime, clock, 30, "A")  # ids 1 to 30
    assert await engine.check_triggers() is not None
    clock.advance(65)
    await _burst(dbs, runtime, clock, 5, "B")  # ids 31 to 35, below the burst size
    assert await engine.check_triggers() is None
    dbs.metrics.write_sync(lambda conn: conn.execute("DELETE FROM upstream_429 WHERE id > 30"))  # the newest go
    clock.advance(65)
    assert await engine.check_triggers() is None  # nothing at or after the cursor row's time is left
    clock.advance(65)
    await _burst(dbs, runtime, clock, 25, "C")  # ids 31 to 55 again: above the cursor (30) the poll moved to
    report = await engine.check_triggers()
    assert report is not None
    assert "roblox_429_burst" in report.trigger
