"""The production providers read what the producers recorded, so the rules that waited on them use real data.

Covers the wave 3b producers lane, the wiring part: `DefaultProviders` (built exactly as `InsightsEngine
.from_context` builds it: from the recorder, no extra arguments) answers TARPIT-TUNE, ABUSE-BOT, SYS-METRICS-DROP
and SYS-DISK from the schema version 5 tables, and FILTER-REMOVE, SEC-BYPASS-FOREVER and UP-CHALLENGE read the rule
hits and attempt flags the producers now record. Each test records through the real metrics recorder (or the real
tarpit and pipeline) into temporary databases and evaluates the real rule through the real engine.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from roxy.abuse.tarpit import Tarpit
from roxy.config.audit import Actor
from roxy.config.runtime import RuntimeSettings, load_runtime_settings
from roxy.config.settings_service import SettingsService
from roxy.core.clock import FakeClock
from roxy.core.reasons import AuthClass, CacheState, Egress, Outcome, ReasonCode, Source
from roxy.insights.context import DefaultProviders
from roxy.insights.engine import InsightsEngine
from roxy.metrics import disk_history
from roxy.metrics.recorder import KIND_SAMPLES, MetricsRecorder, OutcomeEvent
from roxy.metrics.samples import SampleRow
from roxy.rules.service import RulesService
from roxy.rules.store import RulesStore, load_rules_store

NOW = 1_791_385_200.0  # 2026-10-07T15:00:00Z, a whole minute
ADMIN = Actor("admin", "tester", "203.0.113.5")
TEMPLATE = "games.roblox.com/v1/games"


class World:
    """One worker's view: settings, rules, a recorder and the engine with production providers."""

    def __init__(
        self, dbs: Any, clock: FakeClock, settings: RuntimeSettings, rules: RulesStore, state_dir: Path
    ) -> None:
        self.dbs, self.clock, self.settings, self.rules = dbs, clock, settings, rules
        self.recorder = MetricsRecorder(dbs, settings, clock, worker_id="w1")
        # Exactly what `InsightsEngine.from_context` passes: the recorder brings the databases and the clock.
        self.providers = DefaultProviders(state_dir=state_dir, db_paths=dbs.paths, recorder=self.recorder, memo_s=0)
        self.engine = InsightsEngine(dbs=dbs, settings=settings, rules=rules, clock=clock, providers=self.providers)

    async def set(self, **changes: Any) -> None:
        await SettingsService(self.dbs.control, runtime=self.settings, clock=self.clock).update(changes, ADMIN, "test")

    def service(self) -> RulesService:
        return RulesService(self.dbs.control, clock=self.clock, store=self.rules)

    async def evaluate(self, rule_id: str) -> list[Any]:
        await self.recorder.flush()
        await self.rules.reload()
        outcome = await self.engine.evaluate_rule(rule_id)
        assert outcome.error is None, outcome.error
        assert outcome.skipped is None, outcome.skipped
        return outcome.recommendations


@pytest.fixture
async def world(dbs: Any, state_dir: Path) -> World:
    clock = FakeClock(NOW)
    settings = await load_runtime_settings(dbs, clock)
    rules = await load_rules_store(dbs, clock)
    return World(dbs, clock, settings, rules, state_dir)


def outcome(clock: FakeClock, ip: str) -> OutcomeEvent:
    return OutcomeEvent(
        at_ms=clock.now_ms(),
        request_id="01PRODUCERS",
        endpoint_template=TEMPLATE,
        host="games.roblox.com",
        method="GET",
        egress=Egress.DIRECT,
        outcome=Outcome.SERVED_UPSTREAM,
        reason=ReasonCode.UPSTREAM_OK,
        status=200,
        source=Source.ROBLOX,
        cache_state=CacheState.MISS,
        auth_class=AuthClass.ANON,
        caller_bytes_in=10,
        caller_bytes_out=100,
        upstream_calls=1,
        upstream_bytes_in=100,
        upstream_bytes_out=10,
        latency_ms=30.0,
        queue_wait_ms=0.0,
        upstream_ms=25.0,
        client_ip=ip,
        place_id=None,
        user_agent="python-requests/2.31",
        bypass=False,
        error=False,
    )


def sparse_file(path: Path, size: int) -> None:
    """A sparse file: `size` bytes on paper (what `stat` reports), nothing written to the disk."""
    with open(path, "wb") as handle:
        handle.truncate(size)


# ------------------------------------------------------------------------------------------------ TARPIT-TUNE


async def test_tarpit_tune_raises_the_cap_from_recorded_skips(world: World) -> None:
    for n in range(20):
        held = n < 12
        world.recorder.record_tarpit(
            category="probe",
            kind="hold",
            held_s=14.0 if held else 0.0,
            skipped=not held,
            gap_s=40.0 if n % 2 else 4.0,
            after_hold=bool(n % 2),  # held clients come back 10 times later: holding works
        )
    await world.recorder.flush()
    found = await world.providers.tarpit()
    assert found is not None
    assert (found["eligible_holds"], found["holds"], found["skipped"]) == (20, 12, 8)
    assert (found["gap_with_hold_s"], found["gap_without_hold_s"]) == (40.0, 4.0)
    [rec] = await world.evaluate("TARPIT-TUNE")
    assert rec.subject == "tarpit"
    assert [change.key for change in rec.changes] == ["tarpit_max_concurrent"]
    assert int(rec.changes[0].proposed) > 50


async def test_tarpit_tune_sees_useless_holds_through_the_real_tarpit(world: World) -> None:
    await world.set(tarpit_max_concurrent=1)

    async def no_wait(_seconds: float) -> None:
        return None

    pit = Tarpit(world.settings, world.dbs.hot, world.clock, "w1", sleep=no_wait, recorder=world.recorder)
    client = type("Req", (), {"limit_key": "203.0.113.50", "client_ip": "203.0.113.50", "bypass": False})()
    held = await pit.plan("probe", client)  # the only slot
    assert held is not None
    world.clock.advance(3)
    assert await pit.plan("probe", client) is None  # skipped: back 3 s after a hold
    world.clock.advance(4)
    assert await pit.plan("probe", client) is None  # skipped: back 4 s after an instant refusal
    await held.release()
    await world.recorder.flush()
    found = await world.providers.tarpit()
    assert found is not None
    assert (found["gap_with_hold_s"], found["gap_without_hold_s"]) == (3.0, 4.0)
    [rec] = await world.evaluate("TARPIT-TUNE")  # holding did not slow the client down: hold for less
    assert {change.key for change in rec.changes} <= {"tarpit_max_seconds", "tarpit_min_seconds", "tarpit_default_type"}


# --------------------------------------------------------------------------------------------- SYS-METRICS-DROP


async def test_metrics_drop_is_fleet_wide_and_goes_quiet_after_an_hour(world: World) -> None:
    other = MetricsRecorder(world.dbs, world.settings, world.clock, worker_id="w2")
    await world.set(metrics_queue_max=1000)
    row = SampleRow(world.clock.now_ms(), None, TEMPLATE, "GET", None, None, "MISS", 200, "direct", None, 1, "anon")
    for recorder, extra in ((world.recorder, 40), (other, 2)):
        for _ in range(1000 + extra):
            recorder.batch.add(KIND_SAMPLES, row)
        await recorder.flush()
    found = await world.providers.metrics_pipeline()
    assert found is not None
    assert (found["dropped"], found["scope"], found["workers"]) == (42, "fleet", 2)
    [rec] = await world.evaluate("SYS-METRICS-DROP")
    assert "in the last hour" in rec.explanation
    world.clock.advance(2 * 3600)
    assert await world.evaluate("SYS-METRICS-DROP") == []  # no new drops: quiet, the worker's counter is not read


async def test_metrics_drop_falls_back_to_the_worker_counter_without_the_table(world: World) -> None:
    world.dbs.metrics.write_sync(lambda conn: conn.execute("DROP TABLE metrics_pipeline_minute"))
    found = await world.providers.metrics_pipeline()
    assert found == {"dropped": 0, "scope": "worker"}


# --------------------------------------------------------------------------------------------------- ABUSE-BOT


async def test_abuse_bot_fires_on_a_recorded_score(world: World) -> None:
    for _ in range(510):
        world.recorder.record_outcome(outcome(world.clock, "198.51.100.77"))
    for _ in range(510):
        world.recorder.record_outcome(outcome(world.clock, "198.51.100.78"))
    world.recorder.record_client_score("198.51.100.77", 91)
    world.recorder.record_client_score("198.51.100.78", 35)  # busy but not bot-like: never judged a bot
    await world.recorder.flush()
    world.clock.advance(60)  # the rule reads whole minutes before now
    assert await world.providers.client_scores() == {"198.51.100.77": 91.0, "198.51.100.78": 35.0}
    [rec] = await world.evaluate("ABUSE-BOT")
    assert rec.subject == "ip:198.51.100.77"
    assert rec.changes[0].kind == "ban_add"


# ----------------------------------------------------------------------------------------------------- SYS-DISK


async def test_sys_disk_projects_the_recorded_growth(world: World, state_dir: Path) -> None:
    await world.set(storage_total_budget_gb=1)
    exports = state_dir / "exports"
    exports.mkdir(exist_ok=True)
    sparse_file(exports / "big.bin", 600_000_000)
    base = disk_history.FilesMeasure(total_bytes=10**12, free_bytes=9 * 10**11)
    for day, storage in ((10, 100_000_000), (5, 350_000_000), (1, 550_000_000)):
        base.files = {"metrics.db": {"bytes": storage, "wal_bytes": 0}}
        at = int(NOW) - day * 86_400
        world.dbs.metrics.write_sync(
            lambda conn, at=at: disk_history.write_sample(
                conn, at, base, 2000.0, {"metrics": {"rollup_minute": 40_000_000, "events": 9_000_000}}
            )
        )
    disk = await world.providers.disk()
    assert disk is not None
    assert disk["growth"][0]["at"] == int(NOW) - 10 * 86_400
    assert disk["growth"][-1]["at"] == int(NOW)  # a point now equal to today's storage
    assert disk["growth"][-1]["total_bytes"] >= 600_000_000
    assert disk["tables"] == {"metrics.rollup_minute": 40_000_000, "metrics.events": 9_000_000}
    assert disk["dims_per_minute_7d_avg"] == 2000.0  # samples of the last 7 days only
    [rec] = await world.evaluate("SYS-DISK")
    assert "in 30 days" in rec.explanation  # the projection reason, from real samples
    assert "new dimension rows a minute" in rec.explanation
    assert rec.evidence.details["tables"]["metrics.rollup_minute"] == 40_000_000
    os.remove(exports / "big.bin")


async def test_a_growth_line_shorter_than_a_day_is_not_projected(world: World) -> None:
    measure = disk_history.FilesMeasure(total_bytes=10**12, free_bytes=9 * 10**11, files={"metrics.db": {"bytes": 1}})
    world.dbs.metrics.write_sync(lambda conn: disk_history.write_sample(conn, int(NOW) - 3600, measure, None, None))
    disk = await world.providers.disk()
    assert disk is not None
    assert disk["growth"] == []  # an hour of WAL noise carried 30 days forward would mean nothing
    assert disk["dims_per_minute_7d_avg"] is None


# ------------------------------------------------------------------------------ FILTER-REMOVE, SEC-BYPASS-FOREVER


async def test_filter_remove_and_bypass_forever_read_real_hits(world: World) -> None:
    service = world.service()
    world.clock.set(NOW - 40 * 86_400)
    idle = await service.create("rules_endpoint_block", {"pattern": "games.roblox.com/v1/idle"}, ADMIN)
    busy = await service.create("rules_endpoint_block", {"pattern": "games.roblox.com/v1/busy"}, ADMIN)
    forever = await service.create(
        "access_list", {"kind": "bypass", "cidr": "198.51.100.0/24", "expires_at": None}, ADMIN
    )
    world.clock.set(NOW)
    world.recorder.record_rule_hit("rules_endpoint_block", busy.key, at_s=int(NOW) - 86_400)
    world.recorder.record_rule_hit("access_list", forever.key, at_s=int(NOW) - 3600)
    recs = {rec.subject: rec for rec in await world.evaluate("FILTER-REMOVE")}
    assert f"rules_endpoint_block:{idle.key}" in recs  # never matched in 40 days
    assert f"rules_endpoint_block:{busy.key}" not in recs  # matched yesterday: in use
    bypass = recs["bypass:198.51.100.0/24"]
    assert bypass.changes[0].kind == "rule_upsert"  # in use, so it gets an expiry rather than removal
    [sec] = await world.evaluate("SEC-BYPASS-FOREVER")
    assert sec.evidence.details["last_hit_at"] is not None


# -------------------------------------------------------------------------------------------------- UP-CHALLENGE


async def test_up_challenge_fires_on_recorded_challenge_pages(world: World) -> None:
    for _ in range(6):
        world.recorder.record_attempt(
            endpoint_template=TEMPLATE, egress="rotator", attempt=1, kind="first", status=403, challenge=True
        )
    world.clock.advance(60)  # the rule reads whole minutes before now
    [rec] = await world.evaluate("UP-CHALLENGE")
    assert rec.subject == f"{TEMPLATE} via rotator"
    assert rec.evidence.metrics[0].value == 6
