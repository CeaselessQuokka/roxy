"""The abuse pipeline wired to the real stores: runtime settings, the rules store, the switches and `install()`.

Every database is a temporary file (the `dbs` fixture); nothing leaves the machine.
"""

from __future__ import annotations

from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

from roxy.abuse.pause import set_pause
from roxy.abuse.pipeline import AbusePipeline, install
from roxy.abuse.verdict import Allow, Refuse
from roxy.config.audit import Actor
from roxy.config.defaults import seed_control_defaults
from roxy.config.runtime import load_runtime_settings
from roxy.config.settings_service import SettingsService
from roxy.core.clock import FakeClock
from roxy.core.reasons import ReasonCode
from roxy.core.tasks import TaskSupervisor
from roxy.rules.service import RulesService
from roxy.rules.store import load_rules_store

ADMIN = Actor("admin", "owner")
IP = "203.0.113.7"  # TEST-NET-3 documentation range


@dataclass
class Req:
    """The ProxyRequest attributes the abuse layer reads (DESIGN.md 7)."""

    client_ip: str = IP
    limit_key: str = IP
    method: str = "GET"
    host: str = "games.roblox.com"
    path: str = "/v1/games"
    query: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=lambda: {"user-agent": "Roblox/Linux"})
    header_names_in_order: list[str] = field(default_factory=lambda: ["user-agent"])
    user_agent: str = "Roblox/Linux"
    place_id: str | None = None
    is_browser: bool = False
    template: str = "games.roblox.com/v1/games"
    bypass: bool = False
    deadline_at: float = 0.0
    target_problem: ReasonCode | None = None
    fresh_cache_hit: bool = False
    request_id: str = "01INTEGRATION"


async def context(dbs: Any, clock: FakeClock, worker: str) -> SimpleNamespace:
    """An AppContext-shaped object for one simulated worker over the shared databases."""
    settings = await load_runtime_settings(dbs, clock)
    rules = await load_rules_store(dbs, clock)
    return SimpleNamespace(
        env=SimpleNamespace(workers=2),
        clock=clock,
        dbs=dbs,
        settings=settings,
        rules=rules,
        worker_id=worker,
        recorder=None,
        ip_hash_key=None,
        tasks=TaskSupervisor(clock=clock),
        abuse=None,
    )


async def test_settings_rules_and_switches_reach_the_pipeline(dbs: Any, fake_clock: FakeClock) -> None:
    await seed_control_defaults(dbs.control, fake_clock)
    ctx_a = await context(dbs, fake_clock, "worker-a")
    ctx_b = await context(dbs, fake_clock, "worker-b")
    pipe_a = AbusePipeline.from_context(ctx_a)
    pipe_b = AbusePipeline.from_context(ctx_b)
    await pipe_a.switches.reload()
    await pipe_b.switches.reload()

    # A settings change on worker A reaches worker B after its config watcher polls.
    service = SettingsService(dbs.control, runtime=ctx_a.settings, clock=fake_clock)
    await service.update({"allowed_requests_per_minute": 2}, ADMIN, "test")
    await ctx_b.settings.refresh_if_changed()
    assert isinstance(await pipe_b.evaluate(Req()), Allow)
    assert isinstance(await pipe_a.evaluate(Req()), Allow)  # the limit is shared: two workers, one budget
    refused = await pipe_b.evaluate(Req())
    assert isinstance(refused, Refuse)
    assert refused.reason is ReasonCode.THROTTLE
    assert refused.body == "Too many requests; please slow down."  # the seeded ladder, C5 text

    # A rule written through the rules service is live on the writing worker at once, on the other after a poll.
    rules = RulesService(dbs.control, clock=fake_clock, store=ctx_a.rules)
    await rules.create("rules_endpoint_block", {"pattern": "games.roblox.com/v1/secret"}, ADMIN)
    blocked = await pipe_a.evaluate(Req(path="/v1/secret", client_ip="198.51.100.1", limit_key="198.51.100.1"))
    assert isinstance(blocked, Refuse)
    assert blocked.reason is ReasonCode.ENDPOINT_BLOCKED
    await ctx_b.rules.refresh_if_changed()
    blocked_b = await pipe_b.evaluate(Req(path="/v1/secret", client_ip="198.51.100.2", limit_key="198.51.100.2"))
    assert isinstance(blocked_b, Refuse)
    assert blocked_b.reason is ReasonCode.ENDPOINT_BLOCKED

    # Pause written by one worker is seen by the other through config_version.
    await set_pause(dbs.control, fake_clock, ADMIN, paused=True, reason="Maintenance window")
    assert await pipe_b.switches.refresh_if_changed()
    paused = await pipe_b.evaluate(Req(client_ip="198.51.100.3", limit_key="198.51.100.3"))
    assert isinstance(paused, Refuse)
    assert (paused.status, paused.body, paused.headers["Roxy-Paused"]) == (503, "Maintenance window", "True")


async def test_tarpit_hold_for_a_header_filter_refusal(dbs: Any, fake_clock: FakeClock) -> None:
    ctx = await context(dbs, fake_clock, "worker-a")
    rules = RulesService(dbs.control, clock=fake_clock, store=ctx.rules)
    await rules.create("rules_header", {"needle": "executor"}, ADMIN)
    slept: list[float] = []

    async def sleep(seconds: float) -> None:
        slept.append(seconds)

    pipeline = AbusePipeline(
        settings=ctx.settings,
        rules=ctx.rules,
        hot_db=dbs.hot,
        control_db=dbs.control,
        clock=fake_clock,
        tarpit_sleep=sleep,
    )
    req = Req(
        headers={"user-agent": "Roblox/Linux", "x-executor": "1"}, header_names_in_order=["user-agent", "x-executor"]
    )
    refusal = await pipeline.evaluate(req)
    assert isinstance(refusal, Refuse)
    assert refusal.tarpit_category == "header_rule"
    plan = await pipeline.tarpit.plan(refusal.tarpit_category, req, reason=refusal.detail)
    assert plan is not None
    try:
        await plan.wait()
    finally:
        await plan.release()
    assert len(slept) == 1
    assert 8 <= slept[0] <= 20
    assert pipeline.tarpit.stats.snapshot()["reasons"] == {
        "header_rule|Filter |either|contains|executor (matched X-Executor)": {
            "held": 1,
            "skipped": 0,
            "total_held_s": 0.0,
            "max_held_s": 0.0,
            "last_at": fake_clock.now(),
        }
    }


async def test_install_wires_ctx_and_background_loops(dbs: Any, fake_clock: FakeClock) -> None:
    ctx = await context(dbs, fake_clock, "worker-a")
    async with AsyncExitStack() as stack:
        pipeline = await install(ctx, stack)
        assert ctx.abuse is pipeline
        names = {status.name for status in ctx.tasks.status()}
        assert {"abuse_spam_flush", "abuse_switches", "abuse_ban_hits"} <= names
        verdict = await pipeline.evaluate(Req())
        assert isinstance(verdict, Allow)
        await ctx.tasks.stop(drain_timeout_s=1)
