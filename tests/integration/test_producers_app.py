"""The producers through the fully wired app: real requests feed rule hits, page flags and bot scores to the rules.

What this is
    Tests that drive `create_app(env)` with its real lifespan over temporary databases, `respx` playing Roblox behind
    the real egress clients (nothing leaves the machine). A refused request records the hit of the rule that refused
    it; Roblox answering HTML on a JSON endpoint records `html_body` attempts that UP-CHALLENGE then reports; library
    callers get recorded bot scores that the insights providers return. The engine is the one the lifespan built
    (`ctx.insights`, with `DefaultProviders` from the recorder), so no wiring is assumed beyond what runs in
    production.

Why it exists
    Each producer has unit tests; only this module shows the router, the abuse pipeline, the upstream exchange, the
    recorder and the insights providers fit together with the lifespan's own objects.

What to read next
    `roxy/abuse/pipeline.py` (`Facts.note_match`, `record_bot_scores`), `roxy/upstream/pages.py`,
    `roxy/insights/context.py` (`DefaultProviders`).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from roxy.config.audit import Actor
from roxy.config.settings_service import SettingsService
from roxy.core.clock import FakeClock
from roxy.main import create_app
from roxy.metrics import read_history, read_producers
from roxy.rules.service import RulesService

ADMIN = Actor("admin", "producers")
GAMES = "games.roblox.com"
TEMPLATE = "games.roblox.com/v1/games"
HTML = b"<!DOCTYPE html><html><head><title>Blocked</title></head><body>no</body></html>"


class App:
    """The running app, its context, and one HTTP client on the ASGI transport."""

    def __init__(self, app: Any, http: httpx.AsyncClient, clock: FakeClock) -> None:
        self.app, self.http, self.clock = app, http, clock
        self.ctx = app.state.ctx

    async def get(self, path: str, ip: str, user_agent: str = "Roblox/Linux") -> httpx.Response:
        return await self.http.get(path, headers={"User-Agent": user_agent, "X-Forwarded-For": ip})

    async def settings(self, **changes: Any) -> None:
        service = SettingsService(self.ctx.dbs.control, runtime=self.ctx.settings, clock=self.clock)
        await service.update(changes, ADMIN, "producers test")

    def rules(self) -> RulesService:
        return RulesService(self.ctx.dbs.control, clock=self.clock, store=self.ctx.rules)


@pytest.fixture
async def running(env: Any, credentials_dir: Path, respx_mock: Any) -> AsyncIterator[App]:
    for name in ("smtp_password", "alert_webhook_url"):
        (credentials_dir / name).unlink(missing_ok=True)  # alerts go to the log only
    clock = FakeClock()
    app = create_app(env, clock=clock)
    lifespan = app.router.lifespan_context(app)
    await lifespan.__aenter__()
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 50000))
    http = httpx.AsyncClient(transport=transport, base_url="http://testserver")
    harness = App(app, http, clock)
    await harness.settings(tarpit_enabled=0, rotator_enabled=0)  # no 8 to 20 s holds; Roblox through direct only
    try:
        yield harness
    finally:
        await http.aclose()
        await lifespan.__aexit__(None, None, None)


async def test_a_refusal_records_the_hit_of_the_rule_that_refused_it(running: App, respx_mock: Any) -> None:
    change = await running.rules().create("rules_endpoint_block", {"pattern": "games.roblox.com/v1/blocked"}, ADMIN)
    route = respx_mock.route(host=GAMES).mock(return_value=httpx.Response(200, json={"data": []}))
    for n in range(3):
        response = await running.get(f"/{GAMES}/v1/blocked", ip=f"203.0.113.{n + 1}")
        assert response.status_code == 403
    assert route.call_count == 0
    await running.ctx.recorder.flush()
    now = int(running.clock.now())
    hits = running.ctx.dbs.metrics.read_sync(
        lambda conn: read_producers.rule_hit_counts(conn, now - 3600, now + 60, "rules_endpoint_block")
    )
    assert hits == {("rules_endpoint_block", str(change.key)): 3}
    lifetime = running.ctx.dbs.metrics.read_sync(lambda conn: read_history.rule_hits(conn, "rules_endpoint_block"))
    assert lifetime[("rules_endpoint_block", str(change.key))]["last_hit_at"] == now


async def test_html_answers_on_a_json_endpoint_reach_up_challenge(running: App, respx_mock: Any) -> None:
    respx_mock.route(host=GAMES, path="/v1/games").mock(
        return_value=httpx.Response(200, content=HTML, headers={"content-type": "text/html; charset=utf-8"})
    )
    for n in range(6):
        response = await running.get(f"/{GAMES}/v1/games?universeIds={n}", ip=f"198.51.100.{n + 1}")
        assert response.status_code == 200
    await running.ctx.recorder.flush()
    now = int(running.clock.now())
    rows = running.ctx.dbs.metrics.read_sync(lambda conn: read_history.attempt_rows(conn, now - 3600, now + 60))
    assert sum(row["count"] for row in rows if row["html_body"] and row["endpoint_template"] == TEMPLATE) == 6
    outcome = await running.ctx.insights.evaluate_rule("UP-CHALLENGE", now=running.clock.now() + 60)
    assert outcome.error is None
    [rec] = outcome.recommendations
    assert rec.subject == f"{TEMPLATE} via direct"
    assert rec.evidence.metrics[0].value == 6


async def test_library_callers_get_recorded_bot_scores(running: App, respx_mock: Any) -> None:
    respx_mock.route(host=GAMES, path="/v1/games").mock(return_value=httpx.Response(200, json={"data": []}))
    for n in range(3):
        await running.get(f"/{GAMES}/v1/games?universeIds={n}", ip="192.0.2.10", user_agent="python-requests/2.31")
    await running.get(f"/{GAMES}/v1/games?universeIds=9", ip="192.0.2.11", user_agent="Roblox/Linux")
    assert await running.ctx.abuse.record_bot_scores() == 2
    await running.ctx.recorder.flush()
    providers = running.ctx.insights.providers
    providers.memo_s = 0  # the evaluation the leader ran at start remembered "no scores yet" for a few seconds
    scores = await providers.client_scores()
    assert set(scores) >= {"192.0.2.10", "192.0.2.11"}
    assert scores["192.0.2.10"] > scores["192.0.2.11"]
