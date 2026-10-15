"""Proxy refusals in the security records of the fully wired app: the probe log and the rule that refused.

What this is
    Tests that drive `create_app(env)` with its real lifespan over temporary databases (`respx` plays Roblox; no
    request here reaches it). A probe through the proxy route (a non-Roblox URL, a Roblox host outside the allowlist,
    a smuggled login marker) becomes an entry of the Security probe log with v1's texts (finding parity-2), and the
    refusal event of a request an endpoint block refused names that block's row (the lane producers request: the
    router passes `Refuse.matches` to the outcome record).

Why it exists
    The unit tests check each piece (`abuse/pipeline.py _probe`, `proxy/router.py refusal_matches`); only the wired
    app shows the router, the abuse pipeline, the recorder's batch flush and the read models fit together.

What to read next
    `roxy/abuse/pipeline.py` (`probe_log_reason`), `roxy/metrics/security_events.py` (`ring`),
    `roxy/metrics/recorder.py` (`_record_refusal_event`).
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from roxy.config.audit import Actor
from roxy.config.settings_service import SettingsService
from roxy.core.clock import FakeClock
from roxy.core.redact import TOKEN_PREFIX
from roxy.main import create_app
from roxy.metrics import security_events
from roxy.rules.service import RulesService

ADMIN = Actor("admin", "probe-log")
GAMES = "games.roblox.com"


class App:
    """The running app, its context, and one HTTP client on the ASGI transport."""

    def __init__(self, app: Any, http: httpx.AsyncClient, clock: FakeClock) -> None:
        self.app, self.http, self.clock = app, http, clock
        self.ctx = app.state.ctx

    async def get(self, path: str, ip: str, **headers: str) -> httpx.Response:
        return await self.http.get(path, headers={"User-Agent": "Roblox/Linux", "X-Forwarded-For": ip, **headers})

    def probes(self, ip: str) -> list[dict[str, Any]]:
        page = self.ctx.dbs.metrics.read_sync(
            lambda conn: security_events.ring(conn, security_events.PROBE, ip=ip, limit=100)
        )
        return list(page["items"])


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
    service = SettingsService(harness.ctx.dbs.control, runtime=harness.ctx.settings, clock=clock)
    await service.update({"tarpit_enabled": 0, "rotator_enabled": 0}, ADMIN, "probe log test")  # no 8 to 20 s holds
    try:
        yield harness
    finally:
        await http.aclose()
        await lifespan.__aexit__(None, None, None)


async def test_proxy_probes_reach_the_security_probe_log(running: App, respx_mock: Any) -> None:
    route = respx_mock.route(host=GAMES).mock(return_value=httpx.Response(200, json={"data": []}))
    ip = "203.0.113.50"
    secret = TOKEN_PREFIX + "NOT-A-REAL-VALUE-made-up-for-this-test"
    assert (await running.get("/this-is-not-roblox", ip)).status_code == 404
    assert (await running.get("/unknownhost.roblox.com/v1/x", ip)).status_code == 404
    assert (await running.get(f"/{GAMES}/v1/games?universeIds=1", ip, **{"X-Custom-Auth": secret})).status_code == 400
    assert (await running.get(f"/{GAMES}/v1/games?universeIds=1", "203.0.113.51")).status_code == 200  # no probe
    assert route.call_count == 1
    await running.ctx.recorder.flush()
    items = running.probes(ip)
    by_reason = {item["reason"]: item for item in items}
    assert set(by_reason) == {
        "Non-Roblox URL",
        "Host not allowed",
        "Sent a ROBLOSECURITY token (a header carried a ROBLOSECURITY-shaped value)",
    }
    assert by_reason["Non-Roblox URL"]["target"] == "this-is-not-roblox"  # caller text in its own column
    assert by_reason["Non-Roblox URL"]["path"] == "/this-is-not-roblox"
    assert by_reason["Host not allowed"]["path"] == "/unknownhost.roblox.com/v1/x"
    assert all(item["ip"] == ip and item["user_agent"] == "Roblox/Linux" for item in items)
    assert running.probes("203.0.113.51") == []
    stored = running.ctx.dbs.metrics.read_sync(
        lambda conn: [str(r[0]) + str(r[1]) for r in conn.execute("SELECT reason_code, detail_json FROM events")]
    )
    assert not any("NOT-A-REAL-VALUE" in text or "X-Custom-Auth" in text for text in stored)


async def test_a_refusal_event_names_the_rule_that_refused(running: App, respx_mock: Any) -> None:
    change = await RulesService(running.ctx.dbs.control, clock=running.clock, store=running.ctx.rules).create(
        "rules_endpoint_block", {"pattern": f"{GAMES}/v1/blocked"}, ADMIN
    )
    respx_mock.route(host=GAMES).mock(return_value=httpx.Response(200, json={"data": []}))
    assert (await running.get(f"/{GAMES}/v1/blocked", "203.0.113.60")).status_code == 403
    await running.ctx.recorder.flush()
    rows = running.ctx.dbs.metrics.read_sync(
        lambda conn: [
            (str(r[0]), json.loads(r[1]))
            for r in conn.execute("SELECT reason_code, detail_json FROM events WHERE type = 'refusal'")
        ]
    )
    [(reason, detail)] = rows
    assert reason == "endpoint_blocked"
    assert detail["check"] == "endpoint_blocked"
    assert detail["rules"] == {"rules_endpoint_block": str(change.key)}
