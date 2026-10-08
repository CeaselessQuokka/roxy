"""Adversarial review (multi-process and failure modes lens): plan C7 through the fully wired application.

What this is
    Tests that run the real app (lifespan, egress clients with their guard, credential manager, upstream, cache,
    abuse pipeline, recorder) with `respx` playing Roblox, and make a shared database read-only while it serves.
    They check what C7 promises when shared state cannot be written: the credential is not used, the tarpit does
    not hold, the per-IP limiter falls back to `limit / workers` in memory, and metrics degrade open (keep serving,
    flag the gap, write the numbers once the database is back). One test reproduces a finding and is marked
    `xfail(strict=True)` with the finding id.

Why it exists
    The package tests fake `SharedStateUnavailable` at one call site at a time. A read-only file fails every write
    of that database at once, through SQLite's own error path, which is how a full disk, a read-only remount or a
    permissions mistake looks in production.

How it works
    `read_only(db, True)` sets `PRAGMA query_only=1` on the database's writer thread connection: from then on
    `BEGIN IMMEDIATE` fails with SQLITE_READONLY ("attempt to write a readonly database"), exactly what SQLite
    reports for a read-only file, and `Database.write` turns it into `SharedStateUnavailable`. Reads keep working,
    as they do on a read-only file. `read_only(db, False)` restores it. The app runs with ROXY_WORKERS=2 so the
    degraded limit is visibly `limit / 2`, and with a `FakeClock` so limiter windows and cooldowns do not move.

What to read next
    `roxy/abuse/pipeline.py` (`_degraded_walk`), `roxy/abuse/tarpit.py` (`plan`), `roxy/upstream/service.py`
    (`_after_call`, finding UP-COOLDOWN-LOST), `roxy/storage/batch.py` (requeue on failure).
"""

from __future__ import annotations

import json
import time
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import pytest

from roxy.config.audit import Actor
from roxy.config.settings_service import SettingsService
from roxy.core.clock import FakeClock
from roxy.main import create_app
from roxy.rules.service import RulesService
from roxy.storage.db import Database

ADMIN = Actor("admin", "review")
GAMES = "games.roblox.com"
ECONOMY = "economy.roblox.com"
CURRENCY = "/v1/user/currency"


def read_only(db: Database, on: bool) -> None:
    """Make `db`'s writer connection refuse every write (SQLITE_READONLY), or accept them again."""
    writer = next(thread for thread in db._threads if thread.role == "writer")
    assert writer._conn is not None, "the writer connection is opened at startup"
    writer._conn.execute(f"PRAGMA query_only={1 if on else 0}")


@dataclass
class App:
    ctx: Any
    clock: FakeClock
    http: httpx.AsyncClient
    roblox: Any
    credential: str
    _ip: int = 0
    rules_made: list[Any] = field(default_factory=list)

    def ip(self) -> str:
        self._ip += 1
        return f"198.51.100.{self._ip}"

    async def get(self, path: str, *, ip: str | None = None, **kwargs: Any) -> httpx.Response:
        headers = {"User-Agent": "Roblox/Linux", "X-Forwarded-For": ip or self.ip()}
        return await self.http.get(path, headers=headers, **kwargs)

    async def post(self, path: str, body: bytes, *, ip: str | None = None) -> httpx.Response:
        headers = {
            "User-Agent": "Roblox/Linux",
            "X-Forwarded-For": ip or self.ip(),
            "Content-Type": "application/json",
        }
        return await self.http.post(path, content=body, headers=headers)

    async def settings(self, **changes: Any) -> None:
        service = SettingsService(self.ctx.dbs.control, runtime=self.ctx.settings, clock=self.clock)
        await service.update(changes, ADMIN, "review test")

    async def rule(self, table: str, row: Mapping[str, Any]) -> Any:
        service = RulesService(self.ctx.dbs.control, clock=self.clock, store=self.ctx.rules)
        return await service.create(table, dict(row), ADMIN, "review test")

    async def activate_credential(self) -> None:
        """Probe the (fake) credential once, as the admin's "check now" does, so its status becomes active."""
        self.roblox.route(host="users.roblox.com", path="/v1/users/authenticated").mock(
            return_value=httpx.Response(200, json={"id": 1, "name": "owner"})
        )
        probe = await self.ctx.egress.credential.probe("admin_check", fetch=self.ctx.upstream.credential_probe_fetch)
        assert probe.ok, probe


@pytest.fixture
async def app(
    env_vars: dict[str, str],
    credentials_dir: Path,
    fake_secrets: dict[str, str],
    respx_mock: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[App]:
    from roxy.config.env import EnvSettings

    monkeypatch.setenv("ROXY_WORKERS", "2")  # the degraded per-IP share is limit / 2
    for name in ("smtp_password", "alert_webhook_url"):
        (credentials_dir / name).unlink(missing_ok=True)
    clock = FakeClock()
    application = create_app(EnvSettings(), clock=clock)
    lifespan = application.router.lifespan_context(application)
    await lifespan.__aenter__()
    transport = httpx.ASGITransport(app=application, client=("127.0.0.1", 50000))
    client = httpx.AsyncClient(transport=transport, base_url="http://testserver")
    harness = App(application.state.ctx, clock, client, respx_mock, fake_secrets["roblox_credential"])
    await harness.settings(tarpit_enabled=0, rotator_enabled=0)
    try:
        yield harness
    finally:
        for db in (harness.ctx.dbs.hot, harness.ctx.dbs.metrics):
            read_only(db, False)
        await client.aclose()
        await lifespan.__aexit__(None, None, None)


# ---------------------------------------------------------------------------------------- the per-IP limiter


async def test_review_readonly_hot_per_ip_limit_is_limit_over_workers(app: App) -> None:
    """C7: hot.db read-only, ROXY_WORKERS=2, limit 10 per 50 s: one client gets 10 // 2 = 5 answers from this worker
    (here fresh cache hits, which count toward the limit), then the throttle refusal."""
    app.roblox.route(host=GAMES, path="/v1/games").mock(return_value=httpx.Response(200, json={"data": [1]}))
    url = f"/{GAMES}/v1/games?universeIds=77"
    assert (await app.get(url)).status_code == 200  # cached while hot.db still works
    read_only(app.ctx.dbs.hot, True)
    client = app.ip()
    statuses = [(await app.get(url, ip=client)) for _ in range(7)]
    assert [r.status_code for r in statuses] == [200] * 5 + [429] * 2
    assert all(r.headers.get("roxy-cache") == "HIT" for r in statuses[:5])
    assert {r.headers.get("roxy-refusal") for r in statuses[5:]} == {"throttle"}
    assert app.ctx.abuse.degraded


# ------------------------------------------------------------------------------------------------ the tarpit


async def test_review_readonly_hot_tarpit_never_holds(app: App) -> None:
    """C7 and plan 10.6: a probe refusal is held 2 s while hot.db works, and answered at once while it is
    read-only (no shared slot count, no hold)."""
    await app.settings(tarpit_enabled=1, tarpit_on_probe=1, tarpit_min_seconds=2, tarpit_max_seconds=2)
    started = time.monotonic()
    held = await app.get("/evil.example.com/wp-login.php")
    held_s = time.monotonic() - started
    read_only(app.ctx.dbs.hot, True)
    started = time.monotonic()
    instant = await app.get("/evil.example.com/wp-login.php")
    instant_s = time.monotonic() - started
    assert held.status_code == instant.status_code == 404
    assert held_s >= 1.5, held_s
    assert instant_s < 0.5, instant_s
    assert app.ctx.abuse.tarpit.stats.snapshot()["skipped"] >= 1


# ------------------------------------------------------------------------------------------- the credential


async def test_review_readonly_hot_credential_never_used(app: App) -> None:
    """C7: an allowlisted credential endpoint while hot.db is read-only answers 503 `degraded` and sends nothing
    (not with the credential, not anonymously). After hot.db recovers the credential is used again (control)."""
    await app.activate_credential()
    await app.rule("credential_allowlist", {"pattern": f"{ECONOMY}{CURRENCY}", "cache_private": True})
    route = app.roblox.route(host=ECONOMY, path=CURRENCY).mock(return_value=httpx.Response(200, json={"robux": 5}))
    read_only(app.ctx.dbs.hot, True)
    response = await app.get(f"/{ECONOMY}{CURRENCY}")
    assert response.status_code == 503
    assert response.headers["roxy-refusal"] == "degraded"
    assert response.headers["retry-after"] == "10"
    assert route.call_count == 0
    read_only(app.ctx.dbs.hot, False)
    recovered = await app.get(f"/{ECONOMY}{CURRENCY}")
    assert recovered.status_code == 200
    assert route.call_count == 1
    assert route.calls[0].request.headers.get("cookie") == f".ROBLOSECURITY={app.credential}"


@pytest.mark.xfail(
    strict=True,
    reason="finding UP-COOLDOWN-LOST: a 429 that arrives while hot.db cannot be written raises out of "
    "UpstreamService._after_call before any cooldown is kept (not even the credential manager's local one), so "
    "the next request after hot.db recovers goes to Roblox again inside its Retry-After",
)
@pytest.mark.parametrize("path", ["credential", "anonymous"])
async def test_review_429_during_hot_outage_still_cools_down(app: App, path: str) -> None:
    """Plan 7.5 and 7.9: Roblox says 429 with Retry-After 60 at the moment hot.db becomes read-only. Once hot.db
    is back (and long before 60 s passed), the endpoint must not be contacted again through that path."""
    calls: list[bool] = []
    hot = app.ctx.dbs.hot

    def answer(request: httpx.Request) -> httpx.Response:
        calls.append("cookie" in request.headers)
        if len(calls) == 1:
            read_only(hot, True)  # hot.db goes read-only while Roblox is answering
            return httpx.Response(429, headers={"Retry-After": "60"}, json={"errors": [{"code": 0}]})
        return httpx.Response(200, json={"ok": True})

    if path == "credential":
        await app.activate_credential()
        await app.rule("credential_allowlist", {"pattern": f"{ECONOMY}{CURRENCY}", "cache_private": True})
        app.roblox.route(host=ECONOMY, path=CURRENCY).mock(side_effect=answer)
        first = await app.get(f"/{ECONOMY}{CURRENCY}")
    else:
        # A POST is not cacheable here (cache_post_requests = allowlist), so no single-flight lease is involved.
        app.roblox.route(host=GAMES, path="/v1/games/multiget").mock(side_effect=answer)
        first = await app.post(f"/{GAMES}/v1/games/multiget", json.dumps({"ids": [1]}).encode())
    assert first.status_code in (429, 503)
    read_only(hot, False)
    app.clock.advance(5)  # 5 s later: still well inside Roblox's Retry-After of 60 s
    if path == "credential":
        second = await app.get(f"/{ECONOMY}{CURRENCY}")
    else:
        second = await app.post(f"/{GAMES}/v1/games/multiget", json.dumps({"ids": [1]}).encode())
    print(f"\n{path}: first {first.status_code}, second {second.status_code}, calls {calls}")
    assert len(calls) == 1, f"Roblox was called again inside its Retry-After: {calls}"


# -------------------------------------------------------------------------------------------------- alerts


@pytest.mark.xfail(
    strict=True,
    reason="finding ALERT-CAP: while hot.db cannot be written the notifier falls back to MemoryGate, which only "
    "dedupes by cooldown key: the per-channel hourly cap (alert_rate_limit_per_hour) is not applied at all, and "
    "each worker would send its own copies",
)
async def test_review_readonly_hot_alert_cap_still_holds(app: App) -> None:
    """Plan 17.7: at most `alert_rate_limit_per_hour` messages per channel per hour (leak guard trips excepted).
    With hot.db read-only, 25 distinct warning alerts must still produce at most 20 mails."""
    from pydantic import SecretStr

    from roxy.admin.auth.testing import RecordingTransport
    from roxy.notify.alerts import Alert
    from roxy.notify.mail import MailConfig, MailSender
    from roxy.notify.notifier import Notifier

    transport = RecordingTransport()
    config = MailConfig(to_addr="owner@example.invalid", from_addr="alerts@example.invalid", password=SecretStr("x"))
    notifier = Notifier(
        hot_db=app.ctx.dbs.hot,
        settings=app.ctx.settings,
        site_origin="http://localhost",
        mail=MailSender(config, transport=transport),
        webhook=None,
        clock=app.clock,
    )
    cap = int(app.ctx.settings.get("alert_rate_limit_per_hour"))
    read_only(app.ctx.dbs.hot, True)
    for n in range(cap + 5):
        await notifier.send(
            Alert(type="error", severity="critical", subject=f"Roxy: review {n}", summary="x", cooldown_key=f"r:{n}")
        )
    print(f"\ncap {cap}, mails sent {len(transport.messages)}")
    assert len(transport.messages) <= cap


# ------------------------------------------------------------------------------------------------- metrics


async def test_review_readonly_metrics_degrade_open(app: App) -> None:
    """C7: with metrics.db read-only every request is still answered; the flush fails and keeps the numbers
    (flagged as a flush failure, nothing dropped), and they are written once metrics.db is writable again."""
    app.roblox.route(host=GAMES, path="/v1/games").mock(return_value=httpx.Response(200, json={"data": []}))
    recorder = app.ctx.recorder
    await recorder.flush()

    def total(conn: Any) -> int:
        return int(conn.execute("SELECT coalesce(sum(requests), 0) FROM rollup_minute").fetchone()[0])

    before = await app.ctx.dbs.metrics.read(total)
    read_only(app.ctx.dbs.metrics, True)
    answers = [await app.get(f"/{GAMES}/v1/games?universeIds={n}") for n in range(5)]
    assert [r.status_code for r in answers] == [200] * 5
    failed = await recorder.flush()
    assert "metrics" in failed.failed_dbs
    assert recorder.batch.flush_failures >= 1
    assert recorder.batch.dropped == 0
    read_only(app.ctx.dbs.metrics, False)
    await recorder.flush()
    assert await app.ctx.dbs.metrics.read(total) == before + 5
