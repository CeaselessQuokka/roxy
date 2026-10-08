"""Adversarial review (multi-process and failure modes lens): plan C7 through the fully wired application.

What this is
    Tests that run the real app (lifespan, egress clients with their guard, credential manager, upstream, cache,
    abuse pipeline, recorder) with `respx` playing Roblox, and make a shared database read-only while it serves.
    They check what C7 promises when shared state cannot be written: the credential is not used, the tarpit does
    not hold, the per-IP limiter falls back to `limit / workers` in memory, and metrics degrade open (keep serving,
    flag the gap, write the numbers once the database is back). Two tests reproduced findings of the review
    (UP-COOLDOWN-LOST: `test_review_429_during_hot_outage_still_cools_down`; ALERT-CAP:
    `test_review_readonly_hot_alert_cap_still_holds`); both are fixed, so no test here is marked `xfail` any more.

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


@pytest.mark.parametrize("path", ["credential", "anonymous"])
async def test_review_429_during_hot_outage_still_cools_down(app: App, path: str) -> None:
    """Plan 7.5 and 7.9: Roblox says 429 with Retry-After 60 at the moment hot.db becomes read-only. Once hot.db
    is back (and long before 60 s passed), the endpoint must not be contacted again through that path.

    Finding UP-COOLDOWN-LOST (fixed): the cooldown used to be lost with the failed hot.db write. Now the caller
    gets the cooldown answer, the worker keeps the cooldown in memory (upstream and credential manager), and the
    next request shares it to hot.db for every worker before deciding, so it is refused with the time left."""
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
    # The caller learns about the 429 (never `degraded`: Roblox did answer), with Roblox's own wait.
    assert (first.status_code, first.headers.get("retry-after")) == (429, "60")
    assert first.headers.get("roxy-refusal") == "upstream_cooldown"
    read_only(hot, False)
    app.clock.advance(5)  # 5 s later: still well inside Roblox's Retry-After of 60 s
    if path == "credential":
        second = await app.get(f"/{ECONOMY}{CURRENCY}")
    else:
        second = await app.post(f"/{GAMES}/v1/games/multiget", json.dumps({"ids": [1]}).encode())
    print(f"\n{path}: first {first.status_code}, second {second.status_code}, calls {calls}")
    assert len(calls) == 1, f"Roblox was called again inside its Retry-After: {calls}"
    expected = (503, "credential_unavailable") if path == "credential" else (429, "upstream_cooldown")
    assert (second.status_code, second.headers.get("roxy-refusal")) == expected
    assert second.headers.get("retry-after") == "55"  # the cooldown's real remaining time
    # hot.db took the cooldown when it came back, so every other worker honors it too.
    egress = "credential" if path == "credential" else "direct"
    template = f"{ECONOMY}{CURRENCY}" if path == "credential" else f"{GAMES}/v1/games/multiget"

    def keys(conn: Any) -> set[str]:
        return {row[0] for row in conn.execute("SELECT key FROM cooldown WHERE until_ms > ?", (app.clock.now_ms(),))}

    shared = await hot.read(keys)
    assert any(key.startswith("endpoint:") and key.endswith(f":{egress}") and template in key for key in shared)
    if path == "credential":
        assert "credential" in shared


# -------------------------------------------------------------------------------------------------- alerts


async def test_review_readonly_hot_alert_cap_still_holds(app: App) -> None:
    """Finding ALERT-CAP (fixed). Plan 17.7: at most `alert_rate_limit_per_hour` messages per channel per hour
    (leak guard trips excepted). With hot.db read-only every worker falls back to its in-memory gate, which keeps
    the cap at its share (`cap // ROXY_WORKERS`), so 25 distinct alerts per worker on 2 workers still produce at
    most `cap` mails for the fleet; dedupe becomes per worker (each worker may send one copy per cooldown key);
    the next mail after the hour reports what was held back; a leak guard trip is never held back."""
    from pydantic import SecretStr

    from roxy.admin.auth.testing import RecordingTransport
    from roxy.notify.alerts import Alert
    from roxy.notify.mail import MailConfig, MailSender
    from roxy.notify.notifier import Notifier

    workers = int(app.ctx.env.workers)
    assert workers == 2
    transport = RecordingTransport()  # one owner mailbox for the whole fleet
    config = MailConfig(to_addr="owner@example.invalid", from_addr="alerts@example.invalid", password=SecretStr("x"))

    def worker_notifier() -> Notifier:
        return Notifier(
            hot_db=app.ctx.dbs.hot,
            settings=app.ctx.settings,
            site_origin="http://localhost",
            mail=MailSender(config, transport=transport),
            webhook=None,
            clock=app.clock,
            workers=workers,
        )

    fleet = [worker_notifier() for _ in range(workers)]
    cap = int(app.ctx.settings.get("alert_rate_limit_per_hour"))
    read_only(app.ctx.dbs.hot, True)
    for notifier in fleet:
        for n in range(cap + 5):
            alert = Alert(
                type="error", severity="critical", subject=f"Roxy: review {n}", summary="x", cooldown_key=f"r:{n}"
            )
            await notifier.send(alert)
    print(f"\ncap {cap}, workers {workers}, mails sent {len(transport.messages)}")
    assert len(transport.messages) <= cap, "the fleet stays within alert_rate_limit_per_hour"
    assert len(transport.messages) == workers * (cap // workers), "each worker used its whole share, no more"

    # Per worker dedupe: inside the cooldown, a key every worker has already sent goes out from nobody.
    for notifier in fleet:
        again = Alert(type="error", severity="critical", subject="Roxy: again", summary="x", cooldown_key="r:0")
        assert (await notifier.send(again)).skipped == "deduped"
    transport.messages.clear()
    app.clock.advance(3600)  # a new hourly window
    # In the new window each worker sends again, and its first mail reports what its cap held back.
    for notifier in fleet:
        await notifier.send(
            Alert(type="error", severity="critical", subject="Roxy: new", summary="x", cooldown_key="n")
        )
    new = [body for body in transport.bodies() if "Suppressed since last alert" in body]
    assert new, transport.subjects()
    assert sum(1 for s in transport.subjects() if s == "Roxy: new") == workers  # one copy per worker, at most

    # The leak guard is never held back, even with every worker's cap used up.
    for _ in range(cap):
        await fleet[0].send(Alert(type="error", severity="critical", subject="Roxy: fill", summary="x"))
    leak = await fleet[0].send(
        Alert(type="leak_guard", severity="critical", subject="Roxy SECURITY: credential leak blocked", summary="x")
    )
    assert leak.sent == ("email",)


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
