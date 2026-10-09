"""Fixtures for the v1 parity tests (plan 19.11): the real app, Roblox played by respx, and a signed-in admin.

What this is
    The `parity` fixture (`ParityApp`) used by every `tests/parity/test_v1_<area>.py` file. It starts
    `create_app(env)` with its real lifespan over temporary databases through `roxy.admin.auth.testing.auth_harness`
    (fast argon2 hasher, a `FakeClock`, a notifier whose mail is recorded instead of sent), with Roblox played by
    the root conftest's `respx_mock` (any unmocked outgoing request fails), and the tarpit and the rotator off, as
    the v1 smoke suite ran (it switched the tarpit off right after import).

Why it exists
    Each test here ports one v1 smoke check that no other v2 test covered. They drive the same doors the v1 suite
    used (a proxied request, an admin API call, a setting change) and look at the same evidence (status, body,
    headers, the upstream calls, the alerts sent), so `tests/V1_PARITY.md` can point at them.

How it works
    - `parity.proxy(method, path, ip=..., headers=...)` sends a caller request; every call gets its own client
      address unless `ip` is given (the peer is the trusted loopback proxy, so `X-Forwarded-For` is the client).
    - `parity.admin()` signs an admin in through the real password and TOTP steps and returns an `AdminClient`
      whose `get`, `post`, `put`, `patch` and `delete` send the browser headers and a fresh CSRF token.
    - `parity.settings(**values)` changes settings through the audited `SettingsService`; `parity.rule(table, row)`
      creates a rule through `RulesService` (both reload the worker's snapshot).
    - `parity.mail` is the recorded mail (`subjects()`), `parity.last()` the newest outcome record of the Live ring.

What to read next
    `tests/V1_PARITY.md` (which rows these tests cover), `roxy/admin/auth/testing.py` (the harness underneath),
    `tests/integration/test_pipeline_e2e.py` (the end-to-end tests these follow).
"""

from __future__ import annotations

import itertools
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import pytest

from roxy.admin.auth.testing import AuthHarness, TestAdmin, auth_harness
from roxy.config.audit import Actor
from roxy.config.settings_service import SettingsService
from roxy.core.clock import FakeClock
from roxy.rules.service import RulesService

API = "/admin/api/v1"
UNSAFE = frozenset({"POST", "PUT", "PATCH", "DELETE"})
ADMIN_ACTOR = Actor("admin", "parity")
NETS = ("192.0.2", "198.51.100", "203.0.113")  # documentation ranges (RFC 5737): never real clients


@dataclass
class AdminClient:
    """A browser signed in as an admin (the real login), talking to the admin API."""

    owner: ParityApp
    http: httpx.AsyncClient
    account: TestAdmin

    @staticmethod
    def url(path: str) -> str:
        return path if path.startswith("/admin") else f"{API}/{path.lstrip('/')}"

    async def request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> httpx.Response:
        upper = method.upper()
        harness = self.owner.harness
        token = await harness.csrf(client=self.http) if upper in UNSAFE else None
        sent = harness.headers(csrf=token)
        sent.update(headers or {})
        kwargs: dict[str, Any] = {"headers": sent, "params": params}
        if json is not None or upper in UNSAFE:
            kwargs["json"] = {} if json is None else json
        return await self.http.request(upper, self.url(path), **kwargs)

    async def get(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", path, **kwargs)

    async def post(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", path, **kwargs)

    async def put(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self.request("PUT", path, **kwargs)

    async def patch(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self.request("PATCH", path, **kwargs)

    async def delete(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self.request("DELETE", path, **kwargs)


@dataclass
class ParityApp:
    """The running app for one parity test (see the module docstring)."""

    harness: AuthHarness
    roblox: Any  # the respx router playing Roblox
    _ips: Any = field(default_factory=itertools.count)

    @property
    def app(self) -> Any:
        return self.harness.app

    @property
    def ctx(self) -> Any:
        return self.harness.ctx

    @property
    def clock(self) -> FakeClock:
        clock: FakeClock = self.harness.clock
        return clock

    @property
    def http(self) -> httpx.AsyncClient:
        client: httpx.AsyncClient = self.harness.http
        return client

    @property
    def mail(self) -> Any:
        return self.harness.mail

    def ip(self) -> str:
        """A client address no other request in this test has used."""
        n = next(self._ips)
        return f"{NETS[n // 254 % len(NETS)]}.{n % 254 + 1}"

    async def proxy(
        self,
        method: str,
        path: str,
        *,
        ip: str | None = None,
        headers: Mapping[str, str] | None = None,
        client: httpx.AsyncClient | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        """A caller request (an API client's User-Agent, its own address unless `ip` is given)."""
        sent = {"User-Agent": "Roblox/Linux", "X-Forwarded-For": ip or self.ip()}
        sent.update(headers or {})
        return await (client or self.http).request(method, path, headers=sent, **kwargs)

    async def get(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self.proxy("GET", path, **kwargs)

    async def settings(self, **values: Any) -> None:
        service = SettingsService(self.ctx.dbs.control, runtime=self.ctx.settings, clock=self.clock)
        await service.update(values, ADMIN_ACTOR, "parity test setup")
        await self.ctx.settings.reload()

    def rules(self) -> RulesService:
        return RulesService(self.ctx.dbs.control, clock=self.clock, store=self.ctx.rules)

    async def rule(self, table: str, row: Mapping[str, Any]) -> Any:
        created = await self.rules().create(table, dict(row), ADMIN_ACTOR, "parity test setup")
        await self.ctx.rules.reload()
        return created

    def last(self) -> dict[str, Any]:
        """The outcome record of the latest proxy request (the newest Live row)."""
        rows = self.ctx.recorder.live.snapshot(limit=1)
        assert rows, "no outcome was recorded"
        return dict(rows[0])

    async def admin(self) -> AdminClient:
        """Sign a new admin in through the real password and TOTP steps, on its own browser."""
        account = self.harness.admin(username=f"owner{next(self._ips)}")
        http = self.harness.new_client()
        response = await self.harness.login(account, client=http)
        assert response.status_code == 200, response.text
        return AdminClient(owner=self, http=http, account=account)


@pytest.fixture
async def parity(env: Any, fake_clock: FakeClock, credentials_dir: Path, respx_mock: Any) -> AsyncIterator[ParityApp]:
    """The running app (see the module docstring)."""
    for name in ("smtp_password", "alert_webhook_url"):
        (credentials_dir / name).unlink(missing_ok=True)  # the startup notifier only logs
    async with auth_harness(env, clock=fake_clock, credentials_dir=credentials_dir) as harness:
        running = ParityApp(harness=harness, roblox=respx_mock)
        await running.settings(tarpit_enabled=0, rotator_enabled=0)
        yield running
