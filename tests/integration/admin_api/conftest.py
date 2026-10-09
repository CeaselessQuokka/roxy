"""Fixtures for the admin API integration tests (P9): the real app, a signed-in admin, and seeded metrics.

What this is
    The fixtures every `/admin/api/v1` test uses. Name test files `test_api_<area>.py` (test module names must be
    unique across the suite: the tests folders are not packages).
      * `api_app` (`ApiApp`): `create_app(env)` with its real lifespan over temporary databases (the root
        conftest's `env` and fake credentials), a `FakeClock`, a fast argon2 hasher and recorded mail
        (`roxy.admin.auth.testing.auth_harness`), Roblox played by `respx` (`api_app.roblox`; any unmocked
        outgoing request fails), the tarpit and the rotator off (a refusal would be held 8 to 20 s; tests that
        need them turn them on with `await api_app.settings(...)`). `api_app.ctx`, `.clock`, `.harness`
        (`AuthHarness`: `next_code`, `set_settings`, `allow_admin_cidr`, `mail`) and `.include(router)` (adds a
        router to the running app, after the admin catch-all, which steps aside for it) are there too.
      * `api_admin` (`TestAdmin`): an admin made with `roxy.admin.auth.testing.make_admin` (password, TOTP secret,
        recovery codes).
      * `api` (`ApiSession`): a client that signed in as `api_admin` through the real flow (password, then a TOTP
        code) and holds the `__Host-roxy_session` cookie. `await api.get(path, params=...)`,
        `api.post(path, json=...)`, `put`, `patch`, `delete` and `request(method, path, ...)` send the browser
        headers (`Origin`, `Sec-Fetch-Site: same-origin`, `Accept`) and, on POST, PUT, PATCH and DELETE, a fresh
        `X-CSRF-Token` (`csrf=False` leaves it out, `headers=` overrides). A `path` that does not start with
        `/admin` is relative to `/admin/api/v1`. The session has a fresh second factor right after the login:
        `api.make_mfa_stale()` moves the clock past `admin_reauth_window_s`, `await api.fresh_mfa()` re-enters a
        TOTP code (`POST /admin/api/v1/auth/reauth`, which rotates the session cookie and the CSRF secret).
      * `anon_api` (`ApiSession`): the same helpers on a client with no session (no CSRF token is sent).
      * `metrics_seed` (`MetricsSeeder`): `record(count, **fields)` feeds `OutcomeEvent`s (defaults: a served
        `GET games.roblox.com` at the clock's current time; any field can be overridden) to the real recorder,
        `event(type, ...)` records an `events` row, `outcome(**fields)` only builds the event, and
        `await metrics_seed.flush()` writes everything to metrics.db so the read models see it.
      * `api_json(response)`: the decoded body after checking the answer is JSON and `no-store`.
      * `section13(response, status, code)`: checks the DESIGN.md section 13 error shape and returns its fields.

Why it exists
    Four API specialists test against the same running app; one set of fixtures keeps their tests honest (the real
    guards, the real login, the real recorder and read models, no shortcuts that skip a check) and short.

How it works
    `auth_harness` starts the app and swaps in the cheap hasher and the recording notifier; the mail and webhook
    credentials are removed first, so the startup notifier only logs. The login is `AuthHarness.login` (password
    step, then the TOTP step with the next code), and the CSRF token comes from `GET /admin/api/v1/auth/session`,
    as the dashboard does. Every request comes from the trusted loopback peer with no `X-Forwarded-For`, unless
    `ip=` is given.

What to read next
    `roxy/admin/auth/testing.py` (the harness), `roxy/admin/api/common.py` (what the tests exercise),
    `tests/integration/test_pipeline_e2e.py` (the same app driven through the proxy).
"""

from __future__ import annotations

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
from roxy.core.reasons import AuthClass, CacheState, Egress, Outcome, ReasonCode, Source
from roxy.metrics.recorder import OutcomeEvent

API = "/admin/api/v1"
UNSAFE = frozenset({"POST", "PUT", "PATCH", "DELETE"})
TEMPLATE = "games.roblox.com/v1/games"
_UNSET: Any = object()


@dataclass
class ApiApp:
    """The running app for one test (see the module docstring)."""

    harness: AuthHarness
    roblox: Any  # the respx router playing Roblox

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

    async def settings(self, **values: Any) -> None:
        """Change settings through the real `SettingsService` (audited, `config_version` bumped) and reload."""
        service = SettingsService(self.ctx.dbs.control, runtime=self.ctx.settings, clock=self.clock)
        await service.update(values, Actor("cli", "test"), "admin api test setup")
        await self.ctx.settings.reload()

    def include(self, router: Any) -> None:
        """Add a router to the running app (the admin catch-all steps aside for routes added later)."""
        self.app.include_router(router)


@dataclass
class ApiSession:
    """One browser talking to the admin API (signed in when `admin` is set)."""

    owner: ApiApp
    http: httpx.AsyncClient
    admin: TestAdmin | None = None
    ip: str | None = None
    sent: list[httpx.Response] = field(default_factory=list)

    @staticmethod
    def url(path: str) -> str:
        return path if path.startswith("/admin") else f"{API}/{path.lstrip('/')}"

    def headers(self, *, csrf: str | None = None) -> dict[str, str]:
        return self.owner.harness.headers(ip=self.ip, csrf=csrf)

    async def csrf(self) -> str:
        """A fresh masked CSRF token for this session (as the dashboard reads it)."""
        return await self.owner.harness.csrf(client=self.http, ip=self.ip)

    async def request(
        self,
        method: str,
        path: str,
        *,
        json: Any = _UNSET,
        content: bytes | str | None = None,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        csrf: bool = True,
    ) -> httpx.Response:
        upper = method.upper()
        token = await self.csrf() if csrf and upper in UNSAFE and self.admin is not None else None
        sent = self.headers(csrf=token)
        sent.update(headers or {})
        kwargs: dict[str, Any] = {"headers": sent, "params": params}
        if json is not _UNSET:
            kwargs["json"] = json
        elif content is not None:
            kwargs["content"] = content
        response = await self.http.request(upper, self.url(path), **kwargs)
        self.sent.append(response)
        return response

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

    def make_mfa_stale(self) -> None:
        """Move the clock just past `admin_reauth_window_s`: the session lives on, its second factor is old."""
        window = int(self.owner.ctx.settings.int("admin_reauth_window_s"))
        self.owner.clock.advance(window + 1)

    async def fresh_mfa(self) -> httpx.Response:
        """Re-enter a TOTP code (`POST /auth/reauth`); the session cookie and CSRF secret rotate."""
        assert self.admin is not None, "an anonymous client cannot re-authenticate"
        code = self.owner.harness.next_code(self.admin)
        response = await self.post("/admin/api/v1/auth/reauth", json={"method": "totp", "code": code})
        assert response.status_code == 200, response.text
        return response


@dataclass
class MetricsSeeder:
    """Feeds the real recorder (DESIGN.md section 8) and flushes it, so the read models see real rows."""

    owner: ApiApp
    requests: int = 0

    def outcome(self, **fields: Any) -> OutcomeEvent:
        base: dict[str, Any] = {
            "at_ms": self.owner.clock.now_ms(),
            "request_id": f"SEED{self.requests:022d}",
            "endpoint_template": TEMPLATE,
            "host": "games.roblox.com",
            "method": "GET",
            "egress": Egress.DIRECT,
            "outcome": Outcome.SERVED_UPSTREAM,
            "reason": ReasonCode.UPSTREAM_OK,
            "status": 200,
            "source": Source.ROBLOX,
            "cache_state": CacheState.MISS,
            "auth_class": AuthClass.ANON,
            "caller_bytes_in": 100,
            "caller_bytes_out": 500,
            "upstream_calls": 1,
            "upstream_bytes_in": 900,
            "upstream_bytes_out": 300,
            "latency_ms": 40.0,
            "queue_wait_ms": 1.0,
            "upstream_ms": 30.0,
            "client_ip": "203.0.113.5",
            "place_id": "12345",
            "user_agent": "Roblox/WinInet",
            "bypass": False,
            "error": False,
        }
        base.update(fields)
        return OutcomeEvent(**base)

    def record(self, count: int = 1, **fields: Any) -> None:
        """Record `count` outcomes (each through `MetricsRecorder.record_outcome`, as the proxy does)."""
        for _ in range(count):
            self.owner.ctx.recorder.record_outcome(self.outcome(**fields))
            self.requests += 1

    def event(self, event_type: str, severity: str = "info", reason: str = "", detail: Any = None, **kw: Any) -> None:
        """Record one `events` row (`MetricsRecorder.record_event`)."""
        self.owner.ctx.recorder.record_event(event_type, severity, reason, detail or {}, **kw)

    async def flush(self) -> None:
        """Write everything recorded so far to metrics.db (the open minute included)."""
        await self.owner.ctx.recorder.flush()


@pytest.fixture
async def api_app(env: Any, fake_clock: FakeClock, credentials_dir: Path, respx_mock: Any) -> AsyncIterator[ApiApp]:
    """The running app (see the module docstring)."""
    for name in ("smtp_password", "alert_webhook_url"):
        (credentials_dir / name).unlink(missing_ok=True)  # the startup notifier only logs
    async with auth_harness(env, clock=fake_clock, credentials_dir=credentials_dir) as harness:
        running = ApiApp(harness=harness, roblox=respx_mock)
        await running.settings(tarpit_enabled=0, rotator_enabled=0)
        yield running


@pytest.fixture
def api_admin(api_app: ApiApp) -> TestAdmin:
    """An admin account with a password, a TOTP secret and recovery codes."""
    return api_app.harness.admin()


@pytest.fixture
async def api(api_app: ApiApp, api_admin: TestAdmin) -> ApiSession:
    """A client signed in as `api_admin` through the real password and TOTP flow."""
    session = ApiSession(owner=api_app, http=api_app.harness.http, admin=api_admin)
    response = await api_app.harness.login(api_admin)
    assert response.status_code == 200, response.text
    return session


@pytest.fixture
def anon_api(api_app: ApiApp) -> ApiSession:
    """A client with no session."""
    return ApiSession(owner=api_app, http=api_app.harness.new_client())


@pytest.fixture
def metrics_seed(api_app: ApiApp) -> MetricsSeeder:
    """Seeds metrics through the real recorder (see `MetricsSeeder`)."""
    return MetricsSeeder(owner=api_app)


def _json_body(response: httpx.Response) -> Any:
    assert response.headers.get("cache-control") == "no-store", dict(response.headers)
    assert response.headers.get("content-type", "").startswith("application/json"), response.headers
    return response.json()


def _section13(response: httpx.Response, status: int, code: str) -> dict[str, str]:
    assert response.status_code == status, (response.status_code, response.text)
    body = _json_body(response)
    assert set(body) == {"error"}, body
    error = body["error"]
    assert set(error) == {"code", "message", "fields"}, error
    assert error["code"] == code, error
    assert isinstance(error["message"], str), error
    assert error["message"], error
    fields: dict[str, str] = error["fields"]
    return fields


@pytest.fixture
def api_json() -> Any:
    """`api_json(response)`: the decoded JSON body of an admin API answer (checks JSON and no-store)."""
    return _json_body


@pytest.fixture
def section13() -> Any:
    """`section13(response, status, code)`: checks the DESIGN.md section 13 error object, returns its fields."""
    return _section13
