"""Fixtures for the dashboard page integration tests (P11): the real app in process, a signed-in admin, seeded data.

What this is
    The fixtures every `tests/integration/pages/test_page_<page>.py` uses (the folder is a package, see
    `__init__.py`):
      * `pages_app` (`PagesApp`): `create_app(env)` with its real lifespan over temporary databases (the root
        conftest's `env`, fake credentials and socket guard), a `FakeClock`, the fast password hasher and recorded
        mail of `roxy.admin.auth.testing.auth_harness`, and Roblox played by `respx` with
        `roxy.admin.pages.testing.roblox_answer` (JSON with hostile names, a 429 on `/too-many` paths, a 503 on
        `/fail` paths). The settings are `testing.SEED_SETTINGS` (no tarpit, no rotator, no upstream queue
        waits). `await pages_app.seed_traffic()` sends the harness's `traffic_plan()` through the REAL proxy
        (served, cached, refused, probed, Roblox 429 and 503, several IPs, places and User-Agents, the hostile
        text set) and flushes the recorder; `await pages_app.seed_all()` also writes audit rows with hostile text
        (through `SettingsService` and `config.audit.record`), an open recommendation and a finished health run.
        `pages_app.ctx`, `.clock`, `.harness` and `await pages_app.settings(**values)` are there too.
      * `page` (`PageSession`): a client signed in through the real password and TOTP steps. `await
        page.get("/admin/audit", params=...)` (HTML; `htmx=True` sends `HX-Request`), `await page.doc(path)`
        (200 checked, parsed with `roxy.admin.pages.testing.parse_html`: `doc.select("#log [data-table]")`),
        `await page.fragment("audit", "log", entry=1)`, `await page.api("PUT", "settings/cache_ttl_seconds",
        json={...})` (CSRF token added for unsafe methods; `csrf=False` leaves it out), `page.make_mfa_stale()` and
        `await page.fresh_mfa()`.
      * `anon` (`PageSession` without a session), `hostile` (the `HOSTILE` dict), `inert` (`assert_inert`).

Why it exists
    Seven page builders test against the same running app; one set of fixtures keeps their tests honest (the real
    guards, the real login, data that went through the real proxy and the real read models) and short. Nothing
    here opens a port: the app runs in process (httpx ASGI transport), so parallel test runs never collide.

How it works
    `auth_harness` starts the app and swaps in the cheap hasher; the login is `AuthHarness.login` (password step,
    then the TOTP step), the CSRF token comes from `GET /admin/api/v1/auth/session` as the dashboard reads it.
    Requests come from the trusted loopback peer; proxy traffic names its client in `X-Forwarded-For`.

What to read next
    `roxy/admin/pages/testing.py`, `tests/integration/pages/test_pages_core.py`, `tests/integration/pages/
    test_page_audit.py` (the reference page's tests), `.remake/P11_CONTRACT.md`.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import pytest

from roxy.admin.auth.testing import AuthHarness, TestAdmin, auth_harness
from roxy.admin.pages import testing
from roxy.config.audit import Actor
from roxy.config.settings_service import SettingsService
from roxy.core.clock import FakeClock

API = "/admin/api/v1"
UNSAFE = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_UNSET: Any = object()


def _roblox(request: httpx.Request) -> httpx.Response:
    status, headers, body = testing.roblox_answer(request.url.host, request.url.path)
    return httpx.Response(status, headers=headers, content=body)


@dataclass
class PagesApp:
    """The running app for one test (see the module docstring)."""

    harness: AuthHarness
    roblox: Any
    seeded: dict[str, Any] = field(default_factory=dict)

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
        """Change settings through the real `SettingsService` (audited) and reload."""
        service = SettingsService(self.ctx.dbs.control, runtime=self.ctx.settings, clock=self.clock)
        await service.update(values, Actor("cli", "test"), "pages test setup")
        await self.ctx.settings.reload()

    async def flush(self) -> None:
        cache = getattr(self.ctx, "cache", None)
        if cache is not None:
            await cache.settle()
        await self.ctx.recorder.flush()

    async def seed_traffic(self, plan: list[testing.PlannedRequest] | None = None) -> list[int]:
        """Send the seeding plan through the real proxy (in process) and flush; returns the statuses."""
        client = self.harness.new_client()
        statuses = []
        for item in plan if plan is not None else testing.traffic_plan():
            response = await client.request(item.method, item.path, headers=testing.request_headers(item))
            statuses.append(response.status_code)
        await self.flush()
        self.seeded["statuses"] = statuses
        return statuses

    async def seed_all(self) -> dict[str, Any]:
        """Traffic, audit rows, a recommendation and a health run (see the module docstring)."""
        await self.seed_traffic()
        self.seeded["audit"] = await testing.seed_audit(self.ctx, self.clock)
        self.seeded["recommendation"] = await testing.seed_recommendation(self.ctx, self.clock)
        self.seeded["health_run"] = await testing.seed_health_run(self.ctx, self.clock)
        await self.flush()
        return self.seeded


@dataclass
class PageSession:
    """One browser talking to the dashboard (signed in when `admin` is set)."""

    owner: PagesApp
    http: httpx.AsyncClient
    admin: TestAdmin | None = None

    async def csrf(self) -> str:
        return await self.owner.harness.csrf(client=self.http)

    async def get(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        htmx: bool = False,
        headers: Mapping[str, str] | None = None,
    ) -> httpx.Response:
        sent = self.owner.harness.headers()
        sent["Accept"] = "text/html"
        if htmx:
            sent["HX-Request"] = "true"
        sent.update(headers or {})
        return await self.http.get(path, params=params, headers=sent)

    async def doc(self, path: str, **kwargs: Any) -> testing.Node:
        """GET a page or fragment, check it answered 200 HTML, and parse it."""
        response = await self.get(path, **kwargs)
        assert response.status_code == 200, (path, response.status_code, response.text[:500])
        assert response.headers.get("content-type", "").startswith("text/html"), response.headers
        return testing.parse_html(response.text)

    async def fragment(self, page_id: str, card_id: str, **params: Any) -> httpx.Response:
        return await self.get(f"/admin/{page_id}/fragment/{card_id}", params=params or None, htmx=True)

    async def api(
        self,
        method: str,
        path: str,
        *,
        json: Any = _UNSET,
        params: Mapping[str, Any] | None = None,
        csrf: bool = True,
        headers: Mapping[str, str] | None = None,
    ) -> httpx.Response:
        upper = method.upper()
        token = await self.csrf() if csrf and upper in UNSAFE and self.admin is not None else None
        sent = self.owner.harness.headers(csrf=token)
        sent.update(headers or {})
        kwargs: dict[str, Any] = {"headers": sent, "params": params}
        if json is not _UNSET:
            kwargs["json"] = json
        url = path if path.startswith("/admin") else f"{API}/{path.lstrip('/')}"
        return await self.http.request(upper, url, **kwargs)

    def make_mfa_stale(self) -> None:
        """Move the clock just past `admin_reauth_window_s` (the session lives on, its second factor is old)."""
        window = int(self.owner.ctx.settings.int("admin_reauth_window_s"))
        self.owner.clock.advance(window + 1)

    async def fresh_mfa(self) -> httpx.Response:
        assert self.admin is not None
        code = self.owner.harness.next_code(self.admin)
        response = await self.api("POST", "/admin/api/v1/auth/reauth", json={"method": "totp", "code": code})
        assert response.status_code == 200, response.text
        return response


@pytest.fixture
async def pages_app(env: Any, fake_clock: FakeClock, credentials_dir: Path, respx_mock: Any) -> AsyncIterator[PagesApp]:
    """The running app (see the module docstring)."""
    for name in ("smtp_password", "alert_webhook_url"):
        (credentials_dir / name).unlink(missing_ok=True)  # the startup notifier only logs
    respx_mock.route(host__regex=r"(?:[a-z0-9-]+\.)*roblox\.com").mock(side_effect=_roblox)
    async with auth_harness(env, clock=fake_clock, credentials_dir=credentials_dir) as harness:
        running = PagesApp(harness=harness, roblox=respx_mock)
        await running.settings(**testing.SEED_SETTINGS)
        yield running


@pytest.fixture
def page_admin(pages_app: PagesApp) -> TestAdmin:
    """An admin account with a password, a TOTP secret and recovery codes."""
    return pages_app.harness.admin()


@pytest.fixture
async def page(pages_app: PagesApp, page_admin: TestAdmin) -> PageSession:
    """A client signed in as `page_admin` through the real password and TOTP flow."""
    session = PageSession(owner=pages_app, http=pages_app.harness.http, admin=page_admin)
    response = await pages_app.harness.login(page_admin)
    assert response.status_code == 200, response.text
    return session


@pytest.fixture
def anon(pages_app: PagesApp) -> PageSession:
    """A client with no session."""
    return PageSession(owner=pages_app, http=pages_app.harness.new_client())


@pytest.fixture
def hostile() -> dict[str, str]:
    """The hostile caller text set (`roxy.admin.pages.testing.HOSTILE`)."""
    return dict(testing.HOSTILE)


@pytest.fixture
def inert() -> Any:
    """`inert(html, where)`: fails when hostile text reached the page as markup (`testing.assert_inert`)."""
    return testing.assert_inert
