"""Cookie flags (plan 9.6, parity rows 98, 100): `__Host-` prefix, Secure, HttpOnly, SameSite=Strict, Path=/, no
Domain; the session cookie lives only as long as the browser; dead cookies are cleared; admin answers are no-store."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from roxy.admin.auth.testing import AuthHarness, auth_harness
from roxy.core.clock import FakeClock

API = "/admin/api/v1/auth"


@pytest.fixture
async def harness(env: Any, fake_clock: FakeClock, credentials_dir: Path) -> AsyncIterator[AuthHarness]:
    async with auth_harness(env, clock=fake_clock, credentials_dir=credentials_dir) as running:
        yield running


def _cookie(response: Any, name: str) -> dict[str, str]:
    for raw in response.headers.get_list("set-cookie"):
        first, *attributes = [part.strip() for part in raw.split(";")]
        if first.startswith(f"{name}="):
            parsed = {"value": first.split("=", 1)[1]}
            for attribute in attributes:
                key, _, value = attribute.partition("=")
                parsed[key.lower()] = value
            return parsed
    raise AssertionError(f"no Set-Cookie for {name}: {response.headers.get_list('set-cookie')}")


def _assert_host_cookie(cookie: dict[str, str]) -> None:
    assert "secure" in cookie
    assert "httponly" in cookie
    assert cookie["samesite"].lower() == "strict"
    assert cookie["path"] == "/"
    assert "domain" not in cookie


async def test_session_and_trusted_cookie_flags(harness: AuthHarness) -> None:
    admin = harness.admin()
    response = await harness.login(admin, trust=True)
    session = _cookie(response, "__Host-roxy_session")
    _assert_host_cookie(session)
    assert "max-age" not in session
    assert "expires" not in session
    assert len(session["value"]) >= 43  # 256 random bits
    trusted = _cookie(response, "__Host-roxy_trusted")
    _assert_host_cookie(trusted)
    assert trusted["max-age"] == str(30 * 86400)
    seen = _cookie(response, "roxy_admin_seen")
    assert seen["value"] == "1"
    assert "secure" in seen
    assert "httponly" in seen
    assert response.headers["cache-control"] == "no-store"


async def test_logout_and_dead_sessions_clear_the_cookie(harness: AuthHarness) -> None:
    admin = harness.admin()
    await harness.login(admin)
    out = await harness.post(f"{API}/logout")
    cleared = _cookie(out, "__Host-roxy_session")
    assert cleared["value"] in ("", '""')
    assert cleared.get("max-age") == "0" or "expires" in cleared
    _assert_host_cookie(cleared)
    dead = await harness.http.get(
        f"{API}/session", headers={**harness.headers(), "Cookie": "__Host-roxy_session=x" * 1}
    )
    assert dead.status_code == 401
    assert _cookie(dead, "__Host-roxy_session").get("max-age") == "0"


async def test_admin_responses_are_never_cached(harness: AuthHarness) -> None:
    for path in ("/admin", "/admin/invalidate/token"):
        response = await harness.http.get(path)
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["referrer-policy"] == "no-referrer"  # the kill-switch token never leaks
