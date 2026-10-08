"""CSRF (plan 9.4, 9.6): every state-changing auth route needs this session's token from Roxy's own origin;
tokens are masked per response (BREACH); malformed bodies are 400, never `{}`."""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.routing import APIRoute

from roxy.admin.auth import csrf, sessions
from roxy.admin.auth.routes import router
from roxy.admin.auth.testing import TEST_UA, AuthHarness, auth_harness
from roxy.core.clock import FakeClock

API = "/admin/api/v1/auth"
PRE_SESSION = {f"{API}/login", f"{API}/mfa", f"{API}/mfa/email", f"{API}/mfa/passkey/options"}
PATH_VALUES = {"{passkey_id}": "1", "{device_id}": "1", "{session_id}": "0" * 16}


@pytest.fixture
async def harness(env: Any, fake_clock: FakeClock, credentials_dir: Path) -> AsyncIterator[AuthHarness]:
    async with auth_harness(env, clock=fake_clock, credentials_dir=credentials_dir) as running:
        yield running


def _state_changing_paths() -> list[str]:
    paths = []
    for route in router.routes:
        if not isinstance(route, APIRoute) or "POST" not in route.methods:
            continue
        if route.path in PRE_SESSION or route.path.startswith("/admin/invalidate/"):
            continue
        path = route.path
        for placeholder, value in PATH_VALUES.items():
            path = path.replace(placeholder, value)
        paths.append(path)
    return paths


def test_route_inventory_is_complete() -> None:
    paths = _state_changing_paths()
    assert len(paths) >= 15
    assert f"{API}/logout" in paths
    assert f"{API}/sessions/revoke-all" in paths


async def test_every_state_changing_route_rejects_bad_csrf(harness: AuthHarness) -> None:
    admin = harness.admin()
    other = harness.new_client()
    await harness.login(admin, client=other)
    foreign_token = await harness.csrf(client=other)
    await harness.login(admin)
    good = await harness.csrf()
    base = {"User-Agent": TEST_UA, "Accept": "application/json"}
    variants = {
        "missing_token": {**base, "Origin": harness.site_origin},
        "malformed_token": {**base, "Origin": harness.site_origin, "X-CSRF-Token": "not-a-token"},
        "other_sessions_token": {**base, "Origin": harness.site_origin, "X-CSRF-Token": foreign_token},
        "foreign_origin": {**base, "Origin": "https://evil.example", "X-CSRF-Token": good},
        "cross_site_fetch": {**base, "Sec-Fetch-Site": "cross-site", "X-CSRF-Token": good},
        "no_origin_headers": {**base, "X-CSRF-Token": good},
    }
    for path in _state_changing_paths():
        for name, headers in variants.items():
            response = await harness.http.post(path, json={}, headers=headers)
            assert response.status_code == 403, (path, name, response.status_code, response.text)
    # Nothing happened: the session is still there.
    assert (await harness.http.get(f"{API}/session", headers=harness.headers())).status_code == 200


async def test_tokens_are_masked_differently_in_every_response(harness: AuthHarness) -> None:
    admin = harness.admin()
    await harness.login(admin)
    tokens = [await harness.csrf() for _ in range(10)]
    assert len(set(tokens)) == 10  # never the same string twice (BREACH)
    secret = sessions.csrf_secret(str(harness.http.cookies.get(sessions.SESSION_COOKIE)))
    assert all(csrf.unmask(token) == secret for token in tokens)
    for token in tokens[:3]:  # every masked form is accepted
        response = await harness.http.post(f"{API}/heartbeat", json={"idle_ms": 0}, headers=harness.headers(csrf=token))
        assert response.status_code == 200


async def test_pages_embed_a_fresh_masked_token(harness: AuthHarness) -> None:
    admin = harness.admin(with_totp=False, bootstrap=True)
    tx = (await harness.password_step(admin)).json()["Transaction"]
    await harness.mfa(tx, "email", code=harness.mail.bodies("Admin 2FA")[0].strip())
    pages = [await harness.http.get("/admin/enroll") for _ in range(3)]
    found = [re.search(r'<meta name="csrf-token" content="([^"]+)">', page.text) for page in pages]
    values = [m.group(1) for m in found if m is not None]
    assert len(values) == 3
    assert len(set(values)) == 3


async def test_foreign_origin_is_refused_on_reads_and_on_login(harness: AuthHarness) -> None:
    admin = harness.admin()
    await harness.login(admin)
    evil = {"Origin": "https://evil.example", "User-Agent": TEST_UA}
    assert (await harness.http.get(f"{API}/session", headers=evil)).status_code == 403
    login = await harness.http.post(f"{API}/login", json={"username": "a", "password": "b"}, headers=evil)
    assert login.status_code == 403
    cross = {"Sec-Fetch-Site": "cross-site", "User-Agent": TEST_UA}
    assert (
        await harness.http.post(f"{API}/login", json={"username": "a", "password": "b"}, headers=cross)
    ).status_code == 403


async def test_malformed_bodies_are_400_never_empty_objects(harness: AuthHarness) -> None:
    admin = harness.admin()
    await harness.login(admin)
    token = await harness.csrf()
    headers = harness.headers(csrf=token)
    for path, content in (
        (f"{API}/heartbeat", ""),
        (f"{API}/heartbeat", "[]"),
        (f"{API}/heartbeat", '{"idle_ms": -1}'),
        (f"{API}/reauth", "{}"),
        (f"{API}/reauth", '{"method": "totp", "code": "1", "surprise": true}'),
        (f"{API}/totp/enroll/confirm", "not json"),
    ):
        response = await harness.http.post(
            path, content=content, headers={**headers, "Content-Type": "application/json"}
        )
        assert response.status_code in (400, 403), (path, content, response.status_code)
        if path != f"{API}/totp/enroll/confirm":
            assert response.status_code == 400
            assert response.json() == "Invalid request"
