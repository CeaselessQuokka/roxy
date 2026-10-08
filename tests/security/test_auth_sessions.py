"""Session security (plan 9.6, parity rows 98 to 101): no fixation, rotation on login and privilege change,
only hashes at rest, real revocation, the epoch kill switch, and the emailed kill switch revoking trusted
devices too (v1 bug B10)."""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from roxy.admin.auth import sessions, totp
from roxy.admin.auth.testing import AuthHarness, auth_harness
from roxy.core.clock import FakeClock

API = "/admin/api/v1/auth"


@pytest.fixture
async def harness(env: Any, fake_clock: FakeClock, credentials_dir: Path) -> AsyncIterator[AuthHarness]:
    async with auth_harness(env, clock=fake_clock, credentials_dir=credentials_dir) as running:
        yield running


def _with_cookie(harness: AuthHarness, token: str) -> dict[str, str]:
    return {**harness.headers(), "Cookie": f"{sessions.SESSION_COOKIE}={token}"}


async def _alive(harness: AuthHarness, token: str) -> bool:
    response = await harness.new_client().get(f"{API}/session", headers=_with_cookie(harness, token))
    return response.status_code == 200


async def test_login_never_adopts_a_planted_session_id(harness: AuthHarness) -> None:
    admin = harness.admin()
    planted = "attacker-chosen-session-id-" + "x" * 20
    victim = harness.new_client()
    headers = _with_cookie(harness, planted)  # the browser arrives carrying a value the attacker picked
    first = await victim.post(
        "/admin/api/v1/auth/login", json={"username": admin.username, "password": admin.password}, headers=headers
    )
    done = await victim.post(
        "/admin/api/v1/auth/mfa",
        json={"transaction": first.json()["Transaction"], "method": "totp", "code": harness.next_code(admin)},
        headers=headers,
    )
    assert done.status_code == 200
    issued = done.cookies.get(sessions.SESSION_COOKIE)
    assert issued
    assert issued != planted
    assert not await _alive(harness, planted)


async def test_login_rotates_away_a_session_the_browser_already_had(harness: AuthHarness) -> None:
    admin = harness.admin()
    attacker = harness.new_client()
    await harness.login(admin, client=attacker)
    attacker_token = str(attacker.cookies.get(sessions.SESSION_COOKIE))
    # The attacker plants their own valid session id in the victim's browser; the victim then logs in.
    victim_headers = _with_cookie(harness, attacker_token)
    first = await harness.http.post(
        "/admin/api/v1/auth/login",
        json={"username": admin.username, "password": admin.password},
        headers=victim_headers,
    )
    done = await harness.http.post(
        "/admin/api/v1/auth/mfa",
        json={"transaction": first.json()["Transaction"], "method": "totp", "code": harness.next_code(admin)},
        headers=victim_headers,
    )
    assert done.status_code == 200
    assert done.cookies.get(sessions.SESSION_COOKIE) != attacker_token
    assert not await _alive(harness, attacker_token)  # the planted session was ended, not upgraded


async def test_only_hashes_are_stored(harness: AuthHarness) -> None:
    admin = harness.admin()
    response = await harness.login(admin, trust=True)
    session_token = response.cookies.get(sessions.SESSION_COOKIE)
    trusted_token = response.cookies.get("__Host-roxy_trusted")
    await harness.drain()
    kill = re.search(r"/admin/invalidate/([A-Za-z0-9_-]+)", harness.mail.bodies("Roxy Admin Login")[0])
    assert kill is not None
    dump = "\n".join(harness.ctx.dbs.control.read_sync(lambda c: list(c.iterdump())))
    hot_dump = "\n".join(harness.ctx.dbs.hot.read_sync(lambda c: list(c.iterdump())))
    for secret in (
        session_token,
        trusted_token,
        kill.group(1),
        admin.password,
        admin.totp_secret,
        *admin.recovery_codes,
    ):
        assert secret
        assert secret not in dump, secret[:6]
        assert secret not in hot_dump, secret[:6]


async def test_reauth_and_enrollment_rotate_the_session(harness: AuthHarness) -> None:
    admin = harness.admin()
    await harness.login(admin)
    before = str(harness.http.cookies.get(sessions.SESSION_COOKIE))
    response = await harness.post(f"{API}/reauth", {"method": "totp", "code": harness.next_code(admin)})
    after = response.cookies.get(sessions.SESSION_COOKIE)
    assert after
    assert after != before
    assert not await _alive(harness, before)
    assert await _alive(harness, after)

    start = await harness.post(f"{API}/totp/enroll/start")
    secret = start.json()["Secret"]
    harness.clock.advance(30)
    confirm = await harness.post(f"{API}/totp/enroll/confirm", {"code": totp.code_at(secret, harness.clock.now())})
    rotated = confirm.cookies.get(sessions.SESSION_COOKIE)
    assert rotated
    assert rotated != after
    assert not await _alive(harness, after)


async def test_sign_out_everywhere_bumps_the_epoch(harness: AuthHarness) -> None:
    admin = harness.admin()
    others = [harness.new_client() for _ in range(3)]
    for client in others:
        await harness.login(admin, client=client)
    await harness.login(admin)
    tokens = [str(c.cookies.get(sessions.SESSION_COOKIE)) for c in others]
    before = harness.ctx.dbs.control.read_sync(sessions.read_epoch)
    assert (await harness.post(f"{API}/sessions/revoke-all")).status_code == 200
    assert harness.ctx.dbs.control.read_sync(sessions.read_epoch) == before + 1
    for token in tokens:
        assert not await _alive(harness, token)
    remaining = harness.ctx.dbs.control.read_sync(
        lambda c: c.execute("SELECT count(*) FROM admin_sessions").fetchone()[0]
    )
    assert remaining == 0


async def test_kill_switch_also_revokes_trusted_devices(harness: AuthHarness) -> None:
    admin = harness.admin()
    await harness.login(admin, trust=True)
    harness.http.cookies.delete(sessions.SESSION_COOKIE)
    skip = await harness.password_step(admin)
    assert skip.json().get("LoggedIn") is True  # the trusted device skips the second factor
    await harness.drain()
    body = harness.mail.bodies("Roxy Admin Login")[-1]
    path = re.search(r"http://localhost(/admin/invalidate/[A-Za-z0-9_-]+)", body)
    assert path is not None

    done = await harness.new_client().post(path.group(1), data={"all_sessions": "1", "revoke_trusted": "1"})
    assert done.status_code == 200
    assert (await harness.http.get(f"{API}/session", headers=harness.headers())).status_code == 401
    again = await harness.password_step(admin)  # same browser, same trusted cookie
    assert again.status_code == 200
    assert again.json().get("TwoFA") is True
    count = harness.ctx.dbs.control.read_sync(lambda c: c.execute("SELECT count(*) FROM trusted_devices").fetchone()[0])
    assert count == 0


async def test_kill_switch_without_the_option_keeps_trusted_devices(harness: AuthHarness) -> None:
    admin = harness.admin()
    await harness.login(admin, trust=True)
    await harness.drain()
    body = harness.mail.bodies("Roxy Admin Login")[-1]
    path = re.search(r"http://localhost(/admin/invalidate/[A-Za-z0-9_-]+)", body)
    assert path is not None
    await harness.new_client().post(path.group(1), data={"all_sessions": "1"})
    harness.http.cookies.delete(sessions.SESSION_COOKIE)
    assert (await harness.password_step(admin)).json().get("LoggedIn") is True
