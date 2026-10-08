"""Uniform second factor failure (plan 9.5, parity row 96): every cause answers the same 404 `Not Found`, so a
response never tells an attacker which check failed."""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest

from roxy.admin.auth import totp
from roxy.admin.auth.testing import AuthHarness, SoftwarePasskey, auth_harness
from roxy.core.clock import FakeClock

API = "/admin/api/v1/auth"
VARYING_HEADERS = {"roxy-request-id", "date", "content-security-policy", "content-length", "server-timing"}


@pytest.fixture
async def harness(env: Any, fake_clock: FakeClock, credentials_dir: Path) -> AsyncIterator[AuthHarness]:
    async with auth_harness(env, clock=fake_clock, credentials_dir=credentials_dir) as running:
        yield running


def _shape(response: Any) -> tuple[int, bytes, str, frozenset[str]]:
    names = frozenset(name.lower() for name in response.headers) - VARYING_HEADERS
    return response.status_code, response.content, response.headers["content-type"], names


async def test_every_second_factor_failure_looks_identical(harness: AuthHarness) -> None:
    admin = harness.admin()
    assert admin.totp_secret is not None
    key = SoftwarePasskey()
    await harness.login(admin)
    options = await harness.post(f"{API}/passkeys/register/options")
    credential = key.register(options.json()["Options"], origin=harness.site_origin)
    assert (await harness.post(f"{API}/passkeys/register/verify", {"credential": credential})).status_code == 200

    async def fresh_tx() -> str:
        return str((await harness.password_step(admin, client=harness.new_client())).json()["Transaction"])

    async def wrong_totp() -> Any:
        return await harness.mfa(await fresh_tx(), "totp", code="000000")

    async def missing_tx() -> Any:
        return await harness.mfa("A" * 43, "totp", code="123456")

    async def other_ip() -> Any:
        return await harness.mfa(await fresh_tx(), "totp", code=harness.next_code(admin), ip="203.0.113.99")

    async def other_ua() -> Any:
        return await harness.mfa(await fresh_tx(), "totp", code=harness.next_code(admin), ua="curl/8.1")

    async def expired() -> Any:
        tx = await fresh_tx()
        harness.clock.advance(150)
        return await harness.mfa(tx, "totp", code=harness.next_code(admin))

    async def wrong_recovery() -> Any:
        return await harness.mfa(await fresh_tx(), "recovery", code="AAAA-BBBB-CCCC-DDDD")

    async def email_not_allowed() -> Any:
        return await harness.mfa(await fresh_tx(), "email", code="1234567812345678")

    async def replayed_totp() -> Any:
        assert admin.totp_secret is not None
        code = harness.next_code(admin)
        assert (await harness.mfa(await fresh_tx(), "totp", code=code)).status_code == 200
        return await harness.mfa(await fresh_tx(), "totp", code=code)

    async def forged_passkey() -> Any:
        client = harness.new_client()
        tx = (await harness.password_step(admin, client=client)).json()["Transaction"]
        opts = await client.post(f"{API}/mfa/passkey/options", json={"transaction": tx}, headers=harness.headers())
        forged = SoftwarePasskey()
        forged.credential_id = key.credential_id
        return await harness.mfa(
            tx,
            "passkey",
            credential=forged.authenticate(opts.json()["Options"], origin=harness.site_origin),
            client=client,
        )

    async def too_many_attempts() -> Any:
        tx = await fresh_tx()
        for _ in range(3):
            await harness.mfa(tx, "totp", code="000000")
        return await harness.mfa(tx, "totp", code=harness.next_code(admin))

    async def code_for_wrong_secret() -> Any:
        return await harness.mfa(await fresh_tx(), "totp", code=totp.code_at(totp.new_secret(), harness.clock.now()))

    cases: dict[str, Callable[[], Awaitable[Any]]] = {
        "wrong_totp": wrong_totp,
        "missing_transaction": missing_tx,
        "ip_mismatch": other_ip,
        "user_agent_mismatch": other_ua,
        "expired_transaction": expired,
        "wrong_recovery_code": wrong_recovery,
        "email_not_offered": email_not_allowed,
        "replayed_totp": replayed_totp,
        "forged_passkey": forged_passkey,
        "fourth_attempt": too_many_attempts,
        "other_secret": code_for_wrong_secret,
    }
    shapes = {}
    for name, case in cases.items():
        await harness.set_settings(admin_login_max_failures=100)  # keep the lockout out of this comparison
        shapes[name] = _shape(await case())
    reference = shapes["wrong_totp"]
    assert reference[0] == 404
    assert reference[1] == b'"Not Found"\n'
    assert reference[2].startswith("application/json")
    for name, shape in shapes.items():
        assert shape == reference, name


async def test_reauth_failures_are_the_same_404(harness: AuthHarness) -> None:
    admin = harness.admin()
    await harness.login(admin)
    wrong = await harness.post(f"{API}/reauth", {"method": "totp", "code": "000000"})
    recovery = await harness.post(f"{API}/reauth", {"method": "recovery", "code": "AAAA-BBBB-CCCC-DDDD"})
    for response in (wrong, recovery):
        assert response.status_code == 404
        assert response.content == b'"Not Found"\n'
