"""argon2 never runs on the event loop thread (plan 9.5): every hash and verification of a login, a recovery
code and an enrollment happens on a worker thread, so a slow hash cannot freeze the worker."""

from __future__ import annotations

import threading
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from roxy.admin.auth import totp
from roxy.admin.auth.testing import AuthHarness, auth_harness
from roxy.core.clock import FakeClock

API = "/admin/api/v1/auth"


@pytest.fixture
async def harness(env: Any, fake_clock: FakeClock, credentials_dir: Path) -> AsyncIterator[AuthHarness]:
    async with auth_harness(env, clock=fake_clock, credentials_dir=credentials_dir) as running:
        yield running


async def test_argon2_runs_off_the_loop_thread(harness: AuthHarness) -> None:
    loop_thread = threading.get_ident()
    seen: list[int] = []
    real = harness.hasher._argon2

    class Spy:
        """Stands in for argon2's hasher and records which thread each call runs on."""

        def hash(self, *args: Any, **kwargs: Any) -> str:
            seen.append(threading.get_ident())
            return str(real.hash(*args, **kwargs))

        def verify(self, *args: Any, **kwargs: Any) -> bool:
            seen.append(threading.get_ident())
            return bool(real.verify(*args, **kwargs))

        def check_needs_rehash(self, encoded: str) -> bool:
            return bool(real.check_needs_rehash(encoded))

    admin = harness.admin()  # the test account is hashed synchronously on purpose, before the spy
    harness.hasher._argon2 = Spy()  # type: ignore[assignment]
    try:
        await harness.password_step(admin, username="nobody-here")  # unknown user: dummy hash and verify
        tx = (await harness.password_step(admin)).json()["Transaction"]
        assert (await harness.mfa(tx, "recovery", code=admin.recovery_codes[0])).status_code == 200
        start = await harness.post(f"{API}/totp/enroll/start")
        harness.clock.advance(30)
        code = totp.code_at(start.json()["Secret"], harness.clock.now())
        assert (await harness.post(f"{API}/totp/enroll/confirm", {"code": code})).status_code == 200
    finally:
        harness.hasher._argon2 = real
    assert len(seen) >= 14  # dummy hash, 3 verifications, 10 recovery code hashes
    assert loop_thread not in seen
