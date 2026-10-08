"""The global login guard (plan 9.5): beyond `admin_login_global_max_per_min` attempts are slowed, never
refused; allowlisted networks and trusted devices are exempt from both the delay and the count; it alerts once."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from roxy.admin.auth.testing import AuthHarness, auth_harness
from roxy.core.clock import FakeClock


@pytest.fixture
async def harness(env: Any, fake_clock: FakeClock, credentials_dir: Path) -> AsyncIterator[AuthHarness]:
    async with auth_harness(env, clock=fake_clock, credentials_dir=credentials_dir) as running:
        yield running


@pytest.fixture
def delays(harness: AuthHarness) -> list[float]:
    recorded: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        recorded.append(seconds)

    harness.hasher._sleep = fake_sleep
    return recorded


async def test_guard_slows_but_never_refuses(harness: AuthHarness, delays: list[float]) -> None:
    await harness.set_settings(admin_login_global_max_per_min=3, admin_login_global_delay_s=4)
    admin = harness.admin()
    for i in range(10):  # a distributed attack: every attempt from its own network
        response = await harness.password_step(admin, password=f"guess {i} wrong", ip=f"198.51.{i}.1")
        assert response.status_code == 403  # checked (slowly), never refused
    assert delays == [4.0] * 7
    real = await harness.password_step(admin, ip="203.0.113.50")
    assert real.status_code == 200
    assert real.json()["TwoFA"] is True
    assert delays[-1] == 4.0

    await harness.drain()
    assert harness.mail.subjects().count("Roxy: login attempts throttled globally") == 1
    audit = harness.ctx.dbs.control.read_sync(
        lambda c: c.execute("SELECT count(*) FROM audit_log WHERE action = 'auth.global_guard'").fetchone()[0]
    )
    assert audit == 1


async def test_allowlisted_network_is_exempt_and_not_counted(harness: AuthHarness, delays: list[float]) -> None:
    await harness.set_settings(admin_login_global_max_per_min=2, admin_login_global_delay_s=5)
    await harness.allow_admin_cidr("203.0.113.0/24")  # on the list; the allowlist switch itself stays off
    admin = harness.admin()
    for i in range(5):
        await harness.password_step(admin, password=f"guess {i} wrong", ip=f"198.51.{i}.1")
    delayed_so_far = len(delays)
    assert delayed_so_far == 3
    for _ in range(3):
        exempt = await harness.password_step(admin, ip="203.0.113.7")
        assert exempt.status_code == 200
    assert len(delays) == delayed_so_far  # no delay for the allowlisted network
    count = harness.ctx.dbs.hot.read_sync(
        lambda c: c.execute("SELECT count FROM login_failures WHERE subject = 'global'").fetchone()[0]
    )
    assert count == 5  # and its attempts were not counted


async def test_trusted_device_is_exempt(harness: AuthHarness, delays: list[float]) -> None:
    admin = harness.admin()
    assert (await harness.login(admin, ip="203.0.113.7", trust=True)).status_code == 200
    await harness.set_settings(admin_login_global_max_per_min=1, admin_login_global_delay_s=5)
    harness.clock.advance(61)  # a fresh one-minute window for the guard
    for i in range(4):
        await harness.password_step(admin, password=f"guess {i} wrong", ip=f"198.51.{i}.1", client=harness.new_client())
    before = len(delays)
    assert before == 3
    trusted = await harness.password_step(admin, ip="192.0.2.44")  # this browser holds the trusted cookie
    assert trusted.status_code == 200
    assert trusted.json()["LoggedIn"] is True
    assert len(delays) == before
