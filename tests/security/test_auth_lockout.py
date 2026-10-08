"""Login lockout (plan 9.5, C6): counted atomically BEFORE the password is checked, per (username, network),
for every worker at once; second factor failures count too; a busy hasher never locks the owner out."""

from __future__ import annotations

import asyncio
import threading
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


def _count_verifications(harness: AuthHarness) -> list[int]:
    calls: list[int] = []
    lock = threading.Lock()
    original = harness.hasher.verify_sync

    def counting(encoded: str, secret: str) -> bool:
        with lock:
            calls.append(1)
        return original(encoded, secret)

    harness.hasher.verify_sync = counting  # type: ignore[method-assign]
    return calls


async def test_parallel_guesses_cannot_pass_the_limit(harness: AuthHarness) -> None:
    admin = harness.admin()
    calls = _count_verifications(harness)
    responses = await asyncio.gather(
        *(harness.password_step(admin, password=f"wrong guess number {i}", ip="203.0.113.10") for i in range(12))
    )
    statuses = sorted(r.status_code for r in responses)
    assert statuses.count(403) == 5
    assert statuses.count(429) == 7
    assert len(calls) == 5  # exactly max_failures passwords were ever checked
    locked = next(r for r in responses if r.status_code == 429)
    assert locked.json() == "Too many attempts; try again in 600 seconds."
    assert locked.headers["Retry-After"] == "600"
    # Even the right password is refused while locked, before any hashing.
    right = await harness.password_step(admin, ip="203.0.113.10")
    assert right.status_code == 429
    assert len(calls) == 5


async def test_two_workers_share_one_count(env: Any, fake_clock: FakeClock, credentials_dir: Path) -> None:
    """Two app instances (separate connections and writer threads, like two worker processes) on one hot.db."""
    async with (
        auth_harness(env, clock=fake_clock, credentials_dir=credentials_dir) as first,
        auth_harness(env, clock=fake_clock, credentials_dir=credentials_dir) as second,
    ):
        admin = first.admin()
        calls_a = _count_verifications(first)
        calls_b = _count_verifications(second)
        attempts = [
            (first if i % 2 else second).password_step(admin, password=f"guess {i} is wrong", ip="203.0.113.10")
            for i in range(14)
        ]
        responses = await asyncio.gather(*attempts)
        assert sum(1 for r in responses if r.status_code == 403) == 5
        assert len(calls_a) + len(calls_b) == 5


async def test_lockout_is_per_username_and_network(harness: AuthHarness) -> None:
    admin = harness.admin()
    for i in range(5):
        await harness.password_step(admin, password=f"wrong {i} wrong wrong", ip="203.0.113.10")
    assert (await harness.password_step(admin, ip="203.0.113.99")).status_code == 429  # same /24
    assert (await harness.password_step(admin, ip="198.51.100.4")).status_code == 200  # another network
    other = harness.admin(username="second")
    assert (await harness.password_step(other, ip="203.0.113.10")).status_code == 200  # another username


async def test_window_slides(harness: AuthHarness) -> None:
    admin = harness.admin()
    for i in range(5):
        await harness.password_step(admin, password=f"wrong {i} wrong wrong", ip="203.0.113.10")
        harness.clock.advance(60)
    locked = await harness.password_step(admin, ip="203.0.113.10")
    assert locked.status_code == 429
    assert locked.json() == "Too many attempts; try again in 300 seconds."
    harness.clock.advance(301)  # the first failure left the window: one slot is free again
    assert (await harness.password_step(admin, ip="203.0.113.10")).status_code == 200


async def test_second_factor_failures_count_and_success_clears(harness: AuthHarness) -> None:
    admin = harness.admin()
    for _ in range(2):
        tx = (await harness.password_step(admin, ip="203.0.113.10")).json()["Transaction"]
        for _ in range(2):
            assert (await harness.mfa(tx, "totp", code="000000", ip="203.0.113.10")).status_code == 404
    tx = (await harness.password_step(admin, ip="203.0.113.10")).json()["Transaction"]
    assert (await harness.mfa(tx, "totp", code="000000", ip="203.0.113.10")).status_code == 404
    # Five second factor failures: the next attempt of any kind is locked out.
    assert (await harness.mfa(tx, "totp", code=harness.next_code(admin), ip="203.0.113.10")).status_code == 429
    assert (await harness.password_step(admin, ip="203.0.113.10")).status_code == 429


async def test_success_resets_the_count(harness: AuthHarness) -> None:
    admin = harness.admin()
    for i in range(4):
        await harness.password_step(admin, password=f"wrong {i} wrong wrong", ip="203.0.113.10")
    assert (await harness.login(admin, ip="203.0.113.10")).status_code == 200
    for i in range(4):
        assert (await harness.password_step(admin, password=f"again {i} wrong", ip="203.0.113.10")).status_code == 403


async def test_queue_full_refusal_does_not_count_as_a_failure(harness: AuthHarness) -> None:
    admin = harness.admin()
    gate = threading.Event()
    original = harness.hasher.verify_sync

    def blocked(encoded: str, secret: str) -> bool:
        gate.wait(5)
        return original(encoded, secret)

    harness.hasher.verify_sync = blocked  # type: ignore[method-assign]
    waiting = [
        asyncio.create_task(harness.password_step(admin, password=f"slow {i}", ip=f"198.51.{i}.1")) for i in range(6)
    ]
    await asyncio.sleep(0.2)
    refused = await harness.password_step(admin, ip="203.0.113.10")
    assert refused.status_code == 429
    assert refused.json() == "Too many attempts; try again in 5 seconds."
    gate.set()
    await asyncio.gather(*waiting)
    harness.hasher.verify_sync = original  # type: ignore[method-assign]
    # The refused attempt gave its slot back: five real tries remain for that network.
    for i in range(5):
        assert (await harness.password_step(admin, password=f"no {i} no no", ip="203.0.113.10")).status_code == 403
    assert (await harness.password_step(admin, ip="203.0.113.10")).status_code == 429


async def test_lockout_audit_rows_are_bounded(harness: AuthHarness) -> None:
    admin = harness.admin()
    for i in range(12):
        await harness.password_step(admin, password=f"wrong {i} wrong wrong", ip="203.0.113.10")
    rows = harness.ctx.dbs.control.read_sync(
        lambda c: c.execute("SELECT action FROM audit_log WHERE action LIKE 'auth.%' ORDER BY id").fetchall()
    )
    assert [r[0] for r in rows] == ["auth.login_failed", "auth.lockout"]
