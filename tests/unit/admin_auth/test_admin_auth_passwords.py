"""Passwords (plan 9.5): argon2id parameters, the dummy hash, rehash detection, the queue bound and the policy."""

from __future__ import annotations

import asyncio
import threading

import pytest

from roxy.admin.auth.passwords import (
    ARGON2_MEMORY_KIB,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    MIN_PASSWORD_LENGTH,
    PRODUCTION_PARAMS,
    HashQueueFull,
    PasswordHasher,
    check_password_policy,
    common_passwords,
)
from roxy.admin.auth.testing import fast_hasher


def test_production_parameters_are_the_plan_values() -> None:
    assert (ARGON2_TIME_COST, ARGON2_MEMORY_KIB, ARGON2_PARALLELISM) == (3, 65536, 2)
    assert PRODUCTION_PARAMS.time_cost == 3
    assert PRODUCTION_PARAMS.memory_kib == 65536
    assert MIN_PASSWORD_LENGTH == 14


async def test_hash_and_verify() -> None:
    hasher = fast_hasher()
    encoded = await hasher.hash("a long and unusual passphrase")
    assert encoded.startswith("$argon2id$")
    assert (await hasher.verify(encoded, "a long and unusual passphrase")).ok
    assert not (await hasher.verify(encoded, "a long and unusual passphrasf")).ok


async def test_unknown_user_verifies_against_a_dummy_hash_and_fails() -> None:
    hasher = fast_hasher()
    calls: list[str] = []
    original = hasher.verify_sync

    def spy(encoded: str, secret: str) -> bool:
        calls.append(encoded)
        return original(encoded, secret)

    hasher.verify_sync = spy  # type: ignore[method-assign]
    result = await hasher.verify(None, "anything at all")
    assert result.ok is False
    assert len(calls) == 1
    assert calls[0].startswith("$argon2id$")


async def test_needs_rehash_when_parameters_change() -> None:
    cheap = fast_hasher()
    encoded = cheap.hash_sync("another long passphrase here")
    production = PasswordHasher()
    assert production.needs_rehash(encoded) is True
    assert cheap.needs_rehash(encoded) is False
    assert production.needs_rehash("not a hash") is True


async def test_queue_bound_refuses_immediately() -> None:
    gate = threading.Event()
    hasher = fast_hasher(capacity=1, max_queued=1)

    def slow(value: str) -> str:
        gate.wait(5)
        return value

    first = asyncio.create_task(hasher.run(slow, "a"))
    second = asyncio.create_task(hasher.run(slow, "b"))
    await asyncio.sleep(0.05)
    assert hasher.pending == 2
    with pytest.raises(HashQueueFull):
        await hasher.run(slow, "c")
    gate.set()
    assert await first == "a"
    assert await second == "b"
    assert hasher.pending == 0


async def test_delay_counts_as_pending() -> None:
    slept: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)

    hasher = fast_hasher(sleep=fake_sleep)
    assert await hasher.run(str.upper, "x", delay_s=5) == "X"
    assert slept == [5]


@pytest.mark.parametrize(
    ("password", "username", "fragment"),
    [
        ("short", None, "at least 14"),
        ("passwordpassword", None, "common passwords"),
        ("QWERTYUIOPASDFGHJKL", None, "common passwords"),
        ("owner-is-my-secret-word", "owner", "username"),
        ("aaaaaaaaaaaaaaaaaa", None, "repeats"),
        ("x" * 1025, None, "at most 1024"),
    ],
)
def test_password_policy_rejects(password: str, username: str | None, fragment: str) -> None:
    problems = check_password_policy(password, username)
    assert any(fragment in problem for problem in problems), problems


def test_password_policy_accepts_a_good_passphrase() -> None:
    assert check_password_policy("violet tractor ladder 7731", "owner") == []


def test_common_password_list_is_bundled_and_lowercase() -> None:
    entries = common_passwords()
    assert len(entries) > 1000
    assert "passwordpassword" in entries
    assert "1q2w3e4r5t6y7u8i" in entries
    assert all(entry == entry.lower() for entry in list(entries)[:500])
