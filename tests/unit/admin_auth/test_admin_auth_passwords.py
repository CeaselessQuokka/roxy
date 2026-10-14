"""Passwords (plan 9.5): argon2id parameters, the dummy hash, rehash detection, the queue bound and the policy."""

from __future__ import annotations

import asyncio
import threading
from typing import Any

import pytest

from auth_harness import fast_hasher
from roxy.admin.auth.passwords import (
    ARGON2_MEMORY_KIB,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    HASH_CONCURRENCY,
    MAX_QUEUED_HASHES,
    MIN_PASSWORD_LENGTH,
    PRODUCTION_PARAMS,
    RESERVED_EXEMPT_HASHES,
    HashQueueFull,
    PasswordHasher,
    check_password_policy,
    common_passwords,
)

OWASP_MIN_MEMORY_KIB = 19456
"""OWASP's argon2id minimum (19 MiB with t=2, p=1); the production set must never go below it."""


def test_production_parameters_fit_the_909_mb_server() -> None:
    """Finding sec-2: plan 9.5's 64 MiB with two hashes per worker (256 MiB a color under a login burst) did not fit
    the headroom a warm color has under `MemoryMax=500M` (about 95 MiB, DESIGN.md section 0). One 19 MiB hash per
    worker does (about 40 MiB for 2 workers; tests/review_final/test_security.py measures the real burst)."""
    assert (ARGON2_TIME_COST, ARGON2_MEMORY_KIB, ARGON2_PARALLELISM) == (3, 19456, 1)
    assert (PRODUCTION_PARAMS.time_cost, PRODUCTION_PARAMS.memory_kib, PRODUCTION_PARAMS.parallelism) == (3, 19456, 1)
    assert ARGON2_MEMORY_KIB >= OWASP_MIN_MEMORY_KIB
    assert (HASH_CONCURRENCY, MAX_QUEUED_HASHES, RESERVED_EXEMPT_HASHES) == (1, 4, 2)
    workers = 2  # ROXY_WORKERS on the server
    assert workers * HASH_CONCURRENCY * ARGON2_MEMORY_KIB <= 48 * 1024  # half the headroom; other peaks need the rest
    assert MIN_PASSWORD_LENGTH == 14


def test_a_plan_9_5_hash_still_verifies_and_is_rehashed() -> None:
    """A hash made with the old plan 9.5 parameters keeps working; the next login stores the new parameters."""
    old = PasswordHasher(type(PRODUCTION_PARAMS)(time_cost=3, memory_kib=65536, parallelism=2))
    encoded = old.hash_sync("an older but still good passphrase")
    production = PasswordHasher()
    assert production.verify_sync(encoded, "an older but still good passphrase")
    assert production.needs_rehash(encoded) is True


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


async def test_exempt_callers_pass_a_full_queue_within_their_reserve() -> None:
    """Finding sec-4 (plan 9.5): slowed or queued attempts of others fill `capacity + max_queued`; an exempt caller
    (admin allowlist, trusted device, signed-in admin) still gets in, up to `reserved` at a time, and still waits for
    the limiter, so no more than `capacity` hashes ever run at once."""
    gate = threading.Event()
    hasher = fast_hasher(capacity=1, max_queued=1, reserved=2)
    running = 0
    most = 0
    lock = threading.Lock()

    def slow(value: str) -> str:
        nonlocal running, most
        with lock:
            running += 1
            most = max(most, running)
        gate.wait(5)
        with lock:
            running -= 1
        return value

    others = [asyncio.create_task(hasher.run(slow, name)) for name in ("a", "b")]
    await asyncio.sleep(0.05)
    with pytest.raises(HashQueueFull):
        await hasher.run(slow, "c")  # the queue is full for everyone else
    owners = [asyncio.create_task(hasher.run(slow, name, exempt=True)) for name in ("owner", "owner again")]
    await asyncio.sleep(0.05)
    assert (hasher.pending, hasher.exempt_pending) == (4, 2)
    with pytest.raises(HashQueueFull):
        await hasher.run(slow, "a third at once", exempt=True)  # the reserve is bounded too (plan P9)
    with pytest.raises(HashQueueFull):
        await hasher.run(slow, "d")  # exempt callers never open the queue to others
    gate.set()
    assert [await task for task in others + owners] == ["a", "b", "owner", "owner again"]
    assert (hasher.pending, hasher.exempt_pending, most) == (0, 0, 1)


async def test_the_dummy_hash_is_made_once_inside_the_queue_bound() -> None:
    """Finding sec-6: a burst of unknown usernames at a fresh worker makes ONE dummy hash, on a worker thread, and
    the callers beyond the queue bound are refused before any hash (plan 9.5)."""
    hasher = fast_hasher()
    real = hasher._argon2
    made: list[int] = []
    loop_thread = threading.get_ident()

    class Counting:
        def __getattr__(self, name: str) -> Any:
            return getattr(real, name)

        def hash(self, value: str) -> str:
            assert threading.get_ident() != loop_thread
            made.append(1)
            return str(real.hash(value))

    hasher._argon2 = Counting()  # type: ignore[assignment]
    burst = HASH_CONCURRENCY + MAX_QUEUED_HASHES + 7
    results = await asyncio.gather(*(hasher.verify(None, f"guess {n}") for n in range(burst)), return_exceptions=True)
    assert sum(isinstance(result, HashQueueFull) for result in results) == 7
    assert all(result.ok is False for result in results if not isinstance(result, BaseException))
    assert made == [1]
    await hasher.verify(None, "one more guess later")
    assert made == [1]


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
