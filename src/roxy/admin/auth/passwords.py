"""Admin passwords: argon2id hashing that never blocks the event loop, and the password policy.

What this is
    `PasswordHasher`, which hashes and verifies admin passwords (and recovery codes) with argon2id in a thread
    pool, and `check_password_policy`, which rejects short or common passwords before one is ever stored.

Why it exists
    argon2id is deliberately slow and memory hungry (64 MiB and about 250 ms per hash on the server, plan 9.5),
    which is what makes a stolen hash expensive to crack. The same property is dangerous inside an asyncio
    server: the event loop is ONE thread that serves every request of this worker. A 250 ms hash run on that
    thread freezes every other request (proxy traffic included) for 250 ms, and ten parallel login attempts would
    freeze it for 2.5 s and claim 640 MiB of memory on a box that has under 1 GiB. CPU-heavy work must leave the
    event loop: here it runs on a worker thread through `anyio.to_thread.run_sync`, and a per-worker
    `CapacityLimiter(2)` lets at most two hashes run at once. When the queue behind those two is already 4 deep,
    further attempts are refused at once with the lockout-style 429 instead of piling up (plan 9.5).
    Timing: verifying a password against a hash takes the same time whether the password is right or wrong
    (argon2's comparison is constant time). For a username that does not exist there is no hash to verify, so
    the hasher verifies against a dummy hash instead; otherwise the fast "no such user" answer would tell an
    attacker which usernames exist.

How it works
    - Parameters are fixed by the plan (`time_cost=3`, `memory_cost=65536` KiB, `parallelism=2`). A stored hash
      made with other parameters still verifies; `needs_rehash` then tells the login flow to store a new one.
    - `pending` counts hashes that are running or waiting in this worker. The event loop thread is the only one
      that changes it, so it needs no lock.
    - An optional `delay_s` (the global login slow-down, `lockout.py`) is spent while counted as pending, so a
      flood of slowed attempts still fills the queue and gets refused instead of growing without bound.
    - The policy: at least 14 characters, at most 1024, not on the bundled list of common passwords
      (`common_passwords.txt`, loaded on first use), and not containing the username.

What to read next
    `roxy/admin/auth/lockout.py` (what happens before a hash is attempted), then `roxy/admin/auth/flow.py`.
"""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from functools import cache
from importlib import resources
from typing import TypeVar

import anyio
import anyio.to_thread
from argon2 import PasswordHasher as _Argon2Hasher
from argon2 import Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

T = TypeVar("T")

# Plan 9.5 parameters. They are protocol facts of the stored hashes, not runtime tunables: changing them only
# makes new hashes differ (old ones keep verifying and are rehashed on the next login).
ARGON2_TIME_COST = 3
ARGON2_MEMORY_KIB = 65536
ARGON2_PARALLELISM = 2
ARGON2_HASH_LEN = 32
ARGON2_SALT_LEN = 16

HASH_CONCURRENCY = 2
"""Hashes that may run at the same time in one worker (plan 9.5: `CapacityLimiter(2)`)."""

MAX_QUEUED_HASHES = 4
"""Hashes that may wait behind the running ones before new attempts are refused (plan 9.5)."""

BUSY_RETRY_AFTER_S = 5
"""Seconds a refused (queue full) attempt is told to wait."""

MIN_PASSWORD_LENGTH = 14
MAX_PASSWORD_LENGTH = 1024  # bounds the work per attempt (plan P9); no real password is longer


@dataclass(frozen=True, slots=True)
class Argon2Params:
    """argon2id cost parameters. Production uses `PRODUCTION_PARAMS`; tests use a cheap set."""

    time_cost: int = ARGON2_TIME_COST
    memory_kib: int = ARGON2_MEMORY_KIB
    parallelism: int = ARGON2_PARALLELISM


PRODUCTION_PARAMS = Argon2Params()


class HashQueueFull(Exception):
    """Too many hashes are already queued in this worker; the attempt is refused without hashing (plan 9.5)."""

    retry_after_s = BUSY_RETRY_AFTER_S


@dataclass(frozen=True, slots=True)
class VerifyResult:
    """Whether a password matched, and whether its stored hash should be replaced with current parameters."""

    ok: bool
    needs_rehash: bool = False


class PasswordHasher:
    """argon2id off the event loop, with this worker's capacity limiter and queue bound (see module docstring)."""

    def __init__(
        self,
        params: Argon2Params = PRODUCTION_PARAMS,
        *,
        capacity: int = HASH_CONCURRENCY,
        max_queued: int = MAX_QUEUED_HASHES,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.params = params
        self.capacity = capacity
        self.max_queued = max_queued
        self._sleep = sleep
        self._argon2 = _Argon2Hasher(
            time_cost=params.time_cost,
            memory_cost=params.memory_kib,
            parallelism=params.parallelism,
            hash_len=ARGON2_HASH_LEN,
            salt_len=ARGON2_SALT_LEN,
            type=Type.ID,
        )
        # Created on first use, inside the running event loop (anyio binds a limiter to the loop that uses it).
        self._limiter: anyio.CapacityLimiter | None = None
        self.pending = 0
        self._dummy_hash: str | None = None

    # ------------------------------------------------------------------------------------------------ plumbing

    def _get_limiter(self) -> anyio.CapacityLimiter:
        if self._limiter is None:
            self._limiter = anyio.CapacityLimiter(self.capacity)
        return self._limiter

    def check_capacity(self) -> None:
        """Raise `HashQueueFull` now if a new hash could not even queue (lets callers refuse before any work)."""
        if self.pending >= self.capacity + self.max_queued:
            raise HashQueueFull()

    async def run(self, fn: Callable[..., T], *args: object, delay_s: float = 0.0) -> T:
        """Run `fn(*args)` on a worker thread under the capacity limiter, after an optional delay.

        Raises `HashQueueFull` immediately when `capacity + max_queued` hashes are already pending here.
        """
        self.check_capacity()
        self.pending += 1
        try:
            if delay_s > 0:
                await self._sleep(delay_s)
            # The thread pool runs fn; the limiter makes the third concurrent caller wait for a free token.
            return await anyio.to_thread.run_sync(fn, *args, limiter=self._get_limiter())
        finally:
            self.pending -= 1

    # ------------------------------------------------------------------------------------------------ hashing

    def hash_sync(self, secret: str) -> str:
        """Hash on the calling thread. For scripts (`create_admin.py`) only; servers use `hash`."""
        return self._argon2.hash(secret)

    def verify_sync(self, encoded: str, secret: str) -> bool:
        """Verify on the calling thread (scripts and the worker thread itself). Never raises for a mismatch."""
        try:
            return bool(self._argon2.verify(encoded, secret))
        except (VerifyMismatchError, VerificationError, InvalidHashError, ValueError, TypeError):
            return False

    def needs_rehash(self, encoded: str) -> bool:
        """True when `encoded` was made with other parameters than this hasher's (plan 9.5: rehash on login)."""
        try:
            return bool(self._argon2.check_needs_rehash(encoded))
        except (InvalidHashError, ValueError):
            return True

    async def hash(self, secret: str, *, delay_s: float = 0.0) -> str:
        """argon2id hash of `secret`, computed off the event loop."""
        return await self.run(self._argon2.hash, secret, delay_s=delay_s)

    async def verify(self, encoded: str | None, secret: str, *, delay_s: float = 0.0) -> VerifyResult:
        """Verify `secret` against `encoded` off the event loop.

        `encoded=None` (an unknown username) verifies against the dummy hash and always fails, so the answer
        takes as long as a real wrong password.
        """
        target = encoded if encoded else await self.dummy_hash()
        ok = await self.run(self.verify_sync, target, secret, delay_s=delay_s)
        if not encoded:
            return VerifyResult(ok=False)
        return VerifyResult(ok=ok, needs_rehash=ok and self.needs_rehash(encoded))

    async def dummy_hash(self) -> str:
        """A real argon2id hash of a random value nobody knows, made once per worker."""
        if self._dummy_hash is None:
            # Hashed outside the queue bound on purpose: it happens once, and refusing it would refuse a login.
            value = secrets.token_urlsafe(24)
            self._dummy_hash = await anyio.to_thread.run_sync(self._argon2.hash, value, limiter=self._get_limiter())
        return self._dummy_hash


# ------------------------------------------------------------------------------------------------------ policy


@cache
def common_passwords() -> frozenset[str]:
    """The bundled list of common passwords (lowercase), loaded once on first use."""
    text = resources.files("roxy.admin.auth").joinpath("common_passwords.txt").read_text(encoding="utf-8")
    return frozenset(
        line.strip().lower() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")
    )


def check_password_policy(password: str, username: str | None = None) -> list[str]:
    """Problems with a new password (an empty list means it is acceptable)."""
    problems: list[str] = []
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"Use at least {MIN_PASSWORD_LENGTH} characters.")
    if len(password) > MAX_PASSWORD_LENGTH:
        problems.append(f"Use at most {MAX_PASSWORD_LENGTH} characters.")
    lowered = password.lower()
    if lowered in common_passwords() or lowered.strip() in common_passwords():
        problems.append("This password is on the list of common passwords; choose a less predictable one.")
    if username and len(username) >= 3 and username.lower() in lowered:
        problems.append("The password must not contain the username.")
    if password and len(set(password)) <= 2:
        problems.append("The password repeats the same one or two characters; choose a less predictable one.")
    return problems
