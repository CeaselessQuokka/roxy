"""Admin passwords: argon2id hashing that never blocks the event loop, and the password policy.

What this is
    `PasswordHasher`, which hashes and verifies admin passwords (and recovery codes) with argon2id in a thread
    pool, and `check_password_policy`, which rejects short or common passwords before one is ever stored.

Why it exists
    argon2id is deliberately slow and memory hungry (19 MiB and tens of milliseconds per hash), which is what
    makes a stolen hash expensive to crack. The same property is dangerous inside an asyncio server: the event
    loop is ONE thread that serves every request of this worker. A hash run on that thread freezes every other
    request (proxy traffic included) for its whole duration, and parallel login attempts would freeze it longer
    and multiply the memory. CPU-heavy work must leave the event loop: here it runs on a worker thread through
    `anyio.to_thread.run_sync`, and a per-worker `CapacityLimiter(1)` lets one hash run at a time. When the queue
    behind it is already 4 deep, further attempts are refused at once with the lockout-style 429 instead of
    piling up (plan 9.5).
    Memory (the 909 MB server, DESIGN.md section 0): anyone can make Roxy hash (an unknown username verifies
    against a dummy hash), so the worst case `ROXY_WORKERS x HASH_CONCURRENCY x memory` must fit the headroom a
    warm color has under `MemoryMax` (about 95 MiB). The plan's 64 MiB with two hashes per worker would add 256
    MiB per color and get a worker OOM-killed (finding sec-2); 19 MiB with one hash per worker adds about 40 MiB.
    Timing: verifying a password against a hash takes the same time whether the password is right or wrong
    (argon2's comparison is constant time). For a username that does not exist there is no hash to verify, so
    the hasher verifies against a dummy hash instead; otherwise the fast "no such user" answer would tell an
    attacker which usernames exist.

How it works
    - Parameters: argon2id with `time_cost=3` (the plan's), `memory_cost=19456` KiB and `parallelism=1` (OWASP's
      argon2id minimum is 19 MiB with t=2, p=1; plan 9.5 had 64 MiB and p=2, sized for a 2 GB box). A stored hash
      made with other parameters still verifies; `needs_rehash` then tells the login flow to store a new one.
    - `pending` counts hashes that are sleeping, waiting or running in this worker. The event loop thread is the
      only one that changes it, so it needs no lock.
    - An optional `delay_s` (the global login slow-down, `lockout.py`) is spent while counted as pending, so a
      flood of slowed attempts still fills the queue and gets refused instead of growing without bound.
    - Exempt callers (the admin allowlist, a valid trusted device, a signed-in admin) never compete with that
      flood: they pass `exempt=True` and are admitted while fewer than `RESERVED_EXEMPT_HASHES` of their own are
      pending, whatever the queue holds (plan 9.5: the guard never locks the owner out; finding sec-4). They still
      wait for the one running hash, so memory stays bounded.
    - The dummy hash is made once per worker, on the worker thread, inside the queue bound: the first unknown
      username makes it under a lock and every other caller reuses it (finding sec-6).
    - The policy: at least 14 characters, at most 1024, not on the bundled list of common passwords
      (`common_passwords.txt`, loaded on first use), and not containing the username.

What to read next
    `roxy/admin/auth/lockout.py` (what happens before a hash is attempted), then `roxy/admin/auth/flow.py`.
"""

from __future__ import annotations

import asyncio
import secrets
import threading
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

# argon2id parameters, sized for the 909 MB server (see the module docstring; plan 9.5 had 65536 KiB and p=2).
# They are protocol facts of the stored hashes, not runtime tunables: changing them only makes new hashes differ
# (old ones keep verifying and are rehashed on the next login).
ARGON2_TIME_COST = 3
ARGON2_MEMORY_KIB = 19456
ARGON2_PARALLELISM = 1
ARGON2_HASH_LEN = 32
ARGON2_SALT_LEN = 16

HASH_CONCURRENCY = 1
"""Hashes that may run at the same time in one worker (plan 9.5 had 2; one keeps a login burst inside the
memory a warm color has left: `ROXY_WORKERS x HASH_CONCURRENCY x ARGON2_MEMORY_KIB`, finding sec-2)."""

MAX_QUEUED_HASHES = 4
"""Hashes that may wait behind the running ones before new attempts are refused (plan 9.5)."""

RESERVED_EXEMPT_HASHES = 2
"""Hashes exempt callers (admin allowlist, trusted device, signed-in admin) may have pending in one worker,
outside the queue bound, so a flood of other attempts never locks the owner out (plan 9.5, finding sec-4)."""

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
        reserved: int = RESERVED_EXEMPT_HASHES,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.params = params
        self.capacity = capacity
        self.max_queued = max_queued
        self.reserved = reserved
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
        # Every hash of this worker that is sleeping (`delay_s`), waiting for the limiter or running, and the part
        # of it exempt callers hold (bounded by `reserved`, not by the queue bound).
        self.pending = 0
        self.exempt_pending = 0
        self._dummy_hash: str | None = None
        # The dummy hash is made on a worker thread; with more than one thread a lock keeps it to one hash.
        self._dummy_lock = threading.Lock()

    # ------------------------------------------------------------------------------------------------ plumbing

    def _get_limiter(self) -> anyio.CapacityLimiter:
        if self._limiter is None:
            self._limiter = anyio.CapacityLimiter(self.capacity)
        return self._limiter

    def check_capacity(self, *, exempt: bool = False) -> None:
        """Raise `HashQueueFull` now if a new hash could not even queue (lets callers refuse before any work).

        Exempt callers have their own `reserved` slots: the queue may be full of other attempts (a flood) and the
        owner still gets in (plan 9.5). Everyone else shares `capacity + max_queued`.
        """
        if exempt:
            if self.exempt_pending >= self.reserved:
                raise HashQueueFull()
            return
        if self.pending - self.exempt_pending >= self.capacity + self.max_queued:
            raise HashQueueFull()

    async def run(self, fn: Callable[..., T], *args: object, delay_s: float = 0.0, exempt: bool = False) -> T:
        """Run `fn(*args)` on a worker thread under the capacity limiter, after an optional delay.

        Raises `HashQueueFull` immediately when `capacity + max_queued` hashes are already pending here (for an
        exempt caller: when `reserved` exempt hashes are).
        """
        self.check_capacity(exempt=exempt)
        self.pending += 1
        self.exempt_pending += 1 if exempt else 0
        try:
            if delay_s > 0:
                await self._sleep(delay_s)
            # The thread pool runs fn; the limiter makes every caller beyond `capacity` wait for a free token, so
            # exempt callers too: at most `capacity` argon2 buffers exist in this worker at any moment.
            return await anyio.to_thread.run_sync(fn, *args, limiter=self._get_limiter())
        finally:
            self.pending -= 1
            self.exempt_pending -= 1 if exempt else 0

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

    async def hash(self, secret: str, *, delay_s: float = 0.0, exempt: bool = False) -> str:
        """argon2id hash of `secret`, computed off the event loop (`exempt`: see `check_capacity`)."""
        return await self.run(self._argon2.hash, secret, delay_s=delay_s, exempt=exempt)

    async def verify(
        self, encoded: str | None, secret: str, *, delay_s: float = 0.0, exempt: bool = False
    ) -> VerifyResult:
        """Verify `secret` against `encoded` off the event loop (`exempt`: see `check_capacity`).

        `encoded=None` (an unknown username) verifies against the dummy hash and always fails, so the answer
        takes as long as a real wrong password. Both paths take a place in the queue bound first.
        """
        if not encoded:
            await self.run(self._verify_dummy, secret, delay_s=delay_s, exempt=exempt)
            return VerifyResult(ok=False)
        ok = await self.run(self.verify_sync, encoded, secret, delay_s=delay_s, exempt=exempt)
        return VerifyResult(ok=ok, needs_rehash=ok and self.needs_rehash(encoded))

    def dummy_hash_sync(self) -> str:
        """A real argon2id hash of a random value nobody knows, made once per worker (call on a worker thread).

        The lock makes it once even when several threads ask at the same moment; the callers are already inside
        the queue bound and the limiter (`verify` runs this through `run`), so a burst of unknown usernames at a
        fresh worker costs one extra hash, never one per request (finding sec-6).
        """
        with self._dummy_lock:
            if self._dummy_hash is None:
                self._dummy_hash = self._argon2.hash(secrets.token_urlsafe(24))
            return self._dummy_hash

    def _verify_dummy(self, secret: str) -> bool:
        """The unknown-username path on the worker thread: verify against the dummy hash (never a match)."""
        self.verify_sync(self.dummy_hash_sync(), secret)
        return False


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
