"""Importing the v1 admin account (only with `--import-admin-password`): an argon2id hash and the email bootstrap.

What this is
    `import_admin(db, secrets, report, clock, enabled=...)` creates the v2 `admin_users` row for the v1 admin: the
    username, an argon2id hash of the v1 plain text password, the admin email from the v1 emails file, and
    `mfa_bootstrap_pending = 1`.

Why it exists
    Plan 18.3 and DESIGN.md section 0 (D5). v1 kept the admin password in plain text. v2 never stores a password,
    only an argon2id hash, and it hashes the v1 password only when the owner asks for it with
    `--import-admin-password` (otherwise the owner creates the account with `scripts/create_admin.py`). TOTP is
    mandatory in v2, so the imported account carries the one-time bootstrap flag: the first login uses the
    imported password plus a code emailed to the admin address, then forces TOTP enrollment, which clears the flag.

How it works
    The hasher is the admin auth module's own (`roxy.admin.auth.passwords.PasswordHasher` with its production
    parameters) when it is importable, otherwise `argon2-cffi` with the plan 9.5 parameters (time cost 3,
    64 MiB, parallelism 2), so a hash made here verifies exactly like one made at login. Hashing is CPU heavy, so
    it runs in a worker thread. The v2 password policy is checked and any problem is reported (the password is
    still imported, so the owner can sign in and change it). An account with the same username is never
    replaced: if the v1 password verifies against it the result is "already imported", otherwise it is kept and
    the report says so. An account an earlier run imported and the owner deleted since (the import ledger) is
    never created again: it would bring back the v1 password with an open email bootstrap. The audit row names
    the account and the hash parameters, never the hash.

What to read next
    `roxy/admin/auth/passwords.py`, `roxy/admin/auth/users.py`, and REMAKE_PLAN.md section 9.5.
"""

from __future__ import annotations

import asyncio
import importlib
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Final

from argon2 import PasswordHasher as Argon2Hasher
from argon2 import Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from roxy.config import audit
from roxy.core.clock import Clock
from roxy.migration.report import ALREADY, IMPORTED, KEPT, NOT_IMPORTED, REMOVED, SKIPPED, MigrationReport
from roxy.migration.rules_import import IMPORT_ACTOR, IMPORT_REASON
from roxy.migration.secrets_out import masked_email
from roxy.migration.v1_tree import V1Secrets
from roxy.storage.db import Database

PLAN_TIME_COST: Final = 3
PLAN_MEMORY_COST_KIB: Final = 65536
PLAN_PARALLELISM: Final = 2
_AUTH_PASSWORDS: Final = "roxy.admin.auth.passwords"
USERNAME_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}")
"""The v2 username rule (`roxy/admin/auth/users.py`): 1 to 64 letters, digits, `_`, `.`, `@` or `-`."""


@dataclass(frozen=True, slots=True)
class Hasher:
    """Synchronous argon2id hash and verify (called in a worker thread), plus where they came from."""

    hash: Callable[[str], str]
    verify: Callable[[str, str], bool]
    source: str
    time_cost: int
    memory_kib: int
    parallelism: int

    @property
    def parameters(self) -> str:
        return f"argon2id t={self.time_cost} m={self.memory_kib}KiB p={self.parallelism}"


def plan_hasher() -> Hasher:
    """argon2id with the plan 9.5 parameters (`argon2-cffi` directly)."""
    argon2 = Argon2Hasher(
        time_cost=PLAN_TIME_COST, memory_cost=PLAN_MEMORY_COST_KIB, parallelism=PLAN_PARALLELISM, type=Type.ID
    )

    def verify(encoded: str, secret: str) -> bool:
        try:
            return bool(argon2.verify(encoded, secret))
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    return Hasher(
        argon2.hash,
        verify,
        "argon2-cffi with the plan 9.5 parameters",
        PLAN_TIME_COST,
        PLAN_MEMORY_COST_KIB,
        PLAN_PARALLELISM,
    )


def choose_hasher() -> Hasher:
    """The admin auth module's hasher when it is importable (same parameters as a v2 login), else `plan_hasher`."""
    try:
        module: Any = importlib.import_module(_AUTH_PASSWORDS)
        params = module.PRODUCTION_PARAMS
        hasher = module.PasswordHasher(params)
        return Hasher(
            hasher.hash_sync,
            hasher.verify_sync,
            f"{_AUTH_PASSWORDS}.PasswordHasher (the login's own hasher)",
            int(params.time_cost),
            int(params.memory_kib),
            int(params.parallelism),
        )
    except (ImportError, AttributeError, TypeError):
        return plan_hasher()


def _policy_problems(password: str, username: str) -> list[str]:
    """The v2 password policy problems (`check_password_policy`), or the length rule alone without the module."""
    try:
        module: Any = importlib.import_module(_AUTH_PASSWORDS)
        problems = module.check_password_policy(password, username)
        return [str(problem) for problem in problems]
    except (ImportError, AttributeError, TypeError):
        return ["Use at least 14 characters."] if len(password) < 14 else []


async def import_admin(
    db: Database,
    v1: V1Secrets,
    report: MigrationReport,
    clock: Clock,
    *,
    enabled: bool,
    previously: frozenset[str] = frozenset(),
) -> set[str]:
    """Create the admin account from v1 (see the module docstring). Records the outcome in `report.admin`.

    `previously` holds the usernames an earlier run imported (the import ledger). Returns the usernames this run
    handled, for the ledger.
    """
    if not enabled:
        report.admin = {
            "status": NOT_IMPORTED,
            "detail": "run with --import-admin-password to import the v1 password as an argon2id hash, or create "
            "the account with scripts/create_admin.py",
        }
        return set()
    username = (v1.admin_username or "").strip()
    password = v1.admin_password
    if not username or not password:
        report.admin = {"status": SKIPPED, "detail": "the v1 admin credentials file has no username or password"}
        report.error("the admin account was not imported: the v1 credentials file has no username or password")
        return set()
    if not USERNAME_RE.fullmatch(username):
        report.admin = {
            "status": SKIPPED,
            "detail": "the v1 username is not a valid v2 username (1 to 64 letters, digits, _ . @ -); create the "
            "account with scripts/create_admin.py",
        }
        report.error("the admin account was not imported: the v1 username does not meet the v2 username rule")
        return set()
    notes: list[str] = []
    if username != (v1.admin_username or ""):
        notes.append("surrounding spaces were removed from the username")
    problems = _policy_problems(password, username)
    if problems:
        notes.append(
            "the v1 password does not meet the v2 policy (" + " ".join(problems) + "); change it after the first login"
        )
        report.warn("the imported admin password does not meet the v2 password policy; change it after the first login")
    email = v1.email_to
    if not email:
        notes.append("no admin email was found, so the emailed bootstrap code cannot be sent; add one by hand")
        report.warn("the admin account has no email address; the TOTP bootstrap needs one")

    existing = await db.read(
        lambda conn: conn.execute(
            "SELECT id, password_hash FROM admin_users WHERE username = ?", (username,)
        ).fetchone()
    )
    if existing is None and username in previously:
        report.admin = {
            "status": REMOVED,
            "username": username,
            "detail": f"account {username!r} was imported by an earlier run and deleted in v2 since; it was not "
            "created again",
        }
        return {username}
    hasher = choose_hasher()
    if existing is not None:
        # argon2 is CPU heavy: never on the event loop.
        matches = await asyncio.to_thread(hasher.verify, str(existing[1]), password)
        detail = f"account {username!r} (id {existing[0]}) already exists"
        detail += "" if matches else " with a different password; it was not changed"
        report.admin = {
            "status": ALREADY if matches else KEPT,
            "username": username,
            "id": int(existing[0]),
            "detail": detail,
        }
        return {username}

    encoded = await asyncio.to_thread(hasher.hash, password)
    now = int(clock.now())

    def write(conn: sqlite3.Connection) -> int:
        cursor = conn.execute(
            "INSERT INTO admin_users (username, password_hash, created_at, mfa_bootstrap_pending, email) "
            "VALUES (?, ?, ?, 1, ?)",
            (username, encoded, now, email),
        )
        user_id = int(cursor.lastrowid or 0)
        audit.record(
            conn,
            IMPORT_ACTOR,
            "admin_user.import",
            f"admin_user:{user_id}",
            None,
            {
                "username": username,
                "email": masked_email(email),
                "mfa_bootstrap_pending": 1,
                "hash_parameters": hasher.parameters,
            },
            IMPORT_REASON,
            None,
            at=now,
            secret=False,
        )
        return user_id

    user_id = await db.write(write)
    report.changed()
    report.admin = {
        "status": IMPORTED,
        "username": username,
        "id": user_id,
        "email": masked_email(email),
        "mfa_bootstrap_pending": True,
        "hasher": hasher.source,
        "hash_parameters": hasher.parameters,
        "detail": (
            f"account {username!r} created with an argon2id hash ({hasher.parameters}); the first login uses the "
            "v1 password plus an emailed code, then TOTP enrollment is required. "
            + " ".join(f"{note[0].upper()}{note[1:]}." for note in notes)
        ).strip(),
        "notes": notes,
    }
    return {username}


__all__ = ["USERNAME_RE", "Hasher", "choose_hasher", "import_admin", "plan_hasher"]
