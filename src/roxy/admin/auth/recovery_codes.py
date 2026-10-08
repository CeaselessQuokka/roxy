"""Recovery codes: ten single-use codes that stand in for the authenticator app when the phone is lost.

What this is
    `generate()` makes 10 codes like `7KQ2-M9XD-4TPA-W3HN`; `hash_codes` turns them into the stored form;
    `find_entry`, `mark_used` and `remaining` check and spend one. The codes are shown once, at enrollment or
    regeneration, and only their argon2id hashes are kept in `admin_users.recovery_codes_hash_json` (plan 9.5).

Why it exists
    TOTP is mandatory (owner decision D5), so a lost phone must not mean a lost admin panel. Each code works once,
    and a stolen database does not reveal them (argon2id, like passwords).

How it works
    - A code is 16 characters of Crockford base32 (no I, L, O or U, so it reads aloud and types cleanly), shown in
      four groups. The first group is a public lookup id; the whole code is the secret. With the id the server
      verifies ONE stored hash instead of trying all ten, which would cost ten 250 ms argon2 runs per attempt.
    - Input is normalized before checking: case, spaces and dashes do not matter, and the letters O, I and L are
      read as 0, 1 and 1.
    - Spending a code is a compare-and-set inside one control.db write transaction (`mark_used`): two parallel
      logins with the same code cannot both succeed.

What to read next
    `roxy/admin/auth/passwords.py` (the hasher used here), then `roxy/admin/auth/enrollment.py` (where codes are
    created) and `roxy/admin/auth/flow.py` (where they are spent).
"""

from __future__ import annotations

import json
import secrets
import sqlite3
from dataclasses import dataclass
from typing import Any

from roxy.admin.auth.passwords import PasswordHasher

ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
"""Crockford base32: 32 symbols, 5 bits each, without the easily confused I, L, O and U."""

CODE_COUNT = 10
CODE_LENGTH = 16  # 80 bits: 20 bits of lookup id plus 60 secret bits, then argon2id on top
GROUP = 4
ID_LENGTH = 4
LOW_REMAINING = 3
"""When this few codes are left the dashboard suggests generating a new set."""

_READ_AS = {"O": "0", "I": "1", "L": "1"}


@dataclass(frozen=True, slots=True)
class RecoveryEntry:
    """One stored recovery code: its public id, its argon2id hash, and when it was used (None if unused)."""

    id: str
    hash: str
    used_at: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"id": self.id, "hash": self.hash, "used_at": self.used_at}


def _random_code(prefix: str | None = None) -> str:
    body = prefix or "".join(secrets.choice(ALPHABET) for _ in range(ID_LENGTH))
    body += "".join(secrets.choice(ALPHABET) for _ in range(CODE_LENGTH - ID_LENGTH))
    return "-".join(body[i : i + GROUP] for i in range(0, CODE_LENGTH, GROUP))


def generate(count: int = CODE_COUNT) -> list[str]:
    """`count` fresh codes whose lookup ids are all different."""
    codes: list[str] = []
    seen: set[str] = set()
    while len(codes) < count:
        code = _random_code()
        ident = code[:ID_LENGTH]
        if ident in seen:
            continue
        seen.add(ident)
        codes.append(code)
    return codes


def normalize(code: str) -> str | None:
    """The 16 canonical characters of a typed code, or None when it cannot be a recovery code."""
    if not isinstance(code, str) or len(code) > 64:
        return None
    text = "".join(ch for ch in code.upper() if ch not in " -\t")
    text = "".join(_READ_AS.get(ch, ch) for ch in text)
    if len(text) != CODE_LENGTH or any(ch not in ALPHABET for ch in text):
        return None
    return text


def lookup_id(normalized: str) -> str:
    """The public lookup id of a normalized code."""
    return normalized[:ID_LENGTH]


async def hash_codes(hasher: PasswordHasher, codes: list[str]) -> list[RecoveryEntry]:
    """Stored entries for `codes` (each hashed off the event loop, one after another)."""
    entries: list[RecoveryEntry] = []
    for code in codes:
        normalized = normalize(code)
        if normalized is None:  # pragma: no cover - generate() only makes valid codes
            raise ValueError("not a recovery code")
        entries.append(RecoveryEntry(lookup_id(normalized), await hasher.hash(normalized)))
    return entries


def hash_codes_sync(hasher: PasswordHasher, codes: list[str]) -> list[RecoveryEntry]:
    """Same as `hash_codes` on the calling thread (`scripts/create_admin.py`)."""
    entries: list[RecoveryEntry] = []
    for code in codes:
        normalized = normalize(code)
        if normalized is None:  # pragma: no cover
            raise ValueError("not a recovery code")
        entries.append(RecoveryEntry(lookup_id(normalized), hasher.hash_sync(normalized)))
    return entries


def dumps(entries: list[RecoveryEntry]) -> str:
    """The JSON stored in `admin_users.recovery_codes_hash_json`."""
    return json.dumps([entry.as_dict() for entry in entries], separators=(",", ":"))


def loads(text: str | None) -> list[RecoveryEntry]:
    """Parse the stored JSON (a damaged value reads as no codes at all)."""
    if not text:
        return []
    try:
        raw = json.loads(text)
    except ValueError:
        return []
    entries: list[RecoveryEntry] = []
    if isinstance(raw, list):
        for item in raw[: CODE_COUNT * 2]:
            if isinstance(item, dict) and isinstance(item.get("id"), str) and isinstance(item.get("hash"), str):
                used = item.get("used_at")
                entries.append(RecoveryEntry(item["id"], item["hash"], used if isinstance(used, int) else None))
    return entries


def find_entry(entries: list[RecoveryEntry], normalized: str) -> RecoveryEntry | None:
    """The unused entry whose id matches the code, or None."""
    ident = lookup_id(normalized)
    for entry in entries:
        if entry.id == ident and entry.used_at is None:
            return entry
    return None


def remaining(entries: list[RecoveryEntry]) -> int:
    """How many codes are still unused."""
    return sum(1 for entry in entries if entry.used_at is None)


def mark_used(conn: sqlite3.Connection, user_id: int, code_id: str, code_hash: str, now: int) -> int | None:
    """Spend one code inside the caller's control.db write transaction. Returns codes left, or None if already used.

    Compare-and-set: the row is re-read inside the write lock, and the entry must still be unused and still carry
    the hash that was verified (a regenerated set in between makes this fail).
    """
    row = conn.execute("SELECT recovery_codes_hash_json FROM admin_users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        return None
    entries = loads(row[0])
    updated: list[RecoveryEntry] = []
    spent = False
    for entry in entries:
        if not spent and entry.id == code_id and entry.hash == code_hash and entry.used_at is None:
            updated.append(RecoveryEntry(entry.id, entry.hash, now))
            spent = True
        else:
            updated.append(entry)
    if not spent:
        return None
    conn.execute("UPDATE admin_users SET recovery_codes_hash_json = ? WHERE id = ?", (dumps(updated), user_id))
    return remaining(updated)
