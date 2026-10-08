"""Passkeys (WebAuthn): optional, phishing-resistant second factor, with user verification required.

What this is
    Thin wrappers around the `py_webauthn` library: `registration_options` / `verify_registration` to add a
    passkey, `authentication_options` / `verify_authentication` to use one, and the control.db functions for
    `admin_passkeys` rows (`list_passkeys`, `insert_passkey`, `delete_passkey`, `update_sign_count`).

Why it exists
    Plan 9.5 (D5): passkeys are optional and preferred when enrolled. A passkey is a key pair kept by the
    device (or a password manager); the browser signs a fresh server challenge with it, and only for the site the
    key was made for, so a phishing page on another domain cannot get a usable signature. "User verification
    required" means the device must check the person too (fingerprint, face or device PIN), so a stolen unlocked
    laptop alone is not enough.

How it works
    - The relying party id is the host name of `ROXY_SITE_ORIGIN`, and the expected origin is that origin.
    - A challenge is 32 random bytes made by py_webauthn; the login flow keeps it in the login transaction, and
      registration keeps it in a short-lived hot.db record (`transactions.py`), so it works across workers.
    - The user handle given to authenticators is a hash of the admin id, never the username (no personal data
      on the device).
    - Every library error (bad signature, wrong origin, wrong challenge, replayed sign counter) becomes a plain
      "not verified": the caller turns it into the uniform 404.
    - Bounded: at most `MAX_PASSKEYS_PER_USER` passkeys per admin.

What to read next
    `roxy/admin/auth/flow.py` (passkey as the second factor), `roxy/admin/auth/enrollment.py` (adding one), and
    `roxy/static/js/auth.js` (the browser side).
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

log = logging.getLogger("roxy.admin.auth.webauthn")

RP_NAME = "Roxy Admin"
MAX_PASSKEYS_PER_USER = 10
TIMEOUT_MS = 120_000
MAX_NAME = 64


def rp_id_for(site_origin: str) -> str:
    """The relying party id: the host name of the site origin (`roxytheproxy.com`)."""
    return urlsplit(site_origin).hostname or "localhost"


def user_handle(user_id: int) -> bytes:
    """An opaque, stable handle for one admin (no username or other personal data)."""
    return hashlib.sha256(f"roxy-admin-user:{user_id}".encode()).digest()[:16]


@dataclass(frozen=True, slots=True)
class Passkey:
    id: int
    user_id: int
    credential_id: bytes
    public_key: bytes
    sign_count: int
    transports: list[str]
    name: str | None
    created_at: int
    last_used_at: int | None

    def public(self) -> dict[str, object]:
        """The fields the dashboard may show (never the key material)."""
        return {"Id": self.id, "Name": self.name, "CreatedAt": self.created_at, "LastUsedAt": self.last_used_at}


@dataclass(frozen=True, slots=True)
class NewPasskey:
    credential_id: bytes
    public_key: bytes
    sign_count: int
    transports: list[str]


def registration_options(
    *, rp_id: str, user_id: int, username: str, existing: list[bytes]
) -> tuple[dict[str, Any], bytes]:
    """Options for `navigator.credentials.create()` (as JSON-ready dict) and the challenge to remember."""
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=RP_NAME,
        user_name=username,
        user_id=user_handle(user_id),
        user_display_name=username,
        timeout=TIMEOUT_MS,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,  # "resident keys allowed" (plan 9.5)
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=cid) for cid in existing],
    )
    return json.loads(options_to_json(options)), options.challenge


def verify_registration(credential: dict[str, Any], *, challenge: bytes, rp_id: str, origin: str) -> NewPasskey | None:
    """The new passkey when the browser's answer is valid for `challenge`, else None."""
    try:
        verified = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            require_user_verification=True,
        )
    except Exception as exc:  # any library failure means "not verified"
        log.info("passkey_registration_rejected", extra={"fields": {"error": type(exc).__name__}})
        return None
    transports = credential.get("response", {}).get("transports") if isinstance(credential, dict) else None
    clean = [str(t)[:20] for t in transports[:8]] if isinstance(transports, list) else []
    return NewPasskey(verified.credential_id, verified.credential_public_key, verified.sign_count, clean)


def authentication_options(*, rp_id: str, credential_ids: list[bytes]) -> tuple[dict[str, Any], bytes]:
    """Options for `navigator.credentials.get()` and the challenge to remember."""
    options = generate_authentication_options(
        rp_id=rp_id,
        timeout=TIMEOUT_MS,
        allow_credentials=[PublicKeyCredentialDescriptor(id=cid) for cid in credential_ids],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return json.loads(options_to_json(options)), options.challenge


def credential_id_of(credential: dict[str, Any]) -> bytes | None:
    """The raw credential id the browser says it used (looked up before verifying)."""
    if not isinstance(credential, dict):
        return None
    raw = credential.get("rawId") or credential.get("id")
    if not isinstance(raw, str) or len(raw) > 1400:
        return None
    try:
        return base64url_to_bytes(raw)
    except Exception:
        return None


def verify_authentication(
    credential: dict[str, Any], *, challenge: bytes, rp_id: str, origin: str, passkey: Passkey
) -> int | None:
    """The new signature counter when the assertion is valid for `challenge` and `passkey`, else None."""
    try:
        verified = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=passkey.public_key,
            credential_current_sign_count=passkey.sign_count,
            require_user_verification=True,
        )
    except Exception as exc:
        log.info("passkey_assertion_rejected", extra={"fields": {"error": type(exc).__name__}})
        return None
    return int(verified.new_sign_count)


# ------------------------------------------------------------------------------------------------ storage


def _row(row: Any) -> Passkey:
    transports: list[str] = []
    if row[5]:
        try:
            loaded = json.loads(row[5])
            transports = [str(t) for t in loaded] if isinstance(loaded, list) else []
        except ValueError:
            transports = []
    return Passkey(
        id=int(row[0]),
        user_id=int(row[1]),
        credential_id=bytes(row[2]),
        public_key=bytes(row[3]),
        sign_count=int(row[4]),
        transports=transports,
        name=row[6],
        created_at=int(row[7]),
        last_used_at=int(row[8]) if row[8] is not None else None,
    )


_SELECT = (
    "SELECT id, user_id, credential_id, public_key, sign_count, transports, name, created_at, last_used_at "
    "FROM admin_passkeys"
)


def list_passkeys(conn: sqlite3.Connection, user_id: int) -> list[Passkey]:
    return [_row(r) for r in conn.execute(f"{_SELECT} WHERE user_id = ? ORDER BY id", (user_id,))]


def find_passkey(conn: sqlite3.Connection, user_id: int, credential_id: bytes) -> Passkey | None:
    row = conn.execute(f"{_SELECT} WHERE user_id = ? AND credential_id = ?", (user_id, credential_id)).fetchone()
    return _row(row) if row is not None else None


def insert_passkey(conn: sqlite3.Connection, *, user_id: int, new: NewPasskey, name: str, now: int) -> int | None:
    """Store a verified passkey. Returns its id, or None when the admin already has the maximum."""
    count = int(conn.execute("SELECT count(*) FROM admin_passkeys WHERE user_id = ?", (user_id,)).fetchone()[0])
    if count >= MAX_PASSKEYS_PER_USER:
        return None
    cursor = conn.execute(
        "INSERT INTO admin_passkeys (user_id, credential_id, public_key, sign_count, transports, name, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, new.credential_id, new.public_key, new.sign_count, json.dumps(new.transports), name[:MAX_NAME], now),
    )
    return int(cursor.lastrowid) if cursor.lastrowid is not None else None


def delete_passkey(conn: sqlite3.Connection, user_id: int, passkey_id: int) -> bool:
    return conn.execute("DELETE FROM admin_passkeys WHERE id = ? AND user_id = ?", (passkey_id, user_id)).rowcount > 0


def update_sign_count(conn: sqlite3.Connection, passkey_id: int, sign_count: int, now: int) -> None:
    conn.execute(
        "UPDATE admin_passkeys SET sign_count = ?, last_used_at = ? WHERE id = ?", (sign_count, now, passkey_id)
    )
