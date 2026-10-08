"""Second factor management: TOTP enrollment (forced after the D5 bootstrap login), recovery codes, passkeys.

What this is
    `start_totp` / `confirm_totp` (enroll or replace the authenticator app), `regenerate_recovery`, and the
    passkey management functions `passkey_register_options`, `passkey_register_verify`, `passkey_delete` and
    `passkey_list`. Each takes the worker's `AuthService` and the caller's session.

Why it exists
    Owner decision D5: the first v2 login of the imported v1 account uses the password plus an emailed code once,
    and the resulting "bootstrap" session can do exactly one thing: enroll an authenticator app. Confirming it
    stores the secret (encrypted), creates 10 recovery codes (shown once), clears `mfa_bootstrap_pending` so the
    email path closes, and rotates the session to a full one. Replacing the authenticator later, regenerating
    recovery codes and managing passkeys are sensitive actions: the routes require a fresh second factor
    (`require_admin("fresh_mfa")`, plan 9.6).

How it works
    - A new TOTP secret waits in hot.db for its first code (`auth_enroll:<session hash>`, 10 minutes), encrypted
      and bound to the session, so it works across workers and is never stored in clear.
    - The confirming code must match AND pass the per-user replay guard, and the attempt counts toward the
      lockout like any second factor attempt.
    - Recovery codes are hashed before anything is spent, so a busy hasher (429) leaves the enrollment
      untouched and the admin simply retries.
    - Passkey registration keeps its challenge in hot.db (`auth_webauthn:register:<session hash>`) and takes it
      with `DELETE ... RETURNING`, so a challenge works once.

What to read next
    `roxy/admin/auth/flow.py` (the login that leads here), `roxy/admin/auth/totp.py`, then
    `roxy/admin/auth/routes.py`.
"""

from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING, Any

from roxy.admin.auth import lockout, recovery_codes, sessions, totp, transactions, users, webauthn
from roxy.admin.auth.events import REASON_BAD_CODE, audit_auth
from roxy.admin.auth.flow import AuthError, RequestInfo, b64url_decode, b64url_encode, lockout_error, mfa_failure
from roxy.admin.auth.passwords import HashQueueFull

if TYPE_CHECKING:
    from roxy.admin.auth.flow import AuthService

ENROLL_TTL_S = 600
TOTP_KEY_MISSING_TEXT = "The authenticator key (totp_encryption_key) is not configured on the server."
START_ENROLL_AGAIN_TEXT = "Start the enrollment again."
PASSKEY_START_AGAIN_TEXT = "Start adding the passkey again."
PASSKEY_INVALID_TEXT = "The passkey could not be verified."
PASSKEY_LIMIT_TEXT = f"At most {webauthn.MAX_PASSKEYS_PER_USER} passkeys per admin."


def _enroll_name(record: sessions.SessionRecord) -> str:
    return f"{transactions.ENROLL}{record.id_hash}"


def _register_name(record: sessions.SessionRecord) -> str:
    return f"{transactions.WEBAUTHN}register:{record.id_hash}"


async def start_totp(service: AuthService, record: sessions.SessionRecord) -> dict[str, Any]:
    """A new authenticator secret, its QR code and `otpauth://` URI. Nothing changes until it is confirmed."""
    cipher = service.cipher()
    if cipher is None:
        raise AuthError(503, TOTP_KEY_MISSING_TEXT)
    secret = totp.new_secret()
    blob = cipher.encrypt(secret, f"enroll:{record.id_hash}")
    expires = service.clock.now_ms() + ENROLL_TTL_S * 1000
    name = _enroll_name(record)

    def store(conn: sqlite3.Connection) -> None:
        transactions.cap(conn, transactions.ENROLL, service.clock.now_ms())
        transactions.put(conn, name, {"secret": b64url_encode(blob)}, expires)

    await service.hot_write(store)
    uri = totp.provisioning_uri(secret, record.username)
    return {"Secret": secret, "Uri": uri, "Qr": totp.qr_svg_data_uri(uri), "ExpiresIn": ENROLL_TTL_S}


async def confirm_totp(
    service: AuthService, info: RequestInfo, record: sessions.SessionRecord, code: str
) -> tuple[str, list[str]]:
    """Check the first code from the new authenticator; store it, make recovery codes, rotate the session.

    Returns (new session cookie token, the 10 recovery codes to show once).
    """
    cipher = service.cipher()
    if cipher is None:
        raise AuthError(503, TOTP_KEY_MISSING_TEXT)
    now = int(service.clock.now())
    now_ms = service.clock.now_ms()
    key = lockout.lockout_key(record.username, info.ip)
    max_failures = service.settings.int("admin_login_max_failures")
    window = service.settings.int("admin_login_window_s")
    name = _enroll_name(record)

    def begin(conn: sqlite3.Connection) -> tuple[lockout.Reservation, dict[str, Any] | None]:
        reservation = lockout.reserve(conn, key, now, max_failures, window)
        return reservation, transactions.get(conn, name, now_ms) if reservation.allowed else None

    reservation, pending = await service.hot_write(begin)
    if not reservation.allowed:
        raise lockout_error(reservation.retry_after_s)
    blob = b64url_decode(str(pending.get("secret", ""))) if pending else None
    secret = cipher.decrypt(blob, f"enroll:{record.id_hash}") if blob else None
    if secret is None:
        await service.hot_write(lambda conn: lockout.release(conn, reservation.subject))
        raise AuthError(409, START_ENROLL_AGAIN_TEXT)
    step = totp.match_step(secret, code, service.clock.now())
    if step is None:
        await service.audit_quietly(
            "auth.mfa_failed",
            info,
            user_id=record.user_id,
            username=record.username,
            reason=f"{REASON_BAD_CODE} (authenticator enrollment)",
        )
        raise mfa_failure()
    codes = recovery_codes.generate()
    try:
        entries = await recovery_codes.hash_codes(service.hasher, codes)
    except HashQueueFull:
        await service.hot_write(lambda conn: lockout.release(conn, reservation.subject))
        raise lockout_error(HashQueueFull.retry_after_s) from None

    def finish(conn: sqlite3.Connection) -> bool:
        if not transactions.accept_totp_step(conn, record.user_id, step, now_ms):
            return False
        if transactions.take(conn, name, now_ms) is None:
            return False
        lockout.clear(conn, key)
        return True

    if not await service.hot_write(finish):
        raise mfa_failure()
    stored = cipher.encrypt(secret, totp.user_context(record.user_id))
    max_age = service.settings.int("admin_session_max_age_s")

    def write(conn: sqlite3.Connection) -> str:
        users.store_totp(conn, record.user_id, stored, recovery_codes.dumps(entries))
        audit_auth(
            conn,
            "auth.totp_enrolled",
            user_id=record.user_id,
            username=record.username,
            ip=info.ip,
            request_id=info.request_id,
            target=f"admin_user:{record.user_id}:totp_secret",
            reason="authenticator app enrolled"
            + (" (first login after the upgrade)" if record.mfa_level == "bootstrap" else ""),
            at=now,
        )
        audit_auth(
            conn,
            "auth.recovery_codes_generated",
            user_id=record.user_id,
            username=record.username,
            ip=info.ip,
            request_id=info.request_id,
            target=f"admin_user:{record.user_id}:recovery_codes",
            reason=f"{len(entries)} new recovery codes",
            at=now,
        )
        token, _ = sessions.rotate(conn, record, mfa_level="totp", now=now, ip=info.ip, ua=info.ua, max_age_s=max_age)
        return token

    token = await service.control_write(write)
    return token, codes


async def regenerate_recovery(service: AuthService, info: RequestInfo, record: sessions.SessionRecord) -> list[str]:
    """Replace every recovery code with a new set (the old ones stop working)."""
    codes = recovery_codes.generate()
    try:
        entries = await recovery_codes.hash_codes(service.hasher, codes)
    except HashQueueFull:
        raise lockout_error(HashQueueFull.retry_after_s) from None
    now = int(service.clock.now())

    def write(conn: sqlite3.Connection) -> None:
        users.set_recovery_codes(conn, record.user_id, recovery_codes.dumps(entries))
        audit_auth(
            conn,
            "auth.recovery_codes_generated",
            user_id=record.user_id,
            username=record.username,
            ip=info.ip,
            request_id=info.request_id,
            target=f"admin_user:{record.user_id}:recovery_codes",
            reason=f"{len(entries)} new recovery codes; the previous set no longer works",
            at=now,
        )

    await service.control_write(write)
    return codes


async def recovery_status(service: AuthService, record: sessions.SessionRecord) -> dict[str, int]:
    user = await service.control_read(lambda conn: users.get_by_id(conn, record.user_id))
    entries = recovery_codes.loads(user.recovery_codes_hash_json if user else None)
    return {"Total": len(entries), "Remaining": recovery_codes.remaining(entries)}


async def passkey_list(service: AuthService, record: sessions.SessionRecord) -> list[dict[str, object]]:
    keys = await service.control_read(lambda conn: webauthn.list_passkeys(conn, record.user_id))
    return [key.public() for key in keys]


async def passkey_register_options(service: AuthService, record: sessions.SessionRecord) -> dict[str, Any]:
    keys = await service.control_read(lambda conn: webauthn.list_passkeys(conn, record.user_id))
    if len(keys) >= webauthn.MAX_PASSKEYS_PER_USER:
        raise AuthError(409, PASSKEY_LIMIT_TEXT)
    options, challenge = webauthn.registration_options(
        rp_id=service.rp_id, user_id=record.user_id, username=record.username, existing=[k.credential_id for k in keys]
    )
    expires = service.clock.now_ms() + webauthn.TIMEOUT_MS
    name = _register_name(record)
    await service.hot_write(lambda conn: transactions.put(conn, name, {"challenge": b64url_encode(challenge)}, expires))
    return options


async def passkey_register_verify(
    service: AuthService, info: RequestInfo, record: sessions.SessionRecord, credential: dict[str, Any], label: str
) -> dict[str, object]:
    now = int(service.clock.now())
    name = _register_name(record)
    stored = await service.hot_write(lambda conn: transactions.take(conn, name, service.clock.now_ms()))
    challenge = b64url_decode(str(stored.get("challenge", ""))) if stored else None
    if challenge is None:
        raise AuthError(409, PASSKEY_START_AGAIN_TEXT)
    new = webauthn.verify_registration(credential, challenge=challenge, rp_id=service.rp_id, origin=service.site_origin)
    if new is None:
        raise AuthError(400, PASSKEY_INVALID_TEXT)
    clean = " ".join(label.split())[: webauthn.MAX_NAME] or "Passkey"

    def write(conn: sqlite3.Connection) -> int | None:
        passkey_id = webauthn.insert_passkey(conn, user_id=record.user_id, new=new, name=clean, now=now)
        if passkey_id is not None:
            audit_auth(
                conn,
                "auth.passkey_added",
                user_id=record.user_id,
                username=record.username,
                ip=info.ip,
                request_id=info.request_id,
                after={"passkey_id": passkey_id, "name": clean},
                at=now,
            )
        return passkey_id

    try:
        passkey_id = await service.control_write(write)
    except sqlite3.IntegrityError:
        raise AuthError(409, "This passkey is already registered.") from None
    if passkey_id is None:
        raise AuthError(409, PASSKEY_LIMIT_TEXT)
    return {"Id": passkey_id, "Name": clean, "CreatedAt": now}


async def passkey_delete(
    service: AuthService, info: RequestInfo, record: sessions.SessionRecord, passkey_id: int
) -> bool:
    now = int(service.clock.now())

    def write(conn: sqlite3.Connection) -> bool:
        removed = webauthn.delete_passkey(conn, record.user_id, passkey_id)
        if removed:
            audit_auth(
                conn,
                "auth.passkey_removed",
                user_id=record.user_id,
                username=record.username,
                ip=info.ip,
                request_id=info.request_id,
                before={"passkey_id": passkey_id},
                at=now,
            )
        return removed

    return await service.control_write(write)
