"""The login state machine (`AuthService`): password step, second factor step, re-authentication, logout.

What this is
    `AuthService`, one per worker, with `login` (username and password), `mfa` (finish a login with TOTP, a
    recovery code, an emailed code or a passkey), `resend_email`, `passkey_options`, `reauth` (fresh second factor
    for sensitive actions), `reauth_passkey_options`, `load_session` and `logout`. Errors are `AuthError` values
    carrying the exact HTTP status and v1 body the route sends.

Why it exists
    Plan 9.5 and parity rows 94 to 101. The order of the checks IS the security, so it lives in one readable
    place instead of being spread over route handlers:

    Password step (`POST /admin/api/v1/auth/login`)
      1. Lockout first: one atomic hot.db transaction counts this attempt for (username, network) and, unless the
         caller is exempt (admin allowlist or a valid trusted device), for the global per-minute guard. A locked
         key gets 429 `Too many attempts; try again in N seconds.` before any password is hashed.
      2. Over the global cap the attempt is slowed (`admin_login_global_delay_s`), never refused; the first
         attempt over the cap writes an audit row and raises the `login_global` alert.
      3. argon2id verification off the event loop; an unknown username verifies against a dummy hash, so both
         answers take the same time. A full hash queue refuses with the lockout-style 429 and gives the slot back.
      4. Wrong password: 403 `Invalid credentials` (v1). The slot stays used: that is the failure being counted.
      5. Right password: the slot is given back. A valid trusted device for this account skips the second factor
         (only when `admin_trusted_devices_enabled`). Otherwise a login transaction is stored in hot.db, bound to
         the IP and a hash of the User-Agent, for `challenge_expiration` seconds, and its random token goes to the
         browser. The one-time D5 bootstrap login (imported v1 account, no authenticator yet) emails a code now.

    Second factor step (`POST /admin/api/v1/auth/mfa`)
      1. One hot.db transaction: count the attempt for the lockout (keyed by the transaction's username), then
         check the transaction exists, matches the IP and User-Agent, has not expired, and has had at most
         `MFA_ATTEMPTS_PER_TX` attempts. Each failure gives the uniform 404 `Not Found` and logs v1's reason.
      2. Verify the factor. TOTP: the newest matching step, accepted only if newer than the last used step (replay
         guard). Recovery code: one argon2 check by lookup id, then a compare-and-set that spends it. Email code:
         salted digest, constant-time compare, bound to this transaction. Passkey: signature over the challenge
         stored in this transaction.
      3. Success takes the transaction (`DELETE ... RETURNING`, so exactly one request can finish it), clears the
         lockout key, creates the session (deleting any session cookie the browser brought: no fixation), mints
         the kill-switch token, records the login, and sends the `Roxy Admin Login` email in the background.

    C7: if hot.db or control.db cannot be used, every step answers 503 with a clear message (`UNAVAILABLE_TEXT`)
    instead of guessing.

How it works
    Every database touch is a short function run on the database's own thread (`db.write`/`db.read`), so the
    event loop never blocks. Times come from `ctx.clock`, settings from `ctx.settings` (read on each request, so
    changes apply within a second fleet-wide).

What to read next
    `roxy/admin/auth/lockout.py`, `roxy/admin/auth/transactions.py`, `roxy/admin/auth/sessions.py`, then
    `roxy/admin/auth/routes.py` (how results become HTTP responses).
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import logging
import sqlite3
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal, TypeVar

from roxy.admin.auth import (
    email_codes,
    invalidation,
    lockout,
    recovery_codes,
    sessions,
    totp,
    transactions,
    trusted_devices,
    users,
    webauthn,
)
from roxy.admin.auth.allowlist import in_admin_allowlist
from roxy.admin.auth.events import (
    REASON_BAD_CHALLENGE,
    REASON_BAD_CODE,
    REASON_IP_MISMATCH,
    REASON_MISSING_CHALLENGE,
    REASON_RATE_LIMITED,
    REASON_UA_MISMATCH,
    audit_auth,
    record_login,
    record_probe,
)
from roxy.admin.auth.passwords import HashQueueFull, PasswordHasher
from roxy.notify.alerts import make_alert
from roxy.notify.mail import MailError
from roxy.notify.notifier import get_notifier
from roxy.storage.db import Database, SharedStateUnavailable

log = logging.getLogger("roxy.admin.auth.flow")
T = TypeVar("T")

MFA_ATTEMPTS_PER_TX = 3
"""Second factor tries one login transaction allows (each also counts toward the lockout)."""

NOT_FOUND_TEXT = "Not Found"
INVALID_CREDENTIALS_TEXT = "Invalid credentials"
INVALID_REQUEST_TEXT = "Invalid request"
START_AGAIN_TEXT = "Start the login again."
UNAVAILABLE_TEXT = (
    "Admin login is unavailable right now because shared state cannot be read or written; please try again shortly."
)
LOGIN_ALERT_SUMMARY = "A successful login to the Roxy admin panel just occurred."

Method = Literal["totp", "recovery", "email", "passkey"]


class AuthError(Exception):
    """A refusal with its exact HTTP status and v1-shaped JSON body (a JSON string, like v1's `jsonify`)."""

    def __init__(self, status: int, body: Any, *, headers: dict[str, str] | None = None) -> None:
        super().__init__(f"{status}: {body}")
        self.status = status
        self.body = body
        self.headers = headers or {}


def lockout_error(seconds: int) -> AuthError:
    seconds = max(1, int(seconds))
    return AuthError(429, lockout.LOCKOUT_TEXT.format(seconds=seconds), headers={"Retry-After": str(seconds)})


def mfa_failure() -> AuthError:
    """The uniform second factor failure (plan 9.5): identical for every cause."""
    return AuthError(404, NOT_FOUND_TEXT)


def unavailable() -> AuthError:
    return AuthError(503, UNAVAILABLE_TEXT, headers={"Retry-After": "5"})


@dataclass(frozen=True, slots=True)
class RequestInfo:
    """What the flow needs to know about the HTTP request."""

    ip: str
    ua: str
    request_id: str | None = None
    path: str = ""
    session_cookie: str | None = None
    trusted_cookie: str | None = None


@dataclass(frozen=True, slots=True)
class LoginOutcome:
    """Either "a second factor is needed" (`kind="mfa"`) or "logged in" (`kind="session"`)."""

    kind: Literal["mfa", "session"]
    transaction: str | None = None
    methods: tuple[str, ...] = ()
    expires_in: int = 0
    email_expires_in: int | None = None
    bootstrap: bool = False
    session_token: str | None = None
    trusted_token: str | None = None
    mfa_level: str | None = None
    user_id: int | None = None
    username: str | None = None

    @property
    def enrollment_required(self) -> bool:
        return self.mfa_level == "bootstrap"


@dataclass(slots=True)
class _FactorCheck:
    ok: bool
    step: int | None = None
    recovery: recovery_codes.RecoveryEntry | None = None
    recovery_normalized: str | None = None
    passkey: webauthn.Passkey | None = None
    sign_count: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)


def ua_hash(ua: str) -> str:
    return hashlib.sha256(ua.encode("utf-8", "replace")).hexdigest()[:32]


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_decode(text: str) -> bytes | None:
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        return None


def _tx_name(token: str | None) -> str | None:
    if not isinstance(token, str) or not 16 <= len(token) <= 128 or not token.isascii():
        return None
    return transactions.LOGIN_TX + transactions.token_hash(token)


class AuthService:
    """The login flow for one worker (see the module docstring)."""

    def __init__(
        self,
        ctx: Any,
        *,
        hasher: PasswordHasher | None = None,
        notifier: Any | None = None,
        cipher: totp.TotpCipher | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.ctx = ctx
        self.hasher = hasher or PasswordHasher(sleep=sleep)
        self._notifier = notifier
        self._cipher = cipher
        self._cipher_loaded = cipher is not None

    # ------------------------------------------------------------------------------------------ plumbing

    @property
    def clock(self) -> Any:
        return self.ctx.clock

    @property
    def settings(self) -> Any:
        return self.ctx.settings

    @property
    def site_origin(self) -> str:
        return str(self.ctx.env.site_origin)

    @property
    def rp_id(self) -> str:
        return webauthn.rp_id_for(self.site_origin)

    def cipher(self) -> totp.TotpCipher | None:
        """The TOTP cipher from the `totp_encryption_key` credential (loaded once; None when missing)."""
        if not self._cipher_loaded:
            self._cipher = totp.load_cipher(getattr(self.ctx.env, "credentials_dir", None))
            self._cipher_loaded = True
            if self._cipher is None:
                log.error("totp_key_missing", extra={"fields": {"credential": totp.TOTP_KEY_NAME}})
        return self._cipher

    def notifier(self) -> Any:
        return self._notifier if self._notifier is not None else get_notifier(self.ctx)

    async def _db(self, name: str, kind: str, fn: Callable[[sqlite3.Connection], T]) -> T:
        """Run `fn` on a database; shared state problems become the C7 503."""
        database: Database = getattr(self.ctx.dbs, name)
        try:
            if kind == "write":
                return await database.write(fn)
            return await database.read(fn)
        except SharedStateUnavailable as exc:
            log.error("auth_shared_state_unavailable", extra={"fields": {"db": name, "error": str(exc)[:200]}})
            raise unavailable() from exc

    async def control_read(self, fn: Callable[[sqlite3.Connection], T]) -> T:
        return await self._db("control", "read", fn)

    async def control_write(self, fn: Callable[[sqlite3.Connection], T]) -> T:
        return await self._db("control", "write", fn)

    async def hot_read(self, fn: Callable[[sqlite3.Connection], T]) -> T:
        return await self._db("hot", "read", fn)

    async def hot_write(self, fn: Callable[[sqlite3.Connection], T]) -> T:
        return await self._db("hot", "write", fn)

    async def audit_quietly(self, action: str, info: RequestInfo, **kwargs: Any) -> None:
        """An audit row for an event that is already failing anyway; a database problem is logged, not raised."""
        try:
            await self.control_write(
                lambda conn: audit_auth(conn, action, ip=info.ip, request_id=info.request_id, **kwargs)
            )
        except Exception:
            log.warning("auth_audit_failed", extra={"fields": {"action": action}}, exc_info=True)

    def _s(self, key: str) -> int:
        return int(self.settings.int(key))

    # ------------------------------------------------------------------------------------------ sessions

    async def load_session(self, token: str | None) -> sessions.SessionRecord | None:
        """The live session for a cookie value, or None (expired, revoked, idle, or from an older epoch)."""
        if not token or len(token) > 128:
            return None
        id_hash = sessions.hash_token(token)
        found = await self.control_read(lambda conn: sessions.load(conn, id_hash))
        if found is None:
            return None
        record, epoch = found
        idle = self._s("admin_session_idle_timeout_s")
        if not sessions.is_live(record, epoch, self.clock.now(), idle):
            return None
        return record

    async def touch_session(self, record: sessions.SessionRecord) -> None:
        """Real use: push the idle deadline forward (skipped when it moved in the last few seconds)."""
        now = int(self.clock.now())
        if now - record.last_seen_at < 5:
            return
        await self.control_write(lambda conn: sessions.touch(conn, record.id_hash, now))

    async def logout(self, info: RequestInfo, record: sessions.SessionRecord) -> None:
        def write(conn: sqlite3.Connection) -> None:
            sessions.revoke(conn, record.id_hash)
            audit_auth(
                conn,
                "auth.logout",
                user_id=record.user_id,
                username=record.username,
                ip=info.ip,
                request_id=info.request_id,
                reason="logout",
            )

        await self.control_write(write)

    # ------------------------------------------------------------------------------------------ password step

    async def _trusted_cookie_valid(self, info: RequestInfo, now: int) -> trusted_devices.TrustedDevice | None:
        if not info.trusted_cookie or not self.settings.bool("admin_trusted_devices_enabled"):
            return None
        cookie = info.trusted_cookie
        return await self.control_read(lambda conn: trusted_devices.find_valid(conn, cookie, info.ua, now))

    async def login(self, info: RequestInfo, username: str, password: str, trust_device: bool) -> LoginOutcome:
        """The password step (see the module docstring for the order of checks)."""
        now = int(self.clock.now())
        max_failures = self._s("admin_login_max_failures")
        window = self._s("admin_login_window_s")
        cap = self._s("admin_login_global_max_per_min")
        key = lockout.lockout_key(username, info.ip)
        device = await self._trusted_cookie_valid(info, now)
        exempt = device is not None or in_admin_allowlist(self.ctx, info.ip)

        def begin(conn: sqlite3.Connection) -> tuple[lockout.Reservation, lockout.GlobalTick | None, list[Any]]:
            reservation = lockout.reserve(conn, key, now, max_failures, window)
            tick = lockout.global_tick(conn, now, cap) if reservation.allowed and not exempt else None
            top = lockout.top_prefixes(conn, now, 600) if tick is not None and tick.just_engaged else []
            return reservation, tick, top

        reservation, tick, top = await self.hot_write(begin)
        if not reservation.allowed:
            record_probe(self.ctx, ip=info.ip, reason=REASON_RATE_LIMITED, user_agent=info.ua, path=info.path)
            raise lockout_error(reservation.retry_after_s)
        if tick is not None and tick.just_engaged:
            await self._global_guard_engaged(info, tick, top)
        delay_s = float(self._s("admin_login_global_delay_s")) if tick is not None and tick.engaged else 0.0

        user = await self.control_read(lambda conn: users.get_by_username(conn, username))
        try:
            result = await self.hasher.verify(user.password_hash if user else None, password, delay_s=delay_s)
        except HashQueueFull:
            # Never checked, so not a failure: give the slot back (otherwise an attack would lock the owner out).
            await self.hot_write(lambda conn: lockout.release(conn, reservation.subject))
            raise lockout_error(HashQueueFull.retry_after_s) from None
        if user is None or not result.ok:
            await self._password_failed(info, user, reservation)
            raise AuthError(403, INVALID_CREDENTIALS_TEXT)
        if result.needs_rehash:
            await self._rehash(user, password)

        bootstrap = user.mfa_bootstrap_pending and not user.has_totp
        if device is not None and device.user_id == user.id and not bootstrap:
            await self.hot_write(lambda conn: lockout.clear(conn, key))
            return await self._finish_login(info, user, "trusted_device", trust_device=False, device_id=device.id)

        methods = await self._methods_for(user, bootstrap)
        token = transactions.new_token()
        name = transactions.LOGIN_TX + transactions.token_hash(token)
        ttl = self._s("challenge_expiration")
        payload: dict[str, Any] = {
            "uid": user.id,
            "user": username.strip().casefold(),
            "ip": info.ip,
            "ua": ua_hash(info.ua),
            "trust": bool(trust_device) and bool(self.settings.bool("admin_trusted_devices_enabled")),
            "methods": methods,
            "bootstrap": bootstrap,
            "attempts": 0,
            "sends": 0,
            "created": now,
        }
        now_ms = self.clock.now_ms()

        def store(conn: sqlite3.Connection) -> None:
            lockout.release(conn, reservation.subject)
            transactions.cap(conn, transactions.LOGIN_TX, now_ms)
            transactions.put(conn, name, payload, now_ms + ttl * 1000)

        await self.hot_write(store)
        email_expires_in: int | None = None
        if bootstrap:
            try:
                email_expires_in = await self._send_email_code(user, name, first=True)
            except AuthError:
                await self.hot_write(lambda conn: transactions.delete(conn, name))
                raise
        return LoginOutcome(
            kind="mfa",
            transaction=token,
            methods=tuple(methods),
            expires_in=ttl,
            email_expires_in=email_expires_in,
            bootstrap=bootstrap,
            user_id=user.id,
            username=user.username,
        )

    async def _password_failed(self, info: RequestInfo, user: users.AdminUser | None, r: lockout.Reservation) -> None:
        record_login(
            self.ctx, ip=info.ip, successful=False, username=user.username if user else None, method="password"
        )
        # Audit only the first failure of a key in its window and the one that fills the last slot (events.py).
        if r.failures_before != 0 and not r.last_chance:
            return
        await self.audit_quietly(
            "auth.lockout" if r.last_chance else "auth.login_failed",
            info,
            user_id=user.id if user else None,
            username=None,
            target=None if user else f"admin_login:{lockout.ip_prefix(info.ip)}",
            reason="wrong password" + ("; further attempts from this network are locked out" if r.last_chance else ""),
            after={"failures_in_window": r.failures_before + 1, "network": lockout.ip_prefix(info.ip)},
            actor_kind="system",
        )

    async def _rehash(self, user: users.AdminUser, password: str) -> None:
        try:
            new_hash = await self.hasher.hash(password)
        except HashQueueFull:
            return  # try again on the next login
        await self.control_write(lambda conn: users.set_password_hash(conn, user.id, new_hash))
        log.info("admin_password_rehashed", extra={"fields": {"user_id": user.id}})

    async def _global_guard_engaged(self, info: RequestInfo, tick: lockout.GlobalTick, top: list[Any]) -> None:
        networks = ", ".join(f"{network} ({count})" for network, count in top) or "n/a"
        await self.audit_quietly(
            "auth.global_guard",
            info,
            user_id=None,
            username=None,
            target="admin_login:global",
            reason="login attempts above admin_login_global_max_per_min; attempts are slowed",
            after={"attempts_this_minute": tick.count, "top_networks": networks},
            actor_kind="system",
        )
        alert = make_alert(
            "login_global",
            summary="Admin login attempts passed the global limit; further attempts are slowed, not refused.",
            fields={"Attempts this minute": tick.count, "Top networks": networks},
            link=f"{self.site_origin}/admin/security",
        )
        try:
            self.notifier().notify(alert)
        except Exception:
            log.warning("login_global_alert_failed", exc_info=True)

    async def _methods_for(self, user: users.AdminUser, bootstrap: bool) -> list[str]:
        if bootstrap:
            return ["email"]
        methods: list[str] = []
        if user.has_totp:
            methods.append("totp")
        if recovery_codes.remaining(recovery_codes.loads(user.recovery_codes_hash_json)):
            methods.append("recovery")
        keys = await self.control_read(lambda conn: webauthn.list_passkeys(conn, user.id))
        if keys:
            methods.append("passkey")
        if self.settings.bool("admin_email_code_enabled") and self._email_destination(user):
            methods.append("email")
        return methods

    def _email_destination(self, user: users.AdminUser) -> str | None:
        notifier = self.notifier()
        mail = getattr(notifier, "mail", None)
        fallback = getattr(getattr(mail, "config", None), "to_addr", None)
        return users.email_for(user, fallback)

    async def _send_email_code(self, user: users.AdminUser, name: str, *, first: bool) -> int:
        """Issue a new code for transaction `name` (replacing any previous one) and mail it."""
        now = int(self.clock.now())
        now_ms = self.clock.now_ms()
        lifetime = self._s("two_fa_expiration")
        ttl_ms = self._s("challenge_expiration") * 1000
        code = email_codes.new_code(self._s("email_code_digits"))

        def update(conn: sqlite3.Connection) -> int | None:
            found = transactions.get_any(conn, name)
            if found is None or found[0] is None or found[1] <= now_ms:
                return None
            payload = found[0]
            sends = int(payload.get("sends", 0))
            last = int(payload.get("last_sent", 0))
            if not first and sends >= email_codes.MAX_SENDS_PER_TX:
                return -1
            if not first and now - last < email_codes.RESEND_MIN_INTERVAL_S:
                return email_codes.RESEND_MIN_INTERVAL_S - (now - last)
            payload.update(
                email_hash=email_codes.digest(code, name), email_exp=now + lifetime, sends=sends + 1, last_sent=now
            )
            # A resend also restarts the transaction clock (v1 re-minted the challenge on resend).
            transactions.put(conn, name, payload, max(found[1], now_ms + ttl_ms))
            return 0

        outcome = await self.hot_write(update)
        if outcome is None:
            raise AuthError(403, START_AGAIN_TEXT)
        if outcome == -1:
            raise lockout_error(self._s("challenge_expiration"))
        if outcome > 0:
            raise lockout_error(outcome)
        destination = self._email_destination(user)
        try:
            await email_codes.send_code(self.notifier(), destination, code)
        except (MailError, AttributeError, TimeoutError) as exc:
            log.warning("email_code_send_failed", extra={"fields": {"error": type(exc).__name__}})
            raise AuthError(503, email_codes.SEND_FAILED_TEXT) from exc
        return min(lifetime, self._s("challenge_expiration"))

    # ------------------------------------------------------------------------------------------ second factor

    async def _begin_tx_attempt(
        self, info: RequestInfo, token: str | None, method: str
    ) -> tuple[str, dict[str, Any], str, str]:
        """Lockout count plus every transaction check, in one hot.db transaction. Returns (name, payload, raw, key)."""
        now = int(self.clock.now())
        now_ms = self.clock.now_ms()
        name = _tx_name(token)
        max_failures = self._s("admin_login_max_failures")
        window = self._s("admin_login_window_s")
        agent = ua_hash(info.ua)

        def begin(conn: sqlite3.Connection) -> tuple[str, Any, Any, str]:
            found = transactions.get_any(conn, name) if name else None
            payload = found[0] if found is not None else None
            key = lockout.lockout_key(str(payload.get("user", "")) if payload else "", info.ip)
            reservation = lockout.reserve(conn, key, now, max_failures, window)
            if not reservation.allowed:
                return "locked", reservation.retry_after_s, None, key
            if found is None or payload is None or name is None:
                return "fail", REASON_MISSING_CHALLENGE, None, key
            if payload.get("ip") != info.ip:
                return "fail", REASON_IP_MISMATCH, payload, key
            if payload.get("ua") != agent:
                return "fail", REASON_UA_MISMATCH, payload, key
            attempts = int(payload.get("attempts", 0)) + 1
            if found[1] <= now_ms or attempts > MFA_ATTEMPTS_PER_TX:
                transactions.delete(conn, name)
                return "fail", REASON_BAD_CHALLENGE, payload, key
            payload["attempts"] = attempts
            transactions.put(conn, name, payload, found[1])
            if method not in payload.get("methods", []):
                return "fail", REASON_BAD_CODE, payload, key
            return "ok", transactions.raw_payload(conn, name), payload, key

        status, detail, payload, key = await self.hot_write(begin)
        if status == "locked":
            record_probe(self.ctx, ip=info.ip, reason=REASON_RATE_LIMITED, user_agent=info.ua, path=info.path)
            raise lockout_error(int(detail))
        if status == "fail":
            await self._mfa_failed(info, str(detail), payload)
            raise mfa_failure()
        assert name is not None
        assert payload is not None
        return name, payload, str(detail), key

    async def _mfa_failed(self, info: RequestInfo, reason: str, payload: dict[str, Any] | None) -> None:
        record_probe(self.ctx, ip=info.ip, reason=reason, user_agent=info.ua, path=info.path)
        record_login(self.ctx, ip=info.ip, successful=False, username=None, method="second_factor")
        if payload is not None and reason != REASON_BAD_CHALLENGE:
            # A real transaction exists, so the password was right: always worth an audit row (bounded by lockout).
            await self.audit_quietly(
                "auth.mfa_failed",
                info,
                user_id=int(payload.get("uid", 0)) or None,
                username=None,
                reason=reason,
                after={"network": lockout.ip_prefix(info.ip)},
                actor_kind="system",
            )

    async def _check_factor(
        self,
        user: users.AdminUser,
        method: str,
        code: str | None,
        credential: dict[str, Any] | None,
        *,
        challenge_b64: str | None,
        email: tuple[str, int, str] | None,
    ) -> _FactorCheck:
        """Verify one factor without spending anything (spending is atomic, in the caller)."""
        now = self.clock.now()
        if method == "totp":
            cipher = self.cipher()
            if cipher is None or not user.totp_secret_enc or not isinstance(code, str):
                return _FactorCheck(False)
            secret = cipher.decrypt(user.totp_secret_enc, totp.user_context(user.id))
            step = totp.match_step(secret, code, now) if secret else None
            return _FactorCheck(step is not None, step=step)
        if method == "recovery":
            normalized = recovery_codes.normalize(code) if isinstance(code, str) else None
            entries = recovery_codes.loads(user.recovery_codes_hash_json)
            entry = recovery_codes.find_entry(entries, normalized) if normalized else None
            # No matching entry still costs one argon2 run (the dummy hash), so timing reveals nothing.
            result = await self.hasher.verify(entry.hash if entry else None, normalized or "x")
            return _FactorCheck(result.ok, recovery=entry, recovery_normalized=normalized)
        if method == "email":
            if email is None or not isinstance(code, str):
                return _FactorCheck(False)
            stored, expires_at, salt = email
            ok = now < expires_at and email_codes.matches(code, stored, salt)
            return _FactorCheck(ok)
        if method == "passkey":
            challenge = b64url_decode(challenge_b64) if challenge_b64 else None
            if challenge is None or not isinstance(credential, dict):
                return _FactorCheck(False)
            credential_id = webauthn.credential_id_of(credential)
            if credential_id is None:
                return _FactorCheck(False)
            passkey = await self.control_read(lambda conn: webauthn.find_passkey(conn, user.id, credential_id))
            if passkey is None:
                return _FactorCheck(False)
            count = webauthn.verify_authentication(
                credential, challenge=challenge, rp_id=self.rp_id, origin=self.site_origin, passkey=passkey
            )
            return _FactorCheck(count is not None, passkey=passkey, sign_count=count)
        return _FactorCheck(False)

    async def mfa(
        self,
        info: RequestInfo,
        token: str | None,
        method: str,
        code: str | None,
        credential: dict[str, Any] | None,
    ) -> LoginOutcome:
        """The second factor step (see the module docstring)."""
        name, payload, raw, key = await self._begin_tx_attempt(info, token, method)
        user = await self.control_read(lambda conn: users.get_by_id(conn, int(payload["uid"])))
        if user is None:
            await self._mfa_failed(info, REASON_BAD_CHALLENGE, payload)
            raise mfa_failure()
        email = None
        if method == "email" and payload.get("email_hash"):
            email = (str(payload["email_hash"]), int(payload.get("email_exp", 0)), name)
        try:
            check = await self._check_factor(
                user, method, code, credential, challenge_b64=payload.get("webauthn"), email=email
            )
        except HashQueueFull:
            raise lockout_error(HashQueueFull.retry_after_s) from None
        if not check.ok:
            await self._mfa_failed(info, REASON_BAD_CODE, payload)
            raise mfa_failure()

        now = int(self.clock.now())
        now_ms = self.clock.now_ms()
        step = check.step

        def finish(conn: sqlite3.Connection) -> bool:
            if method == "totp" and (step is None or not transactions.accept_totp_step(conn, user.id, step, now_ms)):
                return False  # replay: this step (or a newer one) was already used
            taken = transactions.take(conn, name, now_ms, expect=raw)
            if taken is None:
                return False  # another request finished (or changed) this transaction first
            lockout.clear(conn, key)
            return True

        if not await self.hot_write(finish):
            await self._mfa_failed(info, REASON_BAD_CODE, payload)
            raise mfa_failure()
        if method == "recovery" and not await self._spend_recovery(info, user, check, now):
            await self._mfa_failed(info, REASON_BAD_CODE, payload)
            raise mfa_failure()
        if method == "passkey" and check.passkey is not None and check.sign_count is not None:
            passkey_id, count = check.passkey.id, check.sign_count
            await self.control_write(lambda conn: webauthn.update_sign_count(conn, passkey_id, count, now))
        level = "bootstrap" if payload.get("bootstrap") else method
        return await self._finish_login(info, user, level, trust_device=bool(payload.get("trust")))

    async def _spend_recovery(self, info: RequestInfo, user: users.AdminUser, check: _FactorCheck, now: int) -> bool:
        entry = check.recovery
        if entry is None:
            return False

        def write(conn: sqlite3.Connection) -> int | None:
            left = recovery_codes.mark_used(conn, user.id, entry.id, entry.hash, now)
            if left is not None:
                audit_auth(
                    conn,
                    "auth.recovery_code_used",
                    user_id=user.id,
                    username=user.username,
                    ip=info.ip,
                    request_id=info.request_id,
                    reason="recovery code used as the second factor",
                    after={"codes_left": left},
                    target=f"admin_user:{user.id}",
                    at=now,
                )
            return left

        return await self.control_write(write) is not None

    async def _finish_login(
        self,
        info: RequestInfo,
        user: users.AdminUser,
        level: str,
        *,
        trust_device: bool,
        device_id: int | None = None,
    ) -> LoginOutcome:
        """Create the session (rotating away any old one), mint the kill switch, audit, and alert."""
        now = int(self.clock.now())
        max_age = self._s("admin_session_max_age_s")
        trusted_days = self._s("trusted_device_days")
        ttl = self._s("invalidation_link_ttl_s")
        issue_trust = (
            trust_device
            and level in sessions.FULL_MFA_LEVELS
            and bool(self.settings.bool("admin_trusted_devices_enabled"))
        )
        old_cookie = info.session_cookie

        def write(conn: sqlite3.Connection) -> tuple[str, str | None, str]:
            if old_cookie:
                # Session fixation defense: whatever session id the browser brought is ended, never reused.
                sessions.revoke(conn, sessions.hash_token(old_cookie))
            token, _ = sessions.create(
                conn, user_id=user.id, ip=info.ip, ua=info.ua, mfa_level=level, now=now, max_age_s=max_age
            )
            trusted = (
                trusted_devices.issue(conn, user_id=user.id, ua=info.ua, now=now, days=trusted_days)
                if issue_trust
                else None
            )
            if device_id is not None:
                trusted_devices.touch(conn, device_id, now)
            users.mark_login(conn, user.id, now)
            kill = invalidation.mint(conn, user_id=user.id, now=now, ttl_s=ttl)
            audit_auth(
                conn,
                "auth.login",
                user_id=user.id,
                username=user.username,
                ip=info.ip,
                request_id=info.request_id,
                reason=f"login with {level.replace('_', ' ')}",
                after={
                    "mfa_level": level,
                    "trusted_device_added": trusted is not None,
                    "network": lockout.ip_prefix(info.ip),
                },
                at=now,
            )
            return token, trusted, kill

        token, trusted, kill = await self.control_write(write)
        record_login(self.ctx, ip=info.ip, successful=True, username=user.username, method=level)
        self._send_login_alert(info, kill, now)
        return LoginOutcome(
            kind="session",
            session_token=token,
            trusted_token=trusted,
            mfa_level=level,
            user_id=user.id,
            username=user.username,
        )

    def _send_login_alert(self, info: RequestInfo, kill_token: str, now: int) -> None:
        url = invalidation.link(self.site_origin, kill_token)
        when = datetime.fromtimestamp(now, tz=UTC).strftime("%Y-%m-%d %H:%M:%S")
        body = (
            f"{LOGIN_ALERT_SUMMARY}\n\nIP: {info.ip}\nUser-Agent: {info.ua}\nTime: {when} UTC\n\n"
            f"If this was not you, invalidate all admin sessions immediately:\n{url}\n"
        )
        alert = make_alert(
            "admin_login",
            summary=LOGIN_ALERT_SUMMARY,
            fields={"IP": info.ip, "User-Agent": info.ua, "Time": f"{when} UTC"},
            link=url,
            body=body,
        )
        try:
            self.notifier().notify(alert)
        except Exception:
            log.warning("login_alert_failed", exc_info=True)

    async def resend_email(self, info: RequestInfo, token: str | None) -> int:
        """Send a new emailed code for a transaction (the old one stops working). Returns its lifetime."""
        name = _tx_name(token)
        now_ms = self.clock.now_ms()
        agent = ua_hash(info.ua)

        def check(conn: sqlite3.Connection) -> dict[str, Any] | None:
            payload = transactions.get(conn, name, now_ms) if name else None
            if payload is None or payload.get("ip") != info.ip or payload.get("ua") != agent:
                return None
            return payload if "email" in payload.get("methods", []) else None

        payload = await self.hot_read(check)
        if payload is None or name is None:
            raise AuthError(403, START_AGAIN_TEXT)
        user = await self.control_read(lambda conn: users.get_by_id(conn, int(payload["uid"])))
        if user is None:
            raise AuthError(403, START_AGAIN_TEXT)
        return await self._send_email_code(user, name, first=int(payload.get("sends", 0)) == 0)

    async def passkey_options(self, info: RequestInfo, token: str | None) -> dict[str, Any]:
        """WebAuthn assertion options for a login transaction (the challenge is stored in the transaction)."""
        name = _tx_name(token)
        now_ms = self.clock.now_ms()
        agent = ua_hash(info.ua)
        found = await self.hot_read(lambda conn: transactions.get_any(conn, name) if name else None)
        payload = found[0] if found else None
        if (
            found is None
            or payload is None
            or found[1] <= now_ms
            or payload.get("ip") != info.ip
            or payload.get("ua") != agent
            or "passkey" not in payload.get("methods", [])
        ):
            raise AuthError(403, START_AGAIN_TEXT)
        uid = int(payload["uid"])
        keys = await self.control_read(lambda conn: webauthn.list_passkeys(conn, uid))
        options, challenge = webauthn.authentication_options(
            rp_id=self.rp_id, credential_ids=[k.credential_id for k in keys]
        )
        encoded = b64url_encode(challenge)

        def store(conn: sqlite3.Connection) -> bool:
            current = transactions.get_any(conn, name) if name else None
            if current is None or current[0] is None or current[1] <= now_ms:
                return False
            current[0]["webauthn"] = encoded
            transactions.put(conn, str(name), current[0], current[1])
            return True

        if not await self.hot_write(store):
            raise AuthError(403, START_AGAIN_TEXT)
        return options

    # ------------------------------------------------------------------------------------------ re-auth

    async def reauth_passkey_options(self, record: sessions.SessionRecord) -> dict[str, Any]:
        keys = await self.control_read(lambda conn: webauthn.list_passkeys(conn, record.user_id))
        if not keys:
            raise AuthError(403, START_AGAIN_TEXT)
        options, challenge = webauthn.authentication_options(
            rp_id=self.rp_id, credential_ids=[k.credential_id for k in keys]
        )
        name = f"{transactions.WEBAUTHN}reauth:{record.id_hash}"
        expires = self.clock.now_ms() + webauthn.TIMEOUT_MS
        await self.hot_write(
            lambda conn: transactions.put(conn, name, {"challenge": b64url_encode(challenge)}, expires)
        )
        return options

    async def reauth(
        self,
        info: RequestInfo,
        record: sessions.SessionRecord,
        method: str,
        code: str | None,
        credential: dict[str, Any] | None,
    ) -> str:
        """A fresh second factor for sensitive actions. Rotates the session; returns the new cookie token."""
        now = int(self.clock.now())
        now_ms = self.clock.now_ms()
        key = lockout.lockout_key(record.username, info.ip)
        max_failures = self._s("admin_login_max_failures")
        window = self._s("admin_login_window_s")
        challenge_name = f"{transactions.WEBAUTHN}reauth:{record.id_hash}"

        def begin(conn: sqlite3.Connection) -> tuple[lockout.Reservation, str | None]:
            reservation = lockout.reserve(conn, key, now, max_failures, window)
            challenge = None
            if reservation.allowed and method == "passkey":
                stored = transactions.take(conn, challenge_name, now_ms)
                challenge = str(stored.get("challenge")) if stored else None
            return reservation, challenge

        reservation, challenge = await self.hot_write(begin)
        if not reservation.allowed:
            raise lockout_error(reservation.retry_after_s)
        user = await self.control_read(lambda conn: users.get_by_id(conn, record.user_id))
        if user is None or method not in ("totp", "recovery", "passkey"):
            raise mfa_failure()
        try:
            check = await self._check_factor(user, method, code, credential, challenge_b64=challenge, email=None)
        except HashQueueFull:
            await self.hot_write(lambda conn: lockout.release(conn, reservation.subject))
            raise lockout_error(HashQueueFull.retry_after_s) from None
        payload = {"uid": user.id}
        if not check.ok:
            await self._mfa_failed(info, REASON_BAD_CODE, payload)
            raise mfa_failure()
        step = check.step

        def finish(conn: sqlite3.Connection) -> bool:
            if method == "totp" and (step is None or not transactions.accept_totp_step(conn, user.id, step, now_ms)):
                return False
            lockout.clear(conn, key)
            return True

        if not await self.hot_write(finish):
            await self._mfa_failed(info, REASON_BAD_CODE, payload)
            raise mfa_failure()
        if method == "recovery" and not await self._spend_recovery(info, user, check, now):
            raise mfa_failure()
        if method == "passkey" and check.passkey is not None and check.sign_count is not None:
            passkey_id, count = check.passkey.id, check.sign_count
            await self.control_write(lambda conn: webauthn.update_sign_count(conn, passkey_id, count, now))
        max_age = self._s("admin_session_max_age_s")

        def rotate(conn: sqlite3.Connection) -> str:
            token, _ = sessions.rotate(
                conn, record, mfa_level=method, now=now, ip=info.ip, ua=info.ua, max_age_s=max_age
            )
            audit_auth(
                conn,
                "auth.reauth",
                user_id=user.id,
                username=user.username,
                ip=info.ip,
                request_id=info.request_id,
                reason=f"fresh second factor ({method}) for a sensitive action",
                at=now,
            )
            return token

        return await self.control_write(rotate)
