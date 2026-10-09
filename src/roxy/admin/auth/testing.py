"""Test helpers for admin auth: a cheap hasher, test admin accounts, a recording mail transport, a software passkey.

What this is
    Small helpers the unit, security and end-to-end tests share: `fast_hasher()` (argon2id with tiny cost
    parameters), `make_admin(...)` (an account with a known password, TOTP secret and recovery codes),
    `RecordingTransport` (a mail transport that keeps messages in memory instead of sending them), and
    `SoftwarePasskey` (a WebAuthn authenticator in pure Python that answers registration and login challenges).

Why it exists
    Real argon2id costs 64 MiB and about 250 ms per hash; a test suite with hundreds of logins would take minutes
    and gigabytes. Tests never talk to a mail server (plan 19.12), and no test machine has a fingerprint reader,
    so passkeys need a stand-in that produces exactly what a browser would send. Nothing here weakens production:
    production code never imports this module, and the software passkey can only sign with keys it made itself.

How it works
    `SoftwarePasskey` holds one P-256 key pair. `register` builds a `none`-attestation answer (client data JSON,
    CBOR attestation object with the COSE public key); `assert_` signs authenticator data plus the client data
    hash, with the user-present and user-verified flags set, like a platform authenticator after a fingerprint.

What to read next
    `tests/unit/admin_auth/conftest.py` (how the fixtures use these), then `roxy/admin/auth/webauthn.py`.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import struct
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Any

from roxy.admin.auth import recovery_codes, totp, users
from roxy.admin.auth.passwords import Argon2Params, PasswordHasher

FAST_PARAMS = Argon2Params(time_cost=1, memory_kib=8, parallelism=1)


def fast_hasher(**kwargs: Any) -> PasswordHasher:
    """argon2id with minimal cost (tests only)."""
    return PasswordHasher(FAST_PARAMS, **kwargs)


@dataclass(frozen=True, slots=True)
class TestAdmin:
    __test__ = False  # not a pytest test class

    id: int
    username: str
    password: str
    totp_secret: str | None
    recovery_codes: list[str]


def make_admin(
    db: Any,
    *,
    cipher: totp.TotpCipher,
    hasher: PasswordHasher | None = None,
    username: str = "owner",
    password: str | None = None,
    email: str | None = None,
    bootstrap: bool = False,
    with_totp: bool = True,
    now: int = 1_760_000_000,
) -> TestAdmin:
    """Create an admin directly in control.db (synchronously) and return its secrets for the test to use."""
    hasher = hasher or fast_hasher()
    password = password or "correct horse battery " + secrets.token_hex(4)
    secret = totp.new_secret() if with_totp else None
    codes = recovery_codes.generate() if with_totp else []
    entries = recovery_codes.hash_codes_sync(hasher, codes) if codes else []
    password_hash = hasher.hash_sync(password)

    def write(conn: Any) -> int:
        user_id = users.insert_user(conn, username=username, password_hash=password_hash, now=now, email=email)
        if secret is not None:
            users.store_totp(
                conn, user_id, cipher.encrypt(secret, totp.user_context(user_id)), recovery_codes.dumps(entries)
            )
        if bootstrap:
            conn.execute("UPDATE admin_users SET mfa_bootstrap_pending = 1 WHERE id = ?", (user_id,))
        return user_id

    user_id = db.write_sync(write)
    return TestAdmin(user_id, username, password, secret, codes)


@dataclass
class RecordingTransport:
    """A mail transport that records messages instead of sending them (and can be told to fail)."""

    messages: list[EmailMessage] = field(default_factory=list)
    fail: bool = False

    async def __call__(self, message: EmailMessage, config: Any) -> None:
        if self.fail:
            raise ConnectionError("simulated mail failure")
        self.messages.append(message)

    def subjects(self) -> list[str]:
        return [str(m["Subject"]) for m in self.messages]

    def bodies(self, subject: str | None = None) -> list[str]:
        return [str(m.get_content()) for m in self.messages if subject is None or str(m["Subject"]) == subject]


# ------------------------------------------------------------------------------------------- software passkey


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class SoftwarePasskey:
    """A WebAuthn authenticator in Python: one EC P-256 key, user presence and verification always given."""

    def __init__(self) -> None:
        from cryptography.hazmat.primitives.asymmetric import ec

        self._key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = secrets.token_bytes(32)
        self.sign_count = 0
        self.user_handle: bytes | None = None

    def _cose_key(self) -> bytes:
        import cbor2

        numbers = self._key.public_key().public_numbers()
        return bytes(
            cbor2.dumps({1: 2, 3: -7, -1: 1, -2: numbers.x.to_bytes(32, "big"), -3: numbers.y.to_bytes(32, "big")})
        )

    @staticmethod
    def _client_data(kind: str, challenge: str, origin: str) -> bytes:
        return json.dumps(
            {"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": False}, separators=(",", ":")
        ).encode()

    def register(self, options: dict[str, Any], *, origin: str) -> dict[str, Any]:
        """The browser's answer to `navigator.credentials.create()` for these options."""
        import cbor2

        rp_id = str(options["rp"]["id"])
        self.user_handle = _unb64(str(options["user"]["id"]))
        client_data = self._client_data("webauthn.create", str(options["challenge"]), origin)
        flags = 0x01 | 0x04 | 0x40  # user present, user verified, attested credential data included
        attested = bytes(16) + struct.pack(">H", len(self.credential_id)) + self.credential_id + self._cose_key()
        auth_data = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", 0) + attested
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {
            "id": _b64(self.credential_id),
            "rawId": _b64(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": _b64(client_data),
                "attestationObject": _b64(attestation),
                "transports": ["internal"],
            },
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        }

    def authenticate(self, options: dict[str, Any], *, origin: str, rp_id: str | None = None) -> dict[str, Any]:
        """The browser's answer to `navigator.credentials.get()` for these options (signs the challenge)."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        rp = rp_id or str(options.get("rpId"))
        self.sign_count += 1
        client_data = self._client_data("webauthn.get", str(options["challenge"]), origin)
        auth_data = hashlib.sha256(rp.encode()).digest() + bytes([0x01 | 0x04]) + struct.pack(">I", self.sign_count)
        signature = self._key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        response: dict[str, Any] = {
            "clientDataJSON": _b64(client_data),
            "authenticatorData": _b64(auth_data),
            "signature": _b64(signature),
        }
        if self.user_handle is not None:
            response["userHandle"] = _b64(self.user_handle)
        return {
            "id": _b64(self.credential_id),
            "rawId": _b64(self.credential_id),
            "type": "public-key",
            "response": response,
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        }


# ------------------------------------------------------------------------------------------- HTTP harness

TEST_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"
LOGIN_PATH = "/admin/api/v1/auth/login"
MFA_PATH = "/admin/api/v1/auth/mfa"
SESSION_PATH = "/admin/api/v1/auth/session"


@dataclass
class AuthHarness:
    """A running app (lifespan started) with the auth routes, a fast hasher, recorded mail and helpers.

    Requests go through `http` (an httpx client on `https://testserver`, so Secure cookies round-trip). The
    caller IP is set per request with `X-Forwarded-For` (the test peer is loopback, a trusted proxy).
    """

    app: Any
    ctx: Any
    http: Any
    mail: RecordingTransport
    clock: Any
    hasher: PasswordHasher
    cipher: totp.TotpCipher
    site_origin: str
    clients: list[Any] = field(default_factory=list)

    def new_client(self) -> Any:
        """Another browser (its own cookie jar) talking to the same app."""
        import httpx

        transport = httpx.ASGITransport(app=self.app, client=("127.0.0.1", 50000))
        client = httpx.AsyncClient(transport=transport, base_url="https://testserver")
        self.clients.append(client)
        return client

    def admin(self, **kwargs: Any) -> TestAdmin:
        return make_admin(
            self.ctx.dbs.control, cipher=self.cipher, hasher=self.hasher, now=int(self.clock.now()), **kwargs
        )

    def headers(self, *, ip: str | None = None, ua: str | None = TEST_UA, csrf: str | None = None) -> dict[str, str]:
        out = {"Origin": self.site_origin, "Sec-Fetch-Site": "same-origin", "Accept": "application/json"}
        if ua is not None:
            out["User-Agent"] = ua
        if ip is not None:
            out["X-Forwarded-For"] = ip
        if csrf is not None:
            out["X-CSRF-Token"] = csrf
        return out

    async def set_settings(self, **values: Any) -> None:
        from roxy.config.audit import Actor
        from roxy.config.settings_service import SettingsService

        service = SettingsService(self.ctx.dbs.control, runtime=self.ctx.settings, clock=self.clock)
        await service.update(values, Actor("cli", "test"), "test setup")
        await self.ctx.settings.reload()

    async def allow_admin_cidr(self, cidr: str) -> None:
        """Add an `allow_admin` access list row and reload the rules snapshot."""
        now = int(self.clock.now())
        sql = (
            "INSERT INTO access_list (kind, cidr, note, created_by, created_at) "
            "VALUES ('allow_admin', ?, 'test', 'test', ?)"
        )
        self.ctx.dbs.control.write_sync(lambda conn: conn.execute(sql, (cidr, now)))
        await self.ctx.rules.reload()

    def next_code(self, admin: TestAdmin) -> str:
        """Move to the next 30 s step (the replay guard refuses a step twice) and return its TOTP code."""
        assert admin.totp_secret is not None
        self.clock.advance(totp.TOTP_STEP_S)
        return totp.code_at(admin.totp_secret, self.clock.now())

    async def password_step(
        self,
        admin: TestAdmin,
        *,
        client: Any = None,
        ip: str | None = None,
        ua: str | None = TEST_UA,
        trust: bool = False,
        password: str | None = None,
        username: str | None = None,
    ) -> Any:
        http = client or self.http
        return await http.post(
            LOGIN_PATH,
            json={
                "username": username or admin.username,
                "password": admin.password if password is None else password,
                "trust_device": trust,
            },
            headers=self.headers(ip=ip, ua=ua),
        )

    async def mfa(
        self,
        transaction: str,
        method: str,
        *,
        code: str | None = None,
        credential: dict[str, Any] | None = None,
        client: Any = None,
        ip: str | None = None,
        ua: str | None = TEST_UA,
    ) -> Any:
        http = client or self.http
        body: dict[str, Any] = {"transaction": transaction, "method": method}
        if code is not None:
            body["code"] = code
        if credential is not None:
            body["credential"] = credential
        return await http.post(MFA_PATH, json=body, headers=self.headers(ip=ip, ua=ua))

    async def login(
        self,
        admin: TestAdmin,
        *,
        client: Any = None,
        ip: str | None = None,
        ua: str | None = TEST_UA,
        trust: bool = False,
    ) -> Any:
        """Password plus TOTP; returns the final response (200 with a session cookie on success)."""
        first = await self.password_step(admin, client=client, ip=ip, ua=ua, trust=trust)
        assert first.status_code == 200, first.text
        data = first.json()
        if data.get("LoggedIn"):
            return first
        return await self.mfa(data["Transaction"], "totp", code=self.next_code(admin), client=client, ip=ip, ua=ua)

    async def csrf(self, *, client: Any = None, ip: str | None = None, ua: str | None = TEST_UA) -> str:
        """A fresh masked CSRF token for the client's current session."""
        http = client or self.http
        response = await http.get(SESSION_PATH, headers=self.headers(ip=ip, ua=ua))
        assert response.status_code == 200, response.text
        return str(response.json()["CsrfToken"])

    async def post(
        self,
        path: str,
        body: Any = None,
        *,
        client: Any = None,
        ip: str | None = None,
        ua: str | None = TEST_UA,
        csrf: bool = True,
    ) -> Any:
        """POST JSON to an authenticated endpoint with a fresh CSRF token."""
        http = client or self.http
        token = await self.csrf(client=http, ip=ip, ua=ua) if csrf else None
        payload = body if body is not None else {}
        return await http.post(path, json=payload, headers=self.headers(ip=ip, ua=ua, csrf=token))

    async def drain(self) -> None:
        notifier = getattr(self.ctx, "alerts", None)
        if notifier is not None:
            await notifier.drain()


def ensure_auth_routes(app: Any) -> None:
    """Include the auth router unless the admin router already did (it does in every app `create_app` builds).

    FastAPI keeps an included router's routes nested (it no longer copies them into `app.router.routes`), so the
    login route is looked for with `iter_route_contexts`, which walks the nested routers; a flat look missed it and
    included the auth router a second time.
    """
    from fastapi.routing import iter_route_contexts

    from roxy.admin.auth.routes import router

    if not any(str(context.path or "") == LOGIN_PATH for context in iter_route_contexts(app.router.routes)):
        app.include_router(router)


@asynccontextmanager
async def auth_harness(env: Any, *, clock: Any, credentials_dir: Any) -> AsyncIterator[AuthHarness]:
    """Start an app with the auth routes and yield an `AuthHarness` (see the class docstring)."""
    import httpx
    from pydantic import SecretStr

    from roxy.main import create_app
    from roxy.notify.mail import MailConfig, MailSender
    from roxy.notify.notifier import Notifier

    app = create_app(env, clock=clock)
    ensure_auth_routes(app)
    hasher = fast_hasher()
    app.state.auth_hasher = hasher
    lifespan = app.router.lifespan_context(app)
    await lifespan.__aenter__()
    try:
        ctx = app.state.ctx
        mail = RecordingTransport()
        config = MailConfig(
            to_addr="owner@example.invalid", from_addr="alerts@example.invalid", password=SecretStr("not-a-secret")
        )
        ctx.alerts = Notifier(
            hot_db=ctx.dbs.hot,
            settings=ctx.settings,
            site_origin=str(ctx.env.site_origin),
            mail=MailSender(config, transport=mail),
            webhook=None,
            clock=clock,
        )
        cipher = totp.load_cipher(credentials_dir)
        assert cipher is not None, "the test credentials directory has no totp_encryption_key"
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 50000))
        async with httpx.AsyncClient(transport=transport, base_url="https://testserver") as http:
            harness = AuthHarness(
                app=app,
                ctx=ctx,
                http=http,
                mail=mail,
                clock=clock,
                hasher=hasher,
                cipher=cipher,
                site_origin=str(ctx.env.site_origin),
            )
            try:
                yield harness
            finally:
                await harness.drain()
                for client in harness.clients:
                    await client.aclose()
    finally:
        await lifespan.__aexit__(None, None, None)
