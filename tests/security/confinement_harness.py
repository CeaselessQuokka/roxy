"""Shared harness for the credential confinement probes (`tests/security/test_confinement_*.py`).

What this is
    Helpers the adversarial credential review (lens C1, C2, D1, plan 19.5) uses in several test modules:
    `leak_scan` (where a credential, or any 24 character run of its secret part, shows up in a blob, also after
    percent-decoding), `load_fixture` (loads `tests/fixtures/*.py` or another test folder's helper by path), and
    `running_app`, the fully wired application over temporary databases with a loopback `MockUpstream` playing
    every Roblox host and a loopback `RecordingProxy` playing DataImpulse, so the bytes sent on each egress path
    can be inspected after the fact.

Why it exists
    The review has to prove invariants across package boundaries: a caller request (any verb, path encoding,
    routing rule or fallback) never leaves with the cookie, the cookie never goes through the rotator, the
    credential never lands in a log, a database row, a capture or an admin answer. Only the real objects wired
    together can show that, and only a mock that records every request (headers included) can show what was sent.

How it works
    `running_app` sets the development-only egress override (`ROXY_TEST_UPSTREAM_BASE` sends direct and credential
    traffic to the mock; `ROXY_TEST_ROTATOR_PROXY` sends rotator traffic through the recording proxy, which also
    forwards to the mock), removes the mail and webhook credentials (alerts go to the log), builds `create_app`
    with a `FakeClock`, runs the lifespan, and turns the tarpit off. Requests rotated through documentation
    address ranges (RFC 5737) in `X-Forwarded-For` so per-IP limits never interfere. Requests that went through the
    proxy carry its `X-Exit-Ip` header at the mock, so a test can tell the rotator path apart from the server IP.
    `leak_scan` uses the same sampling idea as the leak guard: a 24 character run of the secret always contains one
    of the secret's 12 character pieces that start at a multiple of 12, so the blob is searched for those pieces
    first (fast, C level) and only a hit is confirmed against every 24 character window around it.

What to read next
    `tests/security/test_confinement_routing.py` (the main battery), `tests/fixtures/recording_proxy.py` (the
    proxy and the mock), and `tests/security/test_credential_suite.py` (the per-layer 19.5 tests).
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib.util
import itertools
import secrets
import sys
from collections.abc import AsyncIterator, Callable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any
from urllib.parse import unquote_to_bytes

import httpx
import pytest

from roxy.config.audit import Actor
from roxy.config.settings_service import SettingsService
from roxy.core.clock import FakeClock
from roxy.core.redact import TOKEN_PREFIX
from roxy.main import create_app
from roxy.rules.service import RulesService

ROOT = Path(__file__).resolve().parents[2]
ADMIN = Actor("admin", "confinement")
WINDOW = 24
"""Shortest run of the credential that counts as a leak (plan C2 item 4, 9.15)."""
PIECE = 12
NETS = ("192.0.2", "198.51.100", "203.0.113")  # documentation ranges (RFC 5737): never real clients
PROBE_PATH = "/v1/users/authenticated"
"""The default `credential_probe_url` path (Roxy's own credential probe, the one allowed credential use, D1)."""


def load_fixture(name: str, folder: str = "fixtures") -> ModuleType:
    """Load `tests/<folder>/<name>.py` by path once (tests are not a package)."""
    key = f"roxy_confinement_{folder.replace('/', '_')}_{name}"
    if key in sys.modules:
        return sys.modules[key]
    spec = importlib.util.spec_from_file_location(key, ROOT / "tests" / folder / f"{name}.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[key] = module
    spec.loader.exec_module(module)
    return module


def secret_part(value: str) -> str:
    """The secret part of a cookie value: what follows the public `TOKEN_PREFIX` (the whole value without it)."""
    return value.removeprefix(TOKEN_PREFIX)


def _variants(data: bytes) -> list[bytes]:
    out = [data]
    current = data
    for _ in range(2):
        if b"%" not in current:
            break
        decoded = unquote_to_bytes(current)
        if decoded == current:
            break
        out.append(decoded)
        current = decoded
    return out


def _piece_offset(folded: bytes, secret: bytes) -> int | None:
    """The secret offset of a 24 character run of `secret` found in `folded`, else None (module docstring)."""
    if len(secret) < WINDOW:
        return None
    for start in range(0, len(secret) - PIECE + 1, PIECE):
        if secret[start : start + PIECE] not in folded:
            continue
        for window_start in range(max(0, start - PIECE), min(start, len(secret) - WINDOW) + 1):
            if secret[window_start : window_start + WINDOW] in folded:
                return window_start
    return None


def leak_scan(blob: bytes | str, value: str) -> list[str]:
    """Where `value` (a credential) shows up in `blob`: the whole value, or any 24+ character run of its secret
    part, ignoring ASCII case, as sent and after up to two rounds of percent-decoding. Empty when clean."""
    data = blob.encode("utf-8", "replace") if isinstance(blob, str) else bytes(blob)
    secret = secret_part(value).encode("utf-8").lower()
    found: list[str] = []
    for variant in _variants(data):
        if value.encode("utf-8") in variant and "full value" not in found:
            found.append("full value")
        offset = _piece_offset(variant.lower(), secret)
        if offset is not None:
            found.append(f"24 character piece at secret offset {offset}")
            break
    return found


def test_leak_scan_is_not_vacuous() -> None:
    """Self-check (collected only where imported into a test module): the scanner finds what it must."""
    value = TOKEN_PREFIX + secrets.token_hex(160).upper()
    part = secret_part(value)
    assert leak_scan(b"x" + value.encode() + b"y", value) == ["full value", "24 character piece at secret offset 0"]
    for start in (0, 5, 11, 12, 13, 100, len(part) - WINDOW):
        assert leak_scan(b"noise " + part[start : start + WINDOW].lower().encode() + b" noise", value), start
    assert leak_scan(part[3 : 3 + WINDOW - 1].encode(), value) == []  # 23 characters is below the threshold
    encoded = "".join(f"%{ord(ch):02X}" for ch in part[40:80])
    assert leak_scan(encoded, value)
    assert leak_scan(TOKEN_PREFIX + "zz", value) == []  # the public prefix alone is not a leak


# ------------------------------------------------------------------------------------------------ the app


@dataclass
class AppRun:
    """The running app and the tools a probe uses on it."""

    app: Any
    ctx: Any
    clock: FakeClock
    http: httpx.AsyncClient
    mock: Any
    proxy: Any
    credential: str = field(repr=False)  # never in an assertion message, even a fake one
    _ips: Iterator[int] = field(default_factory=itertools.count)

    def ip(self) -> str:
        """A client address no other request in this run has used."""
        n = next(self._ips)
        return f"{NETS[n // 254 % len(NETS)]}.{n % 254 + 1}"

    async def request(
        self,
        method: str,
        path: str,
        *,
        ip: str | None = None,
        headers: Mapping[str, str] | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        sent = {"User-Agent": "Roblox/Linux", "X-Forwarded-For": ip or self.ip()}
        sent.update(headers or {})
        return await self.http.request(method, path, headers=sent, **kwargs)

    async def get(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", path, **kwargs)

    async def settings(self, **changes: Any) -> None:
        service = SettingsService(self.ctx.dbs.control, runtime=self.ctx.settings, clock=self.clock)
        await service.update(changes, ADMIN, "confinement probe")

    def rules(self) -> RulesService:
        return RulesService(self.ctx.dbs.control, clock=self.clock, store=self.ctx.rules)

    async def rule(self, table: str, row: Mapping[str, Any]) -> Any:
        """Create a rule through the audited service; returns its key."""
        change = await self.rules().create(table, dict(row), ADMIN, "confinement probe")
        return change.key

    async def activate_credential(self) -> None:
        """Run Roxy's own probe (the D1 use) so the credential status is `active`."""
        self.mock.routes[PROBE_PATH] = self.fixture().MockResponse(body=b'{"id": 1, "name": "owner"}')
        probe = await self.ctx.egress.credential.probe("admin_check", fetch=self.ctx.upstream.credential_probe_fetch)
        assert probe.ok, probe

    @staticmethod
    def fixture() -> ModuleType:
        return load_fixture("recording_proxy")

    def mock_requests(self) -> list[Any]:
        return list(self.mock.requests)

    def cookie_requests(self) -> list[Any]:
        """Every request the mock Roblox received with a `Cookie` header."""
        return [r for r in self.mock_requests() if r.header("Cookie")]

    async def settle(self, predicate: Callable[[], bool] | None = None, timeout_s: float = 5.0) -> bool:
        """Wait until `predicate` holds (False after `timeout_s`); without one, give background work 0.3 s."""
        if predicate is None:
            await asyncio.sleep(0.3)
            return True
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout_s
        while loop.time() < deadline:
            if predicate():
                return True
            await asyncio.sleep(0.02)
        return predicate()


@contextlib.asynccontextmanager
async def running_app(
    env: Any,
    credentials_dir: Path,
    fake_secrets: Mapping[str, str],
    monkeypatch: pytest.MonkeyPatch,
    *,
    credential_file_text: str | None = None,
) -> AsyncIterator[AppRun]:
    """The real app, Roblox played by a loopback mock, DataImpulse by a loopback recording proxy (module doc)."""
    fixture = load_fixture("recording_proxy")
    mock = fixture.MockUpstream().start()
    proxy = fixture.RecordingProxy(upstream=mock.address).start()
    monkeypatch.setenv("ROXY_TEST_UPSTREAM_BASE", mock.base_url)
    monkeypatch.setenv("ROXY_TEST_ROTATOR_PROXY", proxy.url)
    for name in ("smtp_password", "alert_webhook_url"):
        (credentials_dir / name).unlink(missing_ok=True)  # alerts go to the log only
    if credential_file_text is not None:
        (credentials_dir / "roblox_credential").write_text(credential_file_text, encoding="utf-8")
    clock = FakeClock()
    app = create_app(env, clock=clock)
    lifespan = app.router.lifespan_context(app)
    await lifespan.__aenter__()
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("127.0.0.1", 50000)), base_url="http://testserver"
    )
    run = AppRun(app, app.state.ctx, clock, client, mock, proxy, fake_secrets["roblox_credential"])
    try:
        await run.settings(tarpit_enabled=0, rotator_enabled=1, backoff_base_ms=10, backoff_cap_ms=20)
        yield run
    finally:
        await client.aclose()
        await lifespan.__aexit__(None, None, None)
        proxy.stop()
        mock.stop()


__all__ = [
    "ADMIN",
    "PROBE_PATH",
    "WINDOW",
    "AppRun",
    "leak_scan",
    "load_fixture",
    "running_app",
    "secret_part",
]
