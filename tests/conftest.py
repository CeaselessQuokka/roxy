"""Shared pytest fixtures for every Roxy v2 test.

What this is
    The fixtures DESIGN.md section 10 promises: `state_dir`, `credentials_dir`, `env`, `dbs`, `fake_clock`,
    `app`, `client` and `respx_mock`, plus an autouse socket guard that fails any test that tries to open a
    network connection to anything but this machine (plan 19.12).

Why it exists
    Tests must never touch real systems: no Roblox, no DataImpulse, no ipify, no Gmail, no webhooks, and no real
    secrets. Every database lives in a temporary directory, every secret is a fake generated at runtime, and a
    connection to a non-loopback address raises `NetworkAccessBlocked` instead of leaving the machine.

How it works
    - The guard replaces `socket.socket.connect`, `connect_ex` and `socket.getaddrinfo` for each test. Loopback
      addresses (127.0.0.0/8, ::1), `localhost`, names ending in `.localhost` and Unix sockets are allowed, so
      local mock servers, multiprocessing and asyncio still work. A DNS lookup of any other name is refused too,
      because the lookup itself would leave the machine.
    - `env` sets only fake `ROXY_*` variables (after removing any the developer's shell had) and builds
      `EnvSettings` from them, falling back to a plain object while `config/env.py` does not exist yet.
    - `app` and `client` skip the test cleanly while `roxy.main.create_app` cannot be imported yet.
    - Tests marked `live` run only with `ROXY_LIVE_TESTS=1`, and then without the guard. Agents never set it.

What to read next
    `tests/unit/storage/test_storage_db.py` for fixtures in use, and `roxy/storage/db.py`.
"""

from __future__ import annotations

import ipaddress
import os
import secrets
import socket
import warnings
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from roxy.core.clock import FakeClock

# ------------------------------------------------------------------------------------------- socket guard


class NetworkAccessBlocked(RuntimeError):
    """A test tried to reach a non-loopback address. Use respx or a local mock server instead (plan 19.12)."""


_REAL_CONNECT = socket.socket.connect
_REAL_CONNECT_EX = socket.socket.connect_ex
_REAL_GETADDRINFO = socket.getaddrinfo
_ALLOWED_NAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"})


def is_loopback_host(host: object) -> bool:
    """True for loopback addresses and names that always resolve to this machine."""
    if host is None:
        return True  # getaddrinfo(None, port) means "this machine" (passive or loopback)
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    if not isinstance(host, str):
        return False
    name = host.strip().strip("[]").lower().rstrip(".")
    if name in _ALLOWED_NAMES or name.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(name.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped.is_loopback
    return address.is_loopback


def _check_target(family: int, address: Any) -> None:
    if family == getattr(socket, "AF_UNIX", object()):
        return
    host = address[0] if isinstance(address, tuple) and address else address
    if not is_loopback_host(host):
        raise NetworkAccessBlocked(f"test tried to connect to {host!r}; tests may only use loopback (plan 19.12)")


def _guarded_connect(self: socket.socket, address: Any) -> None:
    _check_target(self.family, address)
    _REAL_CONNECT(self, address)


def _guarded_connect_ex(self: socket.socket, address: Any) -> int:
    _check_target(self.family, address)
    return _REAL_CONNECT_EX(self, address)


def _guarded_getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
    if not is_loopback_host(host):
        raise NetworkAccessBlocked(f"test tried to resolve {host!r}; tests may only use loopback (plan 19.12)")
    return _REAL_GETADDRINFO(host, *args, **kwargs)


def _live_tests_enabled() -> bool:
    return os.environ.get("ROXY_LIVE_TESTS") == "1"


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip tests marked `live` unless ROXY_LIVE_TESTS=1 (never in CI, never by the implementing agents)."""
    if _live_tests_enabled():
        return
    skip_live = pytest.mark.skip(reason="live test: set ROXY_LIVE_TESTS=1 to run (never in CI)")
    for item in items:
        if "live" in item.keywords:
            item.add_marker(skip_live)


@pytest.fixture(autouse=True)
def _socket_guard(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Fail any connection to a non-loopback address for the duration of the test."""
    if "live" in request.keywords and _live_tests_enabled():
        yield
        return
    monkeypatch.setattr(socket.socket, "connect", _guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", _guarded_connect_ex)
    monkeypatch.setattr(socket, "getaddrinfo", _guarded_getaddrinfo)
    yield


@pytest.fixture
def loopback_check() -> Any:
    """The guard's `is_loopback_host` function. A fixture, because `import conftest` is ambiguous once nested
    test folders have their own conftest.py."""
    return is_loopback_host


# ------------------------------------------------------------------------------------------- fake secrets

TOKEN_PREFIX = (
    "_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-"
    "items.|_"
)
"""The public warning text every Roblox cookie starts with (v1 config.py). Public, not a secret (plan C2.5)."""


def make_fake_secrets() -> dict[str, str]:
    """Fresh fake values for every systemd credential name (plan 9.8). Generated at runtime, never committed.

    Keys are 32 random bytes as 64 hex characters. URLs point at loopback port 9 (discard), so even a bug that
    used them could not leave the machine.
    """
    return {
        "roblox_credential": TOKEN_PREFIX + "FAKETESTCREDENTIAL" + secrets.token_hex(160).upper(),
        "rotator_url": f"http://fakeuser:fake{secrets.token_hex(8)}@127.0.0.1:9",
        "smtp_password": "fake-" + secrets.token_hex(8),
        "alert_emails": "owner@example.invalid",
        "alert_webhook_url": f"http://127.0.0.1:9/fake-webhook/{secrets.token_hex(8)}",
        "credential_encryption_key": secrets.token_hex(32),
        "totp_encryption_key": secrets.token_hex(32),
        "ip_hash_key": secrets.token_hex(32),
        "rclone_config": "[fake]\ntype = local\n",
    }


# ------------------------------------------------------------------------------------------- environment


@pytest.fixture
def state_dir(tmp_path: Path) -> Path:
    """An empty state directory (mode 0750, like systemd's StateDirectory) for this test only."""
    directory = tmp_path / "state"
    directory.mkdir()
    directory.chmod(0o750)
    return directory


@pytest.fixture
def fake_secrets() -> dict[str, str]:
    """The fake credential values written to `credentials_dir` (so tests can look for leaks of them)."""
    return make_fake_secrets()


@pytest.fixture
def credentials_dir(tmp_path: Path, fake_secrets: dict[str, str]) -> Path:
    """A fake systemd CREDENTIALS_DIRECTORY: one file per credential, mode 0600, directory mode 0700."""
    directory = tmp_path / "credentials"
    directory.mkdir()
    for name, value in fake_secrets.items():
        path = directory / name
        path.write_text(value, encoding="utf-8")
        path.chmod(0o600)
    directory.chmod(0o700)
    return directory


@dataclass
class FallbackEnv:
    """Stand-in for `config.env.EnvSettings` while it does not exist (same field names, lowercase)."""

    env: str
    auto_migrate: bool
    state_dir: Path
    control_db: Path
    hot_db: Path
    metrics_db: Path
    cache_db: Path
    color: str
    workers: int
    log_level: str
    max_requests: int
    site_origin: str
    credentials_dir: Path


@pytest.fixture
def env_vars(state_dir: Path, credentials_dir: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """Set the test process environment: only fake ROXY_* values pointing into the temporary directories."""
    for name in list(os.environ):
        if name.startswith("ROXY_") or name == "CREDENTIALS_DIRECTORY":
            monkeypatch.delenv(name, raising=False)
    values = {
        "ROXY_ENV": "development",
        "ROXY_AUTO_MIGRATE": "1",
        "ROXY_STATE_DIR": str(state_dir),
        "ROXY_CONTROL_DB": str(state_dir / "control.db"),
        "ROXY_HOT_DB": str(state_dir / "hot.db"),
        "ROXY_METRICS_DB": str(state_dir / "metrics.db"),
        "ROXY_CACHE_DB": str(state_dir / "cache.db"),
        "ROXY_COLOR": "dev",
        "ROXY_WORKERS": "1",
        "ROXY_LOG_LEVEL": "info",
        "ROXY_MAX_REQUESTS": "20000",
        "ROXY_BIND": "127.0.0.1:0",
        "ROXY_INTERNAL_SOCKET": str(state_dir / "internal.sock"),
        "ROXY_TRUSTED_PROXY_HOPS": "1",
        "ROXY_TRUSTED_PROXY_CIDRS": "127.0.0.1/32,::1/128",
        "ROXY_SITE_ORIGIN": "http://localhost",
        "ROXY_ROTATOR_IP_ECHO_URL": "http://127.0.0.1:9/ip",
        "CREDENTIALS_DIRECTORY": str(credentials_dir),
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    return values


@pytest.fixture
def env(env_vars: dict[str, str]) -> Any:
    """`EnvSettings` for the temporary state (ROXY_ENV=development, ROXY_AUTO_MIGRATE=1, fake credentials)."""
    try:
        from roxy.config.env import EnvSettings
    except ImportError:
        return _fallback_env(env_vars)
    try:
        return EnvSettings()
    except Exception as exc:  # config/env.py is being written in parallel; keep storage tests independent of it
        warnings.warn(f"EnvSettings() failed in tests ({exc!r}); using FallbackEnv", stacklevel=2)
        return _fallback_env(env_vars)


def _fallback_env(values: dict[str, str]) -> FallbackEnv:
    return FallbackEnv(
        env=values["ROXY_ENV"],
        auto_migrate=values["ROXY_AUTO_MIGRATE"] == "1",
        state_dir=Path(values["ROXY_STATE_DIR"]),
        control_db=Path(values["ROXY_CONTROL_DB"]),
        hot_db=Path(values["ROXY_HOT_DB"]),
        metrics_db=Path(values["ROXY_METRICS_DB"]),
        cache_db=Path(values["ROXY_CACHE_DB"]),
        color=values["ROXY_COLOR"],
        workers=int(values["ROXY_WORKERS"]),
        log_level=values["ROXY_LOG_LEVEL"],
        max_requests=int(values["ROXY_MAX_REQUESTS"]),
        site_origin=values["ROXY_SITE_ORIGIN"],
        credentials_dir=Path(values["CREDENTIALS_DIRECTORY"]),
    )


# --------------------------------------------------------------------------------------------- storage


@pytest.fixture
def dbs(env: Any) -> Iterator[Any]:
    """The four databases for `env`, fully migrated (expand and contract), closed after the test."""
    from roxy.storage.db import open_databases
    from roxy.storage.migrate import migrate_all

    databases = open_databases(env)
    migrate_all(databases, contract=True)
    try:
        yield databases
    finally:
        databases.close_all_sync()


@pytest.fixture
def fake_clock() -> FakeClock:
    """A clock that moves only when the test calls `advance()` (starts at a fixed time in 2025)."""
    return FakeClock()


# ------------------------------------------------------------------------------------------- app and client


@pytest.fixture
def app(env: Any) -> Any:
    """`create_app(env)`. Skips the test while the application factory cannot be imported yet."""
    try:
        from roxy.main import create_app
    except ImportError as exc:
        pytest.skip(f"roxy.main.create_app is not available yet: {exc}")
    try:
        return create_app(env)
    except (ImportError, NotImplementedError) as exc:
        pytest.skip(f"create_app(env) cannot start yet: {exc!r}")


@pytest.fixture
async def client(app: Any) -> AsyncIterator[Any]:
    """An httpx.AsyncClient talking to `app` in process, with the lifespan (startup and shutdown) running."""
    import httpx

    lifespan = app.router.lifespan_context(app)
    try:
        await lifespan.__aenter__()
    except (ImportError, NotImplementedError) as exc:
        pytest.skip(f"the app lifespan cannot start yet: {exc!r}")
    try:
        # client=... sets the ASGI peer address; a loopback peer, like nginx in production.
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 50000))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
            yield http
    finally:
        await lifespan.__aexit__(None, None, None)


@pytest.fixture
def respx_mock() -> Iterator[Any]:
    """A respx router for mock Roblox hosts. Any request without a matching route fails (nothing gets out)."""
    import respx

    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        yield router
