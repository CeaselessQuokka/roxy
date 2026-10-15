"""Fixtures for the egress unit tests.

What this is
    `harness` (the `tests/fixtures/recording_proxy.py` module, loaded by path), `settings` (catalog defaults that a
    test may override), `mock_upstream` (a loopback Roblox stand-in), `make_egress` (builds and starts an
    `EgressClients` over the test databases and closes it afterwards), and `secret` (the fake credential value).

Why it exists
    Most egress tests need the same setup: migrated temporary databases, fake systemd credentials, a mock upstream
    and the development test override that sends Roblox traffic to it. Keeping it here keeps each test short.

How it works
    The root `tests/conftest.py` provides `env` (EnvSettings with fake credentials), `dbs` (migrated databases)
    and the socket guard. `make_egress(**options)` passes `environ` explicitly, so no test depends on (or
    changes) the real process environment unless it says so.

What to read next
    `tests/fixtures/recording_proxy.py`, then `src/roxy/egress/clients.py`.
"""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from roxy.core.clock import SYSTEM_CLOCK
from roxy.core.redact import SecretRegistry
from roxy.egress import metering

_HARNESS_PATH = Path(__file__).resolve().parents[2] / "fixtures" / "recording_proxy.py"


def load_harness() -> ModuleType:
    """Load `tests/fixtures/recording_proxy.py` once by file path (tests/ is not a package)."""
    name = "roxy_test_recording_proxy"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, _HARNESS_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def harness() -> ModuleType:
    return load_harness()


@pytest.fixture(autouse=True)
def _clean_process_state() -> Iterator[None]:
    """Each test starts with an empty secret registry and an untested metering mode."""
    SecretRegistry.clear()
    metering.reset_self_test()
    yield
    SecretRegistry.clear()
    metering.reset_self_test()


@pytest.fixture
def settings(harness: ModuleType) -> Any:
    return harness.FakeSettings()


@pytest.fixture
def secret(fake_secrets: dict[str, str]) -> str:
    """The fake Roblox credential written to the test CREDENTIALS_DIRECTORY."""
    return fake_secrets["roblox_credential"]


@pytest.fixture
def mock_upstream(harness: ModuleType) -> Iterator[Any]:
    with harness.MockUpstream() as server:
        yield server


@pytest.fixture
async def make_egress(env: Any, dbs: Any, settings: Any) -> AsyncIterator[Callable[..., Awaitable[Any]]]:
    """`await make_egress(environ={...}, settings=..., clock=..., **kwargs)` -> a started EgressClients."""
    from roxy.egress.clients import EgressClients

    built: list[Any] = []

    async def factory(**options: Any) -> Any:
        environ = options.pop("environ", {})
        use_env = options.pop("env", env)
        clients = EgressClients(
            env=use_env,
            settings=options.pop("settings", settings),
            dbs=options.pop("dbs", dbs),
            clock=options.pop("clock", SYSTEM_CLOCK),
            worker_id=options.pop("worker_id", f"test:{len(built)}"),
            environ=environ,
            **options,
        )
        built.append(clients)
        await clients.start()
        return clients

    yield factory
    for clients in built:
        await clients.aclose()


def override_environ(mock: Any, proxy_url: str | None = None) -> dict[str, str]:
    """The development test override pointing Roblox traffic (and optionally the rotator) at loopback servers."""
    environ = {"ROXY_TEST_UPSTREAM_BASE": mock.base_url}
    if proxy_url:
        environ["ROXY_TEST_ROTATOR_PROXY"] = proxy_url
    return environ


@pytest.fixture
def override(mock_upstream: Any) -> dict[str, str]:
    return override_environ(mock_upstream)
