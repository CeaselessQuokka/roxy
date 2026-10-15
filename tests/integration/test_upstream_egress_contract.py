"""The real egress package under the real upstream service (DESIGN.md 11.3 meets 11.4), over loopback.

Uses the egress package's `MockUpstream` and its development test override (Roblox traffic goes to a loopback
server, `ROXY_TEST_UPSTREAM_BASE`), so the contract between the two packages is exercised for real: the outbound
request fields, the header profile the egress adds, purposes, exception names, the credential probe hook
(`CredentialManager.probe(kind, fetch=...)`) paced by the reserved probe sub-bucket, and the credential confinement.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from roxy.core.clock import SYSTEM_CLOCK
from roxy.core.reasons import AuthClass, Egress, ReasonCode
from roxy.upstream.queue import Priority

pytest.importorskip("roxy.egress.clients")

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: Path) -> Any:
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


fakes = load("upstream_fakes", ROOT / "unit" / "upstream" / "upstream_fakes.py")
harness = load("roxy_test_recording_proxy", ROOT / "fixtures" / "recording_proxy.py")


@pytest.fixture
def mock() -> Any:
    with harness.MockUpstream() as server:
        yield server


@pytest.fixture
async def wired(env: Any, dbs: Any, mock: Any) -> AsyncIterator[Any]:
    from roxy.core.redact import SecretRegistry
    from roxy.egress.clients import EgressClients

    SecretRegistry.clear()
    settings = fakes.FakeSettings(rotator_enabled=0)
    egress = EgressClients(
        env=env,
        settings=settings,
        dbs=dbs,
        clock=SYSTEM_CLOCK,
        worker_id="contract:1",
        environ={"ROXY_TEST_UPSTREAM_BASE": mock.base_url},
    )
    await egress.start()
    rules = fakes.FakeRules()
    ctx = fakes.make_ctx(dbs, SYSTEM_CLOCK, egress, settings=settings, rules=rules)
    service = fakes.make_service(ctx)
    try:
        yield service
    finally:
        await egress.aclose()
        SecretRegistry.clear()


async def get(service: Any, **fields: Any) -> Any:
    return await service.fetch(fakes.request(service, **fields), priority=Priority.INTERACTIVE, stale_available=False)


async def test_direct_call_through_the_real_egress(wired: Any, mock: Any) -> None:
    mock.routes["/v1/games"] = harness.MockResponse(body=b'{"data":[1]}')
    result = await get(wired, query=[("universeIds", "1"), ("universeIds", "2")])
    assert (result.status, result.reason, result.egress) == (200, ReasonCode.UPSTREAM_OK, Egress.DIRECT)
    assert result.body == b'{"data":[1]}'
    assert result.bytes_out > 0
    seen = mock.requests[-1]
    assert seen.path == "/v1/games?universeIds=1&universeIds=2"
    assert seen.header("Host") == "games.roblox.com"
    assert seen.header("User-Agent")  # the egress header profile was applied
    assert seen.header("Cookie") is None  # anonymous


async def test_429_cooldown_through_the_real_egress(wired: Any, mock: Any) -> None:
    mock.routes["/v1/games"] = harness.MockResponse(status=429, headers=[("Retry-After", "30")], body=b"{}")
    first = await get(wired)
    assert (first.status, first.reason, first.retry_after_s) == (429, ReasonCode.UPSTREAM_COOLDOWN, 30)
    count = len(mock.requests)
    second = await get(wired)
    assert second.reason is ReasonCode.UPSTREAM_COOLDOWN
    assert len(mock.requests) == count  # nothing was sent during the cooldown


async def test_redirect_hops_followed_by_upstream(wired: Any, mock: Any) -> None:
    mock.routes["/v1/old"] = harness.MockResponse(status=302, headers=[("Location", "https://games.roblox.com/v1/new")])
    mock.routes["/v1/new"] = harness.MockResponse(body=b'{"moved":true}')
    result = await get(wired, path="/v1/old", query=[])
    assert result.status == 200
    assert result.calls == 2  # two calls, two bucket slots
    assert [r.path for r in mock.requests[-2:]] == ["/v1/old", "/v1/new"]


async def test_credential_probe_hook_is_paced_by_the_probe_bucket(wired: Any, mock: Any, dbs: Any) -> None:
    mock.routes["/v1/users/authenticated"] = harness.MockResponse(body=json.dumps({"id": 42}).encode())
    manager = wired._ctx.egress.credential
    result = await manager.probe("admin_check", fetch=wired.credential_probe_fetch)
    assert result.outcome == "ok", result
    keys = {row[0] for row in fakes.read_rows(dbs.hot, "SELECT bucket_key FROM upstream_bucket")}
    assert "egress:credential:probe" in keys
    assert "egress:credential" not in keys
    assert mock.requests[-1].header("Cookie")  # the credential path attaches the cookie itself


async def test_allowlisted_get_uses_the_credential_and_never_anonymous(wired: Any, mock: Any) -> None:
    mock.routes["/v1/users/authenticated"] = harness.MockResponse(body=json.dumps({"id": 42}).encode())
    manager = wired._ctx.egress.credential
    await manager.probe("admin_check", fetch=wired.credential_probe_fetch)
    # Allowlist rows grant exactly what they name (finding F3): `/v1/users/1` needs the explicit wildcard.
    wired._ctx.rules.allow_credential("users.roblox.com/v1/users/*")
    mock.routes["/v1/users/1"] = harness.MockResponse(body=b'{"id":1}')
    result = await get(wired, host="users.roblox.com", path="/v1/users/1", query=[])
    assert (result.status, result.egress, result.auth_class) == (200, Egress.CREDENTIAL, AuthClass.CRED)
    assert result.cacheable is False  # cache_private
    await manager.mark_rejected("test")
    count = len(mock.requests)
    refused = await get(wired, host="users.roblox.com", path="/v1/users/1", query=[])
    assert refused.reason is ReasonCode.CREDENTIAL_UNAVAILABLE
    assert len(mock.requests) == count  # no anonymous substitute


async def test_non_allowlisted_never_carries_the_cookie(wired: Any, mock: Any) -> None:
    mock.routes["/v1/users/authenticated"] = harness.MockResponse(body=json.dumps({"id": 42}).encode())
    manager = wired._ctx.egress.credential
    await manager.probe("admin_check", fetch=wired.credential_probe_fetch)
    for status in (200, 500, 429):
        mock.routes["/v1/x"] = harness.MockResponse(status=status, body=b"{}")
        await get(wired, path="/v1/x", query=[])
    calls = [r for r in mock.requests if r.path.startswith("/v1/x")]
    assert calls
    assert all(r.header("Cookie") is None for r in calls)
