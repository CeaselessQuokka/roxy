"""EgressClients end to end over loopback: headers, the test override, redirects, errors, limits and self-tests.

What this is
    Tests for `roxy.egress.clients` against `MockUpstream` (and `RecordingProxy` for the rotator), using the
    development test override that sends Roblox requests to the mock.

Why it exists
    `EgressClients.send` is the only door out of Roxy. These tests pin what goes through it (API headers, the
    original host, no cookie except on the credential path, no `Set-Cookie` back), how failures surface
    (`UpstreamTimeout`, `UpstreamConnectError`, `EgressDisabled`), that redirects are followed only within the
    allowlist, and the H-CRED-GUARD and H-ENV-PROXY self-tests.

How it works
    `make_egress(environ=...)` builds a started `EgressClients` over the test databases; the mock records every
    request it receives.

What to read next
    `src/roxy/egress/clients.py`.
"""

from __future__ import annotations

import asyncio
import json
import socket
from types import SimpleNamespace
from typing import Any

import brotli
import httpx
import pytest

from roxy.core.clock import SYSTEM_CLOCK
from roxy.core.reasons import Egress
from roxy.egress import clients as clients_module
from roxy.egress.clients import DIRECT_LIMITS, EgressClients, build_egress_clients
from roxy.egress.errors import (
    CredentialUnavailable,
    EgressConfigError,
    EgressDisabled,
    TargetNotAllowed,
    UpstreamConnectError,
    UpstreamTimeout,
)
from roxy.egress.headers import ACCEPT_LANGUAGE, API_ACCEPT
from roxy.egress.models import OutboundRequest

TIMEOUT = httpx.Timeout(5.0)


def out(url: str, method: str = "GET", **kwargs: Any) -> OutboundRequest:
    return OutboundRequest(method, url, kwargs.pop("headers", {}), kwargs.pop("content", None), TIMEOUT, **kwargs)


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


async def activate_credential(egress: EgressClients, mock: Any, harness: Any, account: int = 42) -> None:
    mock.routes["/v1/users/authenticated"] = harness.MockResponse(body=json.dumps({"id": account}).encode())
    result = await egress.credential.probe("admin_check")
    assert result.outcome == "ok", result


async def test_production_refuses_the_test_override(env: Any, dbs: Any, settings: Any) -> None:
    production = env.model_copy(update={"env": "production"})
    with pytest.raises(EgressConfigError):
        EgressClients(
            env=production,
            settings=settings,
            dbs=dbs,
            clock=SYSTEM_CLOCK,
            worker_id="w",
            environ={"ROXY_TEST_UPSTREAM_BASE": "http://127.0.0.1:18080"},
        )


async def test_direct_request_through_the_override(
    make_egress: Any, override: dict[str, str], mock_upstream: Any, harness: Any, settings: Any
) -> None:
    mock_upstream.routes["/v1/games"] = harness.MockResponse(
        body=b'{"data":[]}', headers=[("Content-Type", "application/json"), ("Set-Cookie", "tracker=1; path=/")]
    )
    egress = await make_egress(environ=override)
    response = await egress.send(Egress.DIRECT, out("https://games.roblox.com/v1/games?universeIds=1&x=%2F"))
    assert response.status == 200
    assert response.body == b'{"data":[]}'
    assert response.egress is Egress.DIRECT
    assert "set-cookie" not in response.headers
    assert response.http_version == "HTTP/1.1"
    assert response.bytes_out > 100
    assert response.bytes_in > 50
    assert response.metering == "socket"
    seen = mock_upstream.requests[-1]
    assert seen.path == "/v1/games?universeIds=1&x=%2F"
    assert seen.header("Host") == "games.roblox.com"
    assert seen.header("X-Roxy-Test-Host") == "games.roblox.com"
    assert seen.header("Accept") == API_ACCEPT
    assert seen.header("Accept-Language") == ACCEPT_LANGUAGE
    assert seen.header("User-Agent") == settings.get("direct_user_agent")
    assert seen.header("Cookie") is None
    assert egress.accounting.totals()["direct"]["requests"] == 1
    second = await egress.send(Egress.DIRECT, out("https://games.roblox.com/v1/games"))
    assert second.status == 200
    assert mock_upstream.requests[-1].header("Cookie") is None


async def test_post_body_and_extra_headers(make_egress: Any, override: dict[str, str], mock_upstream: Any) -> None:
    egress = await make_egress(environ=override)
    request = out(
        "https://games.roblox.com/v1/x",
        "POST",
        content=b'{"a":1}',
        headers={"Content-Type": "application/json", "x-csrf-token": "abc", "Cookie": "smuggled=1", "Host": "evil"},
    )
    await egress.send(Egress.DIRECT, request)
    seen = mock_upstream.requests[-1]
    assert seen.method == "POST"
    assert seen.body == b'{"a":1}'
    assert seen.header("Content-Type") == "application/json"
    assert seen.header("x-csrf-token") == "abc"
    assert seen.header("Cookie") is None
    assert seen.header("Host") == "games.roblox.com"


async def test_credential_path_attaches_the_cookie_and_drops_set_cookie(
    make_egress: Any, override: dict[str, str], mock_upstream: Any, harness: Any, secret: str
) -> None:
    notifier = SimpleNamespace(alerts=[])
    notifier.send = notifier.alerts.append
    egress = await make_egress(environ=override, alerts=lambda: notifier)
    with pytest.raises(CredentialUnavailable) as raised:  # unknown status: probes only
        await egress.send(Egress.CREDENTIAL, out("https://users.roblox.com/v1/users/1"))
    assert raised.value.why == "not_confirmed"
    await activate_credential(egress, mock_upstream, harness)
    probe_seen = mock_upstream.requests[-1]
    assert probe_seen.header("Cookie") == f".ROBLOSECURITY={secret}"
    rotated = "NEWCOOKIEFROMROBLOX" + "A1" * 100
    mock_upstream.routes["/v1/users/1"] = harness.MockResponse(
        body=b'{"id":1}', headers=[("Set-Cookie", f".ROBLOSECURITY={rotated}; domain=.roblox.com; path=/")]
    )
    response = await egress.send(Egress.CREDENTIAL, out("https://users.roblox.com/v1/users/1"))
    assert response.status == 200
    assert "set-cookie" not in response.headers
    assert [alert.subject for alert in notifier.alerts] == ["Roxy: Roblox sent a new credential cookie"]
    assert egress.credential.status().fingerprint == egress.credential.fingerprint_of(secret)
    count = len(mock_upstream.requests)
    for method in ("POST", "PUT", "DELETE"):  # the account cookie never rides on a write (D1, 9.13)
        with pytest.raises(TargetNotAllowed):
            await egress.send(Egress.CREDENTIAL, out("https://users.roblox.com/v1/users/1", method, content=b"{}"))
    assert len(mock_upstream.requests) == count
    with pytest.raises(TargetNotAllowed):
        await egress.send(Egress.CREDENTIAL, out("https://unlisted.roblox.com/v1/x"))
    assert egress.accounting.totals()["credential"]["requests"] == 2


async def test_redirects_are_followed_only_inside_the_allowlist(
    make_egress: Any, override: dict[str, str], mock_upstream: Any, harness: Any, secret: str
) -> None:
    egress = await make_egress(environ=override)
    redirect = harness.MockResponse
    mock_upstream.routes["/hop"] = redirect(
        status=302, body=b"", headers=[("Location", "https://users.roblox.com/v1/end")]
    )
    mock_upstream.routes["/away"] = redirect(status=302, body=b"", headers=[("Location", "https://evil.example/steal")])
    mock_upstream.routes["/plain"] = redirect(status=301, body=b"", headers=[("Location", "http://users.roblox.com/x")])
    mock_upstream.routes["/loop"] = redirect(status=307, body=b"", headers=[("Location", "/loop")])
    mock_upstream.routes["/see"] = redirect(status=303, body=b"", headers=[("Location", "/v1/end")])
    followed = await egress.send(Egress.DIRECT, out("https://games.roblox.com/hop"))
    assert followed.status == 200
    assert followed.redirects == 1
    assert followed.url == "https://users.roblox.com/v1/end"
    assert mock_upstream.requests[-1].header("Host") == "users.roblox.com"
    for path in ("/away", "/plain"):
        stopped = await egress.send(Egress.DIRECT, out(f"https://games.roblox.com{path}"))
        assert stopped.status in (301, 302)
        assert stopped.redirects == 0
    looped = await egress.send(Egress.DIRECT, out("https://games.roblox.com/loop"))
    assert looped.status == 307
    assert looped.redirects == 3
    seen_before = len(mock_upstream.requests)
    posted = await egress.send(Egress.DIRECT, out("https://games.roblox.com/see", "POST", content=b"x=1"))
    assert posted.status == 200
    assert mock_upstream.requests[-1].method == "GET"
    assert mock_upstream.requests[-1].body == b""
    assert len(mock_upstream.requests) == seen_before + 2
    not_following = await egress.send(Egress.DIRECT, out("https://games.roblox.com/hop", follow_redirects=False))
    assert not_following.status == 302
    # The credential follows an allowlisted hop with a fresh check, and never an off-list one.
    await activate_credential(egress, mock_upstream, harness)
    count = len(mock_upstream.requests)
    credential_hop = await egress.send(Egress.CREDENTIAL, out("https://users.roblox.com/hop"))
    assert credential_hop.status == 200
    assert [r.header("Cookie") for r in mock_upstream.requests[count:]] == [f".ROBLOSECURITY={secret}"] * 2
    count = len(mock_upstream.requests)
    credential_away = await egress.send(Egress.CREDENTIAL, out("https://users.roblox.com/away"))
    assert credential_away.status == 302
    assert len(mock_upstream.requests) == count + 1


async def test_errors_become_egress_errors(
    make_egress: Any, override: dict[str, str], mock_upstream: Any, harness: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    mock_upstream.routes["/slow"] = harness.MockResponse(delay_s=1.5)
    mock_upstream.routes["/big"] = harness.MockResponse(body=b"z" * 1000)
    egress = await make_egress(environ=override)
    slow = out("https://games.roblox.com/slow")
    slow.timeout = httpx.Timeout(0.3)
    with pytest.raises(UpstreamTimeout):
        await egress.send(Egress.DIRECT, slow)
    monkeypatch.setattr(clients_module, "MAX_RESPONSE_BYTES", 100)
    with pytest.raises(UpstreamConnectError):
        await egress.send(Egress.DIRECT, out("https://games.roblox.com/big"))
    with pytest.raises(TargetNotAllowed):
        await egress.send(Egress.DIRECT, out("https://evil.example/x"))
    closed = await make_egress(environ={"ROXY_TEST_UPSTREAM_BASE": f"http://127.0.0.1:{free_port()}"})
    with pytest.raises(UpstreamConnectError):
        await closed.send(Egress.DIRECT, out("https://games.roblox.com/v1/games"))
    with pytest.raises(EgressDisabled):  # `none` is not a path anything can leave by
        await egress.send(Egress.NONE, out("https://games.roblox.com/v1/games"))


async def test_brotli_responses_are_decoded(
    make_egress: Any, override: dict[str, str], mock_upstream: Any, harness: Any
) -> None:
    payload = json.dumps({"data": list(range(200))}).encode()
    mock_upstream.routes["/br"] = harness.MockResponse(
        body=brotli.compress(payload), headers=[("Content-Type", "application/json"), ("Content-Encoding", "br")]
    )
    egress = await make_egress(environ=override)
    response = await egress.send(Egress.DIRECT, out("https://games.roblox.com/br"))
    assert response.body == payload
    # The body is decoded, so the framing headers that described the compressed bytes are not passed on.
    assert "content-encoding" not in response.headers
    assert "content-length" not in response.headers
    assert response.headers["content-type"] == "application/json"
    assert "br" in (mock_upstream.requests[-1].header("Accept-Encoding") or "")


async def test_switches_disable_egresses(make_egress: Any, override: dict[str, str], settings: Any, env: Any) -> None:
    egress = await make_egress(environ=override)
    settings.set("direct_enabled", 0)
    assert egress.is_enabled(Egress.DIRECT) == (False, "direct_disabled")
    with pytest.raises(EgressDisabled):
        await egress.send(Egress.DIRECT, out("https://games.roblox.com/v1/games"))
    settings.set("direct_enabled", 1)
    assert egress.is_enabled(Egress.DIRECT) == (True, "")
    settings.set("rotator_enabled", 0)
    assert egress.is_enabled(Egress.ROTATOR) == (False, "rotator_disabled")
    (env.credentials_dir / "rotator_url").unlink()
    bare = await make_egress(environ=override)
    assert bare.is_enabled(Egress.ROTATOR) == (False, "rotator_not_configured")
    assert bare.is_enabled(Egress.NONE) == (False, "no_egress")


async def test_jar_and_transport_cannot_be_swapped(make_egress: Any, override: dict[str, str]) -> None:
    egress = await make_egress(environ=override)
    client = egress.direct_client
    with pytest.raises(AttributeError):
        client.http.cookies = {".ROBLOSECURITY": "x"}  # type: ignore[assignment]
    client.http._transport = httpx.AsyncHTTPTransport()  # bypass attempt
    with pytest.raises(EgressDisabled) as raised:
        await egress.send(Egress.DIRECT, out("https://games.roblox.com/v1/games"))
    assert raised.value.why == "client_transport_replaced"


async def test_limits_and_timeouts(make_egress: Any, override: dict[str, str], settings: Any) -> None:
    egress = await make_egress(environ=override)
    assert (DIRECT_LIMITS.max_connections, DIRECT_LIMITS.keepalive_expiry) == (50, 30.0)
    for client in (egress.direct_client, egress.credential_client):
        pool = client.metering._pool
        assert pool._max_connections == 50
        assert pool._keepalive_expiry == 30.0
        assert pool._http2 is True
        assert client.http.trust_env is False
    settings.set("request_timeout", 22)
    settings.set("upstream_connect_timeout_s", 4)
    request = out("https://games.roblox.com/v1/games")
    request.timeout = None  # type: ignore[assignment]
    timeout = egress._timeout(request)
    assert (timeout.connect, timeout.read, timeout.write, timeout.pool) == (4.0, 22.0, 10.0, 5.0)


async def test_rotator_sessions_through_a_forward_proxy(
    make_egress: Any, mock_upstream: Any, harness: Any, settings: Any, env: Any
) -> None:
    settings.set("rotator_session_username_template", "{user}-sessid-{session}")
    with harness.RecordingProxy(upstream=mock_upstream.address) as proxy:
        environ = {
            "ROXY_TEST_UPSTREAM_BASE": mock_upstream.base_url,
            "ROXY_TEST_ROTATOR_PROXY": proxy.url_with_auth("dpuser", "dppass"),
        }
        echo_env = env.model_copy(update={"rotator_ip_echo_url": f"{mock_upstream.base_url}/ip"})
        egress = await make_egress(environ=environ, env=echo_env)
        first = await egress.rotator.exit_ip_probe()
        again = await egress.rotator.exit_ip_probe(first.session_id)
        other = await egress.rotator.exit_ip_probe(egress.rotator.new_session_id())
        assert first.exit_ip
        assert first.exit_ip == again.exit_ip
        assert other.exit_ip != first.exit_ip
        mock_upstream.routes["/v1/limited"] = harness.MockResponse(status=429)
        session = egress.rotator.session_for()
        response = await egress.send(Egress.ROTATOR, out("https://games.roblox.com/v1/limited", session_id=session))
        assert response.status == 429
        assert response.session_id == session
        assert egress.rotator.session_for() != session  # sticky_until_429 moved to a new exit
        seen = mock_upstream.requests[-1]
        assert seen.header("Host") == "games.roblox.com"
        assert seen.header("Cookie") is None
        assert any(ex.username and "sessid-" in ex.username for ex in proxy.exchanges)


async def test_no_egress_client_logs_tls_keys(
    make_egress: Any, override: dict[str, str], monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """Finding cred-6: CPython's `ssl.create_default_context` copies SSLKEYLOGFILE into the context whatever
    httpx's `trust_env` says; every egress TLS context (direct, credential, rotator, a test's own context) has its
    key log switched off, and the H-ENV-PROXY self-test fails while the variable is set."""
    import ssl

    from roxy.egress.clients import make_credential_client
    from roxy.egress.metering import tls_context

    monkeypatch.setenv("SSLKEYLOGFILE", str(tmp_path / "keys.log"))
    assert ssl.create_default_context().keylog_filename  # the environment really is read by CPython
    egress = await make_egress(environ=override)
    rotator = egress._make_rotator_client("http://127.0.0.1:9", "keylog", False)
    built = make_credential_client()
    try:
        for client in (egress.direct_client, egress.credential_client, rotator, built):
            assert client.metering.keylog_file() is None
            assert client.http._transport is not None
    finally:
        await rotator.aclose()
        await built.aclose()
    assert tls_context(ssl.create_default_context()).keylog_filename is None  # a passed-in context too
    check = egress.self_test_env_proxy({"SSLKEYLOGFILE": str(tmp_path / "keys.log")})
    assert (check.status, check.value) == ("fail", "SSLKEYLOGFILE")
    assert egress.self_test_env_proxy({}).status == "pass"
    egress.credential_client.metering.tls.keylog_filename = str(tmp_path / "late.log")
    honoring = egress.self_test_env_proxy({})
    assert honoring.status == "fail"
    assert "credential" in honoring.value
    egress.credential_client.metering.tls.keylog_filename = None


async def test_self_tests(make_egress: Any, override: dict[str, str], env: Any) -> None:
    egress = await make_egress(environ=override)
    guard = await egress.self_test_leak_guard()
    assert guard.status == "pass"
    assert guard.facts["blocked"] == 3
    assert guard.facts["reached_network"] == 0
    assert egress.self_test_env_proxy({}).status == "pass"
    warn = egress.self_test_env_proxy({"HTTPS_PROXY": "http://127.0.0.1:1", "all_proxy": "x"})
    assert warn.status == "warn"
    assert warn.value == "ALL_PROXY, HTTPS_PROXY"
    egress.direct_client.http._trust_env = True
    failing = egress.self_test_env_proxy({})
    assert failing.status == "fail"
    assert "direct" in failing.value
    (env.credentials_dir / "roblox_credential").unlink()
    bare = await make_egress(environ=override)
    synthetic = await bare.self_test_leak_guard()
    assert synthetic.status == "warn"
    assert synthetic.facts["synthetic_value"] is True
    await asyncio.sleep(0.01)


async def test_build_from_context_and_refresh_loop(env: Any, dbs: Any, settings: Any) -> None:
    ctx = SimpleNamespace(
        env=env, settings=settings, dbs=dbs, clock=SYSTEM_CLOCK, worker_id="host:1:abc", alerts=None, recorder=None
    )
    egress = await build_egress_clients(ctx)
    try:
        assert egress.metering_self_test is not None
        assert egress.metering_self_test.mode.value == "socket"
        stop = asyncio.Event()
        task = asyncio.create_task(egress.run(stop))
        await asyncio.sleep(0.1)
        stop.set()
        await asyncio.wait_for(task, 3)
        stats = egress.stats()
        assert stats["rotator"]["url"] == "http://127.0.0.1:9"
        assert stats["tripped"] == []
        assert "fake" not in json.dumps(stats)
    finally:
        await egress.aclose()
