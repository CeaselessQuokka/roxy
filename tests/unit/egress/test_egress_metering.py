"""Byte metering against a recording proxy's raw socket count (plan 8.3, acceptance 19.10 row 8).

What this is
    Tests that the socket-level meter counts what actually crossed the wire to the proxy (the CONNECT exchange,
    TLS handshakes and records included): within 5% of the recording proxy's raw byte count on the rotator's
    HTTP/1.1 path, for plain forwarding, a blind CONNECT tunnel to a TLS upstream, and a TLS-intercepting proxy.
    The fallback estimate must land within 15% once `rotator_tls_overhead_bytes` is calibrated (EGR-CALIBRATE).

Why it exists
    DataImpulse bills wire bytes. If the meter is wrong, the quota, the daily cap and the cost projection are
    wrong, and the hard stop fires too late.

How it works
    `RecordingProxy` and `MockUpstream` from `tests/fixtures/recording_proxy.py` on loopback; certificates from a
    throwaway `trustme` CA trusted only by the test client context.

What to read next
    `src/roxy/egress/metering.py`, then `tests/fixtures/recording_proxy.py`.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from roxy.core.reasons import Egress
from roxy.egress import metering
from roxy.egress.clients import GuardHooks, make_rotator_client
from roxy.egress.credential import LeakMatcher
from roxy.egress.metering import ByteMeter, MeteringMode, MeteringTransport, RequestUsage, attribute_to
from roxy.egress.models import OutboundRequest

HOOKS = GuardHooks(matcher=lambda: LeakMatcher([]), max_body_bytes=lambda: 2_000_000)
TIMEOUT = httpx.Timeout(10.0)


def within(measured: int, truth: int, tolerance: float) -> bool:
    return truth > 0 and abs(measured - truth) <= tolerance * truth


async def test_self_test_selects_socket_metering() -> None:
    result = await metering.run_self_test()
    assert result.mode is MeteringMode.SOCKET, result
    assert result.client_out == result.server_in > 0
    assert result.client_in == result.server_out > 0
    assert metering.socket_metering_enabled()


async def test_failed_self_test_falls_back_to_the_estimate(monkeypatch: pytest.MonkeyPatch) -> None:
    async def broken() -> Any:
        raise RuntimeError("httpcore changed")

    monkeypatch.setattr(metering, "_self_test_once", broken)
    result = await metering.run_self_test()
    assert result.mode is MeteringMode.ESTIMATE
    assert not metering.socket_metering_enabled()
    transport = MeteringTransport(meter=ByteMeter("x"), limits=httpx.Limits())
    assert transport.mode is MeteringMode.ESTIMATE
    await transport.aclose()


async def _send_all(client: Any, urls: list[str], bodies: list[bytes | None]) -> list[RequestUsage]:
    usages = []
    for url, body in zip(urls, bodies, strict=True):
        usage = RequestUsage()
        with attribute_to(usage):
            request = client.http.build_request("POST" if body else "GET", url, content=body, timeout=TIMEOUT)
            response = await client.send(request)
            await response.aread()
            await response.aclose()
            assert response.status_code == 200
        usages.append(usage)
    return usages


async def test_forward_proxy_counts_match_raw_bytes(harness: Any, mock_upstream: Any) -> None:
    mock_upstream.routes["/big"] = harness.MockResponse(body=b"x" * 50_000)
    with harness.RecordingProxy() as proxy:
        meter = ByteMeter("rotator")
        client = make_rotator_client(
            proxy.url_with_auth("u", "p"),
            session_id="s",
            keepalive=True,
            hooks=HOOKS,
            meter=meter,
            socket_metering=True,
        )
        urls = [f"{mock_upstream.base_url}/a", f"{mock_upstream.base_url}/big", f"{mock_upstream.base_url}/c"]
        usages = await _send_all(client, urls, [None, None, b"body" * 100])
        await client.aclose()
        proxy.wait_settled()
        raw = proxy.raw_total()
    metered = meter.bytes_out + meter.bytes_in
    assert within(metered, raw, 0.05), (metered, raw)
    assert sum(u.bytes_out + u.bytes_in for u in usages) == metered  # every byte attributed to a request
    assert usages[0].new_connections == 1
    assert usages[1].new_connections == 0


async def test_connect_tunnel_to_tls_upstream_within_5_percent(harness: Any) -> None:
    ca = harness.make_ca()
    with harness.MockUpstream(tls_context=harness.server_ssl_context(ca)) as tls_upstream:
        tls_upstream.routes["/v1/games"] = harness.MockResponse(body=b'{"data":[' + b'{"id":1},' * 300 + b'{"id":2}]}')
        with harness.RecordingProxy(tunnel_upstream=tls_upstream.address) as proxy:
            meter = ByteMeter("rotator")
            client = make_rotator_client(
                proxy.url_with_auth("u", "p"),
                session_id="s",
                keepalive=False,
                hooks=HOOKS,
                meter=meter,
                verify=harness.client_ssl_context(ca),
                socket_metering=True,
            )
            urls = ["https://games.roblox.com/v1/games?universeIds=1"] * 3
            usages = await _send_all(client, urls, [None, None, None])
            await client.aclose()
            proxy.wait_settled()
            raw = proxy.raw_total()
            assert {ex.kind for ex in proxy.exchanges} == {"tunnel"}
    metered = meter.bytes_out + meter.bytes_in
    assert within(metered, raw, 0.05), (metered, raw)
    assert all(u.new_connections == 1 for u in usages)  # per_request style: a new tunnel (and exit) each time
    assert all(u.bytes_in > 1000 for u in usages)  # the TLS handshake is inside each count


async def _intercepting_run(
    harness: Any, make_egress: Any, settings: Any, *, socket_metering: bool, sizes: list[int]
) -> tuple[int, int, list[Any]]:
    """Send one GET per size through the rotator and a TLS-intercepting proxy; return (metered, raw, responses)."""
    ca = harness.make_ca()
    with harness.MockUpstream() as upstream:
        for size in sizes:
            upstream.routes[f"/v1/size/{size}"] = harness.MockResponse(body=b"y" * size)
        with harness.RecordingProxy(
            upstream=upstream.address, intercept_context=harness.server_ssl_context(ca)
        ) as proxy:
            egress = await make_egress(
                environ={"ROXY_TEST_ROTATOR_PROXY": proxy.url_with_auth("u", "pw")},
                tls_verify=harness.client_ssl_context(ca),
                socket_metering=socket_metering,
                settings=settings,
            )
            responses = []
            for size in sizes:
                out = OutboundRequest("GET", f"https://games.roblox.com/v1/size/{size}", {}, None, TIMEOUT)
                responses.append(await egress.send(Egress.ROTATOR, out))
            proxy.wait_settled()
            raw = proxy.raw_total()
            assert {ex.kind for ex in proxy.exchanges} == {"intercept"}
    usage = egress.accounting.totals()["rotator"]
    metered = usage["req_bytes"] + usage["resp_bytes"] + usage["overhead_bytes"]
    return metered, raw, responses


async def test_tls_intercepting_proxy_within_5_percent(harness: Any, make_egress: Any, settings: Any) -> None:
    metered, raw, responses = await _intercepting_run(
        harness, make_egress, settings, socket_metering=True, sizes=[10, 2_000, 40_000, 120_000]
    )
    assert within(metered, raw, 0.05), (metered, raw)
    assert all(r.metering == "socket" and r.new_connections == 1 for r in responses)
    assert sum(r.bytes_out + r.bytes_in for r in responses) == metered


async def test_fallback_estimate_within_15_percent_once_calibrated(
    harness: Any, make_egress: Any, settings: Any
) -> None:
    # Calibrate the per-connection overhead the way EGR-CALIBRATE would: one measured exchange vs the estimate.
    settings.set("rotator_tls_overhead_bytes", 0)
    truth, _, _ = await _intercepting_run(harness, make_egress, settings, socket_metering=True, sizes=[500])
    uncalibrated, _, _ = await _intercepting_run(harness, make_egress, settings, socket_metering=False, sizes=[500])
    settings.set("rotator_tls_overhead_bytes", max(0, truth - uncalibrated))
    sizes = [10, 700, 5_000, 30_000, 90_000]
    estimated, raw, responses = await _intercepting_run(
        harness, make_egress, settings, socket_metering=False, sizes=sizes
    )
    assert all(r.metering == "estimate" for r in responses)
    assert within(estimated, raw, 0.15), (estimated, raw)
