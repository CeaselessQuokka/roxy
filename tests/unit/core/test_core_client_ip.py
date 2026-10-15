"""Real client IP tests (plan 9.11): only the rightmost trusted hops of X-Forwarded-For count."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import Request

from roxy.core.client_ip import UNKNOWN_IP, limit_key, normalize_ip, parse_cidrs, resolve_client_ip

LOOPBACK = parse_cidrs("127.0.0.1/32,::1/128")
WITH_CDN = parse_cidrs("127.0.0.1/32,::1/128,198.51.100.0/24")


def test_spoofed_leftmost_xff_ignored() -> None:
    # The caller sent "X-Forwarded-For: 1.2.3.4"; nginx appended the address it really saw.
    assert resolve_client_ip("127.0.0.1", "1.2.3.4, 203.0.113.7", LOOPBACK, 1) == "203.0.113.7"
    assert resolve_client_ip("127.0.0.1", "1.2.3.4,5.6.7.8, 203.0.113.7", LOOPBACK, 1) == "203.0.113.7"


def test_untrusted_peer_cannot_set_its_ip() -> None:
    # A direct connection (not nginx) gets no say: the header is ignored and the peer is the client.
    assert resolve_client_ip("203.0.113.50", "1.2.3.4", LOOPBACK, 1) == "203.0.113.50"


def test_no_header_means_peer() -> None:
    assert resolve_client_ip("127.0.0.1", None, LOOPBACK, 1) == "127.0.0.1"
    assert resolve_client_ip("127.0.0.1", "", LOOPBACK, 1) == "127.0.0.1"


def test_two_hops_behind_a_trusted_cdn() -> None:
    # client -> CDN (198.51.100.10) -> nginx -> app. nginx appended the CDN address; the CDN appended the client.
    xff = "6.6.6.6, 203.0.113.7, 198.51.100.10"
    assert resolve_client_ip("127.0.0.1", xff, WITH_CDN, 2) == "203.0.113.7"


def test_two_hops_stop_at_an_untrusted_hop() -> None:
    # Someone bypassed the CDN and hit nginx directly: the rightmost entry is NOT a CDN address, so it is the client
    # and whatever it wrote further left is ignored.
    xff = "198.51.100.99, 203.0.113.66"
    assert resolve_client_ip("127.0.0.1", xff, WITH_CDN, 2) == "203.0.113.66"


def test_several_header_lines_are_one_list() -> None:
    assert resolve_client_ip("127.0.0.1", "1.2.3.4,203.0.113.7", LOOPBACK, 1) == "203.0.113.7"


def test_garbage_rightmost_entry_keeps_the_peer() -> None:
    assert resolve_client_ip("127.0.0.1", "203.0.113.7, not-an-ip", LOOPBACK, 1) == "127.0.0.1"


def test_zero_hops_ignores_the_header() -> None:
    assert resolve_client_ip("127.0.0.1", "203.0.113.7", LOOPBACK, 0) == "127.0.0.1"


def test_missing_peer() -> None:
    assert resolve_client_ip(None, "203.0.113.7", LOOPBACK, 1) == UNKNOWN_IP


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("::ffff:203.0.113.7", "203.0.113.7"),
        ("203.0.113.7:5678", "203.0.113.7"),
        ("[2001:db8::1]:443", "2001:db8::1"),
        ("2001:DB8:0:0:0:0:0:1", "2001:db8::1"),
        ("fe80::1%eth0", "fe80::1"),
        ('"203.0.113.7"', "203.0.113.7"),
        ("unknown", None),
        ("", None),
    ],
)
def test_normalize_ip(raw: str, expected: str | None) -> None:
    assert normalize_ip(raw) == expected


def test_ipv4_mapped_peer_is_trusted_as_ipv4() -> None:
    assert resolve_client_ip("::ffff:127.0.0.1", "203.0.113.7", LOOPBACK, 1) == "203.0.113.7"


def test_limit_key_groups_ipv6_by_prefix() -> None:
    assert limit_key("203.0.113.7", 64) == "203.0.113.7"
    assert limit_key("2001:db8:1:2:aaaa::1", 64) == "2001:db8:1:2::/64"
    assert limit_key("2001:db8:1:2:bbbb::9", 64) == "2001:db8:1:2::/64"
    assert limit_key("2001:db8:1:2:bbbb::9", 128) == "2001:db8:1:2:bbbb::9"
    assert limit_key("2001:db8:1:2:bbbb::9", 48) == "2001:db8:1::/48"
    assert limit_key("unknown", 64) == "unknown"


def test_parse_cidrs_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        parse_cidrs("127.0.0.1/32,not-a-network")


async def test_middleware_sets_client_ip_and_request_client(make_app: Any, client_for: Any) -> None:
    app = make_app()

    @app.get("/who")
    async def who(request: Request) -> dict[str, object]:
        return {
            "state": request.state.client_ip,
            "client": request.client.host if request.client else None,
            "peer": request.state.peer_ip,
        }

    async with client_for(app) as client:
        spoofed = await client.get("/who", headers={"X-Forwarded-For": "1.2.3.4, 203.0.113.7"})
    assert spoofed.json() == {"state": "203.0.113.7", "client": "203.0.113.7", "peer": "127.0.0.1"}


async def test_middleware_ignores_header_from_untrusted_peer(make_app: Any, client_for: Any) -> None:
    app = make_app()

    @app.get("/who")
    async def who(request: Request) -> dict[str, object]:
        return {"state": request.state.client_ip}

    async with client_for(app, peer=("203.0.113.50", 4000)) as client:
        response = await client.get("/who", headers={"X-Forwarded-For": "1.2.3.4"})
    assert response.json() == {"state": "203.0.113.50"}
