"""Unit tests for `roxy/proxy/scrub.py`: the plan 9.13 header allowlists, inbound and outbound.

What this is
    Inbound: exactly `Accept` (only `application/json` or `*/*`), and `Content-Type` and `Content-Length` for
    body methods, ever reach Roblox; every header v1 forwarded by mistake (B5) is dropped; the cache key's vary
    input equals the forward list. Outbound: only `Retry-After` and `x-ratelimit-*` reach callers.

Why it exists
    A header that is forwarded but not in the cache key lets one caller's answer be served to another (v1 B5,
    B26); a relayed `Set-Cookie` could leak account state. Both directions are pinned here.

How it works
    Direct calls with header dicts shaped like `ProxyRequest.headers` (lowercase names).

What to read next
    `roxy/proxy/scrub.py`, then `tests/integration/test_proxy_golden.py` (the same rules through the app).
"""

from __future__ import annotations

import importlib

import pytest

from roxy.proxy import scrub

V1_LEAKY_HEADERS = {
    "authorization": "Bearer abc",
    "proxy-authorization": "Basic abc",
    "x-csrf-token": "tok",
    "x-api-key": "key",
    "roblox-place-id": "123",
    "accept-language": "de-DE",
    "cookie": "a=b",
    "x-roblox-token": "x",
    "user-agent": "Mozilla/5.0",
    "x-forwarded-for": "1.2.3.4",
    "cf-connecting-ip": "1.2.3.4",
    "roxy-anything": "1",
    "tracestate": "x",
    "keep-alive": "5",
    "upgrade": "h2c",
    "te": "trailers",
    "host": "evil.example",
    "origin": "https://evil.example",
    "referer": "https://evil.example/",
    "cache-control": "no-cache",
    "sec-fetch-mode": "navigate",
    "x-custom": "1",
}


def test_forward_list_is_exactly_the_plan() -> None:
    assert scrub.FORWARDED_REQUEST_HEADERS == ("accept", "content-type", "content-length")


@pytest.mark.parametrize("method", ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
def test_leaky_v1_headers_never_forwarded(method: str) -> None:
    forwarded = scrub.forwarded_request_headers(method, V1_LEAKY_HEADERS, b"")
    assert set(forwarded) <= set(scrub.FORWARDED_REQUEST_HEADERS)
    assert not set(forwarded) & set(V1_LEAKY_HEADERS)


@pytest.mark.parametrize(
    ("accept", "forwarded"),
    [
        ("application/json", "application/json"),
        (" Application/JSON ", "application/json"),
        ("*/*", "*/*"),
        ("text/html,application/xhtml+xml", None),
        ("application/json, text/plain, */*", None),
        ("application/json;q=0.9", None),
        ("", None),
    ],
)
def test_accept_only_when_json_or_any(accept: str, forwarded: str | None) -> None:
    result = scrub.forwarded_request_headers("GET", {"accept": accept}, b"")
    assert result.get("accept") == forwarded


def test_body_headers_only_for_body_methods() -> None:
    headers = {"content-type": "application/json", "content-length": "999"}
    assert scrub.forwarded_request_headers("GET", headers, b"") == {}
    post = scrub.forwarded_request_headers("POST", headers, b'{"a":1}')
    assert post == {"content-type": "application/json", "content-length": "7"}  # length from the real body
    assert scrub.forwarded_request_headers("DELETE", {}, b"") == {"content-length": "0"}


def test_unsafe_content_type_dropped() -> None:
    assert "content-type" not in scrub.forwarded_request_headers("POST", {"content-type": "a" * 300}, b"x")
    assert "content-type" not in scrub.forwarded_request_headers("POST", {"content-type": "text/plain\x7f"}, b"x")


@pytest.mark.parametrize("method", ["GET", "POST", "PATCH"])
def test_cache_vary_items_equal_the_forwarded_headers(method: str) -> None:
    """Plan 9.13: every forwarded header varies the cache key, and nothing else does."""
    headers = {"accept": "*/*", "content-type": "application/json", **V1_LEAKY_HEADERS}
    body = b'{"usernames":["a"]}'
    forwarded = scrub.forwarded_request_headers(method, headers, body)
    vary = scrub.cache_vary_items(method, headers, body)
    assert dict(vary) == forwarded
    assert [name for name, _ in vary] == [n for n in scrub.FORWARDED_REQUEST_HEADERS if n in forwarded]


def test_forward_list_equals_cache_key_vary_list() -> None:
    """`cache/keys.py` must vary on exactly the forwarded headers (it asserts the same; checked here too)."""
    try:
        keys = importlib.import_module("roxy.cache.keys")
    except ModuleNotFoundError:
        pytest.skip("roxy.cache.keys is not built yet (cache specialist)")
    vary = next(
        (
            getattr(keys, name)
            for name in ("VARY_HEADERS", "VARY_HEADER_NAMES", "KEY_VARY_HEADERS")
            if hasattr(keys, name)
        ),
        None,
    )
    if vary is None:
        pytest.skip("roxy.cache.keys exposes no vary list under a known name yet")
    assert {str(name).lower() for name in vary} == set(scrub.FORWARDED_REQUEST_HEADERS)


def test_outbound_allowlist() -> None:
    upstream = {
        "Content-Type": "application/json",
        "Set-Cookie": ".ROBLOSECURITY=secret; domain=.roblox.com",
        "x-csrf-token": "abc",
        "Cache-Control": "public, max-age=3600",
        "Retry-After": "7",
        "X-RateLimit-Remaining": "0",
        "x-ratelimit-reset": "30",
        "x-ratelimit-limit": "100",
        "x-ratelimit-other": "1",
        "roblox-machine-id": "CHI1-WEB1234",
        "Location": "https://evil.example/",
        "Access-Control-Allow-Origin": "https://www.roblox.com",
    }
    kept = scrub.safe_response_headers(upstream)
    assert kept == [
        ("Retry-After", "7"),
        ("x-ratelimit-remaining", "0"),
        ("x-ratelimit-reset", "30"),
        ("x-ratelimit-limit", "100"),
    ]
    assert not {name.lower() for name, _ in kept} & scrub.NEVER_RELAYED


def test_outbound_drops_unsafe_values_and_duplicates() -> None:
    pairs = [
        ("retry-after", "5\r\nSet-Cookie: x=y"),
        ("Retry-After", "9"),
        ("retry-after", "11"),
        ("x-ratelimit-limit", ""),
    ]
    assert scrub.safe_response_headers(pairs) == [("Retry-After", "9")]
    assert scrub.safe_response_headers(None) == []
