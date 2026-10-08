"""Header profiles: API-shaped, stable per identity, nothing from the caller but an allowlist (plan 7.11, 9.13).

What this is
    Unit tests for `roxy.egress.headers`.

Why it exists
    v1 sent a page-navigation header set to JSON APIs and a random User-Agent per rotator request (R9, B23). These
    tests pin the v2 behavior: fixed `Accept-Language`, no navigation headers, one coherent profile per rotator
    session, and the inbound allowlist that the cache key mirrors.

How it works
    `HeaderProfiles` over `FakeSettings`; pure functions otherwise.

What to read next
    `src/roxy/egress/headers.py`.
"""

from __future__ import annotations

from typing import Any

from roxy.core.reasons import Egress
from roxy.egress.headers import (
    ACCEPT_LANGUAGE,
    API_ACCEPT,
    FORWARDED_CALLER_HEADERS,
    ROTATOR_PROFILES,
    HeaderProfiles,
    forwardable_caller_headers,
    merge_outbound,
    profile_for_session,
)


def test_direct_and_credential_headers_are_api_shaped(settings: Any) -> None:
    profiles = HeaderProfiles(settings, "https://example.test")
    for egress in (Egress.DIRECT, Egress.CREDENTIAL):
        headers = profiles.api_headers(egress)
        assert headers["Accept"] == API_ACCEPT
        assert headers["Accept-Language"] == ACCEPT_LANGUAGE == "en-US,en;q=0.9"
        assert headers["User-Agent"] == settings.get("direct_user_agent")
        lowered = {name.lower() for name in headers}
        assert "sec-fetch-mode" not in lowered
        assert "upgrade-insecure-requests" not in lowered
        assert "accept-encoding" not in lowered  # left to httpx, which only advertises what it can decode


def test_ua_experiment_splits_direct_traffic_by_identity(settings: Any) -> None:
    settings.set("ua_experiment_enabled", 1)
    profiles = HeaderProfiles(settings, "https://example.test")
    variants = {profiles.ua_variant(Egress.DIRECT, f"key{i}") for i in range(50)}
    assert variants == {"primary", "alt"}
    alt_key = next(f"key{i}" for i in range(50) if profiles.ua_variant(Egress.DIRECT, f"key{i}") == "alt")
    assert profiles.user_agent(Egress.DIRECT, alt_key) == "Roxy/2 (+https://example.test)"
    assert profiles.user_agent(Egress.DIRECT, alt_key) == profiles.user_agent(Egress.DIRECT, alt_key)
    # The credential path never takes part in the experiment.
    assert profiles.ua_variant(Egress.CREDENTIAL, alt_key) == "primary"


def test_rotator_profile_is_stable_and_coherent_per_session(settings: Any) -> None:
    profiles = HeaderProfiles(settings, "https://example.test")
    first = profiles.api_headers(Egress.ROTATOR, "abc123")
    assert first == profiles.api_headers(Egress.ROTATOR, "abc123")
    profile = profile_for_session("abc123")
    assert first["User-Agent"] == profile.user_agent
    seen = {profile_for_session(f"s{i}").name for i in range(200)}
    assert len(seen) == len(ROTATOR_PROFILES)
    for item in ROTATOR_PROFILES:
        has_hints = any(name == "sec-ch-ua" for name, _ in item.extra)
        assert has_hints == ("Chrome/" in item.user_agent and "Firefox" not in item.user_agent)
        if "Firefox" in item.user_agent or "Version/" in item.user_agent:
            assert item.extra == ()


def test_inbound_allowlist() -> None:
    caller = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Accept-Language": "fr-FR",
        "Cookie": "x=y",
        "Authorization": "Bearer z",
        "X-Custom": "1",
    }
    assert forwardable_caller_headers(caller, has_body=True) == {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    assert forwardable_caller_headers(caller, has_body=False) == {"Accept": "application/json"}
    assert forwardable_caller_headers({"Accept": "text/html"}, has_body=False) == {}
    assert FORWARDED_CALLER_HEADERS == ("content-type", "accept")


def test_merge_outbound_drops_cookies_auth_host_and_hop_by_hop() -> None:
    merged = merge_outbound(
        {"Accept": "a", "User-Agent": "u"},
        {
            "accept": "application/json",
            "Cookie": "c",
            "authorization": "x",
            "Host": "evil",
            "Connection": "close",
            "x-csrf-token": "t",
            "Proxy-Authorization": "p",
        },
    )
    assert merged == {"accept": "application/json", "User-Agent": "u", "x-csrf-token": "t"}
