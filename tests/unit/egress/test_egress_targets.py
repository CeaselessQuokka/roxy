"""Egress target checks: the last SSRF and credential-host check before bytes leave (plan 9.10, C2 item 7).

What this is
    Unit tests for `roxy.egress.targets`: `check_roblox_target`, `check_echo_target` and the development-only
    `UpstreamTestOverride`.

Why it exists
    A URL that passes here is one Roxy will connect to. The SSRF corpus of plan 9.10 must fail, the credential must
    need the explicit host list, and the test override must be impossible in production.

How it works
    Plain function calls with the plan's corpus; no network.

What to read next
    `src/roxy/egress/targets.py`.
"""

from __future__ import annotations

import httpx
import pytest

from roxy.core.reasons import Egress
from roxy.egress.errors import EgressConfigError, TargetNotAllowed
from roxy.egress.targets import (
    TEST_HOST_HEADER,
    UpstreamTestOverride,
    check_echo_target,
    check_roblox_target,
    normalize_host,
)

ALLOWED = ("games.roblox.com", "users.roblox.com")


def check(url: str, *, strict: bool = True, listed: bool = False) -> httpx.URL:
    return check_roblox_target(url, egress=Egress.DIRECT, allowed_hosts=ALLOWED, strict=strict, require_listed=listed)


@pytest.mark.parametrize(
    "url",
    [
        "https://games.roblox.com/v1/games?universeIds=1",
        "https://GAMES.ROBLOX.COM/v1/games",
        "https://games.roblox.com./v1/games",
        "https://games.roblox.com:443/v1/games",
    ],
)
def test_allowed_targets_pass(url: str) -> None:
    assert check(url).host == "games.roblox.com"


@pytest.mark.parametrize(
    "url",
    [
        "http://games.roblox.com/v1/games",  # not https
        "https://games.roblox.com:8080/v1/games",  # other port
        "https://user:pass@games.roblox.com/v1/games",  # userinfo
        "https://games.roblox.com@evil.com/",  # userinfo trick
        "https://roblox.com.evil.com/",
        "https://evilroblox.com/",
        "https://127.0.0.1/",
        "https://[::1]/",
        "https://games.roblox.com../x",
        "https://catalog.roblox.com/v1/x",  # not in the strict list
        "https://games.roblox.com\n/v1",
        "ftp://games.roblox.com/",
    ],
)
def test_ssrf_corpus_is_refused(url: str) -> None:
    with pytest.raises(TargetNotAllowed):
        check(url)


def test_non_strict_allows_any_roblox_subdomain_but_credential_needs_the_list() -> None:
    assert check("https://catalog.roblox.com/v1/x", strict=False).host == "catalog.roblox.com"
    with pytest.raises(TargetNotAllowed):
        check("https://catalog.roblox.com/v1/x", strict=False, listed=True)


def test_normalize_host_rules() -> None:
    assert normalize_host("Games.Roblox.Com.") == "games.roblox.com"
    assert normalize_host("games.roblox.com..") == "games.roblox.com."
    assert normalize_host("") is None
    assert normalize_host("gämes.roblox.com") is None


def test_echo_target_is_exact() -> None:
    echo = "https://api.ipify.org?format=json"
    assert check_echo_target("https://api.ipify.org?format=json", egress=Egress.ROTATOR, echo_url=echo).host
    for bad in ("https://evil.example/?format=json", "https://api.ipify.org/other", "http://api.ipify.org/"):
        with pytest.raises(TargetNotAllowed):
            check_echo_target(bad, egress=Egress.ROTATOR, echo_url=echo)


def test_override_absent_by_default() -> None:
    assert UpstreamTestOverride.from_environ("production", {}) is None
    assert UpstreamTestOverride.from_environ("development", {}) is None


@pytest.mark.parametrize(
    "environ",
    [
        {"ROXY_TEST_UPSTREAM_BASE": "http://127.0.0.1:18080"},
        {"ROXY_TEST_ROTATOR_PROXY": "http://127.0.0.1:18081"},
    ],
)
def test_override_is_a_startup_error_in_production(environ: dict[str, str]) -> None:
    with pytest.raises(EgressConfigError) as raised:
        UpstreamTestOverride.from_environ("production", environ)
    assert "127.0.0.1" not in str(raised.value)  # names only, never values


@pytest.mark.parametrize(
    "value",
    ["http://10.0.0.5:18080", "http://example.com:80", "http://127.0.0.1", "http://127.0.0.1:1/path", "ftp://x:1"],
)
def test_override_base_must_be_a_loopback_origin(value: str) -> None:
    with pytest.raises(EgressConfigError):
        UpstreamTestOverride.from_environ("development", {"ROXY_TEST_UPSTREAM_BASE": value})


def test_override_rewrite_keeps_path_query_and_names_the_host() -> None:
    override = UpstreamTestOverride.from_environ(
        "development",
        {"ROXY_TEST_UPSTREAM_BASE": "http://127.0.0.1:18080", "ROXY_TEST_ROTATOR_PROXY": "http://127.0.0.1:1"},
    )
    assert override is not None
    assert override.rotator_proxy == "http://127.0.0.1:1"
    target, headers = override.rewrite(httpx.URL("https://games.roblox.com/v1/games?universeIds=1&x=%2F"))
    assert str(target) == "http://127.0.0.1:18080/v1/games?universeIds=1&x=%2F"
    assert headers == {"Host": "games.roblox.com", TEST_HOST_HEADER: "games.roblox.com"}
    assert override.owns(target)
