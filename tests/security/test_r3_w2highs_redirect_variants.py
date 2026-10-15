"""Wave 2 credential fix cred-3, new variants (review round 3, lens w2highs): redirect hops of the credential path.

What this is
    Variants of finding cred-3 ("credential redirect hops matched raw and never path-validated"), fixed by sending
    every hop through `proxy/validate.py parse_redirect` and matching the credential allowlist on the hop's decoded
    target. The fix test uses two Locations (`%2E%2E` dot segments and `%2F` slashes). Here: double encoding, mixed
    case hex, IIS `%u` escapes, overlong UTF-8, backslashes, a tab inside the host, a lookalike or punycode host, a
    trailing dot, user info and fragment tricks, scheme and port changes, a CR LF in the path, a triple slash, and
    hops to an allowed host the allowlist does not name (Roxy's own probe endpoint among them).

Why it exists
    The credential is the one secret Roxy sends to Roblox. A hop the caller validator would refuse, or one the
    allowlist does not grant, must never be followed with the cookie, and what is fetched must be exactly what was
    checked (plan C2 item 7, 9.10). A neighbor spelling of the original repro is the usual way such a fix is undone.

How it works
    The corpus calls `parse_redirect` directly and requires either a refusal, or an accepted hop whose rebuilt URL
    stays on the current host and parses back to the same target (checked == fetched). The app probe uses
    `confinement_harness.running_app` like the cred-3 fix test: allowlisted start endpoints answer 302s to the
    variant Locations, and every request the mock received with the cookie must be a caller-valid URL that an
    allowlist row grants.

What to read next
    `src/roxy/proxy/validate.py` (`parse_redirect`, `parse_upstream_url`), `src/roxy/upstream/service.py`
    (`_redirect_url`), `tests/security/test_rr_cred_redirect_hops.py` (the fix test this extends).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from confinement_harness import PROBE_PATH, running_app

from roxy.proxy.validate import parse_redirect, parse_upstream_url

ECONOMY = "economy.roblox.com"
START = f"https://{ECONOMY}/v1/user/currency/start"
ALLOWED = frozenset({ECONOMY, "games.roblox.com", "users.roblox.com"})

REFUSED = {
    "double_encoded_dots": "/v1/user/currency/%252E%252E/%252E%252E/v2/secret",
    "mixed_case_hex_dots": "/v1/user/currency/%2e%2E/%2E%2e/v2/secret",
    "iis_u_escapes": "/v1/user/currency/%u002e%u002e/v2/secret",
    "overlong_utf8_dots": "/v1/user/currency/%c0%ae%c0%ae/v2/secret",
    "encoded_slash_lower": "/v1/user/currency%2f..%2f..%2fv2%2fsecret",
    "backslash_path": "/v1/user/currency\\..\\..\\v2\\secret",
    "backslash_scheme": "https:\\\\evil.example/x",
    "slash_backslash_scheme": "https:/\\evil.example/x",
    "protocol_relative": "//evil.example/x",
    "trailing_dot_host_dots": f"https://{ECONOMY}./v1/user/currency/%2e%2e/x",
    "encoded_dot_in_host": f"https://{ECONOMY}%2Eevil.example/x",
    "userinfo_trick": f"https://{ECONOMY}:443@evil.example/x",
    "tab_in_host": f"https://{ECONOMY}\t.evil.example/x",
    "cyrillic_lookalike_host": "https://еconomy.roblox.com/v1/x",
    "punycode_host": "https://xn--conomy-roblox.com/v1/x",
    "crlf_in_path": f"https://{ECONOMY}/v1/user/currency/x%0d%0aSet-Cookie:a",
    "nul_in_query": "/v1/user/currency/x?a=%00",
    "other_port": f"https://{ECONOMY}:8443/v1/user/currency/x",
    "plain_http": f"http://{ECONOMY}/v1/user/currency/x",
    "ip_literal": "https://127.0.0.1/v1/user/currency/x",
    "ipv6_literal": "https://[::1]/v1/user/currency/x",
    "unclosed_bracket": "//[",
}

ACCEPTED_ON_THE_SAME_HOST = {
    "uppercase_host": f"https://{ECONOMY.upper()}/v1/user/currency/x",
    "triple_slash": "https:///evil.example/x",
    "scheme_without_slashes": f"https:{ECONOMY}/v1/x",
    "fragment_trick": f"https://{ECONOMY}#@evil.example/x",
    "tab_in_path": "/v1/user/curr\tency/x",
}


@pytest.mark.parametrize("name", sorted(REFUSED))
def test_cred3_variant_locations_are_refused(name: str) -> None:
    parsed = parse_redirect(
        START, REFUSED[name], allowed_hosts=ALLOWED, strict_host_allowlist=True, max_url_length=4096
    )
    assert not parsed.ok, (name, parsed.target)


@pytest.mark.parametrize("name", sorted(ACCEPTED_ON_THE_SAME_HOST))
def test_cred3_accepted_odd_locations_stay_on_the_host_and_are_fetched_as_checked(name: str) -> None:
    """Locations `urljoin` folds into the current host: accepted, but what is fetched is what was checked."""
    location = ACCEPTED_ON_THE_SAME_HOST[name]
    parsed = parse_redirect(START, location, allowed_hosts=ALLOWED, strict_host_allowlist=True, max_url_length=4096)
    assert parsed.ok, name
    assert parsed.host == ECONOMY
    again = parse_upstream_url(parsed.upstream_url, allowed_hosts=ALLOWED, max_url_length=4096)
    assert (again.ok, again.target) == (True, parsed.target)


HOPS = {
    # allowlisted start path -> where Roblox's 302 points
    "/v1/user/currency/a": "/v1/user/currency/%252E%252E/%252E%252E/v2/secret?via=double",
    "/v1/user/currency/b": "/v1/user/currency/%2e%2E/%2E%2e/v2/secret?via=mixed",
    "/v1/user/currency/c": f"https://users.roblox.com{PROBE_PATH}?via=probe_endpoint",
    "/v1/user/currency/d": f"https:///users.roblox.com{PROBE_PATH}?via=triple_slash",
    "/v1/user/currency/e": f"https://{ECONOMY.upper()}/V2/USER/SECRET?via=uppercase",
}


async def test_cred3_variant_hops_never_carry_the_cookie_off_the_allowlist(
    env: Any, credentials_dir: Path, fake_secrets: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    async with running_app(env, credentials_dir, fake_secrets, monkeypatch) as run:
        respond = run.fixture().MockResponse
        for start, location in HOPS.items():
            run.mock.routes[start] = respond(
                status=302, body=b"", headers=[("Location", location), ("Content-Type", "application/json")]
            )
        await run.activate_credential()
        await run.rule(
            "credential_allowlist",
            {"pattern": r"economy\.roblox\.com/v1/user/currency(?:/.*)?", "type": "regex", "cache_private": True},
        )
        statuses = []
        for start in HOPS:
            run.clock.advance(5)
            statuses.append((await run.get(f"/{ECONOMY}{start}")).status_code)
        cookie_paths = [r.path for r in run.cookie_requests() if r.path.split("?")[0] != PROBE_PATH]
        assert sorted(path.split("?")[0] for path in cookie_paths) == sorted(HOPS)  # only the allowlisted starts
        assert statuses == [302] * len(HOPS)  # Roblox's own 3xx relayed, never a followed hop
        probe_calls = [r for r in run.cookie_requests() if r.path.split("?")[0] == PROBE_PATH]
        assert all("via=" not in r.path for r in probe_calls)  # the probe endpoint was never reached by a hop
