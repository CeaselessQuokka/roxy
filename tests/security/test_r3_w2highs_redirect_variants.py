"""Wave 2 credential fix cred-3, new variants (review round 3, lens w2highs): redirect hops of the credential path.

What this is
    Variants of finding cred-3 ("credential redirect hops matched raw and never path-validated"), fixed by sending
    every hop through `proxy/validate.py parse_redirect` and asking for a credential grant on the hop's decoded
    target. The fix test uses two Locations (`%2E%2E` dot segments and `%2F` slashes). Here: double encoding, mixed
    case hex, IIS `%u` escapes, overlong UTF-8, backslashes, a tab inside the host, a lookalike or punycode host, a
    trailing dot, user info and fragment tricks, scheme and port changes, a CR LF in the path, a triple slash, and
    hops to endpoints the endpoint policy does not grant (Roxy's own probe endpoint, a BLOCK row, in any letter
    case; an ALLOW_ANON row), next to one hop whose target is granted (D1 revised: that one keeps the cookie).

Why it exists
    The credential is the one secret Roxy sends to Roblox. A hop the caller validator would refuse, or one whose target
    the endpoint policy does not grant (ALLOW_TOKEN), must never be followed with the cookie, and what is fetched must
    be exactly what was checked (plan C2 item 7, 9.10). A neighbor spelling of the original repro is the usual way such
    a fix is undone.

How it works
    The corpus calls `parse_redirect` directly and requires either a refusal, or an accepted hop whose rebuilt URL
    stays on the current host and parses back to the same target (checked == fetched). The app probe uses
    `confinement_harness.running_app` like the cred-3 fix test: ALLOW_TOKEN start endpoints of the shipped policy
    (`users GET /v1/users/{userId}`) answer 302s to the variant Locations; the mock must receive the cookie on
    the starts and the one granted hop only, and no other hop at all.

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


USERS = "users.roblox.com"
HOPS = {
    # ALLOW_TOKEN start path on users.roblox.com (`users GET /v1/users/{userId}`) -> where Roblox's 302 points
    "/v1/users/201": "/v1/users/%252E%252E/%252E%252E/v2/secret?via=double",
    "/v1/users/202": "/v1/users/%2e%2E/%2E%2e/v2/secret?via=mixed",
    "/v1/users/203": f"https://{USERS}{PROBE_PATH}?via=probe_endpoint",
    "/v1/users/204": f"https:///{USERS}{PROBE_PATH}?via=triple_slash",
    "/v1/users/205": f"https://{USERS.upper()}{PROBE_PATH.upper()}?via=uppercase",
    "/v1/users/206": f"https://{USERS}/v1/display-names/validate?via=anon_endpoint",
    "/v1/users/207": f"https://{USERS}/v1/users/999?via=granted",
}
GRANTED_HOP = "/v1/users/999?via=granted"
"""The one hop whose own target is ALLOW_TOKEN: followed, and it alone keeps the cookie (D1 revised)."""


async def test_cred3_variant_hops_never_carry_the_cookie_to_a_target_without_a_grant(
    env: Any, credentials_dir: Path, fake_secrets: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Hops a caller could not have sent are refused; valid hops to a BLOCK endpoint (Roxy's own probe endpoint,
    in any letter case) or an ALLOW_ANON endpoint are not followed on the credential egress; a valid hop to an
    ALLOW_TOKEN endpoint is followed with the cookie."""
    async with running_app(env, credentials_dir, fake_secrets, monkeypatch) as run:
        respond = run.fixture().MockResponse
        for start, location in HOPS.items():
            run.mock.routes[start] = respond(
                status=302, body=b"", headers=[("Location", location), ("Content-Type", "application/json")]
            )
        await run.activate_credential()
        statuses = {}
        for start in HOPS:
            run.clock.advance(5)
            statuses[start] = (await run.get(f"/{USERS}{start}")).status_code
        cookie_paths = [r.path for r in run.cookie_requests() if r.path.split("?")[0] != PROBE_PATH]
        assert sorted(cookie_paths) == sorted([*HOPS, GRANTED_HOP])  # the starts, and the one granted hop
        assert all(r.header("X-Exit-Ip") is None for r in run.cookie_requests())
        assert statuses == {start: 200 if GRANTED_HOP in HOPS[start] else 302 for start in HOPS}
        followed = [r.path for r in run.mock_requests() if "via=" in r.path]
        assert followed == [GRANTED_HOP]  # no other hop was fetched, with the cookie or without
        probe_calls = [r for r in run.cookie_requests() if r.path.split("?")[0] == PROBE_PATH]
        assert all("via=" not in r.path for r in probe_calls)  # the probe endpoint was never reached by a hop
