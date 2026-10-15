"""Credential redirect hops skip the path validation every caller path gets (review lens cred, finding cred-3).

What this is
    A probe of finding F3's exact grants ("a row grants exactly the endpoints it names") along the one route a
    caller does not type: a redirect Roblox answers on an allowlisted credential request. `UpstreamService
    ._redirect_url` checks a hop's host (`is_roblox_https_url`) and matches the allowlist against the hop's RAW,
    still percent-encoded path; it never runs `proxy/validate.py: parse_redirect`, which exists for exactly this
    (plan 9.10: "Redirects are followed manually and re-validated"; "no `..` segments, no encoded slashes").

Why it exists
    A caller path with an encoded slash or an encoded dot segment is refused as `unsafe_url` (v1 bug B4: dot
    segments let a request reach a path the rules did not see). A hop is not: `[^/]*` (a glob `*`) and `(?:/.*)?`
    (the documented way to grant subpaths) both match `%2E%2E` and `%2F` text, so the cookie is sent to
    `.../currency/%2E%2E/%2E%2E/%2E%2E/v2/secret`, which a server that decodes before removing dot segments (as
    Kestrel does) serves as `/v2/secret`: an endpoint no allowlist row names.

How it works
    `confinement_harness.running_app` runs the real app against a loopback mock. Two allowlist rows (a regex that
    grants subpaths, a glob with one wildcard) cover two start endpoints, whose mock answers are 302s to such paths.
    After the caller GETs, every request the mock received WITH the cookie must be a URL that
    `validate.parse_upstream_url` accepts (the same checks as a caller path). Fixed in the review round:
    `_redirect_url` runs every hop through `parse_upstream_url` and matches the allowlist on its decoded target, so
    these hops are not followed and the caller gets Roblox's own 302.

What to read next
    `src/roxy/upstream/service.py` (`_redirect_url`, `_exchange_and_record`), `src/roxy/proxy/validate.py`
    (`parse_redirect`, `normalize_path`), `tests/security/test_confinement_routing.py`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from confinement_harness import PROBE_PATH, running_app

from roxy.proxy.validate import parse_upstream_url

ECONOMY = "economy.roblox.com"
HOPS = {
    # start path (allowlisted) -> where Roblox's 302 points (a path the caller validator refuses)
    "/v1/user/currency/start": "/v1/user/currency/%2E%2E/%2E%2E/%2E%2E/v2/secret?via=dotted",
    "/v1/user/start": "/v1/user/%2E%2E%2F%2E%2E%2Fv2%2Fsecret?via=slashed",
}


async def test_credential_never_follows_a_hop_the_caller_validator_refuses(
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
        await run.rule("credential_allowlist", {"pattern": f"{ECONOMY}/v1/user/*", "cache_private": True})
        statuses = []
        for start in HOPS:
            assert parse_upstream_url(f"https://{ECONOMY}{start}").ok  # the start itself is a valid caller path
            run.clock.advance(5)
            statuses.append((await run.get(f"/{ECONOMY}{start}")).status_code)
        assert statuses == [302] * len(HOPS)  # the hop is not followed: Roblox's own 3xx is the answer
        caller_cookie_paths = [r.path for r in run.cookie_requests() if r.path.split("?")[0] != PROBE_PATH]
        assert len(caller_cookie_paths) >= len(HOPS)  # the allowlisted starts really went out with the cookie
        refused = [path for path in caller_cookie_paths if not parse_upstream_url(f"https://{ECONOMY}{path}").ok]
        assert refused == []
