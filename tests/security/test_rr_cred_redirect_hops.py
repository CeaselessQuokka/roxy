"""Credential redirect hops skip the path validation every caller path gets (review lens cred, finding cred-3).

What this is
    A probe of exact grants along the one route a caller does not type: a redirect Roblox answers on a credential
    request. `UpstreamService._redirect_url` used to check a hop's host (`is_roblox_https_url`) and match the
    grant against the hop's RAW, still percent-encoded path; it never ran `proxy/validate.py: parse_redirect`,
    which exists for exactly this (plan 9.10: "Redirects are followed manually and re-validated"; "no `..`
    segments, no encoded slashes").

Why it exists
    A caller path with an encoded slash or an encoded dot segment is refused as `unsafe_url` (v1 bug B4: dot
    segments let a request reach a path the rules did not see). A hop must be too. Since D1 revised the grant is
    the endpoint policy's ALLOW_TOKEN verdict, and a template parameter (`{userId}`, one segment) matches any raw
    segment text, `%2E%2E%2F...` included. Matched raw, the cookie would go to
    `/v1/users/%2E%2E%2F%2E%2E%2Fv1%2Fusers%2Fauthenticated`, which a server that decodes before removing dot
    segments (as Kestrel does) serves as `/v1/users/authenticated`: a BLOCK endpoint that names the account.

How it works
    `confinement_harness.running_app` runs the real app against a loopback mock, with the shipped endpoint policy.
    Three ALLOW_TOKEN start endpoints (`users GET /v1/users/{userId}` twice, `groups GET /v1/groups/{groupId}`)
    answer 302s to such paths. After the caller GETs, every request the mock received WITH the cookie must be a
    URL that `validate.parse_upstream_url` accepts (the same checks as a caller path), and no hop was fetched at
    all, with or without the cookie. Fixed in the review round: `_redirect_url` runs every hop through
    `parse_upstream_url` and asks the policy for a grant on its decoded target, so these hops are not followed
    and the caller gets Roblox's own 302.

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

HOPS = {
    # (host, ALLOW_TOKEN start path) -> where Roblox's 302 points (a path the caller validator refuses)
    ("users.roblox.com", "/v1/users/101"): "/v1/users/%2E%2E%2F%2E%2E%2Fv1%2Fusers%2Fauthenticated?via=slashed",
    ("users.roblox.com", "/v1/users/102"): "/v1/users/%2E%2E?via=dotted",
    ("groups.roblox.com", "/v1/groups/7"): "/v1/groups/7/%2E%2E/%2E%2E/%2E%2E/v1/user/currency?via=dotted-deep",
}


async def test_credential_never_follows_a_hop_the_caller_validator_refuses(
    env: Any, credentials_dir: Path, fake_secrets: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    async with running_app(env, credentials_dir, fake_secrets, monkeypatch) as run:
        respond = run.fixture().MockResponse
        for (_host, start), location in HOPS.items():
            run.mock.routes[start] = respond(
                status=302, body=b"", headers=[("Location", location), ("Content-Type", "application/json")]
            )
        await run.activate_credential()
        statuses = []
        for host, start in HOPS:
            assert parse_upstream_url(f"https://{host}{start}").ok  # the start itself is a valid caller path
            assert run.ctx.rules.snapshot.credential_rule_for(f"{host}{start}", "GET") is not None  # ALLOW_TOKEN
            run.clock.advance(5)
            statuses.append((await run.get(f"/{host}{start}")).status_code)
        assert statuses == [302] * len(HOPS)  # the hop is not followed: Roblox's own 3xx is the answer
        caller_cookie = [r for r in run.cookie_requests() if r.path.split("?")[0] != PROBE_PATH]
        assert sorted(r.path for r in caller_cookie) == sorted(start for _host, start in HOPS)  # the starts went
        refused = [r.path for r in caller_cookie if not parse_upstream_url(f"https://{r.header('Host')}{r.path}").ok]
        assert refused == []
        assert [r.path for r in run.mock_requests() if "via=" in r.path] == []  # no hop fetched, cookie or not
