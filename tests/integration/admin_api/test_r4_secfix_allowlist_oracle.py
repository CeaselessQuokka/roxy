"""Review round 4 (lens secfix): a real admin path with a wrong method must look exactly like a missing path.

What this is
    Variants of the apisec-3 fix (`admin/router.py AdminNotFoundRoute`): a request whose path exists for other
    methods only is answered after the session guard, the missing path's 404 to anyone the guard refuses. These
    tests compare the WHOLE answer (status, every header except the per-request id and date, body) of a wrong method
    on a real path with the answer for a path that does not exist, for the callers the guard refuses in different
    ways: outside the admin allowlist, signed out, with a dead session cookie (the guard's own 401 clears the
    cookie), from a foreign origin. It also checks the login page (`/admin`, which since parity-3 counts a visit and
    sets the `roxy_admin_counted` cookie) never sets a cookie for a network outside the allowlist.

Why it exists
    D6 and plan 9.5: a network outside the allowlist, or anyone signed out, must not tell a hidden admin path from a
    missing one. Any difference (a `Set-Cookie`, an `Allow`, another length or content type) is that oracle again.

How it works
    The real app (`api_app`); requests from the loopback peer with `X-Forwarded-For` naming the caller. For each
    refused caller, the pair (wrong method on a real path, same method on a missing path) is sent and compared.

What to read next
    `roxy/admin/router.py`, `roxy/admin/auth/deps.py` (`require_admin`, `_reject_unauthenticated`),
    `roxy/core/errors.py` (`not_found_response`), `roxy/admin/auth/routes.py` (`login_page`).
"""

from __future__ import annotations

import re
from typing import Any

import httpx

VOLATILE = frozenset({"date", "x-request-id", "roxy-request-id", "server-timing"})
PAIRS = (
    ("PUT", "/admin/api/v1/settings", "/admin/api/v1/zz-no-such-area"),
    ("DELETE", "/admin/api/v1/credential/replace", "/admin/api/v1/credential/zz-no-such"),
    ("HEAD", "/admin/api/v1/openapi.json", "/admin/api/v1/zz-openapi.json"),
    ("POST", "/admin/enroll", "/admin/zz-enroll"),
    ("OPTIONS", "/admin", "/admin/zz-login"),
)


def _shape(response: httpx.Response) -> tuple[int, list[tuple[str, str]], bytes]:
    """Status, headers (per-request ids and dates left out, CSP nonces normalized) and body."""
    headers = sorted(
        (k.lower(), re.sub(r"nonce-[A-Za-z0-9_\-+/=]+", "nonce-N", v))
        for k, v in response.headers.items()
        if k.lower() not in VOLATILE
    )
    return response.status_code, headers, response.content


async def _compare(client: httpx.AsyncClient, headers: dict[str, str]) -> list[str]:
    problems: list[str] = []
    for method, real, missing in PAIRS:
        wrong = await client.request(method, real, headers=headers)
        absent = await client.request(method, missing, headers=headers)
        left, right = _shape(wrong), _shape(absent)
        if left != right:
            only_wrong = sorted(set(left[1]) - set(right[1]))
            only_missing = sorted(set(right[1]) - set(left[1]))
            problems.append(
                f"{method} {real}: status {left[0]} vs {right[0]}, headers only on the real path {only_wrong}, "
                f"only on the missing path {only_missing}, bodies equal {left[2] == right[2]}"
            )
    return problems


def _browser(api_app: Any, ip: str, **extra: str) -> dict[str, str]:
    headers: dict[str, str] = dict(api_app.harness.headers(ip=ip))
    headers.update(extra)
    return headers


async def test_outside_the_allowlist_a_wrong_method_is_byte_identical_to_a_missing_path(api_app: Any) -> None:
    await api_app.harness.allow_admin_cidr("192.0.2.0/24")
    await api_app.settings(admin_allowlist_enabled=1)
    client = api_app.harness.new_client()
    assert await _compare(client, _browser(api_app, "203.0.113.50")) == []


async def test_signed_out_and_dead_cookie_callers_cannot_tell_a_real_path_either(api_app: Any) -> None:
    client = api_app.harness.new_client()
    assert await _compare(client, _browser(api_app, "203.0.113.51")) == []
    dead = _browser(api_app, "203.0.113.51", Cookie="__Host-roxy_session=" + "A" * 43)
    assert await _compare(client, dead) == []  # the guard's 401 clears this cookie; the 404 must not
    foreign = _browser(api_app, "203.0.113.51", Origin="https://evil.example", **{"Sec-Fetch-Site": "cross-site"})
    assert await _compare(client, foreign) == []


async def test_the_login_page_sets_no_cookie_and_counts_no_visit_outside_the_allowlist(api_app: Any) -> None:
    await api_app.harness.allow_admin_cidr("192.0.2.0/24")
    await api_app.settings(admin_allowlist_enabled=1)
    client = api_app.harness.new_client()
    outside = _browser(api_app, "203.0.113.52", Accept="text/html")
    page = await client.get("/admin", headers=outside)
    missing = await client.get("/admin/zz-login", headers=outside)
    assert _shape(page) == _shape(missing)
    assert "set-cookie" not in {k.lower() for k in page.headers}
