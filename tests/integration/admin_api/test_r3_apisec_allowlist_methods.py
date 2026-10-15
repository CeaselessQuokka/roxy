"""Review round 3 (lens apisec): the admin network allowlist (D6) and requests with a method a route does not take.

What this is
    Tests for finding apisec-3 (fixed; it was a strict xfail). With the admin allowlist on, plan 9.5 and D6 promise
    that a network that is not listed "gets the plain 404 for every /admin route, including the login page", byte
    for byte the answer for a path that does not exist (`core/errors.py not_found_response`). A request whose path
    exists but whose method does not (HEAD or OPTIONS on a GET route, GET on a POST route, PUT anywhere) never
    reached a guard: the admin catch-all stepped aside for a partial match and Starlette answered 405 with an
    `Allow` header. Now the catch-all (`admin/router.py AdminNotFoundRoute`, also on `/admin` itself) answers it:
    the session guard runs first, so anyone it refuses (outside the allowlist, signed out) gets the missing path's
    404, and only a signed-in admin gets 405 `method_not_allowed` (a section 13 object) with `Allow`.

Why it exists
    The 404-versus-405 difference is an oracle: from outside the allowlist anyone can confirm that `/admin` is the
    dashboard (`HEAD /admin` is 405 while `GET /admin` is 404), and walk the whole admin API map with the methods
    each path takes, which is exactly what hiding the dashboard and keeping the OpenAPI document signed-in only
    are meant to prevent.

How it works
    The allowlist is switched on for a documentation network the test client is not in (it sends
    `X-Forwarded-For: 203.0.113.50` from the trusted loopback peer). The answers for real paths with a wrong method
    are compared with the answers for paths that do not exist.

What to read next
    `roxy/admin/router.py` (`AdminNotFoundRoute.matches`), `roxy/admin/auth/allowlist.py`, `roxy/core/errors.py`
    (`not_found_response`, `_http_exception_handler`).
"""

from __future__ import annotations

from typing import Any

import pytest

from roxy.admin import router as admin_router

OUTSIDE = {"X-Forwarded-For": "203.0.113.50"}
API = "/admin/api/v1"

PROBES: tuple[tuple[str, str, str], ...] = (
    ("HEAD", "/admin", "/admin/no-such-page"),
    ("OPTIONS", "/admin", "/admin/no-such-page"),
    ("OPTIONS", f"{API}/settings", f"{API}/no-such-area"),
    ("PUT", f"{API}/settings", f"{API}/no-such-area"),
    ("GET", f"{API}/credential/replace", f"{API}/no-such-area/replace"),
    ("DELETE", f"{API}/auth/login", f"{API}/no-such-area/login"),
    ("HEAD", f"{API}/openapi.json", f"{API}/no-such-file.json"),
)
"""(method, a real path that does not take that method, a path that does not exist at all)."""


@pytest.fixture
async def hidden(api_app: Any) -> Any:
    await api_app.harness.allow_admin_cidr("192.0.2.0/24")
    await api_app.settings(admin_allowlist_enabled=1)
    return api_app.harness.new_client()


async def test_listed_paths_are_hidden_from_outside_the_allowlist(api_app: Any, hidden: Any) -> None:
    """Control (passes today): with the route's own method the allowlist answers the missing-path 404."""
    headers = {**api_app.harness.headers(), **OUTSIDE}
    pairs = (
        ("GET", "/admin", "/admin/no-such-page"),
        ("GET", f"{API}/settings", f"{API}/no-such-area"),
        ("POST", f"{API}/auth/login", f"{API}/no-such-area/login"),
    )
    for method, path, missing_path in pairs:
        real = await hidden.request(method, path, headers=headers)
        missing = await hidden.request(method, missing_path, headers=headers)
        assert real.status_code == missing.status_code == 404, (method, path)
        assert real.content == missing.content, (method, path)


async def test_a_wrong_method_does_not_reveal_admin_paths_outside_the_allowlist(api_app: Any, hidden: Any) -> None:
    headers = {**api_app.harness.headers(), **OUTSIDE}
    revealed: list[str] = []
    for method, real_path, missing_path in PROBES:
        real = await hidden.request(method, real_path, headers=headers)
        missing = await hidden.request(method, missing_path, headers=headers)
        same = (
            real.status_code == missing.status_code == 404
            and real.content == missing.content
            and "allow" not in real.headers
        )
        if not same:
            revealed.append(f"{method} {real_path}: {real.status_code} allow={real.headers.get('allow')}")
    assert revealed == [], "paths told apart from missing ones: " + "; ".join(revealed)


async def test_signed_out_callers_cannot_map_methods_either(api_app: Any) -> None:
    """With the allowlist off, a caller without a session learns no more from a wrong method than from a typo."""
    anonymous = api_app.harness.new_client()
    headers = api_app.harness.headers()
    for method, real_path, missing_path in PROBES:
        real = await anonymous.request(method, real_path, headers=headers)
        missing = await anonymous.request(method, missing_path, headers=headers)
        assert (real.status_code, real.content) == (missing.status_code, missing.content) == (404, missing.content)
        assert "allow" not in real.headers, (method, real_path)


async def test_a_signed_in_admin_gets_a_section13_405_with_allow(api: Any) -> None:
    for method, path, allowed in (
        ("PUT", f"{API}/settings", "GET, PATCH"),
        ("GET", f"{API}/credential/replace", "POST"),
        ("OPTIONS", "/admin", "GET"),
        ("DELETE", f"{API}/auth/login", "POST"),
    ):
        response = await api.request(method, path, csrf=False)
        assert response.status_code == 405, (method, path, response.text[:200])
        assert response.headers["allow"] == allowed, (method, path)
        if method != "HEAD":
            assert response.json()["error"]["code"] == admin_router.METHOD_NOT_ALLOWED_CODE
        assert response.headers["cache-control"] == "no-store"
    head = await api.request("HEAD", "/admin", csrf=False)
    assert (head.status_code, head.headers["allow"]) == (405, "GET")
    login = await api.get("/admin")
    assert login.status_code in (200, 302), login.status_code  # the login page itself is untouched (302 when signed in)
