"""Security header tests (plan 9.2 and 9.3): the exact CSP, a new nonce per response, and the other headers."""

from __future__ import annotations

import re
from typing import Any

from fastapi import Request
from fastapi.responses import HTMLResponse, PlainTextResponse

from roxy.core.security_headers import (
    PERMISSIONS_POLICY,
    PROXIED_CSP,
    get_nonce,
    mark_proxied,
    page_csp,
)

# The plan 9.2 policy, written out here line by line exactly as the plan prints it, then joined with "; ".
PLAN_POLICY_LINES = [
    "default-src 'none'",
    "script-src 'nonce-{n}' 'strict-dynamic'",
    "style-src 'self' 'nonce-{n}'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "object-src 'none'",
    "manifest-src 'self'",
    "upgrade-insecure-requests",
    "report-to csp-endpoint",
    "report-uri /csp-report",
]
NONCE_RE = re.compile(r"'nonce-([A-Za-z0-9_\-+/=]+)'")


def expected_policy(nonce: str) -> str:
    return "; ".join(line.format(n=nonce) for line in PLAN_POLICY_LINES)


def test_page_csp_is_exactly_the_plan_policy() -> None:
    assert page_csp("abc123") == expected_policy("abc123")
    assert "unsafe-inline" not in page_csp("x")
    assert "unsafe-eval" not in page_csp("x")


def html_app(make_app: Any) -> Any:
    app = make_app()

    @app.get("/page", response_class=HTMLResponse)
    async def page(request: Request) -> HTMLResponse:
        nonce = get_nonce(request.scope)
        return HTMLResponse(f'<html><head><style nonce="{nonce}">p{{}}</style></head><body>ok</body></html>')

    @app.get("/admin/settings")
    async def admin() -> PlainTextResponse:
        return PlainTextResponse("admin", headers={"Cache-Control": "public, max-age=600"})

    @app.get("/games.roblox.com/v1/games")
    async def proxied(request: Request) -> PlainTextResponse:
        mark_proxied(request.scope)
        return PlainTextResponse("<pre>upstream</pre>", headers={"Content-Security-Policy": "default-src *"})

    @app.get("/server")
    async def server_header() -> PlainTextResponse:
        return PlainTextResponse("x", headers={"Server": "uvicorn", "X-Frame-Options": "ALLOWALL"})

    return app


async def test_html_page_gets_exact_csp_with_its_own_nonce(make_app: Any, client_for: Any) -> None:
    async with client_for(html_app(make_app)) as client:
        response = await client.get("/page")
    csp = response.headers["content-security-policy"]
    nonce = NONCE_RE.search(csp)
    assert nonce is not None
    assert csp == expected_policy(nonce.group(1))
    assert f'nonce="{nonce.group(1)}"' in response.text  # the page used the same nonce as its header
    assert response.headers["reporting-endpoints"] == 'csp-endpoint="/csp-report"'


async def test_nonce_is_new_for_every_response(make_app: Any, client_for: Any) -> None:
    app = html_app(make_app)
    nonces = set()
    async with client_for(app) as client:
        for _ in range(5):
            response = await client.get("/page")
            match = NONCE_RE.search(response.headers["content-security-policy"])
            assert match is not None
            nonces.add(match.group(1))
    assert len(nonces) == 5
    assert all(len(n) >= 22 for n in nonces)  # 128 bits of randomness


async def test_other_security_headers_on_every_response(make_app: Any, client_for: Any) -> None:
    async with client_for(html_app(make_app)) as client:
        for path in ("/page", "/admin/settings", "/games.roblox.com/v1/games", "/missing"):
            response = await client.get(path)
            assert response.headers["x-content-type-options"] == "nosniff"
            assert response.headers["x-frame-options"] == "DENY"
            assert response.headers["referrer-policy"] == "no-referrer"
            assert response.headers["permissions-policy"] == PERMISSIONS_POLICY
            assert response.headers["cross-origin-opener-policy"] == "same-origin"
            assert "strict-transport-security" not in response.headers  # nginx owns HSTS (9.1)
    for feature in ("camera=()", "microphone=()", "geolocation=()", "usb=()", "payment=()", "interest-cohort=()"):
        assert feature in PERMISSIONS_POLICY


async def test_admin_responses_are_never_cached_and_isolated(make_app: Any, client_for: Any) -> None:
    async with client_for(html_app(make_app)) as client:
        admin = await client.get("/admin/settings")
        page = await client.get("/page")
    assert admin.headers["cache-control"] == "no-store"
    assert admin.headers.get_list("cache-control") == ["no-store"]
    assert admin.headers["cross-origin-embedder-policy"] == "require-corp"
    assert admin.headers["cross-origin-resource-policy"] == "same-origin"
    assert "cross-origin-embedder-policy" not in page.headers


async def test_proxied_response_gets_sandbox_csp(make_app: Any, client_for: Any) -> None:
    async with client_for(html_app(make_app)) as client:
        response = await client.get("/games.roblox.com/v1/games")
    assert response.headers.get_list("content-security-policy") == [PROXIED_CSP]
    assert "reporting-endpoints" not in response.headers


async def test_route_cannot_weaken_or_duplicate_owned_headers(make_app: Any, client_for: Any) -> None:
    async with client_for(html_app(make_app)) as client:
        response = await client.get("/server")
    assert "server" not in response.headers
    assert response.headers.get_list("x-frame-options") == ["DENY"]


async def test_hsts_only_when_enabled(make_app: Any, client_for: Any) -> None:
    app = make_app(send_hsts=True)

    @app.get("/x")
    async def x() -> PlainTextResponse:
        return PlainTextResponse("x")

    async with client_for(app) as client:
        response = await client.get("/x")
    assert response.headers["strict-transport-security"] == "max-age=63072000; includeSubDomains"


# --- fix pass: security review L4 -------------------------------------------------------------------------------------


async def test_outer_500_and_504_answers_get_every_security_header(make_app: Any, client_for: Any) -> None:
    """L4: the unhandled 500 and the deadline 504 are built outside the security headers middleware."""
    import asyncio

    app = make_app(settings={"request_deadline_s": 0.2})

    async def boom() -> None:
        raise RuntimeError("bug")

    async def slow() -> None:
        await asyncio.sleep(5)

    for path in ("/boom", "/admin/boom"):
        app.add_api_route(path, boom)
    for path in ("/slow", "/admin/slow"):
        app.add_api_route(path, slow)
    async with client_for(app) as client:
        for path, status in (("/boom", 500), ("/slow", 504), ("/admin/boom", 500), ("/admin/slow", 504)):
            response = await client.get(path)
            assert response.status_code == status, path
            csp = response.headers.get("content-security-policy", "")
            assert csp.startswith("default-src 'none'; script-src 'nonce-"), path
            assert response.headers["x-frame-options"] == "DENY"
            assert len(response.headers.get_list("content-security-policy")) == 1
            if path.startswith("/admin"):
                assert response.headers["cache-control"] == "no-store", path
                assert response.headers["cross-origin-embedder-policy"] == "require-corp", path
            else:
                assert "cross-origin-embedder-policy" not in response.headers


async def test_outer_answers_send_hsts_when_enabled(make_app: Any, client_for: Any) -> None:
    from types import SimpleNamespace

    app = make_app(send_hsts=True)
    app.state.env = SimpleNamespace(send_hsts=True)

    async def boom() -> None:
        raise RuntimeError("bug")

    app.add_api_route("/boom", boom)
    async with client_for(app) as client:
        response = await client.get("/boom")
    assert response.status_code == 500
    assert response.headers["strict-transport-security"].startswith("max-age=")
