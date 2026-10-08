"""End-to-end pipeline tests: the fully wired application, from the caller's bytes to Roblox and back.

What this is
    Tests that drive `create_app(env)` with its real lifespan (every wave 2 package wired: notifier, egress,
    recorder, upstream, cache with single-flight, abuse, proxy) over temporary databases, with `respx` playing
    Roblox behind the real egress clients. They cover every refusal golden through the real abuse pipeline, every
    plan 7.13 row (with `compat_collapse_upstream_errors` off and on where it changes the answer), the cache states
    HIT, MISS, REVALIDATING, STALE (after a failure and during a cooldown), COALESCED, negative caching and the POST
    allowlist, plan 19.5 item 4 (the end-to-end recording proxy) and item 10
    (`test_cred_response_never_served_to_other_auth_class`) through the full app.

Why it exists
    Each package has unit tests against fakes of its neighbors; only this module proves the real objects fit
    together: the DESIGN 11.1 order holds when every step is the real one, callers receive the golden bytes and
    headers, and the credential rules (C1, C2, plan 6.9) hold across the package boundaries.

How it works
    The `e2e` fixture builds the app with a `FakeClock` (cache lifetimes, cooldowns and limiter windows move only
    when a test advances it), removes the mail and webhook credentials (alerts go to the log only), and turns the
    tarpit off (a refusal would otherwise be held 8 to 20 s; one test turns it on with a short hold). Every request
    gets its own client address through `X-Forwarded-For` (the peer is the trusted loopback proxy), so one test's
    per-IP limiter never touches another request unless the test wants it to. Settings change through the real
    `SettingsService` and rules through the real `RulesService`; both are live at once on the writing worker.
    `last()` reads the newest row of the recorder's Live ring, which is the outcome record of the latest request.
    Header checks list every `Roxy-*` and `Retry-After` header expected; an extra one fails the test.

What to read next
    `roxy/proxy/router.py` (the flow), `roxy/proxy/respond.py` (the bytes), `roxy/lifespan.py` (the wiring), then
    `tests/multiprocess/test_gunicorn_mp.py` (the same app under real gunicorn workers).
"""

from __future__ import annotations

import asyncio
import importlib.util
import itertools
import json
import sys
from collections.abc import AsyncIterator, Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import pytest

from roxy.abuse.pause import set_pause
from roxy.abuse.throttle_all import set_throttle_all
from roxy.config.audit import Actor
from roxy.config.settings_service import SettingsService
from roxy.core.clock import FakeClock
from roxy.core.reasons import Egress
from roxy.core.redact import TOKEN_PREFIX
from roxy.main import create_app
from roxy.rules.service import RulesService

ADMIN = Actor("admin", "e2e")
GAMES = "games.roblox.com"
GAMES_PATH = "/v1/games"
FAILED = b"Upstream request failed; please try again later."
BUSY = b"All request methods are busy right now; please try again shortly."
RUNG1 = "Too many requests; please slow down."
TEXT = "text/plain; charset=utf-8"
JSON = "application/json"
NETS = ("192.0.2", "198.51.100", "203.0.113")  # documentation ranges (RFC 5737): never real clients
UNCOUNTED = {"Roxy-Requests-Left": "10", "Roxy-Throttle-Reset": "0", "Roxy-Throttled": "False"}
"""The per-IP trio of a client the limiter has not counted (a refusal before the limiter, or a bypass)."""
ALLOWED = {"Roxy-Requests-Left": "9", "Roxy-Throttle-Reset": "5", "Roxy-Throttled": "False"}
"""The trio after a client's first admitted request (GCRA, 10 per 50 s)."""
THROTTLED = {
    "Retry-After": "50",
    "Roxy-Requests-Left": "0",
    "Roxy-Throttle-Reset": "50",
    "Roxy-Throttled": "True",
    "Roxy-Refusal": "throttle",
}


def wire(text: str) -> bytes:
    """v1's refusal wire form: a JSON string plus a newline (Flask jsonify)."""
    return (json.dumps(text) + "\n").encode()


def load_fixture(name: str) -> Any:
    """Load a module from tests/fixtures by path (tests are not a package)."""
    if name in sys.modules:
        return sys.modules[name]
    path = Path(__file__).resolve().parents[1] / "fixtures" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def roxy_headers(response: httpx.Response) -> dict[str, str]:
    """Every `Roxy-*` header and `Retry-After` (lowercase names), without the request id."""
    return {
        name: value
        for name, value in response.headers.items()
        if (name.startswith("roxy-") or name == "retry-after") and name != "roxy-request-id"
    }


def expect(
    response: httpx.Response, status: int, body: bytes | None, headers: Mapping[str, str], content_type: str | None
) -> None:
    """Exact status, body, `Roxy-*` and `Retry-After` headers, and content type; the request id is always there."""
    seen = roxy_headers(response)
    assert response.status_code == status, (response.status_code, response.content[:200], seen)
    if body is not None:
        assert response.content == body
    assert seen == {name.lower(): value for name, value in headers.items()}
    if content_type is not None:
        assert response.headers["content-type"] == content_type
    assert len(response.headers["roxy-request-id"]) == 26


def json_response(payload: Any, status: int = 200, **headers: str) -> httpx.Response:
    return httpx.Response(status, json=payload, headers=headers)


@dataclass
class E2E:
    """The running app and the tools a test uses on it."""

    app: Any
    ctx: Any
    clock: FakeClock
    http: httpx.AsyncClient
    roblox: Any  # the respx router (absent for the recording proxy tests)
    credential: str
    _ips: Any = field(default_factory=itertools.count)

    def ip(self) -> str:
        """A client address no other request in this test has used."""
        n = next(self._ips)
        return f"{NETS[n // 254 % len(NETS)]}.{n % 254 + 1}"

    async def request(
        self,
        method: str,
        path: str,
        *,
        ip: str | None = None,
        headers: Mapping[str, str] | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        sent = {"User-Agent": "Roblox/Linux", "X-Forwarded-For": ip or self.ip()}
        sent.update(headers or {})
        return await self.http.request(method, path, headers=sent, **kwargs)

    async def get(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", path, **kwargs)

    async def settings(self, **changes: Any) -> None:
        service = SettingsService(self.ctx.dbs.control, runtime=self.ctx.settings, clock=self.clock)
        await service.update(changes, ADMIN, "e2e test")

    def rules(self) -> RulesService:
        return RulesService(self.ctx.dbs.control, clock=self.clock, store=self.ctx.rules)

    async def rule(self, table: str, row: Mapping[str, Any]) -> Any:
        return await self.rules().create(table, dict(row), ADMIN, "e2e test")

    def last(self) -> dict[str, Any]:
        """The outcome record of the latest proxy request (the newest Live row)."""
        rows = self.ctx.recorder.live.snapshot(limit=1)
        assert rows, "no outcome was recorded"
        return dict(rows[0])

    def route(self, host: str, path: str) -> Any:
        return self.roblox.route(host=host, path=path)


@pytest.fixture
async def e2e(env: Any, credentials_dir: Path, fake_secrets: dict[str, str], respx_mock: Any) -> AsyncIterator[E2E]:
    """The real app over temp databases, Roblox played by respx, the tarpit off."""
    async with running_app(env, credentials_dir, fake_secrets, respx_mock) as harness:
        yield harness


class _Running:
    def __init__(self, env: Any, credentials_dir: Path, secrets: dict[str, str], roblox: Any) -> None:
        self.env, self.credentials_dir, self.secrets, self.roblox = env, credentials_dir, secrets, roblox
        self.lifespan: Any = None
        self.client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> E2E:
        for name in ("smtp_password", "alert_webhook_url"):
            (self.credentials_dir / name).unlink(missing_ok=True)  # alerts go to the log only
        clock = FakeClock()
        app = create_app(self.env, clock=clock)
        self.lifespan = app.router.lifespan_context(app)
        await self.lifespan.__aenter__()
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 50000))
        self.client = httpx.AsyncClient(transport=transport, base_url="http://testserver")
        harness = E2E(app, app.state.ctx, clock, self.client, self.roblox, self.secrets["roblox_credential"])
        # The tarpit off (a refusal would be held 8 to 20 s) and the rotator off (with direct cooling down, routing
        # would rightly send the next request through the rotator, plan 7.2); tests that need them turn them on.
        await harness.settings(tarpit_enabled=0, rotator_enabled=0)
        return harness

    async def __aexit__(self, *exc: object) -> None:
        if self.client is not None:
            await self.client.aclose()
        await self.lifespan.__aexit__(None, None, None)


def running_app(env: Any, credentials_dir: Path, secrets: dict[str, str], roblox: Any) -> _Running:
    return _Running(env, credentials_dir, secrets, roblox)


async def wait_for(predicate: Callable[[], bool], timeout_s: float = 5.0) -> bool:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_s
    while loop.time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.02)
    return predicate()


def games(universe: int | str = 1) -> str:
    return f"/{GAMES}{GAMES_PATH}?universeIds={universe}"


# =================================================================================================== refusal goldens


async def test_refusal_paused(e2e: E2E) -> None:
    route = e2e.route(GAMES, GAMES_PATH).mock(return_value=json_response({"data": []}))
    await set_pause(e2e.ctx.dbs.control, e2e.clock, ADMIN, paused=True)
    await e2e.ctx.abuse.switches.reload()
    response = await e2e.get(games())
    expect(
        response,
        503,
        wire("Service down for maintenance."),
        {**UNCOUNTED, "Roxy-Paused": "True", "Retry-After": "60", "Roxy-Refusal": "paused"},
        JSON,
    )
    assert e2e.last()["reason"] == "paused"
    assert route.call_count == 0
    health = json.loads((await e2e.http.get("/health")).content)
    assert health["Paused"] is True


async def test_refusal_banned_disguised_as_throttle(e2e: E2E) -> None:
    ip = e2e.ip()
    await e2e.rule("bans", {"subject_type": "ip", "subject": ip, "reason_text": "e2e"})
    response = await e2e.get(games(), ip=ip)
    expect(response, 429, wire(RUNG1), THROTTLED, JSON)
    assert e2e.last()["reason"] == "banned"


async def test_refusal_deny_list(e2e: E2E) -> None:
    await e2e.settings(ban_disguise_as_throttle=0)
    await e2e.rule("access_list", {"kind": "deny", "cidr": "203.0.113.0/24"})
    response = await e2e.get(games(), ip="203.0.113.77")
    expect(response, 403, wire("Access denied."), {**UNCOUNTED, "Roxy-Refusal": "deny_list"}, JSON)


async def test_refusal_flood(e2e: E2E) -> None:
    await e2e.settings(flood_limit_per_minute=10, allowed_requests_per_minute=1000)
    e2e.route(GAMES, GAMES_PATH).mock(return_value=json_response({"data": []}))
    ip = e2e.ip()
    for n in range(10):
        assert (await e2e.get(games(n), ip=ip)).status_code == 200
    response = await e2e.get(games(99), ip=ip)
    assert response.status_code == 429
    assert response.content == wire("You are sending requests too fast; try again in 6 seconds.")
    assert roxy_headers(response)["retry-after"] == "6"
    assert roxy_headers(response)["roxy-refusal"] == "flood"


async def test_refusal_spam_disguised(e2e: E2E) -> None:
    await e2e.settings(spam_probe_action="tarpit", spam_probe_threshold=2, spam_dry_run=0)
    ip = e2e.ip()
    for _ in range(2):
        assert (await e2e.get("/evil.example.com/wp-login.php", ip=ip)).status_code == 404
    await e2e.ctx.abuse.spam.flush()
    response = await e2e.get(games(), ip=ip)
    assert response.status_code == 429
    assert response.content == wire(RUNG1)
    assert roxy_headers(response)["roxy-refusal"] == "throttle"  # disguised: looks like a genuine throttle
    assert e2e.last()["reason"] == "spam"


async def test_refusal_throttle_all(e2e: E2E) -> None:
    e2e.route(GAMES, GAMES_PATH).mock(return_value=json_response({"data": []}))
    await set_throttle_all(e2e.ctx.dbs.control, e2e.clock, ADMIN, enabled=True)
    await e2e.ctx.abuse.switches.reload()
    ip = e2e.ip()
    assert (await e2e.get(games(1), ip=ip)).status_code == 200
    response = await e2e.get(games(2), ip=ip)
    expect(
        response,
        429,
        wire("Service down for maintenance."),
        {
            "Roxy-Requests-Left": "9",
            "Roxy-Throttle-Reset": "60",
            "Roxy-Throttled": "False",
            "Roxy-Global-Throttled": "True",
            "Retry-After": "60",
            "Roxy-Refusal": "throttle_all",
        },
        JSON,
    )


async def test_refusal_per_ip_throttle(e2e: E2E) -> None:
    route = e2e.route(GAMES, GAMES_PATH).mock(return_value=json_response({"data": []}))
    ip = e2e.ip()
    for n in range(10):
        assert (await e2e.get(games(n), ip=ip)).status_code == 200
    response = await e2e.get(games(99), ip=ip)
    expect(response, 429, wire(RUNG1), THROTTLED, JSON)
    assert route.call_count == 10
    assert e2e.last()["reason"] == "throttle"


async def test_refusal_place_limit(e2e: E2E) -> None:
    await e2e.settings(place_limit_enabled=1, place_limit_per_minute=2, allowed_requests_per_minute=1000)
    e2e.route(GAMES, GAMES_PATH).mock(return_value=json_response({"data": []}))
    ip = e2e.ip()
    for n in range(2):
        assert (await e2e.get(games(n), ip=ip, headers={"Roblox-Id": "1818"})).status_code == 200
    response = await e2e.get(games(9), ip=ip, headers={"Roblox-Id": "1818"})
    assert response.status_code == 429
    assert response.content == wire("This experience is over its request limit; try again in 30 seconds.")
    assert roxy_headers(response)["roxy-refusal"] == "place_limit"


async def test_refusal_bot_score(e2e: E2E) -> None:
    await e2e.settings(bot_score_block_threshold=30)
    response = await e2e.get(games(), headers={"User-Agent": "python-requests/2.31"})
    expect(response, 403, wire("Access denied."), {**UNCOUNTED, "Roxy-Refusal": "bot_score"}, JSON)


async def test_refusal_challenge_page(e2e: E2E) -> None:
    await e2e.settings(challenge_enabled=1, challenge_trigger_score=10)
    response = await e2e.get(games(), headers={"User-Agent": "Mozilla/5.0 curl/8"})
    assert response.status_code == 403
    assert response.headers["content-type"].startswith("text/html")
    assert response.content.startswith(b"<!doctype html>")
    assert roxy_headers(response)["roxy-refusal"] == "challenge"
    # The page's script runs under the page CSP with this response's nonce, not the proxied sandbox CSP.
    csp = response.headers["content-security-policy"]
    assert "sandbox" not in csp
    assert "nonce-" in csp


async def test_refusal_user_agent_rule(e2e: E2E) -> None:
    e2e.route(GAMES, GAMES_PATH).mock(return_value=json_response({"data": []}))
    await e2e.rule("rules_user_agent", {"needle": "scraper", "kind": "burst", "limit": 2, "period": 60})
    ip = e2e.ip()
    ua = {"User-Agent": "MyScraper/1"}
    for n in range(2):
        assert (await e2e.get(games(n), ip=ip, headers=ua)).status_code == 200
    response = await e2e.get(games(9), ip=ip, headers=ua)
    expect(
        response,
        429,
        wire("This client is limited to 2 requests per 60s. Try again in 60 seconds."),
        {
            "Roxy-Requests-Left": "8",
            "Roxy-Throttle-Reset": "60",
            "Roxy-Throttled": "True",
            "Retry-After": "60",
            "Roxy-Client-Limited": "True",
            "Roxy-Refusal": "user_agent_rule",
        },
        JSON,
    )


async def test_refusal_ignored_path(e2e: E2E) -> None:
    response = await e2e.get("/.well-known/appspecific/com.chrome.devtools.json")
    expect(response, 404, wire("Not Found"), {**UNCOUNTED, "Roxy-Refusal": "ignored_path"}, JSON)


@pytest.mark.parametrize(
    ("path", "body", "reason"),
    [
        ("/games.roblox.com/v1/<script>", wire("Invalid URL"), "unsafe_url"),
        ("/evil.example.com/wp-login.php", wire("Not a Roblox URL"), "not_roblox"),
        ("/www.roblox.com/home", wire("Not a Roblox URL"), "host_not_allowed"),
    ],
)
async def test_refusal_target_problems(e2e: E2E, path: str, body: bytes, reason: str) -> None:
    response = await e2e.get(path)
    expect(response, 404, body, {**UNCOUNTED, "Roxy-Refusal": reason}, JSON)
    assert e2e.last()["reason"] == reason


async def test_refusal_auth_smuggling(e2e: E2E) -> None:
    route = e2e.route(GAMES, GAMES_PATH).mock(return_value=json_response({"data": []}))
    response = await e2e.get(games(), headers={"X-Roblox-Token": ""})
    expect(
        response,
        400,
        wire("Requests requiring authentication are not allowed with this proxy."),
        {**UNCOUNTED, "Roxy-Refusal": "auth_smuggling"},
        JSON,
    )
    cookie = await e2e.get(games(), headers={"Cookie": ".ROBLOSECURITY=anything"})
    assert cookie.status_code == 400
    assert route.call_count == 0


async def test_refusal_header_rule_disguised(e2e: E2E) -> None:
    await e2e.rule("rules_header", {"needle": "xeno", "scope": "either"})
    response = await e2e.get(games(), headers={"Xeno-Fingerprint": "4f3a91c0"})
    expect(response, 429, wire(RUNG1), THROTTLED, JSON)
    assert e2e.last()["reason"] == "header_rule"


async def test_refusal_endpoint_block(e2e: E2E) -> None:
    await e2e.rule("rules_endpoint_block", {"pattern": "games.roblox.com/v1/games"})
    response = await e2e.get(games())
    expect(
        response,
        403,
        wire("This endpoint is currently blocked."),
        {**UNCOUNTED, "Roxy-Blocked": "True", "Roxy-Refusal": "endpoint_blocked"},
        JSON,
    )


async def test_refusal_endpoint_rule(e2e: E2E) -> None:
    e2e.route(GAMES, GAMES_PATH).mock(return_value=json_response({"data": []}))
    await e2e.rule("rules_endpoint_limit", {"pattern": "games.roblox.com/v1/*", "limit": 1, "period": 60})
    ip = e2e.ip()
    assert (await e2e.get(games(1), ip=ip)).status_code == 200
    response = await e2e.get(games(2), ip=ip)
    expect(
        response,
        429,
        wire("This endpoint is rate-limited for you; try again in 60 seconds."),
        {
            "Roxy-Requests-Left": "9",
            "Roxy-Throttle-Reset": "60",
            "Roxy-Throttled": "True",
            "Retry-After": "60",
            "Roxy-Endpoint-Limited": "True",
            "Roxy-Refusal": "endpoint_rule",
        },
        JSON,
    )


async def test_refusals_by_the_size_limits_and_methods(e2e: E2E) -> None:
    await e2e.settings(max_url_length=256)
    long_url = await e2e.get(games("1," * 200))
    expect(long_url, 414, b"Request URL is too long.", {"Roxy-Refusal": "url_too_long"}, TEXT)
    await e2e.settings(max_body_bytes=1024)
    big = await e2e.request("POST", "/thumbnails.roblox.com/v1/batch", content=b"x" * 2048)
    expect(big, 413, b"Request body is too large.", {"Roxy-Refusal": "body_too_large"}, TEXT)
    many = await e2e.get(games(), headers={f"X-Filler-{n}": "1" for n in range(200)})
    expect(many, 431, b"Request header fields are too large.", {"Roxy-Refusal": "headers_too_large"}, TEXT)
    trace = await e2e.request("TRACE", games())
    assert trace.status_code == 405


async def test_options_and_head(e2e: E2E) -> None:
    route = e2e.route(GAMES, GAMES_PATH).mock(return_value=json_response({"data": [7]}))
    options = await e2e.request("OPTIONS", games())
    assert options.status_code == 204
    assert options.headers["allow"] == "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"
    assert route.call_count == 0
    head = await e2e.request("HEAD", games(5))
    assert head.status_code == 200
    assert head.content == b""
    assert route.call_count == 1
    assert route.calls.last.request.method == "GET"  # HEAD runs as GET upstream; only the body is dropped


async def test_public_health_and_post_health(e2e: E2E) -> None:
    response = await e2e.http.get("/health")
    assert response.status_code == 200
    assert response.headers["content-type"] == JSON
    assert response.content.endswith(b"}\n")
    body = json.loads(response.content)
    assert list(body) == sorted(body)  # v1 jsonify: sorted keys
    assert set(body) == {"DataBytes", "DataLimitBytes", "Degraded", "Paused", "PersistenceOK", "Status"}
    assert body["Status"] == "ok"
    assert body["PersistenceOK"] is True
    assert body["Degraded"] == []
    assert body["DataLimitBytes"] == 12 * 1024**3
    assert body["DataBytes"] > 0
    post = await e2e.request("POST", "/health")
    assert post.status_code == 404
    assert post.content == wire("Not a Roblox URL")


# ====================================================================================================== plan 7.13


async def test_row_roblox_2xx(e2e: E2E) -> None:
    route = e2e.route(GAMES, GAMES_PATH).mock(return_value=json_response({"data": [1]}, 200))
    response = await e2e.get(games())
    expect(
        response,
        200,
        b'{"data":[1]}',
        {**ALLOWED, "Roxy-Cache": "MISS", "Roxy-Upstream-Status": "200"},
        JSON,
    )
    assert route.call_count == 1
    sent = route.calls.last.request
    assert "cookie" not in sent.headers  # anonymous traffic never carries a cookie (C2)
    assert sent.url.params["universeIds"] == "1"
    created = e2e.route("groups.roblox.com", "/v1/groups/7").mock(return_value=json_response({"id": 7}, 201))
    second = await e2e.get("/groups.roblox.com/v1/groups/7")
    assert second.status_code == 201  # a 2xx other than 200 is a success, passed through (D4)
    assert created.call_count == 1
    assert e2e.last()["reason"] == "upstream_ok"


async def test_row_redirect_followed(e2e: E2E) -> None:
    e2e.route(GAMES, "/v1/old").mock(
        return_value=httpx.Response(302, headers={"Location": "https://games.roblox.com/v1/new"})
    )
    final = e2e.route(GAMES, "/v1/new").mock(return_value=json_response({"moved": True}))
    response = await e2e.get(f"/{GAMES}/v1/old")
    assert response.status_code == 200
    assert response.content == b'{"moved":true}'
    assert final.call_count == 1


@pytest.mark.parametrize("compat", [0, 1])
async def test_row_roblox_4xx(e2e: E2E, compat: int) -> None:
    await e2e.settings(compat_collapse_upstream_errors=compat)
    body = b'{"errors":[{"code":0,"message":"BadRequest"}]}'
    e2e.route(GAMES, "/v1/games/votes").mock(return_value=httpx.Response(400, content=body))
    response = await e2e.get(f"/{GAMES}/v1/games/votes?universeIds=1")
    if compat:
        assert response.status_code == 500
        assert response.content == FAILED
    else:
        expect(response, 400, body, {**ALLOWED, "Roxy-Cache": "MISS", "Roxy-Upstream-Status": "400"}, None)


async def test_row_429_with_stale_entry(e2e: E2E) -> None:
    state = {"limited": False}

    def roblox(request: httpx.Request) -> httpx.Response:
        if state["limited"]:
            return json_response({"errors": [{"message": "Too many requests"}]}, 429, **{"Retry-After": "30"})
        return json_response({"data": ["old"]})

    route = e2e.route(GAMES, GAMES_PATH).mock(side_effect=roblox)
    assert (await e2e.get(games())).status_code == 200
    e2e.clock.advance(400)  # past the 300 s rule TTL and the 60 s SWR window, inside the 600 s stale window
    state["limited"] = True
    response = await e2e.get(games())
    expect(
        response,
        200,
        b'{"data":["old"]}',
        {
            **ALLOWED,
            "Roxy-Cache": "STALE",
            "Roxy-Upstream-Cooldown": "30",
            "Roxy-Upstream-Status": "429",
            "Roxy-Cache-Age": "400",
            "Roxy-Cache-TTL": "300",
        },
        JSON,
    )
    assert route.call_count == 2


async def test_row_429_without_stale_and_the_fleet_cooldown(e2e: E2E) -> None:
    route = e2e.route(GAMES, GAMES_PATH).mock(
        return_value=json_response({"errors": [{"message": "Too many requests"}]}, 429, **{"Retry-After": "30"})
    )
    first = await e2e.get(games(1))
    expect(
        first,
        429,
        BUSY,
        {
            **ALLOWED,
            "Retry-After": "30",
            "Roxy-Upstream-Cooldown": "30",
            "Roxy-Refusal": "upstream_cooldown",
            "Roxy-Cache": "MISS",
            "Roxy-Upstream-Status": "429",  # this request did reach Roblox
        },
        TEXT,
    )
    assert route.call_count == 1
    e2e.clock.advance(10)
    other_key = await e2e.get(games(2))  # same endpoint, other key: no call while the cooldown lasts
    assert other_key.status_code == 429
    assert roxy_headers(other_key)["retry-after"] == "20"
    assert roxy_headers(other_key)["roxy-refusal"] == "upstream_cooldown"
    assert route.call_count == 1
    assert e2e.last()["reason"] == "upstream_cooldown"


async def test_row_upstream_busy(e2e: E2E) -> None:
    await e2e.settings(endpoint_bucket_default_per_min=1, endpoint_bucket_default_burst=1, queue_wait_interactive_ms=0)
    route = e2e.route(GAMES, GAMES_PATH).mock(return_value=json_response({"data": []}))
    assert (await e2e.get(games(1))).status_code == 200
    response = await e2e.get(games(2))
    assert response.status_code == 429
    assert response.content == BUSY
    headers = roxy_headers(response)
    assert headers["roxy-refusal"] == "upstream_busy"
    assert int(headers["retry-after"]) >= 1
    assert route.call_count == 1


async def test_row_queue_overflow(e2e: E2E) -> None:
    await e2e.settings(
        endpoint_bucket_default_per_min=600,
        endpoint_bucket_default_burst=1,
        queue_max_length=10,
        queue_wait_interactive_ms=20_000,
    )
    e2e.route(GAMES, GAMES_PATH).mock(return_value=json_response({"data": []}))
    responses = await asyncio.gather(*(e2e.get(games(n)) for n in range(30)))
    overflow = [r for r in responses if roxy_headers(r).get("roxy-refusal") == "queue_overflow"]
    assert overflow, [r.status_code for r in responses]
    for response in overflow:
        assert response.status_code == 429
        assert response.content == BUSY
        assert int(roxy_headers(response)["retry-after"]) >= 1


@pytest.mark.parametrize("compat", [0, 1])
async def test_row_upstream_5xx(e2e: E2E, compat: int) -> None:
    await e2e.settings(compat_collapse_upstream_errors=compat, backoff_base_ms=10, backoff_cap_ms=20)
    route = e2e.route(GAMES, GAMES_PATH).mock(return_value=httpx.Response(503, content=b"down"))
    response = await e2e.get(games())
    assert route.call_count == 2  # upstream_max_attempts
    if compat:
        expect(
            response,
            500,
            FAILED,
            {**ALLOWED, "Retry-After": "5", "Roxy-Upstream-Status": "503", "Roxy-Cache": "MISS"},
            TEXT,
        )
    else:
        expect(
            response,
            503,
            FAILED,
            {**ALLOWED, "Retry-After": "5", "Roxy-Upstream-Status": "503", "Roxy-Cache": "MISS"},
            TEXT,
        )


@pytest.mark.parametrize("compat", [0, 1])
@pytest.mark.parametrize(
    ("error", "status", "reason"),
    [(httpx.ReadTimeout("slow"), 504, "upstream_timeout"), (httpx.ConnectError("refused"), 502, "upstream_connect")],
)
async def test_row_timeout_and_connect(e2e: E2E, compat: int, error: Exception, status: int, reason: str) -> None:
    await e2e.settings(compat_collapse_upstream_errors=compat, backoff_base_ms=10, backoff_cap_ms=20)
    e2e.route(GAMES, GAMES_PATH).mock(side_effect=error)
    response = await e2e.get(games())
    expected = {**ALLOWED, "Retry-After": "5", "Roxy-Refusal": reason, "Roxy-Cache": "MISS"}
    expect(response, 500 if compat else status, FAILED, expected, TEXT)
    assert e2e.last()["reason"] == reason


async def test_row_deadline(e2e: E2E) -> None:
    # The smallest valid deadline (10 s) with every inner budget inside it (catalog cross rule, plan 5.2).
    await e2e.settings(
        request_deadline_s=10,
        request_timeout=2,
        upstream_max_attempts=1,
        queue_wait_interactive_ms=1000,
        backoff_base_ms=50,
        backoff_cap_ms=100,
        tarpit_min_seconds=1,
        tarpit_max_seconds=5,
    )

    async def hang(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(30)  # respx bypasses the socket timeouts: only the request deadline can end this
        return json_response({})

    e2e.route(GAMES, GAMES_PATH).mock(side_effect=hang)
    response = await e2e.get(games())
    assert response.status_code == 504
    assert response.content == FAILED
    assert roxy_headers(response) == {"retry-after": "5", "roxy-refusal": "deadline"}
    record = e2e.last()  # the canceled flow recorded its own fallback outcome (DESIGN 7)
    assert (record["status"], record["reason"]) == (504, "deadline")


async def test_row_coalesce_timeout(
    e2e: E2E, env: Any, credentials_dir: Path, fake_secrets: dict[str, str], respx_mock: Any
) -> None:
    """Plan 6.9 step 5 across two workers (two apps sharing the databases): the follower in the other worker stops
    waiting after `cache_coalesce_wait_ms` and answers 503 with the owner's remaining deadline. (A follower in the
    owner's own worker waits for the owner's answer, whose fetch has its own deadline.)"""
    await e2e.settings(cache_coalesce_wait_ms=200)
    gate = asyncio.Event()
    started: list[str] = []

    async def slow(request: httpx.Request) -> httpx.Response:
        started.append(str(request.url))  # respx records a call only once it has answered
        await gate.wait()
        return json_response({"data": ["late"]})

    route = e2e.route(GAMES, GAMES_PATH).mock(side_effect=slow)
    async with running_app(env, credentials_dir, fake_secrets, respx_mock) as other:
        assert other.ctx.worker_id != e2e.ctx.worker_id
        await other.ctx.settings.refresh_if_changed()
        owner = asyncio.create_task(e2e.get(games()))
        assert await wait_for(lambda: len(started) == 1)
        follower = await other.get(games(), ip="203.0.113.250")  # a client the owner's worker has not seen
        gate.set()
        assert (await owner).status_code == 200
        expect(
            follower,
            503,
            BUSY,
            {
                **ALLOWED,
                "Retry-After": roxy_headers(follower).get("retry-after", "missing"),
                "Roxy-Refusal": "coalesce_timeout",
                "Roxy-Cache": "MISS",
            },
            TEXT,
        )
        assert 1 <= int(roxy_headers(follower)["retry-after"]) <= 36  # the owner deadline (plan 5.2) at most
        assert other.last()["reason"] == "coalesce_timeout"
        assert route.call_count == 1  # followers never go upstream


async def test_row_egress_disabled(e2e: E2E) -> None:
    await e2e.settings(direct_enabled=0, rotator_enabled=0)
    route = e2e.route(GAMES, GAMES_PATH).mock(return_value=json_response({}))
    response = await e2e.get(games())
    expect(
        response,
        503,
        BUSY,
        {**ALLOWED, "Retry-After": "60", "Roxy-Refusal": "egress_disabled", "Roxy-Cache": "MISS"},
        TEXT,
    )
    assert route.call_count == 0


async def test_row_credential_unavailable(e2e: E2E) -> None:
    await e2e.rule("credential_allowlist", {"pattern": "economy.roblox.com/v1/user/currency", "cache_private": True})
    await e2e.ctx.egress.credential.mark_rejected("e2e test")
    route = e2e.route("economy.roblox.com", "/v1/user/currency").mock(return_value=json_response({"robux": 1}))
    response = await e2e.get("/economy.roblox.com/v1/user/currency")
    assert response.status_code == 503
    assert response.content == BUSY
    headers = roxy_headers(response)
    assert headers["roxy-refusal"] == "credential_unavailable"
    assert headers["retry-after"] == "300"
    assert route.call_count == 0  # never anonymous instead (plan 6.9)


async def test_row_degraded_shared_state(e2e: E2E, monkeypatch: pytest.MonkeyPatch) -> None:
    from roxy.storage.db import SharedStateUnavailable

    route = e2e.route(GAMES, GAMES_PATH).mock(return_value=json_response({}))

    async def unavailable(*args: Any, **kwargs: Any) -> Any:
        raise SharedStateUnavailable("hot", "test: disk gone")

    monkeypatch.setattr(e2e.ctx.dbs.hot, "write", unavailable)
    monkeypatch.setattr(e2e.ctx.dbs.hot, "read", unavailable)
    response = await e2e.get(games())
    assert response.status_code == 503
    assert response.content == BUSY
    headers = roxy_headers(response)
    assert headers["retry-after"] == "10"
    assert headers["roxy-refusal"] == "degraded"
    assert route.call_count == 0  # C7: nothing goes out unpaced


async def test_row_internal_error_is_recorded_once(e2e: E2E, monkeypatch: pytest.MonkeyPatch) -> None:
    async def broken(req: Any, peek: Any) -> Any:
        raise RuntimeError("e2e: a bug in the cache layer")

    monkeypatch.setattr(e2e.ctx.cache, "serve", broken)
    before = len(e2e.ctx.recorder.live)
    response = await e2e.get(games())
    assert response.status_code == 500
    assert response.content == b"Internal Server Error"
    assert response.headers["retry-after"] == "5"
    assert len(e2e.ctx.recorder.live) == before + 1
    assert (e2e.last()["reason"], e2e.last()["status"]) == ("internal_error", 500)


# ===================================================================================================== cache states


async def test_cache_miss_then_hit(e2e: E2E) -> None:
    route = e2e.route(GAMES, GAMES_PATH).mock(return_value=json_response({"data": [1]}))
    first = await e2e.get(games())
    second = await e2e.get(games())
    assert roxy_headers(first)["roxy-cache"] == "MISS"
    expect(
        second,
        200,
        b'{"data":[1]}',
        {**UNCOUNTED, "Roxy-Requests-Left": "10", "Roxy-Cache": "HIT", "Roxy-Cache-Age": "0", "Roxy-Cache-TTL": "300"},
        JSON,
    )
    assert route.call_count == 1
    assert e2e.last()["reason"] == "cache_hit"


async def test_cache_revalidating(e2e: E2E) -> None:
    bodies = iter([{"data": ["v1"]}, {"data": ["v2"]}])
    route = e2e.route(GAMES, GAMES_PATH).mock(side_effect=lambda request: json_response(next(bodies)))
    await e2e.get(games())
    e2e.clock.advance(330)  # expired 30 s ago: inside the 60 s stale-while-revalidate window
    response = await e2e.get(games())
    assert roxy_headers(response)["roxy-cache"] == "REVALIDATING"
    assert response.content == b'{"data":["v1"]}'
    assert await wait_for(lambda: route.call_count == 2)  # one background refresh
    requests = 2
    for _ in range(50):
        fresh = await e2e.get(games())
        requests += 1
        if fresh.content == b'{"data":["v2"]}':
            break
        await asyncio.sleep(0.02)
    assert roxy_headers(fresh)["roxy-cache"] == "HIT"
    assert fresh.content == b'{"data":["v2"]}'
    assert route.call_count == 2
    # Honest numbers (P6): the refresh is an upstream call that no caller request made.
    await e2e.ctx.recorder.flush()
    totals = await e2e.ctx.dbs.metrics.read(
        lambda conn: tuple(conn.execute("SELECT sum(requests), sum(upstream_calls) FROM rollup_minute").fetchone())
    )
    assert totals == (requests, 2)


async def test_cache_stale_after_failure(e2e: E2E) -> None:
    await e2e.settings(backoff_base_ms=10, backoff_cap_ms=20)
    state = {"down": False}

    def roblox(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, content=b"oops") if state["down"] else json_response({"data": ["kept"]})

    e2e.route(GAMES, GAMES_PATH).mock(side_effect=roblox)
    await e2e.get(games())
    e2e.clock.advance(400)
    state["down"] = True
    response = await e2e.get(games())
    assert response.status_code == 200
    assert response.content == b'{"data":["kept"]}'
    assert roxy_headers(response)["roxy-cache"] == "STALE"
    assert e2e.last()["reason"] == "cache_stale_error"


async def test_cache_stale_during_cooldown_without_a_call(e2e: E2E) -> None:
    calls: list[str] = []

    def roblox(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.params.get("universeIds", ""))
        if request.url.params.get("universeIds") == "2":
            return json_response({"errors": []}, 429, **{"Retry-After": "120"})
        return json_response({"data": ["a"]})

    e2e.route(GAMES, GAMES_PATH).mock(side_effect=roblox)
    await e2e.get(games(1))  # cached
    e2e.clock.advance(400)  # games(1) is now stale (past TTL and SWR)
    limited = await e2e.get(games(2))  # opens the endpoint cooldown
    assert limited.status_code == 429
    await e2e.ctx.upstream.refresh_mirror()
    response = await e2e.get(games(1))
    assert response.status_code == 200
    assert response.content == b'{"data":["a"]}'
    headers = roxy_headers(response)
    assert headers["roxy-cache"] == "STALE"
    assert int(headers["roxy-upstream-cooldown"]) > 0
    assert calls == ["1", "2"]  # the stale serve made no call
    assert e2e.last()["reason"] == "cache_stale_cooldown"


async def test_cache_coalesced(e2e: E2E) -> None:
    gate = asyncio.Event()

    async def slow(request: httpx.Request) -> httpx.Response:
        await gate.wait()
        return json_response({"data": ["shared"]})

    route = e2e.route(GAMES, GAMES_PATH).mock(side_effect=slow)
    tasks = [asyncio.create_task(e2e.get(games())) for _ in range(5)]
    await asyncio.sleep(0.1)
    gate.set()
    responses = await asyncio.gather(*tasks)
    states = sorted(roxy_headers(r)["roxy-cache"] for r in responses)
    assert states == ["COALESCED"] * 4 + ["MISS"]
    assert all(r.content == b'{"data":["shared"]}' for r in responses)
    assert route.call_count == 1


async def test_cache_negative_entries(e2e: E2E) -> None:
    body = b'{"errors":[{"code":1,"message":"NotFound"}]}'
    route = e2e.route("users.roblox.com", "/v1/users/404404").mock(return_value=httpx.Response(404, content=body))
    first = await e2e.get("/users.roblox.com/v1/users/404404")
    second = await e2e.get("/users.roblox.com/v1/users/404404")
    assert (first.status_code, second.status_code) == (404, 404)
    assert second.content == body
    assert roxy_headers(second)["roxy-cache"] == "HIT"
    assert route.call_count == 1
    assert e2e.last()["reason"] == "cache_negative"


async def test_cache_post_allowlist(e2e: E2E) -> None:
    batch = e2e.route("thumbnails.roblox.com", "/v1/batch").mock(return_value=json_response({"data": ["t"]}))
    payload = [{"requestId": "1", "targetId": 1, "type": "Avatar", "size": "48x48"}]
    first = await e2e.request("POST", "/thumbnails.roblox.com/v1/batch", json=payload)
    second = await e2e.request("POST", "/thumbnails.roblox.com/v1/batch", json=payload)
    other = await e2e.request("POST", "/thumbnails.roblox.com/v1/batch", json=[*payload, {"targetId": 2}])
    assert [roxy_headers(r)["roxy-cache"] for r in (first, second, other)] == ["MISS", "HIT", "MISS"]
    assert batch.call_count == 2
    write = e2e.route(GAMES, "/v1/games/list").mock(return_value=json_response({"ok": True}))
    for _ in range(2):
        response = await e2e.request("POST", f"/{GAMES}/v1/games/list", json={"a": 1})
        assert roxy_headers(response)["roxy-cache"] == "OFF"
    assert write.call_count == 2  # a POST outside the allowlist is never cached


async def test_outcomes_reach_the_rollups(e2e: E2E) -> None:
    """Every proxy request is recorded exactly once, and the batch writer puts it in metrics.db."""
    e2e.route(GAMES, GAMES_PATH).mock(return_value=json_response({"data": []}))

    def total(conn: Any) -> int:
        return int(conn.execute("SELECT coalesce(sum(requests), 0) FROM rollup_minute").fetchone()[0])

    before = await e2e.ctx.dbs.metrics.read(total)
    await e2e.ctx.recorder.flush()
    before = await e2e.ctx.dbs.metrics.read(total)
    sent = 0
    for path in (games(1), games(1), "/evil.example.com/x", "/games.roblox.com/v1/<x>"):
        await e2e.get(path)
        sent += 1
    await e2e.request("OPTIONS", games(1))
    sent += 1
    await e2e.ctx.recorder.flush()
    assert await e2e.ctx.dbs.metrics.read(total) == before + sent


# ========================================================================================= plan 19.5 through the app


async def test_cred_response_never_served_to_other_auth_class(e2e: E2E) -> None:
    """Plan 6.9 and 19.5 item 10 through the full app: an answer fetched with the credential is never served to a
    request that would not itself use the credential (after the owner removes the allowlist row), whether as a hit,
    a coalesced flight, a stale-while-revalidate serve or a stale serve."""
    secret = f".ROBLOSECURITY={e2e.credential}"
    e2e.route("users.roblox.com", "/v1/users/authenticated").mock(
        return_value=json_response({"id": 1, "name": "owner"})
    )
    probe = await e2e.ctx.egress.credential.probe("admin_check", fetch=e2e.ctx.upstream.credential_probe_fetch)
    assert probe.ok, probe
    gate = asyncio.Event()
    gate.set()
    seen: list[bool] = []

    async def currency(request: httpx.Request) -> httpx.Response:
        with_cookie = request.headers.get("cookie") == secret
        seen.append(with_cookie)
        await gate.wait()
        if with_cookie:
            return json_response({"robux": "secret"})
        return json_response({"robux": "anonymous"})

    e2e.route("economy.roblox.com", "/v1/user/currency").mock(side_effect=currency)
    path = "/economy.roblox.com/v1/user/currency"
    row = await e2e.rule(
        "credential_allowlist", {"pattern": "economy.roblox.com/v1/user/currency", "cache_private": False}
    )
    rule_id = row.after["id"] if hasattr(row, "after") and isinstance(row.after, dict) else row.id

    # Hits: the credential answer is cached under the credential class only.
    cred = await e2e.get(path)
    assert cred.content == b'{"robux":"secret"}'
    assert (await e2e.get(path)).content == b'{"robux":"secret"}'
    assert seen == [True]
    await e2e.rules().delete("credential_allowlist", rule_id, ADMIN, "e2e test")
    anon = await e2e.get(path)
    assert anon.content == b'{"robux":"anonymous"}'
    assert roxy_headers(anon)["roxy-cache"] == "MISS"
    assert seen == [True, False]

    # Stale-while-revalidate and stale serves: each class only ever sees its own copy.
    e2e.clock.advance(150)  # both entries expired, inside the SWR window
    revalidating = await e2e.get(path)
    assert revalidating.content == b'{"robux":"anonymous"}'
    assert await wait_for(lambda: len(seen) == 3)
    assert seen[2] is False

    # Coalescing: a credential flight in progress is never joined by an anonymous request.
    e2e.clock.advance(2000)  # every entry is past its stale window
    gate.clear()
    readd = await e2e.rule(
        "credential_allowlist", {"pattern": "economy.roblox.com/v1/user/currency", "cache_private": False}
    )
    readd_id = readd.after["id"] if hasattr(readd, "after") and isinstance(readd.after, dict) else readd.id
    cred_task = asyncio.create_task(e2e.get(path))
    assert await wait_for(lambda: len(seen) == 4)
    await e2e.rules().delete("credential_allowlist", readd_id, ADMIN, "e2e test")
    anon_task = asyncio.create_task(e2e.get(path))
    assert await wait_for(lambda: len(seen) == 5)  # its own upstream call, not a follower of the credential flight
    gate.set()
    cred_late, anon_late = await asyncio.gather(cred_task, anon_task)
    assert cred_late.content == b'{"robux":"secret"}'
    assert anon_late.content == b'{"robux":"anonymous"}'
    assert roxy_headers(anon_late)["roxy-cache"] != "COALESCED"
    assert seen[3:] == [True, False]


async def test_public_markers_do_not_disable_egress(e2e: E2E) -> None:
    """Plan 19.5 item 2b through the app: the public markers (the warning text every cookie starts with, and the
    cookie name) are refused at ingress with 400 wherever they appear, and never switch an egress off."""
    route = e2e.route("thumbnails.roblox.com", "/v1/batch").mock(return_value=json_response({"data": []}))
    bodies = [json.dumps({"x": TOKEN_PREFIX}).encode(), b'{"note":".ROBLOSECURITY=abc"}']
    for body in bodies:
        refused = await e2e.request("POST", "/thumbnails.roblox.com/v1/batch", content=body)
        assert refused.status_code == 400
        assert roxy_headers(refused)["roxy-refusal"] == "auth_smuggling"
    in_query = await e2e.get(f"/{GAMES}{GAMES_PATH}", params={"universeIds": "1", "x": TOKEN_PREFIX + "ABC"})
    assert in_query.status_code == 400
    assert route.call_count == 0
    assert not e2e.ctx.egress.tripped(Egress.DIRECT)
    assert e2e.ctx.egress.is_enabled(Egress.DIRECT)[0]
    ok = await e2e.request("POST", "/thumbnails.roblox.com/v1/batch", json=[{"targetId": 1}])
    assert ok.status_code == 200  # the egress is still on


async def test_direct_guard_trip_through_the_app(e2e: E2E) -> None:
    """Plan 19.5 item 2a end to end: a caller body carrying a piece of the credential (no public marker, so the
    ingress check cannot know) is stopped by the direct client's guard: nothing is sent, the direct egress is
    disabled fleet-wide, and the caller gets the busy answer."""
    route = e2e.route("thumbnails.roblox.com", "/v1/batch").mock(return_value=json_response({"data": []}))
    piece = e2e.credential[-40:]
    response = await e2e.request("POST", "/thumbnails.roblox.com/v1/batch", json=[{"note": piece}])
    assert response.status_code == 503
    assert response.content == BUSY
    assert roxy_headers(response)["retry-after"] == "60"
    assert route.call_count == 0
    assert e2e.ctx.egress.tripped(Egress.DIRECT)
    health = json.loads((await e2e.http.get("/health")).content)
    assert "egress_direct_disabled" in health["Degraded"]


async def test_tarpit_hold_then_refusal(e2e: E2E) -> None:
    await e2e.settings(tarpit_enabled=1, tarpit_min_seconds=0, tarpit_max_seconds=1)
    loop = asyncio.get_running_loop()
    started = loop.time()
    response = await e2e.get("/evil.example.com/wp-login.php")
    assert response.status_code == 404
    assert response.content == wire("Not a Roblox URL")
    assert loop.time() - started <= 3
    assert e2e.ctx.abuse.tarpit.stats.snapshot()["reasons"]


# ================================================================================ plan 19.5 item 4 (recording proxy)


@pytest.fixture
async def through_rotator(
    env: Any, credentials_dir: Path, fake_secrets: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[tuple[E2E, Any, Any]]:
    """The full app with every anonymous request sent through the rotator, pointed at a local recording proxy, and
    every Roblox target rewritten to a local mock upstream (the development-only egress override)."""
    fixture = load_fixture("recording_proxy")
    mock = fixture.MockUpstream().start()
    proxy = fixture.RecordingProxy(upstream=mock.address).start()
    monkeypatch.setenv("ROXY_TEST_UPSTREAM_BASE", mock.base_url)
    monkeypatch.setenv("ROXY_TEST_ROTATOR_PROXY", proxy.url)
    try:
        async with running_app(env, credentials_dir, fake_secrets, None) as harness:
            await harness.settings(direct_enabled=0, rotator_enabled=1)
            yield harness, proxy, mock
    finally:
        proxy.stop()
        mock.stop()


async def test_end_to_end_recording_proxy(through_rotator: tuple[E2E, Any, Any]) -> None:
    """Plan 19.5 item 4 through the full app: caller traffic of every kind plus the health checks' credential
    probe and guard self-test, with the rotator pointed at a recording forward proxy. Not one recorded byte may
    contain the credential, a 24-character piece of it, or its cookie name."""
    e2e, proxy, mock = through_rotator
    fixture = load_fixture("recording_proxy")
    mock.routes["/v1/users/authenticated"] = fixture.MockResponse(body=b'{"id":1,"name":"owner"}')
    mock.routes["/v1/users/404404"] = fixture.MockResponse(status=404, body=b'{"errors":[]}')
    statuses = []
    for path in (games(1), games(1), games(2), "/users.roblox.com/v1/users/404404", "/groups.roblox.com/v1/groups/9"):
        statuses.append((await e2e.get(path)).status_code)
    batch = await e2e.request("POST", "/thumbnails.roblox.com/v1/batch", json=[{"targetId": 1}])
    statuses.append(batch.status_code)
    marker_body = json.dumps({"x": fixture.TOKEN_PREFIX}).encode()  # the public warning text, not the secret
    marker = await e2e.request("POST", "/thumbnails.roblox.com/v1/batch", content=marker_body)
    assert marker.status_code == 400  # refused at ingress: never reaches any egress (plan C2 item 5)
    assert statuses == [200, 200, 200, 404, 200, 200]

    # The health check's credential work: the probe (credential path, direct) and the guard self-test.
    probe = await e2e.ctx.egress.credential.probe("admin_check", fetch=e2e.ctx.upstream.credential_probe_fetch)
    assert probe.ok, probe
    self_test = await e2e.ctx.egress.self_test_leak_guard()
    assert getattr(self_test, "ok", getattr(self_test, "passed", True))

    # Last: a credential piece in a caller body is stopped by the rotator's guard before anything is sent.
    leak = await e2e.request("POST", "/thumbnails.roblox.com/v1/batch", json=[{"note": e2e.credential[-40:]}])
    assert leak.status_code == 503

    proxy.wait_settled()
    recorded = proxy.all_recorded()
    assert len(proxy.exchanges) >= 1
    assert b"games.roblox.com" in recorded  # the caller traffic really went through the rotator
    assert fixture.leak_findings(recorded, e2e.credential) == []
    # The credential went straight to the mock (the credential client, never the rotator), exactly once.
    cookie_requests = [r for r in mock.requests if (r.header("Cookie") or "").startswith(".ROBLOSECURITY=")]
    assert len(cookie_requests) == 1
    assert cookie_requests[0].path.startswith("/v1/users/authenticated")
