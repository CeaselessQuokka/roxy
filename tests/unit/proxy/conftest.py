"""Fakes and helpers for the proxy unit tests: a fake abuse pipeline, cache, recorder and tarpit, and a small app.

What this is
    Stand-ins for `ctx.abuse`, `ctx.cache`, `ctx.upstream` and `ctx.recorder` shaped exactly like DESIGN.md 7, 8
    and 11 (`evaluate`, `peek`, `serve`, `fetch`, `record_outcome`, `tarpit.plan`), a `make_req` builder for
    `ProxyRequest`, and `proxy_app`: a Starlette app with the real middleware stack and the real proxy router.

Why it exists
    The real abuse, cache, upstream and metrics packages are built by other specialists at the same time, so the
    proxy is tested against the contract instead. Each fake records what it was given, so tests can check what
    the router handed to each stage, and how many outcome events were recorded (exactly one per request).

How it works
    Plain classes with async methods. `FakeSettings.get` raises KeyError for keys it does not override, so the
    router falls back to the catalog defaults exactly as it does with live settings.

What to read next
    `tests/unit/proxy/test_proxy_router.py`.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from starlette.applications import Starlette

from roxy.core.client_ip import parse_cidrs
from roxy.core.clock import FakeClock
from roxy.core.middleware import build_middleware
from roxy.core.reasons import AuthClass, CacheState, Egress, Outcome, ReasonCode, Source
from roxy.proxy import respond
from roxy.proxy.context import ProxyRequest
from roxy.proxy.router import router

TRIO = {"Roxy-Requests-Left": 9, "Roxy-Throttle-Reset": 49, "Roxy-Throttled": False}


class FakeSettings:
    """`ctx.settings` with a few overrides; anything else raises KeyError (the router then uses the catalog)."""

    def __init__(self, **overrides: Any) -> None:
        self.overrides = dict(overrides)

    def get(self, key: str) -> Any:
        if key in self.overrides:
            return self.overrides[key]
        raise KeyError(key)


@dataclass
class FakeAllow:
    headers: dict[str, Any] = field(default_factory=lambda: dict(TRIO))
    serve_throttled_from_cache: bool = False


class FakeAbuse:
    """Refuses target problems like the real pipeline does; otherwise returns `verdict` (Allow by default)."""

    def __init__(self, verdict: Any = None, *, tarpit: Any = None, refuse_targets: bool = True) -> None:
        self.verdict = verdict
        self.tarpit = tarpit
        self.refuse_targets = refuse_targets
        self.seen: list[ProxyRequest] = []

    async def evaluate(self, req: ProxyRequest) -> Any:
        self.seen.append(req)
        if self.refuse_targets and req.target_problem is not None:
            refusal = respond.target_refusal(req.target_problem)
            refusal.headers.update(TRIO)
            return refusal
        return self.verdict if self.verdict is not None else FakeAllow()


@dataclass
class FakePeek:
    key: Any = None
    fresh: Any = None
    stale: Any = None


def served(
    body: bytes = b'{"data":[]}',
    *,
    status: int = 200,
    reason: ReasonCode = ReasonCode.UPSTREAM_OK,
    cache_state: CacheState = CacheState.MISS,
    content_type: str | None = "application/json; charset=utf-8",
    outcome: Outcome = Outcome.SERVED_UPSTREAM,
    source: Source = Source.ROBLOX,
    **fields: Any,
) -> respond.ProxyResult:
    """A ServeResult-shaped served answer (Roblox's status and body)."""
    fields.setdefault("upstream_status", status)
    fields.setdefault("egress", Egress.DIRECT)
    fields.setdefault("upstream_calls", 1)
    return respond.ProxyResult(
        reason=reason,
        status=status,
        body=body,
        content_type=content_type,
        cache_state=cache_state,
        outcome=outcome,
        source=source,
        **fields,
    )


class FakeCache:
    """`peek` returns `peek_result`; `serve` returns `result` (or calls it with the request)."""

    def __init__(self, result: Any = None, *, peek_result: Any = None, peek_error: BaseException | None = None):
        self.result = result if result is not None else served()
        self.peek_result = peek_result if peek_result is not None else FakePeek(key="key-1")
        self.peek_error = peek_error
        self.peeked: list[ProxyRequest] = []
        self.served: list[ProxyRequest] = []

    async def peek(self, req: ProxyRequest) -> Any:
        self.peeked.append(req)
        if self.peek_error is not None:
            raise self.peek_error
        return self.peek_result

    async def serve(self, req: ProxyRequest, peek: Any) -> Any:
        self.served.append(req)
        if callable(self.result):
            return self.result(req)
        return self.result


@dataclass
class FakeUpstreamResult:
    """`upstream.service.UpstreamResult` fields (DESIGN 11.3)."""

    status: int = 200
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b'{"ok":true}'
    content_type: str | None = "application/json"
    egress: Egress = Egress.DIRECT
    auth_class: AuthClass = AuthClass.ANON
    upstream_status: int | None = 200
    reason: ReasonCode = ReasonCode.UPSTREAM_OK
    retry_after_s: int | None = None
    cooldown_s: int | None = None
    attempts: int = 1
    calls: int = 1
    bytes_in: int = 11
    bytes_out: int = 300
    queue_wait_ms: float = 1.0
    upstream_ms: float = 20.0
    trace: Any = None
    cacheable: bool = True
    negative_ttl_s: int | None = None


class FakeUpstream:
    def __init__(self, result: Any = None) -> None:
        self.result = result if result is not None else FakeUpstreamResult()
        self.calls: list[tuple[ProxyRequest, dict[str, Any]]] = []

    async def fetch(self, req: ProxyRequest, **kwargs: Any) -> Any:
        self.calls.append((req, kwargs))
        return self.result


class FakeRecorder:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def record_outcome(self, event: Any) -> None:
        self.events.append(event)


class FakePlan:
    """A tarpit plan: `wait()` for hold and jitter, `drip_chunks()` for drip, `release()` always."""

    def __init__(self, kind: str = "hold", *, ticks: int = 3, interval_s: float = 0.0) -> None:
        self.kind = kind
        self.ticks = ticks
        self.interval_s = interval_s
        self.waited = 0
        self.released = 0

    async def wait(self) -> None:
        self.waited += 1
        await asyncio.sleep(self.interval_s)

    async def drip_chunks(self) -> AsyncIterator[bytes]:
        for _ in range(self.ticks):
            await asyncio.sleep(self.interval_s)
            yield b" "

    def release(self) -> None:
        self.released += 1


class FakeTarpit:
    def __init__(self, plan: FakePlan | None) -> None:
        self.next_plan = plan
        self.asked: list[tuple[str, ProxyRequest]] = []
        self.reasons: list[str] = []

    async def plan(self, category: str, req: ProxyRequest, *, reason: str = "") -> FakePlan | None:
        self.asked.append((category, req))
        self.reasons.append(reason)
        return self.next_plan


def make_ctx(**overrides: Any) -> SimpleNamespace:
    """A fake AppContext with the fields the proxy reads."""
    settings = overrides.pop("settings", None) or FakeSettings()
    values: dict[str, Any] = {
        "settings": settings,
        "clock": FakeClock(),
        "abuse": FakeAbuse(),
        "cache": FakeCache(),
        "upstream": None,
        "recorder": FakeRecorder(),
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def make_req(**overrides: Any) -> ProxyRequest:
    """A valid `ProxyRequest` for `games.roblox.com/v1/games` with sensible defaults."""
    values: dict[str, Any] = {
        "request_id": "01TESTREQUESTID0000000000",
        "received_ms": 1_760_000_000_000,
        "deadline_at": 10**9,
        "client_ip": "203.0.113.7",
        "limit_key": "203.0.113.7",
        "method": "GET",
        "host": "games.roblox.com",
        "path": "/v1/games",
        "query": [("universeIds", "1")],
        "prettyprint": False,
        "body": b"",
        "content_type": None,
        "headers": {},
        "header_names_in_order": [],
        "user_agent": "Roblox/Linux",
        "place_id": None,
        "is_browser": False,
        "template": "games.roblox.com/v1/games",
        "target": "games.roblox.com/v1/games",
    }
    values.update(overrides)
    return ProxyRequest(**values)


@pytest.fixture
def ctx() -> SimpleNamespace:
    return make_ctx()


@pytest.fixture
def proxy_app(ctx: SimpleNamespace) -> Starlette:
    """The real middleware stack and the real proxy router, with the fake context."""
    app = Starlette(
        routes=list(router.routes),
        middleware=build_middleware(trusted_cidrs=parse_cidrs("127.0.0.1/32,::1/128"), hops=1),
    )
    app.state.ctx = ctx
    return app


@pytest.fixture
async def proxy_client(proxy_app: Starlette) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=proxy_app, client=("127.0.0.1", 50000))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


@pytest.fixture
def fakes() -> SimpleNamespace:
    """Every fake and builder above. A fixture, because `import conftest` is ambiguous with nested conftests."""
    return SimpleNamespace(
        TRIO=TRIO,
        FakeSettings=FakeSettings,
        FakeAllow=FakeAllow,
        FakeAbuse=FakeAbuse,
        FakePeek=FakePeek,
        FakeCache=FakeCache,
        FakeUpstreamResult=FakeUpstreamResult,
        FakeUpstream=FakeUpstream,
        FakeRecorder=FakeRecorder,
        FakePlan=FakePlan,
        FakeTarpit=FakeTarpit,
        served=served,
        make_ctx=make_ctx,
        make_req=make_req,
    )
