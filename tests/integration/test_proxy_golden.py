"""Golden tests: the exact status, body bytes and headers callers receive, through the real application.

What this is
    Every refusal of plan row 7 (v1 texts, with the C5 dash replacements) and every plan 7.13 row, with
    `compat_collapse_upstream_errors` off and on, sent through `create_app(env)`: the real middleware stack, the
    real router order (proxy catch-all last), the real proxy package. Plus the caller-visible features of rows 2,
    3, 4 and 10 (repeated parameters, prettyprint, the browser view, HEAD, OPTIONS, the header allowlists both
    ways) and the deadline row answered by the core middleware.

Why it exists
    Parity means byte for byte (plan 19.2). These tables are the contract a game script relies on: when a value
    here changes, a caller somewhere breaks, so a change must be deliberate and recorded in CHANGES.md.

How it works
    The application is built for real; `app.state.ctx` is a small context whose settings are the real catalog
    defaults plus per-test overrides, and whose abuse pipeline, cache and recorder are fakes that return the
    refusal or serve result under test (the real ones are built by other specialists against the same
    contracts). One test also runs the real lifespan to show the route in the fully wired app.
    Header tables list every `Roxy-*` and `Retry-After` header expected; any extra one fails the test.

What to read next
    `roxy/proxy/respond.py` (where these bytes come from) and plan 7.13.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from roxy.config import catalog
from roxy.core.clock import FakeClock
from roxy.core.reasons import CacheState, Egress, Outcome, ReasonCode, Source
from roxy.lifespan import CatalogDefaultsSettings
from roxy.main import create_app
from roxy.proxy import respond

GAMES = "/games.roblox.com/v1/games?universeIds=1"
TRIO = {"Roxy-Requests-Left": 9, "Roxy-Throttle-Reset": 49, "Roxy-Throttled": False}
TRIO_TEXT = {"Roxy-Requests-Left": "9", "Roxy-Throttle-Reset": "49", "Roxy-Throttled": "False"}
SANDBOX_CSP = "default-src 'none'; sandbox"


# --- fakes ----------------------------------------------------------------------------------------------------------


class OverlaySettings:
    """The real catalog defaults with per-test overrides (stands in for RuntimeSettings)."""

    def __init__(self, overrides: Mapping[str, Any] | None = None) -> None:
        self.base = CatalogDefaultsSettings(catalog.defaults())
        self.overrides = dict(overrides or {})

    def get(self, key: str) -> Any:
        return self.overrides[key] if key in self.overrides else self.base.get(key)

    def snapshot(self) -> Mapping[str, Any]:
        return {**self.base.snapshot(), **self.overrides}


@dataclass
class Allow:
    headers: dict[str, Any] = field(default_factory=lambda: dict(TRIO))
    serve_throttled_from_cache: bool = False


class Abuse:
    def __init__(self, verdict: Any = None) -> None:
        self.verdict = verdict
        self.tarpit = None
        self.seen: list[Any] = []

    async def evaluate(self, req: Any) -> Any:
        self.seen.append(req)
        if req.target_problem is not None and self.verdict is None:
            refusal = respond.target_refusal(req.target_problem)
            refusal.headers.update(TRIO)
            return refusal
        return self.verdict if self.verdict is not None else Allow()


@dataclass
class Peek:
    key: Any = "k"
    fresh: Any = None


class Cache:
    def __init__(self, result: Any = None) -> None:
        self.result = result
        self.served: list[Any] = []

    async def peek(self, req: Any) -> Peek:
        return Peek()

    async def serve(self, req: Any, peek: Any) -> Any:
        self.served.append(req)
        if isinstance(self.result, BaseException):
            raise self.result
        if callable(self.result):
            return await self.result(req)
        return self.result


class Recorder:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def record_outcome(self, event: Any) -> None:
        self.events.append(event)


def served(
    body: bytes,
    *,
    status: int = 200,
    reason: ReasonCode = ReasonCode.UPSTREAM_OK,
    cache_state: CacheState = CacheState.MISS,
    content_type: str | None = "application/json; charset=utf-8",
    outcome: Outcome = Outcome.SERVED_UPSTREAM,
    **fields: Any,
) -> respond.ProxyResult:
    fields.setdefault("upstream_status", status)
    return respond.ProxyResult(
        reason=reason,
        status=status,
        body=body,
        content_type=content_type,
        cache_state=cache_state,
        outcome=outcome,
        source=Source.CACHE if outcome is Outcome.SERVED_CACHE else Source.ROBLOX,
        egress=Egress.NONE if outcome is Outcome.SERVED_CACHE else Egress.DIRECT,
        **fields,
    )


def failure(reason: ReasonCode, **fields: Any) -> respond.ProxyResult:
    fields.setdefault("cache_state", CacheState.MISS)
    return respond.failure_result(reason, **fields)


@pytest.fixture
def golden(env: Any) -> SimpleNamespace:
    """The real app with a test context: settings overlay, fake abuse, cache and recorder."""
    app = create_app(env)
    ctx = SimpleNamespace(
        settings=OverlaySettings(),
        clock=FakeClock(),
        abuse=Abuse(),
        cache=Cache(served(b'{"data":[]}')),
        upstream=None,
        recorder=Recorder(),
    )
    app.state.ctx = ctx

    async def call(method: str, path: str, **kwargs: Any) -> httpx.Response:
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 50000))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.request(method, path, **kwargs)

    return SimpleNamespace(app=app, ctx=ctx, call=call)


def roxy_header_names(response: httpx.Response) -> set[str]:
    return {name for name in response.headers if name.startswith("roxy-") or name == "retry-after"}


def assert_common(response: httpx.Response) -> None:
    """Every proxy answer: request id, sandbox CSP, no-store, the 9.3 headers, no Server header."""
    assert len(response.headers["roxy-request-id"]) == 26
    assert response.headers["content-security-policy"] == SANDBOX_CSP
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "server" not in response.headers
    assert "reporting-endpoints" not in response.headers


def assert_headers(response: httpx.Response, expected: Mapping[str, str]) -> None:
    """Exactly these `Roxy-*` and `Retry-After` headers (plus the request id), with these values."""
    for name, value in expected.items():
        assert response.headers.get(name) == value, name
    assert roxy_header_names(response) == {name.lower() for name in expected} | {"roxy-request-id"}


# --- refusals (plan row 7) ------------------------------------------------------------------------------------------

LADDER_RUNG_1 = "Too many requests; please slow down."  # C5 replacement of the v1 rung 1 text
THROTTLE_HEADERS = {"Roxy-Requests-Left": 0, "Roxy-Throttle-Reset": 50, "Roxy-Throttled": True}


@dataclass(frozen=True)
class RefusalGolden:
    id: str
    refusal: respond.Refusal
    status: int
    body: bytes
    headers: dict[str, str]


REFUSALS = [
    RefusalGolden(
        "pause",
        respond.Refusal(
            503,
            "Service down for maintenance.",
            ReasonCode.PAUSED,
            headers={**TRIO, "Retry-After": 60, "Roxy-Paused": True},
        ),
        503,
        b'"Service down for maintenance."\n',
        {**TRIO_TEXT, "Retry-After": "60", "Roxy-Paused": "True", "Roxy-Refusal": "paused"},
    ),
    RefusalGolden(
        "pause_custom_reason_non_ascii",
        respond.Refusal(503, "Back soon: café upgrade", ReasonCode.PAUSED, headers={"Roxy-Paused": True}),
        503,
        b'"Back soon: caf\\u00e9 upgrade"\n',
        {"Roxy-Paused": "True", "Roxy-Refusal": "paused"},
    ),
    RefusalGolden(
        "throttle_all",
        respond.Refusal(
            429,
            "Service down for maintenance.",
            ReasonCode.THROTTLE_ALL,
            headers={**TRIO, "Roxy-Throttle-Reset": 37, "Roxy-Global-Throttled": True},
            tarpit_category="throttle_all",
        ),
        429,
        b'"Service down for maintenance."\n',
        {
            "Roxy-Requests-Left": "9",
            "Roxy-Throttle-Reset": "37",
            "Roxy-Throttled": "False",
            "Roxy-Global-Throttled": "True",
            "Roxy-Refusal": "throttle_all",
        },
    ),
    RefusalGolden(
        "per_ip_ladder_rung_1",
        respond.Refusal(429, LADDER_RUNG_1, ReasonCode.THROTTLE, headers={"Retry-After": 50, **THROTTLE_HEADERS}),
        429,
        b'"Too many requests; please slow down."\n',
        {
            "Retry-After": "50",
            "Roxy-Requests-Left": "0",
            "Roxy-Throttle-Reset": "50",
            "Roxy-Throttled": "True",
            "Roxy-Refusal": "throttle",
        },
    ),
    RefusalGolden(
        "per_ip_fallback_text",
        respond.Refusal(
            429,
            "You have been throttled; try again in 50 seconds (you get ~10 requests per ~minute).",
            ReasonCode.THROTTLE,
            headers={"Retry-After": 50, **THROTTLE_HEADERS},
        ),
        429,
        b'"You have been throttled; try again in 50 seconds (you get ~10 requests per ~minute)."\n',
        {
            "Retry-After": "50",
            "Roxy-Requests-Left": "0",
            "Roxy-Throttle-Reset": "50",
            "Roxy-Throttled": "True",
            "Roxy-Refusal": "throttle",
        },
    ),
    RefusalGolden(
        "user_agent_burst",
        respond.Refusal(
            429,
            "This client is limited to 10 requests per 60s. Try again in 12 seconds.",
            ReasonCode.USER_AGENT_RULE,
            headers={
                **TRIO,
                "Retry-After": 12,
                "Roxy-Throttle-Reset": 12,
                "Roxy-Throttled": True,
                "Roxy-Client-Limited": True,
            },
        ),
        429,
        b'"This client is limited to 10 requests per 60s. Try again in 12 seconds."\n',
        {
            "Retry-After": "12",
            "Roxy-Requests-Left": "9",
            "Roxy-Throttle-Reset": "12",
            "Roxy-Throttled": "True",
            "Roxy-Client-Limited": "True",
            "Roxy-Refusal": "user_agent_rule",
        },
    ),
    RefusalGolden(
        "user_agent_cooldown",
        respond.Refusal(
            429,
            "This client is limited to one request every 30.0s. Try again in 29 seconds.",
            ReasonCode.USER_AGENT_RULE,
            headers={"Retry-After": 29, "Roxy-Throttle-Reset": 29, "Roxy-Throttled": True, "Roxy-Client-Limited": True},
        ),
        429,
        b'"This client is limited to one request every 30.0s. Try again in 29 seconds."\n',
        {
            "Retry-After": "29",
            "Roxy-Throttle-Reset": "29",
            "Roxy-Throttled": "True",
            "Roxy-Client-Limited": "True",
            "Roxy-Refusal": "user_agent_rule",
        },
    ),
    RefusalGolden(
        "ignored_path",
        respond.Refusal(404, "Not Found", ReasonCode.IGNORED_PATH, headers=dict(TRIO)),
        404,
        b'"Not Found"\n',
        {**TRIO_TEXT, "Roxy-Refusal": "ignored_path"},
    ),
    RefusalGolden(
        "invalid_url",
        respond.Refusal(404, "Invalid URL", ReasonCode.UNSAFE_URL, headers=dict(TRIO), tarpit_category="probe"),
        404,
        b'"Invalid URL"\n',
        {**TRIO_TEXT, "Roxy-Refusal": "unsafe_url"},
    ),
    RefusalGolden(
        "not_roblox",
        respond.Refusal(404, "Not a Roblox URL", ReasonCode.NOT_ROBLOX, headers=dict(TRIO), tarpit_category="probe"),
        404,
        b'"Not a Roblox URL"\n',
        {**TRIO_TEXT, "Roxy-Refusal": "not_roblox"},
    ),
    RefusalGolden(
        "host_not_allowed",
        respond.Refusal(404, "Not a Roblox URL", ReasonCode.HOST_NOT_ALLOWED, headers=dict(TRIO)),
        404,
        b'"Not a Roblox URL"\n',
        {**TRIO_TEXT, "Roxy-Refusal": "host_not_allowed"},
    ),
    RefusalGolden(
        "auth_smuggling",
        respond.Refusal(
            400,
            "Requests requiring authentication are not allowed with this proxy.",
            ReasonCode.AUTH_SMUGGLING,
            headers=dict(TRIO),
            tarpit_category="auth_attempt",
        ),
        400,
        b'"Requests requiring authentication are not allowed with this proxy."\n',
        {**TRIO_TEXT, "Roxy-Refusal": "auth_smuggling"},
    ),
    RefusalGolden(
        "header_filter_disguised",
        # The abuse layer's disguise: exactly the headers of a genuine throttle refusal (abuse/checks/base.py).
        respond.Refusal(
            429,
            LADDER_RUNG_1,
            ReasonCode.HEADER_RULE,
            headers={
                "Retry-After": "50",
                "Roxy-Requests-Left": "0",
                "Roxy-Throttle-Reset": "50",
                "Roxy-Throttled": "True",
                "Roxy-Refusal": "throttle",
            },
            disguised=True,
            tarpit_category="header_rule",
        ),
        429,
        b'"Too many requests; please slow down."\n',
        {
            "Retry-After": "50",
            "Roxy-Requests-Left": "0",
            "Roxy-Throttle-Reset": "50",
            "Roxy-Throttled": "True",
            "Roxy-Refusal": "throttle",
        },
    ),
    RefusalGolden(
        "header_filter_custom_message",
        respond.Refusal(
            429,
            "Automated scanners are not welcome here.",
            ReasonCode.HEADER_RULE,
            headers={"Roxy-Requests-Left": 9, "Roxy-Throttle-Reset": 50, "Roxy-Throttled": True},
            message_source="custom",
        ),
        429,
        b'"Automated scanners are not welcome here."\n',
        {
            "Roxy-Requests-Left": "9",
            "Roxy-Throttle-Reset": "50",
            "Roxy-Throttled": "True",
            "Roxy-Refusal": "header_rule",
        },
    ),
    RefusalGolden(
        "endpoint_block_default",
        respond.Refusal(
            403,
            "This endpoint is currently blocked.",
            ReasonCode.ENDPOINT_BLOCKED,
            headers={**TRIO, "Roxy-Blocked": True},
        ),
        403,
        b'"This endpoint is currently blocked."\n',
        {**TRIO_TEXT, "Roxy-Blocked": "True", "Roxy-Refusal": "endpoint_blocked"},
    ),
    RefusalGolden(
        "endpoint_block_custom",
        respond.Refusal(
            403, "Use the v2 endpoint instead.", ReasonCode.ENDPOINT_BLOCKED, headers={"Roxy-Blocked": True}
        ),
        403,
        b'"Use the v2 endpoint instead."\n',
        {"Roxy-Blocked": "True", "Roxy-Refusal": "endpoint_blocked"},
    ),
    RefusalGolden(
        "endpoint_rule",
        respond.Refusal(
            429,
            "This endpoint is rate-limited for you; try again in 7 seconds.",
            ReasonCode.ENDPOINT_RULE,
            headers={
                "Roxy-Requests-Left": 4,
                "Roxy-Throttle-Reset": 7,
                "Roxy-Throttled": True,
                "Roxy-Endpoint-Limited": True,
            },
        ),
        429,
        b'"This endpoint is rate-limited for you; try again in 7 seconds."\n',
        {
            "Roxy-Requests-Left": "4",
            "Roxy-Throttle-Reset": "7",
            "Roxy-Throttled": "True",
            "Roxy-Endpoint-Limited": "True",
            "Roxy-Refusal": "endpoint_rule",
        },
    ),
    RefusalGolden(
        "ban_plain",
        respond.Refusal(403, "Access denied.", ReasonCode.BANNED),
        403,
        b'"Access denied."\n',
        {"Roxy-Refusal": "banned"},
    ),
]


@pytest.mark.parametrize("golden_row", REFUSALS, ids=lambda row: row.id)
async def test_refusal_golden(golden: SimpleNamespace, golden_row: RefusalGolden) -> None:
    golden.ctx.abuse = Abuse(golden_row.refusal)
    response = await golden.call("GET", GAMES, headers={"User-Agent": "Mozilla/5.0 Chrome/141"})
    assert response.status_code == golden_row.status
    assert response.content == golden_row.body  # JSON string plus newline, never HTML, even for a browser
    assert response.headers["content-type"] == "application/json"
    assert int(response.headers["content-length"]) == len(golden_row.body)
    assert_headers(response, golden_row.headers)
    assert_common(response)
    assert golden.ctx.cache.served == []
    [event] = golden.ctx.recorder.events
    assert event.outcome is Outcome.REFUSED
    assert event.reason is golden_row.refusal.reason
    assert event.status == golden_row.status


async def test_refusal_header_names_keep_v1_casing(golden: SimpleNamespace) -> None:
    golden.ctx.abuse = Abuse(REFUSALS[3].refusal)
    response = await golden.call("GET", GAMES)
    names = {name for name, _ in response.headers.raw}
    assert {b"Retry-After", b"Roxy-Requests-Left", b"Roxy-Throttle-Reset", b"Roxy-Throttled", b"Roxy-Refusal"} <= names


# --- plan 7.13 rows, compat off and on ------------------------------------------------------------------------------

BUSY = respond.UPSTREAM_BUSY_TEXT.encode()
FAILED = respond.UPSTREAM_FAILED_TEXT.encode()
JSON = "application/json"
TEXT = "text/plain; charset=utf-8"
NOT_FOUND_BODY = b'{"errors":[{"code":0,"message":"NotFound"}]}'


@dataclass(frozen=True)
class Expect:
    status: int
    body: bytes
    content_type: str | None
    headers: dict[str, str]


@dataclass(frozen=True)
class RowGolden:
    id: str
    result: respond.ProxyResult
    compat_off: Expect
    compat_on: Expect


def _same(expect: Expect) -> tuple[Expect, Expect]:
    return expect, expect


ROWS: list[RowGolden] = [
    RowGolden(
        "roblox_200",
        served(b'{"data":[{"id":1}]}'),
        *_same(
            Expect(
                200, b'{"data":[{"id":1}]}', JSON, {**TRIO_TEXT, "Roxy-Cache": "MISS", "Roxy-Upstream-Status": "200"}
            )
        ),
    ),
    RowGolden(
        "roblox_204",
        served(b"", status=204),
        *_same(Expect(204, b"", None, {**TRIO_TEXT, "Roxy-Cache": "MISS", "Roxy-Upstream-Status": "204"})),
    ),
    RowGolden(
        "roblox_404_live",
        served(NOT_FOUND_BODY, status=404, reason=ReasonCode.UPSTREAM_4XX),
        Expect(404, NOT_FOUND_BODY, JSON, {**TRIO_TEXT, "Roxy-Cache": "MISS", "Roxy-Upstream-Status": "404"}),
        Expect(500, FAILED, TEXT, {**TRIO_TEXT, "Roxy-Cache": "MISS", "Roxy-Upstream-Status": "404"}),
    ),
    RowGolden(
        "roblox_400_live",
        served(b'{"errors":[{"code":1}]}', status=400, reason=ReasonCode.UPSTREAM_4XX),
        Expect(
            400, b'{"errors":[{"code":1}]}', JSON, {**TRIO_TEXT, "Roxy-Cache": "MISS", "Roxy-Upstream-Status": "400"}
        ),
        Expect(500, FAILED, TEXT, {**TRIO_TEXT, "Roxy-Cache": "MISS", "Roxy-Upstream-Status": "400"}),
    ),
    RowGolden(
        "roblox_404_cached",
        served(
            NOT_FOUND_BODY,
            status=404,
            reason=ReasonCode.CACHE_NEGATIVE,
            cache_state=CacheState.HIT,
            outcome=Outcome.SERVED_CACHE,
            cache_age_s=3.9,
            cache_ttl_s=60,
        ),
        Expect(
            404,
            NOT_FOUND_BODY,
            JSON,
            {
                **TRIO_TEXT,
                "Roxy-Cache": "HIT",
                "Roxy-Cache-Age": "3",
                "Roxy-Cache-TTL": "60",
                "Roxy-Upstream-Status": "404",
            },
        ),
        Expect(
            500,
            FAILED,
            TEXT,
            {
                **TRIO_TEXT,
                "Roxy-Cache": "HIT",
                "Roxy-Cache-Age": "3",
                "Roxy-Cache-TTL": "60",
                "Roxy-Upstream-Status": "404",
            },
        ),
    ),
    RowGolden(
        "cache_hit",
        served(
            b'{"data":[]}',
            reason=ReasonCode.CACHE_HIT,
            cache_state=CacheState.HIT,
            outcome=Outcome.SERVED_CACHE,
            cache_age_s=12,
            cache_ttl_s=60,
        ),
        *_same(
            Expect(
                200,
                b'{"data":[]}',
                JSON,
                {
                    **TRIO_TEXT,
                    "Roxy-Cache": "HIT",
                    "Roxy-Cache-Age": "12",
                    "Roxy-Cache-TTL": "60",
                    "Roxy-Upstream-Status": "200",
                },
            )
        ),
    ),
    RowGolden(
        "cache_revalidating",
        served(
            b'{"data":[]}',
            reason=ReasonCode.CACHE_REVALIDATING,
            cache_state=CacheState.REVALIDATING,
            outcome=Outcome.SERVED_CACHE,
            cache_age_s=75,
            cache_ttl_s=60,
        ),
        *_same(
            Expect(
                200,
                b'{"data":[]}',
                JSON,
                {
                    **TRIO_TEXT,
                    "Roxy-Cache": "REVALIDATING",
                    "Roxy-Cache-Age": "75",
                    "Roxy-Cache-TTL": "60",
                    "Roxy-Upstream-Status": "200",
                },
            )
        ),
    ),
    RowGolden(
        "cache_coalesced",
        served(
            b'{"data":[]}',
            reason=ReasonCode.CACHE_COALESCED,
            cache_state=CacheState.COALESCED,
            outcome=Outcome.SERVED_CACHE,
            cache_age_s=0,
            cache_ttl_s=60,
        ),
        *_same(
            Expect(
                200,
                b'{"data":[]}',
                JSON,
                {
                    **TRIO_TEXT,
                    "Roxy-Cache": "COALESCED",
                    "Roxy-Cache-Age": "0",
                    "Roxy-Cache-TTL": "60",
                    "Roxy-Upstream-Status": "200",
                },
            )
        ),
    ),
    RowGolden(
        "roblox_429_stale_available",
        served(
            b'{"data":["old"]}',
            reason=ReasonCode.CACHE_STALE_COOLDOWN,
            cache_state=CacheState.STALE,
            outcome=Outcome.SERVED_CACHE,
            cache_age_s=700,
            cache_ttl_s=60,
            cooldown_s=29.2,
            upstream_status=429,
        ),
        *_same(
            Expect(
                200,
                b'{"data":["old"]}',
                JSON,
                {
                    **TRIO_TEXT,
                    "Roxy-Cache": "STALE",
                    "Roxy-Cache-Age": "700",
                    "Roxy-Cache-TTL": "60",
                    "Roxy-Upstream-Cooldown": "30",
                    "Roxy-Upstream-Status": "429",
                },
            )
        ),
    ),
    RowGolden(
        "stale_after_error",
        served(
            b'{"data":["old"]}',
            reason=ReasonCode.CACHE_STALE_ERROR,
            cache_state=CacheState.STALE,
            outcome=Outcome.SERVED_CACHE,
            cache_age_s=90,
            cache_ttl_s=60,
            upstream_status=503,
            stale_after_failure=True,
        ),
        *_same(
            Expect(
                200,
                b'{"data":["old"]}',
                JSON,
                {
                    **TRIO_TEXT,
                    "Roxy-Cache": "STALE",
                    "Roxy-Cache-Age": "90",
                    "Roxy-Cache-TTL": "60",
                    "Roxy-Upstream-Status": "503",
                },
            )
        ),
    ),
    RowGolden(
        "cooldown_no_stale",
        failure(ReasonCode.UPSTREAM_COOLDOWN, status=429, cooldown_s=27.2, upstream_status=429),
        *_same(
            Expect(
                429,
                BUSY,
                TEXT,
                {
                    **TRIO_TEXT,
                    "Retry-After": "28",
                    "Roxy-Cache": "MISS",
                    "Roxy-Upstream-Cooldown": "28",
                    "Roxy-Upstream-Status": "429",
                    "Roxy-Refusal": "upstream_cooldown",
                },
            )
        ),
    ),
    RowGolden(
        "upstream_busy",
        failure(ReasonCode.UPSTREAM_BUSY, status=429, retry_after_s=3),
        *_same(
            Expect(
                429,
                BUSY,
                TEXT,
                {**TRIO_TEXT, "Retry-After": "3", "Roxy-Cache": "MISS", "Roxy-Refusal": "upstream_busy"},
            )
        ),
    ),
    RowGolden(
        "queue_overflow",
        failure(ReasonCode.QUEUE_OVERFLOW, status=429, retry_after_s=0.2),
        *_same(
            Expect(
                429,
                BUSY,
                TEXT,
                {**TRIO_TEXT, "Retry-After": "1", "Roxy-Cache": "MISS", "Roxy-Refusal": "queue_overflow"},
            )
        ),
    ),
    RowGolden(
        "roblox_5xx_with_retry_after",
        failure(ReasonCode.UPSTREAM_5XX, status=503, upstream_status=503, retry_after_s=20),
        Expect(
            503, FAILED, TEXT, {**TRIO_TEXT, "Retry-After": "20", "Roxy-Cache": "MISS", "Roxy-Upstream-Status": "503"}
        ),
        Expect(
            500, FAILED, TEXT, {**TRIO_TEXT, "Retry-After": "20", "Roxy-Cache": "MISS", "Roxy-Upstream-Status": "503"}
        ),
    ),
    RowGolden(
        "roblox_5xx_default_retry",
        failure(ReasonCode.UPSTREAM_5XX, status=502, upstream_status=502),
        Expect(
            502, FAILED, TEXT, {**TRIO_TEXT, "Retry-After": "5", "Roxy-Cache": "MISS", "Roxy-Upstream-Status": "502"}
        ),
        Expect(
            500, FAILED, TEXT, {**TRIO_TEXT, "Retry-After": "5", "Roxy-Cache": "MISS", "Roxy-Upstream-Status": "502"}
        ),
    ),
    RowGolden(
        "upstream_timeout",
        failure(ReasonCode.UPSTREAM_TIMEOUT, status=504),
        Expect(
            504,
            FAILED,
            TEXT,
            {**TRIO_TEXT, "Retry-After": "5", "Roxy-Cache": "MISS", "Roxy-Refusal": "upstream_timeout"},
        ),
        Expect(
            500,
            FAILED,
            TEXT,
            {**TRIO_TEXT, "Retry-After": "5", "Roxy-Cache": "MISS", "Roxy-Refusal": "upstream_timeout"},
        ),
    ),
    RowGolden(
        "upstream_connect",
        failure(ReasonCode.UPSTREAM_CONNECT, status=502),
        Expect(
            502,
            FAILED,
            TEXT,
            {**TRIO_TEXT, "Retry-After": "5", "Roxy-Cache": "MISS", "Roxy-Refusal": "upstream_connect"},
        ),
        Expect(
            500,
            FAILED,
            TEXT,
            {**TRIO_TEXT, "Retry-After": "5", "Roxy-Cache": "MISS", "Roxy-Refusal": "upstream_connect"},
        ),
    ),
    RowGolden(
        "deadline",
        failure(ReasonCode.DEADLINE, status=504),
        Expect(504, FAILED, TEXT, {**TRIO_TEXT, "Retry-After": "5", "Roxy-Cache": "MISS", "Roxy-Refusal": "deadline"}),
        Expect(500, FAILED, TEXT, {**TRIO_TEXT, "Retry-After": "5", "Roxy-Cache": "MISS", "Roxy-Refusal": "deadline"}),
    ),
    RowGolden(
        "coalesce_timeout",
        failure(ReasonCode.COALESCE_TIMEOUT, status=503, retry_after_s=12.3),
        *_same(
            Expect(
                503,
                BUSY,
                TEXT,
                {**TRIO_TEXT, "Retry-After": "13", "Roxy-Cache": "MISS", "Roxy-Refusal": "coalesce_timeout"},
            )
        ),
    ),
    RowGolden(
        "egress_disabled",
        failure(ReasonCode.EGRESS_DISABLED, status=503),
        *_same(
            Expect(
                503,
                BUSY,
                TEXT,
                {**TRIO_TEXT, "Retry-After": "60", "Roxy-Cache": "MISS", "Roxy-Refusal": "egress_disabled"},
            )
        ),
    ),
    RowGolden(
        "credential_rejected",
        failure(ReasonCode.CREDENTIAL_UNAVAILABLE, status=503),
        *_same(
            Expect(
                503,
                BUSY,
                TEXT,
                {**TRIO_TEXT, "Retry-After": "300", "Roxy-Cache": "MISS", "Roxy-Refusal": "credential_unavailable"},
            )
        ),
    ),
    RowGolden(
        "credential_cooling_down",
        failure(ReasonCode.CREDENTIAL_UNAVAILABLE, status=503, cooldown_s=45),
        *_same(
            Expect(
                503,
                BUSY,
                TEXT,
                {**TRIO_TEXT, "Retry-After": "45", "Roxy-Cache": "MISS", "Roxy-Refusal": "credential_unavailable"},
            )
        ),
    ),
    RowGolden(
        "degraded",
        failure(ReasonCode.DEGRADED, status=503, cache_state=CacheState.NA),
        *_same(Expect(503, BUSY, TEXT, {**TRIO_TEXT, "Retry-After": "10", "Roxy-Refusal": "degraded"})),
    ),
    RowGolden(
        "internal_error",
        failure(ReasonCode.INTERNAL_ERROR, status=500, cache_state=CacheState.NA),
        *_same(Expect(500, b"Internal Server Error", TEXT, {**TRIO_TEXT, "Retry-After": "5"})),
    ),
]


@pytest.mark.parametrize("compat", [0, 1], ids=["compat_off", "compat_on"])
@pytest.mark.parametrize("row", ROWS, ids=lambda row: row.id)
async def test_7_13_row_golden(golden: SimpleNamespace, row: RowGolden, compat: int) -> None:
    golden.ctx.settings.overrides["compat_collapse_upstream_errors"] = compat
    golden.ctx.cache = Cache(row.result)
    expect = row.compat_on if compat else row.compat_off
    response = await golden.call("GET", GAMES)
    assert response.status_code == expect.status
    assert response.content == expect.body
    assert response.headers.get("content-type") == expect.content_type
    assert_headers(response, expect.headers)
    assert_common(response)
    [event] = golden.ctx.recorder.events
    assert event.status == expect.status
    assert event.reason is row.result.reason


async def test_paused_row_is_a_refusal_unaffected_by_compat(golden: SimpleNamespace) -> None:
    """Plan 7.13: Roxy's own refusals are unaffected by compat mode."""
    golden.ctx.settings.overrides["compat_collapse_upstream_errors"] = 1
    golden.ctx.abuse = Abuse(REFUSALS[0].refusal)
    response = await golden.call("GET", GAMES)
    assert response.status_code == 503
    assert response.content == b'"Service down for maintenance."\n'


async def test_deadline_row_from_the_core_middleware_matches(golden: SimpleNamespace) -> None:
    """The deadline 504 written by `core/deadline.py` carries the same bytes as the 7.13 `deadline` row."""

    async def slow(req: Any) -> Any:
        await asyncio.sleep(5)

    golden.ctx.settings.overrides["request_deadline_s"] = 0.1
    golden.ctx.cache = Cache(slow)
    response = await golden.call("GET", GAMES)
    assert response.status_code == 504
    assert response.content == FAILED
    assert response.headers["content-type"] == TEXT
    assert response.headers["Retry-After"] == "5"
    assert response.headers["Roxy-Refusal"] == "deadline"
    # The canceled flow records the fallback outcome itself, exactly once (DESIGN 7; wave 2 wiring).
    assert len(golden.ctx.recorder.events) == 1
    event = golden.ctx.recorder.events[0]
    assert (event.status, event.reason, event.outcome) == (504, ReasonCode.DEADLINE, Outcome.FAILED)
    assert event.endpoint_template == "games.roblox.com/v1/games"


# --- caller-visible features (rows 2, 3, 4, 10, 1) ------------------------------------------------------------------


async def test_repeated_params_and_prettyprint(golden: SimpleNamespace) -> None:
    golden.ctx.cache = Cache(served(b'{"data":[{"id":1,"name":"caf\xc3\xa9"}]}'))
    response = await golden.call("GET", "/games.roblox.com/v1/games/votes?universeIds=1&universeIds=2&prettyprint=true")
    req = golden.ctx.cache.served[0]
    assert req.query == [("universeIds", "1"), ("universeIds", "2")]  # prettyprint stripped, repeats kept
    assert req.upstream_url == "https://games.roblox.com/v1/games/votes?universeIds=1&universeIds=2"
    assert response.status_code == 200
    assert response.content == (
        b'{\n    "data": [\n        {\n            "id": 1,\n            "name": "caf\\u00e9"\n        }\n    ]\n}'
    )
    assert response.headers["content-type"] == "application/json"


async def test_browser_gets_escaped_html_with_sandbox_csp(golden: SimpleNamespace) -> None:
    golden.ctx.cache = Cache(served(b'{"name":"<script>alert(1)</script> & \'q\'"}'))
    response = await golden.call("GET", GAMES, headers={"User-Agent": "Mozilla/5.0 (X11) Gecko/20100101 Firefox/130.0"})
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/html; charset=utf-8"
    assert response.content == (
        b"<pre>{&#34;name&#34;:&#34;&lt;script&gt;alert(1)&lt;/script&gt; &amp; &#39;q&#39;&#34;}</pre>"
    )
    assert response.headers["content-security-policy"] == SANDBOX_CSP


async def test_non_json_upstream_type_replayed(golden: SimpleNamespace) -> None:
    golden.ctx.cache = Cache(served(b"\x89PNG\r\n\x1a\n", content_type="image/png"))
    response = await golden.call("GET", "/thumbnails.roblox.com/v1/x.png")
    assert response.headers["content-type"] == "image/png"
    assert response.content == b"\x89PNG\r\n\x1a\n"


async def test_head_and_options(golden: SimpleNamespace) -> None:
    golden.ctx.cache = Cache(served(b'{"data":[]}'))
    head = await golden.call("HEAD", GAMES)
    assert head.status_code == 200
    assert head.content == b""
    assert head.headers["content-length"] == "11"
    assert head.headers["Roxy-Cache"] == "MISS"
    assert golden.ctx.cache.served[0].method == "GET"
    options = await golden.call("OPTIONS", "/anything/at/all")
    assert options.status_code == 204
    assert options.content == b""
    assert options.headers["allow"] == "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"
    assert roxy_header_names(options) == {"roxy-request-id"}
    assert [event.method for event in golden.ctx.recorder.events] == ["HEAD", "OPTIONS"]


async def test_header_allowlist_both_ways(golden: SimpleNamespace) -> None:
    golden.ctx.cache = Cache(
        served(
            b"{}",
            upstream_headers={
                "Set-Cookie": ".ROBLOSECURITY=abc; domain=.roblox.com",
                "x-csrf-token": "tok",
                "Cache-Control": "public, max-age=600",
                "Retry-After": "3",
                "x-ratelimit-remaining": "0",
                "roblox-machine-id": "WEB1",
            },
        )
    )
    response = await golden.call(
        "POST",
        "/users.roblox.com/v1/usernames/users",
        content=b'{"usernames":["a"]}',
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Accept-Language": "de-DE",
            "Authorization": "Bearer x",
            "X-Csrf-Token": "abc",
            "X-Api-Key": "k",
            "Origin": "https://evil.example",
            "Roblox-Place-Id": "1",
        },
    )
    req = golden.ctx.cache.served[0]
    assert req.forwarded_headers() == {
        "accept": "application/json",
        "content-type": "application/json",
        "content-length": "19",
    }
    assert "set-cookie" not in response.headers
    assert "x-csrf-token" not in response.headers
    assert "roblox-machine-id" not in response.headers
    assert response.headers["cache-control"] == "no-store"  # Roxy's own, never upstream's
    assert response.headers["retry-after"] == "3"
    assert response.headers["x-ratelimit-remaining"] == "0"


async def test_proxy_route_in_the_fully_wired_app(app: Any, client: httpx.AsyncClient) -> None:
    """The real lifespan and AppContext: the route is the catch-all, and it fails closed until abuse exists."""
    ctx = app.state.ctx
    real_abuse, real_cache, real_recorder = ctx.abuse, ctx.cache, ctx.recorder
    if real_abuse is None:
        degraded = await client.get(GAMES)
        assert degraded.status_code == 503
        assert degraded.headers["Roxy-Refusal"] == "degraded"
    refused = await client.get("/evil.example/x")
    assert refused.status_code == 404
    assert refused.headers["Roxy-Refusal"] in {"not_roblox", "ignored_path"}
    assert (await client.options(GAMES)).status_code == 204
    ctx.abuse, ctx.cache, ctx.recorder = Abuse(), Cache(served(b'{"data":[7]}')), Recorder()
    try:
        response = await client.get(GAMES)
        assert response.status_code == 200
        assert response.content == b'{"data":[7]}'
        assert len(ctx.recorder.events) == 1
        home = await client.get("/")
        assert home.status_code == 200  # the proxy catch-all never shadows a real page
        assert "roxy-cache" not in home.headers
    finally:
        ctx.abuse, ctx.cache, ctx.recorder = real_abuse, real_cache, real_recorder


# --- with the real abuse pipeline (abuse/pipeline.py) -----------------------------------------------------------------


async def test_real_abuse_pipeline_through_the_route(golden: SimpleNamespace, dbs: Any, fake_clock: FakeClock) -> None:
    """The proxy renders the real pipeline's verdicts: one Roxy-Refusal, the v1 wire form, real throttle headers."""
    from roxy.abuse.pipeline import AbusePipeline
    from roxy.config.defaults import seed_defaults
    from roxy.rules.store import build_rules_snapshot

    dbs.control.write_sync(lambda conn: seed_defaults(conn, int(fake_clock.now())))
    rules = dbs.control.read_sync(lambda conn: build_rules_snapshot(conn, fake_clock.now()))
    sleeps: list[float] = []

    async def record_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    golden.ctx.clock = fake_clock
    golden.ctx.settings.overrides["allowed_requests_per_minute"] = 3
    golden.ctx.abuse = AbusePipeline(
        settings=golden.ctx.settings,
        rules=rules,
        hot_db=dbs.hot,
        control_db=dbs.control,
        clock=fake_clock,
        worker_id="golden-worker",
        tarpit_sleep=record_sleep,
        monotonic=fake_clock.monotonic,
    )

    served_ok = await golden.call("GET", GAMES)
    assert served_ok.status_code == 200
    assert served_ok.headers["Roxy-Throttled"] == "False"
    assert served_ok.headers["Roxy-Requests-Left"].isdigit()

    probe = await golden.call("GET", "/evil.example/wp-login.php")
    assert probe.status_code == 404
    assert probe.content == b'"Not a Roblox URL"\n'
    assert probe.headers.get_list("Roxy-Refusal") == ["not_roblox"]

    ignored = await golden.call("POST", "/favicon.ico")
    assert ignored.status_code == 404
    assert ignored.content == b'"Not Found"\n'
    assert ignored.headers.get_list("Roxy-Refusal") == ["ignored_path"]

    smuggled = await golden.call("GET", GAMES, headers={"X-Roblox-Token": "anything"})
    assert smuggled.status_code == 400
    assert smuggled.content == b'"Requests requiring authentication are not allowed with this proxy."\n'

    statuses = [(await golden.call("GET", GAMES)).status_code for _ in range(4)]
    assert 429 in statuses
    throttled = await golden.call("GET", GAMES)
    assert throttled.status_code == 429
    assert throttled.headers["content-type"] == "application/json"
    assert throttled.content.endswith(b'"\n')
    assert isinstance(json.loads(throttled.content), str)
    assert int(throttled.headers["Retry-After"]) >= 1
    assert throttled.headers["Roxy-Throttled"] == "True"
    assert len(throttled.headers.get_list("Roxy-Refusal")) == 1
    assert len(golden.ctx.recorder.events) == 9  # exactly one record per request
