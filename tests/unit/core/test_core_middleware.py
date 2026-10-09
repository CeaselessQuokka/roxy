"""Middleware stack tests: request id on every response, size limits (plan 9.12), the unhandled error answer."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from fastapi import Request
from fastapi.responses import PlainTextResponse

from roxy.core.deadline import DeadlineMiddleware
from roxy.core.errors import ErrorEvent, UnhandledErrorMiddleware
from roxy.core.middleware import (
    BODY_TOO_LARGE_TEXT,
    HEADERS_TOO_LARGE_TEXT,
    URL_TOO_LONG_TEXT,
    ClientIPMiddleware,
    RequestIdMiddleware,
    SizeLimitMiddleware,
    TimingMiddleware,
    build_middleware,
)
from roxy.core.security_headers import SecurityHeadersMiddleware

CROCKFORD = set("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
LIMITS = {"max_body_bytes": 1024, "max_header_count": 30, "max_header_bytes": 512, "max_url_length": 256}


def limited_app(make_app: Any) -> Any:
    app = make_app(settings=LIMITS)

    @app.get("/ok")
    async def ok(request: Request) -> dict[str, Any]:
        return {"request_id": request.state.request_id}

    @app.post("/echo")
    async def echo(request: Request) -> PlainTextResponse:
        body = await request.body()
        return PlainTextResponse(f"{len(body)}")

    @app.post("/swallow")
    async def swallow(request: Request) -> PlainTextResponse:
        try:
            await request.body()
        except Exception:
            return PlainTextResponse("I handled it myself", status_code=200)
        return PlainTextResponse("fine")

    @app.get("/boom")
    async def boom() -> PlainTextResponse:
        raise RuntimeError("something broke")

    return app


def test_middleware_order_matches_plan_5_3() -> None:
    order = [m.cls for m in build_middleware(trusted_cidrs=(), hops=1)]
    assert order == [
        RequestIdMiddleware,
        UnhandledErrorMiddleware,
        ClientIPMiddleware,
        DeadlineMiddleware,
        SecurityHeadersMiddleware,
        SizeLimitMiddleware,
        TimingMiddleware,
    ]


async def test_request_id_on_every_response(make_app: Any, client_for: Any) -> None:
    app = limited_app(make_app)
    seen: set[str] = set()
    async with client_for(app) as client:
        responses = [
            await client.get("/ok"),
            await client.get("/missing"),  # 404 from the router
            await client.get("/boom"),  # 500 from the error middleware
            await client.post("/echo", content=b"x" * 2048),  # 413 from the size limits
            await client.get("/ok?" + "a" * 300),  # 414
        ]
    for response in responses:
        request_id = response.headers["roxy-request-id"]
        assert len(request_id) == 26
        assert set(request_id) <= CROCKFORD
        seen.add(request_id)
    assert len(seen) == len(responses)
    assert responses[0].json()["request_id"] == responses[0].headers["roxy-request-id"]


async def test_unhandled_exception_is_the_7_13_500(make_app: Any, client_for: Any) -> None:
    app = limited_app(make_app)
    events: list[ErrorEvent] = []
    app.state.error_hooks.add("server_error", events.append)
    async with client_for(app) as client:
        response = await client.get("/boom")
    assert response.status_code == 500
    assert response.content == b'"Internal Server Error"\n'  # v1's jsonify form (plan 7.13 "as v1")
    assert response.headers["content-type"].split(";")[0] == "application/json"
    assert response.headers["retry-after"] == "5"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "something broke" not in response.text  # never leak exception text to callers
    assert len(events) == 1
    assert isinstance(events[0].exc, RuntimeError)
    assert events[0].request_id == response.headers["roxy-request-id"]


async def test_broken_or_slow_hooks_never_break_the_answer(make_app: Any, client_for: Any) -> None:
    app = limited_app(make_app)
    seen: list[int] = []

    def broken(event: ErrorEvent) -> None:
        raise ValueError("hook bug")

    async def recorded(event: ErrorEvent) -> None:
        seen.append(event.status)

    app.state.error_hooks.add("server_error", broken)
    app.state.error_hooks.add("server_error", recorded)
    async with client_for(app) as client:
        response = await client.get("/boom")
    assert response.status_code == 500
    assert seen == [500]  # a failing hook does not stop the next one


async def test_client_errors_reach_the_probe_hook(make_app: Any, client_for: Any) -> None:
    app = limited_app(make_app)
    events: list[ErrorEvent] = []
    app.state.error_hooks.add("client_error", events.append)
    async with client_for(app) as client:
        not_found = await client.get("/wp-login.php", headers={"User-Agent": "scanner/1.0"})
        wrong_method = await client.delete("/ok")
    assert not_found.status_code == 404
    assert wrong_method.status_code == 405
    assert [(e.status, e.path) for e in events] == [(404, "/wp-login.php"), (405, "/ok")]
    assert events[0].user_agent == "scanner/1.0"
    assert events[0].detail == "HTTP 404 via GET /wp-login.php"
    assert events[0].client_ip == "127.0.0.1"


async def test_url_too_long_is_414(make_app: Any, client_for: Any) -> None:
    async with client_for(limited_app(make_app)) as client:
        at_limit = await client.get("/ok?" + "a" * (256 - len("/ok?")))
        over = await client.get("/ok?" + "a" * 300)
    assert at_limit.status_code == 200
    assert over.status_code == 414
    assert over.text == URL_TOO_LONG_TEXT
    assert over.headers["roxy-refusal"] == "url_too_long"


async def test_too_many_headers_is_431(make_app: Any, client_for: Any) -> None:
    async with client_for(limited_app(make_app)) as client:
        response = await client.get("/ok", headers={f"x-h{i}": "v" for i in range(40)})
    assert response.status_code == 431
    assert response.text == HEADERS_TOO_LARGE_TEXT
    assert response.headers["roxy-refusal"] == "headers_too_large"


async def test_one_oversized_header_is_431(make_app: Any, client_for: Any) -> None:
    async with client_for(limited_app(make_app)) as client:
        response = await client.get("/ok", headers={"x-big": "v" * 600})
    assert response.status_code == 431


async def test_declared_body_too_large_is_413(make_app: Any, client_for: Any) -> None:
    events: list[ErrorEvent] = []
    app = limited_app(make_app)
    app.state.error_hooks.add("client_error", events.append)
    async with client_for(app) as client:
        ok = await client.post("/echo", content=b"x" * 1024)
        too_big = await client.post("/echo", content=b"x" * 1025)
    assert ok.status_code == 200
    assert ok.text == "1024"
    assert too_big.status_code == 413
    assert too_big.text == BODY_TOO_LARGE_TEXT
    assert too_big.headers["roxy-refusal"] == "body_too_large"
    assert [e.status for e in events] == [413]  # logged as a probe (9.12)


async def chunks(total: int, size: int = 256) -> AsyncIterator[bytes]:
    sent = 0
    while sent < total:
        piece = min(size, total - sent)
        sent += piece
        yield b"y" * piece


async def test_streamed_body_too_large_is_413_without_buffering(make_app: Any, client_for: Any) -> None:
    async with client_for(limited_app(make_app)) as client:
        response = await client.post("/echo", content=chunks(4096))  # chunked: no Content-Length to check
        small = await client.post("/echo", content=chunks(512))
    assert response.status_code == 413
    assert response.text == BODY_TOO_LARGE_TEXT
    assert small.status_code == 200
    assert small.text == "512"


async def test_app_that_swallows_the_limit_still_answers_413(make_app: Any, client_for: Any) -> None:
    async with client_for(limited_app(make_app)) as client:
        response = await client.post("/swallow", content=chunks(4096))
    assert response.status_code == 413
    assert response.text == BODY_TOO_LARGE_TEXT


async def test_limits_fall_back_to_catalog_defaults(make_app: Any, client_for: Any) -> None:
    app = make_app()  # no live values: catalog defaults (2 MiB, 100 headers, 8 KiB, 4096)

    @app.post("/echo")
    async def echo(request: Request) -> PlainTextResponse:
        return PlainTextResponse(str(len(await request.body())))

    async with client_for(app) as client:
        fine = await client.post("/echo", content=b"z" * 200_000)
        too_big = await client.post("/echo", content=b"z" * (2 * 1024 * 1024 + 1))
        long_url = await client.post("/echo?" + "q" * 5000)
    assert fine.status_code == 200
    assert too_big.status_code == 413
    assert long_url.status_code == 414


async def test_timing_records_app_time(make_app: Any, client_for: Any) -> None:
    app = make_app()
    captured: dict[str, Any] = {}

    @app.get("/t")
    async def timed(request: Request) -> PlainTextResponse:
        captured["state"] = request.state
        return PlainTextResponse("t")

    async with client_for(app) as client:
        await client.get("/t")
    assert captured["state"].app_ms >= 0
    assert isinstance(captured["state"].received_ms, int)


async def test_kill_switch_token_is_masked_in_error_events(make_app: Any, client_for: Any) -> None:
    """Security review L5: a 4xx on `/admin/invalidate/<token>` must not hand the token to logs or hooks."""
    import secrets

    app = make_app()
    events: list[ErrorEvent] = []
    app.state.error_hooks.add("client_error", events.append)
    token = secrets.token_urlsafe(32)
    async with client_for(app) as client:
        response = await client.get(f"/admin/invalidate/{token}")
    assert response.status_code == 404
    assert len(events) == 1
    assert token not in events[0].path
    assert token not in events[0].detail
    assert events[0].path.startswith("/admin/invalidate/")


def test_error_events_scrub_a_bounded_prefix_of_the_path(monkeypatch: Any) -> None:
    """Review findings INGRESS-1 and public-4 (defense in depth): a 414 is answered before every rate limit, so an
    error event cuts the path and the detail to `MAX_EVENT_PATH_CHARS` BEFORE scrubbing them, whatever the caller
    sent; a secret near the start is still masked."""
    from roxy.core import errors

    seen: list[int] = []
    real = errors.redact_path

    def counting(text: str) -> str:
        seen.append(len(text))
        return real(text)

    monkeypatch.setattr(errors, "redact_path", counting)
    token = "A" * 43
    path = f"/admin/invalidate/{token}/" + "%0A" * 6000
    scope = {"type": "http", "method": "GET", "path": path, "headers": [], "state": {}}
    event = errors.event_from_scope(scope, 414, detail=path)
    assert seen
    assert max(seen) <= errors.MAX_EVENT_PATH_CHARS
    assert len(event.path) <= errors.MAX_EVENT_PATH_CHARS
    assert token not in event.path
    assert token not in event.detail
