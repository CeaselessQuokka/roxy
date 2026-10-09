"""Request deadline tests (plan 5.2 and the 7.13 "deadline" row)."""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import Request
from fastapi.responses import PlainTextResponse

from roxy.core.deadline import DEADLINE_BODY, STATE_COMPAT_COLLAPSE, deadline_remaining, disable_deadline
from roxy.core.errors import ErrorEvent
from roxy.core.security_headers import mark_proxied


def slow_app(make_app: Any, deadline_s: float = 0.2) -> Any:
    app = make_app(settings={"request_deadline_s": deadline_s})

    @app.get("/slow")
    async def slow() -> PlainTextResponse:
        await asyncio.sleep(5)
        return PlainTextResponse("too late")

    @app.get("/fast")
    async def fast(request: Request) -> dict[str, float | None]:
        return {"remaining": deadline_remaining(request.scope)}

    @app.get("/stream")
    async def stream(request: Request) -> PlainTextResponse:
        disable_deadline(request.scope)  # a deliberately long response opts out
        await asyncio.sleep(0.4)
        return PlainTextResponse("still here")

    @app.get("/inner-timeout")
    async def inner_timeout() -> PlainTextResponse:
        async with asyncio.timeout(0.01):
            await asyncio.sleep(1)
        return PlainTextResponse("unreachable")

    return app


async def test_deadline_returns_504_with_7_13_body_and_headers(make_app: Any, client_for: Any) -> None:
    app = slow_app(make_app)
    events: list[ErrorEvent] = []
    app.state.error_hooks.add("deadline", events.append)
    async with client_for(app) as client:
        response = await client.get("/slow")
    assert response.status_code == 504
    assert response.text == DEADLINE_BODY == "Upstream request failed; please try again later."
    assert response.headers["retry-after"] == "5"
    assert response.headers["roxy-refusal"] == "deadline"
    assert len(response.headers["roxy-request-id"]) == 26
    assert response.headers["x-content-type-options"] == "nosniff"
    assert [event.status for event in events] == [504]
    assert events[0].request_id == response.headers["roxy-request-id"]


async def test_deadline_comes_from_live_settings(make_app: Any, client_for: Any) -> None:
    async with client_for(slow_app(make_app, deadline_s=30)) as client:
        response = await client.get("/fast")
    remaining = response.json()["remaining"]
    assert 29 < remaining <= 30


async def test_fast_request_is_untouched(make_app: Any, client_for: Any) -> None:
    async with client_for(slow_app(make_app)) as client:
        response = await client.get("/fast")
    assert response.status_code == 200
    assert "roxy-refusal" not in response.headers


async def test_disable_deadline_lets_streams_run(make_app: Any, client_for: Any) -> None:
    async with client_for(slow_app(make_app, deadline_s=0.1)) as client:
        response = await client.get("/stream")
    assert response.status_code == 200
    assert response.text == "still here"


async def test_inner_timeout_is_a_bug_not_a_deadline(make_app: Any, client_for: Any) -> None:
    async with client_for(slow_app(make_app, deadline_s=30)) as client:
        response = await client.get("/inner-timeout")
    assert response.status_code == 500
    assert response.content == b'"Internal Server Error"\n'  # v1's jsonify form (plan 7.13 "as v1")
    assert response.headers["content-type"].split(";")[0] == "application/json"
    assert "roxy-refusal" not in response.headers


# --- v1 compatibility (finding spec-5) ---------------------------------------------------------------------------


def proxied_app(make_app: Any, *, compat: bool, chosen: bool | None = None) -> Any:
    """An app whose `/proxied` route marks itself as proxied content (as the proxy route does) and then stalls."""
    app = make_app(settings={"request_deadline_s": 0.2, "compat_collapse_upstream_errors": compat})

    @app.get("/proxied")
    async def proxied(request: Request) -> PlainTextResponse:
        mark_proxied(request.scope)
        if chosen is not None:
            request.state.compat_collapse = chosen  # what the proxy flow rendered and recorded with
        await asyncio.sleep(5)
        return PlainTextResponse("too late")

    @app.get("/page")
    async def page() -> PlainTextResponse:
        await asyncio.sleep(5)
        return PlainTextResponse("too late")

    return app


async def test_compat_mode_collapses_the_deadline_row_of_a_proxied_request(make_app: Any, client_for: Any) -> None:
    app = proxied_app(make_app, compat=True)
    events: list[ErrorEvent] = []
    app.state.error_hooks.add("deadline", events.append)
    async with client_for(app) as client:
        proxied = await client.get("/proxied")
        page = await client.get("/page")
    assert (proxied.status_code, proxied.text) == (500, DEADLINE_BODY)  # v1 scripts only know 200 and 500
    assert proxied.headers["retry-after"] == "5"
    assert proxied.headers["roxy-refusal"] == "deadline"
    assert page.status_code == 504  # Roxy's own pages are not Roblox answers: never collapsed
    assert [event.status for event in events] == [500, 504]


async def test_the_proxy_flows_own_compat_choice_wins_over_the_live_setting(make_app: Any, client_for: Any) -> None:
    """The proxy flow records its fallback outcome with the choice it read at the start of the request; the answer
    follows that choice, so the record and the wire agree even if the setting changed meanwhile."""
    async with client_for(proxied_app(make_app, compat=True, chosen=False)) as client:
        assert (await client.get("/proxied")).status_code == 504
    async with client_for(proxied_app(make_app, compat=False, chosen=True)) as client:
        assert (await client.get("/proxied")).status_code == 500
    async with client_for(proxied_app(make_app, compat=False)) as client:
        assert (await client.get("/proxied")).status_code == 504


def test_state_key_matches_the_constant() -> None:
    assert STATE_COMPAT_COLLAPSE == "compat_collapse"  # `request.state.compat_collapse` in the test above
