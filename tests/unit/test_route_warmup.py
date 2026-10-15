"""The served app prepares its routes before it serves: a new worker's first proxy request builds no route state.

What this is
    Unit tests for `roxy/main.py` `warm_routes`, the one startup warm-up, which `create_asgi_app` runs for the app
    gunicorn's worker, plain uvicorn and the tests' in-process client serve.

Why it exists
    FastAPI (0.142 here) prepares the routes of an included router lazily, on the first request matched through it,
    and every page and API route stands in front of the proxy catch-all. Before the warm-up, the first proxy request
    of each new worker built about 390 route contexts and 48,000 objects on the event loop (250 to 370 ms). The
    requests that arrived meanwhile left together: in the plan 19.4 cooldown scenario seven calls reached the
    endpoint Roblox was refusing before its first 429 came back, and in the replays it was the worst heartbeat
    (docs/PERFORMANCE.md, "Startup warm-up (2026-10-14)").

How it works
    The tests count FastAPI's route preparations (`_IncludedRouter._build_effective_context`) and the objects a
    first proxy match leaves behind, instead of timing anything. The control shows a plain `create_app` still builds
    them on its first request; the app `create_asgi_app` returns builds none, before and after its lifespan ran. The
    counter fixture skips if FastAPI ever stops building routes lazily (there would be nothing left to warm).

What to read next
    `roxy/main.py` (`warm_routes`, `create_asgi_app`), `roxy/worker.py` (the freeze of the app as built),
    `tests/unit/test_worker_gc.py`.
"""

from __future__ import annotations

import asyncio
import gc
import logging
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
from starlette.routing import Match

from roxy import main
from roxy.main import RouteWarmup, create_app, create_asgi_app, warm_routes

PROXY_PATH = "/badges.roblox.com/v1/badges/2020000"
FIRST_MATCH_OBJECT_BOUND = 1_000
"""Objects a first proxy match may leave behind once the routes are warm (3 measured; about 48,000 cold)."""


@pytest.fixture
def route_builds(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """A one-item list counting FastAPI's lazy route preparations (skips when this FastAPI has none)."""
    routing = pytest.importorskip("fastapi.routing")
    included = getattr(routing, "_IncludedRouter", None)
    original = getattr(included, "_build_effective_context", None)
    if included is None or original is None:
        pytest.skip("this FastAPI prepares routes when they are included: there is nothing to warm")
    count = [0]

    def counting(self: Any, route: Any) -> Any:
        count[0] += 1
        return original(self, route)

    monkeypatch.setattr(included, "_build_effective_context", counting)
    return count


@pytest.fixture
def _restore_root_logging() -> Iterator[None]:
    """The lifespan configures logging; put the root logger back afterwards."""
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    yield
    root.handlers[:] = handlers
    root.setLevel(level)
    logging.captureWarnings(False)


def _http_scope(path: str) -> dict[str, Any]:
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "root_path": "",
        "query_string": b"",
        "headers": [(b"host", b"127.0.0.1:8001")],
        "client": ("127.0.0.1", 40000),
        "server": ("127.0.0.1", 8001),
        "state": {},
    }


async def proxy_request(app: Any, path: str = PROXY_PATH) -> int:
    """One GET through the whole ASGI app on the public TCP listener; returns the status (no lifespan ran, so the
    proxy fails closed with 503 `degraded` before any upstream work)."""
    messages: list[dict[str, Any]] = []
    sent = False

    async def receive() -> dict[str, Any]:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await asyncio.sleep(3600)
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    await app(_http_scope(path), receive, send)
    return next(int(m["status"]) for m in messages if m["type"] == "http.response.start")


def _first_full_match(app: Any, path: str) -> Any:
    """The route Starlette's router would pick for `path` (it asks each top-level route in order)."""
    scope = _http_scope(path)
    for route in app.router.routes:
        match, _child = route.matches(scope)
        if match is Match.FULL:
            return route
    return None


async def test_the_first_proxy_request_of_a_served_app_builds_no_route_state(env: Any, route_builds: list[int]) -> None:
    cold = create_app(env)
    route_builds[0] = 0
    assert await proxy_request(cold) == 503
    assert route_builds[0] > 100  # control: FastAPI prepares every route in front of the catch-all on demand

    route_builds[0] = 0
    served: Any = create_asgi_app(env)  # what gunicorn loads in each worker before it accepts a connection
    assert route_builds[0] > 100  # prepared here, at boot
    warmup = served.public.state.route_warmup
    assert isinstance(warmup, RouteWarmup)
    assert warmup.routes is not None
    assert warmup.routes >= 300  # every admin, API, page and public route (about 390)
    assert warmup.ms >= 0
    assert served.state.route_warmup is warmup  # the dispatcher shows the public app's state (the worker's log)
    route_builds[0] = 0
    assert await proxy_request(served) == 503
    assert route_builds[0] == 0  # nothing left to build on the first request
    for path in ("/health", "/admin", "/"):
        await proxy_request(served, path)
    assert route_builds[0] == 0  # nor on the first page or health request


def test_the_warmup_builds_what_a_cold_proxy_request_would(env: Any, route_builds: list[int]) -> None:
    """The walk prepares every route context a proxy request's matching prepares (all those in front of the
    catch-all), and FastAPI keeps them: a second walk builds nothing."""
    route_builds[0] = 0
    assert _first_full_match(create_app(env), PROXY_PATH) is not None
    by_matching = route_builds[0]
    warmed = create_app(env)
    route_builds[0] = 0
    first = warm_routes(warmed)
    assert route_builds[0] >= by_matching > 100
    route_builds[0] = 0
    again = warm_routes(warmed)
    assert route_builds[0] == 0
    assert again.routes == first.routes
    assert warmed.state.route_warmup is again


def test_the_first_proxy_match_of_a_served_app_leaves_almost_nothing_behind(env: Any) -> None:
    """Counted in objects, not time: the first proxy match after the warm-up made 3 objects, about 48,000 before."""
    app: Any = create_asgi_app(env)  # the listener dispatcher gunicorn serves (its `public` app is FastAPI)
    gc.collect()
    before = len(gc.get_objects())
    route = _first_full_match(app.public, PROXY_PATH)
    gc.collect()
    added = len(gc.get_objects()) - before
    assert getattr(route, "path", None) == "/{path:path}"  # the proxy catch-all, reached after every router
    assert added < FIRST_MATCH_OBJECT_BOUND, f"the first proxy match still built {added} objects of route state"


@pytest.mark.usefixtures("_restore_root_logging")
async def test_the_served_app_stays_warm_through_its_lifespan(env: Any, route_builds: list[int]) -> None:
    """The in-process client of the tests (and plain uvicorn) runs the lifespan, which may add routes of its own
    (the development gallery, after the catch-all): nothing the warm-up built is invalidated."""
    served: Any = create_asgi_app(env)
    public = served.public
    route_builds[0] = 0
    async with public.router.lifespan_context(public):
        transport = httpx.ASGITransport(app=served, client=("127.0.0.1", 50000))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            health = await client.get("/health")
        assert health.status_code == 200
        assert getattr(_first_full_match(public, PROXY_PATH), "path", None) == "/{path:path}"
    assert route_builds[0] == 0


def test_a_failed_warmup_never_stops_a_worker(
    env: Any, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A FastAPI that walks differently is logged and left to the lazy build of before; the app is still served."""

    def broken(routes: Any) -> Any:
        raise RuntimeError("a router that cannot be walked")

    monkeypatch.setattr(main, "iter_route_contexts", broken)
    with caplog.at_level(logging.WARNING, logger="roxy.main"):
        served: Any = create_asgi_app(env)
    warmup = served.public.state.route_warmup
    assert warmup.routes is None
    assert warmup.ms >= 0
    assert any(record.getMessage() == "route_warmup_failed" for record in caplog.records)
