"""App skeleton tests (P0): the app starts with its lifespan, the internal endpoints exist only on the Unix
socket (plan 5.8), the worker class has the plan 5.2 options, and the admin guards fail closed."""

from __future__ import annotations

import asyncio
import json
import logging
import socket
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import Depends, FastAPI

from roxy.config.audit import Actor
from roxy.config.settings_service import SettingsService
from roxy.deps import get_db, require_admin, require_csrf
from roxy.internal_app import ListenerDispatcher, listener_kind
from roxy.lifespan import AppContext
from roxy.main import create_app, create_asgi_app
from roxy.worker import RoxyUvicornWorker

STARTUP_ORDER = [
    "env",
    "logging",
    "databases",
    "schema",
    "cache_db_check",
    "settings",
    "rules",
    "alerts",
    "clients",
    "recorder",
    "upstream",
    "cache",
    "abuse",
    "error_hooks",
    "heartbeat",
    "leader",
    "jobs",
    "config_watcher",
    "sse_tail",
]


@pytest.fixture(autouse=True)
def _restore_root_logging() -> Iterator[None]:
    """The lifespan configures logging; put the root logger back afterwards."""
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    yield
    root.handlers[:] = handlers
    root.setLevel(level)
    logging.captureWarnings(False)


async def asgi_request(app: Any, method: str, path: str, server: tuple[str, int | None]) -> tuple[int, bytes]:
    """Send one raw ASGI HTTP request with a chosen `scope["server"]` (to emulate the Unix socket listener)."""
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", b"x")],
        "server": server,
        "client": None if server[1] is None else ("127.0.0.1", 40000),
    }
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

    await app(scope, receive, send)
    status = next(m["status"] for m in messages if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    return status, body


async def test_app_starts_with_lifespan(app: FastAPI, client: httpx.AsyncClient) -> None:
    ctx = app.state.ctx
    assert isinstance(ctx, AppContext)
    assert ctx.ready
    assert ctx.color == "dev"
    assert ctx.worker_id.count(":") == 2
    assert ctx.dbs is not None
    expected = [step for step in STARTUP_ORDER if step in ctx.startup_steps]
    assert ctx.startup_steps == expected  # DESIGN.md section 1 order
    assert ctx.startup_steps[:6] == STARTUP_ORDER[:6]
    response = await client.get("/")
    assert response.status_code == 200
    assert len(response.headers["roxy-request-id"]) == 26
    assert "nonce-" in response.headers["content-security-policy"]


async def test_shutdown_stops_everything(app: FastAPI) -> None:
    async with app.router.lifespan_context(app):
        ctx = app.state.ctx
        assert ctx.ready
        if ctx.leader is not None:
            for _ in range(100):  # the first leader tick happens right after startup
                if ctx.leader.is_leader:
                    break
                await asyncio.sleep(0.01)
    assert not ctx.ready
    assert all(not status.running for status in ctx.tasks.status())
    if ctx.leader is not None:
        assert not ctx.leader.is_leader  # the lease was released on shutdown


async def test_startup_refused_when_schema_is_too_old(env: Any) -> None:
    production_like = env.model_copy(update={"auto_migrate": False})  # empty databases, nobody migrates
    app = create_app(production_like)
    with pytest.raises(Exception, match=r"(?i)schema"):
        async with app.router.lifespan_context(app):
            pass


async def test_public_app_has_no_internal_routes(app: FastAPI, client: httpx.AsyncClient) -> None:
    assert not [route for route in app.routes if getattr(route, "path", "").startswith("/internal")]
    for path in ("/internal/version", "/internal/ready"):
        assert (await client.get(path)).status_code == 404
    assert (await client.post("/internal/flush")).status_code in (404, 405)


def test_listener_kind() -> None:
    sock = "/run/roxy-blue/internal.sock"
    assert listener_kind({"server": (sock, None)}, sock) == "internal"
    assert listener_kind({"server": ("/run/roxy-blue/other.sock", None)}, sock) == "public"
    assert listener_kind({"server": ("127.0.0.1", 8001)}, sock) == "public"
    assert listener_kind({"server": None}, sock) == "public"
    assert listener_kind({"server": (sock, None)}, None) == "public"


async def test_dispatcher_routes_by_listener(env: Any) -> None:
    dispatcher = create_asgi_app(env)
    assert isinstance(dispatcher, ListenerDispatcher)
    public = dispatcher.public
    async with public.router.lifespan_context(public):  # type: ignore[attr-defined]
        unix = (str(env.internal_socket), None)
        status, body = await asgi_request(dispatcher, "GET", "/internal/version", unix)
        assert status == 200
        version = json.loads(body)
        assert version["Color"] == "dev"
        assert version["WorkerId"] == public.state.ctx.worker_id  # type: ignore[attr-defined]
        status, body = await asgi_request(dispatcher, "GET", "/internal/ready", unix)
        assert status == 200
        ready = json.loads(body)
        assert ready["Ready"] is True
        assert ready["PersistenceOK"] is True
        status, body = await asgi_request(dispatcher, "POST", "/internal/flush", unix)
        assert status == 200
        status, _ = await asgi_request(dispatcher, "GET", "/internal/version", ("127.0.0.1", 8001))
        assert status == 404


async def test_internal_only_on_unix_socket_with_real_uvicorn(env: Any) -> None:
    """The plan 5.8 experiment as a test: real uvicorn, one TCP and one Unix listener, one app."""
    import uvicorn

    socket_path = Path(env.internal_socket)
    if len(str(socket_path)) > 100:
        pytest.skip("temporary path too long for a Unix socket")
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind(("127.0.0.1", 0))
    port = tcp.getsockname()[1]
    uds = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    uds.bind(str(socket_path))
    asgi_app = create_asgi_app(env)
    config = uvicorn.Config(asgi_app, lifespan="on", log_config=None, proxy_headers=False, server_header=False)
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve(sockets=[tcp, uds]))
    try:
        for _ in range(500):
            if server.started:
                break
            await asyncio.sleep(0.01)
        assert server.started
        # `/internal/version` on the public port is an ordinary unknown path there: the proxy route refuses it as
        # not a Roblox URL, and the wired abuse pipeline would hold that probe in the tarpit for 8 to 20 s first.
        ctx = asgi_app.public.state.ctx
        await SettingsService(ctx.dbs.control, runtime=ctx.settings).update(
            {"tarpit_enabled": 0}, Actor("admin", "test"), "no tarpit hold in this test"
        )
        async with httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=str(socket_path))) as internal:
            version = await internal.get("http://roxy/internal/version")
            ready = await internal.get("http://roxy/internal/ready")
        async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}") as public:
            hidden = await public.get("/internal/version")
            home = await public.get("/")
        assert version.status_code == 200
        assert version.json()["Color"] == "dev"
        assert ready.status_code == 200
        assert hidden.status_code == 404
        assert home.status_code == 200
        assert "server" not in home.headers
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, timeout=15)
        tcp.close()
        uds.close()


def test_worker_class_options() -> None:
    kwargs = RoxyUvicornWorker.CONFIG_KWARGS
    assert kwargs["proxy_headers"] is False
    assert kwargs["server_header"] is False
    assert kwargs["date_header"] is True
    assert kwargs["timeout_keep_alive"] == 75
    assert kwargs["lifespan"] == "on"


async def test_admin_guards_fail_closed(env: Any) -> None:
    app = create_app(env)

    @app.get("/admin/api/v1/probe", dependencies=[Depends(require_admin("session"))])
    async def probe() -> dict[str, str]:
        return {"ok": "should never be reached"}

    @app.post("/admin/api/v1/write", dependencies=[Depends(require_csrf)])
    async def write() -> dict[str, str]:
        return {"ok": "should never be reached"}

    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 50000))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        assert (await client.get("/admin/api/v1/probe")).status_code == 404
        assert (await client.post("/admin/api/v1/write")).status_code == 403


def test_get_db_rejects_unknown_names() -> None:
    with pytest.raises(ValueError):
        get_db("secrets")
    assert callable(get_db("metrics"))
