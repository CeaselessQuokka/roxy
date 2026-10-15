"""Fixtures for the core tests: a small FastAPI app with Roxy's real middleware stack and stub live settings.

The full app (`create_app`) needs databases and a lifespan; these tests only need the middleware, so they build
a bare FastAPI app with `build_middleware(...)`, Roxy's exception handlers, and an `app.state.ctx` whose
`settings.get(key)` answers from a dict (the same lookup the middleware does against the real settings store).
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator, Mapping
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from roxy.core.client_ip import parse_cidrs
from roxy.core.clock import SYSTEM_CLOCK, Clock
from roxy.core.errors import install_exception_handlers
from roxy.core.middleware import build_middleware
from roxy.core.redact import SecretRegistry

PEER = ("127.0.0.1", 50000)  # the ASGI peer of test requests: loopback, like nginx in production


class StubSettings:
    """Answers `get(key)` from a dict and raises KeyError otherwise, like `RuntimeSettings`."""

    def __init__(self, values: Mapping[str, Any]) -> None:
        self.values = dict(values)

    def get(self, key: str) -> Any:
        return self.values[key]


class StubCtx:
    def __init__(self, settings: StubSettings, clock: Clock = SYSTEM_CLOCK) -> None:
        self.settings = settings
        self.clock = clock


AppFactory = Callable[..., FastAPI]


@pytest.fixture
def make_app() -> AppFactory:
    """Build a FastAPI app with the real P0 middleware stack. Add routes to the returned app."""

    def factory(
        *,
        settings: Mapping[str, Any] | None = None,
        trusted: str = "127.0.0.1/32,::1/128",
        hops: int = 1,
        send_hsts: bool = False,
    ) -> FastAPI:
        app = FastAPI(
            docs_url=None,
            redoc_url=None,
            openapi_url=None,
            middleware=build_middleware(trusted_cidrs=parse_cidrs(trusted), hops=hops, send_hsts=send_hsts),
        )
        install_exception_handlers(app)
        app.state.ctx = StubCtx(StubSettings(settings or {}))
        return app

    return factory


ClientFactory = Callable[..., httpx.AsyncClient]


@pytest.fixture
def client_for() -> ClientFactory:
    """`client_for(app, peer=...)`: an in-process client for `app` (no lifespan) whose requests come from `peer`."""

    def factory(app: Any, peer: tuple[str, int] = PEER) -> httpx.AsyncClient:
        transport = httpx.ASGITransport(app=app, client=peer)
        return httpx.AsyncClient(transport=transport, base_url="http://testserver")

    return factory


@pytest.fixture(autouse=True)
def _clean_secret_registry() -> Iterator[None]:
    """Every test starts and ends with an empty secret registry (it is process wide)."""
    SecretRegistry.clear()
    yield
    SecretRegistry.clear()


@pytest.fixture
def restore_logging() -> Iterator[None]:
    """Undo `configure_logging` after a test: handlers and levels of the root and pinned loggers. A background
    handler the test installed is closed, so its writer thread ends with the test."""
    from roxy.core.logging import BackgroundStreamHandler

    root = logging.getLogger()
    handlers = list(root.handlers)
    level = root.level
    pinned = {name: logging.getLogger(name).level for name in ("httpx", "httpcore", "h2", "hpack", "aiosmtplib")}
    yield
    for handler in root.handlers:
        if handler not in handlers and isinstance(handler, BackgroundStreamHandler):
            handler.close()
    root.handlers[:] = handlers
    root.setLevel(level)
    for name, value in pinned.items():
        logging.getLogger(name).setLevel(value)
    logging.captureWarnings(False)
    from roxy.core.logging import set_ip_hasher

    set_ip_hasher(None)
