"""Shared helpers for the ingress security probes (`tests/security/test_ingress_*.py`).

What this is
    Small, dependency-free helpers the ingress probes share: `CatalogSettings` (catalog defaults plus overrides,
    read like `RuntimeSettings`), `proxy_request` (a real `ProxyRequest` built from a raw path exactly the way
    `proxy/router.py` builds one), `raw_asgi_request` (one request with an exact raw path through any ASGI app,
    as uvicorn would pass it), and `make_proxy_app` (the real middleware stack plus the real proxy route over a
    context the test supplies).

Why it exists
    The ingress review (plan 9.9 to 9.13 and 10) probes the request path end to end: the raw bytes a caller sends,
    the parse, the cache key, the abuse verdict and the tarpit. HTTP clients normalize URLs (httpx removes `..` and
    re-encodes), which would hide the attacks, so these helpers drive the ASGI app with hand-built scopes.

How it works
    Plain functions and one class; no fixtures here (the probes use `tests/conftest.py` fixtures such as `dbs`).
    A module (not a conftest) so the probe files can import it by name; pytest puts this directory on `sys.path`.

What to read next
    `tests/security/test_ingress_ssrf_corpus.py`, then the other `test_ingress_*.py` probes.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import unquote

from starlette.applications import Starlette

from roxy.config.catalog import CATALOG
from roxy.core.client_ip import limit_key, parse_cidrs
from roxy.core.middleware import build_middleware
from roxy.proxy import scrub, validate
from roxy.proxy.context import ProxyRequest, endpoint_template, is_browser, problem_template
from roxy.proxy.router import router

CLIENT_IP = "203.0.113.7"
"""TEST-NET-3 documentation address: never a real system."""


class CatalogSettings:
    """The read side of `RuntimeSettings`: every catalog default plus overrides, with a moving `version`."""

    def __init__(self, overrides: Mapping[str, Any] | None = None) -> None:
        self.values: dict[str, Any] = {key: spec.default for key, spec in CATALOG.items()}
        unknown = set(overrides or {}) - set(self.values)
        assert not unknown, f"unknown settings: {sorted(unknown)}"
        self.values.update(overrides or {})
        self.version = 1

    def snapshot(self) -> Mapping[str, Any]:
        return dict(self.values)

    def get(self, key: str) -> Any:
        return self.values[key]

    def set(self, **changes: Any) -> None:
        self.values.update(changes)
        self.version += 1


def proxy_request(
    raw_path: bytes | str,
    query: bytes | str = b"",
    *,
    method: str = "GET",
    headers: Iterable[tuple[str, str]] = (("user-agent", "Roblox/Linux"), ("accept", "*/*")),
    client_ip: str = CLIENT_IP,
    body: bytes = b"",
    allowed_hosts: Any = None,
    strict: bool = True,
) -> ProxyRequest:
    """A `ProxyRequest` built the way `ProxyFlow.build_request` builds one (no ASGI app needed)."""
    upper = method.upper()
    body = body if upper in scrub.BODY_METHODS else b""  # the router reads a body only for these methods
    parse = validate.parse_target(raw_path, query, upper, allowed_hosts=allowed_hosts, strict_host_allowlist=strict)
    header_map: dict[str, str] = {}
    names: list[str] = []
    for name, value in headers:
        lowered = name.lower()
        names.append(lowered)
        header_map[lowered] = f"{header_map[lowered]}, {value}" if lowered in header_map else value
    user_agent = header_map.get("user-agent", "")
    is_head = upper == "HEAD"
    template = endpoint_template(parse.host, parse.path) if parse.problem is None else problem_template(parse.problem)
    now = time.monotonic()
    return ProxyRequest(
        request_id="01INGRESSPROBE",
        received_ms=0,
        deadline_at=now + 60.0,
        client_ip=client_ip,
        limit_key=limit_key(client_ip, 64),
        method="GET" if is_head else upper,
        host=parse.host,
        path=parse.path,
        query=list(parse.query),
        prettyprint=parse.prettyprint,
        body=body,
        content_type=header_map.get("content-type"),
        headers=header_map,
        header_names_in_order=names,
        user_agent=user_agent,
        place_id=header_map.get("roblox-id", "").strip()[:64] or None,
        is_browser=is_browser(user_agent),
        template=template,
        target_problem=parse.problem,
        is_head=is_head,
        target=parse.target,
        target_detail=parse.detail,
        raw_query=parse.raw_query,
        received_monotonic=now,
        raw_path=parse.raw_target,
    )


def make_proxy_app(ctx: Any) -> Starlette:
    """The real middleware stack (loopback trusted, one hop) and the real proxy route over `ctx`."""
    app = Starlette(
        routes=list(router.routes),
        middleware=build_middleware(trusted_cidrs=parse_cidrs("127.0.0.1/32"), hops=1),
    )
    app.state.ctx = ctx
    return app


async def raw_asgi_request(
    app: Any,
    raw_path: bytes,
    *,
    method: str = "GET",
    query: bytes = b"",
    headers: Iterable[tuple[bytes, bytes]] = ((b"host", b"testserver"),),
    body_chunks: Iterable[bytes] = (b"",),
    disconnect_after_first_body: bool = False,
    stall_after_chunks: bool = False,
) -> tuple[int, dict[bytes, bytes], bytes, dict[str, Any]]:
    """Send one request with an exact raw path (no client-side normalization), as uvicorn would pass it.

    Returns (status, headers with lowercase names, body, receive_stats) where `receive_stats["chunks_read"]`
    counts how many body chunks the app pulled. With `disconnect_after_first_body`, `send` raises on the second
    body message (a client that went away mid-stream). With `stall_after_chunks`, the body never ends: after the
    given chunks `receive` waits forever (a slow-body client).
    """
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": unquote(raw_path.decode("latin-1")),
        "raw_path": raw_path,
        "query_string": query,
        "root_path": "",
        "headers": list(headers),
        "client": ("127.0.0.1", 50000),
        "server": ("testserver", 80),
    }
    chunks = list(body_chunks)
    stats: dict[str, Any] = {"chunks_read": 0}
    messages: list[dict[str, Any]] = []
    body_messages = 0

    async def receive() -> dict[str, Any]:
        index = stats["chunks_read"]
        if index < len(chunks):
            stats["chunks_read"] += 1
            more = stall_after_chunks or index + 1 < len(chunks)
            return {"type": "http.request", "body": chunks[index], "more_body": more}
        if stall_after_chunks:
            await asyncio.Event().wait()
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        nonlocal body_messages
        if message["type"] == "http.response.body":
            body_messages += 1
            if disconnect_after_first_body and body_messages > 1:
                raise OSError("client went away")
        messages.append(message)

    try:
        await app(scope, receive, send)
    except Exception:  # Starlette turns the OSError into ClientDisconnect; either means "the client went away"
        if not disconnect_after_first_body:
            raise
    start = next(m for m in messages if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    response_headers = {bytes(name).lower(): bytes(value) for name, value in start.get("headers", [])}
    return int(start["status"]), response_headers, body, stats


__all__ = [
    "CLIENT_IP",
    "CatalogSettings",
    "make_proxy_app",
    "proxy_request",
    "raw_asgi_request",
]
