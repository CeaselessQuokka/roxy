"""Byte metering: how many bytes each upstream call really put on the wire, TLS and proxy handshake included.

What this is
    `MeteringTransport`, an `httpx.AsyncHTTPTransport` whose connections run on `MeteredNetworkBackend`, a network
    backend that counts every byte written to and read from the socket. `attribute_to(usage)` makes the bytes moved
    by the current task count toward one request. `estimate_exchange` is the fallback when socket metering is off,
    and `run_self_test` decides at startup which of the two is in use (plan 8.3).

Why it exists
    DataImpulse bills the bytes that cross its gateway: the CONNECT exchange, the TLS handshake, the TLS record
    framing and the encrypted HTTP. httpx only reports decoded HTTP bodies, which undercounts badly for small API
    calls (a new TLS connection alone is several KB). Counting below TLS gives the number the provider sees, so
    the monthly quota, the daily cap and the cost projection are honest (the UI still calls them estimates).

How it works
    httpcore opens connections through a "network backend". This module's backend opens the TCP connection with
    anyio, exactly as httpcore's own anyio backend does, but slips a counting stream between the socket and
    everything above it. When httpcore upgrades the connection to TLS (to Roblox, or inside a CONNECT tunnel), the
    TLS layer wraps the counting stream, so TLS records pass through the counter: the count is of wire bytes, not
    plaintext. Attribution uses a context variable: `EgressClients.send` sets a `RequestUsage` for the duration of
    one call, and every byte the current task moves is added to it (connection setup bytes therefore land on the
    first request of a new connection). The rotator uses HTTP/1.1, so one connection serves one request at a time
    and attribution is exact; on HTTP/2 (direct, credential) totals are exact but per-request splits are not.
    httpx does not let callers pass a backend, so `MeteringTransport` swaps it into the connection pool right
    after construction. If that private attribute ever disappears (an httpcore upgrade) the startup self-test
    fails, the transport reports `estimate` mode, and `estimate_exchange` adds up headers, bodies, TLS record
    framing and `rotator_tls_overhead_bytes` per new connection instead.

What to read next
    `roxy/egress/accounting.py` (where the counts go), then `roxy/egress/rotator.py` (the quota checks).
"""

from __future__ import annotations

import asyncio
import contextlib
import select
import ssl
from collections.abc import Callable, Iterator, Mapping
from contextvars import ContextVar
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import anyio
import anyio.abc
import httpcore
import httpx
from anyio.streams.tls import TLSAttribute, TLSStream

TLS_RECORD_PAYLOAD = 16_384
"""Largest plaintext a TLS record carries."""

TLS_RECORD_OVERHEAD = 22
"""Bytes TLS 1.3 with AES-GCM adds per record: 5 header, 16 tag, 1 inner content type."""

CONNECT_RESPONSE = b"HTTP/1.1 200 Connection established\r\n\r\n"
"""The usual proxy answer to CONNECT, used by the fallback estimate."""


class MeteringMode(StrEnum):
    """Which method produced a byte count (shown on the Egress page)."""

    SOCKET = "socket"
    ESTIMATE = "estimate"


@dataclass(slots=True)
class RequestUsage:
    """Wire bytes moved on behalf of one egress call (all redirect hops together)."""

    bytes_out: int = 0
    bytes_in: int = 0
    new_connections: int = 0


_ACTIVE: ContextVar[RequestUsage | None] = ContextVar("roxy_egress_request_usage", default=None)


@contextlib.contextmanager
def attribute_to(usage: RequestUsage) -> Iterator[RequestUsage]:
    """Count every byte the current task moves on a metered socket toward `usage` until the block ends."""
    token = _ACTIVE.set(usage)
    try:
        yield usage
    finally:
        _ACTIVE.reset(token)


class ByteMeter:
    """Running totals for one client (per egress). Bytes moved outside any `attribute_to` block are counted as
    unattributed (for example a connection closing in the background), so totals stay exact."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.bytes_out = 0
        self.bytes_in = 0
        self.connections = 0
        self.unattributed_out = 0
        self.unattributed_in = 0

    def add_out(self, count: int) -> None:
        self.bytes_out += count
        usage = _ACTIVE.get()
        if usage is None:
            self.unattributed_out += count
        else:
            usage.bytes_out += count

    def add_in(self, count: int) -> None:
        self.bytes_in += count
        usage = _ACTIVE.get()
        if usage is None:
            self.unattributed_in += count
        else:
            usage.bytes_in += count

    def add_connection(self) -> None:
        self.connections += 1
        usage = _ACTIVE.get()
        if usage is not None:
            usage.new_connections += 1

    def snapshot(self) -> dict[str, int | str]:
        return {
            "name": self.name,
            "bytes_out": self.bytes_out,
            "bytes_in": self.bytes_in,
            "connections": self.connections,
            "unattributed_out": self.unattributed_out,
            "unattributed_in": self.unattributed_in,
        }


# --- the counting network backend ---------------------------------------------------------------------------------


class _CountingByteStream(anyio.abc.ByteStream):
    """An anyio byte stream that counts what passes through it. It sits directly on the TCP socket."""

    def __init__(self, inner: anyio.abc.ByteStream, meter: ByteMeter) -> None:
        self._inner = inner
        self._meter = meter

    async def receive(self, max_bytes: int = 65536) -> bytes:
        data = await self._inner.receive(max_bytes)
        self._meter.add_in(len(data))
        return data

    async def send(self, item: bytes) -> None:
        await self._inner.send(item)
        self._meter.add_out(len(item))

    async def send_eof(self) -> None:
        await self._inner.send_eof()

    async def aclose(self) -> None:
        await self._inner.aclose()

    @property
    def extra_attributes(self) -> Mapping[Any, Callable[[], Any]]:
        return self._inner.extra_attributes


@contextlib.contextmanager
def _map_errors(mapping: Mapping[type[Exception], type[Exception]]) -> Iterator[None]:
    """Re-raise library exceptions as httpcore's public ones (what httpx expects from a backend)."""
    try:
        yield
    except Exception as exc:
        for source, target in mapping.items():
            if isinstance(exc, source):
                raise target(exc) from exc
        raise


def _is_socket_readable(sock: Any) -> bool:
    """True when an idle pooled socket has data or was closed by the peer (so it must not be reused)."""
    if sock is None:
        return False
    fileno = sock.fileno()
    if fileno == -1:
        return True
    if hasattr(select, "poll"):
        poller = select.poll()
        poller.register(fileno, select.POLLIN)
        return bool(poller.poll(0))
    readable, _, _ = select.select([fileno], [], [], 0)
    return bool(readable)


class _MeteredNetworkStream(httpcore.AsyncNetworkStream):
    """httpcore's view of one connection. Same behavior as httpcore's anyio stream; the counting happens below."""

    def __init__(self, stream: anyio.abc.ByteStream) -> None:
        self._stream = stream

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:  # noqa: ASYNC109 (httpcore API)
        errors = {
            TimeoutError: httpcore.ReadTimeout,
            anyio.BrokenResourceError: httpcore.ReadError,
            anyio.ClosedResourceError: httpcore.ReadError,
            anyio.EndOfStream: httpcore.ReadError,
        }
        with _map_errors(errors), anyio.fail_after(timeout):
            try:
                return await self._stream.receive(max_bytes=max_bytes)
            except anyio.EndOfStream:
                return b""

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:  # noqa: ASYNC109 (httpcore API)
        if not buffer:
            return
        errors = {
            TimeoutError: httpcore.WriteTimeout,
            anyio.BrokenResourceError: httpcore.WriteError,
            anyio.ClosedResourceError: httpcore.WriteError,
        }
        with _map_errors(errors), anyio.fail_after(timeout):
            await self._stream.send(item=buffer)

    async def aclose(self) -> None:
        await self._stream.aclose()

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,  # noqa: ASYNC109 (the httpcore backend API takes a timeout)
    ) -> httpcore.AsyncNetworkStream:
        errors = {
            TimeoutError: httpcore.ConnectTimeout,
            anyio.BrokenResourceError: httpcore.ConnectError,
            anyio.EndOfStream: httpcore.ConnectError,
            ssl.SSLError: httpcore.ConnectError,
        }
        try:
            with _map_errors(errors), anyio.fail_after(timeout):
                # The TLS layer wraps the counting stream, so every TLS record is counted on the wire.
                tls_stream = await TLSStream.wrap(
                    self._stream,
                    ssl_context=ssl_context,
                    hostname=server_hostname,
                    standard_compatible=False,
                    server_side=False,
                )
        except Exception:
            await self.aclose()
            raise
        return _MeteredNetworkStream(tls_stream)

    def get_extra_info(self, info: str) -> Any:
        if info == "ssl_object":
            return self._stream.extra(TLSAttribute.ssl_object, None)  # noqa: S610 (anyio attribute, not Django)
        if info == "client_addr":
            return self._stream.extra(anyio.abc.SocketAttribute.local_address, None)  # noqa: S610 (anyio attribute, not Django)
        if info == "server_addr":
            return self._stream.extra(anyio.abc.SocketAttribute.remote_address, None)  # noqa: S610 (anyio attribute, not Django)
        if info == "socket":
            return self._stream.extra(anyio.abc.SocketAttribute.raw_socket, None)  # noqa: S610 (anyio attribute, not Django)
        if info == "is_readable":
            return _is_socket_readable(self._stream.extra(anyio.abc.SocketAttribute.raw_socket, None))  # noqa: S610 (anyio attribute, not Django)
        return None


class MeteredNetworkBackend(httpcore.AsyncNetworkBackend):
    """Opens TCP connections like httpcore's anyio backend, with a byte counter directly on the socket."""

    def __init__(self, meter: ByteMeter) -> None:
        self._meter = meter
        self._fallback = httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,  # noqa: ASYNC109 (the httpcore backend API takes a timeout)
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        errors = {
            TimeoutError: httpcore.ConnectTimeout,
            OSError: httpcore.ConnectError,
            anyio.BrokenResourceError: httpcore.ConnectError,
        }
        with _map_errors(errors), anyio.fail_after(timeout):
            stream: anyio.abc.SocketStream = await anyio.connect_tcp(
                remote_host=host, remote_port=port, local_host=local_address
            )
            raw = stream.extra(anyio.abc.SocketAttribute.raw_socket)  # noqa: S610 (anyio attribute)
            for option in socket_options or ():
                raw.setsockopt(*option)
        self._meter.add_connection()
        return _MeteredNetworkStream(_CountingByteStream(stream, self._meter))

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,  # noqa: ASYNC109 (the httpcore backend API takes a timeout)
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        # Never used by Roxy's egress (no client is built with uds=...); delegated unmetered for completeness.
        return await self._fallback.connect_unix_socket(path, timeout=timeout, socket_options=socket_options)

    async def sleep(self, seconds: float) -> None:
        await anyio.sleep(seconds)


# --- the transport ------------------------------------------------------------------------------------------------

_socket_metering_ok: bool | None = None  # set by run_self_test; None means "not tested yet" (assume it works)


def socket_metering_enabled() -> bool:
    """False only after the startup self-test showed that socket metering does not work in this process."""
    return _socket_metering_ok is not False


def tls_context(verify: ssl.SSLContext | bool = True) -> ssl.SSLContext:
    """The TLS context of an egress transport: certifi's CA bundle, and never a key log file (finding cred-6).

    `trust_env=False` keeps httpx from reading `SSL_CERT_FILE` and `SSL_CERT_DIR`, but CPython's own
    `ssl.create_default_context` copies the `SSLKEYLOGFILE` environment variable into `keylog_filename` (unless
    Python runs with `-E`). With that variable left in the service environment (a debugging leftover), every TLS
    session of the credential client would write its secrets to a file, and anyone who can read it and capture
    traffic recovers `Cookie: .ROBLOSECURITY=<value>`. So the context is built here and its key log is switched
    off, also on a context a test passes in (plan C2 item 2: environment settings are ignored).
    """
    if isinstance(verify, ssl.SSLContext):
        context = verify
    elif verify:
        import certifi  # httpx's own CA bundle (a dependency of httpx)

        context = ssl.create_default_context(cafile=certifi.where())
    else:  # verification off (loopback tests only): what httpx builds for verify=False
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    context.keylog_filename = None  # type: ignore[assignment]  # None turns key logging off (CPython docs)
    return context


class MeteringTransport(httpx.AsyncHTTPTransport):
    """An httpx transport whose sockets are metered. `proxy` set means a forward proxy (the rotator only)."""

    def __init__(
        self,
        *,
        meter: ByteMeter,
        limits: httpx.Limits,
        http2: bool = False,
        proxy: str | None = None,
        verify: ssl.SSLContext | bool = True,
        socket_metering: bool | None = None,
    ) -> None:
        # trust_env=False: SSL_CERT_FILE, SSL_CERT_DIR and the proxy variables are ignored (plan C2 item 2), and
        # `tls_context` switches off the key log file CPython itself takes from SSLKEYLOGFILE (finding cred-6).
        self.tls = tls_context(verify)
        super().__init__(
            verify=self.tls, trust_env=False, http1=True, http2=http2, limits=limits, proxy=proxy, retries=0
        )
        self.meter = meter
        self.proxy_configured = proxy is not None
        self.mode = MeteringMode.ESTIMATE
        wanted = socket_metering_enabled() if socket_metering is None else socket_metering
        pool = getattr(self, "_pool", None)
        if wanted and pool is not None and hasattr(pool, "_network_backend"):
            pool._network_backend = MeteredNetworkBackend(meter)
            self.mode = MeteringMode.SOCKET

    def keylog_file(self) -> str | None:
        """The key log file this transport's TLS context writes to (None: no TLS secrets ever leave the process)."""
        return getattr(self.tls, "keylog_filename", None)

    def pool_is_proxy(self) -> bool:
        """True when the connection pool forwards through a proxy (or cannot be inspected, which counts as unsafe)."""
        pool = getattr(self, "_pool", None)
        if pool is None:
            return True
        proxy_types = tuple(
            found
            for found in (getattr(httpcore, "AsyncHTTPProxy", None), getattr(httpcore, "AsyncSOCKSProxy", None))
            if isinstance(found, type)
        )
        return isinstance(pool, proxy_types)


# --- startup self-test --------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MeteringSelfTest:
    """The outcome of `run_self_test`: the mode in use and what was measured on the loopback exchange."""

    mode: MeteringMode
    detail: str
    client_out: int = 0
    client_in: int = 0
    server_in: int = 0
    server_out: int = 0


_SELF_TEST_RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"


async def _self_test_once() -> MeteringSelfTest:
    counts = {"in": 0, "out": 0}

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = await reader.read(65536)
            if not chunk:
                break
            data += chunk
        counts["in"] += len(data)
        writer.write(_SELF_TEST_RESPONSE)
        await writer.drain()
        counts["out"] += len(_SELF_TEST_RESPONSE)
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    try:
        port = server.sockets[0].getsockname()[1]
        meter = ByteMeter("self_test")
        transport = MeteringTransport(
            meter=meter, limits=httpx.Limits(max_connections=1, max_keepalive_connections=0), socket_metering=True
        )
        if transport.mode is not MeteringMode.SOCKET:
            await transport.aclose()
            return MeteringSelfTest(MeteringMode.ESTIMATE, "the connection pool does not accept a network backend")
        usage = RequestUsage()
        async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
            with attribute_to(usage):
                response = await client.get(f"http://127.0.0.1:{port}/roxy-metering-self-test")
                await response.aread()
        for _ in range(50):  # the server task may still be finishing its bookkeeping
            if counts["out"]:
                break
            await asyncio.sleep(0.01)
    finally:
        server.close()
        await server.wait_closed()
    exact = usage.bytes_out == counts["in"] and usage.bytes_in == counts["out"] and usage.bytes_out > 0
    detail = "socket counts match the server" if exact else "socket counts differ from the server"
    return MeteringSelfTest(
        MeteringMode.SOCKET if exact else MeteringMode.ESTIMATE,
        detail,
        client_out=usage.bytes_out,
        client_in=usage.bytes_in,
        server_in=counts["in"],
        server_out=counts["out"],
    )


async def run_self_test(timeout_s: float = 5.0) -> MeteringSelfTest:
    """Check on loopback that socket metering counts exactly what a server saw; set the process-wide mode."""
    global _socket_metering_ok
    try:
        async with asyncio.timeout(timeout_s):
            result = await _self_test_once()
    except Exception as exc:
        result = MeteringSelfTest(MeteringMode.ESTIMATE, f"self test failed ({type(exc).__name__})")
    _socket_metering_ok = result.mode is MeteringMode.SOCKET
    return result


def reset_self_test() -> None:
    """Forget the self-test result (tests only)."""
    global _socket_metering_ok
    _socket_metering_ok = None


# --- fallback estimate ---------------------------------------------------------------------------------------------


def _records(size: int) -> int:
    return 0 if size <= 0 else -(-size // TLS_RECORD_PAYLOAD)


def _header_block(raw: list[tuple[bytes, bytes]]) -> int:
    return sum(len(name) + len(value) + 4 for name, value in raw) + 2


@dataclass(frozen=True, slots=True)
class Estimate:
    """A fallback byte estimate: `bytes_out` and `bytes_in` include TLS framing; `overhead` is per connection."""

    bytes_out: int
    bytes_in: int
    overhead: int

    @property
    def total(self) -> int:
        return self.bytes_out + self.bytes_in + self.overhead


def estimate_exchange(
    request: httpx.Request,
    response: httpx.Response | None,
    *,
    tls: bool,
    proxied: bool,
    new_connection: bool,
    tls_overhead_bytes: int,
    proxy_auth_bytes: int = 0,
) -> Estimate:
    """Estimate wire bytes for one HTTP/1.1 exchange when socket metering is unavailable (plan 8.3)."""
    if proxied and not tls:
        target = str(request.url).encode("ascii", "replace")  # a forward proxy gets the absolute URL
    else:
        target = request.url.raw_path
    head_out = len(request.method) + 1 + len(target) + len(b" HTTP/1.1\r\n") + _header_block(request.headers.raw)
    try:
        body_out = len(request.content)
    except httpx.RequestNotRead:
        body_out = 0
    plain_out = head_out + body_out
    plain_in = 0
    if response is not None:
        status_line = len(b"HTTP/1.1 ") + 4 + len(response.reason_phrase.encode("latin-1", "replace")) + 2
        plain_in = status_line + _header_block(response.headers.raw) + response.num_bytes_downloaded
    bytes_out, bytes_in = plain_out, plain_in
    if tls:
        bytes_out += _records(plain_out) * TLS_RECORD_OVERHEAD
        bytes_in += _records(plain_in) * TLS_RECORD_OVERHEAD
    overhead = 0
    if new_connection:
        if tls:
            overhead += tls_overhead_bytes
        if tls and proxied:
            authority = f"{request.url.host}:{request.url.port or 443}".encode("ascii", "replace")
            connect = len(b"CONNECT ") + len(authority) + len(b" HTTP/1.1\r\nHost: ") + len(authority)
            connect += len(b"\r\nAccept: */*\r\n") + proxy_auth_bytes + 2
            overhead += connect + len(CONNECT_RESPONSE)
    return Estimate(bytes_out, bytes_in, overhead)


__all__ = [
    "ByteMeter",
    "Estimate",
    "MeteredNetworkBackend",
    "MeteringMode",
    "MeteringSelfTest",
    "MeteringTransport",
    "RequestUsage",
    "attribute_to",
    "estimate_exchange",
    "reset_self_test",
    "run_self_test",
    "socket_metering_enabled",
    "tls_context",
]
