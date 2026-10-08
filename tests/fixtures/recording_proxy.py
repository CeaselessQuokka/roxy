"""Egress test harness: a recording forward proxy, a mock Roblox upstream, fake settings and a leak scanner.

What this is
    * `RecordingProxy`: a loopback HTTP forward proxy that records every byte it relays on the client side. It
      handles absolute-form requests (`GET http://host/path`, plain http targets), CONNECT as a blind tunnel to a
      TLS upstream, and CONNECT with TLS interception (it terminates TLS with a certificate from a test CA made by
      `trustme`, records the plaintext, and forwards it to the plain mock upstream). Like DataImpulse it gives
      each connection an "exit IP", the same one for every connection of one `sessid-<x>` proxy user name.
    * `MockUpstream`: a loopback HTTP (or HTTPS) server standing in for Roblox and the IP echo service. It
      records requests and answers from programmable routes.
    * `FakeSettings`, `leak_findings`, `make_ca` and `client_ssl_context`.
    It can also run on its own for multi-process tests: `python tests/fixtures/recording_proxy.py --port 0
    --upstream 127.0.0.1:18080 --log exchanges.jsonl` prints its port and writes one JSON line per exchange.

Why it exists
    Plan 19.5 item 4 asks for an end-to-end check that the bytes leaving through the rotator never contain the
    credential or its cookie name, with plain HTTP for inspection and a TLS-intercepting variant with a test CA,
    and 19.10 row 8 compares Roxy's byte meter with the raw socket byte count of such a proxy. Tests never leave
    the machine (19.12), so the "internet" is these two loopback servers.

How it works
    Plain threads and blocking sockets, one thread per connection, so the servers work beside any event loop.
    Raw counting happens on the client-facing socket, so it includes the CONNECT exchange, TLS handshakes and TLS
    record framing, which is what a paid proxy bills. TLS interception uses `ssl.MemoryBIO`: raw records are read
    from the socket (and counted), fed to an `SSLObject`, and the decrypted bytes are recorded separately.
    Tests load this file by path (`importlib`), like the other fixtures under `tests/fixtures`.

What to read next
    `tests/unit/egress/test_metering.py` and `tests/security/test_credential_suite.py` (the users).
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import http.server
import json
import select
import socket
import ssl
import sys
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

TOKEN_PREFIX = (
    "_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-"
    "items.|_"
)
"""Public text at the start of every Roblox cookie (same as roxy.core.redact.TOKEN_PREFIX)."""

ROBLOX_TEST_HOSTS = ("games.roblox.com", "users.roblox.com", "thumbnails.roblox.com", "localhost", "127.0.0.1")


# ------------------------------------------------------------------------------------------------ helpers


def leak_findings(blob: bytes, value: str, *, window: int = 24) -> list[str]:
    """What of the credential `value` appears in `blob`: the value, the cookie name, or a 24+ char piece."""
    found: list[str] = []
    folded = blob.lower()
    if value.encode("utf-8") in blob:
        found.append("full value")
    if b".roblosecurity" in folded:
        found.append("cookie name")
    secret = value.removeprefix(TOKEN_PREFIX).encode("utf-8").lower()
    for start in range(max(0, len(secret) - window + 1)):
        if secret[start : start + window] in folded:
            found.append(f"piece at {start}")
            break
    return found


class FakeSettings:
    """A settings object with the `RuntimeSettings` read API: catalog defaults plus test overrides."""

    def __init__(self, **overrides: Any) -> None:
        from roxy.config.catalog import defaults

        self._values = defaults()
        self._values.update(overrides)

    def get(self, key: str) -> Any:
        return self._values[key]

    def set(self, key: str, value: Any) -> None:
        self._values[key] = value

    def int(self, key: str) -> int:
        return int(self._values[key])

    def float(self, key: str) -> float:
        return float(self._values[key])

    def bool(self, key: str) -> bool:
        return bool(self._values[key])

    def str(self, key: str) -> str:
        return str(self._values[key])

    def list(self, key: str) -> list[Any]:
        return list(self._values[key])


def make_ca() -> Any:
    """A throwaway test certificate authority (trustme). Its certificates are trusted only by test contexts."""
    import trustme

    return trustme.CA()


def client_ssl_context(ca: Any) -> ssl.SSLContext:
    """A client context that trusts only `ca` (what the egress clients get as `tls_verify` in tests)."""
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ca.configure_trust(context)
    return context


def server_ssl_context(ca: Any, hosts: tuple[str, ...] = ROBLOX_TEST_HOSTS) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ca.issue_cert(*hosts).configure_cert(context)
    context.set_alpn_protocols(["http/1.1"])
    return context


def _split_head(data: bytes) -> tuple[bytes, bytes] | None:
    index = data.find(b"\r\n\r\n")
    if index < 0:
        return None
    return data[: index + 4], data[index + 4 :]


def _parse_head(head: bytes) -> tuple[str, list[tuple[str, str]]]:
    lines = head.decode("latin-1").split("\r\n")
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            headers.append((name.strip(), value.strip()))
    return lines[0], headers


def _header(headers: list[tuple[str, str]], name: str) -> str | None:
    for key, value in headers:
        if key.lower() == name.lower():
            return value
    return None


# ------------------------------------------------------------------------------------------------ mock upstream


@dataclass
class RecordedRequest:
    method: str
    path: str
    headers: list[tuple[str, str]]
    body: bytes

    def header(self, name: str) -> str | None:
        return _header(self.headers, name)


@dataclass
class MockResponse:
    status: int = 200
    body: bytes = b'{"ok":true}'
    headers: list[tuple[str, str]] = field(default_factory=lambda: [("Content-Type", "application/json")])
    delay_s: float = 0.0


Route = MockResponse | Callable[[RecordedRequest], MockResponse]


class MockUpstream:
    """A loopback server that records requests and answers from `routes` (path without query -> response)."""

    def __init__(self, *, tls_context: ssl.SSLContext | None = None) -> None:
        self.requests: list[RecordedRequest] = []
        self.routes: dict[str, Route] = {}
        self._lock = threading.Lock()
        self._tls_context = tls_context
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                return None

            def _serve(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                record = RecordedRequest(self.command, self.path, list(self.headers.items()), body)
                with owner._lock:
                    owner.requests.append(record)
                response = owner._answer(record)
                if response.delay_s:
                    time.sleep(response.delay_s)
                self.send_response(response.status)
                for name, value in response.headers:
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(response.body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(response.body)

            do_GET = do_POST = do_HEAD = do_PUT = do_PATCH = do_DELETE = _serve

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        if tls_context is not None:
            self._server.socket = tls_context.wrap_socket(self._server.socket, server_side=True)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.05}, name="mock-upstream", daemon=True
        )

    def _answer(self, record: RecordedRequest) -> MockResponse:
        path = record.path.split("?", 1)[0]
        route = self.routes.get(path)
        if route is None:
            if path == "/ip":
                exit_ip = record.header("X-Exit-Ip") or "203.0.113.1"
                return MockResponse(body=json.dumps({"ip": exit_ip}).encode())
            payload = {
                "path": record.path,
                "host": record.header("Host"),
                "test_host": record.header("X-Roxy-Test-Host"),
                "method": record.method,
            }
            return MockResponse(body=json.dumps(payload).encode())
        return route(record) if callable(route) else route

    @property
    def address(self) -> tuple[str, int]:
        return "127.0.0.1", self.port

    @property
    def base_url(self) -> str:
        scheme = "https" if self._tls_context is not None else "http"
        return f"{scheme}://127.0.0.1:{self.port}"

    def start(self) -> MockUpstream:
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def __enter__(self) -> MockUpstream:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    def all_bytes(self) -> bytes:
        with self._lock:
            return b"".join(
                (r.method + " " + r.path).encode() + b"".join(f"{k}: {v}".encode() for k, v in r.headers) + r.body
                for r in self.requests
            )


# ------------------------------------------------------------------------------------------------ recording proxy


@dataclass
class ProxyExchange:
    """One client connection to the proxy."""

    kind: str = "unknown"  # forward, tunnel or intercept
    target: str = ""
    username: str | None = None
    exit_ip: str = ""
    bytes_from_client: int = 0
    bytes_to_client: int = 0
    raw: bytearray = field(default_factory=bytearray)
    plaintext: bytearray = field(default_factory=bytearray)
    requests: int = 0
    closed: bool = False

    @property
    def raw_total(self) -> int:
        return self.bytes_from_client + self.bytes_to_client


class _ClientSide:
    """The client socket with counting and recording."""

    def __init__(self, sock: socket.socket, exchange: ProxyExchange) -> None:
        self.sock = sock
        self.exchange = exchange

    def recv(self, size: int = 65536) -> bytes:
        try:
            data = self.sock.recv(size)
        except OSError:
            return b""
        self.exchange.bytes_from_client += len(data)
        self.exchange.raw += data
        return data

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)
        self.exchange.bytes_to_client += len(data)
        self.exchange.raw += data


class _TlsServerPipe:
    """Server-side TLS over the counted client socket with MemoryBIO, so raw records stay countable."""

    def __init__(self, side: _ClientSide, context: ssl.SSLContext, leftover: bytes) -> None:
        self.side = side
        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        self.tls = context.wrap_bio(self.incoming, self.outgoing, server_side=True)
        if leftover:
            self.incoming.write(leftover)

    def _flush(self) -> None:
        data = self.outgoing.read()
        if data:
            self.side.send(data)

    def _fill(self) -> bool:
        data = self.side.recv()
        if not data:
            self.incoming.write_eof()
            return False
        self.incoming.write(data)
        return True

    def handshake(self) -> None:
        while True:
            try:
                self.tls.do_handshake()
                self._flush()
                return
            except ssl.SSLWantReadError:
                self._flush()
                if not self._fill():
                    raise ConnectionError("client closed during the TLS handshake") from None

    def recv(self, size: int = 65536) -> bytes:
        while True:
            try:
                data = self.tls.read(size)
                self._flush()
                return data
            except ssl.SSLWantReadError:
                self._flush()
                if not self._fill():
                    return b""
            except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
                return b""

    def send(self, data: bytes) -> None:
        self.tls.write(data)
        self._flush()


def _read_message(recv: Callable[[], bytes], buffered: bytes) -> tuple[bytes, bytes, bytes] | None:
    """Read one HTTP message (head, body by Content-Length) from `recv`. Returns (head, body, leftover)."""
    data = buffered
    while _split_head(data) is None:
        chunk = recv()
        if not chunk:
            return None
        data += chunk
    split = _split_head(data)
    assert split is not None
    head, rest = split
    _, headers = _parse_head(head)
    length = int(_header(headers, "Content-Length") or 0)
    while len(rest) < length:
        chunk = recv()
        if not chunk:
            break
        rest += chunk
    return head, rest[:length], rest[length:]


def _fetch_upstream(address: tuple[str, int], request: bytes) -> bytes:
    """Send one request (with Connection: close) to a plain upstream and read the whole answer."""
    with socket.create_connection(address, timeout=10) as upstream:
        upstream.sendall(request)
        chunks = []
        while True:
            chunk = upstream.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks)


def _rebuild_request(method: str, target: str, headers: list[tuple[str, str]], body: bytes, exit_ip: str) -> bytes:
    lines = [f"{method} {target} HTTP/1.1"]
    for name, value in headers:
        if name.lower() in ("proxy-authorization", "proxy-connection", "connection", "keep-alive"):
            continue
        lines.append(f"{name}: {value}")
    lines.append(f"X-Exit-Ip: {exit_ip}")
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


def _keepalive_response(raw: bytes) -> bytes:
    """An upstream answer with its Connection header removed (the proxy keeps the client connection open)."""
    split = _split_head(raw)
    if split is None:
        return raw
    head, body = split
    status_line, headers = _parse_head(head)
    kept = [(k, v) for k, v in headers if k.lower() not in ("connection", "keep-alive")]
    if _header(kept, "Content-Length") is None:
        kept.append(("Content-Length", str(len(body))))
    lines = [status_line, *(f"{k}: {v}" for k, v in kept)]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


class RecordingProxy:
    """A loopback forward proxy that records every client-side byte (see the module docstring)."""

    def __init__(
        self,
        *,
        upstream: tuple[str, int] | None = None,
        intercept_context: ssl.SSLContext | None = None,
        tunnel_upstream: tuple[str, int] | None = None,
    ) -> None:
        self.upstream = upstream
        self.intercept_context = intercept_context
        self.tunnel_upstream = tunnel_upstream
        self.exchanges: list[ProxyExchange] = []
        self._lock = threading.Lock()
        self._threads: list[threading.Thread] = []
        self._client_sockets: set[socket.socket] = set()
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(64)
        self.port = self._listener.getsockname()[1]
        self._stopping = False
        self._connection_counter = 0
        self._accept_thread = threading.Thread(target=self._accept_loop, name="recording-proxy", daemon=True)

    # --- lifecycle

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def url_with_auth(self, user: str, password: str) -> str:
        return f"http://{user}:{password}@127.0.0.1:{self.port}"

    def start(self) -> RecordingProxy:
        self._accept_thread.start()
        return self

    def stop(self) -> None:
        self._stopping = True
        with contextlib.suppress(OSError):
            self._listener.close()
        # Kept-alive client connections would hold their handler threads in recv(); end them first.
        with self._lock:
            open_sockets = list(self._client_sockets)
        for sock in open_sockets:
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
        for thread in list(self._threads):
            thread.join(timeout=2)

    def __enter__(self) -> RecordingProxy:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # --- results

    def all_recorded(self) -> bytes:
        with self._lock:
            return b"".join(bytes(ex.raw) + bytes(ex.plaintext) for ex in self.exchanges)

    def raw_total(self) -> int:
        with self._lock:
            return sum(ex.raw_total for ex in self.exchanges)

    def wait_settled(self, timeout_s: float = 2.0) -> None:
        """Wait until every handler thread has finished its bookkeeping (counts stop moving)."""
        deadline = time.monotonic() + timeout_s
        last = -1
        while time.monotonic() < deadline:
            current = self.raw_total()
            if current == last:
                return
            last = current
            time.sleep(0.05)

    # --- serving

    def _accept_loop(self) -> None:
        while not self._stopping:
            try:
                client, _ = self._listener.accept()
            except OSError:
                return
            thread = threading.Thread(target=self._handle, args=(client,), daemon=True)
            self._threads.append(thread)
            thread.start()

    def _exit_ip(self, username: str | None) -> str:
        if username and "sessid-" in username:
            session = username.split("sessid-", 1)[1].split("-", 1)[0]
            digest = hashlib.sha256(session.encode()).digest()
            return f"203.0.113.{digest[0] % 200 + 1}"
        with self._lock:
            self._connection_counter += 1
            counter = self._connection_counter
        return f"198.51.100.{counter % 250 + 1}"

    def _handle(self, sock: socket.socket) -> None:
        exchange = ProxyExchange()
        with self._lock:
            self.exchanges.append(exchange)
            self._client_sockets.add(sock)
        side = _ClientSide(sock, exchange)
        try:
            first = _read_message(side.recv, b"")
            if first is None:
                return
            head, body, leftover = first
            request_line, headers = _parse_head(head)
            method, target, _ = request_line.split(" ", 2)
            auth = _header(headers, "Proxy-Authorization")
            if auth and auth.lower().startswith("basic "):
                decoded = base64.b64decode(auth[6:]).decode("utf-8", "replace")
                exchange.username = decoded.split(":", 1)[0]
            exchange.exit_ip = self._exit_ip(exchange.username)
            exchange.target = target
            if method == "CONNECT":
                side.send(b"HTTP/1.1 200 Connection established\r\n\r\n")
                if self.intercept_context is not None:
                    exchange.kind = "intercept"
                    self._intercept(side, exchange, leftover)
                else:
                    exchange.kind = "tunnel"
                    self._tunnel(side, leftover)
                return
            exchange.kind = "forward"
            self._forward_loop(side, exchange, method, target, headers, body, leftover)
        except (OSError, ConnectionError, ValueError):
            return
        finally:
            exchange.closed = True
            with self._lock:
                self._client_sockets.discard(sock)
            with contextlib.suppress(OSError):
                sock.close()

    def _forward_address(self, target: str) -> tuple[str, int]:
        from urllib.parse import urlsplit

        parts = urlsplit(target)
        host = parts.hostname or ""
        if host in ("127.0.0.1", "localhost") and parts.port:
            return "127.0.0.1", parts.port
        if self.upstream is None:
            raise ValueError("no upstream for a non-loopback target")
        return self.upstream

    def _forward_loop(
        self,
        side: _ClientSide,
        exchange: ProxyExchange,
        method: str,
        target: str,
        headers: list[tuple[str, str]],
        body: bytes,
        leftover: bytes,
    ) -> None:
        while True:
            from urllib.parse import urlsplit

            parts = urlsplit(target)
            origin_form = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
            request = _rebuild_request(method, origin_form, headers, body, exchange.exit_ip)
            exchange.requests += 1
            answer = _fetch_upstream(self._forward_address(target), request)
            side.send(_keepalive_response(answer))
            nxt = _read_message(side.recv, leftover)
            if nxt is None:
                return
            head, body, leftover = nxt
            request_line, headers = _parse_head(head)
            method, target, _ = request_line.split(" ", 2)

    def _tunnel(self, side: _ClientSide, leftover: bytes) -> None:
        if self.tunnel_upstream is None:
            return
        with socket.create_connection(self.tunnel_upstream, timeout=10) as upstream:
            if leftover:
                upstream.sendall(leftover)
            sockets = [side.sock, upstream]
            while True:
                readable, _, _ = select.select(sockets, [], [], 10)
                if not readable:
                    return
                for ready in readable:
                    if ready is side.sock:
                        data = side.recv()
                        if not data:
                            return
                        upstream.sendall(data)
                    else:
                        data = upstream.recv(65536)
                        if not data:
                            return
                        side.send(data)

    def _intercept(self, side: _ClientSide, exchange: ProxyExchange, leftover: bytes) -> None:
        assert self.intercept_context is not None
        pipe = _TlsServerPipe(side, self.intercept_context, leftover)
        pipe.handshake()
        buffered = b""
        while True:
            message = _read_message(pipe.recv, buffered)
            if message is None:
                return
            head, body, buffered = message
            exchange.plaintext += head + body
            request_line, headers = _parse_head(head)
            method, target, _ = request_line.split(" ", 2)
            if self.upstream is None:
                return
            exchange.requests += 1
            answer = _keepalive_response(
                _fetch_upstream(self.upstream, _rebuild_request(method, target, headers, body, exchange.exit_ip))
            )
            exchange.plaintext += answer
            pipe.send(answer)


# ------------------------------------------------------------------------------------------------ CLI


def main(argv: list[str] | None = None) -> int:
    """Run a recording proxy until interrupted (multi-process tests). Prints the port on the first line."""
    parser = argparse.ArgumentParser(description="Loopback recording forward proxy for Roxy tests.")
    parser.add_argument("--upstream", default="", help="host:port of the plain mock upstream (loopback only)")
    parser.add_argument("--log", default="", help="append one JSON line per finished exchange to this file")
    args = parser.parse_args(argv)
    upstream: tuple[str, int] | None = None
    if args.upstream:
        host, _, port = args.upstream.rpartition(":")
        if host not in ("127.0.0.1", "localhost"):
            parser.error("--upstream must be a loopback address")
        upstream = ("127.0.0.1", int(port))
    proxy = RecordingProxy(upstream=upstream).start()
    print(proxy.port, flush=True)
    written = 0
    try:
        while True:
            time.sleep(0.5)
            if not args.log:
                continue
            with proxy._lock:
                done: list[ProxyExchange] = []
                for ex in proxy.exchanges[written:]:
                    if not ex.closed:
                        break  # keep the file in connection order
                    done.append(ex)
            if not done:
                continue
            with open(args.log, "a", encoding="utf-8") as handle:
                for ex in done:
                    record = {
                        "kind": ex.kind,
                        "target": ex.target,
                        "raw_total": ex.raw_total,
                        "raw_b64": base64.b64encode(bytes(ex.raw)).decode(),
                    }
                    handle.write(json.dumps(record) + "\n")
            written += len(done)
    except KeyboardInterrupt:
        return 0
    finally:
        proxy.stop()


def iter_exchanges(path: str) -> Iterator[dict[str, Any]]:
    """Read the JSON lines a CLI proxy wrote."""
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


if __name__ == "__main__":
    sys.exit(main())
