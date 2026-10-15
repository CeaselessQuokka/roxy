"""A mock Roblox for load tests: every Roblox host on one loopback port, rate limited per endpoint like Roblox.

What this is
    `MockRoblox`, an asyncio HTTP/1.1 server (keep-alive, Content-Length bodies) running on its own event loop in
    a background thread. Roxy reaches it through the development-only egress override `ROXY_TEST_UPSTREAM_BASE`,
    which rewrites every Roblox URL to this server and names the original host in the `X-Roxy-Test-Host` header.
    Each call is matched to an `Endpoint` (host, method and a path pattern), answered after the endpoint's latency,
    and logged as a `CallRecord`.

Why it exists
    Plan 19.10 row 7 asks for "a mock that rate-limits per endpoint at realistic thresholds", and plan 19.4 for a
    Roblox mock that answers 429 on one endpoint. The existing multi-process mock (tests/multiprocess) answers
    every call at once and limits nothing; load tests need latency (it decides how many callers overlap and can be
    coalesced), limits, and a call log cheap enough for thousands of calls a second.

How it works
    - Limits: Roblox's limits for anonymous traffic are per source address and per endpoint, and every Roxy call
      leaves from the one server address, so each endpoint has one `SlidingWindow`: a call is refused when `limit`
      calls (refused ones included, as a hammering client stays limited) arrived in the last 60 s. The window keeps
      only the newest `limit` arrival times (a bounded deque): that is enough to answer "were there `limit` calls in
      the last 60 s", because those are the newest ones.
    - A refusal is Roblox's usual one: status 429, `{"errors":[{"code":0,"message":"Too many requests"}]}`, and no
      `Retry-After` (Roblox's web APIs rarely send one), unless the endpoint sets `retry_after`. An endpoint with
      `always_429` refuses every call (the 19.4 "429 on one endpoint" scenario).
    - Bodies are deterministic JSON of roughly `body_bytes` bytes, so two fetches of one key return the same bytes.
    - The log is bounded (`MAX_RECORDS`; later calls are counted in `overflow` instead of stored). Times are the
      harness clock (`clock.now()`: the wall clock Roxy paces itself by, never stepping back), which every process
      of the machine shares, so call times line up with the client's request times and a mock "minute" is as
      long as Roxy's. `peak_in_window` replays the window over a list of call times (how close an endpoint came).

What to read next
    `traffic.py` (where the endpoint table and its thresholds come from), then `fleet.py`.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import re
import threading
from collections import Counter, deque
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Final
from urllib.parse import urlsplit

from load import clock

MAX_RECORDS: Final = 1_000_000
"""At most this many calls are kept in the log (plan P9: every list is bounded); the rest are only counted."""

WINDOW_S: Final = 60.0
"""The length of every endpoint's sliding window (Roblox states its limits per minute)."""

TOO_MANY: Final = b'{"errors":[{"code":0,"message":"Too many requests"}]}'
"""Roblox's usual 429 body."""

TEST_HOST_HEADER: Final = "x-roxy-test-host"
"""The header naming the original Roblox host (`roxy/egress/targets.py TEST_HOST_HEADER`, lowercased)."""

_REASONS: Final = {200: "OK", 404: "Not Found", 429: "Too Many Requests"}


def peak_in_window(times: Sequence[float], window_s: float = WINDOW_S) -> int:
    """The most calls that ever sat in one window as `SlidingWindow` counts them: for each call at `t`, the calls in
    `(t - window_s, t]` (itself included). An endpoint with limit `L` refused a call exactly when this exceeds `L`,
    so `L - peak_in_window(...)` is how close the endpoint came to Roblox's threshold (its headroom)."""
    ordered = sorted(times)
    best = 0
    first = 0
    for index, at in enumerate(ordered):
        while at - ordered[first] >= window_s:  # the mock refuses when `now - oldest < window_s`
            first += 1
        best = max(best, index - first + 1)
    return best


class SlidingWindow:
    """At most `limit` calls in any `window_s` seconds, counting refused calls too (bounded memory)."""

    def __init__(self, limit: int, window_s: float = WINDOW_S) -> None:
        self.limit = limit
        self.window_s = window_s
        self._arrivals: deque[float] = deque(maxlen=max(1, limit))

    def admit(self, now: float) -> bool:
        """Record one call at `now`; True when it is within the limit, False when it must be refused."""
        if self.limit <= 0:
            return True  # 0 means "no limit"
        full = len(self._arrivals) == self.limit and now - self._arrivals[0] < self.window_s
        self._arrivals.append(now)  # every call counts, refused or not; maxlen drops the oldest
        return not full


@dataclass(frozen=True, slots=True)
class Endpoint:
    """One Roblox endpoint the mock knows: how to recognize it and how it behaves."""

    name: str
    method: str
    host: str
    path: str
    """A regular expression for the whole path (`fullmatch`), for example `/v1/users/\\d+`."""
    limit_per_min: int = 0
    """Calls allowed in any 60 s from Roxy's one address; 0 means unlimited."""
    latency_s: float = 0.05
    body_bytes: int = 600
    always_429: bool = False
    retry_after: str | None = None


@dataclass(frozen=True, slots=True)
class CallRecord:
    at: float
    """`clock.now()` (the harness clock) when the request head arrived."""
    endpoint: str
    status: int
    cookie: bool
    """True when the call carried a Cookie header (Roxy's own credential probes do; caller traffic never may)."""


@dataclass(slots=True)
class _Compiled:
    spec: Endpoint
    pattern: re.Pattern[str]
    window: SlidingWindow


@dataclass(slots=True)
class MockStats:
    calls: int = 0
    overflow: int = 0
    by_endpoint: Counter[str] = field(default_factory=Counter)
    refused: Counter[str] = field(default_factory=Counter)


class MockRoblox:
    """The mock server. `start()` returns once it listens; `stop()` closes it. Thread-safe snapshots."""

    def __init__(self, endpoints: list[Endpoint], *, default_latency_s: float = 0.02) -> None:
        self._endpoints = [
            _Compiled(spec, re.compile(spec.path), SlidingWindow(spec.limit_per_min)) for spec in endpoints
        ]
        self._default_latency_s = default_latency_s
        self._records: list[CallRecord] = []
        self._stats = MockStats()
        self._lock = threading.Lock()
        self._bodies: dict[tuple[str, str], bytes] = {}
        self.port = 0
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run, name="mock-roblox", daemon=True)
        self._server: asyncio.AbstractServer | None = None
        self._ticker: asyncio.Future[None] | None = None

    # ------------------------------------------------------------------------------------------------ control

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> MockRoblox:
        self._thread.start()
        if not self._ready.wait(10):
            raise RuntimeError("the mock Roblox server did not start")
        return self

    def stop(self) -> None:
        def close() -> None:
            if self._server is not None:
                self._server.close()
            self._loop.stop()

        with contextlib.suppress(RuntimeError):
            self._loop.call_soon_threadsafe(close)
        self._thread.join(timeout=5)

    def records(self) -> list[CallRecord]:
        with self._lock:
            return list(self._records)

    def stats(self) -> MockStats:
        with self._lock:
            return MockStats(
                self._stats.calls, self._stats.overflow, Counter(self._stats.by_endpoint), Counter(self._stats.refused)
            )

    # ------------------------------------------------------------------------------------------------ server

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)

        async def serve() -> None:
            self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0, backlog=1024)
            self.port = int(self._server.sockets[0].getsockname()[1])
            self._ticker = asyncio.ensure_future(clock.tick_forever())  # see clock.tick_forever
            self._ready.set()

        self._loop.run_until_complete(serve())
        self._loop.run_forever()
        if self._ticker is not None:  # stopped: let the ticker see its cancellation before the thread ends
            self._ticker.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                self._loop.run_until_complete(self._ticker)

    def _match(self, method: str, host: str, path: str) -> _Compiled | None:
        for item in self._endpoints:
            if item.spec.method == method and item.spec.host == host and item.pattern.fullmatch(path):
                return item
        return None

    def _body(self, endpoint: str, key: str, size: int) -> bytes:
        cached = self._bodies.get((endpoint, key))
        if cached is not None:
            return cached
        digest = hashlib.sha256(key.encode()).hexdigest()
        filler = (digest * (size // len(digest) + 1))[: max(0, size - 80)]
        body = json.dumps({"endpoint": endpoint, "id": digest[:12], "data": filler}).encode()
        if len(self._bodies) < 100_000:  # bounded memo (P9)
            self._bodies[(endpoint, key)] = body
        return body

    def decide(self, method: str, host: str, target: str, cookie: bool) -> tuple[int, dict[str, str], bytes, float]:
        """Status, headers, body and delay for one call; records it. Runs on the server loop thread only (the
        windows need no lock); the log and counters are written under the lock that snapshots read."""
        now = clock.now()  # Roxy's time line, so the mock's minute is as long as Roxy's (clock.py)
        parts = urlsplit(target)
        item = self._match(method, host, parts.path)
        name = item.spec.name if item is not None else "other"
        headers: dict[str, str] = {}
        if item is None:
            status, body, delay = 200, self._body(name, target, 300), self._default_latency_s
        else:
            spec = item.spec
            delay = spec.latency_s
            if spec.always_429 or not item.window.admit(now):
                status, body = 429, TOO_MANY
                if spec.retry_after is not None:
                    headers["Retry-After"] = spec.retry_after
            else:
                status, body = 200, self._body(name, target, spec.body_bytes)
        with self._lock:
            self._stats.calls += 1
            self._stats.by_endpoint[name] += 1
            if status == 429:
                self._stats.refused[name] += 1
            if len(self._records) < MAX_RECORDS:
                self._records.append(CallRecord(now, name, status, cookie))
            else:
                self._stats.overflow += 1
        return status, headers, body, delay

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                try:
                    head = await reader.readuntil(b"\r\n\r\n")
                except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError):
                    return
                lines = head.decode("latin-1").split("\r\n")
                method, target, _version = lines[0].split(" ", 2)
                headers: dict[str, str] = {}
                for line in lines[1:]:
                    if ":" in line:
                        name, value = line.split(":", 1)
                        headers[name.strip().lower()] = value.strip()
                length = int(headers.get("content-length") or 0)
                if length:
                    await reader.readexactly(length)
                host = headers.get(TEST_HOST_HEADER) or headers.get("host", "")
                status, extra, body, delay = self.decide(method, host, target, "cookie" in headers)
                if delay > 0:
                    await asyncio.sleep(delay)
                out = [f"HTTP/1.1 {status} {_REASONS.get(status, 'Status')}", "Content-Type: application/json"]
                out += [f"{name}: {value}" for name, value in extra.items()]
                out.append(f"Content-Length: {len(body)}")
                writer.write(("\r\n".join(out) + "\r\n\r\n").encode("latin-1") + body)
                await writer.drain()
                if headers.get("connection", "").lower() == "close":
                    return
        except (ConnectionError, ValueError):
            return
        finally:
            with contextlib.suppress(Exception):
                writer.close()


__all__ = [
    "MAX_RECORDS",
    "TOO_MANY",
    "CallRecord",
    "Endpoint",
    "MockRoblox",
    "MockStats",
    "SlidingWindow",
    "peak_in_window",
]
