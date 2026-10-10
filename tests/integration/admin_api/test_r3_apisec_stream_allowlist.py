"""Review round 3 (lens apisec): an open event stream after its network leaves the admin allowlist (D6).

What this is
    Test for finding apisec-8 (fixed; it was a strict xfail). The stream (`GET /admin/api/v1/stream`,
    `admin/sse.py`) checked its caller once, when it opened. Every `SESSION_CHECK_S` it re-reads the session (gone,
    idle, revoked, past its lifetime: the stream ends with `unauthorized`), but it never asked the admin allowlist
    again. When the owner switched the allowlist on (or removed a network from it), every other request from that
    network got the plain 404 at once, while a stream already open from it kept pushing live rows (client addresses,
    URLs, User-Agents), `kpi` and alerts until the session itself ended. Now the stream asks the allowlist on every
    turn of its loop (`Stream._network_allowed`) and ends with no further frame once its network is shut out.

Why it exists
    D6 and plan 9.5: a network that is not listed sees nothing under `/admin`. Turning the allowlist on is how the
    owner shuts a network out (for example after a login alert from an unknown place); a stream that outlives that
    decision is the one door left open. The stream already ends promptly for the session cases (DESIGN.md 13.1).

How it works
    A small ASGI driver (as in `test_sse.py`: httpx's test transport waits for the whole body, a stream never ends)
    opens the stream from 203.0.113.50 with a session signed in from there. The allowlist is then switched on for
    192.0.2.0/24 only. A new request from 203.0.113.50 gets the 404 (control); the open stream should end within a
    few session checks.

What to read next
    `roxy/admin/sse.py` (`Stream.run`, `_session_alive`), `roxy/admin/auth/allowlist.py` (`admin_ip_allowed`),
    `tests/integration/admin_api/test_sse.py` (the stream tests this one follows).
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from roxy.admin import sse

PATH = "/admin/api/v1/stream"
OUTSIDE_IP = "203.0.113.50"


class RawStream:
    """One stream driven over ASGI; `chunks` collects the body as it is sent, `ended` once the body is complete."""

    def __init__(self, app: Any, headers: dict[str, str]) -> None:
        self.app = app
        self.headers = headers
        self.status: int | None = None
        self.chunks: list[bytes] = []
        self.ended = False
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._disconnect = asyncio.Event()
        self._sent = False
        self._task: asyncio.Task[None] | None = None
        self._reader: asyncio.Task[None] | None = None

    async def open(self) -> RawStream:
        scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "https",
            "path": PATH,
            "raw_path": PATH.encode(),
            "query_string": b"events=kpi",
            "root_path": "",
            "headers": [(k.lower().encode(), v.encode()) for k, v in self.headers.items()],
            "client": ("127.0.0.1", 50000),
            "server": ("testserver", 443),
        }

        async def receive() -> dict[str, Any]:
            if not self._sent:
                self._sent = True
                return {"type": "http.request", "body": b"", "more_body": False}
            await self._disconnect.wait()
            return {"type": "http.disconnect"}

        async def send(message: dict[str, Any]) -> None:
            await self._queue.put(dict(message))

        self._task = asyncio.get_running_loop().create_task(self.app(scope, receive, send))
        start = await asyncio.wait_for(self._queue.get(), timeout=10)
        self.status = int(start["status"])
        self._reader = asyncio.get_running_loop().create_task(self._read())
        return self

    async def _read(self) -> None:
        while True:
            message = await self._queue.get()
            if message["type"] == "http.response.body":
                self.chunks.append(bytes(message.get("body", b"")))
                if not message.get("more_body"):
                    self.ended = True
                    return

    async def close(self) -> None:
        self._disconnect.set()
        for task in (self._reader, self._task):
            if task is not None and not task.done():
                try:
                    await asyncio.wait_for(task, timeout=5)
                except (TimeoutError, asyncio.CancelledError):
                    task.cancel()


async def test_an_open_stream_ends_when_its_network_leaves_the_allowlist(
    api_app: Any, api_admin: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sse, "SESSION_CHECK_S", 0.2)
    monkeypatch.setattr(sse, "KPI_INTERVAL_S", 0.2)
    harness = api_app.harness
    browser = harness.new_client()
    signed_in = await harness.login(api_admin, client=browser, ip=OUTSIDE_IP)
    assert signed_in.status_code == 200, signed_in.text
    token = browser.cookies.get("__Host-roxy_session")
    headers = {
        **harness.headers(ip=OUTSIDE_IP),
        "Host": "testserver",
        "Accept": "text/event-stream",
        "Cookie": f"__Host-roxy_session={token}",
    }
    stream = await RawStream(api_app.app, headers).open()
    try:
        assert stream.status == 200
        await harness.allow_admin_cidr("192.0.2.0/24")
        await api_app.settings(admin_allowlist_enabled=1)
        shut_out = await browser.get("/admin/api/v1/settings", headers=harness.headers(ip=OUTSIDE_IP))
        assert shut_out.status_code == 404  # control: every new request from that network is hidden now
        before = len(stream.chunks)
        for _ in range(30):  # 3 s: fifteen session checks
            if stream.ended:
                break
            await asyncio.sleep(0.1)
        sent_after = b"".join(stream.chunks[before:])
        assert stream.ended, f"still streaming {len(sent_after)} bytes later: {sent_after[:160]!r}"
        assert b"event: unauthorized" not in sent_after  # a shut-out network is told nothing, not even that
        assert api_app.app.state.sse_hub.local_streams == {}  # the stream gave its slot back
    finally:
        await stream.close()
