"""Cross-worker event stream delivery (plan 14.11, C6): a dashboard connected to worker A sees what worker B did.

What this is
    Worker A is the real app (lifespan started, a signed-in admin, its `events` tail running) with one open
    `GET /admin/api/v1/stream`. Worker B is a separate process (spawned, its own `Database` objects and its own
    `MetricsRecorder`, nothing shared in memory) that records one proxy request and one breaker event into the same
    metrics.db and exits. The stream on worker A must deliver both, B's request as a `live` frame matching the
    stream's filter and B's breaker as a `breaker` frame, each exactly once and with its `events` row id.

Why it exists
    v1 merged each worker's live list through a JSON file, so a dashboard saw another worker's requests late or not
    at all (row 81). The integration tests run every worker in one process; only a second process shows that
    nothing but the shared database carries the events from one worker's recorder to another worker's stream.

How it works
    The stream is read through a small ASGI driver (httpx's test transport waits for a response to finish, which
    a stream never does). Worker B uses the `spawn` start method, so it inherits nothing from the test process.

What to read next
    `roxy/admin/sse.py`, `roxy/metrics/live.py` (`EventTail`), `tests/integration/admin_api/test_sse.py`.
"""

from __future__ import annotations

import asyncio
import json
import multiprocessing as mp
import random
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import pytest

import roxy.admin.api  # noqa: F401 - first: the API package mounts roxy.admin.sse
from roxy.admin.auth.testing import auth_harness
from roxy.config import catalog
from roxy.core.clock import FakeClock
from roxy.core.reasons import AuthClass, CacheState, Egress, Outcome, ReasonCode, Source
from roxy.metrics.recorder import MetricsRecorder, OutcomeEvent
from roxy.storage.db import DB_NAMES, Database, Databases

pytestmark = [
    pytest.mark.multiprocess,
    pytest.mark.skipif(sys.platform == "win32", reason="POSIX multiprocessing semantics"),
]

CTX = mp.get_context("spawn")
PATH = "/admin/api/v1/stream"
OTHER_WORKER_REQUEST = "W" * 26
OTHER_WORKER_CLIENT = "198.51.100.77"


class _Settings:
    """Catalog defaults: what worker B's recorder reads (no runtime settings store in the child)."""

    def __init__(self) -> None:
        self.values = catalog.defaults()
        self.version = 1

    def get(self, key: str) -> Any:
        return self.values[key]


def _worker_b(paths: dict[str, str], now: float) -> None:
    """Another worker: record one refused request and one breaker event, write them, exit."""
    dbs = Databases(
        **{name: Database(name, paths[name]) for name in DB_NAMES}, paths={k: Path(v) for k, v in paths.items()}
    )
    clock = FakeClock(now)
    recorder = MetricsRecorder(dbs, _Settings(), clock, worker_id="worker-b", rng=random.Random(7).random)
    recorder.record_outcome(
        OutcomeEvent(
            at_ms=clock.now_ms(),
            request_id=OTHER_WORKER_REQUEST,
            endpoint_template="games.roblox.com/v1/games",
            host="games.roblox.com",
            method="GET",
            egress=Egress.NONE,
            outcome=Outcome.REFUSED,
            reason=ReasonCode.THROTTLE,
            status=429,
            source=Source.ROXY,
            cache_state=CacheState.NA,
            auth_class=AuthClass.ANON,
            caller_bytes_in=100,
            caller_bytes_out=60,
            upstream_calls=0,
            upstream_bytes_in=0,
            upstream_bytes_out=0,
            latency_ms=3.0,
            queue_wait_ms=0.0,
            upstream_ms=0.0,
            client_ip=OTHER_WORKER_CLIENT,
            place_id="31337",
            user_agent="Roblox/Linux",
            bypass=False,
            error=False,
        )
    )
    recorder.record_event("breaker_open", "warning", "upstream_cooldown", {"key": "direct:games.roblox.com", "by": "b"})
    recorder.close()  # writes everything synchronously, the open minute included
    dbs.close_all_sync()


class _Stream:
    """Reads one SSE response chunk by chunk over ASGI."""

    def __init__(self, app: Any, headers: dict[str, str], params: dict[str, str]) -> None:
        self.app, self.headers, self.params = app, headers, params
        self.queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self.disconnect = asyncio.Event()
        self.buffer = ""
        self.sent = False
        self.task: asyncio.Task[None] | None = None
        self.status = 0

    async def open(self) -> None:
        scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "https",
            "path": PATH,
            "raw_path": PATH.encode(),
            "query_string": urlencode(self.params).encode(),
            "root_path": "",
            "headers": [(k.lower().encode(), v.encode()) for k, v in self.headers.items()],
            "client": ("127.0.0.1", 50000),
            "server": ("testserver", 443),
        }

        async def receive() -> dict[str, Any]:
            if not self.sent:
                self.sent = True
                return {"type": "http.request", "body": b"", "more_body": False}
            await self.disconnect.wait()
            return {"type": "http.disconnect"}

        async def send(message: dict[str, Any]) -> None:
            await self.queue.put(dict(message))

        self.task = asyncio.get_running_loop().create_task(self.app(scope, receive, send))
        start = await asyncio.wait_for(self.queue.get(), timeout=10)
        self.status = int(start["status"])

    async def frames(self, seconds: float) -> list[tuple[str, int | None, Any]]:
        """Every data frame that arrives within `seconds`: `(event, id, data)`."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + seconds
        out: list[tuple[str, int | None, Any]] = []
        while loop.time() < deadline:
            try:
                message = await asyncio.wait_for(self.queue.get(), timeout=max(0.01, deadline - loop.time()))
            except TimeoutError:
                break
            self.buffer += bytes(message.get("body", b"")).decode()
            while "\n\n" in self.buffer:
                block, self.buffer = self.buffer.split("\n\n", 1)
                event, ident, data = "message", None, None
                for line in block.split("\n"):
                    if line.startswith("event: "):
                        event = line[7:]
                    elif line.startswith("id: "):
                        ident = int(line[4:])
                    elif line.startswith("data: "):
                        data = json.loads(line[6:])
                if data is not None:
                    out.append((event, ident, data))
        return out

    async def close(self) -> None:
        self.disconnect.set()
        if self.task is not None:
            try:
                await asyncio.wait_for(self.task, timeout=5)
            except (TimeoutError, asyncio.CancelledError):
                self.task.cancel()


@pytest.mark.timeout(120)
async def test_a_stream_on_worker_a_delivers_what_worker_b_recorded(
    env: Any, fake_clock: FakeClock, credentials_dir: Path, respx_mock: Any
) -> None:
    for name in ("smtp_password", "alert_webhook_url"):
        (credentials_dir / name).unlink(missing_ok=True)
    async with auth_harness(env, clock=fake_clock, credentials_dir=credentials_dir) as harness:
        admin = harness.admin()
        login = await harness.login(admin)
        assert login.status_code == 200, login.text
        headers = harness.headers()
        token = harness.http.cookies.get("__Host-roxy_session")
        headers.update({"Host": "testserver", "Accept": "text/event-stream", "Cookie": f"__Host-roxy_session={token}"})
        # Worker A's stream: refused requests of one client, plus breakers.
        stream = _Stream(
            harness.app, headers, {"events": "live,breaker", "outcome": "refused", "client": OTHER_WORKER_CLIENT}
        )
        await stream.open()
        try:
            assert stream.status == 200
            tail = harness.ctx.live_tail
            for _ in range(100):  # the tail takes its first position within a poll (0.5 s)
                if tail.last_id is not None:
                    break
                await asyncio.sleep(0.05)
            paths = {name: str(harness.ctx.dbs.get(name).path) for name in DB_NAMES}
            child = CTX.Process(target=_worker_b, args=(paths, fake_clock.now()), daemon=True)
            child.start()
            await asyncio.to_thread(child.join, 60)
            assert child.exitcode == 0, child.exitcode
            frames = await stream.frames(4.0)
        finally:
            await stream.close()
    live = [(ident, data) for event, ident, data in frames if event == "live"]
    breakers = [(ident, data) for event, ident, data in frames if event == "breaker"]
    assert [data["request_id"] for _ident, data in live] == [OTHER_WORKER_REQUEST]  # exactly once
    assert live[0][0] == live[0][1]["event_id"]
    assert live[0][1]["client"] == OTHER_WORKER_CLIENT
    assert [data["detail"]["by"] for _ident, data in breakers] == ["b"]
    assert breakers[0][0] is not None
