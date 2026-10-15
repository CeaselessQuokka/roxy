"""The event stream (`GET /admin/api/v1/stream`, plan 14.11) in the real app: guards, `kpi`, filtered and sampled
`live` rows, the notable event kinds, `settings_changed`, cooldown changes, `Last-Event-ID` resume, the per-session
cap, heartbeats, the end of a revoked session and of a draining worker, and the request deadline switched off.

The stream is read through a small ASGI driver (`Stream`): httpx's test transport waits for a response to finish
before returning it, which a stream never does, so the driver calls the app itself and reads each body chunk as it
is sent.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

import pytest

from roxy.admin import sse
from roxy.core.reasons import CacheState, Egress, Outcome, ReasonCode, Source
from roxy.metrics.live import read_after
from roxy.metrics.queries import LAST_HOUR_KPIS as LAST_HOUR

PATH = "/admin/api/v1/stream"
REFUSED = {
    "outcome": Outcome.REFUSED,
    "reason": ReasonCode.THROTTLE,
    "status": 429,
    "source": Source.ROXY,
    "cache_state": CacheState.NA,
    "upstream_calls": 0,
    "egress": Egress.NONE,
}


@dataclass
class Frame:
    event: str
    data: Any
    id: int | None = None


@dataclass
class Stream:
    """One open stream, driven over ASGI (see the module docstring)."""

    app: Any
    headers: dict[str, str]
    params: dict[str, Any] = field(default_factory=dict)
    status: int | None = None
    body: bytes = b""
    scope: dict[str, Any] = field(default_factory=dict)
    frames: list[Frame] = field(default_factory=list)
    ended: bool = False
    _queue: asyncio.Queue[dict[str, Any]] = field(default_factory=asyncio.Queue)
    _disconnect: asyncio.Event = field(default_factory=asyncio.Event)
    _task: asyncio.Task[None] | None = None
    _buffer: str = ""
    _sent_request: bool = False

    async def open(self) -> Stream:
        self.scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "https",
            "path": PATH,
            "raw_path": PATH.encode(),
            "query_string": urlencode(self.params).encode(),
            "root_path": "",
            "headers": [(name.lower().encode(), value.encode()) for name, value in self.headers.items()],
            "client": ("127.0.0.1", 50000),
            "server": ("testserver", 443),
        }

        async def receive() -> dict[str, Any]:
            if not self._sent_request:
                self._sent_request = True
                return {"type": "http.request", "body": b"", "more_body": False}
            await self._disconnect.wait()
            return {"type": "http.disconnect"}

        async def send(message: dict[str, Any]) -> None:
            await self._queue.put(dict(message))

        self._task = asyncio.get_running_loop().create_task(self.app(self.scope, receive, send))
        start = await asyncio.wait_for(self._queue.get(), timeout=10)
        assert start["type"] == "http.response.start", start
        self.status = int(start["status"])
        self.response_headers = {bytes(k).decode().lower(): bytes(v).decode() for k, v in start["headers"]}
        if self.status != 200:
            while True:
                message = await asyncio.wait_for(self._queue.get(), timeout=10)
                self.body += message.get("body", b"")
                if not message.get("more_body"):
                    break
            self.ended = True
        return self

    def _parse(self) -> list[Frame]:
        out: list[Frame] = []
        while "\n\n" in self._buffer:
            block, self._buffer = self._buffer.split("\n\n", 1)
            event, data, ident = "message", [], None
            comments = []
            for line in block.split("\n"):
                if line.startswith(":"):
                    comments.append(line[1:].strip())
                elif line.startswith("event: "):
                    event = line[7:]
                elif line.startswith("data: "):
                    data.append(line[6:])
                elif line.startswith("id: "):
                    ident = int(line[4:])
                elif line.startswith("retry: "):
                    out.append(Frame("retry", int(line[7:])))
            for text in comments:
                out.append(Frame("comment", text))
            if data:
                out.append(Frame(event, json.loads("\n".join(data)), ident))
        return out

    async def next(self, limit_s: float = 10.0) -> Frame | None:
        """The next frame, or None when the stream ended (or nothing came within `limit_s`)."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + limit_s
        while True:
            parsed = self._parse()
            if parsed:
                self._pending = parsed[1:] + getattr(self, "_pending", [])
                self.frames.append(parsed[0])
                return parsed[0]
            pending: list[Frame] = getattr(self, "_pending", [])
            if pending:
                frame = pending.pop(0)
                self.frames.append(frame)
                return frame
            if self.ended:
                return None
            left = deadline - loop.time()
            if left <= 0:
                return None
            try:
                message = await asyncio.wait_for(self._queue.get(), timeout=left)
            except TimeoutError:
                return None
            if message["type"] == "http.response.body":
                self._buffer += bytes(message.get("body", b"")).decode()
                if not message.get("more_body"):
                    self.ended = True

    async def until(self, predicate: Callable[[Frame], bool], limit_s: float = 10.0) -> Frame:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + limit_s
        while True:
            frame = await self.next(limit_s=max(0.01, deadline - loop.time()))
            if frame is None:
                raise AssertionError(f"no matching frame; seen {[(f.event, f.data) for f in self.frames][-12:]}")
            if predicate(frame):
                return frame

    async def drain(self, seconds: float) -> list[Frame]:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + seconds
        out = []
        while loop.time() < deadline:
            frame = await self.next(limit_s=max(0.01, deadline - loop.time()))
            if frame is None:
                if self.ended:
                    break
                continue
            out.append(frame)
        return out

    async def close(self) -> None:
        self._disconnect.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=5)
            except (TimeoutError, asyncio.CancelledError):
                self._task.cancel()


def headers_of(api: Any, **extra: str) -> dict[str, str]:
    owner = api.owner
    token = api.http.cookies.get("__Host-roxy_session")
    out: dict[str, str] = owner.harness.headers()
    out.update({"Host": "testserver", "Accept": "text/event-stream", "Cookie": f"__Host-roxy_session={token}"})
    out.update(extra)
    return out


async def open_stream(api: Any, params: dict[str, Any] | None = None, **extra: str) -> Stream:
    return await Stream(api.owner.app, headers_of(api, **extra), dict(params or {})).open()


@pytest.fixture(autouse=True)
def fast_hub(monkeypatch: pytest.MonkeyPatch) -> None:
    """The hub ticks every 0.2 s here (2 s in production), so `kpi` and cooldown frames come quickly."""
    monkeypatch.setattr(sse, "KPI_INTERVAL_S", 0.2)


async def wait_for(predicate: Callable[[], bool], limit_s: float = 5.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + limit_s
    while not predicate():
        assert loop.time() < deadline, "condition not met in time"
        await asyncio.sleep(0.02)


# ============================================================================================== guards


async def test_stream_needs_a_session_and_valid_parameters(api: Any, anon_api: Any, section13: Any) -> None:
    assert (await anon_api.get("stream")).status_code == 401
    fields = section13(await api.get("stream", params={"events": "kpi,weather"}), 422, "validation_failed")
    assert "events" in fields
    fields = section13(await api.get("stream", params={"outcome": "partying"}), 422, "validation_failed")
    assert "outcome" in fields
    cross = await api.get("stream", headers={"Origin": "https://evil.example"})
    assert cross.status_code == 403


async def test_stream_switches_the_request_deadline_off(api: Any) -> None:
    stream = await open_stream(api, {"events": "kpi"})
    try:
        assert stream.status == 200
        assert stream.response_headers["content-type"].startswith("text/event-stream")
        assert stream.response_headers["cache-control"] == "no-store"
        assert stream.response_headers["x-accel-buffering"] == "no"
        assert stream.scope["state"]["deadline_at"] is None  # core/deadline.py disable_deadline
        first = await stream.next()
        assert first is not None
        assert first.event == "retry"
    finally:
        await stream.close()


# ============================================================================================== frames


async def test_kpi_then_filtered_live_rows(api: Any, metrics_seed: Any) -> None:
    stream = await open_stream(api, {"outcome": "refused", "client": "198.51.100"})
    try:
        kpi = await stream.until(lambda f: f.event == "kpi")
        assert set(kpi.data["values"]) >= {"requests", "avoided_pct", "roblox_429", "p95_ms", *LAST_HOUR}
        assert kpi.data["proxy"] == {"paused": False, "throttle_all": False}
        assert kpi.data["stream"] == {"live_sampled_out": 0, "lost": 0} or "stream" in kpi.data
        metrics_seed.record(1, request_id="S" * 26)
        metrics_seed.record(1, request_id="R" * 26, client_ip="198.51.100.9", **REFUSED)
        metrics_seed.record(1, request_id="T" * 26, **REFUSED)  # refused, but another client
        await metrics_seed.flush()
        live = await stream.until(lambda f: f.event == "live")
        assert live.data["request_id"] == "R" * 26
        assert live.data["event_id"] == live.id
        assert live.data["client"] == "198.51.100.9"
        assert live.data["endpoint"]
        assert "latency_ms" in live.data
        rest = [f for f in await stream.drain(1.5) if f.event == "live"]
        assert rest == []  # the other rows did not match the filter
    finally:
        await stream.close()


async def test_notable_events_carry_their_names_and_ids(api: Any, metrics_seed: Any) -> None:
    stream = await open_stream(api, {"events": "recommendation,health,alert,breaker,cooldown"})
    try:
        await stream.next()
        metrics_seed.event("breaker_open", "warning", "upstream_cooldown", {"key": "direct:games.roblox.com"})
        metrics_seed.event("credential_cooldown", "warn", "upstream_cooldown", {"seconds": 30})
        metrics_seed.event("leak_blocked", "critical", "leak_blocked", {"egress": "rotator"})
        metrics_seed.event("health_run_finished", "info", "health", {"summary": {"fail": 0}})
        metrics_seed.event("recommendation", "warn", "UP-429-ENDPOINT", {"id": "rec_1", "action": "opened"})
        metrics_seed.event("visit", "info", None, {"page": "home"})  # not a stream kind
        await metrics_seed.flush()
        names: list[tuple[str, str]] = []
        while len(names) < 5:
            frame = await stream.until(lambda f: f.id is not None)
            names.append((frame.event, frame.data["type"]))
            assert frame.data["detail"]
        assert names == [
            ("breaker", "breaker_open"),
            ("cooldown", "credential_cooldown"),
            ("alert", "leak_blocked"),
            ("health", "health_run_finished"),
            ("recommendation", "recommendation"),
        ]
        assert [f.id for f in stream.frames if f.id is not None] == sorted(f.id for f in stream.frames if f.id)
    finally:
        await stream.close()


async def test_settings_changed(api: Any, api_app: Any) -> None:
    stream = await open_stream(api, {"events": "settings_changed"})
    try:
        await stream.next()
        await api_app.settings(cache_ttl_seconds=300)
        frame = await stream.until(lambda f: f.event == "settings_changed")
        assert frame.data == {"config_version": api_app.ctx.settings.version}
    finally:
        await stream.close()


async def test_cooldowns_start_and_end(api: Any, api_app: Any) -> None:
    stream = await open_stream(api, {"events": "cooldown"})
    try:
        await asyncio.sleep(0.5)  # the hub's first look is its baseline
        now_ms = api_app.clock.now_ms()

        def add(conn: Any) -> None:
            conn.execute(
                "INSERT INTO cooldown (key, until_ms, source, set_at, hits) VALUES (?, ?, 'retry_after', ?, 1)",
                ("direct|games.roblox.com|games.roblox.com/v1/games", now_ms + 30_000, now_ms // 1000),
            )

        await api_app.ctx.dbs.hot.write(add)
        started = await stream.until(lambda f: f.event == "cooldown" and f.data.get("action") == "started")
        assert started.data["source"] == "retry_after"
        assert started.data["remaining_s"] == 30.0
        await api_app.ctx.dbs.hot.write(lambda conn: conn.execute("DELETE FROM cooldown"))
        ended = await stream.until(lambda f: f.event == "cooldown" and f.data.get("action") == "ended")
        assert ended.data["key"] == started.data["key"]
    finally:
        await stream.close()


async def test_the_hub_runs_only_while_a_stream_is_open(api: Any) -> None:
    first = await open_stream(api, {"events": "kpi,cooldown"})
    try:
        await first.until(lambda f: f.event == "kpi")
        snapshot = await first.until(lambda f: f.event == "cooldown")  # sent once the hub has had its first look
        assert snapshot.data == {"action": "snapshot", "active": []}
    finally:
        await first.close()
    hub = api.owner.app.state.sse_hub
    await wait_for(lambda: hub.users == 0)
    assert hub.task is None  # no more metrics.db and hot.db reads with nobody listening
    assert hub.kpi is None  # a later stream never gets these old numbers
    assert hub.cooldowns is None  # and the restarted hub takes a fresh baseline
    second = await open_stream(api, {"events": "kpi,cooldown"})
    try:
        assert hub.task is not None
        kpi = await second.until(lambda f: f.event == "kpi")
        assert kpi.data["values"]
        snapshot = await second.until(lambda f: f.event == "cooldown")
        assert snapshot.data["action"] == "snapshot"
    finally:
        await second.close()


async def test_last_event_id_resumes_exactly(api: Any, api_app: Any, metrics_seed: Any) -> None:
    for n in range(4):
        metrics_seed.event("breaker_open", "warning", "upstream_cooldown", {"n": n})
    await metrics_seed.flush()
    rows = await api_app.ctx.dbs.metrics.read(lambda conn: read_after(conn, 0, 100, ["breaker_open"]))
    ids = [row.id for row in rows]
    tail = api_app.ctx.live_tail
    await wait_for(lambda: tail.last_id is not None and tail.last_id >= ids[-1])
    stream = await open_stream(api, {"events": "breaker"}, **{"Last-Event-ID": str(ids[0])})
    try:
        replayed = [await stream.until(lambda f: f.event == "breaker") for _ in range(3)]
        assert [f.id for f in replayed] == ids[1:]
        assert [f.data["detail"]["n"] for f in replayed] == [1, 2, 3]
        metrics_seed.event("breaker_open", "warning", "upstream_cooldown", {"n": 4})
        await metrics_seed.flush()
        live = await stream.until(lambda f: f.event == "breaker")
        assert live.data["detail"]["n"] == 4
        assert live.id > ids[-1]
        assert [f for f in await stream.drain(1.0) if f.event == "breaker"] == []  # nothing twice
    finally:
        await stream.close()


async def test_a_resume_that_cannot_catch_up_says_so(
    api: Any, api_app: Any, metrics_seed: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sse, "BACKFILL_MAX", 2)
    for n in range(5):
        metrics_seed.event("breaker_open", "warning", "upstream_cooldown", {"n": n})
    await metrics_seed.flush()
    rows = await api_app.ctx.dbs.metrics.read(lambda conn: read_after(conn, 0, 100, ["breaker_open"]))
    tail = api_app.ctx.live_tail
    await wait_for(lambda: tail.last_id is not None and tail.last_id >= rows[-1].id)
    stream = await open_stream(api, {"events": "breaker"}, **{"Last-Event-ID": str(rows[0].id)})
    try:
        gap = await stream.until(lambda f: f.event == "gap")
        assert gap.data["after_id"] == rows[0].id
        assert gap.data["resumed_to"] == rows[2].id
    finally:
        await stream.close()


async def test_live_rows_are_sampled_above_50_a_second(api: Any, api_app: Any) -> None:
    stream = await open_stream(api, {"events": "live,kpi"})
    try:
        await stream.until(lambda f: f.event == "kpi")
        now_ms = api_app.clock.now_ms()

        def burst(conn: Any) -> None:
            rows = []
            for n in range(300):
                detail = {"request_id": f"B{n:025d}", "at_ms": now_ms, "outcome": "served_upstream", "status": 200,
                          "ip": "203.0.113.5", "url": "games.roblox.com/v1/games", "egress": "direct"}  # fmt: skip
                rows.append((now_ms, "live", "info", "upstream_ok", json.dumps(detail)))
            conn.executemany(
                "INSERT INTO events (at_ms, type, severity, reason_code, detail_json) VALUES (?, ?, ?, ?, ?)", rows
            )

        await api_app.ctx.dbs.metrics.write(burst)
        frames = await stream.drain(2.5)
        delivered = sum(1 for f in frames if f.event == "live")
        assert 50 <= delivered < 300  # a burst of 50, then 50 a second
        kpi = await stream.until(lambda f: f.event == "kpi")
        assert delivered + kpi.data["stream"]["live_sampled_out"] == 300
        assert kpi.data["stream"]["lost"] == 0
    finally:
        await stream.close()


# ============================================================================================== endings and bounds


async def test_a_revoked_session_ends_the_stream_with_401(
    api: Any, api_app: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sse, "SESSION_CHECK_S", 0.2)
    stream = await open_stream(api, {"events": "kpi"})
    try:
        await stream.until(lambda f: f.event == "kpi")
        await api_app.ctx.dbs.control.write(lambda conn: conn.execute("DELETE FROM admin_sessions"))
        frame = await stream.until(lambda f: f.event == "unauthorized")
        assert frame.data["status"] == 401
        await stream.drain(1.0)
        assert stream.ended
    finally:
        await stream.close()
    again = await open_stream(api, {"events": "kpi"})
    assert again.status == 401  # the reconnect gets a real 401: the session-expired overlay (row 119)


async def test_an_idle_session_expires_while_streaming(api: Any, api_app: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sse, "SESSION_CHECK_S", 0.2)
    stream = await open_stream(api, {"events": "kpi"})
    try:
        await stream.until(lambda f: f.event == "kpi")
        api_app.clock.advance(int(api_app.ctx.settings.int("admin_session_idle_timeout_s")) + 1)
        await stream.until(lambda f: f.event == "unauthorized")  # watching is not activity (plan 9.6)
    finally:
        await stream.close()


async def test_streams_per_session_are_capped(api: Any, monkeypatch: pytest.MonkeyPatch, section13: Any) -> None:
    monkeypatch.setattr(sse, "MAX_STREAMS_PER_SESSION", 2)
    first = await open_stream(api, {"events": "kpi"})
    second = await open_stream(api, {"events": "kpi"})
    third = await open_stream(api, {"events": "kpi"})
    try:
        assert (first.status, second.status, third.status) == (200, 200, 429)
        error = json.loads(third.body)["error"]
        assert error["code"] == "rate_limited"
        assert third.response_headers["retry-after"] == "5"
        await first.close()
        await asyncio.sleep(0.3)  # the closed stream gives its slot back on its own task
        fourth = await open_stream(api, {"events": "kpi"})
        assert fourth.status == 200
        await fourth.close()
    finally:
        await second.close()


async def test_heartbeats_and_drain(api: Any, api_app: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sse, "HEARTBEAT_S", 0.2)
    stream = await open_stream(api, {"events": "kpi"})
    try:
        beat = await stream.until(lambda f: f.event == "comment")
        assert beat.data == "keepalive"
        api_app.ctx.ready = False  # the worker starts draining: streams end at once
        end = await stream.until(lambda f: f.event == "comment" and f.data == "server restarting")
        assert end is not None
        await stream.drain(0.5)
        assert stream.ended
    finally:
        api_app.ctx.ready = True
        await stream.close()


def test_frames_are_one_line_json() -> None:
    data = sse.frame("live", {"text": "a\nb", "n": 1}, 42)
    assert data == b'id: 42\nevent: live\ndata: {"text":"a\\nb","n":1}\n\n'
    assert sse.parse_last_event_id(" 17 ", None) == 17
    assert sse.parse_last_event_id("x", "9") == 9
    assert sse.parse_last_event_id("1" * 40, None) is None
    assert sse.tail_types({"breaker"}) == frozenset({"breaker_open", "breaker_half_open", "breaker_closed"})
    payload = sse.live_payload({"ip": "203.0.113.1", "url": "games.roblox.com/v1", "duration_ms": 3.5})
    assert payload["client"] == "203.0.113.1"
    assert payload["endpoint"] == "games.roblox.com/v1"
    assert payload["latency_ms"] == 3.5
