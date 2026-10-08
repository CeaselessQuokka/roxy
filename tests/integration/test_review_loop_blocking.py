"""Adversarial review (multi-process and failure modes lens): blocking work on the event loop thread.

What this is
    One test that runs the fully wired application (real lifespan, every background loop, `respx` playing Roblox)
    with probes on every kind of blocking call the brief forbids on the loop: SQLite statements (a trace callback on
    every connection opened while the test runs, including the ones the lifespan opens), argon2 hashing, zstd
    compression of cache and capture bodies, and file system calls made from Roxy's own code. It drives the request
    paths that exist today (proxy miss, memory and disk cache hits, refusals with large captured bodies, health,
    public pages, the admin password and TOTP login) and reports every blocking call it saw on the loop thread.

Why it exists
    AGENT_BRIEF "never block the event loop" and plan 5.2: one blocking call on the loop stalls every request of the
    worker, and gunicorn kills a worker whose loop is frozen for its `timeout`. Static reading finds the obvious
    `write_sync` calls; only a run shows what really executes on the loop thread.

How it works
    Every probe records `(kind, detail, roxy frame)` when it runs on the loop thread while `LoopWatch.active` is set
    (startup and shutdown are excluded: no request is served then). The assertions are per kind: no SQLite statement,
    no argon2 call and no zstd work on a large body may run on the loop. A known violation is marked `xfail(strict)`
    with the finding id, so it shows as XFAIL now and fails loudly (XPASS) once fixed, telling the fixer to remove
    the marker.

What to read next
    `roxy/storage/db.py` (the thread model), `roxy/metrics/capture.py` (finding LOOP-1), `roxy/cache/store.py`.
"""

from __future__ import annotations

import builtins
import os
import sqlite3
import sys
import threading
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from pathlib import Path
from types import FrameType
from typing import Any

import httpx
import pytest

from roxy.admin.auth.testing import auth_harness
from roxy.core.clock import FakeClock

LARGE_BODY = 64 * 1024
"""zstd or redaction work on more than this many bytes counts as "a large body" (the brief's wording)."""

GAMES = "games.roblox.com"
_SRC_MARKER = f"{os.sep}src{os.sep}roxy{os.sep}"


def _roxy_frame(depth: int = 2, limit: int = 12) -> str:
    """`module:line` of the nearest caller frame inside src/roxy (empty when the call did not come from Roxy)."""
    frame: FrameType | None = sys._getframe(depth)
    for _ in range(limit):
        if frame is None:
            break
        name = frame.f_code.co_filename
        if _SRC_MARKER in name:
            return f"{name.split(_SRC_MARKER, 1)[1]}:{frame.f_lineno}"
        frame = frame.f_back
    return ""


@dataclass
class LoopWatch:
    """Records blocking calls made on the event loop thread while `active`."""

    loop_thread: int
    active: bool = False
    phase: str = ""
    hits: list[tuple[str, str, str, str]] = field(default_factory=list)  # (phase, kind, detail, where)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def on_loop(self) -> bool:
        return self.active and threading.get_ident() == self.loop_thread

    def record(self, kind: str, detail: str, where: str) -> None:
        with self.lock:
            if len(self.hits) < 5000:
                self.hits.append((self.phase, kind, detail[:120], where))

    def of(self, kind: str, phase: str | None = None) -> list[tuple[str, str, str, str]]:
        return [hit for hit in self.hits if hit[1] == kind and (phase is None or hit[0] == phase)]


def _install_probes(monkeypatch: pytest.MonkeyPatch, watch: LoopWatch) -> None:
    """Wrap SQLite connections, argon2, zstd body codecs and file system calls (see the module docstring)."""
    real_connect = sqlite3.connect

    def connect(*args: Any, **kwargs: Any) -> sqlite3.Connection:
        conn: sqlite3.Connection = real_connect(*args, **kwargs)

        def trace(statement: str) -> None:
            if watch.on_loop():
                watch.record("sqlite", statement, _roxy_frame(2, 30))

        conn.set_trace_callback(trace)
        return conn

    monkeypatch.setattr(sqlite3, "connect", connect)

    import argon2

    for name in ("hash", "verify"):
        original = getattr(argon2.PasswordHasher, name)

        def wrapped(self: Any, *args: Any, _original: Callable[..., Any] = original, _name: str = name) -> Any:
            if watch.on_loop():
                watch.record("argon2", _name, _roxy_frame())
            return _original(self, *args)

        monkeypatch.setattr(argon2.PasswordHasher, name, wrapped)

    from roxy.cache import store
    from roxy.metrics import capture, recorder

    def sized(module: Any, name: str, size_of: Callable[..., int]) -> None:
        original = getattr(module, name)

        def wrapped(*args: Any, **kwargs: Any) -> Any:
            if watch.on_loop():
                watch.record("zstd", f"{module.__name__}.{name} {size_of(*args, **kwargs)} bytes", _roxy_frame())
            return original(*args, **kwargs)

        monkeypatch.setattr(module, name, wrapped)

    sized(store, "encode_body", lambda body, *a, **k: len(body or b""))
    sized(store, "decode_body", lambda blob, *a, **k: len(blob or b""))
    # The recorder imported `make_row` by name, so its own reference is the one to wrap.
    sized(
        recorder,
        "make_row",
        lambda inp, *a, **k: len(inp.request_body or b"") + len(inp.response_body or b""),
    )
    sized(capture, "decode_record", lambda blob, *a, **k: len(blob or b""))

    real_open = builtins.open
    real_stat = os.stat

    def open_probe(file: Any, *args: Any, **kwargs: Any) -> Any:
        if watch.on_loop():
            where = _roxy_frame()
            if where:
                watch.record("file", f"open {file}", where)
        return real_open(file, *args, **kwargs)

    def stat_probe(path: Any, *args: Any, **kwargs: Any) -> Any:
        if watch.on_loop():
            where = _roxy_frame()
            if where:
                watch.record("file", f"stat {path}", where)
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", open_probe)
    monkeypatch.setattr(os, "stat", stat_probe)


@pytest.fixture
async def watched(
    env: Any, credentials_dir: Path, respx_mock: Any, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[tuple[Any, LoopWatch, Any]]:
    watch = LoopWatch(loop_thread=threading.get_ident())
    _install_probes(monkeypatch, watch)  # before startup, so every connection the lifespan opens is traced
    for name in ("smtp_password", "alert_webhook_url"):
        (credentials_dir / name).unlink(missing_ok=True)
    async with auth_harness(env, clock=FakeClock(), credentials_dir=credentials_dir) as harness:
        await harness.set_settings(
            tarpit_enabled=0,
            rotator_enabled=0,
            capture_max_body=512 * 1024,  # the catalog maximum: what a large capture costs on the loop
            capture_sample_served_pct=100,
            allowed_requests_per_minute=1000,
        )
        yield harness, watch, respx_mock
        watch.active = False


async def _drive(harness: Any, watch: LoopWatch, roblox: Any) -> None:
    http = harness.http
    big = b'{"data":"' + b"x" * (200 * 1024) + b'"}'
    roblox.route(host=GAMES, path="/v1/games").mock(return_value=httpx.Response(200, content=big))
    headers = {"User-Agent": "Roblox/Linux", "X-Forwarded-For": "203.0.113.10"}
    url = f"/{GAMES}/v1/games?universeIds=1"

    watch.active, watch.phase = True, "proxy"
    assert (await http.get(url, headers=headers)).status_code == 200  # miss: upstream, store (zstd)
    assert (await http.get(url, headers=headers)).status_code == 200  # memory tier hit
    harness.ctx.cache.store.memory.clear()
    assert (await http.get(url, headers=headers)).status_code == 200  # cache.db hit (decode)
    refused = await http.post(  # a refusal (not a Roblox URL) carrying a large body: always captured
        "/evil.example.com/upload", content=b"y" * (600 * 1024), headers=headers
    )
    assert refused.status_code in (400, 404), refused.status_code
    await http.get("/evil.example.com/wp-login.php", headers=headers)  # probe refusal

    watch.phase = "public"
    for path in ("/health", "/", "/docs", "/robots.txt", "/sitemap.xml"):
        await http.get(path, headers={"User-Agent": "Mozilla/5.0", "X-Forwarded-For": "203.0.113.11"})

    watch.active = False
    admin = harness.admin()  # a test helper that writes with write_sync: not part of what is measured
    watch.active, watch.phase = True, "auth"
    response = await harness.login(admin, ip="203.0.113.12")
    assert response.status_code == 200, response.text
    watch.phase = "idle"
    await harness.ctx.recorder.flush()


async def test_review_no_sqlite_or_argon2_on_the_loop_thread(watched: tuple[Any, LoopWatch, Any]) -> None:
    harness, watch, roblox = watched
    await _drive(harness, watch, roblox)
    watch.active = False
    sqlite_hits = watch.of("sqlite")
    argon_hits = watch.of("argon2")
    print("\nfile system calls on the loop thread:", sorted({(h[0], h[2][:60], h[3]) for h in watch.of("file")}))
    assert sqlite_hits == [], sqlite_hits[:10]
    assert argon_hits == [], argon_hits[:10]


async def test_review_cache_bodies_are_not_compressed_on_the_loop(watched: tuple[Any, LoopWatch, Any]) -> None:
    harness, watch, roblox = watched
    await _drive(harness, watch, roblox)
    watch.active = False
    cache_codec = [hit for hit in watch.of("zstd") if "roxy.cache.store" in hit[2]]
    assert cache_codec == [], cache_codec[:10]


@pytest.mark.xfail(
    strict=True,
    reason="finding LOOP-1: capture rows (redaction, JSON and zstd of up to 2 x capture_max_body) are built on the "
    "event loop thread in MetricsRecorder.record_capture",
)
async def test_review_large_capture_is_not_encoded_on_the_loop(watched: tuple[Any, LoopWatch, Any]) -> None:
    harness, watch, roblox = watched
    await _drive(harness, watch, roblox)
    watch.active = False
    print("\nzstd and capture work on the loop thread:", watch.of("zstd"))
    large = [hit for hit in watch.of("zstd") if "make_row" in hit[2] and int(hit[2].split()[1]) > LARGE_BODY]
    assert large == [], large[:5]


async def test_review_proxy_path_makes_no_file_system_call_on_the_loop(watched: tuple[Any, LoopWatch, Any]) -> None:
    harness, watch, roblox = watched
    await _drive(harness, watch, roblox)
    watch.active = False
    assert watch.of("file", "proxy") == []


@pytest.mark.xfail(
    strict=True,
    reason="finding LOOP-2: GET /health stats every database file and WAL (public/health.py data_bytes) on the "
    "event loop thread on every call; on a disk that stalls (the C7 situation) the whole worker freezes",
)
async def test_review_health_makes_no_file_system_call_on_the_loop(watched: tuple[Any, LoopWatch, Any]) -> None:
    harness, watch, _roblox = watched
    watch.active, watch.phase = True, "health"
    for _ in range(3):
        response = await harness.http.get("/health", headers={"X-Forwarded-For": "203.0.113.13"})
        assert response.status_code == 200
    watch.active = False
    hits = watch.of("file", "health")
    print("\n/health file system calls on the loop thread:", len(hits), sorted({h[3] for h in hits}))
    assert hits == []
