"""Fleet-wide single-flight across real worker processes (plan 6.9, fix F1, C6; plan 19.3).

Each child process builds its own CacheService (own SQLite connections, memory tier, flights) on shared temp
database files, like a gunicorn worker. A fake upstream appends one line per call to a shared file (an O_APPEND
write of a few bytes is atomic), so the parent counts upstream calls across all processes.

1. N concurrent requests for one key spread over 2 and 4 processes -> exactly 1 upstream call.
2. The owner fails -> 1 upstream call, not N; every request gets the owner's status and Retry-After.
3. The owner process is killed (SIGKILL) mid-fetch -> exactly one follower takes the lease over (1 more call).
"""

from __future__ import annotations

import asyncio
import multiprocessing as mp
import os
import signal
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from roxy.cache.service import CacheService
from roxy.cache.testing import FakeResult, FakeSettings, FakeUpstream, StaticRules, failure, make_request, ok
from roxy.core.clock import SystemClock
from roxy.core.reasons import ReasonCode
from roxy.storage.db import DB_NAMES, Database
from roxy.storage.migrate import migrate_paths

pytestmark = [
    pytest.mark.multiprocess,
    pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX signals (SIGKILL)"),
]

CTX = mp.get_context("spawn")
TARGET = "games.roblox.com/v1/games/votes?universeIds=4242"
REQUESTS_PER_PROCESS = 5


class RecordingUpstream(FakeUpstream):
    """FakeUpstream that also appends `label` to a shared file for every call, then behaves per `mode`."""

    def __init__(self, calls_file: str, label: str, mode: str) -> None:
        super().__init__()
        self.calls_file = calls_file
        self.label = label
        self.mode = mode

    async def fetch(self, req: Any, *, priority: Any, stale_available: bool, purpose: str = "caller") -> FakeResult:
        fd = os.open(self.calls_file, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, f"{self.label}\n".encode())
        finally:
            os.close(fd)
        if self.mode == "hang":
            await asyncio.sleep(120)  # the parent kills this process while it "fetches"
        await asyncio.sleep(0.5)  # long enough for every other request to arrive and follow
        if self.mode == "fail":
            return failure(ReasonCode.UPSTREAM_5XX, 503, retry_after_s=7)
        return ok('{"answer":"the one"}')


def _child(
    paths: dict[str, str], calls_file: str, label: str, mode: str, settings: dict[str, Any], go: Any, out: Any
) -> None:
    asyncio.run(_child_main(paths, calls_file, label, mode, settings, go, out))


async def _child_main(
    paths: dict[str, str], calls_file: str, label: str, mode: str, settings: dict[str, Any], go: Any, out: Any
) -> None:
    dbs = SimpleNamespace(cache=Database("cache", paths["cache"]), hot=Database("hot", paths["hot"]))
    try:
        service = CacheService(
            dbs=dbs,
            settings=FakeSettings(settings),
            rules=StaticRules(),
            clock=SystemClock(),
            upstream=RecordingUpstream(calls_file, label, mode),
            worker_id=f"{label}:{os.getpid()}",
        )
        await service.start()
        out.put(("ready", label, None))
        await asyncio.get_running_loop().run_in_executor(None, go.wait, 60)

        async def one() -> tuple[str, int, str, int | None]:
            req = make_request(TARGET)
            result = await service.serve(req, await service.peek(req))
            return result.cache_state.value, result.status, result.body.decode(), result.retry_after_s

        results = await asyncio.gather(*(one() for _ in range(REQUESTS_PER_PROCESS)))
        out.put(("done", label, results))
    finally:
        dbs.cache.close_sync()
        dbs.hot.close_sync()


@pytest.fixture
def shared_files(tmp_path: Path) -> tuple[dict[str, str], str]:
    paths = {name: tmp_path / f"{name}.db" for name in DB_NAMES}
    migrate_paths(paths)
    return {name: str(path) for name, path in paths.items()}, str(tmp_path / "upstream_calls.txt")


@pytest.fixture
def procs() -> Iterator[list[Any]]:
    started: list[Any] = []
    yield started
    for proc in started:
        if proc.is_alive():
            proc.kill()
        proc.join(5)


def _start(procs: list[Any], *args: Any) -> Any:
    proc = CTX.Process(target=_child, args=args, daemon=True)
    proc.start()
    procs.append(proc)
    return proc


def _collect(out: Any, kind: str, count: int, timeout: float = 60.0) -> list[tuple[str, str, Any]]:
    got: list[tuple[str, str, Any]] = []
    deadline = time.monotonic() + timeout
    while len(got) < count:
        item = out.get(True, max(0.1, deadline - time.monotonic()))
        if item[0] == kind:
            got.append(item)
    return got


def _calls(calls_file: str) -> list[str]:
    path = Path(calls_file)
    return path.read_text().split() if path.exists() else []


@pytest.mark.parametrize("processes", [2, 4])
def test_concurrent_requests_in_many_processes_make_one_upstream_call(
    processes: int, shared_files: tuple[dict[str, str], str], procs: list[Any]
) -> None:
    paths, calls_file = shared_files
    go, out = CTX.Event(), CTX.Queue()
    for index in range(processes):
        _start(procs, paths, calls_file, f"p{index}", "ok", {}, go, out)
    _collect(out, "ready", processes)
    go.set()
    done = _collect(out, "done", processes)
    results = [result for _kind, _label, batch in done for result in batch]
    assert len(results) == processes * REQUESTS_PER_PROCESS
    assert len(_calls(calls_file)) == 1  # one upstream call for the whole fleet
    states = [state for state, _status, _body, _retry in results]
    assert states.count("MISS") == 1
    assert states.count("COALESCED") == len(results) - 1
    assert {status for _state, status, _body, _retry in results} == {200}
    assert {body for _state, _status, body, _retry in results} == {'{"answer":"the one"}'}


@pytest.mark.parametrize("processes", [2, 4])
def test_owner_failure_costs_one_upstream_call_not_n(
    processes: int, shared_files: tuple[dict[str, str], str], procs: list[Any]
) -> None:
    paths, calls_file = shared_files
    go, out = CTX.Event(), CTX.Queue()
    for index in range(processes):
        _start(procs, paths, calls_file, f"p{index}", "fail", {}, go, out)
    _collect(out, "ready", processes)
    go.set()
    done = _collect(out, "done", processes)
    results = [result for _kind, _label, batch in done for result in batch]
    assert len(_calls(calls_file)) == 1  # followers never go upstream after the owner failed
    assert {(status, retry) for _state, status, _body, retry in results} == {(503, 7)}


@pytest.mark.parametrize("processes", [2, 4])
def test_crashed_owner_is_taken_over_by_exactly_one_follower(
    processes: int, shared_files: tuple[dict[str, str], str], procs: list[Any]
) -> None:
    paths, calls_file = shared_files
    # Owner deadline 0.5 s + 2 s x 1 + 0.5 s = 3 s, so the dead owner's lease expires quickly.
    settings = {
        "queue_wait_interactive_ms": 500,
        "request_timeout": 2,
        "upstream_max_attempts": 1,
        "backoff_cap_ms": 500,
        "cache_coalesce_wait_ms": 20_000,
    }
    owner_go, followers_go, out = CTX.Event(), CTX.Event(), CTX.Queue()
    for index in range(processes - 1):  # followers first, so they are ready before the owner's lease expires
        _start(procs, paths, calls_file, f"f{index}", "ok", settings, followers_go, out)
    _collect(out, "ready", processes - 1)
    owner = _start(procs, paths, calls_file, "owner", "hang", settings, owner_go, out)
    _collect(out, "ready", 1)
    owner_go.set()
    deadline = time.monotonic() + 30
    while "owner" not in _calls(calls_file):  # the owner holds the lease and is "fetching"
        assert time.monotonic() < deadline, "the owner never started its fetch"
        time.sleep(0.05)
    followers_go.set()
    time.sleep(0.8)  # every follower is now waiting on the owner's lease
    assert owner.pid is not None
    os.kill(owner.pid, signal.SIGKILL)
    done = _collect(out, "done", processes - 1)
    results = [result for _kind, _label, batch in done for result in batch]
    calls = _calls(calls_file)
    assert calls.count("owner") == 1  # its own requests coalesced in-process before it died
    follower_calls = [label for label in calls if label != "owner"]
    assert len(follower_calls) == 1  # exactly one follower took the lease over, never all
    assert {status for _state, status, _body, _retry in results} == {200}
    states = [state for state, _status, _body, _retry in results]
    assert states.count("MISS") == 1
    assert states.count("COALESCED") == len(results) - 1
