"""Two worker processes, one set of databases, and a mock Roblox that says 429 with Retry-After: 30 (plan 19.10 row 7).

What this checks (plan 19.10, section 7 acceptance, and 19.3 "upstream buckets hold"):
    1. Once the first 429 is recorded (its cooldown is in hot.db, where every process reads it), NEITHER process
       makes a single call to that endpoint through that egress until the cooldown ends (allowing only calls
       already on the wire when it was recorded), and the record follows the 429 promptly.
    2. Every caller answer during the cooldown carries a Retry-After.
    3. After the cooldown ends, the call rate to the endpoint is at most its bucket rate (measured over 60 s).
    4. Nothing ever goes through the credential.

How it runs fast: both processes use a `ScaledClock`, a wall clock that runs SPEED times faster than real time and
is computed from the system-wide monotonic clock, so both processes agree on "now" (and it never steps back, unlike
WSL's wall clock). The service sleeps through the clock (`clock.sleep`), so a 30 s cooldown and a 60 s measuring
window take about 9 real seconds. The mock records every call it receives in its own SQLite file.

Why the in-flight allowance starts at the record, not at the 429: the clock runs SPEED times faster, but the time
Roxy needs to record the cooldown (the 429's answer, then a hot.db write that may wait for the other process's
lock) is real time. On a loaded machine (the gate ran two test sessions side by side) it passed the 50 real ms that
the allowance's 500 fake ms are, about once in 40 runs, and a call the other process had been granted before the
record counted as "during the cooldown". `CooldownWatcher`, a thread of the test process, notes on the same clock
when the cooldown first shows in hot.db; the allowance starts there, and `RECORD_LAG_MAX_MS` bounds the record's lag.
"""

from __future__ import annotations

import asyncio
import json
import multiprocessing as mp
import sqlite3
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import pytest

from roxy.core.reasons import Egress, ReasonCode
from roxy.storage.db import DB_NAMES
from roxy.storage.migrate import migrate_paths

pytestmark = [
    pytest.mark.multiprocess,
    pytest.mark.skipif(sys.platform == "win32", reason="POSIX multiprocessing with a shared monotonic clock"),
]

CTX = mp.get_context("spawn")
SPEED = 10.0
BASE_EPOCH = 1_760_000_000.0
LIMITED_FOR_S = 3.0  # the mock answers 429 for the first 3 fake seconds
RETRY_AFTER_S = 30
RUN_FOR_S = 100.0  # fake seconds: 3 limited + 30 cooldown + 60 measured + margin
REQUEST_GAP_S = 0.2  # fake seconds between new requests in each process (300 per minute each)
ENDPOINT_PER_MIN = 60
ENDPOINT_BURST = 2
TEMPLATE = "games.roblox.com/v1/games"
COOLDOWN_KEY = f"endpoint:{TEMPLATE}:direct"
IN_FLIGHT_TOLERANCE_MS = 500  # fake ms after the record: calls already on the wire when it was recorded may land
RECORD_LAG_MAX_MS = 5_000  # fake ms (0.5 real s): the cooldown is in hot.db this soon after the first 429
WATCH_POLL_S = 0.001  # real seconds between the watcher's reads of hot.db


class ScaledClock:
    """A shared fast clock: `SPEED` fake seconds per real second, the same in every process."""

    def __init__(self, mono0: float, speed: float = SPEED, base: float = BASE_EPOCH) -> None:
        self.mono0 = mono0
        self.speed = speed
        self.base = base

    def _elapsed(self) -> float:
        return (time.monotonic() - self.mono0) * self.speed

    def now(self) -> float:
        return self.base + self._elapsed()

    def now_ms(self) -> int:
        return int(self.now() * 1000)

    def monotonic(self) -> float:
        return 1000.0 + self._elapsed()

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(max(0.0, seconds) / self.speed)


class CooldownWatcher:
    """Notes, on the shared scaled clock, when the endpoint's cooldown first shows in hot.db: the moment the 429 is
    recorded for every process. A thread of the test process reads hot.db every `WATCH_POLL_S`; `seen_ms` is the
    time just before the read that saw it (a WAL read sees what was committed when it began)."""

    def __init__(self, hot_path: str, clock: ScaledClock) -> None:
        self.hot_path = hot_path
        self.clock = clock
        self.seen_ms: int | None = None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="cooldown-watcher", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=10)

    def _run(self) -> None:
        conn = sqlite3.connect(self.hot_path, timeout=30, isolation_level=None)
        try:
            while not self._stop.is_set():
                before = self.clock.now_ms()
                try:
                    row = conn.execute("SELECT 1 FROM cooldown WHERE key = ?", (COOLDOWN_KEY,)).fetchone()
                except sqlite3.OperationalError:
                    row = None  # a busy moment: read again
                if row is not None:
                    self.seen_ms = before
                    return
                time.sleep(WATCH_POLL_S)
        finally:
            conn.close()


@dataclass
class MockResponse:
    status: int
    headers: httpx.Headers
    body: bytes
    elapsed_ms: float = 20.0
    bytes_out: int = 300
    bytes_in: int = 500
    egress: Egress = Egress.DIRECT
    session_id: str | None = None
    http_version: str = "HTTP/2"


class MockRoblox:
    """`ctx.egress` for the test: records every call in mock.db and answers like a rate-limited Roblox."""

    def __init__(self, mock_path: str, worker: str, clock: ScaledClock) -> None:
        self.conn = sqlite3.connect(mock_path, timeout=30, isolation_level=None)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.worker = worker
        self.clock = clock
        self.credential = None
        self.rotator = None
        self.headers = None

    def is_enabled(self, egress: Egress) -> tuple[bool, str]:
        return (egress is Egress.DIRECT), ""

    async def send(self, egress: Egress, out: Any) -> MockResponse:
        at_ms = self.clock.now_ms()
        limited = at_ms < int((BASE_EPOCH + LIMITED_FOR_S) * 1000)
        status = 429 if limited else 200
        self.conn.execute(
            "INSERT INTO calls (at_ms, worker, egress, url, status) VALUES (?, ?, ?, ?, ?)",
            (at_ms, self.worker, egress.value, out.url, status),
        )
        if limited:
            headers = httpx.Headers({"retry-after": str(RETRY_AFTER_S), "content-type": "application/json"})
            return MockResponse(429, headers, b'{"errors":[{"code":0,"message":"Too many requests"}]}')
        return MockResponse(200, httpx.Headers({"content-type": "application/json"}), b'{"data":[]}')


@dataclass
class Collected:
    results: list[dict[str, Any]] = field(default_factory=list)


class Recorder:
    def __init__(self) -> None:
        self.rows_429 = 0

    def record_upstream_429(self, **row: Any) -> None:
        self.rows_429 += 1

    def record_event(self, *args: Any) -> None:
        pass

    def record_internal_call(self, purpose: str, **row: Any) -> None:
        pass


@dataclass
class Request:
    deadline_at: float
    request_id: str
    host: str = "games.roblox.com"
    path: str = "/v1/games"
    method: str = "GET"
    query: list[tuple[str, str]] = field(default_factory=lambda: [("universeIds", "1")])
    body: bytes = b""
    content_type: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    template: str = TEMPLATE


async def _worker(paths: dict[str, str], mock_path: str, name: str, mono0: float, out_path: str) -> None:
    from types import SimpleNamespace

    from roxy.config.runtime import load_runtime_settings
    from roxy.rules.store import load_rules_store
    from roxy.storage.db import open_databases
    from roxy.upstream.queue import Priority
    from roxy.upstream.service import UpstreamService

    clock = ScaledClock(mono0)
    env = {f"ROXY_{key.upper()}_DB": value for key, value in paths.items()}
    env["ROXY_STATE_DIR"] = str(Path(paths["hot"]).parent)
    dbs = open_databases(env)
    settings = await load_runtime_settings(dbs, clock)
    rules = await load_rules_store(dbs, clock)
    ctx = SimpleNamespace(
        clock=clock,
        dbs=dbs,
        settings=settings,
        rules=rules,
        egress=MockRoblox(mock_path, name, clock),
        recorder=Recorder(),
        worker_id=name,
        tasks=None,
    )
    service = UpstreamService(ctx, deadline_clock=clock.monotonic)  # deadlines below are on the scaled clock
    collected = Collected()
    limit = asyncio.Semaphore(40)
    tasks: set[asyncio.Task[Any]] = set()
    counter = 0

    async def one(index: int) -> None:
        async with limit:
            req = Request(deadline_at=clock.monotonic() + 60, request_id=f"{name}-{index}")
            started = clock.now_ms()
            result = await service.fetch(req, priority=Priority.INTERACTIVE, stale_available=False)
            collected.results.append(
                {
                    "at_ms": started,
                    "reason": result.reason.value,
                    "status": result.status,
                    "retry_after_s": result.retry_after_s,
                    "egress": result.egress.value,
                }
            )

    next_refresh = clock.now() + 1.0
    try:
        while clock.now() < BASE_EPOCH + RUN_FOR_S:
            counter += 1
            task = asyncio.ensure_future(one(counter))
            tasks.add(task)
            task.add_done_callback(tasks.discard)
            if clock.now() >= next_refresh:
                await settings.refresh_if_changed()
                await rules.refresh_if_changed()
                next_refresh = clock.now() + 1.0
            await clock.sleep(REQUEST_GAP_S)
        await asyncio.gather(*list(tasks), return_exceptions=True)
    finally:
        await asyncio.to_thread(Path(out_path).write_text, json.dumps(collected.results), encoding="utf-8")
        await dbs.close_all()


def worker_main(paths: dict[str, str], mock_path: str, name: str, mono0: float, out_path: str) -> None:
    asyncio.run(_worker(paths, mock_path, name, mono0, out_path))


def _prepare(tmp_path: Path) -> tuple[dict[str, str], str]:
    paths = {name: tmp_path / f"{name}.db" for name in DB_NAMES}
    migrate_paths(paths)
    control = sqlite3.connect(str(paths["control"]), isolation_level=None)
    now = int(BASE_EPOCH)
    overrides = {
        "endpoint_bucket_default_per_min": ENDPOINT_PER_MIN,
        "endpoint_bucket_default_burst": ENDPOINT_BURST,
        "rotator_enabled": 0,
    }
    for key, value in overrides.items():
        control.execute(
            "INSERT INTO settings (key, value_json, updated_at, updated_by) VALUES (?, ?, ?, 'test')",
            (key, json.dumps(value), now),
        )
    from roxy.config.runtime import bump_config_version

    control.execute("BEGIN IMMEDIATE")
    bump_config_version(control, now)
    control.execute("COMMIT")
    control.close()
    mock_path = tmp_path / "mock.db"
    mock = sqlite3.connect(str(mock_path), isolation_level=None)
    mock.execute("PRAGMA journal_mode=WAL")
    mock.execute(
        "CREATE TABLE calls (id INTEGER PRIMARY KEY, at_ms INTEGER, worker TEXT, egress TEXT, url TEXT, status INTEGER)"
    )
    mock.close()
    return {name: str(path) for name, path in paths.items()}, str(mock_path)


def test_429_retry_after_30_holds_across_two_processes(tmp_path: Path) -> None:
    paths, mock_path = _prepare(tmp_path)
    mono0 = time.monotonic() + 1.5  # both processes start their fake time at the same instant, after spawning
    outputs = [tmp_path / f"results-{name}.json" for name in ("a", "b")]
    procs = [
        CTX.Process(target=worker_main, args=(paths, mock_path, name, mono0, str(out)), daemon=True)
        for name, out in zip(("a", "b"), outputs, strict=True)
    ]
    watcher = CooldownWatcher(paths["hot"], ScaledClock(mono0))  # when the 429 is recorded for every process
    watcher.start()
    try:
        for proc in procs:
            proc.start()
        for proc in procs:
            proc.join(timeout=90)
    finally:
        watcher.stop()
    for proc in procs:
        if proc.is_alive():
            proc.kill()
    assert all(proc.exitcode == 0 for proc in procs), [proc.exitcode for proc in procs]

    mock = sqlite3.connect(mock_path)
    calls = mock.execute("SELECT at_ms, worker, egress, status FROM calls ORDER BY at_ms").fetchall()
    mock.close()
    hot = sqlite3.connect(paths["hot"])
    row = hot.execute("SELECT until_ms, set_at, source FROM cooldown WHERE key = ?", (COOLDOWN_KEY,)).fetchone()
    hot.close()

    assert calls, "the mock saw no calls at all"
    assert {egress for _, _, egress, _ in calls} == {"direct"}  # never the credential (and the rotator is off)
    limited = [call for call in calls if call[3] == 429]
    assert limited, "the mock never answered 429"
    assert row is not None, "no cooldown was recorded"
    until_ms, _set_at, source = int(row[0]), float(row[1]), str(row[2])
    assert source == "retry_after"
    first_429 = limited[0][0]
    assert until_ms >= first_429 + RETRY_AFTER_S * 1000
    recorded = watcher.seen_ms
    assert recorded is not None, "hot.db never showed the cooldown while the processes ran"
    assert recorded - first_429 <= RECORD_LAG_MAX_MS, (first_429, recorded)  # recorded promptly after the 429

    # 1. Once the cooldown is recorded, no process calls the endpoint until it ends (beyond calls already on the wire).
    during = [call for call in calls if recorded + IN_FLIGHT_TOLERANCE_MS < call[0] < until_ms]
    assert during == [], f"calls during the cooldown: {during[:5]} (first 429 at {first_429}, recorded at {recorded})"

    # 3. After the cooldown, at most the bucket's limit in any minute, burst included (a window bucket: 60 per minute
    #    with burst 2 means at most 60, never 61), and it recovers. The 429 also cut the limit for both processes
    #    (adaptive rate, rate and burst together), and no minute after the cooldown holds more than the cut limit.
    after = [call for call in calls if until_ms <= call[0] < until_ms + 60_000]
    assert 1 <= len(after) <= ENDPOINT_PER_MIN, len(after)
    assert all(call[3] == 200 for call in after)
    control = sqlite3.connect(paths["control"])
    learned = control.execute(
        "SELECT per_min, burst, origin FROM upstream_limits WHERE bucket_key = ?", (f"endpoint:{TEMPLATE}",)
    ).fetchone()
    control.close()
    assert learned is not None, "the 429 cut no limit"
    assert learned[2] == "adaptive", learned
    assert float(learned[0]) < ENDPOINT_PER_MIN, learned
    assert int(learned[1]) <= ENDPOINT_BURST, learned
    recovered = [call[0] for call in calls if call[0] >= until_ms]
    for at in recovered:
        assert sum(1 for t in recovered if at - 60_000 <= t <= at) <= int(float(learned[0])), (at, learned)

    # 2. Every caller answer refused during the cooldown carried a Retry-After, in both processes.
    results = {path.name: json.loads(path.read_text(encoding="utf-8")) for path in outputs}
    for name, items in results.items():
        cooling = [item for item in items if item["reason"] == ReasonCode.UPSTREAM_COOLDOWN.value]
        assert cooling, f"{name} never answered from the cooldown"
        assert all(item["retry_after_s"] and item["retry_after_s"] >= 1 for item in cooling)
        assert all(item["status"] == 429 for item in cooling)
        assert not [item for item in items if item["egress"] == "credential"]
    print(  # for the report: what the fleet did
        f"\ncalls={len(calls)} 429s={len(limited)} recorded_after={recorded - first_429}ms "
        f"cooldown={(until_ms - first_429) / 1000:.1f}s "
        f"after_60s={len(after)} answers={sum(len(v) for v in results.values())}"
    )
