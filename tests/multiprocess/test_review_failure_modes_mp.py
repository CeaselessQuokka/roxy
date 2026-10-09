"""Adversarial review (multi-process and failure modes lens): reproductions with real processes.

What this is
    Tests written by the review of plan C6, C7, 6.3, 6.9, 7.3, 7.5 and 10.6. Each one runs real processes that
    share temporary SQLite files: worker processes, and a "lock holder" process that takes hot.db's write lock
    (`BEGIN IMMEDIATE`) the way a stalled worker, a long prune batch or a backup would. They check that limits and
    budgets do not multiply with workers, that cooldowns and breakers act fleet-wide, that single-flight followers
    never go upstream, and what the request path does while hot.db cannot be written.

Why it exists
    The package tests prove each mechanism on its own; these tests attack the seams between processes and the
    failure paths (plan 19.3, C7). A test that reproduced a finding of the review names the finding id in its
    docstring. Every such finding is fixed (wave 2 fix pass 1), so the tests run as ordinary tests that pin the
    corrected behavior; none is marked `xfail` any more.

How it works
    `_hold_hot_lock` (a child process) keeps hot.db write-locked until told to stop. Abuse, tarpit, cache and
    upstream objects are the real ones, built the way the lifespan builds them, over migrated temporary databases;
    Roblox is a fake egress or a fake upstream that counts calls in a file or in shared memory. Clocks are real
    (wall clock and monotonic), or a shared scaled clock where minutes of simulated time are needed.

What to read next
    `roxy/storage/db.py` (the writer thread and busy circuit), `roxy/abuse/pipeline.py` (C7 degraded mode),
    `roxy/upstream/singleflight.py` and `roxy/cache/service.py` (single-flight), `roxy/upstream/breaker.py`.
"""

from __future__ import annotations

import asyncio
import json
import multiprocessing as mp
import os
import sqlite3
import sys
import time
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from roxy.abuse.pipeline import AbusePipeline
from roxy.abuse.tarpit import Tarpit
from roxy.abuse.verdict import Allow
from roxy.cache.service import CacheService
from roxy.cache.testing import FakeSettings, FakeUpstream, StaticRules, failure, make_request, ok
from roxy.config.catalog import CATALOG
from roxy.core.clock import SystemClock
from roxy.core.reasons import Egress, ReasonCode
from roxy.rules.store import RulesSnapshot
from roxy.storage.db import DB_NAMES, Database
from roxy.storage.migrate import migrate_paths

pytestmark = [
    pytest.mark.multiprocess,
    pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX processes"),
]

CTX = mp.get_context("spawn")
IP = "203.0.113.7"  # TEST-NET-3 documentation range: never a real client


# --------------------------------------------------------------------------------------------- shared helpers


def _hold_hot_lock(path: str, ready: Any, release: Any, hold_s: float) -> None:
    """Child process: hold hot.db's write lock until `release` is set (or `hold_s` passed)."""
    conn = sqlite3.connect(path, isolation_level=None, timeout=30)
    conn.execute("BEGIN IMMEDIATE")
    ready.set()
    release.wait(hold_s)
    conn.execute("ROLLBACK")
    conn.close()


@pytest.fixture
def paths(tmp_path: Path) -> dict[str, str]:
    """Four migrated databases in a temporary directory."""
    files = {name: tmp_path / f"{name}.db" for name in DB_NAMES}
    migrate_paths(files)
    return {name: str(path) for name, path in files.items()}


@pytest.fixture
def procs() -> Iterator[list[Any]]:
    started: list[Any] = []
    yield started
    for proc in started:
        if proc.is_alive():
            proc.kill()
        proc.join(5)


@dataclass
class HotLock:
    """A running lock holder process and the event that ends its hold."""

    release: Any
    proc: Any

    def stop(self) -> None:
        self.release.set()
        self.proc.join(10)


def _lock_hot(procs: list[Any], hot_path: str, hold_s: float = 60.0) -> HotLock:
    ready, release = CTX.Event(), CTX.Event()
    proc = CTX.Process(target=_hold_hot_lock, args=(hot_path, ready, release, hold_s), daemon=True)
    proc.start()
    procs.append(proc)
    assert ready.wait(20), "the lock holder never took hot.db's write lock"
    return HotLock(release, proc)


class _Settings:
    """Catalog defaults plus overrides (the read side of RuntimeSettings that abuse and tarpit use)."""

    def __init__(self, overrides: dict[str, Any]) -> None:
        self.values = {key: spec.default for key, spec in CATALOG.items()}
        self.values.update(overrides)

    def snapshot(self) -> dict[str, Any]:
        return dict(self.values)


class _Req:
    """The ProxyRequest fields the abuse pipeline and the tarpit read."""

    def __init__(self, ip: str = IP) -> None:
        self.client_ip = ip
        self.limit_key = ip
        self.method = "GET"
        self.host = "games.roblox.com"
        self.path = "/v1/games"
        self.query: list[tuple[str, str]] = []
        self.body = b""
        self.headers = {"user-agent": "Roblox/Linux"}
        self.header_names_in_order = ["user-agent"]
        self.user_agent = "Roblox/Linux"
        self.place_id = None
        self.is_browser = False
        self.template = "games.roblox.com/v1/games"
        self.bypass = False
        self.deadline_at = time.monotonic() + 60.0
        self.target_problem = None
        self.fresh_cache_hit = False
        self.request_id = "review"


def _pipeline(hot: Database, workers: int, limit: int = 10, window: int = 50) -> AbusePipeline:
    settings = _Settings(
        {
            "allowed_requests_per_minute": limit,
            "throttle_reset_duration": window,
            "flood_limit_per_minute": 100_000,
            "spam_enabled": 0,
        }
    )
    return AbusePipeline(
        settings=settings,
        rules=RulesSnapshot.empty(),
        hot_db=hot,
        control_db=None,
        clock=SystemClock(),
        worker_id=f"review-{os.getpid()}",
        workers=workers,
    )


# ============================================================ C7: hot.db write-locked by another process


async def test_review_locked_hot_db_abuse_decisions_stay_prompt(paths: dict[str, str], procs: list[Any]) -> None:
    """C7: while another process holds hot.db, every request must still get its verdict promptly from the
    per-worker degraded limiter. 16 requests arrive together (a modest burst for one worker). Finding HOT-HOL (fixed
    in `storage/db.py`): a short busy budget is a deadline from enqueue time, so the queue cannot add N x 0.5 s."""
    lock = _lock_hot(procs, paths["hot"])
    hot = Database("hot", paths["hot"])
    pipeline = _pipeline(hot, workers=2)
    started = time.monotonic()
    finished: list[float] = []

    async def one(index: int) -> None:
        await pipeline.evaluate(_Req(f"203.0.113.{index + 1}"))
        finished.append(time.monotonic() - started)

    try:
        await asyncio.gather(*(one(i) for i in range(16)))
    finally:
        lock.stop()
        await hot.close()
    assert pipeline.degraded
    print(f"\nslowest verdict {max(finished):.2f} s, median {sorted(finished)[8]:.2f} s")
    assert max(finished) < 2.0, f"the last of 16 verdicts took {max(finished):.2f} s"
    assert sorted(finished)[8] < 1.0, "the median verdict waited more than one 0.5 s budget"
    assert hot.stats.deadline_failures >= 1  # the queued jobs gave up at their deadline instead of waiting in turn


def _degraded_worker(hot_path: str, count: int, start: Any, out: Any) -> None:
    asyncio.run(_degraded(hot_path, count, start, out))


async def _degraded(hot_path: str, count: int, start: Any, out: Any) -> None:
    hot = Database("hot", hot_path)
    pipeline = _pipeline(hot, workers=2)  # ROXY_WORKERS=2: the degraded share is 10 // 2 = 5
    await asyncio.get_running_loop().run_in_executor(None, start.wait, 60)
    admitted = refused = 0
    try:
        for _ in range(count):
            if isinstance(await pipeline.evaluate(_Req()), Allow):
                admitted += 1
            else:
                refused += 1
    finally:
        await hot.close()
        out.put((admitted, refused, pipeline.degraded))


def test_review_locked_hot_db_per_ip_limit_is_limit_over_workers_fleet_wide(
    paths: dict[str, str], procs: list[Any]
) -> None:
    """C7: with hot.db unavailable each of 2 workers enforces limit / workers in memory, so one client gets at most
    the configured limit fleet-wide (10 per 50 s), never 10 per worker."""
    lock = _lock_hot(procs, paths["hot"])
    start, out = CTX.Event(), CTX.Queue()
    workers = [CTX.Process(target=_degraded_worker, args=(paths["hot"], 8, start, out), daemon=True) for _ in "ab"]
    for proc in workers:
        proc.start()
        procs.append(proc)
    start.set()
    try:
        results = [out.get(timeout=120) for _ in workers]
    finally:
        lock.stop()
    assert all(degraded for _, _, degraded in results)
    assert [admitted for admitted, _, _ in results] == [5, 5]
    assert sum(admitted for admitted, _, _ in results) <= 10


async def test_review_entering_degraded_mode_does_not_refill_the_allowance(
    paths: dict[str, str], procs: list[Any]
) -> None:
    """C7 says the fallback is conservative. A client that sent its 10 allowed requests through hot.db must not be
    admitted again inside the same 50 s window just because hot.db became write-locked (finding DEGRADED-REFILL,
    fixed: the degraded walk starts from the shared row, which stays readable under another process's write lock).
    Concurrent requests of the client in one worker must not all start from that same row either."""
    hot = Database("hot", paths["hot"])
    pipeline = _pipeline(hot, workers=2)
    try:
        shared = [isinstance(await pipeline.evaluate(_Req()), Allow) for _ in range(10)]
        assert shared == [True] * 10
        assert not isinstance(await pipeline.evaluate(_Req()), Allow)  # the 11th is refused, as it should be
        lock = _lock_hot(procs, paths["hot"])
        try:
            degraded = [isinstance(await pipeline.evaluate(_Req()), Allow) for _ in range(5)]
            # A second client with half its allowance used in hot.db before the lock: 8 concurrent requests in
            # degraded mode admit at most what is left of a 5-per-50 s share, never 5 more per request batch.
            other = "198.51.100.77"
        finally:
            lock.stop()
        for _ in range(5):
            assert isinstance(await pipeline.evaluate(_Req(other)), Allow)
        lock = _lock_hot(procs, paths["hot"])
        try:
            burst = await asyncio.gather(*(pipeline.evaluate(_Req(other)) for _ in range(8)))
        finally:
            lock.stop()
    finally:
        await hot.close()
    assert pipeline.degraded
    print(f"\nadmitted after the switch to degraded mode: {sum(degraded)} of 5")
    assert sum(degraded) == 0
    admitted = sum(isinstance(verdict, Allow) for verdict in burst)
    print(f"admitted in a concurrent degraded burst after 5 shared requests: {admitted} of 8")
    assert admitted <= 2  # GCRA at 5 per 50 s from a row 5 requests deep (out of 10): at most 2 more fit


async def test_review_locked_hot_db_tarpit_never_holds(paths: dict[str, str], procs: list[Any]) -> None:
    """C7 and plan 10.6: without the shared slot count the tarpit fails closed: no hold, an instant refusal."""
    lock = _lock_hot(procs, paths["hot"])
    hot = Database("hot", paths["hot"])
    pit = Tarpit(_Settings({"tarpit_enabled": 1, "tarpit_on_probe": 1}), hot, SystemClock(), "review")
    started = time.monotonic()
    try:
        plan = await pit.plan("probe", _Req())
    finally:
        lock.stop()
        await hot.close()
    assert plan is None
    assert time.monotonic() - started < 1.0
    assert pit.stats.snapshot()["skipped"] == 1


# ------------------------------------------------- C7: the credential is never used while hot.db is unwritable


@dataclass
class _EgressReply:
    status: int
    headers: httpx.Headers
    body: bytes
    elapsed_ms: float = 5.0
    bytes_out: int = 100
    bytes_in: int = 100
    egress: Egress = Egress.DIRECT
    session_id: str | None = None
    http_version: str = "HTTP/2"


class _FakeCredential:
    """An active, usable credential (the manager's read side)."""

    def __init__(self) -> None:
        self.cooldowns: list[float] = []

    def status(self) -> Any:
        return SimpleNamespace(status="active")

    def available(self) -> bool:
        return True

    def cooldown_remaining(self) -> float:
        return 0.0

    async def set_cooldown(self, seconds: float, source: str) -> float:
        self.cooldowns.append(seconds)
        return seconds


class _FakeEgress:
    """`ctx.egress`: direct and credential enabled; records every send."""

    def __init__(self) -> None:
        self.sent: list[Egress] = []
        self.credential = _FakeCredential()
        self.rotator = None
        self.headers = None

    def is_enabled(self, egress: Egress, purpose: str | None = None) -> tuple[bool, str]:
        return egress in (Egress.DIRECT, Egress.CREDENTIAL), ""

    async def send(self, egress: Egress, out: Any) -> _EgressReply:
        self.sent.append(egress)
        return _EgressReply(200, httpx.Headers({"content-type": "application/json"}), b'{"robux":1}', egress=egress)


class _NullRecorder:
    def record_upstream_429(self, **row: Any) -> None:
        pass

    def record_event(self, *args: Any, **kwargs: Any) -> None:
        pass

    def record_internal_call(self, purpose: str, **row: Any) -> None:
        pass


@dataclass
class _UpReq:
    deadline_at: float
    request_id: str = "review"
    host: str = "economy.roblox.com"
    path: str = "/v1/user/currency"
    method: str = "GET"
    query: Sequence[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    content_type: str | None = None
    headers: Mapping[str, str] = field(default_factory=dict)
    template: str = "economy.roblox.com/v1/user/currency"


async def test_review_locked_hot_db_credential_never_used(paths: dict[str, str], procs: list[Any]) -> None:
    """C7: an allowlisted credential endpoint while hot.db is write-locked gets `degraded`, and nothing is sent
    with the credential (or anonymously instead). The control after the lock proves the credential would be used."""
    from roxy.config.audit import Actor
    from roxy.config.runtime import load_runtime_settings
    from roxy.rules.service import RulesService
    from roxy.rules.store import load_rules_store
    from roxy.storage.db import open_databases
    from roxy.upstream.queue import Priority
    from roxy.upstream.service import UpstreamService

    env = {f"ROXY_{name.upper()}_DB": path for name, path in paths.items()}
    env["ROXY_STATE_DIR"] = str(Path(paths["hot"]).parent)
    dbs = open_databases(env)
    clock = SystemClock()
    await RulesService(dbs.control).create(
        "credential_allowlist",
        {"pattern": "economy.roblox.com/v1/user/currency", "cache_private": True},
        Actor("cli", "review"),
        "review test",
    )
    egress = _FakeEgress()
    ctx = SimpleNamespace(
        clock=clock,
        dbs=dbs,
        settings=await load_runtime_settings(dbs, clock),
        rules=await load_rules_store(dbs, clock),
        egress=egress,
        recorder=_NullRecorder(),
        worker_id="review",
        tasks=None,
    )
    service = UpstreamService(ctx)
    try:
        lock = _lock_hot(procs, paths["hot"])
        try:
            locked = await service.fetch(
                _UpReq(deadline_at=time.monotonic() + 60), priority=Priority.INTERACTIVE, stale_available=False
            )
        finally:
            lock.stop()
        assert locked.reason is ReasonCode.DEGRADED
        assert egress.sent == []
        control = await service.fetch(
            _UpReq(deadline_at=time.monotonic() + 60), priority=Priority.INTERACTIVE, stale_available=False
        )
        assert control.reason is ReasonCode.UPSTREAM_OK
        assert egress.sent == [Egress.CREDENTIAL]
    finally:
        await dbs.close_all()


# ======================================================================= 6.9: single-flight across processes

TARGET = "games.roblox.com/v1/games/votes?universeIds=4343"
BIG_BODY = '{"data":"' + "z" * (16 * 1024) + '"}'  # 16 KiB: over the 8 KiB a lease row may carry


class _CountingUpstream(FakeUpstream):
    """FakeUpstream that appends one line per call to a shared file, then answers `BIG_BODY` after 0.5 s."""

    def __init__(self, calls_file: str, label: str) -> None:
        super().__init__()
        self.calls_file = calls_file
        self.label = label

    async def fetch(
        self, req: Any, *, priority: Any, stale_available: bool, purpose: str = "caller", lease: Any = None
    ) -> Any:
        await self.take_lease(lease)  # like the real upstream: the single-flight lease first, the call only if won
        fd = os.open(self.calls_file, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, f"{self.label}\n".encode())
        finally:
            os.close(fd)
        await asyncio.sleep(0.5)  # every other request arrives and follows meanwhile
        return ok(BIG_BODY)


def _flight_child(
    paths: dict[str, str], calls_file: str, label: str, settings: dict[str, Any], go: Any, out: Any
) -> None:
    asyncio.run(_flight_main(paths, calls_file, label, settings, go, out))


async def _flight_main(
    paths: dict[str, str], calls_file: str, label: str, settings: dict[str, Any], go: Any, out: Any
) -> None:
    dbs = SimpleNamespace(cache=Database("cache", paths["cache"]), hot=Database("hot", paths["hot"]))
    try:
        service = CacheService(
            dbs=dbs,
            settings=FakeSettings(settings),
            rules=StaticRules(),
            clock=SystemClock(),
            upstream=_CountingUpstream(calls_file, label),
            worker_id=f"{label}:{os.getpid()}",
        )
        await service.start()
        out.put(("ready", label, None))
        await asyncio.get_running_loop().run_in_executor(None, go.wait, 60)

        async def one() -> tuple[str, int]:
            req = make_request(TARGET)
            result = await service.serve(req, await service.peek(req))
            return result.cache_state.value, result.status

        results = await asyncio.gather(*(one() for _ in range(3)))
        out.put(("done", label, results))
        # A worker's graceful shutdown (lifespan close): the owner's store and outcome publish, which run after
        # its own callers were answered, land before the process exits.
        await service.close()
    finally:
        dbs.cache.close_sync()
        dbs.hot.close_sync()


def _collect(out: Any, kind: str, count: int, timeout: float = 90.0) -> list[tuple[str, str, Any]]:
    got: list[tuple[str, str, Any]] = []
    deadline = time.monotonic() + timeout
    while len(got) < count:
        item = out.get(True, max(0.1, deadline - time.monotonic()))
        if item[0] == kind:
            got.append(item)
    return got


@pytest.mark.parametrize(
    "settings",
    [{"cache_max_body": 4096}, {"cache_disk_enabled": 0}],
    ids=["answer_over_cache_max_body", "shared_disk_tier_off"],
)
def test_review_unstored_large_answer_costs_one_upstream_call(
    settings: dict[str, Any], paths: dict[str, str], procs: list[Any], tmp_path: Path
) -> None:
    """Finding SF-NOSTORE, plan 6.9 and 19.2: N concurrent requests for one key over 4 processes cause exactly 1
    upstream call, also when the owner's 16 KiB answer cannot be stored in cache.db (too big for
    `cache_max_body`, or the shared tier is off): it reaches the other processes through a handoff row."""
    calls_file = str(tmp_path / "calls.txt")
    go, out = CTX.Event(), CTX.Queue()
    for index in range(4):
        proc = CTX.Process(target=_flight_child, args=(paths, calls_file, f"p{index}", settings, go, out), daemon=True)
        proc.start()
        procs.append(proc)
    _collect(out, "ready", 4)
    go.set()
    done = _collect(out, "done", 4)
    results = [result for _, _, batch in done for result in batch]
    calls = Path(calls_file).read_text().split()
    print(f"\nupstream calls {len(calls)} for {len(results)} requests: {calls}")
    assert {status for _, status in results} == {200}
    assert len(calls) == 1
    states = sorted(state for state, _ in results)
    assert states == ["COALESCED"] * 11 + ["MISS"]  # every follower got the one answer, none fetched its own
    conn = sqlite3.connect(paths["cache"])
    try:  # the answer itself was never stored as a cache entry (only the short-lived handoff row exists)
        rows = conn.execute("SELECT key FROM entries WHERE substr(key, -8) != ' !flight'").fetchall()
    finally:
        conn.close()
    assert rows == []


async def test_review_unpublished_outcome_does_not_block_the_key(paths: dict[str, str], procs: list[Any]) -> None:
    """Finding SF-ORPHAN. The owner's fetch finishes (Roblox failed) while another process holds hot.db for about
    2 s, so the owner's outcome cannot be written into its lease row in time (its first publish attempt gives up
    after 1 s, and the one second linger passes). The owner's caller is answered at once anyway. Once hot.db is
    free, a new request for the key in the owner's worker AND one in another worker are answered at once (a new
    flight, or the owner's outcome when its retried publish lands), never after the owner deadline and never with
    503 coalesce_timeout; the other worker never calls upstream itself."""
    settings = {  # owner deadline 0.5 + 10 x 1 + 0.5 = 11 s, and followers give up after 5 s: a regression fails fast
        "queue_wait_interactive_ms": 500,
        "request_timeout": 10,
        "upstream_max_attempts": 1,
        "backoff_cap_ms": 500,
        "cache_coalesce_wait_ms": 5000,
    }

    def failing(req: Any, n: int) -> Any:
        return failure(ReasonCode.UPSTREAM_5XX, 503, retry_after_s=5)

    def worker(name: str, upstream: FakeUpstream) -> tuple[CacheService, Any]:
        dbs = SimpleNamespace(cache=Database("cache", paths["cache"]), hot=Database("hot", paths["hot"]))
        service = CacheService(
            dbs=dbs,
            settings=FakeSettings(settings),
            rules=StaticRules(),
            clock=SystemClock(),
            upstream=upstream,
            worker_id=name,
        )
        return service, dbs

    gate = asyncio.Event()
    up_owner, up_other = FakeUpstream(failing, gate=gate), FakeUpstream(failing)
    owner, owner_dbs = worker("review-owner", up_owner)
    other, other_dbs = worker("review-other", up_other)

    async def call(service: CacheService) -> Any:
        req = make_request(TARGET)
        return await service.serve(req, await service.peek(req))

    await owner.start()
    await other.start()
    try:
        first = asyncio.ensure_future(call(owner))
        await asyncio.wait_for(up_owner.started.wait(), 10)  # the owner holds the lease and is "fetching"
        lock = _lock_hot(procs, paths["hot"])
        released = False
        try:
            gate.set()
            opened = time.monotonic()
            answer = await asyncio.wait_for(first, 20)
            answered_after = time.monotonic() - opened
            assert answer.status == 503
            await asyncio.sleep(2.0)  # hot.db stays locked: the first publish attempt fails, the linger ends
            lock.stop()
            released = True
        finally:
            if not released:
                lock.stop()
        started = time.monotonic()
        mine, theirs = await asyncio.gather(call(owner), call(other))
        waited = time.monotonic() - started
    finally:
        for service, dbs in ((owner, owner_dbs), (other, other_dbs)):
            await service.close()
            await dbs.cache.close()
            await dbs.hot.close()
    print(
        f"\nowner answered after {answered_after:.2f} s; then {mine.reason.value} and {theirs.reason.value} after "
        f"{waited:.2f} s; publish retries {owner.flights.stats.publish_retries}"
    )
    assert answered_after < 1.0  # the owner's caller never waits for the publish
    assert mine.reason is not ReasonCode.COALESCE_TIMEOUT
    assert theirs.reason is not ReasonCode.COALESCE_TIMEOUT
    assert (mine.status, theirs.status) == (503, 503)
    assert waited < 1.5
    assert up_other.count == 0  # the other worker followed (the retried outcome, or the owner's new flight)


async def test_review_locked_cache_db_does_not_delay_answers(paths: dict[str, str], procs: list[Any]) -> None:
    """Finding CACHE-WAIT, plan 6.1 and C7 (the cache is disposable): while another process holds cache.db's write
    lock, 6 concurrent misses on different keys still get Roblox's answer promptly; only the caching of it fails,
    after the answer, and every failed write is counted. The worker keeps serving the answers from memory."""
    upstream = FakeUpstream()  # answers at once
    dbs = SimpleNamespace(cache=Database("cache", paths["cache"]), hot=Database("hot", paths["hot"]))
    service = CacheService(
        dbs=dbs,
        settings=FakeSettings({}),
        rules=StaticRules(),
        clock=SystemClock(),
        upstream=upstream,
        worker_id="review-cache",
    )
    await service.start()
    lock = _lock_hot(procs, paths["cache"])  # the same helper locks any database file
    started = time.monotonic()
    times: list[float] = []

    def target(n: int) -> str:
        return f"games.roblox.com/v1/games/votes?universeIds={500 + n}"

    async def one(n: int) -> Any:
        req = make_request(target(n))
        result = await service.serve(req, await service.peek(req))
        times.append(time.monotonic() - started)
        return result

    try:
        try:
            results = await asyncio.gather(*(one(n) for n in range(6)))
            await asyncio.sleep(3.0)  # cache.db stays locked past every write's 2 s budget: all six writes fail
        finally:
            lock.stop()
        await service.settle()
        again = await one(0)
        failures = service.stats.store_failures
        disk = service.disk_status()
    finally:
        await service.close()
        await dbs.cache.close()
        await dbs.hot.close()
    print(f"\nanswers after {sorted(round(t, 2) for t in times[:6])} s; failed writes {failures}")
    assert [result.status for result in results] == [200] * 6
    assert max(times[:6]) < 1.0
    assert upstream.count == 6
    assert failures == 6  # counted, never the caller's problem
    assert disk["Failures"] == 6
    assert again.cache_state.value == "HIT"  # still served from this worker's memory tier
    assert upstream.count == 6


# ============================================================================== 7.10: breakers are fleet-wide

SPEED = 10.0
BASE_EPOCH = 1_760_000_000.0
FAIL_FOR_S = 1000.0  # the mock answers 503 for the whole run, so the half-open probe fails too (and is visible)
BREAKER_OPEN_S = 30
RUN_FOR_S = 45.0
REQUEST_GAP_S = 0.2


class ScaledClock:
    """A shared fast clock: `SPEED` fake seconds per real second, the same in every process (plan 19.3)."""

    def __init__(self, mono0: float) -> None:
        self.mono0 = mono0

    def _elapsed(self) -> float:
        return (time.monotonic() - self.mono0) * SPEED

    def now(self) -> float:
        return BASE_EPOCH + self._elapsed()

    def now_ms(self) -> int:
        return int(self.now() * 1000)

    def monotonic(self) -> float:
        return 1000.0 + self._elapsed()

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(max(0.0, seconds) / SPEED)


class _BreakerLog:
    """What one worker process saw, kept in memory and written to mock.db once, after the run.

    The mock must not block the event loop: a synchronous SQLite insert per call (with a commit and an fsync, while
    the other process inserts into the same file) stalled the loop between a reservation and its send, so a call
    reserved before the breaker opened could be sent well after it, which the test then read as a call through an
    open breaker (a flake seen in the review round gate). Real egress sends are async and never do that.
    """

    def __init__(self, worker: str, clock: ScaledClock) -> None:
        self.worker = worker
        self.clock = clock
        self.calls: list[tuple[int, str, int]] = []
        self.events: list[tuple[int, str, str]] = []

    def write(self, mock_path: str) -> None:
        conn = sqlite3.connect(mock_path, timeout=30, isolation_level=None)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.executemany("INSERT INTO calls (at_ms, worker, status) VALUES (?, ?, ?)", self.calls)
            conn.executemany("INSERT INTO events (at_ms, worker, type) VALUES (?, ?, ?)", self.events)
            conn.execute("COMMIT")
        finally:
            conn.close()


class _FailingRoblox:
    """`ctx.egress`: direct only; 503 for the first `FAIL_FOR_S` fake seconds; every call kept in the `_BreakerLog`."""

    def __init__(self, log: _BreakerLog) -> None:
        self.log = log
        self.credential = None
        self.rotator = None
        self.headers = None

    def is_enabled(self, egress: Egress, purpose: str | None = None) -> tuple[bool, str]:
        return egress is Egress.DIRECT, ""

    async def send(self, egress: Egress, out: Any) -> _EgressReply:
        at_ms = self.log.clock.now_ms()
        status = 503 if at_ms < int((BASE_EPOCH + FAIL_FOR_S) * 1000) else 200
        self.log.calls.append((at_ms, self.log.worker, status))
        return _EgressReply(status, httpx.Headers({"content-type": "application/json"}), b"{}")


class _BreakerEventRecorder(_NullRecorder):
    """`ctx.recorder` for the breaker test: keeps each breaker transition with the shared clock's time.

    The upstream records a transition right after the hot.db write that made it commits, so the first `breaker_open`
    row is when the breaker really opened for the fleet. The fifth failing call's send time is only an estimate of
    it: that call's own bookkeeping write lands later, after the answer, and how much later depends on how busy
    hot.db and the machine are.
    """

    def __init__(self, log: _BreakerLog) -> None:
        self.log = log

    def record_event(self, event_type: str, *args: Any, **kwargs: Any) -> None:
        if event_type.startswith("breaker_"):
            self.log.events.append((self.log.clock.now_ms(), self.log.worker, event_type))


async def _breaker_worker(paths: dict[str, str], mock_path: str, name: str, mono0: float) -> None:
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
    log = _BreakerLog(name, clock)
    ctx = SimpleNamespace(
        clock=clock,
        dbs=dbs,
        settings=settings,
        rules=rules,
        egress=_FailingRoblox(log),
        recorder=_BreakerEventRecorder(log),
        worker_id=name,
        tasks=None,
    )
    service = UpstreamService(ctx, deadline_clock=clock.monotonic)
    tasks: set[asyncio.Task[Any]] = set()
    counter = 0

    async def one(index: int) -> None:
        req = _UpReq(
            deadline_at=clock.monotonic() + 60,
            request_id=f"{name}-{index}",
            host="games.roblox.com",
            path="/v1/games",
            template="games.roblox.com/v1/games",
        )
        await service.fetch(req, priority=Priority.INTERACTIVE, stale_available=False)

    try:
        while clock.now() < BASE_EPOCH + RUN_FOR_S:
            counter += 1
            task = asyncio.ensure_future(one(counter))
            tasks.add(task)
            task.add_done_callback(tasks.discard)
            await clock.sleep(REQUEST_GAP_S)
        await asyncio.gather(*list(tasks), return_exceptions=True)
    finally:
        await dbs.close_all()
        log.write(mock_path)


def _breaker_main(paths: dict[str, str], mock_path: str, name: str, mono0: float) -> None:
    asyncio.run(_breaker_worker(paths, mock_path, name, mono0))


def test_review_breaker_opens_and_probes_fleet_wide(paths: dict[str, str], procs: list[Any], tmp_path: Path) -> None:
    """Plan 7.10 and C6: once 5 failures (counted from both processes) open the breaker, NEITHER process calls the
    endpoint until it turns half-open; then exactly one probe goes out for the whole fleet. The mock keeps failing,
    so the probe fails and reopens the breaker for twice as long: one call in the half-open window, no more."""
    from roxy.config.runtime import bump_config_version

    control = sqlite3.connect(paths["control"], isolation_level=None)
    overrides = {
        "rotator_enabled": 0,
        "upstream_max_attempts": 1,  # one call per request, so calls are easy to attribute
        "breaker_failure_threshold": 5,
        "breaker_window_s": 30,
        "breaker_open_s": BREAKER_OPEN_S,
    }
    for key, value in overrides.items():
        control.execute(
            "INSERT INTO settings (key, value_json, updated_at, updated_by) VALUES (?, ?, ?, 'review')",
            (key, json.dumps(value), int(BASE_EPOCH)),
        )
    control.execute("BEGIN IMMEDIATE")
    bump_config_version(control, int(BASE_EPOCH))
    control.execute("COMMIT")
    control.close()
    mock_path = str(tmp_path / "mock.db")
    mock = sqlite3.connect(mock_path, isolation_level=None)
    mock.execute("PRAGMA journal_mode=WAL")
    mock.execute("CREATE TABLE calls (id INTEGER PRIMARY KEY, at_ms INTEGER, worker TEXT, status INTEGER)")
    mock.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, at_ms INTEGER, worker TEXT, type TEXT)")
    mock.close()

    mono0 = time.monotonic() + 1.5  # both processes start their fake time at the same instant
    for name in ("a", "b"):
        proc = CTX.Process(target=_breaker_main, args=(paths, mock_path, name, mono0), daemon=True)
        proc.start()
        procs.append(proc)
    for proc in procs:
        proc.join(timeout=120)
    assert all(proc.exitcode == 0 for proc in procs), [proc.exitcode for proc in procs]

    mock = sqlite3.connect(mock_path)
    calls = mock.execute("SELECT at_ms, worker, status FROM calls ORDER BY at_ms").fetchall()
    opens = [row[0] for row in mock.execute("SELECT at_ms FROM events WHERE type = 'breaker_open' ORDER BY at_ms")]
    mock.close()
    assert len(calls) >= 5
    assert {call[1] for call in calls[:5]} == {"a", "b"}  # both processes fed the breaker
    assert opens, "the breaker never opened"
    # The time the breaker really opened for the fleet: the commit of the write that counted the fifth failure,
    # recorded by the upstream right after it (`_BreakerEventRecorder`). The fifth call's own send time used to stand
    # in for it, but that call's bookkeeping lands after its answer, so calls the still closed breaker admitted
    # meanwhile were counted as calls through an open breaker (a flake in the review round gate).
    opened_at = opens[0]
    assert len([call for call in calls if call[0] <= opened_at]) >= 5  # it opened on the fifth failure, not before
    settle_ms = 1000  # fake ms (0.1 s real): calls reserved before the breaker opened may still land
    half_open_ms = opened_at + BREAKER_OPEN_S * 1000
    during = [call for call in calls if opened_at + settle_ms < call[0] < half_open_ms - 1500]
    assert during == [], f"calls while the breaker was open: {during[:5]}"
    probes = [call for call in calls if call[0] >= half_open_ms - 1500]
    print(f"\ncalls={len(calls)} open_window_calls={len(during)} probes={probes} open_lag_ms={opened_at - calls[4][0]}")
    assert len(probes) == 1, probes  # one probe for the fleet; its failure reopened the breaker for 60 s
