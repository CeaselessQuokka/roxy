"""Multi-process correctness of the abuse layer (plan 19.3, C6): real processes sharing one temporary hot.db.

1. `test_gcra_at_exact_limit_never_refused` (plan 10.2): two processes take turns sending requests at exactly
   L per W for 10 simulated minutes (a controlled clock: each request is evaluated at its scheduled time), and not
   one is refused.
2. A burst from two processes at the same instant admits exactly L requests in total (atomic admit, no limit + 1).
3. The tarpit's fleet-wide cap holds under contention from 4 processes (plan 10.6): never more holds than the cap.
"""

from __future__ import annotations

import asyncio
import multiprocessing as mp
import sys
from pathlib import Path
from typing import Any

import pytest

from roxy.abuse.pipeline import AbusePipeline
from roxy.abuse.tarpit import Tarpit
from roxy.abuse.verdict import Allow
from roxy.config.catalog import CATALOG
from roxy.core.clock import FakeClock, SystemClock
from roxy.rules.store import RulesSnapshot
from roxy.storage.db import DB_NAMES, Database
from roxy.storage.migrate import migrate_paths

pytestmark = [
    pytest.mark.multiprocess,
    pytest.mark.skipif(sys.platform == "win32", reason="needs fork-safe POSIX processes"),
]

CTX = mp.get_context("spawn")
START_MS = 1_760_000_000_000
IP = "203.0.113.7"  # TEST-NET-3 documentation range


class _Settings:
    """Catalog defaults plus overrides (the read side of RuntimeSettings)."""

    def __init__(self, overrides: dict[str, Any]) -> None:
        self.values = {key: spec.default for key, spec in CATALOG.items()}
        self.values.update(overrides)

    def snapshot(self) -> dict[str, Any]:
        return dict(self.values)


class _Req:
    def __init__(self) -> None:
        self.client_ip = IP
        self.limit_key = IP
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
        self.deadline_at = 0.0
        self.target_problem = None
        self.fresh_cache_hit = False
        self.request_id = "mp"


def _pipeline(hot: Database, clock: Any, index: int, limit: int, window: int) -> AbusePipeline:
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
        clock=clock,
        worker_id=f"worker-{index}",
        workers=2,
    )


# --- 1. exact rate, two processes, controlled clock -------------------------------------------------------------------


def _exact_rate_worker(
    hot_path: str,
    index: int,
    workers: int,
    limit: int,
    window: int,
    total: int,
    turn: Any,
    cond: Any,
    out: Any,
    speed: float = 1.0,
) -> None:
    asyncio.run(_exact_rate(hot_path, index, workers, limit, window, total, turn, cond, out, speed))


async def _exact_rate(
    hot_path: str,
    index: int,
    workers: int,
    limit: int,
    window: int,
    total: int,
    turn: Any,
    cond: Any,
    out: Any,
    speed: float,
) -> None:
    hot = Database("hot", hot_path)
    clock = FakeClock(START_MS / 1000)
    pipeline = _pipeline(hot, clock, index, limit, window)
    interval_ms = window * 1000 / limit / speed  # speed 1.0 is exactly L per W
    admitted = refused = 0
    try:
        for i in range(index, total, workers):
            with cond:
                if not cond.wait_for(lambda i=i: turn.value == i, timeout=60):
                    raise TimeoutError(f"turn {i} never came")
            clock.set((START_MS + round(i * interval_ms)) / 1000)  # this request's scheduled time
            verdict = await pipeline.evaluate(_Req())
            if isinstance(verdict, Allow):
                admitted += 1
            else:
                refused += 1
            with cond:
                turn.value = i + 1
                cond.notify_all()
    finally:
        await hot.close()
        out.put((index, admitted, refused, pipeline.degraded))


@pytest.fixture
def hot_path(tmp_path: Path) -> Path:
    paths = {name: tmp_path / f"{name}.db" for name in DB_NAMES}
    migrate_paths(paths)
    return paths["hot"]


def _run_rate(hot_path: Path, limit: int, window: int, total: int, speed: float) -> list[Any]:
    """Two processes take turns: request i is evaluated by process i % 2 at its scheduled time."""
    workers = 2
    turn = CTX.Value("i", 0)
    cond = CTX.Condition()
    out = CTX.Queue()
    procs = [
        CTX.Process(
            target=_exact_rate_worker,
            args=(str(hot_path), i, workers, limit, window, total, turn, cond, out, speed),
        )
        for i in range(workers)
    ]
    for proc in procs:
        proc.start()
    results = [out.get(timeout=120) for _ in procs]
    for proc in procs:
        proc.join(timeout=30)
        assert proc.exitcode == 0
    return results


@pytest.mark.parametrize(("limit", "window"), [(10, 50), (7, 60), (1, 5)])
def test_gcra_at_exact_limit_never_refused(hot_path: Path, limit: int, window: int) -> None:
    total = int(600 * limit / window) + 1  # 10 simulated minutes at exactly L per W, both ends included
    results = _run_rate(hot_path, limit, window, total, 1.0)
    assert sum(r[1] for r in results) == total
    assert sum(r[2] for r in results) == 0
    assert not any(r[3] for r in results)  # never degraded: every decision used the shared hot.db
    assert all(r[1] > 0 for r in results)  # both processes really took part


def test_slightly_faster_than_the_limit_is_refused_across_processes(hot_path: Path) -> None:
    """The control for the test above: the same setup 2 percent too fast must see refusals."""
    results = _run_rate(hot_path, 1, 5, 60, 1.02)
    assert sum(r[2] for r in results) > 0


# --- 2. burst from two processes --------------------------------------------------------------------------------------


def _burst_worker(hot_path: str, index: int, count: int, barrier: Any, out: Any) -> None:
    asyncio.run(_burst(hot_path, index, count, barrier, out))


async def _burst(hot_path: str, index: int, count: int, barrier: Any, out: Any) -> None:
    hot = Database("hot", hot_path)
    clock = FakeClock(START_MS / 1000)  # both processes: the same instant
    pipeline = _pipeline(hot, clock, index, 10, 50)
    barrier.wait(timeout=30)
    admitted = 0
    try:
        for _ in range(count):
            if isinstance(await pipeline.evaluate(_Req()), Allow):
                admitted += 1
    finally:
        await hot.close()
        out.put(admitted)


def test_gcra_burst_across_processes_admits_exactly_the_limit(hot_path: Path) -> None:
    barrier = CTX.Barrier(2)
    out = CTX.Queue()
    procs = [CTX.Process(target=_burst_worker, args=(str(hot_path), i, 15, barrier, out)) for i in range(2)]
    for proc in procs:
        proc.start()
    admitted = [out.get(timeout=120) for _ in procs]
    for proc in procs:
        proc.join(timeout=30)
        assert proc.exitcode == 0
    assert sum(admitted) == 10  # v1 served limit + 1 and raced; v2 admits exactly L fleet-wide


# --- 3. tarpit cap under contention -----------------------------------------------------------------------------------


def _tarpit_worker(
    hot_path: str, index: int, attempts: int, cap: int, current: Any, peak: Any, lock: Any, out: Any
) -> None:
    asyncio.run(_tarpit(hot_path, index, attempts, cap, current, peak, lock, out))


async def _tarpit(
    hot_path: str, index: int, attempts: int, cap: int, current: Any, peak: Any, lock: Any, out: Any
) -> None:
    hot = Database("hot", hot_path)
    pit = Tarpit(_Settings({"tarpit_max_concurrent": cap}), hot, SystemClock(), f"worker-{index}")

    async def one() -> bool:
        plan = await pit.plan("probe", _Req())
        if plan is None:
            return False
        try:
            with lock:
                current.value += 1
                peak.value = max(peak.value, current.value)
            await asyncio.sleep(0.3)  # the hold itself (shortened for the test)
            with lock:
                current.value -= 1
        finally:
            await plan.release()
        return True

    try:
        held = 0
        for _ in range(3):
            results = await asyncio.gather(*(one() for _ in range(attempts)))
            held += sum(results)
        snapshot = pit.stats.snapshot()
    finally:
        await hot.close()
    out.put((held, snapshot["skipped"]))


def test_tarpit_cap_holds_under_contention_across_processes(hot_path: Path) -> None:
    cap = 5
    current = CTX.Value("i", 0)
    peak = CTX.Value("i", 0)
    lock = CTX.Lock()
    out = CTX.Queue()
    procs = [
        CTX.Process(target=_tarpit_worker, args=(str(hot_path), i, 8, cap, current, peak, lock, out)) for i in range(4)
    ]
    for proc in procs:
        proc.start()
    results = [out.get(timeout=120) for _ in procs]
    for proc in procs:
        proc.join(timeout=30)
        assert proc.exitcode == 0
    held = sum(r[0] for r in results)
    skipped = sum(r[1] for r in results)
    assert peak.value <= cap  # the fleet-wide cap held at every instant
    assert held >= cap  # holds really happened
    assert skipped > 0  # and the cap really refused some (contention happened)
    assert held + skipped == 4 * 8 * 3
