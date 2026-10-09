"""Worker heartbeats: every worker writes its vital signs every 5 s, and the fleet view reads them back.

What this is
    `HeartbeatReporter` upserts this worker's row in metrics.db `worker_heartbeat` (pid, color, start time, RSS,
    request counters, event loop lag p99, open connections, in-flight upstream calls, recycle threshold, leader
    flag). `fleet_view` reads all rows and marks which are fresh (seen in the last 20 s) and which one is the
    worker answering. `LoopLagMonitor` measures how late the event loop wakes up. `reset_fleet_counters`
    implements the System page "reset counts" button (parity rows 84 and 122).

Why it exists
    With several worker processes and two colors during a deploy, "how many workers are alive and how are they
    doing" can only be answered from shared state. A row that stops being updated (a crashed or frozen worker)
    goes stale after 20 s, so the System page shows Expected vs Count honestly (plan 4.5 row 84).

How it works
    - `beat()` is one small write. The upsert keeps the newest `counters_reset_at`: if an admin reset the
      counters after this worker's last beat, the row keeps the reset (zero counters) and the worker adopts it
      on the next beat by zeroing its in-memory counters.
    - Loop lag: a background coroutine sleeps 250 ms at a time and records how much later than asked it woke
      up. A blocked loop (synchronous SQLite, CPU work) shows up here long before gunicorn's 30 s watchdog.
    - Worker history: each beat also hands its CPU share (`CpuMeter`), loop lag p99, open connections and RSS to
      `on_sample` (the recorder's `record_worker_sample`), the per-minute history SYS-WORKER-SAT and SYS-LOOP-LAG
      read (plan 11.5).

What to read next
    `roxy/scheduler/jobs.py`, then the System page API (`roxy/admin/api/system.py`).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import socket
import sqlite3
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from roxy.core.clock import SYSTEM_CLOCK, Clock
from roxy.storage.db import Database, SharedStateUnavailable

log = logging.getLogger(__name__)

HEARTBEAT_INTERVAL_S = 5.0
HEARTBEAT_STALE_S = 20.0
REMOVE_BUSY_BUDGET_MS = 1000  # the shutdown delete of this worker's row: a stale row expires by itself in 20 s
"""A worker whose row is older than this is counted as gone (four missed beats)."""


@dataclass(slots=True)
class WorkerCounters:
    """In-memory per-worker counters shown in the fleet view. The proxy increments them on the event loop."""

    requests: int = 0
    proxied: int = 0
    reset_at: int | None = None

    def reset(self, at: int) -> None:
        self.requests = 0
        self.proxied = 0
        self.reset_at = at


@dataclass(frozen=True, slots=True)
class WorkerInfo:
    """Facts about this worker process that do not change while it runs."""

    worker_id: str
    color: str
    pid: int
    started_at: int
    hostname: str = ""
    master_pid: int | None = None
    max_requests: int | None = None
    version: str = ""

    @classmethod
    def current(
        cls, worker_id: str, color: str, started_at: float, *, max_requests: int | None = None, version: str = ""
    ) -> WorkerInfo:
        """Describe the running process (pid, parent pid as the gunicorn master, hostname)."""
        return cls(
            worker_id=worker_id,
            color=color,
            pid=os.getpid(),
            started_at=int(started_at),
            hostname=socket.gethostname(),
            master_pid=os.getppid(),
            max_requests=max_requests,
            version=version,
        )


def read_rss_bytes() -> int | None:
    """Current resident memory of this process, from /proc/self/statm (Linux), or None if unavailable."""
    try:
        with open("/proc/self/statm", encoding="ascii") as handle:
            resident_pages = int(handle.read().split()[1])
        return resident_pages * os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError, IndexError):
        return None


class CpuMeter:
    """This process's CPU use since the previous reading, in percent of one core (all threads: the event loop plus
    the SQLite writer and reader threads), for the per-minute worker history (SYS-WORKER-SAT, plan 11.5).

    `time.process_time()` is the process's user plus system CPU seconds, so no file under /proc or the cgroup has to
    be read; dividing its growth by the monotonic time between two readings gives the share of one core.
    """

    def __init__(
        self, *, clock: Callable[[], float] = time.monotonic, cpu: Callable[[], float] = time.process_time
    ) -> None:
        self._clock = clock
        self._cpu = cpu
        self._last: tuple[float, float] | None = None

    def read(self) -> float | None:
        """Percent of one core used since the last call; None on the first call (nothing to compare with yet)."""
        now, used = self._clock(), self._cpu()
        last, self._last = self._last, (now, used)
        if last is None or now - last[0] <= 0:
            return None
        return round(max(0.0, (used - last[1]) / (now - last[0]) * 100.0), 1)


class LoopLagMonitor:
    """Measures event loop lag: how much later than requested a short sleep returns. Bounded sample window."""

    def __init__(self, interval_s: float = 0.25, window: int = 240) -> None:
        self.interval_s = interval_s
        self._samples: deque[float] = deque(maxlen=window)  # 240 x 250 ms = the last minute

    def record(self, lag_ms: float) -> None:
        self._samples.append(max(0.0, lag_ms))

    def p99(self) -> float | None:
        """99th percentile of recent lag samples in ms (None before the first sample)."""
        if not self._samples:
            return None
        ordered = sorted(self._samples)
        index = min(len(ordered) - 1, round(0.99 * (len(ordered) - 1)))
        return round(ordered[index], 3)

    async def run(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            asked = time.monotonic()
            await asyncio.sleep(self.interval_s)
            self.record((time.monotonic() - asked - self.interval_s) * 1000)


_UPSERT = """
INSERT INTO worker_heartbeat (
    pid, started_at, last_seen, rss, requests, proxied, loop_lag_ms_p99, open_conns, inflight_upstream,
    worker_id, hostname, color, master_pid, max_requests, counters_reset_at, version, is_leader, cache_generation
) VALUES (
    :pid, :started_at, :last_seen, :rss, :requests, :proxied, :lag, :open_conns, :inflight,
    :worker_id, :hostname, :color, :master_pid, :max_requests, :reset_at, :version, :is_leader, :cache_generation
)
ON CONFLICT (pid) DO UPDATE SET
    started_at = excluded.started_at,
    last_seen = excluded.last_seen,
    rss = excluded.rss,
    -- An admin reset newer than this worker's own reset wins: keep zero counters until the worker adopts it.
    requests = CASE WHEN coalesce(worker_heartbeat.counters_reset_at, 0) > coalesce(excluded.counters_reset_at, 0)
                    THEN 0 ELSE excluded.requests END,
    proxied = CASE WHEN coalesce(worker_heartbeat.counters_reset_at, 0) > coalesce(excluded.counters_reset_at, 0)
                   THEN 0 ELSE excluded.proxied END,
    counters_reset_at = max(coalesce(worker_heartbeat.counters_reset_at, 0), coalesce(excluded.counters_reset_at, 0)),
    loop_lag_ms_p99 = excluded.loop_lag_ms_p99,
    open_conns = excluded.open_conns,
    inflight_upstream = excluded.inflight_upstream,
    worker_id = excluded.worker_id,
    hostname = excluded.hostname,
    color = excluded.color,
    master_pid = excluded.master_pid,
    max_requests = excluded.max_requests,
    version = excluded.version,
    is_leader = excluded.is_leader,
    cache_generation = excluded.cache_generation
"""


class HeartbeatReporter:
    """Writes this worker's heartbeat row. Run `run(stop)` as a per-worker background task."""

    def __init__(
        self,
        metrics: Database,
        info: WorkerInfo,
        clock: Clock | None = None,
        *,
        counters: WorkerCounters | None = None,
        lag: LoopLagMonitor | None = None,
        open_conns: Callable[[], int | None] | None = None,
        inflight_upstream: Callable[[], int | None] | None = None,
        is_leader: Callable[[], bool] | None = None,
        cache_generation: Callable[[], int | None] | None = None,
        rss: Callable[[], int | None] = read_rss_bytes,
        on_sample: Callable[[dict[str, Any]], None] | None = None,
        cpu: CpuMeter | None = None,
    ) -> None:
        self.metrics = metrics
        self.info = info
        self.clock = clock or SYSTEM_CLOCK
        self.counters = counters or WorkerCounters()
        self.lag = lag
        self._open_conns = open_conns
        self._inflight = inflight_upstream
        self._is_leader = is_leader
        self._cache_generation = cache_generation
        self._rss = rss
        # `on_sample(values)` receives this worker's vital signs on every beat, whether or not the row could be
        # written: the lifespan hands them to `MetricsRecorder.record_worker_sample` (the per-minute worker history).
        self._on_sample = on_sample
        self.cpu = cpu or CpuMeter()
        self.beats = 0
        self.failures = 0

    def _row(self) -> dict[str, Any]:
        return {
            "pid": self.info.pid,
            "started_at": self.info.started_at,
            "last_seen": int(self.clock.now()),
            "rss": self._rss(),
            "requests": self.counters.requests,
            "proxied": self.counters.proxied,
            "lag": self.lag.p99() if self.lag is not None else None,
            "open_conns": self._open_conns() if self._open_conns else None,
            "inflight": self._inflight() if self._inflight else None,
            "worker_id": self.info.worker_id,
            "hostname": self.info.hostname,
            "color": self.info.color,
            "master_pid": self.info.master_pid,
            "max_requests": self.info.max_requests,
            "reset_at": self.counters.reset_at,
            "version": self.info.version,
            "is_leader": 1 if (self._is_leader and self._is_leader()) else 0,
            "cache_generation": self._cache_generation() if self._cache_generation else None,
        }

    @staticmethod
    def _write(conn: sqlite3.Connection, row: dict[str, Any]) -> int | None:
        conn.execute(_UPSERT, row)
        stored = conn.execute("SELECT counters_reset_at FROM worker_heartbeat WHERE pid = ?", (row["pid"],)).fetchone()
        return None if stored is None or stored[0] is None else int(stored[0])

    def _adopt_reset(self, stored_reset_at: int | None) -> None:
        local = self.counters.reset_at or 0
        if stored_reset_at and stored_reset_at > local:
            self.counters.reset(stored_reset_at)

    def _sample(self, row: dict[str, Any]) -> None:
        """Hand this beat's vital signs to `on_sample` (never raises: a metrics hook never stops the heartbeat)."""
        if self._on_sample is None:
            return
        try:
            self._on_sample(
                {
                    "cpu_pct": self.cpu.read(),
                    "loop_lag_ms_p99": row["lag"],
                    "open_conns": row["open_conns"],
                    "rss": row["rss"],
                }
            )
        except Exception:
            log.warning("heartbeat_sample_failed", exc_info=True)

    async def beat(self) -> None:
        """Write one heartbeat. Raises `SharedStateUnavailable` if metrics.db cannot be written."""
        row = self._row()
        self._sample(row)
        stored = await self.metrics.write(lambda conn: self._write(conn, row))
        self._adopt_reset(stored)
        self.beats += 1

    def beat_sync(self) -> None:
        """Synchronous `beat` (scripts and tests)."""
        row = self._row()
        self._adopt_reset(self.metrics.write_sync(lambda conn: self._write(conn, row)))
        self.beats += 1

    async def remove(self) -> None:
        """Delete this worker's row (clean shutdown), so the fleet count drops at once instead of after 20 s.

        The delete waits at most `REMOVE_BUSY_BUDGET_MS` for a locked metrics.db: it runs inside the 8 s shutdown
        budget, before the final metrics flush, and the row goes stale by itself after 20 s anyway (review finding
        mp-6: with metrics.db locked, the unbudgeted delete took 5 s of that budget).
        """
        pid = self.info.pid

        def delete_row(conn: sqlite3.Connection) -> None:
            conn.execute("DELETE FROM worker_heartbeat WHERE pid = ?", (pid,))

        try:
            await self.metrics.write(delete_row, busy_timeout_ms=REMOVE_BUSY_BUDGET_MS)
        except SharedStateUnavailable as exc:
            log.warning("heartbeat_remove_failed", extra={"fields": {"error": str(exc)}})

    async def run(self, stop: asyncio.Event, interval_s: float = HEARTBEAT_INTERVAL_S) -> None:
        """Beat every `interval_s` until `stop` is set, then remove the row."""
        try:
            while not stop.is_set():
                try:
                    await self.beat()
                except SharedStateUnavailable as exc:
                    self.failures += 1
                    log.warning("heartbeat_failed", extra={"fields": {"error": str(exc)}})
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(stop.wait(), timeout=interval_s)
        finally:
            await self.remove()


def fleet_view(
    conn: sqlite3.Connection, now_s: float, *, this_pid: int | None = None, stale_after_s: float = HEARTBEAT_STALE_S
) -> list[dict[str, Any]]:
    """Every heartbeat row with `fresh` (seen within `stale_after_s`), `is_this_worker` and `uptime_s` added."""
    rows = conn.execute("SELECT * FROM worker_heartbeat ORDER BY color, started_at, pid").fetchall()
    view: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        item["fresh"] = now_s - int(item["last_seen"]) <= stale_after_s
        item["is_this_worker"] = this_pid is not None and int(item["pid"]) == this_pid
        item["uptime_s"] = max(0, int(now_s) - int(item["started_at"]))
        view.append(item)
    return view


def fresh_counts(conn: sqlite3.Connection, now_s: float, stale_after_s: float = HEARTBEAT_STALE_S) -> dict[str, int]:
    """Count of fresh workers per color (the fleet header's Count, compared with ROXY_WORKERS per color)."""
    rows = conn.execute(
        "SELECT coalesce(color, ''), count(*) FROM worker_heartbeat WHERE last_seen >= ? GROUP BY 1",
        (int(now_s - stale_after_s),),
    ).fetchall()
    return {str(r[0]): int(r[1]) for r in rows}


def reset_fleet_counters(conn: sqlite3.Connection, at: int) -> int:
    """Reset counts (parity row 122): set `counters_reset_at` and zero requests and proxied for every worker.

    Each worker adopts the reset on its next beat (it sees a newer `counters_reset_at` than its own). Returns the
    number of rows changed.
    """
    return conn.execute(
        "UPDATE worker_heartbeat SET counters_reset_at = ?, requests = 0, proxied = 0", (int(at),)
    ).rowcount
