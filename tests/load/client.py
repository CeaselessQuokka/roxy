"""The load generator: sends a request plan on schedule (open loop) with httpx, over one or more processes.

What this is
    `run_plan(base_url, plan, ...)` sends every `PlannedRequest` at its planned time and returns one `Outcome` per
    attempt: when it was planned and sent, how long the answer took, the status and Roxy's headers (cache state,
    refusal reason, Retry-After, upstream status). `percentile`, `latency_ms`, `max_overlap` and `per_second`
    summarize outcomes.

Why it exists
    Load tests must not slow down when the server does. A closed loop ("send the next request when the last one
    answered") quietly lowers the offered rate as latency grows and hides the very queueing it should show
    (coordinated omission). Here a request leaves at its planned time whatever happened before, and the outcome
    records both times, so a late client is visible (`lag`) instead of being mistaken for a slow server.

How it works
    - The plan is split round robin over `processes` client processes (spawned, so each has its own interpreter
      and GIL; the mock Roblox and the samplers stay in the parent). Each process imports httpx, opens its client
      and then waits at a barrier; once every process has checked in, the parent sets one start instant `t0` a
      quarter second ahead. Counting the processes instead of sleeping a fixed start delay means a slow start on a
      busy machine only delays `t0`; it can never make the first seconds of the plan leave late in one bunch.
    - Planned instants are on the harness clock (`clock.now()`, the steady wall clock Roxy paces itself by), the
      same time line as the mock's call log, so `sent` and the mock's `at` compare directly. Latency is a duration
      and is measured with `time.monotonic()` (on WSL 2 that clock runs about 9.5 percent fast against the host,
      which inflates the latency figures by as much; see clock.py).
    - Each process runs one asyncio loop with one `httpx.AsyncClient` (`trust_env=False`, so no proxy variable can
      redirect it; keep-alive connections like nginx's upstream pool). `connections` bounds its connections and
      `max_inflight` the requests it has open; a request that waits for either is sent late, and the wait shows in
      its `sent - at` lag.
    - The client sends `X-Forwarded-For` with the planned address (Roxy trusts it from the loopback peer, as it
      trusts nginx in production) and Roblox's game server User-Agent.
    - `retry_429_max_s` > 0 makes a caller do what a well-behaved game script does after a 429: wait the
      Retry-After (when it is at most that many seconds) and try once more. Both attempts are recorded.
    - Latency includes the client's own overhead (a few hundred microseconds per request in Python); figures are
      indicative, not exact server timings.

What to read next
    `scenarios.py` (what each scenario sends and how outcomes become the results table).
"""

from __future__ import annotations

import asyncio
import math
import os
import queue
import time
from collections.abc import Iterable, Sequence
from concurrent.futures import Future, ProcessPoolExecutor
from dataclasses import dataclass
from multiprocessing import get_context
from typing import Any, Final

import httpx

from load import clock
from load.traffic import ROBLOX_UA, PlannedRequest

START_MARGIN_S: Final = 0.25
"""Between the barrier (every client process ready) and the common start instant, so every process has read it."""
BARRIER_POLL_S: Final = 0.01
READY_TIMEOUT_S: Final = 120.0
"""How long the client processes may take to start, import httpx and open their client."""


@dataclass(frozen=True, slots=True)
class Outcome:
    """One attempt and its answer. Times are seconds after the common start instant `t0`."""

    at: float
    """When the plan wanted the request sent."""
    sent: float
    latency: float
    """Seconds from sending to the end of the answer's body; for a transport error, until the error."""
    status: int
    """HTTP status, 0 for a transport error."""
    cache: str
    refusal: str
    retry_after: str
    upstream_status: str
    label: str
    ip: str
    attempt: int
    error: str = ""

    @property
    def done(self) -> float:
        return self.sent + self.latency


@dataclass(frozen=True, slots=True)
class ClientOptions:
    connections: int = 128
    max_inflight: int = 1024
    timeout_s: float = 70.0
    retry_429_max_s: float = 0.0


def _headers(request: PlannedRequest) -> dict[str, str]:
    headers = {"X-Forwarded-For": request.ip, "User-Agent": ROBLOX_UA}
    if request.body is not None:
        headers["Content-Type"] = "application/json"
    return headers


_ready: Any = None
"""In a client process: the queue on which it says "imported, connected, waiting for the start" (`_init`)."""
_start: Any = None
"""In a client process: the shared start instant `t0` on the harness clock (negative: the run was called off)."""
_go: Any = None
"""In a client process: the event the parent sets once `_start` holds the start instant."""


def _init(ready: Any, start: Any, go: Any) -> None:
    """Initializer of every client process: keep the three shared objects the start barrier uses."""
    global _ready, _start, _go
    _ready, _start, _go = ready, start, go


async def _start_instant() -> float:
    """Say this process is ready, then wait (on a thread, the event is a process-shared one) for the start."""
    _ready.put(os.getpid())
    if not await asyncio.to_thread(_go.wait, READY_TIMEOUT_S + 30):
        raise RuntimeError("no start instant from the parent")
    if _start.value < 0:
        raise RuntimeError("the parent called the run off (another client process failed to start)")
    return float(_start.value)


async def _drive(base_url: str, plan: Sequence[PlannedRequest], options: ClientOptions) -> list[Outcome]:
    out: list[Outcome] = []
    limits = httpx.Limits(max_connections=options.connections, max_keepalive_connections=options.connections)
    ticker = asyncio.ensure_future(clock.tick_forever())  # keeps this process's harness clock current
    try:
        return await _send(base_url, plan, options, limits, out)
    finally:
        ticker.cancel()


async def _send(
    base_url: str, plan: Sequence[PlannedRequest], options: ClientOptions, limits: httpx.Limits, out: list[Outcome]
) -> list[Outcome]:
    # trust_env=False: proxy environment variables (HTTP_PROXY and friends) can never redirect load traffic.
    async with httpx.AsyncClient(
        base_url=base_url, limits=limits, timeout=options.timeout_s, trust_env=False
    ) as client:
        gate = asyncio.Semaphore(options.max_inflight)
        t0 = await _start_instant()

        async def attempt(request: PlannedRequest, number: int) -> Outcome:
            async with gate:
                sent = clock.now() - t0  # where on the shared time line it left
                started = time.monotonic()  # a duration: monotonic never steps
                try:
                    response = await client.request(
                        request.method, request.path, content=request.body, headers=_headers(request)
                    )
                except httpx.HTTPError as exc:
                    return Outcome(
                        request.at, sent, time.monotonic() - started, 0, "", "", "", "", request.label,
                        request.ip, number, type(exc).__name__,
                    )  # fmt: skip
                latency = time.monotonic() - started
            h = response.headers
            return Outcome(
                request.at, sent, latency, response.status_code, h.get("roxy-cache", ""),
                h.get("roxy-refusal", ""), h.get("retry-after", ""), h.get("roxy-upstream-status", ""),
                request.label, request.ip, number,
            )  # fmt: skip

        async def one(request: PlannedRequest) -> None:
            first = await attempt(request, 0)
            out.append(first)
            if options.retry_429_max_s > 0 and first.status == 429:
                wait = _seconds(first.retry_after)
                if wait is not None and wait <= options.retry_429_max_s:
                    await clock.sleep_until(clock.now() + wait)  # Retry-After is in Roxy's seconds
                    out.append(await attempt(request, 1))

        tasks: list[asyncio.Task[None]] = []
        for request in plan:
            await clock.sleep_until(t0 + request.at)  # open loop: leave on schedule, whatever came back
            tasks.append(asyncio.create_task(one(request)))
        await asyncio.gather(*tasks)
    return out


def _seconds(text: str) -> float | None:
    try:
        value = float(text)
    except ValueError:
        return None
    return value if math.isfinite(value) and value >= 0 else None


def _share(base_url: str, plan: list[PlannedRequest], options: ClientOptions) -> list[Outcome]:
    """Entry point of one client process."""
    return asyncio.run(_drive(base_url, plan, options))


def _await_ready(ready: Any, futures: Sequence[Future[list[Outcome]]]) -> None:
    """Block until every client process said it is ready (the barrier), or fail when one died first."""
    deadline = time.monotonic() + READY_TIMEOUT_S
    waiting = len(futures)
    while waiting:
        try:
            ready.get(timeout=BARRIER_POLL_S * 10)
            waiting -= 1
        except queue.Empty:
            failed = [future for future in futures if future.done()]
            if failed:
                failed[0].result()  # raises the client process's exception
                raise RuntimeError("a client process ended before the start") from None
            if time.monotonic() > deadline:
                raise RuntimeError(f"client processes not ready after {READY_TIMEOUT_S:g} s") from None


def run_plan(
    base_url: str, plan: Sequence[PlannedRequest], *, processes: int = 1, options: ClientOptions | None = None
) -> tuple[float, list[Outcome]]:
    """Send `plan` from `processes` client processes; returns the start instant `t0` (harness clock) and every
    outcome."""
    options = options or ClientOptions()
    ordered = sorted(plan, key=lambda request: request.at)
    shares = [share for share in (ordered[i::processes] for i in range(processes)) if share]
    # spawn: a fresh interpreter per client process. Forking this process would copy the mock server's running
    # thread and its locks into the child, which is undefined behavior for threads.
    context = get_context("spawn")
    ready = context.Queue()
    start = context.Value("d", 0.0)
    go = context.Event()
    with ProcessPoolExecutor(
        max_workers=len(shares), mp_context=context, initializer=_init, initargs=(ready, start, go)
    ) as pool:
        # Each task blocks at the barrier until `go` is set, so no process can take a second task: every share
        # runs in its own process.
        futures = [pool.submit(_share, base_url, share, options) for share in shares]
        try:
            _await_ready(ready, futures)  # counting, not sleeping: a slow spawn on a busy machine only delays t0
        except BaseException:
            start.value = -1.0  # release the processes that did start, so the pool can shut down at once
            go.set()
            raise
        t0 = clock.now() + START_MARGIN_S
        start.value = t0
        go.set()
        outcomes = [outcome for future in futures for outcome in future.result()]
    outcomes.sort(key=lambda outcome: outcome.sent)
    return t0, outcomes


# ------------------------------------------------------------------------------------------------ summaries


def percentile(values: Sequence[float], q: float) -> float | None:
    """Nearest-rank percentile (q in 0..1) of `values`; None when empty."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(q * len(ordered)))
    return ordered[min(rank, len(ordered)) - 1]


def latency_ms(outcomes: Iterable[Outcome]) -> dict[str, float | int | None]:
    """Count and p50, p95, p99 and max latency in milliseconds."""
    values = [outcome.latency * 1000 for outcome in outcomes]
    summary: dict[str, float | int | None] = {"n": len(values)}
    for name, q in (("p50", 0.50), ("p95", 0.95), ("p99", 0.99), ("max", 1.0)):
        value = percentile(values, q)
        summary[name] = None if value is None else round(value, 2)
    return summary


def max_overlap(intervals: Iterable[tuple[float, float]]) -> int:
    """The largest number of intervals `[start, end)` open at one instant (a sweep over sorted edges)."""
    edges: list[tuple[float, int]] = []
    for start, end in intervals:
        edges.append((start, 1))
        edges.append((end, -1))
    edges.sort(key=lambda edge: (edge[0], edge[1]))  # an end before a start at the same instant
    best = current = 0
    for _, step in edges:
        current += step
        best = max(best, current)
    return best


def per_second(times: Iterable[float], *, start: float, end: float) -> float:
    """Events per second between `start` and `end` (seconds)."""
    span = end - start
    if span <= 0:
        return 0.0
    return sum(1 for t in times if start <= t < end) / span


def lag_ms(outcomes: Sequence[Outcome]) -> dict[str, float | int | None]:
    """How late first attempts left compared with the plan (the client's own health, p50 and p99)."""
    values = [(outcome.sent - outcome.at) * 1000 for outcome in outcomes if outcome.attempt == 0]
    p50, p99 = percentile(values, 0.5), percentile(values, 0.99)
    return {
        "n": len(values),
        "p50": None if p50 is None else round(p50, 2),
        "p99": None if p99 is None else round(p99, 2),
    }


__all__ = [
    "ClientOptions",
    "Outcome",
    "lag_ms",
    "latency_ms",
    "max_overlap",
    "per_second",
    "percentile",
    "run_plan",
]
