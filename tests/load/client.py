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
      and GIL; the mock Roblox and the samplers stay in the parent). All processes start at one instant `t0` on
      `time.monotonic()`, which on Linux is one clock for every process, so every timeline (client, mock, Roxy's
      `monotonic_s` log fields) lines up.
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
import time
from collections.abc import Iterable, Sequence
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from multiprocessing import get_context
from typing import Final

import httpx

from load.traffic import ROBLOX_UA, PlannedRequest

START_DELAY_S: Final = 3.0
"""Time for the client processes to start and import httpx before the common start instant."""


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


async def _drive(base_url: str, plan: Sequence[PlannedRequest], t0: float, options: ClientOptions) -> list[Outcome]:
    out: list[Outcome] = []
    limits = httpx.Limits(max_connections=options.connections, max_keepalive_connections=options.connections)
    # trust_env=False: proxy environment variables (HTTP_PROXY and friends) can never redirect load traffic.
    async with httpx.AsyncClient(
        base_url=base_url, limits=limits, timeout=options.timeout_s, trust_env=False
    ) as client:
        gate = asyncio.Semaphore(options.max_inflight)

        async def attempt(request: PlannedRequest, number: int) -> Outcome:
            async with gate:
                sent = time.monotonic()
                try:
                    response = await client.request(
                        request.method, request.path, content=request.body, headers=_headers(request)
                    )
                except httpx.HTTPError as exc:
                    return Outcome(
                        request.at, sent - t0, time.monotonic() - sent, 0, "", "", "", "", request.label,
                        request.ip, number, type(exc).__name__,
                    )  # fmt: skip
                latency = time.monotonic() - sent
            h = response.headers
            return Outcome(
                request.at, sent - t0, latency, response.status_code, h.get("roxy-cache", ""),
                h.get("roxy-refusal", ""), h.get("retry-after", ""), h.get("roxy-upstream-status", ""),
                request.label, request.ip, number,
            )  # fmt: skip

        async def one(request: PlannedRequest) -> None:
            first = await attempt(request, 0)
            out.append(first)
            if options.retry_429_max_s > 0 and first.status == 429:
                wait = _seconds(first.retry_after)
                if wait is not None and wait <= options.retry_429_max_s:
                    await asyncio.sleep(wait)
                    out.append(await attempt(request, 1))

        tasks: list[asyncio.Task[None]] = []
        for request in plan:
            delay = t0 + request.at - time.monotonic()
            if delay > 0:
                await asyncio.sleep(delay)
            tasks.append(asyncio.create_task(one(request)))
        await asyncio.gather(*tasks)
    return out


def _seconds(text: str) -> float | None:
    try:
        value = float(text)
    except ValueError:
        return None
    return value if math.isfinite(value) and value >= 0 else None


def _share(base_url: str, plan: list[PlannedRequest], t0: float, options: ClientOptions) -> list[Outcome]:
    """Entry point of one client process."""
    return asyncio.run(_drive(base_url, plan, t0, options))


def run_plan(
    base_url: str, plan: Sequence[PlannedRequest], *, processes: int = 1, options: ClientOptions | None = None
) -> tuple[float, list[Outcome]]:
    """Send `plan` from `processes` client processes; returns the start instant `t0` and every outcome."""
    options = options or ClientOptions()
    ordered = sorted(plan, key=lambda request: request.at)
    shares = [ordered[i::processes] for i in range(processes)]
    t0 = time.monotonic() + START_DELAY_S
    # spawn: a fresh interpreter per client process. Forking this process would copy the mock server's running
    # thread and its locks into the child, which is undefined behavior for threads.
    with ProcessPoolExecutor(max_workers=processes, mp_context=get_context("spawn")) as pool:
        futures = [pool.submit(_share, base_url, share, t0, options) for share in shares if share]
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
