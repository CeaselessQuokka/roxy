"""Background task supervisor: every loop and fire-and-forget job in a worker runs through here.

What this is
    `TaskSupervisor` starts named background loops (`start`), runs bounded one-shot jobs (`spawn`), reports their
    health (`status`), and stops them all cleanly on shutdown (`stop`). One instance lives on `AppContext.tasks`.

Why it exists
    A bare `asyncio.create_task(loop())` has three classic bugs: if the loop raises, the exception is only reported
    when the task is garbage collected (often never), so the job silently stops; nothing limits how many tasks
    pile up; and on shutdown nobody cancels them, so the process hangs or loses work. v1's `background.schedule`
    created unbounded threads for the same reasons (plan 5.6). Every loop going through one supervisor gives
    logging, restart with backoff, bounds and a clean shutdown in one place.

How it works
    `start(name, coro_fn, interval_s=...)` wraps the job in a supervising coroutine. With `interval_s` the job is
    called every `interval_s` seconds (fixed delay, optional per run `timeout_s`); without it the job is a
    long-running loop that is called once. Either way an exception is logged with its traceback and the job is
    restarted after a backoff that doubles from `backoff_initial_s` up to `backoff_max_s`, so a broken database
    does not turn into a busy loop. `asyncio.CancelledError` is never swallowed: it is how `stop()` ends a task.
    `spawn(name, coro, group=..., limit=...)` runs a one-shot coroutine (a stale-while-revalidate refresh) only if
    its group has fewer than `limit` running, and otherwise refuses it, which is the back pressure plan 5.6 asks
    for (`swr_max_inflight`). `stop()` lets one-shot jobs finish for up to `drain_timeout_s`, then cancels
    everything and waits for the cancellations to complete.

What to read next
    `roxy/lifespan.py` (what starts and stops which loops, in which order), then `roxy/scheduler/leader.py`.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Coroutine
from dataclasses import dataclass, field
from typing import Any

from roxy.core.clock import SYSTEM_CLOCK, Clock

_log = logging.getLogger("roxy.core.tasks")


@dataclass(slots=True)
class TaskStatus:
    """What the System page shows about one supervised loop."""

    name: str
    interval_s: float | None
    running: bool
    runs: int = 0
    failures: int = 0
    last_run_at: float | None = None
    last_error: str | None = None
    last_error_at: float | None = None


@dataclass(slots=True)
class _Loop:
    status: TaskStatus
    coro_fn: Callable[[], Awaitable[Any]]
    timeout_s: float | None
    run_immediately: bool
    task: asyncio.Task[None] | None = None


@dataclass(slots=True)
class _Group:
    limit: int
    tasks: set[asyncio.Task[Any]] = field(default_factory=set)
    refused: int = 0


class TaskSupervisor:
    """Starts, watches, restarts and stops a worker's background tasks. Bounded in every dimension (plan P9)."""

    def __init__(
        self,
        *,
        clock: Clock | None = None,
        max_loops: int = 64,
        max_groups: int = 32,
        backoff_initial_s: float = 1.0,
        backoff_max_s: float = 60.0,
    ) -> None:
        self._clock = clock or SYSTEM_CLOCK
        self._max_loops = max_loops
        self._max_groups = max_groups
        self._backoff_initial_s = backoff_initial_s
        self._backoff_max_s = backoff_max_s
        self._loops: dict[str, _Loop] = {}
        self._groups: dict[str, _Group] = {}
        self._stopping = False

    # --- supervised loops ---------------------------------------------------------------------------------------

    def start(
        self,
        name: str,
        coro_fn: Callable[[], Awaitable[Any]],
        *,
        interval_s: float | None = None,
        timeout_s: float | None = None,
        run_immediately: bool = True,
    ) -> asyncio.Task[None]:
        """Start a supervised background loop called `name` (must be unique). Returns its task.

        `coro_fn` is a zero-argument async function. With `interval_s` it runs every `interval_s` seconds (first
        run at once unless `run_immediately` is False); without it, it is a long-running loop started once and
        restarted after a backoff if it raises. A run that returns normally without `interval_s` ends the task.
        """
        if self._stopping:
            raise RuntimeError("TaskSupervisor is stopping; no new loops")
        if self.is_running(name):
            raise ValueError(f"a background loop named {name!r} is already running")
        if name not in self._loops and len(self._loops) >= self._max_loops:
            raise RuntimeError(f"too many background loops (limit {self._max_loops})")
        if interval_s is not None and interval_s <= 0:
            raise ValueError("interval_s must be positive")
        loop = _Loop(
            status=TaskStatus(name=name, interval_s=interval_s, running=True),
            coro_fn=coro_fn,
            timeout_s=timeout_s,
            run_immediately=run_immediately,
        )
        loop.task = asyncio.create_task(self._supervise(loop), name=f"roxy:{name}")
        self._loops[name] = loop
        _log.info("task_started", extra={"fields": {"task": name, "interval_s": interval_s}})
        return loop.task

    def _backoff(self, failures_in_a_row: int, interval_s: float | None) -> float:
        base = self._backoff_initial_s * float(2 ** max(failures_in_a_row - 1, 0))
        delay = min(base, self._backoff_max_s)
        # A periodic job never retries faster than its own interval.
        return max(delay, interval_s or 0.0)

    async def _run_once(self, loop: _Loop) -> None:
        if loop.timeout_s is not None:
            async with asyncio.timeout(loop.timeout_s):
                await loop.coro_fn()
        else:
            await loop.coro_fn()

    async def _supervise(self, loop: _Loop) -> None:
        status = loop.status
        failures_in_a_row = 0
        first = True
        try:
            while not self._stopping:
                if status.interval_s is not None and not (first and loop.run_immediately) and failures_in_a_row == 0:
                    await asyncio.sleep(status.interval_s)
                first = False
                try:
                    await self._run_once(loop)
                except asyncio.CancelledError:
                    raise  # the only way a supervised task ends early: stop() or an explicit cancel
                except Exception as exc:
                    failures_in_a_row += 1
                    status.failures += 1
                    status.last_error = f"{type(exc).__name__}: {exc}"[:500]
                    status.last_error_at = self._clock.now()
                    delay = self._backoff(failures_in_a_row, status.interval_s)
                    _log.exception(
                        "task_failed",
                        extra={"fields": {"task": status.name, "failures": status.failures, "retry_in_s": delay}},
                    )
                    await asyncio.sleep(delay)
                    continue
                status.runs += 1
                status.last_run_at = self._clock.now()
                failures_in_a_row = 0
                if status.interval_s is None:
                    return  # a long-running loop that returned normally has finished its work
        finally:
            status.running = False

    # --- bounded one-shot jobs ----------------------------------------------------------------------------------

    def spawn(
        self,
        name: str,
        coro: Coroutine[Any, Any, Any],
        *,
        group: str = "default",
        limit: int = 64,
    ) -> asyncio.Task[Any] | None:
        """Run a one-shot coroutine in `group` if fewer than `limit` are running; otherwise refuse (return None).

        A refused coroutine is closed, so Python does not warn that it was never awaited. Exceptions are logged.
        """
        bucket = self._groups.get(group)
        if bucket is None:
            if len(self._groups) >= self._max_groups:
                coro.close()
                raise RuntimeError(f"too many task groups (limit {self._max_groups})")
            bucket = self._groups[group] = _Group(limit=limit)
        bucket.limit = limit
        if self._stopping or len(bucket.tasks) >= bucket.limit:
            bucket.refused += 1
            coro.close()
            return None
        task = asyncio.create_task(coro, name=f"roxy:{group}:{name}")
        bucket.tasks.add(task)  # keep a strong reference: the event loop only holds weak ones

        def _done(finished: asyncio.Task[Any]) -> None:
            bucket.tasks.discard(finished)
            if finished.cancelled():
                return
            error = finished.exception()
            if error is not None:
                _log.error(
                    "spawned_task_failed",
                    exc_info=(type(error), error, error.__traceback__),
                    extra={"fields": {"task": name, "group": group}},
                )

        task.add_done_callback(_done)
        return task

    def group_size(self, group: str) -> int:
        """How many one-shot jobs of `group` are running now."""
        bucket = self._groups.get(group)
        return 0 if bucket is None else len(bucket.tasks)

    # --- introspection and shutdown -----------------------------------------------------------------------------

    def is_running(self, name: str) -> bool:
        loop = self._loops.get(name)
        return bool(loop and loop.task is not None and not loop.task.done())

    def status(self) -> list[TaskStatus]:
        """A copy of every loop's status, sorted by name."""
        return [
            TaskStatus(
                name=loop.status.name,
                interval_s=loop.status.interval_s,
                running=loop.status.running,
                runs=loop.status.runs,
                failures=loop.status.failures,
                last_run_at=loop.status.last_run_at,
                last_error=loop.status.last_error,
                last_error_at=loop.status.last_error_at,
            )
            for loop in sorted(self._loops.values(), key=lambda item: item.status.name)
        ]

    async def cancel(self, name: str) -> None:
        """Stop one loop and wait until it has stopped."""
        loop = self._loops.get(name)
        if loop is None or loop.task is None:
            return
        loop.task.cancel()
        await asyncio.gather(loop.task, return_exceptions=True)

    async def stop(self, *, drain_timeout_s: float = 10.0) -> None:
        """Let one-shot jobs finish (up to `drain_timeout_s`), then cancel every task and wait for all of them."""
        self._stopping = True
        pending = [task for bucket in self._groups.values() for task in bucket.tasks]
        if pending:
            _done, still_running = await asyncio.wait(pending, timeout=drain_timeout_s)
            for task in still_running:
                task.cancel()
            await asyncio.gather(*still_running, return_exceptions=True)
        loops = [loop.task for loop in self._loops.values() if loop.task is not None and not loop.task.done()]
        for task in loops:
            task.cancel()
        await asyncio.gather(*loops, return_exceptions=True)
        _log.info("tasks_stopped", extra={"fields": {"loops": len(loops), "drained": len(pending)}})
