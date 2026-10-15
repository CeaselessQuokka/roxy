"""Stale-while-revalidate: serve a just-expired entry at once and refresh it once, in the background.

What this is
    `SwrRefresher.schedule(key_id, make_refresh)` starts one background refresh for a cache key, unless one is
    already running for that key in this worker or the worker's refresh budget (`swr_max_inflight`) is used up.

Why it exists
    v1 served stale data only after an upstream call had already failed, so stale entries never reduced load
    (plan 2.4, fix F5). With stale-while-revalidate (plan 7.6), the caller who finds an entry expired within the
    SWR window is answered from it immediately (`Roxy-Cache: REVALIDATING`) and exactly one refresh replaces it.
    The refresh itself goes through fleet single-flight (`SingleFlight.try_lead`) at background priority, so
    across all workers one expiring key costs one upstream call, and only when a bucket has room to spare.

How it works
    - A refresh runs as a one-shot task in the `swr` group of the worker's `TaskSupervisor`, which bounds how
      many run at once and drains them at shutdown (plan 5.6). The set of keys being refreshed has the same bound.
    - `schedule` returns False when the budget is 0 (background refreshes switched off) or full; the cache then
      fetches while the caller waits, with the stale entry as its fallback if the fetch fails.
    - A second caller for a key that is already being refreshed is also answered REVALIDATING; no second
      refresh starts.
    - The refresh function comes from the cache service (it knows how to fetch and store); this module only
      decides whether it may run, and keeps a refresh that fails from becoming anyone's error.

What to read next
    `roxy/upstream/singleflight.py` (`try_lead`), then `roxy/cache/service.py` (`_refresh`).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Coroutine
from typing import Any, Final, Protocol

log = logging.getLogger(__name__)

SWR_GROUP: Final = "swr"


class Spawner(Protocol):
    """The part of `core/tasks.py: TaskSupervisor` used here."""

    def spawn(
        self, name: str, coro: Coroutine[Any, Any, Any], *, group: str = "default", limit: int = 64
    ) -> asyncio.Task[Any] | None: ...


class SwrRefresher:
    """Bounded, deduplicated background refreshes for one worker."""

    def __init__(self, spawner: Spawner | None, limit: Callable[[], int]) -> None:
        self._spawner = spawner
        self._limit = limit
        self._active: set[str] = set()
        self._own_tasks: set[asyncio.Task[Any]] = set()  # strong references when no supervisor is given
        self.started = 0
        self.joined = 0
        self.refused = 0
        self.failed = 0

    def schedule(self, key_id: str, make_refresh: Callable[[], Coroutine[Any, Any, Any]]) -> bool:
        """Start (or join) the refresh of `key_id`. False when refreshes are off or the budget is full."""
        limit = self._limit()
        if limit <= 0:
            self.refused += 1
            return False
        if key_id in self._active:
            self.joined += 1
            return True
        if len(self._active) >= limit:
            self.refused += 1
            return False
        self._active.add(key_id)
        runner = self._run(key_id, make_refresh)
        task: asyncio.Task[Any] | None
        if self._spawner is None:
            task = asyncio.get_running_loop().create_task(runner, name=f"roxy:{SWR_GROUP}:{key_id[:16]}")
            self._own_tasks.add(task)
            task.add_done_callback(self._own_tasks.discard)
        else:
            task = self._spawner.spawn(f"{SWR_GROUP}:{key_id[:16]}", runner, group=SWR_GROUP, limit=limit)
        if task is None:  # the supervisor refused (full or stopping) and closed the coroutine
            self._active.discard(key_id)
            self.refused += 1
            return False
        self.started += 1
        return True

    async def _run(self, key_id: str, make_refresh: Callable[[], Coroutine[Any, Any, Any]]) -> None:
        try:
            await make_refresh()
        except Exception:
            # The caller was already answered; a failed refresh only means the stale entry stays a little longer.
            self.failed += 1
            log.exception("swr_refresh_failed", extra={"fields": {"key_id": key_id[:24]}})
        finally:
            self._active.discard(key_id)

    def active(self) -> int:
        """Refreshes running now in this worker."""
        return len(self._active)

    def is_refreshing(self, key_id: str) -> bool:
        return key_id in self._active

    async def drain(self) -> None:
        """Wait for refreshes started without a supervisor (tests)."""
        while self._own_tasks:
            await asyncio.gather(*list(self._own_tasks), return_exceptions=True)


__all__ = ["SWR_GROUP", "Spawner", "SwrRefresher"]
