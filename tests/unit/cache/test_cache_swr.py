"""Stale-while-revalidate scheduling (plan 7.6, setting `swr_max_inflight`): bounded and deduplicated."""

from __future__ import annotations

import asyncio

from roxy.cache.swr import SWR_GROUP, SwrRefresher
from roxy.core.tasks import TaskSupervisor


async def test_one_refresh_per_key_and_bounded() -> None:
    gate = asyncio.Event()
    ran: list[str] = []

    def make(name: str):
        async def refresh() -> None:
            await gate.wait()
            ran.append(name)

        return refresh

    refresher = SwrRefresher(None, lambda: 2)
    assert refresher.schedule("a", make("a"))
    assert refresher.schedule("a", make("a-again"))  # joined: still a REVALIDATING serve, no second refresh
    assert refresher.schedule("b", make("b"))
    assert not refresher.schedule("c", make("c"))  # budget of 2 is full
    assert refresher.active() == 2
    assert refresher.joined == 1
    assert refresher.refused == 1
    gate.set()
    await refresher.drain()
    assert sorted(ran) == ["a", "b"]
    assert refresher.active() == 0
    assert refresher.schedule("c", make("c"))
    await refresher.drain()


async def test_zero_budget_turns_refreshes_off() -> None:
    refresher = SwrRefresher(None, lambda: 0)

    async def never() -> None:  # pragma: no cover - must not run
        raise AssertionError

    assert not refresher.schedule("a", never)


async def test_failed_refresh_is_contained_and_supervisor_bounds_it() -> None:
    tasks = TaskSupervisor()
    refresher = SwrRefresher(tasks, lambda: 1)

    async def boom() -> None:
        raise RuntimeError("upstream exploded")

    assert refresher.schedule("a", boom)
    for _ in range(50):
        if refresher.active() == 0:
            break
        await asyncio.sleep(0.01)
    assert refresher.failed == 1
    assert refresher.active() == 0
    assert tasks.group_size(SWR_GROUP) == 0
    await tasks.stop(drain_timeout_s=1)
    assert not refresher.schedule("b", boom)  # a stopping supervisor refuses new refreshes
