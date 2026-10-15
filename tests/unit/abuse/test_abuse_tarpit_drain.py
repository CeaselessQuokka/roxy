"""`Tarpit.wake_all`: a worker that starts shutting down answers every held refusal at once (plan 10.6, 19.10 row 5).

What this is
    Unit tests for the drain hook `roxy.lifespan.begin_drain` calls: holds and drips in progress end at once, no
    new hold is planned, slots are released, and a call from another thread is safe.

Why it exists
    Finding SHUTDOWN-HOLD (multi-process review): a hold may last 55 s, longer than gunicorn's 30 s
    `graceful_timeout`, so without a wake-up the held caller got no answer and the worker was killed before its
    lifespan shutdown. `tests/multiprocess/test_review_gunicorn_mp.py` proves it with real workers.

How it works
    A real `Tarpit` over the test's hot.db with the real `asyncio.sleep` and short holds, so the wake-up is what
    ends them.

What to read next
    `roxy/abuse/tarpit.py` (`hold`, `wake_all`), `roxy/lifespan.py` (`begin_drain`).
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Any

from abuse_support import FakeReq, FakeSettings

from roxy.abuse.tarpit import Tarpit
from roxy.core.clock import SystemClock

HOLD = {"tarpit_enabled": 1, "tarpit_on_probe": 1, "tarpit_min_seconds": 30, "tarpit_max_seconds": 30}


def pit(dbs: Any, **overrides: Any) -> Tarpit:
    return Tarpit(FakeSettings({**HOLD, **overrides}), dbs.hot, SystemClock(), "w1")


async def test_wake_all_ends_holds_in_progress_and_plans_no_new_ones(dbs: Any) -> None:
    tarpit = pit(dbs)
    plans = [await tarpit.plan("probe", FakeReq(), reason="r") for _ in range(3)]
    assert all(plan is not None for plan in plans)
    started = time.monotonic()
    waits = [asyncio.create_task(plan.wait()) for plan in plans if plan is not None]
    await asyncio.sleep(0.05)
    tarpit.wake_all()
    await asyncio.wait_for(asyncio.gather(*waits), timeout=5)
    assert time.monotonic() - started < 2.0  # not the planned 30 s
    for plan in plans:
        assert plan is not None
        await plan.release()
    assert await tarpit.active_holds() == 0
    assert await tarpit.plan("probe", FakeReq(), reason="r") is None  # draining: no new hold


async def test_wake_all_ends_a_drip_with_the_rest_of_the_body(dbs: Any) -> None:
    tarpit = pit(dbs, tarpit_default_type="drip", tarpit_drip_interval_ms=1000)
    plan = await tarpit.plan("probe", FakeReq(), reason="r")
    assert plan is not None
    body = b'"Not a Roblox URL"\n'
    chunks: list[bytes] = []

    async def read() -> None:
        async for chunk in plan.drip_chunks(body):
            chunks.append(chunk)

    task = asyncio.create_task(read())
    await asyncio.sleep(0.05)
    tarpit.wake_all()
    await asyncio.wait_for(task, timeout=5)
    await plan.release()
    assert b"".join(chunks) == body  # every byte still arrives, just now


async def test_wake_all_from_another_thread_and_before_any_hold(dbs: Any) -> None:
    tarpit = pit(dbs)
    plan = await tarpit.plan("probe", FakeReq(), reason="r")
    assert plan is not None
    waiting = asyncio.create_task(plan.wait())
    await asyncio.sleep(0.05)
    caller = threading.Thread(target=tarpit.wake_all)  # roxy.worker may call it outside the loop thread
    caller.start()
    await asyncio.wait_for(waiting, timeout=5)
    caller.join(5)
    await plan.release()
    fresh = pit(dbs)
    fresh.wake_all()  # nothing held yet: never raises, and holds nothing afterwards
    assert await fresh.plan("probe", FakeReq(), reason="r") is None
