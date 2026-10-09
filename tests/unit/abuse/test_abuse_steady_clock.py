"""The abuse pipeline's limiter time never steps back inside one worker (wave 3b integration, a flake's root cause).

What this is
    Tests of `AbusePipeline.steady_now_ms` and of a GCRA burst across a wall clock step back, through the real
    pipeline over temporary databases with a `FakeClock` whose wall time is set back by `set()`.

Why it exists
    Limiter rows hold wall-clock times shared through hot.db, and WSL's wall clock steps back about 0.9 s every 31 s
    (an NTP step does the same on a server). A step back between two requests of one burst made the last request of
    an allowance GCRA had just granted look early, so it was refused: `test_rr_mp_degraded.py` admitted 11 of a
    share of 12 now and then. The pipeline now holds its last time until the clock catches up.

How it works
    `make_pipeline` from the abuse unit conftest; `FakeReq` from `abuse_support`. The clock is set back by 0.9 s
    between requests; a forward move is taken at once; the limit itself still holds.

What to read next
    `roxy/abuse/pipeline.py` (`steady_now_ms`), `roxy/abuse/limiter.py` (`gcra`).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from abuse_support import FakeReq

from roxy.abuse.pipeline import AbusePipeline
from roxy.abuse.verdict import Allow
from roxy.core.clock import FakeClock

LIMIT_3 = {
    "allowed_requests_per_minute": 3,
    "throttle_reset_duration": 300,
    "throttle_window_mode": "gcra",
    "flood_limit_per_minute": 100_000,
    "spam_enabled": 0,
    "tarpit_enabled": 0,
}


def test_steady_time_holds_across_a_step_back_and_follows_a_step_forward(
    make_pipeline: Callable[..., AbusePipeline], fake_clock: FakeClock
) -> None:
    pipeline = make_pipeline(LIMIT_3)
    first = pipeline.steady_now_ms()
    fake_clock.set(fake_clock.now() - 0.9)  # the wall clock steps back
    assert pipeline.steady_now_ms() == first
    fake_clock.advance(0.5)
    assert pipeline.steady_now_ms() == first  # not caught up yet
    fake_clock.advance(1.0)
    assert pipeline.steady_now_ms() == fake_clock.now_ms() > first


async def test_a_step_back_inside_a_burst_never_refuses_the_granted_allowance(
    make_pipeline: Callable[..., AbusePipeline], fake_clock: FakeClock
) -> None:
    pipeline = make_pipeline(LIMIT_3)
    verdicts: list[Any] = [await pipeline.evaluate(FakeReq()), await pipeline.evaluate(FakeReq())]
    fake_clock.set(fake_clock.now() - 0.9)
    verdicts.append(await pipeline.evaluate(FakeReq()))
    assert all(isinstance(verdict, Allow) for verdict in verdicts), verdicts  # the burst of 3 is honored
    assert not isinstance(await pipeline.evaluate(FakeReq()), Allow)  # and the limit still holds
