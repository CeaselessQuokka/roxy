"""Reviewer finding spec-9: a scheduled pause's `Retry-After` must not end before the maintenance window does.

What this is
    `PauseState.retry_after(now)` during a scheduled window, at a time that is not a whole number of seconds before
    the window's end.

Why it exists
    Plan 7.13 (Paused row): `Retry-After` is the time to `scheduled_end`. The value was rounded down
    (`int(scheduled_end - now)`), so a caller that honored it came back up to a second early, while the proxy was
    still paused, and got a second 503. Every other v2 `Retry-After` uses a true ceiling of at least 1 so that a
    client never retries early (CHANGES.md "Retry-After on more refusals"; `respond.seconds_header`; plan 10.2 uses
    `ceil` for the throttle).

How it works
    A window from 0 to 100 s, asked at 40.5 s: 59.5 s remain, so the header must say 60 (rounded up, never a whole
    second more than needed). The control shows the manual pause keeps its fixed 60. Fixed: the scheduled value is
    rounded up with `math.ceil` and is at least 1.

What to read next
    `roxy/abuse/pause.py` (`PauseState.retry_after`), `roxy/abuse/checks/pause.py`, `roxy/proxy/respond.py`
    (`seconds_header`).
"""

from __future__ import annotations

import math

import pytest

from roxy.abuse.pause import DEFAULT_RETRY_AFTER_S, PauseState


def test_spec_9_control_manual_pause_uses_the_fixed_60() -> None:
    assert PauseState(paused=True).retry_after(40.5) == DEFAULT_RETRY_AFTER_S == 60


@pytest.mark.parametrize("now", [40.5, 70.9])
def test_spec_9_scheduled_retry_after_covers_the_rest_of_the_window(now: float) -> None:
    state = PauseState(scheduled_start=0, scheduled_end=100)
    assert state.active(now)
    assert state.retry_after(now) == math.ceil(100 - now)  # rounded up, never a whole second more than needed
    assert not state.active(now + state.retry_after(now))  # a caller that waits as told finds the proxy open


@pytest.mark.parametrize(("now", "expected"), [(40.0, 60), (99.2, 1), (99.999, 1)])
def test_spec_9_scheduled_retry_after_at_the_edges(now: float, expected: int) -> None:
    """A whole number of seconds stays as it is; the last fraction of a second still says 1, never 0."""
    assert PauseState(scheduled_start=0, scheduled_end=100).retry_after(now) == expected
