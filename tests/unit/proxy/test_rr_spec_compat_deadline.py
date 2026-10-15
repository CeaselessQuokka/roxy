"""Reviewer finding spec-5: the request deadline row follows `compat_collapse_upstream_errors` like every other 504.

What this is
    Proxy tests for the plan 7.13 `deadline` row (504) with v1 compatibility mode on. The answer comes from
    `core/deadline.py DeadlineMiddleware` when a proxied request outlives `request_deadline_s`, and the outcome
    record from `ProxyFlow.record_failure`.

Why it exists
    Plan 7.13: with `compat_collapse_upstream_errors=1` "every row whose status would be a 4xx from Roblox, a Roblox
    5xx, 502 or 504 becomes 500 with the v1 body", and DESIGN.md 11.9 (fix pass 1) repeats it for the 502 and 504
    rows; `respond.FAILURE_ROWS[DEADLINE]` is marked collapsible. The middleware writes the 504 itself without
    looking at the setting, so an old script that only knows 200 and 500 gets a 504 in compat mode. Worse, the
    router renders its fallback record through `respond` with compat on, so the outcome record says 500 while the
    caller received 504: the dashboard and the wire disagree.

How it works
    The proxy unit app (`tests/unit/proxy/conftest.py`: real middleware and router, fake cache and recorder) with a
    0.2 s deadline and a cache whose `serve` never returns. Fixed: `core/deadline.py deadline_status` collapses
    the row to 500 for a proxied request in compat mode (the proxy flow's own choice when it stored one in
    `STATE_COMPAT_COLLAPSE`, else the live setting); pages keep the 504.

What to read next
    `roxy/core/deadline.py`, `roxy/proxy/respond.py` (`FAILURE_ROWS`, `render_failure`), `roxy/proxy/router.py`
    (`record_failure`).
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest

GAMES = "/games.roblox.com/v1/games?universeIds=1"
FAILED = b"Upstream request failed; please try again later."


async def _never(req: Any, peek: Any) -> Any:
    await asyncio.sleep(30)  # longer than the deadline: only DeadlineMiddleware ends this request
    raise AssertionError("unreachable")


async def test_spec_5_control_deadline_without_compat_is_504(
    proxy_client: httpx.AsyncClient, ctx: Any, fakes: Any
) -> None:
    ctx.settings = fakes.FakeSettings(request_deadline_s=0.2, compat_collapse_upstream_errors=False)
    ctx.cache.serve = _never
    response = await proxy_client.get(GAMES)
    assert (response.status_code, response.content) == (504, FAILED)
    assert ctx.recorder.events[-1].status == 504


async def test_spec_5_deadline_row_collapses_to_500_in_compat_mode(
    proxy_client: httpx.AsyncClient, ctx: Any, fakes: Any
) -> None:
    ctx.settings = fakes.FakeSettings(request_deadline_s=0.2, compat_collapse_upstream_errors=True)
    ctx.cache.serve = _never
    response = await proxy_client.get(GAMES)
    record = ctx.recorder.events[-1]
    assert record.status == response.status_code  # what the dashboard records is what the caller got
    assert (response.status_code, response.content) == (500, FAILED)
    assert response.headers["Retry-After"] == "5"  # the collapsed row keeps the 7.13 headers
    assert response.headers["Roxy-Refusal"] == "deadline"


@pytest.mark.parametrize("compat_at_start", [True, False])
async def test_spec_5_deadline_answer_follows_the_flows_choice_when_the_setting_changes_mid_request(
    proxy_client: httpx.AsyncClient, ctx: Any, fakes: Any, compat_at_start: bool
) -> None:
    """The proxy flow stores the compat choice it renders and records with (`STATE_COMPAT_COLLAPSE`), so an admin
    flipping the setting while a request waits never splits the wire from the record."""
    ctx.settings = fakes.FakeSettings(request_deadline_s=0.2, compat_collapse_upstream_errors=compat_at_start)

    async def flip_then_wait(req: Any, peek: Any) -> Any:
        ctx.settings = fakes.FakeSettings(request_deadline_s=0.2, compat_collapse_upstream_errors=not compat_at_start)
        return await _never(req, peek)

    ctx.cache.serve = flip_then_wait
    response = await proxy_client.get(GAMES)
    assert response.status_code == (500 if compat_at_start else 504)
    assert ctx.recorder.events[-1].status == response.status_code
