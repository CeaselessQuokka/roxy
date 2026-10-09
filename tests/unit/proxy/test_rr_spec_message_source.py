"""Reviewer finding spec-4: every refusal's outcome record says whose words it carried (parity row 116).

What this is
    Router tests for the refusals the upstream layer makes on its own (the egress guard seeing a public credential
    marker answers 400 with the auth smuggling text; an egress host refusal answers 404 "Not a Roblox URL", DESIGN.md
    11.9 Upstream). The router renders them as Roxy's refusals, so their outcome record must say `default`, like
    the same refusals made by the abuse pipeline.

Why it exists
    Fix pass 1 (spec F9) gave failures `roxy` or `roblox` and kept `custom` or `default` for refusals, but
    `router.message_source` only looked at the abuse pipeline's refusal object. A refusal that came back from the
    cache or upstream as a result was recorded with `message_source` "", so the row 116 split ("Custom vs default")
    lost it: it was neither, while its outcome is `refused`.

How it works
    The proxy unit app (`tests/unit/proxy/conftest.py`: real middleware and router, fake cache and recorder) serves a
    result whose reason is a refusal code. The caller gets v1's refusal bytes and the recorded event says `default`
    (Roxy's built-in text), as the same refusal made by the abuse pipeline does. Fixed in `router.message_source`:
    a REFUSED outcome without a refusal object is `default`.

What to read next
    `roxy/proxy/router.py` (`message_source`, `build_outcome_event`), `roxy/proxy/respond.py` (`render`).
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from roxy.core.reasons import Outcome, ReasonCode
from roxy.proxy import respond

GAMES = "/games.roblox.com/v1/games?universeIds=1"
CASES = [
    (ReasonCode.AUTH_SMUGGLING, 400, b'"Requests requiring authentication are not allowed with this proxy."\n'),
    (ReasonCode.HOST_NOT_ALLOWED, 404, b'"Not a Roblox URL"\n'),
]


@pytest.mark.parametrize(("reason", "status", "body"), CASES, ids=["guard_marker", "egress_host"])
async def test_spec_4_control_upstream_refusal_bytes(
    proxy_client: httpx.AsyncClient, ctx: Any, reason: ReasonCode, status: int, body: bytes
) -> None:
    """Control (passes today): the caller gets v1's refusal and the outcome is a refusal."""
    ctx.cache.result = respond.ProxyResult(reason=reason, status=status, outcome=Outcome.REFUSED)
    response = await proxy_client.get(GAMES)
    assert (response.status_code, response.content) == (status, body)
    assert ctx.recorder.events[-1].outcome is Outcome.REFUSED


@pytest.mark.parametrize(("reason", "status", "body"), CASES, ids=["guard_marker", "egress_host"])
async def test_spec_4_upstream_refusal_records_its_message_source(
    proxy_client: httpx.AsyncClient, ctx: Any, reason: ReasonCode, status: int, body: bytes
) -> None:
    ctx.cache.result = respond.ProxyResult(reason=reason, status=status, outcome=Outcome.REFUSED)
    response = await proxy_client.get(GAMES)
    assert (response.status_code, response.content) == (status, body)
    event = ctx.recorder.events[-1]
    assert event.outcome is Outcome.REFUSED
    assert event.message_source == "default"  # Roxy's own built-in v1 text, never an admin's
