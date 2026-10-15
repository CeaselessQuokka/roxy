"""Adversarial review (public site lens): what `/status` says about the caller limit while throttle-all is on.

What this is
    One integration test on the fully wired app: switch the emergency per-IP limit (throttle-all) on with the real
    writer (`roxy.abuse.throttle_all.set_throttle_all`) and read `/status` the way a game developer would during an
    incident.

Why it exists
    Plan 16.1: `/status` answers "is it Roxy or is it me?" with "current cache and rate-limit notes in plain words".
    While throttle-all is on, every proxy caller is held to `global_throttle_limit` per `global_throttle_period`
    and refused with 429 `Roxy-Global-Throttled`, but the page still says "Operational" and states the normal
    per-IP limit (10 requests every 50 seconds by default) as "Your limit". A developer whose game gets 429 after
    its first request reads the status page, sees a limit it never reached, and concludes the bug is on their side.
    - Finding public-3 (fixed): the status page ignored the throttle-all switch (control.db `service_state` key
      `throttle_all`), so its rate-limit note contradicted the live limit for as long as the emergency limit was
      on. `compute_status` now reads that switch in the same control.db read as the pause record; while it is on
      the banner says degraded and "Your limit right now" states the emergency limit and its header.

How it works
    The emergency limit is set to distinctive numbers (3 requests per 77 seconds) through the real settings
    service, throttle-all is switched on through the real writer, and the visible text of `/status` must mention
    that limit and the degraded state; once the switch is off again the page is back to the usual limit.

What to read next
    `roxy/public/pages.py` (`compute_status`, `status`), `roxy/templates/public/status.html`,
    `roxy/abuse/throttle_all.py` (`ThrottleAllState`, `set_throttle_all`).
"""

from __future__ import annotations

import re

import httpx
from fastapi import FastAPI

from roxy.config.audit import Actor
from roxy.config.settings_service import SettingsService


async def test_rr_public_status_reports_the_emergency_limit_while_throttle_all_is_on(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    from roxy.abuse.throttle_all import set_throttle_all

    ctx = app.state.ctx
    actor = Actor("cli", "public-review-test")
    service = SettingsService(ctx.dbs.control, runtime=ctx.settings, clock=ctx.clock)
    await service.update({"global_throttle_limit": 3, "global_throttle_period": 77}, actor, "review test")
    await ctx.settings.refresh_if_changed()
    state = await set_throttle_all(ctx.dbs.control, ctx.clock, actor, enabled=True, reason="incident")
    assert state.enabled
    app.state.public_status_cache = None  # the status page caches its view for a few seconds

    response = await client.get("/status")
    assert response.status_code == 200
    visible = " ".join(re.sub(r"<[^>]+>", " ", response.text).split())
    print("\n/status while throttle-all is on:", visible[visible.find("Your limit") :][:200])
    # Whatever the wording, the page must tell the caller that the emergency limit (3 per 77 s) is in force.
    assert "3 requests" in visible, visible
    assert "77 seconds" in visible, visible
    assert "Roxy-Global-Throttled" in visible  # the header the refusals carry, so a caller can match the two
    assert 'class="status-banner state-degraded"' in response.text  # not "Operational: working normally"

    await set_throttle_all(ctx.dbs.control, ctx.clock, actor, enabled=False)
    app.state.public_status_cache = None
    text = (await client.get("/status")).text
    visible = " ".join(re.sub(r"<[^>]+>", " ", text).split())
    assert 'class="status-banner state-operational"' in text
    assert "Your limit: 10 requests every 50 seconds per IP address." in visible
    assert "77 seconds" not in visible
