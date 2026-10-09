"""Adversarial review (public site lens): a visitor who types `/docs/` is treated as an attacker.

What this is
    One integration test on the fully wired app (lifespan, abuse pipeline, spam detectors running): a person asks
    for the user guide and the status page with a trailing slash, the most common way a link to a page gets
    written, and then their game (or Studio play test, from the same address) calls the proxy.

Why it exists
    Only `/docs` and `/status` are routes (plan 16.1). `/docs/` and `/status/` fall through to the proxy catch-all,
    which reads them as a request for the host `docs` and refuses it as `not_roblox`: a probe. With the defaults
    that means the tarpit holds the visitor's browser for 8 to 20 seconds (`tarpit_on_probe` = 1; measured here:
    10.9 s for `/docs/`, 12.4 s for `/status/`), then answers a JSON 404 "Not a Roblox URL", and the spam probe
    detector counts it (`spam_probe_threshold` 5 in `spam_probe_window_s` 600, action `ban` for 60 minutes).
    While `spam_dry_run` is 1 (the shipped default) that is a "would ban" event and an ABUSE-SPAM recommendation
    naming the visitor; once the owner turns dry run off, a developer who reloads the slow page a few times bans
    their own address (and the Studio play tests sent from it) from the proxy for an hour (measured here: ban
    `auto:spam_probe`, next proxy call refused with 429). The probe log fills with innocent visitors either way
    (the problem v1's `/favicon.ico` route comment was written about).
    - Finding public-5 (fixed): trailing-slash variants of the public pages were refused, tarpitted and counted as
      probes. `pages.PageAliasRoute` now answers GET and HEAD of `/docs/`, `/status/` and other spellings of the
      two page paths (`/Docs`, `/STATUS//`) with a 308 to the page, before the proxy catch-all sees them.

How it works
    The tarpit is switched off only to keep the test fast (it does not change whether a request is a probe), the
    per-IP limit is raised so it cannot refuse anything, and `spam_dry_run` is 0 so the detectors act. Five visits to
    `/docs/` and `/status/` come from one address; the test then waits a few seconds for a ban of that address and
    makes one proxy call from it (answered by `respx`). It expects the trailing-slash pages to reach the page (a
    redirect to the canonical path, never a `Roxy-Refusal`), no ban, and the visitor's next proxy call served.

What to read next
    `roxy/public/pages.py` (the routes), `roxy/abuse/checks/probe.py` (`NotRobloxCheck`), `roxy/abuse/spam.py`.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
from fastapi import FastAPI

from roxy.config.audit import Actor
from roxy.config.settings_service import SettingsService

VISITOR = "192.0.2.77"
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "X-Forwarded-For": VISITOR}


async def test_rr_public_trailing_slash_pages_are_not_probes(
    app: FastAPI, client: httpx.AsyncClient, respx_mock: Any
) -> None:
    ctx = app.state.ctx
    service = SettingsService(ctx.dbs.control, runtime=ctx.settings, clock=ctx.clock)
    # spam_dry_run 0: the detectors act, as they do once the owner has checked their accuracy (plan 10.3).
    changes = {"tarpit_enabled": 0, "allowed_requests_per_minute": 1000, "spam_dry_run": 0}
    await service.update(changes, Actor("cli", "public-review"), "review test")
    await ctx.settings.refresh_if_changed()
    respx_mock.get(host="games.roblox.com", path="/v1/games").mock(return_value=httpx.Response(200, json={"data": []}))

    visits = []
    for path in ("/docs/", "/status/", "/docs/", "/docs/", "/status/"):
        response = await client.get(path, headers=HEADERS)
        visits.append((path, response.status_code, response.headers.get("roxy-refusal")))
        assert response.headers.get("location") == path.rstrip("/"), response.headers

    def bans_of_visitor(conn: Any) -> list[tuple[str, str]]:
        rows = conn.execute("SELECT created_by, reason_code FROM bans WHERE subject = ?", (VISITOR,)).fetchall()
        return [(str(row[0]), str(row[1])) for row in rows]

    bans: list[tuple[str, str]] = []
    last: tuple[int, str | None] = (0, None)
    for _ in range(40):  # the detectors run every second in the background; a ban lands within a few seconds
        bans = await ctx.dbs.control.read(bans_of_visitor)
        if bans:
            response = await client.get("/games.roblox.com/v1/games?universeIds=1", headers=HEADERS)
            last = (response.status_code, response.headers.get("roxy-refusal"))
            break
        await asyncio.sleep(0.2)
    print("\nvisits:", visits, "\nbans of the visitor:", bans, "\ntheir next proxy call:", last)

    assert all(refusal is None for _, _, refusal in visits), visits
    assert all(status in (200, 301, 302, 303, 307, 308) for _, status, _ in visits), visits
    assert bans == []
    served = await client.get("/games.roblox.com/v1/games?universeIds=1", headers=HEADERS)
    assert served.status_code == 200, (served.status_code, served.headers.get("roxy-refusal"))
