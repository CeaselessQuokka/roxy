"""v1 parity: the service switches (throttle-all, pause) and the bypass list, from the admin API to the caller.

What this is
    Ports of the v1 smoke sections S013 ("Global throttle-all mode"), S014 ("Pause: custom message and
    dropped-request counter"), S022 ("Service messages persist after disabling") and S050 ("Throttle-bypass
    allowlist") as far as no other v2 test proved them end to end.

Why it exists
    The admin API tests check what the routes store and answer; the abuse unit tests check the refusals on fake
    requests. v1's suite also proved the round trip: switching throttle-all or pause on changes what the next caller
    gets, the drop counter counts those callers, switching it off lets the next caller through again, and removing
    a bypass entry makes the per-IP limit apply again.

How it works
    The `parity` fixture runs the real app; an admin signs in through the real login and flips the switches with the
    admin API (`/protection/throttle-all`, `/protection/pause`, `/protection/access/bypass`). Callers come from their
    own addresses; respx counts what reaches Roblox. Drop counters are read after the recorder flushed.

What to read next
    `roxy/admin/api/protection.py`, `roxy/abuse/pause.py`, `roxy/abuse/throttle_all.py` and
    `roxy/abuse/checks/bypass.py`.
"""

from __future__ import annotations

from typing import Any

import httpx


def ok(response: httpx.Response) -> Any:
    assert response.status_code in (200, 201), response.text
    return response.json()


def games_route(parity: Any) -> Any:
    return parity.roblox.route(host="games.roblox.com").mock(return_value=httpx.Response(200, json={"ok": True}))


async def flushed(parity: Any) -> None:
    """Close the current minute and write the recorder's numbers, so the drop counters can see them."""
    parity.clock.advance(1)
    await parity.ctx.recorder.flush()


async def test_v1_throttle_all_limit_message_drops_and_switch_off(parity: Any) -> None:
    """v1 smoke lines 576 to 603 (S013)."""
    admin = await parity.admin()
    route = games_route(parity)
    state = ok(
        await admin.post(
            "protection/throttle-all",
            json={"enabled": True, "message": "Heavy load, slow down.", "limit": 2, "period": 3600},
        )
    )
    assert (state["enabled"], state["limit"], state["period"]) == (True, 2, 3600)
    assert state["message"] == "Heavy load, slow down."
    ip = parity.ip()
    statuses = [(await parity.get(f"/games.roblox.com/v1/games?u={n}", ip=ip)).status_code for n in range(2)]
    assert statuses == [200, 200]
    assert route.call_count == 2
    third = await parity.get("/games.roblox.com/v1/games?u=3", ip=ip)
    assert third.status_code == 429
    assert b"Heavy load, slow down." in third.content
    assert third.headers["roxy-global-throttled"] == "True"
    assert route.call_count == 2  # the over-limit request never reached Roblox
    await flushed(parity)
    state = ok(await admin.get("protection/throttle-all"))
    assert state["drops_since_start"] >= 1
    state = ok(await admin.post("protection/throttle-all", json={"enabled": False}))
    assert state["enabled"] is False
    after = await parity.get("/games.roblox.com/v1/games?u=4")
    assert after.status_code == 200
    assert route.call_count == 3


async def test_v1_pause_message_drops_default_text_resume_and_kept_message(parity: Any) -> None:
    """v1 smoke lines 607 to 637 (S014) and 834 (S022)."""
    admin = await parity.admin()
    route = games_route(parity)
    state = ok(await admin.post("protection/pause", json={"paused": True, "message": "Updating tokens, back soon."}))
    assert state["paused"] is True
    first = await parity.get("/games.roblox.com/v1/games?u=1")
    second = await parity.get("/games.roblox.com/v1/games?u=2")
    assert (first.status_code, second.status_code) == (503, 503)
    assert b"Updating tokens, back soon." in first.content
    await flushed(parity)
    assert ok(await admin.get("protection/pause"))["drops_since_start"] >= 2

    ok(await admin.post("protection/pause", json={"paused": False}))
    # The banner counts from the minute the new pause began (minute rollups, plan 6.4), so start it in a new minute.
    parity.clock.advance(60 - int(parity.clock.now()) % 60 + 1)
    ok(await admin.post("protection/pause", json={"paused": True}))  # no message: the stored one is reused
    again = await parity.get("/games.roblox.com/v1/games?u=3")
    assert again.status_code == 503
    assert b"Updating tokens, back soon." in again.content
    await flushed(parity)
    assert ok(await admin.get("protection/pause"))["drops_since_start"] == 1  # counted from the new pause

    ok(await admin.post("protection/pause", json={"paused": True, "message": ""}))
    default = await parity.get("/games.roblox.com/v1/games?u=4")
    assert default.status_code == 503
    assert b"Service down for maintenance." in default.content

    ok(await admin.post("protection/pause", json={"paused": True, "message": "Persisted pause msg"}))
    ok(await admin.post("protection/pause", json={"paused": False}))
    resumed = await parity.get("/games.roblox.com/v1/games?u=5")
    assert resumed.status_code == 200
    assert route.call_count == 1
    assert ok(await admin.get("protection/pause"))["message"] == "Persisted pause msg"  # kept after resuming


async def test_v1_bypass_entries_skip_the_limit_until_they_are_removed(parity: Any) -> None:
    """v1 smoke lines 1489 to 1507 (S050)."""
    admin = await parity.admin()
    games_route(parity)
    await parity.settings(allowed_requests_per_minute=3)
    control = parity.ip()
    control_statuses = [
        (await parity.get(f"/games.roblox.com/v1/games?c={n}", ip=control)).status_code for n in range(6)
    ]
    assert 429 in control_statuses
    tester = parity.ip()
    added = ok(await admin.post("protection/access/bypass", json={"cidr": tester, "note": "spam test"}))
    listed = ok(await admin.get("protection/access/bypass"))
    assert f"{tester}/32" in [item["cidr"] for item in listed["items"]]
    assert listed["your_ip"]  # the requester's own address, for the one-click add
    bypassed = [(await parity.get(f"/games.roblox.com/v1/games?b={n}", ip=tester)).status_code for n in range(12)]
    assert bypassed == [200] * 12
    ok(await admin.delete(f"protection/access/bypass/{added['key']}"))
    listed = ok(await admin.get("protection/access/bypass"))
    assert f"{tester}/32" not in [item["cidr"] for item in listed["items"]]
    after = [(await parity.get(f"/games.roblox.com/v1/games?a={n}", ip=tester)).status_code for n in range(6)]
    assert 429 in after  # the per-IP limit applies again
