"""v1 parity: who is calling, per address and per experience, from real requests.

What this is
    A port of the v1 smoke section S075 ("Who is calling: per-IP and per-place activity", lines 2361 to 2383).

Why it exists
    Game servers change addresses all the time, so the experience (`Roblox-Id`, the calling place) is the identity
    that tells the owner who is really calling. v1 showed one row per place with its requests, refusals, distinct
    addresses, rate and User-Agent; the v2 Clients page (parity row 73) promises the same from the minute rollups of
    client activity. The admin API tests check that page with seeded rows; this test feeds it real requests.

How it works
    The `parity` fixture runs the real app. Three game servers (three addresses) call with the same `Roblox-Id`, one
    more request of that place is refused by an endpoint block, the recorder writes its minute, and the Clients read
    models (`GET /admin/api/v1/clients/places`, `/clients/places/{place}` and `/clients/ips`) are read. Then the
    `activity_tracking` switch is turned off and a new address must not appear.

What to read next
    `roxy/metrics/recorder.py` (client rows), `roxy/metrics/read_clients.py` and `roxy/admin/api/clients.py`.
"""

from __future__ import annotations

from typing import Any

import httpx

PLACE = "75227619283955"
SERVERS = ("203.0.113.56", "203.0.113.57", "203.0.113.58")


def ok(response: httpx.Response) -> Any:
    assert response.status_code == 200, response.text
    return response.json()


async def test_v1_one_experience_is_one_row_with_its_servers_rate_and_refusals(parity: Any) -> None:
    """v1 smoke lines 2361 to 2379."""
    parity.roblox.route(host="games.roblox.com").mock(return_value=httpx.Response(200, json={"ok": True}))
    await parity.rule("rules_endpoint_block", {"pattern": "economy.roblox.com"})
    caller = {"Roblox-Id": PLACE, "User-Agent": "Roblox/Linux"}
    for n, ip in enumerate(SERVERS):
        response = await parity.get(f"/games.roblox.com/v1/games?universeIds={n}", ip=ip, headers=caller)
        assert response.status_code == 200
    refused = await parity.get("/economy.roblox.com/v1/assets/1", ip=SERVERS[0], headers=caller)
    assert refused.status_code == 403
    await parity.ctx.recorder.flush()
    admin = await parity.admin()

    places = {item["key"]: item for item in ok(await admin.get("clients/places"))["items"]}
    row = places[PLACE]  # one experience is one row, whatever addresses its servers use (v1 line 2361)
    assert row["requests"] == 4  # refusals count in the total (v1 line 2379)
    assert row["refused"] == 1  # v1 line 2378
    assert row["served"] == 3  # v1 line 2370: three served
    assert row["rate1"] >= 3  # v1 line 2364: a trailing 60 s rate
    page = ok(await admin.get(f"clients/places/{PLACE}"))
    assert page["totals"]["requests"] == 4
    # v1 line 2368: v2 keeps the busiest endpoint of each minute and says so, instead of exact counts per endpoint.
    assert page["top_endpoints"][0]["endpoint"] == "games.roblox.com/v1/games"
    assert "busiest endpoint" in page["top_endpoints_basis"]
    # v1 lines 2363, 2365, 2369 and 2371: the place's servers, User-Agent and statuses, from its recent requests.
    recent = page["recent_requests"]
    assert {item["ip"] for item in recent} == set(SERVERS)
    assert {item["user_agent"] for item in recent} == {"Roblox/Linux"}
    assert sorted(item["status"] for item in recent) == [200, 200, 200, 403]

    ips = {item["key"] for item in ok(await admin.get("clients/ips"))["items"]}
    assert set(SERVERS) <= ips  # each server address has its own row too (v1 line 2362)


async def test_v1_activity_tracking_off_records_no_new_client(parity: Any) -> None:
    """v1 smoke line 2383: with `activity_tracking` 0 a new address is absent from the IP activity."""
    parity.roblox.route(host="games.roblox.com").mock(return_value=httpx.Response(200, json={"ok": True}))
    await parity.settings(activity_tracking=0)
    assert (await parity.get("/games.roblox.com/v1/games?universeIds=9", ip="203.0.113.99")).status_code == 200
    parity.clock.advance(61)
    await parity.ctx.recorder.flush()
    admin = await parity.admin()
    ips = {item["key"] for item in ok(await admin.get("clients/ips"))["items"]}
    assert "203.0.113.99" not in ips
