"""v1 parity: what the owner sees about real traffic: endpoint templates, the live feed, captures, cache sources.

What this is
    Ports of v1 smoke checks whose v2 read models were tested only with seeded rows: S017 (ids collapse into a
    template, with a concrete drill-down, lines 707 to 721), S023 (the last caller of a concrete path, line 856),
    S076 (the live feed covers refusals, lines 2395 to 2402), S077 (a request's capture, lines 2464 to 2471) and S099
    (a cached answer counts as the cache's, not Roblox's, lines 3129 and 3130).

Why it exists
    A read model can be right about seeded rows and still never see a real request (the producer is not wired, or
    writes another shape). These tests send real requests through the proxy route and read the same admin API
    routes the dashboard pages use.

How it works
    The `parity` fixture runs the real app with Roblox played by respx. Requests come from known addresses; the
    recorder is flushed after the fake clock closed the minute; then `/endpoints/detail`, `/live`, `/live/{id}` and
    `/traffic/status/sources` are read through a signed-in admin.

What to read next
    `roxy/metrics/templating.py`, `roxy/metrics/live.py`, `roxy/metrics/capture.py` and
    `roxy/admin/api/endpoints.py`, `live.py` and `traffic.py`.
"""

from __future__ import annotations

from typing import Any

import httpx

OUTFITS = "avatar.roblox.com/v2/avatar/users/{userId}/outfits"
SERVERS = "games.roblox.com/v1/games/{gameId}/servers/{serverId}"
CALLER = "203.0.113.21"


def ok(response: httpx.Response) -> Any:
    assert response.status_code == 200, response.text
    return response.json()


async def closed_minute(parity: Any) -> None:
    await parity.ctx.cache.settle()
    parity.clock.advance(61)
    await parity.ctx.recorder.flush()


async def test_v1_ids_collapse_into_templates_with_a_concrete_drill_down(parity: Any) -> None:
    """v1 smoke lines 707 to 721 and 856."""
    parity.roblox.route(host="avatar.roblox.com").mock(return_value=httpx.Response(200, json={"ok": True}))
    parity.roblox.route(host="games.roblox.com").mock(return_value=httpx.Response(200, json={"ok": True}))
    for user in (111, 222, 333):
        response = await parity.get(f"/avatar.roblox.com/v2/avatar/users/{user}/outfits", ip=CALLER)
        assert response.status_code == 200
    assert (await parity.get("/games.roblox.com/v1/games/694768217/servers/0", ip=CALLER)).status_code == 200
    await closed_minute(parity)
    admin = await parity.admin()
    detail = ok(await admin.get("endpoints/detail", params={"range": "1h", "template": OUTFITS}))
    assert detail["totals"]["requests"]["value"] == 3  # three ids, one template
    paths = {item["path"]: item["requests"] for item in detail["concrete_paths"]}
    assert len(paths) == 3
    assert paths["avatar.roblox.com/v2/avatar/users/111/outfits"] == 1
    callers = {item["ip"]: item["requests"] for item in detail["top_callers"]["last_15_minutes"]["ips"]}
    assert callers == {CALLER: 3}
    table = {row["key"] for row in ok(await admin.get("endpoints", params={"range": "1h"}))["items"]}
    assert {OUTFITS, SERVERS} <= table


async def test_v1_the_live_feed_covers_refusals_and_a_capture_can_be_opened(parity: Any) -> None:
    """v1 smoke lines 2395 to 2402 and 2464 to 2471."""
    await parity.settings(capture_sample_served_pct=100)
    parity.roblox.route(host="users.roblox.com").mock(return_value=httpx.Response(200, json={"ok": True}))
    await parity.rule("rules_endpoint_block", {"pattern": "economy.roblox.com"})
    served = await parity.proxy("POST", "/users.roblox.com/v1/users", json={"userIds": [398800, 398801]})
    assert served.status_code == 200
    refused = await parity.get("/economy.roblox.com/v1/assets/1")
    assert refused.status_code == 403
    await closed_minute(parity)
    admin = await parity.admin()
    rows = {row["request_id"]: row for row in ok(await admin.get("live"))["items"]}
    served_row = rows[served.headers["roxy-request-id"]]
    refused_row = rows[refused.headers["roxy-request-id"]]
    assert (served_row["outcome"], refused_row["outcome"]) == ("served_upstream", "refused")
    assert refused_row["reason"] == "endpoint_blocked"
    assert served_row["status"] == 200
    assert served_row["egress"] == "direct"
    assert isinstance(served_row["duration_ms"], int | float)

    detail = ok(await admin.get(f"live/{served.headers['roxy-request-id']}"))
    capture = detail["capture"]
    assert "userIds" in capture["request_body"]
    assert capture["response_body"] == '{"ok":true}'
    assert isinstance(capture["response_headers"], dict)
    missing = await admin.get("live/01JAAAAAAAAAAAAAAAAAAAAAAA")
    assert missing.status_code == 404  # an unknown or expired capture is a 404 that says so


async def test_v1_a_cached_answer_counts_as_the_caches(parity: Any) -> None:
    """v1 smoke lines 3129 and 3130: two identical requests, one from Roblox and one from the cache."""
    parity.roblox.route(host="games.roblox.com").mock(return_value=httpx.Response(200, json={"ok": True}))
    for _ in range(2):
        assert (await parity.get("/games.roblox.com/v1/games/votes?universeIds=9967558039")).status_code == 200
        await parity.ctx.cache.settle()
    await closed_minute(parity)
    admin = await parity.admin()
    body = ok(await admin.get("traffic/status/sources", params={"range": "1h"}))
    pairs = {(row["source"], row["status"]): row["requests"] for row in body["items"]}
    assert pairs.get(("cache", 200)) == 1
    assert pairs.get(("roblox", 200)) == 1
