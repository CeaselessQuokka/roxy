"""v1 parity: the escalating throttle, from a ladder saved in the admin API to what a repeat offender gets.

What this is
    A port of the v1 smoke sections S089 ("Escalating throttle: each strike costs more than the last", lines 2838
    to 2892) and S090 (forgiving strikes, lines 2896 to 2900) through the real app.

Why it exists
    The ladder logic has unit tests and the ladder and strike board routes have API tests; v1's suite proved the
    chain a bot actually meets: the owner saves a ladder, each new offense gets the next rung's message and a longer
    wait, the strike board shows the client on its rung, the rung hits are counted, and forgiving puts the client
    back on the first rung.

How it works
    The `parity` fixture runs the real app with a fixed window of 2 requests per 10 s and escalation on. An admin
    saves a 3-rung ladder with `PUT /protection/ladder`. `earn_a_throttle` sends requests from one address until
    the first 429; the fake clock then moves past the penalty for the next offense. The strike board and the
    ladder's rung hits are read back from the admin API.

What to read next
    `roxy/abuse/throttle.py` (strikes and rungs), `roxy/admin/api/protection.py` (ladder, strike board, forgive).
"""

from __future__ import annotations

import json
from typing import Any

import httpx

LADDER = [
    {"multiplier": 1, "message": "Too many requests"},
    {"multiplier": 2, "message": "You are about to get severely throttled"},
    {"multiplier": 4, "message": "You have been harshly throttled due to bot behavior"},
]
IP = "203.0.113.77"


def ok(response: httpx.Response) -> Any:
    assert response.status_code == 200, response.text
    return response.json()


async def earn_a_throttle(parity: Any, counter: list[int]) -> httpx.Response:
    """Requests from one address until the first refusal (v1's `earn_a_throttle`)."""
    for _ in range(12):
        counter[0] += 1
        response: httpx.Response = await parity.get(f"/games.roblox.com/v1/games?universeIds={counter[0]}", ip=IP)
        if response.status_code == 429:
            return response
    raise AssertionError("no throttle within 12 requests")


async def test_v1_each_strike_costs_more_and_the_dashboard_sees_it(parity: Any) -> None:
    """v1 smoke lines 2838 to 2892 and 2896 to 2900."""
    parity.roblox.route(host="games.roblox.com").mock(return_value=httpx.Response(200, json={"ok": True}))
    await parity.settings(
        cache_enabled=0,
        allowed_requests_per_minute=2,
        throttle_reset_duration=10,
        throttle_window_mode="fixed",
        throttle_escalation_enabled=1,
        throttle_strike_decay_seconds=3600,
    )
    admin = await parity.admin()
    saved = ok(await admin.put("protection/ladder", json={"tiers": LADDER}))
    assert [rung["multiplier"] for rung in saved["rungs"]] == [1.0, 2.0, 4.0]

    counter = [0]
    bodies, waits = [], []
    for _offense in range(4):
        refused = await earn_a_throttle(parity, counter)
        bodies.append(json.loads(refused.content))
        waits.append(int(refused.headers["retry-after"]))
        if not waits[1:]:
            assert 5 <= int(refused.headers["roxy-throttle-reset"]) <= 10  # the plain 10 s window on rung 1
        parity.clock.advance(waits[-1] + 1)  # sit the penalty out, then offend again
    assert bodies == [rung["message"] for rung in LADDER] + [LADDER[-1]["message"]]  # the last rung repeats
    assert waits[0] < waits[1] < waits[2]  # each strike waits longer than the one before
    assert waits[3] == waits[2]

    board = {item["ip"]: item for item in ok(await admin.get("protection/strikes"))["items"]}
    assert board[IP]["strikes"] == 4
    assert board[IP]["tier"] == 3

    parity.clock.advance(61)
    await parity.ctx.recorder.flush()
    hits = [rung["hits"] for rung in ok(await admin.get("protection/ladder"))["rungs"]]
    assert hits == [1, 1, 2]  # the repeating top rung counts twice

    forgiven = ok(await admin.post("protection/strikes/forgive", json={"ip": IP}))
    assert forgiven["forgiven"] == 1
    board = {item["ip"]: item for item in ok(await admin.get("protection/strikes"))["items"]}
    assert IP not in board or board[IP]["strikes"] == 0
    parity.clock.advance(waits[-1] + 1)
    again = await earn_a_throttle(parity, counter)
    assert json.loads(again.content) == "Too many requests"  # back on the first rung
