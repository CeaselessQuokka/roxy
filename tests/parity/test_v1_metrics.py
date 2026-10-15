"""v1 parity: the worker request counters, status code attribution, and a statistics reset that stays a reset.

What this is
    Ports of v1 smoke lines 2132 to 2139 (S070: `/health` raises the request count but not the proxied count;
    probes, refused or not, raise the proxied count), lines 2261 to 2292 (S072: status codes are attributed to
    whoever produced them) and lines 428 and 1333 (S008 and S044: after a reset of the request counters, counting
    resumes from zero and nothing from before the reset comes back; finding parity-4, fixed).

Why it exists
    The worker table of the System page (parity row 84) separates requests that reached the proxy route from
    everything else, as v1 did; the "Who returned it?" split (rows 68 and 132) is how the owner tells Roblox's
    throttling from Roxy's. And v1 spent real effort (its `ClearEpochs`) on one promise: a cleared counter is never
    refilled by numbers a worker had counted before the clear but not written yet.

How it works
    The `parity` fixture runs the real app. The counter test reads `ctx.heartbeat.counters` around requests. The
    attribution test sends real requests (served, blocked, a Roblox 429, a throttle-all refusal) and reads
    `GET /admin/api/v1/traffic/status/sources`. The reset tests send proxied requests, reset the traffic family
    through the admin API (preview, then the run with the typed phrase), send one more request, flush the recorder
    and count the requests in the minute rollups.

What to read next
    `roxy/scheduler/heartbeat.py` (the counters), `roxy/admin/api/traffic.py` (the sources),
    `roxy/admin/api/data.py` (the reset) and `roxy/metrics/recorder.py` (what a worker holds before a flush).
"""

from __future__ import annotations

from typing import Any

import httpx

from roxy.abuse.throttle_all import set_throttle_all
from roxy.config.audit import Actor


async def test_v1_health_counts_as_a_request_and_probes_as_proxied(parity: Any) -> None:
    """v1 smoke lines 2132, 2133, 2138 and 2139."""
    counters = parity.ctx.heartbeat.counters
    requests, proxied = counters.requests, counters.proxied
    for _ in range(6):
        assert (await parity.http.get("/health")).status_code == 200
    assert counters.requests >= requests + 6
    assert counters.proxied == proxied  # /health never reaches the proxy route
    proxied = counters.proxied
    for n in range(4):
        assert (await parity.get(f"/not-roblox-{n}.example.com/x")).status_code == 404
    assert counters.proxied == proxied + 4  # refused proxy requests are counted too


async def requests_in_rollups(parity: Any) -> int:
    def read(conn: Any) -> int:
        row = conn.execute("SELECT coalesce(sum(requests), 0) FROM rollup_minute").fetchone()
        return int(row[0])

    total: int = await parity.ctx.dbs.metrics.read(read)
    return total


async def reset_traffic(admin: Any) -> None:
    scope = {"scope": "family", "families": ["traffic"]}
    preview = await admin.post("data/resets/preview", json=scope)
    assert preview.status_code == 200, preview.text
    body = preview.json()
    run = await admin.post(
        "data/resets",
        json={**scope, "preview": body["preview"], "confirm": body.get("confirm_phrase"), "reason": "parity"},
    )
    assert run.status_code == 200, run.text
    assert run.json()["status"] == "done"


async def test_v1_a_reset_counter_resumes_from_zero_and_nothing_comes_back(parity: Any) -> None:
    """v1 smoke lines 428 and 1333: requests counted before the reset never reappear after it (finding parity-4,
    fixed by the reset fence: `metrics/recorder.py ResetFences`, `admin/api/data.py fence_pending_counts`)."""
    parity.roblox.route(host="games.roblox.com").mock(return_value=httpx.Response(200, json={"ok": True}))
    for n in range(3):
        assert (await parity.get(f"/games.roblox.com/v1/games?u={n}")).status_code == 200
    admin = await parity.admin()
    await reset_traffic(admin)
    assert (await parity.get("/games.roblox.com/v1/games?u=99")).status_code == 200
    parity.clock.advance(61)
    await parity.ctx.recorder.flush()
    assert await requests_in_rollups(parity) == 1


async def test_v1_control_a_reset_after_a_flush_leaves_only_new_requests(parity: Any) -> None:
    """Control for the test above: when the recorder had flushed before the reset, the reset deletes those
    rows and only the request made afterwards is counted, so the measurement itself is sound."""
    parity.roblox.route(host="games.roblox.com").mock(return_value=httpx.Response(200, json={"ok": True}))
    for n in range(3):
        assert (await parity.get(f"/games.roblox.com/v1/games?u={n}")).status_code == 200
    parity.clock.advance(61)
    await parity.ctx.recorder.flush()
    assert await requests_in_rollups(parity) == 3
    admin = await parity.admin()
    await reset_traffic(admin)
    assert await requests_in_rollups(parity) == 0
    assert (await parity.get("/games.roblox.com/v1/games?u=99")).status_code == 200
    parity.clock.advance(61)
    await parity.ctx.recorder.flush()
    assert await requests_in_rollups(parity) == 1


async def test_v1_status_codes_are_attributed_to_whoever_produced_them(parity: Any) -> None:
    """v1 smoke lines 2261 to 2292 (S072), through real requests: Roblox's answers count as Roblox's, Roxy's own
    refusals as Roxy's, and a Roblox 429 is counted as Roblox's 429 apart from the 429 Roxy then answers."""

    games = "games.roblox.com"
    parity.roblox.route(host=games, path="/v1/games").mock(return_value=httpx.Response(200, json={"ok": True}))
    parity.roblox.route(host=games, path="/v1/limited").mock(
        return_value=httpx.Response(429, text="Too Many Requests", headers={"Retry-After": "30"})
    )
    assert (await parity.get(f"/{games}/v1/games?universeIds=1")).status_code == 200
    await parity.rule("rules_endpoint_block", {"pattern": f"{games}/v1/blocked-two"})
    assert (await parity.get(f"/{games}/v1/blocked-two")).status_code == 403
    assert (await parity.get(f"/{games}/v1/limited")).status_code == 429
    await parity.settings(global_throttle_limit=1, global_throttle_period=60)
    await set_throttle_all(parity.ctx.dbs.control, parity.clock, Actor("admin", "parity"), enabled=True)
    await parity.ctx.abuse.switches.reload()
    ip = parity.ip()
    assert (await parity.get(f"/{games}/v1/games?universeIds=2", ip=ip)).status_code == 200
    assert (await parity.get(f"/{games}/v1/games?universeIds=3", ip=ip)).status_code == 429
    parity.clock.advance(61)
    await parity.ctx.recorder.flush()
    admin = await parity.admin()
    answer = await admin.get("traffic/status/sources", params={"range": "1h"})
    assert answer.status_code == 200, answer.text
    body = answer.json()
    pairs = {(row["source"], row["status"]): row["requests"] for row in body["items"]}
    assert pairs.get(("roblox", 200)) == 2  # Roblox's own answers (v1 Roblox and Relay 200)
    assert pairs.get(("roxy", 403)) == 1  # the block is Roxy's answer ...
    assert ("roblox", 403) not in pairs  # ... never Roblox's
    assert body["tiles"]["roblox_429"] >= 1  # Roblox's 429 is counted as Roblox's
    assert pairs.get(("roxy", 429), 0) >= 1  # throttle-all (and the cooldown answer) are Roxy's 429s
