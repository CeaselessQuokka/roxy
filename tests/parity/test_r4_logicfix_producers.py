"""Review round 4, lens logicfix: the producers lane end to end, from a caller request to the admin route.

What this is
    Checks that real traffic through the fully wired app (the `parity` fixture: `create_app(env)` with its real
    lifespan, respx playing Roblox, a signed-in admin) produces the schema 5 rows the producers lane added, and that
    the admin API routes (and the insights providers) read them back: a tarpit hold (`tarpit_minute`), a rule hit
    (`rule_hit_minute`, `rule_hits`), a recorded bot score (`client_score_hour`), a challenge or HTML answer on a JSON
    endpoint (`upstream_attempt_minute`), and the hourly disk sample (`disk_samples`, the leader job
    `metrics_disk_history` the integrator wired). These tests are expected to pass: they are the checked-clean
    evidence of the lens.

Why it exists
    The lane's own tests write the producer rows straight into metrics.db (`test_r3_fix_pages_lane.py`) or stop at
    the provider (`tests/integration/test_producers_app.py`); the integrator found the disk history jobs had never
    been wired at all. Only an end to end run shows every link (check, recorder hook, batch flush, read model,
    route) is connected in the running app.

How it works
    Each test sends caller requests through the proxy, flushes the worker's recorder (`ctx.recorder.flush()`, what
    the 2 s flush loop does), then reads the admin route over HTTP as a signed-in admin.

What to read next
    `roxy/metrics/producers.py`, `roxy/metrics/read_producers.py`, `roxy/metrics/jobs.py` (`register_producer_jobs`),
    `roxy/admin/api/protection.py` (`tarpit_state`, `rule_hit_history`), `roxy/admin/api/system.py` (`persistence`).
"""

from __future__ import annotations

from typing import Any

import httpx

GAMES = "games.roblox.com"
TEMPLATE = "games.roblox.com/v1/games"
HTML = b"<!DOCTYPE html><html><head><title>Just a moment</title></head><body>challenge</body></html>"


async def test_r4_logicfix_a_tarpit_hold_reaches_the_fleet_history_and_the_provider(parity: Any) -> None:
    await parity.settings(tarpit_enabled=1, tarpit_min_seconds=0, tarpit_max_seconds=1)
    for _ in range(3):
        response = await parity.get("/evil.example.com/wp-login.php", ip="203.0.113.77")
        assert response.status_code == 404
    await parity.ctx.recorder.flush()
    admin = await parity.admin()
    body = (await admin.get("protection/tarpit", params={"range": "1h"})).json()
    history = body["history"]
    assert body["history_scope"] == "fleet"
    assert history["eligible"] >= 3, history
    assert history["holds"] + history["skipped"] == history["eligible"], history
    assert history["holds"] >= 1, history
    providers = parity.ctx.insights.providers
    providers.memo_s = 0
    seen = await providers.tarpit()
    assert seen is not None
    assert seen["eligible_holds"] == history["eligible"], seen


async def test_r4_logicfix_a_rule_hit_reaches_the_rule_table_and_its_history(parity: Any) -> None:
    admin = await parity.admin()
    created = await admin.post("protection/endpoint-blocks", json={"pattern": f"{GAMES}/v1/blocked"})
    assert created.status_code in (200, 201), created.text
    rule_id = str(created.json()["item"]["id"])
    for n in range(2):
        response = await parity.get(f"/{GAMES}/v1/blocked", ip=f"198.51.100.{n + 40}")
        assert response.status_code == 403
    await parity.ctx.recorder.flush()
    table = (await admin.get("protection/endpoint-blocks", params={"range": "1h"})).json()
    row = next(item for item in table["items"] if str(item["id"]) == rule_id)
    assert (row["hits"], row["hits_total"]) == (2, 2), row
    assert row["last_hit_at"] is not None
    history = (
        await admin.get("protection/rule-hits", params={"range": "1h", "table": "endpoint-blocks", "rule_id": rule_id})
    ).json()
    assert history["total"] == 2, history


async def test_r4_logicfix_a_recorded_bot_score_reaches_the_client_page(parity: Any) -> None:
    parity.roblox.route(host=GAMES, path="/v1/games").mock(return_value=httpx.Response(200, json={"data": []}))
    for n in range(3):
        await parity.get(f"/{GAMES}/v1/games?universeIds={n}", ip="192.0.2.70", headers={"User-Agent": "curl/8.0"})
    assert await parity.ctx.abuse.record_bot_scores() >= 1
    await parity.ctx.recorder.flush()
    admin = await parity.admin()
    page = (await admin.get("clients/ips/192.0.2.70", params={"range": "1h"})).json()
    recorded = page["bot_score"]["recorded"]
    assert recorded is not None, page["bot_score"]
    providers = parity.ctx.insights.providers
    providers.memo_s = 0
    assert "192.0.2.70" in await providers.client_scores()


async def test_r4_logicfix_a_challenge_page_reaches_the_upstream_cards_and_table(parity: Any) -> None:
    parity.roblox.route(host=GAMES, path="/v1/games").mock(
        return_value=httpx.Response(200, content=HTML, headers={"content-type": "text/html; charset=utf-8"})
    )
    for n in range(4):
        response = await parity.get(f"/{GAMES}/v1/games?universeIds={n + 100}")
        assert response.status_code == 200
    await parity.ctx.recorder.flush()
    admin = await parity.admin()
    cards = (await admin.get("upstream/egress", params={"range": "1h"})).json()
    direct = next(card for card in cards["items"] if card["egress"] == "direct")
    assert direct["challenges"] + direct["html_bodies"] >= 4, direct
    table = (await admin.get("upstream/challenges", params={"range": "1h"})).json()
    assert any(item["template"] == TEMPLATE for item in table["items"]), table


async def test_r4_logicfix_the_wired_disk_job_feeds_the_persistence_card_and_the_provider(parity: Any) -> None:
    status = await parity.ctx.jobs.run_job_now("metrics_disk_history")
    assert status.last_ok, status.last_error
    admin = await parity.admin()
    body = (await admin.get("system/persistence")).json()
    assert body["growth"], body["growth"]
    assert body["growth"][-1]["total_bytes"] > 0, body["growth"]
    providers = parity.ctx.insights.providers
    providers.memo_s = 0
    disk = await providers.disk()
    # SYS-DISK's growth line needs a day of samples (by design); the table sizes come from the same job run.
    assert disk is not None
    assert disk.get("tables"), disk
    assert disk.get("tables_sampled_at"), disk
