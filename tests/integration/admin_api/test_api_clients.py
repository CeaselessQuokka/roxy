"""The Clients page API (`/admin/api/v1/clients`) in the real app: places and IPs with rates, refusals and bot
score, the per-client pages, the ban, bypass and rule actions, and the experience lookup through the upstream
service with its cache (plan 14.1 Clients; parity rows 38, 73, 92).

Metrics are seeded through the real recorder (`metrics_seed`); Roblox is played by respx (`api_app.roblox`).
"""

from __future__ import annotations

import csv
import io
from typing import Any

import httpx
import pytest

from roxy.core.reasons import CacheState, Outcome, ReasonCode, Source

pytestmark = pytest.mark.asyncio

GOOD = "203.0.113.61"
BAD = "203.0.113.62"


def ok(response: Any, api_json: Any, status: int = 200) -> Any:
    assert response.status_code == status, response.text
    return api_json(response)


def seed_clients(seed: Any) -> None:
    seed.record(5, client_ip=GOOD, place_id="111", user_agent="Roblox/WinInet")
    seed.record(
        3,
        client_ip=BAD,
        place_id="222",
        user_agent="python-requests/2.31",
        outcome=Outcome.REFUSED,
        reason=ReasonCode.THROTTLE,
        status=429,
        source=Source.ROXY,
        cache_state=CacheState.NA,
        upstream_calls=0,
        check="throttle",
        path="games.roblox.com/v1/games/9",
    )


def mock_lookup(api_app: Any, *, place: str = "4242", universe: int = 77, created: str = "2020-01-01T00:00:00Z") -> Any:
    api_app.roblox.get(host="apis.roblox.com", path=f"/universes/v1/places/{place}/universe").mock(
        return_value=httpx.Response(200, json={"universeId": universe})
    )
    game = {
        "id": universe,
        "rootPlaceId": int(place),
        "name": "Obby World",
        "description": "Jump around.",
        "creator": {"id": 9, "name": "Builder", "type": "User", "hasVerifiedBadge": False},
        "created": created,
        "updated": created,
        "playing": 12,
        "visits": 500,
        "maxPlayers": 30,
        "favoritedCount": 3,
    }
    return api_app.roblox.get(host="games.roblox.com", path="/v1/games").mock(
        return_value=httpx.Response(200, json={"data": [game]})
    )


async def test_ip_table_rates_flags_bot_score_sort_search_and_export(
    api: Any, api_json: Any, section13: Any, metrics_seed: Any
) -> None:
    seed_clients(metrics_seed)
    await metrics_seed.flush()
    ok(await api.post(f"clients/ips/{BAD}/ban", json={"minutes": 10}), api_json)
    ok(await api.post(f"clients/ips/{GOOD}/bypass", json={}), api_json)
    table = ok(await api.get("clients/ips"), api_json)
    rows = {item["key"]: item for item in table["items"]}
    assert table["bot_score_scope"] == "this_worker"
    assert rows[GOOD]["requests"] == 5
    assert rows[GOOD]["rate1"] == 5
    assert rows[GOOD]["bypassed"] is True
    assert rows[GOOD]["banned"] is False
    assert rows[BAD]["refused"] == 3
    assert rows[BAD]["refused_pct"] == 100.0
    assert rows[BAD]["banned"] is True
    assert rows[BAD]["user_agent"] == "python-requests/2.31"
    assert isinstance(rows[BAD]["bot_score"], int)
    assert rows[BAD]["bot_score"] > rows[GOOD]["bot_score"]  # a library UA that keeps getting refused
    ordered = ok(await api.get("clients/ips", params={"sort": "refused", "order": "asc"}), api_json)
    assert [item["key"] for item in ordered["items"]] == [GOOD, BAD]
    found = ok(await api.get("clients/ips", params={"q": "113.62"}), api_json)
    assert [item["key"] for item in found["items"]] == [BAD]
    section13(await api.get("clients/ips", params={"sort": "bot_score"}), 422, "invalid_table_query")
    export = await api.get("clients/ips", params={"format": "csv"})
    assert export.status_code == 200
    text = export.content.decode()
    assert GOOD not in text  # addresses are hashed in exports unless export_include_ips is on
    assert next(csv.reader(io.StringIO(text)))[:2] == ["IP", "Requests"]


async def test_ip_page_totals_timeline_refusals_strikes_probes_and_bot_signals(
    api: Any, api_app: Any, api_json: Any, section13: Any, metrics_seed: Any
) -> None:
    seed_clients(metrics_seed)
    api_app.ctx.recorder.record_probe(BAD, 'Non-Roblox URL: "wp-admin.php"', "python-requests/2.31", "/wp-admin.php")
    await metrics_seed.flush()
    now = int(api_app.clock.now())

    def strikes(conn: Any) -> None:
        conn.execute(
            "INSERT INTO strikes (ip, strikes, last_strike_at, tier, throttled_until) VALUES (?, 2, ?, 2, ?)",
            (BAD, now, now + 90),
        )

    await api_app.ctx.dbs.hot.write(strikes)
    page = ok(await api.get(f"clients/ips/{BAD}"), api_json)
    assert page["totals"]["requests"] == 3
    assert page["totals"]["refused"] == 3
    assert sum(point["requests"] for point in page["timeline"]) == 3
    assert page["top_endpoints"] == [{"endpoint": "games.roblox.com/v1/games", "requests": 3}]
    assert page["refusals"][0]["reason"] == "throttle"
    assert page["refusals"][0]["count"] == 3
    assert page["last_hour"]["rates"]["1"] == 3
    assert page["strikes"]["throttled"] is True
    assert page["strikes"]["penalty_ends_in_s"] == 90
    assert page["strikes"]["strikes"] == 2
    assert page["recent_probes"][0]["reason"] == "Non-Roblox URL"
    assert page["recent_requests"][0]["user_agent"] == "python-requests/2.31"
    signals = page["bot_score"]["signals"]
    assert signals["library_ua"] == 1.0
    assert page["bot_score"]["scope"] == "this_worker"
    quiet = ok(await api.get("clients/ips/198.51.100.77"), api_json)
    assert quiet["totals"]["requests"] == 0
    assert quiet["bot_score"]["score"] is None  # no recent request: no User-Agent, no guess
    assert quiet["bot_score"]["recorded"] is None
    section13(await api.get("clients/ips/not-an-ip"), 422, "validation_failed")


async def test_recorded_fleet_scores_answer_when_no_live_row_exists(
    api: Any, api_app: Any, api_json: Any, metrics_seed: Any
) -> None:
    """lane_producers request 6: the bot score the fleet recorded (`client_score_hour`, written once a minute by every
    worker off the request path) answers for an address this worker has no recent request of, labeled `recorded`."""
    seed_clients(metrics_seed)
    await metrics_seed.flush()
    now = int(api_app.clock.now())
    hour = now - now % 3600

    def recorded(conn: Any) -> None:
        conn.execute("DELETE FROM events WHERE type = 'live' AND json_extract(detail_json, '$.ip') = ?", (GOOD,))
        for bucket, top in ((hour - 3600, 90), (hour, 64)):
            conn.execute(
                "INSERT INTO client_score_hour (bucket_start, client_key, score_max, score_last, last_at, samples) "
                "VALUES (?, ?, ?, ?, ?, 3)",
                (bucket, GOOD, top, top - 4, bucket + 60),
            )

    await api_app.ctx.dbs.metrics.write(recorded)  # the live rows of GOOD expired (15 minutes)
    table = ok(await api.get("clients/ips"), api_json)
    rows = {item["key"]: item for item in table["items"]}
    assert (rows[GOOD]["bot_score"], rows[GOOD]["bot_score_source"]) == (64, "recorded")  # its latest hour
    assert rows[BAD]["bot_score_source"] == "this_worker"
    assert set(table["bot_score_sources"]) == {"this_worker", "recorded"}
    assert table["caller_text"] == ["top_endpoint", "user_agent"]  # the busiest endpoint is caller text (secfix-5)
    page = ok(await api.get(f"clients/ips/{GOOD}", params={"range": "24h"}), api_json)
    assert page["bot_score"]["score"] is None  # no live view in this worker
    assert page["bot_score"]["recorded"] == {"score": 64, "score_last": 60, "at": hour + 60, "hour": hour}
    assert [h["score_max"] for h in page["bot_score"]["recorded_history"]] == [90, 64]


async def test_ip_actions_ban_bypass_and_deny_rule(api: Any, api_app: Any, api_json: Any, section13: Any) -> None:
    banned = ok(await api.post(f"clients/ips/{BAD}/ban", json={"minutes": 15, "message": "abuse"}), api_json)
    assert banned["ban"]["expires_in_s"] == 900
    section13(await api.post(f"clients/ips/{BAD}/ban", json={}), 422, "validation_failed")
    bans = ok(await api.get("protection/bans"), api_json)
    assert [item["subject"] for item in bans["items"]] == [BAD]
    section13(await api.post(f"clients/ips/{GOOD}/bypass", json={"never": True}), 422, "confirmation_required")
    bypass = ok(await api.post(f"clients/ips/{GOOD}/bypass", json={"expires_in_h": 1}), api_json)
    assert bypass["item"]["cidr"] == f"{GOOD}/32"
    deny = ok(await api.post(f"clients/ips/{BAD}/rule", json={"note": "scraper"}), api_json)
    assert deny["item"]["kind"] == "deny"
    section13(await api.post(f"clients/ips/{BAD}/rule", json={}), 409, "conflict")
    now = api_app.clock.now()
    assert api_app.ctx.rules.snapshot.access.deny.contains(BAD, now)
    page = ok(await api.get(f"clients/ips/{BAD}"), api_json)
    assert page["denied"] is True
    assert page["ban"]["subject"] == BAD


async def test_place_table_page_actions_and_lookup_cache(
    api: Any, api_app: Any, api_json: Any, section13: Any, metrics_seed: Any
) -> None:
    metrics_seed.record(4, client_ip=GOOD, place_id="4242")
    await metrics_seed.flush()
    table = ok(await api.get("clients/places"), api_json)
    assert table["items"][0]["key"] == "4242"
    assert table["items"][0]["name"] is None  # only a cached lookup names a place in a table
    route = mock_lookup(api_app)
    found = ok(await api.post("clients/places/4242/lookup"), api_json)
    assert found["cached"] is False
    assert found["result"]["name"] == "Obby World"
    assert found["result"]["universe_id"] == "77"
    assert found["result"]["creator_url"] == "https://www.roblox.com/users/9/profile"
    assert found["result"]["recently_created_warning"] is False
    again = ok(await api.post("clients/lookup", json={"id": "4242", "kind": "place"}), api_json)
    assert again["cached"] is True
    assert route.call_count == 1  # cached 10 minutes per worker (row 38)
    table = ok(await api.get("clients/places"), api_json)
    assert table["items"][0]["name"] == "Obby World"
    page = ok(await api.get("clients/places/4242"), api_json)
    assert page["totals"]["requests"] == 4
    assert page["lookup"]["name"] == "Obby World"
    assert page["ban"] is None
    ok(await api.post("clients/places/4242/ban", json={"permanent": True}), api_json)
    page = ok(await api.get("clients/places/4242"), api_json)
    assert page["ban"]["permanent"] is True
    rule = ok(await api.post("clients/places/4242/rule", json={}), api_json)
    assert rule["item"]["canonical_key"] == "roblox-id|value|exact|4242"
    section13(await api.post("clients/places/4242/rule", json={}), 409, "conflict")
    section13(await api.get("clients/places/abc"), 422, "validation_failed")


async def test_lookup_errors_are_section13(api: Any, api_app: Any, section13: Any) -> None:
    section13(await api.post("clients/lookup", json={"id": "12a"}), 422, "validation_failed")
    fields = section13(await api.post("clients/lookup", json={"id": "１２"}), 422, "validation_failed")
    assert "id" in fields  # ASCII digits only
    api_app.roblox.get(host="apis.roblox.com", path="/universes/v1/places/5/universe").mock(
        return_value=httpx.Response(200, json={})
    )
    section13(await api.post("clients/lookup", json={"id": "5"}), 404, "not_found")
    api_app.roblox.get(host="apis.roblox.com", path="/universes/v1/places/6/universe").mock(
        return_value=httpx.Response(400, json={"errors": [{"message": "bad"}]})
    )
    section13(await api.post("clients/lookup", json={"id": "6"}), 502, "upstream_failed")
