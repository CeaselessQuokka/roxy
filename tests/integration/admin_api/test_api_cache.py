"""The Cache API (`/admin/api/v1/cache`) in the real app: stats with honest avoided calls, the per-endpoint table,
rules and ignored parameters through the audited services, the key spread, and the browser (search, sort, inspect,
refresh of GET and POST entries, purge by every scope, audited first; handoff rows hidden) (plan 14.1 Cache row,
parity rows 52 to 67)."""

from __future__ import annotations

import itertools
import json
from typing import Any

import httpx
import pytest

from roxy.cache.keys import HANDOFF_SUFFIX, MARKER_SUFFIX, key_id
from roxy.cache.store import CacheEntry
from roxy.config.audit import Actor
from roxy.core.reasons import AuthClass, CacheState, Egress, Outcome, ReasonCode, Source
from roxy.rules.service import RulesService
from roxy.storage.db import SharedStateUnavailable

GAMES = "games.roblox.com"
ACTOR = Actor("cli", "test")
_ips = itertools.count(1)


async def proxy(api_app: Any, method: str, path: str, **kwargs: Any) -> httpx.Response:
    """One caller request through the real proxy route (a new client address each time: no per-IP limit)."""
    n = next(_ips)
    headers = {"User-Agent": "Roblox/Linux", "X-Forwarded-For": f"198.51.{n // 250}.{n % 250 + 1}"}
    response: httpx.Response = await api_app.harness.http.request(method, path, headers=headers, **kwargs)
    await api_app.ctx.cache.settle()
    return response


def games_route(api_app: Any, body: Any = None) -> Any:
    return api_app.roblox.route(host=GAMES, path="/v1/games").mock(
        return_value=httpx.Response(200, json=body if body is not None else {"data": [1]})
    )


def games_key(universe: int) -> str:
    """The key text of a proxied games lookup: httpx sends `Accept: */*`, a forwarded header the key varies on."""
    return f"GET {GAMES}/v1/games?universeIds={universe} ^accept=%2A%2F%2A"


async def fill(api_app: Any, values: tuple[int, ...] = (1, 2, 3)) -> None:
    for value in values:
        response = await proxy(api_app, "GET", f"/{GAMES}/v1/games?universeIds={value}")
        assert response.status_code == 200, response.text


async def entry_ids(api: Any, api_json: Any, **params: Any) -> dict[str, str]:
    body = api_json(await api.get("cache/entries", params=params))
    return {row["key"]: row["id"] for row in body["items"]}


async def audit_actions(api_app: Any) -> list[tuple[str, str]]:
    rows = await api_app.ctx.dbs.control.read(
        lambda conn: conn.execute("SELECT action, target FROM audit_log ORDER BY id").fetchall()
    )
    return [(str(r[0]), str(r[1])) for r in rows]


def raw_entry(key: str, *, now: int, **fields: Any) -> CacheEntry:
    base: dict[str, Any] = {
        "id": key_id(key),
        "key": key,
        "auth_class": AuthClass.ANON,
        "method": "GET",
        "host": GAMES,
        "path": "v1/games",
        "status": 200,
        "body": b'{"data": []}',
        "content_type": "application/json",
        "stored_at": now,
        "expires_at": now + 300,
        "stale_until": now + 900,
        "ttl": 300,
    }
    base.update(fields)
    return CacheEntry(**base)


# ============================================================================================== numbers


async def test_cache_needs_a_session(anon_api: Any) -> None:
    for path in ("cache/stats", "cache/entries", "cache/rules", "cache/spread", "cache/ignored-params"):
        assert (await anon_api.get(path)).status_code == 401, path
    assert (await anon_api.post("cache/purge", json={"scope": "all", "confirm": True})).status_code == 401


async def test_stats_are_honest(api: Any, metrics_seed: Any, api_json: Any) -> None:
    metrics_seed.record(4, outcome=Outcome.SERVED_CACHE, reason=ReasonCode.CACHE_HIT, source=Source.CACHE,
                        cache_state=CacheState.HIT, upstream_calls=0, egress=Egress.NONE)  # fmt: skip
    metrics_seed.record(2)  # two misses, one upstream call each
    metrics_seed.record(1, outcome=Outcome.SERVED_CACHE, reason=ReasonCode.CACHE_STALE_ERROR, source=Source.CACHE,
                        cache_state=CacheState.STALE, upstream_calls=1, egress=Egress.DIRECT)  # fmt: skip
    metrics_seed.record(3, outcome=Outcome.REFUSED, reason=ReasonCode.THROTTLE, status=429, source=Source.ROXY,
                        cache_state=CacheState.NA, upstream_calls=0, egress=Egress.NONE)  # fmt: skip
    await metrics_seed.flush()
    body = api_json(await api.get("cache/stats", params={"range": "1h"}))
    tiles = {tile["key"]: tile for tile in body["tiles"]}
    assert tiles["hit_ratio"]["value"] == round(5 / 7, 4)
    assert tiles["demand"]["value"] == 7  # refusals are not demand
    assert tiles["upstream_calls"]["value"] == 3  # the failed refresh behind the stale serve counts too (P6)
    assert tiles["avoided"]["value"] == 4
    assert tiles["errors_hidden"]["value"] == 1  # a stale serve after a failure is not a success
    assert body["states"] == {"cache_hit": 4, "cache_revalidating": 0, "cache_stale": 1, "cache_coalesced": 0,
                              "cache_miss": 2}  # fmt: skip
    assert body["recent_hit_ratio"]["5m"]["hit_ratio"] == round(5 / 7, 4)
    assert set(body["size"]) >= {"rows", "bytes", "max_entries", "max_bytes", "disk_enabled"}
    assert "memory" in body["this_worker"]
    assert "OK" in body["disk"]
    assert "Dir" not in body["disk"]
    assert body["settings"]["ttl_s"] == 120
    ratios = api_json(await api.get("cache/ratios", params={"range": "1h"}))
    assert {entry["key"] for entry in ratios["series"]} == {"hit_ratio", "avoided_pct"}
    states = api_json(await api.get("cache/states", params={"range": "1h"}))
    by_key = {entry["key"]: entry for entry in states["series"]}
    assert sum(p[1] for p in by_key["cache_hit"]["points"]) == 4
    assert by_key["cache_stale"]["label"].startswith("Stale")


async def test_endpoint_table_with_negative_hits_and_rules(
    api: Any, api_app: Any, metrics_seed: Any, api_json: Any
) -> None:
    template = "games.roblox.com/v1/games/{universeId}/badges"
    rules = RulesService(api_app.ctx.dbs.control, clock=api_app.clock, store=api_app.ctx.rules)
    rule = await rules.create("rules_cache", {"pattern": "games.roblox.com/v1/games/*/badges", "ttl": 900}, ACTOR)
    metrics_seed.record(3, endpoint_template=template, outcome=Outcome.SERVED_CACHE, reason=ReasonCode.CACHE_HIT,
                        source=Source.CACHE, cache_state=CacheState.HIT, upstream_calls=0)  # fmt: skip
    metrics_seed.record(2, endpoint_template=template, outcome=Outcome.SERVED_CACHE, status=404,
                        reason=ReasonCode.CACHE_NEGATIVE, source=Source.CACHE, cache_state=CacheState.HIT,
                        upstream_calls=0)  # fmt: skip
    metrics_seed.record(1)
    await metrics_seed.flush()
    body = api_json(await api.get("cache/endpoints", params={"range": "1h"}))
    rows = {row["key"]: row for row in body["items"]}
    assert rows[template]["negative_hits"] == 2
    assert rows[template]["cache_hit"] == 5
    assert rows[template]["rule_id"] == rule.key
    assert rows[template]["ttl_s"] == 900
    assert rows["games.roblox.com/v1/games"]["negative_hits"] == 0
    download = await api.get("cache/endpoints", params={"range": "1h", "format": "json"})
    exported = download.json()
    assert exported["table"] == "cache_endpoints"
    assert exported["total"] == 2
    assert {item["key"]: item["negative_hits"] for item in exported["items"]}[template] == 2


# ============================================================================================== rules


async def test_rule_crud_is_audited_and_purges(api: Any, api_app: Any, api_json: Any, section13: Any) -> None:
    games_route(api_app)
    await fill(api_app, (1, 2))
    before = api_app.ctx.settings.version
    created = await api.post(
        "cache/rules",
        json={
            "pattern": "games.roblox.com/v1/games",
            "ttl": 600,
            "stale_ttl": 60,
            "negative_ttl": 30,
            "methods": ["GET", "POST"],
            "normalize_flags": ["sort_csv:universeIds"],
            "note": "owner zebra note",
            "reason": "longer TTL",
        },
    )
    assert created.status_code == 201, created.text
    body = api_json(created)
    rule = body["rule"]
    assert rule["methods"] == ["GET", "POST"]
    assert rule["normalize_flags"] == ["sort_csv:universeIds"]
    assert rule["origin"] == "admin"
    assert rule["created_by"] == "admin:" + api.admin.username
    assert body["config_version"] > before
    assert body["purge"]["removed"] == 2  # the stored answers the rule now covers
    assert ("rule.create", f"rules_cache:{rule['id']}") in await audit_actions(api_app)
    assert any(action == "cache.purge" for action, _ in await audit_actions(api_app))
    assert await entry_ids(api, api_json) == {}

    section13(await api.post("cache/rules", json={"pattern": "games.roblox.com/v1/games"}), 409, "conflict")
    fields = section13(
        await api.post("cache/rules", json={"pattern": "x.roblox.com/a", "normalize_flags": ["shuffle"]}),
        422,
        "invalid_rule",
    )
    assert "normalize_flags" in fields
    fields = section13(await api.post("cache/rules", json={"pattern": "x.roblox.com/b", "color": "red"}), 422,
                       "validation_failed")  # fmt: skip
    assert "color" in fields
    section13(await api.post("cache/rules", content=b"[1]", headers={"Content-Type": "application/json"}), 400,
              "invalid_body")  # fmt: skip
    assert (await api.post("cache/rules", json={"pattern": "x.roblox.com/c"}, csrf=False)).status_code == 403

    listed = api_json(await api.get("cache/rules", params={"q": "zebra"}))
    assert [row["id"] for row in listed["items"]] == [rule["id"]]
    updated = api_json(await api.patch(f"cache/rules/{rule['id']}", json={"ttl": 1200, "purge": False}))
    assert updated["changed"] is True
    assert updated["rule"]["ttl"] == 1200
    assert updated["purges"] == []
    section13(await api.patch(f"cache/rules/{rule['id']}", json={}), 422, "validation_failed")
    removed = api_json(await api.delete(f"cache/rules/{rule['id']}"))
    assert removed["deleted"]["id"] == rule["id"]
    assert removed["purge"]["scope"] == f"rule:{rule['id']}"
    section13(await api.delete(f"cache/rules/{rule['id']}"), 404, "not_found")


async def test_ignored_params_add_and_remove_purge_only_their_entries(api: Any, api_app: Any, api_json: Any) -> None:
    games_route(api_app)
    body = api_json(await api.get("cache/ignored-params"))
    assert "v" in body["suggestions"]
    assert "t" not in body["suggestions"]
    assert body["cap"] == 100
    for path in (f"/{GAMES}/v1/games?universeIds=1&v=7", f"/{GAMES}/v1/games?universeIds=2"):
        assert (await proxy(api_app, "GET", path)).status_code == 200
    added = await api.post("cache/ignored-params", json={"name": "v", "note": "app version", "reason": "buster"})
    assert added.status_code == 201, added.text
    assert added.json()["purge"]["removed"] == 1  # only the entry keyed with v
    keys = await entry_ids(api, api_json)
    assert list(keys) == [games_key(2)]
    assert "v" in {row["name"] for row in api_json(await api.get("cache/ignored-params"))["items"]}
    removed = api_json(await api.delete("cache/ignored-params/v", json={"reason": "back in the key"}))
    assert removed["deleted"]["name"] == "v"


# ============================================================================================== browser


async def test_browser_search_sort_page_and_hidden_handoff_rows(
    api: Any, api_app: Any, api_json: Any, section13: Any
) -> None:
    games_route(api_app)
    await fill(api_app, (1, 2, 3))
    now = int(api_app.clock.now())
    shared = api_app.ctx.cache.store.shared
    plain = games_key(1)
    await shared.write(raw_entry(plain + HANDOFF_SUFFIX, now=now, negative=True, expires_at=now - 1), compress=True)
    await shared.write(raw_entry(plain + MARKER_SUFFIX, now=now, negative=True, status=429), compress=True)
    body = api_json(await api.get("cache/entries", params={"sort": "key", "order": "asc"}))
    keys = [row["key"] for row in body["items"]]
    assert all(not key.endswith(HANDOFF_SUFFIX) for key in keys)  # plumbing, never shown
    assert keys == sorted(keys)
    assert body["total"] == 4
    states = {row["key"]: row["state"] for row in body["items"]}
    assert states[plain] == "fresh"
    assert states[plain + MARKER_SUFFIX] == "marker"
    desc = api_json(await api.get("cache/entries", params={"sort": "key", "order": "desc"}))
    assert [row["key"] for row in desc["items"]] == list(reversed(keys))  # v1 always sorted descending (bug 3)
    found = api_json(await api.get("cache/entries", params={"q": "UNIVERSEIDS=2"}))
    assert [row["key"] for row in found["items"]] == [games_key(2)]
    paged = api_json(await api.get("cache/entries", params={"page_size": 10, "page": 2}))
    assert paged["items"] == []
    assert paged["total"] == 4
    assert body["fresh"] == 4
    section13(await api.get("cache/entries", params={"sort": "body"}), 422, "invalid_table_query")


async def test_inspect_and_refresh_a_get_entry(api: Any, api_app: Any, api_json: Any, section13: Any) -> None:
    route = games_route(api_app, {"data": ["old"]})
    await fill(api_app, (5,))
    entry = (await entry_ids(api, api_json))[games_key(5)]
    inspected = api_json(await api.get(f"cache/entries/{entry}"))
    assert json.loads(inspected["body"]) == {"data": ["old"]}
    assert inspected["state"] == "fresh"
    assert inspected["params"] == [["universeIds", "5"]]
    assert inspected["request_body"] is None
    assert inspected["body_truncated"] is False
    calls = route.call_count
    route.mock(return_value=httpx.Response(200, json={"data": ["new"]}))
    api_app.clock.advance(5)
    refreshed = await api.post(f"cache/entries/{entry}/refresh")
    assert refreshed.status_code == 200, refreshed.text
    result = refreshed.json()
    assert result["ok"] is True
    assert result["stored"] is True
    assert result["upstream_calls"] == 1
    assert result["cache_state"] == "MISS"
    assert route.call_count == calls + 1
    assert json.loads(api_json(await api.get(f"cache/entries/{entry}"))["body"]) == {"data": ["new"]}
    assert ("cache.refresh", f"cache:{entry}") in await audit_actions(api_app)
    api_app.clock.advance(61)
    await api_app.ctx.recorder.flush()
    internal = await api_app.ctx.dbs.metrics.read(
        lambda conn: conn.execute("SELECT reason_code FROM events WHERE type = 'internal_call'").fetchall()
    )
    assert [row[0] for row in internal] == ["admin_cache_refresh"]  # Roxy's own call, never caller demand

    section13(await api.get("cache/entries/" + "0" * 24), 404, "not_found")
    section13(await api.get("cache/entries/not-an-id"), 422, "validation_failed")
    section13(await api.post("cache/entries/" + "0" * 24 + "/refresh"), 404, "not_found")


async def test_refresh_a_post_entry_resends_its_body(api: Any, api_app: Any, api_json: Any) -> None:
    route = api_app.roblox.route(host="presence.roblox.com", path="/v1/presence/users").mock(
        return_value=httpx.Response(200, json={"userPresences": [1]})
    )
    payload = {"userIds": [1, 2]}
    first = await proxy(api_app, "POST", "/presence.roblox.com/v1/presence/users", json=payload)
    assert first.headers["roxy-cache"] == "MISS"
    keys = await entry_ids(api, api_json)
    ((key, entry),) = keys.items()
    assert key.startswith("POST presence.roblox.com/v1/presence/users #")
    inspected = api_json(await api.get(f"cache/entries/{entry}"))
    assert json.loads(inspected["request_body"]) == payload
    api_app.clock.advance(5)
    result = api_json(await api.post(f"cache/entries/{entry}/refresh"))
    assert result["ok"] is True
    assert result["stored"] is True
    assert route.call_count == 2
    assert json.loads(route.calls.last.request.content) == payload  # the stored body was sent again


async def test_refresh_refusals(api: Any, api_app: Any, section13: Any) -> None:
    now = int(api_app.clock.now())
    shared = api_app.ctx.cache.store.shared
    cred = raw_entry("GET economy.roblox.com/v1/user/currency @cred", now=now, auth_class=AuthClass.CRED,
                     host="economy.roblox.com", path="v1/user/currency")  # fmt: skip
    marker = raw_entry(f"GET {GAMES}/v1/games?universeIds=9{MARKER_SUFFIX}", now=now, negative=True, status=429)
    for entry in (cred, marker):
        await shared.write(entry, compress=True)
    message = section13(await api.post(f"cache/entries/{cred.id}/refresh"), 409, "wrong_state")
    assert message == {}
    section13(await api.post(f"cache/entries/{marker.id}/refresh"), 409, "wrong_state")
    rules = RulesService(api_app.ctx.dbs.control, clock=api_app.clock, store=api_app.ctx.rules)
    games = raw_entry(f"GET {GAMES}/v1/games?universeIds=8", now=now)
    await shared.write(games, compress=True)
    await rules.create("rules_cache", {"pattern": f"{GAMES}/v1/games", "ttl": 0}, ACTOR)  # never cache it now
    section13(await api.post(f"cache/entries/{games.id}/refresh"), 409, "wrong_state")


# ============================================================================================== purges


async def test_purge_every_scope_is_audited_first(api: Any, api_app: Any, api_json: Any, section13: Any) -> None:
    games_route(api_app)
    api_app.roblox.route(host="users.roblox.com", path="/v1/users/1").mock(
        return_value=httpx.Response(200, json={"id": 1})
    )
    await fill(api_app, (1, 2, 3, 4))
    assert (await proxy(api_app, "GET", "/users.roblox.com/v1/users/1")).status_code == 200
    keys = await entry_ids(api, api_json)
    one = keys[games_key(1)]

    by_id = api_json(await api.post("cache/purge", json={"scope": "id", "value": one, "reason": "bad copy"}))
    assert by_id["removed"] == 1
    assert by_id["scope"] == f"id:{one}"
    assert by_id["message"] == "1 entry removed."
    assert ("cache.purge", f"cache:id:{one}") in await audit_actions(api_app)
    regex = api_json(await api.post("cache/purge", json={"scope": "pattern", "value": r"games\.roblox\.com/v1/gam",
                                                         "type": "regex"}))  # fmt: skip
    assert regex["removed"] == 3  # a regex is matched as a regex (v1 bug 5)
    host = api_json(await api.post("cache/purge", json={"scope": "host", "value": "USERS.roblox.com"}))
    assert host["removed"] == 1
    assert await entry_ids(api, api_json) == {}

    section13(await api.post("cache/purge", json={"scope": "pattern", "value": "(", "type": "regex"}), 422,
              "invalid_pattern")  # fmt: skip
    section13(await api.post("cache/purge", json={"scope": "id"}), 422, "validation_failed")
    fields = section13(await api.post("cache/purge", json={"scope": "all"}), 422, "confirmation_required")
    assert "confirm" in fields
    await fill(api_app, (7,))
    expired = api_json(await api.post("cache/purge", json={"scope": "expired"}))
    assert expired["removed"] == 0
    everything = api_json(await api.post("cache/purge", json={"scope": "all", "confirm": True}))
    assert everything["removed"] == 1
    assert everything["fleet_invalidated"] is True


async def test_purge_is_refused_when_its_audit_row_cannot_be_written(
    api: Any, api_app: Any, api_json: Any, section13: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    games_route(api_app)
    await fill(api_app, (1,))
    control = api_app.ctx.dbs.control
    real_write = control.write
    blocked = {"on": False}

    async def write(fn: Any, **kwargs: Any) -> Any:
        if blocked["on"]:
            raise SharedStateUnavailable("control", "simulated lock")
        return await real_write(fn, **kwargs)

    monkeypatch.setattr(control, "write", write)
    csrf = await api.csrf()  # read before the lock (the session lookup never writes)
    blocked["on"] = True
    response = await api.post("cache/purge", json={"scope": "all", "confirm": True}, csrf=False,
                              headers={"X-CSRF-Token": csrf})  # fmt: skip
    section13(response, 503, "unavailable")
    blocked["on"] = False
    assert len(await entry_ids(api, api_json)) == 1  # nothing was purged without its audit row


# ============================================================================================== key spread


async def test_key_spread_finds_the_splitting_parameter(api: Any, api_app: Any, api_json: Any) -> None:
    now = int(api_app.clock.now())
    shared = api_app.ctx.cache.store.shared
    for n in range(8):
        key = f"GET {GAMES}/v1/games?nonce={n}&universeIds=1"
        await shared.write(raw_entry(key, now=now, params=(("nonce", str(n)), ("universeIds", "1"))), compress=True)
    body = api_json(await api.get("cache/spread"))
    group = body["items"][0]
    assert group["suspect"] is True
    assert group["suspect_param"] == "nonce"
    assert group["entries"] == 8
    assert group["varying"][0]["name"] == "nonce"
    params = api_json(await api.get("cache/ignored-params"))
    assert {"param": "nonce", "path": f"{GAMES}/v1/games", "entries": 8, "hits": 0} in params["suspects"]
