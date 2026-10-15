"""v1 parity: the response cache as a caller and the owner see it, end to end.

What this is
    Ports of the v1 smoke cache sections that the v2 unit and admin API tests did not prove through the proxy
    route: S100 (what counts as the same request, prettyprint from the cache), S101 (per-endpoint rules and their
    lifetime in the browser), S102 (an expired answer is fetched again), S106 (no disk tier means a cold worker
    misses), S108 (cache off) and S110 (refreshing an entry resends the parameters it was built from).

Why it exists
    The cache is where a proxy can silently go wrong: two different requests sharing an answer, a stale answer
    served as fresh, or a refresh that asks Roblox for something else than the stored request. v1's suite checked
    those through real requests; these tests keep that view next to the v2 unit tests of `roxy/cache/`.

How it works
    The `parity` fixture runs the real app with Roblox played by respx (each route counts its calls). Every request
    comes from its own client address; `ctx.cache.settle()` waits for the background cache.db write that follows an
    answer (DESIGN 11.9), so the cache browser sees the entry. Lifetimes move with the fake clock.

What to read next
    `roxy/cache/service.py` (lookup, store, refresh), `roxy/cache/keys.py` (the key text) and
    `roxy/admin/api/cache.py` (browser, rules, refresh).
"""

from __future__ import annotations

from typing import Any

import httpx

USERS = "users.roblox.com"


def ok(response: httpx.Response) -> Any:
    assert response.status_code in (200, 201), response.text
    return response.json()


def route(parity: Any, host: str, payload: Any = None) -> Any:
    answer = httpx.Response(200, json=payload if payload is not None else {"ok": True})
    return parity.roblox.route(host=host).mock(return_value=answer)


async def get(parity: Any, path: str) -> httpx.Response:
    response: httpx.Response = await parity.get(path)
    await parity.ctx.cache.settle()
    return response


async def test_v1_query_order_shares_one_entry_and_another_value_does_not(parity: Any) -> None:
    """v1 smoke lines 3140 and 3143: the order of query names does not split the cache; a different value does."""
    games = route(parity, "games.roblox.com")
    first = await get(parity, "/games.roblox.com/v1/games/votes?universeIds=1&other=2")
    second = await get(parity, "/games.roblox.com/v1/games/votes?other=2&universeIds=1")
    assert (first.headers["roxy-cache"], second.headers["roxy-cache"]) == ("MISS", "HIT")
    assert games.call_count == 1
    other = await get(parity, "/games.roblox.com/v1/games/votes?universeIds=999")
    assert other.headers["roxy-cache"] == "MISS"
    assert games.call_count == 2


async def test_v1_prettyprint_is_served_from_the_cached_body(parity: Any) -> None:
    """v1 smoke lines 3146 to 3148: `prettyprint=true` reuses the cached answer and formats it at serve time."""
    games = route(parity, "games.roblox.com", {"data": [1, 2]})
    plain = await get(parity, "/games.roblox.com/v1/games/votes?universeIds=5")
    assert plain.content == b'{"data":[1,2]}'
    pretty = await get(parity, "/games.roblox.com/v1/games/votes?universeIds=5&prettyprint=true")
    assert games.call_count == 1  # no new call
    assert pretty.headers["roxy-cache"] == "HIT"
    assert b"\n" in pretty.content  # formatted (indent 4, as v1)
    assert pretty.content.startswith(b"{\n    ")


async def test_v1_an_expired_answer_is_fetched_again_not_reused(parity: Any) -> None:
    """v1 smoke lines 3187 to 3200, with the v2 stale-while-revalidate window off (cache_swr_seconds 0) so that an
    expired entry behaves as in v1: the next request is a MISS that goes to Roblox, then the new copy is reused."""
    await parity.settings(cache_swr_seconds=0, cache_default_rules_enabled=0, cache_ttl_seconds=5)
    users = route(parity, USERS)
    path = f"/{USERS}/v1/users/expiry-test"
    assert (await get(parity, path)).headers["roxy-cache"] == "MISS"
    assert (await get(parity, path)).headers["roxy-cache"] == "HIT"
    admin = await parity.admin()
    before = ok(await admin.get("cache/entries", params={"q": "expiry-test"}))["items"][0]
    parity.clock.advance(6)
    refetched = await get(parity, path)
    assert refetched.headers["roxy-cache"] == "MISS"  # not STALE: a stale copy is only a fallback
    assert users.call_count == 2
    assert (await get(parity, path)).headers["roxy-cache"] == "HIT"
    after = ok(await admin.get("cache/entries", params={"q": "expiry-test"}))["items"][0]
    assert after["expires_at"] > before["expires_at"]  # the lifetime started again


async def test_v1_cache_rules_set_the_lifetime_and_can_say_never(parity: Any) -> None:
    """v1 smoke lines 3158 to 3174: a rule with TTL 0 means never cache, a rule with TTL 3600 caches with that
    lifetime and the browser names the rule; deleting a rule removes it from the list."""
    await parity.settings(cache_default_rules_enabled=0)
    users = route(parity, USERS)
    admin = await parity.admin()
    never = ok(await admin.post("cache/rules", json={"pattern": f"{USERS}/v1/never", "ttl": 0, "note": "test"}))
    long = ok(await admin.post("cache/rules", json={"pattern": f"{USERS}/v1/long", "ttl": 3600}))
    patterns = [item["pattern"] for item in ok(await admin.get("cache/rules"))["items"]]
    assert {f"{USERS}/v1/never", f"{USERS}/v1/long"} <= set(patterns)
    await get(parity, f"/{USERS}/v1/never")
    await get(parity, f"/{USERS}/v1/never")
    assert users.call_count == 2  # TTL 0: both went to Roblox
    await get(parity, f"/{USERS}/v1/long")
    await get(parity, f"/{USERS}/v1/long")
    assert users.call_count == 3  # TTL 3600: the second was a hit
    entry = ok(await admin.get("cache/entries", params={"q": "v1/long"}))["items"][0]
    assert entry["ttl"] == 3600
    assert entry["rule_id"] == long["rule"]["id"]
    ok(await admin.delete(f"cache/rules/{never['rule']['id']}"))
    patterns = [item["pattern"] for item in ok(await admin.get("cache/rules"))["items"]]
    assert f"{USERS}/v1/never" not in patterns


async def test_v1_cache_off_sends_every_request_upstream(parity: Any) -> None:
    """v1 smoke lines 3344 and 3345."""
    await parity.settings(cache_enabled=0)
    games = route(parity, "games.roblox.com")
    first = await get(parity, "/games.roblox.com/v1/games/votes?universeIds=7")
    second = await get(parity, "/games.roblox.com/v1/games/votes?universeIds=7")
    assert games.call_count == 2
    assert (first.headers["roxy-cache"], second.headers["roxy-cache"]) == ("OFF", "OFF")


async def test_v1_without_the_disk_tier_a_cold_worker_misses(parity: Any) -> None:
    """v1 smoke line 3307: with `cache_disk_enabled` 0 and an empty memory tier the repeat is a miss."""
    await parity.settings(cache_disk_enabled=0)
    games = route(parity, "games.roblox.com")
    assert (await get(parity, "/games.roblox.com/v1/games/votes?universeIds=8")).headers["roxy-cache"] == "MISS"
    parity.ctx.cache.store.memory.clear()  # a worker that never saw the answer
    parity.clock.advance(2)  # past the 1 s a finished single-flight outcome lingers (DESIGN 11.9)
    again = await get(parity, "/games.roblox.com/v1/games/votes?universeIds=8")
    assert again.headers["roxy-cache"] == "MISS"
    assert games.call_count == 2


async def test_v1_refresh_resends_the_parameters_the_entry_was_built_from(parity: Any) -> None:
    """v1 smoke lines 3388 to 3401: a refresh costs one call, keeps repeated values and never re-parses an encoded
    `=` out of the display key."""
    games = route(parity, "games.roblox.com")
    path = "/games.roblox.com/v1/games/refresh-me?universeIds=1&universeIds=2&note=a%3Db"
    await get(parity, path)
    admin = await parity.admin()
    entry = ok(await admin.get("cache/entries", params={"q": "refresh-me"}))["items"][0]
    calls = games.call_count
    parity.clock.advance(5)
    refreshed = ok(await admin.post(f"cache/entries/{entry['id']}/refresh"))
    assert refreshed["ok"] is True
    assert games.call_count == calls + 1
    sent = games.calls.last.request.url.params
    assert sent.get_list("universeIds") == ["1", "2"]
    assert sent.get_list("note") == ["a=b"]
    after = ok(await admin.get(f"cache/entries/{entry['id']}"))
    assert after["stored_at"] > entry["stored_at"]
    assert after["expires_at"] > entry["expires_at"]


async def test_v1_an_empty_ignored_parameter_name_is_refused(parity: Any) -> None:
    """v1 smoke line 3473: `{"name": ""}` is refused (v1 400, v2 422 as DESIGN 13 says) and nothing is stored."""
    admin = await parity.admin()
    before = ok(await admin.get("cache/ignored-params"))["items"]
    refused = await admin.post("cache/ignored-params", json={"name": ""})
    assert refused.status_code == 422, refused.text
    assert ok(await admin.get("cache/ignored-params"))["items"] == before
