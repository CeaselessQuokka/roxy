"""Review round 3, parity lens: the cache browser's "Purge matching" against its search (v1 bug 4; parity row 66).

What this is
    Tests for v1 dashboard bug 4 (`.remake/v1notes/dashboard.md` section 13), which its "impact for v2" column says to
    fix by defining one matching rule: the browser search is a case-insensitive substring of the whole key, while
    "Purge matching" sent the same text as a glob over host and path, so searching `votes` listed entries that the
    purge then left alone. The fix (finding parity-15): `POST /cache/purge` takes `scope: search`, which runs the
    browser's own condition (`cache/read_browser.py SEARCH_CONDITION`) through the store's purge kind
    `PurgeKind.SEARCH` (`cache/store.py`). Both tests were strict xfails until that kind landed (review round 3
    integration); they now pin the fixed behavior.

Why it exists
    The api_traffic report claims v1 bugs 3 to 5 are fixed; bug 5 (a regex rule purged as a glob) and bug 3 (sort
    direction) are, bug 4 is not. An admin who searches, sees N entries and presses "Purge matching" must get those N
    entries purged (plan 14.1 Cache: "browser (search, sort, inspect, refresh, purge)").

How it works
    Two entries are stored through the real proxy route (respx plays Roblox), the browser search finds both, then the
    purge is sent with the `search` scope, which must purge exactly what the search listed (the old glob `pattern`
    reading of the same text is what v1 bug 4 got wrong, so it is no longer an acceptable way in).

What to read next
    `roxy/admin/api/cache.py` (`PurgeBody`, `cache_purge`), `roxy/cache/read_browser.py` (the search),
    `roxy/cache/service.py` (`purge`).
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

pytestmark = pytest.mark.asyncio

GAMES = "games.roblox.com"


async def _proxy_get(api_app: Any, path: str, n: int) -> httpx.Response:
    headers = {"User-Agent": "Roblox/Linux", "X-Forwarded-For": f"198.51.100.{n}"}
    response: httpx.Response = await api_app.harness.http.get(path, headers=headers)
    await api_app.ctx.cache.settle()
    return response


async def test_parity_15_purge_matching_purges_exactly_what_the_search_lists(
    api: Any, api_app: Any, api_json: Any
) -> None:
    api_app.roblox.route(host=GAMES, path="/v1/games/votes").mock(
        return_value=httpx.Response(200, json={"data": [{"upVotes": 1}]})
    )
    for n, universe in ((11, 1), (12, 2)):
        response = await _proxy_get(api_app, f"/{GAMES}/v1/games/votes?universeIds={universe}", n)
        assert response.status_code == 200, response.text
    listed = api_json(await api.get("cache/entries", params={"q": "votes"}))
    assert listed["total"] == 2, listed
    purged = api_json(
        await api.post("cache/purge", json={"scope": "search", "value": "votes", "reason": "purge matching"})
    )
    assert purged["removed"] == listed["total"], purged
    after = api_json(await api.get("cache/entries", params={"q": "votes"}))
    assert after["total"] == 0, after


async def test_parity_15_search_purge_removes_exactly_the_listed_entries_and_nothing_else(
    api: Any, api_app: Any, api_json: Any, section13: Any
) -> None:
    """The `search` scope runs the browser's own condition: case-insensitive substring of the whole key (query text
    included), so `UNIVERSEIDS=1` removes one entry of two and leaves the other; an empty search is refused (Purge
    all has its own confirmation); the purge is audited like every other."""
    api_app.roblox.route(host=GAMES, path="/v1/games/votes").mock(
        return_value=httpx.Response(200, json={"data": [{"upVotes": 1}]})
    )
    for n, universe in ((21, 1), (22, 2)):
        response = await _proxy_get(api_app, f"/{GAMES}/v1/games/votes?universeIds={universe}", n)
        assert response.status_code == 200, response.text
    section13(await api.post("cache/purge", json={"scope": "search", "value": "  "}), 422, "validation_failed")
    listed = api_json(await api.get("cache/entries", params={"q": "UNIVERSEIDS=1"}))
    assert listed["total"] == 1, listed
    purged = api_json(await api.post("cache/purge", json={"scope": "search", "value": "UNIVERSEIDS=1"}))
    assert (purged["removed"], purged["scope"]) == (1, "search:universeids=1"), purged
    left = api_json(await api.get("cache/entries", params={"q": "votes"}))
    assert left["total"] == 1, left
    assert "universeids=2" in str(left["items"][0]["key"]).lower(), left

    def audit_targets(conn: Any) -> list[str]:
        rows = conn.execute("SELECT target FROM audit_log WHERE action = 'cache.purge' ORDER BY id").fetchall()
        return [str(r[0]) for r in rows]

    assert await api_app.ctx.dbs.control.read(audit_targets) == ["cache:search:universeids=1"]
