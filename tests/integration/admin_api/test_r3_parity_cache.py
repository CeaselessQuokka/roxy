"""Review round 3, parity lens: the cache browser's "Purge matching" against its search (v1 bug 4; parity row 66).

What this is
    A strict xfail test for v1 dashboard bug 4 (`.remake/v1notes/dashboard.md` section 13), which its "impact for v2"
    column says to fix by defining one matching rule: the browser search is a case-insensitive substring of the whole
    key, while "Purge matching" sent the same text as a glob over host and path, so searching `votes` listed entries
    that the purge then left alone. v2 keeps both halves as they were: `GET /cache/entries?q=` searches substrings of
    the key, and `POST /cache/purge` offers only `pattern` (glob or regex over host and path), with no scope that
    purges exactly what a search lists.

Why it exists
    The api_traffic report claims v1 bugs 3 to 5 are fixed; bug 5 (a regex rule purged as a glob) and bug 3 (sort
    direction) are, bug 4 is not. An admin who searches, sees N entries and presses "Purge matching" must get those N
    entries purged (plan 14.1 Cache: "browser (search, sort, inspect, refresh, purge)").

How it works
    Two entries are stored through the real proxy route (respx plays Roblox), the browser search finds both, then the
    purge is tried the two ways a page could send it (a `search` scope, or the search text as a `pattern`); one of
    them must purge exactly what the search listed. The test is `xfail(strict=True)` with its finding id.

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


@pytest.mark.xfail(
    strict=True, reason="finding parity-15: cache 'Purge matching' cannot purge what the browser search lists (v1 B4)"
)
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
    attempts = []
    for body in ({"scope": "search", "value": "votes"}, {"scope": "pattern", "value": "votes"}):
        response = await api.post("cache/purge", json={**body, "reason": "purge matching"})
        removed = response.json().get("removed") if response.status_code == 200 else None
        attempts.append((body["scope"], response.status_code, removed))
        if response.status_code == 200 and removed:
            break
    after = api_json(await api.get("cache/entries", params={"q": "votes"}))
    assert after["total"] == 0, (attempts, after["total"])
