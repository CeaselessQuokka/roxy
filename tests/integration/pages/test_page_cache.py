"""The Cache page (`/admin/cache`, plan 14.1 Cache row; v1 Response Cache, parity rows 52 to 67): integration tests.

What this is
    Tests against the real app with traffic sent through the real proxy (`pages_app.seed_traffic()`: cached repeats,
    misses, a Roblox 429 and 503, hostile paths, User-Agents and places): the page and every fragment and drawer
    answer 200 for an admin and redirect otherwise; every registry card and every catalog setting of its anchors is
    there; the numbers equal the cache API's for the same range and filters; the browser pages, sorts and searches
    on the server with the API's names and never fails on a bad value; "Purge matching" sends the search scope and
    removes exactly what the search lists; the forms post to the API with CSRF (refused without it); hostile text
    stays inert everywhere; an empty database explains itself; and the rendered page passes the style guard.

Why it exists
    Plan P11 page rules: one source of truth per number (P6), security (9.2, 9.6, 9.16), help on every part (14.7),
    every setting next to its feature (15.6) and v1 parity (C3).

What to read next
    `roxy/admin/pages/cache.py`, `tests/e2e/test_page_cache.py` (the same page in a browser).
"""

from __future__ import annotations

from typing import Any

import pytest

from roxy.admin.pages import registry
from roxy.admin.pages.cache import explainer, span_words
from roxy.admin.pages.testing import HOSTILE, parse_html
from roxy.core.style_guard import find_style_issues

PAGE = "/admin/cache"
LAZY = ("ratios", "settings", "coalescing", "endpoints", "rules", "ignored-params", "spread")


async def _entry_ids(page: Any, **params: Any) -> list[str]:
    answer = (await page.api("GET", "cache/entries", params=params)).json()
    return [str(item["id"]) for item in answer["items"]]


async def test_the_page_its_fragments_and_drawers_need_a_signed_in_admin(anon: Any) -> None:
    paths = [PAGE, *(f"{PAGE}/fragment/{card.id}" for card in registry.cards_for("cache"))]
    paths += [f"{PAGE}/drawer/entry?id=0", f"{PAGE}/drawer/endpoint?template=x", f"{PAGE}/drawer/rule?id=1"]
    for path in paths:
        response = await anon.get(path)
        assert response.status_code == 302, path
        assert response.headers["location"] == "/admin"


async def test_every_card_fragment_and_inline_setting_is_there(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    doc = await page.doc(PAGE)
    assert len(doc.select("h1")) == 1
    for card in registry.cards_for("cache"):
        assert doc.select_one(f"section#{card.id}[data-card]") is not None, card.id
        fragment = await page.doc(f"{PAGE}/fragment/{card.id}")
        assert fragment.select_one(f"section#{card.id}[data-card]") is not None, card.id
        assert "data-card-error" not in str(fragment.text()), card.id
        for spec in registry.settings_for(registry.anchor("cache", card.id)):
            assert fragment.select_one(f'[data-setting-key="{spec.key}"]') is not None, (card.id, spec.key)
    for card_id in LAZY:
        assert doc.select_one(f"section#{card_id}.page-card--lazy") is not None, card_id
    stats = doc.select_one("section#stats")
    for key in ("hit_ratio", "served_cache", "avoided_pct"):
        assert stats.select_one(f'[data-kpi="{key}"]') is not None, key
    assert doc.select_one('#browser [data-table="cache_entries"]') is not None
    assert doc.select_one('#stats [data-action="cache-clear-stats"]') is not None
    for dialog in ("dlg-cache-purge", "dlg-cache-purge-all", "dlg-cache-unignore", "dlg-cache-rule-delete"):
        assert doc.select_one(f"dialog#{dialog}") is not None, dialog
    assert doc.select_one('link[href*="css/pages/cache"]') is not None
    assert doc.select_one('script[type="module"][src*="js/pages/cache"]') is not None
    rules = await page.doc(f"{PAGE}/fragment/rules")
    assert rules.select_one('[data-table="cache_rules"]') is not None
    spread = await page.doc(f"{PAGE}/fragment/spread")
    assert spread.select_one("#key-spread") is not None


async def test_the_numbers_equal_the_cache_api(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    for params in ({}, {"range": "1h"}, {"range": "7d"}):
        api = (await page.api("GET", "cache/stats", params=params)).json()
        doc = await page.doc(f"{PAGE}/fragment/stats", params=params)
        for tile in api["tiles"]:
            node = doc.select_one(f'[data-kpi="{tile["key"]}"] .kpi__number')
            assert node is not None, tile["key"]
            if tile["key"] == "served_cache":
                assert node.text() == f"{tile['value']:,}", params
    endpoints = (await page.api("GET", "cache/endpoints")).json()
    doc = await page.doc(f"{PAGE}/fragment/endpoints")
    count = doc.select_one(".dt__count").text()
    assert (f"of {endpoints['total']:,}" in count) if endpoints["total"] else count == "No rows"
    entries = (await page.api("GET", "cache/entries", params={"sort": "key", "order": "asc"})).json()
    browser = await page.doc(f"{PAGE}/fragment/browser", params={"sort": "key", "order": "asc"})
    rows = [row.get("data-row-id") for row in browser.select("tbody tr[data-row-id]")]
    assert rows == [f"entry-{item['id']}" for item in entries["items"]]
    assert entries["total"] > 0


async def test_the_browser_searches_sorts_and_pages_with_the_api_names(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    doc = await page.doc(PAGE, params={"q": "universeids=1", "sort": "hits", "order": "asc"})
    table = doc.select_one('#browser [data-table="cache_entries"]')
    assert table.select_one('input[name="q"]').get("value") == "universeids=1"
    assert table.select_one('th[data-col="hits"]').get("aria-sort") == "ascending"
    keys = [row.text() for row in table.select("tbody tr[data-row-id]")]
    assert keys
    assert all("universeids=1" in key.lower() for key in keys)
    button = doc.select_one("[data-purge-matching]")
    assert button.get("disabled") is None
    assert '"scope": "search"' in button.get("data-fill")
    plain = await page.doc(PAGE)
    assert plain.select_one("[data-purge-matching]").get("disabled") is not None


async def test_purge_matching_removes_exactly_what_the_search_lists(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    everything = await _entry_ids(page, page_size=250)
    listed = await _entry_ids(page, q="universeIds=1", page_size=250)
    assert listed
    assert len(listed) < len(everything)
    refused = await page.api("POST", "cache/purge", json={"scope": "search", "value": "universeIds=1"}, csrf=False)
    assert refused.status_code == 403
    done = await page.api("POST", "cache/purge", json={"scope": "search", "value": "universeIds=1"})
    assert done.status_code == 200, done.text
    assert done.json()["removed"] == len(listed)
    left = await _entry_ids(page, page_size=250)
    assert sorted(left) == sorted(set(everything) - set(listed))
    doc = await page.doc(f"{PAGE}/fragment/browser", params={"q": "universeIds=1"})
    assert "No stored answer matches" in doc.text()


async def test_hostile_text_is_inert_on_the_page_fragments_and_drawers(page: Any, pages_app: Any, inert: Any) -> None:
    await pages_app.seed_traffic()
    # Text a person or a caller chose, in every place the page shows it: a rule's note, an ignored parameter's
    # name and note, a stored key (the hostile query value), and an endpoint template in the drawer's link.
    rule = await page.api(
        "POST", "cache/rules", json={"pattern": "games.roblox.com/v1/games/*/votes", "ttl": 60, "note": HOSTILE["img"]}
    )
    assert rule.status_code == 201, rule.text
    param = await page.api("POST", "cache/ignored-params", json={"name": HOSTILE["script"], "note": HOSTILE["attr"]})
    assert param.status_code == 201, param.text
    client = pages_app.harness.new_client()
    await client.get(
        "/games.roblox.com/v1/games?universeIds=" + HOSTILE["js_url"], headers={"X-Forwarded-For": "192.0.2.77"}
    )
    await pages_app.flush()
    response = await page.get(PAGE, params={"q": HOSTILE["img"]})
    inert(response.text, "cache page")
    assert find_style_issues(response.text, "cache page") == []
    for card in registry.cards_for("cache"):
        fragment = await page.fragment("cache", card.id)
        inert(fragment.text, f"cache {card.id}")
        assert find_style_issues(fragment.text, f"cache {card.id}") == [], card.id
    rules = await page.fragment("cache", "rules")
    assert "&lt;img src=x onerror=alert(1)&gt;" in rules.text
    ignored = await page.fragment("cache", "ignored-params")
    assert "&lt;script&gt;alert(&#39;roxy&#39;)&lt;/script&gt;" in ignored.text
    drawer = await page.get(f"{PAGE}/drawer/endpoint", params={"template": "games.roblox.com/" + HOSTILE["img"]})
    assert drawer.status_code == 200
    inert(drawer.text, "endpoint drawer")
    assert "&lt;img src=x onerror=alert(1)&gt;" in drawer.text
    rule_drawer = await page.get(f"{PAGE}/drawer/rule", params={"id": rule.json()["rule"]["id"]})
    inert(rule_drawer.text, "rule drawer")
    for entry_id in (await _entry_ids(page, page_size=250))[:6]:
        body = await page.get(f"{PAGE}/drawer/entry", params={"id": entry_id})
        assert body.status_code == 200
        inert(body.text, "entry drawer")
        assert find_style_issues(body.text, "entry drawer") == []


async def test_the_drawers_show_an_entry_an_endpoint_and_a_rule(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    entry_id = (await _entry_ids(page, q="universeIds=1"))[0]
    doc = parse_html((await page.get(f"{PAGE}/drawer/entry", params={"id": entry_id})).text)
    assert doc.select_one(f'[data-cache-entry="{entry_id}"]') is not None
    refresh = doc.select_one(f'form[data-api-url="/admin/api/v1/cache/entries/{entry_id}/refresh"]')
    assert refresh is not None
    purge = doc.select_one('[data-action="cache-entry-purge"]')
    assert '"scope": "id"' in purge.get("data-fill")
    assert entry_id in purge.get("data-fill")
    assert '"data"' in doc.select_one("pre.cache-body").text()
    endpoint = parse_html(
        (await page.get(f"{PAGE}/drawer/endpoint", params={"template": "games.roblox.com/v1/games"})).text
    )
    form = endpoint.select_one('form[data-api-url="/admin/api/v1/cache/rules"]')
    assert form.select_one('input[name="pattern"]').get("value") == "games.roblox.com/v1/games"
    created = await page.api("POST", "cache/rules", json={"pattern": "games.roblox.com/v1/games", "ttl": 600})
    assert created.status_code == 201, created.text
    rule_id = created.json()["rule"]["id"]
    rule = parse_html((await page.get(f"{PAGE}/drawer/rule", params={"id": rule_id})).text)
    edit = rule.select_one('form[data-api-method="PATCH"]')
    assert edit.get("data-api-url") == f"/admin/api/v1/cache/rules/{rule_id}"
    assert edit.select_one('input[name="ttl"]').get("value") == "600"
    remove = rule.select_one('[data-action="cache-rule-delete"]')
    assert f"/admin/api/v1/cache/rules/{rule_id}" in remove.get("data-fill")
    for path, text in (
        (f"{PAGE}/drawer/entry?id=nothex", "24 lowercase hex"),
        (f"{PAGE}/drawer/entry?id={'a' * 24}", "expired or been evicted"),
        (f"{PAGE}/drawer/rule?id=999999", "No cache rule has that id"),
        (f"{PAGE}/drawer/rule?id=abc", "not valid"),
        (f"{PAGE}/drawer/endpoint", "Choose an endpoint"),
    ):
        response = await page.get(path)
        assert response.status_code == 200, path
        assert text in response.text, path
        assert "data-card-error" in response.text


async def test_the_forms_post_to_the_cache_api_and_need_csrf(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    rules = parse_html((await page.fragment("cache", "rules")).text)
    add = rules.select_one('form[data-api-url="/admin/api/v1/cache/rules"]')
    assert add.get("data-api-method") == "POST"
    assert {n.get("name") for n in add.select("[name]")} >= {"pattern", "type", "ttl", "methods", "purge", "reason"}
    ignored = parse_html((await page.fragment("cache", "ignored-params")).text)
    assert ignored.select_one('form[data-api-url="/admin/api/v1/cache/ignored-params"]') is not None
    refused = await page.api("POST", "cache/rules", json={"pattern": "games.roblox.com/v1/x", "ttl": 5}, csrf=False)
    assert refused.status_code == 403
    added = await page.api("POST", "cache/ignored-params", json={"name": "zz test", "note": "test " + HOSTILE["img"]})
    assert added.status_code == 201, added.text
    after = await page.get(f"{PAGE}/fragment/ignored-params")
    doc = parse_html(after.text)
    fills = [node.get("data-fill") for node in doc.select('[data-action="cache-unignore"]')]
    assert any("/admin/api/v1/cache/ignored-params/zz%20test" in fill for fill in fills)
    assert "&lt;img src=x onerror=alert(1)&gt;" in after.text
    removed = await page.api("DELETE", "cache/ignored-params/zz%20test", json={"reason": "test"})
    assert removed.status_code == 200, removed.text


async def test_clear_stats_is_a_previewed_family_reset(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    doc = parse_html((await page.fragment("cache", "stats")).text)
    dialog = doc.select_one("dialog#dlg-cache-reset-stats")
    form = dialog.select_one("form[data-api-form]")
    assert form.get("data-api-url") == "/admin/api/v1/data/resets"
    assert form.get("data-expected") == "reset cache_stats"
    digest = form.select_one('input[name="preview"]').get("value")
    preview = await page.api("POST", "data/resets/preview", json={"scope": "family", "families": ["cache_stats"]})
    assert preview.status_code == 200, preview.text
    assert preview.json()["preview"] == digest
    run = await page.api(
        "POST",
        "data/resets",
        json={
            "scope": "family",
            "families": ["cache_stats"],
            "preview": digest,
            "reason": "test",
            "confirm": "reset cache_stats",
        },
    )
    assert run.status_code in (200, 202), run.text


@pytest.mark.parametrize(
    "params",
    [
        {"page": "abc"},
        {"page": "0"},
        {"page_size": "7"},
        {"sort": "bogus"},
        {"order": "sideways"},
        {"q": "x" * 500},
        {"range": "forever"},
        {"range": "custom", "from": "yesterday"},
        {"page": "99999999"},
        {"compare": "previous"},
    ],
    ids=lambda p: "-".join(p),
)
async def test_no_filter_or_range_ever_fails_the_page(page: Any, pages_app: Any, params: dict[str, str]) -> None:
    await pages_app.seed_traffic()
    for path in (PAGE, *(f"{PAGE}/fragment/{card.id}" for card in registry.cards_for("cache"))):
        response = await page.get(path, params=params)
        assert response.status_code == 200, (path, params, response.text[:300])
        assert "data-card-error" not in response.text, (path, params)


async def test_an_empty_database_explains_itself(page: Any) -> None:
    for card_id, text in (
        ("browser", "The cache is empty"),
        ("endpoints", "No proxied requests in this range"),
        ("rules", "TTL tuner suggestions"),
        ("spread", "Nothing stored yet"),
        ("ignored-params", "Commonly used as cache busters"),
    ):
        response = await page.fragment("cache", card_id)
        assert response.status_code == 200, card_id
        assert text in response.text, card_id
        assert "data-card-error" not in response.text, card_id


def test_the_explainer_follows_the_settings() -> None:
    class Settings:
        def __init__(self, **values: Any) -> None:
            self.values = {
                "cache_enabled": 1,
                "cache_ttl_seconds": 60,
                "cache_stale_seconds": 600,
                "cache_swr_seconds": 0,
                "cache_coalesce": 1,
                **values,
            }

        def bool(self, key: str) -> bool:
            return bool(self.values[key])

        def int(self, key: str) -> int:
            return int(self.values[key])

    steps = explainer(Settings())["steps"]
    assert [step["at"] for step in steps] == ["0s", "up to 1 minute", "1 minute", "just after 1 minute", "11 minutes"]
    assert explainer(Settings(cache_enabled=0))["steps"][0]["at"] == "always"
    assert "is 0" in explainer(Settings(cache_ttl_seconds=0))["steps"][0]["parts"][0]["text"]
    no_stale = explainer(Settings(cache_stale_seconds=0))["steps"]
    assert any("Stale serving window" in str(part) for part in no_stale[-1]["parts"])
    with_swr = explainer(Settings(cache_swr_seconds=60))["steps"]
    assert any(any(p.get("badge") == "REVALIDATING" for p in step["parts"]) for step in with_swr)
    assert [span_words(1), span_words(90), span_words(3700)] == ["1 second", "1 minute 30s", "1 hour 1m"]
