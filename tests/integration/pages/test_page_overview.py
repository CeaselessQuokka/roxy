"""The Overview page (`/admin/overview` and `/admin/dashboard`, plan 14.1, 11.6, 13.1): integration tests.

What this is
    Tests against the real app with data that went through the real proxy (`pages_app.seed_all()`: served, cached,
    refused, probed, a Roblox 429 and 503, hostile paths, User-Agents and places, a recommendation and a health run):
    the page and every card answer 200 for an admin and redirect otherwise, every registry card and every v1 tile is
    there, the numbers equal the Overview API's for the same range, a reset that touched a tile's data shows its
    notice instead of a delta, the events table pages and exports through the API, the top recommendations link to
    their drawer, hostile text stays inert, a bad range or table value never fails the page, and an empty database
    says why each card is empty.

Why it exists
    The P11 page rules (truth, security, help, parity) for the Overview, proven without a browser;
    `tests/e2e/test_page_overview.py` proves the same page in Chromium.

What to read next
    `roxy/admin/pages/overview.py`, `roxy/admin/api/overview.py`, `tests/integration/pages/test_page_audit.py`.
"""

from __future__ import annotations

from typing import Any

import pytest

from roxy.admin.pages import overview, registry
from roxy.admin.pages.testing import HOSTILE, parse_html
from roxy.core.style_guard import find_style_issues
from roxy.metrics.annotate import insert_annotation

PAGE = "/admin/overview"
V1_TILES = (
    "requests",
    "status_2xx",
    "status_4xx",
    "served_cache",
    "requests_last_hour",
    "failures_last_hour",
    "roblox_429",
    "roxy_429",
    "roblox_5xx",
    "service_uptime_s",
)
VISITOR_TILES = ("human_visitors", "crawler_visitors", "home_visits", "admin_visits", "robots_crawls")
CARDS = [card.id for card in registry.cards_for("overview")]


async def test_the_page_and_its_fragments_need_a_signed_in_admin(anon: Any) -> None:
    for path in (PAGE, "/admin/dashboard", *(f"{PAGE}/fragment/{card}" for card in CARDS)):
        response = await anon.get(path)
        assert response.status_code == 302, path
        assert response.headers["location"] == "/admin"


@pytest.mark.parametrize("card", CARDS)
async def test_every_card_fragment_answers_for_an_admin(page: Any, pages_app: Any, card: str) -> None:
    await pages_app.seed_all()
    response = await page.fragment("overview", card)
    assert response.status_code == 200, response.text[:300]
    doc = parse_html(response.text)
    assert doc.select_one(f"section#{card}[data-card]") is not None
    assert not doc.select("[data-card-error]"), response.text[:500]
    assert find_style_issues(response.text, card) == []


async def test_every_registry_card_and_the_v1_tiles_are_on_the_page(page: Any, pages_app: Any) -> None:
    await pages_app.seed_all()
    for path in (PAGE, "/admin/dashboard"):
        doc = await page.doc(path)
        assert doc.select_one("body").get("data-page") == "overview"
        for card in CARDS:
            assert doc.select_one(f"section#{card}[data-card]") is not None, (path, card)
        assert not doc.select("[data-card-error]")
    for key in V1_TILES:
        assert doc.select_one(f'#kpis [data-kpi="{key}"]') is not None, key
    for key in VISITOR_TILES:
        assert doc.select_one(f'#visitors [data-kpi="{key}"]') is not None, key
    assert doc.select_one('#events [data-table="overview_events"]') is not None
    chart = doc.select_one("#traffic [data-chart]")
    assert chart is not None
    assert chart.get("data-series-src", "").startswith("/admin/api/v1/overview/chart")
    button = doc.select_one('.page-header__actions form[data-health-start] [data-action="overview-health-run"]')
    assert button is not None
    assert doc.select_one("form[data-health-start]").get("data-run-url") == "/admin/api/v1/health/runs"
    assert doc.select_one('link[href*="css/pages/overview"]') is not None
    assert doc.select_one('script[type="module"][src*="js/pages/overview"]') is not None
    assert len(doc.select("h1")) == 1


async def test_hostile_text_is_inert_on_the_page_and_in_every_fragment(page: Any, pages_app: Any, inert: Any) -> None:
    await pages_app.seed_all()
    response = await page.get(PAGE, params={"range": "1h"})
    inert(response.text, "overview page")
    assert find_style_issues(response.text, "overview") == []
    for card in CARDS:
        fragment = await page.fragment("overview", card, range="1h")
        inert(fragment.text, f"overview {card}")
    places = await page.fragment("overview", "top-places", range="1h")
    assert "&lt;script&gt;alert(&#39;roxy&#39;)&lt;/script&gt;" in places.text  # the hostile place, as text
    doc = parse_html(places.text)
    assert any(HOSTILE["script"] in node.text() for node in doc.select(".caller-text"))
    endpoints = parse_html((await page.fragment("overview", "top-endpoints", range="1h")).text)
    for link in endpoints.select("a[href]"):
        assert link.get("href").startswith("/admin/"), link.get("href")
    recs = parse_html((await page.fragment("overview", "recommendations")).text)
    assert any(HOSTILE["script"] in node.text() for node in recs.select(".ov-rec__title .caller-text"))


async def test_tile_numbers_equal_the_api_for_the_same_range(page: Any, pages_app: Any) -> None:
    await pages_app.seed_all()
    for params in ({"range": "1h"}, {"range": "24h", "compare": "week"}):
        api = (await page.api("GET", "overview/kpis", params=params)).json()
        doc = await page.doc(f"{PAGE}/fragment/kpis", params=params)
        for tile in api["tiles"]:
            node = doc.select_one(f'[data-kpi="{tile["key"]}"] .kpi__number')
            assert node is not None, tile["key"]
            if tile["key"] in ("requests", "requests_last_hour", "failures_last_hour", "roblox_429", "status_2xx"):
                assert node.text() == f"{tile['value']:,}", (params, tile["key"], node.text(), tile["value"])
        with_delta = [t for t in api["tiles"] if t["delta_pct"] is not None and not t.get("partial")]
        for tile in with_delta:
            words = doc.select_one(f'[data-kpi="{tile["key"]}"] .delta').text()
            assert overview.compare_label(params.get("compare", "previous")) in words, (tile["key"], words)
    assert overview.compare_label("week") == "vs the same period last week"
    assert overview.compare_label(None) == "vs the previous period"
    requests = (await page.api("GET", "overview/kpis", params={"range": "1h"})).json()
    total = next(t["value"] for t in requests["tiles"] if t["key"] == "requests")
    assert total == len(pages_app.seeded["statuses"])  # every seeded request is counted once
    visitors = (await page.api("GET", "overview/visitors", params={"range": "1h"})).json()
    vdoc = await page.doc(f"{PAGE}/fragment/visitors", params={"range": "1h"})
    for tile in visitors["tiles"]:
        assert vdoc.select_one(f'[data-kpi="{tile["key"]}"] .kpi__number').text() == f"{tile['value']:,}"


async def test_breakdown_cards_list_the_api_rows(page: Any, pages_app: Any) -> None:
    await pages_app.seed_all()
    api = (await page.api("GET", "overview", params={"range": "1h"})).json()
    outcomes = await page.doc(f"{PAGE}/fragment/outcomes", params={"range": "1h"})
    shown = {row.get("data-outcome") for row in outcomes.select("tr[data-outcome]")}
    assert shown == {item["outcome"] for item in api["outcomes"]["items"]}
    assert outcomes.select("meter")  # the share as a native, accessible bar
    endpoints = await page.doc(f"{PAGE}/fragment/top-endpoints", params={"range": "1h"})
    assert len(endpoints.select(".ov-top tbody tr")) == len(api["top_endpoints"])
    places = await page.doc(f"{PAGE}/fragment/top-places", params={"range": "1h"})
    assert len(places.select(".ov-top tbody tr")) == len(api["top_places"])
    first = api["top_endpoints"][0]["key"]
    link = endpoints.select_one(".ov-top tbody tr a")
    assert link.get("href").startswith("/admin/endpoints?q=")
    assert first.split("/")[0] in link.text()


async def test_the_status_strip_reports_state_never_the_credential(page: Any, pages_app: Any) -> None:
    await pages_app.seed_all()
    doc = await page.doc(f"{PAGE}/fragment/status")
    keys = [node.get("data-status") for node in doc.select("[data-status]")]
    assert keys == ["proxy", "credential", "rotator", "leader", "workers", "version"]
    for item in doc.select("[data-status]"):
        assert item.select_one(".badge") is not None  # the state in words with an icon, never color alone
    credential = (pages_app.ctx.egress.credential.status()).masked or ""
    if credential:
        assert credential not in doc.text()
    proxy = doc.select_one('[data-status="proxy"]').text()
    assert "Running" in proxy
    await page.api("POST", "protection/pause", json={"paused": True, "message": "Back soon"})
    try:
        paused = await page.doc(f"{PAGE}/fragment/status")
        assert "Paused" in paused.select_one('[data-status="proxy"]').text()
    finally:
        await page.api("POST", "protection/pause", json={"paused": False})


async def test_a_reset_shows_the_tiles_notice_instead_of_a_delta(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    now = int(pages_app.clock.now())
    await pages_app.ctx.dbs.metrics.write(
        lambda conn: insert_annotation(conn, now - 5400, "reset", "test reset", None, until=now - 3700)
    )
    api = (await page.api("GET", "overview/kpis", params={"range": "1h", "compare": "previous"})).json()
    partial = [tile for tile in api["tiles"] if tile.get("partial")]
    assert partial, api["tiles"]
    doc = await page.doc(f"{PAGE}/fragment/kpis", params={"range": "1h", "compare": "previous"})
    for tile in partial:
        node = doc.select_one(f'[data-kpi="{tile["key"]}"]')
        assert node.select_one(".kpi__notice") is not None, tile["key"]
        assert node.select_one(".delta") is None, tile["key"]
    assert doc.select(".card__notice")  # the card lists the reset too


async def test_the_events_table_pages_sorts_and_exports_through_the_api(page: Any, pages_app: Any) -> None:
    await pages_app.seed_all()
    api = (await page.api("GET", "overview/events", params={"range": "1h"})).json()
    doc = await page.doc(f"{PAGE}/fragment/events", params={"range": "1h"})
    table = doc.select_one('[data-table="overview_events"]')
    assert table.get("data-dt-src", "").startswith("/admin/overview/fragment/events")
    assert {n.get("name") for n in table.select("form[data-dt-state] [name]")} >= {
        "q",
        "page",
        "page_size",
        "sort",
        "order",
        "range",
    }
    rows = [row.get("data-row-id") for row in doc.select("tbody tr[data-row-id]")]
    assert rows == [f"event-{item['id']}" for item in api["items"]]
    export = table.select_one('a[data-export][href*="format=csv"]')
    assert export.get("href").startswith("/admin/api/v1/overview/events?")
    download = await page.api("GET", export.get("href"))
    assert download.status_code == 200
    assert download.headers["content-type"].startswith("text/csv")


async def test_top_recommendations_open_their_drawer_on_the_recommendations_page(page: Any, pages_app: Any) -> None:
    await pages_app.seed_all()
    rec_id = pages_app.seeded["recommendation"]
    doc = await page.doc(f"{PAGE}/fragment/recommendations")
    item = doc.select_one(f'[data-rec="{rec_id}"]')
    assert item is not None
    assert item.select_one("a").get("href") == f"/admin/recommendations?rec={rec_id}"
    assert "Critical" in item.text()


@pytest.mark.parametrize(
    "params",
    [
        {"range": "forever"},
        {"range": "custom", "from": "yesterday"},
        {"range": "all"},
        {"range": "7d", "compare": "year"},
        {"compare": "sideways"},
        {"granularity": "minute", "range": "90d"},
        {"page": "abc"},
        {"page_size": "7"},
        {"sort": "bogus"},
        {"order": "sideways"},
        {"q": "x" * 500},
        {"page": "99999999"},
    ],
    ids=lambda p: "-".join(p),
)
async def test_no_range_or_table_value_ever_fails_the_page(page: Any, pages_app: Any, params: dict[str, str]) -> None:
    await pages_app.seed_traffic()
    for path in (PAGE, f"{PAGE}/fragment/events", f"{PAGE}/fragment/kpis"):
        response = await page.get(path, params=params)
        assert response.status_code == 200, (path, params, response.text[:300])
        assert "data-card-error" not in response.text, (path, params, response.text[:2000])


async def test_an_empty_database_explains_every_card(page: Any) -> None:
    doc = await page.doc(PAGE)
    assert not doc.select("[data-card-error]")
    assert "Nothing needs your attention" in doc.select_one("#recommendations").text()
    assert "No endpoint was called in this range" in doc.select_one("#top-endpoints").text()
    assert "No place sent requests in this range" in doc.select_one("#top-places").text()
    assert "No requests in this range" in doc.select_one("#outcomes").text()
    assert "No notable events in this range" in doc.select_one("#events").text()
    for key in V1_TILES:
        assert doc.select_one(f'[data-kpi="{key}"]') is not None, key


async def test_the_health_button_posts_to_the_health_api_with_csrf(page: Any, pages_app: Any) -> None:
    await pages_app.settings(health_auto_interval_h=0)
    refused = await page.api("POST", "health/runs", json={"checks": ["H-DISK"], "include_credential": False}, csrf=False)
    assert refused.status_code == 403
    started = await page.api("POST", "health/runs", json={"checks": ["H-DISK"], "include_credential": False})
    assert started.status_code == 202, started.text
    from roxy.health.runner import runner_for

    await runner_for(pages_app.ctx).wait(started.json()["run_id"])
