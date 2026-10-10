"""The Endpoints page (`/admin/endpoints`, plan 14.1 Endpoints row, row 11; parity rows 74 and 89): integration
tests against the real app.

What this is
    With traffic sent through the real proxy: the page, its fragments, the drill-down page and the reset drawer
    answer 200 for an admin and redirect otherwise; the main table carries v1's Top Endpoints columns, pages, sorts,
    searches and filters on the server with the API's names and equals `GET /admin/api/v1/endpoints` row for row;
    the drill-down (drawer and page) equals `GET /endpoints/detail`; the recent card equals `GET /endpoints/recent`;
    templates, paths, places and User-Agents stay inert text; bad values never fail the page; an empty database
    explains itself; and the one-endpoint reset previews and runs only through the Data API.

Why it exists
    Plan P6 (one source of truth), the P11 page rules (no 500, caller text never markup), plan 6.8 (inline resets).

What to read next
    `roxy/admin/pages/endpoints.py`, `tests/e2e/test_page_endpoints.py`.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest

from roxy.admin.pages import registry
from roxy.admin.pages.testing import parse_html
from roxy.core.style_guard import find_style_issues

PAGE = "/admin/endpoints"
GAMES = "games.roblox.com/v1/games"


async def _templates(page: Any) -> list[str]:
    answer = (await page.api("GET", "endpoints", params={"page_size": 250})).json()
    return [str(item["key"]) for item in answer["items"]]


async def test_the_page_its_fragments_and_drawers_need_a_signed_in_admin(anon: Any) -> None:
    for path in (
        PAGE,
        f"{PAGE}/fragment/table",
        f"{PAGE}/fragment/recent",
        f"{PAGE}/fragment/detail?template={GAMES}",
        f"{PAGE}/template?template={GAMES}",
        f"{PAGE}/reset?template={GAMES}",
    ):
        response = await anon.get(path)
        assert response.status_code == 302, path
        assert response.headers["location"] == "/admin"


async def test_every_card_and_the_v1_columns_are_on_the_page(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    doc = await page.doc(PAGE)
    for card in registry.cards_for("endpoints"):
        if card.fragment_only:
            assert doc.select_one(f"#{card.id}") is None
            response = await page.fragment("endpoints", card.id, template=GAMES)
            assert response.status_code == 200
            assert "data-endpoint-detail" in response.text
        else:
            assert doc.select_one(f"section#{card.id}[data-card]") is not None, card.id
    table = doc.select_one('section#table [data-table="endpoints"]')  # v1 row 11: Top Endpoints
    assert table is not None
    headers = {th.get("data-col") for th in table.select("thead th")}
    assert {"key", "requests", "methods", "last_request_ms", "last_status", "last_caller", "last_place"} <= headers
    assert {node.get("name") for node in table.select("form[data-dt-state] [name]")} >= {
        "q",
        "host",
        "method",
        "page",
        "page_size",
        "sort",
        "order",
    }
    export = table.select_one('a[data-export][href*="format=csv"]')
    assert export is not None and export.get("href").startswith("/admin/api/v1/endpoints?")
    row = table.select_one("tbody tr[data-drawer-src]")
    assert row is not None and row.get("data-drawer-src").startswith(f"{PAGE}/fragment/detail?")
    assert doc.select_one('section#recent.page-card--lazy[hx-get^="/admin/endpoints/fragment/recent"]') is not None
    assert doc.select_one('link[href*="css/pages/endpoints"]') is not None


async def test_the_table_equals_the_api_for_the_same_filters(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    for params in (
        {},
        {"q": "games"},
        {"host": "games.roblox.com"},
        {"method": "GET"},
        {"sort": "roblox_429", "order": "desc"},
        {"sort": "key", "order": "asc", "page_size": 10},
    ):
        api = (await page.api("GET", "endpoints", params=params)).json()
        doc = await page.doc(f"{PAGE}/fragment/table", params={**params, "part": "table"})
        assert doc.select_one("section[data-card]") is None  # the table alone
        keys = [r.select_one('td[data-col="key"]').text() for r in doc.select("tbody tr[data-row-id]")]
        assert keys == [str(item["key"]) for item in api["items"]], params
        count = doc.select_one(".dt__count").text()
        assert (f"of {api['total']:,}" in count) if api["total"] else count == "No rows", params
    games = next(item for item in (await page.api("GET", "endpoints")).json()["items"] if item["key"] == GAMES)
    doc = await page.doc(f"{PAGE}/fragment/table", params={"q": GAMES})
    cells = doc.select_one("tbody tr[data-row-id]")
    assert cells.select_one('td[data-col="requests"]').text() == f"{games['requests']:,}"
    expected = " ".join(f"{name}:{count}" for name, count in games["methods"].items())
    assert cells.select_one('td[data-col="methods"]').text() == expected  # v1's `GET:3 POST:1`
    assert cells.select_one('td[data-col="last_status"]').text() == str(games["last_status"])


async def test_a_deep_link_by_template_lands_on_it(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    doc = await page.doc(PAGE, params={"q": GAMES})
    rows = doc.select("#table tbody tr[data-row-id]")
    assert rows and all(GAMES in r.text() for r in rows)
    assert doc.select_one('#table input[name="q"]').get("value") == GAMES


async def test_the_drill_down_equals_the_api_in_the_drawer_and_on_its_page(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    api = (await page.api("GET", "endpoints/detail", params={"template": GAMES})).json()
    drawer = parse_html((await page.fragment("endpoints", "detail", template=GAMES)).text)
    tile = drawer.select_one('[data-kpi="requests"] .kpi__number')
    assert tile.text() == f"{api['totals']['requests']['value']:,}"
    assert len(drawer.select("[data-endpoint-detail] figure[data-chart]")) == 2
    shown_paths = [r.select_one("td").text() for r in drawer.select(".ep-detail__paths tbody tr")]
    assert shown_paths == [item["path"] for item in api["concrete_paths"]]
    assert len(drawer.select(".ep-requests__table tbody tr")) == len(api["recent_requests"])
    assert drawer.select_one('a[data-action="endpoint-page"]') is not None
    href = drawer.select_one('a[data-action="endpoint-page"]').get("href")
    assert parse_qs(urlparse(href).query)["template"] == [GAMES]
    full = await page.doc(f"{PAGE}/template", params={"template": GAMES})
    assert full.select_one("h1").text() == "Endpoint detail"
    assert full.select_one("[data-endpoint-detail]") is not None
    assert full.select_one('[data-action="endpoint-page"]') is None  # already the page
    assert full.select_one('[data-action="endpoint-reset"]') is not None  # plan 6.8: the header menu's reset
    assert full.select_one('[data-kpi="requests"] .kpi__number').text() == tile.text()


async def test_the_recent_card_equals_the_api(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    api = (await page.api("GET", "endpoints/recent", params={"template": GAMES, "limit": 25})).json()
    doc = parse_html((await page.fragment("endpoints", "recent", template=GAMES)).text)
    rows = doc.select("#recent .ep-requests__table tbody tr")
    assert len(rows) == len(api["items"]) > 0
    drawers = [r.select_one("[data-drawer-src]") for r in rows]
    assert all(d is not None and d.get("data-drawer-src").startswith("/admin/live/request?id=") for d in drawers)
    busiest = parse_html((await page.fragment("endpoints", "recent")).text)
    first = (await page.api("GET", "endpoints")).json()["items"][0]["key"]
    assert busiest.select_one(f'#recent select[name="template"] option[selected][value="{first}"]') is not None


@pytest.mark.parametrize(
    "params",
    [
        {"host": "bad/host"},
        {"method": "N0T A METHOD"},
        {"sort": "bogus"},
        {"page": "abc", "page_size": "7"},
        {"q": "x" * 500},
        {"range": "forever"},
        {"range": "custom", "from": "yesterday"},
        {"compare": "week"},
        {"template": "\u0000bad"},
        {"template": "x" * 2000},
    ],
    ids=lambda p: "-".join(p),
)
async def test_no_filter_or_range_ever_fails_the_page(page: Any, pages_app: Any, params: dict[str, str]) -> None:
    await pages_app.seed_traffic()
    for path in (PAGE, f"{PAGE}/fragment/table", f"{PAGE}/fragment/recent"):
        response = await page.get(path, params=params)
        assert response.status_code == 200, (path, params, response.text[:300])
        assert "data-card-error" not in response.text, (path, params)


async def test_a_bad_or_missing_template_says_so_in_the_drawer(page: Any, pages_app: Any) -> None:
    for params, text in (({}, "Choose an endpoint"), ({"template": "a\u0007b"}, "printable"), ({"template": ""}, "Choose")):
        for path in (f"{PAGE}/fragment/detail", f"{PAGE}/template", f"{PAGE}/reset"):
            response = await page.get(path, params=params)
            assert response.status_code == 200, (path, params)
            assert "data-card-error" in response.text, (path, params)
    response = await page.fragment("endpoints", "detail", template="a\u0007b")
    assert "printable" in response.text


async def test_hostile_text_is_inert_everywhere(page: Any, pages_app: Any, inert: Any) -> None:
    await pages_app.seed_all()
    response = await page.get(PAGE)
    inert(response.text, "endpoints page")
    assert find_style_issues(response.text, "endpoints page") == []
    for name in await _templates(page):
        for path in (f"{PAGE}/fragment/detail", f"{PAGE}/template", f"{PAGE}/fragment/recent", f"{PAGE}/reset"):
            answer = await page.get(path, params={"template": name})
            inert(answer.text, f"{path} {name!r}")
            assert find_style_issues(answer.text, f"{path} {name!r}") == []
    recent = parse_html((await page.fragment("endpoints", "recent", template=GAMES)).text)
    assert "<script>alert('roxy')</script>" in recent.text()  # the hostile place and User-Agent, as text


async def test_an_empty_database_explains_itself(page: Any) -> None:
    doc = await page.doc(PAGE)
    assert "No endpoints in this range" in doc.select_one("#table").text()
    recent = parse_html((await page.fragment("endpoints", "recent")).text)
    assert "No endpoints in this range" in recent.text()
    detail = parse_html((await page.fragment("endpoints", "detail", template=GAMES)).text)
    assert "None in this range" in detail.text()
    assert "No recent requests" in detail.text()


async def test_the_endpoint_reset_previews_then_runs_only_through_the_data_api(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    doc = parse_html((await page.get(f"{PAGE}/reset", params={"template": GAMES})).text)
    form = doc.select_one('form[data-api-form][data-api-url="/admin/api/v1/data/resets"]')
    fields = {node.get("name"): node.get("value") for node in form.select("input[type=hidden]")}
    assert fields["scope"] == "endpoint"
    assert fields["template"] == GAMES
    assert doc.select_one('input[name="confirm"]') is None  # one endpoint: no typed phrase
    body = {"scope": "endpoint", "template": GAMES, "preview": fields["preview"], "reason": "test"}
    refused = await page.api("POST", "data/resets", json=body, csrf=False)
    assert refused.status_code == 403
    done = await page.api("POST", "data/resets", json=body)
    assert done.status_code in (200, 202), done.text
    for _ in range(50):
        names = await _templates(page)
        if GAMES not in names:
            break
        await pages_app.flush()
    assert GAMES not in names
    assert names  # the other endpoints stay
