"""The Endpoints page in a real browser (P11): clean, accessible, and its table, drawer and drill-down work.

What this is
    Browser tests against the real app (`dashboard`: a free port, a signed-in admin, seeded traffic with hostile
    paths, places and User-Agents). For each theme and size (1440x900 and 390x844, dark and light) the page and the
    drill-down page of one template load with no console error, page error or CSP violation, no axe finding, no
    sideways scroll on a phone, and a screenshot for the visual review. Then the interactions: search and the method
    filter swap the main table in place and keep its state in the address, a row opens the template's drill-down
    in the drawer (charts drawn, hostile text inert), the recent card switches to another endpoint and a request row
    opens the Live page's request drawer, and the one-endpoint reset opens its preview without deleting anything.

Why it exists
    The integration tests prove what the server sends; only a browser proves the drawer, the swaps and the charts
    work under the strict CSP.

What to read next
    tests/e2e/conftest.py (`open_admin`, `AdminPage`), tests/integration/pages/test_page_endpoints.py.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any
from urllib.parse import urlencode

import pytest

from pages_harness import THEMES, VIEWPORTS

PAGE = "/admin/endpoints"
GAMES = "games.roblox.com/v1/games"
USERS = "users.roblox.com/v1/users/{userId}"
TEMPLATE_PAGE = f"{PAGE}/template?" + urlencode({"template": GAMES})
NO_HOSTILE_MARKUP = """() => !document.querySelector(
    'img[src="x"], [onerror], [onclick], [onfocus], a[href^="javascript:"]'
  ) && typeof window.__pwned === "undefined\""""
ROWS = "#table [data-table='endpoints'] tbody tr[data-row-id]"
CHARTS_READY = "Array.from(document.querySelectorAll('{scope} figure[data-chart]')).every((f) => f.dataset.chartReady)"
EVERY_INCLUDES = "Array.from(document.querySelectorAll({selector})).every((n) => n.textContent.includes({text}))"


def _row_id(template: str) -> str:
    return "endpoint-" + hashlib.sha256(template.encode("utf-8")).hexdigest()[:16]


def _loaded(admin: Any) -> None:
    admin.wait("!document.querySelector('.page-card--lazy')", timeout=20)


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("size", list(VIEWPORTS))
def test_the_page_is_clean_accessible_and_fits(open_admin: Any, theme: str, size: str) -> None:
    width, height = VIEWPORTS[size]
    admin = open_admin(PAGE, theme=theme, width=width, height=height)
    _loaded(admin)
    assert admin.page.locator(ROWS).count() > 0
    assert admin.page.locator("#recent .ep-requests__table tbody tr").count() > 0
    assert admin.page.evaluate(NO_HOSTILE_MARKUP)
    assert not admin.overflows(), "the page scrolls sideways"
    assert admin.axe() == []
    admin.shot("endpoints")
    admin.assert_clean()


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("size", list(VIEWPORTS))
def test_the_drill_down_page_is_clean_accessible_and_fits(open_admin: Any, theme: str, size: str) -> None:
    width, height = VIEWPORTS[size]
    admin = open_admin(TEMPLATE_PAGE, theme=theme, width=width, height=height)
    assert admin.page.locator("h1").inner_text().strip() == "Endpoint detail"
    admin.wait(CHARTS_READY.format(scope="[data-endpoint-detail]"))
    assert admin.page.locator('[data-endpoint-detail] [data-kpi="requests"]').count() == 1
    assert admin.page.evaluate(NO_HOSTILE_MARKUP)
    assert not admin.overflows(), "the page scrolls sideways"
    assert admin.axe() == []
    admin.shot("endpoint-page")
    admin.assert_clean()


def test_search_and_the_method_filter_swap_the_table_in_place(open_admin: Any) -> None:
    admin = open_admin(PAGE)
    page = admin.page
    page.evaluate("window.__sameDocument = true")
    everything = page.locator(ROWS).count()
    page.fill('#table input[name="q"]', "users.roblox.com")
    admin.wait("new URL(location.href).searchParams.get('q') === 'users.roblox.com'")
    admin.wait(EVERY_INCLUDES.format(selector=json.dumps(ROWS), text=json.dumps("users.roblox.com")))
    assert 0 < page.locator(ROWS).count() < everything
    page.fill('#table input[name="q"]', "")
    admin.wait(f"document.querySelectorAll({json.dumps(ROWS)}).length === {everything}")
    # A method nothing in the shared dashboard ever proxies: the seed sends GET only, but a health run of another
    # browser test (the Overview's Check Proxy Health) adds the presence probe's POST row, so POST depended on order.
    page.select_option('#table select[name="method"]', "DELETE")
    admin.wait("new URL(location.href).searchParams.get('method') === 'DELETE'")
    admin.wait("document.querySelector('#table .dt__count').textContent.includes('No rows')")
    assert "No endpoints in this range" in page.locator("#table").inner_text()
    page.select_option('#table select[name="method"]', "")
    admin.wait(f"document.querySelectorAll({json.dumps(ROWS)}).length === {everything}")
    assert page.evaluate("window.__sameDocument === true"), "the table reloaded the whole page"
    admin.assert_clean()


def test_a_row_opens_the_drill_down_in_the_drawer(open_admin: Any) -> None:
    admin = open_admin(PAGE, theme="light")
    page = admin.page
    page.locator(f'#table tr[data-row-id="{_row_id(GAMES)}"]').click()
    admin.wait("document.querySelector('#drawer[open] [data-endpoint-detail]') !== null")
    admin.wait(CHARTS_READY.format(scope="#drawer"))
    assert page.locator("#drawer-title").inner_text().strip() == f"Endpoint {GAMES}"
    drawer = page.locator("#drawer")
    assert GAMES in drawer.inner_text()
    assert drawer.locator('[data-kpi="requests"]').count() == 1
    assert drawer.locator('a[data-action="endpoint-page"]').get_attribute("href").startswith(f"{PAGE}/template?")
    assert page.evaluate(NO_HOSTILE_MARKUP)
    assert admin.axe() == []
    admin.shot("endpoints-drawer")
    page.keyboard.press("Escape")
    admin.wait("!document.querySelector('#drawer[open]')")
    admin.assert_clean()


def test_the_recent_card_switches_endpoint_and_opens_a_request(open_admin: Any) -> None:
    admin = open_admin(PAGE)
    page = admin.page
    _loaded(admin)
    page.locator("#endpoints-recent-template").focus()
    page.select_option("#endpoints-recent-template", USERS)
    admin.wait(
        "document.querySelectorAll('#recent .ep-requests__url').length > 0 && "
        + EVERY_INCLUDES.format(selector=json.dumps("#recent .ep-requests__url"), text=json.dumps("users.roblox.com"))
    )
    assert page.locator("section#recent").count() == 1  # swapped in place, never nested
    assert page.evaluate("document.activeElement && document.activeElement.id") == "endpoints-recent-template"
    page.locator("#recent .ep-requests__table tbody tr [data-drawer-src]").first.click()
    admin.wait("document.querySelector('#drawer[open] [data-live-request]') !== null")
    drawer = page.locator("#drawer")
    assert "users.roblox.com" in drawer.inner_text()
    assert "Why did this request wait?" in drawer.inner_text()
    assert admin.axe() == []
    page.keyboard.press("Escape")
    admin.wait("!document.querySelector('#drawer[open]')")
    admin.assert_clean()


def test_the_endpoint_reset_opens_its_preview_and_cancel_deletes_nothing(open_admin: Any, dashboard: Any) -> None:
    before = dashboard.api("GET", "endpoints", params={"q": GAMES}).json()["total"]
    admin = open_admin(TEMPLATE_PAGE, theme="dark", width=390, height=844)
    page = admin.page
    page.locator('[data-action="endpoint-reset"]').click()
    admin.wait("document.querySelector('#drawer[open] [data-reset=\"endpoint\"]') !== null")
    drawer = page.locator("#drawer")
    assert GAMES in drawer.inner_text()
    assert drawer.locator('input[name="confirm"]').count() == 0  # one endpoint: no typed phrase
    assert drawer.locator('button[data-action="reset-endpoint"]').is_enabled()
    assert not admin.overflows()
    assert admin.axe() == []
    admin.shot("endpoints-reset")
    drawer.locator("button[data-dialog-close]").last.click()
    admin.wait("!document.querySelector('#drawer[open]')")
    assert dashboard.api("GET", "endpoints", params={"q": GAMES}).json()["total"] == before
    admin.assert_clean()
