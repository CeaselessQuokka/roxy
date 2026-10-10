"""The Clients page in a real browser: clean, accessible, fits a phone, and its controls work.

What this is
    Browser tests against the real app (`dashboard`, tests/e2e/conftest.py: traffic through the real proxy from
    several addresses and places, a hostile `Roblox-Id`, User-Agents and paths). For each theme and size the page
    loads every lazy card with no console error, page error or CSP violation, axe-core finds nothing serious, the
    phone never scrolls sideways, and a screenshot is saved. Then the controls: the places search swaps the table in
    place and keeps the address, a row opens the client in the drawer (accessible, hostile text inert), a ban from
    the drawer's confirm dialog goes through the API and the drawer shows it, the lookup form draws the experience
    as text (hostile names stay text), and the client's own page renders.

Why it exists
    Only a browser proves the drawer, the nested confirm dialogs, the lookup drawing and the CSP work together.

What to read next
    tests/integration/pages/test_page_clients.py, roxy/admin/pages/clients.py, static/js/pages/clients.js.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from roxy.admin.pages.testing import HOSTILE, PLACES, THEMES, VIEWPORTS

PAGE = "/admin/clients"
NO_HOSTILE_MARKUP = """() => !document.querySelector('img[src="x"], [onerror], [onclick], a[href^="javascript:"]')
  && !document.querySelector('script:not([type="module"]):not([type="importmap"])')
  && typeof window.__pwned === "undefined\""""


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("size", list(VIEWPORTS))
def test_the_page_is_clean_accessible_and_fits(open_admin: Any, theme: str, size: str) -> None:
    width, height = VIEWPORTS[size]
    admin = open_admin(PAGE, theme=theme, width=width, height=height)
    page = admin.page
    assert page.locator(f'html[data-theme="{theme}"]').count() == 1
    assert page.locator(".page-card--lazy").count() == 0, "every lazy card loaded"
    assert page.locator("[data-card-error]").count() == 0
    assert page.locator('#places [data-table="client_places"] tbody tr[data-row-id]').count() > 0
    assert page.locator('#ips [data-table="client_ips"] tbody tr[data-row-id]').count() > 0
    assert page.locator("#client-score [data-setting-key]").count() == 10
    assert page.evaluate(NO_HOSTILE_MARKUP)
    assert not admin.overflows(), "the page scrolls sideways"
    assert admin.axe() == []
    admin.shot("clients")
    admin.assert_clean()


def test_the_places_search_swaps_in_place_and_keeps_the_address(open_admin: Any) -> None:
    admin = open_admin(PAGE)
    page = admin.page
    page.evaluate("window.__sameDocument = true")
    page.fill('#places input[name="q"]', PLACES[1])
    admin.wait(f"new URL(location.href).searchParams.get('q') === {json.dumps(PLACES[1])}")
    admin.wait("document.querySelectorAll('#places tbody tr[data-row-id]').length === 1")
    assert PLACES[1] in page.locator("#places tbody tr[data-row-id]").first.inner_text()
    assert page.locator("#places section[data-card]").count() == 0, "the table swap nested a card"
    src = page.evaluate("document.getElementById('places').dataset.cardSrc")
    assert f"q={PLACES[1]}" in src
    assert page.evaluate("window.__sameDocument === true")
    admin.assert_clean()


@pytest.mark.parametrize("theme,size", [("light", "desktop"), ("dark", "phone")])
def test_a_row_opens_the_client_in_the_drawer(open_admin: Any, theme: str, size: str) -> None:
    width, height = VIEWPORTS[size]
    admin = open_admin(PAGE, theme=theme, width=width, height=height)
    page = admin.page
    page.locator("#ips").scroll_into_view_if_needed()
    row = page.locator('#ips tbody tr[data-row-id]').first
    row.locator("[data-dt-open]").click()
    admin.wait("document.querySelector('#drawer[open] [data-client-view]') !== null")
    drawer = page.locator("#drawer")
    assert "Refusals by reason" in drawer.inner_text()
    assert drawer.locator('[data-action="client-ban"]').count() == 1
    assert page.evaluate(NO_HOSTILE_MARKUP)
    assert admin.axe() == []
    admin.shot("clients-drawer")
    page.keyboard.press("Escape")
    admin.wait("!document.querySelector('#drawer[open]')")
    admin.assert_clean()


def test_a_ban_from_the_drawer_goes_through_and_the_drawer_shows_it(open_admin: Any, dashboard: Any) -> None:
    address = "192.0.2.40"
    admin = open_admin(f"{PAGE}?q=192.0.2.40")
    page = admin.page
    try:
        page.locator("#ips").scroll_into_view_if_needed()
        admin.settle()
        page.fill('#ips input[name="q"]', address)
        admin.wait("document.querySelectorAll('#ips tbody tr[data-row-id]').length === 1")
        page.locator("#ips tbody tr[data-row-id] [data-dt-open]").first.click()
        admin.wait("document.querySelector('#drawer[open] [data-client-view]') !== null")
        page.locator('#drawer [data-action="client-ban"]').click()
        admin.wait("document.querySelector('#dlg-client-ban[open]') !== null")
        assert page.locator("#drawer[open]").count() == 1, "the drawer stays open under the confirm dialog"
        page.locator("#dlg-client-ban [data-ban-permanent]").check()
        assert page.locator("#dlg-client-ban-minutes").is_disabled()
        page.fill("#dlg-client-ban-reason", "browser test ban")
        page.locator('#dlg-client-ban button[type="submit"]').click()
        admin.wait("/Banned/.test(document.body.innerText)")
        admin.wait("/Banned permanently/.test(document.querySelector('#drawer-body').textContent)")
        bans = dashboard.api("GET", f"clients/ips/{address}").json()["ban"]
        assert bans is not None
        assert bans["permanent"] is True
        admin.assert_clean()
    finally:
        found = dashboard.api("GET", "protection/bans", params={"q": address}).json()
        for item in found.get("items") or ():
            dashboard.api("DELETE", f"protection/bans/{item['id']}", json={"reason": "browser test cleanup"})


def test_the_lookup_draws_the_experience_as_text(open_admin: Any) -> None:
    admin = open_admin(PAGE)
    page = admin.page
    page.locator("#lookup").scroll_into_view_if_needed()
    page.fill("#clients-lookup-id", PLACES[0])
    page.locator('[data-action="clients-lookup"]').click()
    admin.wait("document.querySelector('#lookup [data-lookup-result] .clients-lookup__head') !== null")
    result = page.locator("#lookup [data-lookup-result]")
    assert HOSTILE["img"] in result.inner_text()  # Roblox's (hostile) name, shown as text
    assert HOSTILE["script"] in result.inner_text()
    assert result.locator("[data-copy]").count() == 2
    assert page.evaluate(NO_HOSTILE_MARKUP)
    assert admin.axe() == []
    admin.assert_clean()


def test_the_client_has_a_page_of_its_own(open_admin: Any) -> None:
    admin = open_admin(f"{PAGE}/place/{PLACES[0]}", width=390, height=844)
    page = admin.page
    assert page.locator("h1").inner_text().strip() == f"Place {PLACES[0]}"
    assert page.locator("[data-client-view]").count() == 1
    assert not admin.overflows()
    assert admin.axe() == []
    admin.shot("clients-page")
    admin.assert_clean()
