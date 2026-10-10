"""The Cache page in a real browser: clean, accessible, fits a phone, and its controls work.

What this is
    Browser tests against the real app (`dashboard`, tests/e2e/conftest.py: a free port, a signed-in admin, traffic
    through the real proxy). For each theme and size (1440x900 and 390x844, dark and light) the page loads with
    every lazy card, no console error, page error or CSP violation, axe-core finds nothing serious, the phone never
    scrolls sideways, and a screenshot is saved for the visual review. Then the controls: the browser's search
    swaps the table in place and keeps the address, "Purge matching" follows the search and removes exactly what it
    lists, a row opens the inspector drawer, the inline TTL setting reviews and saves, a cache rule is added from
    the form and edited in its drawer, and "Clear stats" waits for the typed phrase.

Why it exists
    The integration tests prove what the server sends; only a browser proves the page works with the strict CSP,
    htmx, the shared dialogs and this page's script. Tests that change shared state run last and put it back.

What to read next
    tests/integration/pages/test_page_cache.py, roxy/admin/pages/cache.py, static/js/pages/cache.js.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from roxy.admin.pages.testing import THEMES, VIEWPORTS

PAGE = "/admin/cache"
NO_HOSTILE_MARKUP = """() => !document.querySelector('img[src="x"], [onerror], [onclick], a[href^="javascript:"]')
  && typeof window.__pwned === "undefined\""""
COUNT = "document.querySelector('#browser .dt__count').textContent.trim()"


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("size", list(VIEWPORTS))
def test_the_page_is_clean_accessible_and_fits(open_admin: Any, theme: str, size: str) -> None:
    width, height = VIEWPORTS[size]
    admin = open_admin(PAGE, theme=theme, width=width, height=height)
    page = admin.page
    assert page.locator(f'html[data-theme="{theme}"]').count() == 1
    assert page.locator(".page-card--lazy").count() == 0, "every lazy card loaded"
    assert page.locator("[data-card-error]").count() == 0
    assert page.locator('#browser [data-table="cache_entries"] tbody tr[data-row-id]').count() > 0
    assert page.locator('#stats [data-kpi="hit_ratio"]').count() == 1
    assert page.locator("#settings [data-setting-key]").count() >= 20
    assert page.evaluate(NO_HOSTILE_MARKUP)
    assert not admin.overflows(), "the page scrolls sideways"
    assert admin.axe() == []
    admin.shot("cache")
    admin.assert_clean()


def test_the_browser_search_swaps_in_place_and_purge_matching_follows_it(open_admin: Any) -> None:
    admin = open_admin(PAGE)
    page = admin.page
    page.evaluate("window.__sameDocument = true")
    button = page.locator("[data-purge-matching]")
    assert button.is_disabled()
    everything = page.locator("#browser .dt__count").inner_text()
    page.fill('#browser input[name="q"]', "universeIds=1")
    admin.wait("new URL(location.href).searchParams.get('q') === 'universeIds=1'")
    admin.wait(f"{COUNT} !== {json.dumps(everything.strip())}")
    rows = page.locator("#browser tbody tr[data-row-id]")
    assert rows.count() > 0
    assert all("universeids=1" in rows.nth(i).inner_text().lower() for i in range(rows.count()))
    assert not button.is_disabled()
    fill = json.loads(button.get_attribute("data-fill") or "{}")
    assert fill["scope"] == "search"
    assert fill["value"] == "universeIds=1"
    button.click()
    admin.wait("document.querySelector('#dlg-cache-purge[open]') !== null")
    assert "universeIds=1" in page.locator("#dlg-cache-purge [data-fill-label]").inner_text()
    assert page.locator('#dlg-cache-purge input[name="scope"]').input_value() == "search"
    assert admin.axe() == []
    page.keyboard.press("Escape")
    admin.wait("!document.querySelector('#dlg-cache-purge[open]')")
    assert page.evaluate("window.__sameDocument === true"), "the table reloaded the whole page"
    admin.assert_clean()


def test_a_row_opens_the_inspector_drawer(open_admin: Any) -> None:
    admin = open_admin(PAGE, theme="light")
    page = admin.page
    page.locator("#browser tbody tr[data-row-id]").first.click()
    admin.wait("document.querySelector('#drawer[open] [data-cache-entry]') !== null")
    drawer = page.locator("#drawer")
    assert "Fresh until" in drawer.inner_text()
    assert drawer.locator("pre.cache-body").count() == 1
    assert page.evaluate(NO_HOSTILE_MARKUP)
    assert admin.axe() == []
    admin.shot("cache-drawer")
    page.keyboard.press("Escape")
    admin.wait("!document.querySelector('#drawer[open]')")
    admin.assert_clean()


def test_the_purge_card_reviews_before_it_purges(open_admin: Any) -> None:
    admin = open_admin(f"{PAGE}#purge")
    page = admin.page
    page.locator('#purge [data-action="cache-purge"]').click()
    error = page.locator("#purge [data-purge-error]")
    assert error.is_visible()
    assert page.locator("#dlg-cache-purge[open]").count() == 0
    page.fill("#cache-purge-value", "thumbnails.roblox.com")
    page.select_option("#cache-purge-scope", "host")
    page.locator('#purge [data-action="cache-purge"]').click()
    admin.wait("document.querySelector('#dlg-cache-purge[open]') !== null")
    assert "thumbnails.roblox.com" in page.locator("#dlg-cache-purge [data-fill-label]").inner_text()
    assert page.locator('#dlg-cache-purge input[name="scope"]').input_value() == "host"
    page.keyboard.press("Escape")
    admin.assert_clean()


def test_clear_stats_waits_for_the_typed_phrase(open_admin: Any) -> None:
    admin = open_admin(PAGE)
    page = admin.page
    page.locator('#stats [data-action="cache-clear-stats"]').click()
    admin.wait("document.querySelector('#dlg-cache-reset-stats[open]') !== null")
    admin.wait("!/Counting/.test(document.querySelector('#dlg-cache-reset-stats [data-reset-summary]').textContent)")
    assert "This will" in page.locator("#dlg-cache-reset-stats [data-reset-summary]").inner_text()
    submit = page.locator('#dlg-cache-reset-stats button[type="submit"]')
    assert submit.is_disabled()
    page.fill("#dlg-cache-reset-stats-confirm", "reset cache_stats")
    admin.wait("!document.querySelector('#dlg-cache-reset-stats button[type=submit]').disabled")
    assert admin.axe() == []
    page.keyboard.press("Escape")
    admin.assert_clean()


def test_the_inline_ttl_setting_reviews_and_saves(open_admin: Any, dashboard: Any) -> None:
    before = dashboard.api("GET", "settings/cache_ttl_seconds").json()["setting"]["value"]
    try:
        admin = open_admin(PAGE)
        page = admin.page
        control = page.locator('#settings form[data-setting-key="cache_ttl_seconds"]')
        control.scroll_into_view_if_needed()
        control.locator("[data-setting-input]").fill("4m")
        control.locator('input[name="reason"]').fill("Browser test of the cache settings card")
        control.locator('button[type="submit"]').click()
        admin.wait("(() => { const r = document.querySelector('#settings [data-setting-key=\"cache_ttl_seconds\"] "
                   "[data-setting-review]'); return r && !r.hidden; })()")
        control.locator('button[type="submit"]').click()
        admin.wait("document.querySelector('#settings .setting__saved') !== null")
        assert dashboard.api("GET", "settings/cache_ttl_seconds").json()["setting"]["value"] == 240
        admin.assert_clean()
    finally:
        dashboard.change_settings({"cache_ttl_seconds": before})


def test_a_rule_is_added_from_the_form_and_edited_in_its_drawer(open_admin: Any, dashboard: Any) -> None:
    admin = open_admin(PAGE)
    page = admin.page
    created = None
    try:
        page.locator("#rules details.cache-add > summary").click()
        page.fill("#cache-rule-new-pattern", "catalog.roblox.com/v1/e2e/*")
        page.fill("#cache-rule-new-ttl", "900")
        page.fill("#cache-rule-new-note", "added by the browser test")
        page.locator('[data-action="cache-rule-add"]').click()
        admin.wait("document.querySelector('.toast') !== null && /Cache rule added/.test(document.body.innerText)")
        admin.wait("document.querySelector('#rules tbody') && /catalog.roblox.com\\/v1\\/e2e/.test("
                   "document.querySelector('#rules tbody').textContent)")
        rules = dashboard.api("GET", "cache/rules", params={"q": "e2e"}).json()["items"]
        assert len(rules) == 1
        created = rules[0]["id"]
        page.locator(f'#rules tr[data-row-id="cache-rule-{created}"]').click()
        admin.wait("document.querySelector('#drawer[open] form[data-api-method=\"PATCH\"]') !== null")
        page.fill(f"#cache-rule-{created}-ttl", "1200")
        page.locator('#drawer [data-action="cache-rule-save"]').click()
        admin.wait("/Rule saved/.test(document.body.innerText)")
        assert dashboard.api("GET", "cache/rules", params={"q": "e2e"}).json()["items"][0]["ttl"] == 1200
        admin.assert_clean()
    finally:
        if created is not None:
            dashboard.api("DELETE", f"cache/rules/{created}", json={"reason": "browser test cleanup"})


def test_purge_matching_removes_exactly_what_the_search_lists(open_admin: Any, dashboard: Any) -> None:
    listed = dashboard.api("GET", "cache/entries", params={"q": "universeIds=1", "page_size": 250}).json()["total"]
    total = dashboard.api("GET", "cache/entries", params={"page_size": 250}).json()["total"]
    assert listed > 0
    admin = open_admin(f"{PAGE}?q=universeIds%3D1")
    page = admin.page
    page.locator("[data-purge-matching]").click()
    admin.wait("document.querySelector('#dlg-cache-purge[open]') !== null")
    page.fill("#dlg-cache-purge-reason", "browser test of purge matching")
    page.locator('#dlg-cache-purge button[type="submit"]').click()
    admin.wait("/Purged/.test(document.body.innerText)")
    admin.wait("/No stored answer matches/.test(document.querySelector('#browser').textContent)")
    after = dashboard.api("GET", "cache/entries", params={"page_size": 250}).json()["total"]
    assert after == total - listed
    admin.assert_clean()
