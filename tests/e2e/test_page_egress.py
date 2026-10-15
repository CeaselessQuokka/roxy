"""The Egress page in a real browser (P11): clean, accessible, and its controls work.

What this is
    Browser tests against the real app (`dashboard`, tests/e2e/conftest.py: a free port, a signed-in admin, seeded
    traffic with hostile text). For each theme and size (1440x900 and 390x844, dark and light) the page loads with
    every deferred card, with no console error, page error or CSP violation, axe-core finds nothing serious, the
    phone layout never scrolls sideways, and a screenshot is saved for the visual review. Then the controls: the
    top endpoints egress filter swaps the table in place and keeps the address, a row opens its details in the
    drawer, "Verify rotation now" says what the probe found, the provider figure is recorded through the API, and
    an inline rotator setting is reviewed and saved.

Why it exists
    The integration tests prove what the server sends; only a browser proves the page works under the strict CSP
    with htmx, the drawer, the dialogs and the design system's scripts.

What to read next
    tests/e2e/conftest.py (`open_admin`, `AdminPage`), tests/integration/pages/test_page_egress.py.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from pages_harness import THEMES, VIEWPORTS

PAGE = "/admin/egress"
NO_HOSTILE_MARKUP = """() => !document.querySelector('img[src="x"], [onerror], [onclick], a[href^="javascript:"]')
  && typeof window.__pwned === "undefined\""""
TOP_COUNT = "document.querySelector('#top-endpoints .dt__count').textContent.trim()"


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("size", list(VIEWPORTS))
def test_the_page_is_clean_accessible_and_fits(open_admin: Any, theme: str, size: str) -> None:
    width, height = VIEWPORTS[size]
    admin = open_admin(PAGE, theme=theme, width=width, height=height)
    page = admin.page
    assert page.locator(f'html[data-theme="{theme}"]').count() == 1
    assert page.locator(".page-card--lazy").count() == 0, "a deferred card did not load"
    assert page.locator("[data-card-error]").count() == 0
    assert page.locator('#top-endpoints [data-table="egress_top_endpoints"]').count() == 1
    assert page.locator("#usage .g3-usage").count() == 3
    assert page.locator('#rotator [data-setting-key="rotator_enabled"]').count() == 1
    assert page.evaluate(NO_HOSTILE_MARKUP)
    assert not admin.overflows(), "the page scrolls sideways"
    assert admin.axe() == []
    admin.shot("egress")
    admin.assert_clean()


def _toast(admin: Any, text: str) -> None:
    admin.wait(f"[...document.querySelectorAll('.toast')].some((t) => t.textContent.includes({json.dumps(text)}))")


def test_the_egress_filter_swaps_the_top_endpoints_in_place_and_a_row_opens_its_detail(open_admin: Any) -> None:
    admin = open_admin(PAGE)
    page = admin.page
    page.evaluate("window.__sameDocument = true")
    assert page.locator("#top-endpoints tbody tr[data-row-id]").count() == 0  # the rotator carries nothing here
    before = page.evaluate(TOP_COUNT)
    page.select_option('#top-endpoints select[name="egress"]', "direct")
    admin.wait(f"{TOP_COUNT} !== {json.dumps(before)}")
    assert "egress=direct" in page.url  # the main table keeps its state in the address
    rows = page.locator("#top-endpoints tbody tr[data-row-id]")
    assert rows.count() > 0
    admin.wait("document.querySelector('#top-endpoints-summary').textContent.startsWith('Direct:')")
    assert "(direct)" in page.locator("#top-endpoints-slots summary").inner_text()  # the slots follow the filter
    assert page.locator("#top-endpoints [data-table]").count() == 1, "the table was nested in itself"
    rows.first.locator("[data-dt-open]").click()
    admin.wait("document.querySelector('#drawer[open] #drawer-body dl') !== null")
    assert "Bytes" in page.locator("#drawer-body").inner_text()
    assert page.evaluate(NO_HOSTILE_MARKUP)
    page.keyboard.press("Escape")
    admin.wait("!document.querySelector('#drawer[open]')")
    assert page.evaluate("window.__sameDocument === true"), "the table reloaded the whole page"
    admin.assert_clean()


def test_verify_rotation_says_what_the_probe_found(open_admin: Any) -> None:
    admin = open_admin(PAGE)
    page = admin.page
    button = page.locator('[data-action="rotator-verify"]')
    assert button.is_enabled()  # a (fake) rotator URL is configured
    button.click()
    admin.wait("[...document.querySelectorAll('.toast')].some((t) => /Rotation/.test(t.textContent))", timeout=30)
    text = " ".join(page.locator(".toast").all_inner_texts())
    assert "Rotation FAILED" in text  # the fake gateway (a closed loopback port) never answers
    admin.wait("document.querySelector('#exit-ips') !== null")  # the card is refreshed in place
    admin.assert_clean()


def test_the_provider_figure_is_recorded_from_the_budget_card(open_admin: Any, dashboard: Any) -> None:
    admin = open_admin(PAGE, theme="light", width=390, height=844)
    page = admin.page
    page.fill("#provider-gb", "3.25")
    page.fill("#provider-reason", "Browser test of the provider figure")
    page.locator('[data-action="provider-report"]').click()
    _toast(admin, "Figure recorded")
    admin.wait("document.querySelector('#budget').textContent.includes('3.25 GB')")
    latest = dashboard.api("GET", "egress/provider-report").json()["latest"]
    assert latest["reported_bytes"] == 3_250_000_000
    admin.assert_clean()


def test_an_inline_rotator_setting_is_reviewed_and_saved(open_admin: Any, dashboard: Any) -> None:
    before = dashboard.api("GET", "settings/rotator_price_per_gb_usd").json()["setting"]["value"]
    target = 2.5 if float(before) != 2.5 else 3.0
    try:
        admin = open_admin(PAGE)
        page = admin.page
        page.locator("#budget-settings > summary").click()
        control = page.locator('#budget form[data-setting-key="rotator_price_per_gb_usd"]')
        control.scroll_into_view_if_needed()
        control.locator("[data-setting-input]").fill(str(target))
        control.locator('input[name="reason"]').fill("Browser test of the budget card")
        control.locator('button[type="submit"]').click()
        admin.wait(
            '(() => { const r = document.querySelector(\'#budget [data-setting-key="rotator_price_per_gb_usd"] '
            "[data-setting-review]'); return r && !r.hidden; })()"
        )
        control.locator('button[type="submit"]').click()
        admin.wait("document.querySelector('#budget .setting__saved') !== null")
        value = dashboard.api("GET", "settings/rotator_price_per_gb_usd").json()["setting"]["value"]
        assert float(value) == target
        admin.assert_clean()
    finally:
        dashboard.change_settings({"rotator_price_per_gb_usd": before})
