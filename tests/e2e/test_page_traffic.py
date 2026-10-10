"""The Traffic page in a real browser (P11): clean, accessible, every card loads, and its controls work.

What this is
    Browser tests against the real app (`dashboard`: a free port, a signed-in admin, seeded traffic). For each theme
    and size (1440x900 and 390x844, dark and light) the page loads with every card (the lazy ones too), no console
    error, page error or CSP violation, no axe finding, no sideways scroll on a phone, and a screenshot for the
    visual review. Then the controls: the status chart's view and the latency split swap their card in place (never
    a card inside a card), a table sorts in place, and the inline reset opens its preview in the drawer with the
    confirm button off until the phrase is typed (the reset itself runs in the integration tests: the browser
    tests share one seeded server).

Why it exists
    Only a browser proves the charts draw under the strict CSP, the lazy cards arrive, and the controls swap the
    right element.

What to read next
    tests/e2e/conftest.py (`open_admin`, `AdminPage`), tests/integration/pages/test_page_traffic.py.
"""

from __future__ import annotations

from typing import Any

import pytest

from roxy.admin.pages.testing import THEMES, VIEWPORTS

PAGE = "/admin/traffic"
CARDS = ("requests", "bytes", "verbs", "status", "latency", "heatmap", "trends")
NO_HOSTILE_MARKUP = """() => !document.querySelector('img[src="x"], [onerror], [onclick], a[href^="javascript:"]')"""
ONE_OF_EACH = "() => ['status', 'latency', 'verbs'].every((id) => document.querySelectorAll('section#' + id).length === 1)"


def _total(answer: dict[str, Any]) -> float:
    return sum(v for series in answer["series"] for _t, v in series["points"] if isinstance(v, int | float))


def _loaded(admin: Any) -> None:
    admin.wait("!document.querySelector('.page-card--lazy')", timeout=20)
    admin.wait("document.querySelector('#traffic-requests-chart').dataset.chartReady === '1'")


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("size", list(VIEWPORTS))
def test_the_page_is_clean_accessible_and_fits(open_admin: Any, theme: str, size: str) -> None:
    width, height = VIEWPORTS[size]
    admin = open_admin(PAGE, theme=theme, width=width, height=height)
    _loaded(admin)
    for card in CARDS:
        assert admin.page.locator(f"section#{card}[data-card]").count() == 1, card
    admin.wait("Array.from(document.querySelectorAll('figure[data-chart]')).every((f) => f.dataset.chartReady)")
    assert admin.page.evaluate(NO_HOSTILE_MARKUP)
    assert not admin.overflows(), "the page scrolls sideways"
    assert admin.axe() == []
    admin.shot("traffic")
    admin.assert_clean()


def test_the_status_view_and_the_latency_split_swap_their_card_in_place(open_admin: Any) -> None:
    admin = open_admin(PAGE)
    page = admin.page
    _loaded(admin)
    page.evaluate("window.__sameDocument = true")
    page.select_option("#traffic-status-view", "source")
    admin.wait("document.querySelector('#traffic-status-chart-title').textContent.includes('who returned')")
    admin.wait("document.querySelector('#traffic-status-chart').dataset.chartReady === '1'")
    labels = page.locator("#traffic-status-chart .legend-item__label").all_inner_texts()
    assert any("Roblox to caller" in label for label in labels), labels
    assert page.evaluate("document.activeElement && document.activeElement.id") == "traffic-status-view"
    page.select_option("#traffic-latency-split", "outcome")
    admin.wait("document.querySelector('#traffic-latency-chart-title').textContent.includes('outcome')")
    header = page.locator('#latency [data-table="traffic_latency_split"] th[data-col="key"]').inner_text()
    assert "Outcome" in header
    page.select_option("#traffic-heatmap-metric", "refused")
    admin.wait("document.querySelector('#traffic-heatmap-grid-title').textContent.startsWith('Refused')")
    assert page.evaluate(ONE_OF_EACH)
    assert page.evaluate("window.__sameDocument === true"), "a control reloaded the whole page"
    admin.assert_clean()


def test_a_table_sorts_in_place_without_nesting_its_card(open_admin: Any) -> None:
    admin = open_admin(PAGE)
    page = admin.page
    _loaded(admin)
    sort = '#status [data-table="traffic_status_sources"] [data-dt-sort="status"]'
    page.locator(sort).click()
    admin.wait(
        "document.querySelector('#status th[data-col=\"status\"]').getAttribute('aria-sort') !== 'none'"
    )
    assert page.evaluate(ONE_OF_EACH)
    assert page.locator("section#status section#status").count() == 0
    codes = page.locator('#status [data-table="traffic_status_sources"] td[data-col="status"]').all_inner_texts()
    order = page.locator("#status th[data-col=\"status\"]").get_attribute("aria-sort")
    numbers = [int(code) for code in codes]
    assert numbers == sorted(numbers, reverse=order == "descending")
    assert "status=" not in page.url  # a second table of the page keeps its state out of the address
    admin.assert_clean()


def test_the_reset_opens_its_preview_and_waits_for_the_typed_phrase(open_admin: Any, dashboard: Any) -> None:
    admin = open_admin(PAGE, theme="light")
    page = admin.page
    before = dashboard.api("GET", "traffic/requests").json()
    page.locator('[data-action="traffic-reset"]').click()
    admin.wait("document.querySelector('#drawer[open] [data-reset=\"traffic\"]') !== null")
    drawer = page.locator("#drawer")
    assert "This will delete" in drawer.inner_text()
    submit = drawer.locator('button[data-action="reset-traffic"]')
    assert submit.is_disabled()
    drawer.locator('input[name="confirm"]').fill("reset traffic")
    admin.wait("!document.querySelector('#drawer button[data-action=\"reset-traffic\"]').disabled")
    assert admin.axe() == []
    admin.shot("traffic-reset")
    drawer.locator("button[data-dialog-close]").last.click()
    admin.wait("!document.querySelector('#drawer[open]')")
    after = dashboard.api("GET", "traffic/requests").json()
    assert _total(after) >= _total(before) > 0  # cancel deleted nothing
    admin.assert_clean()
