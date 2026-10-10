"""The Overview page in a real browser (P11): clean, accessible, fits a phone, and its controls work.

What this is
    Browser tests against the real app (`dashboard`, tests/e2e/conftest.py: a free port, a signed-in admin, traffic
    with hostile text sent through the real proxy, a recommendation and a health run). For each theme and size
    (1440x900 and 390x844, dark and light) the page loads with no console error, page error or CSP violation,
    axe-core finds nothing serious, the phone layout never scrolls sideways, and a screenshot is saved for the
    visual review. Then the controls: the chart draws from the API series with its data table, the events table
    searches in place, a top recommendation opens its drawer on the Recommendations page, and Check Proxy Health
    starts a run and lands on the Health page.

Why it exists
    The integration tests prove what the server sends; only a browser proves the page works with the strict CSP,
    htmx, uPlot and the design system's scripts.

What to read next
    tests/e2e/conftest.py (`open_admin`, `AdminPage`), tests/integration/pages/test_page_overview.py.
"""

from __future__ import annotations

from typing import Any

import pytest

from roxy.admin.pages.testing import THEMES, VIEWPORTS, seed_recommendation

PAGE = "/admin/overview"
NO_HOSTILE_MARKUP = """() => !document.querySelector('img[src="x"], [onerror], [onclick], a[href^="javascript:"]')
  && typeof window.__pwned === "undefined\""""
CHART_READY = "(document.querySelector('#traffic [data-chart]') || {dataset: {}}).dataset.chartReady === '1'"


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("size", list(VIEWPORTS))
def test_the_page_is_clean_accessible_and_fits(open_admin: Any, theme: str, size: str) -> None:
    width, height = VIEWPORTS[size]
    admin = open_admin(f"{PAGE}?range=1h", theme=theme, width=width, height=height)
    page = admin.page
    assert page.locator(f'html[data-theme="{theme}"]').count() == 1
    assert page.locator('#kpis [data-kpi="requests"]').count() == 1
    admin.wait(CHART_READY)
    assert page.evaluate(NO_HOSTILE_MARKUP)
    assert not admin.overflows(), "the page scrolls sideways"
    assert admin.axe() == []
    admin.shot("overview")
    admin.assert_clean()


def test_the_chart_draws_the_api_series_with_a_data_table(open_admin: Any) -> None:
    admin = open_admin(f"{PAGE}?range=1h")
    page = admin.page
    admin.wait(CHART_READY)
    admin.wait("document.querySelector('#traffic [data-chart-table] table') !== null")
    page.locator("#traffic .chart__table summary").click()
    table = page.locator("#traffic [data-chart-table] table")
    assert table.locator("th").count() >= 2
    assert page.locator("#traffic [data-chart-legend] button, #traffic [data-chart-legend] [role=switch]").count() >= 1
    admin.assert_clean()


def test_the_events_table_searches_in_place(open_admin: Any) -> None:
    admin = open_admin(f"{PAGE}?range=1h")
    page = admin.page
    page.evaluate("window.__sameDocument = true")
    page.fill('#events input[name="q"]', "no-such-event-type")
    admin.wait("new URL(location.href).searchParams.get('q') === 'no-such-event-type'")
    admin.wait("document.querySelector('#events .dt__empty-row') !== null")
    assert page.evaluate("window.__sameDocument === true"), "the table reloaded the whole page"
    assert page.evaluate("document.querySelectorAll('section#events, #events h2').length") == 2, "a card in a card"
    admin.assert_clean()


def test_a_top_recommendation_opens_its_drawer(open_admin: Any, dashboard: Any) -> None:
    # The live engine would resolve a seeded UP-429-ENDPOINT card the seeded traffic does not prove: the rule is off
    # meanwhile (a rule that does not run never resolves its cards).
    dashboard.change_settings({"insight_up_429_endpoint_enabled": 0})
    try:
        rec_id = dashboard.run(seed_recommendation(dashboard.ctx, dashboard.clock, severity="critical"))
        admin = open_admin(PAGE, width=390, height=844)
        page = admin.page
        link = page.locator(f'#recommendations [data-rec="{rec_id}"] a').first
        link.click()
        page.wait_for_url(f"**/admin/recommendations?rec={rec_id}")
        admin.settle()
        admin.wait(f"document.querySelector('#drawer[open] [data-rec-detail=\"{rec_id}\"]') !== null", timeout=15)
        admin.assert_clean()
    finally:
        dashboard.change_settings({"insight_up_429_endpoint_enabled": 1})


def test_check_proxy_health_starts_a_run_and_opens_it(open_admin: Any, dashboard: Any) -> None:
    dashboard.change_settings({"health_auto_interval_h": 0})
    admin = open_admin(PAGE)
    page = admin.page
    page.locator('[data-action="overview-health-run"]').click()
    page.wait_for_url("**/admin/health?run=*", timeout=20_000)
    admin.settle()
    admin.wait("document.querySelector('#run [data-run-id]') !== null")
    run_id = page.locator("#run [data-run-id]").first.get_attribute("data-run-id")
    assert run_id and run_id.isdigit()
    # The run finishes on its own (local checks answer at once; outside calls are refused by the test guard).
    admin.wait("document.querySelector('#run [data-run-state=\"finished\"]') !== null", timeout=120)
    admin.assert_clean(expected=["status of 409"])
