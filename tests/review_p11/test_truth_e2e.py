"""P11 adversarial review, lens "honest numbers": browser reproductions (regression tests now; see test_truth.py).

What this is
    The findings of `.remake/p11_review/find_truth.md` that only a browser can show: what static/js renders. The
    fixtures are tests/e2e/conftest.py's (`browser`, `dashboard`), imported as a module because this folder is not
    tests/e2e; a browser context is built here like `open_admin` builds one, with a browser time zone of its own.

What to read next
    `static/js/charts.js`, `static/js/format.js`, `tests/e2e/test_page_overview.py`.
"""

from __future__ import annotations

from typing import Any

import pytest

from e2e import conftest as browser_fixtures

# The browser fixtures of tests/e2e/conftest.py (this folder is not under it): module globals, so pytest finds them.
browser = browser_fixtures.browser
dashboard = browser_fixtures.dashboard
wait_for_js = browser_fixtures.wait_for_js

pytestmark = pytest.mark.e2e

BROWSER_ZONE = "America/Los_Angeles"  # an admin three hours west of the dashboard's ui_timezone (America/New_York)
CHART_TIME = """([at, zone]) => new Intl.DateTimeFormat("en-US", {hour: "2-digit", minute: "2-digit", second: "2-digit",
  hour12: false, weekday: "short", month: "short", day: "numeric", timeZone: zone}).format(new Date(at * 1000))"""


def _signed_in_page(browser: Any, dashboard: Any, timezone_id: str) -> tuple[Any, Any]:
    from pages_harness import SESSION_COOKIE_NAME

    context = browser.new_context(
        viewport={"width": 1440, "height": 900}, base_url=dashboard.base_url, timezone_id=timezone_id
    )
    context.add_cookies(
        [
            {
                "name": SESSION_COOKIE_NAME,
                "value": dashboard.signed_in.cookie,
                "domain": "127.0.0.1",
                "path": "/",
                "secure": True,
                "httpOnly": True,
                "sameSite": "Strict",
            }
        ]
    )
    return context, context.new_page()


# Fixed in the P11 review round (truth-9, shared fixer): a regression test now.
def test_truth_9_chart_times_are_shown_in_the_dashboard_time_zone(browser: Any, dashboard: Any) -> None:
    zone = str(dashboard.ctx.settings.get("ui_timezone") or "UTC")
    assert zone != BROWSER_ZONE
    answer = dashboard.api("GET", "overview/chart", params={"range": "24h"}).json()
    first = min(point[0] for series in answer["series"] for point in series["points"])
    context, page = _signed_in_page(browser, dashboard, BROWSER_ZONE)
    try:
        page.goto(dashboard.base_url + "/admin/overview?range=24h", wait_until="load")
        wait_for_js(
            page, "(document.querySelector('#traffic [data-chart]') || {dataset: {}}).dataset.chartReady === '1'"
        )
        wait_for_js(page, "document.querySelector('#traffic [data-chart-table] table tbody th') !== null")
        shown = page.locator("#traffic [data-chart-table] table tbody th").first.text_content() or ""
        # The ui_timezone setting: "The timezone for every time shown in the dashboard". The server renders the
        # tables in it (fmt.time_cell); the chart's first bucket must read the same way, whatever the browser's zone.
        expected = page.evaluate(CHART_TIME, [first, zone])
        browser_zone = page.evaluate(CHART_TIME, [first, BROWSER_ZONE])
        assert expected != browser_zone  # the two zones really differ at that time
        assert shown.strip() == expected, (shown, expected, browser_zone)
    finally:
        context.close()


DRAW_SERIES = r"""async ([values, id]) => {
  // A copy of the Cache page's "Avoided upstream calls" chart (an embedded admin API series answer, unit percent),
  // fed `values`, drawn by static/js/charts.js like any chart htmx swaps in.
  const source = document.querySelector("#cache-avoided");
  const figure = source.cloneNode(true);
  figure.id = id;
  delete figure.dataset.chartReady;
  const t0 = 1760000000;
  figure.dataset.series = JSON.stringify({
    range: {from: t0, to: t0 + 60 * values.length, granularity: "minute", tz: "UTC"},
    series: [{key: "avoided_pct", label: "Avoided upstream calls (percent)", unit: "percent",
              points: values.map((v, i) => [t0 + 60 * i, v])}],
    compare: null, annotations: [], notices: [],
  });
  figure.querySelector("[data-chart-plot]").replaceChildren();
  figure.querySelector("[data-chart-legend]").replaceChildren();
  source.parentElement.append(figure);
  figure.dispatchEvent(new CustomEvent("htmx:load", {bubbles: true, detail: {elt: figure}}));
  for (let i = 0; i < 100 && figure.dataset.chartReady !== "1"; i += 1) await new Promise((r) => setTimeout(r, 50));
  // How many canvas pixels carry the series color (the line itself; axes and grid use other tokens).
  const probe = document.createElement("span");
  probe.className = "sr-only";
  document.body.append(probe);
  probe.style.color = "var(--series-1)";
  const [r, g, b] = getComputedStyle(probe).color.match(/\d+/g).map(Number);
  probe.remove();
  const canvas = figure.querySelector("canvas");
  const data = canvas.getContext("2d").getImageData(0, 0, canvas.width, canvas.height).data;
  let hits = 0;
  for (let p = 0; p < data.length; p += 4) {
    const distance = Math.abs(data[p] - r) + Math.abs(data[p + 1] - g) + Math.abs(data[p + 2] - b);
    if (data[p + 3] > 200 && distance < 40) hits += 1;
  }
  return {ready: figure.dataset.chartReady, hits};
}"""


# Fixed in the P11 review round (truth-12, shared fixer): a regression test now.
def test_truth_12_a_negative_avoided_share_is_drawn_on_the_chart(browser: Any, dashboard: Any) -> None:
    context, page = _signed_in_page(browser, dashboard, "America/New_York")
    try:
        page.goto(dashboard.base_url + "/admin/cache?range=1h", wait_until="load")
        wait_for_js(page, "document.querySelector('#cache-avoided') !== null", 30.0)
        positive = page.evaluate(DRAW_SERIES, [[20, 50, 35, 60], "truth-avoided-positive"])
        negative = page.evaluate(DRAW_SERIES, [[-100, -50, -80, -60], "truth-avoided-negative"])
        assert positive["ready"] == "1", positive  # the method: a positive share is drawn and counted
        assert positive["hits"] > 20, positive
        # Plan P6: "-100% means 2 upstream calls per request ... shown as it is". The line must be on the plot.
        assert negative["ready"] == "1", negative
        assert negative["hits"] > 20, (positive, negative)
    finally:
        context.close()
