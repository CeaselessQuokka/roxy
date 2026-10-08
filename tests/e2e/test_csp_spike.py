"""CSP spike (plan 9.2, the P0 gate item moved to P11): the vendored libraries run under exactly the 9.2 policy.

What this is
    Browser tests that load htmx 2.0.11, Alpine.js 3.17.4 (CSP build) and uPlot 1.6.32 under the exact policy
    `roxy.core.security_headers.page_csp(nonce)` sends (nonce plus 'strict-dynamic' for scripts, 'self' plus the
    nonce for styles, no 'unsafe-inline', no 'unsafe-eval'), exercise the features most likely to trip it, and
    record every violation three ways: the `securitypolicyviolation` DOM event, the browser console, and reports
    posted to /csp-report.

Why it exists
    Plan 9.2 makes this spike blocking for the dashboard: if a library needed inline style attributes or eval, the
    policy would need `style-src-attr 'unsafe-hashes'` with specific hashes (documented in docs/SECURITY.md), or
    the library would have to go. Result recorded on 2026-10-07: zero violations for every library and for the
    whole design system gallery, so the policy needs no exception. What made that true: htmx with
    `allowEval=false`, `includeIndicatorStyles=false` and `attributesToSettle` without "style"; Alpine's CSP build
    (no eval; x-show and x-transition write styles through the CSSOM, which CSP allows); uPlot positions everything
    through the CSSOM too. The import map pins SRI hashes, and a wrong hash makes the browser refuse the file.
    Two rules the spike found (both followed by static/js): htmx must be configured before it starts, so it is
    imported statically by the entry module (a late `await import()` let htmx inject its indicator <style> without
    a nonce: one style-src-elem violation); and Alpine's CSP build refuses property assignments on DOM objects in
    expressions (component state only). Test helpers must not use Playwright's `wait_for_function`, which evals in
    the page and is itself refused by the policy (conftest `wait_for_js` polls through the DevTools protocol).

How it works
    `ui_server` (tests/e2e/conftest.py) serves tests/e2e/spike/spike.html and the gallery through Roxy's real
    SecurityHeadersMiddleware. Each test drives the page with Playwright and then asserts the three violation
    sources are empty and no page error was raised.

What to read next
    tests/e2e/spike/spike.html, src/roxy/core/security_headers.py, tests/e2e/test_design_system.py.
"""

from __future__ import annotations

from typing import Any

import pytest

from roxy.core.security_headers import page_csp

pytestmark = pytest.mark.e2e

SPIKE = "/admin/_spike"


def _assert_clean(record: Any, ui_server: Any) -> None:
    assert record.csp_violations() == []
    assert record.console_csp() == []
    assert ui_server.app.state.csp_reports == []
    assert record.errors == []


def _wait_ready(page: Any, wait_js: Any) -> None:
    wait_js(page, "window.__spike && window.__spike.uplot === true", 15)


def test_spike_page_sends_exactly_the_plan_policy(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    record = open_page()
    response = record.page.goto(ui_server.base_url + SPIKE)
    assert response is not None
    assert response.ok
    headers = response.headers
    nonce = record.page.evaluate("document.querySelector('script[nonce]').nonce")
    assert nonce
    assert headers["content-security-policy"] == page_csp(nonce)
    policy = headers["content-security-policy"]
    assert "unsafe-inline" not in policy
    assert "unsafe-eval" not in policy
    assert "unsafe-hashes" not in policy
    assert headers["reporting-endpoints"] == 'csp-endpoint="/csp-report"'
    # The nonce is new for every response (a reused nonce protects nothing).
    second = record.page.request.get(ui_server.base_url + SPIKE)
    assert nonce not in second.headers["content-security-policy"]


def test_htmx_indicators_and_swaps_run_without_violations(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    record = open_page()
    page = record.page
    page.goto(ui_server.base_url + SPIKE)
    _wait_ready(page, wait_js)
    assert page.evaluate("window.__spike.htmx") is True
    # hx-trigger="load" swapped itself out on its own.
    page.wait_for_selector("#swapped-9")
    page.click("#load")
    # The indicator gets htmx-request (and becomes visible) while the request is in flight.
    page.wait_for_selector("#spinner.htmx-request", timeout=5000)
    assert page.eval_on_selector("#spinner", "e => getComputedStyle(e).opacity") == "1"
    page.wait_for_selector("#swapped-1")
    page.wait_for_selector("#spinner:not(.htmx-request)")
    # outerHTML swap of the swapped content (settling copies class, never style).
    page.click("#inner-1")
    page.wait_for_selector("#swapped-2")
    assert page.locator("#swapped-1").count() == 0
    page.wait_for_timeout(200)
    _assert_clean(record, ui_server)


def test_alpine_directives_run_without_violations(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    record = open_page()
    page = record.page
    page.goto(ui_server.base_url + SPIKE)
    _wait_ready(page, wait_js)
    assert page.is_visible("#alpine-demo")  # x-cloak removed
    assert not page.is_visible("#shown")  # x-show false
    assert page.text_content("#state") == "closed"
    page.click("#toggle")
    page.wait_for_selector("#shown", state="visible")  # x-show with x-transition
    assert page.text_content("#state") == "open"
    assert page.get_attribute("#toggle", "aria-expanded") == "true"
    assert "on" in (page.get_attribute("#toggle", "class") or "")  # x-bind:class
    page.fill("#model", "hello csp")  # x-model
    wait_js(page, "document.querySelector('#echo').textContent === 'hello csp'", 15)
    page.click("#add")  # x-for re-renders the list
    wait_js(page, "document.querySelectorAll('#list li').length === 4", 15)
    assert page.text_content("#count") == "4"  # x-effect re-ran when x-for's list grew
    assert page.text_content("#refs") == "count"  # x-ref and $refs
    page.click("#toggle")
    page.wait_for_selector("#shown", state="hidden")
    page.wait_for_timeout(300)
    _assert_clean(record, ui_server)


def test_uplot_legend_cursor_and_zoom_run_without_violations(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    record = open_page()
    page = record.page
    page.goto(ui_server.base_url + SPIKE)
    _wait_ready(page, wait_js)
    over = page.locator("#plot .u-over")
    box = over.bounding_box()
    assert box is not None
    # Hover: the live legend shows values at the cursor.
    page.mouse.move(box["x"] + box["width"] * 0.3, box["y"] + box["height"] / 2)
    page.wait_for_timeout(100)
    values = page.eval_on_selector_all("#plot .u-legend .u-value", "els => els.map(e => e.textContent)")
    assert any(v.strip() not in ("", "--") for v in values[1:])
    # Click a legend entry: the series turns off.
    page.click("#plot .u-legend .u-series:nth-child(2) th")
    assert "u-off" in (page.get_attribute("#plot .u-legend .u-series:nth-child(2)", "class") or "")
    assert page.evaluate("window.__plot.series[1].show") is False
    # Drag to zoom: the x scale narrows.
    before = page.evaluate("window.__plot.scales.x.max - window.__plot.scales.x.min")
    page.mouse.move(box["x"] + box["width"] * 0.2, box["y"] + 20)
    page.mouse.down()
    page.mouse.move(box["x"] + box["width"] * 0.6, box["y"] + 20, steps=6)
    page.mouse.up()
    after = page.evaluate("window.__plot.scales.x.max - window.__plot.scales.x.min")
    assert after < before
    page.wait_for_timeout(200)
    _assert_clean(record, ui_server)


def test_a_modified_vendor_file_is_refused_by_its_sri_hash(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    record = open_page()
    page = record.page
    page.goto(ui_server.base_url + SPIKE + "?sri=bad")
    wait_js(page, "window.__spike && window.__spike.uplot === true", 15)  # the other libraries still load
    page.wait_for_timeout(800)
    assert page.evaluate("window.__spike.htmx") is False
    assert page.locator("#auto").count() == 1  # htmx never ran, so hx-trigger="load" never swapped
    assert any("integrity" in line.lower() for line in record.console)  # Chrome names the failed digest check


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_the_whole_gallery_runs_without_violations(ui_server: Any, open_page: Any, wait_js: Any, theme: str) -> None:
    record = open_page(color_scheme=theme)
    page = record.page
    response = page.goto(f"{ui_server.base_url}/admin/_gallery?theme={theme}")
    assert response is not None
    assert response.ok
    nonce = page.evaluate("document.querySelector('script[nonce]').nonce")
    assert response.headers["content-security-policy"] == page_csp(nonce)
    wait_js(page, "document.documentElement.dataset.ready === '1'", 15)
    wait_js(page, "[...document.querySelectorAll('[data-chart]')].every(f => f.dataset.chartReady === '1')", 15)
    # Touch the interactive parts: palette, menus, tooltips, a chart, the table, a dialog, a setting.
    page.keyboard.press("Control+k")
    page.wait_for_selector("#palette[open]")
    page.keyboard.type("cache")
    page.keyboard.press("Escape")
    page.hover("#chart-traffic [data-chart-plot]")
    page.hover("#g-kpis .help-dot")
    page.click("#gallery-endpoints [data-dt-sort='p95']")
    page.wait_for_selector("#gallery-endpoints th[data-col='p95'][aria-sort]:not([aria-sort='none'])")
    page.click("[data-dialog-open='dlg-demo-purge']")
    page.keyboard.press("Escape")
    page.fill("#set-cache_ttl_seconds-value", "15m")
    page.wait_for_timeout(600)
    _assert_clean(record, ui_server)
