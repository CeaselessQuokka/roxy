"""The Upstream page in a real browser (P11): clean, accessible, and its controls work.

What this is
    Browser tests against the real app (`dashboard`, tests/e2e/conftest.py: a free port, a signed-in admin, seeded
    traffic with hostile text, a Roblox 429 and a 503). For each theme and size (1440x900 and 390x844, dark and
    light) the page loads with every deferred card, with no console error, page error or CSP violation, axe-core
    finds nothing serious, the phone layout never scrolls sideways, and a screenshot is saved for the visual review.
    Then the controls: the failures filter swaps the table in place and keeps the address, a failure row opens its
    last detail in the drawer, a bucket row opens its history and override in the drawer, a routing rule is added,
    tested and deleted through the forms and the confirm dialog, the trace explains a real request, the reset
    dialog clears cooldowns with a reason, and an inline breaker setting is reviewed and saved.

Why it exists
    The integration tests prove what the server sends; only a browser proves the page works under the strict CSP
    with htmx, the drawer, the dialogs and the design system's scripts.

What to read next
    tests/e2e/conftest.py (`open_admin`, `AdminPage`), tests/integration/pages/test_page_upstream.py.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from pages_harness import THEMES, VIEWPORTS, PlannedRequest, request_headers

PAGE = "/admin/upstream"
NO_HOSTILE_MARKUP = """() => !document.querySelector('img[src="x"], [onerror], [onclick], a[href^="javascript:"]')
  && typeof window.__pwned === "undefined\""""
FAILURE_COUNT = "document.querySelector('#failures .dt__count').textContent.trim()"
TOO_MANY = PlannedRequest("/thumbnails.roblox.com/v1/too-many?size=150x150", "203.0.113.91")
E2E_PATTERN = "games.roblox.com/v1/e2e/*"


def _too_many(dashboard: Any) -> str:
    """One request Roblox answers 429 (it opens a cooldown); returns its Roxy-Request-Id."""
    with dashboard.http() as client:
        response = client.get(TOO_MANY.path, headers=request_headers(TOO_MANY))
    dashboard.flush()
    return str(response.headers["Roxy-Request-Id"])


def _toast(admin: Any, text: str) -> None:
    admin.wait(f"[...document.querySelectorAll('.toast')].some((t) => t.textContent.includes({json.dumps(text)}))")


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("size", list(VIEWPORTS))
def test_the_page_is_clean_accessible_and_fits(open_admin: Any, theme: str, size: str) -> None:
    width, height = VIEWPORTS[size]
    admin = open_admin(PAGE, theme=theme, width=width, height=height)
    page = admin.page
    assert page.locator(f'html[data-theme="{theme}"]').count() == 1
    assert page.locator(".page-card--lazy").count() == 0, "a deferred card did not load"
    assert page.locator("[data-card-error]").count() == 0
    assert page.locator('#failures [data-table="upstream_failures"]').count() == 1
    assert page.locator("#health .g3-egress").count() == 3
    assert page.locator('#breakers [data-setting-key="breaker_open_s"]').count() == 1
    assert page.evaluate(NO_HOSTILE_MARKUP)
    assert not admin.overflows(), "the page scrolls sideways"
    assert admin.axe() == []
    admin.shot("upstream")
    admin.assert_clean()


def test_the_failures_filter_swaps_the_table_in_place_and_a_row_opens_its_detail(open_admin: Any) -> None:
    admin = open_admin(PAGE)
    page = admin.page
    page.evaluate("window.__sameDocument = true")
    everything = page.evaluate(FAILURE_COUNT)
    page.select_option('#failures select[name="egress"]', "rotator")
    admin.wait(f"{FAILURE_COUNT} !== {json.dumps(everything)}")
    assert "egress=rotator" in page.url  # the main table keeps its state in the address
    assert page.locator("#failures tbody tr[data-row-id]").count() == 0
    assert "No failed requests in this range" in page.locator("#failures").inner_text()
    admin.wait("document.querySelector('#failures-summary').textContent.includes('rotator egress')")
    assert page.locator("#failures-summary").inner_text().startswith("0 failed requests")
    page.select_option('#failures select[name="egress"]', "")
    admin.wait(f"{FAILURE_COUNT} === {json.dumps(everything)}")
    assert page.locator("#failures [data-table]").count() == 1, "the table was nested in itself"
    first = page.locator("#failures tbody tr[data-row-id] [data-dt-open]").first
    first.click()
    admin.wait("document.querySelector('#drawer[open] #drawer-body dl') !== null")
    details = page.locator("#drawer-body").inner_text()
    assert "Last path" in details
    assert "Reason" in details
    assert page.evaluate(NO_HOSTILE_MARKUP)
    page.keyboard.press("Escape")
    admin.wait("!document.querySelector('#drawer[open]')")
    assert page.evaluate("window.__sameDocument === true"), "the table reloaded the whole page"
    admin.assert_clean()


def test_a_bucket_row_opens_its_history_and_override_in_the_drawer(open_admin: Any) -> None:
    admin = open_admin(PAGE, theme="light")
    page = admin.page
    row = page.locator('#buckets tr[data-row-id^="bucket-endpoint:"]').first
    key = str(row.get_attribute("data-row-id")).removeprefix("bucket-")
    row.locator("[data-dt-open]").click()
    admin.wait("document.querySelector('#drawer[open] [data-bucket-drawer]') !== null")
    drawer = page.locator("#drawer")
    assert key in drawer.inner_text()
    assert page.locator("#drawer-title").inner_text().strip() == f"Bucket {key}"
    assert drawer.locator("[data-chart]").count() == 1
    assert drawer.locator('form[data-api-form] input[name="per_min"]').count() == 1
    assert admin.axe() == []
    admin.shot("upstream-bucket-drawer")
    page.keyboard.press("Escape")
    admin.wait("!document.querySelector('#drawer[open]')")
    admin.assert_clean()


def test_a_routing_rule_is_added_tested_and_deleted_through_the_forms(open_admin: Any, dashboard: Any) -> None:
    admin = open_admin(PAGE)
    page = admin.page
    try:
        page.locator("#routing details.g3-add > summary").click()
        page.fill("#routing-new-pattern", E2E_PATTERN)
        page.select_option("#routing-new-mode", "prefer_direct")
        page.fill("#routing-new-reason", "Browser test of the routing form")
        page.locator('[data-action="routing-rule-add"]').click()
        _toast(admin, "Routing rule added")
        admin.wait("document.querySelector('#routing tr[data-row-id^=\"routing-\"]') !== null")
        row = page.locator('#routing tr[data-row-id^="routing-"]').first
        rule_id = str(row.get_attribute("data-row-id")).removeprefix("routing-")
        page.fill("#routing-test-target", "games.roblox.com/v1/e2e/abc")
        page.locator('[data-action="routing-test"]').click()
        admin.wait(f"document.querySelector('#routing-test-result').textContent.includes('Rule #{rule_id}')")
        assert "Prefer direct" in page.locator("#routing-test-result").inner_text()
        row.locator("[data-dt-open]").click()
        admin.wait("document.querySelector('#drawer[open] [data-routing-rule]') !== null")
        page.locator('#drawer [data-dialog-open="dlg-routing-delete"]').click()
        admin.wait("document.querySelector('#dlg-routing-delete[open]') !== null")
        assert admin.axe() == []
        page.fill("#dlg-routing-delete-reason", "Browser test cleanup")
        page.locator('#dlg-routing-delete button[type="submit"]').click()
        _toast(admin, "Rule deleted")
        admin.wait("!document.querySelector('#drawer[open]') && !document.querySelector('#dlg-routing-delete[open]')")
        admin.wait("document.querySelector('#routing tr[data-row-id^=\"routing-\"]') === null")
        assert dashboard.api("GET", "routing-rules").json()["total"] == 0
        admin.assert_clean()
    finally:
        for item in dashboard.api("GET", "routing-rules").json()["items"]:
            dashboard.api("DELETE", f"routing-rules/{item['id']}", json={"reason": "e2e cleanup"})


def test_the_trace_explains_a_real_request(open_admin: Any, dashboard: Any) -> None:
    request_id = _too_many(dashboard)
    admin = open_admin(PAGE)
    page = admin.page
    page.fill("#trace-request-id", request_id)
    page.locator('[data-action="upstream-trace"]').click()
    admin.wait("document.querySelectorAll('#trace .g3-reasons li').length > 0")
    text = page.locator("#trace").inner_text()
    assert "thumbnails.roblox.com/v1/too-many" in text
    assert page.locator("#trace .g3-trace__link a").get_attribute("href") == f"{PAGE}?request_id={request_id}#trace"
    page.fill("#trace-request-id", "not a request id")
    page.locator('[data-action="upstream-trace"]').click()
    admin.wait("document.querySelector('#trace-request-id[aria-invalid=\"true\"]') !== null")
    assert page.locator("#trace-request-id-error").is_visible()
    admin.assert_clean()


def test_the_reset_dialog_clears_cooldowns_with_a_reason(open_admin: Any, dashboard: Any) -> None:
    keys = ("cooldown_min_s", "cooldown_default_s")
    before = {key: dashboard.api("GET", f"settings/{key}").json()["setting"]["value"] for key in keys}
    dashboard.change_settings(dict.fromkeys(keys, 120))  # the stand-in's Retry-After (5 s) would end it too soon
    try:
        _too_many(dashboard)
        admin = open_admin(PAGE, width=390, height=844)
        page = admin.page
        assert "thumbnails.roblox.com/v1/too-many" in page.locator("#cooldowns").inner_text()
        page.locator('#cooldowns [data-action="upstream-reset"]').click()
        admin.wait("document.querySelector('#dlg-upstream-reset[open]') !== null")
        assert admin.axe() == []
        page.fill("#dlg-upstream-reset-reason", "Browser test of the reset dialog")
        page.locator('#dlg-upstream-reset button[type="submit"]').click()
        _toast(admin, "Cooldowns and breakers cleared")
        admin.wait("document.querySelector('#cooldowns').textContent.includes('No cooldowns are open')")
        assert dashboard.api("GET", "upstream/cooldowns").json()["items"] == []
        resets = dashboard.api("GET", "audit", params={"action": "upstream.reset_state"}).json()
        assert resets["total"] >= 1
        admin.assert_clean()
    finally:
        dashboard.change_settings(before)


def test_an_inline_breaker_setting_is_reviewed_and_saved(open_admin: Any, dashboard: Any) -> None:
    before = dashboard.api("GET", "settings/breaker_open_s").json()["setting"]["value"]
    target = 45 if int(before) != 45 else 50
    try:
        admin = open_admin(PAGE)
        page = admin.page
        page.locator("#breakers-settings > summary").click()
        control = page.locator('#breakers form[data-setting-key="breaker_open_s"]')
        control.scroll_into_view_if_needed()
        control.locator("[data-setting-input]").fill(f"{target}s")
        control.locator('input[name="reason"]').fill("Browser test of the breakers card")
        control.locator('button[type="submit"]').click()
        admin.wait(
            '(() => { const r = document.querySelector(\'#breakers [data-setting-key="breaker_open_s"] '
            "[data-setting-review]'); return r && !r.hidden; })()"
        )
        control.locator('button[type="submit"]').click()
        admin.wait("document.querySelector('#breakers .setting__saved') !== null")
        assert dashboard.api("GET", "settings/breaker_open_s").json()["setting"]["value"] == target
        admin.assert_clean()
    finally:
        dashboard.change_settings({"breaker_open_s": before})
