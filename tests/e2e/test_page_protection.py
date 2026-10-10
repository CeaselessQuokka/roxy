"""The Protection page in a real browser: clean, accessible at both sizes and themes, and its controls work.

What this is
    Browser tests against the real app (`dashboard`, tests/e2e/conftest.py) with Protection data added for this
    module (`protection_data`: rules, lists and bans carrying hostile text, and traffic they refuse; every row is
    removed again afterwards, so later tests of the session see the dashboard as it was). For each theme and size
    the page loads with every lazy card, no console error, page error or CSP violation, axe-core finds nothing
    serious, the phone never scrolls sideways, and a screenshot is saved for the visual review. Then the controls:
    the sub-tabs (mouse and keyboard), a table filter swapping the table in place, a row's drawer with hostile text
    shown as text, adding and removing a request filter through the dialogs, the two testers, the ladder editor and
    restore defaults, Bypass my IP, an inline setting saved on its card, and the emergency limit's dialog.

Why it exists
    The integration tests prove what the server sends; only a browser proves the page works with the strict CSP,
    htmx, the design system's scripts and the page's own script.

What to read next
    tests/e2e/conftest.py (`open_admin`, `AdminPage`), tests/integration/pages/test_page_protection.py.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from roxy.admin.pages.testing import HOSTILE, THEMES, VIEWPORTS, PlannedRequest

PAGE = "/admin/protection"
NO_HOSTILE_MARKUP = """() => !document.querySelector('img[src="x"], [onerror], [onclick], a[href^="javascript:"]')
  && typeof window.__pwned === "undefined\""""
LAZY_DONE = "document.querySelectorAll('.page-card--lazy').length === 0"


@pytest.fixture(scope="module")
def protection_data(dashboard: Any) -> Iterator[dict[str, Any]]:
    """Rules, lists and bans with hostile text, traffic they refuse, and their removal afterwards."""
    made: dict[str, Any] = {}
    removals: list[str] = []

    def add(name: str, path: str, body: dict[str, Any], delete: str) -> None:
        response = dashboard.api("POST", path, json=body)
        assert response.status_code == 200, (name, response.text)
        item = response.json()["item"]
        made[name] = item
        removals.append(delete.format(id=item.get("id")))

    add(
        "ua",
        "protection/ua-rules",
        {"needle": "E2eBot", "kind": "burst", "limit": 2, "period": 60, "note": HOSTILE["img"]},
        "protection/ua-rules/{id}",
    )
    add(
        "filter",
        "protection/header-rules",
        {"needle": "e2e-curl", "note": HOSTILE["script"]},
        "protection/header-rules/{id}",
    )
    add(
        "block",
        "protection/endpoint-blocks",
        {"pattern": "catalog.roblox.com/v1/e2e-blocked", "message": "Blocked " + HOSTILE["img"]},
        "protection/endpoint-blocks/{id}",
    )
    add(
        "rule",
        "protection/endpoint-rules",
        {"pattern": "users.roblox.com/v1/e2e-users", "limit": 1, "period": 60},
        "protection/endpoint-rules/{id}",
    )
    add(
        "ban",
        "protection/bans",
        {"subject_type": "ip", "subject": "198.51.100.177", "minutes": 60, "message": HOSTILE["img"]},
        "protection/bans/{id}",
    )
    add(
        "deny",
        "protection/access/deny",
        {"cidr": "192.0.2.210/32", "note": HOSTILE["script"]},
        "protection/access/deny/{id}",
    )
    plan = [
        PlannedRequest("/catalog.roblox.com/v1/e2e-blocked/1", "203.0.113.190"),
        *(PlannedRequest(f"/users.roblox.com/v1/e2e-users/{i}", "203.0.113.191") for i in range(3)),
        *(
            PlannedRequest("/games.roblox.com/v1/games?universeIds=990", "203.0.113.192", user_agent="E2eBot/1")
            for _ in range(4)
        ),
        PlannedRequest("/games.roblox.com/v1/games?universeIds=991", "198.51.100.177"),
        PlannedRequest("/games.roblox.com/v1/games?universeIds=992", "203.0.113.193", user_agent="e2e-curl/1"),
    ]
    dashboard.send_traffic(plan)
    dashboard.flush()
    try:
        yield made
    finally:
        for path in removals:
            dashboard.api("DELETE", path)


def _cards_loaded(admin: Any) -> None:
    admin.settle()
    admin.wait(LAZY_DONE, timeout=30)


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("size", list(VIEWPORTS))
def test_the_page_is_clean_accessible_and_fits(open_admin: Any, protection_data: Any, theme: str, size: str) -> None:
    width, height = VIEWPORTS[size]
    admin = open_admin(PAGE, theme=theme, width=width, height=height)
    _cards_loaded(admin)
    page = admin.page
    assert page.locator(f'html[data-theme="{theme}"]').count() == 1
    assert page.locator("#pipeline .prot-step").count() >= 10
    assert page.locator('#ua-rules [data-table="ua_rules"] tbody tr[data-row-id]').count() >= 1
    assert page.evaluate(NO_HOSTILE_MARKUP)
    assert page.evaluate("document.querySelectorAll('section.page-card[data-card]').length") >= 27
    assert not admin.overflows(), "the page scrolls sideways"
    assert admin.axe() == []
    admin.shot("protection")
    admin.assert_clean()


def test_sub_tabs_switch_with_the_mouse_and_the_keyboard(open_admin: Any, protection_data: Any) -> None:
    admin = open_admin(PAGE)
    page = admin.page
    page.locator("#endpoint-blocks").scroll_into_view_if_needed()
    admin.wait("document.querySelector('#prot-block-tabs') !== null")
    attempts = page.locator('#prot-block-tabs [role="tab"][data-tab="attempts"]')
    attempts.click()
    assert attempts.get_attribute("aria-selected") == "true"
    assert page.locator("#prot-block-tabs-panel-attempts").is_visible()
    assert not page.locator("#prot-block-tabs-panel-blocks").is_visible()
    assert (
        page.locator('#prot-block-tabs-panel-attempts [data-table="refusal_attempts"] tbody tr[data-row-id]').count()
        >= 1
    )
    page.keyboard.press("ArrowLeft")
    admin.wait("document.activeElement && document.activeElement.dataset.tab === 'blocks'")
    assert page.locator("#prot-block-tabs-panel-blocks").is_visible()
    page.keyboard.press("End")
    admin.wait("document.activeElement && document.activeElement.dataset.tab === 'attempts'")
    admin.assert_clean()


def test_a_table_filter_swaps_only_the_table_in_place(open_admin: Any, protection_data: Any) -> None:
    admin = open_admin(PAGE)
    page = admin.page
    page.locator("#bans").scroll_into_view_if_needed()
    admin.wait("document.querySelector('#prot-bans') !== null")
    page.evaluate("window.__sameDocument = true; document.querySelector('#prot-bans').dataset.old = '1'")
    page.select_option('#prot-bans select[name="state"]', "all")
    admin.wait("document.querySelector('#prot-bans') && !document.querySelector('#prot-bans').dataset.old")
    assert page.locator('#prot-bans select[name="state"]').input_value() == "all"
    assert page.evaluate("document.querySelectorAll('#bans').length") == 1, "a card inside a card"
    assert page.evaluate("document.querySelectorAll('#prot-bans').length") == 1
    assert page.locator("#prot-bans tbody tr[data-row-id]").count() >= 1
    assert page.evaluate("window.__sameDocument === true"), "the filter reloaded the whole page"
    admin.assert_clean()


def test_a_row_opens_its_drawer_with_hostile_text_shown_as_text(open_admin: Any, protection_data: Any) -> None:
    admin = open_admin(PAGE, theme="light")
    page = admin.page
    rule_id = protection_data["ua"]["id"]
    page.locator("#ua-rules").scroll_into_view_if_needed()
    admin.wait(f"document.querySelector('#prot-ua tr[data-row-id=\"ua-{rule_id}\"]') !== null")
    page.locator(f'#prot-ua tr[data-row-id="ua-{rule_id}"] [data-dt-open]').click()
    admin.wait("document.querySelector('#drawer[open] [data-prot-drawer=\"ua\"]') !== null")
    drawer = page.locator("#drawer")
    assert HOSTILE["img"] in drawer.inner_text()  # shown as text
    assert page.evaluate(NO_HOSTILE_MARKUP)
    assert admin.axe() == []
    admin.shot("protection-drawer")
    page.keyboard.press("Escape")
    admin.wait("!document.querySelector('#drawer[open]')")
    admin.assert_clean()


def test_add_a_request_filter_then_remove_it(open_admin: Any, dashboard: Any, protection_data: Any) -> None:
    admin = open_admin(PAGE)
    page = admin.page
    page.locator("#request-filters").scroll_into_view_if_needed()
    admin.wait("document.querySelector('#request-filters [data-action=\"filter-add\"]') !== null")
    page.locator('#request-filters [data-action="filter-add"]').click()
    admin.wait("document.querySelector('#dlg-prot-filter-add[open]') !== null")
    page.fill("#dlg-prot-filter-add-needle", "e2e-added-filter")
    page.fill("#dlg-prot-filter-add-reason", "Browser test")
    page.locator('#dlg-prot-filter-add button[type="submit"]').click()
    admin.wait(
        "document.querySelector('#prot-filters')"
        " && /e2e-added-filter/.test(document.querySelector('#prot-filters').innerText)"
    )
    rules = dashboard.api("GET", "protection/header-rules").json()["items"]
    added = next(rule for rule in rules if rule["needle"] == "e2e-added-filter")
    page.locator(f'#prot-filters tr[data-row-id="filter-{added["id"]}"] [data-dt-open]').click()
    admin.wait("document.querySelector('#drawer[open] [data-prot-drawer=\"header\"]') !== null")
    page.locator('#drawer [data-action="rule-remove"]').click()
    admin.wait(f"document.querySelector('#dlg-prot-rule-del-header-{added['id']}[open]') !== null")
    page.fill(f"#dlg-prot-rule-del-header-{added['id']}-reason", "Browser test cleanup")
    page.locator(f'#dlg-prot-rule-del-header-{added["id"]} button[type="submit"]').click()
    admin.wait("!document.querySelector('#drawer[open]')")
    admin.wait("!/e2e-added-filter/.test(document.querySelector('#prot-filters').innerText)")
    remaining = dashboard.api("GET", "protection/header-rules").json()["items"]
    assert all(rule["needle"] != "e2e-added-filter" for rule in remaining)
    audit = dashboard.api("GET", "audit", params={"q": "e2e-added-filter"}).json()
    assert audit["total"] >= 1
    admin.assert_clean()


def test_the_testers_show_their_verdicts(open_admin: Any, protection_data: Any) -> None:
    admin = open_admin(PAGE)
    page = admin.page
    page.locator("#ua-rules").scroll_into_view_if_needed()
    admin.wait("document.querySelector('#prot-ua-tabs') !== null")
    page.locator('#prot-ua-tabs [role="tab"][data-tab="tester"]').click()
    page.fill("#ua-test-value", "E2eBot/2.0 " + HOSTILE["img"])
    page.locator('#ua-rules [data-action="ua-test"]').click()
    admin.wait("/would be rate-limited/.test(document.querySelector('#ua-rules [data-tester-result]').innerText)")
    assert page.evaluate(NO_HOSTILE_MARKUP)
    page.locator("#request-filters").scroll_into_view_if_needed()
    admin.wait("document.querySelector('#prot-filter-tabs') !== null")
    page.locator('#prot-filter-tabs [role="tab"][data-tab="tester"]').click()
    page.locator("#request-filters [data-tester-example]").click()
    assert "Xeno-Fingerprint" in page.input_value("#filter-test-headers")
    page.locator('#request-filters [data-action="filter-test"]').click()
    admin.wait(
        "/would be allowed through|would be BLOCKED/"
        ".test(document.querySelector('#request-filters [data-tester-result]').innerText)"
    )
    page.fill("#filter-test-headers", "User-Agent: e2e-curl/9")
    page.locator('#request-filters [data-action="filter-test"]').click()
    admin.wait("/would be BLOCKED/.test(document.querySelector('#request-filters [data-tester-result]').innerText)")
    assert admin.axe() == []
    admin.assert_clean()


def test_the_ladder_editor_saves_and_restores_the_defaults(open_admin: Any, dashboard: Any) -> None:
    admin = open_admin(PAGE)
    page = admin.page
    try:
        page.locator("#ladder").scroll_into_view_if_needed()
        admin.wait("document.querySelector('#ladder [data-ladder-form]') !== null")
        assert page.locator("#ladder .prot-timeline li").count() == 5
        page.locator("#ladder [data-ladder-add]").click()
        assert page.locator("#ladder [data-ladder-rows] [data-ladder-row]").count() == 5
        page.fill("#ladder-message-5", "Fifth strike " + HOSTILE["script"])
        page.fill("#ladder-reason", "Browser test")
        page.locator('#ladder [data-action="ladder-save"]').click()
        admin.wait("document.querySelectorAll('#ladder .prot-timeline li').length === 6")
        rungs = dashboard.api("GET", "protection/ladder").json()["rungs"]
        assert len(rungs) == 5
        assert rungs[4]["multiplier"] == 16
        assert page.evaluate(NO_HOSTILE_MARKUP)
        page.locator('#ladder [data-action="ladder-reset"]').click()
        admin.wait("document.querySelector('#dlg-prot-ladder-reset[open]') !== null")
        page.locator('#dlg-prot-ladder-reset button[type="submit"]').click()
        admin.wait("document.querySelectorAll('#ladder .prot-timeline li').length === 5")
        admin.assert_clean()
    finally:
        dashboard.api("POST", "protection/ladder/reset", json={"reason": "browser test cleanup"})


def test_bypass_my_ip_adds_my_address(open_admin: Any, dashboard: Any) -> None:
    admin = open_admin(PAGE)
    page = admin.page
    try:
        page.locator("#bypass").scroll_into_view_if_needed()
        admin.wait("document.querySelector('#bypass [data-action=\"bypass-my-ip\"]') !== null")
        page.locator('#bypass [data-action="bypass-my-ip"]').click()
        admin.wait(
            "document.querySelector('#bypass .prot-me')"
            " && /Bypassed/.test(document.querySelector('#bypass .prot-me').innerText)"
        )
        me = dashboard.api("GET", "protection/access/bypass/me").json()
        assert me["bypassed"] is True
        admin.assert_clean()
    finally:
        for entry in dashboard.api("GET", "protection/access/bypass").json()["items"]:
            dashboard.api("DELETE", f"protection/access/bypass/{entry['id']}")


def test_an_inline_setting_saves_on_its_card(open_admin: Any, dashboard: Any) -> None:
    admin = open_admin(PAGE)
    page = admin.page
    try:
        page.locator("#bypass").scroll_into_view_if_needed()
        admin.wait("document.querySelector('#bypass-settings') !== null")
        page.locator("#bypass-settings > summary").click()
        control = page.locator('#bypass form[data-setting-key="bypass_default_expiry_h"]')
        control.locator("[data-setting-input]").fill("12")
        control.locator('input[name="reason"]').fill("Browser test of an inline setting")
        control.locator('button[type="submit"]').click()
        admin.wait(
            "document.querySelector('#bypass [data-setting-review]') &&"
            " !document.querySelector('#bypass [data-setting-review]').hidden"
        )
        control.locator('button[type="submit"]').click()
        admin.wait("document.querySelector('#bypass .setting__saved') !== null")
        value = dashboard.api("GET", "settings/bypass_default_expiry_h").json()["setting"]["value"]
        assert float(value) == 12
        admin.assert_clean()
    finally:
        dashboard.change_settings({"bypass_default_expiry_h": 24})


def test_the_emergency_limit_card_opens_the_top_bar_dialog(open_admin: Any) -> None:
    admin = open_admin(PAGE, width=390, height=844)
    page = admin.page
    page.locator("#throttle-all").scroll_into_view_if_needed()
    admin.wait("document.querySelector('#throttle-all [data-action=\"throttle-all-toggle\"]') !== null")
    page.locator('#throttle-all [data-action="throttle-all-toggle"]').click()
    admin.wait("document.querySelector('#dlg-throttle-all[open]') !== null")
    assert page.locator('#dlg-throttle-all [data-setting-key="global_throttle_limit"]').count() == 1
    page.keyboard.press("Escape")
    admin.wait("!document.querySelector('#dlg-throttle-all[open]')")
    admin.assert_clean()
