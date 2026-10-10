"""The dashboard shell in a real browser (P11 core): every page's frame, the controls in it, and the shared flows.

What this is
    Browser tests against the real app (`dashboard`, tests/e2e/conftest.py) for what every page shares: a page
    nobody has built yet renders its "coming soon" body cleanly (no console error, page error or CSP violation,
    axe clean in both themes at both sizes, no sideways scroll on a phone); the command palette jumps to a page and
    offers the LLM export actions; the pause dialog pauses and resumes the proxy through the API; the inline editor
    of `pause_message_default` in that dialog reviews and saves the setting; the preferences dialog saves the
    admin's own preferences; and a change that needs a fresh second factor asks for the code ("Confirm it is you")
    and then goes through, on the reference page's revert form.

Why it exists
    The page builders reuse all of this without touching it; these tests are what lets them trust it.

What to read next
    tests/e2e/test_page_audit.py, static/js/api_forms.js, static/js/settings_api.js, static/js/reauth.js.
"""

from __future__ import annotations

from typing import Any

import pytest

from roxy.admin.pages import registry
from roxy.admin.pages.testing import SESSION_COOKIE_NAME, THEMES, VIEWPORTS


def _unbuilt_page() -> str:
    for spec in registry.PAGES:
        if not registry.is_built(spec.id):
            return spec.id
    pytest.skip("every page is built")


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("size", list(VIEWPORTS))
def test_a_page_not_built_yet_is_a_clean_coming_soon_page(open_admin: Any, theme: str, size: str) -> None:
    page_id = _unbuilt_page()
    width, height = VIEWPORTS[size]
    admin = open_admin(f"/admin/{page_id}", theme=theme, width=width, height=height)
    assert admin.page.locator("[data-coming-soon]").count() == 1
    assert admin.page.locator("h1").first.inner_text().strip() == registry.page(page_id).title
    assert not admin.overflows(), "the page scrolls sideways"
    assert admin.axe() == []
    admin.shot("coming-soon")
    admin.assert_clean()


def test_the_palette_jumps_to_a_page_and_offers_the_llm_export(open_admin: Any) -> None:
    admin = open_admin("/admin/overview")
    page = admin.page
    page.keyboard.press("Control+k")
    admin.wait("document.querySelector('#palette[open]') !== null")
    for item in ("#pal-act-llm-copy", "#pal-act-llm-json", "#pal-act-llm-schema", "#pal-act-health"):
        assert page.locator(item).count() == 1, item
    assert page.locator("#pal-act-llm-copy").get_attribute("data-url") == "/admin/api/v1/export/llm?format=text"
    page.keyboard.type("audit")
    admin.wait("document.querySelector('#pal-page-audit') && !document.querySelector('#pal-page-audit').hidden")
    page.keyboard.press("Enter")
    page.wait_for_url("**/admin/audit")
    admin.settle()
    admin.assert_clean()


def test_copy_for_llm_puts_the_summary_on_the_clipboard(open_admin: Any, dashboard: Any) -> None:
    admin = open_admin("/admin/audit")
    page = admin.page
    page.context.grant_permissions(["clipboard-read", "clipboard-write"], origin=dashboard.base_url)
    page.keyboard.press("Control+k")
    admin.wait("document.querySelector('#palette[open]') !== null")
    page.keyboard.type("copy for llm")
    page.locator("#pal-act-llm-copy").click()
    admin.wait("document.querySelector('.toast') !== null")
    text = page.evaluate("navigator.clipboard.readText()")
    assert len(text) > 100
    assert "Roxy" in text
    admin.assert_clean()


def test_the_pause_dialog_pauses_and_resumes_through_the_api(open_admin: Any, dashboard: Any) -> None:
    admin = open_admin("/admin/audit")
    page = admin.page
    try:
        page.locator(".topbar__pause").click()
        admin.wait("document.querySelector('#dlg-pause[open]') !== null")
        assert admin.axe() == []
        page.fill("#dlg-pause-message", "Back after a short test")
        with page.expect_navigation():
            page.locator('#dlg-pause .dialog__foot button[type="submit"]').click()
        admin.settle()
        assert dashboard.api("GET", "protection/pause").json()["paused"] is True
        assert "Resume" in page.locator(".topbar__pause").inner_text()
        assert "Back after a short test" in page.locator("body").inner_text()  # the pause banner
        page.locator(".topbar__pause").click()
        admin.wait("document.querySelector('#dlg-pause[open]') !== null")
        with page.expect_navigation():
            page.locator('#dlg-pause .dialog__foot button[type="submit"]').click()
        admin.settle()
        assert dashboard.api("GET", "protection/pause").json()["paused"] is False
        admin.assert_clean()
    finally:
        dashboard.api("POST", "protection/pause", json={"paused": False})


def test_the_inline_default_message_editor_reviews_then_saves(open_admin: Any, dashboard: Any) -> None:
    admin = open_admin("/admin/audit")
    page = admin.page
    page.locator(".topbar__pause").click()
    admin.wait("document.querySelector('#dlg-pause[open]') !== null")
    page.locator("#dlg-pause details.dialog__extra > summary").click()
    control = page.locator('#dlg-pause form[data-setting-key="pause_message_default"]')
    control.locator("[data-setting-input]").fill("Roxy is resting for a moment, try again soon.")
    control.locator('input[name="reason"]').fill("Browser test of the inline editor")
    control.locator('button[type="submit"]').click()
    admin.wait(
        "document.querySelector('#dlg-pause [data-setting-review]') &&"
        " !document.querySelector('#dlg-pause [data-setting-review]').hidden"
    )
    assert "Roxy is resting" in control.locator("[data-setting-review]").inner_text()
    assert control.locator("[data-setting-submit-label]").inner_text().strip() == "Save"
    control.locator('button[type="submit"]').click()
    admin.wait("document.querySelector('#dlg-pause .setting__saved') !== null")
    saved = dashboard.api("GET", "settings/pause_message_default").json()["setting"]
    assert saved["value"] == "Roxy is resting for a moment, try again soon."
    admin.assert_clean()


def test_the_preferences_dialog_saves_my_preferences(open_admin: Any, dashboard: Any) -> None:
    admin = open_admin("/admin/audit")
    page = admin.page
    page.locator(".topbar [data-dialog-open='preferences']").first.dispatch_event("click")
    admin.wait("document.querySelector('#preferences[open]') !== null")
    assert admin.axe() == []
    page.select_option("#pref-range", "7d")
    page.fill("#pref-tz", "America/New_York")
    page.locator('#preferences button[type="submit"]').first.click()
    admin.wait("document.querySelector('.toast') !== null")
    prefs = dashboard.api("GET", "prefs").json()["prefs"]
    assert prefs["default_range"] == "7d"
    assert prefs["timezone"] == "America/New_York"
    admin.assert_clean()
    dashboard.api("DELETE", "prefs/default_range")
    dashboard.api("DELETE", "prefs/timezone")


def test_a_change_that_needs_a_fresh_second_factor_asks_for_it_then_goes_through(
    open_admin: Any, dashboard: Any
) -> None:
    dashboard.change_settings({"admin_login_max_failures": 6})
    changes = dashboard.api(
        "GET", "audit", params={"action": "setting.update", "target": "setting:admin_login_max_failures"}
    ).json()
    entry_id = changes["items"][0]["id"]
    window = dashboard.api("GET", "settings/admin_reauth_window_s").json()["setting"]["value"]
    dashboard.clock.advance(int(window) + 1)  # the session lives on (idle timeout 900 s); its factor is old
    admin = open_admin(f"/admin/audit?entry={entry_id}")
    page = admin.page
    try:
        admin.wait("document.querySelector('#drawer[open] form.audit-revert') !== null")
        page.fill("#drawer form.audit-revert textarea[name=reason]", "Undo the test change")
        page.locator('#drawer [data-action="audit-revert"]').click()
        admin.wait("document.querySelector('#reauth[open]') !== null")
        assert admin.axe() == []
        page.fill("#reauth-code", dashboard.next_code())
        page.locator('#reauth button[type="submit"]').click()
        admin.wait("document.querySelector('.toast') && /Reverted/.test(document.body.innerText)")
    finally:
        # A fresh second factor rotates the session (fixation defense): the browser holds the new cookie now, and
        # the old one the dashboard fixture used is gone, so the fixture takes the new one for later tests.
        for cookie in page.context.cookies():
            if cookie["name"] == SESSION_COOKIE_NAME:
                dashboard.signed_in.cookie = cookie["value"]
    value = dashboard.api("GET", "settings/admin_login_max_failures").json()["setting"]["value"]
    assert int(value) == 5
    admin.assert_clean(expected=["status of 403"])  # the first attempt, answered reauth_required
