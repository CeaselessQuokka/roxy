"""The Credential page in a real browser (P11): clean, accessible, never shows the value, and its controls work.

What this is
    Browser tests against the real app (`dashboard`, tests/e2e/conftest.py: a free port, a signed-in admin, seeded
    traffic, a fake credential written at runtime). For each theme and size (1440x900 and 390x844, dark and light)
    the page loads with no console error, page error or CSP violation, axe-core finds nothing serious, the phone
    layout never scrolls sideways, the credential value is nowhere in the page, and a screenshot is saved for the
    visual review. Then the controls: an allowlist row is added through the form (the second factor prompt, then
    the retry), opened in the drawer and removed through its confirm dialog; the tester answers; the replace dialog
    refuses a wrong typed confirmation next to the field.

Why it exists
    Plan C1 and 9.8: the credential is the most sensitive value Roxy holds, and every act on it is deliberate. Only a
    browser proves the forms, dialogs and the second factor prompt work under the strict CSP.

What to read next
    tests/e2e/conftest.py (`open_admin`, `AdminPage`), tests/integration/pages/test_page_credential.py.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from pages_harness import SESSION_COOKIE_NAME, THEMES, VIEWPORTS

PAGE = "/admin/credential"
PATTERN = "economy.roblox.com/v1/user/currency"
NO_HOSTILE_MARKUP = """() => !document.querySelector('img[src="x"], [onerror], [onclick], a[href^="javascript:"]')
  && typeof window.__pwned === "undefined\""""


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("size", list(VIEWPORTS))
def test_the_page_is_clean_accessible_and_fits(open_admin: Any, dashboard: Any, theme: str, size: str) -> None:
    width, height = VIEWPORTS[size]
    admin = open_admin(PAGE, theme=theme, width=width, height=height)
    page = admin.page
    assert page.locator(f'html[data-theme="{theme}"]').count() == 1
    assert page.locator(".page-card--lazy").count() == 0
    assert page.locator("[data-card-error]").count() == 0
    assert page.locator('#allowlist [data-table="credential_allowlist"]').count() == 1
    assert page.locator('#status [data-setting-key="credential_enabled"]').count() == 1
    assert page.evaluate(NO_HOSTILE_MARKUP)
    assert not admin.overflows(), "the page scrolls sideways"
    assert dashboard.ctx.egress.credential.status().masked in page.locator("#status").inner_text()
    assert admin.axe() == []
    admin.shot("credential")
    admin.assert_clean()


def _toast(admin: Any, text: str) -> None:
    admin.wait(f"[...document.querySelectorAll('.toast')].some((t) => t.textContent.includes({json.dumps(text)}))")


def _keep_session(page: Any, dashboard: Any) -> None:
    """A fresh second factor rotates the session cookie (fixation defense): hand the new one back to the fixture."""
    for cookie in page.context.cookies():
        if cookie["name"] == SESSION_COOKIE_NAME:
            dashboard.signed_in.cookie = cookie["value"]


def _stale_factor(dashboard: Any) -> None:
    window = dashboard.api("GET", "settings/admin_reauth_window_s").json()["setting"]["value"]
    dashboard.clock.advance(int(window) + 1)  # the session lives on (idle timeout 900 s); its factor is old


def test_an_allowlist_row_is_added_after_the_second_factor_then_removed_in_its_drawer(
    open_admin: Any, dashboard: Any
) -> None:
    _stale_factor(dashboard)
    admin = open_admin(PAGE)
    page = admin.page
    try:
        page.locator("#allowlist details.g3-add > summary").click()
        page.fill("#allow-new-pattern", PATTERN)
        page.locator('#allowlist input[name="cache_private"][value="true"]').check()
        page.fill("#allow-new-reason", "Browser test of the allowlist form")
        page.locator('[data-action="allowlist-add"]').click()
        admin.wait("document.querySelector('#reauth[open]') !== null")
        assert admin.axe() == []
        page.fill("#reauth-code", dashboard.next_code())
        page.locator('#reauth button[type="submit"]').click()
        _toast(admin, "Row added")
        _keep_session(page, dashboard)
        admin.wait("document.querySelector('#allowlist tr[data-row-id^=\"allow-\"]') !== null")
        row = page.locator('#allowlist tr[data-row-id^="allow-"]').first
        assert PATTERN in row.inner_text()
        assert "Private" in row.inner_text()
        row.locator("[data-dt-open]").click()
        admin.wait("document.querySelector('#drawer[open] [data-allowlist-row]') !== null")
        assert admin.axe() == []
        admin.shot("credential-drawer")
        page.locator('#drawer [data-dialog-open="dlg-allow-delete"]').click()
        admin.wait("document.querySelector('#dlg-allow-delete[open]') !== null")
        page.fill("#dlg-allow-delete-reason", "Browser test cleanup")
        page.locator('#dlg-allow-delete button[type="submit"]').click()
        _toast(admin, "Row removed")
        admin.wait("!document.querySelector('#drawer[open]')")
        admin.wait("document.querySelector('#allowlist').textContent.includes('No endpoint may use the credential')")
        assert dashboard.api("GET", "credential-allowlist").json()["total"] == 0
        admin.assert_clean(expected=["status of 403"])  # the first attempt, answered reauth_required
    finally:
        _keep_session(page, dashboard)
        for item in dashboard.api("GET", "credential-allowlist").json()["items"]:
            dashboard.api("DELETE", f"credential-allowlist/{item['id']}", json={"reason": "e2e cleanup"})


def test_the_tester_says_whether_a_path_may_use_the_credential(open_admin: Any) -> None:
    admin = open_admin(PAGE, theme="light", width=390, height=844)
    page = admin.page
    page.fill("#allowlist-test-target", "users.roblox.com/v1/users/authenticated")
    page.locator('[data-action="allowlist-test"]').click()
    admin.wait("document.querySelector('#allowlist-test-result').textContent.includes('never uses the credential')")
    assert not admin.overflows()
    admin.assert_clean()


def test_the_replace_dialog_refuses_a_wrong_typed_confirmation_next_to_the_field(
    open_admin: Any, dashboard: Any
) -> None:
    before = dashboard.ctx.egress.credential.status().fingerprint
    admin = open_admin(PAGE)
    page = admin.page
    try:
        page.locator('[data-action="credential-replace"]').click()
        admin.wait("document.querySelector('#dlg-credential-replace[open]') !== null")
        assert admin.axe() == []
        page.fill("#dlg-credential-replace-value", "BROWSERTEST" + "A1B2C3D4" * 12)
        page.fill("#dlg-credential-replace-confirm", "yes please")
        page.locator('#dlg-credential-replace button[type="submit"]').click()
        shown = "document.querySelector('#dlg-credential-replace [data-field-error=\"confirm\"]:not([hidden])')"
        state = admin.wait(f"document.querySelector('#reauth[open]') ? 'reauth' : ({shown} ? 'error' : '')")
        if state == "reauth":
            page.fill("#reauth-code", dashboard.next_code())
            page.locator('#reauth button[type="submit"]').click()
            admin.wait(shown)
        error = page.locator('#dlg-credential-replace [data-field-error="confirm"]').inner_text()
        assert "replace the credential" in error
        assert page.locator("#dlg-credential-replace-confirm").get_attribute("aria-invalid") == "true"
        assert page.locator("#dlg-credential-replace[open]").count() == 1  # nothing was replaced; the dialog stays
        assert dashboard.ctx.egress.credential.status().fingerprint == before
        page.keyboard.press("Escape")
        admin.assert_clean(expected=["status of 403", "status of 422"])
    finally:
        _keep_session(page, dashboard)
