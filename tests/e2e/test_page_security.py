"""The Security page in a real browser: clean, accessible, fits a phone, and its controls work.

What this is
    Browser tests against the real app (`dashboard`, tests/e2e/conftest.py: a free port, an admin signed in through
    the real password and TOTP steps, seeded traffic with hostile text). For each theme and size the page loads with
    no console error, page error or CSP violation, axe-core finds nothing serious, the phone layout never scrolls
    sideways, and a screenshot is saved for the visual review. Then the controls: the probe log's filter swaps only
    its table (never a second copy of the card), the fingerprint tabs work with the mouse and the arrow keys, a
    header opens in the drawer with its values as text, another session is ended, and new recovery codes are shown
    once after "Confirm it is you".

Why it exists
    The integration tests prove what the server sends; only a browser proves the page works under the strict CSP
    with htmx, the dialogs and the page script.

What to read next
    tests/integration/pages/test_page_security.py, roxy/admin/pages/security.py, static/js/pages/security.js.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from pages_harness import SESSION_COOKIE_NAME, THEMES, VIEWPORTS
from roxy.admin.pages import registry

PAGE = "/admin/security"
NO_HOSTILE_MARKUP = """() => !document.querySelector('img[src="x"], [onerror], [onclick], a[href^="javascript:"]')
  && typeof window.__pwned === "undefined\""""
NO_ERROR_CARD = "() => !document.querySelector('[data-card-error]') && !document.querySelector('.page-card--lazy')"
CARD_SHOTS = Path(__file__).resolve().parents[2] / ".remake" / "p11_reports" / "shots" / "g6_cards"


def shoot_cards(admin: Any, page_id: str) -> list[str]:
    """One screenshot per card under `shots/g6_cards/` (the full-page shot of a long page is too small to read);
    each card must have a body. Returns the card ids shot."""
    CARD_SHOTS.mkdir(parents=True, exist_ok=True)
    page = admin.page
    ids: list[str] = page.evaluate("[...document.querySelectorAll('main section[data-card]')].map((s) => s.id)")
    stem = f"{page_id}_{admin.theme}_{admin.width}"
    page.locator("main .page-header").screenshot(path=str(CARD_SHOTS / f"{stem}_header.png"))
    for card_id in ids:
        locator = page.locator(f"main section#{card_id}").first
        locator.scroll_into_view_if_needed()
        admin.settle()
        box = locator.bounding_box()
        assert box is not None, f"{card_id} is not on the page"
        assert box["height"] > 40, f"{card_id} is empty"
        locator.screenshot(path=str(CARD_SHOTS / f"{stem}_{card_id}.png"))
    return ids


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("size", list(VIEWPORTS))
def test_the_page_is_clean_accessible_and_fits(open_admin: Any, theme: str, size: str) -> None:
    width, height = VIEWPORTS[size]
    admin = open_admin(PAGE, theme=theme, width=width, height=height)
    page = admin.page
    assert page.locator(f'html[data-theme="{theme}"]').count() == 1
    assert page.evaluate(NO_ERROR_CARD)
    assert page.locator('#probes [data-table="probes"] tbody tr').count() > 0
    assert page.locator('#fingerprints [data-table="fingerprint_headers"]').count() == 1
    assert page.locator("#admin-access [data-setting-key]").count() > 0
    assert page.evaluate(NO_HOSTILE_MARKUP)
    assert not admin.overflows(), "the page scrolls sideways"
    assert admin.axe() == []
    admin.shot("security")
    ids = shoot_cards(admin, "security")
    assert set(ids) == {card.id for card in registry.cards_for("security")}
    assert not admin.overflows(), "a card scrolls the page sideways"
    admin.assert_clean()


def test_the_probe_filter_swaps_only_its_table(open_admin: Any) -> None:
    admin = open_admin(PAGE)
    page = admin.page
    page.evaluate("window.__sameDocument = true")
    options = page.locator('#probes select[name="signature"] option')
    assert options.count() > 1
    value = options.nth(1).get_attribute("value")
    page.select_option('#probes select[name="signature"]', value)
    admin.wait(f"new URL(location.href).searchParams.get('signature') === {json.dumps(value)}")
    assert page.evaluate("document.querySelectorAll('section#probes').length") == 1
    assert page.evaluate("document.querySelectorAll('#probes-title').length") == 1
    rows = page.locator("#probes tbody tr[data-row-id]")
    assert rows.count() >= 1
    assert all(value in rows.nth(i).inner_text() for i in range(rows.count()))
    assert page.evaluate("window.__sameDocument === true"), "the filter reloaded the whole page"
    admin.assert_clean()


def test_fingerprint_tabs_work_with_the_mouse_and_the_keyboard(open_admin: Any) -> None:
    admin = open_admin(PAGE)
    page = admin.page
    page.locator("#fp-tab-agents").click()
    assert page.locator("#fp-tab-agents").get_attribute("aria-selected") == "true"
    assert page.locator("#fp-panel-agents").is_visible()
    assert page.locator("#fp-panel-headers").is_hidden()
    page.keyboard.press("ArrowRight")
    assert page.evaluate("document.activeElement.id") == "fp-tab-blocked"
    assert page.locator("#fp-panel-blocked").is_visible()
    page.keyboard.press("End")
    assert page.evaluate("document.activeElement.id") == "fp-tab-ignored"
    page.keyboard.press("Home")
    assert page.evaluate("document.activeElement.id") == "fp-tab-headers"
    assert page.locator("#fp-panel-headers").is_visible()
    # A table swap inside a tab answers that table alone.
    page.fill("#fp-headers-q", "agent")
    admin.wait(
        "document.querySelector('#fp-headers .dt__count') && new URL(location.href).pathname === '/admin/security'"
    )
    admin.wait(
        "[...document.querySelectorAll('#fp-headers tbody tr[data-row-id]')].every((r) => /agent/.test(r.innerText))"
    )
    assert page.evaluate("document.querySelectorAll('section#fingerprints').length") == 1
    admin.assert_clean()


def test_a_header_opens_in_the_drawer_with_its_values_as_text(open_admin: Any) -> None:
    admin = open_admin(PAGE, theme="light")
    page = admin.page
    row = page.locator("#fp-headers tbody tr[data-drawer-src]").first
    name = row.locator("td").first.inner_text().strip()
    row.click()
    admin.wait("document.querySelector('#drawer[open] [data-fp-header]') !== null")
    assert page.locator("#drawer-title").inner_text().strip() == f"Header {name}"
    drawer = page.locator("#drawer")
    assert drawer.locator("form[data-api-form]").count() >= 1
    assert page.evaluate(NO_HOSTILE_MARKUP)
    assert admin.axe() == []
    admin.shot("security-drawer")
    CARD_SHOTS.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(CARD_SHOTS / f"security-drawer_{admin.theme}_{admin.width}.png"))  # what the eye sees
    page.keyboard.press("Escape")
    admin.wait("!document.querySelector('#drawer[open]')")
    admin.assert_clean()


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_a_user_agent_opens_its_newest_request_in_the_drawer(open_admin: Any, theme: str) -> None:
    """v1's User-Agent drill-down (gap G1): a User-Agent row opens where its newest request went, its address and the
    header names it sent; caller text stays text and the drawer passes axe."""
    admin = open_admin(PAGE, theme=theme)
    page = admin.page
    page.locator("#fp-tab-agents").click()
    row = page.locator("#fp-agents tbody tr[data-drawer-src]").first
    row.click()
    admin.wait("document.querySelector('#drawer[open] [data-fp-agent]') !== null")
    assert page.locator("#drawer-title").inner_text().strip() == "User-Agent"
    drawer = page.locator("#drawer")
    assert drawer.locator("[data-fp-agent-detail]").count() == 1  # seeded traffic went through the real proxy
    assert drawer.locator(".fp-header-names li").count() >= 1
    assert page.evaluate(NO_HOSTILE_MARKUP)
    assert admin.axe() == []
    page.keyboard.press("Escape")
    admin.wait("!document.querySelector('#drawer[open]')")
    admin.assert_clean()


def test_another_session_is_ended_from_its_row(open_admin: Any, dashboard: Any) -> None:
    other = dashboard.login()  # a second browser signed in as the same admin
    admin = open_admin(PAGE)
    page = admin.page
    before = page.locator("#sessions tr[data-session-row]").count()
    assert before >= 2
    row = page.locator("#sessions tr[data-session-row]:not(.is-current)").first
    row.locator('[data-action="session-end"]').click()
    admin.wait(f"document.querySelectorAll('#sessions tr[data-session-row]').length === {before - 1}")
    assert "That session was ended" in page.locator(".toast").first.inner_text()
    with dashboard.http() as client:
        gone = client.get("/admin/api/v1/auth/session", headers=dashboard.headers(cookie=other.cookie))
    assert gone.status_code == 401
    admin.assert_clean()


def test_new_recovery_codes_are_shown_once_after_the_second_factor(open_admin: Any, dashboard: Any) -> None:
    window = dashboard.api("GET", "settings/admin_reauth_window_s").json()["setting"]["value"]
    dashboard.clock.advance(int(window) + 1)  # the session lives on; its second factor is old
    admin = open_admin(PAGE)
    page = admin.page
    try:
        page.locator('[data-action="recovery-regenerate"]').click()
        admin.wait("document.querySelector('#dlg-recovery-new[open]') !== null")
        page.locator('#dlg-recovery-new button[type="submit"]').click()
        admin.wait("document.querySelector('#reauth[open]') !== null")
        page.fill("#reauth-code", dashboard.next_code())
        page.locator('#reauth button[type="submit"]').click()
        admin.wait("document.querySelectorAll('[data-recovery-list] li').length === 10")
    finally:
        for cookie in page.context.cookies():
            if cookie["name"] == SESSION_COOKIE_NAME:
                dashboard.signed_in.cookie = cookie["value"]
    assert page.locator("[data-recovery-new]").is_visible()
    assert page.locator("[data-recovery-remaining]").inner_text() == "10"
    assert admin.axe() == []
    admin.shot("security-recovery")
    page.locator("#recovery-codes").screenshot(path=str(CARD_SHOTS / "security-recovery_dark_1440_card.png"))
    page.locator("[data-recovery-hide]").click()
    assert page.locator("[data-recovery-list] li").count() == 0
    admin.assert_clean(expected=["status of 403"])  # the first attempt, answered reauth_required
