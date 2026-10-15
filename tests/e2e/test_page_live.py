"""The Live page in a real browser (P11): the tail streams, pauses, filters and opens a request; capture settings save.

What this is
    Browser tests against the real app (`dashboard`: a free port, a signed-in admin, seeded traffic with hostile
    places and User-Agents). Each test first sends a few fresh requests through the real proxy, so the live records
    (kept 15 minutes) are there whatever ran before in the session. For each theme and size (1440x900 and 390x844,
    dark and light) the page fills its tail from the event stream with no console error, page error or CSP
    violation, no axe finding, no sideways scroll on a phone, and a screenshot for the visual review. Then the
    interactions: Pause holds new rows (counted as waiting) and Resume shows them, the outcome filter narrows the
    list, a row opens its request in the drawer (record, trace, capture), the address's filters and `?request=<id>`
    land where they point, and the capture card's inline setting reviews and saves through the settings API.

Why it exists
    Only a browser proves the stream, the virtual list and the drawer work together under the strict CSP.

What to read next
    tests/e2e/conftest.py (`open_admin`, `AdminPage`), tests/integration/pages/test_page_live.py,
    static/js/live_tail.js.
"""

from __future__ import annotations

from typing import Any

import pytest

from pages_harness import DOC_NETS, THEMES, VIEWPORTS, PlannedRequest

PAGE = "/admin/live"
TAIL = "#live-tail"
SHOWN = f"document.querySelectorAll('{TAIL} .tail__row:not([hidden])').length"
NO_HOSTILE_MARKUP = """() => !document.querySelector(
    'img[src="x"], [onerror], [onclick], [onfocus], a[href^="javascript:"]'
  ) && typeof window.__pwned === "undefined\""""


def _fresh(dashboard: Any, count: int = 3, first: int = 300) -> None:
    """A few served requests through the real proxy, so the live records are recent."""
    plan = [
        PlannedRequest(f"/users.roblox.com/v1/users/{first + i}", f"{DOC_NETS[1]}.{60 + i}", note="live e2e")
        for i in range(count)
    ]
    dashboard.send_traffic(plan)


def _streaming(admin: Any) -> None:
    admin.wait(f"{SHOWN} > 0", timeout=20)
    admin.wait(f"document.querySelector('{TAIL}').dataset.state === 'live'", timeout=20)


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("size", list(VIEWPORTS))
def test_the_page_is_clean_accessible_and_fits(open_admin: Any, dashboard: Any, theme: str, size: str) -> None:
    _fresh(dashboard)
    width, height = VIEWPORTS[size]
    admin = open_admin(PAGE, theme=theme, width=width, height=height)
    _streaming(admin)
    assert admin.page.locator('#capture [data-setting-key="capture_enabled"]').count() == 1
    assert admin.page.evaluate(NO_HOSTILE_MARKUP)
    assert not admin.overflows(), "the page scrolls sideways"
    assert admin.axe() == []
    admin.shot("live")
    admin.assert_clean()


def test_pause_holds_new_rows_and_resume_shows_them(open_admin: Any, dashboard: Any) -> None:
    _fresh(dashboard, first=320)
    admin = open_admin(PAGE)
    page = admin.page
    _streaming(admin)
    pause = page.locator(f"{TAIL} [data-tail-pause]")
    pause.click()
    admin.wait(f"document.querySelector('{TAIL}').dataset.state === 'paused'")
    assert pause.get_attribute("aria-pressed") == "true"
    before = page.evaluate(f"document.querySelector('{TAIL} [data-tail-count]').textContent")
    shown = page.evaluate(SHOWN)
    _fresh(dashboard, count=2, first=340)
    admin.wait(f"document.querySelector('{TAIL} [data-tail-count]').textContent.includes('waiting')", timeout=20)
    assert "waiting" not in before
    assert page.evaluate(SHOWN) == shown  # held while paused: the list does not move
    pause.click()
    admin.wait(f"document.querySelector('{TAIL}').dataset.state === 'live'")
    admin.wait(f"!document.querySelector('{TAIL} [data-tail-count]').textContent.includes('waiting')")
    assert _rows_counted(page) >= _count_of(before) + 2  # the held rows joined the list
    admin.assert_clean()


def _count_of(text: str) -> int:
    return int(text.split(" row", 1)[0].replace(",", ""))


def _rows_counted(page: Any) -> int:
    return _count_of(str(page.evaluate(f"document.querySelector('{TAIL} [data-tail-count]').textContent")))


def test_the_outcome_filter_narrows_the_list_and_a_row_opens_its_request(open_admin: Any, dashboard: Any) -> None:
    _fresh(dashboard, first=360)
    dashboard.send_traffic([PlannedRequest("/wp-login.php", f"{DOC_NETS[2]}.70", user_agent="curl/8.0", note="probe")])
    admin = open_admin(PAGE, theme="light")
    page = admin.page
    _streaming(admin)
    page.select_option(f'{TAIL} select[data-tail-filter="outcome"]', "refused")
    admin.wait(f"{SHOWN} > 0")
    outcomes = page.locator(f"{TAIL} .tail__row:not([hidden]) .tail__outcome").all_inner_texts()
    assert outcomes
    assert all(text == "Refused" for text in outcomes), outcomes
    page.select_option(f'{TAIL} select[data-tail-filter="outcome"]', "served_upstream")
    admin.wait(
        f"Array.from(document.querySelectorAll('{TAIL} .tail__row:not([hidden]) .tail__outcome'))"
        ".every((n) => n.textContent === 'Served by Roblox')"
    )
    page.locator(f"{TAIL} .tail__row:not([hidden])").first.click()
    admin.wait("document.querySelector('#drawer[open] [data-live-request]') !== null")
    drawer = page.locator("#drawer")
    text = drawer.inner_text()
    assert "Served by Roblox" in text
    assert "Why did this request wait?" in text
    assert "Captured request and answer" in text
    assert page.evaluate(NO_HOSTILE_MARKUP)
    assert admin.axe() == []
    admin.shot("live-drawer")
    page.keyboard.press("Escape")
    admin.wait("!document.querySelector('#drawer[open]')")
    admin.assert_clean()


def test_the_address_filters_and_a_request_link_land_where_they_point(open_admin: Any, dashboard: Any) -> None:
    _fresh(dashboard, first=380)
    newest = dashboard.api("GET", "live", params={"limit": 1}).json()["items"][0]
    admin = open_admin(f"{PAGE}?outcome=served_upstream&endpoint=users.roblox.com&request={newest['request_id']}")
    page = admin.page
    admin.wait(f"document.querySelector('#drawer[open] [data-live-request=\"{newest['request_id']}\"]') !== null")
    admin.wait(f"document.querySelector('{TAIL} select[data-tail-filter=\"outcome\"]').value === 'served_upstream'")
    assert page.locator(f'{TAIL} input[data-tail-filter="endpoint"]').input_value() == "users.roblox.com"
    page.keyboard.press("Escape")
    admin.wait("!document.querySelector('#drawer[open]')")
    admin.wait(f"{SHOWN} > 0", timeout=20)
    endpoints = page.locator(f"{TAIL} .tail__row:not([hidden]) .tail__endpoint").all_inner_texts()
    assert endpoints
    assert all("users.roblox.com" in text for text in endpoints), endpoints
    admin.assert_clean()


def test_the_capture_setting_reviews_then_saves_inline(open_admin: Any, dashboard: Any) -> None:
    key = "capture_sample_served_pct"
    before = dashboard.api("GET", f"settings/{key}").json()["setting"]["value"]
    wanted = 35 if before != 35 else 40
    try:
        admin = open_admin(PAGE)
        page = admin.page
        control = page.locator(f'#capture form[data-setting-key="{key}"]')
        control.scroll_into_view_if_needed()
        control.locator("[data-setting-input]").first.fill(str(wanted))
        control.locator('input[name="reason"]').fill("Browser test of the capture sample")
        control.locator('button[type="submit"]').click()
        admin.wait(
            f"document.querySelector('#capture form[data-setting-key=\"{key}\"] [data-setting-review]') && "
            f"!document.querySelector('#capture form[data-setting-key=\"{key}\"] [data-setting-review]').hidden"
        )
        control.locator('button[type="submit"]').click()
        admin.wait(f"document.querySelector('#capture [data-setting-key=\"{key}\"] .setting__saved') !== null")
        saved = dashboard.api("GET", f"settings/{key}").json()["setting"]["value"]
        assert saved == wanted
        admin.assert_clean()
    finally:
        dashboard.change_settings({key: before})
