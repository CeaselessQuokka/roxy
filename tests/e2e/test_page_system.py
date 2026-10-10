"""The System page in a real browser: clean, accessible, and its tables, drawer and actions work.

What this is
    Browser tests against the real app (`dashboard`, tests/e2e/conftest.py) with an error log seeded through the
    recorder (one signature carrying hostile text). For each theme and size (1440x900 and 390x844, dark and light) the
    page loads with every lazy card, no console error, page error or CSP violation, axe-core finds nothing serious,
    the phone never scrolls sideways, and a screenshot is saved for the visual review. Then the controls: the error
    log's search and source filter swap the table in place and keep the address, a row opens its traceback in the
    drawer as text, "Reset request counts" asks first and then resets, and the forced flush says it worked.

Why it exists
    The integration tests prove what the server sends; only a browser proves the page works with the strict CSP,
    htmx and the design system's scripts.

What to read next
    tests/integration/pages/test_page_system.py, roxy/admin/pages/system.py.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from roxy.admin.pages.testing import HOSTILE, THEMES, VIEWPORTS

PAGE = "/admin/system"
LAZY_LEFT = "[...document.querySelectorAll('.page-card--lazy')].map((node) => node.id)"


def open_page(open_admin: Any, path: str = PAGE, **options: Any) -> Any:
    """`open_admin` without its settle step, then every lazy card loaded one at a time.

    The shared `AdminPage.settle()` scrolls every lazy card into view in one burst and waits until none is left, but
    htmx's `revealed` only sees the last scroll position, so on a phone the lazy cards above it never load and the wait
    times out (integrator request: load them one at a time there). This does it one card at a time."""
    admin = open_admin(path, settle=False, **options)
    page = admin.page
    for _ in range(30):
        left = page.evaluate(LAZY_LEFT)
        if not left:
            break
        page.locator(f"#{left[0]}").scroll_into_view_if_needed()
        for _ in range(200):  # up to 10 s for this card's fragment
            if not page.evaluate(f"!!document.querySelector('#{left[0]}.page-card--lazy')"):
                break
            page.wait_for_timeout(50)
    admin.wait("true")  # then htmx idle (no request, swap or settle left)
    page.evaluate("window.scrollTo(0, 0)")
    return admin


NO_HOSTILE_MARKUP = """() => !document.querySelector('img[src="x"], [onerror], [onclick], a[href^="javascript:"]')
  && typeof window.__pwned === "undefined\""""
COUNT = "document.querySelector('#errors .dt__count').textContent.trim()"


@pytest.fixture(scope="module")
def errors(dashboard: Any) -> list[str]:
    """Two error signatures recorded through the real recorder (one with hostile text), flushed."""
    signatures = ["ValueError: bad path " + HOSTILE["img"], "RuntimeError: the cache tier was busy"]

    async def write() -> None:
        recorder = dashboard.ctx.recorder
        recorder.record_error(
            signatures[0],
            detail="GET /games.roblox.com/" + HOSTILE["script"],
            module_line="roxy/proxy/router.py:812",
            traceback='Traceback (most recent call last):\n  File "' + HOSTILE["img"] + '"\nValueError: bad',
        )
        recorder.record_error(signatures[1], detail="cache.db locked", source="internal")
        await recorder.flush()

    dashboard.run(write())
    return signatures


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("size", list(VIEWPORTS))
def test_the_page_is_clean_accessible_and_fits(open_admin: Any, errors: list[str], theme: str, size: str) -> None:
    width, height = VIEWPORTS[size]
    admin = open_page(open_admin, PAGE, theme=theme, width=width, height=height)
    page = admin.page
    assert page.locator('#fleet [data-table="workers"] tbody tr[data-row-id]').count() >= 1
    assert page.locator("#errors tbody tr[data-row-id]").count() == 2
    assert page.locator(".page-card--lazy").count() == 0  # every lazy card loaded
    assert page.locator("#metrics-pipeline [data-setting-key]").count() == 3
    assert page.evaluate(NO_HOSTILE_MARKUP)
    assert not admin.overflows(), "the page scrolls sideways"
    assert admin.axe() == []
    admin.shot("system")
    admin.assert_clean()


def test_the_error_log_filters_and_searches_in_place(open_admin: Any, errors: list[str]) -> None:
    admin = open_page(open_admin)
    page = admin.page
    page.evaluate("window.__sameDocument = true")
    everything = page.locator("#errors .dt__count").inner_text().strip()
    page.select_option('#errors select[name="source"]', "internal")
    admin.wait(f"{COUNT} !== {json.dumps(everything)}")
    assert page.locator("#errors tbody tr[data-row-id]").count() == 1
    assert "source=internal" in page.url
    assert page.locator("section#errors").count() == 1  # the table was swapped, not a second card inside it
    page.select_option('#errors select[name="source"]', "")
    admin.wait(f"{COUNT} === {json.dumps(everything)}")
    page.fill('#errors input[name="q"]', "cache tier")
    admin.wait("new URL(location.href).searchParams.get('q') === 'cache tier'")
    admin.wait("document.querySelectorAll('#errors tbody tr[data-row-id]').length === 1")
    assert page.evaluate("window.__sameDocument === true"), "the table reloaded the whole page"
    admin.assert_clean()


def test_a_row_opens_its_traceback_in_the_drawer_as_text(open_admin: Any, errors: list[str]) -> None:
    admin = open_page(open_admin, PAGE, theme="light")
    page = admin.page
    row = page.locator("#errors tbody tr[data-row-id]", has_text="ValueError")
    row.locator("[data-dt-open]").click()
    admin.wait("document.querySelector('#drawer[open] [data-error-detail]') !== null")
    drawer = page.locator("#drawer")
    assert page.locator("#drawer-title").inner_text().strip() == "Error details"
    assert HOSTILE["img"] in drawer.inner_text()
    assert page.evaluate(NO_HOSTILE_MARKUP)
    assert drawer.locator("pre.system-trace").count() == 1
    assert admin.axe() == []
    admin.shot("system-drawer")
    page.keyboard.press("Escape")
    admin.wait("!document.querySelector('#drawer[open]')")
    admin.assert_clean()


def test_reset_request_counts_asks_first_then_resets(open_admin: Any, dashboard: Any) -> None:
    admin = open_page(open_admin)
    page = admin.page
    page.locator('#fleet [data-action="reset-counts"]').click()
    admin.wait("document.querySelector('#dlg-reset-counts').open")
    assert "Uptime and memory are not affected" in page.locator("#dlg-reset-counts").inner_text()
    page.fill("#dlg-reset-counts-reason", "Browser test")
    page.locator('#dlg-reset-counts button[type="submit"]').click()
    admin.wait("document.querySelector('.toast') !== null")
    assert "Worker request counts reset" in page.locator(".toast").first.inner_text()
    admin.wait("!document.querySelector('#dlg-reset-counts') || !document.querySelector('#dlg-reset-counts').open")
    audit = dashboard.api("GET", "audit", params={"action": "system.reset_counts"}).json()
    assert audit["total"] >= 1
    admin.assert_clean()


def test_the_forced_flush_says_it_worked(open_admin: Any) -> None:
    admin = open_page(open_admin)
    page = admin.page
    page.locator('#flush [data-action="flush"]').click()
    admin.wait("document.querySelector('.toast') !== null")
    assert "Flush requested" in page.locator(".toast").first.inner_text()
    admin.assert_clean()


def test_a_link_to_one_error_opens_it_on_load(open_admin: Any, errors: list[str]) -> None:
    admin = open_page(open_admin, f"{PAGE}?signature=RuntimeError%3A%20the%20cache%20tier%20was%20busy")
    admin.wait("document.querySelector('#drawer[open] [data-error-detail]') !== null")
    assert "cache tier" in admin.page.locator("#drawer").inner_text()
    admin.assert_clean()
