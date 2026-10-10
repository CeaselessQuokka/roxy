"""The Audit page in a real browser (P11 reference page): clean, accessible, and its controls work.

What this is
    Browser tests against the real app (`dashboard`, tests/e2e/conftest.py: a free port, a signed-in admin, seeded
    traffic and audit rows with hostile text). For each theme and size (1440x900 and 390x844, dark and light) the
    page loads with no console error, page error or CSP violation, axe-core finds nothing serious, the phone layout
    never scrolls sideways, and a screenshot is saved for the visual review. Then the controls: the filter chips,
    search and paging swap the table without a reload, a row opens its entry in the drawer with the diff, hostile
    text stays text, `?entry=<id>` opens the drawer on load, and the revert form puts a setting back through the
    settings API.

Why it exists
    The integration tests prove what the server sends; only a browser proves the page works with the strict CSP,
    htmx and the design system's scripts. The other page builders copy these tests for their pages.

What to read next
    tests/e2e/conftest.py (`open_admin`, `AdminPage`), tests/integration/pages/test_page_audit.py.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from roxy.admin.pages.testing import THEMES, VIEWPORTS

PAGE = "/admin/audit"
NO_HOSTILE_MARKUP = """() => !document.querySelector('img[src="x"], [onerror], [onclick], a[href^="javascript:"]')
  && typeof window.__pwned === "undefined\""""


COUNT = "document.querySelector('#log .dt__count').textContent.trim()"
FIRST_ROW = "document.querySelector('#log tbody tr[data-row-id]').getAttribute('data-row-id')"


def _count(admin: Any) -> str:
    return str(admin.page.locator("#log .dt__count").inner_text()).strip()


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("size", list(VIEWPORTS))
def test_the_page_is_clean_accessible_and_fits(open_admin: Any, theme: str, size: str) -> None:
    width, height = VIEWPORTS[size]
    admin = open_admin(PAGE, theme=theme, width=width, height=height)
    assert admin.page.locator(f'html[data-theme="{theme}"]').count() == 1
    assert admin.page.locator('#log [data-table="audit_log"] tbody tr').count() > 0
    assert admin.page.evaluate(NO_HOSTILE_MARKUP)
    assert not admin.overflows(), "the page scrolls sideways"
    assert admin.axe() == []
    admin.shot("audit")
    admin.assert_clean()


def test_filters_search_and_paging_swap_the_table_in_place(open_admin: Any) -> None:
    admin = open_admin(PAGE)
    page = admin.page
    page.evaluate("window.__sameDocument = true")
    everything = _count(admin)
    page.select_option('#log select[name="action"]', "setting.update")
    admin.wait(f"{COUNT} !== {json.dumps(everything)}")
    filtered = _count(admin)
    assert filtered != everything
    rows = page.locator("#log tbody tr[data-row-id]")
    assert all("setting.update" in rows.nth(i).inner_text() for i in range(rows.count()))
    assert "action=setting.update" in page.url  # the filter is in the address, so the view can be shared
    page.select_option('#log select[name="action"]', "")
    admin.wait(f"{COUNT} === {json.dumps(everything)}")
    page.fill('#log input[name="q"]', "export.download")
    admin.wait("new URL(location.href).searchParams.get('q') === 'export.download'")
    admin.wait("document.querySelectorAll('#log tbody tr[data-row-id]').length === 1")
    assert "export.download" in page.locator("#log tbody tr[data-row-id]").first.inner_text()
    page.fill('#log input[name="q"]', "")
    admin.wait(f"{COUNT} === {json.dumps(everything)}")
    page.select_option("#log select[data-dt-size]", "10")
    admin.wait("document.querySelectorAll('#log tbody tr[data-row-id]').length === 10")
    first_page = page.locator("#log tbody tr[data-row-id]").first.get_attribute("data-row-id")
    page.locator('#log button[aria-label="Next page"]').first.click()
    admin.wait(f"{FIRST_ROW} !== {json.dumps(first_page)}")
    assert page.evaluate("window.__sameDocument === true"), "the table reloaded the whole page"
    admin.assert_clean()


def test_a_row_opens_its_entry_in_the_drawer_with_the_diff_as_text(open_admin: Any, dashboard: Any) -> None:
    admin = open_admin(PAGE, theme="light")
    page = admin.page
    entry_id = dashboard.seeded["audit"]["record_ids"][0]
    page.locator(f'#log tr[data-row-id="audit-{entry_id}"]').click()
    admin.wait("document.querySelector('#drawer[open] .audit-entry') !== null")
    drawer = page.locator("#drawer")
    assert f"Entry #{entry_id}" in drawer.inner_text()
    assert page.locator("#drawer-title").inner_text().strip() == f"Audit entry #{entry_id}"
    assert "<img src=x onerror=alert(1)>" in drawer.inner_text()  # shown as text
    assert page.evaluate(NO_HOSTILE_MARKUP)
    assert drawer.locator(".audit-diff tbody tr").count() > 0
    assert admin.axe() == []
    admin.shot("audit-drawer")
    page.keyboard.press("Escape")
    admin.wait("!document.querySelector('#drawer[open]')")
    admin.assert_clean()


def test_a_link_to_one_entry_opens_it_on_load(open_admin: Any, dashboard: Any) -> None:
    entry_id = dashboard.seeded["audit"]["record_ids"][1]
    admin = open_admin(f"{PAGE}?entry={entry_id}")
    admin.wait(f"document.querySelector('#drawer[open] [data-audit-entry=\"{entry_id}\"]') !== null")
    admin.assert_clean()


def test_the_revert_form_puts_the_setting_back(open_admin: Any, dashboard: Any) -> None:
    before = dashboard.api("GET", "settings/cache_ttl_seconds").json()
    changes = dashboard.api(
        "GET", "audit", params={"action": "setting.update", "target": "setting:cache_ttl_seconds"}
    ).json()
    newest = changes["items"][0]
    admin = open_admin(f"{PAGE}?entry={newest['id']}")
    page = admin.page
    admin.wait("document.querySelector('#drawer[open] form.audit-revert') !== null")
    page.fill("#drawer form.audit-revert textarea[name=reason]", "Back to the earlier TTL (browser test)")
    page.locator('#drawer [data-action="audit-revert"]').click()
    admin.wait("document.querySelector('.toast') !== null")
    assert "Reverted" in page.locator(".toast").first.inner_text()
    after = dashboard.api("GET", "settings/cache_ttl_seconds").json()
    assert after["setting"]["value"] != before["setting"]["value"]
    reverts = dashboard.api("GET", "audit", params={"action": "setting.revert"}).json()
    assert reverts["total"] >= 1
    admin.assert_clean()
