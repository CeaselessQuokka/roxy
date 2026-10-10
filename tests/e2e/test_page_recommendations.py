"""The Recommendations page in a real browser (P11): clean, accessible, and the apply flow works on a phone.

What this is
    Browser tests against the real app (`dashboard`, tests/e2e/conftest.py). For each theme and size (1440x900 and
    390x844, dark and light) the page loads with no console error, page error or CSP violation, axe-core finds nothing
    serious (the open drawer too), the phone layout never scrolls sideways, and screenshots are saved for the visual
    review. Then the flows, on a phone where plan 14.8 asks for them: open a recommendation from `?rec=<id>`, preview
    it, apply exactly the previewed changes with a reason, see it applied with its watch window in the reopened
    drawer, and undo it; snooze one for an hour and dismiss one with a reason; filter the list in place; and tune a
    rule from its drawer. Each test makes its own recommendation (the harness's `seed_recommendation`), so the shared
    seeded one stays open for the other pages' tests.

Why it exists
    Only a browser proves the drawer, htmx, the API forms, the reauth prompt and the strict CSP work together.

What to read next
    tests/e2e/conftest.py, tests/integration/pages/test_page_recommendations.py.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from roxy.admin.pages.testing import THEMES, VIEWPORTS, seed_recommendation

PAGE = "/admin/recommendations"
NO_HOSTILE_MARKUP = """() => !document.querySelector('img[src="x"], [onerror], [onclick], a[href^="javascript:"]')
  && typeof window.__pwned === "undefined\""""
QUIET_RULE = "insight_up_429_endpoint_enabled"


@pytest.fixture(autouse=True)
def quiet_rule(dashboard: Any) -> Iterator[None]:
    """The seeded recommendations come from UP-429-ENDPOINT, which the live engine (every 30 s on the leader) would
    resolve because the seeded traffic does not prove it: the rule is off while these tests run (a rule that does not
    run never resolves its cards), and on again afterwards."""
    dashboard.change_settings({QUIET_RULE: 0})
    try:
        yield
    finally:
        dashboard.change_settings({QUIET_RULE: 1})


def fresh(dashboard: Any, severity: str = "warn") -> str:
    rec_id: str = dashboard.run(seed_recommendation(dashboard.ctx, dashboard.clock, severity=severity))
    return rec_id


def drawer_of(rec_id: str) -> str:
    return f"document.querySelector('#drawer[open] [data-rec-detail=\"{rec_id}\"]') !== null"


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("size", list(VIEWPORTS))
def test_the_page_is_clean_accessible_and_fits(open_admin: Any, dashboard: Any, theme: str, size: str) -> None:
    if not dashboard.api("GET", "recommendations").json()["total"]:
        fresh(dashboard, severity="critical")
    width, height = VIEWPORTS[size]
    admin = open_admin(PAGE, theme=theme, width=width, height=height)
    page = admin.page
    assert page.locator('#list [data-table="recommendations"] tbody tr[data-row-id]').count() >= 1
    assert page.locator('#rules [data-table="recommendation_rules"]').count() == 1
    assert page.evaluate(NO_HOSTILE_MARKUP)
    assert not admin.overflows(), "the page scrolls sideways"
    assert admin.axe() == []
    admin.shot("recommendations")
    admin.assert_clean()


@pytest.mark.parametrize("theme", THEMES)
def test_the_drawer_and_the_preview_are_clean_and_accessible(open_admin: Any, dashboard: Any, theme: str) -> None:
    rec_id = fresh(dashboard, severity="critical")
    admin = open_admin(PAGE, theme=theme, width=390, height=844)
    page = admin.page
    page.locator(f'#list tr[data-row-id="rec-{rec_id}"] [data-dt-open]').click()
    admin.wait(drawer_of(rec_id))
    assert "<script>alert('roxy')</script>" in page.locator("#drawer .rec-detail__title").inner_text()
    assert page.evaluate(NO_HOSTILE_MARKUP)
    page.locator('#drawer [data-action="recommendation-preview"]').click()
    admin.wait("document.querySelector('#drawer form.rec-apply') !== null")
    assert page.evaluate("document.activeElement && document.activeElement.classList.contains('rec-preview__title')")
    assert not admin.overflows()
    assert admin.axe() == []
    admin.shot("recommendations-drawer")
    admin.assert_clean()


def test_preview_apply_and_undo_from_a_phone(open_admin: Any, dashboard: Any) -> None:
    rec_id = fresh(dashboard)
    before = dashboard.api("GET", "settings/cache_ttl_seconds").json()["setting"]["value"]
    admin = open_admin(f"{PAGE}?rec={rec_id}", width=390, height=844)
    page = admin.page
    admin.wait(drawer_of(rec_id))
    page.locator('#drawer [data-action="recommendation-preview"]').click()
    admin.wait("document.querySelector('#drawer form.rec-apply') !== null")
    assert "Cache lifetime" in page.locator("#drawer .rec-preview__body").inner_text() or page.locator(
        "#drawer .rec-diff"
    ).count()
    page.fill("#drawer form.rec-apply textarea[name=reason]", "Applied from a phone (browser test)")
    page.locator('#drawer [data-action="recommendation-apply"]').click()
    admin.wait("document.querySelector('.toast') && /Applied/.test(document.querySelector('#toasts').innerText)")
    admin.wait(drawer_of(rec_id) + " && document.querySelector('#drawer [data-action=\"recommendation-undo\"]') !== null")
    assert "Applied" in page.locator("#drawer .rec-detail__lead").inner_text()
    assert dashboard.api("GET", "settings/cache_ttl_seconds").json()["setting"]["value"] == 300
    admin.shot("recommendations-applied")
    page.locator('#drawer [data-action="recommendation-undo"]').click()
    admin.wait("/Undone/.test(document.querySelector('#toasts').innerText)")
    admin.wait(drawer_of(rec_id) + " && /Rolled back/.test(document.querySelector('#drawer .rec-detail__lead').innerText)")
    assert dashboard.api("GET", "settings/cache_ttl_seconds").json()["setting"]["value"] == before
    history = dashboard.api("GET", "recommendations/history", params={"recommendation": rec_id}).json()
    assert [item["action"] for item in history["items"]] == ["undo", "apply"]
    admin.assert_clean()


def test_snooze_and_dismiss_from_the_drawer(open_admin: Any, dashboard: Any) -> None:
    snoozed = fresh(dashboard)
    admin = open_admin(f"{PAGE}?rec={snoozed}")
    page = admin.page
    admin.wait(drawer_of(snoozed))
    page.locator('#drawer [data-action="recommendation-snooze-1h"]').click()
    admin.wait(drawer_of(snoozed) + " && /Snoozed/.test(document.querySelector('#drawer .rec-detail__lead').innerText)")
    dismissed = fresh(dashboard)
    admin.goto(PAGE)
    page.locator(f'#list tr[data-row-id="rec-{dismissed}"] [data-dt-open]').click()
    admin.wait(drawer_of(dismissed))
    page.select_option("#drawer select[name=reason]", "other")
    page.fill("#drawer textarea[name=text]", "We handle this one by hand")
    page.locator('#drawer [data-action="recommendation-dismiss"]').click()
    admin.wait(drawer_of(dismissed) + " && /Dismissed/.test(document.querySelector('#drawer .rec-detail__lead').innerText)")
    detail = dashboard.api("GET", f"recommendations/{dismissed}").json()
    assert detail["card"]["state"] == "dismissed"
    assert detail["history"][0]["details"]["text"] == "We handle this one by hand"
    admin.assert_clean()


def test_filters_swap_the_list_in_place(open_admin: Any, dashboard: Any) -> None:
    fresh(dashboard, severity="info")
    admin = open_admin(PAGE)
    page = admin.page
    page.evaluate("window.__sameDocument = true")
    page.select_option('#list select[name="severity"]', "info")
    admin.wait("new URL(location.href).searchParams.get('severity') === 'info'")
    admin.wait("[...document.querySelectorAll('#list tbody tr[data-row-id]')].length >= 1")
    rows = page.locator("#list tbody tr[data-row-id]")
    assert all("Info" in rows.nth(i).inner_text() for i in range(rows.count()))
    assert page.evaluate("document.querySelectorAll('section#list').length") == 1, "a card in a card"
    assert page.evaluate("window.__sameDocument === true")
    page.select_option('#list select[name="state"]', "all")
    admin.wait("new URL(location.href).searchParams.get('state') === 'all'")
    admin.assert_clean()


def test_a_rule_drawer_tunes_the_rule_inline(open_admin: Any) -> None:
    admin = open_admin(PAGE)
    page = admin.page
    page.locator("#rules").scroll_into_view_if_needed()
    admin.settle()
    page.locator('#rules tr[data-row-id="rule-up_429_endpoint"] [data-dt-open]').click()
    admin.wait("document.querySelector('#drawer[open] [data-rule=\"UP-429-ENDPOINT\"]') !== null")
    assert page.locator('#drawer [data-setting-key="insight_up_429_endpoint_min_429s"]').count() == 1
    assert page.locator('#drawer [data-setting-key="insight_up_429_endpoint_enabled"]').count() == 1
    assert admin.axe() == []
    admin.assert_clean()
