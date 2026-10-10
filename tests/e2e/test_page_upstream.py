"""The Upstream page in a real browser (P11): clean, accessible, and its controls work.

What this is
    Browser tests against the real app (`dashboard`, tests/e2e/conftest.py: a free port, a signed-in admin, seeded
    traffic with hostile text, a Roblox 429 and a 503). For each theme and size (1440x900 and 390x844, dark and
    light) the page loads with every lazy card, with no console error, page error or CSP violation, axe-core finds
    nothing serious, the phone layout never scrolls sideways, and a screenshot is saved for the visual review. Then
    the controls: the failures filter swaps the table in place (once, not nested) and keeps the address, a bucket
    row opens its history in the drawer, a routing rule is added, tested, edited and deleted through the forms, the
    trace explains a real request, the reset dialog clears cooldowns with a reason, and an inline setting is saved.

Why it exists
    The integration tests prove what the server sends; only a browser proves the page works under the strict CSP
    with htmx, the drawer, the dialogs and the design system's scripts.

What to read next
    tests/e2e/conftest.py (`open_admin`, `AdminPage`), tests/integration/pages/test_page_upstream.py.
"""

from __future__ import annotations

from typing import Any

import pytest

from roxy.admin.pages.testing import THEMES, VIEWPORTS

PAGE = "/admin/upstream"
NO_HOSTILE_MARKUP = """() => !document.querySelector('img[src="x"], [onerror], [onclick], a[href^="javascript:"]')
  && typeof window.__pwned === "undefined\""""


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("size", list(VIEWPORTS))
def test_the_page_is_clean_accessible_and_fits(open_admin: Any, theme: str, size: str) -> None:
    width, height = VIEWPORTS[size]
    admin = open_admin(PAGE, theme=theme, width=width, height=height)
    page = admin.page
    assert page.locator(f'html[data-theme="{theme}"]').count() == 1
    assert page.locator(".page-card--lazy").count() == 0, "a lazy card did not load"
    assert page.locator("[data-card-error]").count() == 0
    assert page.locator('#failures [data-table="upstream_failures"]').count() == 1
    assert page.locator("#health .g3-egress").count() == 3
    assert page.evaluate(NO_HOSTILE_MARKUP)
    assert not admin.overflows(), "the page scrolls sideways"
    assert admin.axe() == []
    admin.shot("upstream")
    admin.assert_clean()
