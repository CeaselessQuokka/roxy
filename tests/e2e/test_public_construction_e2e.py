"""Pages under construction in a real browser: the admin banner, the public view and the way back, and a visitor.

What this is
    One browser flow on the session's dashboard server (`dashboard`, tests/e2e/conftest.py: the real app on a
    loopback port with a signed-in admin) for the owner request of 2026-10-15: with the user guide under construction,
    the admin opens `/docs`, sees the real guide under the "Admins only" banner, presses "See what the public sees",
    gets the under-construction page with the small fixed notice, follows "Back to admin view" to the real guide again;
    a browser that never signed in gets the under-construction page with neither. Every view must pass axe-core, keep
    the strict CSP without a violation, and not scroll sideways on a phone.

Why it exists
    The integration tests read the HTML; only a browser proves the session cookie really reaches `/docs` (it is
    `SameSite=Strict` and `Path=/`), that the buttons are links that work, and that the fixed notice is really fixed
    and readable.

How it works
    `dashboard.change_settings` turns `public_docs_under_construction` on through the real settings service, and a
    `finally` turns it off again: the dashboard is shared by every browser test of the session. Chromium logs a
    document answered with 503 as a console error, which `assert_clean` is told to expect.

What to read next
    `roxy/public/construction.py`, tests/integration/test_public_construction.py.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

SWITCH = "public_docs_under_construction"
BANNER = "Admins only: the public currently sees the under-construction page for this page."
EXPECTED_CONSOLE = ["status of 503"]  # Chromium reports the 503 page load itself as a console error


@pytest.mark.parametrize(("width", "height"), [(1440, 900), (390, 844)], ids=["desktop", "phone"])
def test_the_admin_preview_flow_and_a_visitor(
    dashboard: Any, open_admin: Callable[..., Any], width: int, height: int
) -> None:
    dashboard.change_settings({SWITCH: 1})
    try:
        admin = open_admin(None, width=width, height=height)
        real = admin.goto("/docs", settle=False)
        page = admin.page
        assert real is not None
        assert real.status == 200
        banner = page.locator("aside.preview-banner")
        assert banner.is_visible()
        assert BANNER in banner.inner_text()
        assert page.locator("nav.toc").count() == 1  # the real guide
        assert admin.axe() == []
        assert not admin.overflows()

        with page.expect_navigation():
            page.get_by_role("link", name="See what the public sees").click()
        assert page.url.endswith("/docs?view=public")
        assert page.locator("h1").inner_text() == "Roxy's user guide is under construction"
        assert page.locator("nav.toc").count() == 0
        assert page.locator("aside.preview-banner").count() == 0
        notice = page.locator("aside.preview-notice")
        assert notice.is_visible()
        assert "You are viewing this page as the public sees it." in notice.inner_text()
        assert notice.evaluate("(node) => getComputedStyle(node).position") == "fixed"
        assert admin.axe() == []
        assert not admin.overflows()

        with page.expect_navigation():
            notice.get_by_role("link", name="Back to admin view").click()
        assert page.url.endswith("/docs")
        assert page.locator("aside.preview-banner").is_visible()
        assert page.locator("nav.toc").count() == 1
        admin.assert_clean(expected=EXPECTED_CONSOLE)

        stranger = open_admin(None, signed_in=False, width=width, height=height)
        answer = stranger.goto("/docs", settle=False)
        assert answer is not None
        assert answer.status == 503
        assert answer.headers["roxy-under-construction"] == "True"
        assert stranger.page.locator("h1").inner_text() == "Roxy's user guide is under construction"
        assert stranger.page.locator("aside").count() == 0  # neither the banner nor the notice
        assert stranger.page.locator("nav.toc").count() == 0
        assert stranger.axe() == []
        assert not stranger.overflows()
        stranger.assert_clean(expected=EXPECTED_CONSOLE)
    finally:
        dashboard.change_settings({SWITCH: 0})
