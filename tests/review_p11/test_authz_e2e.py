"""P11 review, lens authz (authentication, authorization, CSRF, CSP and headers): browser reproductions.

What this is
    Reproductions of the authz lens findings that only a browser shows (the event stream, htmx and the session
    overlay together). Each was a strict xfail naming its finding id until the P11 review round fixed it; each is a
    regression test now. The report is `.remake/p11_review/find_authz.md`.

Why it exists
    The integration tests prove what the server answers; these prove what the admin sees on the page afterwards.

What to read next
    `tests/review_p11/test_authz.py` (the server side findings), `tests/e2e/conftest.py` (the fixtures imported
    below), `src/roxy/admin/sse.py`, `src/roxy/static/js/sse.js`, `src/roxy/static/js/session.js`.
"""

# ruff: noqa: F811  (the imported pytest fixtures are the tests' parameters)
from __future__ import annotations

import time
from typing import Any

import pytest

from e2e.conftest import browser, dashboard, open_admin  # noqa: F401  (the e2e fixtures, as tests/e2e uses them)
from pages_harness import SESSION_COOKIE_NAME
from roxy.admin import sse

pytestmark = pytest.mark.e2e

SIGNED_OUT = """() => {
  const overlay = document.getElementById("session-expired");
  return Boolean((overlay && overlay.open) || document.body.dataset.session === "expired");
}"""


def _keep_cookie(page: Any, dashboard: Any) -> None:
    """A fresh second factor rotates the session: hand the browser's new cookie back to the shared fixture."""
    for cookie in page.context.cookies():
        if cookie["name"] == SESSION_COOKIE_NAME:
            dashboard.signed_in.cookie = cookie["value"]


def _signed_out_within(page: Any, seconds: float) -> str | None:
    """Poll the page for `seconds`: what showed it signed out (the overlay, the expired mark, or a navigation away
    from the page), or None when it stayed signed in the whole time."""
    start_url = page.url
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if page.url != start_url:
                return f"navigated away to {page.url}"
            if page.evaluate(SIGNED_OUT):
                pill = page.evaluate("(document.querySelector('[data-live-text]') || {}).textContent || ''")
                return f"the session-expired overlay opened (the Live pill says {pill!r})"
        except Exception as error:  # a navigation in progress
            return f"navigated away ({error.__class__.__name__})"
        page.wait_for_timeout(200)
    return None


# Fixed in the P11 review round (authz-1, shared fixer): a regression test now.
def test_authz_1_a_fresh_second_factor_keeps_the_page_signed_in(open_admin: Any, dashboard: Any) -> None:
    window = dashboard.api("GET", "settings/admin_reauth_window_s").json()["setting"]["value"]
    dashboard.clock.advance(int(window) + 1)  # the session lives on (idle timeout 900 s); its factor is old
    admin = open_admin("/admin/security")
    page = admin.page
    admin.wait("document.querySelector('[data-live-indicator]').dataset.state === 'live'", timeout=15)
    try:
        page.locator('[data-action="recovery-regenerate"]').click()
        admin.wait("document.querySelector('#dlg-recovery-new[open]') !== null")
        page.locator('#dlg-recovery-new button[type="submit"]').click()
        admin.wait("document.querySelector('#reauth[open]') !== null")
        page.fill("#reauth-code", dashboard.next_code())
        page.locator('#reauth button[type="submit"]').click()
        admin.wait("document.querySelectorAll('[data-recovery-list] li').length === 10")
    finally:
        _keep_cookie(page, dashboard)
    # The new recovery codes are shown once: the admin must be able to copy them. The stream re-reads its session
    # every SESSION_CHECK_S seconds, so two checks and a margin are enough to see what happens to the page.
    what = _signed_out_within(page, 2 * sse.SESSION_CHECK_S + 2)
    assert what is None, f"signed in with a fresh second factor, yet {what}"
    assert page.locator("[data-recovery-list] li").count() == 10, "the one-time recovery codes are gone"
