"""Review of the P11 dashboard pages, lens "injection and escaping": the browser reproduction of finding esc-2.

What this is
    One browser test (a strict xfail until esc-2 was fixed, a regression test now). Before the fix, the Security
    page's drawer for a header a caller named `.` sent its "Clear the values" form to an API URL the browser itself
    rewrites (`.../headers/./values` becomes `.../headers/values`), so the admin's click removed the header named
    `values`. The integration test
    `test_escaping.py::test_a_dot_name_keeps_its_drawer_and_row_actions_on_its_own_record` shows the same with a
    Python model of the browser's URL parser; this one clicks the real button in Chromium.

Why it exists
    The finding rests on browser URL semantics (WHATWG dot segments, also for `%2e`), so it is proven where they
    apply: in a browser, through the page's own script (`static/js/api_forms.js` and `fetch`).

How it works
    The e2e fixtures (`tests/e2e/conftest.py`: `dashboard`, `open_admin`, `browser`) are imported as the e2e tests
    get them. A request through the real proxy records the header names `.` and `values`; the test searches the
    Header names tab for ".", opens the row in the drawer, clicks "Clear the values" and reads the headers back
    through the admin API.

What to read next
    `tests/review_p11/test_escaping.py`, `.remake/p11_review/find_escaping.md`, `roxy/admin/pages/security.py`.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

import e2e.conftest as e2e_fixtures
from e2e.conftest import browser, dashboard, open_admin  # noqa: F401

PAGE = "/admin/security"


@pytest.fixture(autouse=True, scope="module")
def _stop_the_dashboard_after_this_module() -> Iterator[None]:
    """The imported `dashboard` fixture is session scoped and its own stop hook only runs for `tests/e2e`: stop the
    server (and its databases' threads) when this module ends, as `tests/e2e/conftest.py` does after its last test."""
    yield
    e2e_fixtures._stop_dashboards()


def header_names(dashboard: Any) -> set[str]:  # noqa: F811
    answer = dashboard.api("GET", "security/fingerprints/headers", params={"page_size": 250, "q": "."})
    assert answer.status_code == 200, answer.text
    names = {str(item["name"]) for item in answer.json()["items"]}
    answer = dashboard.api("GET", "security/fingerprints/headers", params={"page_size": 250, "q": "values"})
    names |= {str(item["name"]) for item in answer.json()["items"]}
    return names


# Fixed in the P11 review round (esc-2, shared fixer): a regression test now.
def test_clear_values_of_a_header_named_dot_clears_that_header_in_the_browser(
    open_admin: Any,  # noqa: F811
    dashboard: Any,  # noqa: F811
) -> None:
    with dashboard.http() as client:
        sent = client.get(
            "/games.roblox.com/v1/games?universeIds=185",
            headers={"X-Forwarded-For": "203.0.113.185", "User-Agent": "Roblox/WinInet", ".": "dot", "values": "kept"},
        )
    assert sent.status_code == 200
    dashboard.flush()
    assert {".", "values"} <= header_names(dashboard)

    admin = open_admin(PAGE)
    page = admin.page
    page.locator("#fp-headers-q").fill(".")
    admin.wait(
        """[...document.querySelectorAll('#fp-headers tbody tr[data-drawer-src]')].some(
             (row) => new URL(row.dataset.drawerSrc, location.href).searchParams.get('name') === '.')"""
    )
    page.evaluate(
        """() => [...document.querySelectorAll('#fp-headers tbody tr[data-drawer-src]')].find(
             (row) => new URL(row.dataset.drawerSrc, location.href).searchParams.get('name') === '.'
           ).querySelector('[data-dt-open]').click()"""
    )
    admin.wait("document.querySelector('#drawer[open] [data-fp-header]') !== null")
    drawer = page.locator("#drawer")
    drawer.locator("summary", has_text="Clear its stored values").click()
    with page.expect_response(lambda response: response.request.method == "DELETE") as sent_delete:
        drawer.locator("button[type=submit]", has_text="Clear the values").click()
    delete_url = sent_delete.value.url
    admin.wait("!document.querySelector('#drawer [aria-busy=\"true\"]')")

    left = header_names(dashboard)
    assert "values" in left, f"the browser sent DELETE {delete_url} and the header named 'values' is gone"
