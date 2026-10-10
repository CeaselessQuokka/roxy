"""Every v1 dashboard section has a home in v2 (plan 14.1): one browser test per row of the map.

What this is
    Data-driven acceptance tests generated from `roxy.admin.pages.registry.V1_SECTIONS`: for row `n` of the plan
    14.1 table there is `test_<row.test>` (for example `test_overview_kpis`), which opens each v2 page the row
    names, finds the card (`section#<card>`, a lazy card loaded by scrolling to it, a fragment-only card through its
    fragment route) or the shell element (`SHELL_PAGE` checks, on the first built page), and checks the key
    elements inside it: `[data-kpi=...]` tiles, `[data-table=<API table name>]` tables, `[data-setting-key=...]`
    inline settings, `[data-action=...]` buttons, `[data-chart]` charts. No page may log a console error, a page
    error or a CSP violation on the way.

    A check on a page nobody has built yet (`registry.is_built` is False: no `roxy/admin/pages/<page>.py`) is not
    run. When a row still has such checks the test is SKIPPED with the reason "page not built: <pages>" after the
    checks on built pages have passed, so a row passes only when every page it names is built and right.

Why it exists
    v2 is a remake: nothing v1 showed may silently disappear (plan 14.1, AGENT_BRIEF parity). The map is the
    contract between the v1 dashboard and the seventeen v2 pages; this file turns it into tests that start
    passing page by page as the builders finish.

What to read next
    `roxy/admin/pages/registry.py` (`V1_SECTIONS`, `CardSpec`), tests/e2e/conftest.py (`open_admin`),
    `.remake/P11_CONTRACT.md` (which attributes a page must render).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from roxy.admin.pages import registry
from roxy.admin.pages.registry import SHELL_PAGE, V1_SECTIONS, V1Check, V1Section
from roxy.admin.pages.testing import parse_html


def _shell_page() -> str | None:
    built = registry.built_pages()
    return built[0] if built else None


def _check_fragment(dashboard: Any, row: V1Section, check: V1Check) -> None:
    """A fragment-only card (a drawer, a rule's detail): its fragment route must carry the key elements."""
    response = dashboard.get(f"/admin/{check.page}/fragment/{check.card}")
    assert response.status_code == 200, (row.test, check, response.status_code)
    doc = parse_html(response.text)
    for selector in check.selectors:
        assert doc.select(selector), f"row {row.row} ({row.v1}): {selector} missing in {check.page}#{check.card}"


def _check_in_browser(admin: Any, row: V1Section, check: V1Check, root: str) -> None:
    page = admin.page
    where = f"{check.page if check.page != SHELL_PAGE else 'the shell'} {root}"
    assert page.locator(root).count() >= 1, f"row {row.row} ({row.v1}): {where} is missing"
    if check.page != SHELL_PAGE:
        page.locator(root).first.scroll_into_view_if_needed()
        admin.settle()
    for selector in check.selectors:
        found = page.locator(f"{root} {selector}").count()
        assert found >= 1, f"row {row.row} ({row.v1}): {selector} missing in {where}"


def check_row(row: V1Section, open_admin: Callable[..., Any], dashboard: Any) -> None:
    pending = sorted({c.page for c in row.checks if c.page != SHELL_PAGE and not registry.is_built(c.page)})
    opened: dict[str, Any] = {}
    ran = 0
    for check in row.checks:
        if check.page == SHELL_PAGE:
            page_id = _shell_page()
            if page_id is None:
                pending.append("any page (for the shell)")
                continue
            root = check.card
        elif check.page in pending:
            continue
        else:
            page_id = check.page
            spec = registry.card(check.page, check.card)
            if spec.fragment_only:
                _check_fragment(dashboard, row, check)
                ran += 1
                continue
            root = f"#{check.card}"
        if page_id not in opened:
            opened[page_id] = open_admin(f"/admin/{page_id}")
        _check_in_browser(opened[page_id], row, check, root)
        ran += 1
    for admin in opened.values():
        admin.assert_clean()
    if pending:
        passed = f"; the {ran} checks on built pages passed" if ran else ""
        pytest.skip(f"page not built: {', '.join(dict.fromkeys(pending))}{passed}")


def _make_test(row: V1Section) -> Callable[..., None]:
    def test(open_admin: Callable[..., Any], dashboard: Any) -> None:
        check_row(row, open_admin, dashboard)

    test.__name__ = f"test_{row.test}"
    test.__qualname__ = test.__name__
    test.__doc__ = f"Plan 14.1 row {row.row}: {row.v1}" + (f" ({row.note})" if row.note else "")
    return test


for _row in V1_SECTIONS:
    globals()[f"test_{_row.test}"] = _make_test(_row)


def test_the_map_has_one_uniquely_named_test_per_row() -> None:
    names = [row.test for row in V1_SECTIONS]
    assert len(names) == len(set(names))
    assert [row.row for row in V1_SECTIONS] == sorted(row.row for row in V1_SECTIONS)
    for row in V1_SECTIONS:
        assert row.test.isidentifier()
        assert row.test != "live"  # the root conftest skips the keyword "live"
        for check in row.checks:
            if check.page != SHELL_PAGE:
                assert registry.known(check.page), (row.test, check.page)
                assert check.card in {c.id for c in registry.cards_for(check.page)}, (row.test, check.card)
