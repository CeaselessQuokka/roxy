"""The Help page and its documents in a real browser: clean, accessible, and the links people follow work.

What this is
    Browser tests against the real app (`dashboard`, tests/e2e/conftest.py). For each theme and size (1440x900 and
    390x844, dark and light) the Help page and the runbooks load with no console error, page error or CSP violation,
    axe-core finds nothing serious, the phone never scrolls sideways, and screenshots are saved for the visual review.
    Then what people do here: filter the glossary, follow an alert email's `/admin/help#runbook-<name>` link to the
    runbook itself, follow a health check's `/admin/help/operations#<name>` link, and open the contents of a document.

Why it exists
    The integration tests prove the links point somewhere; only a browser proves that following one lands on the
    runbook under the strict CSP.

What to read next
    tests/integration/pages/test_page_help.py, roxy/admin/pages/help.py, static/js/pages/help.js.
"""

from __future__ import annotations

from typing import Any

import pytest

from roxy.admin.pages.testing import THEMES, VIEWPORTS

PAGE = "/admin/help"
CLASH = "shortcuts"
"""The registry's Help card `shortcuts` shares its id with the shell's `?` overlay dialog (integrator request 1)."""


def _without_the_known_clash(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """axe findings other than the duplicate ids of the registry clash (see `CLASH`)."""
    rest = []
    for finding in findings:
        targets = [str(target) for node in finding["nodes"] for target in node]
        if finding["id"].startswith("duplicate-id") and all(CLASH in target for target in targets):
            continue
        rest.append(finding)
    return rest


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("size", list(VIEWPORTS))
def test_the_page_is_clean_accessible_and_fits(open_admin: Any, theme: str, size: str) -> None:
    width, height = VIEWPORTS[size]
    admin = open_admin(PAGE, theme=theme, width=width, height=height)
    page = admin.page
    assert page.locator("#guide .help-chapter").count() == 12 or page.locator("#guide .help-toc li").count() > 0
    assert page.locator("#glossary .help-term").count() > 100
    assert not admin.overflows(), "the page scrolls sideways"
    assert _without_the_known_clash(admin.axe()) == []
    admin.shot("help")
    admin.assert_clean()


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("size", list(VIEWPORTS))
def test_the_runbooks_are_clean_accessible_and_fit(open_admin: Any, theme: str, size: str) -> None:
    width, height = VIEWPORTS[size]
    admin = open_admin(f"{PAGE}/runbooks", theme=theme, width=width, height=height)
    page = admin.page
    assert page.locator("h1").inner_text().strip() == "Roxy runbooks"
    assert page.locator("article.doc h2").count() > 30
    if size == "phone":
        assert page.evaluate("!document.querySelector('[data-doc-toc]').open")  # the text comes first on a phone
    assert not admin.overflows(), "the page scrolls sideways"
    assert admin.axe() == []
    admin.shot("help-runbooks")
    admin.assert_clean()


def test_the_glossary_filter_narrows_the_terms_and_says_how_many(open_admin: Any) -> None:
    admin = open_admin(PAGE)
    page = admin.page
    total = page.locator("#glossary .help-term").count()
    page.fill("#glossary-filter", "cooldown")
    admin.wait("[...document.querySelectorAll('#glossary .help-term')].filter((t) => !t.hidden).length < 10")
    visible = page.locator("#glossary .help-term:not([hidden])")
    assert 0 < visible.count() < total
    assert all("cooldown" in visible.nth(i).inner_text().lower() for i in range(visible.count()))
    admin.wait("document.querySelector('#glossary-count').textContent.includes(' of ')")
    page.fill("#glossary-filter", "zzzz-nothing")
    admin.wait("!document.querySelector('[data-glossary-empty]').hidden")
    page.fill("#glossary-filter", "")
    admin.wait(f"document.querySelectorAll('#glossary .help-term:not([hidden])').length === {total}")
    admin.assert_clean()


def test_an_alert_email_link_lands_on_its_runbook(open_admin: Any) -> None:
    admin = open_admin(f"{PAGE}#runbook-credential-rejected")
    admin.wait("location.pathname === '/admin/help/runbooks' && location.hash === '#credential-rejected'")
    admin.settle()
    assert admin.page.locator("#credential-rejected").count() == 1
    assert admin.page.evaluate("document.querySelector('#credential-rejected').closest('article') !== null")
    admin.assert_clean()


def test_a_health_check_operations_link_lands_on_its_runbook(open_admin: Any) -> None:
    admin = open_admin(f"{PAGE}/operations#environment", settle=False)  # settle() would scroll back to the top
    page = admin.page
    assert page.locator("#environment").count() == 1
    assert page.locator("#proxy-variables-in-the-environment").count() == 1
    top = "document.querySelector('#proxy-variables-in-the-environment').getBoundingClientRect().top"
    admin.wait(f"{top} >= 0 && {top} < 400")  # scrolled to the runbook, below the sticky top bar
    admin.assert_clean()


def test_the_contents_list_jumps_to_a_section(open_admin: Any) -> None:
    admin = open_admin(f"{PAGE}/runbooks", width=1440)
    page = admin.page
    page.locator(".doc-toc__list a[href='#leak-guard']").click()
    admin.wait("location.hash === '#leak-guard'")
    top = page.evaluate("document.querySelector('#leak-guard').getBoundingClientRect().top")
    assert 0 <= top < 300, top
    admin.assert_clean()


@pytest.mark.xfail(strict=True, reason="registry card help#shortcuts collides with the shell dialog #shortcuts")
def test_the_shortcut_overlay_opens_from_the_help_page(open_admin: Any) -> None:
    admin = open_admin(PAGE)
    admin.page.locator("#shortcuts [data-shortcuts-open]").click()
    admin.wait("document.querySelector('dialog#shortcuts') && document.querySelector('dialog#shortcuts').open")
