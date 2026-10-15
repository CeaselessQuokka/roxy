"""The Help page and its documents in a real browser: clean, accessible, and the links people follow work.

What this is
    Browser tests against the real app (`dashboard`, tests/e2e/conftest.py). For each theme and size (1440x900 and
    390x844, dark and light) the Help page, the runbooks and the admin guide's pages (its first page and its largest
    chapter) load with no console error, page error or CSP violation, axe-core finds nothing serious, the phone never
    scrolls sideways, and screenshots are saved for the visual review. Then what people do here: filter the glossary,
    follow an alert email's `/admin/help#runbook-<name>` link to the runbook itself, follow a health check's
    `/admin/help/operations#<name>` link, open the contents of a document, follow a guide link into another chapter,
    and walk the guide with Previous and Next.

Why it exists
    The integration tests prove the links point somewhere; only a browser proves that following one lands on the
    runbook under the strict CSP.

What to read next
    tests/integration/pages/test_page_help.py, roxy/admin/pages/help.py, static/js/pages/help.js.
"""

from __future__ import annotations

from typing import Any

import pytest

from pages_harness import THEMES, VIEWPORTS
from roxy.admin.pages.help import SHORTCUTS_CARD

PAGE = "/admin/help"
RUNBOOKS_SHOT_TIMEOUT_MS = 180_000
"""How long the runbooks' full-page review shot may take (see `test_the_runbooks_are_clean_accessible_and_fit`)."""


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("size", list(VIEWPORTS))
def test_the_page_is_clean_accessible_and_fits(open_admin: Any, theme: str, size: str) -> None:
    width, height = VIEWPORTS[size]
    admin = open_admin(PAGE, theme=theme, width=width, height=height)
    page = admin.page
    assert page.locator("#guide .help-chapter").count() == 12
    assert page.locator("#glossary .help-term").count() > 100
    assert not admin.overflows(), "the page scrolls sideways"
    assert admin.axe() == []
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
    # The runbooks are about 25,000 px tall at 1440 px wide, and a full-page capture that large leaves Chromium's
    # fast path: the one picture takes about 50 s (the 19,000 px Protection chapter takes 2 s), longer than
    # Playwright's 30 s default. A reader never meets this (they scroll), so the review shot gets the time it needs.
    page.set_default_timeout(RUNBOOKS_SHOT_TIMEOUT_MS)
    admin.shot("help-runbooks")
    admin.assert_clean()


GUIDE = f"{PAGE}/guide"


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("size", list(VIEWPORTS))
@pytest.mark.parametrize("path", [GUIDE, f"{GUIDE}/protection"], ids=["first-page", "largest-chapter"])
def test_the_admin_guide_chapters_are_clean_accessible_and_fit(
    open_admin: Any, theme: str, size: str, path: str
) -> None:
    """The guide is shown one chapter at a time: its first page and its largest chapter (Protection) load with no
    console error or CSP violation, pass axe, and never scroll sideways on a phone."""
    width, height = VIEWPORTS[size]
    admin = open_admin(path, theme=theme, width=width, height=height)
    page = admin.page
    assert page.locator("h1").count() == 1
    assert page.locator("h1").inner_text().strip() == "Roxy admin guide"
    assert page.locator("article.doc h2").count() >= 1
    assert page.locator("nav[aria-labelledby='guide-pager-title'] a").count() >= 1
    if size == "phone":
        assert page.evaluate("!document.querySelector('[data-doc-toc]').open")  # the text comes first on a phone
    assert not admin.overflows(), "the page scrolls sideways"
    assert admin.axe() == []
    admin.shot("help-guide" if path == GUIDE else "help-guide-protection")
    admin.assert_clean()


def test_a_link_to_another_chapter_opens_that_chapter_at_its_section(open_admin: Any) -> None:
    """Getting started links "[Replace](#replace)", a section of the Credential chapter: the link names that chapter's
    page, and following it lands on the section."""
    admin = open_admin(GUIDE, width=1440)
    page = admin.page
    page.locator("article.doc a[href='/admin/help/guide/credential#replace']").first.click()
    admin.wait("location.pathname === '/admin/help/guide/credential' && location.hash === '#replace'")
    top = "document.querySelector('#replace').getBoundingClientRect().top"
    admin.wait(f"{top} >= 0 && {top} < 400")  # scrolled to the section, below the sticky top bar
    assert page.locator("article.doc h2#credential").count() == 1
    admin.assert_clean()


def test_previous_and_next_walk_the_guide_in_order(open_admin: Any) -> None:
    admin = open_admin(f"{GUIDE}/daily-routine", width=1440)
    page = admin.page
    page.locator("nav[aria-labelledby='guide-pager-title'] a[rel='next']").click()
    admin.wait("location.pathname === '/admin/help/guide/how-roxy-stays-under-robloxs-limits'")
    page.locator("nav[aria-labelledby='guide-pager-title'] a[rel='prev']").click()
    admin.wait("location.pathname === '/admin/help/guide/daily-routine'")
    page.locator("nav[aria-labelledby='guide-pager-title'] a[rel='prev']").click()
    admin.wait("location.pathname === '/admin/help/guide' && location.hash === '#getting-started'")
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


def test_the_shortcut_overlay_opens_from_the_help_page(open_admin: Any) -> None:
    admin = open_admin(PAGE)
    admin.page.locator(f"section#{SHORTCUTS_CARD} [data-shortcuts-open]").click()
    admin.wait("document.querySelector('dialog#shortcuts') && document.querySelector('dialog#shortcuts').open")
    admin.page.keyboard.press("Escape")
    admin.wait("!document.querySelector('dialog#shortcuts').open")
    admin.page.keyboard.press("?")
    admin.wait("document.querySelector('dialog#shortcuts').open")
    admin.assert_clean()
