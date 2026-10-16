"""The Help page (`/admin/help`, plan 14.1, 14.6, 14.7, 16.3, 17.7): integration tests against the real app.

What this is
    The page and its documents as the server renders them: the guards, every registry card, the glossary with an
    entry for every term (the target of every dotted term on the dashboard), the shortcuts equal to the `?` overlay,
    "what each page does" from the registry, the documents rendered once with unique ids, and above all the links
    Roxy sends people to: every runbook name an alert email links to (`/admin/help#runbook-<name>`) and every Help
    link a health check gives as its fix (`/admin/help/runbooks#<anchor>`, `/admin/help/operations#<name>`) lands
    on an element of a page that answers 200.

Why it exists
    An alert or a failed check is the moment the owner needs the runbook; a link that lands nowhere then is worse
    than no link (plan 17.7, 13.2). The Help texts must come from their one source (plan 14.7).

What to read next
    `roxy/admin/pages/help.py`, `roxy/admin/pages/_help_docs.py`, `tests/e2e/test_page_help.py`.
"""

from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from pages_harness import parse_html
from roxy.admin.pages import _help_docs, registry
from roxy.admin.pages import help as help_page
from roxy.admin.pages.texts import load_glossary
from roxy.core.style_guard import find_style_issues
from roxy.health.checks import SPECS as HEALTH_SPECS
from roxy.notify.alerts import ALERT_SPECS
from roxy.notify.notifier import runbook_link

PAGE = "/admin/help"
DOC_PATHS = [f"{PAGE}/{spec.slug}" for spec in _help_docs.DOCS]


def _split(link: str) -> tuple[str, str]:
    path, _, anchor = link.partition("#")
    return path, anchor


async def test_the_page_its_fragments_and_documents_need_a_signed_in_admin(anon: Any) -> None:
    paths = [PAGE, *(f"{PAGE}/fragment/{card.id}" for card in registry.cards_for("help")), *DOC_PATHS]
    for path in paths:
        response = await anon.get(path)
        assert response.status_code == 302, path
        assert response.headers["location"] == "/admin"


async def test_every_card_renders_with_one_h1_clean_markup_and_its_fragment(page: Any) -> None:
    response = await page.get(PAGE)
    assert response.status_code == 200
    doc = parse_html(response.text)
    assert len(doc.select("h1")) == 1
    for card in registry.cards_for("help"):
        assert doc.select_one(f"section#{card.id}[data-card]") is not None, card.id
        fragment = await page.fragment("help", card.id)
        assert fragment.status_code == 200, card.id
        assert f'id="{card.id}"' in fragment.text
        assert "data-card-error" not in fragment.text, card.id
    assert not doc.select("[data-card-error]")
    assert find_style_issues(response.text, "help page") == []
    assert doc.select_one('link[href*="css/pages/help"]') is not None
    assert doc.select_one('script[type="module"][src*="js/pages/help"]') is not None
    ids = doc.ids()
    assert not sorted({i for i in ids if ids.count(i) > 1})


async def test_no_id_on_the_help_page_is_used_twice(page: Any) -> None:
    """The shortcuts card is `keys`: the id `shortcuts` belongs to the shell's `?` overlay dialog, which
    `openDialog("shortcuts")` must find on this page too."""
    ids = parse_html((await page.get(PAGE)).text).ids()
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    assert not duplicates, duplicates
    assert help_page.SHORTCUTS_CARD == "keys"
    assert ids.count("shortcuts") == 1


async def test_a_card_whose_renderer_fails_shows_the_error_in_place(page: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """The kit contract on the real Help page: a renderer that raises becomes the error card, the rest renders."""

    async def broken(view: Any) -> dict[str, Any]:
        raise RuntimeError("boom")

    async def refused(view: Any) -> dict[str, Any]:
        from roxy.admin.api.common import unavailable

        raise unavailable("The metrics database is busy right now; try again shortly.")

    for card_id, render in (("guide", broken), ("glossary", refused)):
        monkeypatch.setitem(help_page.page._cards, card_id, replace(help_page.page._cards[card_id], render=render))
    failed = await page.fragment("help", "guide")
    assert failed.status_code == 200
    assert "data-card-error" in failed.text
    assert "failed to load" in failed.text
    assert "boom" not in failed.text
    busy = await page.fragment("help", "glossary")
    assert "The metrics database is busy" in busy.text
    whole = await page.get(PAGE)
    assert whole.status_code == 200
    doc = parse_html(whole.text)
    assert doc.select_one("section#guide[data-card-error]") is not None  # the card keeps its place, with the error
    assert doc.select_one("section#pages .help-page") is not None  # every other card still renders
    assert doc.select_one(f"section#{help_page.SHORTCUTS_CARD} .help-keys") is not None


async def test_the_glossary_has_every_term_as_the_target_of_the_tooltips(page: Any) -> None:
    doc = await page.doc(PAGE)
    glossary = load_glossary()
    card = doc.select_one("section#glossary")
    assert card is not None
    for term_id, entry in glossary.items():
        node = card.select_one(f"#term-{term_id}")
        assert node is not None, term_id
        assert entry.definition in node.text()
    assert card.select_one("input[data-glossary-filter]") is not None
    assert f"{len(glossary)} terms" in card.text()


async def test_every_alert_runbook_link_lands_on_its_runbook(page: Any) -> None:
    """Alert emails link to `/admin/help#runbook-<name>` (`roxy.notify.notifier.runbook_link`)."""
    help_doc = await page.doc(PAGE)
    runbooks = await page.doc(f"{PAGE}/runbooks")
    runbook_ids = set(runbooks.ids())
    names = sorted({spec.runbook for spec in ALERT_SPECS.values() if spec.runbook})
    assert names
    for name in names:
        link = runbook_link("https://roxy.example", name)
        assert link is not None
        path, anchor = _split(link.removeprefix("https://roxy.example"))
        assert path == PAGE
        entry = help_doc.select_one(f"#{anchor}")
        assert entry is not None, f"{link}: no #{anchor} on the Help page"
        target = entry.get("data-runbook-href") or ""
        assert target.startswith(f"{PAGE}/runbooks#"), target
        assert entry.select_one(f'a[href="{target}"]') is not None
        assert _split(target)[1] in runbook_ids, f"{name}: {target} names no heading of the runbooks"


async def test_every_help_fix_link_of_the_health_checks_lands_on_an_element(page: Any) -> None:
    """Health checks link to `/admin/help/runbooks#<anchor>` and `/admin/help/operations#<name>`."""
    seen = 0
    pages: dict[str, set[str]] = {}
    for spec in HEALTH_SPECS:
        if not spec.fix_link.startswith(f"{PAGE}/"):
            continue
        path, anchor = _split(spec.fix_link)
        if path not in pages:
            response = await page.get(path)
            assert response.status_code == 200, (spec.id, path)
            pages[path] = set(parse_html(response.text).ids())
        assert anchor in pages[path], f"{spec.id}: {spec.fix_link} lands on nothing"
        seen += 1
    assert seen >= 10
    assert {"/admin/help/runbooks", "/admin/help/operations"} <= set(pages)


HELP_LINK = re.compile(r"""["'](/admin/help(?:/[a-z-]+)?#[a-z0-9-]+)["']""")


def _template_help_links() -> set[str]:
    """Every literal `/admin/help...#anchor` link in the dashboard templates (the development gallery left out)."""
    from roxy.core.templating import TEMPLATES_DIR

    links: set[str] = set()
    for path in TEMPLATES_DIR.rglob("*.html"):
        if "_gallery" not in path.parts:
            links.update(HELP_LINK.findall(path.read_text(encoding="utf-8")))
    return links


async def test_every_help_link_written_in_a_dashboard_template_lands_on_an_element(page: Any) -> None:
    """Pages link into Help by hand too (`/admin/help/runbooks#alert-channels-down` on System > Alerts): every such
    literal link in the dashboard templates (the development gallery aside) must land on an element."""
    links = _template_help_links()
    assert "/admin/help/runbooks#alert-channels-down" in links
    ids: dict[str, set[str]] = {}
    for link in sorted(links):
        path, anchor = _split(link)
        if path not in ids:
            response = await page.get(path)
            assert response.status_code == 200, link
            ids[path] = set(parse_html(response.text).ids())
        assert anchor in ids[path], f"{link} lands on nothing"


async def test_the_operations_names_are_anchors_before_their_runbooks(page: Any) -> None:
    response = await page.get(f"{PAGE}/operations")
    links = _help_docs.parse_link_index((_help_docs.DOCS_DIR / "RUNBOOKS.md").read_text(encoding="utf-8"))
    operations = [link for link in links if link.operations]
    assert operations
    doc = parse_html(response.text)
    for link in operations:
        name = link.name.removeprefix("operations#")
        assert doc.select_one(f"#{name}") is not None, name
        assert doc.select_one(f"#{link.anchor}") is not None, link.anchor
    assert 'id="environment"></span><div class="heading heading-h2"><h2 id="proxy-variables-in-the-environment">' in (
        response.text
    )


@pytest.mark.parametrize("path", DOC_PATHS, ids=lambda p: p.rsplit("/", 1)[1])
async def test_every_document_renders_with_the_shell_one_h1_and_unique_ids(page: Any, path: str) -> None:
    response = await page.get(path)
    assert response.status_code == 200, path
    html = response.text
    doc = parse_html(html)
    assert len(doc.select("h1")) == 1
    assert doc.select_one("body").get("data-page") == "help"
    assert doc.select_one('a[aria-current="page"][data-nav-id="help"]') is not None
    ids = doc.ids()
    assert len(ids) == len(set(ids)), sorted({i for i in ids if ids.count(i) > 1})
    assert find_style_issues(html, path) == []
    assert "<script>" not in html
    for link in doc.select(".doc-toc__list a"):
        href = link.get("href") or "#"
        if href.startswith(f"{GUIDE}/") or href.startswith(f"{GUIDE}#"):
            continue  # the guide's contents link its other chapters (test_every_in_guide_link_lands_on_its_target)
        assert href[1:] in set(ids), href
    for region in doc.select(".doc-table"):
        assert region.get("tabindex") == "0"
        assert region.get("role") == "region"
        assert region.select_one("table") is not None


# ============================================================================================ the admin guide

GUIDE = f"{PAGE}/guide"
GUIDE_PAGE_MAX_BYTES = 200 * 1024
"""The heaviest guide page (the Protection chapter, about 72 KB of HTML plus the 80 KB shell) stays below this. As
one page the guide was about 640 KB: too heavy for a phone, which is why it is shown one chapter at a time."""


def _book() -> _help_docs.GuideBook:
    book = _help_docs.load_guide()
    assert book is not None, "docs/ADMIN_GUIDE.md is missing"
    return book


def _guide_pages() -> list[str]:
    return [GUIDE, *(f"{GUIDE}/{chapter.slug}" for chapter in _book().chapters[1:])]


async def test_the_admin_guide_renders_with_its_contents_and_the_outline(page: Any) -> None:
    """`docs/ADMIN_GUIDE.md` is the written guide: `/admin/help/guide` shows its introduction, its contents (every
    chapter linked) and its first chapter, "Getting started" (other files link `/admin/help/guide#getting-started`).
    The card links it with its chapters and still points each plan 16.3 topic to the pages that cover it."""
    assert (_help_docs.DOCS_DIR / "ADMIN_GUIDE.md").is_file()
    book = _book()
    titles = [chapter.title for chapter in book.chapters]
    assert titles[0] == "Getting started"
    assert {"Daily routine", "Alerts", "Backups and resets", "The operator CLI", "Glossary"} <= set(titles)
    assert {spec.title for spec in registry.PAGES} <= set(titles)  # one chapter per dashboard page
    guide = await page.doc(GUIDE)
    assert len(guide.select("h1")) == 1
    assert guide.select_one("h1").text() == book.title
    assert guide.select_one("article.doc h2#getting-started") is not None  # old links land on the first chapter
    contents = [link.get("href") for link in guide.select('nav[aria-labelledby="guide-contents"] a')]
    assert contents == [chapter.href for chapter in book.chapters]
    assert contents[0] == f"{GUIDE}#getting-started"
    assert contents[1] == f"{GUIDE}/daily-routine"
    assert [node.text() for node in guide.select("article.doc h2")] == ["Contents", "Getting started"]
    pager = guide.select_one('nav[aria-labelledby="guide-pager-title"]')
    assert pager is not None
    assert "Next: Daily routine" in " ".join(pager.text().split())
    card = (await page.doc(PAGE)).select_one("section#guide")
    assert card is not None
    assert card.select_one(f'a[href="{GUIDE}"]') is not None
    assert [link.get("href") for link in card.select(".help-toc a")] == contents
    assert len(card.select(".help-chapter__title")) == 12
    assert "not part of this release" not in card.text()


async def test_every_chapter_of_the_guide_renders_as_its_own_page(page: Any) -> None:
    """One page per `##` chapter: the shell, one h1, the chapter's own heading, unique ids, clean markup (no inline
    script or style: the CSP), the contents with this chapter's sections, and Previous and Next in the guide's order."""
    book = _book()
    assert len(book.chapters) == 27
    for chapter in book.chapters:
        path = GUIDE if chapter.first else f"{GUIDE}/{chapter.slug}"
        response = await page.get(path)
        assert response.status_code == 200, path
        html = response.text
        doc = parse_html(html)
        assert len(doc.select("h1")) == 1, path
        assert doc.select_one("body").get("data-page") == "help"
        assert doc.select_one('a[aria-current="page"][data-nav-id="help"]') is not None
        assert doc.select_one(f"article.doc h2#{chapter.slug}") is not None, path
        assert doc.select_one(f'.doc-toc__list a[aria-current="page"][href="#{chapter.slug}"]') is not None, path
        for entry in chapter.sections:
            assert doc.select_one(f'.doc-toc__list a[href="#{entry.anchor}"]') is not None, (path, entry.anchor)
        ids = doc.ids()
        assert len(ids) == len(set(ids)), (path, sorted({i for i in ids if ids.count(i) > 1}))
        assert find_style_issues(html, path) == [], path
        assert "<script>" not in html
        before, after = book.neighbors(chapter)
        pager = doc.select_one('nav[aria-labelledby="guide-pager-title"]')
        assert pager is not None, path
        hrefs = [link.get("href") for link in pager.select("a")]
        assert hrefs == [item.href for item in (before, after) if item is not None], path
        title = doc.select_one("title").text()
        assert title.startswith(book.title if chapter.first else f"{chapter.title}: {book.title}"), title
        if not chapter.first:
            assert f"Chapter {chapter.number} of 27" in doc.select_one(".page-header__purpose").text()


async def test_every_in_guide_link_lands_on_its_target(page: Any) -> None:
    """Every link of the guide still lands now that it is cut into pages: a `#anchor` names an id of the same page,
    a link to another chapter (`/admin/help/guide/<chapter>#anchor`, rewritten from the Markdown's `#anchor`) answers
    200 and has that id, and the links into the runbooks, the other documents and the glossary land on an element.
    Links to dashboard pages answer 200."""
    pages: dict[str, set[str]] = {}

    async def ids_of(path: str) -> set[str]:
        if path not in pages:
            response = await page.get(path)
            assert response.status_code == 200, path
            pages[path] = set(parse_html(response.text).ids())
        return pages[path]

    checked = 0
    for path in _guide_pages():
        doc = await page.doc(path)
        here = set(doc.ids())
        pages[path] = here
        for link in doc.select("article.doc a"):
            href = link.get("href") or ""
            target, _, anchor = href.partition("#")
            if href.startswith("#"):
                assert anchor in here, f"{path}: {href} lands on nothing"
            elif target.startswith("/admin/"):
                found = await ids_of(target)
                assert not anchor or anchor in found, f"{path}: {href} lands on nothing"
            else:
                assert href.startswith(("https://", "http://", "/docs")), f"{path}: unexpected link {href}"
                continue
            checked += 1
    assert checked > 400  # about 500 links: the guide's cross references, runbooks and glossary terms
    book = _book()
    assert {f"{GUIDE}/{chapter.slug}" for chapter in book.chapters[1:]} <= set(pages)


async def test_a_link_to_another_chapter_names_that_chapters_page(page: Any) -> None:
    """The Markdown says `[Step 9](#step-9-choose-where-alerts-go)` inside Getting started and `[Replace](#replace)`
    for a section of the Credential chapter: on the first page the first stays on the page, the second names the
    Credential chapter's page; the Credential chapter links back to Getting started on the guide's page."""
    first = await page.doc(GUIDE)
    assert first.select_one('article.doc a[href="#step-9-choose-where-alerts-go"]') is not None
    assert first.select_one(f'article.doc a[href="{GUIDE}/credential#replace"]') is not None
    assert first.select_one('article.doc a[href="#replace"]') is None
    alerts = await page.doc(f"{GUIDE}/alerts")
    assert alerts.select_one(f'article.doc a[href="{GUIDE}#step-9-choose-where-alerts-go"]') is not None


async def test_the_largest_guide_page_stays_light(page: Any) -> None:
    sizes = {}
    for path in _guide_pages():
        response = await page.get(path)
        assert response.status_code == 200, path
        sizes[path] = len(response.content)
    largest = max(sizes, key=lambda path: sizes[path])
    assert sizes[largest] < GUIDE_PAGE_MAX_BYTES, (largest, sizes[largest])


async def test_unknown_chapters_are_not_pages_and_the_first_one_has_one_address(page: Any, anon: Any) -> None:
    for path in (
        f"{GUIDE}/no-such-chapter",
        f"{GUIDE}/Overview",
        f"{GUIDE}/overview.md",
        f"{GUIDE}/{'a' * 120}",
        f"{GUIDE}/fragment",
    ):
        response = await page.get(path)
        assert response.status_code == 404, path
    first = await page.get(f"{GUIDE}/getting-started")
    assert first.status_code == 302
    assert first.headers["location"] == f"{GUIDE}#getting-started"
    response = await anon.get(f"{GUIDE}/overview")
    assert response.status_code == 302
    assert response.headers["location"] == "/admin"


async def test_the_unwritten_admin_guide_says_so_and_points_to_the_outline(
    page: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Without `ADMIN_GUIDE.md` (a release without the guide) the card says so and the outline is the guide; a
    chapter address is then a 404."""
    for spec in _help_docs.DOCS:
        source = _help_docs.DOCS_DIR / spec.file
        if spec.slug != "guide" and source.is_file():
            (tmp_path / spec.file).write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.setattr(_help_docs, "DOCS_DIR", tmp_path)
    doc = await page.doc(GUIDE)
    assert "The admin guide is not part of this release" in doc.text()
    assert doc.select_one('a[href="/admin/help#guide"]') is not None
    assert (await page.get(f"{GUIDE}/overview")).status_code == 404
    card = (await page.doc(PAGE)).select_one("section#guide")
    assert card is not None
    assert "not part of this release" in card.text()
    titles = [node.text() for node in card.select(".help-chapter__title")]
    assert len(titles) == 12  # plan 16.3 has twelve chapters
    assert titles[0] == "First-time setup"
    assert titles[-1] == "Glossary"


async def test_a_missing_document_folder_never_fails_the_page(
    page: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(_help_docs, "DOCS_DIR", tmp_path)
    for path in (PAGE, f"{PAGE}/runbooks", f"{PAGE}/architecture"):
        response = await page.get(path)
        assert response.status_code == 200, path
        assert "data-card-error" not in response.text
    doc = await page.doc(f"{PAGE}/runbooks")
    assert "This document is not part of this release" in doc.text()
    card = (await page.doc(PAGE)).select_one("section#guide")
    assert "their index is empty" in card.text()


async def test_the_shortcuts_are_the_overlays_own_list(page: Any) -> None:
    doc = await page.doc(PAGE)
    overlay = doc.select_one("dialog#shortcuts")
    card = doc.select_one(f"section#{help_page.SHORTCUTS_CARD}")
    assert overlay is not None
    assert card is not None

    def rows(root: Any) -> list[tuple[str, str]]:
        return [(row.select_one("dt").text(), row.select_one("dd").text()) for row in root.select("dl div")]

    assert rows(card) == rows(overlay)
    general = [(help_page.keys_text(keys), what) for keys, what in help_page.GENERAL_SHORTCUTS]
    assert rows(card)[: len(general)] == general
    assert card.select_one("input[data-shortcuts-toggle]") is not None


async def test_every_page_says_what_it_is_for_from_the_registry(page: Any) -> None:
    card = (await page.doc(PAGE)).select_one("section#pages")
    assert card is not None
    for spec in registry.PAGES:
        item = card.select_one(f"#page-{spec.id}")
        assert item is not None, spec.id
        assert spec.purpose in " ".join(item.text().split())
        assert item.select_one(f'a[href="/admin/{spec.id}"]') is not None
        for paragraph in spec.how_to_read:
            assert paragraph in item.text()


@pytest.mark.parametrize(
    "params",
    [{"range": "forever"}, {"q": "x" * 500}, {"page": "abc"}, {"range": "custom", "from": "yesterday"}],
    ids=lambda p: "-".join(p),
)
async def test_no_parameter_ever_fails_the_page_or_a_document(page: Any, params: dict[str, str]) -> None:
    for path in (PAGE, f"{PAGE}/fragment/glossary", f"{PAGE}/runbooks"):
        response = await page.get(path, params=params)
        assert response.status_code == 200, (path, params)
        assert "data-card-error" not in response.text


async def test_unknown_documents_are_not_pages(page: Any) -> None:
    for path in (f"{PAGE}/settings.md", f"{PAGE}/SETTINGS", f"{PAGE}/../docs", f"{PAGE}/fragment"):
        response = await page.get(path)
        assert response.status_code == 404, path


def test_the_link_index_parser_reads_every_row_of_the_runbooks() -> None:
    text = (_help_docs.DOCS_DIR / "RUNBOOKS.md").read_text(encoding="utf-8")
    links = _help_docs.parse_link_index(text)
    names = {link.name for link in links}
    alerts = {spec.runbook for spec in ALERT_SPECS.values() if spec.runbook}
    assert alerts <= names
    assert all(link.anchor and link.title for link in links)
    assert _help_docs.parse_link_index("# nothing\n\n| `x` | y | [z](#z) |\n") == ()


def test_documents_render_once_per_file_version(tmp_path: Path) -> None:
    spec = _help_docs.DocSpec("t", "T.md", "T", "A test document.")
    (tmp_path / "T.md").write_text("# Title here\n\n## One\n\n| a | b |\n|---|---|\n| 1 | 2 |\n", encoding="utf-8")
    first = _help_docs.load_doc(spec, tmp_path)
    assert first is not None
    assert first.title == "Title here"
    assert "<h1" not in str(first.html)
    assert '<div class="doc-table" role="region" tabindex="0" aria-label="Table 1"><table>' in str(first.html)
    assert _help_docs.load_doc(spec, tmp_path) is first
    (tmp_path / "T.md").write_text("# Title here\n\n<script>alert(1)</script>\n", encoding="utf-8")
    second = _help_docs.load_doc(spec, tmp_path)
    assert second is not None
    assert second is not first
    assert "<script>" not in str(second.html)
    assert _help_docs.load_doc(_help_docs.DocSpec("u", "U.md", "U", "Missing."), tmp_path) is None
