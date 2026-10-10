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

from pathlib import Path
from typing import Any

import pytest

from roxy.admin.pages import _help_docs, help as help_page, registry
from roxy.admin.pages.testing import parse_html
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
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    assert set(duplicates) <= {REGISTRY_CLASH, f"{REGISTRY_CLASH}-title"}, duplicates


REGISTRY_CLASH = "shortcuts"
"""The registry names a Help card `shortcuts`, the id of the shell's `?` overlay dialog (admin/_layout/shortcuts.html):
two elements share the id, so `openDialog("shortcuts")` finds the card instead of the dialog on this page. The fix is
a registry change (the card id `keys`), requested from the integrator; see `.remake/p11_reports/g7_settings.md`."""


@pytest.mark.xfail(strict=True, reason="registry card help#shortcuts collides with the shell dialog #shortcuts")
async def test_no_id_on_the_help_page_is_used_twice(page: Any) -> None:
    ids = parse_html((await page.get(PAGE)).text).ids()
    assert len(ids) == len(set(ids)), sorted({i for i in ids if ids.count(i) > 1})


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
    assert f'id="environment"></span><div class="heading heading-h2"><h2 id="proxy-variables-in-the-environment">' in (
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
        assert (link.get("href") or "#")[1:] in set(ids), link.get("href")
    for region in doc.select(".doc-table"):
        assert region.get("tabindex") == "0"
        assert region.get("role") == "region"
        assert region.select_one("table") is not None


async def test_the_unwritten_admin_guide_says_so_and_points_to_the_outline(page: Any) -> None:
    if (_help_docs.DOCS_DIR / "ADMIN_GUIDE.md").exists():
        pytest.skip("docs/ADMIN_GUIDE.md exists now: the guide renders instead of its outline")
    doc = await page.doc(f"{PAGE}/guide")
    assert "The admin guide is not written yet" in doc.text()
    assert doc.select_one('a[href="/admin/help#guide"]') is not None
    card = (await page.doc(PAGE)).select_one("section#guide")
    assert card is not None
    assert "not part of this release yet" in card.text()
    titles = [node.text() for node in card.select(".help-chapter__title")]
    assert len(titles) == 12  # plan 16.3 has twelve chapters
    assert titles[0] == "First-time setup" and titles[-1] == "Glossary"


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
    card = doc.select_one("section#shortcuts")
    assert overlay is not None and card is not None

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
    assert second is not None and second is not first
    assert "<script>" not in str(second.html)
    assert _help_docs.load_doc(_help_docs.DocSpec("u", "U.md", "U", "Missing."), tmp_path) is None
