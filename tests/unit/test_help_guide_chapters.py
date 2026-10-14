"""The admin guide cut into chapters (`roxy.admin.pages._help_docs.cut_guide`, `load_guide`): unit tests.

What this is
    The Help page shows `docs/ADMIN_GUIDE.md` one `##` chapter at a time. These tests cut small guides written here
    and check the parts: the introduction, one chapter per `##` heading with its `###` sections, every in-guide link
    pointed at the page that holds its target, the addresses (`/admin/help/guide` for the first chapter,
    `/admin/help/guide/<chapter>` for the others), the bound on the number of chapters, and the cache per file version.
    One test cuts the real guide and checks that every in-guide link names an id the guide has.

Why it exists
    A cut in the wrong place, or a link left pointing at an id of another page, sends the owner nowhere while reading
    the guide; the integration tests (tests/integration/pages/test_page_help.py) check the pages the app serves, these
    check the rules themselves, fast.

What to read next
    `roxy/admin/pages/_help_docs.py`, `roxy/admin/pages/help.py`, `templates/admin/pages/help/guide_chapter.html`.
"""

from __future__ import annotations

import re
from pathlib import Path

from roxy.admin.pages import _help_docs
from roxy.admin.pages._help_docs import GUIDE_PATH, DocSpec, chapter_href, cut_guide, render_doc

SPEC = DocSpec("guide", "ADMIN_GUIDE.md", "Admin guide", "The guide.")

SMALL = """# Small guide

Read [the first chapter](#first) or [a section of the second](#second-part), or [nowhere](#no-such-place).

## First

The first chapter, with [its own section](#first-part) and [the third chapter](#third).

### First part

Text.

## Second

```html
<div class="heading heading-h2"><h2 id="fake">not a chapter</h2></div>
```

### Second part

Back to [the first part](#first-part) and [the start of the first](#first).

## Third

[The second chapter](#second). A [runbook](/admin/help/runbooks#deploy-failed) stays as written.
"""


def test_the_cut_has_the_introduction_and_one_chapter_per_heading() -> None:
    book = cut_guide(render_doc(SPEC, SMALL))
    assert book.title == "Small guide"
    assert [chapter.slug for chapter in book.chapters] == ["first", "second", "third"]
    assert [chapter.title for chapter in book.chapters] == ["First", "Second", "Third"]
    assert [chapter.number for chapter in book.chapters] == [1, 2, 3]
    assert [entry.anchor for entry in book.chapters[0].sections] == ["first-part"]
    assert [entry.anchor for entry in book.chapters[1].sections] == ["second-part"]
    assert book.chapters[2].sections == ()
    assert "Read" in str(book.intro)
    assert "<h1" not in str(book.intro)
    # A code block that shows heading markup is escaped text, never a cut.
    assert "&lt;div class=&quot;heading heading-h2&quot;&gt;" in str(book.chapters[1].html)
    assert book.chapters[1].ids == frozenset({"second", "second-part"})
    assert book.chapter("third") is book.chapters[2]
    assert book.chapter("fake") is None
    assert book.neighbors(book.chapters[0]) == (None, book.chapters[1])
    assert book.neighbors(book.chapters[2]) == (book.chapters[1], None)


def test_links_point_at_the_page_that_holds_their_target() -> None:
    book = cut_guide(render_doc(SPEC, SMALL))
    intro, first, second, third = (str(part) for part in (book.intro, *(c.html for c in book.chapters)))
    # The introduction is on the first page: a link into the first chapter stays, one into the second moves.
    assert 'href="#first"' in intro
    assert f'href="{GUIDE_PATH}/second#second-part"' in intro
    assert 'href="#no-such-place"' in intro  # an id the guide lacks stays as written (the integration test reports it)
    assert 'href="#first-part"' in first
    assert f'href="{GUIDE_PATH}/third"' in first  # the chapter's own heading: its page, no fragment
    assert f'href="{GUIDE_PATH}#first-part"' in second  # the first chapter lives on the guide's own page
    assert f'href="{GUIDE_PATH}#first"' in second
    assert f'href="{GUIDE_PATH}/second"' in third
    assert 'href="/admin/help/runbooks#deploy-failed"' in third
    # Each heading's own "#" link stays on its page.
    assert 'class="anchor" href="#second-part"' in second


def test_chapter_addresses() -> None:
    assert chapter_href("getting-started", first=True) == f"{GUIDE_PATH}#getting-started"
    assert chapter_href("getting-started", "step-9", first=True) == f"{GUIDE_PATH}#step-9"
    assert chapter_href("overview") == f"{GUIDE_PATH}/overview"
    assert chapter_href("overview", "overview") == f"{GUIDE_PATH}/overview"
    assert chapter_href("overview", "status") == f"{GUIDE_PATH}/overview#status"
    book = cut_guide(render_doc(SPEC, SMALL))
    assert [chapter.href for chapter in book.chapters] == [
        f"{GUIDE_PATH}#first",
        f"{GUIDE_PATH}/second",
        f"{GUIDE_PATH}/third",
    ]


def test_a_guide_without_chapters_is_its_introduction() -> None:
    book = cut_guide(render_doc(SPEC, "# Only a title\n\nSome text with [a link](#nothing).\n"))
    assert book.chapters == ()
    assert "Some text" in str(book.intro)


def test_the_number_of_chapters_is_bounded() -> None:
    text = "# Many\n\n" + "".join(f"## Chapter {n}\n\nText {n}.\n\n" for n in range(_help_docs.MAX_GUIDE_CHAPTERS + 5))
    book = cut_guide(render_doc(SPEC, text))
    assert len(book.chapters) == _help_docs.MAX_GUIDE_CHAPTERS
    last = str(book.chapters[-1].html)
    assert f"Text {_help_docs.MAX_GUIDE_CHAPTERS + 4}." in last  # the rest stays readable in the last page


def test_the_guide_is_cut_once_per_file_version(tmp_path: Path) -> None:
    (tmp_path / "ADMIN_GUIDE.md").write_text(SMALL, encoding="utf-8")
    first = _help_docs.load_guide(tmp_path)
    assert first is not None
    assert _help_docs.load_guide(tmp_path) is first
    (tmp_path / "ADMIN_GUIDE.md").write_text(SMALL + "\n## Fourth\n\n<script>alert(1)</script>\n", encoding="utf-8")
    second = _help_docs.load_guide(tmp_path)
    assert second is not None
    assert second is not first
    assert [chapter.slug for chapter in second.chapters][-1] == "fourth"
    assert "<script>" not in str(second.chapters[-1].html)  # raw HTML in the file is escaped
    assert _help_docs.load_guide(tmp_path / "missing") is None


def test_every_link_of_the_real_guide_names_an_id_it_has() -> None:
    """The shipped guide: every `#anchor` link is an id of some chapter (the cut can only point a link at the page
    holding its target if the target exists)."""
    book = _help_docs.load_guide()
    assert book is not None
    every_id = set().union(*(chapter.ids for chapter in book.chapters))
    assert book.chapters[0].slug == "getting-started"
    missing: list[str] = []
    for chapter in book.chapters:
        for href in re.findall(r'href="([^"]+)"', str(chapter.html)):
            target, _, anchor = href.partition("#")
            if href.startswith("#") and anchor not in chapter.ids:
                missing.append(f"{chapter.slug}: {href} (not on its page)")
            elif target.startswith(GUIDE_PATH) and anchor and anchor not in every_id:
                missing.append(f"{chapter.slug}: {href}")
    assert missing == []
