"""The documents of the Help page: which guides it serves, how they are rendered once, and the runbook link index.

What this is
    `DOCS` lists the repository guides the Help page renders at `/admin/help/<slug>` (the admin guide, the runbooks,
    the architecture, security, learning path and performance guides). `load_doc(spec)` renders one with the public
    site's Markdown renderer (`roxy.public.pages.render_guide`, the one renderer of every guide) and caches it per
    file version; `runbook_links()` reads the machine-readable "Link index" table of `docs/RUNBOOKS.md`, the table
    that resolves every runbook name the alerts and the health checks link to.

Why it exists
    Plan 14.1 and 16.3 put the admin guide on the Help page, and plan 17.7 and 13.2 send the owner from an alert
    email or a failed health check to a runbook: alerts link to `/admin/help#runbook-<name>`
    (`roxy.notify.notifier.runbook_link`), health checks to `/admin/help/runbooks#<anchor>` and
    `/admin/help/operations#<name>` (`roxy.health.checks`). Every one of those links must land on its runbook.
    `docs/ADMIN_GUIDE.md` is not written yet (the docs lane writes it later); until it exists, its page and the
    Help card say so and point to where each chapter's material already lives.

How it works
    The documents live in `docs/` next to the glossary (`texts.GLOSSARY_PATH.parent`, found the same way, so a
    release ships them together). Rendering is blocking (it reads and parses a file of up to about 90 KB), so the
    page calls `load_doc` through `asyncio.to_thread`; the result is kept per slug until the file's size or mtime
    changes (one entry per document, bounded by `DOCS`). After rendering, the page's own `<h1>` replaces the
    document's (one h1 per page), every table is wrapped in a keyboard-focusable scroll region (a wide table must
    never widen a phone screen, and a scrolling region must be reachable with the keyboard), and on the runbooks the
    `operations#<name>` names of the link index get an anchor just before their runbook's heading. Markdown is
    rendered with raw HTML escaped (markdown-it `html=False`), so nothing in a document becomes markup by itself.

What to read next
    `roxy/admin/pages/help.py` (the routes), `roxy/public/pages.py` (`render_guide`, `slugify`), `docs/RUNBOOKS.md`
    (its "Link index"), `tests/unit/test_docs_references.py` (which pins that index against the alerts and checks).
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from markupsafe import Markup

from roxy.admin.pages.texts import GLOSSARY_PATH
from roxy.public.pages import TocEntry, render_guide

DOCS_DIR: Final = GLOSSARY_PATH.parent
"""`docs/` of this checkout or release (the glossary's directory, found by `texts.find_glossary`)."""

RUNBOOKS_FILE: Final = "RUNBOOKS.md"
LINK_INDEX_HEADING: Final = "## Link index"
OPERATIONS_PREFIX: Final = "operations#"
MAX_DOC_BYTES: Final = 1024 * 1024
"""Largest document the Help page renders (the biggest guide is under 100 KB; plan P9: every read is bounded)."""


@dataclass(frozen=True, slots=True)
class DocSpec:
    """One document the Help page serves at `/admin/help/<slug>`."""

    slug: str
    file: str
    title: str
    about: str
    listed: bool = True
    aliases: bool = False


DOCS: Final[tuple[DocSpec, ...]] = (
    DocSpec(
        "guide",
        "ADMIN_GUIDE.md",
        "Admin guide",
        "How to run Roxy day to day, one chapter per dashboard page.",
    ),
    DocSpec(
        "runbooks",
        RUNBOOKS_FILE,
        "Runbooks",
        "What to do when something goes wrong: symptoms, how to confirm, the fix, how to check it worked.",
        aliases=True,
    ),
    DocSpec(
        "operations",
        RUNBOOKS_FILE,
        "Runbooks",
        "The runbooks, reached from the operations links of the health checks.",
        listed=False,
        aliases=True,
    ),
    DocSpec(
        "architecture",
        "ARCHITECTURE.md",
        "Architecture",
        "How Roxy is built: the processes, the databases, the request path and the background jobs.",
    ),
    DocSpec(
        "security",
        "SECURITY.md",
        "Security",
        "How Roxy protects the credential, the admin sign-in and your data, and what each defense is for.",
    ),
    DocSpec(
        "learning-path",
        "LEARNING_PATH.md",
        "Learning path",
        "Twelve chapters that teach how the code works, each with the files to read, its tests and an exercise.",
    ),
    DocSpec(
        "performance",
        "PERFORMANCE.md",
        "Performance",
        "How fast Roxy is on the production box, how it was measured and how to measure it again.",
    ),
)
DOC_BY_SLUG: Final[dict[str, DocSpec]] = {spec.slug: spec for spec in DOCS}


@dataclass(frozen=True, slots=True)
class RenderedDoc:
    """A document rendered for the Help page: its title, body, contents and every element id in the body."""

    spec: DocSpec
    title: str
    html: Markup
    toc: tuple[TocEntry, ...]
    ids: frozenset[str]


@dataclass(frozen=True, slots=True)
class RunbookLink:
    """One row of the runbooks' link index: the link name, who links to it, and the runbook it lands on."""

    name: str
    used_by: str
    title: str
    anchor: str

    @property
    def operations(self) -> bool:
        """True for an `operations#<name>` row (health check links to `/admin/help/operations#<name>`)."""
        return self.name.startswith(OPERATIONS_PREFIX)

    @property
    def href(self) -> str:
        return f"/admin/help/runbooks#{self.anchor}"


def doc_path(spec: DocSpec, directory: Path | None = None) -> Path:
    return (directory or DOCS_DIR) / spec.file


def _read(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_DOC_BYTES:
            return None
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


# ============================================================================================ the link index

_INDEX_ROW: Final = re.compile(r"^\|\s*`([^`|]+)`\s*\|(.*)\|\s*\[([^\]]+)\]\(#([a-z0-9-]+)\)\s*\|\s*$")


def parse_link_index(text: str) -> tuple[RunbookLink, ...]:
    """The rows of the "Link index" table of the runbooks (`| \\`name\\` | used by | [Title](#anchor) |`)."""
    rows: list[RunbookLink] = []
    inside = False
    for line in text.splitlines():
        if line.strip() == LINK_INDEX_HEADING:
            inside = True
            continue
        if inside and line.startswith("## "):
            break
        if not inside:
            continue
        match = _INDEX_ROW.match(line.strip())
        if match:
            name, used_by, title, anchor = (part.strip() for part in match.groups())
            rows.append(RunbookLink(name, used_by, title, anchor))
    return tuple(rows)


_index_lock = threading.Lock()
_index_cache: dict[Path, tuple[int, int, tuple[RunbookLink, ...]]] = {}


def runbook_links(directory: Path | None = None) -> tuple[RunbookLink, ...]:
    """The link index of `docs/RUNBOOKS.md` (cached per file version; empty when the file cannot be read).

    Blocking (a stat and maybe a read): page routes call it on a thread."""
    path = (directory or DOCS_DIR) / RUNBOOKS_FILE
    try:
        stat = path.stat()
    except OSError:
        return ()
    cached = _index_cache.get(path)
    if cached is not None and cached[:2] == (stat.st_mtime_ns, stat.st_size):
        return cached[2]
    text = _read(path)
    rows = parse_link_index(text) if text is not None else ()
    with _index_lock:
        if len(_index_cache) >= 4 and path not in _index_cache:
            _index_cache.clear()  # bounded (plan P9); only tests read more than one copy
        _index_cache[path] = (stat.st_mtime_ns, stat.st_size, rows)
    return rows


# ============================================================================================ rendering

_LEADING_H1: Final = re.compile(r'^\s*<h1 id="[^"]*">.*?</h1>\s*', re.DOTALL)
_TABLE_OPEN: Final = "<table>"
_TABLE_CLOSE: Final = "</table>"
_ID: Final = re.compile(r'\bid="([^"]+)"')


def _wrap_tables(html: str) -> str:
    """Each `<table>` inside a focusable, labeled scroll region (markdown-it writes the bare tag, never attributes)."""
    out: list[str] = []
    rest = html
    number = 0
    while _TABLE_OPEN in rest:
        before, _, after = rest.partition(_TABLE_OPEN)
        number += 1
        out.append(before)
        out.append(f'<div class="doc-table" role="region" tabindex="0" aria-label="Table {number}">{_TABLE_OPEN}')
        rest = after.replace(_TABLE_CLOSE, f"{_TABLE_CLOSE}</div>", 1)
    out.append(rest)
    return "".join(out)


def _add_aliases(html: str, links: tuple[RunbookLink, ...]) -> str:
    """Put an anchor named after each `operations#<name>` row just before its runbook's heading (when the name is
    not already an id of the document), so `/admin/help/operations#<name>` lands on that runbook."""
    have = set(_ID.findall(html))
    for link in links:
        if not link.operations:
            continue
        alias = link.name[len(OPERATIONS_PREFIX) :]
        if not re.fullmatch(r"[a-z0-9-]+", alias) or alias in have:
            continue
        marker = f'<div class="heading heading-h2"><h2 id="{link.anchor}">'
        if marker not in html:
            continue
        html = html.replace(marker, f'<span class="doc-alias" id="{alias}"></span>{marker}', 1)
        have.add(alias)
    return html


def render_doc(spec: DocSpec, text: str) -> RenderedDoc:
    """Render one document's Markdown for the Help page (see the module docstring)."""
    rendered = render_guide(text, frozenset())  # no `{{ name }}` markers here: a brace pair stays as typed
    body = _LEADING_H1.sub("", str(rendered.html({})), count=1)
    body = _wrap_tables(body)
    if spec.aliases:
        body = _add_aliases(body, parse_link_index(text))
    title = rendered.title if rendered.title != "Roxy user guide" else spec.title
    html = Markup(body)  # noqa: S704 (markdown-it escaped the file: html=False; only our own tags were added)
    return RenderedDoc(spec, title, html, rendered.toc, frozenset(_ID.findall(body)))


_doc_lock = threading.Lock()
_doc_cache: dict[tuple[str, Path], tuple[int, int, RenderedDoc]] = {}


def load_doc(spec: DocSpec, directory: Path | None = None) -> RenderedDoc | None:
    """The rendered document, or None when its file does not exist (or cannot be read). Blocking: call it on a
    thread. Cached per slug and file version (at most one entry per `DOCS` slug, plus test copies)."""
    path = doc_path(spec, directory)
    try:
        stat = path.stat()
    except OSError:
        return None
    key = (spec.slug, path)
    cached = _doc_cache.get(key)
    if cached is not None and cached[:2] == (stat.st_mtime_ns, stat.st_size):
        return cached[2]
    text = _read(path)
    if text is None:
        return None
    doc = render_doc(spec, text)
    with _doc_lock:
        if len(_doc_cache) >= 2 * len(DOCS) and key not in _doc_cache:
            _doc_cache.clear()  # bounded (plan P9)
        _doc_cache[key] = (stat.st_mtime_ns, stat.st_size, doc)
    return doc


def available(directory: Path | None = None) -> dict[str, bool]:
    """Which documents exist (slug -> True when its file is there). Blocking: a stat per document."""
    return {spec.slug: doc_path(spec, directory).is_file() for spec in DOCS}


__all__ = [
    "DOCS",
    "DOCS_DIR",
    "DOC_BY_SLUG",
    "OPERATIONS_PREFIX",
    "DocSpec",
    "RenderedDoc",
    "RunbookLink",
    "available",
    "doc_path",
    "load_doc",
    "parse_link_index",
    "render_doc",
    "runbook_links",
]
