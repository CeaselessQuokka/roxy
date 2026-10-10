"""The Help page (`/admin/help`, plan 14.1, 14.6, 14.7, 16.3): the admin guide, the glossary, the shortcuts, and
what every page is for, plus the guides and runbooks at `/admin/help/<document>`.

What this is
    Four cards from the registry:
      * `guide`: the admin guide. `docs/ADMIN_GUIDE.md` is not written yet, so the card says so and walks the plan
        16.3 outline chapter by chapter, pointing to the pages, cards and documents that already cover each one;
        then the documents this page renders (runbooks, architecture, security, learning path, performance) and the
        incident runbook index, one entry per runbook name the alert emails link to (`#runbook-<name>`).
      * `glossary`: every term of `docs/glossary.yml` (`#term-<id>`, where every dotted term on the dashboard
        links), with a filter.
      * `shortcuts`: every keyboard shortcut (the same list the `?` overlay shows; the "go to" keys come from the page
        registry).
      * `pages`: "what does this page do" for every page, from the registry (purpose, how to read it, its cards).
    Extra routes: `GET /admin/help/<slug>` renders one document of `_help_docs.DOCS` with the shell around it:
    `/admin/help/runbooks#<anchor>` and `/admin/help/operations#<name>` are the links of the health checks.

Why it exists
    Plan 14.7: help comes from one source each (the glossary file, the registry, the docs), and every page has
    "What this page is for". Plan 17.7: alert emails link to `/admin/help#runbook-<name>`
    (`roxy.notify.notifier.runbook_link`), and health checks link into the runbooks (`roxy.health.checks`): every
    one of those links must reach its runbook (a test walks them all).

How it works
    The cards read no database: the glossary is loaded at startup (`shell.glossary_of`), the registry is data, and
    the documents are rendered once per file version on a worker thread (`_help_docs.load_doc`). `static/js/pages/
    help.js` filters the glossary and, when the address names `#runbook-<name>`, goes on to that runbook.

What to read next
    `roxy/admin/pages/_help_docs.py`, `templates/admin/pages/help.html`, `docs/RUNBOOKS.md` (its link index),
    `roxy/admin/pages/registry.py`.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any, Final

from fastapi import Request
from fastapi.responses import HTMLResponse

from roxy.admin.pages import _help_docs, registry, shell
from roxy.admin.pages._help_docs import DOC_BY_SLUG, DOCS, DocSpec, RunbookLink
from roxy.admin.pages.kit import Page, PageAdmin, PageView, templates_of
from roxy.admin.pages.texts import glossary_terms

page = Page("help")
router = page.router

DOC_TEMPLATE: Final = "admin/pages/help/doc.html"

Keys = tuple[tuple[str, ...], ...]
"""One shortcut: its alternatives, each a sequence of keys (`(("Ctrl", "K"), ("/",))` reads "Ctrl K or /")."""

GENERAL_SHORTCUTS: Final[tuple[tuple[Keys, str], ...]] = (
    ((("Ctrl", "K"), ("/",)), "Open the command palette"),
    ((("?",),), "Show this list"),
    ((("Esc",),), "Close a dialog, menu or the palette"),
    ((("T",),), "Cycle the time range"),
    ((("C",),), "Turn the comparison on or off"),
)
"""The general shortcuts of plan 14.6, as the `?` overlay lists them (`admin/_layout/shortcuts.html`; a test keeps
the two lists equal)."""

LIST_SHORTCUTS: Final[tuple[tuple[Keys, str], ...]] = (
    ((("Up", "Down"),), "Move between rows"),
    ((("Enter",),), "Open the row's details"),
    ((("P",),), "Pause or resume the live tail"),
)
"""The live tail and table keys, as the `?` overlay lists them."""


def keys_text(keys: Keys) -> str:
    """How a shortcut reads as plain text: `Ctrl K or /`."""
    return " or ".join(" ".join(sequence) for sequence in keys)


DOC_HOW_TO_READ: Final[tuple[str, ...]] = (
    "The contents list jumps to any section; every heading also has a # link you can copy to point someone at it.",
    "Commands are shown in boxes you can scroll sideways. They are meant for the server's console, as the "
    "runbooks explain; nothing on this page runs anything.",
)


def chapters() -> list[dict[str, Any]]:
    """The plan 16.3 outline of the admin guide, each chapter with the pages and documents that cover it today."""

    def link(label: str, href: str) -> dict[str, str]:
        return {"label": label, "href": href}

    return [
        {
            "title": "First-time setup",
            "text": "Create the admin, enroll your authenticator app and a passkey, keep the recovery codes, then set "
            "the credential, the rotator and where alerts go.",
            "links": [
                link("Security: passkeys and recovery codes", "/admin/security#passkeys"),
                link("Credential", "/admin/credential"),
                link("Egress: rotator", "/admin/egress#rotator"),
                link("Settings: alerts", "/admin/settings#alerts"),
            ],
        },
        {
            "title": "Daily routine",
            "text": "Look at the Overview, act on the recommendations, and run Check Proxy Health when something "
            "seems off.",
            "links": [
                link("Overview", "/admin/overview"),
                link("Recommendations", "/admin/recommendations"),
                link("Health", "/admin/health"),
            ],
        },
        {
            "title": "One chapter per dashboard page",
            "text": "Every page says what it is for in its first line and explains itself in its How to read this "
            "page panel; the list below has them all.",
            "links": [link("What each page does", "#pages")],
        },
        {
            "title": "Recommendations",
            "text": "How rules decide, how to read the evidence, preview with a dry run, apply and undo, and the "
            "guardrails of automatic apply.",
            "links": [
                link("Recommendations", "/admin/recommendations"),
                link("Engine settings", "/admin/recommendations#engine"),
            ],
        },
        {
            "title": "Rate limiting from Roblox",
            "text": "Buckets, cooldowns, breakers and serving stale answers keep Roxy below Roblox's limits; the "
            "runbook walks through a real incident.",
            "links": [
                link("Upstream", "/admin/upstream"),
                link("Runbook: Roblox is rate-limiting us", "/admin/help/runbooks#roblox-is-rate-limiting-us"),
            ],
        },
        {
            "title": "Protection",
            "text": "The order of the checks, which tool to use for which problem, and what the tarpit does.",
            "links": [
                link("Protection", "/admin/protection"),
                link("Runbook: Under attack", "/admin/help/runbooks#under-attack"),
            ],
        },
        {
            "title": "Egress and DataImpulse",
            "text": "Reading the rotator's usage and quota, and when to rotate more or less.",
            "links": [
                link("Egress", "/admin/egress"),
                link(
                    "Runbook: Rotator down or quota exhausted", "/admin/help/runbooks#rotator-down-or-quota-exhausted"
                ),
            ],
        },
        {
            "title": "Settings",
            "text": "How to read a setting, the risk levels, history and revert, and import and export.",
            "links": [link("Settings", "/admin/settings"), link("Change history", "/admin/settings#history")],
        },
        {
            "title": "Data",
            "text": "Retention, the statistics resets (narrower families such as one attempts tab, and the v1 "
            "targets that have nothing to reset), backups with the copies they replaced and the status of the "
            "server backup request, and restoring.",
            "links": [
                link("Data", "/admin/data"),
                link("Runbook: Backups", "/admin/help/runbooks#backups"),
                link("Runbook: Restore from backup", "/admin/help/runbooks#restore-from-backup"),
            ],
        },
        {
            "title": "Security",
            "text": "Sessions, passkeys, trusted devices, the kill switch link in the login email, the admin "
            "allowlist, and the rules for replacing the one credential.",
            "links": [link("Security", "/admin/security"), link("Credential: replace", "/admin/credential#replace")],
        },
        {
            "title": "Incident runbooks",
            "text": "Every alert email links to its runbook below. On the server, the operator command line "
            "(scripts/ctl.py, called roxyctl in the runbooks) pauses, flushes, runs health checks and backups.",
            "links": [
                link("Runbook index", "#runbook-index"),
                link("Everyday commands", "/admin/help/runbooks#everyday-commands"),
            ],
        },
        {
            "title": "Glossary",
            "text": "Every term the dashboard uses, in plain words.",
            "links": [link("Glossary", "#glossary")],
        },
    ]


@page.card("guide")
async def guide_card(view: PageView) -> dict[str, Any]:
    """The admin guide card: the guide (or its outline while it is unwritten), the documents, the runbook index."""

    def read() -> tuple[dict[str, bool], tuple[RunbookLink, ...]]:
        return _help_docs.available(), _help_docs.runbook_links()

    present, links = await asyncio.to_thread(read)
    guide = None
    if present.get("guide"):
        guide = await asyncio.to_thread(_help_docs.load_doc, DOC_BY_SLUG["guide"])
    return {
        "guide": guide,
        "chapters": chapters(),
        "documents": [spec for spec in DOCS if spec.listed and spec.slug != "guide" and present.get(spec.slug)],
        "missing": [spec for spec in DOCS if spec.listed and spec.slug != "guide" and not present.get(spec.slug)],
        "runbooks": [link for link in links if not link.operations],
    }


@page.card("glossary")
async def glossary_card(view: PageView) -> dict[str, Any]:
    """Every glossary term, sorted (`docs/glossary.yml`, loaded at startup)."""
    entries = view.shell.context["glossary"] if view.shell else shell.glossary_of(view.request)
    return {"terms": glossary_terms(entries)}


@page.card("shortcuts")
async def shortcuts_card(view: PageView) -> dict[str, Any]:
    """The shortcuts of the `?` overlay; the "go to" keys come from the page registry."""
    nav = registry.nav_model()
    goto = [
        ((tuple(key.upper() for key in item["keys"].split()),), item["label"]) for item in nav["pages"] if item["keys"]
    ]
    return {"general": GENERAL_SHORTCUTS, "goto": goto, "lists": LIST_SHORTCUTS}


@page.card("pages")
async def pages_card(view: PageView) -> dict[str, Any]:
    """Every page's purpose, how to read it, and its cards (the registry, the one source of these texts)."""
    listing = []
    for item in registry.describe():
        spec = registry.page(str(item["id"]))
        listing.append(
            {**item, "href": spec.href, "how_to_read": spec.how_to_read, "built": registry.is_built(spec.id)}
        )
    return {"pages": listing}


# ============================================================================================ the documents


async def render_doc_page(request: Request, principal: Any, spec: DocSpec) -> HTMLResponse:
    """One document with the shell around it (`/admin/help/<slug>`); a missing file says so (200, never a 500)."""
    built = await shell.build_shell(request, principal, page.spec)
    doc = await asyncio.to_thread(_help_docs.load_doc, spec)
    title = doc.title if doc is not None else spec.title
    context = {
        **built.context,
        "page": {"id": page.id, "title": title, "purpose": spec.about, "how_to_read": DOC_HOW_TO_READ},
        "doc": doc,
        "spec": spec,
        "toc": [entry for entry in doc.toc if entry.level == 2] if doc is not None else [],
        "documents": [item for item in DOCS if item.listed],
        "page_assets": page.assets,
    }
    return templates_of(request).render(request, DOC_TEMPLATE, context)


def _doc_route(spec: DocSpec) -> Callable[[Request, PageAdmin], Awaitable[HTMLResponse]]:
    async def route(request: Request, principal: PageAdmin) -> HTMLResponse:
        return await render_doc_page(request, principal, spec)

    return route


for _spec in DOCS:
    router.add_api_route(
        f"/{_spec.slug}",
        _doc_route(_spec),
        methods=["GET"],
        name=f"page_help_doc_{_spec.slug.replace('-', '_')}",
        include_in_schema=False,
    )


__all__ = ["GENERAL_SHORTCUTS", "LIST_SHORTCUTS", "chapters", "page", "render_doc_page", "router"]
