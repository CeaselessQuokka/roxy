"""Accessibility review of the P11 dashboard pages, server-side reproductions (lens: WCAG 2.2 AA).

What this is
    The accessibility finding that shows in the rendered HTML, without a browser (`.remake/p11_review/find_a11y.md`;
    the browser ones are in test_a11y_e2e.py). It was a strict xfail naming its finding (`a11y-18`) until the P11
    review round fixed it; it is a regression test now. The refuted a11y-12 (a KPI delta's judgment in words for
    screen readers, arrow, signed percent and color for the eye, exactly as plan 14.2 specifies) has no test here.

Why it exists
    A promise of plan 14.9 is visible in the markup alone: "forms with labels and error messages tied by
    aria-describedby" (every error box a form fills must be named by its field).

How it works
    The error boxes are read from every page and every lazy card of the real app, through the integration fixtures
    of tests/integration/pages/conftest.py (`pages_app`, `page`), imported here.

What to read next
    static/js/api_forms.js (`fieldError`), tests/review_p11/test_a11y_e2e.py.
"""

from __future__ import annotations

from typing import Any

from integration.pages.conftest import page, page_admin, pages_app  # noqa: F401  (the page fixtures)
from pages_harness import Node, parse_html

PAGE_IDS = (
    "overview",
    "recommendations",
    "traffic",
    "upstream",
    "egress",
    "cache",
    "endpoints",
    "clients",
    "protection",
    "live",
    "security",
    "health",
    "settings",
    "credential",
    "data",
    "audit",
    "system",
    "help",
)


# ------------------------------------------------------------------------------- a11y-18: error boxes


def _ancestor(node: Node, tag: str) -> Node | None:
    current = node.parent
    while current is not None and current.tag != tag:
        current = current.parent
    return current


def _untied_error_boxes(doc: Node, where: str) -> list[str]:
    """Error boxes (`data-field-error`) that no field of their form, nor a fieldset or group around it, names in
    aria-describedby (static/js/api_forms.js fills a box it finds and ties only the boxes it creates itself)."""
    problems: list[str] = []
    for box in doc.select("[data-field-error]"):
        name = box.get("data-field-error") or ""
        scope = _ancestor(box, "form") or doc
        described: set[str] = set()
        for field in scope.select(f'[name="{name}"]'):
            described.update((field.get("aria-describedby") or "").split())
            holder = field.parent
            while holder is not None and holder is not scope:
                if holder.tag == "fieldset" or holder.get("role") in ("group", "radiogroup"):
                    described.update((holder.get("aria-describedby") or "").split())
                holder = holder.parent
        if not box.id or box.id not in described:
            problems.append(f"{where}: error box for {name!r} (id {box.id!r}) is not named by its field")
    return problems


# Fixed in the P11 review round (a11y-18, shared fixer): a regression test now.
async def test_a11y_18_every_error_box_is_tied_to_its_field(page: Any, pages_app: Any) -> None:  # noqa: F811
    """Plan 14.9: error messages tied by aria-describedby. Protection > Bypass ("Never expire": its box
    `dlg-prot-bypass-add-never-error` is named by no field) and Data > Resets (the families box has no id at all)
    show a 422 message that a screen reader never reads with the field."""
    await pages_app.seed_all()
    problems: list[str] = []
    for page_id in PAGE_IDS:
        answer = await page.get(f"/admin/{page_id}")
        assert answer.status_code == 200, (page_id, answer.status_code)
        doc = parse_html(answer.text)
        problems += _untied_error_boxes(doc, page_id)
        for card in doc.select("section[data-card-src]"):
            if "page-card--lazy" not in card.classes():
                continue
            fragment = await page.get(card.get("data-card-src") or "", htmx=True)
            assert fragment.status_code == 200, (card.id, fragment.status_code)
            problems += _untied_error_boxes(parse_html(fragment.text), f"{page_id}#{card.id}")
    assert not problems, problems
