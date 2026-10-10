"""The Credential page (`/admin/credential`, plan 14.1, C1, C2, D1): integration tests against the real app.

What this is
    Tests with the real credential manager (a fake value written at runtime) and data written by the real services:
    the page and every card fragment answer 200 for an admin and redirect otherwise, every registry card and every
    inline setting of the `credential#*` anchors is there, the value is never in any HTML (only its masked suffix),
    the numbers equal the admin API's, the allowlist forms post to the API with CSRF and a fresh second factor, the
    replace needs the typed C1 confirmation, hostile text stays inert, no filter ever fails the page, and the empty
    allowlist explains owner decision D1.

Why it exists
    The P11 contract, and plan C1, C2 and 9.8: the credential is the most sensitive value Roxy holds.

What to read next
    `roxy/admin/pages/credential.py`, `tests/e2e/test_page_credential.py`.
"""

from __future__ import annotations

from typing import Any

from roxy.admin.pages import registry
from roxy.core.style_guard import find_style_issues

PAGE = "/admin/credential"
PAGE_ID = "credential"


def _cards() -> list[registry.CardSpec]:
    return list(registry.cards_for(PAGE_ID))


async def test_the_page_its_fragments_and_partials_need_a_signed_in_admin(anon: Any) -> None:
    extra = ("/admin/credential/allowlist-row?id=1", "/admin/credential/allowlist-test?target=x")
    for path in [PAGE, *(f"{PAGE}/fragment/{card.id}" for card in _cards()), *extra]:
        response = await anon.get(path)
        assert response.status_code == 302, path
        assert response.headers["location"] == "/admin"


async def test_every_card_renders_without_an_error_and_holds_its_settings(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    doc = await page.doc(PAGE)
    for card in _cards():
        assert doc.select_one(f"section#{card.id}[data-card]") is not None, card.id
        fragment = await page.doc(f"{PAGE}/fragment/{card.id}")
        section = fragment.select_one(f"section#{card.id}[data-card]")
        assert section is not None, card.id
        assert fragment.select_one("[data-card-error]") is None, (card.id, section.text()[:300])
        for spec in registry.settings_for(registry.anchor(PAGE_ID, card.id)):
            assert section.select_one(f'[data-setting-key="{spec.key}"]') is not None, (card.id, spec.key)
    assert not doc.select("[data-card-error]")
    assert find_style_issues(str(doc.text()), "credential") == []
