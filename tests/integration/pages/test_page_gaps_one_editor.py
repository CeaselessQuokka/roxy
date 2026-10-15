"""One setting, one editor per page (gap G11, DESIGN.md 15.2), for every key the catalog anchors twice on one page.

What this is
    The kit's placement rule (`registry.editor_anchor`, `inline.card_settings`): where the catalog's `pages` field
    names a key on two or more cards of one page (`cache_coalesce*` on Cache > Settings and Cache > Coalescing, the
    rotator's budget keys on Egress > Rotator and Budget, ...), exactly one of those cards holds its editor and the
    others show the current value read-only with a link to it. The tests walk `registry.shared_anchors()`, so a key
    the catalog anchors twice later is covered without editing this file.

Why it exists
    Plan 15.6 places `cache_coalesce*` on both Cache cards; two editors of one setting on one page did not refresh
    each other, so the page could show two values. The lead decided the editor stays on Coalescing and Settings shows
    the value with a link, by a general rule of the kit, not a hand-written list.

What to read next
    `roxy/admin/pages/registry.py` (`editor_anchor`), `roxy/admin/pages/inline.py`,
    `templates/components/page_card.html` (`setting_reference`).
"""

from __future__ import annotations

from typing import Any

import pytest

from pages_harness import parse_html
from roxy.admin.pages import registry

SHARED = sorted(registry.shared_anchors().items())


def test_the_rule_picks_the_cards_the_lead_and_the_plan_name() -> None:
    assert registry.editor_anchor("cache_coalesce", "cache") == "cache#coalescing"
    assert registry.editor_anchor("cache_coalesce_wait_ms", "cache") == "cache#coalescing"
    assert registry.editor_anchor("rotator_price_per_gb_usd", "egress") == "egress#budget"
    # A fragment-only drawer (one rule's tuning panel) holds the editor only when no card of the page names the key.
    assert registry.editor_anchor("insight_cred_probe_cost_max_per_hour", "recommendations") == "recommendations#engine"
    assert registry.editor_anchor("cache_ttl_seconds", "cache") == "cache#settings"  # a key on one card
    assert registry.editor_anchor("cache_ttl_seconds", "egress") is None
    assert len(SHARED) >= 13
    for (key, page_id), anchors in SHARED:
        assert registry.editor_anchor(key, page_id) in anchors


@pytest.mark.parametrize(("where", "anchors"), SHARED, ids=[f"{k}@{p}" for (k, p), _a in SHARED])
async def test_one_editor_and_a_linked_value_elsewhere_on_the_page(
    page: Any, where: tuple[str, str], anchors: tuple[str, ...]
) -> None:
    key, page_id = where
    home = registry.editor_anchor(key, page_id)
    assert home is not None
    editors = 0
    for anchor in anchors:
        card_id = anchor.partition("#")[2]
        doc = parse_html((await page.fragment(page_id, card_id)).text)
        forms = doc.select(f'form[data-setting-key="{key}"]')
        if anchor == home:
            assert len(forms) == 1, (anchor, key)
            assert not doc.select(f'[data-setting-ref="{key}"]')
            editors += 1
            continue
        assert forms == [], f"{key}: a second editor on {anchor} (its editor is {home})"
        reference = doc.select_one(f'[data-setting-ref="{key}"]')
        assert reference is not None, (anchor, key)
        link = reference.select_one("a[data-setting-editor]")
        assert link is not None
        assert link.get("href") == "#" + home.partition("#")[2]
        assert registry.card(page_id, home.partition("#")[2]).title in reference.text()
        assert "Now " in reference.text()
    assert editors == 1


async def test_the_reference_shows_the_live_value(page: Any, pages_app: Any) -> None:
    """The read-only value is the setting's current one (the snapshot every card reads)."""
    await pages_app.settings(cache_coalesce_wait_ms=1750)
    doc = parse_html((await page.fragment("cache", "settings")).text)
    reference = doc.select_one('[data-setting-ref="cache_coalesce_wait_ms"]')
    assert reference is not None
    assert "1,750" in reference.text()
    coalescing = parse_html((await page.fragment("cache", "coalescing")).text)
    assert coalescing.select_one('form[data-setting-key="cache_coalesce_wait_ms"]') is not None
