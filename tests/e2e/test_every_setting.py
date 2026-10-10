"""Every setting can be changed on a feature page, not only on the Settings page (plan 15.6, P11).

What this is
    One test per catalog key (`test_every_setting_on_a_feature_page[<key>]`). For each home the catalog gives the
    key (`SettingSpec.pages`, anchors such as `cache#settings`), except the Settings page itself:
      * a page anchor `<page>#<card>`: the card's fragment (`/admin/<page>/fragment/<card>`, the HTML its card
        renders on the page) must hold the inline editor, `[data-setting-key="<key>"]`;
      * a shell home (`topbar#pause`, `topbar#throttle-all`, `user-menu#preferences`): the dialog on every page
        (`#dlg-pause`, `#dlg-throttle-all`, `#preferences`) must hold it.
    A home on a page nobody has built yet is not checked; the test is then SKIPPED with "page not built: <pages>"
    after the built homes passed. The few keys whose only home is the Settings page (the public site's texts,
    `settings#public-site`: they belong to no feature page) are checked there instead, under the same rule.

Why it exists
    v1 kept settings next to the feature they change; v2 keeps that promise for all of them (plan 15.6: the
    Settings page is the index, not the only place). The catalog says where each key lives; this test proves the
    pages honor it, page by page as they are built.

What to read next
    `roxy/config/catalog.py` (`pages`, `NON_PAGE_HOMES`), `roxy/admin/pages/registry.py` (`ANCHOR_SETTINGS`),
    `roxy/admin/pages/inline.py`, `templates/components/setting.html`.
"""

from __future__ import annotations

from typing import Any

import pytest

from roxy.admin.pages import registry
from roxy.admin.pages.testing import Node, parse_html
from roxy.config.catalog import CATALOG

SHELL_HOMES = {
    "topbar#pause": "#dlg-pause",
    "topbar#throttle-all": "#dlg-throttle-all",
    "user-menu#preferences": "#preferences",
}
SETTINGS_PAGE = "settings"


class Pages:
    """Fetched HTML, once per fragment and once for the shell (the dashboard's state does not change here)."""

    def __init__(self, dashboard: Any) -> None:
        self.dashboard = dashboard
        self.docs: dict[str, Node] = {}

    def doc(self, path: str) -> Node:
        if path not in self.docs:
            response = self.dashboard.get(path)
            assert response.status_code == 200, (path, response.status_code)
            self.docs[path] = parse_html(response.text)
        return self.docs[path]

    def shell(self) -> Node | None:
        built = registry.built_pages()
        return self.doc(f"/admin/{built[0]}") if built else None


@pytest.fixture(scope="module")
def pages(dashboard: Any) -> Pages:
    return Pages(dashboard)


def _homes(key: str) -> list[str]:
    anchors = list(CATALOG[key].pages)
    feature = [a for a in anchors if a.split("#", 1)[0] != SETTINGS_PAGE]
    return feature or anchors


@pytest.mark.parametrize("key", sorted(CATALOG))
def test_every_setting_on_a_feature_page(key: str, pages: Pages) -> None:
    selector = f'[data-setting-key="{key}"]'
    pending: list[str] = []
    checked = 0
    for anchor in _homes(key):
        if anchor in SHELL_HOMES:
            shell = pages.shell()
            if shell is None:
                pending.append("any page (for the shell)")
                continue
            dialog = shell.select_one(SHELL_HOMES[anchor])
            assert dialog is not None, f"{SHELL_HOMES[anchor]} is missing from the shell"
            assert dialog.select(selector), f"{key}: not in {SHELL_HOMES[anchor]} ({anchor})"
            checked += 1
            continue
        page_id, _, card_id = anchor.partition("#")
        assert registry.known(page_id), f"{key}: {anchor} names no page"
        assert card_id in {c.id for c in registry.cards_for(page_id)}, f"{key}: {anchor} names no card"
        if not registry.is_built(page_id):
            pending.append(page_id)
            continue
        doc = pages.doc(f"/admin/{page_id}/fragment/{card_id}")
        assert doc.select(selector), f"{key}: no inline editor in {anchor}"
        checked += 1
    if pending:
        passed = f"; {checked} built homes passed" if checked else ""
        pytest.skip(f"page not built: {', '.join(dict.fromkeys(pending))}{passed}")
    assert checked, f"{key} has no home"
