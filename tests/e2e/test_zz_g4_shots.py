"""Temporary: element screenshots of every card for the visual review (deleted after the review)."""
from pathlib import Path
from typing import Any

import pytest

OUT = Path("/mnt/c/Users/hurri/AppData/Local/Temp/claude/--wsl-localhost-ubuntu-24-04-home-hurri-Projects-RobloxProxyServer/fc0a579d-1239-4700-a334-9ab59f818a7b/scratchpad/cards")


@pytest.mark.parametrize("page_id", ["cache", "clients"])
@pytest.mark.parametrize("theme,width,height", [("dark", 1440, 900), ("light", 390, 844)])
def test_cards(open_admin: Any, page_id: str, theme: str, width: int, height: int) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    admin = open_admin(f"/admin/{page_id}", theme=theme, width=width, height=height)
    page = admin.page
    page.screenshot(path=str(OUT / f"{page_id}_{theme}_{width}_top.png"))
    ids = page.evaluate("[...document.querySelectorAll('section[data-card]')].map(e => e.id)")
    for card_id in ids:
        page.locator(f"section#{card_id}").first.screenshot(path=str(OUT / f"{page_id}_{theme}_{width}_{card_id}.png"))


@pytest.mark.parametrize("theme,width,height", [("dark", 1440, 900), ("light", 390, 844)])
def test_drawers(open_admin: Any, theme: str, width: int, height: int) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    admin = open_admin("/admin/clients", theme=theme, width=width, height=height)
    page = admin.page
    page.locator("#ips tbody tr[data-row-id] [data-dt-open]").first.click()
    admin.wait("document.querySelector('#drawer[open] [data-client-view]') !== null")
    page.wait_for_timeout(500)
    page.locator("#drawer-body").screenshot(path=str(OUT / f"drawer_client_ip_{theme}_{width}.png"))
    page.keyboard.press("Escape")
    page.locator("#places tbody tr[data-row-id] [data-dt-open]").first.click()
    admin.wait("document.querySelector('#drawer[open] [data-client-view]') !== null")
    page.locator('#drawer [data-action="client-identify"]').click()
    admin.wait("document.querySelector('#drawer [data-lookup-result] .clients-lookup__head') !== null")
    page.locator("#drawer-body").screenshot(path=str(OUT / f"drawer_client_place_{theme}_{width}.png"))
    page.locator('#drawer [data-action="client-ban"]').click()
    admin.wait("document.querySelector('#dlg-client-ban[open]') !== null")
    page.wait_for_timeout(400)
    page.screenshot(path=str(OUT / f"dialog_ban_{theme}_{width}.png"))
    cache = open_admin("/admin/cache", theme=theme, width=width, height=height)
    cpage = cache.page
    cpage.locator("#browser tbody tr[data-row-id] [data-dt-open]").first.click()
    cache.wait("document.querySelector('#drawer[open] [data-cache-entry]') !== null")
    cpage.locator("#drawer-body").screenshot(path=str(OUT / f"drawer_entry_{theme}_{width}.png"))
    cpage.keyboard.press("Escape")
    cpage.locator("#endpoints tbody tr[data-row-id] [data-dt-open]").first.click()
    cache.wait("document.querySelector('#drawer[open] .cache-drawer form') !== null")
    cpage.locator("#drawer-body").screenshot(path=str(OUT / f"drawer_endpoint_{theme}_{width}.png"))
    cpage.keyboard.press("Escape")
    cpage.locator("#rules tbody tr[data-row-id] [data-dt-open]").first.click()
    cache.wait("document.querySelector('#drawer[open] form[data-api-method=\"PATCH\"]') !== null")
    cpage.locator("#drawer-body").screenshot(path=str(OUT / f"drawer_rule_{theme}_{width}.png"))
    cpage.keyboard.press("Escape")
    cpage.locator('#stats [data-action="cache-clear-stats"]').click()
    cache.wait("document.querySelector('#dlg-cache-reset-stats[open]') !== null")
    cpage.wait_for_timeout(600)
    cpage.screenshot(path=str(OUT / f"dialog_reset_{theme}_{width}.png"))
