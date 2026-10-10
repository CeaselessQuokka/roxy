"""Temporary visual review helper for the g6_security lane (deleted before the report): card-by-card screenshots."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

OUT = Path(__file__).resolve().parents[2] / ".remake" / "p11_reports" / "shots" / "g6_cards"


@pytest.mark.parametrize(("page_id", "theme", "width", "height"), [
    ("security", "dark", 1440, 900),
    ("security", "light", 390, 844),
    ("data", "dark", 1440, 900),
    ("data", "light", 390, 844),
])
def test_card_shots(open_admin: Any, page_id: str, theme: str, width: int, height: int) -> None:
    admin = open_admin(f"/admin/{page_id}", theme=theme, width=width, height=height)
    OUT.mkdir(parents=True, exist_ok=True)
    page = admin.page
    page.locator("main .page-header").screenshot(path=str(OUT / f"{page_id}_{theme}_{width}_header.png"))
    ids = page.evaluate("[...document.querySelectorAll('main section[data-card]')].map((s) => s.id)")
    for card_id in ids:
        locator = page.locator(f"section#{card_id}").first
        locator.scroll_into_view_if_needed()
        admin.settle()
        box = locator.bounding_box()
        if box and box["height"] > 2400:
            page.screenshot(
                path=str(OUT / f"{page_id}_{theme}_{width}_{card_id}.png"),
                clip={"x": 0, "y": 0, "width": width, "height": height},
            )
            locator.screenshot(path=str(OUT / f"{page_id}_{theme}_{width}_{card_id}_full.png"))
        else:
            locator.screenshot(path=str(OUT / f"{page_id}_{theme}_{width}_{card_id}.png"))
