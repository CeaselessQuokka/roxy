"""Plan C5 rewrite of imported admin text (plan 18.3 "dash rewrites"): the rules and the report listing."""

from __future__ import annotations

from typing import Any

import pytest
from v1_migration_helpers import load_report

from roxy.migration.report import write_report
from roxy.migration.text import DASHES, clean_admin_text, has_dash, rewrite_dashes

EM, EN = chr(0x2014), chr(0x2013)


@pytest.mark.parametrize(
    ("before", "after"),
    [
        # The plan's own C5 example (the v1 default ladder message).
        (f"Too many requests {EM} please slow down.", "Too many requests; please slow down."),
        (f"Clone is missing x {EM} refusing to deploy it.", "Clone is missing x; refusing to deploy it."),
        (f"This endpoint {EM} like the others {EM} is blocked.", "This endpoint (like the others) is blocked."),
        (f"Note {EM} this list is shared", "Note: this list is shared"),
        (f"Scheduled maintenance {EM} back at 5", "Scheduled maintenance: back at 5"),
        (f"Cached briefly {EM} but not for long", "Cached briefly, but not for long"),
        (f"We keep answers {EM} briefly.", "We keep answers, briefly."),
        (f"10{EN}20 requests", "10-20 requests"),
        # Only an en dash with no spaces between two digits is a range (review finding 14): a spaced dash between
        # numbers is often a clause break, and a hyphen there reads as a range ("429-2").
        (f"Error 429 {EM} 2 retries left", "Error 429; 2 retries left"),
        (f"Error 429 {EN} 2 retries left", "Error 429; 2 retries left"),
        (f"Error 429{EM}2 retries left", "Error 429; 2 retries left"),
        (f"pages 3 {EN} 5", "pages 3, 5"),
        (f"Roblox{EN}Roxy link", "Roblox-Roxy link"),
        (f"{EM} leading dash", "leading dash"),
        (f"trailing dash {EM}", "trailing dash"),
        (f"a run {EM}{EM} of dashes here", "a run; of dashes here"),
        (f"two words{EM}spaces around this one", "two words; spaces around this one"),
        (f"Line one {EM} the first part here\nLine two stays", "Line one; the first part here\nLine two stays"),
        ("no dash at all", "no dash at all"),
    ],
)
def test_rewrite_dashes(before: str, after: str) -> None:
    assert rewrite_dashes(before) == after


@pytest.mark.parametrize(
    "text",
    [
        f"{EM}{EN}{EM}",
        f"a {EM} b {EM} c {EM} d {EM} e",
        f"x{EN}",
        f"{EN}y",
        f"1 {EM} 2 {EM} three {EN} four",
        f"(odd {EM}) [more {EN}]",
    ],
)
def test_rewrite_never_leaves_a_dash(text: str) -> None:
    result = rewrite_dashes(text)
    assert not has_dash(result)
    assert all(dash not in result for dash in DASHES)


def test_clean_admin_text_flags_and_limits() -> None:
    clean = clean_admin_text(f"  Over the limit {EM} ok\x07  ", 12)
    assert clean.text == "Over the lim"
    assert clean.dashes_rewritten
    assert clean.control_removed
    assert clean.truncated
    assert clean_admin_text(None, 10).text == ""
    plain = clean_admin_text("  just spaces  ", 100)
    assert plain.text == "just spaces"
    assert not plain.dashes_rewritten


async def test_migration_dash_rewrites_are_listed(v1: Any, ws: Any, migrate: Any) -> None:
    """Every rewritten text is in the report with its table, id, before and after (plan 18.3, C5)."""
    builder = v1.small_tree(ws.v1)
    builder.write()
    report = await migrate()
    rewrites = report.text_rewrites
    assert {"table", "id", "field", "before", "after"} <= set(rewrites[0])
    by_place = {(r["table"], r["field"], r["id"]): r for r in rewrites}
    ladder = by_place[("throttle_tiers", "message", "rung 1")]
    assert ladder["before"] == f"Too many requests {EM} please slow down."
    assert ladder["after"] == "Too many requests; please slow down."
    ua_note = next(r for r in rewrites if r["table"] == "rules_user_agent" and r["field"] == "note")
    assert ua_note["id"] == "0f0f0f0f"
    assert ua_note["after"] == "game servers (like the others) share one budget"
    block = next(r for r in rewrites if r["table"] == "rules_endpoint_block" and r["field"] == "message")
    assert block["id"] == "1"  # the v2 id once the row is stored
    assert {r["table"] for r in rewrites} >= {"rules_endpoint_limit", "rules_header", "access_list", "service_state"}
    for item in rewrites:
        assert not has_dash(item["after"])

    # The files: JSON keeps the dash only as a \u escape, Markdown names it in words.
    json_path, markdown_path = write_report(report, ws.report)
    assert all(dash not in json_path.read_text(encoding="utf-8") for dash in DASHES)
    markdown = markdown_path.read_text(encoding="utf-8")
    assert all(dash not in markdown for dash in DASHES)
    assert "Too many requests [em dash] please slow down." in markdown
    data = load_report(ws.report)
    assert any(item["before"] == f"Too many requests {EM} please slow down." for item in data["text_rewrites"])
