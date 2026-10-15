"""Parity rows proven on their dashboard pages: the numbers v1's sections showed, equal to the admin API's.

What this is
    Integration tests (the real app in process: `pages_app` and `page` of tests/integration/pages/conftest.py) for
    the plan section 4 parity rows whose page tests did not yet compare the page with the API, found while the
    CHANGES.md parity checklist was pointed at the page tests (P11): the pause and emergency limit banners count the
    refusals since the state began (row 114), who is throttled right now (row 118) and who the emergency limit
    refuses (row 135) are the API's tables, each rung's new strikes and each User-Agent rule's hits are the API's
    numbers (row 76), and so are the fleet's tarpit hold statistics (row 78).

Why it exists
    C3 and plan 18.1 item 5: every parity row is checked off with the test that proves it on its v2 home. A card that
    rendered without an error proves the wiring, not the numbers; these tests read the card and the API route for the
    same range and compare what an admin would read.

How it works
    Rows about traffic send real requests through the in-process proxy (`pages_app.seed_traffic`): a pause, an
    emergency limit of 3 a minute, the harness's seeding plan with its throttled client. Rows about numbers the
    minute producers write are seeded the way their writers store them: the rung hits as aggregated `throttle_tier`
    events through the recorder (written once their minute closes, so the fake clock moves past it), the rule hits and
    the tarpit minutes straight into their metrics.db tables (as tests/integration/admin_api/test_r3_fix_pages_lane.py
    does). Every switch a test turns on is turned off in a `finally`.

What to read next
    tests/integration/pages/test_page_protection.py, `roxy/admin/pages/protection.py`, `roxy/admin/pages/shell.py`
    (`read_facts`, the banners' counts), CHANGES.md "Parity checklist".
"""

from __future__ import annotations

from typing import Any

from pages_harness import Node, PlannedRequest, parse_html

PAGE = "/admin/protection"
PAUSED_IP = "203.0.113.141"
LIMITED_IP = "203.0.113.142"
THROTTLED_IP = "198.51.100.99"
"""The client of `pages_harness.traffic_plan()` that goes over the per-IP limit (14 requests, 10 allowed)."""


def _games(ip: str, first: int, count: int) -> list[PlannedRequest]:
    """`count` distinct requests (no cache hit between them) from one address."""
    return [
        PlannedRequest(f"/games.roblox.com/v1/games?universeIds={first + i}", ip, note="parity row")
        for i in range(count)
    ]


def _minute(pages_app: Any) -> int:
    now = int(pages_app.clock.now())
    return now - now % 60


async def _metrics(pages_app: Any, *statements: tuple[str, tuple[Any, ...]]) -> None:
    def run(conn: Any) -> None:
        for sql, params in statements:
            conn.execute(sql, params)

    await pages_app.ctx.dbs.metrics.write(run)


def _cell(row: Node, column: str) -> str:
    """The text of a `components/table.html` cell (`td[data-col=<column key>]`)."""
    cell = row.select_one(f"td[data-col={column}]")
    assert cell is not None, column
    return cell.text()


def _labeled(row: Node, label: str) -> str:
    """The text of a small table's cell (`td[data-label=<column label>]`)."""
    cell = row.select_one(f"td[data-label={label}]")
    assert cell is not None, label
    return cell.text()


def _count(table: Node) -> str:
    """A table's "Showing 1 to n of total" line."""
    count = table.select_one(".dt__count")
    assert count is not None
    return count.text()


# ============================================================================================ row 114: the banners


async def test_row_114_the_pause_banner_counts_the_refusals_since_the_pause_began(page: Any, pages_app: Any) -> None:
    try:
        paused = await page.api("POST", "protection/pause", json={"paused": True, "message": "Back after the check."})
        assert paused.status_code == 200, paused.text
        statuses = await pages_app.seed_traffic(_games(PAUSED_IP, 1400, 3))
        assert statuses == [503, 503, 503]
        drops = (await page.api("GET", "protection/pause")).json()["drops_since_start"]
        assert drops == 3
        banner = (await page.doc("/admin/audit")).select_one(".banner--bad")
        assert banner is not None
        assert f"{drops:,} requests refused with 503 since" in banner.text()
        assert "Back after the check." in banner.text()
    finally:
        await page.api("POST", "protection/pause", json={"paused": False})


# ============================================================================================ rows 114 and 135


async def test_rows_114_and_135_the_emergency_limit_banner_and_watch_equal_the_api(page: Any, pages_app: Any) -> None:
    body = {"enabled": True, "message": "Slow down for the check.", "limit": 3, "period": 60, "reason": "parity"}
    try:
        switched = await page.api("POST", "protection/throttle-all", json=body)
        assert switched.status_code == 200, switched.text
        statuses = await pages_app.seed_traffic(_games(LIMITED_IP, 1500, 6))
        refused = statuses.count(429)
        assert refused >= 1, statuses
        drops = (await page.api("GET", "protection/throttle-all")).json()["drops_since_start"]
        assert drops == refused
        banner = (await page.doc("/admin/audit")).select_one(".banner--warn")
        assert banner is not None
        assert f"{drops:,} requests over the limit refused with 429 since" in banner.text()
        watch = (await page.api("GET", "protection/throttle-all/watch")).json()
        doc = parse_html((await page.fragment("protection", "throttle-all", table="watch-all")).text)
        table = doc.select_one("#prot-watch-all")
        assert table is not None
        assert f"of {watch['total']:,}" in _count(table)
        item = next(item for item in watch["items"] if item["ip"] == LIMITED_IP)
        row = table.select_one(f"tr[data-row-id=watch-all-{LIMITED_IP}]")
        assert row is not None
        assert _cell(row, "count") == f"{item['count']:,} of 3"
        if item["refused"] is not None:
            assert f"{item['refused']:,}" in _cell(row, "refused")
    finally:
        await page.api("POST", "protection/throttle-all", json={"enabled": False})


# ============================================================================================ row 118


async def test_row_118_who_is_throttled_now_is_the_apis_table(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    watch = (await page.api("GET", "protection/throttle/watch")).json()
    assert watch["total"] >= 1
    doc = parse_html((await page.fragment("protection", "throttle", table="watch")).text)
    table = doc.select_one("#prot-watch")
    assert table is not None
    assert f"of {watch['total']:,}" in _count(table)
    assert len(table.select("tbody tr[data-row-id]")) == len(watch["items"])
    item = next(item for item in watch["items"] if item["ip"] == THROTTLED_IP)
    row = table.select_one(f"tr[data-row-id=watch-{THROTTLED_IP}]")
    assert row is not None
    assert _cell(row, "tier") == f"Rung {item['tier']}"


# ============================================================================================ row 76


async def test_row_76_rung_strikes_and_user_agent_rule_hits_are_the_apis(page: Any, pages_app: Any) -> None:
    pages_app.ctx.recorder.record_event("throttle_tier", "info", "", {"tier": 2}, aggregate=True, count=5)
    pages_app.clock.advance(61)  # aggregated events are written once their minute closes
    await pages_app.flush()
    ladder = (await page.api("GET", "protection/ladder", params={"range": "1h"})).json()
    hits = [rung["hits"] for rung in ladder["rungs"]]
    assert hits[1] == 5
    doc = parse_html((await page.fragment("protection", "ladder", range="1h")).text)
    shown = [node.text() for node in doc.select("th.prot-ladder__rung .dt__sub")]
    assert shown == [f"{count:,} new strikes in range" for count in hits]

    created = await page.api(
        "POST", "protection/ua-rules", json={"needle": "ParityBot", "kind": "cooldown", "cooldown": 2}
    )
    assert created.status_code == 200, created.text
    rule_id = str(created.json()["item"]["id"])
    minute = _minute(pages_app)
    await _metrics(
        pages_app,
        (
            "INSERT INTO rule_hit_minute (bucket_start, table_name, rule_key, hits) "
            "VALUES (?, 'rules_user_agent', ?, 37)",
            (minute, rule_id),
        ),
        (
            "INSERT INTO rule_hits (table_name, rule_key, hits, first_hit_at, last_hit_at) "
            "VALUES ('rules_user_agent', ?, 1234, ?, ?)",
            (rule_id, minute - 86_400, minute + 5),
        ),
    )
    rules = (await page.api("GET", "protection/ua-rules", params={"range": "1h"})).json()
    item = next(item for item in rules["items"] if str(item["id"]) == rule_id)
    assert (item["hits"], item["hits_total"]) == (37, 1234)
    doc = parse_html((await page.fragment("protection", "ua-rules", table="ua", range="1h")).text)
    row = doc.select_one(f"tr[data-row-id=ua-{rule_id}]")
    assert row is not None
    assert _cell(row, "hits") == f"{item['hits']:,}"
    assert _cell(row, "hits_total") == f"{item['hits_total']:,}"


# ============================================================================================ row 78


async def test_row_78_the_tarpit_tiles_and_categories_are_the_fleets_hold_statistics(page: Any, pages_app: Any) -> None:
    minute = _minute(pages_app)
    await _metrics(
        pages_app,
        (
            "INSERT INTO tarpit_minute (bucket_start, category, kind, holds, skipped, held_s_sum, held_s_max, "
            "gaps_after_hold, gap_after_hold_s_sum, gaps_after_instant, gap_after_instant_s_sum) "
            "VALUES (?, 'probe', 'hold', 4, 1, 40.0, 15.0, 2, 30.0, 1, 2.0)",
            (minute,),
        ),
        ("INSERT INTO tarpit_hold_minute (bucket_start, category, bound_ms, holds) VALUES (?, 'probe', 10000, 4)",
         (minute,)),
    )  # fmt: skip
    answer = (await page.api("GET", "protection/tarpit", params={"range": "1h"})).json()
    history = answer["history"]
    assert (history["holds"], history["skipped"]) == (4, 1)
    doc = parse_html((await page.fragment("protection", "tarpit", range="1h")).text)
    tile = doc.select_one("[data-kpi=tarpit_held]")
    assert tile is not None
    assert f"{history['holds']:,}" in tile.text()
    assert f"Skipped (at capacity): {history['skipped']:,}" in tile.text()
    label = answer["category_labels"]["probe"]
    rows = [row for row in doc.select(".prot-tarpit-cats tbody tr") if row.text().startswith(label)]
    assert len(rows) == 1
    probe = history["by_category"]["probe"]
    assert _labeled(rows[0], "Held") == f"{probe['holds']:,}"
    assert _labeled(rows[0], "Skipped") == f"{probe['skipped']:,}"
