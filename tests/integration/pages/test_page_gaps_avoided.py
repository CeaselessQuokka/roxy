"""A negative avoided share is shown as it is, with why, on every page that shows one (gap G4, plan P6).

What this is
    Integration tests against the real app: one endpoint whose retries made 2 upstream calls for every caller
    request (recorded through the real recorder: demand 4, upstream calls 8, so avoided is -4 and -100%). The
    Overview (its tiles and Top endpoints), the Cache page (its tiles and the avoided chart's note), the Endpoints
    page (the table and the drill-down) and the Traffic page (the trends) show -100.0% with "retries and refreshes
    made 2 upstream calls per request", never a share clamped to 0%, and the metric's help says why it can be negative.

Why it exists
    Plan P6 (honest numbers): "avoided upstream calls" is caller demand minus the upstream calls made for caller
    traffic and never flatters, so it must not be rounded into a flattering number; the lead decided against a floor
    at 0 (`.remake/p11_reports/integrate.md` section 7 item 4).

What to read next
    `roxy/metrics/catalog.py` (`avoided_note`), `roxy/admin/pages/fmt.py` (`avoided_cell`),
    `templates/components/format.html` (`cell_value`).
"""

from __future__ import annotations

from typing import Any

from pages_harness import parse_html
from roxy.core.reasons import AuthClass, CacheState, Egress, Outcome, ReasonCode, Source
from roxy.metrics.catalog import METRICS, avoided_note
from roxy.metrics.recorder import OutcomeEvent

TEMPLATE = "games.roblox.com/v1/games/{gameId}/retried"
NOTE = "retries and refreshes made 2 upstream calls per request"


async def seed_retried_endpoint(pages_app: Any) -> None:
    """Four caller requests that each took two upstream calls (a retry), through the real recorder."""
    recorder = pages_app.ctx.recorder
    for index in range(4):
        recorder.record_outcome(
            OutcomeEvent(
                at_ms=pages_app.clock.now_ms(), request_id=f"GAPSAVOIDED{index:015d}", endpoint_template=TEMPLATE,
                host="games.roblox.com", method="GET", egress=Egress.DIRECT, outcome=Outcome.SERVED_UPSTREAM,
                reason=ReasonCode.UPSTREAM_OK, status=200, source=Source.ROBLOX, cache_state=CacheState.MISS,
                auth_class=AuthClass.ANON, caller_bytes_in=100, caller_bytes_out=500, upstream_calls=2,
                upstream_bytes_in=900, upstream_bytes_out=300, latency_ms=40.0, queue_wait_ms=1.0, upstream_ms=30.0,
                client_ip="203.0.113.5", place_id="12345", user_agent="Roblox/WinInet", bypass=False, error=False,
            )
        )  # fmt: skip
    await pages_app.flush()


def test_the_shared_note_and_cell() -> None:
    from roxy.admin.pages import fmt

    assert avoided_note(-100.0) == NOTE
    assert avoided_note(-50) == "retries and refreshes made 1.5 upstream calls per request"
    assert avoided_note(-33.333) == "retries and refreshes made 1.33 upstream calls per request"
    assert avoided_note(0) is None
    assert avoided_note(42.5) is None
    assert avoided_note(None) is None
    assert avoided_note(True) is None
    assert fmt.avoided_cell(-100.0) == {"text": "-100.0%", "sub": NOTE, "tone": "warn"}
    assert fmt.avoided_cell(12.345) == {"text": "12.3%"}
    assert fmt.avoided_cell(None) is None
    help_text = METRICS["avoided_pct"].description
    assert "below 0%" in help_text
    assert "-100% means 2 upstream calls per request" in help_text


async def test_overview_shows_the_negative_share_with_why(page: Any, pages_app: Any) -> None:
    await seed_retried_endpoint(pages_app)
    top = parse_html((await page.fragment("overview", "top-endpoints")).text)
    row = next(tr for tr in top.select("tbody tr") if TEMPLATE in tr.text())
    cell = row.select_one('td[data-label="Avoided"]')
    assert "-100.0%" in cell.text()
    assert NOTE in cell.text()
    assert cell.select_one(".tone--warn") is not None
    assert "below 0%" in (top.select_one("thead .help-dot").get("data-help") or "")
    kpis = (await page.api("GET", "overview/kpis")).json()
    tiles = {tile["key"]: tile for tile in kpis["tiles"]}
    assert tiles["avoided_pct"]["value"] == -100.0  # never clamped
    assert tiles["avoided_pct"]["notice"].startswith("Below 0%: " + NOTE)
    assert tiles["avoided"]["value"] == -4
    assert NOTE in tiles["avoided"]["notice"]
    doc = parse_html((await page.fragment("overview", "kpis")).text)
    tile = doc.select_one('[data-kpi="avoided_pct"]')
    assert "-100.0" in tile.text()
    assert NOTE in tile.text()


async def test_cache_shows_the_negative_share_with_why(page: Any, pages_app: Any) -> None:
    await seed_retried_endpoint(pages_app)
    stats = (await page.api("GET", "cache/stats")).json()
    tiles = {tile["key"]: tile for tile in stats["tiles"]}
    assert tiles["avoided_pct"]["value"] == -100.0
    assert tiles["avoided_pct"]["notice"] == f"Below 0%: {NOTE}."
    doc = parse_html((await page.fragment("cache", "stats")).text)
    assert NOTE in doc.select_one('[data-kpi="avoided_pct"]').text()
    ratios = (await page.api("GET", "cache/ratios")).json()
    assert any("below 0%" in note for note in ratios["notices"])
    card = parse_html((await page.fragment("cache", "ratios")).text)
    hit_chart = card.select_one("#cache-hit-ratio").get("data-series") or ""
    assert "below 0%" not in hit_chart  # the note belongs to the avoided chart only
    assert "below 0%" in (card.select_one("#cache-avoided").get("data-series") or "")


async def test_endpoints_show_the_negative_share_with_why(page: Any, pages_app: Any) -> None:
    await seed_retried_endpoint(pages_app)
    table = parse_html((await page.fragment("endpoints", "table", q="retried")).text)
    row = next(tr for tr in table.select("tbody tr") if TEMPLATE in tr.text())
    assert "-100.0%" in row.text()
    assert NOTE in row.text()
    detail = parse_html((await page.fragment("endpoints", "detail", template=TEMPLATE)).text)
    tile = detail.select_one('[data-kpi="avoided_pct"]')
    assert "-100.0" in tile.text()
    assert NOTE in tile.text()


async def test_traffic_trends_show_the_negative_share_with_why(page: Any, pages_app: Any) -> None:
    await seed_retried_endpoint(pages_app)
    trends = parse_html((await page.fragment("traffic", "trends")).text)
    row = next(tr for tr in trends.select("tbody tr") if "Avoided upstream calls (percent)" in tr.text())
    assert "-100.0%" in row.text()
    assert NOTE in row.text()
