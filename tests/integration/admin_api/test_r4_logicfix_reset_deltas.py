"""Review round 4, lens logicfix: plan 6.8 reset notices on the KPI deltas built outside `kpis_sync`, attacked.

What this is
    Adversarial tests of the parity-12 fix (`metrics/queries.py kpis_sync`) at the other places that show a value
    with a delta against the previous period: the Cache page tiles (`GET /cache/stats`, `TILE_KEYS`), the endpoint
    drill-down totals (`GET /endpoints/detail`) and the Overview's own `rotator_bytes_today` tile (today against
    yesterday, `overview._extra_tile`). Each test was a strict xfail for finding LOGICFIX-1; every delta of the admin
    API now goes through `queries.mark_partial` (`mark_kpi_partial`), the Traffic trends rows included.

Why it exists
    Plan 6.8: "a KPI or comparison whose current or comparison window overlaps a reset of its family shows a notice
    ... instead of a misleading delta. Comparison baselines are never synthesized to hide the gap." The fix made the
    Overview tiles honest (`test_r3_parity_data.py::test_parity_12_...`), but these routes computed their own delta
    with a local `_delta` helper and never asked `queries.reset_touches`, so the same reset read as growth there.

How it works
    The same seed as the parity-12 test: five requests in the previous hour, five in this hour, then a date range
    reset of the traffic family over the previous hour through the real flow (`POST /data/resets/preview`, then
    `POST /data/resets`). The routes are read over HTTP with `range=1h` (the comparison is the previous hour). The
    rotator tile gets `egress_usage` rows for yesterday and today, and a reset of that family over yesterday.

What to read next
    `roxy/admin/api/cache.py` (`cache_stats`, `_delta`), `roxy/admin/api/endpoints.py` (`endpoint_detail`),
    `roxy/admin/api/overview.py` (`_rotator_today`, `_extra_tile`), `roxy/metrics/queries.py` (`reset_touches`,
    `mark_partial`, `mark_kpi_partial`, `touching_resets`).
"""

from __future__ import annotations

from typing import Any

import pytest

from roxy.metrics import read_dashboard

pytestmark = pytest.mark.asyncio

TEMPLATE = "games.roblox.com/v1/games"


async def _reset_previous_hour(api: Any, api_app: Any, api_json: Any, metrics_seed: Any) -> None:
    """Five requests in the previous hour (then reset away), five in this hour."""
    now = int(api_app.clock.now())
    metrics_seed.record(5, at_ms=(now - 5400) * 1000)  # inside the previous hour
    metrics_seed.record(5)  # this hour
    await metrics_seed.flush()
    scope = {"scope": "date_range", "families": ["traffic"], "from": str(now - 7200), "to": str(now - 3700)}
    preview = api_json(await api.post("data/resets/preview", json=scope))
    response = await api.post("data/resets", json={**scope, "preview": preview["preview"], "reason": "r4 test"})
    assert response.status_code == 200, response.text
    # The precondition: the Overview (the fixed route) already refuses a number against the emptied baseline.
    kpis = api_json(await api.get("overview/kpis", params={"range": "1h", "compare": "previous"}))
    overview = next(t for t in kpis["tiles"] if t["key"] == "requests")
    assert (overview["value"], overview["delta"]) == (5, None), overview


async def test_r4_logicfix_cache_tiles_show_no_delta_over_a_reset_comparison(
    api: Any, api_app: Any, api_json: Any, metrics_seed: Any
) -> None:
    await _reset_previous_hour(api, api_app, api_json, metrics_seed)
    body = api_json(await api.get("cache/stats", params={"range": "1h"}))
    tiles = {tile["key"]: tile for tile in body["tiles"]}
    demand = tiles["demand"]
    assert demand["value"] == 5, demand
    # "+5 requests versus the previous hour" is exactly the misleading delta plan 6.8 forbids (today the tile has
    # delta 5 and no notice, and the page's `notices` list only resets inside the current window: none).
    assert (demand["delta"], demand["delta_pct"]) == (None, None), (demand, body["notices"])
    assert demand["notice"], demand


async def test_r4_logicfix_rotator_bytes_today_shows_no_delta_over_a_reset_yesterday(
    api: Any, api_app: Any, api_json: Any
) -> None:
    """The Overview itself: `rotator_bytes_today` (an `_extra_tile`, today against yesterday from `egress_usage`) is
    built outside `kpis_sync`, so a reset of the `egress_usage` family over yesterday leaves its delta in place."""
    now = api_app.clock.now()
    today = read_dashboard.day_start(now, str(api_app.ctx.settings.get("ui_timezone") or "UTC"))  # local midnight
    insert = (
        "INSERT INTO egress_usage (bucket_start, egress, granularity, requests, req_bytes, resp_bytes, overhead_bytes) "
        "VALUES (?, 'rotator', 'minute', 10, 1000, 4000, 0)"
    )

    def seed(conn: Any) -> None:
        conn.execute(insert, (today - 86_400,))  # yesterday, same time of day (then reset away)
        conn.execute(insert, (today,))  # today

    await api_app.ctx.dbs.metrics.write(seed)
    scope = {
        "scope": "date_range",
        "families": ["egress_usage"],
        "from": str(today - 86_400),
        "to": str(today - 86_400 + 3600),
    }
    preview = api_json(await api.post("data/resets/preview", json=scope))
    response = await api.post("data/resets", json={**scope, "preview": preview["preview"], "reason": "r4 test"})
    assert response.status_code == 200, response.text
    kpis = api_json(await api.get("overview/kpis", params={"range": "24h"}))
    tile = next(t for t in kpis["tiles"] if t["key"] == "rotator_bytes_today")
    assert tile["value"] == 5000, tile
    # "+5,000 bytes versus yesterday" against a yesterday a reset emptied: plan 6.8 wants the notice instead.
    assert (tile["delta"], tile["delta_pct"]) == (None, None), tile
    assert tile["notice"], tile


async def test_r4_logicfix_endpoint_detail_shows_no_delta_over_a_reset_comparison(
    api: Any, api_app: Any, api_json: Any, metrics_seed: Any
) -> None:
    await _reset_previous_hour(api, api_app, api_json, metrics_seed)
    body = api_json(await api.get("endpoints/detail", params={"range": "1h", "template": TEMPLATE}))
    requests = body["totals"]["requests"]
    assert requests["value"] == 5, requests
    assert (requests["delta"], requests["delta_pct"]) == (None, None), requests
    assert requests["notice"], requests
    assert any("reset" in notice for notice in body["notices"]), body["notices"]  # the page names the reset too


async def test_r4_logicfix_traffic_trend_rows_show_no_delta_over_a_reset(
    api: Any, api_app: Any, api_json: Any, metrics_seed: Any
) -> None:
    """The Traffic trends tables (week, month and year over year) build their deltas outside kpis_sync too: a reset
    inside the trailing week makes the week row of requests partial, with no delta and the notice."""
    await _reset_previous_hour(api, api_app, api_json, metrics_seed)
    body = api_json(await api.get("traffic/trends"))
    week = next(period for period in body["periods"] if period["key"] == "week")
    row = next(item for item in week["rows"] if item["metric"] == "requests")
    assert row["current"] == 5, row
    assert (row["delta"], row["delta_pct"], row.get("partial")) == (None, None, True), row
    assert row["notice"], row
    assert week["notices"], week
