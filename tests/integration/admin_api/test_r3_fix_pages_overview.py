"""Review round 3 (group admin_pages): the Overview's "last hour" tiles honor plan 6.8 like every other tile.

What this is
    One integration test: after a data reset of the hour before, `Requests (last hour)` and `Failures (last hour)`
    (finding parity-2) show the read model's partial-data notice and no delta, and the range tiles carry the tile
    notice `queries.kpis` sets (finding parity-12, whose read model part is in `metrics/queries.py`).

Why it exists
    Plan 6.8: "a KPI or comparison whose current or comparison window overlaps a reset of its family shows a notice
    ... instead of a misleading delta". The two last-hour tiles compare the trailing hour with the hour before, so a
    reset of the hour before would otherwise show "+N versus an emptied hour".

How it works
    Requests are seeded through the real recorder, the hour before is reset through the real Data API (preview, then
    run), then `GET /overview/kpis` is read as a signed-in admin.

What to read next
    `roxy/admin/api/overview.py` (`build_kpis`), `roxy/metrics/queries.py` (`kpis_sync`, `_mark_partial`).
"""

from __future__ import annotations

from typing import Any

from roxy.core.reasons import Egress, Outcome, ReasonCode, Source


async def test_last_hour_tiles_show_the_reset_notice_instead_of_a_delta(
    api: Any, api_app: Any, api_json: Any, metrics_seed: Any
) -> None:
    now = int(api_app.clock.now())
    failed = {"outcome": Outcome.FAILED, "status": 504, "source": Source.ROXY, "egress": Egress.DIRECT}
    metrics_seed.record(4, at_ms=(now - 3000) * 1000)  # inside the trailing hour
    metrics_seed.record(1, reason=ReasonCode.UPSTREAM_TIMEOUT, at_ms=(now - 3000) * 1000, **failed)
    metrics_seed.record(6, at_ms=(now - 5400) * 1000)  # the hour before, about to be reset
    await metrics_seed.flush()
    scope = {"scope": "date_range", "families": ["traffic"], "from": str(now - 7200), "to": str(now - 3700)}
    preview = api_json(await api.post("data/resets/preview", json=scope))
    response = await api.post("data/resets", json={**scope, "preview": preview["preview"], "reason": "test"})
    assert response.status_code == 200, response.text
    kpis = api_json(await api.get("overview/kpis", params={"range": "1h", "compare": "previous"}))
    tiles = {tile["key"]: tile for tile in kpis["tiles"]}
    for key, value in (("requests_last_hour", 5), ("failures_last_hour", 1)):
        tile = tiles[key]
        assert tile["value"] == value, tile
        assert (tile["delta"], tile["delta_pct"], tile.get("partial")) == (None, None, True), tile
        assert tile["notice"], tile
    requests = tiles["requests"]
    assert (requests["delta"], requests.get("partial")) == (None, True), requests
    assert requests["notice"], requests  # the read model's tile notice reaches the answer
