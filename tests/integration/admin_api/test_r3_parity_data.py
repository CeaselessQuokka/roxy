"""Review round 3, parity lens: v1 clears as v2 resets, and the Data page retention view (plan 6.8, 6.10; row 83).

What this is
    Tests for defects of the Data area as the parity review found them (they were strict xfails; all are fixed):
      * parity-8: the v1 cache "Clear stats" mapped to the `cache_stats` family left the misses behind, so the hit
        ratio of every window read 0 percent, and it took the cached requests out of the Traffic totals. The family
        now clears the cache state of every lookup (hits, misses, stale, coalesced together) and keeps the requests;
      * parity-9: the v1 per-tab clears of the three attempt logs (and of the pause and throttle-all drop counters)
        mapped to the whole `refusals` family, so clearing one tab emptied the other two. Each tab has its own
        narrower family now, and the drop counters map to "nothing to reset";
      * parity-10: the retention view of the Data page left out catalog settings whose card is `data#retention`; it
        now lists every setting of the retention and record cap cards.

Why it exists
    Plan 6.8: every v1 clear target maps onto a reset scope (`data.V1_CLEAR_TARGETS`, served by `GET /data/resets`
    for the P11 buttons), and a reset must leave headline numbers honest. v1's clears were narrow
    (`.remake/v1notes/dashboard.md` 2.10): "Clear stats" zeroed Hits, Misses, Stale and Coalesced together and never
    touched the request counters; `blocked_attempts`, `rate_limited_attempts` and `header_blocked_attempts` each
    emptied one table. Plan 6.10: every retention setting is shown on the Data page.

How it works
    Data is seeded through the real recorder, the reset runs through the real flow (`POST /data/resets/preview`, then
    `POST /data/resets` with the digest, the typed phrase and a reason), and the affected routes are read back. The
    mapping used is the one the API publishes in `v1_clear_targets`.

What to read next
    `roxy/admin/api/data.py` (`FAMILIES`, `V1_CLEAR_TARGETS`, `retention_view`), `roxy/storage/read_sizes.py`
    (`TABLES`), `roxy/admin/api/cache.py` (`cache_stats`).
"""

from __future__ import annotations

from typing import Any

import pytest

from roxy.config.catalog import CATALOG
from roxy.core.reasons import CacheState, Egress, Outcome, ReasonCode, Source

pytestmark = pytest.mark.asyncio


def refused(seed: Any, count: int, reason: ReasonCode, status: int, **fields: Any) -> None:
    seed.record(
        count,
        outcome=Outcome.REFUSED,
        reason=reason,
        status=status,
        source=Source.ROXY,
        cache_state=CacheState.NA,
        egress=Egress.NONE,
        upstream_calls=0,
        upstream_bytes_in=0,
        upstream_bytes_out=0,
        check=reason.value,
        **fields,
    )


async def run_v1_clear(api: Any, api_json: Any, target: str) -> dict[str, Any]:
    """Run the reset the API maps a v1 clear target to, through preview, digest, phrase and reason."""
    mapping = api_json(await api.get("data/resets"))["v1_clear_targets"][target]
    scope = {key: value for key, value in mapping.items() if key != "note"}
    preview = api_json(await api.post("data/resets/preview", json=scope))
    body = {**scope, "preview": preview["preview"], "reason": f"v1 clear {target}"}
    if preview.get("confirm_phrase"):
        body["confirm"] = preview["confirm_phrase"]
    response = await api.post("data/resets", json=body)
    assert response.status_code == 200, response.text
    result: dict[str, Any] = api_json(response)
    assert result["status"] == "done", result
    return result


async def test_parity_8_clearing_cache_stats_keeps_ratios_honest_and_requests(
    api: Any, api_json: Any, metrics_seed: Any
) -> None:
    metrics_seed.record(
        4, outcome=Outcome.SERVED_CACHE, reason=ReasonCode.CACHE_HIT, source=Source.CACHE,
        cache_state=CacheState.HIT, upstream_calls=0, egress=Egress.NONE,
    )  # fmt: skip
    metrics_seed.record(2)  # two misses, served by Roblox
    await metrics_seed.flush()
    before = api_json(await api.get("cache/stats", params={"range": "1h"}))
    assert before["states"]["cache_hit"] == 4
    assert before["states"]["cache_miss"] == 2
    await run_v1_clear(api, api_json, "cache")
    after = api_json(await api.get("cache/stats", params={"range": "1h"}))
    kpis = api_json(await api.get("overview/kpis", params={"range": "1h"}))
    requests = next(tile["value"] for tile in kpis["tiles"] if tile["key"] == "requests")
    found = {
        "hits": after["states"]["cache_hit"],
        "misses": after["states"]["cache_miss"],
        "hour_ratio": after["recent_hit_ratio"]["1h"]["hit_ratio"],
        "requests": requests,
    }
    # v1: Hits, Misses, Stale and Coalesced are zeroed together (no ratio until new lookups) and the request
    # counters are untouched.
    assert found == {"hits": 0, "misses": 0, "hour_ratio": None, "requests": 6}, found


async def test_parity_9_clearing_one_attempts_tab_keeps_the_others(api: Any, api_json: Any, metrics_seed: Any) -> None:
    refused(metrics_seed, 2, ReasonCode.ENDPOINT_BLOCKED, 403, client_ip="203.0.113.91", path="games.roblox.com/v1/a")
    refused(metrics_seed, 1, ReasonCode.ENDPOINT_RULE, 429, client_ip="203.0.113.92", path="economy.roblox.com/v1/b")
    refused(metrics_seed, 1, ReasonCode.HEADER_RULE, 429, client_ip="203.0.113.93", path="games.roblox.com/v2/c")
    await metrics_seed.flush()
    for tab in ("endpoint-blocks", "endpoint-rules", "header-rules"):
        assert api_json(await api.get(f"protection/{tab}/attempts"))["total"] == 1, tab
    await run_v1_clear(api, api_json, "blocked_attempts")
    totals = {
        tab: api_json(await api.get(f"protection/{tab}/attempts"))["total"]
        for tab in ("endpoint-blocks", "endpoint-rules", "header-rules")
    }
    assert totals == {"endpoint-blocks": 0, "endpoint-rules": 1, "header-rules": 1}, totals


async def test_parity_12_kpi_delta_over_a_reset_window_is_replaced_by_a_notice(
    api: Any, api_app: Any, api_json: Any, metrics_seed: Any
) -> None:
    """Plan 6.8: "a KPI or comparison whose current or comparison window overlaps a reset of its family shows a notice
    ... instead of a misleading delta. Comparison baselines are never synthesized to hide the gap." Here the previous
    hour's traffic was reset, so "+5 requests versus the previous hour" is exactly the misleading delta. (The read
    model's tile notice and the family scoping, a logins reset leaving the request tile alone, are pinned in
    `tests/unit/metrics/test_metrics_reset_scope.py`.)"""
    now = int(api_app.clock.now())
    metrics_seed.record(5, at_ms=(now - 5400) * 1000)  # inside the previous hour
    metrics_seed.record(5)  # this hour
    await metrics_seed.flush()
    scope = {"scope": "date_range", "families": ["traffic"], "from": str(now - 7200), "to": str(now - 3700)}
    preview = api_json(await api.post("data/resets/preview", json=scope))
    response = await api.post("data/resets", json={**scope, "preview": preview["preview"], "reason": "test"})
    assert response.status_code == 200, response.text
    kpis = api_json(await api.get("overview/kpis", params={"range": "1h", "compare": "previous"}))
    assert kpis["notices"], kpis["notices"]  # the page knows a reset touched the comparison
    tile = next(t for t in kpis["tiles"] if t["key"] == "requests")
    assert tile["value"] == 5
    assert (tile["delta"], tile["delta_pct"]) == (None, None), tile  # no number against an emptied baseline


async def test_parity_10_retention_view_lists_every_data_retention_setting(api: Any, api_json: Any) -> None:
    body = api_json(await api.get("data/retention"))
    shown = {item["key"] for item in body["settings"]}
    wanted = {key for key, spec in CATALOG.items() if "data#retention" in spec.pages}
    assert sorted(wanted - shown) == [], sorted(wanted - shown)
