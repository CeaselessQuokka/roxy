"""The Traffic API (`/admin/api/v1/traffic`) in the real app: requests by outcome, bytes, verbs, status classes and
sources with the 429 verdict, the weekday heatmap, latency with its splits, and the trend tables (plan 14.1
Traffic row, 14.3, parity rows 68 to 70, 131, 132)."""

from __future__ import annotations

import csv
import io
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

from roxy.core.reasons import CacheState, Egress, Outcome, ReasonCode, Source


def series_by_key(answer: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {entry["key"]: entry for entry in answer["series"]}


def total(entry: dict[str, Any]) -> float:
    return sum(point[1] or 0 for point in entry["points"])


def seed_traffic(seed: Any) -> None:
    seed.record(3)
    seed.record(1, method="POST", caller_bytes_in=1000)
    seed.record(2, outcome=Outcome.REFUSED, reason=ReasonCode.THROTTLE, status=429, source=Source.ROXY,
                cache_state=CacheState.NA, upstream_calls=0, egress=Egress.NONE, upstream_bytes_in=0,
                upstream_bytes_out=0)  # fmt: skip
    seed.record(1, outcome=Outcome.SERVED_CACHE, reason=ReasonCode.CACHE_HIT, source=Source.CACHE,
                cache_state=CacheState.HIT, upstream_calls=0, egress=Egress.NONE, upstream_bytes_in=0,
                upstream_bytes_out=0, latency_ms=2.0)  # fmt: skip
    seed.record(1, outcome=Outcome.FAILED, reason=ReasonCode.UPSTREAM_5XX, status=502, source=Source.ROXY,
                egress=Egress.ROTATOR, latency_ms=900.0)  # fmt: skip


async def test_traffic_needs_a_session(anon_api: Any) -> None:
    for path in ("traffic/requests", "traffic/bytes", "traffic/heatmap", "traffic/trends", "traffic/status/sources"):
        assert (await anon_api.get(path)).status_code == 401, path


async def test_requests_stacked_by_outcome_with_compare(
    api: Any, api_app: Any, metrics_seed: Any, api_json: Any
) -> None:
    seed_traffic(metrics_seed)
    metrics_seed.record(4, at_ms=api_app.clock.now_ms() - 90 * 60_000)  # the previous hour
    await metrics_seed.flush()
    body = api_json(await api.get("traffic/requests", params={"range": "1h", "compare": "previous"}))
    series = series_by_key(body)
    assert total(series["requests:served_upstream"]) == 4
    assert total(series["requests:refused"]) == 2
    assert total(series["requests:served_cache"]) == 1
    assert total(series["requests:failed"]) == 1
    assert body["compare"]["mode"] == "previous"
    assert sum(total(entry) for entry in body["compare"]["series"]) == 4
    assert body["range"]["granularity"] == "minute"


async def test_bytes_series_and_totals(api: Any, metrics_seed: Any, api_json: Any) -> None:
    seed_traffic(metrics_seed)
    await metrics_seed.flush()
    body = api_json(await api.get("traffic/bytes", params={"range": "1h"}))
    series = series_by_key(body)
    assert set(series) == {"caller_bytes_in", "caller_bytes_out", "upstream_bytes_in", "upstream_bytes_out",
                           "cache_bytes_out"}  # fmt: skip
    assert body["totals"]["caller_bytes_in"] == 3 * 100 + 1000 + 2 * 100 + 100 + 100
    assert body["totals"]["cache_bytes_out"] == 500
    assert total(series["upstream_bytes_in"]) == body["totals"]["upstream_bytes_in"] == 5 * 900
    assert series["caller_bytes_in"]["unit"] == "bytes"


async def test_verbs_series_and_table_with_export(api: Any, api_app: Any, metrics_seed: Any, api_json: Any) -> None:
    seed_traffic(metrics_seed)
    await metrics_seed.flush()
    series = series_by_key(api_json(await api.get("traffic/verbs", params={"range": "1h"})))
    assert total(series["requests:GET"]) == 7
    assert total(series["requests:POST"]) == 1
    table = api_json(await api.get("traffic/verbs/table", params={"range": "1h"}))
    rows = {row["key"]: row for row in table["items"]}
    assert rows["GET"]["requests"] == 7
    assert rows["GET"]["refused"] == 2
    assert rows["GET"]["failed"] == 1
    assert rows["POST"]["served_upstream"] == 1
    assert table["sort"] == "requests"
    assert table["order"] == "desc"
    assert [row["key"] for row in table["items"]] == ["GET", "POST"]
    asc = api_json(await api.get("traffic/verbs/table", params={"range": "1h", "order": "asc"}))
    assert [row["key"] for row in asc["items"]] == ["POST", "GET"]
    download = await api.get("traffic/verbs/table", params={"range": "1h", "format": "csv"})
    assert download.status_code == 200
    lines = list(csv.reader(io.StringIO(download.text)))
    assert lines[0][0] == "Method"
    assert len(lines) == 3


async def test_status_sources_and_the_429_verdict(api: Any, api_app: Any, metrics_seed: Any, api_json: Any) -> None:
    seed_traffic(metrics_seed)
    await metrics_seed.flush()
    body = api_json(await api.get("traffic/status/sources", params={"range": "1h"}))
    pairs = {(row["source"], row["status"]): row["requests"] for row in body["items"]}
    assert pairs[("roxy", 429)] == 2
    assert pairs[("roxy", 502)] == 1
    assert pairs[("roblox", 200)] == 4
    assert pairs[("cache", 200)] == 1
    assert body["tiles"]["roxy_429"] == 2
    assert body["tiles"]["roblox_429"] == 0
    assert body["tiles"]["roxy_5xx"] == 1
    assert body["verdict"]["tone"] == "ok"
    assert "Roxy turning callers away" in body["verdict"]["text"]
    assert {row["source_label"] for row in body["items"]} >= {"Roxy (its own answers)", "Cache to caller"}

    api_app.ctx.recorder.record_upstream_429(endpoint_template="games.roblox.com/v1/games", host="games.roblox.com",
                                             egress="direct")  # fmt: skip
    await metrics_seed.flush()
    again = api_json(await api.get("traffic/status/sources", params={"range": "1h"}))
    assert again["tiles"]["roblox_429"] == 1
    assert again["verdict"]["tone"] == "bad"
    status = series_by_key(api_json(await api.get("traffic/status", params={"range": "1h"})))
    assert total(status["roblox_429"]) == 1
    assert total(status["roxy_429"]) == 2
    assert total(status["status_2xx"]) == 5
    by_source = series_by_key(api_json(await api.get("traffic/status", params={"range": "1h", "view": "source"})))
    assert total(by_source["requests:roxy"]) == 3


async def test_heatmap_puts_requests_in_their_local_hour(
    api: Any, api_app: Any, metrics_seed: Any, api_json: Any
) -> None:
    metrics_seed.record(5)
    await metrics_seed.flush()
    body = api_json(await api.get("traffic/heatmap", params={"range": "24h"}))
    heat = body["heatmap"]
    tz = ZoneInfo(str(api_app.ctx.settings.get("ui_timezone")))
    local = datetime.fromtimestamp(api_app.clock.now(), tz)
    assert heat["cells"][local.weekday()][local.hour] == 5
    assert sum(sum(row) for row in heat["cells"]) == 5
    assert heat["max"] == 5
    assert heat["weekdays"][0] == "Mon"
    assert len(heat["hours"]) == 24
    assert body["read"]["granularity"] == "hour"
    bad = await api.get("traffic/heatmap", params={"metric": "bogus"})
    assert bad.status_code == 422


async def test_latency_series_and_splits(api: Any, metrics_seed: Any, api_json: Any, section13: Any) -> None:
    seed_traffic(metrics_seed)
    await metrics_seed.flush()
    plain = api_json(await api.get("traffic/latency", params={"range": "1h"}))
    assert {entry["key"] for entry in plain["series"]} == {"p50_ms", "p95_ms", "p99_ms", "queue_wait_p95_ms"}
    assert plain["split"] == "none"
    split = series_by_key(api_json(await api.get("traffic/latency", params={"range": "1h", "split": "egress"})))
    assert {"p95_ms:direct", "p95_ms:rotator", "p95_ms:none"} <= set(split)
    table = api_json(await api.get("traffic/latency/split", params={"range": "1h", "by": "egress"}))
    rows = {row["key"]: row for row in table["items"]}
    assert rows["rotator"]["p95_ms"] > rows["direct"]["p95_ms"]
    assert rows["rotator"]["failed"] == 1
    assert table["by"] == "egress"
    section13(await api.get("traffic/latency", params={"split": "planet"}), 422, "validation_failed")
    section13(await api.get("traffic/latency/split", params={"by": "planet"}), 422, "validation_failed")


async def test_trend_tables(api: Any, metrics_seed: Any, api_json: Any) -> None:
    seed_traffic(metrics_seed)
    await metrics_seed.flush()
    body = api_json(await api.get("traffic/trends"))
    assert [period["key"] for period in body["periods"]] == ["week", "month", "year"]
    for period in body["periods"]:
        rows = {row["metric"]: row for row in period["rows"]}
        assert rows["requests"]["current"] == 8
        assert rows["requests"]["previous"] == 0
        assert rows["requests"]["delta"] == 8
        assert rows["requests"]["delta_pct"] is None
        assert rows["roblox_429"]["good_direction"] == "down"
        assert sum(point[1] or 0 for point in rows["requests"]["sparkline"]) == 8
        assert period["previous_range"]["to"] == period["range"]["from"]  # the same length, just before
