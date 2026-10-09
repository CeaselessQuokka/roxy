"""The Overview API (`/admin/api/v1/overview`) in the real app: status strip, KPI tiles with honest avoided calls,
the v1 baseline, sparklines and deltas, visitors, the chart, the breakdown, notable events and recommendations
(plan 14.1 Overview row, 11.6, P6, parity rows 114 and 130)."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

from roxy.abuse.pause import set_pause
from roxy.config.audit import Actor
from roxy.core.reasons import CacheState, Egress, Outcome, ReasonCode, Source

ACTOR = Actor("cli", "test")


def tiles_by_key(answer: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {tile["key"]: tile for tile in answer["tiles"]}


def seed_mix(seed: Any, *, at_ms: int | None = None) -> None:
    """10 served by Roblox (one call each), 5 cache hits (no call), 3 refused with Roxy's 429."""
    extra = {"at_ms": at_ms} if at_ms is not None else {}
    seed.record(10, **extra)
    seed.record(
        5,
        outcome=Outcome.SERVED_CACHE,
        reason=ReasonCode.CACHE_HIT,
        source=Source.CACHE,
        cache_state=CacheState.HIT,
        upstream_calls=0,
        egress=Egress.NONE,
        **extra,
    )
    seed.record(
        3,
        outcome=Outcome.REFUSED,
        reason=ReasonCode.THROTTLE,
        status=429,
        source=Source.ROXY,
        cache_state=CacheState.NA,
        upstream_calls=0,
        egress=Egress.NONE,
        **extra,
    )


async def test_overview_needs_a_session(api: Any, anon_api: Any, api_json: Any) -> None:
    assert (await anon_api.get("overview")).status_code == 401
    assert (await anon_api.get("overview/status")).status_code == 401
    response = await api.get("overview", params={"range": "1h"})
    body = api_json(response)
    for section in ("status", "recommendations", "kpis", "visitors", "requests_vs_upstream", "outcomes",
                    "top_endpoints", "top_places", "events", "notices"):  # fmt: skip
        assert section in body, section


async def test_kpi_tiles_are_honest_and_carry_sparklines_and_deltas(
    api: Any, api_app: Any, metrics_seed: Any, api_json: Any
) -> None:
    now_ms = api_app.clock.now_ms()
    metrics_seed.record(4, at_ms=now_ms - 90 * 60_000)  # in the previous hour only
    seed_mix(metrics_seed)
    recorder = api_app.ctx.recorder
    for _ in range(2):
        recorder.record_upstream_429(endpoint_template="games.roblox.com/v1/games", host="games.roblox.com",
                                     egress="direct", retry_after_s=30)  # fmt: skip
    await metrics_seed.flush()
    await api_app.ctx.heartbeat.beat()  # the fake clock moved during the login: a fresh heartbeat row
    body = api_json(await api.get("overview/kpis", params={"range": "1h"}))
    assert body["compare"]["mode"] == "previous"  # deltas even without a compare choice
    tiles = tiles_by_key(body)
    assert tiles["requests"]["value"] == 18
    assert tiles["requests"]["delta"] == 14
    assert tiles["requests"]["delta_pct"] == 350.0
    # P6: avoided = demand (refusals excluded) minus caller upstream calls.
    assert tiles["avoided"]["value"] == 5
    assert tiles["avoided_pct"]["value"] == round(5 * 100 / 15, 2)
    assert "5 of 15 caller requests" in tiles["avoided_pct"]["notice"]
    assert tiles["upstream_calls"]["value"] == 10
    assert tiles["roxy_429"]["value"] == 3
    assert tiles["roblox_429"]["value"] == 2  # from the upstream_429 log, not caller statuses
    assert tiles["roblox_429"]["notice"] == "20.0% of the upstream calls made for callers."
    assert tiles["roblox_429_per_10k"]["value"] == round(2 * 10_000 / 15, 2)
    assert tiles["roblox_429_per_10k"]["baseline"] is None  # no v1 import in this state
    assert tiles["served_cache"]["value"] == 5
    for key in ("requests", "avoided_pct", "upstream_calls", "roblox_429", "p95_ms", "requests_last_hour"):
        tile = tiles[key]
        assert tile["sparkline"], key
        assert sum(point[1] or 0 for point in tile["sparkline"]) >= 0
        assert set(tile) >= {"key", "label", "value", "unit", "delta", "delta_pct", "good_direction", "help"}
    assert body["sparkline_granularity"] == "minute"  # one hour keeps its own 61 minute buckets
    assert sum(point[1] for point in tiles["requests"]["sparkline"]) == 18
    assert tiles["roblox_429"]["good_direction"] == "down"
    assert tiles["avoided_pct"]["good_direction"] == "up"
    assert tiles["requests_last_hour"]["value"] == 18
    assert tiles["requests_last_hour"]["delta"] == 14  # against the hour before
    assert tiles["active_bans"]["value"] == 0
    assert tiles["service_uptime_s"]["value"] is not None
    assert list(tiles) == [t["key"] for t in body["tiles"]]


async def test_compare_mode_is_respected(api: Any, metrics_seed: Any, api_json: Any) -> None:
    seed_mix(metrics_seed)
    await metrics_seed.flush()
    body = api_json(await api.get("overview/kpis", params={"range": "1h", "compare": "week"}))
    assert body["compare"]["mode"] == "week"
    assert tiles_by_key(body)["requests"]["delta"] == 18


async def test_v1_baseline_comes_from_legacy_totals(api: Any, api_app: Any, api_json: Any) -> None:
    value = {"value": 116.0, "label": "v1 baseline", "since": 1_700_000_000, "source": "roxy v1"}

    def write(conn: Any) -> None:
        conn.execute(
            "INSERT INTO legacy_totals (key, value_json) VALUES (?, ?)",
            ("v1.roblox_429_per_10k_requests", json.dumps(value)),
        )

    await api_app.ctx.dbs.metrics.write(write)
    tiles = tiles_by_key(api_json(await api.get("overview/kpis", params={"range": "24h"})))
    tile = tiles["roblox_429_per_10k"]
    assert tile["baseline"] == value
    assert "116.0 per 10,000" in tile["notice"]


async def test_status_strip_reports_state_and_never_the_credential(
    api: Any, api_app: Any, metrics_seed: Any, api_json: Any, credentials_dir: Path
) -> None:
    body = api_json(await api.get("overview/status"))
    assert body["proxy"]["state"] == "running"
    assert body["proxy"]["pause_drops"] is None
    assert body["leader"]["this_worker"] is True
    assert body["leader"]["epoch"] >= 1
    assert body["version"]["release"]
    assert body["version"]["config_version"] == api_app.ctx.settings.version
    assert body["credential"]["status"]
    assert set(body["credential"]) == {"status", "enabled", "present", "cooldown_remaining_s", "problem"}
    assert "configured" in body["rotator"]
    assert "usable" in body["rotator"]
    secret = (credentials_dir / "roblox_credential").read_text().strip()
    response = await api.get("overview/status")
    assert secret not in response.text
    assert secret[-6:] not in response.text

    ctx = api_app.ctx
    await set_pause(ctx.dbs.control, ctx.clock, ACTOR, paused=True, reason="maintenance")
    await ctx.abuse.switches.reload()
    api_app.clock.advance(1)
    metrics_seed.record(4, outcome=Outcome.REFUSED, reason=ReasonCode.PAUSED, status=503, source=Source.ROXY,
                        cache_state=CacheState.NA, upstream_calls=0, egress=Egress.NONE)  # fmt: skip
    await metrics_seed.flush()
    paused = api_json(await api.get("overview/status"))["proxy"]
    assert paused["state"] == "paused"
    assert paused["paused"] is True
    assert paused["pause_drops"] == 4  # row 114: drops since the pause began
    assert paused["paused_since"] is not None


async def test_visitors_card(api: Any, api_app: Any, metrics_seed: Any, api_json: Any) -> None:
    recorder = api_app.ctx.recorder
    recorder.record_visit("home", "Mozilla/5.0 (Windows NT 10.0) Firefox/130.0")
    recorder.record_visit("home", "Mozilla/5.0 (compatible; Googlebot/2.1)")
    recorder.record_visit("home", "")
    recorder.record_visit("robots", "Googlebot")
    recorder.record_visit("admin", "Mozilla/5.0 Firefox/130.0")
    api_app.clock.advance(61)  # visits are counted per minute and written once their minute has closed
    await metrics_seed.flush()
    body = api_json(await api.get("overview/visitors", params={"range": "1h"}))
    tiles = tiles_by_key(body)
    assert tiles["human_visitors"]["value"] == 1
    assert tiles["crawler_visitors"]["value"] == 1
    assert tiles["unknown_visitors"]["value"] == 1
    assert tiles["home_visits"]["value"] == 3
    assert tiles["robots_crawls"]["value"] == 1
    assert tiles["admin_visits"]["value"] == 1
    assert sum(point[1] for point in tiles["home_visits"]["sparkline"]) == 3
    assert tiles["home_visits"]["delta"] == 3


async def test_chart_breakdown_and_top_tables(api: Any, metrics_seed: Any, api_json: Any) -> None:
    seed_mix(metrics_seed)
    metrics_seed.record(2, endpoint_template="users.roblox.com/v1/users/{userId}", host="users.roblox.com",
                        place_id="777")  # fmt: skip
    await metrics_seed.flush()
    body = api_json(await api.get("overview", params={"range": "1h"}))
    chart = body["requests_vs_upstream"]
    keys = {entry["key"] for entry in chart["series"]}
    assert keys == {"requests", "demand", "upstream_calls", "served_cache"}
    by_key = {entry["key"]: entry for entry in chart["series"]}
    assert sum(p[1] for p in by_key["requests"]["points"]) == 20
    assert sum(p[1] for p in by_key["upstream_calls"]["points"]) == 12
    outcomes = {item["outcome"]: item for item in body["outcomes"]["items"]}
    assert outcomes["served_upstream"]["requests"] == 12
    assert outcomes["served_upstream"]["answered_locally"] == 0
    assert outcomes["refused"]["requests"] == 3
    assert body["outcomes"]["total"] == 20
    assert body["top_endpoints"][0]["key"] == "games.roblox.com/v1/games"
    assert body["top_endpoints"][0]["requests"] == 18
    places = {row["key"]: row for row in body["top_places"]}
    assert places["12345"]["requests"] == 18
    assert places["777"]["requests"] == 2


async def test_notable_events_table_and_export(api: Any, api_app: Any, metrics_seed: Any, api_json: Any) -> None:
    metrics_seed.event("breaker_open", "warning", "upstream_cooldown", {"key": "direct:games.roblox.com"})
    metrics_seed.event("cache_purge", "info", "cache_purge", {"scope": "all", "removed": 3})
    metrics_seed.event("refusal", "info", "throttle", {"status": 429})  # high volume: not listed here
    await metrics_seed.flush()
    body = api_json(await api.get("overview/events", params={"range": "1h"}))
    types = [row["type"] for row in body["items"]]
    assert set(types) == {"breaker_open", "cache_purge"}
    assert body["total"] == 2
    assert body["capped"] is False
    assert {column["key"] for column in body["columns"]} >= {"at_ms", "type", "severity", "detail"}
    sorted_body = api_json(await api.get("overview/events", params={"range": "1h", "sort": "type", "order": "asc"}))
    assert [row["type"] for row in sorted_body["items"]] == ["breaker_open", "cache_purge"]
    composite = api_json(await api.get("overview", params={"range": "1h"}))
    assert {row["type"] for row in composite["events"]["rows"]} == {"breaker_open", "cache_purge"}

    download = await api.get("overview/events", params={"range": "1h", "format": "csv"})
    assert download.status_code == 200
    assert download.headers["content-type"].startswith("text/csv")
    rows = list(csv.reader(io.StringIO(download.text)))
    assert rows[0][:3] == ["Time", "Event", "Severity"]
    assert len(rows) == 3

    def audited(conn: Any) -> list[Any]:
        rows: list[Any] = conn.execute("SELECT target FROM audit_log WHERE action = 'export.download'").fetchall()
        return rows

    assert [row[0] for row in await api_app.ctx.dbs.control.read(audited)] == ["table:overview_events"]


async def test_top_recommendations_most_severe_first(api: Any, api_app: Any, api_json: Any) -> None:
    from roxy.insights.engine import write_recommendation
    from roxy.insights.models import Recommendation

    now = api_app.clock.now()
    recs = []
    for n, severity in enumerate(("info", "critical", "warn", "warn")):
        rec = Recommendation(rule_id=f"RULE-{n}", family="upstream", subject=f"s{n}", title=f"Title {n}",
                             severity=severity)  # fmt: skip
        rec.id = f"rec_{n:026d}"
        rec.fingerprint = f"fp{n}"
        rec.created_at = rec.updated_at = now - 100 + n
        recs.append(rec)
    dismissed = Recommendation(rule_id="RULE-X", family="upstream", subject="x", title="Gone", severity="critical")
    dismissed.id, dismissed.fingerprint, dismissed.state = "rec_x", "fpx", "dismissed"
    dismissed.created_at = dismissed.updated_at = now

    def write(conn: Any) -> None:
        for rec in [*recs, dismissed]:
            write_recommendation(conn, rec)

    await api_app.ctx.dbs.metrics.write(write)
    body = api_json(await api.get("overview/recommendations"))
    assert body["available"] is True
    assert body["open"] == 4
    items = body["items"]
    assert len(items) == 3
    assert [item["severity"] for item in items] == ["critical", "warn", "warn"]
    assert items[1]["rule_id"] == "RULE-3"  # newest first within a severity
    assert set(items[0]) >= {"id", "rule_id", "title", "severity", "risk", "state"}


async def test_bad_range_is_a_section_13_error(api: Any, section13: Any) -> None:
    fields = section13(await api.get("overview", params={"range": "forever"}), 422, "invalid_range")
    assert "range" in fields
