"""Statistics into metrics.db (D17, plan 11.6): legacy totals with the 429 baseline, fingerprints, errors, probes."""

from __future__ import annotations

import json
from typing import Any

from v1_migration_helpers import rows

from roxy.migration.stats_import import EVENT_TYPE, ua_hash, value_hash


async def test_migration_legacy_totals_and_baseline_kpi(v1: Any, ws: Any, migrate: Any) -> None:
    builder = v1.small_tree(ws.v1)
    builder.write()
    report = await migrate()
    metrics = ws.state / "metrics.db"
    totals = {row["key"]: json.loads(row["value_json"]) for row in rows(metrics, "SELECT * FROM legacy_totals")}
    assert totals["v1.roblox_429_total"]["value"] == 579  # plan 2.5: "579 times"
    assert totals["v1.requests_total"]["value"] == 49800  # "just under 50,000 requests"
    assert totals["v1.roblox_429_per_10k_requests"]["value"] == 116.3  # plan 11.6: "about 116 per 10,000"
    assert totals["v1.requests_total"]["since"] == v1.V1_TIME - 86400 * 30  # v1's last clear, so "lifetime" is honest
    assert totals["v1.cache_stats"]["value"]["Hits"] == 21000
    assert totals["v1.status_sources"]["value"]["roblox"]["429"] == 579
    assert totals["v1.drops"]["value"]["pause"] == 7
    assert report.statistics["kpi"] == {
        "roblox_429_total": 579,
        "requests_total": 49800,
        "roblox_429_per_10k_requests": 116.3,
    }
    for value in totals.values():
        assert {"value", "label", "since", "source"} <= set(value)


async def test_migration_fingerprints_errors_and_probes(v1: Any, ws: Any, migrate: Any) -> None:
    builder = v1.small_tree(ws.v1)
    builder.write()
    report = await migrate()
    metrics = ws.state / "metrics.db"
    headers = {row["name"]: row for row in rows(metrics, "SELECT * FROM fingerprint_headers")}
    assert set(headers) == {"user-agent", "x-forwarded-for", "cookie"}
    assert headers["user-agent"]["count"] == 900
    assert (headers["user-agent"]["first_seen"], headers["user-agent"]["last_seen"]) == (v1.V1_TIME - 1000, v1.V1_TIME)

    values = rows(metrics, "SELECT * FROM fingerprint_values")
    assert [(row["name"], row["value"]) for row in values] == [("user-agent", "Roblox/WinInet")]
    assert values[0]["value_hash"] == value_hash("user-agent", "Roblox/WinInet")
    assert report.statistics["fingerprint_values_not_imported"]["count"] == 2  # an IP and a cookie fingerprint

    agents = {row["user_agent"]: row for row in rows(metrics, "SELECT * FROM fingerprint_user_agents")}
    merged = agents["python-requests/2.31"]  # normal and blocked records add up
    assert merged["count"] == 55
    assert merged["first_seen"] == v1.V1_TIME - 2000
    assert merged["ua_hash"] == ua_hash("python-requests/2.31")

    (error,) = rows(metrics, "SELECT * FROM errors")
    assert (error["signature"], error["count"], error["source"]) == ("ValueError: bad thing", 4, "roxy")
    assert (error["first_seen"], error["last_seen"]) == (v1.V1_TIME - 3000, v1.V1_TIME - 100)
    assert "192.0.2.10" not in error["last_detail"]  # client IPs are masked
    assert "IP: [ip]" in error["last_detail"]

    events = {
        json.loads(row["detail_json"])["reason"]: row
        for row in rows(metrics, "SELECT * FROM events WHERE type = ?", (EVENT_TYPE,))
    }
    probe = events['Non-Roblox URL: "evil.example/admin"']
    detail = json.loads(probe["detail_json"])
    assert (detail["count"], detail["first_seen"], detail["last_seen"]) == (12, v1.V1_TIME - 400, v1.V1_TIME - 50)
    assert probe["reason_code"] == "not_roblox"
    assert probe["at_ms"] == (v1.V1_TIME - 50) * 1000
    login = json.loads(events["Invalid 2FA code"]["detail_json"])
    assert login["first_seen"] is None  # v1 kept only the last time for a reason no longer in its recent list
