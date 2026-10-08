"""A large v1 tree (plan 19.6 "large"): every v1 rule store at its v1 cap, big statistics, the host list limit."""

from __future__ import annotations

from typing import Any

from v1_migration_helpers import rows

from roxy.config.defaults import CACHE_RULES, IGNORED_CACHE_PARAMS
from roxy.migration.report import IMPORTED


async def test_migration_large_tree(v1: Any, ws: Any, migrate: Any) -> None:
    builder = v1.large_tree(ws.v1)
    builder.write()
    report = await migrate()
    assert report.errors == []
    control = ws.state / "control.db"

    def count(table: str) -> int:
        return int(rows(control, f"SELECT count(*) FROM {table}")[0][0])

    assert count("rules_endpoint_block") == 200
    assert count("rules_endpoint_limit") == 200
    assert count("rules_cache") == 200 + len(CACHE_RULES)  # the shipped defaults stay next to the v1 rules
    assert count("rules_user_agent") == 100
    assert count("rules_header") == 100
    assert count("access_list") == 100
    assert count("cache_ignored_params") == 50 + len(IGNORED_CACHE_PARAMS)
    assert count("throttle_tiers") == 12
    for table in ("rules_endpoint_block", "rules_endpoint_limit", "rules_user_agent", "rules_header", "access_list"):
        assert {item["status"] for item in report.rules[table]} == {IMPORTED}, table

    positions = [row["position"] for row in rows(control, "SELECT position FROM rules_user_agent ORDER BY position")]
    assert positions == list(range(100))
    assert report.ladder["status"] == IMPORTED
    assert len([r for r in report.text_rewrites if r["table"] == "rules_endpoint_limit"]) == 200
    assert len([r for r in report.text_rewrites if r["table"] == "throttle_tiers"]) == 12

    metrics = ws.state / "metrics.db"
    assert rows(metrics, "SELECT count(*) FROM errors")[0][0] == 1000
    assert rows(metrics, "SELECT count(*) FROM fingerprint_headers")[0][0] == 300
    assert rows(metrics, "SELECT count(*) FROM fingerprint_values")[0][0] == 300 * 20
    assert rows(metrics, "SELECT count(*) FROM fingerprint_user_agents")[0][0] == 1001
    assert rows(metrics, "SELECT count(*) FROM events WHERE type = 'v1_probe_summary'")[0][0] == 100

    hosts = report.hosts
    assert len(hosts["not_added"]) > 0  # 250 extra hosts cannot all fit in the 200 item setting
    assert any("did not fit in allowed_roblox_hosts" in warning for warning in report.warnings)
    stored = rows(control, "SELECT value_json FROM settings WHERE key = 'allowed_roblox_hosts'")[0][0]
    assert stored.count(".roblox.com") == 200
