"""The `allowed_roblox_hosts` union (plans 9.10 and 18.3): shipped list plus every roblox.com host seen in v1."""

from __future__ import annotations

import json
from typing import Any

from v1_migration_helpers import rows

from roxy.config import catalog
from roxy.migration.hosts import HostEvidence, collect_hosts, host_of, plan_hosts
from roxy.migration.report import ALREADY, IMPORTED


def test_host_of() -> None:
    assert host_of("games.roblox.com/v1/games/{gameId}/votes") == "games.roblox.com"
    assert host_of("https://Accountinformation.roblox.com/v1/birthdate") == "accountinformation.roblox.com"
    assert host_of("realtime.roblox.com.") == "realtime.roblox.com"
    assert host_of("api.ipify.org") is None
    assert host_of("roblox.com.evil.example/x") is None
    assert host_of("evilroblox.com/x") is None
    assert host_of("games.roblox.com:8080/x") == "games.roblox.com"
    assert host_of(None) is None


def test_collect_and_plan_hosts(v1: Any) -> None:
    diagnostics = v1.empty_diagnostics()
    v1.add_statistics(diagnostics)
    evidence = collect_hosts(diagnostics)
    assert {"games.roblox.com", "realtime.roblox.com", "chat.roblox.com", "badges.roblox.com"} <= set(evidence)
    assert "accountinformation.roblox.com" in evidence  # internal calls count too (plan 9.10)
    assert evidence["realtime.roblox.com"].successful is True
    assert evidence["chat.roblox.com"].successful is False
    current = [str(host) for host in catalog.DEFAULTS["allowed_roblox_hosts"]]
    plan = plan_hosts(current, evidence)
    assert plan.new_list is not None
    assert plan.new_list[: len(current)] == current  # the shipped list stays first, in order
    assert [item.host for item in plan.added] == ["realtime.roblox.com", "chat.roblox.com"]  # proven first
    assert plan_hosts(plan.new_list, evidence).new_list is None  # nothing left to add


def test_plan_hosts_respects_the_setting_limit() -> None:
    current = [f"h{i}.roblox.com" for i in range(195)]
    evidence = {f"n{i}.roblox.com": HostEvidence(f"n{i}.roblox.com", requests=i) for i in range(10)}
    plan = plan_hosts(current, evidence)
    assert plan.new_list is not None
    assert len(plan.new_list) == 200
    assert [item.host for item in plan.added] == [f"n{i}.roblox.com" for i in (9, 8, 7, 6, 5)]  # busiest first
    assert plan.not_added == [f"n{i}.roblox.com" for i in (4, 3, 2, 1, 0)]


async def test_migration_host_union(v1: Any, ws: Any, migrate: Any) -> None:
    builder = v1.small_tree(ws.v1)
    builder.write()
    report = await migrate()
    hosts = report.hosts
    assert hosts["status"] == IMPORTED
    added = {item["host"]: item for item in hosts["added"]}
    assert set(added) == {"realtime.roblox.com", "chat.roblox.com"}
    assert added["realtime.roblox.com"]["seen_in"] == ["endpoints"]
    assert added["realtime.roblox.com"]["requests"] == 300
    assert added["chat.roblox.com"]["successful"] is False
    stored = rows(ws.state / "control.db", "SELECT value_json FROM settings WHERE key = 'allowed_roblox_hosts'")
    value = json.loads(stored[0][0])
    shipped = [str(host) for host in catalog.DEFAULTS["allowed_roblox_hosts"]]
    assert value == [*shipped, "realtime.roblox.com", "chat.roblox.com"]

    again = await migrate()
    assert again.hosts["status"] == ALREADY
    assert {item["host"] for item in again.hosts["added"]} == set(added)  # still listed, no longer new
    assert all(item["new_this_run"] is False for item in again.hosts["added"])
