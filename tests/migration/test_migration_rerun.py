"""Reruns after the cutover (plan 18.3 "safe to rerun"): what an earlier run placed is never placed again.

What this is
    Tests for the import ledger in the `service_state.v1_import` marker: a rerun adds only v1 items that are new
    since the earlier run, and leaves everything that run placed (and anything the owner changed or deleted in v2
    since) as it is. Also the marker after a failed first run, which must not claim a finished import.

Why it exists
    Review findings 1, 2 and 6. Before the ledger, a rerun after the owner switched the pause off paused production
    again, and a rerun brought back deleted rules, reset settings, removed hosts, a flat ladder, a deleted admin
    account and the bootstrap cookie the C1 runbook told the owner to delete.

How it works
    Each test runs the migrator, changes v2 the way the dashboard would (the services, never raw SQL where a
    service exists), runs it again, and checks both the databases and the report.

What to read next
    `src/roxy/migration/ledger.py` and `src/roxy/migration/runner.py`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from v1_migration_helpers import by_key, db_snapshot, rows

from roxy.abuse.pause import set_pause
from roxy.abuse.throttle_all import set_throttle_all
from roxy.config.audit import Actor
from roxy.config.settings_service import SettingsService
from roxy.migration import runner as runner_module
from roxy.migration.ledger import ImportLedger, rule_key
from roxy.migration.report import ALREADY, IMPORTED, KEPT, REMOVED, render_markdown
from roxy.migration.runner import MARKER_KEY
from roxy.rules.service import RulesService
from roxy.storage.db import open_databases

OWNER = Actor("admin", "owner")
SERVERS_BLOCK = "games.roblox.com/v1/games/*/servers"


def _state(control: Path, key: str) -> dict[str, Any]:
    found = rows(control, "SELECT value_json FROM service_state WHERE key = ?", (key,))
    value = json.loads(found[0][0]) if found else {}
    assert isinstance(value, dict)
    return value


def _hosts(control: Path) -> list[str]:
    stored = rows(control, "SELECT value_json FROM settings WHERE key = 'allowed_roblox_hosts'")[0][0]
    value = json.loads(stored)
    assert isinstance(value, list)
    return value


async def test_migration_rerun_after_unpause_keeps_v2_state(v1: Any, ws: Any, migrate: Any, fake_clock: Any) -> None:
    """v1 was paused and in throttle-all with no reason (the v1 dashboard sends an empty one). After the owner
    switches both off in v2, a rerun must not switch them on again (review finding 1)."""
    builder = v1.V1TreeBuilder(ws.v1)
    builder.runtime.update(Paused=True, PausedSince=float(v1.V1_TIME), PauseReason="")
    builder.runtime.update(ThrottleAll=True, ThrottleAllSince=float(v1.V1_TIME), ThrottleAllReason="")
    builder.write()
    first = await migrate()
    control = ws.state / "control.db"
    assert (_state(control, "pause")["paused"], _state(control, "throttle_all")["enabled"]) == (True, True)
    assert first.status == "imported"

    dbs = open_databases({"ROXY_STATE_DIR": str(ws.state)})
    try:
        await set_pause(dbs.control, fake_clock, OWNER, paused=False)
        await set_throttle_all(dbs.control, fake_clock, OWNER, enabled=False)
    finally:
        await dbs.close_all()
    fake_clock.advance(86400)
    second = await migrate()
    assert (_state(control, "pause")["paused"], _state(control, "throttle_all")["enabled"]) == (False, False)
    items = {item["key"]: item for item in second.service_state}
    assert (items["pause"]["status"], items["throttle_all"]["status"]) == (KEPT, KEPT)
    assert any("first import" in note for note in items["pause"]["notes"])
    assert not any("v2 will start" in warning for warning in second.warnings)
    assert (second.status, second.changes) == ("already_imported", 0)


async def test_migration_rerun_never_recreates_what_v2_removed(v1: Any, ws: Any, migrate: Any, fake_clock: Any) -> None:
    """Deleted rules, a flat ladder, a reset setting, a removed host, a deleted admin account and the bootstrap
    cookie removed per the C1 runbook all stay as the owner left them (review finding 2)."""
    builder = v1.small_tree(ws.v1)
    builder.write()
    await migrate(admin=True)
    control = ws.state / "control.db"
    block_id = rows(control, "SELECT id FROM rules_endpoint_block WHERE pattern = ?", (SERVERS_BLOCK,))[0][0]
    dbs = open_databases({"ROXY_STATE_DIR": str(ws.state)})
    try:
        service = RulesService(dbs.control, clock=fake_clock)
        await service.delete("rules_endpoint_block", block_id, OWNER, "not needed in v2")
        await service.delete("rules_user_agent", "a1b2c3d4", OWNER, "not needed in v2")
        await service.replace_throttle_tiers([], OWNER, "flat ladder in v2")
        settings = SettingsService(dbs.control, clock=fake_clock)
        await settings.reset_to_default("allowed_requests_per_minute", OWNER, "back to the default")
        hosts = [host for host in _hosts(control) if host != "realtime.roblox.com"]
        await settings.update({"allowed_roblox_hosts": hosts}, OWNER, "realtime is not used")
        await dbs.control.write(lambda conn: conn.execute("DELETE FROM admin_users"))
    finally:
        await dbs.close_all()
    (ws.credentials / "roblox_credential").unlink()  # the C1 runbook, after a UI replacement
    before = db_snapshot(control)
    fake_clock.advance(86400)

    second = await migrate(admin=True)
    assert second.errors == []
    assert not rows(control, "SELECT 1 FROM rules_endpoint_block WHERE pattern = ?", (SERVERS_BLOCK,))
    assert not rows(control, "SELECT 1 FROM rules_user_agent WHERE id = 'a1b2c3d4'")
    assert rows(control, "SELECT count(*) FROM throttle_tiers")[0][0] == 0
    assert not rows(control, "SELECT 1 FROM settings WHERE key = 'allowed_requests_per_minute'")
    assert "realtime.roblox.com" not in _hosts(control)
    assert rows(control, "SELECT count(*) FROM admin_users")[0][0] == 0
    assert not (ws.credentials / "roblox_credential").exists()
    assert db_snapshot(control) == before  # nothing at all was written
    assert (second.status, second.changes) == ("already_imported", 0)

    rules = {table: by_key(items) for table, items in second.rules.items()}
    assert rules["rules_endpoint_block"][SERVERS_BLOCK]["status"] == REMOVED
    assert rules["rules_user_agent"]["a1b2c3d4"]["status"] == REMOVED
    assert rules["rules_user_agent"]["0f0f0f0f"]["status"] == ALREADY
    assert by_key(second.settings)["allowed_requests_per_minute"]["status"] == REMOVED
    assert by_key(second.settings)["cache_ttl_seconds"]["status"] == ALREADY
    assert second.ladder["status"] == KEPT
    assert second.hosts["removed_in_v2"] == ["realtime.roblox.com"]
    assert second.admin["status"] == REMOVED
    credentials = {item["name"]: item["status"] for item in second.credentials}
    assert credentials["roblox_credential"] == "removed_after_import"
    assert credentials["rotator_url"] == "already_present"
    markdown = render_markdown(second)
    assert "only v1 items that are new since then" in markdown


async def test_migration_rerun_adds_items_new_in_v1(v1: Any, ws: Any, migrate: Any, fake_clock: Any) -> None:
    """The ledger never blocks a v1 item the earlier run did not see (say, a rule added in v1 after a first real
    run): those are imported, while the deleted ones stay deleted."""
    builder = v1.small_tree(ws.v1)
    builder.write()
    await migrate()
    control = ws.state / "control.db"
    block_id = rows(control, "SELECT id FROM rules_endpoint_block WHERE pattern = ?", (SERVERS_BLOCK,))[0][0]
    dbs = open_databases({"ROXY_STATE_DIR": str(ws.state)})
    try:
        await RulesService(dbs.control, clock=fake_clock).delete("rules_endpoint_block", block_id, OWNER, "gone")
    finally:
        await dbs.close_all()

    rt = builder.runtime
    rt["EndpointBlocks"]["games.roblox.com/v1/games/*/new"] = {"Note": "added later", "Message": "", "Type": "glob"}
    rt["UserAgentRules"]["deadbeef"] = dict(rt["UserAgentRules"]["a1b2c3d4"], Needle="later-bot")
    v1.set_setting(rt, "stale_ip_duration", 120)
    builder.diagnostics["endpoints"]["presence.roblox.com/v1/presence/users"] = {"Count": 40, "LastStatus": 200}
    builder.write()
    second = await migrate()
    assert second.errors == []
    assert second.status == "imported"
    assert any("changed since the first import" in warning for warning in second.warnings)
    rules = {table: by_key(items) for table, items in second.rules.items()}
    assert rules["rules_endpoint_block"]["games.roblox.com/v1/games/*/new"]["status"] == IMPORTED
    assert rules["rules_endpoint_block"][SERVERS_BLOCK]["status"] == REMOVED
    assert rules["rules_user_agent"]["deadbeef"]["status"] == IMPORTED
    assert by_key(second.settings)["stale_ip_duration"]["status"] == IMPORTED
    assert "presence.roblox.com" in _hosts(control)

    third = await migrate()
    assert (third.status, third.changes) == ("already_imported", 0)


async def test_migration_marker_after_a_failed_first_run(
    v1: Any, ws: Any, migrate: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A first run with a failed step records only the steps that finished, and does not claim a finished
    import: the next run imports the rest and says so honestly (review finding 6)."""
    builder = v1.small_tree(ws.v1)
    builder.write()
    original = runner_module._import_rules

    async def broken(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("disk full")

    monkeypatch.setattr(runner_module, "_import_rules", broken)
    first = await migrate()
    monkeypatch.setattr(runner_module, "_import_rules", original)
    assert first.status == "completed_with_errors"
    control = ws.state / "control.db"
    marker = _state(control, MARKER_KEY)
    assert marker["complete"] is False
    assert marker["ledger"]["rules"] == {}
    assert "allowed_requests_per_minute" in marker["ledger"]["settings"]

    second = await migrate()
    assert second.errors == []
    assert second.already_imported is False
    assert second.resumed_incomplete_import is True
    imported = sum(1 for items in second.rules.values() for item in items if item["status"] == IMPORTED)
    assert imported == 11
    markdown = render_markdown(second)
    assert "Already imported" not in markdown
    assert "stopped with errors" in markdown
    assert by_key(second.settings)["allowed_requests_per_minute"]["status"] == ALREADY
    assert _state(control, MARKER_KEY)["complete"] is True

    third = await migrate()
    assert third.already_imported is True
    assert (third.status, third.changes) == ("already_imported", 0)


def test_ledger_round_trip_and_malformed_parts() -> None:
    ledger = ImportLedger(
        settings={"stale_ip_duration", "allowed_requests_per_minute"},
        hosts={"realtime.roblox.com"},
        ladder=True,
        service_state=True,
        admin={"owner-test"},
        credentials={"/etc/roxy/credentials": {"rotator_url"}},
    )
    ledger.add_rules("rules_cache", [SERVERS_BLOCK])
    data = json.loads(json.dumps(ledger.to_json()))
    assert data["settings"] == ["allowed_requests_per_minute", "stale_ip_duration"]  # sorted: stable JSON
    assert ImportLedger.from_json(data) == ledger
    assert ledger.has_rule("rules_cache", SERVERS_BLOCK)
    assert not ledger.has_rule("rules_endpoint_block", SERVERS_BLOCK)
    key = rule_key("rules_cache", SERVERS_BLOCK)
    assert len(key) == 16
    assert "roblox" not in key  # the ledger never holds the text of a v1 rule
    assert ImportLedger.from_json({"settings": "x", "rules": [], "ladder": "yes", "credentials": 3}) == ImportLedger()
    assert ImportLedger.from_json(None) == ImportLedger()


async def test_migration_upgrades_an_old_marker_without_a_ledger(v1: Any, ws: Any, migrate: Any) -> None:
    """A version 1 marker (written before the ledger existed) counts as a finished import; the next run fills the
    ledger from what it finds in v2 and stores a version 2 marker, once."""
    builder = v1.small_tree(ws.v1)
    builder.write()
    first = await migrate()
    old = {"version": 1, "imported_at": first.first_imported_at, "inputs": {}}
    dbs = open_databases({"ROXY_STATE_DIR": str(ws.state)})
    try:
        await dbs.control.write(
            lambda conn: conn.execute(
                "UPDATE service_state SET value_json = ? WHERE key = ?", (json.dumps(old), MARKER_KEY)
            )
        )
    finally:
        await dbs.close_all()
    second = await migrate()
    assert second.already_imported is True
    assert second.changes == 1  # the marker itself, nothing else
    marker = _state(ws.state / "control.db", MARKER_KEY)
    assert (marker["version"], marker["complete"], marker["completed_at"]) == (2, True, first.first_imported_at)
    assert "allowed_requests_per_minute" in marker["ledger"]["settings"]
    third = await migrate()
    assert (third.status, third.changes) == ("already_imported", 0)
