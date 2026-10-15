"""Settings import (plan 18.3 rules table): changed values only, never-import keys, renames, clamps, cross rules."""

from __future__ import annotations

import json
from typing import Any

from v1_migration_helpers import by_key, rows

from roxy.config import catalog
from roxy.config.audit import Actor
from roxy.config.settings_service import SettingsService
from roxy.migration.report import ALREADY, IMPORTED, INVALID, KEPT, SKIPPED
from roxy.migration.v1_settings import V1_SETTINGS, Action, Rule, plan_settings
from roxy.storage.db import Database


def test_v1_settings_table_matches_v1(v1: Any) -> None:
    """71 settings, the v1 defaults of app/runtime.py, and every v2 target exists in the catalog."""
    assert len(V1_SETTINGS) == 71
    assert {key: meta.default for key, meta in V1_SETTINGS.items()} == v1.V1_SETTING_DEFAULTS
    for key, meta in V1_SETTINGS.items():
        assert meta.target(key) in catalog.CATALOG, key
        assert meta.minimum <= meta.default <= meta.maximum, key
        if meta.rule is Rule.NEVER:
            assert meta.why, key


def test_untouched_v1_defaults_import_nothing(v1: Any) -> None:
    """Plan 18.3 rule 1: v1 wrote every default into its file; none of them may become a v2 override."""
    decisions = plan_settings(v1.default_runtime())
    assert len(decisions) == 71
    assert not [d.v1_key for d in decisions if d.action is Action.IMPORT]


def test_plan_rules_for_single_keys(v1: Any) -> None:
    runtime = v1.default_runtime()
    v1.set_setting(runtime, "rotate_cooldown", 120)
    v1.set_setting(runtime, "two_fa_expiration", 300)
    v1.set_setting(runtime, "cache_max_body", 100)
    v1.set_setting(runtime, "cache_memory_entries", 20000)
    v1.set_setting(runtime, "cache_post_requests", 1)
    runtime["Settings"]["request_timeout"] = "abc"
    runtime["Settings"]["made_up_key"] = 5
    plans = {d.v1_key: d for d in plan_settings(runtime)}
    assert plans["rotate_cooldown"].action is Action.IMPORT
    assert (plans["rotate_cooldown"].v2_key, plans["rotate_cooldown"].value) == ("rotator_cooldown_s", 120)
    assert plans["two_fa_expiration"].action is Action.SKIP_NEVER
    assert any("you changed this in v1" in note for note in plans["two_fa_expiration"].notes)
    assert plans["cache_max_body"].action is Action.SKIP_NOT_LARGER
    assert plans["cache_memory_entries"].action is Action.IMPORT
    assert plans["cache_memory_entries"].value == 20000
    assert plans["cache_post_requests"].value == "all"
    assert any("HIGH RISK" in note for note in plans["cache_post_requests"].notes)
    assert plans["request_timeout"].action is Action.SKIP_UNREADABLE
    assert plans["made_up_key"].action is Action.SKIP_UNKNOWN


async def test_migration_out_of_range_settings(v1: Any, ws: Any, migrate: Any) -> None:
    """Out-of-range values: v1's own clamp first, then the v2 range with a report line; cross rules hold."""
    builder = v1.V1TreeBuilder(ws.v1)
    rt = builder.runtime
    v1.set_setting(rt, "email_cooldown", 30)  # v1 allowed 0; v2 minimum is 60
    v1.set_setting(rt, "rotate_cooldown", 0)  # v2 rotator_cooldown_s minimum is 5
    v1.set_setting(rt, "rotate_max_failures", 80)  # v2 maximum is 50
    v1.set_setting(rt, "allowed_requests_per_minute", 500000)  # above v1's own maximum; v1 used 100000
    v1.set_setting(rt, "request_timeout", 60)  # breaks the v2 owner deadline rule: left out
    v1.set_setting(rt, "tarpit_min_seconds", 30)  # above the (default) maximum of 20: left out
    rt["Settings"]["global_throttle_limit"] = None  # unreadable: v1 skipped it too
    builder.write()
    report = await migrate()
    settings = by_key(report.settings)

    assert settings["email_cooldown"]["status"] == IMPORTED
    assert settings["email_cooldown"]["value"] == 60
    assert any("clamped from 30 to 60" in note for note in settings["email_cooldown"]["notes"])
    assert settings["rotate_cooldown"]["value"] == 5
    assert settings["rotate_cooldown"]["v2_key"] == "rotator_cooldown_s"
    assert settings["rotate_max_failures"]["value"] == 50
    assert settings["allowed_requests_per_minute"]["value"] == 100000
    assert any("outside the v1 range" in note for note in settings["allowed_requests_per_minute"]["notes"])
    assert settings["request_timeout"]["status"] == SKIPPED
    assert any("owner deadline" in note for note in settings["request_timeout"]["notes"])
    assert settings["tarpit_min_seconds"]["status"] == SKIPPED
    assert any("must not be greater" in note for note in settings["tarpit_min_seconds"]["notes"])
    assert settings["global_throttle_limit"]["status"] == INVALID

    control = ws.state / "control.db"
    stored = {row["key"]: json.loads(row["value_json"]) for row in rows(control, "SELECT * FROM settings")}
    assert stored["email_cooldown"] == 60
    assert stored["rotator_cooldown_s"] == 5
    assert stored["rotator_max_failures"] == 50
    assert stored["allowed_requests_per_minute"] == 100000
    assert "request_timeout" not in stored
    assert "tarpit_min_seconds" not in stored
    assert "rotate_cooldown" not in stored  # renamed keys never appear under their v1 name


async def test_migration_settings_go_through_the_settings_service(v1: Any, ws: Any, migrate: Any) -> None:
    """Source `import`, actor kind `import`: history rows, audit rows and a config_version bump."""
    builder = v1.small_tree(ws.v1)
    builder.write()
    report = await migrate()
    settings = by_key(report.settings)
    imported = {s["v2_key"] for s in report.settings if s["status"] == IMPORTED}
    assert imported == {
        "allowed_requests_per_minute",
        "cache_ttl_seconds",
        "rotator_cooldown_s",
        "live_tail_buffer",
        "cache_post_requests",
    }
    assert settings["token_weight"]["status"] == SKIPPED  # meaning changed: reported, never imported
    assert settings["token_weight"]["v1_value"] == 50
    assert settings["token_weight"]["v2_default"] == 100
    assert settings["max_endpoint_records"]["status"] == SKIPPED
    assert settings["throttle_reset_duration"]["status"] == SKIPPED  # saved in v1, but equal to the v1 default

    control = ws.state / "control.db"
    written = imported | {"allowed_roblox_hosts"}  # the host union is a settings change too
    history = rows(control, "SELECT * FROM settings_history ORDER BY id")
    assert {row["key"] for row in history} == written
    assert {row["source"] for row in history} == {"import"}
    assert {row["changed_by"] for row in history} == {"import:v1"}
    audits = rows(control, "SELECT * FROM audit_log WHERE action = 'setting.update'")
    assert {row["target"] for row in audits} == {f"setting:{key}" for key in written}
    assert {row["actor"] for row in audits} == {"import:v1"}
    version = rows(control, "SELECT value_json FROM service_state WHERE key = 'config_version'")[0][0]
    assert int(version) > 0


async def test_migration_keeps_a_v2_value_changed_after_the_import(
    v1: Any, ws: Any, migrate: Any, fake_clock: Any
) -> None:
    """A rerun never undoes an admin's v2 change: the differing value is reported as kept."""
    builder = v1.small_tree(ws.v1)
    builder.write()
    await migrate()
    db = Database("control", ws.state / "control.db")
    try:
        service = SettingsService(db, clock=fake_clock)
        await service.update({"allowed_requests_per_minute": 40}, Actor("admin", "owner"), "owner raised it")
    finally:
        await db.close()
    report = await migrate()
    settings = by_key(report.settings)
    assert settings["allowed_requests_per_minute"]["status"] == KEPT
    assert settings["cache_ttl_seconds"]["status"] == ALREADY
    stored = rows(ws.state / "control.db", "SELECT value_json FROM settings WHERE key = 'allowed_requests_per_minute'")
    assert json.loads(stored[0][0]) == 40
