"""Tests for `roxy.config.settings_service` (DESIGN.md section 4; plan 15.2, 5.7, 6.2, 9.7).

Covers the settings round trip (settings, history, audit and config_version in one transaction), validation and
cross-field errors, only-dirty-keys, history and revert, reset to default, export and import with a diff preview,
and that sensitive values never reach history or the audit log.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

import pytest

from roxy.config import audit, catalog
from roxy.config.audit import Actor
from roxy.config.runtime import RuntimeSettings, load_runtime_settings, read_config_version
from roxy.config.settings_service import (
    EXPORT_SCHEMA,
    HistoryNotFound,
    SettingsService,
    SettingsUpdateError,
    check_reason,
)
from roxy.config.spec import Group, SettingSpec, SettingType
from roxy.core.clock import FakeClock

ADMIN = Actor("admin", "owner", "203.0.113.9")
EM_DASH = chr(0x2014)


@pytest.fixture
async def runtime(dbs: Any, fake_clock: FakeClock) -> RuntimeSettings:
    return await load_runtime_settings(dbs, fake_clock)


@pytest.fixture
def service(dbs: Any, runtime: RuntimeSettings, fake_clock: FakeClock) -> SettingsService:
    return SettingsService(dbs.control, runtime=runtime, clock=fake_clock)


def _rows(dbs: Any, sql: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    return [tuple(row) for row in dbs.control.read_sync(lambda conn: conn.execute(sql, params).fetchall())]


def _version(dbs: Any) -> int:
    return int(dbs.control.read_sync(read_config_version))


async def test_update_round_trip_writes_settings_history_audit_and_version(
    dbs: Any, service: SettingsService, runtime: RuntimeSettings, fake_clock: FakeClock
) -> None:
    result = await service.update(
        {"allowed_requests_per_minute": "20"}, ADMIN, "Busy weekend", "admin", request_id="req123"
    )
    assert result.changed_keys == ("allowed_requests_per_minute",)
    change = result.changes[0]
    assert (change.old, change.new, change.overridden) == (10, 20, True)
    assert result.config_version == 1 == _version(dbs)
    now = int(fake_clock.now())
    assert _rows(dbs, "SELECT key, value_json, updated_at, updated_by FROM settings") == [
        ("allowed_requests_per_minute", "20", now, "admin:owner")
    ]
    assert _rows(dbs, "SELECT key, old_json, new_json, changed_by, reason, source FROM settings_history") == [
        ("allowed_requests_per_minute", None, "20", "admin:owner", "Busy weekend", "admin")
    ]
    audit_rows = _rows(
        dbs, "SELECT actor, actor_ip, action, target, before_json, after_json, reason, request_id FROM audit_log"
    )
    assert audit_rows == [
        (
            "admin:owner",
            "203.0.113.9",
            "setting.update",
            "setting:allowed_requests_per_minute",
            json.dumps({"overridden": False, "value": 10}, separators=(",", ":"), sort_keys=True),
            json.dumps({"overridden": True, "value": 20}, separators=(",", ":"), sort_keys=True),
            "Busy weekend",
            "req123",
        )
    ]
    assert change.history_id == 1
    assert change.audit_id == 1
    # The editing worker sees its own change at once.
    assert runtime.int("allowed_requests_per_minute") == 20
    assert runtime.version == 1


async def test_update_is_all_or_nothing(dbs: Any, service: SettingsService, monkeypatch: pytest.MonkeyPatch) -> None:
    real = audit.record
    calls = {"n": 0}

    def flaky(*args: Any, **kwargs: Any) -> int:
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("disk on fire")
        return real(*args, **kwargs)

    monkeypatch.setattr(audit, "record", flaky)
    with pytest.raises(RuntimeError):
        await service.update({"allowed_requests_per_minute": 20, "throttle_reset_duration": 60}, ADMIN, "x")
    assert _rows(dbs, "SELECT count(*) FROM settings") == [(0,)]
    assert _rows(dbs, "SELECT count(*) FROM settings_history") == [(0,)]
    assert _rows(dbs, "SELECT count(*) FROM audit_log") == [(0,)]
    assert _version(dbs) == 0


async def test_only_dirty_keys_are_written(dbs: Any, service: SettingsService) -> None:
    await service.update({"allowed_requests_per_minute": 20}, ADMIN, "first")
    result = await service.update(
        {"allowed_requests_per_minute": 20, "throttle_reset_duration": 50, "cache_ttl_seconds": 300}, ADMIN, "batch"
    )
    # 20 is unchanged and 50 is the default with no override: only cache_ttl_seconds is dirty.
    assert result.changed_keys == ("cache_ttl_seconds",)
    assert set(result.unchanged) == {"allowed_requests_per_minute", "throttle_reset_duration"}
    assert _rows(dbs, "SELECT count(*) FROM settings_history") == [(2,)]
    noop = await service.update({"allowed_requests_per_minute": 20}, ADMIN, "again")
    assert noop.changes == ()
    assert noop.config_version == _version(dbs) == 2


async def test_value_equal_to_default_removes_the_override(dbs: Any, service: SettingsService) -> None:
    await service.update({"allowed_requests_per_minute": 20}, ADMIN, "raise")
    result = await service.update({"allowed_requests_per_minute": 10}, ADMIN, "back to default")
    assert result.changes[0].overridden is False
    assert _rows(dbs, "SELECT count(*) FROM settings") == [(0,)]
    assert _rows(dbs, "SELECT old_json, new_json FROM settings_history ORDER BY id") == [(None, "20"), ("20", None)]


async def test_validation_collects_every_problem_and_writes_nothing(dbs: Any, service: SettingsService) -> None:
    with pytest.raises(SettingsUpdateError) as caught:
        await service.update({"no_such_key": 1, "allowed_requests_per_minute": 0, "cache_enabled": "maybe"}, ADMIN, "x")
    errors = caught.value.errors
    assert errors["no_such_key"] == "Unknown setting"
    assert "between 1 and 100000" in errors["allowed_requests_per_minute"]
    assert "0 or 1" in errors["cache_enabled"]
    assert _rows(dbs, "SELECT count(*) FROM settings_history") == [(0,)]
    assert _version(dbs) == 0


async def test_cross_field_rules_block_the_change(dbs: Any, service: SettingsService) -> None:
    too_high = catalog.DEFAULTS["tarpit_max_seconds"] + 1
    with pytest.raises(SettingsUpdateError) as caught:
        await service.update({"tarpit_min_seconds": too_high}, ADMIN, "x")
    assert caught.value.cross
    assert {"tarpit_min_seconds", "tarpit_max_seconds"} <= set(caught.value.cross[0].keys)
    assert _rows(dbs, "SELECT count(*) FROM settings") == [(0,)]
    # Changing both together is fine.
    result = await service.update({"tarpit_min_seconds": too_high, "tarpit_max_seconds": too_high + 5}, ADMIN, "x")
    assert set(result.changed_keys) == {"tarpit_min_seconds", "tarpit_max_seconds"}


async def test_an_old_cross_problem_never_blocks_an_unrelated_edit(dbs: Any, service: SettingsService) -> None:
    def broken(conn: sqlite3.Connection) -> None:
        conn.execute(
            "INSERT INTO settings (key, value_json, updated_at, updated_by) VALUES ('tarpit_min_seconds', '30', 0, 't')"
        )

    dbs.control.write_sync(broken)
    result = await service.update({"allowed_requests_per_minute": 12}, ADMIN, "unrelated")
    assert result.changed_keys == ("allowed_requests_per_minute",)


async def test_high_risk_values_need_a_reason(service: SettingsService) -> None:
    with pytest.raises(SettingsUpdateError) as caught:
        await service.update({"cache_enabled": 0}, ADMIN, "")
    assert "reason is required" in caught.value.errors["cache_enabled"]
    result = await service.update({"cache_enabled": 0}, ADMIN, "Debugging a stale answer")
    assert result.changed_keys == ("cache_enabled",)


async def test_reason_and_source_are_checked(service: SettingsService) -> None:
    with pytest.raises(SettingsUpdateError) as caught:
        await service.update({"allowed_requests_per_minute": 12}, ADMIN, f"faster {EM_DASH} please")
    assert "dash" in caught.value.errors["reason"]
    with pytest.raises(SettingsUpdateError) as caught:
        await service.update({"allowed_requests_per_minute": 12}, ADMIN, "x", "bogus")
    assert "source" in caught.value.errors
    result = await service.update({"allowed_requests_per_minute": 12}, ADMIN, "x", "recommendation:THROTTLE-TUNE")
    assert result.changed_keys == ("allowed_requests_per_minute",)
    assert check_reason("  ok  ") == "ok"


async def test_v1_key_names_are_accepted(dbs: Any, service: SettingsService) -> None:
    old, new = next(iter(catalog.ALIASES.items()))
    spec = catalog.CATALOG[new]
    value = catalog.DEFAULTS[new]
    target = value + 1 if isinstance(value, int) and (spec.max is None or value + 1 <= spec.max) else value - 1
    result = await service.update({old: target}, ADMIN, "imported name", "import")
    assert result.changed_keys == (new,)


async def test_history_and_revert(dbs: Any, service: SettingsService, runtime: RuntimeSettings) -> None:
    await service.update({"allowed_requests_per_minute": 20}, ADMIN, "one")
    await service.update({"allowed_requests_per_minute": 30}, ADMIN, "two")
    history = await service.history("allowed_requests_per_minute")
    assert [(entry.old, entry.new) for entry in history] == [(20, 30), (None, 20)]
    assert history[0].reason == "two"
    assert history[0].source == "admin"

    reverted = await service.revert(history[0].id, ADMIN, "too fast")
    assert runtime.int("allowed_requests_per_minute") == 20
    assert reverted.changes[0].old == 30
    assert reverted.changes[0].new == 20
    newest = (await service.history(limit=1))[0]
    assert (newest.source, newest.old, newest.new) == ("revert", 30, 20)
    assert _rows(dbs, "SELECT action FROM audit_log ORDER BY id DESC LIMIT 1") == [("setting.revert",)]

    # Reverting the very first change (from "no override") resets to the default. The value is 20 again, which is
    # what that entry set, so there is nothing to warn about.
    first = history[1]
    result = await service.revert(first.id, ADMIN, "all the way back")
    assert runtime.int("allowed_requests_per_minute") == 10
    assert not runtime.is_overridden("allowed_requests_per_minute")
    assert result.warnings == ()
    # Reverting an entry whose value was changed again since then warns.
    stale = await service.revert(history[0].id, ADMIN, "again")
    assert runtime.int("allowed_requests_per_minute") == 20
    assert stale.warnings
    assert "changed again" in stale.warnings[0]
    with pytest.raises(HistoryNotFound):
        await service.revert(9999, ADMIN, "nope")


async def test_history_paging(service: SettingsService) -> None:
    for value in (11, 12, 13, 14):
        await service.update({"allowed_requests_per_minute": value}, ADMIN, "step")
    page = await service.history(limit=2)
    assert [entry.new for entry in page] == [14, 13]
    older = await service.history(limit=2, before_id=page[-1].id)
    assert [entry.new for entry in older] == [12, 11]


async def test_reset_to_default(dbs: Any, service: SettingsService, runtime: RuntimeSettings) -> None:
    await service.update({"throttle_reset_duration": 90}, ADMIN, "slower")
    result = await service.reset_to_default("throttle_reset_duration", ADMIN, "row 124 button")
    assert result.changes[0].new == catalog.DEFAULTS["throttle_reset_duration"]
    assert runtime.int("throttle_reset_duration") == catalog.DEFAULTS["throttle_reset_duration"]
    assert _rows(dbs, "SELECT new_json FROM settings_history ORDER BY id DESC LIMIT 1") == [(None,)]
    assert _rows(dbs, "SELECT action FROM audit_log ORDER BY id DESC LIMIT 1") == [("setting.reset",)]
    again = await service.reset_to_default("throttle_reset_duration", ADMIN, "again")
    assert again.changes == ()
    with pytest.raises(SettingsUpdateError):
        await service.reset_to_default("nope", ADMIN, "x")


async def test_export_and_import_round_trip(dbs: Any, service: SettingsService, runtime: RuntimeSettings) -> None:
    await service.update({"allowed_requests_per_minute": 20, "cache_ttl_seconds": 300}, ADMIN, "tune")
    document = await service.export_overrides()
    assert document["schema"] == EXPORT_SCHEMA
    assert document["catalog_version"] == catalog.CATALOG_VERSION
    assert document["overrides"] == {"allowed_requests_per_minute": 20, "cache_ttl_seconds": 300}
    json.dumps(document)  # exportable as JSON

    await service.reset_to_default("allowed_requests_per_minute", ADMIN, "x")
    await service.update({"cache_ttl_seconds": 600, "throttle_reset_duration": 70}, ADMIN, "drift")

    preview = await service.preview_import(document)
    statuses = {item.key: item.status for item in preview.items}
    assert statuses == {"allowed_requests_per_minute": "change", "cache_ttl_seconds": "change"}
    assert preview.ok
    assert preview.catalog_version_matches
    before = _version(dbs)
    assert _version(dbs) == before  # previews write nothing

    replaced = await service.preview_import(document, replace=True)
    assert {item.key: item.status for item in replaced.items}["throttle_reset_duration"] == "reset"

    result = await service.import_overrides(document, ADMIN, "restore last week", replace=True)
    assert set(result.changed_keys) == {"allowed_requests_per_minute", "cache_ttl_seconds", "throttle_reset_duration"}
    assert runtime.snapshot().overrides == {"allowed_requests_per_minute": 20, "cache_ttl_seconds": 300}
    # History ids 1 to 5 are the edits above; the import wrote 6, 7 and 8.
    assert _rows(dbs, "SELECT DISTINCT source FROM settings_history WHERE id > 5") == [("import",)]
    assert ("settings.import",) in _rows(dbs, "SELECT DISTINCT action FROM audit_log")
    again = await service.preview_import(document)
    assert {item.status for item in again.items} == {"same"}


async def test_import_refuses_invalid_documents_entirely(dbs: Any, service: SettingsService) -> None:
    document = {
        "schema": EXPORT_SCHEMA,
        "catalog_version": "0000",
        "overrides": {"allowed_requests_per_minute": 20, "no_such_key": 1, "cache_enabled": "maybe"},
    }
    preview = await service.preview_import(document)
    statuses = {item.key: item.status for item in preview.items}
    assert statuses == {"allowed_requests_per_minute": "change", "no_such_key": "unknown", "cache_enabled": "invalid"}
    assert not preview.ok
    assert not preview.catalog_version_matches
    with pytest.raises(SettingsUpdateError) as caught:
        await service.import_overrides(document, ADMIN, "x")
    assert set(caught.value.errors) == {"no_such_key", "cache_enabled"}
    assert _rows(dbs, "SELECT count(*) FROM settings") == [(0,)]
    with pytest.raises(SettingsUpdateError):
        await service.preview_import({"schema": "something/else", "overrides": {}})
    with pytest.raises(SettingsUpdateError):
        await service.preview_import(["not", "an", "object"])
    bare = await service.preview_import({"allowed_requests_per_minute": 21})
    assert [item.status for item in bare.items] == ["change"]


async def test_import_cross_rules_are_checked(service: SettingsService) -> None:
    too_high = catalog.DEFAULTS["tarpit_max_seconds"] + 1
    preview = await service.preview_import({"overrides": {"tarpit_min_seconds": too_high}})
    assert preview.cross
    assert not preview.ok


def _secret_spec() -> SettingSpec:
    return SettingSpec(
        key="test_webhook_url",
        group=Group.ALERTS,
        label="Test webhook",
        type=SettingType.STRING,
        default="",
        description="A sensitive test value.",
        pages=("settings#alerts",),
        sensitive=True,
    )


async def test_sensitive_values_never_reach_history_or_audit(dbs: Any, fake_clock: FakeClock) -> None:
    spec = _secret_spec()
    service = SettingsService(dbs.control, clock=fake_clock, specs={spec.key: spec}, fingerprint_key=b"k" * 32)
    secret = "https://hooks.example.invalid/T000/B000/FAKEsecretVALUE123456"
    await service.update({"test_webhook_url": secret}, ADMIN, "new hook")
    await service.update({"test_webhook_url": secret + "x"}, ADMIN, "rotated hook")
    history = _rows(dbs, "SELECT old_json, new_json FROM settings_history ORDER BY id")
    audit_rows = _rows(dbs, "SELECT before_json, after_json FROM audit_log ORDER BY id")
    for text in [cell for row in history + audit_rows for cell in row if cell]:
        assert "FAKEsecretVALUE" not in text
    assert set(json.loads(history[1][1])) == {"fingerprint", "masked"}
    assert json.loads(history[0][1])["fingerprint"] != json.loads(history[1][1])["fingerprint"]
    document = await service.export_overrides()
    assert document["overrides"] == {"test_webhook_url": catalog.REDACTED}
    preview = await service.preview_import(document)
    assert [item.status for item in preview.items] == ["skipped"]
    entry = (await service.history())[0]
    with pytest.raises(SettingsUpdateError):
        await service.revert(entry.id, ADMIN, "x")
