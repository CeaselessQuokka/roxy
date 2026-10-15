"""Tests for `roxy.config.runtime` (DESIGN.md section 4, plan 5.7): the live settings snapshot and its reloads."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from typing import Any

import pytest

from roxy.config import catalog
from roxy.config.runtime import (
    CONFIG_VERSION_KEY,
    RuntimeSettings,
    SettingsSnapshot,
    build_snapshot,
    bump_config_version,
    load_runtime_settings,
    read_config_version,
    same_value,
    thaw,
    watch_config,
)
from roxy.core.clock import FakeClock
from roxy.storage.db import SharedStateUnavailable


def _override(dbs: Any, key: str, value: Any, *, bump: bool = True) -> None:
    def write(conn: sqlite3.Connection) -> None:
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value_json, updated_at, updated_by) VALUES (?, ?, 1, 'test')",
            (key, json.dumps(value)),
        )
        if bump:
            bump_config_version(conn, 1)

    dbs.control.write_sync(write)


def _bump(dbs: Any) -> int:
    return int(dbs.control.write_sync(lambda conn: bump_config_version(conn, 1)))


async def test_load_gives_every_catalog_key_at_its_default(dbs: Any, fake_clock: FakeClock) -> None:
    settings = await load_runtime_settings(dbs, fake_clock)
    snapshot = settings.snapshot()
    assert set(snapshot) == set(catalog.CATALOG)
    assert all(same_value(snapshot[key], value) for key, value in catalog.DEFAULTS.items())
    assert settings.version == 0
    assert not snapshot.overrides
    assert snapshot.loaded_at == fake_clock.now()


async def test_override_and_typed_accessors(dbs: Any) -> None:
    _override(dbs, "allowed_requests_per_minute", 25)
    _override(dbs, "cache_enabled", 0)
    settings = await load_runtime_settings(dbs)
    assert settings.version == 2
    assert settings.int("allowed_requests_per_minute") == 25
    assert settings.get("allowed_requests_per_minute") == 25
    assert settings.is_overridden("allowed_requests_per_minute")
    assert not settings.is_overridden("throttle_reset_duration")
    assert settings.bool("cache_enabled") is False
    assert settings.float("allowed_requests_per_minute") == 25.0
    assert settings.str("allowed_requests_per_minute") == "25"
    assert settings.spec("cache_enabled").key == "cache_enabled"
    assert settings.snapshot().meta["allowed_requests_per_minute"] == (1, "test")


async def test_list_values_are_immutable_in_the_snapshot(dbs: Any) -> None:
    settings = await load_runtime_settings(dbs)
    hosts = settings.get("allowed_roblox_hosts")
    assert isinstance(hosts, tuple)
    copy = settings.list("allowed_roblox_hosts")
    copy.append("evil.example")
    assert "evil.example" not in settings.get("allowed_roblox_hosts")
    with pytest.raises(TypeError):
        settings.snapshot()._values["x"] = 1  # type: ignore[index]


async def test_unknown_key_fails_loudly(dbs: Any) -> None:
    settings = await load_runtime_settings(dbs)
    with pytest.raises(KeyError):
        settings.get("no_such_setting")
    with pytest.raises(KeyError):
        settings.int("no_such_setting")


async def test_invalid_and_unknown_overrides_fall_back_to_defaults(dbs: Any) -> None:
    _override(dbs, "allowed_requests_per_minute", 10**9)  # above the catalog maximum
    _override(dbs, "gone_in_v2", 5)
    settings = await load_runtime_settings(dbs)
    assert settings.int("allowed_requests_per_minute") == catalog.DEFAULTS["allowed_requests_per_minute"]
    assert set(settings.snapshot().invalid) == {"allowed_requests_per_minute", "gone_in_v2"}


async def test_v1_key_aliases_are_accepted(dbs: Any) -> None:
    if not catalog.ALIASES:
        pytest.skip("no renamed keys in the catalog")
    old, new = next(iter(catalog.ALIASES.items()))
    spec = catalog.CATALOG[new]
    value = catalog.DEFAULTS[new]
    candidate = value + 1 if isinstance(value, int) and (spec.max is None or value + 1 <= spec.max) else value
    _override(dbs, old, candidate)
    settings = await load_runtime_settings(dbs)
    assert same_value(settings.get(new), candidate)


async def test_refresh_if_changed_reloads_and_notifies(dbs: Any) -> None:
    settings = await load_runtime_settings(dbs)
    calls: list[tuple[SettingsSnapshot, frozenset[str]]] = []
    settings.subscribe(lambda snapshot, changed: calls.append((snapshot, changed)))
    assert await settings.refresh_if_changed() is False
    _override(dbs, "allowed_requests_per_minute", 42)
    assert await settings.refresh_if_changed() is True
    assert settings.int("allowed_requests_per_minute") == 42
    assert len(calls) == 1
    assert calls[0][1] == frozenset({"allowed_requests_per_minute"})
    assert calls[0][0].version == settings.version
    assert await settings.refresh_if_changed() is False


async def test_version_bump_without_setting_change_does_not_notify(dbs: Any) -> None:
    settings = await load_runtime_settings(dbs)
    calls: list[Any] = []
    unsubscribe = settings.subscribe(lambda snapshot, changed: calls.append(changed))
    new_version = _bump(dbs)  # a rule change bumps the same counter
    assert await settings.refresh_if_changed() is True
    assert settings.version == new_version
    assert calls == []
    unsubscribe()
    _override(dbs, "allowed_requests_per_minute", 11)
    await settings.refresh_if_changed()
    assert calls == []


async def test_subscriber_errors_are_contained_and_async_subscribers_awaited(dbs: Any) -> None:
    settings = await load_runtime_settings(dbs)
    seen: list[int] = []

    def broken(snapshot: SettingsSnapshot, changed: frozenset[str]) -> None:
        raise RuntimeError("boom")

    async def async_listener(snapshot: SettingsSnapshot, changed: frozenset[str]) -> None:
        await asyncio.sleep(0)
        seen.append(snapshot.version)

    settings.subscribe(broken)
    settings.subscribe(async_listener)
    _override(dbs, "allowed_requests_per_minute", 13)
    assert await settings.refresh_if_changed() is True
    assert seen == [settings.version]


class _UnavailableDb:
    """Stands in for control.db when it cannot be read (plan C7)."""

    async def read(self, fn: Any) -> Any:
        raise SharedStateUnavailable("control", "database is locked")


async def test_unreadable_database_keeps_the_last_good_snapshot(dbs: Any) -> None:
    good = await load_runtime_settings(dbs)
    settings = RuntimeSettings(_UnavailableDb(), good.snapshot())  # type: ignore[arg-type]
    assert await settings.refresh_if_changed() is False
    assert await settings.refresh_if_changed() is False
    assert settings.snapshot() is good.snapshot()
    with pytest.raises(SharedStateUnavailable):
        await settings.reload()


async def test_watch_config_picks_up_changes_and_stops(dbs: Any) -> None:
    settings = await load_runtime_settings(dbs)
    stop = asyncio.Event()
    task = asyncio.create_task(watch_config(stop, settings, interval_s=0.02))
    _override(dbs, "allowed_requests_per_minute", 77)
    for _ in range(200):
        if settings.int("allowed_requests_per_minute") == 77:
            break
        await asyncio.sleep(0.01)
    assert settings.int("allowed_requests_per_minute") == 77
    stop.set()
    await asyncio.wait_for(task, timeout=2)


async def test_watch_config_survives_a_failing_target(dbs: Any) -> None:
    class Failing:
        calls = 0

        async def refresh_if_changed(self) -> bool:
            Failing.calls += 1
            raise RuntimeError("broken target")

    settings = await load_runtime_settings(dbs)
    stop = asyncio.Event()
    task = asyncio.create_task(watch_config(stop, Failing(), settings, interval_s=0.01))
    _override(dbs, "allowed_requests_per_minute", 66)
    for _ in range(200):
        if settings.int("allowed_requests_per_minute") == 66:
            break
        await asyncio.sleep(0.01)
    stop.set()
    await asyncio.wait_for(task, timeout=2)
    assert settings.int("allowed_requests_per_minute") == 66
    assert Failing.calls >= 1


def test_config_version_helpers(dbs: Any) -> None:
    assert dbs.control.read_sync(read_config_version) == 0
    assert dbs.control.write_sync(lambda conn: bump_config_version(conn, 5)) == 1
    assert dbs.control.write_sync(lambda conn: bump_config_version(conn, 6)) == 2
    row = dbs.control.read_sync(
        lambda conn: conn.execute(
            "SELECT value_json, updated_at FROM service_state WHERE key = ?", (CONFIG_VERSION_KEY,)
        ).fetchone()
    )
    assert json.loads(row[0]) == 2
    assert row[1] == 6


def test_config_version_missing_row_starts_at_zero(dbs: Any) -> None:
    dbs.control.write_sync(lambda conn: conn.execute("DELETE FROM service_state WHERE key = ?", (CONFIG_VERSION_KEY,)))
    assert dbs.control.read_sync(read_config_version) == 0
    assert dbs.control.write_sync(lambda conn: bump_config_version(conn, 1)) == 1


def test_build_snapshot_reads_version_and_values_together(dbs: Any) -> None:
    _override(dbs, "allowed_requests_per_minute", 30)
    snapshot = dbs.control.read_sync(lambda conn: build_snapshot(conn, 123.0))
    assert snapshot.version == 1
    assert snapshot["allowed_requests_per_minute"] == 30
    assert snapshot.overrides == {"allowed_requests_per_minute": 30}
    assert len(snapshot) == len(catalog.CATALOG)
    other = dbs.control.read_sync(lambda conn: build_snapshot(conn, 124.0))
    assert snapshot.changed_keys(other) == frozenset()


def test_thaw_and_same_value() -> None:
    assert thaw(("a", ("b",))) == ["a", ["b"]]
    assert same_value(("a", "b"), ["a", "b"])
    assert not same_value(1, 2)


# --- fix pass: multi-process review F6 --------------------------------------------------------------------------------


def _restore(dbs: Any, key: str, value: Any, version: int) -> None:
    """What restoring an older control.db snapshot does: older values AND a lower config_version."""

    def write(conn: sqlite3.Connection) -> None:
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value_json, updated_at, updated_by) VALUES (?, ?, 1, 'restore')",
            (key, json.dumps(value)),
        )
        conn.execute("UPDATE service_state SET value_json = ? WHERE key = ?", (json.dumps(version), CONFIG_VERSION_KEY))

    dbs.control.write_sync(write)


async def test_a_lower_config_version_is_applied_and_polls_settle(dbs: Any) -> None:
    key = "allowed_requests_per_minute"
    for value in (21, 22, 23, 24):
        _override(dbs, key, value)
    settings = await load_runtime_settings(dbs)
    assert (settings.version, settings.int(key)) == (4, 24)
    _restore(dbs, key, 20, version=1)
    assert await settings.refresh_if_changed() is True
    assert (settings.version, settings.int(key)) == (1, 20)
    assert await settings.refresh_if_changed() is False  # no full reload on every poll after a restore
    _override(dbs, key, 33)  # an edit after the restore (version 2) reaches the worker at once
    assert await settings.refresh_if_changed() is True
    assert (settings.version, settings.int(key)) == (2, 33)


def test_raise_config_version_never_goes_down(dbs: Any) -> None:
    from roxy.config.runtime import raise_config_version

    assert dbs.control.write_sync(lambda conn: raise_config_version(conn, 50, 1)) == 50
    assert dbs.control.write_sync(lambda conn: raise_config_version(conn, 10, 1)) == 51
    assert dbs.control.write_sync(lambda conn: bump_config_version(conn, 1)) == 52
