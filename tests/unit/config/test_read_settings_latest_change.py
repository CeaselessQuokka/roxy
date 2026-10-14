"""Tests for `roxy.config.read_settings.latest_change_at`: when any of a few keys last changed (the User-Agent
experiment's start, review finding brain-7)."""

from __future__ import annotations

from typing import Any

from roxy.config import read_settings
from roxy.config.audit import Actor
from roxy.config.runtime import load_runtime_settings
from roxy.config.settings_service import SettingsService
from roxy.core.clock import FakeClock

ADMIN = Actor("admin", "owner", "203.0.113.9")
KEYS = ("ua_experiment_enabled", "direct_user_agent", "ua_experiment_alt_user_agent")


async def test_the_newest_change_of_any_key_and_none_without_history(dbs: Any, fake_clock: FakeClock) -> None:
    assert dbs.control.read_sync(lambda conn: read_settings.latest_change_at(conn, KEYS)) is None
    assert dbs.control.read_sync(lambda conn: read_settings.latest_change_at(conn, [])) is None
    service = SettingsService(dbs.control, runtime=await load_runtime_settings(dbs, fake_clock), clock=fake_clock)
    await service.update({"ua_experiment_enabled": 1}, ADMIN, "start the run")
    switched_on = int(fake_clock.now())
    assert dbs.control.read_sync(lambda conn: read_settings.latest_change_at(conn, KEYS)) == switched_on
    fake_clock.advance(3600)
    await service.update({"allowed_requests_per_minute": 20}, ADMIN, "not an experiment key")
    assert dbs.control.read_sync(lambda conn: read_settings.latest_change_at(conn, KEYS)) == switched_on
    fake_clock.advance(3600)
    await service.update({"ua_experiment_alt_user_agent": "Roxy/2 (+https://roxy.test)"}, ADMIN, "new identity")
    assert dbs.control.read_sync(lambda conn: read_settings.latest_change_at(conn, KEYS)) == switched_on + 7200
