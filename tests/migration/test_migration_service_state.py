"""Pause and throttle-all state with their messages (plan 18.3), in the shape the abuse checks read."""

from __future__ import annotations

import json
from typing import Any

from v1_migration_helpers import rows

from roxy.abuse.pause import PauseState
from roxy.abuse.throttle_all import ThrottleAllState
from roxy.config.audit import Actor
from roxy.migration.report import IMPORTED, KEPT
from roxy.storage.db import Database


def _state(ws: Any) -> dict[str, Any]:
    return {
        row["key"]: json.loads(row["value_json"])
        for row in rows(ws.state / "control.db", "SELECT * FROM service_state")
    }


async def test_migration_paused_v1_starts_paused(v1: Any, ws: Any, migrate: Any, fake_clock: Any) -> None:
    builder = v1.V1TreeBuilder(ws.v1)
    rt = builder.runtime
    rt.update(
        Paused=True,
        PausedSince=float(v1.V1_TIME),
        PauseReason=f"Upgrading {v1.EM} back soon",
        ThrottleAll=True,
        ThrottleAllSince=float(v1.V1_TIME + 1),
        ThrottleAllReason="",
    )
    builder.write()
    report = await migrate()
    state = _state(ws)
    pause = PauseState.from_json(state["pause"])
    assert pause.paused is True
    assert pause.active(fake_clock.now())
    assert pause.reason == "Upgrading: back soon"
    assert pause.since == float(v1.V1_TIME)
    assert pause.message(fake_clock.now()) == ("Upgrading: back soon", "custom")
    throttle_all = ThrottleAllState.from_json(state["throttle_all"])
    assert throttle_all.enabled is True
    assert throttle_all.message()[1] == "default"  # no reason: the default text, as in v1
    items = {item["key"]: item for item in report.service_state}
    assert items["pause"]["status"] == IMPORTED
    assert items["throttle_all"]["status"] == IMPORTED
    assert any("v2 will start paused" in warning for warning in report.warnings)
    audits = rows(ws.state / "control.db", "SELECT target FROM audit_log WHERE action = 'service_state.import'")
    assert {row["target"] for row in audits} == {"service_state:pause", "service_state:throttle_all"}


async def test_migration_keeps_a_pause_set_in_v2(v1: Any, ws: Any, migrate: Any, fake_clock: Any) -> None:
    """A pause the owner set in v2 before the import (say, for the cutover window) is never overwritten."""
    from roxy.abuse.pause import set_pause

    builder = v1.V1TreeBuilder(ws.v1)
    builder.runtime["PauseReason"] = "old v1 text"
    builder.write()
    await migrate(credentials=False)  # creates the databases (and imports the v1 reason)
    db = Database("control", ws.state / "control.db")
    try:
        await set_pause(db, fake_clock, Actor("admin", "owner"), paused=True, reason="cutover in progress")
    finally:
        await db.close()
    report = await migrate(credentials=False)
    items = {item["key"]: item for item in report.service_state}
    assert items["pause"]["status"] == KEPT
    assert PauseState.from_json(_state(ws)["pause"]).reason == "cutover in progress"
