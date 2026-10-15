"""Idempotency and the dry run (plan 18.3): a second run changes nothing, a dry run writes nothing."""

from __future__ import annotations

from typing import Any

from v1_migration_helpers import db_snapshot, tree_snapshot

from roxy.migration.report import ALREADY, IMPORTED

DBS = ("control", "hot", "metrics", "cache")


def _state(ws: Any) -> dict[str, Any]:
    return {name: db_snapshot(ws.state / f"{name}.db") for name in DBS}


async def test_migration_second_run_changes_nothing(v1: Any, ws: Any, migrate: Any, fake_clock: Any) -> None:
    builder = v1.small_tree(ws.v1, token_count=2)
    builder.write()
    first = await migrate(admin=True)
    assert first.status == "imported"
    assert first.changes > 0
    databases = _state(ws)
    credentials = tree_snapshot(ws.credentials)

    fake_clock.advance(3600)  # an hour later: nothing time-dependent may sneak in (bypass expiry, timestamps)
    second = await migrate(admin=True)
    assert second.status == "already_imported"
    assert second.changes == 0
    assert second.already_imported is True
    assert second.first_imported_at == first.first_imported_at
    assert _state(ws) == databases  # every row of every table, byte for byte
    assert tree_snapshot(ws.credentials) == credentials
    counts = second.counts()
    assert IMPORTED not in counts
    assert counts[ALREADY] > 20
    assert second.admin["status"] == ALREADY
    assert second.ladder["status"] == ALREADY
    assert all(c["status"] in ("already_present", "no_source") for c in second.credentials)
    assert all(v["imported"] == 0 for k, v in second.statistics.items() if isinstance(v, dict) and "imported" in v)


async def test_migration_large_tree_second_run(v1: Any, ws: Any, migrate: Any) -> None:
    builder = v1.large_tree(ws.v1)
    builder.write()
    await migrate()
    databases = _state(ws)
    second = await migrate()
    assert second.status == "already_imported"
    assert _state(ws) == databases


async def test_migration_dry_run_writes_nothing(v1: Any, ws: Any, migrate: Any) -> None:
    """The dry run reports exactly what a real run would do, and the state and credentials directories stay
    untouched (here: they do not even come into existence)."""
    builder = v1.small_tree(ws.v1)
    builder.write()
    dry = await migrate(dry_run=True, admin=True)
    assert dry.status == "dry_run_would_change"
    assert not ws.state.exists()
    assert not ws.credentials.exists()
    real = await migrate(admin=True)
    assert real.status == "imported"
    assert dry.counts() == real.counts()
    assert [s["status"] for s in dry.settings] == [s["status"] for s in real.settings]


async def test_migration_dry_run_on_existing_state(v1: Any, ws: Any, migrate: Any) -> None:
    builder = v1.small_tree(ws.v1)
    builder.write()
    await migrate()
    files = tree_snapshot(ws.state)  # taken before this test opens the databases itself
    credentials = tree_snapshot(ws.credentials)
    dry = await migrate(dry_run=True)
    assert dry.status == "dry_run_nothing_to_do"
    assert dry.already_imported is True
    assert tree_snapshot(ws.state) == files  # same bytes; not even a -wal or -shm file appeared
    assert tree_snapshot(ws.credentials) == credentials
