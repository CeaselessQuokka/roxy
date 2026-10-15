"""Lifespan wiring tests (integration pass): the pieces built by separate agents are connected at startup.

What this is
    Checks that one worker started through `create_app(env)` with development auto-migrate (a) seeds the plan 15.5
    default rows once, (b) runs the per-worker config watcher, and (c) picks up a setting written by another
    process (here: a second `SettingsService` with no link to this worker) within about a second, with the rules
    snapshot following the same `config_version`.

Why it exists
    Each module has its own unit tests, but nothing else proves the lifespan actually calls them: a missing
    watcher would leave every worker on the settings it loaded at startup, and the fleet would disagree after the
    first edit (plan 5.7, C6).

How it works
    The `app` fixture from `tests/conftest.py` gives a development app over temp databases. Writes go straight to
    control.db through `SettingsService`, the way an admin request in another worker would, and the test polls the
    worker's in-memory snapshot.

What to read next
    `roxy/lifespan.py` (`_check_schema`, `_seed_defaults`, `_start_config_watcher`) and `roxy/config/runtime.py`.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import FastAPI

from roxy.config.audit import Actor
from roxy.config.catalog import CATALOG
from roxy.config.defaults import SEED_MARKER_KEY
from roxy.config.settings_service import SettingsService

WATCH_TIMEOUT_S = 5.0  # the watcher polls every 1 s; generous for a loaded CI machine


@pytest.fixture(autouse=True)
def _restore_root_logging() -> Iterator[None]:
    """The lifespan configures logging; put the root logger back afterwards."""
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    yield
    root.handlers[:] = handlers
    root.setLevel(level)
    logging.captureWarnings(False)


async def _wait_for(predicate: Any, timeout_s: float = WATCH_TIMEOUT_S) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.05)
    return bool(predicate())


async def test_dev_auto_migrate_seeds_defaults_once(app: FastAPI) -> None:
    async with app.router.lifespan_context(app):
        ctx = app.state.ctx

        def read(conn: Any) -> tuple[Any, int, int]:
            marker = conn.execute("SELECT value_json FROM service_state WHERE key = ?", (SEED_MARKER_KEY,)).fetchone()
            paths = conn.execute("SELECT count(*) FROM ignored_paths").fetchone()[0]
            tiers = conn.execute("SELECT count(*) FROM throttle_tiers").fetchone()[0]
            return marker, int(paths), int(tiers)

        marker, paths, tiers = await ctx.dbs.control.read(read)
        assert marker is not None
        assert json.loads(marker[0])["version"] >= 1
        assert paths > 0
        assert tiers > 0
        # The rules step runs after seeding, so the first snapshot already holds the defaults.
        assert len(ctx.rules.snapshot.ignored_path_rows) == paths

    # A second start (another worker, or a restart) finds the marker and inserts nothing new.
    async with app.router.lifespan_context(app):
        ctx = app.state.ctx
        again = await ctx.dbs.control.read(read)
        assert again[1:] == (paths, tiers)


async def test_config_watcher_runs(app: FastAPI) -> None:
    async with app.router.lifespan_context(app):
        ctx = app.state.ctx
        assert "config_watcher" in ctx.startup_steps
        running = {status.name for status in ctx.tasks.status() if status.running}
        assert "config_watcher" in running
    assert all(not status.running for status in ctx.tasks.status())


async def test_setting_written_elsewhere_reaches_this_worker(app: FastAPI) -> None:
    key = "cache_ttl_seconds"
    async with app.router.lifespan_context(app):
        ctx = app.state.ctx
        before_version = ctx.settings.version
        new_value = CATALOG[key].default + 60
        # No `runtime=` link: only the worker's own watcher can make this worker see the change.
        other_worker = SettingsService(ctx.dbs.control, clock=ctx.clock)
        await other_worker.update({key: new_value}, Actor("cli", "integration-test"), "integration pass check")

        assert await _wait_for(lambda: ctx.settings.int(key) == new_value)
        assert ctx.settings.version > before_version
        assert await _wait_for(lambda: ctx.rules.snapshot.version == ctx.settings.version)
