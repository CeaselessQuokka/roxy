"""Fixtures for the v1 migration tests (plan 19.6): fake v1 trees, workspaces and a migrator runner.

What this is
    `v1` (the builders module from `tests/fixtures/v1_trees/builders.py`, loaded by file path), `ws` (temporary
    v1 root, state, credentials and report paths) and `migrate` (runs the migrator in process with the test clock).
    Snapshot and leak-scan helpers live in `v1_migration_helpers.py` next to this file.

Why it exists
    Every migration test needs the same setup: a fake tree with runtime-generated secrets, a fresh v2 state
    directory, and the migrator run against them. Keeping it here keeps each test short.

How it works
    The builders module is loaded with `importlib` and registered in `sys.modules` (dataclasses look their module
    up there). `migrate()` calls `roxy.migration.runner.run_migration` directly, so the root conftest's socket
    guard covers the whole run.

What to read next
    `tests/fixtures/v1_trees/builders.py`, `tests/migration/v1_migration_helpers.py`, then any test file here.
"""

from __future__ import annotations

import importlib.util
import logging
import sys
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

import pytest

from roxy.core.clock import FakeClock
from roxy.core.redact import SecretRegistry
from roxy.migration.report import MigrationReport
from roxy.migration.runner import Options, run_migration

_BUILDERS = Path(__file__).resolve().parents[1] / "fixtures" / "v1_trees" / "builders.py"
_MODULE_NAME = "roxy_test_v1_tree_builders"
V1_ENVIRONMENT = ("ROXY_ROTATE_PROXY", "ROXY_ROTATE_PROXY_FILE")
"""v1 variables the migrator reads (plan 15.3 L); a developer shell may have them set, so every test clears them."""


@pytest.fixture(autouse=True)
def _no_v1_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in V1_ENVIRONMENT:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def restore_logging() -> Iterator[None]:
    """`cli.main` configures the root logger; put the level back and forget the registered secrets afterwards."""
    root = logging.getLogger()
    level = root.level
    yield
    for handler in list(root.handlers):
        if getattr(handler, "_roxy_handler", False):
            root.removeHandler(handler)
    root.setLevel(level)
    for name in SecretRegistry.names():
        if name.startswith("v1_"):
            SecretRegistry.unregister(name)


def load_builders() -> ModuleType:
    """The builders module, loaded once by file path (tests/fixtures is not a package)."""
    module = sys.modules.get(_MODULE_NAME)
    if module is not None:
        return module
    spec = importlib.util.spec_from_file_location(_MODULE_NAME, _BUILDERS)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[_MODULE_NAME] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def v1() -> ModuleType:
    """The fake v1 tree builders."""
    return load_builders()


@dataclass
class Workspace:
    """Paths of one test: the v1 copy, the v2 state and credentials directories, and the report base path."""

    root: Path
    v1: Path
    state: Path
    credentials: Path
    report: Path


@pytest.fixture
def ws(tmp_path: Path) -> Workspace:
    return Workspace(
        root=tmp_path,
        v1=tmp_path / "etc-roxy-copy",
        state=tmp_path / "state",
        credentials=tmp_path / "credentials",
        report=tmp_path / "reports" / "migration",
    )


Migrate = Callable[..., Awaitable[MigrationReport]]


@pytest.fixture
def migrate(ws: Workspace, fake_clock: FakeClock) -> Migrate:
    """Run the migrator on `ws`: `await migrate(dry_run=False, admin=False, credentials=True)` (plus the
    `--v1-state-file` and `--v1-data-file` values as `state_file` and `data_file`)."""

    async def run(
        *,
        dry_run: bool = False,
        admin: bool = False,
        credentials: bool = True,
        clock: FakeClock | None = None,
        state_file: str | None = None,
        data_file: str | None = None,
    ) -> MigrationReport:
        options = Options(
            v1_root=ws.v1,
            state_dir=ws.state,
            credentials_out=ws.credentials if credentials else None,
            dry_run=dry_run,
            import_admin_password=admin,
            v1_state_file=state_file,
            v1_data_file=data_file,
        )
        return await run_migration(options, clock=clock or fake_clock)

    return run
