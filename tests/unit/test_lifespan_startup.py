"""Startup robustness tests (fix pass): a damaged cache.db is rebuilt, and a busy database never halts gunicorn.

What this is
    Lifespan tests for spec review finding 2 (a damaged cache.db must be rebuilt at startup, not reported as a
    schema problem) and multi-process review finding F1 (a database that is only busy at startup must not make
    the worker exit with gunicorn's "failed to boot" status, which stops the whole master).

Why it exists
    Both failures only show up when a worker restarts at a bad moment (a crash or `max_requests` recycle while
    another process holds a lock, or after a power cut damaged the disposable cache file), which is exactly when
    the rest of the color must keep serving.

How it works
    Each test starts a real app lifespan over temporary databases. Locks are held by a plain sqlite3 connection
    (another process, as far as the worker can tell); busy timeouts are lowered so the tests run in seconds.

What to read next
    `roxy/lifespan.py` (`_check_cache_db`, `_retry_unavailable`) and `roxy/worker.py` (`boot_exit_code`).
"""

from __future__ import annotations

import dataclasses
import logging
import sqlite3
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from roxy import lifespan
from roxy.storage import db as dbmod
from roxy.storage.db import SharedStateUnavailable, open_databases
from roxy.storage.migrate import migrate_all


@pytest.fixture(autouse=True)
def _restore_root_logging() -> Iterator[None]:
    """The lifespan configures logging; put the root logger back afterwards."""
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    yield
    root.handlers[:] = handlers
    root.setLevel(level)
    logging.captureWarnings(False)


def _production_like_env(monkeypatch: pytest.MonkeyPatch, env_vars: dict[str, str]) -> Any:
    """EnvSettings with auto-migrate OFF (the production path), over databases migrated the way deploy.sh does."""
    from roxy.config.env import EnvSettings

    monkeypatch.setenv("ROXY_AUTO_MIGRATE", "0")
    env = EnvSettings()
    assert not env.migrate_on_start
    dbs = open_databases(env)
    try:
        migrate_all(dbs, contract=True)
    finally:
        dbs.close_all_sync()
    return env


def _damage(path: Path) -> None:
    for suffix in ("-wal", "-shm"):
        Path(f"{path}{suffix}").unlink(missing_ok=True)
    path.write_bytes(b"this is not a database file " * 512)


def _quick_check(path: Path) -> list[str]:
    conn = sqlite3.connect(str(path))
    try:
        return [str(row[0]) for row in conn.execute("PRAGMA quick_check")]
    finally:
        conn.close()


@pytest.mark.parametrize("auto_migrate", [False, True])
async def test_a_damaged_cache_db_is_rebuilt_at_startup(
    monkeypatch: pytest.MonkeyPatch, env_vars: dict[str, str], env: Any, auto_migrate: bool
) -> None:
    """Spec review 2: the schema check used to read cache.db first, refuse to start, and never rebuild it."""
    from roxy.main import create_app

    run_env = env if auto_migrate else _production_like_env(monkeypatch, env_vars)
    cache_path = Path(env_vars["ROXY_CACHE_DB"])
    if auto_migrate:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
    _damage(cache_path)
    app = create_app(run_env)
    async with app.router.lifespan_context(app):
        ctx = app.state.ctx
        assert ctx.ready
        assert await ctx.dbs.cache.read(lambda c: c.execute("SELECT count(*) FROM entries").fetchone()[0]) == 0
    assert _quick_check(cache_path) == ["ok"]
    assert list(cache_path.parent.glob("cache.db.corrupt-*"))


async def test_startup_waits_out_a_hot_db_lock(monkeypatch: pytest.MonkeyPatch, env_vars: dict[str, str]) -> None:
    """MP review F1: a lock held past busy_timeout while a worker restarts must not fail its startup."""
    from roxy.main import create_app

    env = _production_like_env(monkeypatch, env_vars)
    monkeypatch.setitem(dbmod.PROFILES, "hot", dataclasses.replace(dbmod.PROFILES["hot"], busy_timeout_ms=300))
    monkeypatch.setattr(dbmod, "BUSY_CIRCUIT_COOLDOWN_S", 0.2)
    blocker = sqlite3.connect(env_vars["ROXY_HOT_DB"], isolation_level=None, check_same_thread=False)
    blocker.execute("BEGIN IMMEDIATE")  # another process stalled inside a hot.db transaction
    releaser = threading.Timer(1.5, lambda: blocker.execute("ROLLBACK"))
    releaser.start()
    try:
        app = create_app(env)
        async with app.router.lifespan_context(app):
            assert app.state.ctx.ready
    finally:
        releaser.join(5)
        blocker.close()
    assert not lifespan.transient_startup_failure()


async def test_unavailable_shared_state_fails_as_transient(
    monkeypatch: pytest.MonkeyPatch, env_vars: dict[str, str]
) -> None:
    """MP review F1: when retries run out, the failure is marked transient so the worker does not exit with 3."""
    from roxy.config import runtime
    from roxy.main import create_app
    from roxy.worker import TRANSIENT_BOOT_EXIT_CODE, boot_exit_code

    env = _production_like_env(monkeypatch, env_vars)
    calls = {"n": 0}

    async def never_loads(*_args: Any, **_kwargs: Any) -> Any:
        calls["n"] += 1
        raise SharedStateUnavailable("control", "database is locked")

    monkeypatch.setattr(runtime, "load_runtime_settings", never_loads)
    monkeypatch.setattr(lifespan, "STARTUP_RETRY_S", 0.7)
    app = create_app(env)
    with pytest.raises(lifespan.StartupUnavailable):
        async with app.router.lifespan_context(app):
            pass
    assert calls["n"] >= 2  # retried with backoff before giving up
    assert lifespan.transient_startup_failure()
    assert boot_exit_code(3) == TRANSIENT_BOOT_EXIT_CODE
    assert boot_exit_code(0) == 0


async def test_a_too_old_schema_still_stops_the_master(
    monkeypatch: pytest.MonkeyPatch, env_vars: dict[str, str]
) -> None:
    from roxy.main import create_app
    from roxy.storage import migrate
    from roxy.worker import boot_exit_code

    env = _production_like_env(monkeypatch, env_vars)
    monkeypatch.setitem(migrate.REQUIRED_SCHEMA, "control", 99)
    app = create_app(env)
    with pytest.raises(migrate.SchemaTooOld):
        async with app.router.lifespan_context(app):
            pass
    assert not lifespan.transient_startup_failure()
    assert boot_exit_code(3) == 3  # gunicorn halts: a bad deploy must stop (plan 17.4 step 4)


def test_worker_turns_off_the_uvicorn_access_log() -> None:
    """Security review L6 (and L5): the access line would print raw paths, queries and client IPs."""
    from roxy.worker import RoxyUvicornWorker

    assert RoxyUvicornWorker.CONFIG_KWARGS["access_log"] is False
