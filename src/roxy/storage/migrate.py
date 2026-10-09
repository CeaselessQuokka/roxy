"""Numbered SQL migrations for the four databases, and the check workers run before serving.

What this is
    The runner for the files in `roxy/storage/migrations/<db>/NNNN_<name>.sql`, the `REQUIRED_SCHEMA` this
    release needs, `check_schema(dbs)` (workers call it at startup), `auto_migrate` (development only), and the
    command line tool `python -m roxy.storage.migrate --expand [--contract] [--state-dir DIR]`.

Why it exists
    Plan 5.5: migrations have exactly one owner. `deploy.sh` runs `--expand` before restarting a color, and
    workers never migrate in production; they refuse to start if the schema is older than they need. Expand
    migrations only add (tables, columns, indexes), so the previous release keeps working on the new schema
    during a blue/green deploy. Contract migrations (drops, renames) run one release later with `--contract`,
    when no running code depends on the old shape any more.

How it works
    - Each file starts with `-- kind: expand` or `-- kind: contract` (expand if missing).
    - A brand new file gets `auto_vacuum=INCREMENTAL` before anything else (plan 6.5), then a
      `schema_version(version, applied_at, name)` table.
    - Each migration runs inside one `BEGIN IMMEDIATE` transaction: the runner re-checks inside the lock that
      the version is still missing, runs every statement, records the version, and commits. Two processes
      migrating at once therefore apply each file exactly once, and a failing file leaves nothing behind.

What to read next
    `roxy/storage/migrations/control/0001_initial.sql` (conventions for every migration file), then
    `roxy/storage/db.py`.
"""

from __future__ import annotations

import argparse
import importlib.resources
import logging
import os
import re
import sqlite3
import sys
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from roxy.storage.db import (
    DB_NAMES,
    PROFILES,
    Database,
    Databases,
    connect,
    ensure_state_dir,
    resolve_db_paths,
)

log = logging.getLogger(__name__)

REQUIRED_SCHEMA: dict[str, int] = {"control": 1, "hot": 1, "metrics": 4, "cache": 1}
"""The schema version each database must be at (at least) for this release to start. Raise it in the same
change that adds a migration this release's code depends on (a unit test keeps it equal to the newest expand
migration)."""

MigrationKind = Literal["expand", "contract"]

_FILE_RE = re.compile(r"^(\d{4})_([a-z0-9_]+)\.sql$")
_KIND_RE = re.compile(r"^--\s*kind:\s*(expand|contract)\s*$", re.IGNORECASE)

_SCHEMA_VERSION_DDL = (
    "CREATE TABLE IF NOT EXISTS schema_version ("
    "version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL, name TEXT NOT NULL)"
)


class MigrationError(RuntimeError):
    """A migration file failed; its transaction was rolled back and nothing from it was applied."""


class SchemaTooOld(RuntimeError):
    """A database is older than `REQUIRED_SCHEMA`; the worker must not start (plan 5.5)."""

    def __init__(self, problems: dict[str, tuple[int, int]]) -> None:
        self.problems = problems
        details = ", ".join(f"{name}.db is at {have}, needs {need}" for name, (have, need) in problems.items())
        super().__init__(f"database schema too old ({details}); run `python -m roxy.storage.migrate --expand` first")


@dataclass(frozen=True, slots=True)
class Migration:
    """One migration file."""

    db: str
    version: int
    name: str
    kind: MigrationKind
    sql: str

    @property
    def label(self) -> str:
        return f"{self.version:04d}_{self.name}"

    def statements(self) -> list[str]:
        """Split the file into single statements (SQLite's `execute` runs one statement at a time)."""
        return split_statements(self.sql)


def split_statements(sql: str) -> list[str]:
    """Split SQL text into complete statements.

    `sqlite3.complete_statement` uses SQLite's own tokenizer, so semicolons inside strings, comments and
    trigger bodies (`BEGIN ...; END;`) do not end a statement early.
    """
    statements: list[str] = []
    buffer: list[str] = []
    for char in sql:
        buffer.append(char)
        if char == ";":
            candidate = "".join(buffer)
            if sqlite3.complete_statement(candidate):
                if _has_code(candidate):
                    statements.append(candidate.strip())
                buffer = []
    rest = "".join(buffer)
    if _has_code(rest):
        raise MigrationError(f"incomplete SQL statement at end of migration: {rest.strip()[:80]!r}")
    return statements


def _has_code(text: str) -> bool:
    """True if `text` has anything besides whitespace and `--` comments."""
    for line in text.splitlines():
        stripped = line.split("--", 1)[0].strip()
        if stripped and stripped != ";":
            return True
    return False


def discover(db_name: str) -> list[Migration]:
    """All migration files for one database, ordered by version. Versions must be unique."""
    if db_name not in DB_NAMES:
        raise ValueError(f"unknown database {db_name!r}")
    folder = importlib.resources.files("roxy.storage").joinpath("migrations", db_name)
    found: dict[int, Migration] = {}
    for entry in folder.iterdir():
        match = _FILE_RE.match(entry.name)
        if not match:
            continue
        version, name = int(match.group(1)), match.group(2)
        if version in found:
            raise MigrationError(f"{db_name}: two migrations with version {version}")
        sql = entry.read_text(encoding="utf-8")
        found[version] = Migration(db_name, version, name, _kind_of(sql), sql)
    return [found[v] for v in sorted(found)]


def _kind_of(sql: str) -> MigrationKind:
    for line in sql.splitlines():
        if not line.strip():
            continue
        if not line.lstrip().startswith("--"):
            break
        match = _KIND_RE.match(line.strip())
        if match:
            return "contract" if match.group(1).lower() == "contract" else "expand"
    return "expand"


def latest_expand_version(db_name: str) -> int:
    """The newest expand migration shipped for `db_name` (0 if none)."""
    versions = [m.version for m in discover(db_name) if m.kind == "expand"]
    return max(versions, default=0)


def applied_versions(conn: sqlite3.Connection) -> set[int]:
    """Versions recorded in `schema_version` (empty if the table does not exist yet)."""
    exists = conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_version'").fetchone()
    if exists is None:
        return set()
    return {int(row[0]) for row in conn.execute("SELECT version FROM schema_version")}


def _bootstrap(conn: sqlite3.Connection) -> None:
    """Prepare a database for migrations: incremental auto-vacuum on new files, then `schema_version`."""
    user_tables = conn.execute(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
    ).fetchone()[0]
    if user_tables == 0 and conn.execute("PRAGMA auto_vacuum").fetchone()[0] != 2:
        # The file exists but holds no tables (created without auto_vacuum by some other tool): VACUUM applies
        # the new auto_vacuum mode, and on an empty file it takes no time.
        conn.execute("PRAGMA auto_vacuum=INCREMENTAL")
        conn.execute("VACUUM")
    conn.execute(_SCHEMA_VERSION_DDL)


def apply_migrations(
    conn: sqlite3.Connection, db_name: str, *, contract: bool = False, now: float | None = None
) -> list[Migration]:
    """Apply every pending migration for `db_name` on `conn` (an autocommit connection). Returns what ran.

    Expand migrations always run; contract migrations only when `contract` is True.
    """
    _bootstrap(conn)
    ran: list[Migration] = []
    for migration in discover(db_name):
        if migration.kind == "contract" and not contract:
            continue
        conn.execute("BEGIN IMMEDIATE")
        try:
            # Re-check inside the write lock: another process may have applied it a moment ago.
            if conn.execute("SELECT 1 FROM schema_version WHERE version = ?", (migration.version,)).fetchone():
                conn.execute("ROLLBACK")
                continue
            for statement in migration.statements():
                conn.execute(statement)
            conn.execute(
                "INSERT INTO schema_version (version, applied_at, name) VALUES (?, ?, ?)",
                (migration.version, int(now if now is not None else time.time()), migration.name),
            )
            conn.execute("COMMIT")
        except BaseException as exc:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise MigrationError(f"{db_name}: migration {migration.label} failed: {exc}") from exc
        log.info(
            "migration_applied",
            extra={
                "fields": {"db": db_name, "version": migration.version, "name": migration.name, "kind": migration.kind}
            },
        )
        ran.append(migration)
    if conn.execute("PRAGMA auto_vacuum").fetchone()[0] != 2:
        log.warning("auto_vacuum_not_incremental", extra={"fields": {"db": db_name}})
    return ran


def migrate_database(db: Database, *, contract: bool = False) -> list[Migration]:
    """Apply pending migrations to one `Database` (on a short-lived maintenance connection)."""
    return db.maintenance_sync(lambda conn: apply_migrations(conn, db.name, contract=contract))


def migrate_all(
    dbs: Databases, *, contract: bool = False, names: Iterable[str] | None = None
) -> dict[str, list[Migration]]:
    """Apply pending migrations to all four databases (or only `names`), in the order control, hot, metrics,
    cache."""
    wanted = set(DB_NAMES if names is None else names)
    return {db.name: migrate_database(db, contract=contract) for db in dbs.all() if db.name in wanted}


def migrate_paths(paths: dict[str, Path], *, contract: bool = False) -> dict[str, list[Migration]]:
    """Apply pending migrations to database files by path (used by the command line tool)."""
    results: dict[str, list[Migration]] = {}
    for name in DB_NAMES:
        path = paths[name]
        ensure_state_dir(path.parent)
        conn = connect(path, PROFILES[name], "maintenance")
        try:
            results[name] = apply_migrations(conn, name, contract=contract)
        finally:
            conn.close()
    return results


def current_versions(dbs: Databases) -> dict[str, int]:
    """The highest applied version of each database (0 for an empty file)."""
    return {db.name: max(db.read_sync(applied_versions), default=0) for db in dbs.all()}


def check_schema(
    dbs: Databases, required: dict[str, int] | None = None, *, names: Iterable[str] | None = None
) -> dict[str, int]:
    """Raise `SchemaTooOld` unless every database (or each of `names`) has all expand migrations up to its
    required version.

    Workers call this at startup (plan 5.5) and exit non-zero with a clear log line when it raises. Returns the
    current version of each database checked. The lifespan checks cache.db separately, after the `cache_init`
    lease step has had the chance to rebuild a damaged file (`recover_cache_db`).
    """
    needed = REQUIRED_SCHEMA if required is None else required
    wanted = set(DB_NAMES if names is None else names)
    problems: dict[str, tuple[int, int]] = {}
    versions: dict[str, int] = {}
    for db in dbs.all():
        if db.name not in wanted:
            continue
        applied = db.read_sync(applied_versions)
        have = max(applied, default=0)
        versions[db.name] = have
        need = needed.get(db.name, 0)
        expected = {m.version for m in discover(db.name) if m.kind == "expand" and m.version <= need}
        if have < need or not expected <= applied:
            problems[db.name] = (have, need)
    if problems:
        log.error("schema_too_old", extra={"fields": {"problems": {k: list(v) for k, v in problems.items()}}})
        raise SchemaTooOld(problems)
    return versions


def _truthy(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _env_get(env: object, *names: str) -> object:
    for key in names:
        value = env.get(key) if isinstance(env, Mapping) else getattr(env, key, None)
        if value not in (None, ""):
            return value
    return None


def auto_migrate_enabled(env: object) -> bool:
    """True only when `ROXY_ENV=development` and `ROXY_AUTO_MIGRATE=1` (DESIGN.md section 0).

    Production workers never migrate (plan 5.5), whatever `ROXY_AUTO_MIGRATE` says.
    """
    mode = _env_get(env, "env", "roxy_env", "ROXY_ENV")
    flag = _env_get(env, "auto_migrate", "roxy_auto_migrate", "ROXY_AUTO_MIGRATE")
    mode_text = str(getattr(mode, "value", mode) or "").strip().lower()
    return mode_text == "development" and flag is not None and _truthy(flag)


def auto_migrate(dbs: Databases, env: object, *, names: Iterable[str] | None = None) -> bool:
    """Development convenience: apply expand and contract migrations if `auto_migrate_enabled(env)`.

    Safe with several workers starting at once (each migration is applied exactly once). Returns True when the
    migrations were run. `names` limits it to some databases (the lifespan migrates cache.db after its check).
    """
    if not auto_migrate_enabled(env):
        return False
    migrate_all(dbs, contract=True, names=names)
    return True


def recover_cache_db(path: Path | str) -> Path | None:
    """Startup check for the disposable cache.db (plan 5.5): `quick_check`, and rebuild it if damaged.

    Call it while holding the `cache_init` lease, before this worker opens cache.db. On failure the file and
    its `-wal` and `-shm` companions are renamed aside (`cache.db.corrupt-<unix time>`) and a fresh, migrated
    file takes its place. Returns the path the damaged file was moved to, or None when the file was healthy.
    """
    target = Path(path)
    if not target.exists():
        return None
    try:
        conn = connect(target, PROFILES["cache"], "maintenance")
        try:
            rows = [str(row[0]) for row in conn.execute("PRAGMA quick_check").fetchall()]
        finally:
            conn.close()
        healthy = rows == ["ok"]
    except sqlite3.DatabaseError:
        healthy = False
    if healthy:
        return None
    aside = target.with_name(f"{target.name}.corrupt-{int(time.time())}")
    for suffix in ("", "-wal", "-shm"):
        source = Path(f"{target}{suffix}")
        if source.exists():
            os.replace(source, Path(f"{aside}{suffix}"))
    conn = connect(target, PROFILES["cache"], "maintenance")
    try:
        apply_migrations(conn, "cache", contract=True)
    finally:
        conn.close()
    log.warning("cache_db_recreated", extra={"fields": {"moved_to": str(aside)}})
    return aside


# ---------------------------------------------------------------------------------------------- command line


def _paths_for_cli(state_dir: str | None) -> dict[str, Path]:
    """`--state-dir` puts all four files in that directory; otherwise use EnvSettings or the raw environment."""
    if state_dir:
        base = Path(state_dir)
        return {name: base / f"{name}.db" for name in DB_NAMES}
    env: object
    try:
        from roxy.config.env import EnvSettings  # imported lazily: config may not be importable in every tool

        env = EnvSettings()
    except Exception as exc:
        # Missing module or settings that do not validate in this shell: the raw ROXY_* variables still name
        # the database paths, which is all the migrator needs.
        log.info("migrate_env_fallback", extra={"fields": {"reason": type(exc).__name__}})
        env = dict(os.environ)
    return resolve_db_paths(env)[1]


def main(argv: Sequence[str] | None = None) -> int:
    """Command line entry point. Exit status 0 on success, 1 on a failed migration, 2 on bad arguments."""
    parser = argparse.ArgumentParser(
        prog="python -m roxy.storage.migrate",
        description="Apply Roxy database migrations. Expand migrations are backward compatible and run before a "
        "deploy; contract migrations remove old structure and run one release later.",
    )
    parser.add_argument("--expand", action="store_true", help="apply pending expand migrations")
    parser.add_argument("--contract", action="store_true", help="also apply pending contract migrations")
    parser.add_argument("--state-dir", help="directory holding control.db, hot.db, metrics.db and cache.db")
    parser.add_argument("--status", action="store_true", help="only print the current versions")
    args = parser.parse_args(argv)
    if not (args.expand or args.contract or args.status):
        parser.print_usage(sys.stderr)
        sys.stderr.write("error: give --expand (optionally with --contract) or --status\n")
        return 2
    paths = _paths_for_cli(args.state_dir)
    out = sys.stdout
    if args.status:
        for name in DB_NAMES:
            version = 0
            if paths[name].exists():
                conn = sqlite3.connect(str(paths[name]))
                try:
                    version = max(applied_versions(conn), default=0)
                finally:
                    conn.close()
            out.write(f"{name}: version {version} (this release requires {REQUIRED_SCHEMA[name]})\n")
        return 0
    try:
        results = migrate_paths(paths, contract=args.contract)
    except (MigrationError, sqlite3.Error, OSError) as exc:
        sys.stderr.write(f"migration failed: {exc}\n")
        return 1
    for name in DB_NAMES:
        ran = results.get(name, [])
        if ran:
            for migration in ran:
                out.write(f"{name}: applied {migration.label} ({migration.kind})\n")
        else:
            out.write(f"{name}: up to date\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
