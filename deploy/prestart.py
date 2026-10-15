"""Pre-start step of `roxy@.service`: snapshot control.db when migrations are pending, then apply expand migrations.

What this is
    The program systemd runs as `ExecStartPre=` before gunicorn, as the `roxy` user, with the release's own
    Python: `.venv/bin/python deploy/prestart.py`. It (1) checks whether any of the four databases has an expand
    migration this release ships and the database lacks, (2) if so, and control.db exists, copies control.db with
    `VACUUM INTO` to `<state dir>/snapshots/pre-migrate-<time>-<release>.db` (keeping the newest 10), (3) runs
    `python -m roxy.storage.migrate --expand`, and (4) seeds the built-in default rules into control.db the first
    time (`python -m roxy.config.defaults --seed`, a no-op once its marker exists). A failure exits non-zero, so
    the color does not start.

Why it exists
    Plan 17.4 step 3 has the deploy take a pre-migration snapshot and run the expand migrations before it starts
    the idle color. The databases belong to the `roxy` user (`/var/lib/roxy`, mode 0750, files 0640, plan 17.1),
    and the deploy user may only run `systemctl start|stop|restart|reload roxy@<color>` and two root wrappers
    through sudo (plan 9.14). A migration run as the deploy user could not write the files, and worse, would
    create SQLite's `-wal` and `-shm` files owned by the wrong user, which the service could then not open.
    Running the step inside the unit, as `roxy`, keeps every file owned correctly and needs no extra privilege.
    The order is unchanged: `deploy.sh` restarts the idle color, systemd runs this step first, and gunicorn only
    starts once the schema is current. Expand migrations never break the running (old) color (plan 5.5).
    Running it on every start is safe: with nothing pending it only reads `schema_version`, and an older release
    started after a newer one (a rollback) finds its migrations applied and does nothing.
    Contract migrations (drops and renames, plan 17.4 step 3: "one release later") are never run here. Running
    them automatically would break every kept release older than the one that shipped them, and deploy_rollback.sh
    can start any of the five kept releases. So this step only says, in the journal, which contract migrations are
    pending; the owner runs them by hand once no release that needs the old shape will run again (the command is
    in deploy/README.md, "Contract migrations").

How it works
    `roxy.storage.migrate.discover()` lists the shipped migrations and `applied_versions()` what each file has.
    The snapshot uses SQLite's `VACUUM INTO`, a consistent online copy that works while the other color writes.
    Snapshots are bounded: only the newest `KEEP_SNAPSHOTS` pre-migration files stay. Output is plain lines on
    stdout and stderr, which the journal records under `roxy-<color>`.

What to read next
    `src/roxy/storage/migrate.py` (the runner), `deploy/systemd/roxy@.service` (where this runs), then
    `deploy/deploy.sh` step 4.
"""

from __future__ import annotations

import os
import re
import sqlite3
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path

from roxy.storage.db import DB_NAMES, resolve_db_paths
from roxy.storage.migrate import applied_versions, discover
from roxy.storage.migrate import main as migrate_main


def say(text: str) -> None:
    """One line on stdout (the journal or the deploy log). A function, not print, so output is explicit."""
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


def warn(text: str) -> None:
    """One line on stderr."""
    sys.stderr.write(text + "\n")
    sys.stderr.flush()


KEEP_SNAPSHOTS = 10
"""How many pre-migration snapshots stay in `<state dir>/snapshots` (bounded storage, plan P9)."""

SNAPSHOT_PREFIX = "pre-migrate-"
_RELEASE_RE = re.compile(r"/releases/([0-9a-f]{7,40})(?:/|$)")


def release_label(cwd: Path | None = None) -> str:
    """The release this unit runs (the `<sha>` of `/opt/roxy/releases/<sha>`, shortened), or `unknown`."""
    here = (cwd or Path.cwd()).resolve().as_posix()
    match = _RELEASE_RE.search(here)
    return match.group(1)[:12] if match else "unknown"


def pending_migrations(paths: Mapping[str, Path], kind: str = "expand") -> dict[str, list[str]]:
    """Migrations of `kind` ("expand" or "contract") this release ships that each existing database has not
    applied, by database name.

    A database file that does not exist yet is left out: there is nothing to snapshot, and the migrator creates it.
    """
    pending: dict[str, list[str]] = {}
    for name in DB_NAMES:
        path = paths[name]
        if not path.exists():
            continue
        # Read only: this check must never create or change anything (as_uri() escapes odd path characters).
        conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, timeout=10)
        try:
            have = applied_versions(conn)
        finally:
            conn.close()
        missing = [m.label for m in discover(name) if m.kind == kind and m.version not in have]
        if missing:
            pending[name] = missing
    return pending


def snapshot_control(control_db: Path, snapshot_dir: Path, release: str, *, now: float | None = None) -> Path:
    """Copy control.db with `VACUUM INTO` and return the snapshot path. Keeps the newest KEEP_SNAPSHOTS copies."""
    snapshot_dir.mkdir(mode=0o750, parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(time.time() if now is None else now))
    target = snapshot_dir / f"{SNAPSHOT_PREFIX}{stamp}-{release}.db"
    counter = 1
    while target.exists():  # two starts in one second (a crash loop): never overwrite, VACUUM INTO refuses anyway
        target = snapshot_dir / f"{SNAPSHOT_PREFIX}{stamp}-{release}-{counter}.db"
        counter += 1
    conn = sqlite3.connect(str(control_db), timeout=10)
    try:
        conn.execute("PRAGMA busy_timeout = 10000")
        conn.execute("VACUUM INTO ?", (str(target),))
    finally:
        conn.close()
    os.chmod(target, 0o640)  # the same mode the service's UMask=0027 gives its own files
    prune_snapshots(snapshot_dir)
    return target


def prune_snapshots(snapshot_dir: Path, keep: int = KEEP_SNAPSHOTS) -> list[Path]:
    """Delete all but the newest `keep` pre-migration snapshots. Returns what was deleted."""
    snapshots = sorted(
        (p for p in snapshot_dir.glob(f"{SNAPSHOT_PREFIX}*.db") if p.is_file()),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    removed: list[Path] = []
    for old in snapshots[keep:]:
        old.unlink(missing_ok=True)
        removed.append(old)
    return removed


def main(argv: Sequence[str] | None = None, environ: Mapping[str, str] | None = None) -> int:
    """Snapshot (when needed) and migrate. Exit status 0 on success, 1 on any failure."""
    del argv  # no options: everything comes from the unit's environment
    env = os.environ if environ is None else environ
    state_dir, paths = resolve_db_paths(env)
    release = release_label()
    try:
        pending = pending_migrations(paths)
        contract = pending_migrations(paths, "contract")
    except sqlite3.Error as exc:
        warn(f"prestart: cannot read the schema version: {exc}")
        return 1
    if contract:
        summary = "; ".join(f"{name}: {', '.join(labels)}" for name, labels in contract.items())
        say(
            f"prestart: contract migrations pending ({summary}); they never run automatically (they would break "
            "older kept releases a rollback can start): see deploy/README.md, 'Contract migrations'"
        )
    if pending:
        summary = "; ".join(f"{name}: {', '.join(labels)}" for name, labels in pending.items())
        say(f"prestart: pending expand migrations ({summary})")
        if paths["control"].exists():
            try:
                target = snapshot_control(paths["control"], state_dir / "snapshots", release)
            except (sqlite3.Error, OSError) as exc:
                warn(f"prestart: pre-migration snapshot of control.db failed: {exc}")
                return 1
            say(f"prestart: pre-migration snapshot written to {target}")
    missing = [name for name in DB_NAMES if not paths[name].exists()]
    if missing:
        say(f"prestart: creating {', '.join(f'{name}.db' for name in missing)}")
    if not pending and not missing:
        say("prestart: schema is current; nothing to migrate")
    code = migrate_main(["--expand"])
    if code != 0:
        warn(f"prestart: migration failed (exit {code}); this color will not start")
        return 1
    # The built-in default rules (plan 15.5) are seeded by the migration step, never by workers; the seed records a
    # marker in control.db, so after the first run this only reads one row (roxy/config/defaults.py).
    from roxy.config.defaults import main as seed_main  # imported late: it loads the rule models

    try:
        seed_code = seed_main(["--seed"])
    except Exception as exc:  # any failure here must stop the start with a readable line, not a traceback only
        warn(f"prestart: seeding the built-in defaults failed: {type(exc).__name__}: {exc}")
        return 1
    if seed_code != 0:
        warn(f"prestart: seeding the built-in defaults failed (exit {seed_code})")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
