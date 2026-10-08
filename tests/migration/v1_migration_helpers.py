"""Helpers for the v1 migration tests: file and database snapshots, row queries and leak scans.

What this is
    `tree_snapshot`, `db_snapshot`, `rows`, `all_text`, `assert_no_secret`, `load_report` and `run_cli`, imported by the
    `test_migration_*.py` modules next to this file (a plain module, because `import conftest` is ambiguous once
    several test folders have a conftest.py).

Why it exists
    Plan 19.6 asks to prove that v1 files stay untouched (hash before and after), that a second run changes
    nothing (compare every table), and that no secret reaches the report or a log line. The same helpers serve
    every test file.

How it works
    Snapshots hash file bytes and record modes; database snapshots read every table read-only in a stable order.
    `assert_no_secret` checks exact values and 24 character pieces of each credential (the window the log
    redaction also uses), case-insensitively.

What to read next
    `tests/migration/conftest.py` (the fixtures) and `tests/fixtures/v1_trees/builders.py`.
"""

from __future__ import annotations

import hashlib
import io
import json
import sqlite3
import stat
from pathlib import Path
from typing import Any

WINDOW = 24


def tree_snapshot(root: Path) -> dict[str, tuple[str, int]]:
    """Every file and directory under `root`: relative path -> (sha256 of the bytes, mode)."""
    snapshot: dict[str, tuple[str, int]] = {}
    if not root.exists():
        return snapshot
    for path in sorted(root.rglob("*")):
        relative = str(path.relative_to(root))
        mode = stat.S_IMODE(path.lstat().st_mode)
        digest = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else "dir"
        snapshot[relative] = (digest, mode)
    return snapshot


def db_snapshot(path: Path) -> dict[str, list[tuple[Any, ...]]]:
    """Every row of every table of the SQLite file at `path`, in a stable order."""
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        tables = [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
        return {table: sorted(conn.execute(f'SELECT * FROM "{table}"').fetchall(), key=repr) for table in tables}
    finally:
        conn.close()


def rows(path: Path, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
    """The rows of one read-only query against the SQLite file at `path`."""
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def all_text(path: Path) -> str:
    """Every value of every table of a database as one string (for leak scans)."""
    return repr(db_snapshot(path))


def pieces(secret: str, prefix: str) -> list[str]:
    """24 character pieces of `secret` after its public prefix (any one of them must never appear)."""
    body = secret.removeprefix(prefix)
    return [body[start : start + WINDOW] for start in range(0, max(1, len(body) - WINDOW + 1), 5)]


def assert_no_secret(text: str, values: list[str], tokens: list[str], prefix: str, where: str) -> None:
    """Fail when `text` holds any secret value or any 24 characters of a credential."""
    lowered = text.lower()
    for value in values:
        assert value not in text, f"a secret value leaked into {where}"
    for token in tokens:
        for piece in pieces(token, prefix):
            assert piece.lower() not in lowered, f"24 characters of a credential leaked into {where}"


def load_report(path: Path) -> dict[str, Any]:
    """The JSON report written next to `path` (`write_report` naming)."""
    data = json.loads(path.with_name(path.name + ".json").read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def by_key(items: list[dict[str, Any]], field: str = "v1_key") -> dict[str, dict[str, Any]]:
    return {str(item[field]): item for item in items}


def run_cli(ws: Any, *extra: str, report: Path | None = None) -> tuple[int, str, str]:
    """`cli.main` on the workspace `ws` with debug logging: (exit status, stdout, JSON log lines). Tests that call
    it use the `restore_logging` fixture, because `cli.main` configures the root logger."""
    from roxy.migration import cli

    out, logs = io.StringIO(), io.StringIO()
    argv = [
        "--v1-root",
        str(ws.v1),
        "--state-dir",
        str(ws.state),
        "--credentials-out",
        str(ws.credentials),
        "--report",
        str(report or ws.report),
        "--log-level",
        "debug",
        *extra,
    ]
    status = cli.main(argv, out=out, log_stream=logs)
    return status, out.getvalue(), logs.getvalue()
