"""No function passed to `Database.write` may end the transaction it runs in (the write contract, DESIGN.md section 2).

What this is
    A static scan of `src/roxy`: outside `storage/db.py` (which owns BEGIN, COMMIT, ROLLBACK and the group savepoint)
    and `storage/migrate.py` (which runs on its own autocommit connection), no code runs BEGIN, COMMIT, END or a
    plain ROLLBACK, calls `commit()`, `rollback()` or `executescript()` (which commits first), or names the group
    savepoint; and no SQL anywhere, migrations included, uses the ROLLBACK conflict resolution (`INSERT OR ROLLBACK`,
    `ON CONFLICT ROLLBACK`, `RAISE(ROLLBACK, ...)`), which would roll back a whole transaction from one statement.

Why it exists
    Group commit (finding LOAD-3) runs several callers' writes in one transaction, each in a savepoint. A write that
    ended the transaction would commit or roll back the other callers' writes. `roxy.storage.db` detects it and never
    reports such a group as done (`JobEndedTransaction`), but after a COMMIT that is a false failure; this scan keeps
    it from happening at all. Savepoints of a write's own (`upstream/buckets.py`) nest safely and stay allowed.

How it works
    Regular expressions over every Python and SQL file under `src/roxy`, reporting file and line.

What to read next
    `roxy/storage/db.py` (`_ConnectionThread._run_group`), `test_storage_db_group_faults.py`.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] / "src" / "roxy"
OWNERS = {ROOT / "storage" / "db.py", ROOT / "storage" / "migrate.py"}
"""The two modules that may control transactions themselves."""

ENDS_TRANSACTION = re.compile(
    r"""\.execute\(\s*f?["']\s*(BEGIN|COMMIT|END|ROLLBACK(?!\s+TO\b))\b"""
    r"""|\.(commit|rollback|executescript)\("""
    r"""|roxy_group_write""",
    re.IGNORECASE,
)
ROLLBACK_CONFLICT = re.compile(
    r"\b(INSERT|UPDATE)\s+OR\s+ROLLBACK\b|\bON\s+CONFLICT\s+ROLLBACK\b|\bRAISE\s*\(\s*ROLLBACK\b",
    re.IGNORECASE,
)


def _hits(pattern: re.Pattern[str], paths: list[Path]) -> list[str]:
    found = []
    for path in paths:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if pattern.search(line):
                found.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()}")
    return found


def test_the_scan_finds_what_it_looks_for() -> None:
    for line in (
        'conn.execute("COMMIT")',
        "conn.execute('rollback')",
        'conn.execute(f"END")',
        "conn.commit()",
        "conn.executescript(sql)",
        'conn.execute("RELEASE roxy_group_write")',
    ):
        assert ENDS_TRANSACTION.search(line), line
    for line in ('conn.execute("ROLLBACK TO upstream_reserve")', 'conn.execute("SAVEPOINT upstream_reserve")'):
        assert not ENDS_TRANSACTION.search(line), line
    assert ROLLBACK_CONFLICT.search("INSERT OR ROLLBACK INTO t VALUES (1)")
    assert ROLLBACK_CONFLICT.search("SELECT RAISE(ROLLBACK, 'no')")
    assert not ROLLBACK_CONFLICT.search("ROLLBACK TO x")


def test_no_write_function_ends_its_transaction() -> None:
    python = sorted(p for p in ROOT.rglob("*.py") if p not in OWNERS)
    assert len(python) > 100  # the scan really covers the package
    assert _hits(ENDS_TRANSACTION, python) == []


def test_no_sql_rolls_back_a_whole_transaction_from_one_statement() -> None:
    files = sorted([*ROOT.rglob("*.py"), *ROOT.rglob("*.sql")])
    assert any(p.suffix == ".sql" for p in files)
    assert _hits(ROLLBACK_CONFLICT, files) == []
