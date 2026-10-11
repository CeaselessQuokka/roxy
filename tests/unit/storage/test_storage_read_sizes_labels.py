"""Every table of every database has a plain label on Data > Storage (gap G9, the g6-4 request).

What this is
    The Data page's storage table names each table with `storage/read_sizes.py TABLES` labels; a table the list lacks
    showed its raw SQL name (`admin_passkeys`, `generation`, `schema_version`). This test migrates a fresh state to
    the current schema and checks that every table of the four databases has an entry, that no entry names a table
    the schema does not have, and that the labels are plain words. The credential table's label is registered
    by `egress/credential.py` (plan C1: no other module names that table), so the test imports that module.

What to read next
    `roxy/storage/read_sizes.py`, `roxy/admin/api/data.py` (`measure_storage`).
"""

from __future__ import annotations

import sqlite3
from typing import Any

import pytest

import roxy.egress.credential  # noqa: F401 (registers the credential table's label, plan C1)
from roxy.storage import read_sizes
from roxy.storage.db import DB_NAMES
from roxy.storage.migrate import migrate_all


@pytest.fixture
def migrated(dbs: Any) -> Any:
    migrate_all(dbs)
    return dbs


def _tables(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
    return sorted(str(row[0]) for row in rows)


@pytest.mark.parametrize("db_name", DB_NAMES)
def test_every_table_of_the_schema_has_a_label(migrated: Any, db_name: str) -> None:
    found = getattr(migrated, db_name).read_sync(_tables)
    known = {meta.table: meta for meta in read_sizes.tables_of(db_name)}
    assert [table for table in found if table not in known] == []
    assert sorted(set(known) - set(found)) == []
    for table in found:
        meta = known[table]
        assert meta.label, table
        assert meta.label != table, table
        assert "_" not in meta.label, (table, meta.label)  # words, not a SQL name


def test_the_rule_tables_carry_their_fixed_caps() -> None:
    from roxy.rules.models import RULE_TABLES

    for name, spec in RULE_TABLES.items():
        meta = read_sizes.meta_for("control", name)
        assert meta is not None, name
        if name not in ("access_list", "bans"):  # bounded by other rules (an expiry, the bans cap setting)
            assert meta.fixed_cap == spec.cap, name
