"""Fixtures for the public site unit tests: a catalog-default settings getter and metrics seeding.

What this is
    `catalog_get` (a settings getter that answers every key with its catalog default, optionally overridden) and
    `seed_rollup`, which writes dims and rollup rows into a real migrated metrics.db so the status logic reads
    genuine SQL.

Why it exists
    The public pages read settings and the metrics schema. Testing the helpers against the real catalog and the
    real schema (instead of hand-written dicts) means a renamed setting or a changed column breaks these tests,
    not the production page. Recorder calls are tested against the real `MetricsRecorder` for the same reason.

How it works
    Plain functions and small classes; the `dbs` fixture from tests/conftest.py supplies migrated databases in a
    temporary directory.

What to read next
    `roxy/public/pages.py` and `roxy/public/csp_report.py`, the code under test.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from typing import Any

import pytest

from roxy.config.catalog import CATALOG


def make_getter(**overrides: Any) -> Callable[[str], Any]:
    """A settings getter: overrides first, then the catalog default (KeyError for unknown keys, like the app)."""

    def get(key: str) -> Any:
        if key in overrides:
            return overrides[key]
        return CATALOG[key].default

    return get


@pytest.fixture
def catalog_get() -> Callable[..., Callable[[str], Any]]:
    """`catalog_get(**overrides)` builds a settings getter over the catalog defaults."""
    return make_getter


_DIM_IDS: dict[tuple[str, str], int] = {}


def seed_rollup(
    conn: sqlite3.Connection, table: str, bucket_start: int, outcome: str, reason: str, requests: int
) -> None:
    """Add `requests` to one rollup row (`rollup_minute` or `rollup_hour`) for an (outcome, reason) dimension."""
    assert table in ("rollup_minute", "rollup_hour")
    dim_hash = _DIM_IDS.setdefault((outcome, reason), 1000 + len(_DIM_IDS))
    conn.execute(
        "INSERT OR IGNORE INTO dims (dim_hash, endpoint_template, template_version, host, method, egress, outcome, "
        "reason_code, status, source, cache_state, auth_class) VALUES (?, '/v1/games', 1, 'games.roblox.com', "
        "'GET', 'direct', ?, ?, 200, 'roblox', 'MISS', 'anon')",
        (dim_hash, outcome, reason),
    )
    conn.execute(
        f"INSERT INTO {table} (bucket_start, dim_hash, requests) VALUES (?, ?, ?) "
        "ON CONFLICT (bucket_start, dim_hash) DO UPDATE SET requests = requests + excluded.requests",
        (bucket_start, dim_hash, requests),
    )


@pytest.fixture
def seed() -> Callable[..., None]:
    return seed_rollup
