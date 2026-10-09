"""Disk growth history: Roxy's storage sampled on a slow interval, so SYS-DISK and the Data page can project it.

What this is
    The measuring and writing half of the `disk_samples` and `table_size_samples` tables
    (`storage/migrations/metrics/0005_producer_history.sql`): `measure_files(state_dir, db_paths)` (the state volume's
    size and free space, and each database file with its WAL, plus the `exports` and `snapshots` folders),
    `table_bytes(conn)` (each table's bytes, indexes included, from SQLite's `dbstat` catalog),
    `rollup_rows_per_minute(conn, now_s)` (minute rollup rows written per minute in the last full hour), and
    `take_sample(dbs, ...)`, which the leader job `metrics_disk_history` runs hourly (`metrics/jobs.py
    register_producer_jobs`). The reads are in `metrics/read_producers.py`.

Why it exists
    SYS-DISK (plan 11.5) fires on "30-day projection over budget", and the Data page shows a projected size (plan
    6.6); both need history. The provider measured only the present, so there was never a projection in
    production (integrate.md "Open issues"). One sample an hour from one worker (the leader) is enough for a slope
    over days and weeks, costs a few `stat` calls and one indexed count, and keeps the table tiny.

How it works
    - Files are measured with `stat` and `statvfs` on a worker thread (never on the event loop). Roxy's storage is
      the sum of the files' bytes and WAL bytes, the same figure `insights/rules/system.py storage_bytes` compares
      with `storage_total_budget_gb`.
    - Table sizes walk every page of a database (`dbstat`), real I/O on a large metrics.db, so they are sampled
      every `TABLE_SAMPLE_INTERVAL_S` (6 h) on a short-lived maintenance connection, and only for control.db,
      hot.db and metrics.db: cache.db is one table of response bodies, and its file size says what it holds. A
      SQLite build without `dbstat` gives no table sizes (the files still count).
    - "Distinct metric rows written per minute" (SYS-DISK `dims_per_minute`) is read as the minute rollup rows of
      the last full hour divided by 60: every minute writes one row per distinct combination, which is what makes
      metrics.db grow. An indexed range count on the primary key.
    - The write is fenced by the leader lease (`JobContext.fenced_write`); the leader job `metrics_producer_prune`
      keeps `DISK_KEEP_DAYS` days and the row caps of `metrics/producers.py`.

What to read next
    `roxy/metrics/read_producers.py` (`disk_growth`, `latest_table_sizes`, `rollup_rows_avg`), then
    `roxy/insights/context.py` (`DefaultProviders.disk`, what SYS-DISK reads).
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

DISK_SAMPLE_INTERVAL_S: Final = 3600.0
"""One disk sample an hour: enough for a growth slope over days; plan 6.6 projects 30 days ahead."""
TABLE_SAMPLE_INTERVAL_S: Final = 6 * 3600.0
"""Table sizes every 6 hours: `dbstat` reads every page, so it is the expensive part of a sample."""
DISK_KEEP_DAYS: Final = 90
"""Days of disk and table samples kept (three months of growth for the Data page; the projection uses 30)."""
GROWTH_DAYS: Final = 30
"""How far back the SYS-DISK growth line reaches (the 11.5 "30-day projection")."""
MIN_GROWTH_SPAN_S: Final = 86_400
"""A growth line shorter than a day is not used: WAL files grow and shrink by the hour, and a slope from an hour
of data carried 30 days forward would be noise."""
TABLE_SIZE_DBS: Final[tuple[str, ...]] = ("control", "hot", "metrics")
"""Databases whose tables are walked (cache.db is measured by its file)."""
FOLDERS: Final[tuple[str, ...]] = ("exports", "snapshots")
"""State folders that count toward Roxy's storage (plan 6.6, 6.10)."""
MAX_FOLDER_FILES: Final = 10_000
"""Files counted per folder at most (both folders are pruned by count, age and size; this bounds one walk)."""


@dataclass(slots=True)
class FilesMeasure:
    """The state volume and Roxy's files at one moment."""

    total_bytes: int = 0
    free_bytes: int = 0
    files: dict[str, dict[str, int]] = field(default_factory=dict)  # name -> {bytes, wal_bytes}

    @property
    def storage_bytes(self) -> int:
        """Roxy's storage: every file's bytes plus its WAL (the SYS-DISK budget figure)."""
        return sum(int(v.get("bytes") or 0) + int(v.get("wal_bytes") or 0) for v in self.files.values())


def _size(path: Path) -> int:
    try:
        return int(path.stat().st_size)
    except OSError:
        return 0


def _folder_bytes(directory: Path) -> int:
    total = 0
    if not directory.is_dir():
        return 0
    for count, path in enumerate(directory.rglob("*")):
        if count >= MAX_FOLDER_FILES:
            break
        try:
            if path.is_file():
                total += int(path.stat().st_size)
        except OSError:
            continue
    return total


def measure_files(state_dir: Path | None, db_paths: Mapping[str, Path]) -> FilesMeasure:
    """Measure the state volume and Roxy's files (blocking: call it on a worker thread)."""
    measure = FilesMeasure()
    if state_dir is not None:
        try:
            stat = os.statvfs(state_dir)
            measure.total_bytes = int(stat.f_blocks * stat.f_frsize)
            measure.free_bytes = int(stat.f_bavail * stat.f_frsize)
        except OSError:
            pass
    for name, path in db_paths.items():
        file_path = Path(path)
        measure.files[f"{name}.db"] = {"bytes": _size(file_path), "wal_bytes": _size(Path(f"{file_path}-wal"))}
    if state_dir is not None:
        for folder in FOLDERS:
            directory = Path(state_dir) / folder
            if directory.is_dir():
                measure.files[folder] = {"bytes": _folder_bytes(directory), "wal_bytes": 0}
    return measure


def table_bytes(conn: sqlite3.Connection) -> dict[str, int] | None:
    """Bytes per table, its indexes added to it, from the `dbstat` virtual table (None when SQLite lacks it)."""
    owners = {
        str(row[0]): str(row[1])
        for row in conn.execute("SELECT name, tbl_name FROM sqlite_master WHERE type IN ('table', 'index')")
    }
    try:
        rows = conn.execute("SELECT name, pgsize FROM dbstat WHERE aggregate = 1").fetchall()
    except sqlite3.Error:
        return None
    out: dict[str, int] = {}
    for name, size in rows:
        owner = owners.get(str(name), str(name))
        if owner.startswith("sqlite_"):
            continue  # SQLite's own catalog and statistics tables are not Roxy data
        out[owner] = out.get(owner, 0) + int(size or 0)
    return out


def rollup_rows_per_minute(conn: sqlite3.Connection, now_s: float) -> float | None:
    """Minute rollup rows written per minute over the last full hour (None when the table is missing)."""
    end = int(now_s) // 3600 * 3600
    try:
        row = conn.execute(
            "SELECT count(*) FROM rollup_minute WHERE bucket_start >= ? AND bucket_start < ?", (end - 3600, end)
        ).fetchone()
    except sqlite3.Error:
        return None
    return round(int(row[0] or 0) / 60.0, 2)


def last_table_sample_at(conn: sqlite3.Connection) -> int | None:
    """When table sizes were last sampled (None: never)."""
    row = conn.execute("SELECT max(at) FROM table_size_samples").fetchone()
    return None if row is None or row[0] is None else int(row[0])


def write_sample(
    conn: sqlite3.Connection,
    at: int,
    measure: FilesMeasure,
    rows_per_min: float | None,
    tables: Mapping[str, Mapping[str, int]] | None,
) -> int:
    """Insert one disk sample and, when given, the table sizes `{db: {table: bytes}}`. Returns rows written."""
    conn.execute(
        "INSERT OR REPLACE INTO disk_samples (at, total_bytes, free_bytes, storage_bytes, files_json, "
        "rollup_rows_per_min) VALUES (?, ?, ?, ?, ?, ?)",
        (
            int(at),
            int(measure.total_bytes),
            int(measure.free_bytes),
            int(measure.storage_bytes),
            json.dumps(measure.files, sort_keys=True, separators=(",", ":")),
            rows_per_min,
        ),
    )
    written = 1
    for db, sizes in (tables or {}).items():
        rows = [(int(at), str(db), str(name)[:200], int(size)) for name, size in sizes.items()]
        conn.executemany(
            "INSERT OR REPLACE INTO table_size_samples (at, db, table_name, bytes) VALUES (?, ?, ?, ?)", rows
        )
        written += len(rows)
    return written


Writer = Callable[[Callable[[sqlite3.Connection], Any]], Awaitable[Any]]
"""`write(fn)`: run `fn` in a metrics.db write transaction (the leader job passes its fenced write)."""


async def take_sample(
    dbs: Any,
    *,
    now: float,
    state_dir: Path | None,
    write: Writer,
    tables_every_s: float = TABLE_SAMPLE_INTERVAL_S,
) -> dict[str, Any]:
    """Measure and store one sample (files every call, table sizes when the last table sample is old enough).

    `dbs` is the worker's `Databases`. Every measurement runs off the event loop: files and `dbstat` on worker
    threads, the counts on the read pool. Returns a short report (the job's `last_result`).
    """
    paths = {db.name: Path(db.path) for db in dbs.all()}
    folder = state_dir if state_dir is not None else Path(dbs.metrics.path).parent
    measure = await asyncio.to_thread(measure_files, folder, paths)
    rows_per_min = await dbs.metrics.read(lambda conn: rollup_rows_per_minute(conn, now))
    last = await dbs.metrics.read(last_table_sample_at)
    tables: dict[str, dict[str, int]] | None = None
    if last is None or now - last >= tables_every_s:
        tables = {}
        for name in TABLE_SIZE_DBS:
            sizes = await dbs.get(name).maintenance(table_bytes)
            if sizes is not None:
                tables[name] = sizes
    at = int(now)
    written = await write(lambda conn: write_sample(conn, at, measure, rows_per_min, tables))
    return {
        "at": at,
        "storage_bytes": measure.storage_bytes,
        "free_bytes": measure.free_bytes,
        "rollup_rows_per_min": rows_per_min,
        "tables_sampled": sorted(tables) if tables is not None else [],
        "rows": int(written or 0),
    }


__all__ = [
    "DISK_KEEP_DAYS",
    "DISK_SAMPLE_INTERVAL_S",
    "FOLDERS",
    "GROWTH_DAYS",
    "MIN_GROWTH_SPAN_S",
    "TABLE_SAMPLE_INTERVAL_S",
    "TABLE_SIZE_DBS",
    "FilesMeasure",
    "last_table_sample_at",
    "measure_files",
    "rollup_rows_per_minute",
    "table_bytes",
    "take_sample",
    "write_sample",
]
