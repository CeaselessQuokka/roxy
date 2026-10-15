"""Final review, fixer "data": the storage rules around findings constraints-5, memory-1, data-5, data-6, data-10.

What this is
    Unit tests next to the storage modules the final review's data fixer changed (`.remake/final_review/fix_data.md`):
      * `BatchWriter.register(keep_items=, keep_bytes=, weigh=)`: a kind's own bounds hold on add and on a put back
        after a failed flush, the oldest leave first, and those count in `capped`, never in `dropped` (memory-1);
      * `migrate.recover_cache_db` keeps only the newest damaged copy and `disk_history.measure_files` counts it
        (constraints-5);
      * `retention.prune_captures` with TTL 0, `prune_fingerprint_values` per header with its table safety cap, and
        `prune_recommendation_watches` (data-5, data-6, data-10).

Why it exists
    The reproductions in `tests/review_final/` pin one scenario each; these pin the edges (a kind without bounds is
    unchanged, an item larger than its kind's byte bound, the table safety cap, a watch of a kept recommendation).

How it works
    The migrated temp databases of `tests/conftest.py` (`dbs`) and plain temp folders.

What to read next
    `roxy/storage/batch.py`, `roxy/storage/migrate.py` (`recover_cache_db`), `roxy/storage/retention.py`.
"""

from __future__ import annotations

import os
import sqlite3
import types
from pathlib import Path
from typing import Any

from roxy.metrics import disk_history
from roxy.storage import migrate, retention
from roxy.storage.batch import BatchWriter
from roxy.storage.db import SharedStateUnavailable

NOW = 2_000_000_000


def _events(conn: sqlite3.Connection, items: list[Any]) -> None:
    conn.executemany("INSERT INTO events (at_ms, type, severity) VALUES (?, 'e', 'info')", [(len(i),) for i in items])


# ------------------------------------------------------------------------------------------- batch kind bounds


async def test_a_kind_keeps_its_own_bounds_on_add_and_after_a_failed_flush(dbs: Any, monkeypatch: Any) -> None:
    limits = {"items": 3, "bytes": 100}
    writer = BatchWriter(max_items=1000)
    writer.register(
        "big",
        dbs.metrics,
        _events,
        keep_items=lambda: limits["items"],
        keep_bytes=lambda: limits["bytes"],
        weigh=len,
    )
    writer.register("plain", dbs.metrics, _events)
    for n in range(5):
        writer.add("big", f"{n}" * 20)  # 20 bytes each: the count bound (3) is the one that bites
    writer.add_many("plain", ["x"] * 10)  # a kind without bounds is untouched
    stats = writer.stats()
    assert stats["kinds"]["big"]["queued"] == 3
    assert stats["kinds"]["big"]["queued_bytes"] == 60
    assert (stats["capped"], stats["dropped"]) == (2, 0)  # capped, never counted as lost numbers
    assert stats["kinds"]["plain"]["queued"] == 10
    assert not writer.add("big", "y" * 150)  # one item larger than the byte bound leaves itself (and the rest)
    assert writer.stats()["kinds"]["big"]["queued"] == 0

    async def unwritable(*_args: Any, **_kwargs: Any) -> Any:
        raise SharedStateUnavailable("metrics", "database or disk is full")

    for n in range(3):
        writer.add("big", f"{n}" * 30)
    monkeypatch.setattr(dbs.metrics, "write", unwritable)
    await writer.flush()  # put back at the front of the queue
    limits["items"] = 2  # a lower live bound applies at the put back: the oldest go
    writer.add("big", "z" * 30)
    await writer.flush()
    kinds = writer.stats()["kinds"]["big"]
    assert kinds["queued"] == 2
    assert kinds["queued_bytes"] == 60
    monkeypatch.undo()
    await writer.flush()
    rows = dbs.metrics.read_sync(lambda c: [r[0] for r in c.execute("SELECT at_ms FROM events ORDER BY id")])
    assert rows == [30, 30] + [1] * 10  # the two newest big items (kinds in registration order), then the plain ten


# ------------------------------------------------------------------------------------------- damaged cache copies


def test_only_the_newest_damaged_cache_copy_is_kept_and_counted(tmp_path: Path, monkeypatch: Any) -> None:
    cache = tmp_path / "cache.db"
    for stamp in (1_800_000_000, 1_800_003_600):
        cache.write_bytes(b"not a database " * 1000)
        monkeypatch.setattr(migrate, "time", types.SimpleNamespace(time=lambda stamp=stamp: stamp))
        moved = migrate.recover_cache_db(cache)
        assert moved is not None
    # An older set left by an earlier release (with its companions) goes too at the next recovery.
    for name in ("cache.db.corrupt-1700000000", "cache.db.corrupt-1700000000-wal", "cache.db.corrupt-1700000000-shm"):
        (tmp_path / name).write_bytes(b"x" * 100)
    cache.write_bytes(b"not a database " * 1000)
    monkeypatch.setattr(migrate, "time", types.SimpleNamespace(time=lambda: 1_800_007_200))
    assert migrate.recover_cache_db(cache) == tmp_path / "cache.db.corrupt-1800007200"
    copies = migrate.damaged_copies(cache)
    names = [path.name for path in copies]
    # Only the newest set is left (the file and any companions SQLite left); the older ones went before the rename.
    assert names[0] == "cache.db.corrupt-1800007200"
    assert all(name.startswith("cache.db.corrupt-1800007200") for name in names)
    older = ("1700000000", "1800000000", "1800003600")
    assert not any(stamp in path.name for path in tmp_path.iterdir() for stamp in older)
    measure = disk_history.measure_files(tmp_path, {"cache": cache})
    copy = measure.files["cache.db.corrupt-copy"]
    assert copy["bytes"] == sum(path.stat().st_size for path in copies)
    assert copy["bytes"] >= len(b"not a database " * 1000)
    assert measure.storage_bytes >= copy["bytes"] + os.path.getsize(cache)


# ------------------------------------------------------------------------------------------- retention


def test_capture_ttl_zero_keeps_no_capture_even_one_from_the_future(dbs: Any) -> None:
    dbs.metrics.write_sync(
        lambda conn: conn.executemany(
            "INSERT INTO captures (at, request_id, outcome, status, compressed_blob, bytes) "
            "VALUES (?, 'r', 'x', 1, ?, 1)",
            [(NOW - 10, b"a"), (NOW + 5, b"b")],  # a capture stamped a little ahead (a clock step back)
        )
    )
    policy = retention.RetentionPolicy(capture_ttl_seconds=0)
    assert dbs.metrics.write_sync(lambda conn: retention.prune_captures(conn, NOW, policy, 100)) == 2


def test_header_values_are_capped_per_header_then_by_a_table_safety_cap(dbs: Any) -> None:
    def fill(conn: sqlite3.Connection) -> None:
        for header, values in (("a", 5), ("b", 2), ("c", 4)):
            conn.executemany(
                "INSERT INTO fingerprint_values (value_hash, name, value, count, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, 0, ?)",
                [(f"{header}{i}", header, str(i), i, NOW - i) for i in range(values)],
            )

    dbs.metrics.write_sync(fill)
    per_header = retention.RetentionPolicy(max_header_value_records=3, max_header_name_records=1000)
    assert dbs.metrics.write_sync(lambda c: retention.prune_fingerprint_values(c, NOW, per_header, 100)) == 3

    def left(conn: sqlite3.Connection) -> dict[str, list[str]]:
        rows = conn.execute("SELECT name, value FROM fingerprint_values ORDER BY name, value").fetchall()
        out: dict[str, list[str]] = {}
        for name, value in rows:
            out.setdefault(str(name), []).append(str(value))
        return out

    # The most seen values of each header stay (as the writer keeps them); "b" was within the cap.
    assert dbs.metrics.read_sync(left) == {"a": ["2", "3", "4"], "b": ["0", "1"], "c": ["1", "2", "3"]}
    safety = retention.RetentionPolicy(max_header_value_records=3, max_header_name_records=2)  # at most 6 rows
    assert dbs.metrics.write_sync(lambda c: retention.prune_fingerprint_values(c, NOW, safety, 100)) == 2
    assert sum(len(v) for v in dbs.metrics.read_sync(left).values()) == 6


def test_a_watch_stays_while_its_recommendation_is_kept(dbs: Any) -> None:
    def seed(conn: sqlite3.Connection) -> None:
        conn.execute(
            "INSERT INTO recommendations (id, rule_id, fingerprint, state, severity, payload_json, created_at, "
            "updated_at) VALUES ('rec_kept', 'CACHE-TTL', 'CACHE-TTL:1', 'applied', 'info', '{}', ?, ?)",
            (NOW - 400 * 86_400, NOW - 60),
        )
        conn.executemany(
            "INSERT INTO recommendation_watches (recommendation_id, action_id, started_at, ends_at, state) "
            "VALUES (?, 1, ?, ?, 'watching')",
            [("rec_kept", NOW - 60, NOW + 1800), ("rec_gone", NOW - 400 * 86_400, NOW - 399 * 86_400)],
        )

    dbs.metrics.write_sync(seed)
    policy = retention.RetentionPolicy()
    assert dbs.metrics.write_sync(lambda c: retention.prune_recommendation_watches(c, NOW, policy, 100)) == 1
    kept = dbs.metrics.read_sync(
        lambda c: [r[0] for r in c.execute("SELECT recommendation_id FROM recommendation_watches")]
    )
    assert kept == ["rec_kept"]
