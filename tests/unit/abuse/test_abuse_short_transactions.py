"""The hot.db transactions of the abuse layer run few SQL statements (finding LOAD-3).

What this is
    Statement counts (`sqlite3.Connection.set_trace_callback`) of the spam flush and the limiter and strike writes,
    and checks that the batched forms write exactly what the per-row forms wrote.

Why it exists
    Every SQLite call made inside a write transaction gives up the GIL and may wait for the worker's event loop to
    hand it back, while hot.db's one write lock (shared by every worker) stays taken. The spam flush made two
    statements per subject (hundreds a second under load, holding the lock up to 200 ms), and the abuse transaction
    one upsert per limiter row. Now a flush reads every subject in one statement per 500 and writes them in one per
    300, and limiter and strike rows are written with one statement per 150.

How it works
    The writer's own connection traced while a write runs; counts are bounded by the chunk sizes, never by the
    number of subjects or rows.

What to read next
    `roxy/abuse/spam.py` (`_read_windows`, `_write_windows`), `roxy/abuse/limiter.py` (`save_rows`),
    `roxy/abuse/throttle.py` (`save_strike_rows`), `roxy/storage/db.py` (module docstring, LOAD-3).
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from abuse_support import FakeSettings

from roxy.abuse import spam as spam_mod
from roxy.abuse.limiter import SAVE_CHUNK, LimiterRow, load_rows, save_rows
from roxy.abuse.spam import SpamDetectors
from roxy.abuse.throttle import StrikeRow, load_strike_rows, save_strike_rows
from roxy.core.clock import FakeClock


def _traced(conn: sqlite3.Connection, statements: list[str]) -> None:
    conn.set_trace_callback(lambda sql: statements.append(sql.split(None, 1)[0].upper()))


def _observe(spam: SpamDetectors, ip: str) -> None:
    spam.observe(
        limit_key=ip, place_id=None, template="games.roblox.com/v1/games", path="/v1/games", query=[],
        user_agent="Roblox/Linux", refused=False, probe=False, auth=False, game_server=False, bypass=False,
    )  # fmt: skip


async def test_a_flush_of_many_subjects_runs_a_few_statements(dbs: Any) -> None:
    clock = FakeClock(1_760_000_400)
    spam = SpamDetectors(FakeSettings({}), dbs.hot, clock)
    for index in range(700):  # 700 clients: a "req" and a "bust" subject each, 1,400 subjects
        _observe(spam, f"198.51.100.{index % 250}:{index}")
    subjects = spam.pending_subjects()
    assert subjects >= 1400
    batch, spam._pending = spam._pending, {}
    statements: list[str] = []

    def run(conn: sqlite3.Connection) -> Any:
        _traced(conn, statements)
        try:
            return spam._flush_tx(conn, batch, spam._values(), int(clock.now()))
        finally:
            conn.set_trace_callback(None)

    await dbs.hot.write(run)
    reads = statements.count("SELECT")
    writes = statements.count("INSERT")
    assert writes == -(-subjects // spam_mod.FLUSH_WRITE_CHUNK)  # 1,400 subjects: 5 statements, not 1,400
    assert reads <= -(-subjects // spam_mod.FLUSH_READ_CHUNK) + 4  # the batched read, the eviction and flag reads
    stored = dbs.hot.read_sync(lambda c: c.execute("SELECT count(*) FROM spam_windows").fetchone()[0])
    assert stored == subjects


async def test_the_batched_flush_merges_into_stored_rows_like_before(dbs: Any) -> None:
    """A second flush of the same subjects adds to the stored counts (read, merge, write back)."""
    clock = FakeClock(1_760_000_400)
    spam = SpamDetectors(FakeSettings({}), dbs.hot, clock)
    for _ in range(3):
        _observe(spam, "203.0.113.7")
    await spam.flush()
    for _ in range(2):
        _observe(spam, "203.0.113.7")
    await spam.flush()
    raw = dbs.hot.read_sync(
        lambda c: c.execute("SELECT buckets_json FROM spam_windows WHERE subject = 'req|ip:203.0.113.7'").fetchone()
    )
    counts = json.loads(raw[0])["c"]
    assert sum(int(v) for v in counts.values()) == 5


def test_limiter_and_strike_rows_are_written_in_chunks(dbs: Any) -> None:
    rows = [LimiterRow(f"ip:198.51.100.{i}", 1000 + i, 7, i, True) for i in range(SAVE_CHUNK + 5)]
    rows.append(LimiterRow("ip:198.51.100.0", 9999, 8, 42, True))  # the same key again: the last values win
    strikes = [StrikeRow(f"ip:198.51.100.{i}", 1, 100, 0, 0, True) for i in range(3)]
    statements: list[str] = []

    def write(conn: sqlite3.Connection) -> None:
        _traced(conn, statements)
        try:
            save_rows(conn, rows, 123)
            save_strike_rows(conn, strikes)
        finally:
            conn.set_trace_callback(None)

    dbs.hot.write_sync(write)
    assert statements.count("INSERT") == 3  # two limiter chunks and one strike statement, not 159 statements
    loaded = dbs.hot.read_sync(lambda c: load_rows(c, [r.key for r in rows]))
    assert loaded["ip:198.51.100.0"].tat_ms == 9999
    assert loaded["ip:198.51.100.0"].count == 42
    assert loaded[f"ip:198.51.100.{SAVE_CHUNK + 4}"].tat_ms == 1000 + SAVE_CHUNK + 4
    saved = dbs.hot.read_sync(lambda c: load_strike_rows(c, [s.key for s in strikes]))
    assert all(row.exists and row.strikes == 1 for row in saved.values())
    dbs.hot.write_sync(lambda conn: save_rows(conn, [], 1))  # nothing to write: no statement, no error
