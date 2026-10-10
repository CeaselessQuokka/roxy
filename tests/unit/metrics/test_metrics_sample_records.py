"""The sample reads return compact read-only records (finding LOAD-2).

What this is
    Unit tests for `roxy/metrics/read_history.py` `SampleRecord`, `samples_between` and `refusal_samples_between`.

Why it exists
    The insights engine read up to 50,000 request samples per read as dicts (about 1 KB a row) and kept every read of
    an evaluation until it ended, so the leader worker's memory peak grew with a day of traffic. A record is a tuple
    and a shared column index, and a read shares one string per repeated value; these tests pin that it still reads
    like the dict it replaced (`[]`, `get`, `in`, iteration, equality), keeps the column order and the time order,
    and that repeated values really are shared.

How it works
    Rows written with the recorder's own writers (`metrics/samples.py`) into a migrated metrics.db.

What to read next
    `roxy/metrics/read_history.py`, `roxy/insights/context.py` (`MAX_MEMO_SAMPLE_ROWS`).
"""

from __future__ import annotations

import sys
from typing import Any

from roxy.metrics import read_history
from roxy.metrics.read_history import SAMPLE_COLUMNS, SampleRecord
from roxy.metrics.samples import RefusalSample, SampleRow, write_refusal_samples, write_samples

TEMPLATE = "games.roblox.com/v1/games/{universeId}/votes"


def _write(dbs: Any, count: int) -> None:
    def run(conn: Any) -> None:
        write_samples(
            conn,
            [
                SampleRow(5_000 + i, f"k{i % 3}", TEMPLATE, "GET", f"c{i % 2}", None, "HIT", 200, "none", None, 10,
                          "anon", 100.0)
                for i in range(count)
            ],
        )  # fmt: skip
        write_refusal_samples(conn, [RefusalSample(5_000, "throttle", TEMPLATE, "GET", "c0", "123", 50.0)])

    dbs.metrics.write_sync(run)


def test_records_read_like_the_dicts_they_replace(dbs: Any) -> None:
    _write(dbs, 3)
    rows = dbs.metrics.read_sync(lambda conn: read_history.samples_between(conn, 5, 6))
    assert len(rows) == 3
    first = rows[0]
    assert isinstance(first, SampleRecord)
    assert first["endpoint_template"] == TEMPLATE
    assert first.get("body_hash") is None
    assert first.get("not_a_column", "fallback") == "fallback"
    assert "cache_state" in first
    assert "nope" not in first
    assert list(first) == list(SAMPLE_COLUMNS)  # the column order of the read
    assert len(first) == len(SAMPLE_COLUMNS)
    assert dict(first)["key_id"] == "k0"
    assert first == {**dict(first)}  # equal to the dict of the same row
    assert [r["at_ms"] for r in rows] == [5_000, 5_001, 5_002]  # time order
    refusals = dbs.metrics.read_sync(lambda conn: read_history.refusal_samples_between(conn, 5, 6))
    assert [(r["reason"], r["place"], r.get("sample_pct")) for r in refusals] == [("throttle", "123", 50.0)]


def test_repeated_values_are_one_shared_string(dbs: Any) -> None:
    _write(dbs, 6)
    rows = dbs.metrics.read_sync(lambda conn: read_history.samples_between(conn, 5, 6))
    assert len({id(r["endpoint_template"]) for r in rows}) == 1
    assert len({id(r["key_id"]) for r in rows}) == 3  # k0, k1, k2
    assert len({id(r["client_hash"]) for r in rows}) == 2


def test_a_record_costs_far_less_than_a_dict(dbs: Any) -> None:
    _write(dbs, 1)
    record = dbs.metrics.read_sync(lambda conn: read_history.samples_between(conn, 5, 6))[0]
    as_dict = dict(record)
    own = sys.getsizeof(record) + sys.getsizeof(record._values)
    assert own < sys.getsizeof(as_dict) / 2


def test_the_template_filter_and_the_bound_still_apply(dbs: Any, monkeypatch: Any) -> None:
    _write(dbs, 5)
    assert dbs.metrics.read_sync(lambda conn: read_history.samples_between(conn, 5, 6, ["other/{id}"])) == []
    assert len(dbs.metrics.read_sync(lambda conn: read_history.samples_between(conn, 5, 6, [TEMPLATE]))) == 5
    monkeypatch.setattr(read_history, "MAX_ROWS", 2)
    assert len(dbs.metrics.read_sync(lambda conn: read_history.samples_between(conn, 5, 6))) == 2
