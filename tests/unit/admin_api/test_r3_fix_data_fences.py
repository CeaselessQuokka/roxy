"""Review round 3 fixes of the Data area (group admin_data): the recorder's reset fences and the storage read model.

What this is
    Unit tests, no app: `metrics/recorder.py` `FenceSelector` and `ResetFences` (finding parity-4: a data reset must
    not be refilled by counts a worker gathered before it but had not flushed), the key column map the fences use
    (pinned against the INSERT statements it mirrors), and `storage/read_sizes.py` (finding parity-10 and the
    producers lane: limits the code sets without a setting, idle limits, minimum ages, and the copies of constants
    from packages the storage layer does not import).

Why it exists
    The fence decides which unflushed items every worker drops or rewrites after a reset; a wrong rule either brings
    deleted numbers back or loses numbers nobody reset. The batch rule (the first batch that sees a fence and the
    one after it) is what makes it exact with any number of workers (C6), so it is tested batch by batch here.

How it works
    `ResetFences` takes a `read` callable (the control.db key's text in production); the tests hand it a string, a
    clock and items built like the recorder's own (`RollupDelta`, `EventRecord`, `ProducerItem`, ...).

What to read next
    `roxy/metrics/recorder.py` (the reset fences section), `roxy/admin/api/data.py` (`fence_selectors`,
    `fence_pending_counts`), `tests/integration/admin_api/test_r3_fix_data.py` (the same through the running app).
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from roxy.core.clock import FakeClock
from roxy.metrics import producers, recorder
from roxy.metrics.producers import ProducerItem
from roxy.metrics.recorder import (
    CLEARED_CACHE_STATE,
    FENCE_START_MARGIN_MS,
    FENCED_TABLES,
    MAX_RESET_FENCES,
    EventRecord,
    FenceSelector,
    HistoryItem,
    ResetFences,
    dims_hash,
)
from roxy.metrics.rollups import DIM_COLUMNS, ClientDelta, RollupDelta
from roxy.storage import read_sizes


def rollup(*, cache_state: str = "MISS", source: str = "roblox", template: str = "games.roblox.com/v1/games") -> Any:
    values = {
        "endpoint_template": template,
        "template_version": 1,
        "host": "games.roblox.com",
        "method": "GET",
        "egress": "direct",
        "outcome": "served_upstream",
        "reason_code": "upstream_ok",
        "status": 200,
        "source": source,
        "cache_state": cache_state,
        "auth_class": "anon",
    }
    dims = tuple(values[name] for name in DIM_COLUMNS)
    return RollupDelta(
        bucket_start=1_760_000_040,
        dim_hash=dims_hash(dims),
        dims=dims,
        requests=3,
        latency_hist=b"\x01",
        queue_wait_hist=b"\x02",
    )


def event(event_type: str, at_ms: int = 1_760_000_000_000, **fields: Any) -> EventRecord:
    base: dict[str, Any] = {"severity": "info", "reason_code": None, "ip_hash": None, "place": None}
    base.update(fields)
    return EventRecord(at_ms=at_ms, type=event_type, endpoint_template=None, detail={}, **base)


def fence_doc(*fences: tuple[int, int, list[dict[str, Any]]]) -> str:
    return json.dumps(
        {
            "seq": max((seq for seq, _at, _s in fences), default=0),
            "fences": [{"seq": seq, "at_ms": at, "selectors": sel} for seq, at, sel in fences],
        }
    )


class Key:
    """The control.db key as a mutable string the fences read (production reads it inside each flush)."""

    def __init__(self) -> None:
        self.text: str | None = None
        self.fail = False

    def __call__(self) -> str | None:
        if self.fail:
            raise sqlite3.OperationalError("database is locked")
        return self.text


def fences_at(clock: FakeClock) -> tuple[ResetFences, Key]:
    key = Key()
    return ResetFences(key, clock), key


# ================================================================================================ selectors


def test_a_selector_parses_only_known_tables_actions_and_ranges() -> None:
    assert FenceSelector.parse({"table": "rollup_minute"}) == FenceSelector("rollup_minute")
    assert FenceSelector.parse({"table": "rollup_hour"}) is None  # the recorder never writes it
    assert FenceSelector.parse({"table": "events", "action": "drop_table"}) is None
    assert FenceSelector.parse({"table": "events", "match": {"type": []}}) is None  # would match nothing
    assert FenceSelector.parse({"table": "events", "range": [1, "x"]}) is None
    parsed = FenceSelector.parse({"table": "events", "match": {"type": ["login"]}, "range": [10, 20]})
    assert parsed == FenceSelector("events", "delete", (("type", frozenset({"login"})),), 10, 20)
    assert {"rollup_minute", "events", "client_score_hour", "tarpit_minute", "rule_hit_minute"} <= FENCED_TABLES


def test_a_selector_matches_columns_and_ranges_and_acts() -> None:
    now = 1_760_000_100
    login = FenceSelector.parse({"table": "events", "match": {"type": ["login"]}})
    assert login is not None
    assert login.covers("events", event("login"), now)
    assert not login.covers("events", event("probe"), now)
    assert not login.covers("rollup_minute", rollup(), now)
    past = FenceSelector.parse({"table": "events", "range": [0, 1_000]})
    assert past is not None
    assert not past.covers("events", event("login"), now)
    status = FenceSelector.parse({"table": "rollup_minute", "match": {"status": [200]}})  # JSON ints and str
    assert status is not None
    assert status.covers("rollup_minute", rollup(), now)
    latency = FenceSelector("rollup_minute", "clear_latency")
    kept = latency.act(rollup())
    assert (kept.requests, kept.latency_hist, kept.queue_wait_hist) == (3, None, None)
    cache = FenceSelector("rollup_minute", "clear_cache_state", (("cache_state", frozenset({"HIT", "MISS"})),))
    moved = cache.act(rollup(cache_state="HIT"))
    assert moved.dims[DIM_COLUMNS.index("cache_state")] == CLEARED_CACHE_STATE
    assert moved.dim_hash == dims_hash(moved.dims) != rollup(cache_state="HIT").dim_hash
    assert (moved.requests, moved.latency_hist) == (3, b"\x01")
    assert FenceSelector("events").act(event("login")) is None
    assert FenceSelector("events", "clear_latency").act(event("login")) is not None  # rollups only


def test_producer_and_history_items_match_by_key_column() -> None:
    now = 1_760_000_100
    one = FenceSelector.parse({"table": "client_score_hour", "match": {"client_key": ["203.0.113.5"]}})
    assert one is not None
    assert one.covers("client_score_hour", ProducerItem("client_score_hour", (1_760_000_000, "203.0.113.5"), (1,)), now)
    assert not one.covers(
        "client_score_hour", ProducerItem("client_score_hour", (1_760_000_000, "198.51.100.7"), (1,)), now
    )
    ranged = FenceSelector.parse({"table": "error_minute", "range": [1_760_000_000, 1_760_000_060]})
    assert ranged is not None
    assert ranged.covers("error_minute", HistoryItem("error_minute", ("sig", 1_760_000_040), (1,)), now)
    assert not ranged.covers("error_minute", HistoryItem("error_minute", ("sig", 1_759_000_000), (1,)), now)


def test_a_client_reset_fences_the_pairs_it_is_part_of() -> None:
    now = 1_760_000_100
    by_ip = FenceSelector.parse({"table": "client_minute", "match": {"client_type": ["pair"], "pair_ip": ["10.0.0.1"]}})
    by_place = FenceSelector.parse({"table": "client_minute", "match": {"client_type": ["pair"], "pair_place": ["9"]}})
    assert by_ip is not None
    assert by_place is not None
    mine = ClientDelta(now, "pair", "10.0.0.1|9", 1)
    other = ClientDelta(now, "pair", "10.0.0.2|8", 1)
    plain = ClientDelta(now, "ip", "10.0.0.1", 1)
    assert [by_ip.covers("client_minute", d, now) for d in (mine, other, plain)] == [True, False, False]
    assert [by_place.covers("client_minute", d, now) for d in (mine, other, plain)] == [True, False, False]


def test_key_columns_are_the_first_columns_of_each_insert() -> None:
    statements = {**recorder._HISTORY_SQL, **producers._SQL}
    for table, columns in recorder._HISTORY_KEY_COLUMNS.items():
        found = re.search(rf"INSERT INTO {table} \(([^)]*)\)", statements[table])
        assert found is not None, table
        listed = [name.strip() for name in found.group(1).split(",")]
        assert listed[: len(columns)] == list(columns), table


# ================================================================================================ the batch rule


def test_a_fence_covers_the_batch_that_first_sees_it_and_the_next_one() -> None:
    clock = FakeClock()
    fences, key = fences_at(clock)
    fences.drained()  # batch 1
    first = [rollup()]
    fences.apply(first)  # first look: no fence yet
    assert len(first) == 1
    key.text = fence_doc((1, clock.now_ms(), [{"table": "rollup_minute"}]))
    fences.drained()  # batch 2 gathered before this worker could know of the reset
    batch = [rollup(), event("login")]
    fences.apply(batch)
    assert [type(item).__name__ for item in batch] == ["EventRecord"]
    fences.drained()  # batch 3 started before the fence was seen: still covered
    later = [rollup()]
    fences.apply(later)
    assert later == []
    fences.drained()  # batch 4 began after the fence was seen: kept
    kept = [rollup()]
    fences.apply(kept)
    assert len(kept) == 1
    assert fences.stats()["changed"] == 2


def test_the_worker_that_wrote_a_fence_keeps_what_it_counts_after_its_flush() -> None:
    clock = FakeClock()
    fences, key = fences_at(clock)
    fences.drained()
    fences.apply([event("probe")])  # first look done (nothing)
    key.text = fence_doc((1, clock.now_ms(), [{"table": "rollup_minute"}]))
    fences.note_local(1)
    fences.drained()  # the reset's own flush: gathered before the reset
    before = [rollup()]
    fences.apply(before)
    assert before == []
    fences.drained()  # counted after that flush: kept at once
    after = [rollup()]
    fences.apply(after)
    assert len(after) == 1


def test_a_worker_started_after_a_fence_ignores_it_and_a_young_one_applies_it() -> None:
    clock = FakeClock()
    old = fence_doc((3, clock.now_ms() - FENCE_START_MARGIN_MS - 1, [{"table": "rollup_minute"}]))
    fences, key = fences_at(clock)
    key.text = old
    fences.drained()
    items = [rollup()]
    fences.apply(items)
    assert len(items) == 1
    recent, recent_key = fences_at(clock)
    recent_key.text = fence_doc((3, clock.now_ms() - 1000, [{"table": "rollup_minute"}]))
    recent.drained()
    items = [rollup()]
    recent.apply(items)
    assert items == []  # within the margin of its start: it may hold counts from before the reset


def test_fences_pushed_out_of_the_key_cover_everything() -> None:
    clock = FakeClock()
    fences, key = fences_at(clock)
    key.text = fence_doc((1, clock.now_ms(), [{"table": "events", "match": {"type": ["visit"]}}]))
    fences.drained()
    fences.apply([event("probe")])
    newer = [(seq, clock.now_ms(), [{"table": "events", "match": {"type": ["visit"]}}]) for seq in range(5, 5 + 16)]
    key.text = fence_doc(*newer)  # fences 2 to 4 were never seen
    fences.drained()
    batch = [rollup(), event("probe")]
    fences.apply(batch)
    assert batch == []


def test_a_fence_key_that_cannot_be_read_keeps_the_known_fences() -> None:
    clock = FakeClock()
    fences, key = fences_at(clock)
    fences.drained()
    fences.apply([event("probe")])
    key.text = fence_doc((1, clock.now_ms(), [{"table": "events"}]))
    fences.drained()
    first = [event("probe")]
    fences.apply(first)
    assert first == []
    key.fail = True
    fences.drained()
    second = [event("probe")]
    fences.apply(second)  # still inside the fence's two batches: dropped although the key could not be read
    assert second == []
    assert fences.stats()["read_errors"] == 1
    fences.drained()
    third = [event("probe")]
    fences.apply(third)
    assert len(third) == 1


def test_a_key_written_anew_is_adopted() -> None:
    clock = FakeClock()
    fences, key = fences_at(clock)
    key.text = fence_doc((40, clock.now_ms() - 60_000, [{"table": "events"}]))
    fences.drained()
    fences.apply([event("probe")])
    assert fences.stats()["seen"] == 40
    key.text = fence_doc((1, clock.now_ms(), [{"table": "events"}]))  # the sequence started again
    fences.drained()
    items = [event("probe")]
    fences.apply(items)
    assert len(items) == 1
    assert fences.stats()["seen"] == 1
    key.text = fence_doc((1, clock.now_ms(), [{"table": "events"}]), (2, clock.now_ms(), [{"table": "events"}]))
    fences.drained()
    items = [event("probe")]
    fences.apply(items)
    assert items == []


def test_the_fence_state_is_bounded() -> None:
    clock = FakeClock()
    fences, key = fences_at(clock)
    fences.drained()
    fences.apply([event("probe")])
    for seq in range(1, 100):
        fences.note_local(seq)
    assert len(fences._local) <= MAX_RESET_FENCES
    key.text = fence_doc(*[(seq, clock.now_ms(), [{"table": "events"}]) for seq in range(1, 60)])
    fences.drained()
    fences.apply([event("probe")])
    assert len(fences._active) <= 2 * MAX_RESET_FENCES


# ================================================================================================ read_sizes


def test_read_sizes_copies_match_their_sources() -> None:
    from roxy import insights
    from roxy.metrics import disk_history, jobs
    from roxy.storage import retention

    assert insights.HISTORY_KEEP_DAYS["error_minute"] == read_sizes.ERROR_MINUTE_KEEP_DAYS
    assert insights.HISTORY_KEEP_DAYS["cache_eviction_passes"] == read_sizes.EVICTION_PASSES_KEEP_DAYS
    assert insights.HISTORY_KEEP_DAYS["egress_provider_reports"] == read_sizes.PROVIDER_REPORTS_KEEP_DAYS
    assert read_sizes.SCORE_MIN_KEEP_DAYS == jobs.MIN_SCORE_KEEP_DAYS
    assert producers.ROW_CAPS[producers.TABLE_SCORES] == read_sizes.SCORE_ROW_CAP
    assert read_sizes.DISK_KEEP_DAYS == disk_history.DISK_KEEP_DAYS
    assert producers.ROW_CAPS[producers.TABLE_DISK] == read_sizes.DISK_ROW_CAP
    assert producers.ROW_CAPS[producers.TABLE_SIZES] == read_sizes.TABLE_SIZES_ROW_CAP
    assert read_sizes.AUDIT_MIN_DAYS == retention.AUDIT_MIN_DAYS
    policy = set(retention.RetentionPolicy.__dataclass_fields__)
    for db, metas in read_sizes.TABLES.items():
        for meta in metas:
            for name in (meta.age, meta.cap):
                assert name is None or name in policy, (db, meta.table, name)
            assert meta.label, (db, meta.table)
            assert meta.label != meta.table, (db, meta.table)


@pytest.mark.parametrize(
    ("meta", "oldest", "status", "max_age_s", "cap"),
    [
        (read_sizes.TableMeta("t", "T", "at", fixed_age_s=0), -10, "pruning_due", 0, None),
        (read_sizes.TableMeta("t", "T", "at", age="x", age_unit_s=1, idle=True), -10_000, "ok", 60, None),
        (read_sizes.TableMeta("t", "T", "at", age="days", min_age_s=5 * 86_400), -3 * 86_400, "ok", 5 * 86_400, None),
        (read_sizes.TableMeta("t", "T", "at", fixed_cap=1), 0, "over_cap", None, 1),
        (read_sizes.TableMeta("t", "T", "at", age="forever"), -(10**8), "ok", None, None),
    ],
)
def test_fixed_idle_and_minimum_limits(
    meta: Any, oldest: int, status: str, max_age_s: Any, cap: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = 1_760_000_000
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE t (at INTEGER)")
    conn.executemany("INSERT INTO t VALUES (?)", [(now + oldest,), (now,)])
    monkeypatch.setitem(read_sizes.TABLES, "db", (meta,))
    found = read_sizes.measure_table(
        conn, "db", "t", now_s=now, bytes_by_table=None, limits={"x": 60, "days": 1, "forever": 0}
    )
    assert (found["retention_status"], found["max_age_s"], found["row_cap"]) == (status, max_age_s, cap)


def test_every_metrics_and_hot_table_is_known_with_its_limits() -> None:
    """Lane request 3: the seven schema 5 tables (and every other metrics.db and hot.db table) have a label."""
    root = Path(read_sizes.__file__).parent / "migrations"
    for db in ("metrics", "hot"):
        text = "".join(path.read_text(encoding="utf-8") for path in sorted((root / db).glob("*.sql")))
        created = set(re.findall(r"CREATE TABLE (\w+)", text))
        known = {meta.table for meta in read_sizes.TABLES[db]}
        assert created <= known, (db, sorted(created - known))
    labels = {meta.table: meta for meta in read_sizes.TABLES["metrics"]}
    for table in (
        "rule_hit_minute",
        "tarpit_minute",
        "tarpit_hold_minute",
        "client_score_hour",
        "metrics_pipeline_minute",
        "disk_samples",
        "table_size_samples",
    ):
        meta = labels[table]
        assert meta.time_col is not None, table
        assert meta.age is not None or meta.fixed_age_s is not None, table
