"""The recorder's producer history: the windowed fleet-wide drop counter, its own batch kind, bounds and pruning.

Covers the wave 3b producers lane, item 5 (SYS-METRICS-DROP) and the shared machinery of items 1 to 3: every flush
writes the items this worker dropped since the previous flush into its row of the minute, so a sum over a window and
over workers is the fleet's drops in that window; the producer tables have their own batch kind (a broken table
never holds up the insight history); every in-memory map is bounded; `prune_producers` keeps each table to its age
and row cap.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from roxy.core.clock import FakeClock
from roxy.metrics import producers, read_history, read_producers
from roxy.metrics.producers import ProducerHistory, prune_producers
from roxy.metrics.recorder import KIND_PRODUCERS, KIND_SAMPLES, PRIORITIES, MetricsRecorder
from roxy.metrics.samples import SampleRow


def recorder_for(dbs: Any, settings_factory: Any, clock: FakeClock, worker: str, **overrides: Any) -> MetricsRecorder:
    return MetricsRecorder(dbs, settings_factory(**overrides), clock, worker_id=worker)


def sample(clock: FakeClock) -> SampleRow:
    return SampleRow(
        at_ms=clock.now_ms(),
        key_id=None,
        endpoint_template="games.roblox.com/v1/games",
        method="GET",
        client_hash=None,
        place=None,
        cache_state="MISS",
        upstream_status=200,
        egress="direct",
        body_hash=None,
        bytes=10,
        auth_class="anon",
    )


def drops(dbs: Any, clock: FakeClock) -> dict[str, Any]:
    now = int(clock.now())
    return dbs.metrics.read_sync(lambda conn: read_producers.pipeline_drops(conn, now - 3600, now + 1))


async def test_drops_are_windowed_and_fleet_wide(dbs: Any, settings_factory: Any, fake_clock: FakeClock) -> None:
    first = recorder_for(dbs, settings_factory, fake_clock, "w1", metrics_queue_max=1000)
    second = recorder_for(dbs, settings_factory, fake_clock, "w2", metrics_queue_max=1000)
    for _ in range(1300):
        first.batch.add(KIND_SAMPLES, sample(fake_clock))  # 300 over the queue bound
    for _ in range(1030):
        second.batch.add(KIND_SAMPLES, sample(fake_clock))
    await first.flush()
    await second.flush()
    found = drops(dbs, fake_clock)
    assert found["dropped"] == 330
    assert found["workers"] == {
        "w1": {"dropped": 300, "history_dropped": 0, "capture_dropped": 0},
        "w2": {"dropped": 30, "history_dropped": 0, "capture_dropped": 0},
    }
    await first.flush()  # nothing new dropped: no new row, the total stays
    assert drops(dbs, fake_clock)["dropped"] == 330
    fake_clock.advance(2 * 3600)
    assert drops(dbs, fake_clock)["dropped"] == 0  # an hour later the window is clean: SYS-METRICS-DROP goes quiet
    assert first.stats()["metrics_dropped"] == 300  # the worker's lifetime counter (System page) is unchanged


async def test_history_and_capture_drops_are_reported_too(
    dbs: Any, settings_factory: Any, fake_clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorder = recorder_for(dbs, settings_factory, fake_clock, "w1")
    monkeypatch.setattr(producers, "MAX_PRODUCER_KEYS", 2)
    for n in range(5):
        recorder.record_rule_hit("rules_endpoint_block", n)  # 3 keys do not fit the producer map
    recorder.capture_dropped += 4
    await recorder.flush()
    found = drops(dbs, fake_clock)
    assert (found["dropped"], found["history_dropped"], found["capture_dropped"]) == (0, 3, 4)
    assert recorder.stats()["producers"]["dropped"] == 3
    lifetime = dbs.metrics.read_sync(lambda conn: read_history.rule_hits(conn, "rules_endpoint_block"))
    assert len(lifetime) == 5  # the lifetime table has its own, larger bound


async def test_a_broken_producer_table_never_holds_up_the_insight_history(
    dbs: Any, settings_factory: Any, fake_clock: FakeClock
) -> None:
    assert PRIORITIES[KIND_PRODUCERS] < PRIORITIES["metrics.insight_history"]
    dbs.metrics.write_sync(lambda conn: conn.execute("ALTER TABLE rule_hit_minute RENAME TO rule_hit_minute_gone"))
    recorder = recorder_for(dbs, settings_factory, fake_clock, "w1")
    recorder.record_rule_hit("rules_header", 7)
    await recorder.flush()
    lifetime = dbs.metrics.read_sync(lambda conn: read_history.rule_hits(conn, "rules_header"))
    assert lifetime[("rules_header", "7")]["hits"] == 1  # written by the insight history kind
    assert recorder.batch.stats()["kinds"][KIND_PRODUCERS]["dropped"] == 1  # the unwritable item, counted


async def test_a_refusal_event_names_the_rule_rows_it_matched(
    dbs: Any, settings_factory: Any, fake_clock: FakeClock, make_event: Any, presets: dict[str, Any]
) -> None:
    recorder = recorder_for(dbs, settings_factory, fake_clock, "w1")
    recorder.record_outcome(make_event(**presets["refused"], matches={"rules_endpoint_block": "7"}))
    recorder.record_outcome(make_event(**presets["refused"]))  # no matches: no key
    await recorder.flush()
    now = int(fake_clock.now())
    events = dbs.metrics.read_sync(lambda conn: read_history.events_between(conn, ["refusal"], now - 60, now + 60))
    assert [event["detail"].get("rules") for event in events] == [{"rules_endpoint_block": "7"}, None]


def test_producer_history_drain_shapes() -> None:
    clock = FakeClock()
    counters = [0, 0, 0]
    history = ProducerHistory(clock=clock, worker_id="w9", counters=lambda: (counters[0], counters[1], counters[2]))
    history.rule_hit("rules_user_agent", "abc", 2)
    history.tarpit(category="probe", kind="hold", held_s=9.5, gap_s=4.0, after_hold=True)
    history.tarpit(category="probe", kind="hold", skipped=True, gap_s=2.0, after_hold=False)
    history.client_score("203.0.113.1", 150)  # clamped to 100
    counters[0] = 7
    items = {item.table: item for item in history.drain()}
    minute = int(clock.now()) // 60 * 60
    assert items["rule_hit_minute"].key == (minute, "rules_user_agent", "abc")
    assert items["rule_hit_minute"].values == (2,)
    assert items["tarpit_minute"].values == (1, 1, 9.5, 9.5, 1, 4.0, 1, 2.0)
    assert items["tarpit_hold_minute"].key == (minute, "probe", 10000)
    assert items["client_score_hour"].values[:2] == (100, 100)
    assert items["metrics_pipeline_minute"].key == (minute, "w9")
    assert items["metrics_pipeline_minute"].values == (7, 0, 0)
    assert history.drain() == []  # everything was handed over, and no new drops


def test_prune_keeps_ages_and_row_caps(dbs: Any, fake_clock: FakeClock, monkeypatch: pytest.MonkeyPatch) -> None:
    now = int(fake_clock.now()) // 3600 * 3600
    old, recent = now - 30 * 86_400, now - 600

    def fill(conn: Any) -> None:
        for at in (old, recent):
            conn.execute("INSERT INTO rule_hit_minute VALUES (?, 'bans', '1', 3)", (at,))
            conn.execute(
                "INSERT INTO tarpit_minute (bucket_start, category, kind, holds) VALUES (?, 'ban', 'hold', 1)", (at,)
            )
            conn.execute("INSERT INTO tarpit_hold_minute VALUES (?, 'ban', 10000, 1)", (at,))
            conn.execute(
                "INSERT INTO metrics_pipeline_minute (bucket_start, worker_id, dropped) VALUES (?, 'w', 1)", (at,)
            )
            conn.execute(
                "INSERT INTO disk_samples (at, storage_bytes, files_json) VALUES (?, 1, ?)", (at, json.dumps({}))
            )
            conn.execute("INSERT INTO table_size_samples VALUES (?, 'metrics', 'events', 10)", (at,))
        for hour in range(6):
            for n in range(3):
                conn.execute(
                    "INSERT INTO client_score_hour VALUES (?, ?, 50, 50, ?, 1)",
                    (now - hour * 3600, f"192.0.2.{n}", now),
                )

    dbs.metrics.write_sync(fill)
    monkeypatch.setitem(producers.ROW_CAPS, producers.TABLE_SCORES, 10)
    keep = dict.fromkeys(producers.MINUTE_TABLES, 14.0) | {
        producers.TABLE_SCORES: 2.0,
        producers.TABLE_DISK: 90.0,
        producers.TABLE_SIZES: 90.0,
    }
    deleted = dbs.metrics.write_sync(lambda conn: prune_producers(conn, now, keep))
    for table in producers.MINUTE_TABLES:
        assert deleted[table] == 1, table
    assert deleted[producers.TABLE_DISK] == 0  # 30 days is inside the 90-day keep
    assert deleted[producers.TABLE_SCORES] == 9  # 18 rows over a cap of 10: whole oldest hours go first

    def count(conn: Any, table: str) -> int:
        return int(conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0])

    assert dbs.metrics.read_sync(lambda conn: count(conn, producers.TABLE_SCORES)) == 9
    assert dbs.metrics.read_sync(lambda conn: count(conn, "rule_hit_minute")) == 1
    again = dbs.metrics.write_sync(lambda conn: prune_producers(conn, now, keep))
    assert sum(again.values()) == 0  # idempotent
