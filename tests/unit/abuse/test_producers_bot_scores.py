"""Recorded bot scores: the tracker marks clients, a background loop scores them, the recorder keeps them per hour.

Covers the wave 3b producers lane, item 3 (plan 10.7; ABUSE-BOT, THROTTLE-TUNE, ABUSE-DIST): a client's first
request in a scoring interval keeps its per-request signals (cheap, once per client), `take_scores` scores the
marked clients off the request path (bounded, newest first), the pipeline's `abuse_bot_scores` loop hands the scores
to the metrics recorder, and `read_producers.client_scores` answers `{ip: score}` with the largest score any worker
computed in the client's latest hour.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from abuse_support import FakeReq, FakeSettings

from roxy.abuse.bot import MAX_IPS_PER_CLIENT, SIGNALS, ClientTracker, score
from roxy.abuse.pipeline import AbusePipeline
from roxy.config.catalog import CATALOG
from roxy.core.clock import FakeClock
from roxy.metrics import read_producers
from roxy.metrics.recorder import MetricsRecorder

WEIGHTS = {name: float(CATALOG[f"bot_weight_{name}"].default) for name in SIGNALS}
NOW = 1_760_000_000.0


def observe(tracker: ClientTracker, key: str, *, ua: str, ip: str | None = None, at: float = NOW) -> None:
    tracker.observe(
        key,
        now=at,
        monotonic=at,
        refused=False,
        probe=False,
        query_fp=None,
        ip=ip or key,
        user_agent=ua,
        game_server=False,
        header_names=["host", "user-agent", "accept"],
    )


def scores_since(dbs: Any, since: float) -> dict[str, int]:
    return dbs.metrics.read_sync(lambda conn: read_producers.client_scores(conn, int(since)))


def test_a_client_is_scored_once_per_interval_with_its_first_request() -> None:
    tracker = ClientTracker()
    observe(tracker, "203.0.113.1", ua="python-requests/2.31")
    observe(tracker, "203.0.113.1", ua="Roblox/Linux")  # later requests do not replace the interval's inputs
    assert tracker.pending() == 1
    scored = tracker.take_scores(now=NOW, weights=WEIGHTS, limit=10)
    assert [item.key for item in scored] == ["203.0.113.1"]
    expected = tracker.signals(
        "203.0.113.1",
        now=NOW,
        user_agent="python-requests/2.31",
        game_server=False,
        header_names=["host", "user-agent", "accept"],
    )
    assert scored[0].signals == expected
    assert scored[0].score == score(expected, WEIGHTS)
    assert scored[0].signals.library_ua == 1.0
    assert tracker.pending() == 0
    assert tracker.take_scores(now=NOW, weights=WEIGHTS, limit=10) == []  # nothing new since the last call


def test_take_scores_is_bounded_and_newest_first() -> None:
    tracker = ClientTracker()
    for n in range(5):
        observe(tracker, f"203.0.113.{n}", ua="curl/8")
    first = tracker.take_scores(now=NOW, weights=WEIGHTS, limit=2)
    assert [item.key for item in first] == ["203.0.113.4", "203.0.113.3"]
    assert tracker.pending() == 3  # the rest keep their mark for the next call
    rest = tracker.take_scores(now=NOW, weights=WEIGHTS, limit=10)
    assert [item.key for item in rest] == ["203.0.113.2", "203.0.113.1", "203.0.113.0"]


def test_addresses_behind_one_key_are_bounded() -> None:
    tracker = ClientTracker()
    for n in range(MAX_IPS_PER_CLIENT + 3):
        observe(tracker, "2001:db8::/64", ua="curl/8", ip=f"2001:db8::{n + 1}")
    (item,) = tracker.take_scores(now=NOW, weights=WEIGHTS, limit=10)
    assert len(item.ips) == MAX_IPS_PER_CLIENT
    assert item.ips[-1] == f"2001:db8::{MAX_IPS_PER_CLIENT + 3}"  # the oldest addresses went first


def test_observe_without_request_inputs_marks_nothing() -> None:
    tracker = ClientTracker()
    tracker.observe("203.0.113.1", now=NOW, monotonic=0.0, refused=False, probe=False, query_fp=None)
    assert tracker.pending() == 0


async def test_the_pipeline_records_scores_per_client_and_hour(
    dbs: Any, fake_clock: FakeClock, make_pipeline: Callable[..., AbusePipeline]
) -> None:
    recorder = MetricsRecorder(dbs, FakeSettings(), fake_clock, worker_id="w1")
    pipeline = make_pipeline(recorder=recorder)
    for _ in range(3):
        await pipeline.evaluate(FakeReq().with_headers([("User-Agent", "python-requests/2.31")]))
    await pipeline.evaluate(
        FakeReq(client_ip="198.51.100.4", limit_key="198.51.100.4").with_headers([("User-Agent", "Roblox/Linux")])
    )
    assert await pipeline.record_bot_scores() == 2
    recorder.close()
    found = scores_since(dbs, fake_clock.now() - 3600)
    assert set(found) == {"203.0.113.7", "198.51.100.4"}
    assert found["203.0.113.7"] > found["198.51.100.4"]  # a library User-Agent scores higher
    assert await pipeline.record_bot_scores() == 0  # nothing new


async def test_bypass_clients_are_never_scored(
    dbs: Any, fake_clock: FakeClock, make_pipeline: Callable[..., AbusePipeline]
) -> None:
    recorder = MetricsRecorder(dbs, FakeSettings(), fake_clock, worker_id="w1")
    pipeline = make_pipeline(recorder=recorder)
    await pipeline.evaluate(FakeReq(bypass=True).with_headers([("User-Agent", "curl/8")]))
    assert await pipeline.record_bot_scores() == 0


async def test_two_workers_keep_the_largest_score_of_the_hour(dbs: Any, fake_clock: FakeClock) -> None:
    first = MetricsRecorder(dbs, FakeSettings(), fake_clock, worker_id="w1")
    second = MetricsRecorder(dbs, FakeSettings(), fake_clock, worker_id="w2")
    first.record_client_score("203.0.113.9", 40, at_s=fake_clock.now())
    second.record_client_score("203.0.113.9", 85, at_s=fake_clock.now() + 1)
    first.record_client_score("::ffff:203.0.113.10", 12)  # normalized like the client tables
    first.close()
    second.close()
    found = scores_since(dbs, fake_clock.now() - 3600)
    assert found == {"203.0.113.9": 85, "203.0.113.10": 12}
    history = dbs.metrics.read_sync(
        lambda conn: read_producers.client_score_history(conn, "203.0.113.9", int(fake_clock.now()) - 3600)
    )
    assert [(row["score_max"], row["score_last"], row["samples"]) for row in history] == [(85, 85, 2)]
    fake_clock.advance(3600)  # a new hour: the client's latest hour wins, not its worst
    first.record_client_score("203.0.113.9", 20)
    first.close()
    assert scores_since(dbs, fake_clock.now() - 7200)["203.0.113.9"] == 20


async def test_the_loop_is_started_and_runs_at_close(
    dbs: Any, fake_clock: FakeClock, make_pipeline: Callable[..., AbusePipeline]
) -> None:
    recorder = MetricsRecorder(dbs, FakeSettings(), fake_clock, worker_id="w1")
    pipeline = make_pipeline(recorder=recorder)
    started: dict[str, float] = {}

    class Tasks:
        def start(self, name: str, fn: Any, *, interval_s: float) -> None:
            started[name] = interval_s

    pipeline.start(Tasks())
    assert started["abuse_bot_scores"] == 60.0
    await pipeline.evaluate(FakeReq().with_headers([("User-Agent", "curl/8")]))
    await pipeline.aclose()  # scores of the clients seen since the last run are handed over at shutdown
    recorder.close()
    assert "203.0.113.7" in scores_since(dbs, fake_clock.now() - 3600)
