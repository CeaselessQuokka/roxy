"""One read per window for every rule, bounded dry runs that say so, and replays off the event loop (gaps_insights G7).

What this is
    Tests of `roxy/insights/context.py` (`change_estimate`, `clients`, `by`, `sample_read`, `replay_samples`,
    `bound_note`) and `roxy/insights/simulate.py` (`dry_run` with `MAX_REPLAY_ROWS`, `offload`).

Why it exists
    The leader evaluates every rule every 30 s. At a day's volume the rules read up to 50,000 sample rows per
    template per rule (the oldest of the day, silently cut) and paged the client table one aggregate per page of 250:
    3 to 5 s of the leader's CPU per evaluation. Now each window is read once for every rule, what a rule needs from a
    day of samples is computed in SQL, a dry run replays the newest part of its window that fits its bound and says so,
    and the replay runs on a worker thread so the leader's event loop keeps answering requests.

How it works
    A migrated database set (`dbs`), rows written with the recorder's writers or plain SQL, the engine's own context,
    and a counter around `Database.read` (how many reads a question costs).

What to read next
    `roxy/insights/context.py`, `roxy/insights/simulate.py`, `tests/unit/metrics/test_metrics_sample_aggregates.py`.
"""

from __future__ import annotations

import threading
from typing import Any

import pytest

from roxy.config.runtime import load_runtime_settings
from roxy.core.clock import FakeClock
from roxy.insights import simulate
from roxy.insights.context import InsightContext, SampleRead, bound_note
from roxy.insights.engine import InsightsEngine
from roxy.insights.models import Recommendation
from roxy.insights.rules.cache import new_rule
from roxy.metrics import queries, read_history
from roxy.metrics.samples import SampleRow, write_samples
from roxy.rules.store import RulesStore

NOW = 1_791_385_200.0  # 2026-10-07T15:00:00Z, on a minute
TEMPLATE = "games.roblox.com/v1/games/votes"
OTHER = "users.roblox.com/v1/users/{userId}"


async def _engine(dbs: Any) -> InsightsEngine:
    clock = FakeClock(NOW)
    runtime = await load_runtime_settings(dbs, clock)
    store = RulesStore(dbs.control, clock=clock)
    await store.reload()
    return InsightsEngine(dbs=dbs, settings=runtime, rules=store, clock=clock, rule_set={})


def _count_reads(dbs: Any, monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """A list whose length is the number of metrics.db reads made from now on."""
    calls: list[int] = []
    original = dbs.metrics.read

    async def read(fn: Any) -> Any:
        calls.append(1)
        return await original(fn)

    monkeypatch.setattr(dbs.metrics, "read", read)
    return calls


def _hour_of_samples(dbs: Any, *, every_s: int = 6) -> list[SampleRow]:
    """An hour of samples ending at NOW: two templates, ten keys, bodies that change every few fetches."""
    rows = []
    for index, at_s in enumerate(range(int(NOW) - 3600, int(NOW), every_s)):
        rows.append(
            SampleRow(at_s * 1000, f"k{index % 10}", TEMPLATE if index % 3 else OTHER, "GET", f"c{index % 4}", None,
                      "MISS", 200, "direct", f"{(index // 40) % 3:016x}", 10, "anon", 100.0)
        )  # fmt: skip
    dbs.metrics.write_sync(lambda conn: write_samples(conn, rows))
    return rows


# ------------------------------------------------------------------------------------------ one read each


async def test_the_tuner_is_one_sql_read_per_window_for_every_rule(dbs: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _hour_of_samples(dbs)
    ctx = (await _engine(dbs)).context(NOW)
    window = ctx.window(hours=1)
    reads = _count_reads(dbs, monkeypatch)
    first = await ctx.change_estimate(window, TEMPLATE)
    second = await ctx.change_estimate(window, OTHER)
    again = await ctx.change_estimate(window, TEMPLATE)
    missing = await ctx.change_estimate(window, "nothing/{here}")
    assert len(reads) == 1  # one read for both templates and every rule of the run
    assert first.to_dict() == again.to_dict()
    assert first is not again  # each rule gets its own copy
    assert missing.to_dict() == simulate.ChangeEstimate().to_dict()
    for template, got in ((TEMPLATE, first), (OTHER, second)):
        rows = await ctx.samples(window, [template])
        assert got.to_dict() == simulate.estimate_change_interval(rows).to_dict()
        assert got.keys > 0
        assert got.changes > 0


async def test_clients_and_by_are_one_aggregate_whatever_their_size(dbs: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    def write(conn: Any) -> None:
        conn.executemany(
            "INSERT INTO client_minute (bucket_start, client_type, client_key, requests, refused, served, bytes, "
            "top_endpoint) VALUES (?, 'ip', ?, ?, ?, ?, 10, ?)",
            [(int(NOW) - 600, f"198.51.100.{n % 250}.{n // 250}", n % 9 + 1, n % 2, n % 9, TEMPLATE)
             for n in range(1_000)],
        )  # fmt: skip

    dbs.metrics.write_sync(write)
    ctx = (await _engine(dbs)).context(NOW)
    window = ctx.window(hours=1)
    reads = _count_reads(dbs, monkeypatch)
    rows = await ctx.clients(window, "ip")
    assert len(reads) == 1  # was one aggregate (and one rates read) per page of 250: four pages here
    assert len(rows) == 1_000
    assert [r["requests"] for r in rows] == sorted((r["requests"] for r in rows), reverse=True)
    paged = dbs.metrics.read_sync(
        lambda c: queries.client_table_sync(c, window, "ip", now=NOW, page=queries.Page(size=250))
    )["rows"]
    assert [r["key"] for r in rows[:250]] == [r["key"] for r in paged]
    await ctx.by(window, "endpoint_template")
    assert len(reads) == 2


# ------------------------------------------------------------------------------------------ bounded reads


async def test_a_cut_sample_read_says_so(dbs: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _hour_of_samples(dbs)
    ctx = (await _engine(dbs)).context(NOW)
    window = ctx.window(hours=1)
    whole = await ctx.sample_read(window, [TEMPLATE])
    assert whole.complete
    assert bound_note(whole, "rows") is None
    monkeypatch.setattr(read_history, "MAX_ROWS", 50)
    fresh = (await _engine(dbs)).context(NOW)
    cut = await fresh.sample_read(window, [TEMPLATE])
    assert (len(cut.rows), cut.complete, cut.limit) == (50, False, 50)
    note = bound_note(cut, "cooldown answers")
    assert note is not None
    assert "50 cooldown answers" in note
    assert "lower bound" in note
    filtered = await fresh.sample_read(window, [OTHER], where=read_history.SampleFilter(key_ids=("k1",)))
    assert filtered.complete
    assert len(filtered.rows) == 20  # filtered in SQL: the bound counts only kept rows
    assert {(r["key_id"], r["endpoint_template"]) for r in filtered.rows} == {("k1", OTHER)}
    assert isinstance(filtered, SampleRead)


def _cache_recommendation() -> Recommendation:
    return Recommendation(
        rule_id="CACHE-LOW-HIT",
        family="cache",
        subject=TEMPLATE,
        title="t",
        changes=[new_rule(TEMPLATE, {"ttl": 120, "stale_ttl": 0, "methods": "GET"})],
    )


async def test_a_dry_run_over_a_busy_window_replays_its_newest_part_and_says_so(
    dbs: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    _hour_of_samples(dbs)  # 600 samples in the hour
    engine = await _engine(dbs)
    rec = _cache_recommendation()
    monkeypatch.setattr(simulate, "MAX_REPLAY_ROWS", 100)
    report = await simulate.dry_run(engine.context(NOW), rec, window_s=3600)
    assert report.bounded is True
    assert report.requested_window_s == 3600
    assert report.window_s < 3600
    assert report.window_s % 60 == 0
    assert "only the newest" in report.note
    assert "100" in report.note
    assert 0 < report.sample_size <= 100
    # The bounded replay is exactly the replay of the span it covered.
    monkeypatch.setattr(simulate, "MAX_REPLAY_ROWS", 50_000)
    same = await simulate.dry_run(engine.context(NOW), rec, window_s=report.window_s)
    assert same.bounded is False
    assert same.avoided_calls == report.avoided_calls
    assert same.sample_size == report.sample_size
    assert same.parts == report.parts
    whole = await simulate.dry_run(engine.context(NOW), rec, window_s=3600)
    assert whole.bounded is False
    assert whole.window_s == whole.requested_window_s == 3600
    assert whole.sample_size > report.sample_size
    assert "only the newest" not in whole.note
    assert {"bounded", "requested_window_s"} <= set(whole.to_dict())


async def test_the_replay_runs_on_a_worker_thread(dbs: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _hour_of_samples(dbs)
    engine = await _engine(dbs)
    threads: list[int] = []
    original = simulate.cache_replay

    def spy(*args: Any, **kwargs: Any) -> Any:
        threads.append(threading.get_ident())
        return original(*args, **kwargs)

    monkeypatch.setattr(simulate, "cache_replay", spy)
    report = await engine.dry_run(_cache_recommendation())
    assert report.avoided_calls is not None
    assert report.sample_size > 0
    assert threads
    assert threading.get_ident() not in threads  # never on the event loop's thread


async def test_offload_runs_one_replay_at_a_time_per_loop() -> None:
    running: list[int] = []
    most: list[int] = [0]
    gate = threading.Lock()

    def work(n: int) -> int:
        with gate:
            running.append(n)
            most[0] = max(most[0], len(running))
        try:
            return n * 2
        finally:
            with gate:
                running.remove(n)

    import asyncio

    results = await asyncio.gather(*(simulate.offload(work, n) for n in range(6)))
    assert results == [n * 2 for n in range(6)]
    assert most[0] == simulate.REPLAY_THREADS


def test_insight_context_has_the_shared_reads() -> None:
    for name in ("sample_read", "replay_samples", "change_estimate", "change_estimates", "ua_arm_counts"):
        assert callable(getattr(InsightContext, name))
