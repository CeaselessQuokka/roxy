"""One evaluation keeps a bounded number of sample rows memoized (finding LOAD-2).

What this is
    Unit tests for `roxy/insights/context.py` `InsightContext.samples` and `refusal_samples` with the
    `MAX_MEMO_SAMPLE_ROWS` bound.

Why it exists
    Every read of an evaluation is memoized until the evaluation ends, so 50 rules asking the same question cost one
    query. For sample reads (up to 50,000 rows each, one per template a rule looks at) that held the whole day of
    samples several times over, and the leader worker's memory peak grew with the traffic. The memo now forgets the
    oldest sample reads past the bound; a rule that asks again reads again and gets the same rows.

How it works
    A migrated metrics.db with samples of two templates, the bound lowered to a few rows.

What to read next
    `roxy/insights/context.py`, `roxy/metrics/read_history.py` (`SampleRecord`).
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from roxy.insights import context as context_mod
from roxy.insights.context import InsightContext
from roxy.metrics.samples import RefusalSample, SampleRow, write_refusal_samples, write_samples

FIRST = "games.roblox.com/v1/games/{universeId}/votes"
SECOND = "users.roblox.com/v1/users/{userId}"
NOW = 10_000.0


def _context(dbs: Any) -> InsightContext:
    def run(conn: Any) -> None:
        rows = [
            SampleRow(int(NOW * 1000) - 60_000 + i, f"k{i}", template, "GET", "c", None, "MISS", 200, "direct", None,
                      1, "anon", 100.0)
            for i, template in enumerate([FIRST] * 3 + [SECOND] * 3)
        ]  # fmt: skip
        write_samples(conn, rows)
        write_refusal_samples(conn, [RefusalSample(int(NOW * 1000) - 1000, "throttle", FIRST, "GET", "c", None, 100.0)])

    dbs.metrics.write_sync(run)
    return InsightContext(now=NOW, dbs=dbs, settings={}, rules=None)


async def test_sample_reads_past_the_bound_forget_the_oldest(dbs: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(context_mod, "MAX_MEMO_SAMPLE_ROWS", 4)
    ctx = _context(dbs)
    window = ctx.window(minutes=5)
    first = await ctx.samples(window, [FIRST])
    assert [r["endpoint_template"] for r in first] == [FIRST] * 3
    assert ctx._sample_rows == 3
    second = await ctx.samples(window, [SECOND])
    assert len(second) == 3
    assert ctx._sample_rows == 3  # the first read was forgotten to stay within 4 rows
    assert ("metrics", "samples", window, (FIRST,)) not in ctx._memo
    assert ("metrics", "samples", window, (SECOND,)) in ctx._memo
    again = await ctx.samples(window, [FIRST])  # read again, same answer
    assert [dict(r) for r in again] == [dict(r) for r in first]


async def test_a_read_within_the_bound_is_shared_by_every_rule(dbs: Any) -> None:
    ctx = _context(dbs)
    window = ctx.window(minutes=5)
    one = await ctx.samples(window)
    two = await ctx.samples(window)
    assert one is two  # memoized: one query for every rule of the run
    refused = await ctx.refusal_samples(window)
    assert [r["reason"] for r in refused] == ["throttle"]
    assert ctx._sample_rows == 7


async def test_a_copied_context_keeps_its_own_bookkeeping(dbs: Any) -> None:
    ctx = _context(dbs)
    window = ctx.window(minutes=5)
    await ctx.samples(window)
    copy = dataclasses.replace(ctx, _memo={}, _locks={})
    assert copy._sample_keys == []
    assert copy._sample_rows == 0
    await copy.samples(window, [FIRST])
    assert ctx._sample_rows == 6
    assert copy._sample_rows == 3
