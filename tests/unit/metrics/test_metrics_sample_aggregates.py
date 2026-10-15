"""The sample aggregates and bounded reads the insights rules share (gaps_insights G7).

What this is
    Unit tests for `roxy/metrics/read_history.py` `change_estimates` (the TTL tuner in SQL), `SampleFilter`,
    `sample_cut`, `newest_streams` and `ua_arm_counts`, and for the one-read tables of `roxy/metrics/queries.py`
    (`top_rows_sync`, `client_rows_sync`).

Why it exists
    The recommendations evaluation read up to 50,000 sample rows per template per rule (the oldest of a busy day,
    silently cut) and paged the client table 250 rows at a time, re-running the whole aggregate per page: 3 to 5 s of
    the leader's CPU every 30 s at a day's volume. The rules now read SQL aggregates computed over every row of the
    window, one read per window. These tests pin each aggregate to the Python computation it replaces (same numbers,
    the same float arithmetic), so the fixtures' expectations cannot drift.

How it works
    Random sample rows (fixed seeds) written with the recorder's own writer into a migrated metrics.db; each aggregate
    is compared with the pure Python function over the same rows (`insights/simulate.py estimate_change_interval`,
    `insights/providers_rules_upstream.py arms_from_samples`), and each one-read table with the pages it replaces.

What to read next
    `roxy/metrics/read_history.py`, `roxy/insights/context.py` (how the rules reach these), `tests/insights/
    test_context_one_read.py`.
"""

from __future__ import annotations

import random
from collections.abc import Callable
from typing import Any

import pytest

from roxy.core.clock import FakeClock
from roxy.insights import simulate
from roxy.insights.providers_rules_upstream import arms_from_counts, arms_from_samples
from roxy.metrics import queries as q
from roxy.metrics import read_history
from roxy.metrics.read_history import SampleFilter
from roxy.metrics.recorder import MetricsRecorder, OutcomeEvent
from roxy.metrics.samples import RefusalSample, SampleRow, write_refusal_samples, write_samples

TEMPLATES = ("games.roblox.com/v1/games/{universeId}/votes", "users.roblox.com/v1/users/{userId}", "thumbs/{id}")
START_MS = 1_700_000_000_000
STATES = ("HIT", "MISS", "STALE", "REVALIDATING", "COALESCED", "OFF", None)
EGRESSES = ("none", "direct", "rotator", "credential", "", None)


def _random_rows(seed: int, count: int, *, span_ms: int = 3_600_000) -> list[SampleRow]:
    """Rows with repeated times (ties broken by id), keys shared across templates by name, bodies that change now
    and then, rows without a key or a body, and every egress and cache state."""
    rng = random.Random(seed)
    rows = []
    for _ in range(count):
        template = rng.choice(TEMPLATES)
        key = rng.choice([None, *(f"k{n}" for n in range(12))])
        body = rng.choice([None, "", "a" * 16, "b" * 16, "c" * 16]) if rng.random() < 0.8 else None
        rows.append(
            SampleRow(
                at_ms=START_MS + rng.randrange(0, span_ms, 250),  # coarse times: many ties
                key_id=key,
                endpoint_template=template,
                method=rng.choice(("GET", "POST")),
                client_hash=rng.choice([None, "", "c1", "c2", "c3"]),
                place=rng.choice([None, "123"]),
                cache_state=rng.choice(STATES),
                upstream_status=rng.choice([None, 200, 404, 429, 500]),
                egress=rng.choice(EGRESSES),
                body_hash=body,
                bytes=10,
                auth_class="anon",
                sample_pct=100.0,
            )
        )
    return rows


def _write(dbs: Any, rows: list[SampleRow]) -> None:
    dbs.metrics.write_sync(lambda conn: write_samples(conn, rows))


def _all(dbs: Any, start: int, end: int, templates: Any = None) -> list[read_history.SampleRecord]:
    return dbs.metrics.read_sync(lambda c: read_history.samples_between(c, start, end, templates))  # type: ignore[no-any-return]


# ------------------------------------------------------------------------------------------- the TTL tuner


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
def test_change_estimates_equal_the_python_tuner(dbs: Any, seed: int) -> None:
    _write(dbs, _random_rows(seed, 1500))
    start, end = START_MS // 1000, START_MS // 1000 + 3600
    found = dbs.metrics.read_sync(lambda c: read_history.change_estimates(c, start, end))
    assert found  # the data has keys fetched twice
    for template in TEMPLATES:
        rows = _all(dbs, start, end, [template])
        expected = simulate.estimate_change_interval(rows)
        got = simulate.ChangeEstimate.from_summary(found.get(template))
        assert got.to_dict() == expected.to_dict(), template
        assert got.change_interval_s == expected.change_interval_s  # the same float, not only when rounded
        assert simulate.proposed_ttl(got, cap_s=3600) == simulate.proposed_ttl(expected, cap_s=3600)


def test_change_estimates_have_no_row_limit(dbs: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """A day of samples is many times the read bound: the aggregate counts every row (the old per-template read
    stopped at the oldest `MAX_ROWS` rows)."""
    rows = [
        SampleRow(START_MS + i * 1000, f"k{i % 5}", TEMPLATES[0], "GET", "c", None, "MISS", 200, "direct",
                  "x" * 16 if (i // 40) % 2 else "y" * 16, 1, "anon", 100.0)
        for i in range(600)
    ]  # fmt: skip
    _write(dbs, rows)
    monkeypatch.setattr(read_history, "MAX_ROWS", 100)
    start, end = START_MS // 1000, START_MS // 1000 + 3600
    found = dbs.metrics.read_sync(lambda c: read_history.change_estimates(c, start, end))[TEMPLATES[0]]
    full = simulate.estimate_change_interval(rows_as_records(rows))
    cut = simulate.estimate_change_interval(_all(dbs, start, end, [TEMPLATES[0]]))  # what a row read sees
    assert len(_all(dbs, start, end, [TEMPLATES[0]])) == 100
    assert simulate.ChangeEstimate.from_summary(found).to_dict() == full.to_dict()
    assert cut.changes < full.changes


def rows_as_records(rows: list[SampleRow]) -> list[dict[str, Any]]:
    return [
        {
            "id": n + 1,
            "at_ms": r.at_ms,
            "key_id": r.key_id,
            "body_hash": r.body_hash,
            "endpoint_template": r.endpoint_template,
        }
        for n, r in enumerate(rows)
    ]


def test_change_estimates_of_one_template_and_of_an_empty_window(dbs: Any) -> None:
    _write(dbs, _random_rows(9, 400))
    start, end = START_MS // 1000, START_MS // 1000 + 3600
    every = dbs.metrics.read_sync(lambda c: read_history.change_estimates(c, start, end))
    one = dbs.metrics.read_sync(lambda c: read_history.change_estimates(c, start, end, [TEMPLATES[1]]))
    assert set(one) <= {TEMPLATES[1]}
    assert one.get(TEMPLATES[1]) == every.get(TEMPLATES[1])
    assert dbs.metrics.read_sync(lambda c: read_history.change_estimates(c, end, end + 60)) == {}
    assert simulate.ChangeEstimate.from_summary(None).to_dict() == simulate.ChangeEstimate().to_dict()


# --------------------------------------------------------------------------------------- filtered reads


@pytest.mark.parametrize(
    ("where", "keep"),
    [
        (
            SampleFilter(egress="none", exclude_cache_states=("HIT", "STALE", "REVALIDATING", "COALESCED"),
                         with_client=True),
            lambda s: bool(s.get("client_hash")) and s.get("egress") == "none"
            and s.get("cache_state") not in {"HIT", "STALE", "REVALIDATING", "COALESCED"},
        ),
        (
            SampleFilter(called=True, key_ids=("k1", "k3"), statuses=(404, 500)),
            lambda s: str(s.get("key_id")) in {"k1", "k3"} and s.get("upstream_status") in {404, 500}
            and str(s.get("egress") or "none") != "none",
        ),
        (SampleFilter(), lambda s: True),
    ],
)  # fmt: skip
def test_sample_filters_keep_exactly_the_rows_the_rules_kept(
    dbs: Any, where: SampleFilter, keep: Callable[[Any], bool]
) -> None:
    _write(dbs, _random_rows(5, 800))
    start, end = START_MS // 1000, START_MS // 1000 + 3600
    filtered = dbs.metrics.read_sync(lambda c: read_history.samples_between(c, start, end, where=where))
    expected = [r for r in _all(dbs, start, end) if keep(r)]
    assert [r["id"] for r in filtered] == [r["id"] for r in expected]
    assert filtered  # the filter is not trivially empty


def test_one_more_row_than_the_bound_tells_a_cut_read(dbs: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _write(dbs, _random_rows(6, 50))
    monkeypatch.setattr(read_history, "MAX_ROWS", 20)
    start, end = START_MS // 1000, START_MS // 1000 + 3600
    assert len(dbs.metrics.read_sync(lambda c: read_history.samples_between(c, start, end))) == 20
    assert len(dbs.metrics.read_sync(lambda c: read_history.samples_between(c, start, end, limit=21))) == 21
    assert len(dbs.metrics.read_sync(lambda c: read_history.samples_between(c, start, end, limit=500))) == 21


# ------------------------------------------------------------------------------------------ bounded spans


def test_sample_cut_starts_the_newest_part_that_fits_on_a_minute(dbs: Any) -> None:
    rows = [
        SampleRow(START_MS + i * 6_000, "k", TEMPLATES[0], "GET", "c", None, "MISS", 200, "direct", None, 1, "anon")
        for i in range(600)
    ]  # one row every 6 s for an hour  # fmt: skip
    _write(dbs, rows)
    start, end = START_MS // 1000, START_MS // 1000 + 3600
    assert dbs.metrics.read_sync(lambda c: read_history.sample_cut(c, start, end, 600)) is None
    cut = dbs.metrics.read_sync(lambda c: read_history.sample_cut(c, start, end, 100))
    assert cut is not None
    assert cut % 60 == 0
    assert start < cut < end
    inside = [r for r in rows if r.at_ms >= cut * 1000]
    assert len(inside) <= 100
    assert len(inside) >= 100 - 10  # at most one minute (10 rows) more than needed was cut
    with pytest.raises(ValueError):
        dbs.metrics.read_sync(lambda c: read_history.sample_cut(c, start, end, 10, table="events"))


def test_newest_streams_cut_both_tables_at_one_time(dbs: Any) -> None:
    rows = [
        SampleRow(START_MS + i * 6_000, "k", TEMPLATES[0], "GET", "c", None, "MISS", 200, "direct", None, 1, "anon")
        for i in range(600)
    ]  # fmt: skip
    refused = [RefusalSample(START_MS + 3_000_000 + i * 1_000, "throttle", TEMPLATES[0], "GET", "c", None)
               for i in range(500)]  # fmt: skip
    _write(dbs, rows)
    dbs.metrics.write_sync(lambda c: write_refusal_samples(c, refused))
    start, end = START_MS // 1000, START_MS // 1000 + 3600
    cut, got, got_refused = dbs.metrics.read_sync(
        lambda c: read_history.newest_streams(c, start, end, 200, refusals=True)
    )
    assert len(got) <= 200
    assert len(got_refused) <= 200
    assert all(r["at_ms"] >= cut * 1000 for r in [*got, *got_refused])
    assert got[-1]["at_ms"] == rows[-1].at_ms  # the newest rows are kept, not the oldest
    whole, every, no_refusals = dbs.metrics.read_sync(
        lambda c: read_history.newest_streams(c, start, end, 50_000, refusals=False)
    )
    assert (whole, len(every), no_refusals) == (start, 600, [])


# ------------------------------------------------------------------------------------- the UA experiment


def test_ua_arm_counts_equal_the_python_arms(dbs: Any) -> None:
    _write(dbs, _random_rows(8, 1200))
    start, end = START_MS // 1000, START_MS // 1000 + 3600
    counts = dbs.metrics.read_sync(lambda c: read_history.ua_arm_counts(c, start, end))
    settings = {
        "ua_experiment_enabled": 1,
        "direct_user_agent": "Roxy/primary",
        "ua_experiment_alt_user_agent": "Roxy/alt",
        "request_sample_pct": 100,
    }
    assert arms_from_counts(counts, settings) == arms_from_samples(_all(dbs, start, end), settings)
    assert sum(calls for _i, calls, _l in counts) == sum(
        1 for r in _all(dbs, start, end) if r["egress"] == "direct" and r["upstream_status"] is not None
    )


# ----------------------------------------------------------------------------------- one-read tables


async def test_top_rows_equal_every_page_of_the_paged_table(
    recorder: MetricsRecorder, make_event: Callable[..., OutcomeEvent], fake_clock: FakeClock
) -> None:
    for i in range(30):
        for _ in range(i % 7 + 1):
            recorder.record_outcome(make_event(endpoint_template=f"games.roblox.com/v1/e{i:02d}"))
    recorder.close()
    w = q.resolve_window("1h", now=fake_clock.now())

    def page_of(number: int) -> list[dict[str, Any]]:
        page = q.Page(page=number, size=10)
        answer = recorder.dbs.metrics.read_sync(lambda c: q.top_n_sync(c, w, "endpoint_template", page=page))
        return list(answer["rows"])

    paged = page_of(1) + page_of(2) + page_of(3)
    rows = recorder.dbs.metrics.read_sync(lambda c: q.top_rows_sync(c, w, "endpoint_template"))
    assert q.ordered_rows(rows, "requests") == paged


async def test_client_rows_equal_every_page_of_the_client_table_without_rates(
    recorder: MetricsRecorder, make_event: Callable[..., OutcomeEvent], fake_clock: FakeClock
) -> None:
    for i in range(30):
        for _ in range(i % 5 + 1):
            recorder.record_outcome(make_event(client_ip=f"198.51.100.{i + 1}"))
    recorder.close()
    now = fake_clock.now() + 30
    w = q.resolve_window("24h", now=now)

    def page_of(number: int) -> list[dict[str, Any]]:
        page = q.Page(page=number, size=10)
        answer = recorder.dbs.metrics.read_sync(lambda c: q.client_table_sync(c, w, "ip", now=now, page=page))
        return list(answer["rows"])

    paged = page_of(1) + page_of(2) + page_of(3)
    rows = recorder.dbs.metrics.read_sync(lambda c: q.client_rows_sync(c, w, "ip"))
    rates = ("rate1", "rate5", "rate60")
    assert rows == [{k: v for k, v in row.items() if k not in rates} for row in paged]
    assert recorder.dbs.metrics.read_sync(lambda c: q.client_rows_sync(c, w, "ip", limit=4)) == rows[:4]
    with pytest.raises(ValueError):
        recorder.dbs.metrics.read_sync(lambda c: q.client_rows_sync(c, w, "pair"))
