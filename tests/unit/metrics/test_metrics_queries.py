"""Read models: windows and granularity, series across levels, KPIs with honest numbers, paged top-N (14.2, P6)."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

import pytest

from roxy.core.clock import FakeClock
from roxy.core.reasons import CacheState, Egress, Outcome, ReasonCode, Source
from roxy.metrics import queries as q
from roxy.metrics.recorder import MetricsRecorder, OutcomeEvent
from roxy.metrics.rollups import CompactionConfig, compact_all

NY = "America/New_York"
Make = Callable[..., OutcomeEvent]


def _ts(text: str, tz: str = "UTC") -> int:
    return int(datetime.fromisoformat(text).replace(tzinfo=ZoneInfo(tz)).timestamp())


def _writer(dbs: Any) -> Callable[[Callable[[sqlite3.Connection], Any]], Any]:
    async def write(fn: Callable[[sqlite3.Connection], Any]) -> Any:
        return await dbs.metrics.write(fn)

    return write


# ------------------------------------------------------------------------------------------------ windows


@pytest.mark.parametrize(
    ("span", "unit"),
    [
        (900, "minute"),
        (86_400, "minute"),
        (86_401, "hour"),
        (30 * 86_400, "hour"),
        (90 * 86_400, "day"),
        (365 * 86_400, "day"),
        (400 * 86_400, "month"),
    ],
)
def test_auto_granularity(span: int, unit: str) -> None:
    assert q.auto_granularity(span) == unit


def test_resolve_window_aligns_and_includes_the_open_bucket() -> None:
    now = _ts("2025-10-09T10:17:30")
    w = q.resolve_window("1h", now=now)
    assert (w.start, w.end, w.granularity) == (_ts("2025-10-09T09:17:00"), _ts("2025-10-09T10:18:00"), "minute")
    d = q.resolve_window("90d", now=now, tz=NY)
    assert d.granularity == "day"
    assert datetime.fromtimestamp(d.start, ZoneInfo(NY)).hour == 0
    custom = q.resolve_window(None, now=now, start=now - 7200, end=now - 3600, granularity="hour")
    assert (custom.start, custom.end) == (_ts("2025-10-09T08:00:00"), _ts("2025-10-09T10:00:00"))
    with pytest.raises(ValueError):
        q.resolve_window("2w", now=now)
    with pytest.raises(ValueError):
        q.resolve_window(None, now=now, start=now, end=now - 1)
    assert q.resolve_window("all", now=now, earliest=now - 400 * 86_400).granularity == "month"


def test_comparison_windows() -> None:
    w = q.Window(_ts("2025-10-09T00:00:00"), _ts("2025-10-10T00:00:00"), "hour")
    assert q.comparison_window(w, "previous") == q.Window(w.start - 86_400, w.start, "hour")
    assert q.comparison_window(w, "week").start == w.start - 7 * 86_400
    assert q.comparison_window(w, "month").start == _ts("2025-09-09T00:00:00")
    assert q.comparison_window(w, "year").start == _ts("2024-10-09T00:00:00")
    with pytest.raises(ValueError):
        q.comparison_window(w, "decade")


def test_bucket_starts_follow_dst_and_are_bounded() -> None:
    w = q.Window(_ts("2025-11-01T00:00:00", NY), _ts("2025-11-04T00:00:00", NY), "day", NY)
    starts = q.bucket_starts(w)
    assert [b2 - b1 for b1, b2 in zip(starts, [*starts[1:], w.end], strict=True)] == [86_400, 90_000, 86_400]
    with pytest.raises(ValueError):
        q.bucket_starts(q.Window(0, 10**9, "minute"))


def test_filters_are_whitelisted(dbs: Any) -> None:
    w = q.Window(0, 60, "minute")
    with pytest.raises(ValueError):
        dbs.metrics.read_sync(lambda c: q.collect(c, w, filters={"dim_hash; DROP TABLE dims": 1}))
    with pytest.raises(ValueError):
        dbs.metrics.read_sync(lambda c: q.collect(c, w, group_by="client_key"))
    with pytest.raises(ValueError):
        dbs.metrics.read_sync(lambda c: q.collect(c, w, filters={"status_class": "6xx"}))


# --------------------------------------------------------------------------------- honest numbers (P6)


async def _scenario(recorder: MetricsRecorder, make_event: Make, presets: dict[str, Any]) -> None:
    """10 misses (1 upstream call each, 2 with a CSRF retry), 30 cache hits, 5 stale after failure, 7 refusals,
    1 OPTIONS answered locally, 2 background refreshes (3 calls), 4 internal probes, 6 Roblox 429s."""
    for i in range(10):
        recorder.record_outcome(make_event(upstream_calls=2 if i < 2 else 1, latency_ms=100.0 + i))
    for _ in range(30):
        recorder.record_outcome(make_event(**presets["cache_hit"], latency_ms=2.0))
    for _ in range(5):
        recorder.record_outcome(
            make_event(
                outcome=Outcome.SERVED_CACHE,
                reason=ReasonCode.CACHE_STALE_ERROR,
                cache_state=CacheState.STALE,
                source=Source.CACHE,
                upstream_calls=1,
                error=True,
            )
        )
    for _ in range(7):
        recorder.record_outcome(make_event(**presets["refused"]))
    recorder.record_outcome(
        make_event(
            outcome=Outcome.SERVED_CACHE,
            reason=ReasonCode.OPTIONS_LOCAL,
            method="OPTIONS",
            status=204,
            upstream_calls=0,
            source=Source.ROXY,
            cache_state=CacheState.NA,
        )
    )
    recorder.record_background_fetch(endpoint_template=presets["template"], host="games.roblox.com", calls=2)
    recorder.record_background_fetch(endpoint_template=presets["template"], host="games.roblox.com", calls=1)
    for _ in range(4):
        recorder.record_internal_call(
            "token_check",
            ok=True,
            status=200,
            host="accountinformation.roblox.com",
            endpoint_template="accountinformation.roblox.com/v1/birthdate",
        )
    for _ in range(6):
        recorder.record_upstream_429(
            endpoint_template=presets["template"], host="games.roblox.com", egress=Egress.DIRECT
        )
    recorder.close()


async def test_avoided_calls_are_honest(
    recorder: MetricsRecorder, make_event: Make, presets: dict[str, Any], fake_clock: FakeClock
) -> None:
    await _scenario(recorder, make_event, presets)
    w = q.resolve_window("1h", now=fake_clock.now())
    totals = recorder.dbs.metrics.read_sync(lambda c: q.totals_sync(c, w))
    assert totals["requests"] == 10 + 30 + 5 + 7 + 1
    assert totals["demand"] == 10 + 30 + 5  # refusals and the local OPTIONS answer are not demand
    caller_calls = 12 + 5 + 3  # misses with retries, stale-after-failure attempts, background refreshes
    assert totals["upstream_calls"] == caller_calls
    assert totals["internal_calls"] == 4  # probes reported separately
    assert totals["avoided"] == 45 - caller_calls
    assert totals["avoided_pct"] == round((45 - caller_calls) * 100 / 45, 2)
    assert totals["errors_hidden"] == 5
    assert totals["roblox_429"] == 6
    assert totals["roblox_429_per_10k"] == round(6 * 10_000 / 45, 2)
    assert totals["roxy_429"] == 7
    assert totals["hit_ratio"] == round((30 + 5) / (30 + 5 + 10), 4)
    assert totals["p50_ms"] is not None


async def test_kpis_compare_and_reset_notice(
    recorder: MetricsRecorder, make_event: Make, presets: dict[str, Any], fake_clock: FakeClock
) -> None:
    for _ in range(4):
        recorder.record_outcome(make_event())
    recorder.close()
    fake_clock.advance(3660)  # past the minute the 1 h window starts in
    for _ in range(6):
        recorder.record_outcome(make_event())
    recorder.close()
    now = fake_clock.now()
    recorder.dbs.metrics.write_sync(
        lambda c: c.execute(
            "INSERT INTO annotations (at, kind, label) VALUES (?, 'reset', 'traffic reset')", (int(now) - 10,)
        )
    )
    w = q.resolve_window("1h", now=now)
    result = recorder.dbs.metrics.read_sync(lambda c: q.kpis_sync(c, w, now=now, compare="previous"))
    tile = result["tiles"]["requests"]
    assert tile["value"] == 6
    assert tile["previous"] == 4
    assert tile["delta"] == 2
    assert tile["delta_pct"] == 50.0
    assert result["tiles"]["requests_last_hour"]["value"] == 6
    assert [n["label"] for n in result["notices"]] == ["traffic reset"]


# ------------------------------------------------------------------------------------------ level union


async def test_series_reads_compacted_levels_plus_the_tail(
    recorder: MetricsRecorder, make_event: Make, fake_clock: FakeClock, presets: dict[str, Any]
) -> None:
    fake_clock.set(_ts("2025-10-07T00:00:00", NY))
    expected = 0
    for _hour in range(3 * 24):
        for _ in range(3):
            recorder.record_outcome(make_event(at_ms=fake_clock.now_ms()))
            expected += 1
        recorder.record_outcome(make_event(at_ms=fake_clock.now_ms(), **presets["refused"]))
        expected += 1
        fake_clock.advance(3600)
    recorder.close()
    now = fake_clock.now()
    # Compact everything but the last few hours, so the series must combine days, hours and minutes.
    await compact_all(_writer(recorder.dbs), now - 5 * 3600, CompactionConfig(tz_name=NY, max_buckets=500))
    days = recorder.dbs.metrics.read_sync(lambda c: c.execute("SELECT count(*) FROM rollup_day").fetchone()[0])
    assert days >= 2
    for granularity in ("hour", "day", "week", "month"):
        w = q.resolve_window(
            None, now=now, start=_ts("2025-10-01T00:00:00", NY), end=now + 1, granularity=granularity, tz=NY
        )

        def chart(conn: sqlite3.Connection, w: q.Window = w) -> dict[str, Any]:
            return q.series_sync(conn, w, metrics=["requests", "refused"])

        s = recorder.dbs.metrics.read_sync(chart)
        assert sum(s["groups"]["all"]["requests"]) == expected, granularity
        assert sum(s["groups"]["all"]["refused"]) == expected // 4, granularity
    by_outcome = recorder.dbs.metrics.read_sync(
        lambda c: q.series_sync(c, q.resolve_window("7d", now=now, tz=NY), group_by="outcome", max_groups=1)
    )
    assert set(by_outcome["groups"]) == {"served_upstream", "other groups"}


async def test_top_n_pages_and_sorts_on_the_server(
    recorder: MetricsRecorder, make_event: Make, fake_clock: FakeClock
) -> None:
    for i in range(12):
        for _ in range(i + 1):
            recorder.record_outcome(make_event(endpoint_template=f"games.roblox.com/v1/e{i:02d}", latency_ms=10.0 * i))
    recorder.record_upstream_429(endpoint_template="games.roblox.com/v1/e03", host="games.roblox.com", egress="direct")
    recorder.close()
    w = q.resolve_window("1h", now=fake_clock.now())
    page1 = recorder.dbs.metrics.read_sync(lambda c: q.top_n_sync(c, w, "endpoint_template", page=q.Page(size=10)))
    assert page1["total"] == 12
    assert [r["requests"] for r in page1["rows"]] == list(range(12, 2, -1))
    page2 = recorder.dbs.metrics.read_sync(
        lambda c: q.top_n_sync(c, w, "endpoint_template", page=q.Page(page=2, size=10))
    )
    assert [r["requests"] for r in page2["rows"]] == [2, 1]
    asc = recorder.dbs.metrics.read_sync(
        lambda c: q.top_n_sync(c, w, "endpoint_template", page=q.Page(sort="p95_ms", descending=False, size=10))
    )
    assert asc["rows"][0]["key"] == "games.roblox.com/v1/e00"
    found = recorder.dbs.metrics.read_sync(lambda c: q.endpoint_table_sync(c, w, page=q.Page(search="e03", size=10)))
    assert found["total"] == 1
    assert found["rows"][0]["roblox_429"] == 1
    by_outcome = recorder.dbs.metrics.read_sync(lambda c: q.top_n_sync(c, w, "outcome"))
    assert by_outcome["rows"][0]["roblox_429"] is None  # the 429 log has no outcome: unknown, not zero
    with pytest.raises(ValueError):
        q.Page(size=7).checked()
    with pytest.raises(ValueError):
        q.Page(sort="dim_hash").checked()


async def test_client_table_with_rates(
    recorder: MetricsRecorder, make_event: Make, fake_clock: FakeClock, presets: dict[str, Any]
) -> None:
    for ip, n in (("198.51.100.1", 5), ("198.51.100.2", 2)):
        for _ in range(n):
            recorder.record_outcome(make_event(client_ip=ip))
    recorder.record_outcome(make_event(client_ip="198.51.100.2", **presets["refused"]))
    recorder.close()
    now = fake_clock.now() + 30
    w = q.resolve_window("24h", now=now)
    table = recorder.dbs.metrics.read_sync(lambda c: q.client_table_sync(c, w, "ip", now=now))
    assert [(r["key"], r["requests"], r["refused"]) for r in table["rows"]] == [
        ("198.51.100.1", 5, 0),
        ("198.51.100.2", 3, 1),
    ]
    assert table["rows"][0]["rate60"] == 5.0
    places = recorder.dbs.metrics.read_sync(lambda c: q.client_table_sync(c, w, "place", now=now))
    assert places["rows"][0]["requests"] == 8
    search = recorder.dbs.metrics.read_sync(
        lambda c: q.client_table_sync(c, w, "ip", now=now, page=q.Page(search=".2", sort="requests"))
    )
    assert search["total"] == 1


# ------------------------------------------------------------------------------------------- small views


async def test_drops_since_refusal_reasons_retries_visitors(
    recorder: MetricsRecorder, make_event: Make, fake_clock: FakeClock, presets: dict[str, Any]
) -> None:
    paused = {**presets["refused"], "reason": ReasonCode.PAUSED, "status": 503}
    since = fake_clock.now()
    for _ in range(3):
        recorder.record_outcome(make_event(message_source="custom", **paused))
    recorder.record_outcome(make_event(message_source="default", **presets["refused"]))
    recorder.record_retry(status=403, reason="CSRF token refresh", egress=Egress.DIRECT)
    recorder.record_retry(status=403, reason="CSRF token refresh", egress=Egress.ROTATOR)
    recorder.record_visit("home", "Mozilla/5.0")
    recorder.record_visit("home", "curl/8")
    recorder.record_visit("robots", "Googlebot")
    recorder.record_visit("admin", "Mozilla/5.0")
    recorder.record_admin_visit_discount()
    recorder.record_admin_visit_discount()
    recorder.close()
    now = fake_clock.now() + 1
    w = q.resolve_window("1h", now=now)
    read = recorder.dbs.metrics.read_sync
    assert read(lambda c: q.drops_since(c, "paused", since, now)) == 3
    reasons = read(lambda c: q.refusal_reasons(c, w))
    assert reasons[0] == {"reason": "paused", "requests": 3, "message_source": {"custom": 3}}
    assert reasons[1]["message_source"] == {"default": 1}
    retries = read(lambda c: q.retry_stats(c, w))
    assert retries["total"] == 2
    assert retries["by_reason"] == {"CSRF token refresh": 2}
    assert retries["by_egress"] == {"direct": 1, "rotator": 1}
    visits = read(lambda c: q.visitor_kpis(c, w))
    assert visits["human_visitors"] == 1
    assert visits["crawler_visitors"] == 1
    assert visits["robots_crawls"] == 1
    assert visits["admin_visits"] == 0  # clamped at zero like v1


async def test_misc_read_models(
    recorder: MetricsRecorder, make_event: Make, presets: dict[str, Any], fake_clock: FakeClock
) -> None:
    await _scenario(recorder, make_event, presets)
    recorder.record_egress_usage(Egress.ROTATOR, req_bytes=10, resp_bytes=20, overhead_bytes=30)
    recorder.record_error("RuntimeError: x", detail="d")
    recorder.close()
    now = fake_clock.now() + 1
    w = q.resolve_window("1h", now=now)
    read = recorder.dbs.metrics.read_sync
    calls = read(lambda c: q.internal_calls(c, w))
    assert calls[0]["purpose"] == "token_check"
    assert calls[0]["count"] == 4
    assert len(read(lambda c: q.recent_429s(c, 3))) == 3
    assert read(lambda c: q.egress_bytes(c, w)) == {"rotator": 60}
    usage = read(lambda c: q.egress_usage_series(c, w))
    assert sum(usage["egress"]["rotator"]["bytes"]) == 60
    assert read(lambda c: q.dims_per_minute(c, w.start, w.end)) is not None
    assert read(lambda c: q.earliest_data(c)) is not None
    assert read(lambda c: q.errors_table(c))["total"] == 1
    summary = read(lambda c: q.llm_rollup_summary(c, w))
    assert sum(item["requests"] for item in summary) == 53
    assert sum(sum(item["roblox_429_by_egress"].values()) for item in summary) == 6
    top = read(lambda c: q.llm_top_endpoints(c, w))
    assert top["by_requests"][0]["key"] == presets["template"]
    recent = read(lambda c: q.endpoint_recent(c, presets["template"], 3))
    assert len(recent) == 3
    assert read(lambda c: q.top_values(c, "endpoint_template", now - 3600, now, 5))[0] == presets["template"]
