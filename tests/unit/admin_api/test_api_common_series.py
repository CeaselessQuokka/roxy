"""Chart and KPI answers (DESIGN.md section 13, plan 14.2 and 6.8): the series answer, lines from the read model,
annotations, partial data notices and KPI tiles."""

from __future__ import annotations

from typing import Any

from roxy.admin.api.common import (
    RangeParams,
    annotation_entries,
    build_time_range,
    kpi_from_read_model,
    kpi_tile,
    range_info,
    reset_notices,
    series_answer,
    series_entry,
    series_from_read_model,
)
from roxy.metrics.catalog import METRICS
from roxy.metrics.queries import Window

NOW = 1_760_000_000.0


def test_range_info_and_series_entry() -> None:
    window = Window(100, 400, "minute", "UTC")
    assert range_info(window) == {"from": 100, "to": 400, "granularity": "minute", "tz": "UTC"}
    entry = series_entry("requests", "Requests", "requests", [(100, 1), (160, None)])
    assert entry == {"key": "requests", "label": "Requests", "unit": "requests", "points": [[100, 1], [160, None]]}


def test_series_from_the_read_model() -> None:
    ungrouped = {"buckets": [0, 60, 120], "groups": {"all": {"requests": [1, 2, 3], "p95_ms": [None, 5.0, 6.0]}}}
    (line,) = series_from_read_model(ungrouped, "requests")
    assert line == {
        "key": "requests",
        "label": METRICS["requests"].label,
        "unit": "requests",
        "points": [[0, 1], [60, 2], [120, 3]],
    }
    (p95,) = series_from_read_model(ungrouped, "p95_ms", label="Latency", unit="ms")
    assert (p95["label"], p95["unit"], p95["points"][0]) == ("Latency", "ms", [0, None])
    grouped = {"buckets": [0, 60], "groups": {"GET": {"requests": [1, 1]}, "other groups": {"requests": [0, 2]}}}
    lines = series_from_read_model(grouped, "requests")
    assert [x["key"] for x in lines] == ["requests:GET", "requests:other groups"]
    assert lines[0]["label"] == f"{METRICS['requests'].label}: GET"
    unknown = series_from_read_model({"buckets": [0], "groups": {"all": {"made_up": [4]}}}, "made_up")
    assert unknown[0]["label"] == "made_up"
    assert series_from_read_model({}, "requests") == []


def test_series_answer_with_and_without_a_comparison() -> None:
    tr = build_time_range(RangeParams(range="24h", compare="week"), now=NOW, tz="UTC")
    line = series_entry("requests", "Requests", "requests", [])
    answer = series_answer(tr, [line], compare_series=[line], annotations=[{"at": 1}], notices=["n"])
    assert set(answer) == {"range", "series", "compare", "annotations", "notices"}
    assert answer["range"] == range_info(tr.window)
    assert tr.compare_window is not None
    assert answer["compare"] == {"mode": "week", "range": range_info(tr.compare_window), "series": [line]}
    plain = series_answer(build_time_range(RangeParams(range="1h"), now=NOW, tz="UTC"), [line])
    assert plain["compare"] is None
    assert plain["annotations"] == []
    assert plain["notices"] == []


def test_annotations_and_reset_notices() -> None:
    rows: list[dict[str, Any]] = [
        {"id": 1, "at": 1_760_000_000, "kind": "config", "label": "cache_ttl_seconds", "audit_id": 9}
    ]
    assert annotation_entries(rows) == [
        {"at": 1_760_000_000, "kind": "config", "label": "cache_ttl_seconds", "audit_id": 9}
    ]
    notices = reset_notices([{"at": 1_760_000_000, "label": "metrics reset"}], tz="UTC")
    assert notices == ["Partial data: counters were reset at 2025-10-09 08:53 UTC (metrics reset)."]
    assert "EDT" in reset_notices([{"at": 1_760_000_000, "label": None}], tz="America/New_York")[0]


def test_kpi_tiles() -> None:
    tile = kpi_tile(
        "requests", label="Requests", value=12, unit="requests", delta=-3, delta_pct=-20.0, good_direction="up"
    )
    assert tile == {
        "key": "requests",
        "label": "Requests",
        "value": 12,
        "unit": "requests",
        "delta": -3,
        "delta_pct": -20.0,
        "good_direction": "up",
        "sparkline": [],
        "help": "",
        "notice": None,
    }
    spec = METRICS["roblox_429"]
    expected_direction = {"higher": "up", "lower": "down", "neutral": "neutral"}[spec.better]
    from_model = kpi_from_read_model(
        "roblox_429", {"value": 4, "previous": 8, "delta": -4, "delta_pct": -50.0}, sparkline=[(0, 1)]
    )
    assert from_model["label"] == spec.label
    assert from_model["unit"] == spec.unit
    assert from_model["help"] == spec.description
    assert from_model["good_direction"] == expected_direction
    assert (from_model["value"], from_model["delta"], from_model["delta_pct"]) == (4, -4, -50.0)
    assert from_model["sparkline"] == [[0, 1]]
    bare = kpi_from_read_model("not_a_metric", {"value": 1})
    assert (bare["label"], bare["delta"], bare["good_direction"], bare["help"]) == ("not_a_metric", None, "neutral", "")
