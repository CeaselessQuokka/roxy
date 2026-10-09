"""Time range parsing for the admin API (plan 14.2, DESIGN.md section 13): every picker range, custom ranges, the
granularity override and the comparisons, built on `metrics.queries` (one implementation of windows)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from roxy.admin.api.common import (
    COMPARE_KEYS,
    GRANULARITY_KEYS,
    RANGE_KEYS,
    ApiError,
    RangeParams,
    TimeRange,
    build_time_range,
    parse_instant,
    range_params,
)
from roxy.metrics import queries
from roxy.metrics.queries import comparison_window, resolve_window

NOW = 1_760_000_000.0  # 2025-10-09T08:53:20Z
TZ = "America/New_York"


def build(**kwargs: Any) -> TimeRange:
    return build_time_range(RangeParams(**kwargs), now=NOW, tz=TZ)


def refused(**kwargs: Any) -> dict[str, str]:
    with pytest.raises(ApiError) as caught:
        build(**kwargs)
    assert caught.value.status_code == 422
    assert caught.value.error_code == "invalid_range"
    return caught.value.error_fields


def test_choices_follow_the_read_models() -> None:
    assert RANGE_KEYS == ("live", "1h", "6h", "24h", "7d", "30d", "90d", "1y", "all", "custom")
    assert GRANULARITY_KEYS == ("auto", "minute", "hour", "day", "week", "month")
    assert COMPARE_KEYS == ("none", "previous", "week", "month", "year")


@pytest.mark.parametrize("key", list(queries.RANGES), ids=lambda key: f"range_{key}")
def test_picker_ranges_are_exactly_the_read_model_windows(key: str) -> None:
    tr = build(range=key)
    assert tr.window == resolve_window(key, now=NOW, tz=TZ)
    assert tr.compare is None
    assert tr.compare_window is None


def test_live_is_fifteen_minutes_by_minute_and_default_is_24h() -> None:
    live = build(range="live")
    assert live.window.granularity == "minute"
    assert live.window.end - live.window.start in (900, 960)
    assert build().key == "24h"


def test_all_starts_at_the_oldest_data() -> None:
    earliest = NOW - 3 * 86_400
    tr = build_time_range(RangeParams(range="all"), now=NOW, tz=TZ, earliest=earliest)
    assert tr.window == resolve_window("all", now=NOW, tz=TZ, earliest=earliest)
    assert tr.window.granularity == "hour"
    empty = build_time_range(RangeParams(range="all"), now=NOW, tz=TZ, earliest=None)
    assert empty.window == resolve_window("all", now=NOW, tz=TZ, earliest=None)
    ahead = build_time_range(RangeParams(range="all"), now=NOW, tz=TZ, earliest=NOW + 600)
    assert ahead.window.start < NOW  # data stamped ahead of this clock still gives a window, not an error


def test_custom_ranges_take_iso_or_epoch_seconds() -> None:
    tr = build(range="custom", start="2025-10-01T00:00:00Z", end=str(int(NOW)))
    expected = resolve_window(None, now=NOW, tz=TZ, start=1_759_276_800, end=NOW)
    assert tr.window == expected
    assert tr.key == "custom"
    hourly = build(range="custom", start="2025-10-08", end="2025-10-09", granularity="hour")
    assert hourly.window.granularity == "hour"


def test_custom_range_mistakes_are_named_per_field() -> None:
    assert set(refused(range="custom", start="2025-10-01T00:00:00Z")) == {"to"}
    assert set(refused(range="custom")) == {"from", "to"}
    assert set(refused(range="custom", start=str(int(NOW)), end=str(int(NOW) - 60))) == {"to"}
    assert set(refused(range="custom", start="yesterday", end="today")) == {"from", "to"}
    assert set(refused(range="7d", start=str(int(NOW)))) == {"from"}
    assert set(refused(range="24h", start="1", end="2")) == {"from", "to"}


def test_unknown_choices_are_refused_together() -> None:
    fields = refused(range="2d", granularity="year", compare="decade")
    assert set(fields) == {"range", "granularity", "compare"}
    assert "24h" in fields["range"]


def test_granularity_override_and_point_cap() -> None:
    weekly = build(range="90d", granularity="week")
    assert weekly.window.granularity == "week"
    assert build(range="7d", granularity="hour").window.granularity == "hour"
    fields = refused(range="1y", granularity="minute")
    assert set(fields) == {"granularity"}
    assert str(queries.MAX_POINTS) in fields["granularity"]


@pytest.mark.parametrize("mode", ["previous", "week", "month", "year"])
def test_comparisons_use_the_read_model_comparison_window(mode: str) -> None:
    tr = build(range="7d", compare=mode)
    assert tr.compare == mode
    assert tr.compare_window == comparison_window(tr.window, mode)
    assert build(range="7d", compare="none").compare_window is None


def test_range_info_shape() -> None:
    tr = build(range="6h")
    info = tr.info()
    assert info == {"from": tr.window.start, "to": tr.window.end, "granularity": "minute", "tz": TZ}


# ================================================================================================= instants


def test_parse_instant_forms() -> None:
    assert parse_instant("1760000000", tz=TZ) == 1_760_000_000.0
    assert parse_instant(" 1760000000.25 ", tz=TZ) == 1_760_000_000.25
    assert parse_instant("2025-10-09T08:53:20Z", tz=TZ) == NOW
    assert parse_instant("2025-10-09T10:53:20+02:00", tz=TZ) == NOW
    utc_midnight = datetime(2025, 10, 9, tzinfo=UTC).timestamp()
    assert parse_instant("2025-10-09", tz="UTC") == utc_midnight
    assert parse_instant("2025-10-09", tz=TZ) == utc_midnight + 4 * 3600  # New York is UTC-4 in October
    assert parse_instant("2025-10-09T00:00:00", tz=TZ) == utc_midnight + 4 * 3600


@pytest.mark.parametrize(
    "text", ["", "   ", "yesterday", "-5", "1e9", "99999999999", "4102444801", "1960-01-01T00:00:00Z", "x" * 41]
)
def test_parse_instant_refuses(text: str) -> None:
    with pytest.raises(ValueError):
        parse_instant(text, tz=TZ)


async def test_range_params_dependency_keeps_the_raw_values() -> None:
    params = await range_params("custom", "2025-10-01", "2025-10-02", "day", "week")
    assert params == RangeParams(
        range="custom", start="2025-10-01", end="2025-10-02", granularity="day", compare="week"
    )
    assert await range_params() == RangeParams()
