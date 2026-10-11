"""The spam detector timelines (gap G2, plan 10.9): `read_protection.spam_points` over the decision events.

What this is
    Unit tests of the series read model behind `GET /admin/api/v1/protection/spam/series` and the Protection page's
    timeline chart: decisions per detector per bucket, from the rows `abuse/spam.py` already records (no new write).

Why it exists
    The chart and the decisions table must count the same thing (P6): every decision event, weighted by the count a
    folded row carries, in the bucket of the window's zone it fell in, filtered like the table.

What to read next
    `roxy/metrics/read_protection.py` (`spam_points`, `spam_counts`), then `roxy/admin/api/protection.py`
    (`spam_series_answer`).
"""

from __future__ import annotations

import json
from typing import Any

from roxy.metrics import read_protection
from roxy.metrics.queries import Window

DAY = 86_400
START = 1_760_054_400  # 2025-10-10 00:00 UTC, a whole day in UTC


def _event(dbs: Any, at_s: float, kind: str, detector: str, count: int | None = None) -> None:
    detail: dict[str, Any] = {"detector": detector, "subject": "ip:203.0.113.5", "action": "ban"}
    if count is not None:
        detail["count"] = count
    dbs.metrics.write_sync(
        lambda conn: conn.execute(
            "INSERT INTO events (at_ms, type, severity, detail_json) VALUES (?, ?, 'warn', ?)",
            (int(at_s * 1000), kind, json.dumps(detail)),
        )
    )


def test_decisions_per_detector_per_bucket_with_zeros(dbs: Any) -> None:
    _event(dbs, START + 30, "spam_would_ban", "SPAM-RATE")
    _event(dbs, START + 90, "spam_would_ban", "SPAM-RATE")
    _event(dbs, START + 3_700, "spam_strike", "SPAM-PROBE", count=4)  # a row folded over the event budget
    _event(dbs, START + 3_800, "refusal", "SPAM-RATE")  # not a detector decision
    _event(dbs, START + DAY + 5, "spam_ban", "SPAM-RATE")  # outside the window
    window = Window(START, START + 4 * 3600, "hour")
    found = dbs.metrics.read_sync(lambda conn: read_protection.spam_points(conn, window))
    assert list(found["series"]) == ["SPAM-PROBE", "SPAM-RATE"]
    assert found["series"]["SPAM-RATE"] == [[START, 2], [START + 3600, 0], [START + 7200, 0], [START + 10800, 0]]
    assert found["series"]["SPAM-PROBE"][1] == [START + 3600, 4]
    assert found["totals"] == {"SPAM-PROBE": 4, "SPAM-RATE": 2}
    assert found["partial"] is False
    counts = dbs.metrics.read_sync(
        lambda conn: read_protection.spam_counts(conn, window.start * 1000, window.end * 1000)
    )
    assert {name: sum(kinds.values()) for name, kinds in counts.items()} == found["totals"]  # the table's numbers


def test_kind_and_detector_filters(dbs: Any) -> None:
    _event(dbs, START + 10, "spam_would_ban", "SPAM-RATE")
    _event(dbs, START + 20, "spam_ban", "SPAM-RATE")
    _event(dbs, START + 30, "spam_ban", "SPAM-AUTH")
    window = Window(START, START + 3600, "minute")
    bans = dbs.metrics.read_sync(lambda conn: read_protection.spam_points(conn, window, kinds=("spam_ban",)))
    assert bans["totals"] == {"SPAM-AUTH": 1, "SPAM-RATE": 1}
    rate = dbs.metrics.read_sync(lambda conn: read_protection.spam_points(conn, window, detector="SPAM-RATE"))
    assert rate["totals"] == {"SPAM-RATE": 2}
    assert len(rate["series"]["SPAM-RATE"]) == 60
    nothing = dbs.metrics.read_sync(lambda conn: read_protection.spam_points(conn, window, kinds=("refusal",)))
    assert nothing == {"series": {}, "totals": {}, "partial": False}


def test_days_fold_in_the_windows_zone(dbs: Any) -> None:
    """A half-hour zone: 23:45 UTC on day one is 05:15 local on day two (Asia/Kolkata, UTC+5:30)."""
    _event(dbs, START + DAY - 15 * 60, "spam_would_ban", "SPAM-RATE")
    local_midnight = START - 5 * 3600 - 30 * 60  # 00:00 in Kolkata on day one
    window = Window(local_midnight, local_midnight + 3 * DAY, "day", "Asia/Kolkata")
    found = dbs.metrics.read_sync(lambda conn: read_protection.spam_points(conn, window))
    assert [value for _start, value in found["series"]["SPAM-RATE"]] == [0, 1, 0]


def test_the_read_is_bounded_and_says_when_it_is_partial(dbs: Any) -> None:
    for minute in range(5):
        _event(dbs, START + minute * 60, "spam_would_ban", "SPAM-RATE")
    window = Window(START, START + 3600, "minute")
    found = dbs.metrics.read_sync(lambda conn: read_protection.spam_points(conn, window, limit=3))
    assert found["partial"] is True
    assert found["totals"]["SPAM-RATE"] == 3
