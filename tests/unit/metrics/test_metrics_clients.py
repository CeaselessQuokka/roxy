"""Client tables: top N per type per bucket plus one `other` row, exact totals, rolled to hours and days (6.4, 6.10)."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from typing import Any

from roxy.metrics.queries import trailing_rate
from roxy.metrics.rollups import ClientCaps, ClientDelta, CompactionConfig, compact_all, write_clients

Rows = Callable[..., list[tuple[Any, ...]]]
START = 1_760_000_400  # a minute boundary (and an hour boundary: 1_760_000_400 % 3600 == 0)


def _writer(dbs: Any) -> Callable[[Callable[[sqlite3.Connection], Any]], Any]:
    async def write(fn: Callable[[sqlite3.Connection], Any]) -> Any:
        return await dbs.metrics.write(fn)

    return write


def _clients(dbs: Any, minute: int, ctype: str, counts: dict[str, int], top: str = "t") -> None:
    deltas = [ClientDelta(minute, ctype, key, n, n // 2, n - n // 2, n * 10, top) for key, n in counts.items()]
    dbs.metrics.write_sync(lambda conn: write_clients(conn, deltas))


async def test_minute_keeps_top_n_and_folds_the_rest(dbs: Any, metrics_rows: Rows) -> None:
    assert START % 3600 == 0
    ips = {f"198.51.100.{i}": i for i in range(1, 11)}  # 10 IPs, requests 1..10
    places = {str(1000 + i): 100 + i for i in range(5)}
    _clients(dbs, START, "ip", ips)
    _clients(dbs, START, "place", places)
    config = CompactionConfig(tz_name="UTC", caps=ClientCaps(ips=3, places=2))
    await compact_all(_writer(dbs), START + 7200, config)
    ip_rows = metrics_rows("SELECT client_key, requests FROM client_minute WHERE client_type = 'ip' ORDER BY requests")
    assert ip_rows == [("198.51.100.8", 8), ("198.51.100.9", 9), ("198.51.100.10", 10), ("other", 28)]
    place_rows = metrics_rows(
        "SELECT client_key, requests FROM client_minute WHERE client_type = 'place' ORDER BY requests"
    )
    assert place_rows == [("1003", 103), ("1004", 104), ("other", 100 + 101 + 102)]
    sums = metrics_rows(
        "SELECT sum(requests), sum(refused), sum(served), sum(bytes) FROM client_minute WHERE client_type = 'ip'"
    )
    assert sums == [(55, sum(n // 2 for n in ips.values()), sum(n - n // 2 for n in ips.values()), 550)]


async def test_hours_and_days_are_capped_too(dbs: Any, metrics_rows: Rows) -> None:
    # Every minute: a=1, b=2 and a minute-only client x<m>=5. Minutes are capped first (plan 6.4), so `a` is
    # folded into `other` in every minute and never reaches the hour on its own.
    for m in range(60):
        _clients(dbs, START + 60 * m, "ip", {"a": 1, "b": 2, f"x{m:02d}": 5}, top=f"e{m % 3}")
    config = CompactionConfig(tz_name="UTC", caps=ClientCaps(ips=2, places=2))
    await compact_all(_writer(dbs), START + 2 * 86_400, config)
    hour = metrics_rows(
        "SELECT client_key, requests FROM client_hour WHERE bucket_start = ? ORDER BY requests DESC", (START,)
    )
    total = 60 * (1 + 2 + 5)
    # Hour top 2: b (120) and the first of the tied x clients by key; everything else is `other`.
    assert hour == [("other", total - 120 - 5), ("b", 120), ("x00", 5)]
    assert metrics_rows("SELECT sum(requests) FROM client_day") == [(total,)]
    assert metrics_rows("SELECT count(*) FROM client_day") == [(3,)]


async def test_client_compaction_is_idempotent(dbs: Any, metrics_rows: Rows) -> None:
    _clients(dbs, START, "ip", {f"k{i}": i + 1 for i in range(8)})
    config = CompactionConfig(tz_name="UTC", caps=ClientCaps(ips=3, places=3))
    await compact_all(_writer(dbs), START + 7200, config)
    first = metrics_rows("SELECT * FROM client_minute ORDER BY 1, 2, 3")
    hours = metrics_rows("SELECT * FROM client_hour ORDER BY 1, 2, 3")
    await compact_all(_writer(dbs), START + 7260, config)
    assert metrics_rows("SELECT * FROM client_minute ORDER BY 1, 2, 3") == first
    assert metrics_rows("SELECT * FROM client_hour ORDER BY 1, 2, 3") == hours


async def test_top_endpoint_follows_the_busiest_minute(dbs: Any, metrics_rows: Rows) -> None:
    _clients(dbs, START, "ip", {"a": 3}, top="small")
    _clients(dbs, START + 60, "ip", {"a": 9}, top="big")
    await compact_all(_writer(dbs), START + 7200, CompactionConfig(tz_name="UTC"))
    assert metrics_rows("SELECT top_endpoint FROM client_hour WHERE client_key = 'a'") == [("big",)]


async def test_activity_tracking_off_skips_client_compaction(dbs: Any, metrics_rows: Rows) -> None:
    _clients(dbs, START, "ip", {"a": 1})
    report = await compact_all(_writer(dbs), START + 7200, CompactionConfig(tz_name="UTC", activity_tracking=False))
    assert "client_hour" not in report
    assert metrics_rows("SELECT count(*) FROM client_hour") == [(0,)]


def test_trailing_rate_has_no_minute_boundary_flap() -> None:
    now = START + 60 + 15  # 15 s into the minute that starts at START + 60
    per_minute = {START: 60, START + 60: 15}
    # Trailing 60 s: 45 s of the previous minute (45 requests) plus the 15 s so far (15 requests).
    assert trailing_rate(per_minute, now, 60) == 60.0
    assert trailing_rate(per_minute, now + 45, 60) == 15.0  # previous minute out of the window
    assert trailing_rate(per_minute, now, 3600) == 75.0
    assert trailing_rate({}, now, 60) == 0.0
