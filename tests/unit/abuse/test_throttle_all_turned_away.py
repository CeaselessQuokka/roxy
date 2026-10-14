"""The emergency limit watch lists who it turned away, worst first (row 135, finding v1parity-6).

What this is
    Unit tests of `abuse/throttle_all.py turned_away` (and its readers `refused_clients`, `recorded_clients`,
    `throttle_all_windows`) over temporary databases: client activity rows seeded the way the recorder writes them
    (metrics.db `client_minute`) and emergency windows the way the limiter writes them (hot.db `limiter`, `tall:`).

Why it exists
    v1's "Who is being throttled right now" listed the IPs with refusals, worst first, so the brake could be judged
    and released. v2 listed the windows in force instead: a polite client with an open window was on the list and an
    abuser vanished once its window ended. These tests pin the rows (refused since the marker's minute, most first),
    the window columns (only while a window is in force), and the one case a full window lists a client by itself
    (no activity record can say otherwise: an IPv6 network key, an address not written yet).

How it works
    The fake clock fixes "now"; the marker is the start of the test. Every seeded row names its own minute.

What to read next
    `roxy/abuse/throttle_all.py`, `roxy/admin/api/protection.py _throttle_all_watch_fetch`, then
    tests/review_p11/test_v1parity.py (v1parity-6 through the real proxy and the page).
"""

from __future__ import annotations

from typing import Any

from roxy.abuse.throttle_all import (
    KEY_PREFIX,
    recorded_clients,
    refused_clients,
    throttle_all_windows,
    turned_away,
)
from roxy.core.clock import FakeClock

ABUSER, BUSY, POLITE, EARLY, QUIET = (
    "203.0.113.1",
    "203.0.113.2",
    "203.0.113.3",
    "203.0.113.4",
    "203.0.113.5",
)


def _minute(clock: FakeClock) -> int:
    now = int(clock.now())
    return now - now % 60


async def _activity(dbs: Any, *rows: tuple[int, str, int, int]) -> None:
    """Client minutes `(bucket_start, address, requests, refused)` as the recorder's flush writes them."""

    def write(conn: Any) -> None:
        for bucket, key, requests, refused in rows:
            conn.execute(
                "INSERT INTO client_minute (bucket_start, client_type, client_key, requests, refused, served, bytes, "
                "top_endpoint) VALUES (?, 'ip', ?, ?, ?, ?, 0, 'games.roblox.com/v1/games')",
                (bucket, key, requests, refused, requests - refused),
            )

    await dbs.metrics.write(write)


async def _windows(dbs: Any, clock: FakeClock, *rows: tuple[str, int, int]) -> None:
    """Emergency windows `(limit key, count, seconds left)` in force now (`checks/throttle_all.py` writes them)."""
    now_ms = clock.now_ms()

    def write(conn: Any) -> None:
        for key, count, left in rows:
            conn.execute(
                "INSERT INTO limiter (bucket_key, tat_ms, window_start, count, updated_at) VALUES (?, ?, ?, ?, ?)",
                (KEY_PREFIX + key, now_ms + left * 1000, now_ms - 1000, count, now_ms // 1000),
            )

    await dbs.hot.write(write)


async def _watch(dbs: Any, clock: FakeClock, since: float, **options: Any) -> dict[str, Any]:
    options.setdefault("limit_setting", 1)
    options.setdefault("ipv6_prefix", 64)
    return await turned_away(dbs.hot, dbs.metrics, since=since, now_ms=clock.now_ms(), **options)


async def test_the_watch_lists_who_was_turned_away_refused_most_first(dbs: Any, fake_clock: FakeClock) -> None:
    since = fake_clock.now()
    minute = _minute(fake_clock)
    await _activity(
        dbs,
        (minute, ABUSER, 4, 3),  # refused 3 times; its window has ended since
        (minute, BUSY, 6, 5),  # refused 5 times and still holding a full window
        (minute, POLITE, 1, 0),  # one request, never refused: its full window says nothing about refusals
        (minute - 120, EARLY, 9, 9),  # refused before the emergency limit was switched on
        (minute, "other", 50, 50),  # the folded row of the clients over the cap is not a client
    )
    fake_clock.advance(30)
    await _windows(dbs, fake_clock, (BUSY, 1, 30), (POLITE, 1, 30))
    watch = await _watch(dbs, fake_clock, since)
    assert watch["total"] == 2
    assert watch["rows"] == [
        {"ip": BUSY, "refused": 5, "count": 1, "limited": True, "reset_in_s": 30},
        {"ip": ABUSER, "refused": 3, "count": None, "limited": False, "reset_in_s": None},
    ]


async def test_the_readers_count_from_the_markers_minute(dbs: Any, fake_clock: FakeClock) -> None:
    since = fake_clock.now()
    minute = _minute(fake_clock)
    await _activity(dbs, (minute, ABUSER, 4, 3), (minute - 60, EARLY, 9, 9), (minute, POLITE, 1, 0))
    now = fake_clock.now() + 5
    found = await dbs.metrics.read(lambda conn: refused_clients(conn, since=since, now=now))
    assert found == [(ABUSER, 3)]
    recorded = await dbs.metrics.read(lambda conn: recorded_clients(conn, [POLITE, QUIET, EARLY], since=since, now=now))
    assert recorded == {POLITE}  # EARLY's only row is before the marker's minute; QUIET has none
    windows = await throttle_all_windows(dbs.hot, [ABUSER], now_ms=fake_clock.now_ms(), limit_setting=1)
    assert windows == {}


async def test_a_full_window_lists_a_client_only_where_no_activity_record_exists(
    dbs: Any, fake_clock: FakeClock
) -> None:
    since = fake_clock.now()
    minute = _minute(fake_clock)
    covered_net, lone_net = "2001:db8:2::/64", "2001:db8:1::/64"
    await _activity(dbs, (minute, POLITE, 1, 0), (minute, "2001:db8:2::5", 3, 2))
    await _windows(
        dbs,
        fake_clock,
        (POLITE, 1, 40),  # full, but the activity record says it was never refused
        (QUIET, 1, 40),  # full, and no activity row yet (not flushed, or folded into `other`)
        (lone_net, 1, 40),  # an IPv6 network key: activity is per address, so there is none to judge by
        (covered_net, 1, 40),  # the refused address of this network already carries the window
        ("198.51.100.9", 0, 40),  # an open window that is not full is never listed by itself
    )
    watch = await _watch(dbs, fake_clock, since)
    by_ip = {row["ip"]: row for row in watch["rows"]}
    assert set(by_ip) == {"2001:db8:2::5", QUIET, lone_net}
    address = by_ip["2001:db8:2::5"]
    assert address == {"ip": "2001:db8:2::5", "refused": 2, "count": 1, "limited": True, "reset_in_s": 40}
    assert by_ip[QUIET]["refused"] is None
    assert by_ip[QUIET]["limited"] is True
    assert by_ip[lone_net]["refused"] is None
    assert watch["rows"][0]["ip"] == "2001:db8:2::5"  # known refusals first, unknown ones last


async def test_it_sorts_by_the_window_and_pages(dbs: Any, fake_clock: FakeClock) -> None:
    since = fake_clock.now()
    minute = _minute(fake_clock)
    await _activity(dbs, (minute, ABUSER, 9, 8), (minute, BUSY, 3, 2), (minute, POLITE, 2, 1))
    await _windows(dbs, fake_clock, (BUSY, 3, 20), (POLITE, 2, 20))
    by_count = await _watch(dbs, fake_clock, since, limit_setting=3, sort="count")
    assert [row["ip"] for row in by_count["rows"]] == [BUSY, POLITE, ABUSER]  # no window sorts last
    assert [row["limited"] for row in by_count["rows"]] == [True, False, False]
    second = await _watch(dbs, fake_clock, since, limit_setting=3, limit=1, offset=1)
    assert (second["total"], [row["ip"] for row in second["rows"]]) == (3, [BUSY])
