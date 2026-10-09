"""Status page logic (plan 16.1): pause records, hourly states, recent failures, cooldowns, shared state trouble.

What this is
    Unit tests for `parse_pause_state`, `classify_hour`, `is_degraded`, `read_metrics`, `read_rate_limited`,
    `compute_status` and `StatusCache` in `roxy.public.pages`, against real migrated databases.

Why it exists
    `/status` must say the right one of four words: operational, degraded, paused, maintenance. It reads three
    databases written by other components, so these tests pin the reading side to the real schema and to the
    writers' own formats (`PauseState` from `roxy.abuse.pause`, the cooldown key builders of
    `roxy.upstream.cooldowns`), and check that unreadable shared state shows as degraded (plan C7) instead of a
    500. The metrics read must stay cheap however the compacted hours are spread over the day.

How it works
    The `dbs` fixture gives migrated databases; `seed` (tests/unit/public/conftest.py) writes dims and rollup
    rows; a tiny stand-in context carries the databases and a fake clock. `RecordingConnection` notes every
    statement `read_metrics` runs, so a test can see how far back the minute table is scanned.

What to read next
    `roxy/public/pages.py` (section "status"), plan 6.2 (`service_state`, rollups, `cooldown`).
"""

from __future__ import annotations

import dataclasses
import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import pytest

from roxy.abuse.pause import PauseState
from roxy.core.clock import FakeClock
from roxy.core.reasons import Egress
from roxy.egress.rotator import PARK_KEY
from roxy.public.pages import (
    HOUR_NO_DATA,
    HOURS_SHOWN,
    PAUSE_STATE_KEY,
    STATUS_CACHE_S,
    SiteState,
    StatusCache,
    Tally,
    classify_hour,
    compute_status,
    is_degraded,
    parse_pause_state,
    parse_throttle_all,
    read_metrics,
    read_rate_limited,
)
from roxy.upstream.cooldowns import CREDENTIAL_KEY, CooldownSource, egress_key, endpoint_key, host_key

NOW = 1_760_000_400.0 + 1800  # half past a clock hour (1_760_000_400 is a multiple of 3600)
HOUR = int(NOW // 3600) * 3600


@dataclass
class StubCtx:
    dbs: Any
    clock: Any = None
    ready: bool = True
    egress: Any = None


# --- pause record -------------------------------------------------------------------------------------------------


def stored(**fields: Any) -> str:
    """A pause record exactly as `roxy.abuse.pause` stores it (`PauseState.to_json`)."""
    return json.dumps(dataclasses.replace(PauseState(), **fields).to_json())


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        ("", None),
        ("not json", None),
        ("[1, 2]", None),
        ('{"since": "garbage"}', None),
        (stored(), None),
        (stored(paused=True, reason="x", since=NOW - 30), SiteState.PAUSED),
        (stored(paused=False, since=NOW - 30), None),  # the marker of an earlier pause stays behind
        (stored(scheduled_start=int(NOW) - 60, scheduled_end=int(NOW) + 60), SiteState.MAINTENANCE),
        (stored(scheduled_start=int(NOW) + 60, scheduled_end=int(NOW) + 120), None),
        (stored(scheduled_start=int(NOW) - 120, scheduled_end=int(NOW) - 60), None),
        # The proxy refuses with the manual pause's message while both apply, so the page says paused too.
        (stored(paused=True, scheduled_start=int(NOW) - 60, scheduled_end=int(NOW) + 60), SiteState.PAUSED),
    ],
)
def test_parse_pause_state(value: str | None, expected: SiteState | None) -> None:
    assert parse_pause_state(value, NOW) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, False),
        ("", False),
        ("not json", False),
        ("[1]", False),
        ('{"enabled": false, "since": 0}', False),
        ('{"enabled": true, "reason": "incident", "since": 1760000000}', True),
        ('{"enabled": true, "since": "garbage"}', False),  # unreadable: the proxy's own check decides, not the page
    ],
)
def test_parse_throttle_all(value: str | None, expected: bool) -> None:
    assert parse_throttle_all(value) is expected


def test_parse_pause_state_agrees_with_the_proxy_pause_check() -> None:
    """Paused or maintenance exactly when `PauseState.active` makes the proxy answer 503 (one owner, one rule)."""
    for state in (
        PauseState(),
        PauseState(paused=True),
        PauseState(scheduled_start=int(NOW) - 1, scheduled_end=int(NOW) + 1),
        PauseState(scheduled_start=int(NOW), scheduled_end=int(NOW)),
        PauseState(scheduled_start=int(NOW) + 1, scheduled_end=int(NOW) + 9),
    ):
        assert (parse_pause_state(json.dumps(state.to_json()), NOW) is not None) == state.active(NOW), state


# --- hour and window classification -------------------------------------------------------------------------------


def test_classify_hour() -> None:
    assert classify_hour(None) == HOUR_NO_DATA
    assert classify_hour(Tally()) == HOUR_NO_DATA
    assert classify_hour(Tally(total=100)) == "operational"
    assert classify_hour(Tally(total=100, refused=60, paused=60)) == "paused"
    assert classify_hour(Tally(total=100, refused=40, paused=40)) == "operational"
    assert classify_hour(Tally(total=100, failed=10)) == "degraded"
    assert classify_hour(Tally(total=100, failed=9)) == "operational"


def test_is_degraded_ignores_refusals_and_small_samples() -> None:
    assert not is_degraded(Tally(total=10, failed=10))  # too few to judge
    assert is_degraded(Tally(total=20, failed=2))
    assert not is_degraded(Tally(total=1000, refused=900, failed=9))  # 9 of 100 answered
    assert is_degraded(Tally(total=1000, refused=900, failed=10))


def test_tally_addition() -> None:
    assert Tally(1, 2, 3, 4) + Tally(10, 20, 30, 40) == Tally(11, 22, 33, 44)


# --- reading the databases ----------------------------------------------------------------------------------------


def test_read_metrics_hour_table_then_minutes(dbs: Any, seed: Callable[..., None]) -> None:
    def write(conn: sqlite3.Connection) -> None:
        # Two old hours are compacted into rollup_hour; the minute table still holds the same data (ignored).
        seed(conn, "rollup_hour", HOUR - 3 * 3600, "served_upstream", "upstream_ok", 100)
        seed(conn, "rollup_minute", HOUR - 3 * 3600 + 60, "served_upstream", "upstream_ok", 999)
        seed(conn, "rollup_hour", HOUR - 2 * 3600, "refused", "paused", 80)
        seed(conn, "rollup_hour", HOUR - 2 * 3600, "served_cache", "cache_hit", 20)
        # The previous and current hours exist only as minutes.
        seed(conn, "rollup_minute", HOUR - 3600 + 120, "failed", "upstream_5xx", 30)
        seed(conn, "rollup_minute", HOUR - 3600 + 180, "served_upstream", "upstream_ok", 70)
        seed(conn, "rollup_minute", HOUR + 60, "served_cache", "cache_hit", 5)
        seed(conn, "rollup_minute", int(NOW) - 120, "failed", "upstream_timeout", 25)
        # Older than the 24 hour window: never read.
        seed(conn, "rollup_hour", HOUR - 30 * 3600, "failed", "upstream_5xx", 500)

    dbs.metrics.write_sync(write)
    hours, recent = dbs.metrics.read_sync(lambda conn: read_metrics(conn, NOW))
    assert hours[HOUR - 3 * 3600] == Tally(total=100)
    assert hours[HOUR - 2 * 3600] == Tally(total=100, refused=80, paused=80)
    assert hours[HOUR - 3600] == Tally(total=100, failed=30)
    assert hours[HOUR] == Tally(total=30, failed=25)
    assert HOUR - 30 * 3600 not in hours
    assert recent == Tally(total=25, failed=25)  # only the last 10 minutes
    assert classify_hour(hours[HOUR - 2 * 3600]) == "paused"
    assert classify_hour(hours[HOUR - 3600]) == "degraded"


def _cooldown(dbs: Any, key: str, until_ms: int, source: str = CooldownSource.RETRY_AFTER) -> None:
    dbs.hot.write_sync(
        lambda conn: conn.execute(
            "INSERT INTO cooldown (key, until_ms, source, set_at, hits) VALUES (?, ?, ?, ?, 1) "
            "ON CONFLICT (key) DO UPDATE SET until_ms = excluded.until_ms, source = excluded.source",
            (key, until_ms, str(source), int(NOW)),
        )
    )


def _rate_limited(dbs: Any) -> bool:
    result: bool = dbs.hot.read_sync(lambda conn: read_rate_limited(conn, NOW))
    return result


TEMPLATE = "games.roblox.com/v1/games"


def test_read_rate_limited_ignores_expired_rows(dbs: Any) -> None:
    now_ms = int(NOW * 1000)
    assert _rate_limited(dbs) is False
    _cooldown(dbs, endpoint_key(TEMPLATE, Egress.DIRECT), now_ms - 1)
    assert _rate_limited(dbs) is False
    _cooldown(dbs, endpoint_key(TEMPLATE, Egress.DIRECT), now_ms + 30_000)
    assert _rate_limited(dbs) is True


@pytest.mark.parametrize(
    ("key", "source"),
    [
        # The credential serves only Roxy's own probes (owner decision D1): its cooldowns say nothing to callers.
        (CREDENTIAL_KEY, CooldownSource.RETRY_AFTER),
        (egress_key(Egress.CREDENTIAL), CooldownSource.RETRY_AFTER),
        (host_key("users.roblox.com", Egress.CREDENTIAL), CooldownSource.RATELIMIT_RESET),
        (endpoint_key("users.roblox.com/v1/users/{id}", Egress.CREDENTIAL), CooldownSource.DEFAULT),
        # A parked rotator or an open breaker is Roxy resting a path after failures, not Roblox asking to slow down.
        (PARK_KEY, CooldownSource.BREAKER),
        (host_key("games.roblox.com", Egress.DIRECT), CooldownSource.BREAKER),
    ],
)
def test_rate_limit_note_ignores_rows_that_are_not_roblox_limiting_callers(
    dbs: Any, key: str, source: CooldownSource
) -> None:
    _cooldown(dbs, key, int(NOW * 1000) + 600_000, source)
    assert _rate_limited(dbs) is False


@pytest.mark.parametrize(
    ("key", "source"),
    [
        (endpoint_key(TEMPLATE, Egress.DIRECT), CooldownSource.RETRY_AFTER),
        (endpoint_key(TEMPLATE, Egress.ROTATOR), CooldownSource.DEFAULT),  # a 429 without a Retry-After header
        (host_key("games.roblox.com", Egress.DIRECT), CooldownSource.RATELIMIT_RESET),
        (egress_key(Egress.ROTATOR), CooldownSource.RETRY_AFTER),
    ],
)
def test_rate_limit_note_shows_roblox_limiting_caller_paths(dbs: Any, key: str, source: CooldownSource) -> None:
    _cooldown(dbs, key, int(NOW * 1000) + 600_000, source)
    assert _rate_limited(dbs) is True


class RecordingConnection:
    """Forwards to a real connection and remembers every statement and its parameters."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        self.calls: list[tuple[str, tuple[Any, ...]]] = []

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        self.calls.append((sql, tuple(params)))
        return self.conn.execute(sql, params)


def test_read_metrics_scans_minutes_only_after_the_newest_compacted_hour(dbs: Any, seed: Callable[..., None]) -> None:
    """An idle hour early in the window must not make the page scan a day of minute rows (review finding 7)."""
    first_hour = HOUR - (HOURS_SHOWN - 1) * 3600

    def write(conn: sqlite3.Connection) -> None:
        # The first hour of the window was idle (no row anywhere); every later closed hour is compacted.
        for hour in range(first_hour + 3600, HOUR, 3600):
            seed(conn, "rollup_hour", hour, "served_upstream", "upstream_ok", 10)
            seed(conn, "rollup_minute", hour + 60, "served_upstream", "upstream_ok", 10)
        seed(conn, "rollup_minute", HOUR + 120, "failed", "upstream_5xx", 7)

    dbs.metrics.write_sync(write)

    def read(conn: sqlite3.Connection) -> Any:
        recording = RecordingConnection(conn)
        return read_metrics(recording, NOW), recording.calls  # type: ignore[arg-type]

    (hours, recent), calls = dbs.metrics.read_sync(read)
    minute_scans = [params for sql, params in calls if "FROM rollup_minute" in sql and "GROUP BY" in sql]
    assert minute_scans == [(HOUR, HOUR + 3600)]  # only the hour that is not compacted yet
    assert first_hour not in hours
    assert hours[HOUR - 3600] == Tally(total=10)
    assert hours[HOUR] == Tally(total=7, failed=7)
    assert len(hours) == HOURS_SHOWN - 1
    assert recent == Tally()  # nothing in the last 10 minutes (the failures were 28 minutes ago)


# --- compute_status -----------------------------------------------------------------------------------------------


def _set_pause(dbs: Any, **fields: Any) -> None:
    """Store a pause record in the format of `roxy.abuse.pause` (fields of `PauseState`)."""
    dbs.control.write_sync(
        lambda conn: conn.execute(
            "INSERT INTO service_state (key, value_json, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT (key) DO UPDATE SET value_json = excluded.value_json",
            (PAUSE_STATE_KEY, stored(**fields), int(NOW)),
        )
    )


async def test_compute_status_operational_by_default(dbs: Any) -> None:
    view = await compute_status(StubCtx(dbs), NOW)
    assert view.state is SiteState.OPERATIONAL
    assert len(view.hours) == HOURS_SHOWN
    assert view.hours[-1].start == HOUR
    assert view.hours[0].start == HOUR - (HOURS_SHOWN - 1) * 3600
    assert all(cell.state == HOUR_NO_DATA for cell in view.hours)
    assert view.rate_limited is False
    assert view.label == "Operational"


async def test_compute_status_paused_and_maintenance(dbs: Any) -> None:
    _set_pause(dbs, paused=True, reason="deploy", since=NOW - 30)
    assert (await compute_status(StubCtx(dbs), NOW)).state is SiteState.PAUSED
    _set_pause(dbs, scheduled_start=int(NOW) - 30, scheduled_end=int(NOW) + 600, scheduled_reason="x")
    assert (await compute_status(StubCtx(dbs), NOW)).state is SiteState.MAINTENANCE
    _set_pause(dbs)
    assert (await compute_status(StubCtx(dbs), NOW)).state is SiteState.OPERATIONAL


async def test_compute_status_degraded_by_recent_failures(dbs: Any, seed: Callable[..., None]) -> None:
    dbs.metrics.write_sync(lambda conn: seed(conn, "rollup_minute", int(NOW) - 60, "failed", "upstream_5xx", 40))
    dbs.metrics.write_sync(
        lambda conn: seed(conn, "rollup_minute", int(NOW) - 60, "served_upstream", "upstream_ok", 60)
    )
    view = await compute_status(StubCtx(dbs), NOW)
    assert view.state is SiteState.DEGRADED
    assert view.hours[-1].state == "degraded"


def _set_throttle_all(dbs: Any, enabled: bool) -> None:
    """Store a throttle-all record in the format of `roxy.abuse.throttle_all` (`ThrottleAllState.to_json`)."""
    from roxy.abuse.throttle_all import STATE_KEY, ThrottleAllState

    value = json.dumps(ThrottleAllState(enabled=enabled, reason="x", since=NOW if enabled else 0.0).to_json())
    dbs.control.write_sync(
        lambda conn: conn.execute(
            "INSERT INTO service_state (key, value_json, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT (key) DO UPDATE SET value_json = excluded.value_json",
            (STATE_KEY, value, int(NOW)),
        )
    )


async def test_throttle_all_makes_the_status_degraded_and_says_so(dbs: Any) -> None:
    """Review finding public-3: while the emergency limit refuses every caller, the page is not "operational"."""
    _set_throttle_all(dbs, True)
    view = await compute_status(StubCtx(dbs), NOW)
    assert view.state is SiteState.DEGRADED
    assert view.emergency_limit is True
    _set_pause(dbs, paused=True)  # a pause still wins: the proxy answers 503 before throttle-all refuses
    paused = await compute_status(StubCtx(dbs), NOW)
    assert paused.state is SiteState.PAUSED
    assert paused.emergency_limit is True
    _set_pause(dbs)
    _set_throttle_all(dbs, False)
    view = await compute_status(StubCtx(dbs), NOW)
    assert view.state is SiteState.OPERATIONAL
    assert view.emergency_limit is False


async def test_pause_wins_over_degraded(dbs: Any, seed: Callable[..., None]) -> None:
    dbs.metrics.write_sync(lambda conn: seed(conn, "rollup_minute", int(NOW) - 60, "failed", "upstream_5xx", 100))
    _set_pause(dbs, paused=True)
    assert (await compute_status(StubCtx(dbs), NOW)).state is SiteState.PAUSED


async def test_compute_status_degraded_when_not_ready_or_no_egress(dbs: Any) -> None:
    assert (await compute_status(StubCtx(dbs, ready=False), NOW)).state is SiteState.DEGRADED
    assert (await compute_status(None, NOW)).state is SiteState.DEGRADED

    class NoEgress:
        def is_enabled(self, egress: Egress) -> tuple[bool, str]:
            return False, "disabled by admin"

    class RotatorOnly:
        def is_enabled(self, egress: Egress) -> tuple[bool, str]:
            return egress is Egress.ROTATOR, ""

    assert (await compute_status(StubCtx(dbs, egress=NoEgress()), NOW)).state is SiteState.DEGRADED
    assert (await compute_status(StubCtx(dbs, egress=RotatorOnly()), NOW)).state is SiteState.OPERATIONAL


async def test_unreadable_shared_state_is_degraded_not_an_error(dbs: Any) -> None:
    class Broken:
        async def read(self, fn: Any) -> Any:
            raise RuntimeError("database is locked")

    class BrokenDbs:
        control = Broken()
        hot = Broken()
        metrics = Broken()

    view = await compute_status(StubCtx(BrokenDbs()), NOW)
    assert view.state is SiteState.DEGRADED
    assert view.rate_limited is None
    assert all(cell.state == HOUR_NO_DATA for cell in view.hours)

    class MetricsOnlyBroken:
        control = dbs.control
        hot = dbs.hot
        metrics = Broken()

    # Metrics may degrade open (plan C7): losing the history does not make Roxy itself degraded.
    assert (await compute_status(StubCtx(MetricsOnlyBroken()), NOW)).state is SiteState.OPERATIONAL


async def test_status_cache_reuses_a_view_for_a_few_seconds(dbs: Any) -> None:
    clock = FakeClock(start=NOW)
    ctx = StubCtx(dbs, clock=clock)
    cache = StatusCache()
    first = await cache.get(ctx)
    _set_pause(dbs, paused=True)
    assert await cache.get(ctx) is first  # still cached
    clock.advance(STATUS_CACHE_S + 0.5)
    second = await cache.get(ctx)
    assert second is not first
    assert second.state is SiteState.PAUSED


def test_hour_cell_labels_have_no_counts() -> None:
    from roxy.public.pages import HourCell

    cell = HourCell(HOUR, "operational")
    assert cell.label.endswith(" UTC")
    assert cell.text == "Operational"
