"""Spam detectors (plan 10.3, 15.3 E2): fire on abusive fixtures, stay quiet on legitimate ones, act once fleet-wide."""

from __future__ import annotations

from typing import Any

import pytest
from abuse_support import FakeSettings

from roxy.abuse.bans import escalated_minutes
from roxy.abuse.spam import SpamDetectors, bucket_size, evaluate_row
from roxy.abuse.throttle import load_strike_rows
from roxy.config.catalog import CATALOG
from roxy.core.clock import FakeClock
from roxy.rules.service import RulesService

DEFAULTS = {key: spec.default for key, spec in CATALOG.items()}
NOW = 1_760_000_400


def row(counts: dict[int, int], sets: dict[int, list[str]] | None = None) -> dict[str, Any]:
    data: dict[str, Any] = {"c": {str(k): v for k, v in counts.items()}}
    if sets:
        data["s"] = {str(k): v for k, v in sets.items()}
    return data


def spread(total: int, window_s: int, size: int) -> dict[int, int]:
    """`total` requests spread evenly over the buckets of the last `window_s` seconds."""
    buckets = [NOW // size * size - i * size for i in range(window_s // size)]
    per, extra = divmod(total, len(buckets))
    return {b: per + (1 if i < extra else 0) for i, b in enumerate(buckets)}


def test_bucket_sizes_follow_the_plan() -> None:
    assert bucket_size(60) == 10
    assert bucket_size(600) == 60
    assert bucket_size(3600) == 300
    assert bucket_size(86_400) == 7200


# --- each detector on fixtures -------------------------------------------------------------------------------------


def test_rate_fires_above_five_times_the_per_ip_rate() -> None:
    # 5 x (10 / 50 s) x 600 s = 600 requests in 10 minutes.
    fired, value, threshold = evaluate_row("rate", row(spread(601, 600, 60)), DEFAULTS, NOW)
    assert fired
    assert value == 601
    assert threshold == pytest.approx(600)
    quiet, _, _ = evaluate_row("rate", row(spread(600, 600, 60)), DEFAULTS, NOW)
    assert not quiet


def test_rate_stays_quiet_for_a_client_at_its_limit() -> None:
    """A game server sending exactly its allowance (12 per minute) for an hour never looks like spam."""
    assert not evaluate_row("rate", row(spread(120, 600, 60)), DEFAULTS, NOW)[0]


def test_old_buckets_leave_the_window() -> None:
    old = {NOW - 1200: 5000}
    assert not evaluate_row("rate", row(old), DEFAULTS, NOW)[0]


def test_refused_probe_and_auth() -> None:
    assert evaluate_row("refused", row(spread(201, 600, 60)), DEFAULTS, NOW)[0]
    assert not evaluate_row("refused", row(spread(200, 600, 60)), DEFAULTS, NOW)[0]
    assert evaluate_row("probe", row({NOW // 60 * 60: 5}), DEFAULTS, NOW)[0]
    assert not evaluate_row("probe", row({NOW // 60 * 60: 4}), DEFAULTS, NOW)[0]
    assert evaluate_row("auth", row({NOW // 300 * 300: 3}), DEFAULTS, NOW)[0]
    assert not evaluate_row("auth", row({NOW // 300 * 300: 2}), DEFAULTS, NOW)[0]


def test_enum_counts_distinct_ids_on_one_template() -> None:
    bucket = NOW // 60 * 60
    ids = [str(i) for i in range(501)]
    assert evaluate_row("enum", row({bucket: 501}, {bucket: ids}), DEFAULTS, NOW)[0]
    repeated = [str(i % 100) for i in range(5000)]  # a game polling 100 known players: legitimate
    assert not evaluate_row("enum", row({bucket: 5000}, {bucket: sorted(set(repeated))}), DEFAULTS, NOW)[0]


def test_bust_needs_two_hundred_requests_and_a_high_unique_ratio() -> None:
    bucket = NOW // 60 * 60
    unique = [f"q{i}" for i in range(250)]
    assert evaluate_row("bust", row({bucket: 250}, {bucket: unique}), DEFAULTS, NOW)[0]
    assert not evaluate_row("bust", row({bucket: 150}, {bucket: unique[:150]}), DEFAULTS, NOW)[0]  # too few
    assert not evaluate_row("bust", row({bucket: 250}, {bucket: unique[:20]}), DEFAULTS, NOW)[0]  # cached keys


def test_dist_needs_many_ips_and_many_requests() -> None:
    bucket = NOW // 60 * 60
    ips = [f"ip{i}" for i in range(51)]
    assert evaluate_row("dist", row({bucket: 1001}, {bucket: ips}), DEFAULTS, NOW)[0]
    assert not evaluate_row("dist", row({bucket: 900}, {bucket: ips}), DEFAULTS, NOW)[0]
    assert not evaluate_row("dist", row({bucket: 5000}, {bucket: ips[:30]}), DEFAULTS, NOW)[0]


# --- accumulation, the shared flush, and actions ----------------------------------------------------------------------


def detectors(
    dbs: Any, clock: FakeClock, events: list[Any], service: RulesService | None = None, **overrides: Any
) -> SpamDetectors:
    settings = FakeSettings(overrides)
    return SpamDetectors(
        settings,
        dbs.hot,
        clock,
        control_db=dbs.control,
        rules_service=service,
        events=lambda kind, severity, detail: events.append((kind, severity, dict(detail))),
    )


def observe(spam: SpamDetectors, n: int, *, ip: str = "203.0.113.7", **kwargs: Any) -> None:
    base: dict[str, Any] = {
        "limit_key": ip,
        "place_id": None,
        "template": "games.roblox.com/v1/games",
        "path": "/v1/games",
        "query": [],
        "user_agent": "Roblox/Linux",
        "refused": False,
        "probe": False,
        "auth": False,
        "game_server": False,
        "bypass": False,
    }
    base.update(kwargs)
    for _ in range(n):
        spam.observe(**base)


async def test_two_workers_detect_once_and_both_refuse(dbs: Any, fake_clock: FakeClock) -> None:
    events_a: list[Any] = []
    events_b: list[Any] = []
    worker_a = detectors(dbs, fake_clock, events_a, spam_probe_action="tarpit")
    worker_b = detectors(dbs, fake_clock, events_b, spam_probe_action="tarpit")
    observe(worker_a, 3, probe=True)
    observe(worker_b, 2, probe=True)
    assert await worker_a.flush() == []  # 3 probes so far: below 5
    acted = await worker_b.flush()  # the merged row now holds 5
    assert [d.detector for d in acted] == ["probe"]
    assert [e[0] for e in events_b] == ["spam_tarpit"]
    await worker_a.flush()
    assert events_a == []  # the action happened once, fleet-wide
    now = fake_clock.now()
    assert worker_a.flagged("203.0.113.7", now) is not None
    assert worker_b.flagged("203.0.113.7", now) is not None
    fake_clock.advance(11)
    await worker_a.flush()
    assert worker_a.flagged("203.0.113.7", fake_clock.now()) is None  # the flag lapses when the client calms down


async def test_dry_run_ban_only_logs(dbs: Any, fake_clock: FakeClock, rules_service: RulesService) -> None:
    events: list[Any] = []
    spam = detectors(dbs, fake_clock, events, rules_service)
    observe(spam, 3, auth=True)
    await spam.flush()
    assert [e[0] for e in events] == ["spam_would_ban"]
    assert events[0][2]["detector"] == "SPAM-AUTH"
    bans = dbs.control.read_sync(lambda conn: conn.execute("SELECT count(*) FROM bans").fetchone()[0])
    assert bans == 0
    assert spam.flagged("203.0.113.7", fake_clock.now()) is None  # a dry-run ban never refuses


async def test_armed_ban_escalates_for_repeat_offenders(
    dbs: Any, fake_clock: FakeClock, rules_service: RulesService
) -> None:
    events: list[Any] = []
    spam = detectors(dbs, fake_clock, events, rules_service, spam_dry_run=0)
    observe(spam, 5, probe=True)
    await spam.flush()
    rows = dbs.control.read_sync(
        lambda conn: conn.execute(
            "SELECT subject, reason_code, created_by, expires_at, created_at FROM bans"
        ).fetchall()
    )
    assert [(r[0], r[1], r[2]) for r in rows] == [("203.0.113.7", "spam_probe", "auto:spam_probe")]
    assert rows[0][3] - rows[0][4] == 60 * 60  # first offense: spam_probe_ban_minutes = 60
    assert events[-1][0] == "spam_ban"
    assert events[-1][2]["ban_minutes"] == 60
    assert escalated_minutes(60, 1440, 1) == 120
    assert escalated_minutes(60, 1440, 10) == 1440


async def test_trusted_game_server_gets_a_strike_not_a_ban(
    dbs: Any, fake_clock: FakeClock, rules_service: RulesService
) -> None:
    events: list[Any] = []
    spam = detectors(dbs, fake_clock, events, rules_service, spam_dry_run=0, spam_rate_threshold=1.0)
    observe(spam, 121, game_server=True)  # > 1 x (10 / 50) x 600
    await spam.flush()
    assert [e[0] for e in events] == ["spam_strike"]
    assert events[0][2]["configured_action"] == "ban"
    strikes = await dbs.hot.read(lambda conn: load_strike_rows(conn, ["203.0.113.7"]))
    assert strikes["203.0.113.7"].strikes == 1
    assert dbs.control.read_sync(lambda conn: conn.execute("SELECT count(*) FROM bans").fetchone()[0]) == 0
    assert spam.flagged("203.0.113.7", fake_clock.now()) is not None  # its offending requests are refused


async def test_places_only_ever_recommend(dbs: Any, fake_clock: FakeClock, rules_service: RulesService) -> None:
    events: list[Any] = []
    spam = detectors(dbs, fake_clock, events, rules_service, spam_dry_run=0)
    for i in range(700):  # many IPs, one claimed place
        observe(spam, 1, ip=f"198.51.{i // 250}.{i % 250}", place_id="1818")
    await spam.flush()
    kinds = {(e[0], e[2]["subject"]) for e in events}
    assert ("spam_detected", "place:1818") in kinds
    assert dbs.control.read_sync(lambda conn: conn.execute("SELECT count(*) FROM bans").fetchone()[0]) == 0


async def test_legitimate_traffic_stays_quiet(dbs: Any, fake_clock: FakeClock) -> None:
    events: list[Any] = []
    spam = detectors(dbs, fake_clock, events)
    for minute in range(10):
        for _ in range(12):  # exactly the per-IP allowance
            observe(spam, 1, path=f"/v1/games/{minute}", query=[("universeIds", "1818")])
        await spam.flush()
        fake_clock.advance(60)
    assert events == []


async def test_bypass_and_disabled_detectors_are_not_counted(dbs: Any, fake_clock: FakeClock) -> None:
    events: list[Any] = []
    spam = detectors(dbs, fake_clock, events)
    observe(spam, 50, probe=True, bypass=True)
    assert spam.pending_subjects() == 0
    off = detectors(dbs, fake_clock, events, spam_enabled=0)
    observe(off, 50, probe=True)
    assert off.pending_subjects() == 0


async def test_enum_and_bust_from_observations(dbs: Any, fake_clock: FakeClock) -> None:
    events: list[Any] = []
    spam = detectors(dbs, fake_clock, events)
    for user_id in range(501):
        observe(
            spam,
            1,
            template="users.roblox.com/v1/users/{userId}",
            path=f"/v1/users/{user_id}",
            query=[("cb", str(user_id))],
        )
    await spam.flush()
    detected = {e[2]["detector"] for e in events if e[0] == "spam_detected"}
    assert {"SPAM-ENUM", "SPAM-BUST"} <= detected


async def test_flush_survives_an_unavailable_hot_db(dbs: Any, fake_clock: FakeClock) -> None:
    from roxy.storage.db import SharedStateUnavailable

    events: list[Any] = []
    spam = detectors(dbs, fake_clock, events)
    observe(spam, 10, probe=True)

    async def broken(*_args: Any, **_kwargs: Any) -> Any:
        raise SharedStateUnavailable("hot", "disk I/O error")

    real = dbs.hot.write
    dbs.hot.write = broken
    try:
        assert await spam.flush() == []
    finally:
        dbs.hot.write = real
    assert spam.dropped >= 1
    assert spam.pending_subjects() == 0  # dropped, never piling up
