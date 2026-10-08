"""Pause, throttle-all, bypass, bans, auth smuggling, header and UA rules (rows 6, 9, 42, 44, 45, 49, 113 to 115)."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest
from abuse_support import ADMIN, FakeReq

from roxy.abuse.bans import BanHits, ban_subject_for, create_ladder_ban, ua_hash
from roxy.abuse.bypass import BypassNeedsConfirmation, add_bypass, bypass_expires_at, bypass_my_ip, is_bypassed
from roxy.abuse.checks.auth_smuggling import detect_auth_attempt
from roxy.abuse.header_rules import explain_header_rules, parse_header_text, rule_hit
from roxy.abuse.pause import PauseState, clear_schedule, schedule_pause, set_pause
from roxy.abuse.state import SwitchesCache
from roxy.abuse.throttle_all import ThrottleAllState, set_throttle_all, throttle_all_watch
from roxy.abuse.ua_rules import explain_user_agent_rules, match_ua_rule
from roxy.config.runtime import read_config_version
from roxy.core.clock import FakeClock
from roxy.core.redact import TOKEN_PREFIX
from roxy.rules.service import RulesService
from roxy.rules.store import RulesSnapshot

# --- pause ------------------------------------------------------------------------------------------------------------


def test_pause_state_rules() -> None:
    state = PauseState(paused=False, scheduled_start=100, scheduled_end=200, scheduled_reason="Window")
    assert not state.active(99)
    assert state.active(100)
    assert not state.active(200)
    assert state.message(150) == ("Window", "custom")
    assert state.retry_after(150) == 50
    assert state.active_since(150) == 100
    manual = PauseState(paused=True, since=42.0)
    assert manual.message(0) == ("Service down for maintenance.", "default")
    assert manual.retry_after(0) == 60
    assert PauseState.from_json("garbage") == PauseState()


async def test_set_pause_audits_bumps_config_version_and_keeps_the_reason(dbs: Any, fake_clock: FakeClock) -> None:
    before = dbs.control.read_sync(read_config_version)
    state = await set_pause(dbs.control, fake_clock, ADMIN, paused=True, reason="  Upgrading the database  ")
    assert state.paused
    assert state.reason == "Upgrading the database"
    assert state.since == fake_clock.now()
    assert dbs.control.read_sync(read_config_version) == before + 1
    audit = dbs.control.read_sync(lambda conn: conn.execute("SELECT action, target FROM audit_log").fetchall())
    assert [tuple(r) for r in audit] == [("pause.set", "service_state:pause")]
    off = await set_pause(dbs.control, fake_clock, ADMIN)  # toggle
    assert not off.paused
    assert off.reason == "Upgrading the database"  # v1: the reason persists
    assert off.since == 0.0


async def test_schedule_and_clear(dbs: Any, fake_clock: FakeClock) -> None:
    with pytest.raises(ValueError):
        await schedule_pause(dbs.control, fake_clock, ADMIN, start=10, end=10)
    state = await schedule_pause(dbs.control, fake_clock, ADMIN, start=10, end=20, reason="Night")
    assert state.scheduled_by == "admin:owner"
    cleared = await clear_schedule(dbs.control, fake_clock, ADMIN)
    assert cleared.scheduled_start is None
    assert cleared.scheduled_end is None


async def test_switches_cache_reloads_on_config_version(dbs: Any, fake_clock: FakeClock) -> None:
    cache = SwitchesCache(dbs.control)
    assert await cache.refresh_if_changed()  # first load
    assert not cache.pause.paused
    assert not await cache.refresh_if_changed()  # nothing moved
    await set_throttle_all(dbs.control, fake_clock, ADMIN, enabled=True, reason="Attack")
    assert await cache.refresh_if_changed()
    assert cache.throttle_all.enabled
    assert cache.throttle_all.reason == "Attack"


# --- throttle-all -----------------------------------------------------------------------------------------------------


async def test_enabling_throttle_all_records_a_new_since_marker(dbs: Any, fake_clock: FakeClock) -> None:
    """Row 115: enabling starts a new "since" (v1 cleared the drop counter; v2 counts drops from the marker)."""
    first = await set_throttle_all(dbs.control, fake_clock, ADMIN, enabled=True)
    fake_clock.advance(30)
    again = await set_throttle_all(dbs.control, fake_clock, ADMIN, enabled=True)
    assert again.since == first.since  # already on: same episode
    await set_throttle_all(dbs.control, fake_clock, ADMIN, enabled=False)
    fake_clock.advance(30)
    later = await set_throttle_all(dbs.control, fake_clock, ADMIN, enabled=True)
    assert later.since == fake_clock.now()
    assert later.since > first.since
    stored = dbs.control.read_sync(
        lambda conn: json.loads(
            conn.execute("SELECT value_json FROM service_state WHERE key = 'throttle_all'").fetchone()[0]
        )
    )
    assert stored == {"enabled": True, "reason": "", "since": later.since}
    assert ThrottleAllState(enabled=True).message() == ("Service down for maintenance.", "default")


async def test_throttle_all_watch(make_pipeline: Callable[..., Any], dbs: Any, fake_clock: FakeClock) -> None:
    await set_throttle_all(dbs.control, fake_clock, ADMIN, enabled=True)
    pipeline = make_pipeline()
    pipeline.switches.reload_sync()
    for ip in ("198.51.100.1", "198.51.100.1", "198.51.100.2"):
        await pipeline.evaluate(FakeReq(client_ip=ip, limit_key=ip))
    watch = await throttle_all_watch(dbs.hot, now_ms=fake_clock.now_ms(), limit_setting=1)
    assert watch["total"] == 2
    assert {r["ip"] for r in watch["rows"]} == {"198.51.100.1", "198.51.100.2"}
    assert all(r["limited"] and r["reset_in_s"] == 60 for r in watch["rows"])


# --- bypass -----------------------------------------------------------------------------------------------------------


def test_bypass_expiry_defaults() -> None:
    assert bypass_expires_at(1000, 24) == 1000 + 24 * 3600
    assert bypass_expires_at(1000, 24, 1) == 1000 + 3600
    assert bypass_expires_at(1000, 0) is None


async def test_bypass_my_ip_and_never_needs_confirmation(
    rules_service: RulesService, snapshot_of: Callable[[], RulesSnapshot], fake_clock: FakeClock
) -> None:
    now = fake_clock.now()
    change = await bypass_my_ip(rules_service, "203.0.113.7", ADMIN, now=now, default_expiry_h=24)
    assert change.after["expires_at"] == int(now) + 86_400
    with pytest.raises(BypassNeedsConfirmation):
        await add_bypass(rules_service, "198.51.100.0/24", ADMIN, now=now, default_expiry_h=24, never=True)
    forever = await add_bypass(
        rules_service, "198.51.100.0/24", ADMIN, now=now, default_expiry_h=24, never=True, confirm_never=True
    )
    assert forever.after["expires_at"] is None
    snapshot = snapshot_of()
    assert is_bypassed(snapshot, "203.0.113.7", now)
    assert is_bypassed(snapshot, "198.51.100.77", now)
    assert not is_bypassed(snapshot, "203.0.113.7", now + 86_401)


# --- bans -------------------------------------------------------------------------------------------------------------


def test_ua_hash_and_ban_subjects() -> None:
    assert ua_hash("Roblox/Linux") == ua_hash("Roblox/Linux")
    assert len(ua_hash("x")) == 16
    assert ua_hash("x") != ua_hash("X")
    assert ban_subject_for("203.0.113.7") == ("ip", "203.0.113.7")
    assert ban_subject_for("2001:db8::/64") == ("cidr", "2001:db8::/64")


async def test_ban_hits_flush(rules_service: RulesService, dbs: Any, fake_clock: FakeClock) -> None:
    change = await rules_service.create("bans", {"subject_type": "ip", "subject": "203.0.113.9"}, ADMIN)
    hits = BanHits(max_pending=1)
    hits.record(change.key, 100)
    hits.record(change.key, 105)
    hits.record(999, 100)  # over the bound: dropped
    assert hits.dropped == 1
    assert await hits.flush(dbs.control) == 1
    stored = dbs.control.read_sync(lambda conn: tuple(conn.execute("SELECT hits, last_hit_at FROM bans").fetchone()))
    assert stored == (2, 105)


async def test_ladder_ban(rules_service: RulesService, dbs: Any, fake_clock: FakeClock) -> None:
    await create_ladder_ban(rules_service, limit_key="203.0.113.7", minutes=15, rung=3, now=int(fake_clock.now()))
    row = dbs.control.read_sync(
        lambda conn: tuple(conn.execute("SELECT subject_type, reason_code, created_by FROM bans").fetchone())
    )
    assert row == ("ip", "throttle_ladder", "auto:throttle_ladder")


# --- auth smuggling (row 9, C2 item 5) -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("req", "reason"),
    [
        (FakeReq().with_headers([("X-Roblox-Token", "")]), "X-Roblox-Token header"),
        (
            FakeReq().with_headers([("x-custom", "a" + TOKEN_PREFIX + "b")]),
            '"X-Custom" header carried a ROBLOSECURITY-shaped value',
        ),
        (
            FakeReq().with_headers([("Cookie", "a=1; .ROBLOSECURITY=abc")]),
            '"Cookie" header carried a ROBLOSECURITY-shaped value',
        ),
        (FakeReq().with_headers([("Cookie", "a=1; .roblosecurity")]), "cookie named .ROBLOSECURITY"),
        (FakeReq(query=[("token", TOKEN_PREFIX.lower())]), "query string carried a ROBLOSECURITY-shaped value"),
        (FakeReq(query=[(".ROBLOSECURITY", "x")]), "query string carried a ROBLOSECURITY-shaped value"),
        (FakeReq(body=b'{"c": ".ROBLOSECURITY=x"}'), "request body carried a ROBLOSECURITY-shaped value"),
        (FakeReq(body=b"c=%2EROBLOSECURITY%3Dx"), "request body carried a ROBLOSECURITY-shaped value"),
    ],
)
def test_auth_smuggling_detection(req: FakeReq, reason: str) -> None:
    assert detect_auth_attempt(req) == reason


def test_auth_smuggling_quiet_on_ordinary_requests() -> None:
    req = FakeReq(query=[("universeIds", "1,2")], body=b'{"ids": [1, 2]}').with_headers(
        [("User-Agent", "Roblox/Linux"), ("Cookie", "theme=dark")]
    )
    assert detect_auth_attempt(req) is None
    assert detect_auth_attempt(FakeReq(body=b"x" * 10 + TOKEN_PREFIX.encode()), max_body_bytes=10) is None


# --- header and User-Agent rules (rows 44, 45) ------------------------------------------------------------------------


async def test_header_rule_semantics_and_tester(
    rules_service: RulesService, snapshot_of: Callable[[], RulesSnapshot]
) -> None:
    await rules_service.create("rules_header", {"needle": "xeno", "scope": "key"}, ADMIN)
    await rules_service.create("rules_header", {"needle": "WinInet", "header": "User-Agent", "mode": "contains"}, ADMIN)
    snapshot = snapshot_of()
    pairs = parse_header_text("GET / HTTP/1.1\nUser-Agent: Roblox/WinInet\nXeno-Fingerprint: 4f3a91c0\nAccept: */*\n")
    assert pairs == [("User-Agent", "Roblox/WinInet"), ("Xeno-Fingerprint", "4f3a91c0"), ("Accept", "*/*")]
    first = snapshot.header_rules[0]
    hit = rule_hit(first, pairs)
    assert hit is not None
    assert (hit.header, hit.field, hit.text) == ("Xeno-Fingerprint", "key", "Xeno-Fingerprint")
    report = explain_header_rules(snapshot, pairs, draft={"needle": "4f3a", "scope": "value"})
    assert report["blocked"]
    assert report["blocked_by"] == "|key|contains|xeno"
    assert [r["matched"] for r in report["rules"]] == [True, True]
    assert report["rules"][1]["matched_header"] == "User-Agent"
    assert report["draft"]["valid"]
    assert report["draft"]["matched"]
    assert report["draft"]["already_blocked"]
    invalid = explain_header_rules(snapshot, pairs, draft={"needle": ""})
    assert invalid["draft"]["valid"] is False


async def test_ua_rules_first_match_and_tester_reflects_the_switch(
    rules_service: RulesService, snapshot_of: Callable[[], RulesSnapshot]
) -> None:
    await rules_service.create("rules_user_agent", {"needle": "bot", "kind": "burst", "limit": 5}, ADMIN)
    await rules_service.create("rules_user_agent", {"needle": "^scraper", "mode": "regex", "kind": "cooldown"}, ADMIN)
    snapshot = snapshot_of()
    assert match_ua_rule(snapshot, "Scraper bot") is not None
    assert match_ua_rule(snapshot, "Scraper bot").needle == "bot"  # type: ignore[union-attr]
    assert match_ua_rule(snapshot, "scraper/1").needle == "^scraper"  # type: ignore[union-attr]
    assert match_ua_rule(snapshot, "Roblox/Linux") is None
    assert match_ua_rule(snapshot, "bot", enabled=False) is None
    on = explain_user_agent_rules(snapshot, "bot", enabled=True, draft={"needle": "bo", "mode": "exact"})
    assert on["limited"]
    assert on["draft"]["valid"]
    assert not on["draft"]["matched"]
    off = explain_user_agent_rules(snapshot, "bot", enabled=False)
    assert not off["limited"]  # v1 bug B13: the tester ignored the master switch
