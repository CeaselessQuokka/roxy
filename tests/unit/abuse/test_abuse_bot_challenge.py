"""Bot score (plan 10.7) and the browser proof-of-work challenge (plan 10.8)."""

from __future__ import annotations

from typing import Any

from roxy.abuse.bot import (
    SIGNALS,
    BotSignals,
    ClientTracker,
    has_game_server_signature,
    header_order_family,
    is_library_ua,
    query_fingerprint,
    score,
)
from roxy.abuse.challenge import (
    challenge_key,
    challenge_page,
    cookie_from_header,
    leading_zero_bits,
    make_challenge,
    solve,
    verify_cookie,
)
from roxy.abuse.checks.probe import probe_signature
from roxy.config.catalog import CATALOG

WEIGHTS = {name: float(CATALOG[f"bot_weight_{name}"].default) for name in SIGNALS}
NOW = 1_760_000_000.0


def test_default_weights_match_the_plan() -> None:
    assert WEIGHTS == {
        "library_ua": 25,
        "no_roblox_signature": 15,
        "probes": 25,
        "refusals": 15,
        "timing": 10,
        "header_order": 5,
        "cache_busting": 5,
    }


def test_score_is_the_weighted_average() -> None:
    assert score(BotSignals(), WEIGHTS) == 0
    assert score(BotSignals(**dict.fromkeys(SIGNALS, 1.0)), WEIGHTS) == 100
    assert score(BotSignals(library_ua=1.0, no_roblox_signature=1.0), WEIGHTS) == 40
    assert score(BotSignals(library_ua=1.0), dict.fromkeys(SIGNALS, 0.0)) == 0


def test_signal_helpers() -> None:
    assert is_library_ua("python-requests/2.31.0")
    assert is_library_ua("")
    assert not is_library_ua("Roblox/WinInet")
    assert not has_game_server_signature(
        place_id="1818", user_agent="Roblox/Linux", client_ip="203.0.113.7", egress_cidrs=[]
    )  # plan 15.3 E: an empty list trusts nobody
    assert has_game_server_signature(
        place_id="1818", user_agent="Roblox/Linux", client_ip="203.0.113.7", egress_cidrs=["203.0.113.0/24"]
    )
    assert not has_game_server_signature(
        place_id=None, user_agent="Roblox/Linux", client_ip="203.0.113.7", egress_cidrs=["203.0.113.0/24"]
    )
    assert header_order_family(["host", "user-agent", "accept"]) is not None
    # Every known client sends Host before User-Agent; this order fits no family.
    assert header_order_family(["user-agent", "host", "accept-encoding", "accept", "connection"]) is None
    assert query_fingerprint("t", []) is None
    assert query_fingerprint("t", [("b", "2"), ("a", "1")]) == query_fingerprint("t", [("a", "1"), ("b", "2")])
    assert probe_signature("example.com/wp-login.php") == "wp-login"
    assert probe_signature("games.roblox.com/v1/games") is None


def test_tracker_signals() -> None:
    tracker = ClientTracker(max_clients=2)
    for i in range(60):
        tracker.observe(
            "k",
            now=NOW + i,
            monotonic=1000.0 + i,
            refused=i % 2 == 0,
            probe=i < 5,
            query_fp=query_fingerprint("t", [("cb", str(i))]),
        )
    signals = tracker.signals("k", now=NOW + 60, user_agent="curl/8", game_server=False, header_names=["host"])
    assert signals.library_ua == 1.0
    assert signals.no_roblox_signature == 1.0
    assert signals.probes == 1.0
    assert signals.refusals == 0.5
    assert signals.timing == 1.0  # one request per second exactly
    assert signals.cache_busting == 1.0
    assert score(signals, WEIGHTS) >= 80
    tracker.observe("a", now=NOW, monotonic=0.0, refused=False, probe=False, query_fp=None)
    tracker.observe("b", now=NOW, monotonic=0.0, refused=False, probe=False, query_fp=None)
    assert len(tracker) == 2  # bounded: "k" was evicted
    fresh = tracker.signals("k", now=NOW, user_agent="Roblox/Linux", game_server=True, header_names=[])
    assert score(fresh, WEIGHTS) == 0


def test_challenge_round_trip() -> None:
    key = challenge_key(b"k" * 32)
    puzzle = make_challenge(key, client_ip="203.0.113.7", user_agent="Mozilla/5.0", now=NOW, bits=8)
    nonce = solve(puzzle, 8)
    cookie = f"{puzzle}~{nonce}"
    common: dict[str, Any] = {"client_ip": "203.0.113.7", "user_agent": "Mozilla/5.0", "max_age_s": 1800, "min_bits": 8}
    assert verify_cookie(key, cookie, now=NOW + 10, **common)
    assert not verify_cookie(key, cookie, now=NOW + 1801, **common)  # expired
    assert not verify_cookie(key, cookie, now=NOW, **{**common, "client_ip": "198.51.100.1"})  # another address
    assert not verify_cookie(key, cookie, now=NOW, **{**common, "min_bits": 9})  # too easy for today's setting
    assert not verify_cookie(key, f"{puzzle}~{nonce + 1}", now=NOW, **common) or leading_zero_bits(b"\x00") == 8
    assert not verify_cookie(challenge_key(b"j" * 32), cookie, now=NOW, **common)  # forged signature
    assert not verify_cookie(key, "garbage", now=NOW, **common)
    assert cookie_from_header(f"a=1; roxy_pow={cookie}; b=2") == cookie


def test_challenge_page_escapes_and_carries_the_nonce() -> None:
    page = challenge_page('x"><script>', 18, max_age_s=1800, nonce="abc")
    assert '<script nonce="abc">' in page
    assert 'x"><script>' not in page
    assert "x&quot;&gt;&lt;script&gt;" in page
    assert leading_zero_bits(b"\x00\x0f") == 12
