"""Fast checks of the load harness's own parts: the mock's limits, the traffic profile, the summaries.

What this is
    Unit tests for tests/load (no gunicorn, a few seconds in total): the sliding window and the mock server on
    loopback, the v1-like mix (shares, paths the mock recognizes, bodies that are JSON), Zipf draws, client address
    ranges, the summary helpers, the replay arithmetic and the results table.

Why it exists
    The replay test's verdict is only as good as the harness that measures it. A mock that limits one call too
    early, a profile whose paths the mock does not recognize (they would bypass every threshold), or a demand count
    that includes abuse refusals would each move the numbers without anyone noticing.

How it works
    Plain functions with fixed seeds. The mock test starts the real server on 127.0.0.1 (the conftest socket guard
    allows loopback) and calls it with httpx the way Roxy's egress override does (`X-Roxy-Test-Host`).

What to read next
    tests/load/test_replay_profile.py, tests/load/scenarios.py.
"""

from __future__ import annotations

import ipaddress
import json
import random
import re
from collections import Counter
from pathlib import Path

import httpx
import pytest

from load.client import Outcome, latency_ms, max_overlap, per_second, percentile
from load.harness import absolute_paths, table
from load.mock_roblox import TOO_MANY, CallRecord, Endpoint, MockRoblox, SlidingWindow
from load.scenarios import ABUSE_REFUSALS, PACING_REFUSALS, replay_numbers
from load.traffic import (
    V1_LIKE_MIX,
    MixPicker,
    PlannedRequest,
    Zipf,
    benchmark_addresses,
    build_request,
    burst_plan,
    documentation_addresses,
    hot_keys,
    mix_total,
    poisson_plan,
)

# ------------------------------------------------------------------------------------------------- the mock


def test_sliding_window_refuses_the_call_over_the_limit_and_counts_refused_calls() -> None:
    window = SlidingWindow(3, window_s=60)
    assert [window.admit(t) for t in (0.0, 1.0, 2.0)] == [True, True, True]
    assert window.admit(3.0) is False  # a 4th call within 60 s
    assert window.admit(60.5) is False  # refused calls count: 1, 2 and 3 s are still within 60 s of 60.5
    assert window.admit(63.1) is True  # 3.0, 60.5 and 63.1 s: only two others in the last 60 s


def test_sliding_window_zero_means_unlimited() -> None:
    window = SlidingWindow(0)
    assert all(window.admit(float(t) / 1000) for t in range(1000))


async def test_mock_limits_an_endpoint_and_logs_every_call() -> None:
    endpoints = [
        Endpoint("users", "GET", "users.roblox.com", r"/v1/users/\d+", limit_per_min=2, latency_s=0),
        Endpoint("games", "GET", "games.roblox.com", "/v1/games", latency_s=0),
        Endpoint("badges", "GET", "badges.roblox.com", r"/v1/badges/\d+", always_429=True, retry_after="30"),
    ]
    mock = MockRoblox(endpoints).start()
    try:
        async with httpx.AsyncClient(base_url=mock.base, trust_env=False) as client:
            users = {"X-Roxy-Test-Host": "users.roblox.com"}
            answers = [await client.get(f"/v1/users/{n}", headers=users) for n in range(4)]
            games = {"X-Roxy-Test-Host": "games.roblox.com"}
            same = [await client.get("/v1/games?universeIds=1", headers=games) for _ in range(2)]
            badge = await client.get("/v1/badges/7", headers={"X-Roxy-Test-Host": "badges.roblox.com"})
            other = await client.get("/v1/nothing", headers={**users, "Cookie": "a=b"})
        assert [a.status_code for a in answers] == [200, 200, 429, 429]
        assert answers[2].content == TOO_MANY
        assert "retry-after" not in answers[2].headers
        assert same[0].status_code == 200
        assert same[0].content == same[1].content
        assert badge.status_code == 429
        assert badge.headers["retry-after"] == "30"
        assert other.status_code == 200
        stats = mock.stats()
        assert stats.by_endpoint == Counter({"users": 4, "games": 2, "badges": 1, "other": 1})
        assert stats.refused == Counter({"users": 2, "badges": 1})
        records = mock.records()
        assert [r.endpoint for r in records][:4] == ["users"] * 4
        assert [r.cookie for r in records if r.endpoint == "other"] == [True]
    finally:
        mock.stop()


# -------------------------------------------------------------------------------------------- the profile


def test_v1_like_mix_shares_add_up_and_every_endpoint_is_limited() -> None:
    assert mix_total(V1_LIKE_MIX) == pytest.approx(100.0)
    assert len({item.name for item in V1_LIKE_MIX}) == len(V1_LIKE_MIX)
    for item in V1_LIKE_MIX:
        assert 30 <= item.limit_per_min <= 150, item.name  # realistic per-minute thresholds (traffic.py)
        assert item.host.endswith(".roblox.com")


def test_every_planned_request_reaches_its_own_mock_endpoint() -> None:
    """A path the mock does not recognize would skip every threshold, so every request must match its endpoint."""
    rng = random.Random(1)
    endpoints = [item.mock_endpoint() for item in V1_LIKE_MIX]
    for item in V1_LIKE_MIX:
        for key in (item.id_base + 1, item.id_base + item.keys):
            path, body = build_request(item, key, rng)
            host, _, rest = path[1:].partition("/")
            plain = "/" + rest.split("?", 1)[0]  # the mock matches the path; the query is not part of it
            matches = [
                e.name
                for e in endpoints
                if e.method == item.method and e.host == host and re.fullmatch(e.path, plain) is not None
            ]
            assert matches == [item.name], (path, matches)
            if body is not None:
                assert isinstance(json.loads(body), dict)


def test_presence_bodies_list_between_one_and_six_ids() -> None:
    presence = next(item for item in V1_LIKE_MIX if item.name == "presence")
    rng = random.Random(3)
    sizes = {
        len(json.loads(build_request(presence, presence.id_base + 1, rng)[1] or b"{}")["userIds"]) for _ in range(200)
    }
    assert sizes == {1, 2, 3, 4, 5, 6}


def test_zipf_draws_are_in_range_and_skewed() -> None:
    zipf = Zipf(1000, 1.0)
    rng = random.Random(7)
    draws = [zipf.draw(rng) for _ in range(20_000)]
    assert min(draws) >= 1
    assert max(draws) <= 1000
    top10 = sum(1 for d in draws if d <= 10) / len(draws)
    assert top10 == pytest.approx(zipf.mass(10), abs=0.02)
    assert zipf.mass(1000) == pytest.approx(1.0)
    assert Zipf(10, 0.0).mass(5) == pytest.approx(0.5)  # exponent 0 is uniform


def test_mix_picker_follows_the_shares() -> None:
    picker = MixPicker(V1_LIKE_MIX)
    rng = random.Random(11)
    counts = Counter(picker.draw(rng)[0].name for _ in range(40_000))
    for item in V1_LIKE_MIX:
        assert counts[item.name] / 40_000 == pytest.approx(item.share / 100, abs=0.01), item.name


def test_unique_share_makes_keys_that_never_repeat() -> None:
    picker = MixPicker(V1_LIKE_MIX[:1], unique_share=1.0)
    rng = random.Random(5)
    keys = [picker.draw(rng)[1] for _ in range(500)]
    assert len(set(keys)) == 500
    assert min(keys) > V1_LIKE_MIX[0].id_base + V1_LIKE_MIX[0].keys  # outside the Zipf key space


def test_client_addresses_belong_to_no_real_system() -> None:
    documentation = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
    doc = documentation_addresses(762)
    assert len(set(doc)) == 762
    assert all(any(ipaddress.ip_address(a) in net for net in documentation) for a in doc)
    bench = benchmark_addresses(5000)
    assert len(set(bench)) == 5000
    assert all(ipaddress.ip_address(a) in ipaddress.ip_network("198.18.0.0/15") for a in bench)
    with pytest.raises(ValueError):
        documentation_addresses(763)


def test_poisson_plan_rate_duration_and_seed() -> None:
    picker = MixPicker(V1_LIKE_MIX)
    plan = poisson_plan(picker, rate=10, duration_s=200, addresses=documentation_addresses(300), seed=2026)
    again = poisson_plan(MixPicker(V1_LIKE_MIX), rate=10, duration_s=200, addresses=documentation_addresses(300),
                         seed=2026)  # fmt: skip
    assert plan == again  # reproducible
    assert 1800 <= len(plan) <= 2200
    assert all(0 <= r.at < 200 for r in plan)
    assert [r.at for r in plan] == sorted(r.at for r in plan)


def test_burst_plan_and_hot_keys() -> None:
    keys = hot_keys(V1_LIKE_MIX, 100)
    assert len(set(keys)) == 100
    assert all(item.method == "GET" for item, _ in keys)
    plan = burst_plan(MixPicker(V1_LIKE_MIX), keys=keys, per_address=5, addresses=documentation_addresses(500), seed=1)
    assert len(plan) == 2500
    assert Counter(r.ip for r in plan).most_common(1)[0][1] == 5
    assert all(r.at == 0 for r in plan)


# ------------------------------------------------------------------------------------------- summaries


def _outcome(at: float, status: int = 200, *, cache: str = "MISS", refusal: str = "", label: str = "a",
             latency: float = 0.01) -> Outcome:  # fmt: skip
    return Outcome(at, at, latency, status, cache, refusal, "", "", label, "192.0.2.1", 0)


def test_percentile_latency_overlap_and_rate() -> None:
    assert percentile([], 0.5) is None
    assert percentile([5, 1, 3, 2, 4], 0.5) == 3
    assert percentile(list(range(1, 101)), 0.99) == 99
    summary = latency_ms([_outcome(0, latency=0.001 * n) for n in range(1, 101)])
    assert summary["n"] == 100
    assert summary["p50"] == pytest.approx(50.0)
    assert summary["max"] == pytest.approx(100.0)
    assert max_overlap([(0, 10), (1, 2), (2, 3), (2.5, 4)]) == 3  # an end at 2 closes before the start at 2
    assert max_overlap([]) == 0
    assert per_second([0.5, 1.5, 2.5, 9.0], start=0, end=3) == pytest.approx(1.0)


def test_replay_numbers_demand_shares_and_429s() -> None:
    plan = [PlannedRequest(0, "GET", "/x", None, "192.0.2.1", "a")]
    outcomes = [
        _outcome(1, cache="MISS"),
        _outcome(2, cache="HIT"),
        _outcome(3, cache="COALESCED"),
        _outcome(4, 429, cache="MISS", refusal="upstream_busy"),  # demand, deferred, no call
        _outcome(5, 429, cache="", refusal="throttle"),  # an abuse refusal: not demand
        _outcome(150, cache="HIT"),
        _outcome(160, cache="MISS"),
    ]
    calls = [CallRecord(100.0 + t, "a", s, False) for t, s in ((1, 200), (160, 200), (161, 429))]
    numbers = replay_numbers(plan, outcomes, calls, t0=100.0, duration_s=200)
    assert numbers["demand"] == 6
    assert numbers["upstream_calls"] == 3
    assert numbers["roblox_429"] == 1
    assert numbers["roblox_429_pct"] == pytest.approx(100 / 3)
    assert numbers["avoided_pct"] == pytest.approx(50.0)  # (6 - 3) / 6
    assert numbers["cache_served"] == 3
    assert numbers["deferred"] == 1
    assert numbers["avoided_pct_second_half"] == pytest.approx(0.0)  # 2 requests, 2 calls after 100 s
    assert numbers["roblox_429_times_s"] == [161.0]
    assert numbers["per_endpoint"]["a"]["calls"] == 3
    assert sum(w["requests"] for w in numbers["timeline"]) == len(outcomes)
    assert "upstream_busy" in PACING_REFUSALS
    assert "upstream_busy" not in ABUSE_REFUSALS


# ----------------------------------------------------------------------------------------------- output


def test_table_aligns_columns() -> None:
    text = table([("a", "1", "x"), ("longer metric", "22", "")])
    lines = text.splitlines()
    assert lines[0].startswith("metric        | measured | target or note")
    assert lines[2].startswith("a             | 1        | x")
    assert chr(0x2014) not in text  # no em dash (plan C5)
    assert chr(0x2013) not in text  # no en dash


def test_absolute_paths_rewrites_only_path_options() -> None:
    out = absolute_paths(["replay", "--json", "r.json", "--work=w", "--scale", "0.5"])
    assert out[0] == "replay"
    assert out[4:] == ["--scale", "0.5"]
    assert Path(out[2]).is_absolute()
    assert out[2].endswith("r.json")
    assert out[3].startswith("--work=")
    assert Path(out[3].split("=", 1)[1]).is_absolute()
