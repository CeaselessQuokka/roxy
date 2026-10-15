"""The fixture loader and harness (`tests/insights/harness.py`): format rules, grammar, and every committed fixture.

What this is
    Unit tests of the README grammar (times, windows, distributions, pools, placement, the constraint grammar and
    change matchers), the refusal of malformed files, a fast in-memory check of EVERY committed fixture (format,
    settings, consistency rules and its own `data_checks`), and full database loads of a set of fixtures that
    together use every loader path (each state section and event kind), with their data checks repeated through
    the rollup read models.

Why it exists
    Three more rule families are written on this harness. If it mis-reads a fixture, every rule built on it is
    tested against the wrong data, so the harness is tested on its own, independently of any rule.

What to read next
    `tests/fixtures/insights/README.md` (the format), `tests/insights/harness.py`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from insights import harness
from insights.harness import FixtureError, check, distribution, parse_time, placements, pool
from roxy.metrics import read_history

NOW = parse_time("2026-10-07T15:00:00Z", 0)
ALL_FIXTURES = sorted(p.stem for p in harness.FIXTURE_DIR.glob("*.yaml"))

LOADER_PATHS = {
    "up_429_endpoint__before_after_11_6": "traffic, samples, 429 side output, buckets, cooldowns, settings history",
    "cache_pressure__fires_bytes_cap": "cache stores, evictions, passes, disk",
    "sys_worker_sat__cpu_pegged": "workers and their history",
    "egr_calibrate__fires_estimate_mode": "egress usage, metering mode, provider figure",
    "cred_expiring__fires_probe_401": "credential and probes, internal calls",
    "up_breaker_flap__search_flapping": "breakers and openings",
    "up_csrf_loop__stale_tokens": "upstream attempts",
    "host_add__fires": "dns, paths",
    "sec_admin_allowlist__three_stable_networks": "admin logins",
    "sys_health_fail__disk_check_failing": "health runs",
    "cred_unused__fires": "x_ sections, credential allowlist",
    "filter_remove__stale_filters": "x_last_hit_at, rule tables, access list, bans",
    "abuse_spam__repeated_auto_bans": "security events, client scores",
    "tarpit_tune__saturated": "tarpit provider",
    "up_ua_experiment__alt_ua_wins": "ua experiment provider",
    "sys_metrics_drop__queue_overflow": "metrics pipeline provider",
    "cache_keysplit__fires": "cache entries",
    "sys_errors__known_signature_spike": "errors and occurrences",
}
"""Fixtures loaded fully: together they use every section of the README."""


# ------------------------------------------------------------------------------------------------- grammar


def test_time_grammar() -> None:
    assert parse_time("now", NOW) == NOW
    assert parse_time("0m", NOW) == NOW
    assert parse_time("-60m", NOW) == NOW - 3600
    assert parse_time("+12s", NOW) == NOW + 12
    assert parse_time("-7d", NOW) == NOW - 7 * 86_400
    assert parse_time("2026-10-06", NOW) == NOW - 15 * 3600 - 86_400
    assert parse_time(1234, NOW) == 1234
    for bad in ("-1m30s", "60m", "yesterday", True):
        with pytest.raises(FixtureError):
            parse_time(bad, NOW)


def test_distribution_is_deterministic_and_hits_its_percentiles() -> None:
    spec = {"p50": 180, "p95": 450, "p99": 900}
    values = sorted(distribution(spec, n, where="t") for n in range(10_000))
    assert values[4999] == pytest.approx(180, abs=2)
    assert values[9499] == pytest.approx(450, abs=5)
    assert distribution(spec, 7, where="t") == distribution(spec, 7, where="t")
    assert distribution(42, 3, where="t") == 42
    with pytest.raises(FixtureError):
        distribution({"q50": 1}, 0, where="t")


def test_pools_skip_the_network_address() -> None:
    assert pool({"cidr": "203.0.113.0/26", "count": 3}, where="t") == ["203.0.113.1", "203.0.113.2", "203.0.113.3"]
    assert pool({"list": ["a", "b"]}, where="t") == ["a", "b"]
    assert pool("198.51.100.7", where="t") == ["198.51.100.7"]
    with pytest.raises(FixtureError):
        pool({"cidr": "203.0.113.0/26"}, where="t")


def test_placement_rules() -> None:
    start, end = NOW - 120, NOW
    per_minute = placements({"per_minute": 2}, start, end, where="t")
    assert per_minute == [
        int(start * 1000) + 15_000,
        int(start * 1000) + 45_000,
        int(start * 1000) + 75_000,
        int(start * 1000) + 105_000,
    ]
    assert len(placements({"total": 5}, start, end, where="t")) == 5
    assert [t // 60_000 for t in placements({"total": 3}, start, end, where="t")].count(int(start) // 60) == 2
    assert len(placements({"series": [3, 0]}, start, end, where="t")) == 3
    every = placements({"every": "30m"}, NOW - 7200, NOW, where="t", rows=True)
    assert len(every) == 4
    assert every[1] - every[0] == 1_800_000
    with pytest.raises(FixtureError):
        placements({"series": [1]}, start, end, where="t")
    with pytest.raises(FixtureError):
        placements({"per_minute": 1, "total": 2}, start, end, where="t")


# ------------------------------------------------------------------------------------------ constraint grammar


@pytest.mark.parametrize(
    ("value", "constraint", "ok"),
    [
        (1, True, True),
        (1.0, 1, True),
        ("off", "off", True),
        (None, None, True),
        (harness._MISSING, None, True),
        (5, None, False),
        ([1, 2], [1, 2], True),
        (10, {"between": [5, 10]}, True),
        (10.5, {"between": [5, 10]}, False),
        (3, {"gt": 2, "lt": 4}, True),
        ("a", {"in": ["a", "b"]}, True),
        ("c", {"not_in": ["a", "b"]}, True),
        ("GET,POST", {"contains_all": ["post"]}, True),
        (["GET"], {"contains_all": ["POST"]}, False),
        ('["sort_csv:ids"]', {"contains": "sort_csv:ids"}, True),
        (["sort_csv:ids"], {"contains": "sort_csv:ids"}, True),
        ("users.roblox.com", {"regex": r"^users\."}, True),
        (None, {"present": False}, True),
        (7, {"present": True}, True),
        ({"per_min": 89, "burst": 10}, {"per_min": {"lte": 90}}, True),
        ({"per_min": 95}, {"per_min": {"lte": 90}}, False),
        ("x", {"ne": "y"}, True),
    ],
)
def test_constraint_grammar(value: Any, constraint: Any, ok: bool) -> None:
    assert (check(value, constraint) is None) is ok


def test_matches_targets_reads_the_type_next_to_the_pattern() -> None:
    match = {"pattern": "groups.roblox.com/v1/groups/*", "type": "glob"}
    assert check(match, {"pattern": {"matches_targets": ["groups.roblox.com/v1/groups/12"]}}) is None
    assert check(match, {"pattern": {"not_matches_targets": ["games.roblox.com/v1/games"]}}) is None
    regex = {"pattern": "^users\\.roblox\\.com/v1/users$", "type": "regex"}
    assert check(regex, {"pattern": {"matches_targets": ["users.roblox.com/v1/users"]}}) is None


def test_change_matchers_any_of_and_distinct_assignment() -> None:
    changes: list[dict[str, Any]] = [
        {"kind": "setting", "key": "fallback_on_429", "current": 1, "proposed": 0},
        {"kind": "rule_upsert", "table": "rules_cache", "current": None, "proposed": {"ttl": 600}},
    ]
    assert harness._change_matches(changes[0], {"any_of": [{"kind": "ban_add"}, {"kind": "setting"}]}) is None
    assert harness._assign(changes, [{"kind": "setting"}, {"kind": "rule_upsert", "current": None}]) == [0, 1]
    assert harness._assign(changes, [{"kind": "setting"}, {"kind": "setting"}]) is None


# --------------------------------------------------------------------------------------------- file checks


def _write(tmp_path: Path, stem: str, data: dict[str, Any]) -> Path:
    path = tmp_path / f"{stem}.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def _minimal(case: str = "tiny") -> dict[str, Any]:
    return {
        "format": "roxy.insight_fixture/1",
        "rule": "SYS-ERRORS",
        "case": case,
        "description": "A tiny scenario written by the loader tests.",
        "now": "2026-10-07T15:00:00Z",
        "traffic_defaults": {"client_ip": "203.0.113.9"},
        "traffic": [
            {
                "name": "ok",
                "endpoint_template": "games.roblox.com/v1/games",
                "window": ["-10m", "0m"],
                "per_minute": 3,
                "egress": "none",
                "outcome": "served_cache",
                "reason": "cache_hit",
                "status": 200,
                "source": "cache",
                "cache_state": "HIT",
            },
        ],
        "expect": {"data_checks": [{"window": ["-10m", "0m"], "requests": 30}], "fires": False},
    }


def test_malformed_files_are_refused(tmp_path: Path) -> None:
    good = _minimal()
    harness.read_fixture(_write(tmp_path, "sys_errors__tiny", good))
    with pytest.raises(FixtureError, match="unknown top-level"):
        harness.read_fixture(_write(tmp_path, "sys_errors__tiny", {**good, "tabels": {}}))
    with pytest.raises(FixtureError, match="file name"):
        harness.read_fixture(_write(tmp_path, "sys_errors__other", good))
    with pytest.raises(FixtureError, match="unknown rule"):
        harness.read_fixture(_write(tmp_path, "sys_errors__tiny", {**good, "rule": "NOPE"}))
    bad_traffic = {**good, "traffic": [{**good["traffic"][0], "upstream_calls": 1}]}
    with pytest.raises(FixtureError, match="egress none"):
        harness.dry_check(_write(tmp_path, "sys_errors__tiny", bad_traffic))
    lying = {**good, "expect": {"data_checks": [{"window": ["-10m", "0m"], "requests": 31}], "fires": False}}
    with pytest.raises(FixtureError, match="requests is 30"):
        harness.dry_check(_write(tmp_path, "sys_errors__tiny", lying))
    with pytest.raises(FixtureError, match="boolean"):
        harness.dry_check(_write(tmp_path, "sys_errors__tiny", {**good, "settings": {"cache_post_requests": False}}))


async def test_any_fixture_file_runs_by_path(tmp_path: Path) -> None:
    path = _write(tmp_path, "sys_errors__tiny", _minimal())
    results = await harness.run_fixture(str(path))
    assert results == {"tiny": []}


# ---------------------------------------------------------------------------------------- every committed file


def test_the_committed_fixture_set_is_complete() -> None:
    assert len(ALL_FIXTURES) >= 148
    assert "up_429_endpoint__before_after_11_6" in ALL_FIXTURES


@pytest.mark.parametrize("stem", ALL_FIXTURES)
def test_every_committed_fixture_is_valid_and_honest(stem: str) -> None:
    """Format, settings, consistency rules and `data_checks` against the expanded events (no databases)."""
    dry = harness.dry_check(stem)
    assert dry.name == stem
    assert any(dry.data.get(key) for key in ("traffic", "events", "state", "tables", "settings"))


@pytest.mark.parametrize("stem", sorted(LOADER_PATHS))
async def test_fixture_loads_fully(stem: str) -> None:
    """A full load (data checks repeated through the rollups) of fixtures that use every loader path."""
    state = await harness.loaded(stem)
    assert state.engine.rules  # the rule set loaded with the state
    assert state.clock.now() == state.now


async def test_loader_writes_history_tables_and_providers() -> None:
    pressure = await harness.loaded("cache_pressure__fires_bytes_cap")
    summary = await pressure.dbs.metrics.read(
        lambda c: read_history.cache_summary(c, int(pressure.now) - 3600, int(pressure.now))
    )
    assert summary["stores"] == 6000
    assert summary["young_evictions"] == 420
    assert (await pressure.providers.disk() or {})["files"]["cache.db"]["bytes"] == 69_500_000
    flap = await harness.loaded("up_breaker_flap__search_flapping")
    openings = await flap.dbs.metrics.read(
        lambda c: read_history.events_between(c, ["breaker_open"], int(flap.now) - 86_400, int(flap.now) + 1)
    )
    assert openings
    assert all("key" in row["detail"] for row in openings)
    unused = await harness.loaded("cred_unused__fires")
    assert await unused.providers.extra("x_credential_comparisons")
