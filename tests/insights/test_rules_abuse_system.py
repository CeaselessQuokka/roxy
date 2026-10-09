"""The abuse, filter, system and security rules against their committed fixtures (plan 19.10 row 11), plus units.

What this is
    Every case of every fixture of ABUSE-SPAM, ABUSE-BOT, ABUSE-DIST, FILTER-ADD, FILTER-REMOVE, FILTER-COLLATERAL,
    TARPIT-TUNE, THROTTLE-TUNE, PLACE-HEAVY, SYS-DISK, SYS-WORKER-SAT, SYS-LOOP-LAG, SYS-METRICS-DROP,
    SYS-CHANGE-REGRESSION, SYS-HEALTH-FAIL, SEC-ADMIN-ALLOWLIST, SEC-BYPASS-FOREVER and SEC-DEFAULTS (the file's own
    case and each variant) run through the harness, which evaluates the rule through the engine's per-rule entry point.
    Each result is also checked against the plan's invariants (no place ban, nothing global marked safe to auto-apply)
    and previewed by `RecommendationActions`, so every proposed change is one the apply path accepts. Unit tests cover
    the helpers and the per-caller read model (`roxy/metrics/read_caller_facts.py`).

Why it exists
    The fixtures were written from the 11.5 table before the rules existed; passing them unchanged is the acceptance
    criterion. The preview check proves the changes are not only well described but appliable.

What to read next
    `tests/insights/harness.py`, `roxy/insights/rules/abuse.py`, `roxy/insights/rules/system.py`,
    `roxy/insights/rules/security.py`.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

import pytest
import yaml

from insights.harness import FIXTURE_DIR, RECORDER_SAMPLED_RULES, fixture_ids, loaded, run_case
from roxy.config import catalog
from roxy.config.settings_service import SettingsService
from roxy.insights.actions import RecommendationActions
from roxy.insights.models import Recommendation
from roxy.insights.rules import load_rules
from roxy.insights.rules.abuse import _collateral_places, _detector_id, _owner, _repeated_auto_bans, highest_safe
from roxy.insights.rules.security import covered, network_of, safer_value
from roxy.insights.rules.system import (
    SysChangeRegression,
    projected_bytes,
    regression_rates,
    sentence,
    sustained_workers,
    worse_by,
)
from roxy.metrics import read_caller_facts
from roxy.metrics.queries import Window
from roxy.rules.service import RulesService
from roxy.storage.db import DB_NAMES
from roxy.storage.migrate import migrate_paths

RULE_PREFIXES = {
    "ABUSE-SPAM": "abuse_spam__",
    "ABUSE-BOT": "abuse_bot__",
    "ABUSE-DIST": "abuse_dist__",
    "FILTER-ADD": "filter_add__",
    "FILTER-REMOVE": "filter_remove__",
    "FILTER-COLLATERAL": "filter_collateral__",
    "TARPIT-TUNE": "tarpit_tune__",
    "THROTTLE-TUNE": "throttle_tune__",
    "PLACE-HEAVY": "place_heavy__",
    "SYS-DISK": "sys_disk__",
    "SYS-WORKER-SAT": "sys_worker_sat__",
    "SYS-LOOP-LAG": "sys_loop_lag__",
    "SYS-METRICS-DROP": "sys_metrics_drop__",
    "SYS-CHANGE-REGRESSION": "sys_change_regression__",
    "SYS-HEALTH-FAIL": "sys_health_fail__",
    "SEC-ADMIN-ALLOWLIST": "sec_admin_allowlist__",
    "SEC-BYPASS-FOREVER": "sec_bypass_forever__",
    "SEC-DEFAULTS": "sec_defaults__",
}
CASES = fixture_ids(tuple(RULE_PREFIXES.values()))


def _invariants(recs: list[Recommendation]) -> None:
    """Plan 11.2, 11.4 and 10.3 invariants every recommendation of these rules keeps."""
    for rec in recs:
        for change in rec.changes:
            if change.kind == "ban_add":
                proposed = change.proposed or {}
                assert proposed.get("subject_type") != "place", "places are never banned automatically (10.3)"
                assert proposed.get("expires_at") is not None, "bans proposed by these rules are temporary"
            if change.kind in ("setting", "tarpit_category", "host_add"):
                assert not rec.safe_auto, "a global setting is never safe_auto (11.2)"
        assert rec.title
        assert rec.explanation
        assert rec.expected_impact
        assert rec.evidence.sample_size >= 1


async def _preview_problems(stem: str, recs: list[Recommendation]) -> list[str]:
    """Every change the apply path would refuse (manual steps excepted)."""
    state = await loaded(stem)
    actions = RecommendationActions(
        engine=state.engine,
        settings_service=SettingsService(state.dbs.control, runtime=state.runtime, clock=state.clock),
        rules_service=RulesService(state.dbs.control, clock=state.clock),
        clock=state.clock,
    )
    problems = []
    for rec in recs:
        for item in await actions._preview(rec):
            if item.kind != "manual" and not item.valid:
                problems.append(f"{rec.subject}: {item.target}: {item.message}")
    return problems


@pytest.mark.parametrize(
    ("stem", "case"), CASES, ids=[stem if case is None else f"{stem}[{case}]" for stem, case in CASES]
)
async def test_rule_fixture(stem: str, case: str | None) -> None:
    recs = await run_case(stem, case)
    _invariants(recs)
    assert await _preview_problems(stem, recs) == []


def test_every_rule_has_fixtures_for_fires_quiet_and_switch() -> None:
    by_rule: dict[str, list[str | None]] = {}
    for stem, case in CASES:
        by_rule.setdefault(stem.split("__", 1)[0], []).append(case)
    assert set(by_rule) == {prefix[:-2] for prefix in RULE_PREFIXES.values()}
    for slug, cases in by_rule.items():
        files = list(FIXTURE_DIR.glob(f"{slug}__*.yaml"))
        fires = [yaml.safe_load(p.read_text(encoding="utf-8"))["expect"].get("fires") for p in files]
        assert True in fires, slug  # a scenario that fires (19.10)
        assert False in fires, slug  # and one that does not
        assert "disabled" in cases, slug  # the per-rule switch (19.10)


def test_recorder_sampled_rules_use_no_samples_side_outputs() -> None:
    """The harness hook turns on production sampling for these rules; a `samples` side output would mix sources."""
    for rule in RECORDER_SAMPLED_RULES:
        slug = rule.lower().replace("-", "_")
        for path in FIXTURE_DIR.glob(f"{slug}__*.yaml"):
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            generators = [
                *(data.get("traffic") or []),
                *(data.get("profiles") or {}).values(),
                data.get("traffic_defaults") or {},
            ]
            assert not any("samples" in g for g in generators), path.name


def test_rules_are_registered_with_help_and_settings() -> None:
    rules = load_rules()
    for rule_id in RULE_PREFIXES:
        rule = rules[rule_id]
        assert rule.help_text
        assert not rule.help_text.startswith(" ")
        assert not rule.safe_auto
        assert rule.triggers
        card = rule.describe()
        assert card["settings"]["enabled"] == f"insight_{rule.slug}_enabled"
        for name, key in card["settings"]["params"].items():
            assert key in catalog.CATALOG, (rule_id, name)


# ------------------------------------------------------------------------------------------------ helpers


def test_detector_ids_from_events_and_ban_creators() -> None:
    assert _detector_id("SPAM-RATE") == "rate"
    assert _detector_id("auto:spam_refused") == "refused"
    assert _detector_id("throttle_ladder") is None
    assert _detector_id("SPAM-NOPE") is None


def test_repeated_auto_bans_need_two_recent_automatic_bans() -> None:
    now = 10_000_000.0
    rows = [
        {"subject_type": "ip", "subject": "192.0.2.1", "created_by": "auto:spam_rate", "created_at": now - 7200},
        {"subject_type": "ip", "subject": "192.0.2.1", "created_by": "auto:spam_rate", "created_at": now - 600},
        {"subject_type": "ip", "subject": "192.0.2.2", "created_by": "auto:spam_rate", "created_at": now - 600},
        {"subject_type": "ip", "subject": "192.0.2.3", "created_by": "admin:owner", "created_at": now - 600},
        {"subject_type": "ip", "subject": "192.0.2.3", "created_by": "admin:owner", "created_at": now - 60},
        {"subject_type": "ip", "subject": "192.0.2.4", "created_by": "auto:spam_rate", "created_at": now - 20 * 86_400},
        {"subject_type": "ip", "subject": "192.0.2.4", "created_by": "auto:spam_rate", "created_at": now - 10 * 86_400},
        {"subject_type": "place", "subject": "1", "created_by": "auto:spam_rate", "created_at": now - 60},
        {"subject_type": "place", "subject": "1", "created_by": "auto:spam_rate", "created_at": now - 30},
    ]
    found = _repeated_auto_bans(rows, now)
    assert set(found) == {"ip:192.0.2.1"}  # .2 once, .3 manual, .4 stale, places never
    assert [r["created_at"] for r in found["ip:192.0.2.1"]] == [now - 7200, now - 600]


def test_highest_safe_stays_out_of_the_high_risk_range_and_the_catalog_range() -> None:
    assert highest_safe("allowed_requests_per_minute", 5000) == 999  # gte 1000 is high risk
    assert highest_safe("metrics_queue_max", 300_000) == 200_000  # gt 200000 is high risk
    assert highest_safe("tarpit_max_capacity_fraction", 0.9) == pytest.approx(0.4)  # max 0.5, gt 0.4 high risk
    assert highest_safe("tarpit_max_concurrent", 900) == 500  # the catalog maximum
    assert highest_safe("tarpit_max_concurrent", 65) == 65


def test_filter_ownership_and_collateral_places() -> None:
    rows = [
        {"id": 1, "pattern": "avatar.roblox.com/v1/users/*/avatar", "type": "glob"},
        {"id": 2, "pattern": "avatar.roblox.com/*", "type": "glob"},
    ]
    owner = _owner("rules_endpoint_block", rows, "avatar.roblox.com/v1/users/{userId}/avatar")
    assert owner is not None
    assert owner["id"] == 1  # the most specific match
    assert _owner("rules_endpoint_block", rows, "games.roblox.com/v1/games") is None
    assert _owner("rules_user_agent", [{"id": "a"}], None) == {"id": "a"}
    assert _owner("rules_user_agent", [{"id": "a"}, {"id": "b"}], None) is None  # cannot be told apart
    places = {"1": {"requests": 1000, "served": 990}, "2": {"requests": 100, "served": 50}, "3": {"requests": 5}}
    harmed = _collateral_places({"1": 10, "2": 10, "3": 5, "4": 7}, places, 95)
    assert [h["place"] for h in harmed] == ["1"]
    assert harmed[0]["served_pct"] == 100.0


def test_disk_projection_and_sentence() -> None:
    disk = {"growth": [{"at": 0, "total_bytes": 100}, {"at": 86_400, "total_bytes": 200}]}
    assert projected_bytes(disk, 200, days=30) == 200 + 30 * 100
    assert projected_bytes({"growth": [{"at": 0, "total_bytes": 1}]}, 5) is None
    shrinking = {"growth": [{"at": 0, "total_bytes": 300}, {"at": 86_400, "total_bytes": 200}]}
    assert projected_bytes(shrinking, 200) == 200
    assert sentence(["roxy uses 9 GB", "the disk is full"]) == "Roxy uses 9 GB; the disk is full."


def test_sustained_workers_need_every_minute_over_the_threshold() -> None:
    window = Window(600, 900, "minute", "UTC")
    history = {
        "w1": [{"bucket_start": m, "cpu_pct": 95.0} for m in range(0, 900, 60)],
        "w2": [{"bucket_start": m, "cpu_pct": 95.0 if m != 720 else 80.0} for m in range(0, 900, 60)],
        "w3": [{"bucket_start": m, "cpu_pct": 95.0} for m in range(600, 900, 60) if m != 780],
    }
    assert set(sustained_workers(history, "cpu_pct", 85, window)) == {"w1"}


def test_regression_rates_skip_a_zero_baseline() -> None:
    before = regression_rates({"requests": 100, "errors": 0, "upstream_calls": 50, "roblox_429": 1, "p95_ms": 200})
    after = regression_rates({"requests": 100, "errors": 5, "upstream_calls": 50, "roblox_429": 2, "p95_ms": 210})
    worse = worse_by(before, after)
    assert "error_rate" not in worse  # zero before: no percentage
    assert worse["roblox_429_rate"] == pytest.approx(100.0)
    assert worse["p95_ms"] == pytest.approx(5.0)
    assert regression_rates({"requests": 0})["p95_ms"] is None


def test_regression_reverts_rule_changes_exactly() -> None:
    rule = SysChangeRegression()
    row = {
        "id": 3,
        "pattern": "games.roblox.com/v1/games",
        "type": "glob",
        "ttl": 60,
        "stale_ttl": 0,
        "negative_ttl": 0,
        "methods": "GET",
        "normalize_flags": None,
        "note": "",
        "enabled": 1,
        "origin": "admin",
    }
    ctx: Any = None  # rule changes are reverted from the audit row alone; only setting reverts read the context
    base = {"kind": "rule", "target": "rules_cache:3", "at": 0}
    created = rule._revert(ctx, {**base, "action": "rule.create", "before": None, "after": row})
    assert created is not None
    assert (created.kind, created.match) == ("rule_delete", {"id": 3})
    deleted = rule._revert(ctx, {**base, "action": "rule.delete", "before": row, "after": None})
    assert deleted is not None
    assert (deleted.kind, deleted.current) == ("rule_upsert", None)
    assert (deleted.proposed["ttl"], deleted.proposed["methods"]) == (60, ["GET"])
    updated = rule._revert(ctx, {**base, "action": "rule.update", "before": row, "after": {**row, "ttl": 5}})
    assert updated is not None
    assert (updated.kind, updated.match, updated.proposed["ttl"]) == ("rule_upsert", {"id": 3}, 60)
    assert "id" not in updated.proposed
    unknown = {**base, "target": "not_a_table:1", "action": "rule.create", "before": None, "after": row}
    assert rule._revert(ctx, unknown) is None


def test_admin_networks_and_coverage() -> None:
    assert network_of("198.51.100.10") == "198.51.100.0/24"
    assert network_of("2001:db8:5:1::10") == "2001:db8:5:1::/64"
    assert network_of("::ffff:192.0.2.7") == "192.0.2.0/24"
    assert network_of("unknown") is None
    assert covered("198.51.100.0/24", ["198.51.0.0/16"])
    assert not covered("198.51.100.0/24", ["2001:db8::/32", "203.0.113.0/24", "not a cidr"])
    assert covered("2001:db8:5:1::/64", ["2001:db8::/32"])


def test_safer_values_are_never_high_risk() -> None:
    for key, spec in catalog.CATALOG.items():
        if not spec.high_risk_if or spec.sensitive:
            continue
        assert spec.is_high_risk_value(spec.default) is None, key  # the SEC-DEFAULTS remedy exists for every key
        for condition in spec.high_risk_if:
            if condition.op.value == "eq":
                value = safer_value(key, condition.value)
                assert value is not None, key
                assert spec.is_high_risk_value(value) is None, key


# ------------------------------------------------------------------------------------------------ read model


@pytest.fixture
def metrics_conn(tmp_path: Any) -> Any:
    paths = {name: tmp_path / f"{name}.db" for name in DB_NAMES}
    migrate_paths(paths, contract=True)
    conn = sqlite3.connect(paths["metrics"])
    yield conn
    conn.close()


def test_refusal_groups_add_aggregated_counts(metrics_conn: sqlite3.Connection) -> None:
    rows = [
        (60_000, "refusal", "endpoint_blocked", "1", "a.roblox.com/x", None),
        (61_000, "refusal", "endpoint_blocked", "1", "a.roblox.com/x", json.dumps({"count": 9, "aggregated": True})),
        (62_000, "refusal", "throttle", None, "a.roblox.com/x", None),
        (63_000, "failure", "upstream_busy", "1", "a.roblox.com/x", None),
        (900_000, "refusal", "endpoint_blocked", "1", "a.roblox.com/x", None),  # outside the window
    ]
    metrics_conn.executemany(
        "INSERT INTO events (at_ms, type, severity, reason_code, place, endpoint_template, detail_json) "
        "VALUES (?, ?, 'info', ?, ?, ?, ?)",
        rows,
    )
    found = read_caller_facts.refusal_groups(metrics_conn, 0, 600)
    assert found == [
        {"reason": "endpoint_blocked", "place": "1", "endpoint_template": "a.roblox.com/x", "count": 10},
        {"reason": "throttle", "place": None, "endpoint_template": "a.roblox.com/x", "count": 1},
    ]
    assert read_caller_facts.refusal_groups(metrics_conn, 0, 600, reasons=["throttle"])[0]["count"] == 1
    assert read_caller_facts.refusal_groups(metrics_conn, 0, 600, places=["2"]) == []
    assert read_caller_facts.refusal_groups(metrics_conn, 0, 600, reasons=[]) == []


def test_sampled_upstream_counts_requests_that_reached_roblox(metrics_conn: sqlite3.Connection) -> None:
    rows = [
        (60_000, "games.roblox.com/v1/games", "p1", "h1", "direct"),
        (61_000, "games.roblox.com/v1/games", "p1", "h1", "rotator"),
        (62_000, "users.roblox.com/v1/users/{userId}", "p1", "h2", "direct"),
        (63_000, "games.roblox.com/v1/games", "p2", "h2", "none"),  # a cache hit: no upstream call
        (64_000, "games.roblox.com/v1/games", None, "h3", "direct"),
        (125_000, "games.roblox.com/v1/games", "p1", "h1", "direct"),
    ]
    metrics_conn.executemany(
        "INSERT INTO request_samples (at_ms, endpoint_template, method, place, client_hash, egress) "
        "VALUES (?, ?, 'GET', ?, ?, ?)",
        rows,
    )
    by_place = read_caller_facts.sampled_upstream_by(metrics_conn, 0, 600, "place")
    assert by_place == {"rows": 6, "total": 5, "groups": {"p1": 4}}
    by_client = read_caller_facts.sampled_upstream_by(metrics_conn, 0, 600, "client_hash")
    assert by_client["groups"] == {"h1": 3, "h2": 1, "h3": 1}
    assert read_caller_facts.sampled_place_templates(metrics_conn, 0, 600, "p1") == {
        "games.roblox.com/v1/games": 3,
        "users.roblox.com/v1/users/{userId}": 1,
    }
    assert read_caller_facts.sampled_upstream_minutes(
        metrics_conn, 0, 600, place="p1", template="games.roblox.com/v1/games"
    ) == {60: 2, 120: 1}
    with pytest.raises(ValueError):
        read_caller_facts.sampled_upstream_by(metrics_conn, 0, 600, "egress; DROP TABLE events")


def test_recent_user_agents_newest_first(metrics_conn: sqlite3.Connection) -> None:
    metrics_conn.executemany(
        "INSERT INTO fingerprint_user_agents (ua_hash, user_agent, count, first_seen, last_seen) "
        "VALUES (?, ?, 1, 1, ?)",
        [("a", "okhttp/4.12.0", 10), ("b", "Roblox/Linux", 20)],
    )
    assert read_caller_facts.recent_user_agents(metrics_conn) == ["Roblox/Linux", "okhttp/4.12.0"]
