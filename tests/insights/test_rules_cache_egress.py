"""The cache, host, egress and credential rules (plan 11.5) against their committed fixtures, plus their helpers.

What this is
    Every case of every fixture file of CACHE-LOW-HIT, CACHE-KEYSPLIT, CACHE-PRESSURE, CACHE-OFF, CACHE-NEG,
    HOT-ENDPOINT, HOST-ADD, EGR-BURN, EGR-UNDERUSE, EGR-POOL-BURNED, EGR-CALIBRATE, CRED-EXPIRING, CRED-UNUSED,
    CRED-ROTATOR-GUARD and CRED-PROBE-COST (the file's own case and each variant), run through the harness, which
    evaluates the rule through the engine's per-rule entry point. Plus tests of what the fixtures cannot show:
    the production shapes of the records the fixtures write in a provisional or simplified form (the egress
    module's `leak_blocked` event and disabled-egress rows, a probe result of `rejected`, comparison events,
    refusals filed under a problem template, aggregated internal call rows, sampled request counts, metering mode
    read from the rows), the safety of the key split fix (text and id parameters are never ignored), the parity of
    the new read models with the code they mirror, and that each rule's help text and settings are complete.

Why it exists
    Plan 19.10 row 11: the fixtures were written from the 11.5 table before the rules existed; passing them
    unchanged is the acceptance criterion. The production-shape tests keep the rules working on what the modules
    really record.

What to read next
    `tests/insights/harness.py`, `roxy/insights/rules/cache.py`, `roxy/insights/rules/egress.py`,
    `roxy/insights/rules/credential.py`, `roxy/insights/providers_rules_cache_egress.py`.
"""

from __future__ import annotations

import hashlib
import inspect
import json
from collections.abc import AsyncIterator
from typing import Any

import pytest

from insights.harness import LoadedFixture, apply_case_settings, fixture_ids, load, run_case
from roxy.cache import read_spread
from roxy.cache.store import SharedTier
from roxy.config.catalog import CATALOG
from roxy.config.insight_params import INSIGHT_RULES
from roxy.core.clock import FakeClock
from roxy.egress import read_usage
from roxy.egress.clients import DISABLED_KEY_PREFIX
from roxy.egress.rotator import usage_since
from roxy.insights import providers_rules_cache_egress as extra
from roxy.insights.models import Recommendation
from roxy.insights.rules import load_rules
from roxy.insights.rules.cache import is_id_name, looks_like_buster

PREFIXES = (
    "cache_low_hit__",
    "cache_keysplit__",
    "cache_pressure__",
    "cache_off__",
    "cache_neg__",
    "hot_endpoint__",
    "host_add__",
    "egr_burn__",
    "egr_underuse__",
    "egr_pool_burned__",
    "egr_calibrate__",
    "cred_expiring__",
    "cred_unused__",
    "cred_rotator_guard__",
    "cred_probe_cost__",
)
RULE_IDS = (
    "CACHE-LOW-HIT",
    "CACHE-KEYSPLIT",
    "CACHE-PRESSURE",
    "CACHE-OFF",
    "CACHE-NEG",
    "HOT-ENDPOINT",
    "HOST-ADD",
    "EGR-BURN",
    "EGR-UNDERUSE",
    "EGR-POOL-BURNED",
    "EGR-CALIBRATE",
    "CRED-EXPIRING",
    "CRED-UNUSED",
    "CRED-ROTATOR-GUARD",
    "CRED-PROBE-COST",
)
CASES = fixture_ids(PREFIXES)


@pytest.mark.parametrize(
    ("stem", "case"), CASES, ids=[stem if case is None else f"{stem}[{case}]" for stem, case in CASES]
)
async def test_rule_fixture(stem: str, case: str | None) -> None:
    await run_case(stem, case)


def test_every_rule_has_fixtures_for_fires_quiet_and_switch() -> None:
    by_rule: dict[str, list[str]] = {}
    for stem, case in CASES:
        by_rule.setdefault(stem.split("__", 1)[0], []).append(case or stem.split("__", 1)[1])
    assert set(by_rule) == {INSIGHT_RULES[rule_id].slug for rule_id in RULE_IDS}
    for slug, cases in by_rule.items():
        assert "disabled" in cases, slug  # the per-rule switch (19.10)
        assert len(cases) >= 4, slug


def test_help_text_and_settings_for_every_rule() -> None:
    rules = load_rules()
    for rule_id in RULE_IDS:
        rule = rules[rule_id]
        help_text = rule.help_text
        assert help_text, rule_id
        assert not help_text.startswith(" "), rule_id
        assert len(help_text) > len(rule.spec.title), rule_id
        assert chr(0x2014) not in help_text, rule_id  # C5: no em dash
        assert chr(0x2013) not in help_text, rule_id  # C5: no en dash
        card = rule.describe()
        for key in (card["settings"]["enabled"], card["settings"]["severity"], *card["settings"]["params"].values()):
            assert key in CATALOG, key
        for name in card["settings"]["params"]:
            assert f"`{name}`" in help_text, f"{rule_id}: the help text names every threshold ({name})"


def test_buster_shapes_and_id_names() -> None:
    assert looks_like_buster("_", ["1791384480000", "1791384487919"])
    assert looks_like_buster("cb", ["48213", "a3f9c0d1e2"])
    assert looks_like_buster("v", ["0f9e8d7c-6b5a-4321-8fed-cba987654321"])
    assert looks_like_buster("r", ["0.83921", ".1234"])  # Math.random()
    assert not looks_like_buster("page", ["2", "3", "17"])  # page numbers and limits select different answers
    assert not looks_like_buster("keyword", ["hat", "sword"])  # search terms change the answer
    assert not looks_like_buster("t", ["1791383880", "hat"])  # every value must look like a buster
    assert not looks_like_buster("_", [])
    for name in ("userIds", "universeIds", "placeId", "id", "groupIds", "assetIds"):
        assert is_id_name(name), name
        assert not looks_like_buster(name, ["1000000101", "1000000102"]), name
    for name in ("_", "t", "cb", "keyword", "cursor"):
        assert not is_id_name(name), name


def test_counted_uses_the_right_number() -> None:
    assert extra.counted(1, "key") == "1 key"
    assert extra.counted(2, "key") == "2 keys"
    assert extra.counted(3, "cache entry") == "3 cache entries"
    assert extra.counted(0, "hit") == "0 hits"
    assert extra.counted(1200, "pass") == "1,200 passes"


# ------------------------------------------------------------------------------------------- read model parity


def _entry(entry_id: str, key: str, path: str, params: list[list[str]], **extra_columns: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": entry_id,
        "key": key,
        "method": "GET",
        "host": "games.roblox.com",
        "path": path,
        "params_json": json.dumps({"params": params, "stripped": []}),
        "status": 200,
        "stored_at": 1,
        "expires_at": 2,
        "stale_until": 3,
        "ttl": 60,
        "hits": 0,
        "body_len": 10,
        "body": b"r0123456789",
        "negative": 0,
        "generation": 0,
    }
    row.update(extra_columns)
    return row


def _insert_entries(conn: Any, rows: list[dict[str, Any]]) -> None:
    for row in rows:
        names = ", ".join(row)
        conn.execute(f"INSERT INTO entries ({names}) VALUES ({', '.join('?' for _ in row)})", list(row.values()))


async def test_spread_rows_match_the_shared_tier(dbs: Any) -> None:
    rows = [
        _entry(
            "a" * 24, "GET games.roblox.com/v1/games?_=1&universeIds=1", "v1/games", [["universeIds", "1"], ["_", "1"]]
        ),
        _entry(
            "b" * 24, "GET games.roblox.com/v1/games?_=2&universeIds=1", "v1/games", [["universeIds", "1"], ["_", "2"]]
        ),
        # A 429 marker and a single-flight handoff row are not entries of the key spread.
        _entry(
            "c" * 24,
            "GET games.roblox.com/v1/games?universeIds=9",
            "v1/games",
            [["universeIds", "9"]],
            negative=1,
            status=429,
        ),
        _entry("d" * 24, "GET games.roblox.com/v1/games?universeIds=8 !flight", "v1/games", [["universeIds", "8"]]),
        # An entry of an older purge generation is a miss already.
        _entry("e" * 24, "GET games.roblox.com/v1/games?universeIds=7", "v1/games", [["universeIds", "7"]]),
    ]
    dbs.cache.write_sync(lambda conn: _insert_entries(conn, rows))
    dbs.cache.write_sync(lambda conn: conn.execute("UPDATE entries SET generation = 1 WHERE id != ?", ("e" * 24,)))
    dbs.cache.write_sync(lambda conn: conn.execute("UPDATE generation SET value = 1 WHERE id = 1"))
    mine = dbs.cache.read_sync(lambda conn: read_spread.spread_rows(conn, 100))
    theirs = await SharedTier(dbs.cache, FakeClock()).spread_rows(100)
    assert mine == theirs
    assert sorted(json.loads(str(r[3]))["params"][-1][1] for r in mine) == ["1", "2"]


def test_usage_split_totals_match_usage_since(dbs: Any) -> None:
    day = 1_791_331_200  # 2026-10-07 00:00 UTC
    rows = [
        (day - 2 * 86_400, "rotator", "day", 10, 1000, 2000, 300),
        (day - 86_400, "rotator", "day", 10, 1000, 2000, 300),
        (day, "rotator", "hour", 5, 100, 200, 30),
        (day + 3600, "rotator", "minute", 1, 10, 20, 3),
        (day + 3660, "rotator", "minute", 1, 10, 20, 3),
        (day + 3660, "direct", "minute", 1, 999, 999, 0),
    ]
    dbs.metrics.write_sync(
        lambda conn: conn.executemany(
            "INSERT INTO egress_usage (bucket_start, egress, granularity, requests, req_bytes, resp_bytes, "
            "overhead_bytes) VALUES (?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
    )
    start = day - 2 * 86_400
    split = dbs.metrics.read_sync(lambda conn: read_usage.usage_split(conn, "rotator", start))
    assert split["total_bytes"] == dbs.metrics.read_sync(lambda conn: usage_since(conn, "rotator", start))
    assert split == {
        "requests": 27,
        "req_bytes": 2120,
        "resp_bytes": 4240,
        "overhead_bytes": 636,
        "total_bytes": 6996,
    }
    before = dbs.metrics.read_sync(lambda conn: read_usage.usage_split(conn, "rotator", start, day + 3660))
    assert before["requests"] == 26  # the minute row at the end is left out


# --------------------------------------------------------------------------------------- production shapes


@pytest.fixture
async def fresh() -> AsyncIterator[list[LoadedFixture]]:
    """Fixtures loaded privately for a test that adds rows (the harness cache is shared by the fixture cases)."""
    states: list[LoadedFixture] = []
    yield states
    for state in states:
        state.close()


async def _load(fresh: list[LoadedFixture], name: str) -> LoadedFixture:
    state = await load(name)
    fresh.append(state)
    return state


def _event(
    state: LoadedFixture,
    at_s: float,
    event_type: str,
    reason: str | None,
    detail: dict[str, Any],
    *,
    ip_hash: str | None = None,
    place: str | None = None,
    template: str | None = None,
) -> None:
    state.dbs.metrics.write_sync(
        lambda conn: conn.execute(
            "INSERT INTO events (at_ms, type, severity, reason_code, ip_hash, place, endpoint_template, detail_json) "
            "VALUES (?, ?, 'info', ?, ?, ?, ?, ?)",
            (int(at_s * 1000), event_type, reason, ip_hash, place, template, json.dumps(detail)),
        )
    )


async def _evaluate(state: LoadedFixture) -> list[Recommendation]:
    outcome = await state.engine.evaluate_rule(state.rule, now=state.now)
    assert outcome.error is None, outcome.error
    return outcome.recommendations


async def test_leak_blocked_event_and_a_disabled_egress_fire_the_guard(fresh: list[LoadedFixture]) -> None:
    state = await _load(fresh, "cred_rotator_guard__smuggling_quiet")
    assert await _evaluate(state) == []
    # `egress/clients.py _on_leak`: the event `leak_blocked` and the fleet-wide disabled-egress row.
    _event(state, state.now - 300, "leak_blocked", "leak_blocked", {"egress": "direct", "location": "query"})
    row = {
        "reason": "leak_guard",
        "since": int(state.now - 300),
        "location": "query",
        "purpose": "caller",
        "request_id": "01JREQUEST",
        "worker": "w1",
    }
    state.dbs.control.write_sync(
        lambda conn: conn.execute(
            "INSERT INTO service_state (key, value_json, updated_at) VALUES (?, ?, ?)",
            (DISABLED_KEY_PREFIX + "direct", json.dumps(row), int(state.now)),
        )
    )
    recs = await _evaluate(state)
    assert [r.subject for r in recs] == ["leak guard direct"]
    rec = recs[0]
    assert (rec.severity, rec.safe_auto, rec.change_kinds) == ("critical", False, ("manual",))
    assert rec.evidence.details["egress_disabled_since"]
    assert rec.evidence.details["request_ids"] == ["01JREQUEST"]


async def test_production_probe_shapes_fire_cred_expiring(fresh: list[LoadedFixture]) -> None:
    state = await _load(fresh, "cred_expiring__healthy")
    assert await _evaluate(state) == []
    # `egress/credential.py` records `result: rejected` with the real status (not `rejected_403`).
    probe = {"kind": "liveness", "result": "rejected", "status": 403}
    _event(state, state.now - 300, "credential_probe", "credential", probe)
    recs = await _evaluate(state)
    assert len(recs) == 1
    assert recs[0].severity == "critical"
    assert recs[0].change_kinds == ("manual",)
    probe = {"kind": "admin_check", "result": "rate_limited", "status": 429}
    _event(state, state.now - 200, "credential_probe", "credential", probe)
    assert await _evaluate(state) == []  # the newest check was only rate limited: not a rejection
    _event(
        state,
        state.now - 100,
        "credential_probe",
        "credential",
        {"kind": "admin_check", "result": "account_mismatch", "status": 200},
    )
    recs = await _evaluate(state)
    assert len(recs) == 1
    assert "different Roblox account" in recs[0].explanation


async def test_comparison_events_count_for_cred_unused(fresh: list[LoadedFixture]) -> None:
    state = await _load(fresh, "cred_unused__below_thresholds")
    assert await _evaluate(state) == []
    template = "games.roblox.com/v1/games/{universeId}/favorites/count"
    detail = {"endpoint_template": template, "method": "GET", "anon_status": 200, "cred_status": 200, "identical": True}
    _event(state, state.now - 60, extra.COMPARISON_EVENT, None, detail)
    recs = await _evaluate(state)
    assert [r.subject for r in recs] == ["games.roblox.com/v1/games/*/favorites/count"]
    assert recs[0].evidence.metric("comparisons") == 20
    assert recs[0].change_kinds == ("credential_allowlist_remove",)
    assert recs[0].changes[0].table == "credential_allowlist"  # what the allowlist API's evidence check reads


async def test_host_add_reads_the_host_from_the_refusal_path(fresh: list[LoadedFixture]) -> None:
    state = await _load(fresh, "host_add__below_thresholds")
    assert await _evaluate(state) == []
    # The proxy files a refused target under the fixed template `(host_not_allowed)`; the host is in the path.
    path = {"path": "AdConfiguration.roblox.com/v2/x"}
    _event(state, state.now - 600, "refusal", "host_not_allowed", path, ip_hash="f" * 16, place="1000000099",
           template="(host_not_allowed)")  # fmt: skip
    _event(state, state.now - 590, "refusal", "host_not_allowed", {"status": 404}, ip_hash="e" * 16,
           template="(host_not_allowed)")  # fmt: skip
    recs = await _evaluate(state)
    assert [r.subject for r in recs] == ["adconfiguration.roblox.com"]
    assert recs[0].evidence.metric("distinct_ips") == 50
    assert recs[0].evidence.metric("distinct_places") == 5
    assert recs[0].changes[0].proposed[-1] == "adconfiguration.roblox.com"


async def test_calibrate_reads_estimate_mode_from_the_rows(fresh: list[LoadedFixture]) -> None:
    state = await _load(fresh, "egr_calibrate__fires_estimate_mode")
    # Production providers report `socket` whatever the egress runs; the overhead in the rows tells the truth.
    state.providers.metering = {"metering_mode": "socket"}
    recs = await _evaluate(state)
    assert [c.key for c in recs[0].changes] == ["rotator_tls_overhead_bytes"]


async def test_aggregated_internal_calls_are_counted(fresh: list[LoadedFixture]) -> None:
    state = await _load(fresh, "cred_probe_cost__at_threshold")
    assert await _evaluate(state) == []
    detail = {"ok": True, "trigger": "scheduled", "egress": "credential", "aggregated": True, "count": 10}
    _event(state, state.now - 300, "internal_call", "credential_probe", detail)
    recs = await _evaluate(state)
    assert recs[0].evidence.metric("credential_calls") == 16
    assert recs[0].evidence.metric("scheduled_calls") == 12


async def test_probe_cost_without_recorded_triggers(fresh: list[LoadedFixture]) -> None:
    state = await _load(fresh, "cred_expiring__healthy")  # a credential and no internal calls
    for i in range(8):  # what `upstream/service.py _record_internal` writes today: no trigger
        _event(state, state.now - 600 - i, "internal_call", "credential_probe", {"ok": True, "egress": "credential"})
    outcome = await state.engine.evaluate_rule("CRED-PROBE-COST", now=state.now)
    rec = outcome.recommendations[0]
    # At the default 30 minute interval the liveness job explains 2 calls; the other 6 no setting limits.
    assert rec.change_kinds == ("manual",)
    assert rec.evidence.details["by_trigger"] == {"unrecorded": 8}
    await apply_case_settings(state, {"credential_probe_interval_min": 5})
    outcome = await state.engine.evaluate_rule("CRED-PROBE-COST", now=state.now)
    change = outcome.recommendations[0].changes[0]
    assert (change.key, change.current, change.proposed) == ("credential_probe_interval_min", 5, 30)


async def test_cache_neg_scales_sampled_counts(fresh: list[LoadedFixture]) -> None:
    state = await _load(fresh, "cache_neg__below_threshold")
    assert await _evaluate(state) == []
    await apply_case_settings(state, {"request_sample_pct": 50})
    recs = await _evaluate(state)
    assert recs[0].evidence.metric("identical_error_refetches_per_hour") == 96 * 2 - 1
    assert recs[0].evidence.metric("request_sample_pct") == 50


async def test_text_and_id_parameters_are_never_ignored(fresh: list[LoadedFixture]) -> None:
    state = await _load(fresh, "cache_keysplit__legit_reused_ids")
    assert await _evaluate(state) == []
    rows = []
    for i, word in enumerate(("hat", "sword", "wings", "crown", "shield", "cape")):
        key = f"GET catalog.roblox.com/v1/search/items?keyword={word}"
        rows.append(
            _entry(
                hashlib.sha256(key.encode()).hexdigest()[:24],
                key,
                "v1/search/items",
                [["keyword", word]],
                host="catalog.roblox.com",
                stored_at=int(state.now) - 60 * i,
            )
        )
        key = f"GET badges.roblox.com/v1/badges?badgeId={1000000700 + i}"
        rows.append(
            _entry(
                hashlib.sha256(key.encode()).hexdigest()[:24],
                key,
                "v1/badges",
                [["badgeId", str(1000000700 + i)]],
                host="badges.roblox.com",
                stored_at=int(state.now) - 60 * i,
            )
        )
    state.dbs.cache.write_sync(lambda conn: _insert_entries(conn, rows))
    recs = await _evaluate(state)
    assert sorted(r.subject for r in recs) == ["badges.roblox.com/v1/badges", "catalog.roblox.com/v1/search/items"]
    for rec in recs:
        assert rec.change_kinds == ("manual",), rec.subject  # reported, never ignored
        assert rec.evidence.details["split"]["fix"] == "manual"


def test_rule_modules_hold_no_sql() -> None:
    """Rules read through the context and the read models only (DESIGN.md 13, `rules/base.py` step 4)."""
    from roxy.insights.rules import cache, credential, egress

    for module in (cache, credential, egress):
        source = inspect.getsource(module)
        assert "conn.execute" not in source, module.__name__
        assert ".write(" not in source, module.__name__
