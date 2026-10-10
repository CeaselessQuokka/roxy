"""Review round 3, lens insights: the 11.3 dry run against a replayed ground truth, and what a proposal covers.

What this is
    Adversarial tests (one per finding: insights-6, 7, 8, 9 and 14; they were strict xfails until review round 3
    fixed each, and now pin the fixed behavior) of `roxy/insights/simulate.py` and of the cache rule a
    recommendation proposes: the cache replay against a ground truth that follows the production store policy
    (`cache/policy.py store_decision`), the dry run over the request samples the real proxy records for a request
    the cache had off (the plan 11.6 card), the scope of a "new rule for exactly this template", and the note on a
    sampled replay.

Why it exists
    Plan 19.10 row 11: "dry-run estimates within 10% of a replayed ground truth"; plan 11.2 and 11.4: a change is
    `safe_auto` only when it is scoped to one endpoint, and auto-apply may then write it unattended. A replay that
    disagrees with the cache it models, or a proposal wider than its evidence, misleads the admin who clicks
    Apply on the strength of the preview.

How it works
    The ground truth walks the same samples through `store_decision` (what the cache really keeps) instead of
    "every fetch stores". The 11.6 test drives the real app (`create_app`, the real lifespan, respx playing Roblox)
    with POST batch requests while `cache_post_requests` is off, exactly the 11.6 situation, then asks the worker's
    `InsightsEngine.dry_run` about the 11.6 changes. The scope test inserts the rule a recommendation proposes
    through `RulesService` and asks the cache's own `select_rule` which rule a sibling endpoint gets.

What to read next
    `roxy/insights/simulate.py`, `roxy/cache/policy.py`, `roxy/cache/service.py` (`peek`),
    `roxy/insights/rules/cache.py` (`new_rule`), `tests/fixtures/insights/up_429_endpoint__before_after_11_6.yaml`.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx

from roxy.cache.policy import RequestPolicy, StoreKind, select_rule, store_decision
from roxy.config.audit import Actor
from roxy.config.runtime import load_runtime_settings
from roxy.config.settings_service import SettingsService
from roxy.core.clock import FakeClock
from roxy.core.reasons import AuthClass, ReasonCode
from roxy.insights import simulate
from roxy.insights.engine import InsightsEngine
from roxy.insights.models import Evidence, ProposedChange, Recommendation
from roxy.insights.rules.cache import new_rule
from roxy.main import create_app
from roxy.rules.match import compile_pattern
from roxy.rules.models import RULE_TABLES
from roxy.rules.service import RulesService
from roxy.rules.store import RulesStore, build_rules_snapshot

ADMIN = Actor("admin", "r3-insights")
NOW = 1_791_385_200.0  # 2026-10-07T15:00:00Z
TTL_S = 300
TEMPLATE = "games.roblox.com/v1/games/votes"


# --------------------------------------------------------------------------------------------- ground truth


POLICY = RequestPolicy(cacheable=True, off_reason=None, auth_class=AuthClass.ANON, ttl_s=TTL_S)
CACHE_SETTINGS = SimpleNamespace(negative_429=False, max_body=8 * 1024 * 1024)


def answer(sample: dict[str, Any]) -> SimpleNamespace:
    """The upstream answer a sample records, in the shape `store_decision` reads. A sample without an upstream
    status is a call Roblox never answered (a connect error: Roxy's 502, no upstream status)."""
    if sample.get("upstream_status") is None:
        return SimpleNamespace(
            status=502,
            headers={},
            body=b"",
            auth_class=AuthClass.ANON,
            upstream_status=None,
            reason=ReasonCode.UPSTREAM_CONNECT,
            retry_after_s=None,
            cooldown_s=None,
            cacheable=False,
        )
    status = int(sample["upstream_status"])
    reason = ReasonCode.UPSTREAM_OK if 200 <= status < 300 else ReasonCode.UPSTREAM_5XX
    return SimpleNamespace(
        status=status,
        headers={},
        body=b"{}",
        auth_class=AuthClass.ANON,
        upstream_status=status,
        reason=reason,
        retry_after_s=None,
        cooldown_s=None,
        cacheable=True,
    )


def ground_truth_calls(samples: list[dict[str, Any]], ttl_s: float) -> int:
    """Upstream calls the real cache makes for these requests under a rule of `ttl_s` (no SWR): a fresh entry
    answers; anything else calls Roblox, and the answer is kept only when `store_decision` keeps an entry."""
    stored: dict[str, int] = {}
    calls = 0
    for sample in sorted(samples, key=lambda s: (s["at_ms"], s["id"])):
        key, at = str(sample["key_id"]), int(sample["at_ms"])
        if key in stored and at - stored[key] < ttl_s * 1000:
            continue
        calls += 1
        if store_decision(answer(sample), POLICY, CACHE_SETTINGS).kind is StoreKind.ENTRY:  # type: ignore[arg-type]
            stored[key] = at
    return calls


def episode_samples() -> list[dict[str, Any]]:
    """100 keys asked three times 10 s apart; for 40 of them Roblox's first answer is a 503 (an UP-5XX episode,
    the kind of endpoint UP-5XX proposes a longer cache lifetime and SWR for)."""
    rows: list[dict[str, Any]] = []
    n = 0
    for key in range(100):
        start = NOW - 3000 + key * 20
        for step in range(3):
            failed_first = key < 40 and step == 0
            n += 1
            rows.append(
                {
                    "id": n,
                    "at_ms": int((start + step * 10) * 1000),
                    "key_id": f"k{key:03d}",
                    "endpoint_template": TEMPLATE,
                    "method": "GET",
                    "upstream_status": 503 if failed_first else 200,
                    "egress": "direct",
                    "body_hash": None if failed_first else f"{key:016x}",
                }
            )
    return rows


def test_r3_insights_ground_truth_follows_the_production_store_policy() -> None:
    """Not a finding: the ground truth's premise, checked on the production function."""
    ok = store_decision(answer({"upstream_status": 200}), POLICY, CACHE_SETTINGS)  # type: ignore[arg-type]
    failed = store_decision(answer({"upstream_status": 503}), POLICY, CACHE_SETTINGS)  # type: ignore[arg-type]
    assert ok.kind is StoreKind.ENTRY
    assert failed.kind is StoreKind.NONE  # 5xx answers are never content (DESIGN 11.9: cacheable is 2xx only)
    rows = episode_samples()
    assert ground_truth_calls(rows, TTL_S) == 40 * 2 + 60 * 1


def test_r3_insights_cache_replay_is_within_10_pct_of_the_ground_truth() -> None:
    """Finding insights-6 (fixed): the replay stores an answer only when `store_decision` keeps one."""
    rows = episode_samples()
    truth_avoided = len(rows) - ground_truth_calls(rows, TTL_S)  # 300 - 140 = 160
    replay = simulate.cache_replay(rows, ttl_s=TTL_S, swr_s=0)
    error = abs(replay.avoided_calls - truth_avoided) / truth_avoided
    assert error <= 0.10, (
        f"dry run {replay.avoided_calls} avoided calls, ground truth {truth_avoided} ({error:.0%} off)"
    )
    assert replay.avoided_calls == truth_avoided  # the same store policy gives the same calls
    assert replay.not_stored == 40  # the 40 first answers were 503s


NEGATIVE_TTL_S = 120
STATUS_REASONS = {
    200: ReasonCode.UPSTREAM_OK,
    302: ReasonCode.UPSTREAM_4XX,
    404: ReasonCode.UPSTREAM_4XX,
    410: ReasonCode.UPSTREAM_4XX,
    422: ReasonCode.UPSTREAM_4XX,
}
"""The reason code each status gets (anything else is a 5xx-style failure, as 429 and 503 are)."""


def test_r3_insights_cache_replay_follows_every_store_decision_row() -> None:
    """Finding insights-6 (fixed), every row of the store table: a 2xx is content, a 404 or 410 a negative entry for
    the error lifetime, and a 5xx, a 429, a 302 or a 422 nothing; replay and ground truth agree call for call.
    Review round 4 (finding LOGICFIX-4) adds the row of a call Roblox never answered (a connect error or a timeout:
    no upstream status, cache state MISS), which keeps nothing either."""
    statuses: list[int | None] = [200, 503, 429, 404, 410, 302, 422, 502, None]
    rows: list[dict[str, Any]] = []
    n = 0
    for key in range(90):
        first = statuses[key % len(statuses)]
        for step in range(4):  # the first answer, then three repeats 50 s apart (inside both lifetimes)
            n += 1
            status = first if step == 0 else 200
            rows.append(
                {
                    "id": n,
                    "at_ms": int((NOW - 3000 + key * 30 + step * 50) * 1000),
                    "key_id": f"m{key:03d}",
                    "endpoint_template": TEMPLATE,
                    "method": "GET",
                    "upstream_status": status,
                    "cache_state": "MISS",
                    "egress": "direct",
                    "body_hash": f"{key:016x}" if status == 200 else None,
                }
            )
    policy = RequestPolicy(
        cacheable=True, off_reason=None, auth_class=AuthClass.ANON, ttl_s=TTL_S, negative_ttl_s=NEGATIVE_TTL_S
    )
    stored: dict[str, tuple[int, int]] = {}
    calls = 0
    for sample in rows:
        name, at = str(sample["key_id"]), int(sample["at_ms"])
        if name in stored and at - stored[name][0] < stored[name][1] * 1000:
            continue
        calls += 1
        result = answer(sample)
        if sample["upstream_status"] is not None:
            result.reason = STATUS_REASONS.get(int(sample["upstream_status"]), ReasonCode.UPSTREAM_5XX)
        decision = store_decision(result, policy, CACHE_SETTINGS)  # type: ignore[arg-type]
        if decision.kind in (StoreKind.ENTRY, StoreKind.NEGATIVE):
            stored[name] = (at, decision.ttl_s)
    replay = simulate.cache_replay(rows, ttl_s=TTL_S, negative_ttl_s=NEGATIVE_TTL_S)
    assert calls == 10 * 1 + 20 * 2 + 60 * 2  # 2xx once; 404 and 410 again after 120 s; the rest twice
    assert replay.upstream_calls == calls
    assert (replay.misses, replay.not_stored) == (170, 60)  # 503, 429, 302, 422, 502 and no answer keep nothing
    without_errors = simulate.cache_replay(rows, ttl_s=TTL_S)  # no error lifetime: a 404 or 410 is not kept either
    assert without_errors.not_stored == 80
    assert [simulate.stored_as({"upstream_status": s}) for s in (200, 204, 404, 403, 503, 429)] == [
        "content", "content", "negative", "negative", None, None,
    ]  # fmt: skip
    # No upstream status: content only when the cache served it from an entry it had kept (LOGICFIX-4).
    assert [
        simulate.stored_as({"upstream_status": None, "cache_state": state})
        for state in ("HIT", "STALE", "REVALIDATING", "COALESCED", "MISS", "OFF", None)
    ] == ["content", "content", "content", "content", None, None, None]


# ------------------------------------------------------------------------------- the 11.6 card in production


def card_11_6() -> Recommendation:
    """The changes of the plan 11.6 card (UP-429-ENDPOINT on POST users.roblox.com/v1/users)."""
    pattern = "users.roblox.com/v1/users"
    return Recommendation(
        rule_id="UP-429-ENDPOINT",
        family="upstream",
        subject="POST users.roblox.com/v1/users",
        title="Roblox is rate-limiting POST users.roblox.com/v1/users on the direct path",
        evidence=Evidence(sample_size=40),
        changes=[
            ProposedChange(
                "rule_upsert",
                table="rules_cache",
                match={"pattern": pattern, "type": "glob"},
                current=None,
                proposed={
                    "pattern": pattern,
                    "type": "glob",
                    "ttl": 600,
                    "stale_ttl": 120,
                    "methods": "GET,POST",
                    "origin": "recommendation",
                },
            ),
            ProposedChange("setting", key="cache_post_requests", current="off", proposed="allowlist"),
        ],
    )


async def test_r3_insights_11_6_dry_run_over_production_samples(
    env: Any, credentials_dir: Path, respx_mock: Any
) -> None:
    """Finding insights-7 (fixed): a POST the cache has off by `cache_post_requests` is sampled with the key the
    cache would use (`CachePeek.off_key`), so the 11.6 dry run sees the repeats; nothing is served or stored under
    that key while POST caching is off, and it is the very key the cache uses once POST caching is on."""
    for name in ("smtp_password", "alert_webhook_url"):
        (credentials_dir / name).unlink(missing_ok=True)  # alerts go to the log only
    clock = FakeClock()
    app = create_app(env, clock=clock)
    lifespan = app.router.lifespan_context(app)
    await lifespan.__aenter__()
    try:
        ctx = app.state.ctx
        settings = SettingsService(ctx.dbs.control, runtime=ctx.settings, clock=clock)
        await settings.update(
            {"tarpit_enabled": 0, "rotator_enabled": 0, "cache_post_requests": "off"}, ADMIN, "the 11.6 situation"
        )
        route = respx_mock.route(method="POST", host="users.roblox.com", path="/v1/users").mock(
            return_value=httpx.Response(200, json={"data": [{"id": 1, "name": "x"}]})
        )
        bodies = [json.dumps({"userIds": [n + 1], "excludeBannedUsers": True}) for n in range(4)]
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 50000))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
            for n in range(40):
                response = await http.post(
                    "/users.roblox.com/v1/users",
                    content=bodies[n % 4],
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "Roblox/Linux",
                        "X-Forwarded-For": f"203.0.113.{n + 1}",
                    },
                )
                assert response.status_code == 200, response.content[:200]
                clock.advance(1)
        assert route.call_count == 40  # POST caching is off: every request went to Roblox
        await ctx.cache.settle()
        assert (ctx.cache.stats.off, ctx.cache.stats.misses, ctx.cache.stats.stores) == (40, 0, 0)  # never keyed in
        await ctx.recorder.flush()

        def read_samples() -> list[dict[str, Any]]:
            return ctx.dbs.metrics.read_sync(  # type: ignore[no-any-return]
                lambda c: [
                    dict(r)
                    for r in c.execute(
                        "SELECT key_id, method, upstream_status, cache_state FROM request_samples "
                        "WHERE endpoint_template = ? ORDER BY id",
                        ("users.roblox.com/v1/users",),
                    )
                ]
            )

        samples = read_samples()
        assert len(samples) == 40
        assert {s["cache_state"] for s in samples} == {"OFF"}
        assert len({s["key_id"] for s in samples}) == len(bodies)  # one identity per distinct body, never None
        assert None not in {s["key_id"] for s in samples}
        engine: InsightsEngine = ctx.insights
        report = await engine.dry_run(card_11_6())
        # Ground truth with the card applied: 4 distinct bodies inside the 600 s TTL, so 4 calls and 36 avoided.
        truth = 40 - len(set(bodies))
        assert report.avoided_calls is not None
        assert abs(report.avoided_calls - truth) <= 0.10 * truth, (
            f"dry run says {report.avoided_calls} avoided calls, ground truth {truth}; "
            f"key ids recorded: {sorted({str(s['key_id']) for s in samples})[:3]}"
        )
        # Once POST caching is on (the card's setting change; this endpoint is on the built-in allowlist), the cache
        # keys the first body under the very id its OFF samples carried: a MISS, then a HIT.
        await settings.update({"cache_post_requests": "allowlist"}, ADMIN, "the 11.6 card's setting change")
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
            for state in ("MISS", "HIT"):
                response = await http.post(
                    "/users.roblox.com/v1/users",
                    content=bodies[0],
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "Roblox/Linux",
                        "X-Forwarded-For": "203.0.113.200",
                    },
                )
                assert response.headers["Roxy-Cache"] == state
                await ctx.cache.settle()
        assert route.call_count == 41
        await ctx.recorder.flush()
        after = read_samples()[40:]
        assert [s["key_id"] for s in after] == [samples[0]["key_id"]] * 2
    finally:
        await lifespan.__aexit__(None, None, None)


# --------------------------------------------------------------------------------- what a new rule covers


async def test_r3_insights_a_rule_for_one_template_does_not_cover_its_siblings(dbs: Any) -> None:
    """Finding insights-8 (fixed): a new rule names exactly its template (an anchored regex, `template_match`)."""
    clock = FakeClock(NOW)
    store = RulesStore(dbs.control, clock=clock)
    await store.reload()
    service = RulesService(dbs.control, clock=clock, store=store)
    # HOT-ENDPOINT (safe_auto, so D7 may apply it unattended) proposes this for the hot template only.
    change = new_rule("users.roblox.com/v1/users", {"ttl": 600, "stale_ttl": 120, "methods": "GET"})
    assert change.match == {"pattern": r"^users\.roblox\.com/v1/users/?$", "type": "regex"}
    assert simulate.covers_exactly_one_template(change.match)
    fields = RULE_TABLES["rules_cache"].input_fields
    await service.create("rules_cache", {k: v for k, v in change.proposed.items() if k in fields}, ADMIN, "apply")
    snapshot = dbs.control.read_sync(lambda conn: build_rules_snapshot(conn, NOW))
    assert select_rule(snapshot, "users.roblox.com/v1/users", "GET", False) is not None  # the template itself
    assert select_rule(snapshot, "USERS.roblox.com/v1/users/", "GET", False) is not None  # case and one slash
    for sibling in ("users.roblox.com/v1/users/156", "users.roblox.com/v1/users/156/username-history"):
        covered = select_rule(snapshot, sibling, "GET", False)
        assert covered is None, f"the rule for users.roblox.com/v1/users also caches {sibling} for 600 s"
    # The stored row is the one the rule helpers recognize as the template's own (no second proposal).
    row = next(r for r in snapshot.cache_rules if r.type == "regex")
    assert row.pattern == change.match["pattern"]
    assert simulate.names_template(row.pattern, row.type, "users.roblox.com/v1/users")
    assert not simulate.names_template(row.pattern, row.type, "users.roblox.com/v1/users/{userId}")


def test_r3_insights_exact_template_patterns_cover_one_endpoint_each() -> None:
    """Finding insights-8 (fixed): placeholders cover one segment, any number of them passes rule validation, and
    only an exact template pattern reads as "scoped to one endpoint"."""
    many = "inventory.roblox.com/v1/users/{userId}/items/{itemType}/{itemTargetId}/is-owned/{x}"
    match = simulate.template_match(many)
    assert match["type"] == "regex"  # four placeholders: bounded segments keep it a valid regex
    compiled = compile_pattern(match["pattern"], "regex")
    assert compiled.matches("inventory.roblox.com/v1/users/156/items/Asset/2000/is-owned/1")
    assert not compiled.matches("inventory.roblox.com/v1/users/156/items/Asset/2000/is-owned/1/more")
    assert not compiled.matches("inventory.roblox.com/v1/users/156/items/Asset/is-owned/1")
    roles = simulate.template_match("groups.roblox.com/v1/groups/{groupId}/roles")
    assert compile_pattern(roles["pattern"], "regex").matches("groups.roblox.com/v1/groups/{groupId}/roles")
    assert simulate.covers_exactly_one_template(match)
    assert simulate.covers_exactly_one_template(roles)
    for wider in (
        {"pattern": "users.roblox.com/v1/users", "type": "glob"},
        {"pattern": r"^users\.roblox\.com/v1/users", "type": "regex"},
        {"pattern": r"^users\.roblox\.com/v1/(users|groups)/?$", "type": "regex"},
        {"pattern": r"^users\.roblox\.com/v1/.*/?$", "type": "regex"},
        None,
    ):
        assert not simulate.covers_exactly_one_template(wider), wider
    # The v1 glob of a template still names it (rules written before this fix, and admin rules).
    assert simulate.names_template(
        "groups.roblox.com/v1/groups/*/roles", "glob", "groups.roblox.com/v1/groups/{g}/roles"
    )
    # `safe_auto` (plan 11.2, "scoped to one endpoint"): a new pattern rule counts only when it is exact.
    exact_rule = new_rule("users.roblox.com/v1/users", {"ttl": 600})
    glob_rule = ProposedChange(
        "rule_upsert",
        table="rules_cache",
        match={"pattern": "users.roblox.com/v1/users", "type": "glob"},
        current=None,
        proposed={"pattern": "users.roblox.com/v1/users", "type": "glob", "ttl": 600},
    )
    # Review round 4 (finding LOGICFIX-2): an UPDATE of a template's own legacy glob row is not scoped either (the
    # glob also sets the TTL of every path below the template); an update of its own exact row is.
    own_update = ProposedChange(
        "rule_upsert", table="rules_cache", match=glob_rule.match, current={"ttl": 300}, proposed={"ttl": 600}
    )
    exact_update = ProposedChange(
        "rule_upsert", table="rules_cache", match=exact_rule.match, current={"ttl": 300}, proposed={"ttl": 600}
    )
    widened = ProposedChange(  # an update that rewrites an exact row's pattern into a glob
        "rule_upsert",
        table="rules_cache",
        match=exact_rule.match,
        current={"ttl": 300},
        proposed={"pattern": "users.roblox.com/v1/users", "type": "glob"},
    )
    glob_delete = ProposedChange("rule_delete", table="rules_cache", match=glob_rule.match, current={"ttl": 300})
    bucket = ProposedChange("bucket_override", bucket_key="endpoint:users.roblox.com/v1/users", proposed={})
    setting = ProposedChange("setting", key="cache_ttl_seconds", current=300, proposed=600)
    changes = (exact_rule, glob_rule, own_update, exact_update, widened, glob_delete, bucket, setting)
    assert [simulate.endpoint_scoped(c) for c in changes] == [
        True, False, False, True, False, False, True, False,
    ]  # fmt: skip


# ------------------------------------------------------------------------------------- a sampled dry run


async def test_r3_insights_sampled_dry_run_counts_are_scaled(dbs: Any) -> None:
    """Finding insights-9 (fixed): below 100% sampling the counts are scaled to all requests. Since review round 4
    (finding LOGICFIX-6) each sample counts for the rate in force when it was taken, so the rate change is recorded
    before the samples, as it happens in production."""
    clock = FakeClock(NOW)
    runtime = await load_runtime_settings(dbs, clock)
    await SettingsService(dbs.control, runtime=runtime, clock=FakeClock(NOW - 7200)).update(  # set before the samples
        {"request_sample_pct": 50}, ADMIN, "half of the requests are sampled"
    )
    store = RulesStore(dbs.control, clock=clock)
    await store.reload()
    engine = InsightsEngine(dbs=dbs, settings=runtime, rules=store, clock=clock, rule_set={})
    # The real traffic: 10 keys asked 20 times each within the TTL (10 calls, 190 avoided). At 50% sampling
    # every other request is recorded.
    rows = []
    for key in range(10):
        for step in range(0, 20, 2):
            at_ms = int((NOW - 1800 + key * 60 + step) * 1000)
            rows.append((at_ms, f"k{key}", TEMPLATE, "GET", "200", "direct", f"{key:016x}"))

    def write(conn: Any) -> None:
        conn.executemany(
            "INSERT INTO request_samples (at_ms, key_id, endpoint_template, method, upstream_status, egress, "
            "body_hash, auth_class) VALUES (?, ?, ?, ?, ?, ?, ?, 'anon')",
            rows,
        )

    dbs.metrics.write_sync(write)
    rec = Recommendation(
        rule_id="CACHE-LOW-HIT",
        family="cache",
        subject=TEMPLATE,
        title="t",
        changes=[new_rule(TEMPLATE, {"ttl": 600, "stale_ttl": 0, "methods": "GET"})],
    )
    report = await engine.dry_run(rec)
    truth = 200 - 10
    assert "scaled" in report.note  # the report claims the counts are scaled estimates
    assert report.avoided_calls is not None
    assert abs(report.avoided_calls - truth) <= 0.10 * truth, (
        f"{report.avoided_calls} avoided calls reported for a true {truth} at 50% sampling: {report.note}"
    )
    assert report.scale == 2
    assert report.sample_size == 100  # the samples themselves are never scaled
    assert report.baseline_requests == 200
    assert next(iter(report.parts.values()))["avoided_calls"] == 90  # parts: the replay of the samples


async def test_r3_insights_sampled_limit_replay_meets_the_limit_the_whole_stream_met(dbs: Any) -> None:
    """Finding insights-9 (fixed), limits: a p sample of a client arrives at p times its rate, so the replay thins
    the limit by p and scales the refusals by 1 / p; replaying the sample against the full limit refuses nothing."""
    from roxy.abuse.limiter import LimiterRow, gcra

    clock = FakeClock(NOW)
    runtime = await load_runtime_settings(dbs, clock)
    await SettingsService(dbs.control, runtime=runtime, clock=FakeClock(NOW - 7200)).update(  # set before the samples
        {"request_sample_pct": 50}, ADMIN, "half of the requests are sampled"
    )
    store = RulesStore(dbs.control, clock=clock)
    await store.reload()
    engine = InsightsEngine(dbs=dbs, settings=runtime, rules=store, clock=clock, rule_set={})
    window_s = runtime.int("throttle_reset_duration")
    arrivals = [int((NOW - 1200 + n * 50 / 14) * 1000) for n in range(168)]  # 14 per 50 s, as below

    def write(conn: Any) -> None:
        conn.executemany(
            "INSERT INTO request_samples (at_ms, key_id, endpoint_template, method, client_hash, upstream_status, "
            "egress, auth_class) VALUES (?, ?, ?, 'GET', 'c0ffee0123456789', 200, 'direct', 'anon')",
            [(at, f"k{n}", TEMPLATE) for n, at in enumerate(arrivals) if n % 2 == 0],  # every other one sampled
        )

    dbs.metrics.write_sync(write)
    change = ProposedChange("setting", key="allowed_requests_per_minute", current=10, proposed=12)
    rec = Recommendation(rule_id="THROTTLE-TUNE", family="abuse", subject="per-ip", title="t", changes=[change])
    report = await engine.dry_run(rec)
    row, truth = LimiterRow("c0ffee0123456789"), 0
    for at in arrivals:
        decision = gcra(row, 12, window_s, at)
        if decision.admitted:
            row = decision.row
        else:
            truth += 1
    assert truth > 0
    assert report.refused_requests is not None
    assert abs(report.refused_requests - truth) <= 0.25 * truth, (
        f"sampled dry run refuses {report.refused_requests} requests, the limiter would refuse {truth}"
    )
    unthinned = simulate.limit_replay([(at, "c") for at in arrivals[::2]], limit=12, window_s=window_s)
    assert unthinned.refused == 0  # what the replay said before: the sample looks half as fast as the client


# ----------------------------------------------------------------------------------- a per-IP limit replay


async def test_r3_insights_per_ip_limit_replay_uses_the_limiters_window(dbs: Any) -> None:
    """Finding insights-14 (fixed): the per-IP replay uses `throttle_reset_duration`, as the limiter does."""
    from roxy.abuse.limiter import LimiterRow, gcra

    clock = FakeClock(NOW)
    runtime = await load_runtime_settings(dbs, clock)
    store = RulesStore(dbs.control, clock=clock)
    await store.reload()
    engine = InsightsEngine(dbs=dbs, settings=runtime, rules=store, clock=clock, rule_set={})
    window_s = runtime.int("throttle_reset_duration")  # the per-IP limiter's window (abuse/pipeline.py), 50 s
    assert window_s == 50
    # One client sends 14 requests per 50 s, steadily, for ten minutes (a game server polling a bit too fast).
    arrivals = [int((NOW - 1200 + n * 50 / 14) * 1000) for n in range(168)]

    def write(conn: Any) -> None:
        conn.executemany(
            "INSERT INTO request_samples (at_ms, key_id, endpoint_template, method, client_hash, upstream_status, "
            "egress, auth_class) VALUES (?, ?, ?, 'GET', 'c0ffee0123456789', 200, 'direct', 'anon')",
            [(at, f"k{n}", TEMPLATE) for n, at in enumerate(arrivals)],
        )

    dbs.metrics.write_sync(write)
    # THROTTLE-TUNE's change (plan 11.5: "Adjust allowed_requests_per_minute or window"): 10 -> 12 per window.
    change = ProposedChange("setting", key="allowed_requests_per_minute", current=10, proposed=12)
    rec = Recommendation(rule_id="THROTTLE-TUNE", family="abuse", subject="per-ip", title="t", changes=[change])
    report = await engine.dry_run(rec)
    # Ground truth: the same arrivals through the production limiter with its real window.
    row, truth = LimiterRow("c0ffee0123456789"), 0
    for at in arrivals:
        decision = gcra(row, 12, window_s, at)
        if decision.admitted:
            row = decision.row
        else:
            truth += 1
    assert truth > 0
    assert report.refused_requests is not None
    assert abs(report.refused_requests - truth) <= 0.10 * truth, (
        f"dry run refuses {report.refused_requests} requests, the limiter would refuse {truth}"
    )
    assert report.refused_requests == truth  # the same limiter, the same window, the same arrivals
    # THROTTLE-TUNE's other change, a shorter window with today's limit (10), is one replay with the proposed window.
    shorter = ProposedChange("setting", key="throttle_reset_duration", current=window_s, proposed=40)
    rec_window = Recommendation(rule_id="THROTTLE-TUNE", family="abuse", subject="per-ip", title="t", changes=[shorter])
    assert simulate.can_simulate(rec_window)
    by_window = await engine.dry_run(rec_window)
    row, expected = LimiterRow("c0ffee0123456789"), 0
    for at in arrivals:
        decision = gcra(row, runtime.int("allowed_requests_per_minute"), 40, at)
        if decision.admitted:
            row = decision.row
        else:
            expected += 1
    assert by_window.refused_requests == expected
    both = Recommendation(
        rule_id="THROTTLE-TUNE", family="abuse", subject="per-ip", title="t", changes=[change, shorter]
    )
    together = await engine.dry_run(both)
    row, expected = LimiterRow("c0ffee0123456789"), 0
    for at in arrivals:
        decision = gcra(row, 12, 40, at)
        if decision.admitted:
            row = decision.row
        else:
            expected += 1
    assert together.refused_requests == expected  # one replay with both proposed values, never two summed
