"""The Upstream page API, bucket overrides, routing rules and the experience lookup, in the real app (plan 7.12, 7.3,
7.2, 6.8, parity rows 23, 24, 28, 29, 34, 37, 38, 92, 117).

Every answer is read from data seeded through the real recorder (`metrics_seed`, `ctx.recorder`) or written straight
into the shared state tables the upstream service owns (a bucket TAT, a cooldown, a breaker, an AIMD row), the way
another worker would leave them. Roblox is played by `respx`; nothing leaves the machine.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote

import httpx
import pytest

from roxy.config.audit import Actor
from roxy.core.ids import new_request_id
from roxy.core.reasons import CacheState, Egress, Outcome, ReasonCode, Source
from roxy.metrics.read_upstream import ulid_time_ms
from roxy.rules.service import RulesService
from roxy.upstream.read_trace import WaitFacts, explain_wait

TEMPLATE = "games.roblox.com/v1/games"
OTHER = "users.roblox.com/v1/users/{userId}"
THIRD = "thumbnails.roblox.com/v1/users/avatar-headshot"

GET_ROUTES = (
    "upstream/egress",
    "upstream/hosts",
    "upstream/429-timeline",
    "upstream/latency",
    "upstream/buckets",
    "upstream/buckets/history?key=global",
    "upstream/adaptive",
    "upstream/aimd",
    "upstream/cooldowns",
    "upstream/breakers",
    "upstream/retries",
    "upstream/internal-calls",
    "upstream/trace/01J9Z3ABCDEFGHJKMNPQRSTVWX",
    "upstream-limits",
    "routing-rules",
    "routing-rules/test?target=games.roblox.com/v1/games",
)


def _audit_rows(api_app: Any, action: str) -> list[dict[str, Any]]:
    def read(conn: Any) -> list[dict[str, Any]]:
        rows = conn.execute("SELECT * FROM audit_log WHERE action = ? ORDER BY id", (action,)).fetchall()
        return [dict(row) for row in rows]

    rows: list[dict[str, Any]] = api_app.ctx.dbs.control.read_sync(read)
    return rows


async def _hot(api_app: Any, sql: str, params: tuple[Any, ...]) -> None:
    await api_app.ctx.dbs.hot.write(lambda conn: conn.execute(sql, params))


# ================================================================================================ guards


@pytest.mark.parametrize("path", GET_ROUTES)
async def test_every_upstream_read_needs_a_session(anon_api: Any, path: str) -> None:
    response = await anon_api.get(path)
    assert response.status_code == 401, (path, response.text)
    assert response.json() == {"error": {"code": "unauthorized", "message": "Session expired", "fields": {}}}


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "upstream/reset"),
        ("POST", "upstream-limits"),
        ("PATCH", "upstream-limits/host:games.roblox.com"),
        ("DELETE", "upstream-limits/host:games.roblox.com"),
        ("POST", "routing-rules"),
        ("PATCH", "routing-rules/1"),
        ("DELETE", "routing-rules/1"),
        ("POST", "lookup/place"),
    ],
)
async def test_every_write_needs_the_csrf_header(api: Any, method: str, path: str) -> None:
    response = await api.request(method, path, json={"reason": "x"}, csrf=False)
    assert response.status_code == 403, (method, path, response.text)


# ============================================================================================ health cards


async def test_egress_cards_and_host_table_report_honest_rates(
    api_app: Any, api: Any, metrics_seed: Any, api_json: Any
) -> None:
    metrics_seed.record(8, latency_ms=40.0)
    metrics_seed.record(2, status=502, outcome=Outcome.FAILED, reason=ReasonCode.UPSTREAM_5XX, error=True)
    metrics_seed.record(4, egress=Egress.ROTATOR, host="users.roblox.com", endpoint_template=OTHER)
    now = api_app.clock.now_ms()
    for _ in range(3):
        api_app.ctx.recorder.record_upstream_429(
            endpoint_template=TEMPLATE, host="games.roblox.com", egress="direct", retry_after_s=30, at_ms=now
        )
    await metrics_seed.flush()
    body = api_json(await api.get("upstream/egress", params={"range": "1h"}))
    cards = {card["egress"]: card for card in body["items"]}
    assert set(cards) == {"direct", "rotator", "credential"}
    direct = cards["direct"]
    assert direct["calls"] == 10
    assert direct["roblox_429"] == 3
    assert direct["rate_429_pct"] == 30.0
    assert direct["roblox_5xx"] == 2
    assert direct["rate_5xx_pct"] == 20.0
    assert direct["enabled"] is True
    assert direct["bucket"]["key"] == "egress:direct"
    assert direct["bucket"]["per_min"] == api_app.ctx.settings.get("direct_bucket_per_min")
    assert cards["rotator"]["calls"] == 4
    assert cards["rotator"]["enabled"] is False  # the test app runs with rotator_enabled=0
    assert cards["credential"]["calls"] == 0
    assert cards["credential"]["rate_429_pct"] is None  # no calls: no rate invented (P6)

    hosts = api_json(await api.get("upstream/hosts", params={"range": "1h", "sort": "calls", "order": "desc"}))
    assert [row["host"] for row in hosts["items"]] == ["games.roblox.com", "users.roblox.com"]
    assert hosts["items"][0]["roblox_429"] == 3
    assert hosts["total"] == 2
    export = await api.get("upstream/hosts", params={"range": "1h", "format": "csv"})
    assert export.status_code == 200
    assert export.text.splitlines()[0].startswith('"Host","Calls"')
    assert _audit_rows(api_app, "export.download")[-1]["target"] == "table:upstream_hosts"


async def test_429_timeline_keeps_the_top_endpoints_and_folds_the_rest(
    api_app: Any, api: Any, api_json: Any, metrics_seed: Any
) -> None:
    now = api_app.clock.now_ms()
    for template, count in ((TEMPLATE, 5), (OTHER, 3), (THIRD, 1)):
        host = template.split("/", 1)[0]
        for _ in range(count):
            api_app.ctx.recorder.record_upstream_429(
                endpoint_template=template, host=host, egress="direct", retry_after_s=10, at_ms=now - 120_000
            )
    await metrics_seed.flush()
    body = api_json(await api.get("upstream/429-timeline", params={"range": "1h", "top": 2, "compare": "previous"}))
    keys = [line["key"] for line in body["series"]]
    assert keys == [f"roblox_429:{TEMPLATE}", f"roblox_429:{OTHER}", "roblox_429:other"]
    sums = {line["key"]: sum(point[1] for point in line["points"]) for line in body["series"]}
    assert sums == {f"roblox_429:{TEMPLATE}": 5, f"roblox_429:{OTHER}": 3, "roblox_429:other": 1}
    assert body["totals"] == {"total": 9, "by_endpoint": {TEMPLATE: 5, OTHER: 3}}
    assert body["compare"]["mode"] == "previous"
    assert sum(point[1] for point in body["compare"]["series"][0]["points"]) == 0
    rotator_only = api_json(await api.get("upstream/429-timeline", params={"range": "1h", "egress": "rotator"}))
    assert rotator_only["totals"]["total"] == 0
    bad = await api.get("upstream/429-timeline", params={"top": 99})
    assert bad.status_code == 422


async def test_latency_series_are_percentiles_of_upstream_requests(api: Any, api_json: Any, metrics_seed: Any) -> None:
    metrics_seed.record(20, latency_ms=100.0)
    metrics_seed.record(5, outcome=Outcome.SERVED_CACHE, reason=ReasonCode.CACHE_HIT, latency_ms=1.0, upstream_calls=0)
    await metrics_seed.flush()
    body = api_json(await api.get("upstream/latency", params={"range": "1h", "egress": "direct"}))
    keys = [line["key"] for line in body["series"]]
    assert keys == ["p50_ms", "p95_ms", "p99_ms", "queue_wait_p95_ms"]
    p50 = [point[1] for point in body["series"][0]["points"] if point[1] is not None]
    assert p50
    assert all(80 <= value <= 120 for value in p50)  # cache hits (1 ms) are not upstream latency
    assert body["basis"].startswith("caller latency")


# ================================================================================================ buckets


async def test_buckets_show_fill_rates_and_history_and_a_reset_never_refills_them(
    api_app: Any, api: Any, api_json: Any, metrics_seed: Any, section13: Any
) -> None:
    now = api_app.clock.now_ms()
    # The endpoint bucket ran 3 s ahead of its schedule: at 120 per minute and burst 10 it is 60 percent used.
    await _hot(
        api_app,
        "INSERT INTO upstream_bucket (bucket_key, tat_ms, burst, rate_per_s, updated_at) VALUES (?, ?, ?, ?, ?)",
        (f"endpoint:{TEMPLATE}", now + 3000, 10, 2.0, now // 1000),
    )
    await _hot(
        api_app,
        "INSERT INTO cooldown (key, until_ms, source, set_at, hits) VALUES (?, ?, 'retry_after', ?, 1)",
        (f"endpoint:{TEMPLATE}:direct", now + 30_000, now / 1000),
    )
    await _hot(
        api_app,
        "INSERT INTO breaker (key, state, opened_at, half_open_at, failures, successes, window_start) "
        "VALUES (?, 'open', ?, ?, 5, 0, ?)",
        ("host:games.roblox.com:direct", now / 1000, now / 1000 + 20, now / 1000),
    )
    for minute_back in (3, 2):
        api_app.ctx.recorder.record_bucket(
            f"endpoint:{TEMPLATE}", attempts=4, rejected=1, fill_pct=100.0, at_ms=now - minute_back * 60_000
        )
    await metrics_seed.flush()

    table = api_json(await api.get("upstream/buckets", params={"range": "1h", "q": "endpoint:"}))
    (row,) = table["items"]
    assert row["key"] == f"endpoint:{TEMPLATE}"
    assert row["fill_pct"] == 60.0
    assert row["next_free_in_ms"] == 0.0
    assert row["per_min"] == api_app.ctx.settings.get("endpoint_bucket_default_per_min")
    assert row["origin"] == "setting"
    assert (row["attempts"], row["rejections"], row["fill_pct_peak"]) == (8, 2, 100.0)
    assert "never" in table["refills"]

    history = api_json(await api.get("upstream/buckets/history", params={"range": "1h", "key": f"endpoint:{TEMPLATE}"}))
    sums = {line["key"]: line["points"] for line in history["series"]}
    assert sum(point[1] for point in sums["attempts"]) == 8
    assert max(point[1] or 0 for point in sums["fill_pct_peak"]) == 100.0
    assert history["describe"] == {"kind": "endpoint", "egress": None, "target": TEMPLATE}

    cooling = api_json(await api.get("upstream/cooldowns"))
    (cooldown,) = [item for item in cooling["items"] if item["kind"] == "endpoint"]
    assert (cooldown["egress"], cooldown["target"], cooldown["source"]) == ("direct", TEMPLATE, "retry_after")
    assert cooldown["ends_at_ms"] == now + 30_000
    assert cooldown["remaining_s"] == 30.0
    breakers = api_json(await api.get("upstream/breakers"))
    (breaker,) = breakers["items"]
    assert (breaker["state"], breaker["kind"], breaker["target"]) == ("open", "host", "games.roblox.com")
    assert breaker["reopens_at_ms"] == now + 20_000

    missing = await api.post("upstream/reset", json={"reason": "  "})
    assert "reason" in section13(missing, 422, "validation_failed")
    reset = api_json(await api.post("upstream/reset", json={"reason": "cleared after the incident"}))
    assert reset["cleared"] == {"cooldowns_cleared": 1, "breakers_cleared": 1}
    assert reset["buckets"] == "unchanged"
    assert reset["warnings"] == []
    after = api_json(await api.get("upstream/buckets", params={"q": "endpoint:"}))
    assert after["items"][0]["fill_pct"] == 60.0  # never refilled (v1 bug B21)
    tat = await api_app.ctx.dbs.hot.read(
        lambda conn: conn.execute(
            "SELECT tat_ms FROM upstream_bucket WHERE bucket_key = ?", (f"endpoint:{TEMPLATE}",)
        ).fetchone()[0]
    )
    assert tat == now + 3000
    assert api_json(await api.get("upstream/cooldowns"))["items"] == []
    assert api_json(await api.get("upstream/breakers"))["items"] == []
    (audit_row,) = _audit_rows(api_app, "upstream.reset_state")
    assert json.loads(audit_row["after_json"]) == {"cooldowns_cleared": 1, "breakers_cleared": 1}
    assert audit_row["reason"] == "cleared after the incident"
    assert audit_row["actor"].startswith("admin:")
    marks = await api_app.ctx.dbs.metrics.read(
        lambda conn: [dict(r) for r in conn.execute("SELECT kind, label, audit_id FROM annotations").fetchall()]
    )
    assert marks == [
        {
            "kind": "config_change",
            "label": "Upstream state reset: 1 cooldowns, 1 breakers",
            "audit_id": reset["audit_id"],
        }
    ]


async def test_adaptive_changes_rates_and_aimd(api_app: Any, api: Any, api_json: Any, metrics_seed: Any) -> None:
    now = api_app.clock.now_ms()
    metrics_seed.event(
        "adaptive_rate_decrease",
        "info",
        "upstream_cooldown",
        {
            "bucket_key": f"endpoint:{TEMPLATE}",
            "old_per_min": 120.0,
            "new_per_min": 84.0,
            "evidence": {"kind": "endpoint"},
        },
        at_ms=now - 60_000,
    )
    await metrics_seed.flush()
    service = RulesService(api_app.ctx.dbs.control, clock=api_app.clock, store=api_app.ctx.rules)
    row = {"bucket_key": f"endpoint:{TEMPLATE}", "per_min": 84.0, "burst": 10, "origin": "adaptive"}
    await service.upsert("upstream_limits", row, Actor("system", "adaptive"), "429 on the endpoint")
    body = api_json(await api.get("upstream/adaptive", params={"range": "1h"}))
    assert body["enabled"] is True
    (change,) = body["changes"]
    assert (change["direction"], change["bucket_key"], change["old_per_min"], change["new_per_min"]) == (
        "decrease",
        f"endpoint:{TEMPLATE}",
        120.0,
        84.0,
    )
    assert body["rates"][0]["bucket_key"] == f"endpoint:{TEMPLATE}"
    assert body["rates"][0]["per_min"] == 84.0

    await _hot(
        api_app,
        'INSERT INTO aimd (key, "limit", inflight, last_change_at) VALUES (?, ?, ?, ?)',
        ("games.roblox.com:direct", 6.5, 2, now / 1000),
    )
    aimd = api_json(await api.get("upstream/aimd"))
    assert aimd["enabled"] is False  # Tier 3, off by default (plan 7.4)
    assert aimd["items"] == [
        {
            "key": "games.roblox.com:direct",
            "host": "games.roblox.com",
            "egress": "direct",
            "limit": 6.5,
            "slots": 6,
            "inflight": 2,
            "last_change_at": now / 1000,
        }
    ]


async def test_retries_and_internal_calls(api_app: Any, api: Any, api_json: Any, metrics_seed: Any) -> None:
    recorder = api_app.ctx.recorder
    before = api_app.clock.now_ms() - 120_000  # aggregated rows are written once their minute has closed
    for _ in range(2):
        recorder.record_retry(
            status=403, reason="CSRF token refresh", egress="direct", endpoint_template=TEMPLATE, at_ms=before
        )
    recorder.record_internal_call(
        "credential_probe", ok=False, status=401, duration_ms=12.0, endpoint="https://users.roblox.com/v1/users/authenticated",
        egress=Egress.CREDENTIAL, error="rejected", at_ms=before,
    )  # fmt: skip
    await metrics_seed.flush()
    retries = api_json(await api.get("upstream/retries", params={"range": "1h"}))
    assert retries["total"] == 2
    assert retries["csrf_retries"] == 2
    assert retries["by_status"] == {"403": 2}
    assert retries["by_egress"] == {"direct": 2}
    calls = api_json(await api.get("upstream/internal-calls", params={"range": "1h"}))
    by_purpose = {item["purpose"]: item for item in calls["items"]}
    probe = by_purpose["credential_probe"]
    assert (probe["count"], probe["failed"], probe["health"]) == (1, 1, "failing")
    assert by_purpose["admin_lookup"]["health"] == "not_called"
    assert by_purpose["admin_lookup"]["what"] == "Identify an experience (only when the proxy path is unavailable)"
    assert "never pass through the proxy route" in calls["note"]


# ================================================================================================= trace


async def test_trace_explains_a_cooldown_and_a_wait_for_a_bucket(
    api_app: Any, api: Any, api_json: Any, metrics_seed: Any, section13: Any
) -> None:
    now = api_app.clock.now_ms()
    api_app.ctx.recorder.record_upstream_429(
        endpoint_template=TEMPLATE, host="games.roblox.com", egress="direct", retry_after_s=30, at_ms=now - 5_000
    )
    cooled = new_request_id(api_app.clock)
    metrics_seed.record(
        request_id=cooled, status=429, outcome=Outcome.FAILED, reason=ReasonCode.UPSTREAM_COOLDOWN,
        source=Source.ROXY, upstream_calls=0, cache_state=CacheState.MISS,
    )  # fmt: skip
    waited = new_request_id(api_app.clock)
    metrics_seed.record(request_id=waited, queue_wait_ms=1250.0, attempts=2, retries=1)
    api_app.ctx.recorder.record_bucket(f"endpoint:{TEMPLATE}", attempts=9, rejected=3, fill_pct=100.0, at_ms=now)
    await metrics_seed.flush()

    body = api_json(await api.get(f"upstream/trace/{cooled}"))
    assert body["found"] is True
    assert body["live"]["reason"] == "upstream_cooldown"
    text = " ".join(body["reasons"])
    assert "cooldown was open" in text
    assert "a 429 on games.roblox.com/v1/games through direct" in text
    assert "Retry-After 30 s" in text
    assert body["prior_429s"][0]["retry_after_s"] == 30

    body = api_json(await api.get(f"upstream/trace/{waited.lower()}"))
    text = " ".join(body["reasons"])
    assert body["waited_ms"] == 1250.0
    assert "waited 1250.0 ms for a bucket slot" in text
    assert f"endpoint:{TEMPLATE} was the fullest" in text
    assert "inferred" in text  # honest about what is not stored (P6)
    assert "took 2 attempts" in text
    assert "CSRF token" in text
    assert body["full_buckets"][0] == {"key": f"endpoint:{TEMPLATE}", "fill_pct_peak": 100.0, "rejections": 3}

    unknown = api_json(await api.get(f"upstream/trace/{new_request_id(api_app.clock)}"))
    assert unknown["found"] is False
    assert "15 minutes" in unknown["reasons"][0]
    bad = await api.get("upstream/trace/not-a-request-id")
    section13(bad, 422, "invalid_request_id")


def test_request_ids_carry_their_minting_time() -> None:
    from roxy.core.clock import FakeClock

    clock = FakeClock(1_760_000_123.456)
    assert ulid_time_ms(new_request_id(clock)) == 1_760_000_123_456
    assert ulid_time_ms("short") is None
    assert ulid_time_ms("I" * 26) is None  # not Crockford base32


def test_explainer_without_a_record_says_what_is_kept() -> None:
    answer = explain_wait(WaitFacts(request_id="X", minted_at_ms=1, live=None))
    assert answer["found"] is False
    assert "Roblox 429s are kept 90 days" in answer["reasons"][0]
    with_429 = explain_wait(
        WaitFacts(request_id="X", minted_at_ms=1, live=None, roblox_429s=[{"at_ms": 5, "retry_after_s": 3}])
    )
    assert with_429["found"] is True
    refused = explain_wait(
        WaitFacts(request_id="X", minted_at_ms=1, live={"reason": "throttle", "outcome": "refused", "cache": "n/a"})
    )
    assert refused["reasons"] == [
        "Roxy's protection refused it (throttle) before any upstream call; see the Protection page."
    ]


# ======================================================================================== bucket overrides


async def test_upstream_limit_overrides_crud_with_audit_and_origin(
    api_app: Any, api: Any, api_json: Any, section13: Any
) -> None:
    key = "endpoint:games.roblox.com/v1/games/{universeId}/votes"
    path = "upstream-limits/" + quote(key, safe=":/")
    created = await api.post("upstream-limits", json={"bucket_key": key, "per_min": 60, "burst": 5, "reason": "tight"})
    assert created.status_code == 201, created.text
    item = created.json()["item"]
    assert (item["bucket_key"], item["kind"], item["per_min"], item["burst"], item["origin"]) == (
        key,
        "endpoint",
        60.0,
        5,
        "admin",
    )
    assert item["default_per_min"] == api_app.ctx.settings.get("endpoint_bucket_default_per_min")
    assert created.json()["config_version"] > 0
    assert api_app.ctx.rules.snapshot.upstream_limit(key) is not None  # this worker reloaded at once
    section13(await api.post("upstream-limits", json={"bucket_key": key, "per_min": 10, "burst": 1}), 409, "conflict")
    fields = section13(
        await api.post("upstream-limits", json={"bucket_key": "host:evil.example", "per_min": 10, "burst": 1}),
        422,
        "invalid_rule",
    )
    assert "bucket_key" in fields
    section13(
        await api.post("upstream-limits", json={"bucket_key": key, "per_min": 0, "burst": 1}), 422, "validation_failed"
    )
    section13(
        await api.post("upstream-limits", json={"bucket_key": key, "per_min": 5, "burst": 1, "x": 1}),
        422,
        "validation_failed",
    )

    listed = api_json(await api.get("upstream-limits"))
    assert listed["total"] == 1
    assert listed["defaults"]["endpoint"]["per_min"] == api_app.ctx.settings.get("endpoint_bucket_default_per_min")
    assert api_json(await api.get(path))["per_min"] == 60.0
    section13(await api.get("upstream-limits/host:nothing.roblox.com"), 404, "not_found")

    patched = api_json(await api.patch(path, json={"per_min": 90, "reason": "more room"}))
    assert patched["item"]["per_min"] == 90.0
    assert patched["changed"] is True
    section13(await api.patch(path, json={"reason": "nothing"}), 422, "validation_failed")

    # An adaptive row keeps its origin when only the note changes, and becomes `admin` once its rate is set by hand.
    service = RulesService(api_app.ctx.dbs.control, clock=api_app.clock, store=api_app.ctx.rules)
    host_key = "host:users.roblox.com"
    await service.upsert(
        "upstream_limits",
        {"bucket_key": host_key, "per_min": 100.0, "burst": 8, "origin": "adaptive"},
        Actor("system", "adaptive"),
        "x",
    )
    noted = api_json(await api.patch(f"upstream-limits/{host_key}", json={"note": "watching it"}))
    assert noted["item"]["origin"] == "adaptive"
    rated = api_json(await api.patch(f"upstream-limits/{host_key}", json={"burst": 4}))
    assert rated["item"]["origin"] == "admin"

    deleted = api_json(await api.delete(path, json={"reason": "back to default"}))
    assert deleted["deleted"]["bucket_key"] == key
    section13(await api.delete(path), 404, "not_found")
    created_targets = [row["target"] for row in _audit_rows(api_app, "rule.create")]
    assert f"upstream_limits:{key}" in created_targets
    (deleted_row,) = _audit_rows(api_app, "rule.delete")
    assert deleted_row["target"] == f"upstream_limits:{key}"
    assert deleted_row["reason"] == "back to default"


# ============================================================================================ routing rules


async def test_routing_rules_crud_tester_and_export(api_app: Any, api: Any, api_json: Any, section13: Any) -> None:
    created = await api.post(
        "routing-rules", json={"pattern": "games.roblox.com/v1/games", "mode": "direct_only", "note": "fragile"}
    )
    assert created.status_code == 201, created.text
    rule = created.json()["item"]
    assert (rule["pattern"], rule["type"], rule["mode"], rule["enabled"]) == (
        "games.roblox.com/v1/games",
        "glob",
        "direct_only",
        True,
    )
    tested = api_json(await api.get("routing-rules/test", params={"target": "https://GAMES.roblox.com/v1/games?x=1"}))
    assert tested["target"] == "games.roblox.com/v1/games"
    assert tested["mode"] == "direct_only"
    assert tested["rule"]["id"] == rule["id"]
    none = api_json(await api.get("routing-rules/test", params={"target": "users.roblox.com/v1/users/1"}))
    assert none["rule"] is None

    section13(
        await api.post("routing-rules", json={"pattern": "games.roblox.com/v1/games", "mode": "prefer_rotator"}),
        409,
        "conflict",
    )
    section13(await api.post("routing-rules", json={"pattern": "x", "mode": "sideways"}), 422, "validation_failed")
    section13(
        await api.post("routing-rules", json={"pattern": "(a+)+$", "type": "regex", "mode": "direct_only"}),
        422,
        "invalid_rule",
    )

    patched = api_json(
        await api.patch(f"routing-rules/{rule['id']}", json={"mode": "prefer_rotator", "enabled": False})
    )
    assert (patched["item"]["mode"], patched["item"]["enabled"]) == ("prefer_rotator", False)
    assert api_json(await api.get(f"routing-rules/{rule['id']}"))["mode"] == "prefer_rotator"
    section13(await api.get("routing-rules/999"), 404, "not_found")
    section13(await api.get("routing-rules/abc"), 422, "validation_failed")

    listed = api_json(await api.get("routing-rules", params={"q": "games"}))
    assert listed["total"] == 1
    assert listed["modes"] == ["prefer_direct", "prefer_rotator", "direct_only", "rotator_only"]
    export = await api.get("routing-rules", params={"format": "json"})
    payload = json.loads(export.content)
    assert payload["table"] == "routing_rules"
    assert payload["items"][0]["pattern"] == "games.roblox.com/v1/games"

    gone = api_json(await api.delete(f"routing-rules/{rule['id']}"))
    assert gone["deleted"]["id"] == rule["id"]
    assert api_app.ctx.rules.snapshot.routing_rule_for("games.roblox.com/v1/games") is None


# ================================================================================================ lookup


async def test_identify_an_experience_is_budgeted_cached_and_mapped(
    api_app: Any, api: Any, api_json: Any, section13: Any
) -> None:
    created = "2025-10-08T00:00:00Z"  # one day before the fake clock: a new place
    api_app.roblox.get("https://apis.roblox.com/universes/v1/places/123/universe").mock(
        return_value=httpx.Response(200, json={"universeId": 456})
    )
    game = {
        "name": "Test Place", "description": "d", "rootPlaceId": 123, "created": created, "updated": created,
        "playing": 3, "visits": 10, "maxPlayers": 20, "favoritedCount": 1,
        "creator": {"id": 77, "name": "Someone", "type": "Group", "hasVerifiedBadge": True},
    }  # fmt: skip
    games = api_app.roblox.get("https://games.roblox.com/v1/games", params={"universeIds": "456"}).mock(
        return_value=httpx.Response(200, json={"data": [game]})
    )
    first = api_json(await api.post("lookup/place", json={"id": "123"}))
    assert first["cached"] is False
    experience = first["experience"]
    assert (experience["Name"], experience["UniverseId"], experience["CreatorUrl"]) == (
        "Test Place",
        "456",
        "https://www.roblox.com/groups/77",
    )
    assert len(first["notes"]) == 1
    assert first["notes"][0].startswith("Recently created with very few visits;")
    second = api_json(await api.post("lookup/place", json={"id": "123"}))
    assert second["cached"] is True
    assert games.call_count == 1  # the 10 minute cache (parity row 38)

    section13(await api.post("lookup/place", json={"id": "12a"}), 422, "invalid_id")
    section13(await api.post("lookup/place", json={"id": "1", "kind": "badge"}), 422, "validation_failed")
    api_app.roblox.get("https://apis.roblox.com/universes/v1/places/999/universe").mock(
        return_value=httpx.Response(200, json={"universeId": None})
    )
    missing = await api.post("lookup/place", json={"id": "999"})
    assert section13(missing, 404, "not_found") == {}
    assert missing.json()["error"]["message"] == "Roblox did not return a universe for that place"
    api_app.roblox.get("https://apis.roblox.com/universes/v1/places/555/universe").mock(
        return_value=httpx.Response(500, text="boom")
    )
    failed = await api.post("lookup/place", json={"id": "555"})
    section13(failed, 502, "upstream_failed")
    assert failed.json()["error"]["message"].startswith("Could not resolve that place:")
