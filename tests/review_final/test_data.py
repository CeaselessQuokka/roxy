"""Final review, data lens: storage, metrics and data integrity (plan 6, DESIGN 14.9 and 15.8).

What this is
    One reproduction per finding of `.remake/final_review/find_data.md`. Each was a strict xfail until the final
    review fixed its finding (without weakening any existing assertion); each is a regression test now.

Why it exists
    The last review before go-live: these are the places where the four databases, the metrics rollups, the resets
    and the retention jobs would lose data, keep data the owner asked to drop, or show a number that leads the owner
    to a wrong action.

How it works
    The fixtures of the suites the code belongs to: the admin API app of `tests/integration/admin_api/conftest.py`
    (the real lifespan over temporary databases, a fake clock, Roblox played by respx, the real recorder, leader
    jobs run with `ctx.jobs.run_job_now`), and the migrated `dbs` of the root conftest for the storage functions.
    Nothing leaves the machine (the root conftest's socket guard).

What to read next
    `.remake/final_review/find_data.md`, then the files each test names.
"""

# ruff: noqa: F811  (the imported pytest fixtures are the tests' parameters)

from __future__ import annotations

import asyncio
import json
import math
from typing import Any

import httpx
import pytest

from integration.admin_api.conftest import api, api_admin, api_app, api_json, metrics_seed  # noqa: F401
from roxy.config.audit import Actor

ADMIN = Actor("admin", "review", "127.0.0.1")
DAY_S = 86_400
CALLER_UA = "Roblox/Linux"


async def _run_job(api_app: Any, name: str) -> Any:
    """Run one leader job now, as the leader would: an election step first (the fake clock may have moved past the
    lease), and once more after a step when the run found its lease taken over meanwhile."""
    for _ in range(3):
        await api_app.ctx.leader.tick()
        status = await api_app.ctx.jobs.run_job_now(name)
        if status.last_ok:
            return status
    raise AssertionError((name, status.last_error))


async def _run_leader_jobs(api_app: Any, *names: str) -> None:
    for name in names:
        await _run_job(api_app, name)


def _tiles(body: dict[str, Any]) -> dict[str, Any]:
    return {tile["key"]: tile["value"] for tile in body["tiles"]}


async def _evaluate_insights(api_app: Any) -> list[tuple[str, str]]:
    """Run the leader's `insights_evaluate` job and return the open FILTER-REMOVE recommendations as `(title,
    explanation)`."""
    ctx = api_app.ctx
    await _run_job(api_app, "insights_evaluate")
    rows = await ctx.dbs.metrics.read(
        lambda c: c.execute(
            "SELECT json_extract(payload_json, '$.title'), json_extract(payload_json, '$.explanation') "
            "FROM recommendations WHERE rule_id = 'FILTER-REMOVE' AND state = 'open'"
        ).fetchall()
    )
    return [(str(r[0]), str(r[1])) for r in rows]


async def _reset_family(api_app: Any, family: str) -> dict[str, Any]:
    """Run a family reset as `POST /data/resets` runs it (plan, intent row, lease, `execute_reset`)."""
    from roxy.admin.api import data

    ctx = api_app.ctx
    plan = data.build_plan(
        data.ResetBody.model_validate({"scope": "family", "families": [family]}), ctx, ctx.clock.now()
    )
    op = data.Operation(data._new_id("reset"), "reset", plan.label, ctx.clock.now())
    op.audit_id = await data._audit(ctx, ADMIN, data.AUDIT_RESET, f"operation:{op.id}", {"plan": plan.label}, "", None)
    lease = data.ResetLease(ctx, f"review-{family}")
    assert await lease.acquire()
    result: dict[str, Any] = await data.execute_reset(ctx, op, plan, ADMIN, "start the counts again", None, lease)
    return result


# ============================================================================================ data-1


async def test_data_1_an_upstream_statistics_reset_never_lets_the_adaptive_controller_raise_a_429ing_rate(
    api: Any, api_app: Any
) -> None:
    """Plan 7.3: a rate is raised only "after `adaptive_probe_after_h` (24) hours with zero 429s on the key"
    (`upstream/adaptive.py should_increase`; `adaptive_rate_enabled` is 1 by default). The evidence of those 429s is
    `metrics.upstream_429` (`collect_stats`), which the Upstream family reset (`admin/api/data.py FAMILIES
    ["upstream"]`, the Upstream > Health card's reset, v1's `request_failures` clear) deletes while it keeps the
    traffic rows that hold the rejection evidence. A key whose 429s did not cut its own rate (an egress-wide limit:
    429s on two hosts in a minute open an egress cooldown and cut no endpoint; a 429 through the rotator; a key at
    `adaptive_min_per_min`) has no recent `upstream_limits` change either, so after the reset nothing stops the
    increase: Roxy calls Roblox faster on an endpoint Roblox was refusing (plan C1's account and IP risk)."""
    from roxy.metrics.recorder import dims_hash

    ctx = api_app.ctx
    await api_app.settings(health_auto_interval_h=0)
    now = int(ctx.clock.now())
    template = "games.roblox.com/v1/games/{universeId}/votes"
    host = "games.roblox.com"
    served = (template, 1, host, "GET", "direct", "served_upstream", "upstream_ok", 200, "roblox", "MISS", "anon")
    rejected = (template, 1, host, "GET", "none", "failed", "upstream_busy", 503, "roxy", "MISS", "anon")
    hour = now - now % 3600 - 3 * 3600

    def seed(conn: Any) -> None:
        # Three hours ago: 200 calls served and 20 requests the bucket turned away (10 percent: real demand), as the
        # leader's compaction writes them; two hours ago Roblox answered 429 three times (the recorder's 429 log).
        for dims, requests, calls in ((served, 200, 200), (rejected, 20, 0)):
            key = dims_hash(dims)
            conn.execute(
                "INSERT OR IGNORE INTO dims (dim_hash, endpoint_template, template_version, host, method, egress, "
                "outcome, reason_code, status, source, cache_state, auth_class) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (key, *dims),
            )
            conn.execute(
                "INSERT INTO rollup_hour (bucket_start, dim_hash, requests, caller_bytes_in, caller_bytes_out, "
                "upstream_calls, upstream_bytes_in, upstream_bytes_out, errors) VALUES (?, ?, ?, 0, 0, ?, 0, 0, 0)",
                (hour, key, requests, calls),
            )
        conn.executemany(
            "INSERT INTO upstream_429 (at_ms, endpoint_template, host, egress, retry_after_s, ratelimit_headers_json, "
            "request_id) VALUES (?, ?, ?, 'direct', 30, NULL, ?)",
            [((now - 7200 + i * 60) * 1000, template, host, f"REVIEW{i:020d}") for i in range(3)],
        )

    await ctx.dbs.metrics.write(seed)

    async def increase() -> list[Any]:
        status = await _run_job(api_app, "adaptive_rate_increase")
        return list(status.last_result["raised"])

    assert await increase() == []  # 429s two hours ago: the probe window is not clean, nothing is raised
    deleted = await _reset_family(api_app, "upstream")
    assert deleted["deleted"]["metrics.upstream_429"] == 3
    ctx.clock.advance(60)
    raised = await increase()
    limits = await ctx.dbs.control.read(
        lambda c: [tuple(r) for r in c.execute("SELECT bucket_key, per_min, origin FROM upstream_limits").fetchall()]
    )
    assert raised == [], f"raised after the statistics reset: {raised} {limits}"


# ============================================================================================ data-2


async def test_data_2_a_statistics_reset_never_makes_a_working_filter_read_as_never_hit(api: Any, api_app: Any) -> None:
    """LEAD_NOTES (wave 3b review round 3): "Rule hit history is in no reset family (deleting it would make
    FILTER-REMOVE read a filter as never hit)". The Everything (statistics) scope still deletes `rule_hits` and
    `rule_hit_minute` (`admin/api/data.py STATISTICS_EXTRA`), and `insights/rules/abuse.py FilterRemove` counts a
    rule with no `rule_hits` row as idle since its creation, and its fallbacks (refusals in the rollups, a bypass
    entry's clients in the client tables) were deleted by the same reset. The recommendation then claims, with
    confidence high, that a block which just refused callers "has never matched a request" and offers to remove it
    (the same holds for bypass entries: "Remove the unused bypass entry")."""
    from roxy.admin.api import data

    ctx = api_app.ctx
    await api_app.settings(health_auto_interval_h=0)
    now = int(ctx.clock.now())

    def add_block(conn: Any) -> None:
        # An endpoint block the owner made two months ago (the migrator and the Protection page write such rows).
        conn.execute(
            "INSERT INTO rules_endpoint_block (pattern, type, note, message, created_at, created_by, enabled) "
            "VALUES ('games.roblox.com/v1/blocked/*', 'glob', 'scraper target', NULL, ?, 'admin:owner', 1)",
            (now - 60 * DAY_S,),
        )
        conn.execute(
            "UPDATE service_state SET value_json = CAST(value_json AS INTEGER) + 1 WHERE key = 'config_version'"
        )

    await ctx.dbs.control.write(add_block)
    await ctx.rules.reload()
    client = api_app.harness.new_client()
    for n in range(3):
        refused = await client.get(
            f"/games.roblox.com/v1/blocked/{n}",
            headers={"X-Forwarded-For": f"198.51.100.{n + 1}", "User-Agent": CALLER_UA},
        )
        assert refused.status_code == 403, refused.text
        assert refused.headers.get("roxy-refusal") == "endpoint_blocked", refused.headers
    await ctx.recorder.flush()
    assert await _evaluate_insights(api_app) == []  # the block works: nothing to remove

    body = data.ResetBody.model_validate({"scope": "everything"})
    plan = data.build_plan(body, ctx, ctx.clock.now())
    op = data.Operation(data._new_id("reset"), "reset", plan.label, ctx.clock.now())
    op.audit_id = await data._audit(ctx, ADMIN, data.AUDIT_RESET, f"operation:{op.id}", {"plan": plan.label}, "", None)
    lease = data.ResetLease(ctx, "review-everything")
    assert await lease.acquire()
    await data.execute_reset(ctx, op, plan, ADMIN, "fresh start after the cutover", None, lease)

    ctx.clock.advance(120)
    stale = await _evaluate_insights(api_app)
    assert stale == [], f"FILTER-REMOVE after the statistics reset: {stale}"


# ============================================================================================ data-3


# Fixed (fixer data): Roblox's answers per attempt live in the `roblox_answer_*` tables (metrics 0010), compacted and
# kept like the rollups; the tiles `status_2xx`, `status_4xx` and `roblox_5xx` read them (`queries.ANSWER_METRICS`).
async def test_data_3_roblox_status_tiles_count_roblox_answers_per_attempt_through_the_rollups(
    api: Any, api_app: Any
) -> None:
    """Lead decision (11) for v1parity-1: the Roblox tiles count Roblox's answers again, per attempt (v1
    `app/diagnostics.py log_status_code`), Roxy's own answers (refusals, cache serves) and internal calls left out,
    kept through the hour and day rollups by an expand migration (metrics 10), so a 30 day range is exact after the
    minute rows are gone. Here Roblox answers: 200 three times, 503 then 200 for one call Roxy retried, and 404 once;
    Roxy answers two cache hits and one "Not a Roblox URL" 404 itself."""
    from roxy.storage import migrate

    # No scheduled credential check: once the clock jumps 15 days, its own call (a `rollup_minute` row of source
    # `internal`) could land before the minute count below on a busy machine (seen once in a loaded combined run).
    await api_app.settings(health_auto_interval_h=0, credential_probe_interval_min=0)
    flaky: list[int] = []

    def flaky_answer(request: httpx.Request) -> httpx.Response:
        flaky.append(1)
        if len(flaky) == 1:
            return httpx.Response(503, json={"errors": []})
        return httpx.Response(200, json={"data": []})

    api_app.roblox.route(host="games.roblox.com", path="/v1/games").mock(
        return_value=httpx.Response(200, json={"data": [1]})
    )
    api_app.roblox.route(host="badges.roblox.com", path="/v1/flaky/1").mock(side_effect=flaky_answer)
    api_app.roblox.route(host="catalog.roblox.com", path="/v1/missing").mock(
        return_value=httpx.Response(404, json={"errors": []})
    )
    client = api_app.harness.new_client()
    plan = [
        "/games.roblox.com/v1/games?universeIds=1",
        "/games.roblox.com/v1/games?universeIds=2",
        "/games.roblox.com/v1/games?universeIds=3",
        "/games.roblox.com/v1/games?universeIds=1",  # cache HIT: Roxy's answer
        "/games.roblox.com/v1/games?universeIds=1",  # cache HIT: Roxy's answer
        "/badges.roblox.com/v1/flaky/1",  # Roblox 503, then 200 on Roxy's retry
        "/catalog.roblox.com/v1/missing",  # Roblox 404
        "/example.com/not/roblox",  # Roxy's own 404 (not_roblox)
    ]
    seen = []
    for n, path in enumerate(plan, start=1):
        response = await client.get(path, headers={"X-Forwarded-For": f"198.51.100.{n}", "User-Agent": CALLER_UA})
        seen.append((response.status_code, response.headers.get("roxy-cache"), response.headers.get("roxy-refusal")))
        await api_app.ctx.cache.settle()
    await api_app.ctx.recorder.flush()
    assert [s[0] for s in seen] == [200, 200, 200, 200, 200, 200, 404, 404], seen
    assert [s[1] for s in seen[3:5]] == ["HIT", "HIT"], seen
    assert seen[7][2] == "not_roblox", seen
    assert len(flaky) == 2, flaky  # Roblox answered the flaky call twice

    # The leader compacts the closed hour, then 15 days later the minute rows leave (retention_minute_days 14).
    api_app.clock.advance(3 * 3600)
    await _run_leader_jobs(api_app, "metrics_compaction")
    api_app.clock.advance(15 * DAY_S)
    await _run_leader_jobs(
        api_app, "metrics_compaction", "retention", "insights_history_prune", "metrics_producer_prune"
    )
    minutes = await api_app.ctx.dbs.metrics.read(lambda c: c.execute("SELECT count(*) FROM rollup_minute").fetchone())
    assert minutes[0] == 0  # only the hour and day rollups hold that traffic now

    login = await api_app.harness.login(api.admin)  # the session expired while the clock moved
    assert login.status_code == 200, login.text
    response = await api.get("overview/kpis", params={"range": "30d"})
    assert response.status_code == 200, response.text
    tiles = _tiles(response.json())
    assert tiles["requests"] == 8, tiles  # the caller totals are exact through the rollups today
    # v1: "Times Roblox answered us successfully" (the three games calls and the retried call), never a cache serve.
    assert tiles["status_2xx"] == 4, tiles
    # v1: "Times Roblox refused one of our requests": only Roblox's 404, never Roxy's own "Not a Roblox URL".
    assert tiles["status_4xx"] == 1, tiles
    # v1's "5xx from Roblox": the 503 Roxy's retry hid from the caller still counts.
    assert tiles["roblox_5xx"] == 1, tiles
    # An expand migration keeps Roblox's answers per attempt in the rollups (decision 11: metrics 10).
    assert migrate.REQUIRED_SCHEMA["metrics"] >= 10
    assert migrate.REQUIRED_SCHEMA["metrics"] == migrate.latest_expand_version("metrics")


# ============================================================================================ data-4


async def test_data_4_an_egress_usage_reset_never_lifts_the_rotator_quota_hard_stop(api: Any, api_app: Any) -> None:
    """Plan 8.4: `rotator_quota_gb_per_month` with `rotator_hard_stop_pct` stops rotator traffic for the rest of the
    billing cycle (DataImpulse bills per GB). `egress/rotator.py RotatorPool.usage_snapshot` reads the cycle's bytes
    only from `metrics.egress_usage`, which the Egress usage family reset (Egress > Usage card; also where v1's
    harmless `rotate_ips` clear maps, `V1_CLEAR_TARGETS`) deletes: a rotator stopped at its quota is usable again at
    once and may spend a second full quota in the same cycle. The preview only says the count "starts again from
    what is left"."""
    ctx = api_app.ctx
    await api_app.settings(rotator_quota_gb_per_month=1, rotator_hard_stop_pct=100, health_auto_interval_h=0)
    pool = ctx.egress.rotator
    now = int(ctx.clock.now())

    def seed(conn: Any) -> None:
        conn.execute(
            "INSERT INTO egress_usage (bucket_start, egress, granularity, requests, req_bytes, resp_bytes, "
            "overhead_bytes) VALUES (?, 'rotator', 'minute', 5000, 100000000, 1100000000, 0)",
            (now - now % 60 - 600,),
        )

    await ctx.dbs.metrics.write(seed)  # 1.2 GB through the rotator this cycle, above its 1 GB quota
    await pool.refresh(force=True)
    before = pool.usage_snapshot()
    assert before.stopped, before
    assert before.stop_reason == "rotator_quota_hard_stop", before
    deleted = await _reset_family(api_app, "egress_usage")
    assert deleted["deleted"]["metrics.egress_usage"] == 1
    await pool.refresh(force=True)
    after = pool.usage_snapshot()
    assert after.stopped, f"the quota hard stop lifted after a statistics reset: {after}"
    assert after.cycle_bytes >= before.cycle_bytes, after


# ============================================================================================ data-5


# Fixed (fixer data): `retention.prune_captures` keeps no capture when `capture_ttl_seconds` is 0.
def test_data_5_capture_ttl_zero_removes_stored_payloads(dbs: Any) -> None:
    """The catalog: "in v2 0 means captures expire at once" and "The short default limits how long caller payloads
    sit on disk". `metrics/capture.py` reads 0 that way (no new capture, `get_capture` answers expired), while
    `storage/retention.py prune_captures` turns a TTL of 0 into no age cutoff at all: the payloads already captured
    are never removed by age, while the System page counts none of them (it counts captures inside the TTL)."""
    from roxy.metrics.capture import CapturePolicy
    from roxy.storage import retention

    now = 2_000_000_000

    def seed(conn: Any) -> None:
        conn.executemany(
            "INSERT INTO captures (at, request_id, outcome, status, compressed_blob, bytes) VALUES (?, ?, ?, ?, ?, ?)",
            [(now - 3 * DAY_S + i, f"REQ{i:023d}", "refused", 429, b"caller payload", 14) for i in range(5)],
        )

    dbs.metrics.write_sync(seed)
    settings = {"capture_ttl_seconds": 0, "capture_max_records": 2000, "capture_max_bytes": 64 * 1024 * 1024}
    policy = CapturePolicy.from_settings(settings.get)
    assert not policy.active  # 0 switches capturing off and makes every stored capture read as expired
    keep = retention.RetentionPolicy.from_settings(settings.get)
    dbs.metrics.write_sync(lambda conn: retention.prune_captures(conn, now, keep, retention.BATCH_ROWS))
    left = dbs.metrics.read_sync(lambda conn: conn.execute("SELECT count(*) FROM captures").fetchone()[0])
    assert left == 0, f"{left} captured payloads (three days old) are still on disk with capture_ttl_seconds 0"


# ============================================================================================ data-6


# Fixed (fixer data): `retention.prune_fingerprint_values` caps values per header name, as the writer does.
def test_data_6_header_value_cap_is_per_header_in_retention_too(dbs: Any) -> None:
    """The catalog: "How many distinct values are kept per request header name, for the header drill-down" (v1
    `MAX_HEADER_VALUE_RECORDS` per header too). `metrics/fingerprints.py write_fingerprints` keeps at most that many
    values per name (least seen first), but `storage/retention.py prune_fingerprint_values` passes the same setting
    as a cap on the whole table (oldest `last_seen` first), so three headers with 300 values each (all inside the
    per-header cap of 500) are cut to 500 values in total by the next retention run: the drill-down of most headers
    goes empty, and the busiest varying header pushes every other header's values out."""
    from roxy.metrics.fingerprints import FingerprintItem, write_fingerprints
    from roxy.storage import retention

    now = 2_000_000_000
    items = []
    for header in ("accept-language", "sec-ch-ua-platform", "x-roblox-client"):
        items.append(FingerprintItem("h", header, 300, now - 600, now))
        items.extend(
            FingerprintItem("v", f"{header}\x00value-{i}", 1, now - 600 + i, now - 600 + i) for i in range(300)
        )
    policy = retention.RetentionPolicy()  # the plan 6.10 defaults: max_header_value_records 500
    dbs.metrics.write_sync(lambda conn: write_fingerprints(conn, items, value_cap=policy.max_header_value_records))
    dbs.metrics.write_sync(lambda conn: retention.prune_fingerprint_values(conn, now, policy, retention.BATCH_ROWS))
    per_header = dbs.metrics.read_sync(
        lambda conn: dict(conn.execute("SELECT name, count(*) FROM fingerprint_values GROUP BY name").fetchall())
    )
    assert per_header == {"accept-language": 300, "sec-ch-ua-platform": 300, "x-roblox-client": 300}, per_header


# ============================================================================================ data-7


async def test_data_7_a_reset_canceled_by_shutdown_records_how_it_ended(api: Any, api_app: Any) -> None:
    """Plan 6.8 and 9.7: every reset records its exact row counts in the audit log, and `execute_reset` relabels
    the marker "Data reset (incomplete)" when it stops part way (finding mpjobs-4). A reset runs as a background task
    of one worker (`TaskSupervisor.spawn`), and at a worker's shutdown (gunicorn `max_requests` recycle, a deploy
    stopping the old color) `TaskSupervisor.stop` cancels it after its short drain: `CancelledError` is not an
    `Exception`, so neither the failed audit row nor the marker update runs."""
    from roxy.admin.api import data

    ctx = api_app.ctx
    now_ms = int(ctx.clock.now_ms())

    def seed(conn: Any) -> None:
        conn.executemany(
            "INSERT INTO events (at_ms, type, severity, reason_code, detail_json) "
            "VALUES (?, 'probe', 'info', 'not_roblox', '{}')",
            [(now_ms - 1000 - i,) for i in range(3 * data.BATCH_ROWS)],
        )

    await ctx.dbs.metrics.write(seed)
    body = data.ResetBody.model_validate({"scope": "family", "families": ["probes"]})
    plan = data.build_plan(body, ctx, ctx.clock.now())
    op = data.Operation(data._new_id("reset"), "reset", plan.label, ctx.clock.now())
    target = f"operation:{op.id}"
    op.audit_id = await data._audit(ctx, ADMIN, data.AUDIT_RESET, target, {"plan": plan.label}, "review", None)
    lease = data.ResetLease(ctx, "review-reset")
    assert await lease.acquire()
    task = asyncio.create_task(data.execute_reset(ctx, op, plan, ADMIN, "review", None, lease))
    for _ in range(5000):
        await asyncio.sleep(0.001)
        if sum(op.progress.values()) > 0:
            break
    assert sum(op.progress.values()) > 0, "the reset never started deleting"
    task.cancel()  # what TaskSupervisor.stop does to a still running operation at shutdown
    await asyncio.gather(task, return_exceptions=True)

    def outcome_actions(c: Any) -> list[str]:
        return [str(r[0]) for r in c.execute("SELECT action FROM audit_log WHERE target = ?", (target,))]

    actions: list[str] = []
    for _ in range(100):  # a fix may also let the reset finish on its own (shielded): give it a moment
        actions = await ctx.dbs.control.read(outcome_actions)
        if data.AUDIT_RESET_FAILED in actions or data.AUDIT_RESET_DONE in actions:
            break
        await asyncio.sleep(0.05)
    left = await ctx.dbs.metrics.read(
        lambda c: c.execute("SELECT count(*) FROM events WHERE type = 'probe'").fetchone()
    )
    assert left[0] < 3 * data.BATCH_ROWS  # the reset had started deleting
    # How the reset ended is on record (the rows it deleted before it stopped), as for any other failure.
    assert data.AUDIT_RESET_FAILED in actions or data.AUDIT_RESET_DONE in actions, actions
    if left[0] > 0:
        labels = await ctx.dbs.metrics.read(lambda c: [str(r[0]) for r in c.execute("SELECT label FROM annotations")])
        # A reset that stopped part way never leaves a marker that reads as a finished reset.
        assert not any(label.startswith("Data reset: ") for label in labels), labels


# ============================================================================================ data-9


async def test_data_9_an_infinite_retry_after_is_never_stored_or_sent(api: Any, api_app: Any) -> None:
    """`upstream/cooldowns.py parse_retry_after` accepts any run of digits and `float()` of 309 or more digits is
    infinity (Python raises nothing). The cooldown clamps it, but the 429 log keeps the raw value: SQLite stores Inf,
    `export/upstream_429?format=json` writes `"retry_after_s":Infinity` (json.dumps allows NaN by default, strict
    parsers refuse the file), and `GET /upstream/trace/{id}` for that request answers 422 "A number in this request
    is too large" (an OverflowError from the infinite value). The lens rule: no NaN or infinity stored as a number
    or sent as JSON."""
    huge = "9" * 400
    api_app.roblox.route(host="games.roblox.com", path="/v1/games").mock(
        return_value=httpx.Response(
            429,
            headers={"Retry-After": huge, "x-ratelimit-remaining": "0", "x-ratelimit-reset": huge},
            json={"errors": []},
        )
    )
    client = api_app.harness.new_client()
    caller = await client.get(
        "/games.roblox.com/v1/games?universeIds=1", headers={"X-Forwarded-For": "198.51.100.9", "User-Agent": CALLER_UA}
    )
    assert caller.status_code == 429, caller.text
    await api_app.ctx.recorder.flush()
    stored = await api_app.ctx.dbs.metrics.read(
        lambda c: [tuple(r) for r in c.execute("SELECT retry_after_s, ratelimit_headers_json FROM upstream_429")]
    )
    assert stored, "the 429 was not logged"
    assert all(value is None or math.isfinite(value) for value, _ in stored), stored
    assert all("Infinity" not in str(headers) and "NaN" not in str(headers) for _, headers in stored), stored

    exported = await api.get("export/upstream_429", params={"range": "1h", "format": "json"})
    assert exported.status_code == 200, exported.text
    json.loads(exported.text, parse_constant=lambda name: pytest.fail(f"the export holds {name}, which is not JSON"))

    trace = await api.get(f"upstream/trace/{caller.headers['roxy-request-id']}")
    assert trace.status_code == 200, trace.text


# ============================================================================================ data-10


# Fixed (fixer data): `retention.prune_recommendation_watches` (a retention task) deletes the watches of pruned
# recommendations.
async def test_data_10_watch_rows_leave_with_their_recommendation(dbs: Any) -> None:
    """Plan 6.10: every table has a row cap, a max age, or both (P9: every table bounded). `recommendation_watches`
    (metrics 0002) gets one row per applied recommendation; `storage/retention.py` prunes recommendations (365 days,
    50,000 rows) and the actions of pruned ones, but no task (`RETENTION_TASKS`, `read_history.HISTORY_TABLES`,
    `producers.prune_producers`) touches the watches, and the Data page lists the table with no rule."""
    from roxy.metrics import read_history
    from roxy.storage import retention

    now = 2_000_000_000
    old = now - 400 * DAY_S

    def seed(conn: Any) -> None:
        conn.execute(
            "INSERT INTO recommendations (id, rule_id, fingerprint, state, severity, payload_json, created_at, "
            "updated_at) VALUES ('rec_old', 'CACHE-TTL', 'CACHE-TTL:0', 'applied', 'info', '{}', ?, ?)",
            (old, old),
        )
        conn.execute(
            "INSERT INTO recommendation_actions (recommendation_id, action, at, actor, details_json) "
            "VALUES ('rec_old', 'apply', ?, 'admin:review', '{}')",
            (old,),
        )
        conn.execute(
            "INSERT INTO recommendation_watches (recommendation_id, action_id, started_at, ends_at, state) "
            "VALUES ('rec_old', 1, ?, ?, 'kept')",
            (old, old + 1800),
        )

    dbs.metrics.write_sync(seed)
    policy = retention.RetentionPolicy()
    await retention.run_tasks(dbs, retention.RETENTION_TASKS, policy, now)
    keep = dict.fromkeys(read_history.HISTORY_TABLES, 14.0) | {"rule_hits": 400.0}
    dbs.metrics.write_sync(lambda conn: read_history.prune_history(conn, now, keep))
    counts = dbs.metrics.read_sync(
        lambda conn: [
            conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            for table in ("recommendations", "recommendation_actions", "recommendation_watches")
        ]
    )
    assert counts[:2] == [0, 0], counts  # the recommendation and its actions left with retention
    assert counts[2] == 0, "the watch row of a recommendation pruned long ago is still there"
