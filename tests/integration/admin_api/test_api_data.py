"""The Data page API in the real app (plan 6.6, 6.8, 6.10, 14.1, 17.5; parity rows 83, 88, 133): storage sizes with
projections, the retention view, every reset scope with its preview (exact rows and dates), the typed phrase, the
snapshot, the audit rows and the annotation, backups, VACUUM, and the dataset exports."""

from __future__ import annotations

import asyncio
import csv
import io
import json
from pathlib import Path
from typing import Any

from roxy.admin.api import data
from roxy.admin.api.export import DATASETS
from roxy.config.audit import Actor
from roxy.rules.service import RulesService
from roxy.storage import leases

T0_OFFSET = 7200
V1_TARGETS = [
    "probes",
    "requests",
    "refusals",
    "ip_activity",
    "callers",
    "internal_requests",
    "proxy_timings",
    "request_failures",
    "rotate_ips",
    "endpoints",
    "blocked_attempts",
    "rate_limited_attempts",
    "header_blocked_attempts",
    "pause_drops",
    "throttle_drops",
    "tarpit",
    "cache",
    "throttle_rules",
    "live",
    "logins",
    "crawls",
    "throttled",
    "visits",
    "errors",
    "fingerprints",
    "blocked_fingerprints",
    "all",
]


async def _q(db: Any, sql: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    return await db.read(lambda conn: [tuple(r) for r in conn.execute(sql, params).fetchall()])


async def _w(db: Any, sql: str, params: tuple[Any, ...] = ()) -> None:
    await db.write(lambda conn: conn.execute(sql, params))


async def _count(db: Any, table: str, where: str = "1", params: tuple[Any, ...] = ()) -> int:
    rows = await _q(db, f"SELECT count(*) FROM {table} WHERE {where}", params)
    return int(rows[0][0])


async def _preview(api: Any, api_json: Any, scope: dict[str, Any]) -> dict[str, Any]:
    body: dict[str, Any] = api_json(await api.post("data/resets/preview", json=scope))
    return body


async def _run(api: Any, scope: dict[str, Any], preview: dict[str, Any], **extra: Any) -> Any:
    return await api.post("data/resets", json={**scope, "preview": preview["preview"], **extra})


def _tables(preview: dict[str, Any]) -> dict[str, int]:
    return {f"{t['db']}.{t['table']}": t["rows"] for t in preview["tables"]}


async def _entry(api_app: Any, entry_id: str, host: str, path: str, *, rule_id: int | None = None) -> None:
    now = int(api_app.clock.now())
    await _w(
        api_app.ctx.dbs.cache,
        "INSERT INTO entries (id, key, method, host, path, status, stored_at, expires_at, stale_until, ttl, rule_id, "
        "bytes) VALUES (?, ?, 'GET', ?, ?, 200, ?, ?, ?, 60, ?, 100)",
        (entry_id, f"GET {host}/{path}", host, path, now, now + 60, now + 120, rule_id),
    )


# ================================================================================================ storage


async def test_storage_has_every_database_and_table_with_a_projection(
    api: Any, api_app: Any, api_json: Any, metrics_seed: Any
) -> None:
    metrics_seed.record(5)
    await metrics_seed.flush()
    body = api_json(await api.get("data/storage", params={"refresh": "true"}))
    assert body["cached"] is False
    databases = {database["db"]: database for database in body["databases"]}
    assert set(databases) == {"control", "hot", "metrics", "cache"}
    assert databases["metrics"]["dbstat"] is True
    tables = {t["table"]: t for t in databases["metrics"]["tables"]}
    minute = tables["rollup_minute"]
    assert minute["rows"] == 1
    assert minute["bytes"] > 0
    assert minute["rows_last_7d"] == 1
    assert minute["oldest"] == int(api_app.clock.now()) // 60 * 60
    assert minute["max_age_setting"] == "retention_minute_days"
    assert minute["max_age_s"] == 14 * 86400
    projection = minute["projection_30d"]
    assert projection["rows"] >= 1
    assert projection["method"].startswith("rows added per day")
    assert tables["dims"]["projection_30d"]["method"].startswith("no time column")
    assert {"audit_log", "settings_history", "admin_prefs"} <= {t["table"] for t in databases["control"]["tables"]}
    assert set(body["files"]) == {"control.db", "hot.db", "metrics.db", "cache.db"}
    assert body["budget_bytes"] == 12 * 1024**3
    assert body["total_bytes"] > 0
    assert api_json(await api.get("data/storage"))["cached"] is True
    exported = await api.get("data/storage", params={"format": "csv"})
    rows = list(csv.reader(io.StringIO(exported.text)))
    assert rows[0][:4] == ["Database", "Table", "What it holds", "Rows"]
    assert len(rows) > 20


async def test_retention_view_lists_the_settings_and_each_tables_state(api: Any, api_json: Any) -> None:
    body = api_json(await api.get("data/retention"))
    settings = {item["key"]: item for item in body["settings"]}
    assert settings["retention_minute_days"]["value"] == 14
    assert {"events_max_rows", "retention_audit_days", "snapshots_max_bytes", "maintenance_hour"} <= set(settings)
    tables = {f"{t['db']}.{t['table']}": t for t in body["tables"]}
    assert tables["metrics.events"]["row_cap_setting"] == "events_max_rows"
    assert tables["metrics.events"]["status"] == "ok"
    assert body["audit_min_days"] == 400
    assert body["edit_url"].endswith("/settings")


# ================================================================================================ scopes


async def test_reset_listing_maps_every_v1_clear_target(api: Any, api_json: Any) -> None:
    body = api_json(await api.get("data/resets"))
    assert {item["scope"] for item in body["scopes"]} == set(data.SCOPES)
    assert len(data.SCOPES) == 12
    assert {item["name"] for item in body["families"]} == set(data.FAMILIES)
    assert len(data.FAMILIES) == 17
    assert sorted(body["v1_clear_targets"]) == sorted(V1_TARGETS)
    assert len(V1_TARGETS) == 27
    for target, mapping in body["v1_clear_targets"].items():
        assert mapping["scope"] in data.SCOPES, target
        assert set(mapping.get("families", [])) <= set(data.FAMILIES), target


async def test_family_reset_preview_phrase_snapshot_audit_and_annotation(
    api: Any, api_app: Any, api_json: Any, section13: Any, metrics_seed: Any
) -> None:
    now_ms = api_app.clock.now_ms()
    metrics_seed.record(3, at_ms=now_ms - 3_600_000)
    metrics_seed.record(4)
    await metrics_seed.flush()
    metrics = api_app.ctx.dbs.metrics
    scope = {"scope": "family", "families": ["traffic"]}
    preview = await _preview(api, api_json, scope)
    assert _tables(preview)["metrics.rollup_minute"] == 2
    assert preview["confirm_phrase"] == "reset traffic"
    assert len(preview["preview"]) == 64
    assert preview["summary"].startswith("This will delete 2 rows from 1 table covering")
    assert "Not affected" in preview["summary"]
    assert preview["oldest"] == (now_ms - 3_600_000) // 60_000 * 60
    assert [s["db"] for s in preview["snapshots"]] == ["metrics"]
    assert preview["snapshots"][0]["feasible"] is True
    other = await _preview(api, api_json, {"scope": "family", "families": ["latency"]})
    section13(await _run(api, scope, other, confirm="reset traffic", reason="x"), 409, "preview_required")
    section13(await _run(api, scope, preview, reason="x"), 422, "confirmation_required")
    fields = section13(await _run(api, scope, preview, confirm="reset traffic"), 422, "validation_failed")
    assert set(fields) == {"reason"}
    assert await _count(api_app.ctx.dbs.control, "audit_log", "action LIKE 'data.reset%'") == 0
    response = await _run(api, scope, preview, confirm="Reset Traffic", reason="clean slate")
    body = api_json(response)
    assert response.status_code == 200
    assert body["status"] == "done"
    result = body["result"]
    assert result["deleted"]["metrics.rollup_minute"] == 2
    assert result["total_rows"] == 2
    snapshot = Path(api_app.ctx.env.state_dir) / "snapshots" / result["snapshots"][0]["file"]
    assert snapshot.is_file()
    assert snapshot.name.startswith("reset-")
    assert snapshot.name.endswith("-metrics.db")
    assert await _count(metrics, "rollup_minute") == 0
    audits = await _q(
        api_app.ctx.dbs.control,
        "SELECT id, action, target, after_json, reason FROM audit_log WHERE action LIKE 'data.reset%' ORDER BY id",
    )
    assert [row[1] for row in audits] == ["data.reset", "data.reset.done"]
    assert audits[0][2] == audits[1][2] == f"operation:{body['id']}"
    assert audits[1][4] == "clean slate"
    assert json.loads(audits[0][3])["planned_rows"]["metrics.rollup_minute"] == 2
    assert json.loads(audits[1][3])["deleted"]["metrics.rollup_minute"] == 2
    marks = await _q(metrics, "SELECT kind, label, audit_id FROM annotations")
    assert marks == [("reset", "Data reset: Traffic", audits[1][0])]
    assert api_json(await api.get(f"data/operations/{body['id']}"))["status"] == "done"
    section13(await api.get("data/operations/reset_0000000000000000"), 404, "not_found")


async def test_date_range_reset_deletes_only_inside_the_range(
    api: Any, api_app: Any, api_json: Any, section13: Any, metrics_seed: Any
) -> None:
    t0 = int(api_app.clock.now()) - T0_OFFSET
    metrics_seed.event("refusal", "info", "throttle", {"n": 1}, at_ms=t0 * 1000)
    metrics_seed.event("refusal", "info", "throttle", {"n": 2}, at_ms=(t0 + 5400) * 1000)
    metrics_seed.event("login", "info", "ok", {"n": 3}, at_ms=(t0 + 5400) * 1000)
    await metrics_seed.flush()
    fields = section13(
        await api.post("data/resets/preview", json={"scope": "date_range", "families": ["refusals"]}),
        422,
        "invalid_scope",
    )
    assert set(fields) == {"from"}
    scope = {"scope": "date_range", "families": ["refusals", "tarpit"], "from": str(t0 + 3600), "to": str(t0 + 7200)}
    preview = await _preview(api, api_json, scope)
    assert _tables(preview)["metrics.events"] == 1
    assert preview["confirm_phrase"] is None
    skipped = next(t for t in preview["tables"] if t["table"] == "limiter")
    assert skipped["rows"] == 0
    assert "date range" in skipped["skipped"]
    assert preview["range"] == {"from": t0 + 3600, "to": t0 + 7200}
    body = api_json(await _run(api, scope, preview, reason=""))
    assert body["result"]["deleted"]["metrics.events"] == 1
    left = await _q(api_app.ctx.dbs.metrics, "SELECT type, at_ms FROM events WHERE at_ms < ?", ((t0 + 7200) * 1000,))
    assert sorted(left) == sorted([("refusal", t0 * 1000), ("login", (t0 + 5400) * 1000)])
    marks = await _q(api_app.ctx.dbs.metrics, "SELECT at FROM annotations WHERE kind = 'reset'")
    assert marks == [(t0 + 3600,)]  # the marker sits where the deleted data starts


async def test_single_client_reset(api: Any, api_app: Any, api_json: Any, metrics_seed: Any) -> None:
    metrics_seed.record(2, client_ip="203.0.113.5")
    metrics_seed.record(2, client_ip="198.51.100.7")
    metrics_seed.event("refusal", "info", "throttle", {}, ip="203.0.113.5")
    metrics_seed.event("refusal", "info", "throttle", {}, ip="198.51.100.7")
    await metrics_seed.flush()
    hot = api_app.ctx.dbs.hot
    now = int(api_app.clock.now())
    for ip in ("203.0.113.5", "198.51.100.7"):
        await _w(hot, "INSERT INTO strikes (ip, strikes, last_strike_at) VALUES (?, 2, ?)", (ip, now))
        for key in (ip, f"flood:{ip}", f"ua:abcd1234|{ip}", f"ep:3|{ip}", f"ucr:{ip}|1", f"tarpit_arrival:{ip}"):
            await _w(hot, "INSERT INTO limiter (bucket_key, tat_ms, updated_at) VALUES (?, 1, ?)", (key, now))
    scope = {"scope": "client", "client_type": "ip", "client": "203.0.113.5"}
    preview = await _preview(api, api_json, scope)
    tables = _tables(preview)
    assert tables["metrics.client_minute"] == 1
    assert tables["hot.strikes"] == 1
    assert tables["hot.limiter"] == 6
    assert tables["metrics.events"] == 1
    assert preview["confirm_phrase"] is None
    api_json(await _run(api, scope, preview, reason="false positive"))
    assert await _count(api_app.ctx.dbs.metrics, "client_minute", "client_key = '203.0.113.5'") == 0
    assert await _count(api_app.ctx.dbs.metrics, "client_minute", "client_key = '198.51.100.7'") == 1
    assert await _count(hot, "limiter", "bucket_key LIKE '%203.0.113.5%'") == 0
    assert await _count(hot, "limiter", "bucket_key LIKE '%198.51.100.7%'") == 6
    assert await _count(hot, "strikes") == 1
    assert await _count(api_app.ctx.dbs.metrics, "events", "type = 'refusal'") == 1
    place = await _preview(api, api_json, {"scope": "client", "client_type": "place", "client": "12345"})
    assert _tables(place)["metrics.client_minute"] == 1  # the seeded place of the other client


async def test_endpoint_reset_covers_rollups_429s_cooldowns_and_cache(
    api: Any, api_app: Any, api_json: Any, metrics_seed: Any
) -> None:
    target = "games.roblox.com/v1/games/{gameId}/votes"
    metrics_seed.record(2, endpoint_template=target)
    metrics_seed.record(2)
    await metrics_seed.flush()
    now = int(api_app.clock.now())
    metrics, hot = api_app.ctx.dbs.metrics, api_app.ctx.dbs.hot
    for template in (target, "games.roblox.com/v1/games"):
        await _w(
            metrics,
            "INSERT INTO upstream_429 (at_ms, endpoint_template, host, egress) VALUES (?, ?, 'games.roblox.com', "
            "'direct')",
            (now * 1000, template),
        )
        await _w(
            hot,
            "INSERT INTO cooldown (key, until_ms, source, set_at) VALUES (?, ?, 'retry_after', ?)",
            (f"endpoint:{template}:direct", (now + 60) * 1000, now),
        )
    await _entry(api_app, "e1", "games.roblox.com", "v1/games/123/votes")
    await _entry(api_app, "e2", "games.roblox.com", "v1/games/123")
    scope = {"scope": "endpoint", "template": target}
    preview = await _preview(api, api_json, scope)
    tables = _tables(preview)
    assert tables["metrics.rollup_minute"] == 1
    assert tables["metrics.upstream_429"] == 1
    assert tables["hot.cooldown"] == 1
    assert tables["cache.entries"] == 1
    assert {a["action"] for a in preview["actions"]} == {"cache_purge"}
    body = api_json(await _run(api, scope, preview, reason=""))
    assert body["result"]["deleted"]["cache.entries"] == 1
    assert await _count(metrics, "upstream_429") == 1
    assert await _count(hot, "cooldown") == 1
    assert [r[0] for r in await _q(api_app.ctx.dbs.cache, "SELECT id FROM entries")] == ["e2"]
    assert await _count(metrics, "rollup_minute") == 1


async def test_cache_scope_preview_matches_what_the_purge_removes(
    api: Any, api_app: Any, api_json: Any, section13: Any
) -> None:
    for n in range(3):
        await _entry(api_app, f"a{n}", "games.roblox.com", f"v1/games/{n}", rule_id=7)
    for n in range(2):
        await _entry(api_app, f"b{n}", "users.roblox.com", f"v1/users/{n}")
    by_rule = await _preview(api, api_json, {"scope": "cache", "cache": "rule", "value": "7"})
    assert _tables(by_rule)["cache.entries"] == 3
    pattern = await _preview(api, api_json, {"scope": "cache", "cache": "pattern", "value": "users.roblox.com/v1/*"})
    assert _tables(pattern)["cache.entries"] == 2
    scope = {"scope": "cache", "cache": "host", "value": "games.roblox.com"}
    preview = await _preview(api, api_json, scope)
    assert _tables(preview)["cache.entries"] == 3
    assert preview["confirm_phrase"] is None
    body = api_json(await _run(api, scope, preview, reason=""))
    assert body["result"]["deleted"]["cache.entries"] == 3 == _tables(preview)["cache.entries"]
    everything = {"scope": "cache", "cache": "all"}
    all_preview = await _preview(api, api_json, everything)
    assert all_preview["confirm_phrase"] == "purge cache"
    assert _tables(all_preview)["cache.entries"] == 2
    section13(
        await api.post(
            "data/resets/preview",
            json={"scope": "cache", "cache": "pattern", "value": "(a|aa)+", "pattern_type": "regex"},
        ),
        422,
        "invalid_scope",
    )


async def test_bans_scope_by_kind(api: Any, api_app: Any, api_json: Any) -> None:
    service = RulesService(api_app.ctx.dbs.control, clock=api_app.clock, store=api_app.ctx.rules)
    for subject, actor in (
        ("198.51.100.1", Actor("admin", "owner")),
        ("198.51.100.2", Actor("system", "auto:spam_rate")),
        ("198.51.100.3", Actor("system", "auto:spam_rate")),
        ("198.51.100.4", Actor("system", "auto:spam_probe")),
    ):
        await service.create("bans", {"subject_type": "ip", "subject": subject, "reason_code": "spam"}, actor, "t")
    control = api_app.ctx.dbs.control
    detector = await _preview(api, api_json, {"scope": "bans", "bans": "detector", "detector": "spam_rate"})
    assert _tables(detector)["control.bans"] == 2
    full = await _preview(api, api_json, {"scope": "bans", "bans": "all"})
    assert full["confirm_phrase"] == "delete all bans"
    assert _tables(full)["control.bans"] == 4
    scope = {"scope": "bans", "bans": "auto"}
    preview = await _preview(api, api_json, scope)
    version = int(
        json.loads((await _q(control, "SELECT value_json FROM service_state WHERE key = 'config_version'"))[0][0])
    )
    body = api_json(await _run(api, scope, preview, reason="amnesty"))
    assert body["result"]["deleted"]["control.bans"] == 3
    assert await _q(control, "SELECT subject FROM bans") == [("198.51.100.1",)]
    after = int(
        json.loads((await _q(control, "SELECT value_json FROM service_state WHERE key = 'config_version'"))[0][0])
    )
    assert after == version + 1
    rows = await _q(control, "SELECT reason FROM audit_log WHERE action = 'data.reset.rules'")
    assert rows == [("amnesty",)]
    assert len(api_app.ctx.rules.snapshot.bans) == 1  # this worker reloaded its rules at once


async def test_limiter_upstream_recommendations_and_health_scopes(api: Any, api_app: Any, api_json: Any) -> None:
    hot, metrics = api_app.ctx.dbs.hot, api_app.ctx.dbs.metrics
    now = int(api_app.clock.now())
    await _w(hot, "INSERT INTO strikes (ip, strikes, last_strike_at) VALUES ('203.0.113.9', 3, ?)", (now,))
    await _w(hot, "INSERT INTO limiter (bucket_key, tat_ms, updated_at) VALUES ('tall:203.0.113.9', 1, ?)", (now,))
    await _w(
        hot,
        "INSERT INTO cooldown (key, until_ms, source, set_at) VALUES ('egress:direct', ?, 'default', ?)",
        ((now + 60) * 1000, now),
    )
    await _w(hot, "INSERT INTO breaker (key, state, failures) VALUES ('host:games.roblox.com:direct', 'open', 5)")
    limiter = await _preview(api, api_json, {"scope": "limiter"})
    assert limiter["confirm_phrase"] == "reset limiters"
    assert _tables(limiter)["hot.strikes"] == 1
    assert _tables(limiter)["hot.limiter"] >= 1
    api_json(await _run(api, {"scope": "limiter"}, limiter, confirm="reset limiters", reason="calm"))
    assert await _count(hot, "strikes") == 0
    assert await _count(hot, "limiter") == 0
    upstream = await _preview(api, api_json, {"scope": "upstream"})
    assert _tables(upstream) == {"hot.cooldown": 1, "hot.breaker": 1}
    assert upstream["confirm_phrase"] is None
    body = api_json(await _run(api, {"scope": "upstream"}, upstream, reason=""))
    assert body["result"]["deleted"]["hot.cooldown"] == 1
    assert await _count(hot, "breaker") == 0
    for rec_id, state in (("rec_a", "open"), ("rec_b", "dismissed"), ("rec_c", "expired")):
        await _w(
            metrics,
            "INSERT INTO recommendations (id, rule_id, fingerprint, state, severity, payload_json, created_at, "
            "updated_at) VALUES (?, 'R', ?, ?, 'info', '{}', ?, ?)",
            (rec_id, rec_id, state, now, now),
        )
        await _w(
            metrics,
            "INSERT INTO recommendation_actions (recommendation_id, action, at, actor) VALUES (?, 'snooze', ?, 'x')",
            (rec_id, now),
        )
    history = await _preview(api, api_json, {"scope": "recommendations", "recommendations": "history"})
    assert _tables(history)["metrics.recommendations"] == 2
    assert _tables(history)["metrics.recommendation_actions"] == 2
    api_json(await _run(api, {"scope": "recommendations", "recommendations": "history"}, history, reason=""))
    assert await _q(metrics, "SELECT id FROM recommendations") == [("rec_a",)]
    assert await _q(metrics, "SELECT recommendation_id FROM recommendation_actions") == [("rec_a",)]
    await _w(
        metrics,
        "INSERT INTO health_runs (id, started_at, finished_at, trigger) VALUES (1, ?, ?, 'manual')",
        (now - 100, now - 90),
    )
    await _w(metrics, "INSERT INTO health_runs (id, started_at, trigger) VALUES (2, ?, 'manual')", (now - 5,))
    for run_id in (1, 2):
        await _w(metrics, "INSERT INTO health_results (run_id, check_id, status) VALUES (?, 'H-X', 'pass')", (run_id,))
    health = await _preview(api, api_json, {"scope": "health"})
    assert _tables(health) == {"metrics.health_results": 1, "metrics.health_runs": 1}
    api_json(await _run(api, {"scope": "health"}, health, confirm="delete health history", reason="old"))
    assert await _q(metrics, "SELECT id FROM health_runs") == [(2,)]  # the run in progress stays


async def test_tarpit_family_clears_every_workers_memory(api: Any, api_app: Any, api_json: Any) -> None:
    ctx = api_app.ctx
    ctx.abuse.tarpit.stats.record(
        category="flood", reason="r", ip="203.0.113.1", held_s=2.0, skipped=False, gap_s=0.0, at=ctx.clock.now()
    )
    scope = {"scope": "family", "families": ["tarpit"]}
    preview = await _preview(api, api_json, scope)
    assert {"action": "memory_reset", "family": "tarpit"}.items() <= preview["actions"][0].items()
    api_json(await _run(api, scope, preview, confirm="reset tarpit", reason="new period"))
    assert ctx.abuse.tarpit.stats.snapshot()["held"] == 0
    rows = await _q(ctx.dbs.control, "SELECT value_json FROM service_state WHERE key = 'memory_reset_at'")
    assert json.loads(rows[0][0]) == {"tarpit": int(ctx.clock.now())}


async def test_everything_keeps_control_db(api: Any, api_app: Any, api_json: Any, metrics_seed: Any) -> None:
    metrics_seed.record(3)
    metrics_seed.event("probe", "info", "Invalid URL", {})
    await metrics_seed.flush()
    await _entry(api_app, "x1", "games.roblox.com", "v1/games")
    scope = {"scope": "everything"}
    preview = await _preview(api, api_json, scope)
    assert preview["confirm_phrase"] == "everything"
    assert not any(t["db"] in ("control", "hot") for t in preview["tables"])
    body = api_json(await _run(api, scope, preview, confirm="everything", reason="start over"))
    assert body["status"] == "done"
    metrics = api_app.ctx.dbs.metrics
    assert await _count(metrics, "rollup_minute") == 0
    assert await _count(metrics, "events") == 0
    assert await _count(metrics, "dims") >= 1
    assert await _count(metrics, "worker_heartbeat") >= 1
    assert await _count(metrics, "annotations") == 1  # only the marker of this reset
    assert await _count(api_app.ctx.dbs.cache, "entries") == 0
    assert api_app.ctx.settings.is_overridden("tarpit_enabled")


async def test_factory_reset_needs_a_fresh_second_factor_and_keeps_admin_access(
    api: Any, api_app: Any, api_json: Any, section13: Any
) -> None:
    ctx = api_app.ctx
    service = RulesService(ctx.dbs.control, clock=api_app.clock, store=ctx.rules)
    owner = Actor("admin", "owner")
    await service.create("access_list", {"kind": "allow_admin", "cidr": "127.0.0.0/8"}, owner, "keep me in")
    await service.create("access_list", {"kind": "deny", "cidr": "198.51.100.0/24"}, owner, "bad network")
    await service.create("bans", {"subject_type": "ip", "subject": "198.51.100.9", "reason_code": "spam"}, owner, "x")
    await service.delete("rules_cache", (await service.list_rows("rules_cache"))[0]["id"], owner, "custom")
    api_json(await api.patch("settings", json={"changes": {"cache_ttl_seconds": 900}, "reason": "custom"}))
    scope = {"scope": "factory"}
    preview = await _preview(api, api_json, scope)
    assert preview["fresh_mfa_required"] is True
    assert preview["confirm_phrase"] == "factory reset"
    assert _tables(preview)["control.settings"] == 3  # tarpit, rotator (fixture) and the TTL
    section13(await _run(api, scope, preview, confirm="factory reset", reason="x"), 403, "forbidden")
    api.make_mfa_stale()
    run = {**scope, "preview": preview["preview"], "confirm": "factory reset", "reason": "fresh start"}
    stale = await api.post("data/resets/factory", json=run)
    section13(stale, 403, "reauth_required")
    assert stale.headers["roxy-reauth"] == "required"
    await api.fresh_mfa()
    response = await api.post("data/resets/factory", json=run)
    body = api_json(response)
    assert body["status"] == "done", body
    assert ctx.settings.snapshot().overrides == {}
    kinds = [row[0] for row in await _q(ctx.dbs.control, "SELECT kind FROM access_list")]
    assert kinds == ["allow_admin"]
    assert await _count(ctx.dbs.control, "bans") == 0
    assert await _count(ctx.dbs.control, "rules_cache") == 13  # the shipped defaults, seeded again
    files = [s["file"] for s in body["result"]["snapshots"]]
    assert any(name.endswith("-control.db") for name in files)
    actions = {row[0] for row in await _q(ctx.dbs.control, "SELECT action FROM audit_log")}
    assert {"data.reset", "data.reset.rules", "settings.import", "defaults.seed", "data.reset.done"} <= actions
    assert (await api.get("data/storage")).status_code == 200  # the admin is still let in


async def test_one_reset_at_a_time_fleet_wide(api: Any, api_app: Any, api_json: Any, section13: Any) -> None:
    now_ms = api_app.clock.now_ms()
    await api_app.ctx.dbs.hot.write(
        lambda conn: leases.acquire(conn, data.RESET_LEASE, "other-worker:op", 600_000, now_ms)
    )
    scope = {"scope": "upstream"}
    preview = await _preview(api, api_json, scope)
    section13(await _run(api, scope, preview, reason=""), 409, "reset_in_progress")
    assert await _count(api_app.ctx.dbs.control, "audit_log", "action LIKE 'data.reset%'") == 0


# ================================================================================================ backups, vacuum


async def test_backups_list_and_back_up_now(api: Any, api_app: Any, api_json: Any) -> None:
    state_dir = Path(api_app.ctx.env.state_dir)
    body = api_json(await api.get("data/backups"))
    assert body["nightly"]["known"] is False
    assert body["snapshots"] == []
    (state_dir / "audit").mkdir()
    record = {
        "last_success": {
            "at": "2026-10-08T03:00:00Z",
            "date": "2026-10-08",
            "set": {"dir": "/var/backups/roxy/2026-10-08", "files": {"control.db.zst": 1234}, "encrypted": True},
        },
        "restore_test": {"ok": True, "at": "2026-10-01T03:00:00Z"},
    }
    (state_dir / "audit" / "backup.json").write_text(json.dumps(record), encoding="utf-8")
    response = api_json(await api.post("data/backups", json={"reason": "before an upgrade"}))
    assert response["status"] == "done"
    made = {item["db"]: item for item in response["result"]["snapshots"]}
    assert set(made) == {"control", "metrics"}
    listed = api_json(await api.get("data/backups"))
    assert listed["nightly"]["last_success"]["files"] == {"control.db.zst": 1234}
    assert listed["nightly"]["last_success"]["encrypted"] is True
    assert listed["nightly"]["restore_test"]["ok"] is True
    assert {item["kind"] for item in listed["snapshots"]} == {"manual"}
    assert len(listed["snapshots"]) == 2
    assert listed["snapshots_bytes"] == sum(item["bytes"] for item in made.values())
    actions = [row[0] for row in await _q(api_app.ctx.dbs.control, "SELECT action FROM audit_log ORDER BY id")]
    assert actions[-2:] == ["data.backup", "data.backup.done"]


async def test_vacuum_needs_the_typed_phrase_and_never_touches_hot_db(
    api: Any, api_app: Any, api_json: Any, section13: Any
) -> None:
    estimates = {item["db"]: item for item in api_json(await api.get("data/vacuum"))["databases"]}
    assert estimates["hot"]["allowed"] is False
    assert estimates["hot"]["confirm_phrase"] is None
    assert estimates["metrics"]["confirm_phrase"] == "vacuum metrics"
    assert estimates["metrics"]["estimated_s"] >= 0
    section13(
        await api.post("data/vacuum", json={"database": "metrics", "confirm": "vacuum"}), 422, "confirmation_required"
    )
    section13(
        await api.post("data/vacuum", json={"database": "hot", "confirm": "vacuum hot"}), 422, "validation_failed"
    )
    body = api_json(await api.post("data/vacuum", json={"database": "control", "confirm": "vacuum control"}))
    assert body["status"] == "done"
    assert body["result"]["bytes_after"] > 0
    actions = [row[0] for row in await _q(api_app.ctx.dbs.control, "SELECT action FROM audit_log ORDER BY id")]
    assert actions[-2:] == ["data.vacuum", "data.vacuum.done"]


# ================================================================================================ exports


async def test_dataset_exports(api: Any, api_app: Any, api_json: Any, section13: Any, metrics_seed: Any) -> None:
    metrics_seed.record(4, client_ip="203.0.113.44")
    await metrics_seed.flush()
    listing = api_json(await api.get("export/datasets"))
    names = {item["name"] for item in listing["datasets"]}
    assert {"endpoints", "clients_ip", "audit", "settings", "workers", "errors", "upstream_429"} <= names
    assert listing["max_rows"] == 50_000
    response = await api.get("export/endpoints", params={"format": "csv"})
    assert response.status_code == 200
    rows = list(csv.reader(io.StringIO(response.text)))
    assert rows[0][:2] == ["Endpoint", "Requests"]
    assert rows[1][:2] == ["games.roblox.com/v1/games", "4"]
    clients = await api.get("export/clients_ip", params={"format": "json"})
    item = clients.json()["items"][0]
    assert item["requests"] == 4
    assert item["key"] != "203.0.113.44"
    settings = await api.get("export/settings", params={"format": "csv"})
    assert "cache_ttl_seconds" in settings.text
    for name in sorted(names - {"endpoints", "clients_ip", "settings"}):
        every = await api.get(f"export/{name}", params={"format": "json"})
        assert every.status_code == 200, (name, every.text)
        assert every.json()["table"] == data_export_table(name)
    section13(await api.get("export/endpoints"), 422, "invalid_format")
    section13(await api.get("export/nope", params={"format": "csv"}), 404, "not_found")
    section13(await api.get("export/endpoints", params={"format": "xml"}), 422, "invalid_format")
    targets = [
        row[0]
        for row in await _q(
            api_app.ctx.dbs.control, "SELECT target FROM audit_log WHERE action = 'export.download' ORDER BY id"
        )
    ]
    assert targets[:3] == ["table:endpoints", "table:clients_ip", "table:settings"]
    assert len(targets) == len(names)


async def test_guards(anon_api: Any, api: Any, section13: Any) -> None:
    for path in ("data/storage", "data/resets", "data/backups", "data/vacuum", "export/datasets"):
        assert (await anon_api.get(path)).status_code == 401
    assert (await anon_api.post("data/resets/preview", json={"scope": "upstream"})).status_code == 401
    assert (await api.post("data/resets/preview", json={"scope": "upstream"}, csrf=False)).status_code == 403
    section13(await api.post("data/resets/preview", json={"scope": "nonsense"}), 422, "validation_failed")
    section13(await api.post("data/resets/preview", json={"scope": "family"}), 422, "invalid_scope")
    section13(await api.post("data/resets/preview", json={"scope": "upstream", "from": "1"}), 422, "invalid_scope")


async def test_latency_family_keeps_the_rows_and_empties_the_histograms(
    api: Any, api_app: Any, api_json: Any, metrics_seed: Any
) -> None:
    metrics_seed.record(3, latency_ms=120.0)
    await metrics_seed.flush()
    metrics = api_app.ctx.dbs.metrics
    scope = {"scope": "family", "families": ["latency"]}
    preview = await _preview(api, api_json, scope)
    assert preview["tables"][0]["action"] == "clear_latency"
    assert _tables(preview)["metrics.rollup_minute"] == 1
    api_json(await _run(api, scope, preview, confirm="reset latency", reason="new histogram buckets"))
    assert await _q(metrics, "SELECT requests, latency_hist, queue_wait_hist FROM rollup_minute") == [(3, None, None)]


async def test_every_plan_part_names_a_real_table_row_identity_and_clause(api_app: Any) -> None:
    ctx = api_app.ctx
    now = ctx.clock.now()
    bodies: list[dict[str, Any]] = [
        {"scope": "family", "families": list(data.FAMILIES)},
        {"scope": "date_range", "families": list(data.FAMILIES), "from": "1000", "to": "2000"},
        {"scope": "client", "client_type": "ip", "client": "2001:db8::1"},
        {"scope": "client", "client_type": "place", "client": "99"},
        {"scope": "endpoint", "template": "games.roblox.com/v1/games/{gameId}"},
        {"scope": "limiter"},
        {"scope": "upstream"},
        {"scope": "recommendations", "recommendations": "all"},
        {"scope": "recommendations"},
        {"scope": "health", "from": "1000", "to": "2000"},
        {"scope": "everything"},
        {"scope": "factory"},
    ]
    for raw in bodies:
        plan = data.build_plan(data.ResetBody.model_validate(raw), ctx, now)
        assert plan.parts or plan.upstream_reset, raw
        for part in plan.parts:

            def check(conn: Any, part: data.Part = part, window: Any = plan.range) -> bool:
                conn.execute(f"SELECT {part.key} FROM {part.table} LIMIT 0")  # the batch delete's row identity
                data.count_part(conn, part, window)  # the clause and its parameters
                return True

            assert await ctx.dbs.get(part.db).read(check), (raw, part.table)


def test_template_regex_matches_one_segment_per_placeholder() -> None:
    pattern = data.template_regex("games.roblox.com/v1/games/{gameId}/votes")
    assert pattern == r"^games\.roblox\.com/v1/games/[^/]+/votes$"
    assert data.template_regex("/users.roblox.com/v1/users/{userId}") == r"^users\.roblox\.com/v1/users/[^/]+$"


def data_export_table(name: str) -> str:
    """The table name an export of dataset `name` carries (its TableSpec name)."""
    return DATASETS[name].spec.name


async def test_a_long_operation_answers_202_and_reports_its_progress(api: Any, api_json: Any, monkeypatch: Any) -> None:
    monkeypatch.setattr(data, "INLINE_WAIT_S", 0.0)
    response = await api.post("data/backups", json={})
    assert response.status_code == 202, response.text
    started = api_json(response)
    assert started["status"] == "running"
    assert started["url"].endswith(f"/data/operations/{started['id']}")
    for _ in range(200):
        status = api_json(await api.get(f"data/operations/{started['id']}"))
        if status["status"] != "running":
            break
        await asyncio.sleep(0.02)
    assert status["status"] == "done"
    assert len(status["result"]["snapshots"]) == 2
