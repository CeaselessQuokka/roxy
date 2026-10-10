"""Review round 3 fixes of the Data area (group admin_data), through the running app.

What this is
    Tests that go with the fixes of findings parity-4 (reset fences), mpjobs-4 (the reset marker written before the
    first delete), apisec-5 (Back up now within the snapshot cap, one data operation at a time), parity-8 (cache
    statistics cleared without touching the requests), parity-9 (v1's narrow clears), parity-10 (the retention
    view), and the lane requests: the public `ResetLease`, the backup request file, the schema 5 tables in the
    storage view and in the resets that own their data.

Why it exists
    The strict xfail tests of the findings pin one case each; these pin the rest of each fix: other workers (a
    second `MetricsRecorder` over the same databases stands in for one), every reset scope and the cases where a
    fix must not reach too far (another family, another client, a past date range, reset snapshots).

How it works
    The `api` fixtures of `conftest.py`: the real app, the real login, the real recorder; resets run through
    `POST /data/resets/preview` and `POST /data/resets` with the digest, the phrase and a reason.

What to read next
    `roxy/admin/api/data.py`, `roxy/metrics/recorder.py` (reset fences), `roxy/storage/read_sizes.py`,
    `tests/unit/admin_api/test_r3_fix_data_fences.py`.
"""

from __future__ import annotations

import inspect
import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest

from roxy import internal_app
from roxy.admin.api import data
from roxy.config.catalog import CATALOG
from roxy.core.reasons import CacheState, Egress, Outcome, ReasonCode, Source
from roxy.metrics.recorder import CLEARED_CACHE_STATE, FENCED_TABLES, MAX_RESET_FENCES, RESET_FENCE_KEY, MetricsRecorder
from roxy.storage import leases
from roxy.storage.db import SharedStateUnavailable

HOUR = 3600
MIB = 1024 * 1024
SCHEMA_5_TABLES = (
    "rule_hit_minute",
    "tarpit_minute",
    "tarpit_hold_minute",
    "client_score_hour",
    "metrics_pipeline_minute",
    "disk_samples",
    "table_size_samples",
)
CACHE_SERVE = {
    "outcome": Outcome.SERVED_CACHE,
    "reason": ReasonCode.CACHE_HIT,
    "source": Source.CACHE,
    "upstream_calls": 0,
    "egress": Egress.NONE,
}


# ================================================================================================ helpers


async def _q(db: Any, sql: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    rows: list[tuple[Any, ...]] = await db.read(lambda conn: [tuple(r) for r in conn.execute(sql, params).fetchall()])
    return rows


async def _w(db: Any, sql: str, params: tuple[Any, ...] = ()) -> None:
    await db.write(lambda conn: conn.execute(sql, params))


async def _requests(api_app: Any, where: str = "1") -> int:
    rows = await _q(
        api_app.ctx.dbs.metrics,
        f"SELECT coalesce(sum(r.requests), 0) FROM rollup_minute r JOIN dims d USING (dim_hash) WHERE {where}",
    )
    return int(rows[0][0])


async def _reset(api: Any, api_json: Any, scope: dict[str, Any]) -> dict[str, Any]:
    preview = api_json(await api.post("data/resets/preview", json=scope))
    body = {**scope, "preview": preview["preview"], "reason": "test"}
    if preview.get("confirm_phrase"):
        body["confirm"] = preview["confirm_phrase"]
    response = await api.post("data/resets", json=body)
    assert response.status_code == 200, response.text
    result: dict[str, Any] = api_json(response)
    assert result["status"] == "done", result
    return result


async def _v1_clear(api: Any, api_json: Any, target: str) -> dict[str, Any]:
    mapping = api_json(await api.get("data/resets"))["v1_clear_targets"][target]
    return await _reset(api, api_json, {k: v for k, v in mapping.items() if k != "note"})


def _other_worker(api_app: Any) -> MetricsRecorder:
    """A second worker's recorder over the same databases (each worker has its own unflushed counts)."""
    ctx = api_app.ctx
    return MetricsRecorder(ctx.dbs, ctx.settings, ctx.clock, worker_id="other", ip_hash_key=ctx.ip_hash_key)


async def _flushes(worker: MetricsRecorder, count: int) -> None:
    for _ in range(count):
        await worker.flush()


# ================================================================================================ parity-4: fences


async def test_another_workers_unflushed_counts_never_refill_a_reset(
    api: Any, api_app: Any, api_json: Any, metrics_seed: Any
) -> None:
    other = _other_worker(api_app)
    try:
        for _ in range(3):
            other.record_outcome(metrics_seed.outcome())  # gathered by the other worker, not flushed yet
        metrics_seed.record(2)
        await _reset(api, api_json, {"scope": "family", "families": ["traffic"]})
        assert await _requests(api_app) == 0
        # The other worker learns of the fence in its next flush; that batch and the next were gathered (at least
        # partly) before it could know, so both are fenced off. Two flush intervals at most.
        await _flushes(other, 2)
        assert await _requests(api_app) == 0
        other.record_outcome(metrics_seed.outcome())
        await other.flush()
        metrics_seed.record(1)  # the worker that ran the reset keeps what it counts after it at once
        await metrics_seed.flush()
        assert await _requests(api_app) == 2
        stored = await _q(
            api_app.ctx.dbs.control, "SELECT value_json FROM service_state WHERE key = ?", (RESET_FENCE_KEY,)
        )
        fence = json.loads(stored[0][0])["fences"][-1]
        assert fence["selectors"] == [{"table": "rollup_minute", "action": "delete", "match": {}}]
    finally:
        await other.aclose(budget_s=1.0)


async def test_a_fence_reaches_no_further_than_its_reset(
    api: Any, api_app: Any, api_json: Any, metrics_seed: Any
) -> None:
    other = _other_worker(api_app)
    try:
        now = int(api_app.clock.now())
        for ip in ("203.0.113.5", "203.0.113.5", "198.51.100.7", "198.51.100.7"):
            other.record_outcome(metrics_seed.outcome(client_ip=ip))
        other.record_event("login", "info", "fence_probe", {})
        # Another family, one client and a past date range: none of them covers the traffic counts held.
        await _reset(api, api_json, {"scope": "family", "families": ["probes"]})
        await _reset(api, api_json, {"scope": "client", "client_type": "ip", "client": "203.0.113.5"})
        past = {
            "scope": "date_range",
            "families": ["traffic", "logins"],
            "from": str(now - 2 * HOUR),
            "to": str(now - HOUR),
        }
        await _reset(api, api_json, past)
        await _flushes(other, 1)
        assert await _requests(api_app) == 4
        clients = await _q(
            api_app.ctx.dbs.metrics, "SELECT client_key, requests FROM client_minute WHERE client_type = 'ip'"
        )
        assert clients == [("198.51.100.7", 2)]  # the reset client's rows were fenced off, the other client's kept
        pairs = await _q(api_app.ctx.dbs.metrics, "SELECT client_key FROM client_minute WHERE client_type = 'pair'")
        assert pairs == [("198.51.100.7|12345",)]  # and so were the pairs it is part of (parity-7 rows)
        logins = await _q(
            api_app.ctx.dbs.metrics, "SELECT count(*) FROM events WHERE type = 'login' AND reason_code = 'fence_probe'"
        )
        assert logins == [(1,)]  # the past range of the logins family does not cover a login of now
    finally:
        await other.aclose(budget_s=1.0)


async def test_unflushed_cache_states_and_latency_are_rewritten_not_dropped(
    api: Any, api_app: Any, api_json: Any, metrics_seed: Any
) -> None:
    other = _other_worker(api_app)
    try:
        for _ in range(3):
            other.record_outcome(metrics_seed.outcome(cache_state=CacheState.HIT, **CACHE_SERVE))
        other.record_outcome(metrics_seed.outcome(latency_ms=300.0))
        await _v1_clear(api, api_json, "cache")
        await _reset(api, api_json, {"scope": "family", "families": ["latency"]})
        await _flushes(other, 1)
        rows = await _q(
            api_app.ctx.dbs.metrics,
            "SELECT d.cache_state, sum(r.requests), max(r.latency_hist IS NOT NULL) FROM rollup_minute r "
            "JOIN dims d USING (dim_hash) GROUP BY d.cache_state",
        )
        assert rows == [(CLEARED_CACHE_STATE, 4, 0)]  # every request kept, no lookup state, no histogram
    finally:
        await other.aclose(budget_s=1.0)


async def test_the_fence_key_is_bounded(api: Any, api_app: Any, api_json: Any) -> None:
    for _ in range(MAX_RESET_FENCES + 2):
        await _reset(api, api_json, {"scope": "family", "families": ["visits"]})
    stored = await _q(api_app.ctx.dbs.control, "SELECT value_json FROM service_state WHERE key = ?", (RESET_FENCE_KEY,))
    document = json.loads(stored[0][0])
    assert document["seq"] == MAX_RESET_FENCES + 2
    assert [f["seq"] for f in document["fences"]] == list(range(3, MAX_RESET_FENCES + 3))
    # A reset with nothing the recorder writes leaves the key alone.
    await _reset(api, api_json, {"scope": "upstream"})
    again = await _q(api_app.ctx.dbs.control, "SELECT value_json FROM service_state WHERE key = ?", (RESET_FENCE_KEY,))
    assert json.loads(again[0][0])["seq"] == MAX_RESET_FENCES + 2


async def test_every_part_a_fence_needs_names_its_rows(api_app: Any) -> None:
    ctx = api_app.ctx
    now = ctx.clock.now()
    bodies: list[dict[str, Any]] = [
        {"scope": "family", "families": list(data.FAMILIES)},
        {"scope": "date_range", "families": list(data.FAMILIES), "from": "1000", "to": "2000"},
        {"scope": "client", "client_type": "ip", "client": "2001:db8::1"},
        {"scope": "client", "client_type": "place", "client": "99"},
        {"scope": "endpoint", "template": "games.roblox.com/v1/games/{gameId}"},
        {"scope": "everything"},
        {"scope": "factory"},
    ]
    for raw in bodies:
        plan = data.build_plan(data.ResetBody.model_validate(raw), ctx, now)
        selectors = data.fence_selectors(plan)
        for part in plan.parts:
            table = "rollup_minute" if part.table in data.ROLLUPS else part.table
            if part.db != "metrics" or table not in FENCED_TABLES:
                continue
            assert part.where == "1" or part.match is not None, (raw, part.table, part.where)
            if plan.range is None or part.time_col is not None:
                assert any(s["table"] == table for s in selectors), (raw, part.table)


# ================================================================================================ mpjobs-4: the marker


async def test_a_reset_that_fails_before_deleting_leaves_no_marker(
    api: Any, api_app: Any, api_json: Any, metrics_seed: Any, monkeypatch: Any
) -> None:
    metrics_seed.record(2)
    await metrics_seed.flush()

    async def busy(*_args: Any) -> int:
        raise SharedStateUnavailable("metrics", "database is locked")

    monkeypatch.setattr(data, "_run_part", busy)
    scope = {"scope": "family", "families": ["traffic"]}
    preview = api_json(await api.post("data/resets/preview", json=scope))
    run = {**scope, "preview": preview["preview"], "confirm": "reset traffic", "reason": "x"}
    answer = await api.post("data/resets", json=run)
    assert answer.status_code == 500, answer.text
    assert await _q(api_app.ctx.dbs.metrics, "SELECT count(*) FROM annotations") == [(0,)]
    actions = [
        r[0] for r in await _q(api_app.ctx.dbs.control, "SELECT action FROM audit_log WHERE action LIKE 'data.reset%'")
    ]
    assert actions == ["data.reset", "data.reset.failed"]
    assert await _requests(api_app) == 2


async def test_a_state_reset_marks_a_config_change_and_a_counter_reset_a_reset(
    api: Any, api_app: Any, api_json: Any, metrics_seed: Any
) -> None:
    metrics_seed.record(1)
    await metrics_seed.flush()
    await _reset(api, api_json, {"scope": "upstream"})
    await _reset(api, api_json, {"scope": "family", "families": ["traffic"]})
    marks = await _q(api_app.ctx.dbs.metrics, "SELECT kind, label FROM annotations ORDER BY id")
    assert marks == [("config_change", "Data reset: upstream state"), ("reset", "Data reset: Traffic")]
    done = await _q(api_app.ctx.dbs.control, "SELECT id FROM audit_log WHERE action = 'data.reset.done' ORDER BY id")
    linked = await _q(api_app.ctx.dbs.metrics, "SELECT audit_id FROM annotations ORDER BY id")
    assert linked == done  # each marker links to the row with the exact counts
    plan = data.build_plan(data.ResetBody.model_validate({"scope": "family", "families": ["latency"]}), api_app.ctx, 0)
    assert "metrics.rollup_minute#latency" in data.marker_tables(plan)


# ================================================================================================ apisec-5: backups


def _snapshot(folder: Path, name: str, size: int, age_s: float) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    path.write_bytes(b"\0" * size)
    then = path.stat().st_mtime - age_s
    os.utime(path, (then, then))
    return path


async def test_back_up_now_replaces_only_its_own_oldest_copies(api: Any, api_app: Any, api_json: Any) -> None:
    folder = Path(api_app.ctx.env.state_dir) / "snapshots"
    need = data._database_need(api_app.ctx, "control") + data._database_need(api_app.ctx, "metrics")
    keep = _snapshot(folder, "reset-20260101T000000Z-metrics.db", MIB, 7200)
    old = _snapshot(folder, "manual-20260101T000000Z-control.db", MIB, 3600)
    # Room for the new set and the reset copy, not for the old manual copy too (half a MiB covers the WAL growth
    # of the settings change below).
    await api_app.settings(snapshots_max_bytes=need + MIB + MIB // 2)
    body = api_json(await api.post("data/backups", json={"reason": "before an upgrade"}))
    assert body["status"] == "done", body
    assert body["result"]["replaced"] == [old.name]
    assert keep.exists()
    assert not old.exists()
    intent = await _q(api_app.ctx.dbs.control, "SELECT after_json FROM audit_log WHERE action = 'data.backup'")
    assert json.loads(intent[0][0])["replaces"] == [old.name]


async def test_back_up_now_never_removes_reset_snapshots_to_make_room(
    api: Any, api_app: Any, api_json: Any, section13: Any
) -> None:
    """The reset snapshot stays and the folder stays within its cap: the copy that does not fit is skipped with its
    reason, and the root backup is still asked (review round 4, finding secfix-4: this answered 409 and wrote no
    request before)."""
    folder = Path(api_app.ctx.env.state_dir) / "snapshots"
    need = data._database_need(api_app.ctx, "control") + data._database_need(api_app.ctx, "metrics")
    keep = _snapshot(folder, "reset-20260101T000000Z-metrics.db", need, 7200)
    cap = need + need // 2
    await api_app.settings(snapshots_max_bytes=cap)
    body = api_json(await api.post("data/backups", json={}))
    assert body["status"] == "done", body
    assert keep.exists()
    assert body["result"]["replaced"] == []
    assert body["result"]["skipped"], body["result"]  # at least one copy did not fit, and says why
    assert all(item["reason"] for item in body["result"]["skipped"])
    assert sum(path.stat().st_size for path in folder.iterdir()) <= cap
    assert body["result"]["request"]["written"] is True
    assert (Path(api_app.ctx.env.state_dir) / data.BACKUP_REQUEST_NAME).exists()


async def test_back_up_now_is_not_feasible_only_when_nothing_could_be_asked(
    api: Any, api_app: Any, section13: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With no copy possible (snapshots off) and a request file that cannot be written, 409 `not_feasible` (and a
    `data.backup.failed` audit row); nothing else ever answers it (finding secfix-4)."""
    await api_app.settings(snapshots_max_bytes=0)

    def unwritable(state_dir: Path, by: str, audit_id: int | None, requested_at: float) -> dict[str, Any]:
        return {"written": False, "file": data.BACKUP_REQUEST_NAME, "error": "PermissionError"}

    monkeypatch.setattr(data, "write_backup_request", unwritable)
    section13(await api.post("data/backups", json={}), 409, "not_feasible")
    rows = await _q(
        api_app.ctx.dbs.control, "SELECT action FROM audit_log WHERE action LIKE 'data.backup%' ORDER BY id"
    )
    assert rows == [("data.backup",), ("data.backup.failed",)]
    held = await _q(
        api_app.ctx.dbs.hot,
        "SELECT count(*) FROM lease WHERE name = ? AND expires_ms > ?",
        (data.RESET_LEASE, api_app.clock.now_ms()),
    )
    assert held == [(0,)]  # the lease is given back


async def test_one_backup_or_reset_at_a_time(api: Any, api_app: Any, api_json: Any, section13: Any) -> None:
    now_ms = api_app.clock.now_ms()
    await api_app.ctx.dbs.hot.write(lambda conn: leases.acquire(conn, data.RESET_LEASE, "w2:reset_x", 600_000, now_ms))
    section13(await api.post("data/backups", json={}), 409, "run_in_progress")
    assert await _q(api_app.ctx.dbs.control, "SELECT count(*) FROM audit_log WHERE action LIKE 'data.backup%'") == [
        (0,)
    ]
    await api_app.ctx.dbs.hot.write(lambda conn: leases.release(conn, data.RESET_LEASE, "w2:reset_x"))
    assert api_json(await api.post("data/backups", json={}))["status"] == "done"
    held = await _q(
        api_app.ctx.dbs.hot,
        "SELECT count(*) FROM lease WHERE name = ? AND expires_ms > ?",
        (data.RESET_LEASE, api_app.clock.now_ms()),
    )
    assert held == [(0,)]  # released when the backup ended


async def test_back_up_now_asks_the_root_backup_and_shows_what_it_did(
    api: Any, api_app: Any, api_json: Any, api_admin: Any
) -> None:
    state_dir = Path(api_app.ctx.env.state_dir)
    body = api_json(await api.post("data/backups", json={"reason": "now"}))
    request = state_dir / data.BACKUP_REQUEST_NAME
    document = json.loads(request.read_text(encoding="utf-8"))
    intent = await _q(api_app.ctx.dbs.control, "SELECT id FROM audit_log WHERE action = 'data.backup'")
    assert document == {
        "requested_at": document["requested_at"],
        "by": f"admin:{api_admin.username}",
        "audit_id": intent[0][0],
    }
    assert document["requested_at"].endswith("Z")
    assert stat.S_IMODE(request.stat().st_mode) == 0o640
    assert body["result"]["request"]["written"] is True
    leftovers = [name for name in os.listdir(state_dir) if name.startswith(f".{data.BACKUP_REQUEST_NAME}.")]
    assert leftovers == []  # the temporary file was renamed into place
    listed = api_json(await api.get("data/backups"))
    assert listed["pending_request"] == {k: document[k] for k in ("requested_at", "by", "audit_id")}
    (state_dir / "audit").mkdir(exist_ok=True)
    answered = {
        "at": "2026-10-09T03:00:00Z",
        "by": "admin:owner",
        "requested_at": "x",
        "outcome": "skipped_recent",
        "extra": "<b>dropped</b>",
    }
    record = {"last_request": answered}
    (state_dir / "audit" / "backup.json").write_text(json.dumps(record), encoding="utf-8")
    request.unlink()
    listed = api_json(await api.get("data/backups"))
    assert listed["pending_request"] is None
    assert listed["last_request"] == {
        "at": "2026-10-09T03:00:00Z",
        "requested_at": "x",
        "by": "admin:owner",
        "outcome": "skipped_recent",
    }


# ================================================================================================ parity-8 and 9


async def test_clearing_cache_statistics_merges_rows_at_every_rollup_level(
    api: Any, api_app: Any, api_json: Any, metrics_seed: Any
) -> None:
    metrics_seed.record(2, cache_state=CacheState.HIT, latency_ms=10.0, **CACHE_SERVE)
    metrics_seed.record(3, cache_state=CacheState.STALE, latency_ms=900.0, **CACHE_SERVE)
    await metrics_seed.flush()
    metrics = api_app.ctx.dbs.metrics
    # As compaction would have written them (rollup_day carries its zone).
    await _w(
        metrics,
        "INSERT INTO rollup_hour (bucket_start, dim_hash, requests, latency_hist) "
        "SELECT 0, dim_hash, requests, latency_hist FROM rollup_minute",
    )
    await _w(
        metrics,
        "INSERT INTO rollup_day (bucket_start, dim_hash, requests, latency_hist, tz) "
        "SELECT 0, dim_hash, requests, latency_hist, 'UTC' FROM rollup_minute",
    )
    preview = api_json(await api.post("data/resets/preview", json={"scope": "family", "families": ["cache_stats"]}))
    assert "clear the cache state of 6 rows in 3 tables" in preview["summary"]
    await _v1_clear(api, api_json, "cache")
    for level in ("rollup_minute", "rollup_hour", "rollup_day"):
        rows = await _q(
            metrics,
            f"SELECT d.cache_state, r.requests, r.latency_hist IS NOT NULL FROM {level} r JOIN dims d USING (dim_hash)",
        )
        assert rows == [(CLEARED_CACHE_STATE, 5, 1)], level  # HIT and STALE met in one row, histograms merged
    tz = await _q(metrics, "SELECT tz FROM rollup_day")
    assert tz == [("UTC",)]


async def test_each_v1_attempts_and_throttle_clear_keeps_the_others(
    api: Any, api_app: Any, api_json: Any, metrics_seed: Any
) -> None:
    for reason in ("endpoint_blocked", "endpoint_rule", "header_rule"):
        metrics_seed.event("refusal", "info", reason, {"path": f"games.roblox.com/{reason}"}, ip="203.0.113.9")
    for kind in ("throttled", "throttle_tier", "ua_rule_hit"):
        metrics_seed.event(kind, "info", "x", {}, ip="203.0.113.9")
    await metrics_seed.flush()
    metrics = api_app.ctx.dbs.metrics

    async def left() -> list[str]:
        rows = await _q(
            metrics,
            "SELECT CASE WHEN type = 'refusal' THEN reason_code ELSE type END FROM events "
            "WHERE type IN ('refusal', 'throttled', 'throttle_tier', 'ua_rule_hit')",  # not the sign-in's login event
        )
        return sorted(r[0] for r in rows)

    await _v1_clear(api, api_json, "rate_limited_attempts")
    assert await left() == ["endpoint_blocked", "header_rule", "throttle_tier", "throttled", "ua_rule_hit"]
    await _v1_clear(api, api_json, "header_blocked_attempts")
    await _v1_clear(api, api_json, "throttled")
    assert await left() == ["endpoint_blocked", "throttle_tier", "ua_rule_hit"]
    await _v1_clear(api, api_json, "throttle_rules")
    assert await left() == ["endpoint_blocked"]


# ================================================================================================ parity-10 and lanes


async def test_the_retention_view_lists_both_cards_and_every_bounded_table(api: Any, api_json: Any) -> None:
    body = api_json(await api.get("data/retention"))
    cards = {item["key"]: item["card"] for item in body["settings"]}
    wanted = {key for key, spec in CATALOG.items() if {"data#retention", "data#record-caps"} & set(spec.pages)}
    assert sorted(wanted - set(cards)) == []
    assert cards["max_login_records"] == "record-caps"
    assert cards["retention_expired_bans_days"] == "retention"
    tables = {f"{t['db']}.{t['table']}": t for t in body["tables"]}
    for name in (
        "control.bans",
        "control.admin_sessions",
        "control.trusted_devices",
        "control.invalidation_tokens",
        "metrics.egress_usage",
        "metrics.health_results",
        "metrics.error_minute",
        "metrics.rule_hits",
        "metrics.client_score_hour",
        "metrics.disk_samples",
        "hot.limiter",
        "hot.cooldown",
        "hot.job_runs",
    ):
        assert name in tables, name
    assert tables["control.bans"]["max_age_setting"] == "retention_expired_bans_days"
    assert tables["metrics.error_minute"]["max_age_s"] == 8 * 86_400
    assert tables["metrics.error_minute"]["max_age_setting"] is None  # set by the code, no setting
    assert tables["metrics.client_score_hour"]["row_cap"] == 300_000
    assert tables["metrics.egress_usage"]["rule"]
    assert tables["control.audit_log"]["max_age_s"] >= 400 * 86_400


async def test_the_storage_view_names_the_schema_5_tables(api: Any, api_json: Any) -> None:
    body = api_json(await api.get("data/storage", params={"refresh": "true"}))
    metrics = {t["table"]: t for d in body["databases"] if d["db"] == "metrics" for t in d["tables"]}
    for table in SCHEMA_5_TABLES:
        assert metrics[table]["label"] != table, table


async def test_resets_cover_the_schema_5_tables_that_hold_their_data(api: Any, api_app: Any, api_json: Any) -> None:
    metrics = api_app.ctx.dbs.metrics
    now = int(api_app.clock.now()) // 60 * 60
    for ip in ("203.0.113.5", "198.51.100.7"):
        await _w(
            metrics,
            "INSERT INTO client_score_hour (bucket_start, client_key, score_max, score_last, last_at) "
            "VALUES (?, ?, 50, 50, ?)",
            (now // 3600 * 3600, ip, now),
        )
    for sql in (
        "INSERT INTO tarpit_minute (bucket_start, category, kind, holds) VALUES (?, 'flood', 'hold', 1)",
        "INSERT INTO tarpit_hold_minute (bucket_start, category, bound_ms, holds) VALUES (?, 'flood', 2000, 1)",
        "INSERT INTO rule_hit_minute (bucket_start, table_name, rule_key, hits) VALUES (?, 'bans', '1', 1)",
        "INSERT INTO metrics_pipeline_minute (bucket_start, worker_id, dropped) VALUES (?, 'w', 1)",
        "INSERT INTO disk_samples (at, total_bytes) VALUES (?, 1)",
        "INSERT INTO table_size_samples (at, db, table_name, bytes) VALUES (?, 'metrics', 'events', 1)",
    ):
        await _w(metrics, sql, (now,))

    async def count(table: str) -> int:
        return int((await _q(metrics, f"SELECT count(*) FROM {table}"))[0][0])

    tarpit = await _reset(api, api_json, {"scope": "family", "families": ["tarpit"]})
    assert tarpit["result"]["deleted"]["metrics.tarpit_minute"] == 1
    assert (await count("tarpit_minute"), await count("tarpit_hold_minute")) == (0, 0)
    await _reset(api, api_json, {"scope": "client", "client_type": "ip", "client": "203.0.113.5"})
    assert await _q(metrics, "SELECT client_key FROM client_score_hour") == [("198.51.100.7",)]
    await _reset(api, api_json, {"scope": "family", "families": ["activity"]})
    assert await count("client_score_hour") == 0
    await _reset(api, api_json, {"scope": "everything"})
    for table in ("rule_hit_minute", "metrics_pipeline_minute", "disk_samples", "table_size_samples"):
        assert await count(table) == 0, table


def test_the_reset_lease_is_public_and_shared_with_the_internal_socket() -> None:
    assert not hasattr(data, "_Lease")
    assert "ResetLease" in data.__all__
    assert "data.ResetLease(" in inspect.getsource(internal_app)
