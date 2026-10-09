"""The health API (`/admin/api/v1/health`) on the real app: guards, bodies, runs, history, exports.

What this is
    Integration tests of `roxy/admin/api/health.py` through the shared admin API fixtures (`conftest.py` here): a
    running app, a signed-in admin, respx playing Roblox. Runs use the production `LiveFacts` and only checks that
    read local state (disk, databases, configuration, heartbeats), plus H-CRED-AUTH against a respx mock.

Why it exists
    DESIGN.md section 13 and plan 13.1: every route is guarded, the POST also needs CSRF and, when it would call
    Roblox with the credential, a fresh second factor; bodies refuse unknown fields; one run at a time; runs are
    listed, compared and exported, and every export and run start leaves an audit row.

How it works
    Background runs are awaited with `runner_for(ctx).wait(run_id)`. Rows for history tests are written with the
    store functions the runner itself uses, so the read side is tested against exactly what a run writes.

What to read next
    `roxy/admin/api/health.py`, `tests/health/test_runner.py`.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from roxy.health import report, store
from roxy.health.model import CheckResult, Status
from roxy.health.runner import RUN_LEASE, runner_for
from roxy.storage import leases

LOCAL_CHECKS = ["H-DISK", "H-CONFIG", "H-CACHE-RW", "H-WORKERS"]


def _events(ctx: Any, kind: str) -> list[dict[str, Any]]:
    rows = ctx.dbs.metrics.read_sync(
        lambda conn: conn.execute("SELECT detail_json FROM events WHERE type = ? ORDER BY id", (kind,)).fetchall()
    )
    return [json.loads(r[0] or "{}") for r in rows]


def _audit(ctx: Any, action: str) -> list[dict[str, Any]]:
    rows = ctx.dbs.control.read_sync(
        lambda conn: conn.execute(
            "SELECT actor, action, target, after_json FROM audit_log WHERE action = ? ORDER BY id", (action,)
        ).fetchall()
    )
    return [dict(r) for r in rows]


def _store_run(ctx: Any, trigger: str, results: list[tuple[str, Status]], *, started_at: int | None = None) -> int:
    now = int(ctx.clock.now()) if started_at is None else started_at
    at_ms = now * 1000

    def write(conn: Any) -> int:
        run_id = store.insert_run(
            conn, started_at=now, trigger=trigger, version="test", options={}, actor="admin:owner", at_ms=at_ms
        )
        made = []
        for check_id, status in results:
            result = CheckResult(check_id, status, f"{check_id} value", "t", "explained", "/admin/system")
            store.insert_result(conn, run_id, result, at_ms=at_ms)
            made.append(result)
        store.finish_run(conn, run_id, finished_at=now + 1, summary=store.summarize(made), at_ms=at_ms)
        return run_id

    run_id: int = ctx.dbs.metrics.write_sync(write)
    return run_id


async def test_routes_are_guarded(anon_api: Any, api: Any, section13: Any) -> None:
    assert (await anon_api.get("health/runs")).status_code == 401
    assert (await anon_api.get("health/checks")).status_code == 401
    refused = await api.post("health/runs", json={"checks": ["H-DISK"]}, csrf=False)
    assert refused.status_code == 403


async def test_catalog_lists_every_check(api: Any, api_json: Any) -> None:
    body = api_json(await api.get("health/checks"))
    ids = [item["id"] for item in body["items"]]
    assert ids[0] == "H-CRED-PRESENT"
    assert "H-REACH-<host>" in ids
    assert len(ids) == 34
    assert set(body["events"]) == set(store.EVENT_TYPES)
    assert [item["id"] for item in body["items"] if item["uses_credential"]] == ["H-CRED-AUTH"]


async def test_bodies_are_strict(api: Any, section13: Any) -> None:
    fields = section13(await api.post("health/runs", json={"checks": ["H-DISK"], "extra": 1}), 422, "validation_failed")
    assert "extra" in fields
    section13(await api.post("health/runs", content=b"not json", headers={"Content-Type": "application/json"}),
              400, "invalid_json")  # fmt: skip
    fields = section13(await api.post("health/runs", json={"checks": ["H-NOPE"]}), 422, "unknown_check")
    assert "checks" in fields


async def test_a_run_starts_streams_and_reads_back(api_app: Any, api: Any, api_json: Any) -> None:
    ctx = api_app.ctx
    started = await api.post("health/runs", json={"checks": LOCAL_CHECKS, "include_credential": False})
    assert started.status_code == 202, started.text
    body = api_json(started)
    run_id = body["run_id"]
    assert body["checks"] == len(LOCAL_CHECKS)
    assert body["include_credential"] is False
    await runner_for(ctx).wait(run_id)
    run = api_json(await api.get(f"health/runs/{run_id}"))
    assert run["state"] == "finished"
    assert run["trigger"] == "manual"
    assert [r["check_id"] for r in run["results"]] == ["H-CACHE-RW", "H-DISK", "H-WORKERS", "H-CONFIG"]
    for result in run["results"]:
        assert result["status"] in ("pass", "warn", "fail", "n/a")
        assert result["explanation"]
        assert result["title"]
    assert {e["check_id"] for e in _events(ctx, store.EVENT_RESULT)} == set(LOCAL_CHECKS)
    assert _events(ctx, store.EVENT_RUN_FINISHED)[-1]["run_id"] == run_id
    audit_rows = _audit(ctx, "health.run")
    assert audit_rows
    assert audit_rows[-1]["target"] == f"health_run:{run_id}"
    assert audit_rows[-1]["actor"].startswith("admin:")
    latest = api_json(await api.get("health/runs/latest"))
    assert latest["id"] == run_id


async def test_the_credential_check_needs_a_fresh_second_factor(
    api_app: Any, api: Any, api_json: Any, section13: Any
) -> None:
    ctx = api_app.ctx
    route = api_app.roblox.get("https://users.roblox.com/v1/users/authenticated").mock(
        return_value=httpx.Response(200, json={"id": 1000001, "name": "fixture_user"})
    )
    api.make_mfa_stale()
    refused = await api.post("health/runs", json={"checks": ["H-CRED-AUTH"]})
    section13(refused, 403, "reauth_required")
    assert refused.headers.get("roxy-reauth") == "required"
    skipped = await api.post("health/runs", json={"checks": ["H-CRED-AUTH"], "include_credential": False})
    assert skipped.status_code == 202
    await runner_for(ctx).wait(skipped.json()["run_id"])
    result = api_json(await api.get(f"health/runs/{skipped.json()['run_id']}"))["results"][0]
    assert (result["status"], result["value"]) == ("n/a", "skipped")
    assert route.call_count == 0
    await api.fresh_mfa()
    accepted = await api.post("health/runs", json={"checks": ["H-CRED-AUTH"]})
    assert accepted.status_code == 202, accepted.text
    await runner_for(ctx).wait(accepted.json()["run_id"])
    result = api_json(await api.get(f"health/runs/{accepted.json()['run_id']}"))["results"][0]
    assert (result["check_id"], result["status"]) == ("H-CRED-AUTH", "pass"), result
    assert route.call_count == 1  # exactly one account call (plan 13.3)


async def test_a_second_run_is_a_conflict(api_app: Any, api: Any, section13: Any) -> None:
    ctx = api_app.ctx
    running = _store_run(ctx, "schedule", [])
    ctx.dbs.metrics.write_sync(
        lambda conn: conn.execute("UPDATE health_runs SET finished_at = NULL WHERE id = ?", (running,))
    )
    now_ms = int(ctx.clock.now_ms())
    ctx.dbs.hot.write_sync(lambda conn: leases.acquire(conn, RUN_LEASE, "other-worker#1", 600_000, now_ms))
    answer = await api.post("health/runs", json={"checks": ["H-DISK"]})
    section13(answer, 409, "run_in_progress")
    assert answer.headers.get("roxy-health-run") == str(running)


async def test_run_list_filters_pages_and_downloads(api_app: Any, api: Any, api_json: Any, section13: Any) -> None:
    ctx = api_app.ctx
    now = int(ctx.clock.now())
    first = _store_run(ctx, "manual", [("H-DISK", Status.PASS), ("H-WAL", Status.PASS)], started_at=now - 7200)
    second = _store_run(ctx, "schedule", [("H-DISK", Status.FAIL), ("H-WAL", Status.WARN)], started_at=now - 3600)
    body = api_json(await api.get("health/runs"))
    assert [item["id"] for item in body["items"]] == [second, first]
    assert body["total"] == 2
    assert body["columns"][0]["key"] == "id"
    assert body["items"][0]["failed"] == 1
    assert body["items"][0]["worst"] == "fail"
    assert [i["id"] for i in api_json(await api.get("health/runs", params={"trigger": "manual"}))["items"]] == [first]
    assert [i["id"] for i in api_json(await api.get("health/runs", params={"worst": "fail"}))["items"]] == [second]
    found = api_json(await api.get("health/runs", params={"check": "H-DISK", "check_status": "fail"}))
    assert [i["id"] for i in found["items"]] == [second]
    oldest_first = api_json(await api.get("health/runs", params={"order": "asc", "page_size": 10}))
    assert [i["id"] for i in oldest_first["items"]] == [first, second]
    since = api_json(await api.get("health/runs", params={"from": str(now - 5000)}))
    assert [i["id"] for i in since["items"]] == [second]
    section13(await api.get("health/runs", params={"trigger": "nightly"}), 422, "invalid_filter")
    section13(await api.get("health/runs", params={"sort": "summary"}), 422, "invalid_table_query")
    download = await api.get("health/runs", params={"format": "csv"})
    assert download.status_code == 200
    assert download.headers["content-type"].startswith("text/csv")
    assert "attachment" in download.headers["content-disposition"]
    assert download.text.splitlines()[0].startswith('"Run","Started"')
    assert _audit(ctx, "export.download")[-1]["target"] == "table:health_runs"


async def test_a_run_links_its_fix_and_compares_with_the_run_before(api_app: Any, api: Any, api_json: Any) -> None:
    ctx = api_app.ctx
    first = _store_run(ctx, "manual", [("H-DISK", Status.PASS)], started_at=int(ctx.clock.now()) - 60)
    second = _store_run(ctx, "manual", [("H-DISK", Status.FAIL)])
    payload = json.dumps({"subject": "H-DISK", "title": "Free some disk"})
    ctx.dbs.metrics.write_sync(
        lambda conn: conn.execute(
            "INSERT INTO recommendations (id, rule_id, fingerprint, state, severity, payload_json, created_at, "
            "updated_at) VALUES ('rec_disk', 'SYS-HEALTH-FAIL', 'SYS-HEALTH-FAIL:H-DISK', 'open', 'warn', ?, 1, 1)",
            (payload,),
        )
    )
    run = api_json(await api.get(f"health/runs/{second}"))
    disk = run["results"][0]
    assert disk["recommendation"]["link"] == "/admin/recommendations/rec_disk"
    assert run["comparison"] == {
        "previous_run_id": first,
        "new_failures": ["H-DISK"],
        "fixed": [],
        "counts": {"worse": 1},
    }
    diff = api_json(await api.get(f"health/runs/{second}/compare", params={"with": first}))
    assert diff["previous"]["id"] == first
    assert diff["new_failures"] == ["H-DISK"]


async def test_missing_runs_are_404(api: Any, section13: Any) -> None:
    section13(await api.get("health/runs/424242"), 404, "not_found")
    section13(await api.get("health/runs/latest"), 404, "not_found")
    section13(await api.get("health/runs/424242/compare"), 404, "not_found")
    section13(await api.get("health/runs/424242/export"), 404, "not_found")


async def test_exports_are_audited_and_safe(api_app: Any, api: Any, section13: Any) -> None:
    ctx = api_app.ctx
    run_id = _store_run(ctx, "manual", [("H-NGINX", Status.FAIL), ("H-DISK", Status.PASS)])
    as_json = await api.get(f"health/runs/{run_id}/export", params={"format": "json"})
    assert as_json.status_code == 200
    assert "attachment" in as_json.headers["content-disposition"]
    document = as_json.json()
    assert document["schema_version"] == report.REPORT_SCHEMA
    assert document["run"]["id"] == run_id
    as_html = await api.get(f"health/runs/{run_id}/export", params={"format": "html"})
    assert as_html.headers["content-type"].startswith("text/html")
    assert "<script" not in as_html.text
    assert "H-NGINX" in as_html.text
    as_llm = await api.get(f"health/runs/{run_id}/export", params={"format": "llm", "focus": "H-NGINX"})
    assert as_llm.headers["content-type"].startswith("text/plain")
    assert as_llm.text.startswith(report.LLM_INSTRUCTIONS)
    copied = json.loads(as_llm.text[len(report.LLM_INSTRUCTIONS) + 2 :])
    assert copied["focus"] == "H-NGINX"
    assert copied["untrusted"]
    assert as_llm.headers.get("cache-control") == "no-store"
    section13(await api.get(f"health/runs/{run_id}/export", params={"format": "pdf"}), 422, "invalid_format")
    section13(await api.get(f"health/runs/{run_id}/export", params={"focus": "H-NOPE"}), 422, "unknown_check")
    targets = [row["target"] for row in _audit(ctx, "export.download")]
    assert targets.count(f"health_run:{run_id}") == 3
