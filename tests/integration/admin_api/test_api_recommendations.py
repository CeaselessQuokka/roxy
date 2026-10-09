"""Recommendations API (`/admin/api/v1/recommendations`, plan 11.2, 11.3, 14.1): list, drawer, preview, actions.

What this is
    Tests against the running app (`api_app`) with recommendations written to metrics.db by the engine's own writer
    (`insights.engine.write_recommendation`), request samples written as the recorder writes them, and every action
    sent through the real admin session, CSRF token and audited services.

Why it exists
    The page's promises (plan 11.3, P4): a recommendation is previewed with a validated diff and a replay of real
    samples, applied exactly as previewed through the audited services, undone exactly, snoozed and dismissed with
    a reason; security changes need a fresh second factor; and every number the drawer shows comes from the stored
    rows.

What to read next
    `roxy/admin/api/recommendations.py`, `roxy/insights/actions.py`, `roxy/insights/simulate.py`.
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import threading
from typing import Any

import pytest

from roxy.admin.api.common import ApiError
from roxy.admin.api.recommendations import (
    DRY_RUN_CACHE_ENTRIES,
    DRY_RUN_CACHE_S,
    DRY_RUN_QUEUE,
    DryRunGate,
    sensitive_targets,
)
from roxy.config.insight_params import INSIGHT_RULES
from roxy.core.ids import new_id
from roxy.insights import simulate
from roxy.insights.actions import AppliedChange
from roxy.insights.engine import RECOMMENDATION_EVENT, write_recommendation
from roxy.insights.models import Evidence, ProposedChange, Recommendation, changes_digest, make_fingerprint

BASE = "recommendations"
TEMPLATE = "games.roblox.com/v1/games"
BUCKET = f"endpoint:{TEMPLATE}"


def setting(key: str, current: Any, proposed: Any) -> ProposedChange:
    return ProposedChange("setting", key=key, current=current, proposed=proposed)


def bucket(per_min: int = 90) -> ProposedChange:
    return ProposedChange(
        "bucket_override",
        bucket_key=BUCKET,
        current={"per_min": 120, "burst": 10},
        proposed={"per_min": per_min, "burst": 10},
    )


def cache_rule(ttl: int = 300) -> ProposedChange:
    return ProposedChange(
        "rule_upsert",
        table="rules_cache",
        match={"pattern": TEMPLATE, "type": "glob"},
        current=None,
        proposed={"pattern": TEMPLATE, "type": "glob", "ttl": ttl, "stale_ttl": 60},
    )


async def seed(
    api_app: Any,
    *,
    rule_id: str = "UP-429-ENDPOINT",
    subject: str = TEMPLATE,
    severity: str = "warn",
    state: str = "open",
    changes: list[ProposedChange] | None = None,
    title: str | None = None,
) -> Recommendation:
    """One stored recommendation, written the way the engine writes it."""
    now = api_app.clock.now()
    spec = INSIGHT_RULES[rule_id]
    rec = Recommendation(
        rule_id=rule_id,
        family=spec.family,
        subject=subject,
        title=title or f"{rule_id} on {subject}",
        severity=severity,
        confidence="high",
        explanation="Plain-English explanation.",
        evidence=Evidence(window_from=now - 3600, window_to=now, sample_size=50).add("roblox_429", 50, "responses"),
        changes=list(changes if changes is not None else [setting("cache_ttl_seconds", 120, 150), bucket()]),
        expected_impact="About 1,900 fewer upstream calls per hour.",
        risk="low",
    )
    rec.id = new_id("rec", api_app.clock)
    rec.fingerprint = make_fingerprint(rule_id, subject)
    rec.computed_severity = severity
    rec.state = state
    rec.created_at = rec.updated_at = now
    rec.expires_at = now + 7 * 86_400
    rec.dry_run_available = simulate.can_simulate(rec)
    await api_app.ctx.dbs.metrics.write(lambda conn: write_recommendation(conn, rec))
    return rec


async def digest_of(api: Any, rec: Recommendation) -> str:
    response = await api.get(f"{BASE}/{rec.id}")
    assert response.status_code == 200, response.text
    digest: str = response.json()["changes_digest"]
    assert digest == changes_digest(rec.changes)
    return digest


def audit_reasons(api_app: Any, rec_id: str) -> list[str]:
    reasons: list[str] = api_app.ctx.dbs.control.read_sync(
        lambda c: [str(r[0]) for r in c.execute("SELECT reason FROM audit_log WHERE instr(reason, ?) > 0", (rec_id,))]
    )
    return reasons


def events(api_app: Any) -> list[dict[str, Any]]:
    rows = api_app.ctx.dbs.metrics.read_sync(
        lambda c: c.execute(
            "SELECT detail_json FROM events WHERE type = ? ORDER BY id", (RECOMMENDATION_EVENT,)
        ).fetchall()
    )
    return [json.loads(row[0]) for row in rows]


# ============================================================================================ guards


async def test_every_route_needs_a_session_and_writes_need_csrf(api: Any, anon_api: Any, api_app: Any) -> None:
    rec = await seed(api_app)
    reads = [BASE, f"{BASE}/history", f"{BASE}/rules", f"{BASE}/rules/UP-429-ENDPOINT", f"{BASE}/settings",
             f"{BASE}/{rec.id}", f"{BASE}/{rec.id}/history", f"{BASE}/{rec.id}/preview"]  # fmt: skip
    for path in reads:
        assert (await anon_api.get(path)).status_code == 401, path
    for action in ("apply", "undo", "snooze", "dismiss"):
        assert (await anon_api.post(f"{BASE}/{rec.id}/{action}", json={})).status_code == 401, action
        refused = await api.post(f"{BASE}/{rec.id}/{action}", json={}, csrf=False)
        assert refused.status_code == 403, (action, refused.text)
    assert (await api.get(f"{BASE}/{rec.id}")).json()["recommendation"]["state"] == "open"


# ============================================================================================ list


async def test_list_filters_counts_paging_and_export(api: Any, api_app: Any, api_json: Any, section13: Any) -> None:
    critical = await seed(api_app, severity="critical", subject="a.roblox.com/v1/x", title="=HYPERLINK(evil)")
    warn = await seed(api_app, rule_id="CACHE-LOW-HIT", subject="b.roblox.com/v1/y")
    await seed(api_app, rule_id="SYS-ERRORS", subject="sig-1", severity="info", state="snoozed")
    await seed(api_app, rule_id="UP-5XX", subject="c.roblox.com/v1/z", state="dismissed")

    body = api_json(await api.get(BASE))
    assert [item["id"] for item in body["items"]] == [critical.id, warn.id]  # open only, most severe first
    assert body["total"] == 2
    assert body["counts"]["open"] == 2
    assert body["counts"]["by_state"]["snoozed"] == 1
    assert body["counts"]["by_state"]["dismissed"] == 1
    assert body["counts"]["open_by_severity"] == {"info": 0, "warn": 1, "critical": 1}
    assert body["counts"]["open_by_family"]["cache"] == 1
    assert body["filters"]["state"] == ["open"]
    assert {column["key"] for column in body["columns"]} >= {"severity", "title", "rule_id", "state"}
    item = body["items"][0]
    assert item["url"] == f"/admin/api/v1/recommendations/{critical.id}"
    assert item["change_kinds"] == ["setting", "bucket_override"]
    assert isinstance(item["updated_at"], int)

    assert api_json(await api.get(BASE, params={"state": "all"}))["total"] == 4
    assert [i["id"] for i in api_json(await api.get(BASE, params={"family": "cache"}))["items"]] == [warn.id]
    assert [i["id"] for i in api_json(await api.get(BASE, params={"severity": "critical"}))["items"]] == [critical.id]
    snoozed = api_json(await api.get(BASE, params={"state": "snoozed,dismissed", "sort": "rule_id", "order": "asc"}))
    assert [i["rule_id"] for i in snoozed["items"]] == ["SYS-ERRORS", "UP-5XX"]
    assert api_json(await api.get(BASE, params={"q": "b.roblox", "state": "all"}))["total"] == 1
    paged = api_json(await api.get(BASE, params={"state": "all", "page_size": 10, "page": 2}))
    assert paged["items"] == []
    assert paged["total"] == 4

    fields = section13(await api.get(BASE, params={"state": "openish", "family": "nope"}), 422, "invalid_filter")
    assert set(fields) == {"state", "family"}
    section13(await api.get(BASE, params={"sort": "payload_json"}), 422, "invalid_table_query")

    exported = await api.get(BASE, params={"state": "all", "format": "csv"})
    assert exported.status_code == 200, exported.text
    rows = list(csv.reader(io.StringIO(exported.text)))
    assert rows[0][1] == "Severity"
    assert len(rows) == 5
    assert "'=HYPERLINK(evil)" in exported.text  # formula guard (plan 9.16)
    audited = api_app.ctx.dbs.control.read_sync(
        lambda c: c.execute("SELECT count(*) FROM audit_log WHERE target = 'table:recommendations'").fetchone()[0]
    )
    assert audited == 1


# ============================================================================================ detail


async def test_detail_shows_the_object_its_rule_and_what_can_be_done(
    api: Any, api_app: Any, api_json: Any, section13: Any
) -> None:
    rec = await seed(api_app, changes=[setting("cache_ttl_seconds", 120, 150), ProposedChange("manual", text="Fix it")])
    older = await seed(api_app, state="dismissed")
    body = api_json(await api.get(f"{BASE}/{rec.id}"))
    payload = body["recommendation"]
    assert {"id", "rule_id", "family", "severity", "confidence", "title", "explanation", "evidence", "changes",
            "expected_impact", "risk", "safe_auto", "dry_run", "created_at", "updated_at", "expires_at",
            "state"} <= set(payload)  # fmt: skip
    assert payload["evidence"]["metrics"] == [{"name": "roblox_429", "value": 50, "unit": "responses"}]
    assert payload["changes"][0] == {"kind": "setting", "key": "cache_ttl_seconds", "current": 120, "proposed": 150}
    assert body["changes_digest"] == changes_digest(rec.changes)
    assert body["allowed"]["apply"] == {"allowed": False, "why": "It needs a manual change; there is nothing to apply."}
    assert body["allowed"]["snooze"]["allowed"] is True
    assert body["allowed"]["undo"]["allowed"] is False
    assert body["rule"]["id"] == "UP-429-ENDPOINT"
    assert body["rule"]["settings"]["params"]["min_429s"] == "insight_up_429_endpoint_min_429s"
    assert body["rule"]["open"] == 1
    assert [item["id"] for item in body["earlier"]] == [older.id]  # the same fingerprint, dismissed before
    assert body["history"] == []
    assert body["watch"] is None
    assert body["links"]["preview"].endswith(f"/{rec.id}/preview")

    section13(await api.get(f"{BASE}/rec_01JUNKUNKNOWNID000000000000"), 404, "not_found")
    section13(await api.get(f"{BASE}/not-an-id"), 422, "validation_failed")
    manual = await api.post(f"{BASE}/{rec.id}/apply", json={"changes_digest": body["changes_digest"]})
    section13(manual, 422, "manual_change")


# ============================================================================================ preview


async def test_preview_validates_the_diff_and_replays_the_samples(api: Any, api_app: Any, api_json: Any) -> None:
    now_ms = api_app.clock.now_ms()
    samples = [
        (now_ms - 1_800_000 + i * 10_000, "key1", TEMPLATE, "GET", "client1", "12345", "MISS", 200, "direct", "body1",
         500, "anon")
        for i in range(20)
    ]  # fmt: skip
    await api_app.ctx.dbs.metrics.write(
        lambda conn: conn.executemany(
            "INSERT INTO request_samples (at_ms, key_id, endpoint_template, method, client_hash, place, cache_state, "
            "upstream_status, egress, body_hash, bytes, auth_class) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            samples,
        )
    )
    rec = await seed(api_app, changes=[cache_rule(300), setting("cache_ttl_seconds", 120, -5)])
    body = api_json(await api.get(f"{BASE}/{rec.id}/preview"))
    assert body["changes_digest"] == changes_digest(rec.changes)
    first, second = body["diff"]
    assert first["valid"] is True
    assert first["target"] == f"rules_cache:{TEMPLATE}"
    assert first["after"]["ttl"] == 300
    assert second["valid"] is False
    assert second["target"] == "setting:cache_ttl_seconds"
    assert body["ok"] is False
    report = body["dry_run"]
    # 20 requests 10 s apart on one key under a 300 s rule: one miss stores the entry, 19 hits (plan 11.3).
    assert report["available"] is True
    assert report["sample_size"] == 20
    assert report["avoided_calls"] == 19
    assert report["simulated_hit_ratio"] == 0.95
    assert report["staleness_risk"] == 0.0
    assert report["baseline_upstream_calls"] == 20
    assert report["cached"] is False
    again = api_json(await api.get(f"{BASE}/{rec.id}/preview"))
    assert again["dry_run"]["cached"] is True
    assert again["dry_run"]["avoided_calls"] == 19
    wide = api_json(await api.get(f"{BASE}/{rec.id}/preview", params={"window": "24h"}))
    assert wide["window"] == "24h"
    assert wide["dry_run"]["cached"] is False
    refused = await api.get(f"{BASE}/{rec.id}/preview", params={"window": "1y"})
    assert refused.status_code == 422
    invalid = await api.post(f"{BASE}/{rec.id}/apply", json={"changes_digest": body["changes_digest"]})
    assert invalid.status_code == 422, invalid.text
    error = invalid.json()["error"]
    assert error["code"] == "invalid_change"
    assert "setting:cache_ttl_seconds" in error["fields"]


# ============================================================================================ apply and undo


async def test_apply_then_undo_through_the_audited_services(
    api: Any, api_app: Any, api_json: Any, section13: Any
) -> None:
    rec = await seed(api_app, changes=[setting("cache_ttl_seconds", 120, 150), bucket(90), cache_rule(300)])
    digest = await digest_of(api, rec)
    json_type = {"Content-Type": "application/json"}
    section13(await api.post(f"{BASE}/{rec.id}/apply", content=b"not json", headers=json_type), 400, "invalid_json")
    section13(await api.post(f"{BASE}/{rec.id}/apply", content=b"", headers=json_type), 400, "missing_body")
    stale = await api.post(f"{BASE}/{rec.id}/apply", json={"changes_digest": "0" * 16})
    section13(stale, 409, "changed_since_preview")
    assert api_app.ctx.settings.int("cache_ttl_seconds") == 120  # nothing was applied

    applied = await api.post(f"{BASE}/{rec.id}/apply", json={"changes_digest": digest, "reason": "fewer calls"})
    assert applied.status_code == 200, applied.text
    body = applied.json()
    assert body["recommendation"]["state"] == "applied"
    assert body["action"] == "apply"
    assert [item["target"] for item in body["applied"]] == [
        "setting:cache_ttl_seconds",
        f"upstream_limits:{BUCKET}",
        f"rules_cache:{TEMPLATE}",
    ]
    assert body["watch"]["state"] == "watching"
    assert api_app.ctx.settings.int("cache_ttl_seconds") == 150
    reasons = audit_reasons(api_app, rec.id)
    assert len(reasons) == 3
    assert all(reason.startswith(f"recommendation:{rec.id}") for reason in reasons)
    limits = await api.get(f"upstream-limits/{BUCKET}")
    assert limits.status_code == 200
    assert limits.json()["per_min"] == 90
    assert limits.json()["origin"] == "recommendation"
    assert [event["action"] for event in events(api_app)][-1] == "apply"

    twice = await api.post(f"{BASE}/{rec.id}/apply", json={"changes_digest": digest})
    section13(twice, 409, "wrong_state")
    detail = api_json(await api.get(f"{BASE}/{rec.id}"))
    assert detail["allowed"]["undo"]["allowed"] is True
    assert [item["action"] for item in detail["history"]] == ["apply"]
    assert detail["history"][0]["summary"] == "3 changes: fewer calls"

    undone = await api.post(f"{BASE}/{rec.id}/undo", json={"reason": "testing undo"})
    assert undone.status_code == 200, undone.text
    assert undone.json()["recommendation"]["state"] == "rolled_back"
    assert api_app.ctx.settings.int("cache_ttl_seconds") == 120
    assert (await api.get(f"upstream-limits/{BUCKET}")).status_code == 404
    assert len(audit_reasons(api_app, rec.id)) == 6
    history = api_json(await api.get(f"{BASE}/{rec.id}/history"))
    assert [item["action"] for item in history["items"]] == ["undo", "apply"]
    section13(await api.post(f"{BASE}/{rec.id}/undo", json={}), 409, "wrong_state")


async def test_undo_refuses_a_change_made_since(api: Any, api_app: Any, section13: Any) -> None:
    rec = await seed(api_app, changes=[setting("cache_ttl_seconds", 120, 150)])
    digest = await digest_of(api, rec)
    assert (await api.post(f"{BASE}/{rec.id}/apply", json={"changes_digest": digest})).status_code == 200
    await api_app.settings(cache_ttl_seconds=200)
    section13(await api.post(f"{BASE}/{rec.id}/undo", json={}), 409, "superseded")
    assert api_app.ctx.settings.int("cache_ttl_seconds") == 200


async def test_a_high_risk_value_needs_the_confirmation_and_a_reason(api: Any, api_app: Any, section13: Any) -> None:
    rec = await seed(
        api_app, rule_id="EGR-BURN", subject="rotator", changes=[setting("rotator_hard_stop_pct", 100, 150)]
    )
    preview = (await api.get(f"{BASE}/{rec.id}/preview")).json()
    assert preview["requires"]["confirm_high_risk"] is True
    assert preview["requires"]["high_risk_keys"] == ["rotator_hard_stop_pct"]
    assert preview["dry_run"]["available"] is False
    digest = preview["changes_digest"]
    fields = section13(
        await api.post(f"{BASE}/{rec.id}/apply", json={"changes_digest": digest}), 422, "confirmation_required"
    )
    assert set(fields) == {"rotator_hard_stop_pct"}
    no_reason = await api.post(f"{BASE}/{rec.id}/apply", json={"changes_digest": digest, "confirm_high_risk": True})
    assert set(section13(no_reason, 422, "validation_failed")) == {"reason"}
    assert api_app.ctx.settings.int("rotator_hard_stop_pct") == 100
    done = await api.post(
        f"{BASE}/{rec.id}/apply",
        json={"changes_digest": digest, "confirm_high_risk": True, "reason": "planned overage"},
    )
    assert done.status_code == 200, done.text
    assert api_app.ctx.settings.int("rotator_hard_stop_pct") == 150


async def test_security_changes_need_a_fresh_second_factor(api: Any, api_app: Any, section13: Any) -> None:
    rec = await seed(
        api_app,
        rule_id="SEC-DEFAULTS",
        subject="sessions",
        changes=[setting("admin_session_idle_timeout_s", 900, 1800)],
    )
    preview = (await api.get(f"{BASE}/{rec.id}/preview")).json()
    assert preview["requires"]["fresh_mfa"] is True
    assert preview["requires"]["sensitive_targets"] == ["setting:admin_session_idle_timeout_s"]
    api.make_mfa_stale()
    stale = await api.post(f"{BASE}/{rec.id}/apply", json={"changes_digest": preview["changes_digest"]})
    section13(stale, 403, "reauth_required")
    assert stale.headers.get("roxy-reauth") == "required"
    assert api_app.ctx.settings.int("admin_session_idle_timeout_s") == 900
    await api.fresh_mfa()
    done = await api.post(f"{BASE}/{rec.id}/apply", json={"changes_digest": preview["changes_digest"]})
    assert done.status_code == 200, done.text
    assert api_app.ctx.settings.int("admin_session_idle_timeout_s") == 1800
    api.make_mfa_stale()
    section13(await api.post(f"{BASE}/{rec.id}/undo", json={}), 403, "reauth_required")  # the undo too
    await api.fresh_mfa()
    assert (await api.post(f"{BASE}/{rec.id}/undo", json={})).status_code == 200
    assert api_app.ctx.settings.int("admin_session_idle_timeout_s") == 900


# ============================================================================================ snooze and dismiss


async def test_snooze_and_dismiss_with_a_reason(api: Any, api_app: Any, api_json: Any, section13: Any) -> None:
    first = await seed(api_app)
    second = await seed(api_app, subject="games.roblox.com/v1/other")
    snoozed = await api.post(f"{BASE}/{first.id}/snooze", json={"duration": "1h"})
    assert snoozed.status_code == 200, snoozed.text
    card = snoozed.json()["recommendation"]
    assert card["state"] == "snoozed"
    assert card["snoozed_until"] == int(api_app.clock.now()) + 3600
    section13(await api.post(f"{BASE}/{first.id}/snooze", json={}), 422, "validation_failed")
    both = await api.post(f"{BASE}/{first.id}/snooze", json={"duration": "1d", "until": "2030-01-01T00:00:00Z"})
    section13(both, 422, "validation_failed")
    section13(await api.post(f"{BASE}/{first.id}/snooze", json={"duration": "1y"}), 422, "validation_failed")
    section13(await api.post(f"{BASE}/{first.id}/snooze", json={"until": 1}), 422, "validation_failed")
    later = int(api_app.clock.now()) + 7200
    until = await api.post(f"{BASE}/{first.id}/snooze", json={"until": later})
    assert until.status_code == 200
    assert until.json()["recommendation"]["snoozed_until"] == later

    other = await api.post(f"{BASE}/{second.id}/dismiss", json={"reason": "other"})
    assert set(section13(other, 422, "invalid_change")) == {"text"}
    section13(await api.post(f"{BASE}/{second.id}/dismiss", json={"reason": "meh"}), 422, "validation_failed")
    extra = await api.post(f"{BASE}/{second.id}/dismiss", json={"reason": "not_accurate", "admin": True})
    section13(extra, 422, "validation_failed")
    dismissed = await api.post(f"{BASE}/{second.id}/dismiss", json={"reason": "not_accurate", "text": "wrong host"})
    assert dismissed.status_code == 200, dismissed.text
    body = dismissed.json()
    assert body["recommendation"]["state"] == "dismissed"
    assert body["recommendation"]["dismissed_reason"] == "not_accurate: wrong host"
    cooldown = api_app.ctx.settings.int("dismiss_cooldown_days")
    assert body["quiet_until"] == int(api_app.clock.now()) + cooldown * 86_400
    section13(await api.post(f"{BASE}/{second.id}/dismiss", json={"reason": "other", "text": "x"}), 409, "wrong_state")
    actions = [event["action"] for event in events(api_app)]
    assert actions == ["snoozed", "snoozed", "dismissed"]
    history = api_json(await api.get(f"{BASE}/history"))
    assert [(item["action"], item["recommendation_id"]) for item in history["items"]] == [
        ("dismiss", second.id),
        ("snooze", first.id),
        ("snooze", first.id),
    ]
    assert history["items"][0]["summary"] == "not_accurate: wrong host"
    assert history["items"][0]["title"] == second.title
    only = api_json(await api.get(f"{BASE}/history", params={"action": "dismiss"}))
    assert only["total"] == 1
    section13(await api.get(f"{BASE}/history", params={"action": "explode"}), 422, "invalid_filter")
    exported = await api.get(f"{BASE}/history", params={"format": "json"})
    assert exported.status_code == 200
    assert json.loads(exported.content)["total"] == 3


# ============================================================================================ tuning


async def test_the_tuning_view_lists_every_rule_with_its_settings(
    api: Any, api_app: Any, api_json: Any, section13: Any
) -> None:
    await seed(api_app)
    body = api_json(await api.get(f"{BASE}/rules", params={"page_size": 100}))
    assert body["total"] == len(INSIGHT_RULES)
    assert [item["id"] for item in body["items"]] == list(INSIGHT_RULES)  # plan 11.5 order
    first = body["items"][0]
    assert first["id"] == "UP-429-ENDPOINT"
    assert first["open"] == 1
    assert first["implemented"] is True
    assert first["help"]
    params = {param["name"]: param for param in first["params"]}
    assert params["min_429s"]["value"] == 20
    assert params["min_429s"]["key"] == "insight_up_429_endpoint_min_429s"
    cache_only = api_json(await api.get(f"{BASE}/rules", params={"family": "cache"}))
    assert cache_only["total"] == sum(1 for spec in INSIGHT_RULES.values() if spec.family == "cache")

    changed = await api.put("settings/insight_up_429_endpoint_min_429s", json={"value": 30, "reason": "fewer cards"})
    assert changed.status_code == 200, changed.text
    drawer = api_json(await api.get(f"{BASE}/rules/up_429_endpoint"))
    keys = [entry["key"] for entry in drawer["settings"]]
    assert keys[:2] == ["insight_up_429_endpoint_enabled", "insight_up_429_endpoint_severity"]
    entry = next(e for e in drawer["settings"] if e["key"] == "insight_up_429_endpoint_min_429s")
    assert entry["value"] == 30
    assert entry["changed"] is True
    assert entry["last_change"]["reason"] == "fewer cards"
    assert drawer["rule"]["params"][0]["value"] == 30
    assert drawer["active"]["total"] == 1
    assert drawer["save"]["url"] == "/admin/api/v1/settings"
    section13(await api.get(f"{BASE}/rules/NOT-A-RULE"), 404, "not_found")

    engine = api_json(await api.get(f"{BASE}/settings"))
    assert "insights_enabled" in [e["key"] for e in engine["engine"]]
    assert [e["key"] for e in engine["preview"]] == [
        "request_sample_pct",
        "request_sample_hours",
        "request_sample_max_rows",
    ]


@pytest.mark.parametrize("state", ["applied", "resolved", "expired"])
async def test_closed_recommendations_cannot_be_acted_on(api: Any, api_app: Any, section13: Any, state: str) -> None:
    rec = await seed(api_app, state=state)
    digest = changes_digest(rec.changes)
    section13(await api.post(f"{BASE}/{rec.id}/apply", json={"changes_digest": digest}), 409, "wrong_state")
    section13(await api.post(f"{BASE}/{rec.id}/snooze", json={"duration": "1h"}), 409, "wrong_state")
    section13(await api.post(f"{BASE}/{rec.id}/dismiss", json={"reason": "not_accurate"}), 409, "wrong_state")


async def test_a_recommendation_without_changes_has_nothing_to_apply(api: Any, api_app: Any, section13: Any) -> None:
    rec = await seed(api_app, rule_id="SYS-DISK", subject="disk", changes=[])
    detail = (await api.get(f"{BASE}/{rec.id}")).json()
    assert detail["allowed"]["apply"] == {"allowed": False, "why": "It proposes no change."}
    refused = await api.post(f"{BASE}/{rec.id}/apply", json={"changes_digest": detail["changes_digest"]})
    section13(refused, 422, "nothing_to_apply")
    assert (await api.get(f"{BASE}/{rec.id}")).json()["recommendation"]["state"] == "open"


# ============================================================================================ dry-run bounds


async def test_dry_runs_are_bounded_per_worker() -> None:
    gate = DryRunGate()
    release = threading.Event()
    started = threading.Event()

    def slow() -> dict[str, Any]:
        started.set()
        release.wait(10)
        return {"available": True}

    first = asyncio.ensure_future(gate.run(slow))
    await asyncio.to_thread(started.wait, 10)
    queued = [asyncio.ensure_future(gate.run(lambda: {"available": True})) for _ in range(DRY_RUN_QUEUE)]
    await asyncio.sleep(0)
    assert gate.waiting == DRY_RUN_QUEUE
    with pytest.raises(ApiError) as refused:
        await gate.run(lambda: {"available": True})
    assert refused.value.status_code == 429
    assert refused.value.error_code == "rate_limited"
    first.cancel()  # the request went away; its thread still holds the slot until it finishes
    await asyncio.sleep(0.05)
    assert not any(task.done() for task in queued)
    release.set()
    assert [await task for task in queued] == [{"available": True}] * DRY_RUN_QUEUE
    assert gate.waiting == 0

    for index in range(DRY_RUN_CACHE_ENTRIES + 5):
        gate.keep(("rec", index), 100.0, {"n": index})
    assert len(gate.cache) == DRY_RUN_CACHE_ENTRIES
    assert gate.cached(("rec", 0), 100.0) is None  # the oldest went first
    newest = ("rec", DRY_RUN_CACHE_ENTRIES + 4)
    assert gate.cached(newest, 100.0 + DRY_RUN_CACHE_S) == {"n": DRY_RUN_CACHE_ENTRIES + 4}
    assert gate.cached(newest, 100.0 + DRY_RUN_CACHE_S + 1) is None


def test_fresh_mfa_follows_the_direction_of_the_write() -> None:
    row = {"id": 3, "pattern": "users.roblox.com/v1/users/*", "type": "glob"}
    removal = AppliedChange("credential_allowlist_remove", "credential_allowlist:users", "credential_allowlist", 3, row)
    assert sensitive_targets([removal]) == []  # narrowing what the credential is used for
    assert sensitive_targets([removal], undo=True) == [removal.target]  # undoing it creates the row again
    admin_net = AppliedChange(
        "bypass_add", "access_list:198.51.100.0/24", "access_list", 4, None, {"kind": "allow_admin"}
    )
    bypass = AppliedChange("bypass_add", "access_list:198.51.100.7/32", "access_list", 5, None, {"kind": "bypass"})
    assert sensitive_targets([admin_net, bypass]) == [admin_net.target]
    assert sensitive_targets([admin_net], undo=True) == [admin_net.target]
    security = AppliedChange("setting", "setting:admin_reauth_window_s", None, "admin_reauth_window_s", 600, 300)
    cache = AppliedChange("setting", "setting:cache_ttl_seconds", None, "cache_ttl_seconds", 120, 150)
    assert sensitive_targets([security, cache]) == [security.target]
