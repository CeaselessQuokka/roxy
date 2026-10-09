"""The settings editor API and the per-admin preferences API in the real app (plan 15.2, 6.2 `admin_prefs`).

Settings: the catalog listing with groups, search and every filter, the server-side diff preview, batch updates of
only the dirty keys with a reason, the high-risk confirmation, history per key and global (paging, filters,
export), one-click revert, reset to default, export and import with a diff. Preferences: defaults, JSON and form
updates, validation, bounds and forgetting. Every write goes through the real `SettingsService`, so each test also
checks the audit rows and `config_version` it leaves.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from roxy.admin.api import prefs as prefs_api
from roxy.config import catalog

API = "/admin/api/v1"


async def _control(api_app: Any, sql: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    return await api_app.ctx.dbs.control.read(lambda conn: [tuple(r) for r in conn.execute(sql, params).fetchall()])


async def _config_version(api_app: Any) -> int:
    rows = await _control(api_app, "SELECT value_json FROM service_state WHERE key = 'config_version'")
    return int(json.loads(rows[0][0]))


# ================================================================================================ listing


async def test_listing_has_every_setting_grouped_with_values_and_metadata(api: Any, api_json: Any) -> None:
    body = api_json(await api.get("settings"))
    assert body["total"] == len(catalog.CATALOG) == body["count"]
    assert body["catalog_version"] == catalog.CATALOG_VERSION
    keys = [entry["key"] for group in body["groups"] for entry in group["settings"]]
    assert sorted(keys) == sorted(catalog.CATALOG)
    group_ids = [group["id"] for group in body["groups"]]
    assert group_ids == [g.value for g in catalog.GROUPED]  # Settings page order
    entry = next(e for g in body["groups"] for e in g["settings"] if e["key"] == "cache_ttl_seconds")
    assert entry["value"] == entry["default"] == 120
    assert entry["overridden"] is False
    assert entry["changed"] is False
    assert entry["if_raised"]
    assert entry["description"]
    assert entry["pages"]
    assert entry["open_recommendations"] == []
    # The test app turned the tarpit off through the service: the listing shows who changed it last and why.
    tarpit = next(e for g in body["groups"] for e in g["settings"] if e["key"] == "tarpit_enabled")
    assert tarpit["overridden"] is True
    assert tarpit["value"] == 0
    assert tarpit["last_change"]["changed_by"] == "cli:test"
    assert tarpit["last_change"]["reason"] == "admin api test setup"
    assert tarpit["last_change"]["revert_url"].endswith(f"/settings/history/{tarpit['last_change']['id']}/revert")
    assert body["changed_count"] >= 2
    assert body["cross_field_rules"]


async def test_search_and_filters(api: Any, api_app: Any, api_json: Any, section13: Any) -> None:
    found = api_json(await api.get("settings", params={"q": "tarpit"}))
    assert found["count"] > 0
    assert found["ranked_keys"][0].startswith("tarpit")
    for group in found["groups"]:
        for entry in group["settings"]:
            text = " ".join([entry["key"], entry["label"], entry["description"]]).lower()
            assert "tarpit" in text
    alias = api_json(await api.get("settings", params={"q": "autosave_interval"}))
    assert [e["key"] for g in alias["groups"] for e in g["settings"]] == ["metrics_flush_interval_ms"]
    cache_only = api_json(await api.get("settings", params={"group": "cache"}))
    assert [g["id"] for g in cache_only["groups"]] == ["cache"]
    high = api_json(await api.get("settings", params={"risk": "high"}))
    assert {e["risk"] for g in high["groups"] for e in g["settings"]} == {"high"}
    changed = api_json(await api.get("settings", params={"changed": "true"}))
    assert {e["key"] for g in changed["groups"] for e in g["settings"]} >= {"tarpit_enabled", "rotator_enabled"}
    assert all(e["overridden"] for g in changed["groups"] for e in g["settings"])
    compact = api_json(await api.get("settings", params={"include_text": "false", "q": "cache_ttl_seconds"}))
    first = compact["groups"][0]["settings"][0]
    assert "description" not in first
    assert "if_raised" not in first
    fields = section13(await api.get("settings", params={"group": "nope", "risk": "extreme"}), 422, "validation_failed")
    assert set(fields) == {"group", "risk"}


async def test_has_open_recommendation_filter_links_the_recommendation(api: Any, api_app: Any, api_json: Any) -> None:
    payload = {"changes": [{"kind": "setting", "key": "cache_ttl_seconds", "proposed": 300}]}
    now = int(api_app.clock.now())

    def insert(conn: Any) -> None:
        for rec_id, state in (("rec_open", "open"), ("rec_closed", "dismissed")):
            conn.execute(
                "INSERT INTO recommendations (id, rule_id, fingerprint, state, severity, payload_json, created_at, "
                "updated_at) VALUES (?, 'CACHE-TTL-TUNE', ?, ?, 'info', ?, ?, ?)",
                (rec_id, rec_id, state, json.dumps(payload), now, now),
            )

    await api_app.ctx.dbs.metrics.write(insert)
    body = api_json(await api.get("settings", params={"has_recommendation": "1"}))
    entries = [e for g in body["groups"] for e in g["settings"]]
    assert [e["key"] for e in entries] == ["cache_ttl_seconds"]
    assert [r["id"] for r in entries[0]["open_recommendations"]] == ["rec_open"]
    assert body["with_recommendation_count"] == 1


async def test_values_map(api: Any, api_app: Any, api_json: Any) -> None:
    body = api_json(await api.get("settings/values"))
    assert set(body["values"]) == set(catalog.CATALOG)
    assert body["values"]["tarpit_enabled"] == 0
    assert "tarpit_enabled" in body["overridden"]
    assert body["config_version"] == api_app.ctx.settings.version


# ================================================================================================ preview


async def test_preview_shows_the_diff_consequences_risk_and_cross_rules(api: Any, api_app: Any, api_json: Any) -> None:
    before = await _config_version(api_app)
    body = api_json(
        await api.post(
            "settings/preview",
            json={
                "changes": {
                    "cache_ttl_seconds": "5m",
                    "capture_enabled": 0,
                    "ui_default_theme": "light",
                    "public_cors_allow_any_origin": 1,
                    "tarpit_min_seconds": 30,
                    "allowed_requests_per_minute": 10,
                    "retention_minute_days": 500,
                    "no_such_setting": 1,
                }
            },
        )
    )
    items = {item["key"]: item for item in body["items"]}
    ttl = items["cache_ttl_seconds"]
    assert ttl["status"] == "change"
    assert ttl["current"] == 120
    assert ttl["new"] == 300
    assert ttl["direction"] == "raised"
    assert ttl["consequence"] == catalog.CATALOG["cache_ttl_seconds"].if_raised
    assert ttl["needs_reason"] is False
    capture = items["capture_enabled"]
    assert capture["direction"] == "disabled"
    assert capture["consequence"] == catalog.CATALOG["capture_enabled"].if_disabled
    theme = items["ui_default_theme"]
    light = next(o for o in catalog.CATALOG["ui_default_theme"].options if o.value == "light")
    assert theme["consequence"] == light.description
    cors = items["public_cors_allow_any_origin"]
    assert cors["needs_reason"] is True
    assert cors["high_risk_reason"]
    assert items["allowed_requests_per_minute"]["status"] == "unchanged"
    assert items["retention_minute_days"]["status"] == "invalid"
    assert items["retention_minute_days"]["message"]
    assert items["no_such_setting"]["status"] == "unknown"
    assert any("tarpit_min_seconds" in issue["keys"] for issue in body["cross"])
    assert body["ok"] is False
    assert body["reason_required"] is True
    assert body["confirm_required"] is True
    assert body["high_risk_keys"] == ["public_cors_allow_any_origin"]
    assert body["changes"] == 5
    assert await _config_version(api_app) == before  # nothing written


# ================================================================================================ writes


async def test_batch_update_saves_only_dirty_keys_with_history_audit_and_version(
    api: Any, api_app: Any, api_json: Any
) -> None:
    before = await _config_version(api_app)
    response = await api.patch(
        "settings",
        json={"changes": {"cache_ttl_seconds": 300, "allowed_requests_per_minute": 10}, "reason": "warmer cache"},
    )
    body = api_json(response)
    assert [c["key"] for c in body["changed"]] == ["cache_ttl_seconds"]
    assert body["unchanged"] == ["allowed_requests_per_minute"]
    change = body["changed"][0]
    assert change["old"] == 120
    assert change["new"] == 300
    assert change["overridden"] is True
    assert body["config_version"] == before + 1 == await _config_version(api_app)
    history = await _control(
        api_app, "SELECT key, new_json, reason, source FROM settings_history WHERE id = ?", (change["history_id"],)
    )
    assert history == [("cache_ttl_seconds", "300", "warmer cache", "admin")]
    audit_rows = await _control(
        api_app, "SELECT action, target, actor, reason FROM audit_log WHERE id = ?", (change["audit_id"],)
    )
    assert audit_rows == [
        ("setting.update", "setting:cache_ttl_seconds", f"admin:{api.admin.username}", "warmer cache")
    ]
    assert api_app.ctx.settings.get("cache_ttl_seconds") == 300  # this worker reloaded at once
    one = api_json(await api.get("settings/cache_ttl_seconds"))
    assert one["setting"]["value"] == 300
    assert one["setting"]["overridden"] is True
    assert one["setting"]["last_change"]["reason"] == "warmer cache"
    assert one["history"][0]["new_effective"] == 300
    assert one["history"][0]["old_effective"] == 120
    # Saving the same values again writes nothing.
    again = api_json(await api.patch("settings", json={"changes": {"cache_ttl_seconds": 300}, "reason": ""}))
    assert again["changed"] == []
    assert again["unchanged"] == ["cache_ttl_seconds"]
    assert await _config_version(api_app) == before + 1


async def test_high_risk_changes_need_confirmation_and_a_reason(api: Any, api_app: Any, section13: Any) -> None:
    change = {"public_cors_allow_any_origin": 1}
    fields = section13(await api.patch("settings", json={"changes": change}), 422, "confirmation_required")
    assert set(fields) == {"public_cors_allow_any_origin"}
    fields = section13(
        await api.patch("settings", json={"changes": change, "confirm_high_risk": True}), 422, "validation_failed"
    )
    assert set(fields) == {"reason"}
    response = await api.patch(
        "settings", json={"changes": change, "confirm_high_risk": True, "reason": "browser game test"}
    )
    assert response.status_code == 200, response.text
    assert api_app.ctx.settings.get("public_cors_allow_any_origin") == 1


async def test_invalid_values_refuse_the_whole_batch(api: Any, api_app: Any, section13: Any) -> None:
    count = (await _control(api_app, "SELECT count(*) FROM settings_history"))[0][0]
    fields = section13(
        await api.patch("settings", json={"changes": {"cache_ttl_seconds": 600, "retention_minute_days": 0}}),
        422,
        "invalid_settings",
    )
    assert "retention_minute_days" in fields
    fields = section13(
        await api.patch("settings", json={"changes": {"tarpit_min_seconds": 30}}), 422, "invalid_settings"
    )
    assert "tarpit_min_seconds" in fields  # the cross-field rule names the key
    assert (await _control(api_app, "SELECT count(*) FROM settings_history"))[0][0] == count
    fields = section13(
        await api.patch("settings", json={"changes": {"cache_ttl_seconds": 600}, "reason": "a " + chr(0x2014) + " b"}),
        422,
        "invalid_settings",
    )
    assert "reason" in fields  # dash characters are refused (plan C5)


async def test_put_one_key_and_reset_it_to_default(api: Any, api_app: Any, api_json: Any, section13: Any) -> None:
    body = api_json(await api.put("settings/stale_ip_duration", json={"value": "2m", "reason": "longer memory"}))
    assert body["changed"][0]["new"] == 120
    alias = api_json(await api.put("settings/autosave_interval", json={"value": 5000}))  # a v1 key still works
    assert alias["changed"][0]["key"] == "metrics_flush_interval_ms"
    reset = api_json(await api.post("settings/stale_ip_duration/reset", json={"reason": "back"}))
    assert reset["changed"][0]["new"] == 60
    assert reset["changed"][0]["overridden"] is False
    rows = await _control(
        api_app, "SELECT action FROM audit_log WHERE target = 'setting:stale_ip_duration' ORDER BY id"
    )
    assert [row[0] for row in rows] == ["setting.update", "setting.reset"]
    section13(await api.put("settings/no_such_key", json={"value": 1}), 404, "not_found")
    section13(await api.get("settings/Bad-Key"), 422, "validation_failed")
    section13(await api.put("settings/stale_ip_duration", json={"reason": "x"}), 422, "validation_failed")
    section13(await api.post("settings/stale_ip_duration/reset"), 400, "missing_body")


# ================================================================================================ history


async def test_history_global_and_per_key_with_paging_filters_and_export(api: Any, api_app: Any, api_json: Any) -> None:
    for seconds in (130, 140, 150):
        await api.patch("settings", json={"changes": {"cache_ttl_seconds": seconds}, "reason": f"ttl {seconds}"})
    await api.patch("settings", json={"changes": {"stale_ip_duration": 90}, "reason": "memory"})
    page = api_json(await api.get("settings/history", params={"page_size": 10}))
    assert page["total"] >= 6
    assert page["page_size"] == 10
    ids = [item["id"] for item in page["items"]]
    assert ids == sorted(ids, reverse=True)
    assert page["items"][0]["key"] == "stale_ip_duration"
    assert {s["source"] for s in page["sources"]} >= {"admin"}
    by_key = api_json(await api.get("settings/history", params={"key": "cache_ttl_seconds", "order": "asc"}))
    assert [item["new"] for item in by_key["items"]] == [130, 140, 150]
    searched = api_json(await api.get("settings/history", params={"q": "TTL 14"}))
    assert [item["new"] for item in searched["items"]] == [140]
    actor = api_json(await api.get("settings/history", params={"actor": "cli:test"}))
    assert {item["key"] for item in actor["items"]} == {"tarpit_enabled", "rotator_enabled"}
    per_key = api_json(await api.get("settings/cache_ttl_seconds/history", params={"page_size": 10}))
    assert per_key["total"] == 3
    assert all(item["revertible"] for item in per_key["items"])
    later = int(api_app.clock.now()) + 1
    assert api_json(await api.get("settings/history", params={"from": str(later)}))["total"] == 0
    exported = await api.get("settings/history", params={"format": "csv", "key": "cache_ttl_seconds"})
    assert exported.status_code == 200
    assert exported.headers["content-type"].startswith("text/csv")
    rows = list(csv.reader(io.StringIO(exported.text)))
    assert rows[0][:3] == ["Change", "When", "Setting"]
    assert len(rows) == 4
    audits = await _control(api_app, "SELECT target FROM audit_log WHERE action = 'export.download'")
    assert ("table:settings_history",) in audits
    bad = await api.get("settings/history", params={"sort": "reason"})
    assert bad.status_code == 422


async def test_revert_restores_the_earlier_value_and_is_audited(
    api: Any, api_app: Any, api_json: Any, section13: Any
) -> None:
    first = api_json(await api.patch("settings", json={"changes": {"cache_ttl_seconds": 200}, "reason": "a"}))
    api_json(await api.patch("settings", json={"changes": {"cache_ttl_seconds": 250}, "reason": "b"}))
    history_id = first["changed"][0]["history_id"]
    reverted = api_json(await api.post(f"settings/history/{history_id}/revert", json={"reason": "undo"}))
    assert reverted["reverted"] == history_id
    assert reverted["changed"][0]["new"] == 120
    assert reverted["changed"][0]["overridden"] is False
    assert any("changed again" in warning for warning in reverted["warnings"])
    assert api_app.ctx.settings.get("cache_ttl_seconds") == 120
    rows = await _control(api_app, "SELECT source FROM settings_history ORDER BY id DESC LIMIT 1")
    assert rows == [("revert",)]
    section13(await api.post("settings/history/999999/revert", json={}), 404, "not_found")


async def test_revert_to_a_high_risk_value_needs_confirmation(api: Any, section13: Any, api_json: Any) -> None:
    change = {"public_cors_allow_any_origin": 1}
    api_json(await api.patch("settings", json={"changes": change, "confirm_high_risk": True, "reason": "on"}))
    # Every change of a high-risk setting needs the confirmation and a reason, turning it off included.
    off_change = {"changes": {"public_cors_allow_any_origin": 0}, "reason": "off"}
    section13(await api.patch("settings", json=off_change), 422, "confirmation_required")
    off = api_json(await api.patch("settings", json={**off_change, "confirm_high_risk": True}))
    history_id = off["changed"][0]["history_id"]  # its "before" is the high-risk value 1
    section13(await api.post(f"settings/history/{history_id}/revert", json={}), 422, "confirmation_required")
    done = await api.post(
        f"settings/history/{history_id}/revert", json={"confirm_high_risk": True, "reason": "on again"}
    )
    assert done.status_code == 200, done.text


# ================================================================================================ export and import


async def test_export_and_import_with_a_diff(api: Any, api_app: Any, api_json: Any, section13: Any) -> None:
    api_json(await api.patch("settings", json={"changes": {"cache_ttl_seconds": 600}, "reason": "export me"}))
    exported = await api.get("settings/export")
    assert exported.status_code == 200
    assert exported.headers["content-disposition"].startswith('attachment; filename="roxy_settings_')
    assert exported.headers["cache-control"] == "no-store"
    document = exported.json()
    assert document["schema"] == "roxy.settings_overrides/1"
    assert document["catalog_version"] == catalog.CATALOG_VERSION
    assert document["overrides"]["cache_ttl_seconds"] == 600
    audits = await _control(api_app, "SELECT target, after_json FROM audit_log WHERE action = 'export.download'")
    assert any(target == "settings:overrides" for target, _after in audits)
    api_json(await api.patch("settings", json={"changes": {"cache_ttl_seconds": 30}, "reason": "drift"}))
    preview = api_json(await api.post("settings/import/preview", json={"document": document}))
    items = {item["key"]: item for item in preview["items"]}
    assert items["cache_ttl_seconds"] == {**items["cache_ttl_seconds"], "status": "change", "current": 30, "new": 600}
    assert preview["ok"] is True
    assert preview["catalog_version_matches"] is True
    applied = api_json(await api.post("settings/import", json={"document": document, "reason": "restore"}))
    assert "cache_ttl_seconds" in [c["key"] for c in applied["changed"]]
    assert api_app.ctx.settings.get("cache_ttl_seconds") == 600
    rows = await _control(api_app, "SELECT action FROM audit_log ORDER BY id DESC LIMIT 1")
    assert rows == [("settings.import",)]
    broken = {"schema": "roxy.settings_overrides/1", "overrides": {"no_such_key": 1, "cache_ttl_seconds": -5}}
    bad_preview = api_json(await api.post("settings/import/preview", json={"document": broken}))
    assert bad_preview["ok"] is False
    assert {i["status"] for i in bad_preview["items"]} == {"unknown", "invalid"}
    fields = section13(
        await api.post("settings/import", json={"document": broken, "reason": "x"}), 422, "invalid_settings"
    )
    assert set(fields) == {"no_such_key", "cache_ttl_seconds"}
    no_reason = section13(await api.post("settings/import", json={"document": document}), 422, "validation_failed")
    assert set(no_reason) == {"reason"}
    risky = {"overrides": {"public_cors_allow_any_origin": 1}}
    section13(await api.post("settings/import", json={"document": risky}), 422, "confirmation_required")


# ================================================================================================ guards


async def test_guards_come_before_body_errors(anon_api: Any, api: Any, section13: Any) -> None:
    assert (await anon_api.get("settings")).status_code == 401
    assert (await anon_api.patch("settings", json={"changes": {"cache_ttl_seconds": 1}})).status_code == 401
    assert (await api.patch("settings", json={"changes": {"cache_ttl_seconds": 1}}, csrf=False)).status_code == 403
    section13(
        await api.patch("settings", content=b"not json", headers={"Content-Type": "application/json"}),
        400,
        "invalid_json",
    )
    section13(await api.patch("settings", json=[1, 2]), 400, "invalid_body")
    fields = section13(await api.patch("settings", json={"changes": {"a": 1}, "extra": 1}), 422, "validation_failed")
    assert "extra" in fields
    section13(await api.patch("settings", json={"changes": {}}), 422, "validation_failed")


# ================================================================================================ preferences


async def test_prefs_defaults_follow_the_dashboard_settings(api: Any, api_app: Any, api_json: Any) -> None:
    body = api_json(await api.get("prefs"))
    assert body["prefs"]["theme"] == "dark"
    assert body["prefs"]["density"] == "comfortable"
    assert body["prefs"]["shortcuts"] == "on"
    assert body["prefs"]["tables"] == {}
    assert body["stored"] == []
    assert body["ui_timezone"] == api_app.ctx.settings.get("ui_timezone")
    await api_app.settings(ui_default_theme="light")
    assert api_json(await api.get("prefs"))["prefs"]["theme"] == "light"


async def test_prefs_json_and_form_updates_are_validated_and_stored_per_admin(
    api: Any, api_app: Any, api_json: Any, section13: Any
) -> None:
    body = api_json(
        await api.post(
            "prefs",
            json={
                "theme": "system",
                "density": "dense",
                "shortcuts": "off",
                "timezone": "Europe/Paris",
                "default_range": "7d",
                "compare": "week",
                "live_filters": {"outcome": "refused", "client": " 203.0.113.9 "},
                "tables": {"audit_log": {"page_size": 50, "hidden": ["actor_ip", "actor_ip"]}},
                "panels": {"overview.how-to-read": True},
            },
        )
    )
    prefs = body["prefs"]
    assert prefs["theme"] == "system"
    assert prefs["density"] == "dense"
    assert prefs["shortcuts"] == "off"
    assert prefs["timezone"] == "Europe/Paris"
    assert prefs["default_range"] == "7d"
    assert prefs["compare"] == "week"
    assert prefs["live_filters"] == {"outcome": "refused", "client": "203.0.113.9"}
    assert prefs["tables"] == {"audit_log": {"page_size": 50, "hidden": ["actor_ip"]}}
    assert prefs["panels"] == {"overview.how-to-read": True}
    # theme.js posts form fields with the CSRF header.
    form = await api.post(
        "prefs", content=b"theme=light", headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert api_json(form)["prefs"]["theme"] == "light"
    rows = await _control(api_app, "SELECT DISTINCT user_id FROM admin_prefs")
    assert rows == [(api.admin.id,)]
    fields = section13(
        await api.post("prefs", json={"theme": "pink", "timezone": "Mars/Base"}), 422, "validation_failed"
    )
    assert set(fields) == {"theme", "timezone"}
    section13(await api.post("prefs", json={"wallpaper": "x"}), 422, "validation_failed")
    section13(await api.post("prefs", json={"tables": {"Bad Id": None}}), 422, "validation_failed")
    section13(await api.post("prefs", json={"tables": {"t": {"page_size": 7}}}), 422, "validation_failed")
    section13(await api.post("prefs", content=b"", headers={"Content-Type": "application/json"}), 400, "missing_body")
    section13(await api.post("prefs", json=["theme"]), 400, "invalid_body")
    section13(
        await api.post("prefs", content=b"tables=x", headers={"Content-Type": "application/x-www-form-urlencoded"}),
        422,
        "validation_failed",
    )
    assert (await api.post("prefs", json={"theme": "dark"}, csrf=False)).status_code == 403


async def test_prefs_forget_one_group_or_all_and_stay_bounded(api: Any, api_app: Any, api_json: Any) -> None:
    api_json(await api.post("prefs", json={"theme": "light", "panels": {"a": True, "b": False}}))
    forgot = api_json(await api.delete("prefs/theme"))
    assert forgot["prefs"]["theme"] == "dark"
    assert forgot["removed"] == 1
    forgot = api_json(await api.delete("prefs/panels"))
    assert forgot["prefs"]["panels"] == {}
    assert forgot["removed"] == 2
    assert (await api.delete("prefs/nonsense")).status_code == 404
    many = {f"table{n:03d}": {"page_size": 25} for n in range(prefs_api.MAX_TABLES)}
    api_json(await api.post("prefs", json={"tables": many}))
    api_app.clock.advance(5)
    body = api_json(await api.post("prefs", json={"tables": {"newest": {"page_size": 100}}}))
    assert len(body["prefs"]["tables"]) == prefs_api.MAX_TABLES
    assert body["prefs"]["tables"]["newest"] == {"page_size": 100, "hidden": []}
    cleared = api_json(await api.delete("prefs"))
    assert cleared["stored"] == []
    assert cleared["removed"] == prefs_api.MAX_TABLES
