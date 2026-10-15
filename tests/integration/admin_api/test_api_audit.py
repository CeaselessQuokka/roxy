"""The audit log API in the real app (plan 9.7, 14.1): search, filters, paging, the diff view, revert links and
exports (formula guard and IP hashing), over rows written by the real services."""

from __future__ import annotations

import csv
import io
from typing import Any

from roxy.config import audit
from roxy.config.audit import Actor
from roxy.core.iphash import ip_hash
from roxy.rules.service import RulesService


async def _record(api_app: Any, actor: Actor, action: str, target: str, before: Any, after: Any, reason: str) -> int:
    at = int(api_app.clock.now())

    def write(conn: Any) -> int:
        return audit.record(conn, actor, action, target, before, after, reason, None, at=at)

    result: int = await api_app.ctx.dbs.control.write(write)
    return result


async def test_list_is_newest_first_with_filters_search_and_paging(api: Any, api_app: Any, api_json: Any) -> None:
    for seconds in (200, 300):
        await api.patch("settings", json={"changes": {"cache_ttl_seconds": seconds}, "reason": f"ttl {seconds}"})
        api_app.clock.advance(10)
    await _record(api_app, Actor("system", "auto:spam_rate"), "rule.create", "bans:7", None, {"subject": "x"}, "auto")
    page = api_json(await api.get("audit", params={"page_size": 10}))
    ids = [item["id"] for item in page["items"]]
    assert ids == sorted(ids, reverse=True)
    assert page["total"] >= 5
    first = page["items"][0]
    assert first["action"] == "rule.create"
    assert first["manage"]["href"] == "/admin/protection#bans"
    assert first["detail_url"].endswith(f"/audit/{first['id']}")
    assert {"before_preview", "after_preview", "has_before", "has_after", "actor_ip"} <= set(first)
    settings_only = api_json(await api.get("audit", params={"action": "setting.*"}))
    assert {item["action"] for item in settings_only["items"]} == {"setting.update"}
    target = api_json(await api.get("audit", params={"target": "setting:cache_ttl_seconds"}))
    assert target["total"] == 2
    mine = api_json(await api.get("audit", params={"actor": f"admin:{api.admin.username}"}))
    assert mine["total"] >= 2
    assert all(item["actor"] == f"admin:{api.admin.username}" for item in mine["items"])
    searched = api_json(await api.get("audit", params={"q": "TTL 300"}))
    assert [item["reason"] for item in searched["items"]] == ["ttl 300"]
    paged = api_json(await api.get("audit", params={"page_size": 10, "page": 2}))
    assert paged["page"] == 2
    assert all(item["id"] < ids[-1] for item in paged["items"])
    by_action = api_json(await api.get("audit", params={"sort": "action", "order": "asc"}))
    actions = [item["action"] for item in by_action["items"]]
    assert actions == sorted(actions)
    facets = api_json(await api.get("audit/facets"))
    assert {"action": "setting.update", "count": 4} in facets["actions"]  # 2 by the app fixture, 2 here
    assert any(item["actor"] == "system:auto:spam_rate" for item in facets["actors"])


async def test_time_window_filters_and_bad_values(api: Any, api_app: Any, api_json: Any, section13: Any) -> None:
    start = int(api_app.clock.now())
    api_app.clock.advance(100)
    await _record(api_app, Actor("cli", "ctl"), "service.pause", "service_state:pause", None, {"on": True}, "x")
    later = api_json(await api.get("audit", params={"from": str(start + 50)}))
    assert [item["action"] for item in later["items"]] == ["service.pause"]
    earlier = api_json(await api.get("audit", params={"to": str(start + 50)}))
    assert "service.pause" not in {item["action"] for item in earlier["items"]}
    fields = section13(await api.get("audit", params={"from": "yesterday"}), 422, "invalid_range")
    assert set(fields) == {"from"}
    section13(await api.get("audit", params={"sort": "reason"}), 422, "invalid_table_query")
    section13(await api.get("audit/999999"), 404, "not_found")
    section13(await api.get("audit/0"), 422, "validation_failed")


async def test_entry_has_a_diff_and_a_working_revert_link(api: Any, api_app: Any, api_json: Any) -> None:
    saved = api_json(await api.patch("settings", json={"changes": {"cache_ttl_seconds": 600}, "reason": "warm"}))
    audit_id = saved["changed"][0]["audit_id"]
    body = api_json(await api.get(f"audit/{audit_id}"))
    entry = body["entry"]
    assert entry["before"] == {"value": 120, "overridden": False}
    assert entry["after"] == {"value": 600, "overridden": True}
    changes = {item["path"]: item for item in body["diff"]["entries"]}
    assert changes["value"] == {"path": "value", "change": "changed", "before": 120, "after": 600}
    assert changes["overridden"]["change"] == "changed"
    assert body["diff"]["truncated"] is False
    revert = body["revert"]
    assert revert["available"] is True
    assert revert["history_id"] == saved["changed"][0]["history_id"]
    assert body["manage"]["href"] == "/admin/settings?key=cache_ttl_seconds"
    assert body["secret_target"] is False
    done = api_json(await api.post(revert["url"], json={"reason": "from the audit page"}))
    assert done["changed"][0]["new"] == 120
    assert api_app.ctx.settings.get("cache_ttl_seconds") == 120


async def test_rule_and_secret_entries(api: Any, api_app: Any, api_json: Any) -> None:
    service = RulesService(api_app.ctx.dbs.control, clock=api_app.clock, store=api_app.ctx.rules)
    change = await service.create(
        "access_list", {"kind": "deny", "cidr": "198.51.100.0/24"}, Actor("admin", "owner", "127.0.0.1"), "test"
    )
    rows = await api_app.ctx.dbs.control.read(
        lambda conn: conn.execute("SELECT id FROM audit_log WHERE action = 'rule.create' ORDER BY id DESC").fetchall()
    )
    body = api_json(await api.get(f"audit/{rows[0][0]}"))
    assert body["revert"]["available"] is False
    assert "card" in body["revert"]["reason"]
    assert body["manage"]["href"] == "/admin/protection#bypass"
    assert {item["change"] for item in body["diff"]["entries"]} == {"added"}
    assert change.key is not None
    summary_before = audit.secret_summary("old-secret-value-1234567890", b"k" * 32)
    summary_after = audit.secret_summary("new-secret-value-1234567890", b"k" * 32)
    secret_id = await _record(
        api_app, Actor("admin", "owner"), "credential.replace", "credential", summary_before, summary_after, "rotate"
    )
    secret = api_json(await api.get(f"audit/{secret_id}"))
    assert secret["secret_target"] is True
    assert set(secret["entry"]["after"]) == {"fingerprint", "masked"}
    assert "new-secret-value" not in str(secret)
    assert secret["manage"]["href"] == "/admin/credential#status"


async def test_export_guards_formulas_and_hashes_addresses(api: Any, api_app: Any, api_json: Any) -> None:
    await _record(api_app, Actor("admin", "owner", "203.0.113.77"), "rule.update", "bans:1", None, None, "=1+2")
    response = await api.get("audit", params={"format": "csv", "q": "=1+2"})
    assert response.status_code == 200
    assert response.headers["roxy-export-rows"] == "1"
    rows = list(csv.reader(io.StringIO(response.text)))
    header, row = rows[0], rows[1]
    assert header[:4] == ["Entry", "When", "Who", "From"]
    assert row[header.index("Reason")] == "'=1+2"  # the formula guard
    shown_ip = row[header.index("From")]
    assert shown_ip
    assert shown_ip != "203.0.113.77"
    assert shown_ip != ip_hash("203.0.113.77", api_app.ctx.ip_hash_key)
    as_json = await api.get("audit", params={"format": "json", "action": "rule.update"})
    document = as_json.json()
    assert document["table"] == "audit_log"
    assert document["items"][0]["reason"] == "=1+2"
    exports = await api_app.ctx.dbs.control.read(
        lambda conn: conn.execute(
            "SELECT target, after_json FROM audit_log WHERE action = 'export.download' ORDER BY id"
        ).fetchall()
    )
    assert [row[0] for row in exports] == ["table:audit_log", "table:audit_log"]
    assert '"ip_addresses":"hashed_one_time"' in exports[0][1]


async def test_guards(anon_api: Any) -> None:
    assert (await anon_api.get("audit")).status_code == 401
    assert (await anon_api.get("audit/1")).status_code == 401
    assert (await anon_api.get("audit/facets")).status_code == 401
