"""The Security page API (`/admin/api/v1/security`) in the real app: logins, probes, crawls, fingerprints with the
blocked variants and ignored headers, CSP reports, sessions, trusted devices, passkeys and recovery codes (plan 14.1
Security; parity rows 79, 80, 97, 98, 100, 134).

Events are recorded through the real recorder and flushed to metrics.db; account actions run the real auth
functions, so their audit rows and the fresh second factor rule are checked end to end.
"""

from __future__ import annotations

import csv
import io
from typing import Any

import pytest

from roxy.admin.auth.testing import SoftwarePasskey

pytestmark = pytest.mark.asyncio

AUTH = "/admin/api/v1/auth"


def ok(response: Any, api_json: Any, status: int = 200) -> Any:
    assert response.status_code == status, response.text
    return api_json(response)


async def flush_closed_minute(api_app: Any) -> None:
    """Aggregated events are written once their minute closes: move the clock past it, then flush."""
    api_app.clock.advance(61)
    await api_app.ctx.recorder.flush()


async def audit_count(api_app: Any, action: str) -> int:
    def read(conn: Any) -> int:
        return int(conn.execute("SELECT count(*) FROM audit_log WHERE action = ?", (action,)).fetchone()[0])

    count: int = await api_app.ctx.dbs.control.read(read)
    return count


async def test_logins_and_failed_logins(api: Any, api_app: Any, api_json: Any, section13: Any) -> None:
    recorder = api_app.ctx.recorder
    recorder.record_login("203.0.113.80", False, username="owner", method="password")
    recorder.record_login("203.0.113.80", False, username="root", method="password")
    await recorder.flush()
    table = ok(await api.get("security/logins"), api_json)
    assert table["total"] >= 3  # the fixture's own login, plus the two failures
    assert table["items"][0]["successful"] is False
    failed = ok(await api.get("security/logins", params={"result": "failure"}), api_json)
    assert [item["username"] for item in failed["items"]] == ["root", "owner"]
    mine = ok(await api.get("security/logins", params={"result": "success"}), api_json)
    assert all(item["successful"] for item in mine["items"])
    assert mine["total"] >= 1
    section13(await api.get("security/logins", params={"order": "asc"}), 422, "invalid_table_query")
    export = await api.get("security/logins", params={"format": "csv", "result": "failure"})
    assert export.status_code == 200
    text = export.content.decode()
    assert "203.0.113.80" not in text
    assert next(csv.reader(io.StringIO(text)))[0] == "When"


async def test_probes_ring_summary_and_crawls(api: Any, api_app: Any, api_json: Any) -> None:
    recorder = api_app.ctx.recorder
    recorder.record_probe("203.0.113.81", 'Invalid URL: "a<b"', "curl/8", "/a<b")
    recorder.record_probe("203.0.113.81", 'Invalid URL: "c>d"', "curl/8", "/c>d")
    recorder.record_probe("203.0.113.82", 'Non-Roblox URL: "wp-login.php"', "scanner", "/wp-login.php")
    recorder.record_crawl("203.0.113.83", "robots.txt", "Googlebot")
    recorder.record_crawl("203.0.113.83", "sitemap.xml", "Googlebot")
    recorder.record_crawl("203.0.113.84", "robots.txt", "Bingbot")
    await recorder.flush()
    probes = ok(await api.get("security/probes"), api_json)
    assert probes["total"] == 3
    assert probes["items"][0]["reason"] == "Non-Roblox URL"
    assert probes["items"][0]["target"] == "wp-login.php"
    by_ip = ok(await api.get("security/probes", params={"ip": "203.0.113.81"}), api_json)
    assert by_ip["total"] == 2
    summary = ok(await api.get("security/probes/summary"), api_json)
    assert [(item["reason"], item["count"]) for item in summary["items"]] == [
        ("Invalid URL", 2),
        ("Non-Roblox URL", 1),
    ]  # v1 bug B19 fixed: the probed URL is not part of the signature
    crawls = ok(await api.get("security/crawls"), api_json)
    assert [(item["ip"], item["count"]) for item in crawls["items"]] == [("203.0.113.83", 2), ("203.0.113.84", 1)]


async def test_fingerprints_values_user_agents_blocked_and_ignored_headers(
    api: Any, api_app: Any, api_json: Any, section13: Any
) -> None:
    recorder = api_app.ctx.recorder
    recorder.record_fingerprint([("X-Test", "one"), ("Accept", "*/*")], "Roblox/WinInet")
    recorder.record_fingerprint([("X-Test", "two"), ("Accept", "*/*")], "Roblox/WinInet")
    recorder.record_fingerprint([("X-Test", "two")], "python-requests/2.31")
    recorder.record_fingerprint([("Xeno-Fingerprint", "4f3a")], "Xeno/1.0", blocked=True)
    await flush_closed_minute(api_app)
    headers = ok(await api.get("security/fingerprints/headers"), api_json)
    rows = {item["name"]: item for item in headers["items"]}
    assert rows["x-test"]["count"] == 3
    assert rows["x-test"]["value_count"] == 2
    assert rows["accept"]["count"] == 2
    assert rows["x-test"]["values_ignored"] is False
    values = ok(await api.get("security/fingerprints/headers/X-Test/values"), api_json)
    assert [(item["value"], item["count"]) for item in values["items"]] == [("two", 2), ("one", 1)]
    agents = ok(await api.get("security/fingerprints/user-agents", params={"q": "roblox"}), api_json)
    assert [(item["user_agent"], item["count"]) for item in agents["items"]] == [("Roblox/WinInet", 2)]
    blocked = ok(await api.get("security/fingerprints/blocked"), api_json)
    assert blocked["headers"][0]["name"] == "xeno-fingerprint"
    assert blocked["user_agents"][0]["user_agent"] == "Xeno/1.0"
    ignored = ok(await api.get("security/fingerprints/ignored"), api_json)
    assert "traceparent" in {item["name"] for item in ignored["items"]}  # a shipped default
    added = ok(await api.post("security/fingerprints/ignored", json={"name": "X-Test", "note": "ids"}), api_json)
    assert added["key"] == "x-test"
    assert added["values_removed"] == 2
    section13(await api.post("security/fingerprints/ignored", json={"name": "x-test"}), 409, "conflict")
    section13(await api.post("security/fingerprints/ignored", json={"name": "bad name"}), 422, "invalid_rule")
    headers = ok(await api.get("security/fingerprints/headers"), api_json)
    assert {item["name"]: item for item in headers["items"]}["x-test"]["values_ignored"] is True
    assert "x-test" in api_app.ctx.rules.snapshot.ignored_value_headers
    ok(await api.delete("security/fingerprints/ignored/X-Test"), api_json)
    assert "x-test" not in api_app.ctx.rules.snapshot.ignored_value_headers
    section13(await api.delete("security/fingerprints/ignored/x-test"), 404, "not_found")


async def test_csp_reports_grouped_and_filtered(api: Any, api_app: Any, api_json: Any) -> None:
    recorder = api_app.ctx.recorder
    report = {"document": "/docs", "blocked": "inline", "directive": "script-src-elem", "disposition": "enforce"}
    for _ in range(2):
        recorder.record_event("csp_report", "info", None, report, aggregate=True)
    other = {**report, "directive": "img-src", "blocked": "https://example.invalid"}
    recorder.record_event("csp_report", "info", None, other, aggregate=True)
    await flush_closed_minute(api_app)
    table = ok(await api.get("security/csp-reports"), api_json)
    assert table["total"] == 2
    assert (table["items"][0]["directive"], table["items"][0]["count"]) == ("script-src-elem", 2)
    only = ok(await api.get("security/csp-reports", params={"directive": "img-src"}), api_json)
    assert [item["blocked"] for item in only["items"]] == ["https://example.invalid"]


async def test_sessions_list_revoke_others_and_sign_out_everywhere(
    api: Any, api_app: Any, api_admin: Any, api_json: Any, section13: Any
) -> None:
    other = api_app.harness.new_client()
    assert (await api_app.harness.login(api_admin, client=other)).status_code == 200
    listing = ok(await api.get("security/sessions"), api_json)
    assert listing["total"] == 2
    assert [item["current"] for item in listing["items"]].count(True) == 1
    section13(await api.post("security/sessions/0123456789abcdef/revoke"), 404, "not_found")
    ended = ok(await api.post("security/sessions/revoke-others"), api_json)
    assert ended == {"revoked": 1, "signed_out": False}
    assert (await other.get(f"{AUTH}/session", headers=api_app.harness.headers())).status_code == 401
    assert ok(await api.get("security/sessions"), api_json)["total"] == 1
    assert await audit_count(api_app, "auth.sessions_revoked_others") == 1
    everywhere = await api.post("security/sessions/revoke-all")
    assert everywhere.status_code == 200
    assert everywhere.json()["signed_out"] is True
    assert "set-cookie" in everywhere.headers
    assert (await api.get("security/sessions")).status_code == 401


async def test_trusted_devices_list_and_revoke(api: Any, api_app: Any, api_admin: Any, api_json: Any,
                                               section13: Any) -> None:  # fmt: skip
    await api_app.settings(admin_trusted_devices_enabled=1)
    browser = api_app.harness.new_client()
    assert (await api_app.harness.login(api_admin, client=browser, trust=True)).status_code == 200
    listing = ok(await api.get("security/trusted-devices"), api_json)
    assert listing["enabled"] is True
    assert listing["total"] == 1
    assert listing["this_device"] is None  # the device trusted another browser, not this one
    device = listing["items"][0]["id"]
    section13(await api.post("security/trusted-devices/999/revoke"), 404, "not_found")
    assert ok(await api.post(f"security/trusted-devices/{device}/revoke"), api_json) == {"revoked": 1}
    assert ok(await api.post("security/trusted-devices/revoke-all"), api_json) == {"revoked": 0}
    assert await audit_count(api_app, "auth.trusted_device_revoked") == 1


async def test_passkeys_rename_and_delete_need_a_fresh_second_factor(
    api: Any, api_app: Any, api_json: Any, section13: Any
) -> None:
    harness = api_app.harness
    options = await harness.post(f"{AUTH}/passkeys/register/options")
    credential = SoftwarePasskey().register(options.json()["Options"], origin=harness.site_origin)
    added = await harness.post(f"{AUTH}/passkeys/register/verify", {"credential": credential, "name": "Laptop"})
    assert added.status_code == 200
    listing = ok(await api.get("security/passkeys"), api_json)
    assert [item["name"] for item in listing["items"]] == ["Laptop"]
    passkey = listing["items"][0]["id"]
    api.make_mfa_stale()
    section13(await api.patch(f"security/passkeys/{passkey}", json={"name": "Desk"}), 403, "reauth_required")
    section13(await api.delete(f"security/passkeys/{passkey}"), 403, "reauth_required")
    await api.fresh_mfa()
    renamed = ok(await api.patch(f"security/passkeys/{passkey}", json={"name": "  Work   desk "}), api_json)
    assert renamed == {"id": passkey, "name": "Work desk", "changed": True}
    assert await audit_count(api_app, "auth.passkey_renamed") == 1
    section13(await api.patch("security/passkeys/999", json={"name": "x"}), 404, "not_found")
    assert ok(await api.delete(f"security/passkeys/{passkey}"), api_json) == {"removed": True}
    section13(await api.delete(f"security/passkeys/{passkey}"), 404, "not_found")
    assert ok(await api.get("security/passkeys"), api_json)["total"] == 0


async def test_recovery_codes_status_and_regenerate(api: Any, api_json: Any, section13: Any) -> None:
    status = ok(await api.get("security/recovery-codes"), api_json)
    assert status == {"total": 10, "remaining": 10}
    api.make_mfa_stale()
    section13(await api.post("security/recovery-codes/regenerate"), 403, "reauth_required")
    await api.fresh_mfa()
    fresh = ok(await api.post("security/recovery-codes/regenerate"), api_json)
    assert fresh["total"] == 10
    assert len(set(fresh["codes"])) == 10
    assert ok(await api.get("security/recovery-codes"), api_json) == {"total": 10, "remaining": 10}
