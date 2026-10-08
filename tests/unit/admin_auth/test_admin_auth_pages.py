"""Pages and management endpoints: the kill-switch link, the admin allowlist, sessions and trusted devices lists,
logout, and the templates' CSP and writing style (plan 9.2, 9.5, 9.6, C5; parity rows 99 to 101, D6)."""

from __future__ import annotations

import re

from roxy.admin.auth import sessions
from roxy.admin.auth.testing import AuthHarness, SoftwarePasskey
from roxy.core.style_guard import find_dashes, find_style_issues

API = "/admin/api/v1/auth"


def _kill_link(harness: AuthHarness) -> str:
    body = harness.mail.bodies("Roxy Admin Login")[-1]
    match = re.search(r"http://localhost(/admin/invalidate/[A-Za-z0-9_-]+)", body)
    assert match is not None
    return match.group(1)


async def test_kill_switch_get_confirms_post_consumes_once(harness: AuthHarness) -> None:
    admin = harness.admin()
    await harness.login(admin)
    await harness.drain()
    path = _kill_link(harness)
    stranger = harness.new_client()
    page = await stranger.get(path)
    assert page.status_code == 200
    assert "<title>Roxy: Invalidate Admin Sessions</title>" in page.text
    assert "Sign out all admin sessions" in page.text
    assert "<script" not in page.text
    again = await stranger.get(path)  # GET never uses the token (mail scanners open links)
    assert again.status_code == 200

    done = await stranger.post(path, data={"all_sessions": "1", "revoke_trusted": "1"})
    assert done.status_code == 200
    assert "Every admin session has been signed out" in done.text
    assert (await harness.http.get(f"{API}/session", headers=harness.headers())).status_code == 401
    used = await stranger.post(path, data={"all_sessions": "1"})
    assert used.status_code == 404
    assert "This link is no longer valid" in used.text
    epoch = harness.ctx.dbs.control.read_sync(lambda c: sessions.read_epoch(c))
    assert epoch == 1
    audit = harness.ctx.dbs.control.read_sync(
        lambda c: c.execute("SELECT action FROM audit_log WHERE action = 'auth.kill_switch'").fetchall()
    )
    assert len(audit) == 1


async def test_kill_switch_can_spare_passkey_sessions(harness: AuthHarness) -> None:
    admin = harness.admin()
    await harness.login(admin)
    options = await harness.post(f"{API}/passkeys/register/options")
    key = SoftwarePasskey()
    credential = key.register(options.json()["Options"], origin=harness.site_origin)
    assert (await harness.post(f"{API}/passkeys/register/verify", {"credential": credential})).status_code == 200
    passkey_browser = harness.new_client()
    tx = (await harness.password_step(admin, client=passkey_browser)).json()["Transaction"]
    opts = await passkey_browser.post(f"{API}/mfa/passkey/options", json={"transaction": tx}, headers=harness.headers())
    assertion = key.authenticate(opts.json()["Options"], origin=harness.site_origin)
    assert (await harness.mfa(tx, "passkey", credential=assertion, client=passkey_browser)).status_code == 200
    await harness.drain()
    path = _kill_link(harness)

    done = await harness.new_client().post(path, data={"revoke_trusted": "1"})  # all_sessions unchecked
    assert done.status_code == 200
    assert "not opened with a passkey" in done.text
    assert (await harness.http.get(f"{API}/session", headers=harness.headers())).status_code == 401
    assert (await passkey_browser.get(f"{API}/session", headers=harness.headers())).status_code == 200


async def test_malformed_kill_switch_tokens_are_plain_404(harness: AuthHarness) -> None:
    for path in ("/admin/invalidate/" + "a" * 101, "/admin/invalidate/bad%20token"):
        assert (await harness.http.get(path)).status_code == 404


async def test_allowlist_hides_admin_with_a_plain_404(harness: AuthHarness) -> None:
    admin = harness.admin()
    await harness.login(admin)  # a session from 127.0.0.1 before the allowlist is on
    await harness.drain()
    path = _kill_link(harness)
    await harness.allow_admin_cidr("198.51.100.0/24")
    await harness.set_settings(admin_allowlist_enabled=1)
    outside = {"X-Forwarded-For": "203.0.113.9"}
    # What a path that does not exist answers: v1's `admin_not_found` for pages (plan 4.1 row 15), the DESIGN.md
    # section 13 error object under the versioned API.
    unknown_page = await harness.http.get("/admin/does-not-exist", headers=outside)
    unknown_api = await harness.http.get(f"{API}/does-not-exist", headers=outside)
    assert unknown_page.status_code == unknown_api.status_code == 404
    assert unknown_page.content == b'"Not Found"\n'
    assert unknown_api.json() == {"error": {"code": "not_found", "message": "Not found.", "fields": {}}}
    for response in (
        await harness.http.get("/admin", headers=outside),
        await harness.http.post(f"{API}/login", json={"username": "a", "password": "b"}, headers=outside),
        await harness.http.get(f"{API}/session", headers={**harness.headers(), **outside}),
        await harness.http.get("/admin/invalidate/not-a-valid-token", headers=outside),
    ):
        # A hidden route answers byte for byte what a missing one at the same place answers, or the allowlist
        # would tell an outsider which admin paths exist.
        missing = unknown_api if response.url.path.startswith(API) else unknown_page
        assert response.status_code == 404
        assert response.content == missing.content, response.url.path
        assert response.headers["content-type"] == missing.headers["content-type"] == "application/json"
    # A valid kill-switch link still works from anywhere (the owner may be on mobile data).
    assert (await harness.http.get(path, headers=outside)).status_code == 200
    inside = {"X-Forwarded-For": "198.51.100.20"}
    assert (await harness.http.get("/admin", headers=inside)).status_code in (200, 302)


async def test_logout_deletes_the_server_side_session(harness: AuthHarness) -> None:
    admin = harness.admin()
    await harness.login(admin)
    token = harness.http.cookies.get(sessions.SESSION_COOKIE)
    copied = {**harness.headers(), "Cookie": f"{sessions.SESSION_COOKIE}={token}"}
    copy = harness.new_client()
    assert (await copy.get(f"{API}/session", headers=copied)).status_code == 200
    out = await harness.post(f"{API}/logout")
    assert out.status_code == 200
    assert out.text == '"Logged out"\n'
    assert (await copy.get(f"{API}/session", headers=copied)).status_code == 401  # v1 bug B11 fixed


async def test_sessions_list_and_revoke(harness: AuthHarness) -> None:
    admin = harness.admin()
    other = harness.new_client()
    await harness.login(admin, client=other)
    await harness.login(admin)
    listed = await harness.http.get(f"{API}/sessions", headers=harness.headers())
    data = listed.json()
    assert len(data["Sessions"]) == 2
    other_id = next(s["Id"] for s in data["Sessions"] if s["Id"] != data["Current"])
    revoked = await harness.post(f"{API}/sessions/{other_id}/revoke")
    assert revoked.status_code == 200
    assert revoked.json() == {"Revoked": 1}
    assert (await other.get(f"{API}/session", headers=harness.headers())).status_code == 401
    assert (await harness.post(f"{API}/sessions/{'0' * 16}/revoke")).status_code == 404

    await harness.login(admin, client=other)
    assert (await harness.post(f"{API}/sessions/revoke-others")).json() == {"Revoked": 1}
    assert (await harness.http.get(f"{API}/session", headers=harness.headers())).status_code == 200
    everywhere = await harness.post(f"{API}/sessions/revoke-all")
    assert everywhere.status_code == 200
    assert (await harness.http.get(f"{API}/session", headers=harness.headers())).status_code == 401


async def test_trusted_devices_list_and_revoke(harness: AuthHarness) -> None:
    admin = harness.admin()
    await harness.login(admin, trust=True)
    listed = (await harness.http.get(f"{API}/trusted-devices", headers=harness.headers())).json()
    assert listed["Enabled"] is True
    assert len(listed["Devices"]) == 1
    assert listed["ThisDevice"] == listed["Devices"][0]["Id"]
    assert listed["Devices"][0]["Name"] == "Firefox on Linux"
    revoked = await harness.post(f"{API}/trusted-devices/{listed['Devices'][0]['Id']}/revoke")
    assert revoked.json() == {"Revoked": 1}
    assert (await harness.post(f"{API}/trusted-devices/999/revoke")).status_code == 404
    await harness.login(admin, trust=True)
    assert (await harness.post(f"{API}/trusted-devices/revoke-all")).json() == {"Revoked": 1}


async def test_auth_pages_obey_the_csp_and_the_writing_style(harness: AuthHarness) -> None:
    login = await harness.http.get("/admin")
    admin = harness.admin(username="enroller", with_totp=False, bootstrap=True)
    tx = (await harness.password_step(admin)).json()["Transaction"]
    code = harness.mail.bodies("Admin 2FA")[0].strip()
    await harness.mfa(tx, "email", code=code)
    enroll = await harness.http.get("/admin/enroll")
    invalidate = await harness.http.get("/admin/invalidate/sometoken")
    for response in (login, enroll, invalidate):
        assert response.status_code == 200, response.text
        html = response.text
        nonce = re.search(r"script-src 'nonce-([^']+)'", response.headers["content-security-policy"])
        for tag in re.findall(r"<script[^>]*>", html):
            assert nonce is not None
            assert f'nonce="{nonce.group(1)}"' in tag
            assert "src=" in tag
        assert not re.search(r"<script[^>]*>\s*[^<\s]", html)  # no inline script bodies
        assert "<style" not in html
        assert " style=" not in html
        assert not re.search(r"\son[a-z]+=", html)  # no inline event handlers
        assert find_dashes(html) == []
        assert find_style_issues(html, response.url.path) == []
    assert '<meta name="csrf-token"' in enroll.text


async def test_enroll_page_needs_a_session(harness: AuthHarness) -> None:
    response = await harness.http.get("/admin/enroll", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"] == "/admin"
