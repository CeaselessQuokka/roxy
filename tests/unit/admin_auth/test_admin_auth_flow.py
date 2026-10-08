"""The login flow end to end over HTTP: password step, second factors, bootstrap, trusted devices, re-auth.

Plan 9.5, 9.6, parity rows 94 to 101, owner decision D5.
"""

from __future__ import annotations

import json
import re

from roxy.admin.auth import sessions, totp, transactions
from roxy.admin.auth.testing import TEST_UA, AuthHarness, SoftwarePasskey

API = "/admin/api/v1/auth"


async def test_password_then_totp_logs_in_and_sends_the_login_alert(harness: AuthHarness) -> None:
    admin = harness.admin()
    first = await harness.password_step(admin)
    assert first.status_code == 200
    data = first.json()
    assert data["TwoFA"] is True
    assert data["Status"] == "Success"
    assert data["Methods"] == ["totp", "recovery"]
    assert data["ExpiresIn"] == 120  # challenge_expiration (login transaction lifetime)
    assert len(data["Transaction"]) >= 32

    second = await harness.mfa(data["Transaction"], "totp", code=harness.next_code(admin))
    assert second.status_code == 200, second.text
    body = second.json()
    assert body["LoggedIn"] is True
    assert body["Redirect"] == "/admin/dashboard"
    assert body["MfaLevel"] == "totp"
    assert sessions.SESSION_COOKIE in second.cookies
    status = await harness.http.get(f"{API}/session", headers=harness.headers())
    assert status.status_code == 200
    assert status.json()["Username"] == admin.username
    assert status.json()["Fresh"] is True

    await harness.drain()
    assert harness.mail.subjects() == ["Roxy Admin Login"]
    mail = harness.mail.bodies("Roxy Admin Login")[0]
    assert mail.startswith("A successful login to the Roxy admin panel just occurred.\n\nIP: 127.0.0.1\n")
    assert f"User-Agent: {TEST_UA}\n" in mail
    link = re.search(r"(http://localhost/admin/invalidate/[A-Za-z0-9_-]{40,})\n", mail)
    assert link is not None, mail  # the kill-switch link survives redaction intact


async def test_wrong_password_is_403_invalid_credentials_and_unknown_user_looks_the_same(
    harness: AuthHarness,
) -> None:
    admin = harness.admin()
    wrong = await harness.password_step(admin, password="not the password at all")
    unknown = await harness.password_step(admin, username="nobody-here", password="whatever password 123")
    for response in (wrong, unknown):
        assert response.status_code == 403
        assert response.text == '"Invalid credentials"\n'
        assert response.headers["content-type"].startswith("application/json")


async def test_malformed_login_bodies_are_rejected_with_400(harness: AuthHarness) -> None:
    headers = harness.headers()
    cases = [
        ("", "application/json"),
        ("not json", "application/json"),
        ("[1, 2]", "application/json"),
        ('{"username": "a"}', "application/json"),
        ('{"username": "a", "password": "b", "extra": 1}', "application/json"),
        ('{"username": "a", "password": "b"}', "text/plain"),
    ]
    for content, content_type in cases:
        response = await harness.http.post(
            f"{API}/login", content=content, headers={**headers, "Content-Type": content_type}
        )
        assert response.status_code == 400, (content, response.text)
        assert response.text == '"Invalid request"\n'


async def test_recovery_code_works_once(harness: AuthHarness) -> None:
    admin = harness.admin()
    code = admin.recovery_codes[0]
    first = (await harness.password_step(admin)).json()
    ok = await harness.mfa(first["Transaction"], "recovery", code=code.lower().replace("-", " "))
    assert ok.status_code == 200, ok.text
    assert ok.json()["MfaLevel"] == "recovery"
    again = (await harness.password_step(admin)).json()
    reused = await harness.mfa(again["Transaction"], "recovery", code=code)
    assert reused.status_code == 404
    assert reused.text == '"Not Found"\n'


async def test_totp_code_is_single_use_per_step(harness: AuthHarness) -> None:
    admin = harness.admin()
    code = harness.next_code(admin)
    first = (await harness.password_step(admin)).json()
    assert (await harness.mfa(first["Transaction"], "totp", code=code)).status_code == 200
    second = (await harness.password_step(admin)).json()
    replay = await harness.mfa(second["Transaction"], "totp", code=code)
    assert replay.status_code == 404  # same step again: refused although the code is "valid"


async def test_totp_accepts_one_step_of_drift_but_not_two(harness: AuthHarness) -> None:
    admin = harness.admin()
    assert admin.totp_secret is not None
    harness.clock.advance(300)
    now = harness.clock.now()
    previous = totp.code_for_step(admin.totp_secret, totp.current_step(now) - 1)
    too_old = totp.code_for_step(admin.totp_secret, totp.current_step(now) - 2)
    tx = (await harness.password_step(admin)).json()["Transaction"]
    assert (await harness.mfa(tx, "totp", code=too_old)).status_code == 404
    assert (await harness.mfa(tx, "totp", code=previous)).status_code == 200


async def test_transaction_is_bound_to_ip_and_user_agent_and_expires(harness: AuthHarness) -> None:
    admin = harness.admin()
    tx = (await harness.password_step(admin, ip="198.51.100.7")).json()["Transaction"]
    code = harness.next_code(admin)
    assert (await harness.mfa(tx, "totp", code=code, ip="198.51.100.8")).status_code == 404
    assert (await harness.mfa(tx, "totp", code=code, ip="198.51.100.7", ua="curl/8.0")).status_code == 404
    # The right browser can still finish it (mismatches do not burn the transaction).
    assert (await harness.mfa(tx, "totp", code=code, ip="198.51.100.7")).status_code == 200

    late = (await harness.password_step(admin)).json()["Transaction"]
    harness.clock.advance(121)
    assert (await harness.mfa(late, "totp", code=harness.next_code(admin))).status_code == 404


async def test_three_second_factor_attempts_per_transaction(harness: AuthHarness) -> None:
    admin = harness.admin()
    tx = (await harness.password_step(admin)).json()["Transaction"]
    for _ in range(3):
        assert (await harness.mfa(tx, "totp", code="000000")).status_code == 404
    # The fourth attempt fails even with the right code: the transaction is gone.
    assert (await harness.mfa(tx, "totp", code=harness.next_code(admin))).status_code == 404


async def test_bootstrap_login_uses_email_then_forces_enrollment(harness: AuthHarness) -> None:
    admin = harness.admin(with_totp=False, bootstrap=True, email="owner@example.invalid")
    first = await harness.password_step(admin)
    assert first.status_code == 200, first.text
    data = first.json()
    assert data["Methods"] == ["email"]
    assert data["Bootstrap"] is True
    assert harness.mail.subjects() == ["Admin 2FA"]
    code = harness.mail.bodies("Admin 2FA")[0].strip()
    assert re.fullmatch(r"\d{16}", code)
    done = await harness.mfa(data["Transaction"], "email", code=code)
    assert done.status_code == 200, done.text
    assert done.json()["Redirect"] == "/admin/enroll"
    assert done.json()["EnrollmentRequired"] is True

    # A bootstrap session can do nothing but enroll.
    blocked = await harness.http.get(f"{API}/sessions", headers=harness.headers())
    assert blocked.status_code == 403
    assert blocked.headers["Roxy-Enroll"] == "required"

    start = await harness.post(f"{API}/totp/enroll/start")
    assert start.status_code == 200, start.text
    secret = start.json()["Secret"]
    assert start.json()["Qr"].startswith("data:image/svg+xml")
    harness.clock.advance(30)
    confirm = await harness.post(f"{API}/totp/enroll/confirm", {"code": totp.code_at(secret, harness.clock.now())})
    assert confirm.status_code == 200, confirm.text
    codes = confirm.json()["RecoveryCodes"]
    assert len(codes) == 10
    assert len(set(codes)) == 10
    assert (await harness.http.get(f"{API}/sessions", headers=harness.headers())).status_code == 200

    user = harness.ctx.dbs.control.read_sync(
        lambda c: c.execute(
            "SELECT mfa_bootstrap_pending, totp_secret_enc FROM admin_users WHERE id = ?", (admin.id,)
        ).fetchone()
    )
    assert user[0] == 0
    assert user[1] is not None
    # The email path is closed now: the next login offers the authenticator, not email.
    again = (await harness.password_step(admin)).json()
    assert "email" not in again["Methods"]
    assert "totp" in again["Methods"]


async def test_email_send_failure_is_503_with_v1_text(harness: AuthHarness) -> None:
    admin = harness.admin(with_totp=False, bootstrap=True)
    harness.mail.fail = True
    response = await harness.password_step(admin)
    assert response.status_code == 503
    assert response.json() == "Could not send the 2FA email; please try again shortly."


async def test_email_resend_replaces_the_code_and_is_rate_limited(harness: AuthHarness) -> None:
    admin = harness.admin(with_totp=False, bootstrap=True)
    tx = (await harness.password_step(admin)).json()["Transaction"]
    first_code = harness.mail.bodies("Admin 2FA")[0].strip()
    too_soon = await harness.http.post(f"{API}/mfa/email", json={"transaction": tx}, headers=harness.headers())
    assert too_soon.status_code == 429
    harness.clock.advance(31)
    resent = await harness.http.post(f"{API}/mfa/email", json={"transaction": tx}, headers=harness.headers())
    assert resent.status_code == 200, resent.text
    second_code = harness.mail.bodies("Admin 2FA")[1].strip()
    assert (await harness.mfa(tx, "email", code=first_code)).status_code == 404  # the old code stopped working
    assert (await harness.mfa(tx, "email", code=second_code)).status_code == 200
    missing = await harness.http.post(f"{API}/mfa/email", json={"transaction": "x" * 43}, headers=harness.headers())
    assert missing.status_code == 403
    assert missing.json() == "Start the login again."


async def test_email_factor_refused_when_not_enabled(harness: AuthHarness) -> None:
    admin = harness.admin()
    tx = (await harness.password_step(admin)).json()["Transaction"]
    response = await harness.http.post(f"{API}/mfa/email", json={"transaction": tx}, headers=harness.headers())
    assert response.status_code == 403
    assert (await harness.mfa(tx, "email", code="1234567890123456")).status_code == 404


async def test_email_fallback_when_enabled(harness: AuthHarness) -> None:
    await harness.set_settings(admin_email_code_enabled=1)
    admin = harness.admin()
    data = (await harness.password_step(admin)).json()
    assert data["Methods"] == ["totp", "recovery", "email"]
    sent = await harness.http.post(
        f"{API}/mfa/email", json={"transaction": data["Transaction"]}, headers=harness.headers()
    )
    assert sent.status_code == 200, sent.text
    code = harness.mail.bodies("Admin 2FA")[0].strip()
    done = await harness.mfa(data["Transaction"], "email", code=code)
    assert done.status_code == 200
    assert done.json()["MfaLevel"] == "email"


async def test_trusted_device_skips_only_the_second_factor(harness: AuthHarness) -> None:
    admin = harness.admin()
    done = await harness.login(admin, trust=True)
    assert done.status_code == 200
    assert "__Host-roxy_trusted" in done.cookies
    harness.http.cookies.delete(sessions.SESSION_COOKIE)
    again = await harness.password_step(admin)
    assert again.status_code == 200
    assert again.json()["LoggedIn"] is True
    assert again.json()["MfaLevel"] == "trusted_device"
    # The password is still required.
    wrong = await harness.password_step(admin, password="definitely wrong password")
    assert wrong.status_code == 403
    # A different browser family does not get the skip.
    other = await harness.password_step(admin, ua="Mozilla/5.0 (Windows NT 10.0) Chrome/120.0 Safari/537.36")
    assert other.json().get("TwoFA") is True
    # Turned off: every login asks for the second factor again.
    await harness.set_settings(admin_trusted_devices_enabled=0)
    off = await harness.password_step(admin)
    assert off.json().get("TwoFA") is True


async def test_trusted_device_session_is_not_fresh_and_reauth_rotates(harness: AuthHarness) -> None:
    admin = harness.admin()
    await harness.login(admin, trust=True)
    harness.http.cookies.delete(sessions.SESSION_COOKIE)
    await harness.password_step(admin)  # trusted device login
    old = harness.http.cookies.get(sessions.SESSION_COOKIE)
    refused = await harness.post(f"{API}/recovery-codes/regenerate")
    assert refused.status_code == 403
    assert refused.headers["Roxy-Reauth"] == "required"
    reauth = await harness.post(f"{API}/reauth", {"method": "totp", "code": harness.next_code(admin)})
    assert reauth.status_code == 200, reauth.text
    new = harness.http.cookies.get(sessions.SESSION_COOKIE)
    assert new
    assert new != old
    regenerated = await harness.post(f"{API}/recovery-codes/regenerate")
    assert regenerated.status_code == 200
    assert len(regenerated.json()["RecoveryCodes"]) == 10
    stale = {**harness.headers(), "Cookie": f"{sessions.SESSION_COOKIE}={old}"}
    assert (await harness.new_client().get(f"{API}/session", headers=stale)).status_code == 401
    fresh_cookie = {**harness.headers(), "Cookie": f"{sessions.SESSION_COOKIE}={new}"}
    assert (await harness.new_client().get(f"{API}/session", headers=fresh_cookie)).status_code == 200


async def test_passkey_registration_and_login(harness: AuthHarness) -> None:
    admin = harness.admin()
    await harness.login(admin)
    options = await harness.post(f"{API}/passkeys/register/options")
    assert options.status_code == 200, options.text
    key = SoftwarePasskey()
    credential = key.register(options.json()["Options"], origin=harness.site_origin)
    added = await harness.post(f"{API}/passkeys/register/verify", {"credential": credential, "name": "Laptop"})
    assert added.status_code == 200, added.text
    listed = await harness.http.get(f"{API}/passkeys", headers=harness.headers())
    assert [p["Name"] for p in listed.json()["Passkeys"]] == ["Laptop"]

    fresh = harness.new_client()
    tx = (await harness.password_step(admin, client=fresh)).json()
    assert "passkey" in tx["Methods"]
    opts = await fresh.post(
        f"{API}/mfa/passkey/options", json={"transaction": tx["Transaction"]}, headers=harness.headers()
    )
    assert opts.status_code == 200, opts.text
    assertion = key.authenticate(opts.json()["Options"], origin=harness.site_origin)
    done = await harness.mfa(tx["Transaction"], "passkey", credential=assertion, client=fresh)
    assert done.status_code == 200, done.text
    assert done.json()["MfaLevel"] == "passkey"

    # A forged assertion (another key) is the uniform 404.
    tx2 = (await harness.password_step(admin, client=fresh)).json()["Transaction"]
    opts2 = await fresh.post(f"{API}/mfa/passkey/options", json={"transaction": tx2}, headers=harness.headers())
    forged = SoftwarePasskey()
    forged.credential_id = key.credential_id
    bad = await harness.mfa(
        tx2,
        "passkey",
        credential=forged.authenticate(opts2.json()["Options"], origin=harness.site_origin),
        client=fresh,
    )
    assert bad.status_code == 404
    assert bad.text == '"Not Found"\n'


async def test_login_page_and_logged_in_redirect(harness: AuthHarness) -> None:
    page = await harness.http.get("/admin")
    assert page.status_code == 200
    assert "<title>Roxy Admin Login</title>" in page.text
    assert "<script" in page.text
    assert 'nonce="' in page.text
    assert "style=" not in page.text
    assert "onclick" not in page.text.lower()
    assert page.headers["cache-control"] == "no-store"
    admin = harness.admin()
    await harness.login(admin)
    redirect = await harness.http.get("/admin", follow_redirects=False)
    assert redirect.status_code == 302
    assert redirect.headers["location"] == "/admin/dashboard"


async def test_heartbeat_extends_only_with_recent_input(harness: AuthHarness) -> None:
    admin = harness.admin()
    await harness.login(admin)
    harness.clock.advance(600)
    idle = await harness.post(f"{API}/heartbeat", {"idle_ms": 120_000})
    assert idle.status_code == 200
    assert idle.json()["Extended"] is False
    harness.clock.advance(301)  # 901 s since the last real use: expired despite the idle heartbeat
    assert (await harness.http.get(f"{API}/session", headers=harness.headers())).status_code == 401

    await harness.login(admin)
    harness.clock.advance(600)
    active = await harness.post(f"{API}/heartbeat", {"idle_ms": 5_000})
    assert active.json()["Extended"] is True
    assert active.json()["IdleTimeout"] == 900
    harness.clock.advance(600)
    assert (await harness.http.get(f"{API}/session", headers=harness.headers())).status_code == 200
    # Polling (a plain GET) does not extend it.
    harness.clock.advance(400)
    assert (await harness.http.get(f"{API}/session", headers=harness.headers())).status_code == 401


async def test_session_absolute_lifetime(harness: AuthHarness) -> None:
    admin = harness.admin()
    await harness.login(admin)
    token = await harness.csrf()  # one masked token stays valid for the whole session
    alive_for = 0
    for _ in range(60):  # active use every 880 s, well inside the idle timeout
        harness.clock.advance(880)
        response = await harness.http.post(f"{API}/heartbeat", json={"idle_ms": 0}, headers=harness.headers(csrf=token))
        if response.status_code != 200:
            break
        alive_for += 880
    assert response.status_code == 401
    assert 43200 - 880 <= alive_for < 43200  # ended by admin_session_max_age_s, not by idling


async def test_login_transaction_record_holds_no_secrets(harness: AuthHarness) -> None:
    admin = harness.admin()
    response = await harness.password_step(admin)
    token = response.json()["Transaction"]
    rows = harness.ctx.dbs.hot.read_sync(
        lambda c: c.execute("SELECT name, payload_json FROM lease WHERE name LIKE 'auth_tx:%'").fetchall()
    )
    assert len(rows) == 1
    name, payload = rows[0]
    assert token not in name
    assert token not in payload
    assert name == transactions.LOGIN_TX + transactions.token_hash(token)
    assert TEST_UA not in payload
    assert admin.password not in payload
    assert json.loads(payload)["ip"] == "127.0.0.1"
