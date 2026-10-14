"""The D5 first login closes for good once an authenticator is enrolled (finding sec-3 of the final review).

What this is
    Tests of every place a bootstrap login or session minted BEFORE the enrollment could still act AFTER it: the
    pending login transaction (resend and second factor), the write that creates the session, the leftover
    bootstrap session in another browser, and the enrollment write itself.

Why it exists
    DESIGN.md section 0 (D5): the emailed code is a one-time path for the imported v1 account, closed by the TOTP
    enrollment; plan 9.6: replacing an enrolled authenticator needs a fresh second factor. Before the fix a bootstrap
    transaction or session from before the enrollment still signed in and enrolled a different authenticator over the
    owner's. `tests/review_final/test_security.py` keeps the end-to-end reproduction; these pin each guard alone.

How it works
    The `harness` fixture (`tests/unit/admin_auth/conftest.py`, the real app with a fast hasher and recorded mail).
    "Enrolled elsewhere" is written straight into control.db with `users.store_totp`, the state another worker's
    enrollment leaves, so each guard is reached without the cleanup the enrollment route also does.

What to read next
    `roxy/admin/auth/flow.py` (`mfa`, `_finish_login`, `resend_email`), `roxy/admin/auth/enrollment.py`
    (`confirm_totp`), `roxy/admin/auth/routes.py` (`_require_enroll_rights`).
"""

from __future__ import annotations

from typing import Any

import pytest

from auth_harness import AuthHarness
from roxy.admin.auth import flow, routes, sessions, totp, transactions, users

API = "/admin/api/v1/auth"


def _enroll_elsewhere(harness: AuthHarness, user_id: int) -> bytes:
    """Store an authenticator for `user_id` directly (what an enrollment on another worker leaves behind)."""
    blob = harness.cipher.encrypt(totp.new_secret(), totp.user_context(user_id))
    harness.ctx.dbs.control.write_sync(lambda conn: users.store_totp(conn, user_id, blob, "[]"))
    return blob


def _stored_totp(harness: AuthHarness, user_id: int) -> bytes:
    row = harness.ctx.dbs.control.read_sync(
        lambda conn: conn.execute("SELECT totp_secret_enc FROM admin_users WHERE id = ?", (user_id,)).fetchone()
    )
    return bytes(row[0])


def _audit_reasons(harness: AuthHarness) -> list[str]:
    rows = harness.ctx.dbs.control.read_sync(
        lambda conn: conn.execute("SELECT reason FROM audit_log WHERE action = 'auth.mfa_failed'").fetchall()
    )
    return [str(row[0]) for row in rows]


def _session_levels(harness: AuthHarness, user_id: int) -> list[str]:
    rows = harness.ctx.dbs.control.read_sync(
        lambda conn: conn.execute("SELECT mfa_level FROM admin_sessions WHERE user_id = ?", (user_id,)).fetchall()
    )
    return sorted(str(row[0]) for row in rows)


async def _bootstrap_session(harness: AuthHarness, admin: Any, client: Any) -> None:
    started = await harness.password_step(admin, client=client)
    assert started.status_code == 200, started.text
    code = harness.mail.bodies("Admin 2FA")[-1].strip()
    opened = await harness.mfa(started.json()["Transaction"], "email", code=code, client=client)
    assert opened.status_code == 200, opened.text
    assert opened.json()["MfaLevel"] == "bootstrap"


async def test_a_pending_bootstrap_login_neither_resends_nor_finishes_after_enrollment(harness: AuthHarness) -> None:
    admin = harness.admin(with_totp=False, bootstrap=True, email="owner@example.invalid")
    resend_tx = (await harness.password_step(admin)).json()["Transaction"]
    finish_tx = (await harness.password_step(admin)).json()["Transaction"]
    code = harness.mail.bodies("Admin 2FA")[-1].strip()
    _enroll_elsewhere(harness, admin.id)

    harness.clock.advance(31)  # past the resend interval: only the closed bootstrap can refuse it
    resend = await harness.http.post(f"{API}/mfa/email", json={"transaction": resend_tx}, headers=harness.headers())
    assert resend.status_code == 403
    assert resend.json() == flow.START_AGAIN_TEXT
    assert len(harness.mail.bodies("Admin 2FA")) == 2  # no new code was mailed

    late = await harness.mfa(finish_tx, "email", code=code)
    assert late.status_code == 404
    assert late.text == '"Not Found"\n'  # the uniform second factor failure
    assert "set-cookie" not in late.headers
    assert _session_levels(harness, admin.id) == []
    assert flow.BOOTSTRAP_CLOSED_REASON in _audit_reasons(harness)


async def test_the_session_write_asks_the_account_again(harness: AuthHarness, monkeypatch: pytest.MonkeyPatch) -> None:
    """The enrollment may commit between `mfa` reading the account and the session being created: the write that
    creates the session reads `mfa_bootstrap_pending` and the secret itself (control.db writes are serialized)."""
    admin = harness.admin(with_totp=False, bootstrap=True, email="owner@example.invalid")
    tx = (await harness.password_step(admin)).json()["Transaction"]
    code = harness.mail.bodies("Admin 2FA")[-1].strip()
    _enroll_elsewhere(harness, admin.id)
    # `mfa` read the account before the enrollment committed (its early check sees the old state).
    monkeypatch.setattr(users.AdminUser, "bootstrap_open", property(lambda self: True))

    late = await harness.mfa(tx, "email", code=code)
    assert late.status_code == 404
    assert "set-cookie" not in late.headers
    assert _session_levels(harness, admin.id) == []
    assert flow.BOOTSTRAP_CLOSED_REASON in _audit_reasons(harness)


async def test_enrollment_ends_every_other_bootstrap_session_and_login(harness: AuthHarness) -> None:
    admin = harness.admin(with_totp=False, bootstrap=True, email="owner@example.invalid")
    other_browser = harness.new_client()
    await _bootstrap_session(harness, admin, other_browser)
    pending = (await harness.password_step(admin, client=harness.new_client(), ip="198.51.100.9")).json()
    await _bootstrap_session(harness, admin, harness.http)
    assert _session_levels(harness, admin.id) == ["bootstrap", "bootstrap"]

    secret = (await harness.post(f"{API}/totp/enroll/start")).json()["Secret"]
    harness.clock.advance(totp.TOTP_STEP_S)
    confirmed = await harness.post(f"{API}/totp/enroll/confirm", {"code": totp.code_at(secret, harness.clock.now())})
    assert confirmed.status_code == 200, confirmed.text

    assert _session_levels(harness, admin.id) == ["totp"]  # the other browser's bootstrap session is gone
    leftover = await other_browser.get(f"{API}/session", headers=harness.headers())
    assert leftover.status_code == 401
    name = transactions.LOGIN_TX + transactions.token_hash(pending["Transaction"])
    found = harness.ctx.dbs.hot.read_sync(lambda conn: transactions.get_any(conn, name))
    assert found is None  # the pending bootstrap login was deleted with the enrollment


async def test_a_leftover_bootstrap_session_cannot_enroll_over_an_authenticator(
    harness: AuthHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    admin = harness.admin(with_totp=False, bootstrap=True, email="owner@example.invalid")
    other_browser = harness.new_client()
    await _bootstrap_session(harness, admin, other_browser)
    stored = _enroll_elsewhere(harness, admin.id)  # enrolled on another worker; this session was not ended yet

    refused = await harness.post(f"{API}/totp/enroll/start", client=other_browser)
    assert refused.status_code == 403
    assert refused.headers["Roxy-Reauth"] == "required"

    # Even past the route guard (a request that passed it just before the enrollment committed), the enrollment
    # write itself refuses.
    async def let_through(request: Any, record: sessions.SessionRecord) -> None:
        return None

    monkeypatch.setattr(routes, "_require_enroll_rights", let_through)
    secret = (await harness.post(f"{API}/totp/enroll/start", client=other_browser)).json()["Secret"]
    harness.clock.advance(totp.TOTP_STEP_S)
    code = totp.code_at(secret, harness.clock.now())
    confirm = await harness.post(f"{API}/totp/enroll/confirm", {"code": code}, client=other_browser)
    assert confirm.status_code == 404
    assert _stored_totp(harness, admin.id) == stored


def test_delete_bootstrap_logins_takes_only_that_accounts_bootstrap_transactions(dbs: Any) -> None:
    rows = {
        "a": {"uid": 1, "bootstrap": True},
        "b": {"uid": 1, "bootstrap": False},
        "c": {"uid": 2, "bootstrap": True},
    }

    def seed(conn: Any) -> None:
        for key, payload in rows.items():
            transactions.put(conn, transactions.LOGIN_TX + key, payload, 10**15)
        transactions.put(conn, transactions.ENROLL + "a", {"uid": 1, "bootstrap": True}, 10**15)

    dbs.hot.write_sync(seed)
    assert dbs.hot.write_sync(lambda conn: transactions.delete_bootstrap_logins(conn, 1)) == 1
    left = dbs.hot.read_sync(lambda conn: [row[0] for row in conn.execute("SELECT name FROM lease ORDER BY name")])
    assert left == [transactions.ENROLL + "a", transactions.LOGIN_TX + "b", transactions.LOGIN_TX + "c"]
