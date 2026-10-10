"""Review round 4 (lens secfix): the admin sign-in steps the C7 test of round 3 does not drive, while state refuses.

What this is
    Variants of `tests/security/test_auth_c7_unavailable.py` (the docs lane's C7 test, which drives the login page,
    the password step and the TOTP step): a recovery code as the second factor, re-authentication of a live session
    (`POST /admin/api/v1/auth/reauth`), the session read, the heartbeat and sign-out, each while control.db or
    hot.db refuses every read or every write.

Why it exists
    Plan C7: "admin login is refused with a clear message" when shared state cannot be read or written. Each of
    these steps must answer its normal answer or the C7 503, never the unhandled 500 (which also mails the owner a
    "Roxy Error" alert), and a second factor step that failed must issue no session.

How it works
    The real app (`auth_harness`), one admin signed in on one client and a second client half way through a login
    (password step done). Then one database's `read` or `write` is replaced by a function that raises
    `SharedStateUnavailable` at once (as a full queue, an open busy circuit or an I/O error does) and each step is
    driven. Passing today; a regression test for the C7 rule on these routes.

What to read next
    `src/roxy/admin/auth/flow.py` (`_db`, `UNAVAILABLE_TEXT`), `src/roxy/admin/auth/routes.py`,
    `tests/security/test_auth_c7_unavailable.py`.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from roxy.admin.auth.testing import AuthHarness, auth_harness
from roxy.core.clock import FakeClock
from roxy.storage.db import SharedStateUnavailable

API = "/admin/api/v1/auth"
SESSION_COOKIE = "__Host-roxy_session"
NEVER = frozenset({500, 502, 504})


@pytest.fixture
async def harness(env: Any, fake_clock: FakeClock, credentials_dir: Path) -> AsyncIterator[AuthHarness]:
    async with auth_harness(env, clock=fake_clock, credentials_dir=credentials_dir) as running:
        yield running


def refuse(db: Any, kind: str, monkeypatch: pytest.MonkeyPatch) -> None:
    async def unavailable(*args: Any, **kwargs: Any) -> Any:
        raise SharedStateUnavailable(db.name, "simulated: database is locked")

    monkeypatch.setattr(db, kind, unavailable)


@pytest.mark.parametrize("database", ["control", "hot"])
@pytest.mark.parametrize("kind", ["read", "write"])
async def test_other_sign_in_steps_never_answer_500_when_a_database_refuses(
    harness: AuthHarness, monkeypatch: pytest.MonkeyPatch, database: str, kind: str
) -> None:
    admin = harness.admin()
    signed = await harness.login(admin, ip="203.0.113.9")
    assert signed.status_code == 200, signed.text
    token = await harness.csrf(ip="203.0.113.9")
    other = harness.new_client()
    first = await harness.password_step(admin, client=other, ip="203.0.113.10")
    transaction = first.json()["Transaction"]
    db = getattr(harness.ctx.dbs, database)
    codes: dict[str, int] = {}
    with monkeypatch.context() as patch:
        refuse(db, kind, patch)
        recovery = await harness.mfa(
            transaction, "recovery", code=admin.recovery_codes[0], client=other, ip="203.0.113.10"
        )
        codes["recovery"] = recovery.status_code
        headers = harness.headers(ip="203.0.113.9", csrf=token)
        codes["session"] = (await harness.http.get(f"{API}/session", headers=headers)).status_code
        codes["heartbeat"] = (await harness.http.post(f"{API}/heartbeat", json={}, headers=headers)).status_code
        code = harness.next_code(admin)
        codes["reauth"] = (
            await harness.http.post(f"{API}/reauth", json={"method": "totp", "code": code}, headers=headers)
        ).status_code
        codes["logout"] = (await harness.http.post(f"{API}/logout", json={}, headers=headers)).status_code
    assert not NEVER.intersection(codes.values()), codes
    if codes["recovery"] != 200:
        assert codes["recovery"] == 503, codes
        assert other.cookies.get(SESSION_COOKIE) is None  # a refused second factor issues no session
