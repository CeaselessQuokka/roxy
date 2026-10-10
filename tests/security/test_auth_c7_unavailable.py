"""Admin login fails closed and fast when its shared state is locked or busy (plan C7, docs lane request 4).

What this is
    Tests of the C7 rule for admin login: "if shared state cannot be read or written ... admin login is refused with
    a clear message". Every step of a login (the login page, the password step, the second factor step) is driven
    through the real app while control.db or hot.db is locked by another process, busy, or refusing every call.

Why it exists
    The login flow converts `SharedStateUnavailable` into a 503 with `UNAVAILABLE_TEXT` (`flow.AuthService._db`),
    but nothing proved it end to end: that the answer is a 503 and never a 500, that it comes within one SQLite
    busy timeout and not after a pile of queued waits, that no session cookie is issued by a step that failed, and
    that the login works again once the lock is gone. `docs/SECURITY.md` listed this as a known gap.

How it works
    - A real lock: a second SQLite connection (another process, as far as the app can tell) holds `BEGIN
      EXCLUSIVE` on the file, so the app's writer waits `busy_timeout` and gives up (`storage/db.py`). The first
      test keeps the production 5 s timeout to measure "promptly" against the real setting; the others lower the
      profile's timeout to keep the suite fast (the same code path).
    - A refusing database: `Database.read` or `Database.write` replaced for the duration of a test by a function
      that raises `SharedStateUnavailable` at once, as a full queue, an open busy circuit or an I/O error does.
    The harness (`roxy.admin.auth.testing.auth_harness`) is the real app with its lifespan, a fast hasher and a
    fake clock. Elapsed times are measured with `time.monotonic()` (the WSL wall clock steps back).

What to read next
    `src/roxy/admin/auth/flow.py` (`_db`, `unavailable`, `UNAVAILABLE_TEXT`), `src/roxy/storage/db.py` (busy
    timeout, busy circuit), `tests/security/test_auth_lockout.py`.
"""

from __future__ import annotations

import asyncio
import dataclasses
import sqlite3
import time
from collections.abc import AsyncIterator, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from roxy.admin.auth.flow import UNAVAILABLE_TEXT
from roxy.admin.auth.testing import AuthHarness, auth_harness
from roxy.core.clock import FakeClock
from roxy.storage.db import BUSY_CIRCUIT_COOLDOWN_S, BUSY_TIMEOUT_MS, SharedStateUnavailable

SESSION_COOKIE = "__Host-roxy_session"
MARGIN_S = 2.5  # scheduling slack on a loaded WSL test box; far below any request deadline


@pytest.fixture
async def harness(env: Any, fake_clock: FakeClock, credentials_dir: Path) -> AsyncIterator[AuthHarness]:
    async with auth_harness(env, clock=fake_clock, credentials_dir=credentials_dir) as running:
        yield running


@contextmanager
def write_lock_held(path: Path) -> Iterator[None]:
    """Another connection holds the database's write lock (what a long write in another worker does)."""
    conn = sqlite3.connect(path, timeout=5.0, isolation_level=None)
    try:
        conn.execute("BEGIN EXCLUSIVE")
        yield
    finally:
        conn.execute("ROLLBACK")
        conn.close()


def short_busy_timeout(db: Any, monkeypatch: pytest.MonkeyPatch, ms: int = 200) -> None:
    """The same busy path with a shorter SQLite busy timeout (the writer reads the profile on every job)."""
    monkeypatch.setattr(db, "profile", dataclasses.replace(db.profile, busy_timeout_ms=ms))


def refuse(db: Any, kind: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Every `db.read` or `db.write` raises `SharedStateUnavailable` at once."""

    async def unavailable(*args: Any, **kwargs: Any) -> Any:
        raise SharedStateUnavailable(db.name, "simulated: database is locked")

    monkeypatch.setattr(db, kind, unavailable)


def assert_unavailable(response: Any) -> None:
    assert response.status_code == 503, response.text
    assert response.json() == UNAVAILABLE_TEXT
    assert response.headers["retry-after"] == "5"
    assert SESSION_COOKIE not in response.headers.get("set-cookie", "")


async def timed(step: Any) -> tuple[Any, float]:
    started = time.monotonic()
    response = await step
    return response, time.monotonic() - started


async def test_login_answers_503_within_one_busy_timeout_while_hot_db_is_locked(harness: AuthHarness) -> None:
    """Production busy timeout (5 s): the password step's lockout write gives up and answers the C7 503 within one
    busy timeout; the next attempt answers at once (the busy circuit); once the lock is gone the login works."""
    admin = harness.admin()
    with write_lock_held(harness.ctx.env.hot_db):
        first, first_s = await timed(harness.password_step(admin, ip="203.0.113.7"))
        second, second_s = await timed(harness.password_step(admin, ip="203.0.113.7"))
    assert_unavailable(first)
    assert first_s < BUSY_TIMEOUT_MS / 1000 + MARGIN_S, first_s
    assert_unavailable(second)
    assert second_s < 1.0, second_s  # the busy circuit: no second 5 s wait behind the same lock
    await asyncio.sleep(BUSY_CIRCUIT_COOLDOWN_S + 0.2)  # real time: the circuit uses the monotonic clock
    response = await harness.login(admin, ip="203.0.113.7")
    assert response.status_code == 200, response.text
    assert SESSION_COOKIE in response.headers.get("set-cookie", "")


async def test_second_factor_step_answers_503_while_control_db_is_locked(
    harness: AuthHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The password step needs no control.db write; the second factor step creates the session there. With
    control.db locked it answers the C7 503 promptly and sets no session cookie."""
    admin = harness.admin()
    short_busy_timeout(harness.ctx.dbs.control, monkeypatch)
    first = await harness.password_step(admin, ip="203.0.113.8")
    assert first.status_code == 200, first.text
    transaction = first.json()["Transaction"]
    with write_lock_held(harness.ctx.env.control_db):
        response, elapsed = await timed(
            harness.mfa(transaction, "totp", code=harness.next_code(admin), ip="203.0.113.8")
        )
    assert_unavailable(response)
    assert elapsed < 0.2 + MARGIN_S, elapsed
    assert harness.http.cookies.get(SESSION_COOKIE) is None
    await asyncio.sleep(BUSY_CIRCUIT_COOLDOWN_S + 0.2)
    again = await harness.login(admin, ip="203.0.113.8")  # the owner starts again and gets in
    assert again.status_code == 200, again.text


@pytest.mark.parametrize(
    ("database", "kind", "expected"),
    [
        ("hot", "write", [503]),  # the lockout count of the password step
        ("control", "read", [503]),  # the account lookup of the password step
        ("control", "write", [200, 503]),  # the session the second factor step creates
        ("hot", "read", [200, 200]),  # control: no login step reads hot.db outside a write
    ],
)
async def test_no_login_step_ever_answers_500_when_a_database_refuses(
    harness: AuthHarness, monkeypatch: pytest.MonkeyPatch, database: str, kind: str, expected: list[int]
) -> None:
    """Whichever database refuses reads or writes, every login step answers its normal answer or the C7 503 (never a
    500, never a session from a step that failed), and the login page itself still loads."""
    admin = harness.admin()
    db = getattr(harness.ctx.dbs, database)
    with monkeypatch.context() as patch:
        refuse(db, kind, patch)
        page = await harness.http.get("/admin", headers=harness.headers(ip="203.0.113.9"))
        assert page.status_code == 200, page.text  # the page loads; the login step explains the problem
        responses = [await harness.password_step(admin, ip="203.0.113.9")]
        if responses[0].status_code == 200:
            transaction = responses[0].json()["Transaction"]
            responses.append(await harness.mfa(transaction, "totp", code=harness.next_code(admin), ip="203.0.113.9"))
    assert [response.status_code for response in responses] == expected
    if expected[-1] == 503:
        assert_unavailable(responses[-1])
        assert harness.http.cookies.get(SESSION_COOKIE) is None
    else:
        assert harness.http.cookies.get(SESSION_COOKIE)
