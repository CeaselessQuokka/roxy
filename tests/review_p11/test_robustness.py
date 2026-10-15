"""P11 review, lens "robustness and resource use on a 1 GB server": reproductions of the findings.

What this is
    One test per confirmed finding of `.remake/p11_review/find_robustness.md` (ids `robust-<n>`). Each was marked
    `xfail(strict=True)` until the P11 review round fixed it; each is a regression test now, so a later change that
    brings one back shows up at once. The refuted robust-1 (a JSON 503 while control.db's write lock is held: plan
    C7's refusal) and robust-4 (FastAPI's 422 on the shell's own fetch routes, outside the section 13 API) have no
    test here; robust-6 is authz-4's duplicate and stays as a regression test. The tests drive the real app in
    process with the dashboard page fixtures (`tests/integration/pages/conftest.py`: `pages_app`, `page`), and reach
    into the event stream (`roxy.admin.sse`) the way a slow browser would: one frame at a time.

Why it exists
    The adversarial review of the P11 dashboard pages (robustness lens) looked at every page and fragment under
    hostile and extreme parameters, empty, busy and failing databases, many tabs and a slow event stream reader. The
    parameter sweep itself found the kit sound; these are the places where a page still fails, blames the wrong
    thing, or keeps talking to a session that is gone.

How it works
    A failing read is a read model replaced by one that raises `sqlite3.DatabaseError` (or an I/O error). The slow
    stream reader is the stream's own async generator advanced by hand.

What to read next
    `.remake/p11_review/find_robustness.md`, `roxy/admin/pages/kit.py`, `roxy/admin/pages/shell.py`,
    `roxy/admin/auth/deps.py` (`require_admin`), `roxy/admin/sse.py` (`Stream.run`).
"""

from __future__ import annotations

import asyncio
import sqlite3
from typing import Any

import pytest
from starlette.requests import Request

from integration.pages.conftest import page, page_admin, pages_app  # noqa: F401  (the page fixtures)
from pages_harness import parse_html
from roxy.admin import sse
from roxy.admin.auth import sessions
from roxy.admin.auth.deps import AdminPrincipal
from roxy.insights import read_recommendations
from roxy.metrics import queries
from roxy.metrics.live import LIVE_EVENT, TailItem


def _broken(*_args: Any, **_kwargs: Any) -> Any:
    raise sqlite3.DatabaseError("database disk image is malformed")


# ============================================================================================ robust-2


# Fixed in the P11 review round (robust-2, shared fixer): a regression test now.
async def test_robust_2_a_failing_shell_read_leaves_the_pages_up(
    page: Any,  # noqa: F811
    pages_app: Any,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The bell counts: one metrics.db read every page's shell makes before any card renders.
    monkeypatch.setattr(read_recommendations, "facets", _broken)
    for page_id in ("overview", "data", "system", "help"):
        response = await page.get(f"/admin/{page_id}")
        # Today: 500 `"Internal Server Error"`, even on Data and System, where the admin goes to repair storage.
        assert response.status_code == 200, (page_id, response.status_code, response.text[:120])
        assert response.headers["content-type"].startswith("text/html")
    monkeypatch.undo()
    # A fragment with range=all reads the earliest data time in `Page.view`, outside the card's error handling.
    monkeypatch.setattr(queries, "earliest_data", _broken)
    for page_id, card_id in (("audit", "log"), ("traffic", "requests"), ("system", "errors")):
        response = await page.fragment(page_id, card_id, range="all")
        assert response.status_code == 200, (page_id, card_id, response.status_code, response.text[:120])


# ============================================================================================ robust-3


# Fixed (fixer g1): the history card passes the window as clamped numbers (health_api.window_filter), never as text.
async def test_robust_3_health_history_survives_a_custom_range_at_the_epoch(
    page: Any,  # noqa: F811
    pages_app: Any,  # noqa: F811
) -> None:
    await pages_app.settings(ui_timezone="America/New_York")  # the catalog default, set explicitly
    ranges = (
        {"range": "custom", "from": "1", "to": "2", "granularity": "month"},  # buckets start Dec 1969 in New York
        {"range": "custom", "from": "0", "to": "4102444800"},  # 1970 to 2100: the API's own bounds
    )
    for params in ranges:
        whole = await page.get("/admin/health", params=params)
        assert whole.status_code == 200
        assert "The time range in the address was not valid" not in whole.text  # the shell accepts this range
        history = parse_html(whole.text).select_one("section#history")
        assert history is not None
        # Today: "The run filter is not valid." in place of the run history (its own fallback raises again).
        assert parse_html(whole.text).select_one("section#history[data-card-error]") is None, history.text()[:200]
        fragment = await page.fragment("health", "history", **params)
        assert fragment.status_code == 200
        assert "data-card-error" not in fragment.text, parse_html(fragment.text).text()[:200]


# ============================================================================================ robust-5


def _live_item(event_id: int) -> TailItem:
    detail = {"ip": "203.0.113.7", "url": f"/v1/users/{event_id}", "status": 200, "outcome": "served_upstream"}
    return TailItem(event_id, 1_791_691_980_000, LIVE_EVENT, "info", None, "/v1/users/{id}", detail)


async def _open_stream(pages_app: Any, page: Any) -> tuple[Any, str]:  # noqa: F811
    """The event stream route called as the browser's request would reach it; returns (frames, session hash)."""
    token = page.http.cookies.get(sessions.SESSION_COOKIE)
    assert token, "the page fixture is signed in"
    id_hash = sessions.hash_token(token)
    found = await pages_app.ctx.dbs.control.read(lambda conn: sessions.load(conn, id_hash))
    assert found is not None
    record = found[0]
    principal = AdminPrincipal(
        user_id=record.user_id,
        username=record.username,
        session_id=record.id_hash,
        mfa_level=record.mfa_level,
        mfa_at=record.created_at,
        ip="127.0.0.1",
        ua="robustness review",
    )
    scope = {
        "type": "http",
        "app": pages_app.app,
        "method": "GET",
        "scheme": "https",
        "path": "/admin/api/v1/stream",
        "raw_path": b"/admin/api/v1/stream",
        "root_path": "",
        "query_string": b"events=live",
        "headers": [(b"cookie", f"{sessions.SESSION_COOKIE}={token}".encode())],
        "client": ("127.0.0.1", 50000),
        "server": ("testserver", 443),
        "state": {},
    }
    response = await sse.stream(
        Request(scope),
        principal,
        events="live",
        outcome=None,
        reason=None,
        status=None,
        egress=None,
        cache=None,
        client=None,
        endpoint=None,
        q=None,
        last_event_id=None,
        last_event_id_header=None,
    )
    return response.body_iterator, id_hash


# Fixed in the P11 review round (robust-5, shared fixer): a regression test now.
async def test_robust_5_a_stalled_stream_sends_nothing_after_its_session_is_revoked(
    page: Any,  # noqa: F811
    pages_app: Any,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sse, "SESSION_CHECK_S", 0.2)  # the 5 s re-check, shortened so the test waits 0.3 s
    frames, id_hash = await _open_stream(pages_app, page)
    try:
        assert (await frames.__anext__()).startswith(b"retry:")
        subscription = pages_app.ctx.live_tail._subs[-1]  # this stream's subscription (the newest)
        for event_id in range(1, 6):
            subscription.offer(_live_item(event_id))
        first = b""
        for _ in range(20):  # kpi or cooldown frames may come first
            first = await frames.__anext__()
            if first.startswith(b"id: ") and b"event: live" in first:
                break
        assert b"event: live" in first, first[:200]
        # The browser stops reading here (a slow network, a suspended laptop, a stolen cookie in a script). The
        # owner revokes the session (the kill switch) and traffic goes on.
        await asyncio.sleep(0.3)
        await pages_app.ctx.dbs.control.write(lambda conn: sessions.revoke(conn, id_hash))
        for event_id in range(6, 66):
            subscription.offer(_live_item(event_id))
        after: list[bytes] = []
        for _ in range(250):
            try:
                data = await frames.__anext__()
            except StopAsyncIteration:
                break
            after.append(data)
            if b"event: unauthorized" in data:
                break
    finally:
        await frames.aclose()
    live_after = [data for data in after if b"event: live" in data]
    assert any(b"event: unauthorized" in data for data in after), after[-3:]
    # Today: dozens of live rows (client addresses, paths) go out after the revocation, up to DRAIN_PER_TICK (200)
    # minus the rate gate's sampling, because the drain loop forwards the queue before the loop top re-checks.
    assert len(live_after) <= 1, f"{len(live_after)} live rows after the session was revoked"


# ============================================================================================ robust-6


def _io_error(*_args: Any, **_kwargs: Any) -> Any:
    raise sqlite3.OperationalError("disk I/O error")


# Refuted as a duplicate of authz-4 (same root cause in Stream._session_alive and Stream.run); fixed there in the P11
# review round (shared fixer: the stream's session check fails open), so this is a regression test now.
async def test_robust_6_a_control_db_read_outage_never_signs_the_stream_out(
    page: Any,  # noqa: F811
    pages_app: Any,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sse, "SESSION_CHECK_S", 0.05)  # the 5 s re-check, shortened (three checks in about 0.75 s)
    frames, _id_hash = await _open_stream(pages_app, page)
    seen: list[bytes] = []
    try:
        assert (await frames.__anext__()).startswith(b"retry:")
        # control.db cannot be read for a while (an I/O error, a full read queue): `load_session` raises the C7 503.
        monkeypatch.setattr(sessions, "load", _io_error)
        loop = asyncio.get_running_loop()
        ends = loop.time() + 3.0
        while loop.time() < ends:
            try:
                data = await asyncio.wait_for(frames.__anext__(), timeout=max(0.1, ends - loop.time()))
            except (StopAsyncIteration, TimeoutError):
                break  # the stream ended (the reconnect decides) or is still waiting: both keep the admin signed in
            seen.append(data)
            if b"event: unauthorized" in data:
                break
    finally:
        await frames.aclose()
    # Today: `event: unauthorized` with {"status": 401, "message": "Session expired"}; `static/js/sse.js` then stops
    # for good and raises the session-expired overlay on a session that is still valid.
    assert not any(b"event: unauthorized" in data for data in seen), seen[-2:]
