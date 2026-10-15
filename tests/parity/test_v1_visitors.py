"""v1 parity: the Admin Page Visits counter counts anonymous visits to the login page and skips the owner.

What this is
    Ports of the v1 smoke checks of sections S009 ("Admin-visit counting skips known admin browsers") and S029
    ("Admin page-visit counter works for anonymous GET /admin"): lines 440, 445, 446 and 967.

Why it exists
    The Overview "Visitors" card (parity rows 19 and 130) keeps v1's tiles, Admin Page Visits among them. v1 counted
    one admin page visit for every `GET /admin` from a browser without the `roxy_admin_seen` cookie, set that cookie
    at login, and so never counted the owner's own visits.

How it works
    A fresh client and a client carrying `roxy_admin_seen=1` load `/admin`; the recorder is flushed and the visitor
    read model (`metrics.queries.visitor_kpis`, the same numbers `GET /admin/api/v1/overview/visitors` shows) is
    read for the last hour. The login check reads the `Set-Cookie` header of the real login answer.

What to read next
    `roxy/metrics/visitors.py` (the page names and the -1 correction), `roxy/admin/auth/routes.py` (`login_page`,
    `set_admin_seen_cookie`) and `roxy/metrics/queries.py` (`visitor_kpis`).
"""

from __future__ import annotations

from typing import Any

from roxy.metrics import queries

ADMIN_SEEN = "roxy_admin_seen"
ADMIN_COUNTED = "roxy_admin_counted"


async def visits(parity: Any) -> dict[str, int]:
    """The visitor tiles for the last hour, after closing the current minute (visits are summed per minute)."""
    parity.clock.advance(61)
    await parity.ctx.recorder.flush()
    now = int(parity.clock.now())
    window = queries.Window(start=now - 3600, end=now + 60, granularity="minute")
    counts: dict[str, int] = await parity.ctx.dbs.metrics.read(lambda conn: queries.visitor_kpis(conn, window))
    return counts


async def admin_visits(parity: Any) -> int:
    return int((await visits(parity))["admin_visits"])


async def test_v1_control_home_page_visits_reach_the_same_read_model(parity: Any) -> None:
    """Control for the admin visit tests below: the measurement works, a visit of `/` is counted by the same read
    model (v1 smoke line 129 counted home page visits too)."""
    before = (await visits(parity))["home_visits"]
    assert (await parity.http.get("/", headers=parity.harness.headers())).status_code == 200
    assert (await visits(parity))["home_visits"] == before + 1


async def test_v1_anonymous_admin_page_visits_are_counted_and_known_admins_are_not(parity: Any) -> None:
    """v1 smoke lines 440, 445 and 967 (finding parity-3, fixed): a fresh browser loading /admin adds exactly 1, a
    browser with the `roxy_admin_seen` cookie adds nothing."""
    before = await admin_visits(parity)
    fresh = parity.harness.new_client()
    assert (await fresh.get("/admin", headers=parity.harness.headers())).status_code == 200
    assert await admin_visits(parity) == before + 1
    known = parity.harness.new_client()
    # Sent as a header: the standard cookie jar never sends a cookie set by hand for a dotless host like
    # `testserver` (it matches such hosts as `testserver.local`), so `cookies.set(..., domain=...)` sent nothing.
    seen = {**parity.harness.headers(), "Cookie": f"{ADMIN_SEEN}=1"}
    page = await known.get("/admin", headers=seen)
    assert page.status_code == 200
    assert ADMIN_COUNTED not in page.headers.get("set-cookie", "")  # a known admin's visit is not marked either
    assert await admin_visits(parity) == before + 1


async def test_v1_the_owners_first_login_takes_back_its_own_admin_page_visit(parity: Any) -> None:
    """v1 `_complete_login` (`decrement_admin_visit`, smoke line 445): a browser without `roxy_admin_seen` loads
    /admin (+1) and signs in (-1, it was the owner); once signed in, /admin redirects and counts nothing, and a later
    login from that browser (it now has the cookie) takes nothing back."""
    account = parity.harness.admin(username="visitor_owner")
    before = await admin_visits(parity)
    browser = parity.harness.new_client()
    assert (await browser.get("/admin", headers=parity.harness.headers())).status_code == 200
    assert await admin_visits(parity) == before + 1
    assert (await parity.harness.login(account, client=browser)).status_code == 200
    assert browser.cookies.get(ADMIN_SEEN) == "1"
    assert await admin_visits(parity) == before
    assert browser.cookies.get(ADMIN_COUNTED) is None  # taken back once, then the marker is gone
    assert (await browser.get("/admin", headers=parity.harness.headers())).status_code == 302  # signed in
    assert (await parity.harness.login(account, client=browser)).status_code == 200  # a known browser
    assert await admin_visits(parity) == before


async def test_a_login_that_never_loaded_the_page_takes_no_visit_back(parity: Any) -> None:
    """v2 refinement of v1's decrement (finding parity-3): v1 clamped its lifetime counter at zero when it took the
    owner's visit back; v2 sums per minute, so only a visit this browser made is taken back (`roxy_admin_counted`).
    A stranger's visit stays counted when someone signs in without loading the page (a script, the API)."""
    before = await admin_visits(parity)
    stranger = parity.harness.new_client()
    page = await stranger.get("/admin", headers=parity.harness.headers())
    assert page.status_code == 200
    marker = [value for name, value in page.headers.multi_items() if name == "set-cookie" and ADMIN_COUNTED in value]
    assert marker, page.headers
    assert all(flag in marker[0].lower() for flag in ("secure", "httponly", "samesite=strict", "path=/admin"))
    account = parity.harness.admin(username="script_owner")
    assert (await parity.harness.login(account, client=parity.harness.new_client())).status_code == 200
    assert await admin_visits(parity) == before + 1


async def test_v1_login_marks_the_browser_as_a_known_admin(parity: Any) -> None:
    """v1 smoke line 446: a successful login sets `roxy_admin_seen=1` (long lived), so later visits are skipped."""
    account = parity.harness.admin(username="seen")
    client = parity.harness.new_client()
    response = await parity.harness.login(account, client=client)
    assert response.status_code == 200, response.text
    cookies = [value for name, value in response.headers.multi_items() if name == "set-cookie"]
    seen = [value for value in cookies if value.startswith(f"{ADMIN_SEEN}=1")]
    assert seen, cookies
    assert "max-age=" in seen[0].lower()
    assert client.cookies.get(ADMIN_SEEN) == "1"
