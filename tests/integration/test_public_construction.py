"""Pages under construction end to end: the real app, the real sign-in, the real settings service.

What this is
    Integration tests for the switches `public_home_under_construction`, `public_docs_under_construction` and
    `public_status_under_construction` and the message `site_construction_text` (owner request, 2026-10-15): each
    page in each state (switch off; on for a visitor; on for a signed-in admin; on for an admin asking for the public
    view), every way an admin view must end (sign-out, kill switch, idle and absolute expiry, a forged cookie, a
    first-login session, the D6 allowlist, a foreign Origin), what must never change (the proxy, /health, robots.txt,
    the favicon, static files, /admin, the 405 on POST / and the 308 aliases), the sitemap, the message, session use,
    and the audit trail of a change made through the settings API.

Why it exists
    The owner reviews pages while the public sees an "under construction" page. A mistake here either shows the
    public a page the owner took down, or shows the owner the wrong page without saying so; both are checked on the
    HTML and headers a browser really receives.

How it works
    `auth_harness` (tests/auth_harness.py) starts `create_app` with its lifespan on temporary databases, the fast
    password hasher and a `FakeClock`, and signs an admin in through the real password and TOTP steps; its client
    talks https to the app in process, so the `Secure` session cookie round-trips. Visitors use their own clients
    (their own cookie jars). Settings change through the real `SettingsService`, or through the settings API as the
    dashboard does.

What to read next
    `roxy/public/construction.py`, `roxy/public/pages.py`, `roxy/templates/public/construction.html`,
    tests/unit/public/test_public_construction_logic.py and tests/e2e/test_public_construction_e2e.py.
"""

from __future__ import annotations

import re
import secrets
import sqlite3
import xml.etree.ElementTree as ElementTree
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from markupsafe import escape

from auth_harness import AuthHarness, TestAdmin, auth_harness
from roxy.admin.auth import sessions
from roxy.core.clock import FakeClock
from roxy.public import construction, pages

PATHS = ("/", "/docs", "/status")
SWITCHES = {
    "/": "public_home_under_construction",
    "/docs": "public_docs_under_construction",
    "/status": "public_status_under_construction",
}
REAL_PAGE = {
    "/": 'id="getExampleHeading"',  # the home page's quick start
    "/docs": '<nav class="toc" aria-label="Contents">',  # the guide's contents
    "/status": 'class="status-banner state-',  # the status banner
}
TITLES = {"/": "Roxy's home page", "/docs": "Roxy's user guide", "/status": "Roxy's status page"}
BANNER = "the public currently sees the under-construction page for this page."
NOTICE = "You are viewing this page as the public sees it."
DEFAULT_MESSAGE = "Roxy's site is being updated. Check back soon."
SESSION = sessions.SESSION_COOKIE
NAVIGATION = {"Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1", "Sec-Fetch-Site": "same-origin"}
FIXTURE_ROBOTS = Path(__file__).resolve().parents[1] / "fixtures" / "v1" / "robots.txt"


@pytest.fixture
async def harness(env: Any, fake_clock: FakeClock, credentials_dir: Path) -> AsyncIterator[AuthHarness]:
    async with auth_harness(env, clock=fake_clock, credentials_dir=credentials_dir) as running:
        yield running


async def sign_in(harness: AuthHarness, admin: TestAdmin | None = None) -> str:
    """Sign an admin in on `harness.http` (password and TOTP; a new admin account unless `admin` is given); returns
    the session cookie value."""
    admin = admin or harness.admin()
    response = await harness.login(admin)
    assert response.status_code == 200, response.text
    token = harness.http.cookies.get(SESSION)
    assert token
    return str(token)


def visitor(harness: AuthHarness) -> httpx.AsyncClient:
    """A browser that never signed in (its own cookie jar)."""
    client: httpx.AsyncClient = harness.new_client()
    return client


def assert_public_page(response: httpx.Response, path: str) -> None:
    """The under-construction page exactly as the public gets it."""
    assert response.status_code == 503, (path, response.status_code)
    assert response.headers["retry-after"] == str(construction.RETRY_AFTER_S) == "3600"
    assert response.headers["x-robots-tag"] == "noindex"
    assert response.headers["roxy-under-construction"] == "True"
    assert response.headers["content-type"] == "text/html; charset=utf-8"
    assert "cookie" in response.headers["vary"].lower()
    if response.request.method == "HEAD":
        return
    text = response.text
    title = escape(TITLES[path])  # the template escapes the apostrophe
    assert '<meta name="robots" content="noindex" />' in text
    assert f"<title>Under construction: {title}</title>" in text
    assert f'<h1 id="page-title">{title} is under construction</h1>' in text
    assert REAL_PAGE[path] not in text
    assert "Admins only" not in text
    assert "preview-banner" not in text
    assert "preview-notice" not in text
    assert 'class="previewing"' not in text
    # The strict CSP (plan 9.2): no inline style, every script carries the nonce.
    assert "<style" not in text
    assert not re.search(r"<[a-z]+[^>]* style=", text)
    nonce = re.search(r"'nonce-([^']+)'", response.headers["content-security-policy"])
    assert nonce is not None
    assert f'nonce="{nonce.group(1)}"' in text


def assert_admin_real_page(response: httpx.Response, path: str) -> None:
    """The real page with the admin banner and the admin view's headers."""
    assert response.status_code == 200, (path, response.status_code)
    assert response.headers["cache-control"] == "private, no-store"
    assert "cookie" in response.headers["vary"].lower()
    assert response.headers["x-robots-tag"] == "noindex"
    assert "roxy-under-construction" not in response.headers
    assert "retry-after" not in response.headers
    if response.request.method == "HEAD":
        return
    text = response.text
    assert REAL_PAGE[path] in text
    assert "<strong>Admins only:</strong> " + BANNER in text
    assert f'<a class="button button-primary" href="{path}?view=public">See what the public sees</a>' in text
    assert '<a href="/admin/settings#public-site">Change it in Settings</a>' in text
    assert NOTICE not in text


def without_preview_parts(text: str) -> str:
    """A page without what differs between two answers of the same page: the per-response nonce, and the admin's
    notice and body class (the only additions the admin's public view may have)."""
    text = re.sub(r'nonce="[^"]+"', 'nonce=""', text)
    text = re.sub(r'\s*<aside class="preview-notice".*?</aside>', "", text, flags=re.DOTALL)
    return text.replace('<body class="previewing">', "<body>")


# --- switches off ---------------------------------------------------------------------------------------------------


async def test_switches_off_change_nothing_for_anyone(harness: AuthHarness) -> None:
    anon = visitor(harness)
    for path in PATHS:
        response = await anon.get(path)
        assert response.status_code == 200, path
        assert response.headers["cache-control"] == pages.PAGE_CACHE_CONTROL
        assert "roxy-under-construction" not in response.headers
        assert "x-robots-tag" not in response.headers
        assert REAL_PAGE[path] in response.text
    await sign_in(harness)
    for path in PATHS:
        for params in ({}, {"view": "public"}):
            response = await harness.http.get(path, params=params)
            assert response.status_code == 200, (path, params)
            assert REAL_PAGE[path] in response.text
            assert "Admins only" not in response.text  # no banner while the page is not under construction
            assert NOTICE not in response.text
    sitemap = await anon.get("/sitemap.xml")
    assert sitemap.content == pages.build_sitemap(pages.build_date())


# --- on: the public, the admin, the admin's public view -------------------------------------------------------------


@pytest.mark.parametrize("path", PATHS)
async def test_visitors_get_the_under_construction_page(harness: AuthHarness, path: str) -> None:
    await harness.set_settings(**{SWITCHES[path]: 1})
    anon = visitor(harness)
    response = await anon.get(path)
    assert_public_page(response, path)
    assert response.headers["cache-control"] == "no-store"
    assert f"<p>{DEFAULT_MESSAGE}</p>" in response.text
    assert_public_page(await anon.head(path), path)
    # Only that page: the other two still answer as always.
    for other in PATHS:
        if other != path:
            assert (await anon.get(other)).status_code == 200, other


@pytest.mark.parametrize("path", PATHS)
async def test_the_view_parameter_never_shows_a_visitor_the_real_page(harness: AuthHarness, path: str) -> None:
    await harness.set_settings(**{SWITCHES[path]: 1})
    anon = visitor(harness)
    for params in ({"view": "public"}, {"view": "admin"}, {"view": "real"}, {"preview": "1"}):
        response = await anon.get(path, params=params)
        assert_public_page(response, path)


@pytest.mark.parametrize("path", PATHS)
async def test_a_signed_in_admin_sees_the_real_page_with_the_banner(harness: AuthHarness, path: str) -> None:
    await harness.set_settings(**{SWITCHES[path]: 1})
    await sign_in(harness)
    assert_admin_real_page(await harness.http.get(path), path)
    assert_admin_real_page(await harness.http.head(path), path)
    # The visitor next to the admin still gets the public page.
    assert_public_page(await visitor(harness).get(path), path)


@pytest.mark.parametrize("path", PATHS)
async def test_the_admins_public_view_is_exactly_the_public_page_plus_a_notice(harness: AuthHarness, path: str) -> None:
    await harness.set_settings(**{SWITCHES[path]: 1})
    await sign_in(harness)
    response = await harness.http.get(path, params={"view": "public"})
    assert response.status_code == 503
    assert response.headers["roxy-under-construction"] == "True"
    assert response.headers["retry-after"] == "3600"
    assert response.headers["cache-control"] == "private, no-store"  # an admin's answer is never stored
    assert response.headers["x-robots-tag"] == "noindex"
    text = response.text
    assert '<body class="previewing">' in text
    notice = re.search(r'<aside class="preview-notice" aria-label="Admin preview">(.*?)</aside>', text, re.DOTALL)
    assert notice is not None
    assert f'{NOTICE} <a href="{path}">Back to admin view</a>' in notice.group(1)
    assert "Admins only" not in text
    assert REAL_PAGE[path] not in text
    public = await visitor(harness).get(path)
    assert without_preview_parts(text) == without_preview_parts(public.text)
    # "Back to admin view" leads to the real page again.
    assert_admin_real_page(await harness.http.get(path), path)


# --- every way an admin view must end -------------------------------------------------------------------------------


async def test_signing_out_ends_the_admin_view_at_once(harness: AuthHarness) -> None:
    await harness.set_settings(public_docs_under_construction=1)
    token = await sign_in(harness)
    assert_admin_real_page(await harness.http.get("/docs"), "/docs")
    out = await harness.post("/admin/api/v1/auth/logout")
    assert out.status_code == 200, out.text
    # The browser drops the cookie; a copy kept or replayed must not open the real page either.
    replay = visitor(harness)
    assert_public_page(await replay.get("/docs", headers={"Cookie": f"{SESSION}={token}"}), "/docs")
    assert_public_page(await harness.http.get("/docs"), "/docs")


async def test_the_kill_switch_ends_the_admin_view_at_once(harness: AuthHarness) -> None:
    await harness.set_settings(public_home_under_construction=1)
    await sign_in(harness)
    assert_admin_real_page(await harness.http.get("/"), "/")
    now = int(harness.clock.now())
    harness.ctx.dbs.control.write_sync(lambda conn: sessions.revoke_all(conn, now))
    assert_public_page(await harness.http.get("/"), "/")


async def test_an_idle_or_expired_session_gets_the_public_page(harness: AuthHarness) -> None:
    await harness.set_settings(public_status_under_construction=1)
    admin = harness.admin()
    await sign_in(harness, admin)
    assert_admin_real_page(await harness.http.get("/status"), "/status")
    harness.clock.advance(harness.ctx.settings.int("admin_session_idle_timeout_s") + 1)
    assert_public_page(await harness.http.get("/status"), "/status")

    await sign_in(harness, admin)  # a new session, then its absolute expiry passes
    assert_admin_real_page(await harness.http.get("/status"), "/status")
    past = int(harness.clock.now()) - 1
    harness.ctx.dbs.control.write_sync(lambda conn: conn.execute("UPDATE admin_sessions SET expires_at = ?", (past,)))
    assert_public_page(await harness.http.get("/status"), "/status")


async def test_a_forged_cookie_gets_the_public_page(harness: AuthHarness) -> None:
    await harness.set_settings(public_home_under_construction=1)
    anon = visitor(harness)
    for token in ("forged", secrets.token_urlsafe(32), "x" * 500, "%00%0d%0a"):
        assert_public_page(await anon.get("/", headers={"Cookie": f"{SESSION}={token}"}), "/")


async def test_a_first_login_session_gets_the_public_page(harness: AuthHarness) -> None:
    """A bootstrap session (D5) may only enroll an authenticator; the same row as a full session is admitted."""
    await harness.set_settings(public_home_under_construction=1)
    admin = harness.admin()
    now = int(harness.clock.now())

    def create(level: str) -> str:
        def write(conn: sqlite3.Connection) -> str:
            token, _ = sessions.create(
                conn, user_id=admin.id, ip=None, ua=None, mfa_level=level, now=now, max_age_s=3600
            )
            return token

        token: str = harness.ctx.dbs.control.write_sync(write)
        return token

    anon = visitor(harness)
    bootstrap = create("bootstrap")
    assert_public_page(await anon.get("/", headers={"Cookie": f"{SESSION}={bootstrap}"}), "/")
    full = create("totp")
    assert_admin_real_page(await anon.get("/", headers={"Cookie": f"{SESSION}={full}"}), "/")


async def test_the_admin_allowlist_also_hides_the_admin_view(harness: AuthHarness) -> None:
    """D6: a network that may not reach the dashboard gets the public page, even with a live session."""
    await sign_in(harness)
    await harness.allow_admin_cidr("198.51.100.0/24")
    await harness.set_settings(admin_allowlist_enabled=1, public_docs_under_construction=1)
    listed = await harness.http.get("/docs", headers={"X-Forwarded-For": "198.51.100.7"})
    assert_admin_real_page(listed, "/docs")
    unlisted = await harness.http.get("/docs", headers={"X-Forwarded-For": "203.0.113.9"})
    assert_public_page(unlisted, "/docs")


async def test_a_foreign_origin_gets_the_public_page(harness: AuthHarness) -> None:
    await harness.set_settings(public_home_under_construction=1)
    await sign_in(harness)
    assert_public_page(await harness.http.get("/", headers={"Origin": "https://attacker.example"}), "/")
    assert_admin_real_page(await harness.http.get("/", headers={"Origin": harness.site_origin}), "/")


async def test_a_switched_off_status_page_stays_404_for_everyone(harness: AuthHarness) -> None:
    await harness.set_settings(public_status_page_enabled=0, public_status_under_construction=1)
    await sign_in(harness)
    assert (await harness.http.get("/status")).status_code == 404
    assert (await harness.http.get("/status", params={"view": "public"})).status_code == 404
    assert (await visitor(harness).get("/status")).status_code == 404
    assert "status" not in (await visitor(harness).get("/sitemap.xml")).text


# --- what never changes ---------------------------------------------------------------------------------------------


async def test_the_proxy_health_crawler_files_static_and_admin_are_never_affected(harness: AuthHarness) -> None:
    await harness.set_settings(
        public_home_under_construction=1,
        public_docs_under_construction=1,
        public_status_under_construction=1,
        tarpit_enabled=0,  # the not-Roblox request below would be held 8 to 20 s as a probe
    )
    anon = visitor(harness)
    home = await anon.get("/")
    assert_public_page(home, "/")
    health = await anon.get("/health")
    assert health.status_code == 200
    assert health.headers["content-type"].startswith("application/json")
    robots = await anon.get("/robots.txt")
    assert robots.status_code == 200
    assert robots.content == FIXTURE_ROBOTS.read_bytes()  # v1's bytes: robots.txt never changes
    favicon = await anon.get("/favicon.ico")
    assert favicon.status_code == 200
    assert favicon.headers["content-type"] == "image/png"
    stylesheet = re.search(r'<link rel="stylesheet" href="([^"]+)"', home.text)
    assert stylesheet is not None
    asset = await anon.get(stylesheet.group(1))
    assert asset.status_code == 200
    assert "text/css" in asset.headers["content-type"]
    login = await anon.get("/admin")
    assert login.status_code == 200
    assert "text/html" in login.headers["content-type"]
    assert (await anon.post("/")).status_code == 405  # v1's answer to POST /
    alias = await anon.get("/docs/")
    assert alias.status_code == 308
    assert alias.headers["location"] == "/docs"
    proxied = await anon.get("/example.com/anything")  # the proxy route: refused as not a Roblox URL, as always
    assert proxied.status_code == 404
    assert proxied.headers.get("roxy-refusal") is not None
    for response in (health, robots, favicon, asset, login, alias, proxied):
        assert "roxy-under-construction" not in response.headers, response.request.url
        assert "x-robots-tag" not in response.headers, response.request.url


async def test_the_sitemap_leaves_pages_under_construction_out(harness: AuthHarness) -> None:
    anon = visitor(harness)

    def locs(body: bytes) -> list[str]:
        root = ElementTree.fromstring(body)  # our own sitemap, built from constants
        return [str(loc.text) for loc in root.iter("{http://www.sitemaps.org/schemas/sitemap/0.9}loc")]

    origin = pages.CANONICAL_ORIGIN
    assert locs((await anon.get("/sitemap.xml")).content) == [f"{origin}/", f"{origin}/docs", f"{origin}/status"]
    await harness.set_settings(public_home_under_construction=1, public_status_under_construction=1)
    assert locs((await anon.get("/sitemap.xml")).content) == [f"{origin}/docs"]
    await harness.set_settings(public_docs_under_construction=1)
    assert locs((await anon.get("/sitemap.xml")).content) == []  # still a valid, empty urlset
    await harness.set_settings(
        public_home_under_construction=0, public_docs_under_construction=0, public_status_under_construction=0
    )
    assert (await anon.get("/sitemap.xml")).content == pages.build_sitemap(pages.build_date())


# --- the message, session use, the audit trail, visits --------------------------------------------------------------


async def test_the_message_is_live_escaped_and_links_only_https(harness: AuthHarness) -> None:
    await harness.set_settings(
        public_home_under_construction=1,
        site_construction_text="Back <b>soon</b>.\n\nNews on [the DevForum](https://devforum.roblox.com/t/roxy).",
    )
    text = (await visitor(harness).get("/")).text
    assert "<p>Back &lt;b&gt;soon&lt;/b&gt;.</p>" in text
    assert '<p>News on <a href="https://devforum.roblox.com/t/roxy">the DevForum</a>.</p>' in text
    assert "<b>soon</b>" not in text
    assert DEFAULT_MESSAGE not in text


async def test_an_admins_own_navigation_keeps_the_session_alive(harness: AuthHarness) -> None:
    """Reading the pages one after another counts as use, as a dashboard page load does; a script's request does
    not."""
    await harness.set_settings(public_docs_under_construction=1)
    await sign_in(harness)
    idle = harness.ctx.settings.int("admin_session_idle_timeout_s")
    harness.clock.advance(idle - 60)
    assert_admin_real_page(await harness.http.get("/docs", headers=NAVIGATION), "/docs")
    harness.clock.advance(120)  # past the idle timeout counted from the sign-in, within it counted from the visit
    assert_admin_real_page(await harness.http.get("/docs"), "/docs")  # a request that is not a person's navigation
    harness.clock.advance(idle - 120 + 1)  # past the timeout counted from the visit, within it from that request
    assert_public_page(await harness.http.get("/docs"), "/docs")  # so that request did not extend the session


async def test_a_change_through_the_settings_api_is_audited_and_live(harness: AuthHarness) -> None:
    await sign_in(harness)
    anon = visitor(harness)
    assert (await anon.get("/")).status_code == 200
    csrf = await harness.csrf()
    changed = await harness.http.put(
        "/admin/api/v1/settings/public_home_under_construction",
        json={"value": 1, "reason": "reviewing the home page"},
        headers=harness.headers(csrf=csrf),
    )
    assert changed.status_code == 200, changed.text
    assert_public_page(await anon.get("/"), "/")
    history = await harness.http.get(
        "/admin/api/v1/settings/public_home_under_construction/history", headers=harness.headers()
    )
    assert history.status_code == 200, history.text
    newest = history.json()["items"][0]
    assert newest["key"] == "public_home_under_construction"
    assert newest["new_effective"] in (1, True)
    assert newest["reason"] == "reviewing the home page"
    assert newest["changed_by"]


async def test_visits_to_the_under_construction_page_are_counted(harness: AuthHarness) -> None:
    visits: list[tuple[str, str | None]] = []

    class Recorder:
        def record_visit(self, page: str, user_agent: str | None) -> None:
            visits.append((page, user_agent))

        def __getattr__(self, name: str) -> Any:
            if name.startswith("record_"):
                return lambda *args, **kwargs: None
            raise AttributeError(name)

    real = harness.ctx.recorder
    harness.ctx.recorder = Recorder()
    try:
        await harness.set_settings(public_docs_under_construction=1)
        anon = visitor(harness)
        await anon.get("/docs", headers={"User-Agent": "Mozilla/5.0 Firefox/131.0"})
        await anon.head("/docs")  # a monitor, not a visit
    finally:
        harness.ctx.recorder = real
    assert visits == [("docs", "Mozilla/5.0 Firefox/131.0")]


async def test_the_settings_card_links_each_page_under_construction(harness: AuthHarness) -> None:
    await sign_in(harness)
    card = "/admin/settings/fragment/public-site"
    fragment = await harness.http.get(card, headers={"Accept": "text/html"})
    assert fragment.status_code == 200
    assert "Under construction now" not in fragment.text
    for key in (*SWITCHES.values(), construction.MESSAGE_KEY):
        assert f'data-setting-key="{key}"' in fragment.text, key
    await harness.set_settings(public_home_under_construction=1, public_status_under_construction=1)
    text = (await harness.http.get(card, headers={"Accept": "text/html"})).text
    assert (
        'Under construction now: <a href="/">Roxy&#39;s home page</a>, <a href="/status">Roxy&#39;s status page</a>.'
        in text
    )
