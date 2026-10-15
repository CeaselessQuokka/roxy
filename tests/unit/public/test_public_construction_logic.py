"""Pages under construction (`roxy.public.construction`): the switches, the answers, the admin check, the sitemap.

What this is
    Unit tests for the pieces behind `public_home_under_construction`, `public_docs_under_construction`,
    `public_status_under_construction` and `site_construction_text` (owner request, 2026-10-15): which pages exist and
    match the routes, which are under construction for a settings snapshot, the status and headers of each answer
    (`Preview`), the admin check (`admin_session`) with a stand-in auth service, `preview_for`, the sitemap leaving
    pages out, and the stylesheet and templates the pages use.

Why it exists
    The admin check decides who sees a page the owner took off the public site, and the headers decide whether a cache
    or a search engine keeps it. Each rule is pinned here, fast and without an app; the integration tests
    (tests/integration/test_public_construction.py) check the same rules on the real app and the real sign-in.

How it works
    Requests are Starlette `Request` objects built from an ASGI scope whose app state holds a small stand-in context;
    `get_auth` is replaced with a recording stand-in, so no database is opened. Settings come from `catalog_get`
    (tests/unit/public/conftest.py: the catalog defaults, with overrides).

What to read next
    `roxy/public/construction.py`, `roxy/public/pages.py` (`build_sitemap`, `construction_page`).
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ElementTree
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import pytest
from starlette.requests import Request

from roxy.admin.auth import sessions
from roxy.admin.auth.flow import AuthError
from roxy.config.catalog import CATALOG
from roxy.config.spec import Group, Risk, SettingType
from roxy.public import construction, pages
from roxy.public.construction import CONSTRUCTION_PAGES, Preview

SITE_ORIGIN = "https://roxy.example.test"
NAVIGATION = [(b"sec-fetch-mode", b"navigate"), (b"sec-fetch-user", b"?1")]


def make_request(
    *, cookie: str | None = None, query: str = "", headers: list[tuple[bytes, bytes]] | None = None, ctx: Any = None
) -> Request:
    """A GET request as the public routes receive it, with `ctx` in the app state (None: no worker context)."""
    raw = list(headers or [])
    if cookie is not None:
        raw.append((b"cookie", f"{sessions.SESSION_COOKIE}={cookie}".encode()))
    app = SimpleNamespace(state=SimpleNamespace(ctx=ctx))
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/docs",
        "query_string": query.encode(),
        "headers": raw,
        "client": ("127.0.0.1", 50000),
        "app": app,
        "state": {},
    }
    return Request(scope)


def make_ctx(*, allowlist_on: bool = False) -> SimpleNamespace:
    """A worker context with what the admin check reads: the site origin, the allowlist switch and its rules."""
    settings = SimpleNamespace(bool=lambda key: allowlist_on if key == "admin_allowlist_enabled" else False)
    return SimpleNamespace(env=SimpleNamespace(site_origin=SITE_ORIGIN), settings=settings)


def record(level: str = "totp") -> sessions.SessionRecord:
    return sessions.SessionRecord(
        id_hash="a" * 64,
        user_id=1,
        username="owner",
        created_at=1_760_000_000,
        last_seen_at=1_760_000_000,
        expires_at=1_760_043_200,
        ip=None,
        ua=None,
        epoch=0,
        csrf_secret_hash="b" * 64,
        mfa_level=level,
    )


class FakeAuth:
    """The two `AuthService` methods the admin check uses, recording their calls."""

    def __init__(self, answer: sessions.SessionRecord | None = None, error: Exception | None = None) -> None:
        self.answer = answer
        self.error = error
        self.loaded: list[str] = []
        self.touched: list[sessions.SessionRecord] = []

    async def load_session(self, token: str) -> sessions.SessionRecord | None:
        self.loaded.append(token)
        if self.error is not None:
            raise self.error
        return self.answer

    async def touch_session(self, found: sessions.SessionRecord) -> None:
        self.touched.append(found)


@pytest.fixture
def auth(monkeypatch: pytest.MonkeyPatch) -> Callable[..., FakeAuth]:
    """`auth(answer=..., error=...)` installs a `FakeAuth` as this worker's auth service."""

    def install(**kwargs: Any) -> FakeAuth:
        fake = FakeAuth(**kwargs)
        monkeypatch.setattr(construction, "get_auth", lambda request: fake)
        return fake

    return install


# --- the pages and their switches -----------------------------------------------------------------------------------


def test_the_three_pages_match_the_routes_and_the_sitemap() -> None:
    assert set(CONSTRUCTION_PAGES) == {pages.PAGE_HOME, pages.PAGE_DOCS, pages.PAGE_STATUS}
    sitemap_paths = {pages.SITEMAP_HOME.path, pages.SITEMAP_DOCS.path, pages.SITEMAP_STATUS.path}
    assert {target.path for target in CONSTRUCTION_PAGES.values()} == sitemap_paths
    for name, target in CONSTRUCTION_PAGES.items():
        assert target.page == name
        assert target.title.startswith("Roxy's ")


def test_every_switch_is_a_low_risk_public_site_setting_that_starts_off() -> None:
    for target in CONSTRUCTION_PAGES.values():
        spec = CATALOG[target.switch]
        assert spec.type is SettingType.BOOL
        assert spec.default == 0
        assert spec.risk is Risk.LOW
        assert spec.group is Group.PUBLIC_SITE
        assert spec.pages == ("settings#public-site",)
    message = CATALOG[construction.MESSAGE_KEY]
    assert message.type is SettingType.STRING
    assert message.default == "Roxy's site is being updated. Check back soon."


def test_which_pages_are_under_construction(catalog_get: Callable[..., Callable[[str], Any]]) -> None:
    get = catalog_get()
    assert construction.pages_under_construction(get) == ()
    assert not any(construction.is_under_construction(get, name) for name in CONSTRUCTION_PAGES)
    get = catalog_get(public_status_under_construction=1, public_home_under_construction=1)
    assert [target.page for target in construction.pages_under_construction(get)] == ["home", "status"]
    assert construction.is_under_construction(get, "home")
    assert not construction.is_under_construction(get, "docs")


# --- the answers ----------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("admin", "as_public", "status", "cache_control"),
    [
        (False, False, 503, "no-store"),  # a visitor
        (False, True, 503, "no-store"),  # a visitor who added ?view=public: the same page
        (True, False, 200, "private, no-store"),  # an admin: the real page
        (True, True, 503, "private, no-store"),  # an admin asking for the public view
    ],
)
def test_each_answer_has_its_status_and_headers(admin: bool, as_public: bool, status: int, cache_control: str) -> None:
    preview = Preview(CONSTRUCTION_PAGES["docs"], admin=admin, as_public=as_public)
    headers = preview.headers()
    assert preview.status_code == status
    assert preview.real_page is (status == 200)
    assert preview.admin_as_public is (admin and as_public)
    assert headers["Cache-Control"] == cache_control
    assert headers["Vary"] == "Cookie"
    assert headers["X-Robots-Tag"] == "noindex"
    if status == 503:
        assert headers["Retry-After"] == "3600"
        assert headers[construction.MARKER_HEADER] == "True"
    else:
        assert "Retry-After" not in headers
        assert construction.MARKER_HEADER not in headers


def test_the_preview_links() -> None:
    for name, path in (("home", "/"), ("docs", "/docs"), ("status", "/status")):
        preview = Preview(CONSTRUCTION_PAGES[name], admin=True, as_public=False)
        assert preview.public_view_url == f"{path}?view=public"
        assert preview.admin_view_url == path
        assert preview.settings_url == "/admin/settings#public-site"


# --- the admin check ------------------------------------------------------------------------------------------------


async def test_a_request_without_the_cookie_reads_nothing(auth: Callable[..., FakeAuth]) -> None:
    fake = auth(answer=record())
    assert await construction.admin_session(make_request(ctx=make_ctx())) is None
    assert fake.loaded == []  # nearly every visitor: no database read at all


async def test_no_worker_context_means_no_admin(auth: Callable[..., FakeAuth]) -> None:
    fake = auth(answer=record())
    assert await construction.admin_session(make_request(cookie="token", ctx=None)) is None
    assert fake.loaded == []


async def test_a_live_session_is_an_admin_and_only_a_navigation_is_use(auth: Callable[..., FakeAuth]) -> None:
    live = record()
    fake = auth(answer=live)
    assert await construction.admin_session(make_request(cookie="token", ctx=make_ctx())) == live
    assert fake.loaded == ["token"]
    assert fake.touched == []  # a script's request is not use
    assert await construction.admin_session(make_request(cookie="token", ctx=make_ctx(), headers=NAVIGATION)) == live
    assert fake.touched == [live]


@pytest.mark.parametrize("answer", [None, record("bootstrap")], ids=["dead session", "first login"])
async def test_a_dead_or_first_login_session_is_not_an_admin(
    auth: Callable[..., FakeAuth], answer: sessions.SessionRecord | None
) -> None:
    fake = auth(answer=answer)
    assert await construction.admin_session(make_request(cookie="token", ctx=make_ctx(), headers=NAVIGATION)) is None
    assert fake.touched == []


async def test_the_allowlist_and_a_foreign_origin_hide_the_admin(
    auth: Callable[..., FakeAuth], monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = auth(answer=record())
    ctx = make_ctx(allowlist_on=True)  # on, and the stand-in rules list no network
    assert await construction.admin_session(make_request(cookie="token", ctx=ctx)) is None
    foreign = [(b"origin", b"https://attacker.example")]
    assert await construction.admin_session(make_request(cookie="token", ctx=make_ctx(), headers=foreign)) is None
    assert fake.loaded == []  # refused before any database read
    own = [(b"origin", SITE_ORIGIN.encode())]
    assert await construction.admin_session(make_request(cookie="token", ctx=make_ctx(), headers=own)) is not None


async def test_shared_state_trouble_reads_as_not_an_admin_and_is_logged_once(
    auth: Callable[..., FakeAuth], monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(construction, "_problem_logged", False)
    auth(error=AuthError(503, "Service temporarily unavailable"))
    with caplog.at_level(logging.WARNING, logger="roxy.public.construction"):
        for _ in range(3):
            assert await construction.admin_session(make_request(cookie="token", ctx=make_ctx())) is None
    assert [r.message for r in caplog.records if r.name == "roxy.public.construction"] == [
        "construction_admin_check_failed"
    ]


async def test_preview_for(auth: Callable[..., FakeAuth], catalog_get: Callable[..., Callable[[str], Any]]) -> None:
    fake = auth(answer=record())
    off = catalog_get()
    assert await construction.preview_for(make_request(cookie="token", ctx=make_ctx()), off, "docs") is None
    assert fake.loaded == []  # a page that is not under construction checks nobody
    on = catalog_get(public_docs_under_construction=1)
    admin = await construction.preview_for(make_request(cookie="token", ctx=make_ctx()), on, "docs")
    assert admin == Preview(CONSTRUCTION_PAGES["docs"], admin=True, as_public=False)
    asking = make_request(cookie="token", ctx=make_ctx(), query="view=public")
    asked = await construction.preview_for(asking, on, "docs")
    assert asked == Preview(CONSTRUCTION_PAGES["docs"], admin=True, as_public=True)
    visitor = await construction.preview_for(make_request(ctx=make_ctx(), query="view=admin"), on, "docs")
    assert visitor is not None
    assert not visitor.admin
    assert not visitor.real_page


# --- the sitemap ----------------------------------------------------------------------------------------------------


def test_the_sitemap_leaves_pages_out_and_keeps_v1_bytes_otherwise() -> None:
    assert pages.build_sitemap("2026-10-15", leave_out=()) == pages.build_sitemap("2026-10-15")
    without_home = pages.build_sitemap("2026-10-15", leave_out=["/"]).decode()
    assert "<loc>https://roxytheproxy.com/</loc>" not in without_home
    assert without_home.count("<url>") == 2
    empty = pages.build_sitemap("2026-10-15", leave_out=["/", "/docs", "/status"])
    root = ElementTree.fromstring(empty)  # our own sitemap, built from constants
    assert list(root) == []
    assert empty.decode().endswith("</urlset>\n")
    assert "/status" not in pages.build_sitemap("2026-10-15", include_status=False, leave_out=["/docs"]).decode()


# --- the page's look ------------------------------------------------------------------------------------------------


def test_the_stylesheet_has_every_class_the_preview_templates_use() -> None:
    css = (pages.PUBLIC_STATIC_DIR / "site.css").read_text(encoding="utf-8")
    templates = "".join(
        (pages.PUBLIC_TEMPLATES_DIR / name).read_text(encoding="utf-8")
        for name in ("_preview.html", "construction.html", "base.html")
    )
    classes = ("preview-banner", "preview-bar", "preview-actions", "preview-notice", "previewing", "construction")
    for css_class in classes:
        assert re.search(rf"\.{css_class}\b", css), css_class
        assert css_class in templates, css_class
    notice = css.split(".preview-notice {", 1)[1].split("}", 1)[0]
    assert "position: fixed;" in notice  # the small notice stays put while the page scrolls
    for template in ("_preview.html", "construction.html"):
        text = (pages.PUBLIC_TEMPLATES_DIR / template).read_text(encoding="utf-8")
        assert " style=" not in text  # the strict CSP allows no inline styles
        assert "<script" not in text
