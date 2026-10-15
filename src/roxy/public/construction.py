"""Pages under construction: the public gets a 503 "under construction" page, a signed-in admin the real page.

What this is
    The rules behind the switches `public_home_under_construction`, `public_docs_under_construction` and
    `public_status_under_construction` and the message `site_construction_text` (owner request, 2026-10-15), used by
    the home, guide and status routes of `roxy/public/pages.py`: which pages are under construction
    (`is_under_construction`, `pages_under_construction`), whether a signed-in admin is asking (`admin_session`), how
    the request is answered (`preview_for`, `Preview`) and the response headers of each answer (`Preview.headers`).

Why it exists
    The owner wants to take a public page off the site while reviewing it, keep seeing the real page as an admin with
    a clear sign that the public sees something else, and see exactly what the public sees with one button. Visitors
    must learn that the page is away for a while, not gone (503 with Retry-After, which search engines treat as
    temporary). Nothing else may change: only the three page routes call this module, so the proxy, `/health`,
    robots.txt, the favicon, `/admin`, the sign-in links and static files never see a switch, and sitemap.xml only
    leaves the pages under construction out.

How it works
    - Who is an admin: the dashboard's own session cookie, `__Host-roxy_session` (`roxy/admin/auth/sessions.py`). It
      is already `Path=/` (the `__Host-` prefix requires that path) and `SameSite=Strict`, so the browser sends it
      with a visit that starts on Roxy's own site (a link on the dashboard, an address typed in) and with nothing
      another site starts. No new cookie, key or grant exists and nothing is widened. A request counts as an admin's
      only when ALL of these hold, checked on the server on every request: this page's switch is on (without it
      nothing is checked at all); the caller's address may reach the dashboard (the D6 allowlist,
      `admin_ip_allowed`); no foreign `Origin` header; the session is live (`AuthService.load_session`, the check
      every admin route makes: the row exists, its kill switch epoch is the current one, and neither its absolute nor
      its idle expiry has passed); and it is not a first-login (bootstrap) session, which may only enroll. Signing
      out, revoking the session on the Security page or the kill switch therefore ends the admin view on the very
      next request. Any failure on the way (shared state that cannot be read) means "not an admin": the visitor gets
      the public page, never an error.
    - Cost: only a request for a page under construction that carries the cookie is checked (one indexed control.db
      read through the database read pool, never on the event loop's thread); every other visitor costs one lookup in
      the settings snapshot.
    - What the admin sees: the real page with a banner at the top and a button to `?view=public`, which shows
      exactly the public page plus a small fixed notice with a link back. The parameter can only ever HIDE the real
      page, so anyone else who adds it sees what they would see anyway.
    - Session use: an admin's own navigation to one of these pages (`deps.is_user_activity`: `Sec-Fetch-Mode:
      navigate` with `Sec-Fetch-User: ?1`) counts as use of the session, exactly like loading a dashboard page, so
      reading the pages one after another does not let the session idle out; requests a script or a monitor makes do
      not count.
    - Headers: the public answer is 503 with `Retry-After` (`RETRY_AFTER_S`), `Cache-Control: no-store`, `Vary:
      Cookie`, `X-Robots-Tag: noindex` and `Roxy-Under-Construction: True` (`MARKER_HEADER`), the marker the deploy's
      smoke test (`scripts/smoke_remote.py`) accepts as the owner's choice for `/`, as it accepts a pause. Every
      answer to an admin is `Cache-Control: private, no-store` instead, so no cache between Roxy and the browser can
      ever store the real page and hand it to the public.

What to read next
    `roxy/public/pages.py` (the routes and `construction_page`), `roxy/templates/public/construction.html` and
    `roxy/templates/public/_preview.html`, then `roxy/admin/auth/deps.py` and `roxy/admin/auth/sessions.py` (the
    session rules reused here).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Final

from starlette.requests import Request

from roxy.admin.auth import sessions
from roxy.admin.auth.allowlist import admin_ip_allowed
from roxy.admin.auth.csrf import foreign_origin
from roxy.admin.auth.deps import client_ip, get_auth, get_ctx_or_none, is_user_activity

log = logging.getLogger("roxy.public.construction")

Getter = Callable[[str], Any]

MESSAGE_KEY: Final = "site_construction_text"
"""The setting holding the message of the under-construction page."""

RETRY_AFTER_S: Final = 3600
"""`Retry-After` of the 503, in seconds: an hour. Search engines read 503 with Retry-After as "away for a while, come
back later"; an hour keeps crawlers from hammering the page while it stays down, and a visitor reloads whenever they
like."""

MARKER_HEADER: Final = "Roxy-Under-Construction"
MARKER_VALUE: Final = "True"
"""`Roxy-Under-Construction: True` on every under-construction answer (the `True` of `Roxy-Paused: True`), so the
deploy's smoke test can tell the owner's switch from a broken page."""

PUBLIC_CACHE_CONTROL: Final = "no-store"
"""The public answer is never stored: when the owner turns the switch off, the next visit gets the real page."""
ADMIN_CACHE_CONTROL: Final = "private, no-store"
"""Every answer to an admin: a shared cache must never keep the real page (and a browser need not either)."""
ROBOTS_TAG: Final = "noindex"

VIEW_PARAM: Final = "view"
VIEW_PUBLIC: Final = "public"
"""`?view=public`: an admin asks to see the page exactly as the public sees it."""

SETTINGS_ANCHOR: Final = "/admin/settings#public-site"
"""Where the switches are edited (Settings > Public site), linked from the admin banner."""


@dataclass(frozen=True, slots=True)
class ConstructionPage:
    """One public page that can be put under construction."""

    page: str  # the page name the visitor recorder knows (`roxy.public.pages.PAGE_HOME`...)
    path: str  # its address on the site
    switch: str  # the setting that puts it under construction
    title: str  # how the under-construction page names it ("Roxy's user guide")


CONSTRUCTION_PAGES: Final[dict[str, ConstructionPage]] = {
    "home": ConstructionPage("home", "/", "public_home_under_construction", "Roxy's home page"),
    "docs": ConstructionPage("docs", "/docs", "public_docs_under_construction", "Roxy's user guide"),
    "status": ConstructionPage("status", "/status", "public_status_under_construction", "Roxy's status page"),
}
"""The three pages, keyed by page name. Nothing else on the site can be put under construction."""


def is_under_construction(get: Getter, page: str) -> bool:
    """True when the switch of `page` (a key of `CONSTRUCTION_PAGES`) is on in this settings snapshot."""
    return bool(get(CONSTRUCTION_PAGES[page].switch))


def pages_under_construction(get: Getter) -> tuple[ConstructionPage, ...]:
    """Every page whose switch is on, in site order (home, guide, status)."""
    return tuple(target for name, target in CONSTRUCTION_PAGES.items() if is_under_construction(get, name))


@dataclass(frozen=True, slots=True)
class Preview:
    """How one request for a page under construction is answered.

    `admin` is true for a live admin session (`admin_session`); `as_public` when the request asked for the public
    view (`?view=public`), which only matters for an admin. The public (and an admin who asked) gets the 503
    under-construction page; an admin gets the real page with the banner.
    """

    target: ConstructionPage
    admin: bool
    as_public: bool

    @property
    def real_page(self) -> bool:
        """True when this request gets the real page (an admin who did not ask for the public view)."""
        return self.admin and not self.as_public

    @property
    def admin_as_public(self) -> bool:
        """True for an admin looking at the public page (it carries the small "back to admin view" notice)."""
        return self.admin and self.as_public

    @property
    def public_view_url(self) -> str:
        """The address of this page as the public sees it (the banner's button)."""
        return f"{self.target.path}?{VIEW_PARAM}={VIEW_PUBLIC}"

    @property
    def admin_view_url(self) -> str:
        """The address of the real page (the notice's link back)."""
        return self.target.path

    @property
    def settings_url(self) -> str:
        return SETTINGS_ANCHOR

    @property
    def status_code(self) -> int:
        return 200 if self.real_page else 503

    def headers(self) -> dict[str, str]:
        """The response headers of this answer (see the module docstring, "Headers")."""
        headers = {
            "Cache-Control": ADMIN_CACHE_CONTROL if self.admin else PUBLIC_CACHE_CONTROL,
            "Vary": "Cookie",
            "X-Robots-Tag": ROBOTS_TAG,
        }
        if not self.real_page:
            headers["Retry-After"] = str(RETRY_AFTER_S)
            headers[MARKER_HEADER] = MARKER_VALUE
        return headers


_problem_logged = False


async def admin_session(request: Request) -> sessions.SessionRecord | None:
    """The live, non-bootstrap admin session this request carries, or None (see the module docstring).

    Never raises: anything that goes wrong reads as "not an admin", so a visitor always gets a page. An admin's own
    navigation counts as use of the session (`is_user_activity`), as a dashboard page load does.
    """
    global _problem_logged
    token = request.cookies.get(sessions.SESSION_COOKIE)
    if not token:
        return None  # nearly every visitor: no database read, nothing else to check
    ctx = get_ctx_or_none(request)
    if ctx is None:
        return None  # the worker is starting or stopping: no admin view, as /admin answers 404 then
    try:
        if not admin_ip_allowed(ctx, client_ip(request)):
            return None  # the D6 allowlist hides the dashboard from this network, so its admin view too
        if foreign_origin(request, str(ctx.env.site_origin)):
            return None
        auth = get_auth(request)
        record = await auth.load_session(token)
        if record is None or record.mfa_level == "bootstrap":
            return None  # dead, revoked, idle, from before the kill switch, or a first login that may only enroll
        if is_user_activity(request):
            await auth.touch_session(record)
    except Exception:  # shared state in trouble (AuthError) or anything unexpected: the public page, never an error
        if not _problem_logged:
            _problem_logged = True
            log.warning("construction_admin_check_failed", exc_info=True)
        return None
    return record


async def preview_for(request: Request, get: Getter, page: str) -> Preview | None:
    """None when `page` is not under construction (the route answers as always); otherwise how to answer it."""
    if not is_under_construction(get, page):
        return None
    record = await admin_session(request)
    as_public = request.query_params.get(VIEW_PARAM) == VIEW_PUBLIC
    return Preview(CONSTRUCTION_PAGES[page], admin=record is not None, as_public=as_public)


__all__ = [
    "CONSTRUCTION_PAGES",
    "MARKER_HEADER",
    "MESSAGE_KEY",
    "RETRY_AFTER_S",
    "ConstructionPage",
    "Preview",
    "admin_session",
    "is_under_construction",
    "pages_under_construction",
    "preview_for",
]
