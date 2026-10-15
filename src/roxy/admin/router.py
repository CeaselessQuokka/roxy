"""The admin entry router: every `/admin` route the application serves, included by `roxy/main.py`.

What this is
    `router`, an `APIRouter` that includes the admin sub-routers in a fixed order:
      1. the auth surface (`admin/auth/routes.py`: the login page `GET /admin`, enrollment, the kill-switch link and
         `/admin/api/v1/auth/*`);
      2. the admin API (`admin/api/__init__.py api_router`: every area module of `API_MODULES`, the event stream
         `admin/sse.py` and the admin-only OpenAPI document, all under `/admin/api/v1`, P9);
      3. the dashboard pages (`admin/pages.py`, P11) at the marked include point, once that module exists, checked
         like the API: every page route guarded by `require_admin`, every unsafe one also by `require_csrf`;
      4. LAST, `AdminNotFoundRoute` twice: the catch-all for admin paths nothing else serves (`/admin/...`), and
         the login page's path (`/admin`) for the methods the login page does not take.
    Its lifespan (`admin_lifespan`) adds the development-only component gallery (`admin/gallery.py`,
    `/admin/_gallery`) to an app that runs with `ROXY_ENV=development`, and never to any other.

Why it exists
    `roxy/main.py` includes one router per area so the order of the whole application is visible in one tuple,
    with the proxy catch-all last. The admin area has several owners, so this module is the single place where
    their routers meet, and where their guards are checked before the app serves a request.
    The catch-all keeps v1's answer for an unknown admin path (plan 4.1 row 15, v1 `admin_not_found`): 404 with
    `"Not Found"` as a JSON string plus a newline, and never a probe. v1 added it because without it every typo
    and every stale bookmark fell through to the proxy route and showed up in the security log as an attack. The
    proxy route already refuses to match `/admin` paths, so without this route FastAPI's own 404 would answer,
    with another body and a probe record. Under `/admin/api/v1` the answer is the DESIGN.md section 13 error
    object instead (`{"error": {"code": "not_found", ...}}`), so the P9 API routers need nothing of their own.
    The gallery holds no data and needs no login, which is exactly why it must not exist outside development; a
    module-level router cannot know the environment (the app factory passes it later), so the router's lifespan,
    which receives the app, decides once per app.

How it works
    Plain `include_router` calls at import. Every included router guards its own routes with `require_admin` and
    `require_csrf` from `admin/auth/deps.py` (re-exported by `roxy/deps.py`); the security tests
    (`tests/security/test_admin_routes.py`) discover every route from the application and check those guards and
    the documented exceptions. The catch-all needs no guard: it reveals nothing and does nothing.
    `AdminNotFoundRoute` matches `/admin/` plus anything (and `/admin` itself), for every method, but steps aside
    whenever another route of the application serves the request. So real admin routes always win, wherever they
    sit: earlier in this router, added to this router after the catch-all, or added to the app after `create_app`
    (tests, and the gallery, which the lifespan appends to the app, do that). It checks by asking every route of
    the app's top router, once, with a scope flag that makes it step aside from its own question; that costs a few
    regular expression matches, and only for admin paths no earlier route claimed. For a path nothing serves, its
    answer is `core/errors.py: not_found_response`, the same bytes the `HTTPException` handler sends for a plain
    admin 404 (the network allowlist, D6), so a hidden page and a missing page look identical; it runs no error
    hook, so a typo is never recorded as a probe.
    A real path asked with a method it does not take (another route matches the path only) is answered by the
    catch-all too, never by Starlette's 405, whose `Allow` header would tell a hidden path from a missing one and
    map every method (review finding apisec-3): the session guard runs first (`require_admin("session",
    activity="never")`); anyone it refuses (outside the allowlist, signed out, a bootstrap session, a foreign
    origin) gets the missing path's 404, and a signed-in admin gets 405 `method_not_allowed` (a DESIGN.md section 13
    object) with `Allow`. Both are client errors for the probe hook, as a 405 always was.
    The gallery is imported only when it is mounted (production never imports it); `include_gallery` adds it to
    the app, and the app's state remembers it so a second lifespan run of the same app does not add it twice.

What to read next
    `roxy/admin/auth/routes.py` (the login surface), `roxy/admin/auth/deps.py` (the guards),
    `roxy/admin/api/__init__.py` (how the API areas are mounted), `roxy/core/errors.py` (`not_found_response`),
    then `roxy/main.py`.
"""

from __future__ import annotations

import importlib
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Final

from fastapi import APIRouter, HTTPException
from fastapi.routing import APIRoute, iter_route_contexts
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Match
from starlette.types import Receive, Scope, Send

from roxy.admin.api import ApiMountError, api_router, check_route
from roxy.admin.api.common import API_PREFIX, ApiError
from roxy.admin.auth.deps import require_admin
from roxy.admin.auth.routes import router as auth_router
from roxy.core.errors import NOT_FOUND_TEXT, not_found_response
from roxy.lifespan import optional_import

log = logging.getLogger("roxy.admin.router")

ADMIN_CATCH_ALL_PATH = "/admin/{rest:path}"
"""Every path below `/admin/` (`/admin` itself is the login page)."""

ADMIN_ROOT_PATH = "/admin"
"""The login page's path: a second catch-all route answers the methods the login page does not take."""

WRONG_METHOD_SCOPE: Final = "roxy.admin_wrong_method"
"""Scope key the catch-all sets when the path exists but not for this method: the methods it does take."""

METHOD_NOT_ALLOWED_CODE: Final = "method_not_allowed"
METHOD_NOT_ALLOWED_MESSAGE: Final = "This address does not take that method; see the Allow header."

CATCH_ALL_METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
"""The methods the route declares. Any other method is answered the same way (see `matches`)."""

PAGES_MODULE: Final = "roxy.admin.pages"
"""The dashboard pages (P11): included at the marked point below once the module exists."""

GALLERY_MODULE: Final = "roxy.admin.gallery"
GALLERY_STATE: Final = "admin_gallery_mounted"
"""`app.state` flag: the development gallery was added to this app."""

RESERVED_PAGE_PREFIXES: Final[tuple[str, ...]] = (
    API_PREFIX,  # the admin API
    "/admin/_gallery",  # the development gallery
    "/admin/enroll",  # the login surface (enrollment)
    "/admin/invalidate",  # the kill-switch link
)
"""Paths a dashboard page may not claim: they belong to the API, the gallery or the login surface."""

_ASKING_OTHERS = "roxy.admin_catch_all_asking"
"""Scope flag set while the catch-all asks the other routes, so it does not answer its own question."""

_signed_in_admin = require_admin("session", activity="never")
"""Asked before a wrong method gets its 405 (allowlist, origin, live session, no bootstrap); never activity."""


def _route_path(scope: Scope) -> str:
    return str(scope.get("path", ""))


def _top_routes(scope: Scope) -> list[Any]:
    """The routes of the application's top router (Starlette stores the first router it passes in the scope)."""
    router = scope.get("router") or getattr(scope.get("app"), "router", None)
    return list(getattr(router, "routes", None) or ())


def _match_of(route: Any, scope: Scope) -> Match:
    """How `route` matches this request; a route that cannot judge the scope does not claim it."""
    try:
        match, _ = route.matches(scope)
    except Exception:
        log.debug("admin_catch_all_route_check_failed", extra={"fields": {"route": type(route).__name__}})
        return Match.NONE
    return match if isinstance(match, Match) else Match.NONE


def _allowed_methods(scope: Scope) -> tuple[str, ...]:
    """The methods the app's routes take for this path (the `Allow` header of a 405), the catch-alls left out.

    FastAPI keeps an included router as one route of its parent, whose answer for a partial match says nothing
    about the route inside, so every route of the app is asked through its route context (`iter_route_contexts`).
    A context matches by path and methods only, so a route class with its own `matches` (the catch-alls, the
    public page aliases) is left out: it serves no fixed method set for a path. Only a request with a method its
    path does not take gets this far, so the walk costs nothing on any common path.
    """
    methods: set[str] = set()
    for context in iter_route_contexts(_top_routes(scope)):
        route = context.original_route
        if isinstance(route, APIRoute) and type(route).matches is not APIRoute.matches:
            continue  # its own matching rule (AdminNotFoundRoute, PageAliasRoute, ...)
        if _match_of(context, scope) is Match.PARTIAL:
            # The original route's own methods: what routing really serves (FastAPI adds no HEAD to a GET route).
            served = getattr(context.original_route, "methods", None) or context.methods or ()
            methods.update(str(method) for method in served)
    return tuple(sorted(methods))


class AdminNotFoundRoute(APIRoute):
    """The admin catch-all: v1's 404 for an admin path no other route serves, and the answer for a real admin path
    asked with a method it does not take (see the module docstring)."""

    def matches(self, scope: Scope) -> tuple[Match, Scope]:
        if scope.get(_ASKING_OTHERS):
            return Match.NONE, {}
        match, child_scope = super().matches(scope)
        if match is Match.NONE:
            return match, child_scope
        full, partial, methods = self.others(scope)
        if full:
            return Match.NONE, {}  # a real route serves this request: it wins
        if partial:
            child_scope = {**child_scope, WRONG_METHOD_SCOPE: methods}
        return Match.FULL, child_scope  # every method: a PARTIAL (undeclared method) is still ours to answer

    @staticmethod
    def others(scope: Scope) -> tuple[bool, bool, tuple[str, ...]]:
        """How the other routes of the app match this request: `(full, partial, methods)`. `full`: one serves it;
        `partial`: the path exists for other methods only, `methods` being those methods."""
        scope[_ASKING_OTHERS] = True
        try:
            partial = False
            for route in _top_routes(scope):
                match = _match_of(route, scope)
                if match is Match.FULL:
                    return True, False, ()
                partial = partial or match is Match.PARTIAL
            return False, partial, _allowed_methods(scope) if partial else ()
        finally:
            scope.pop(_ASKING_OTHERS, None)

    @classmethod
    def claimed_elsewhere(cls, scope: Scope) -> bool:
        """True when any other route of the app matches this request, fully or for another method."""
        full, partial, _methods = cls.others(scope)
        return full or partial

    async def handle(self, scope: Scope, receive: Receive, send: Send) -> None:
        methods = scope.get(WRONG_METHOD_SCOPE)
        if methods is None:
            # An unknown path: answered here for every method, without dependencies or a hook (never a probe).
            await not_found_response(_route_path(scope))(scope, receive, send)
            return
        # A real path, another method (review finding apisec-3). Only a signed-in admin may learn that the path
        # exists and which methods it takes: everyone else (outside the admin allowlist, signed out, a bootstrap
        # session, a foreign origin, no worker context) gets the missing path's 404, byte for byte. Both answers
        # go through the app's HTTPException handler, so both stay client errors for the probe hook, as before.
        try:
            await _signed_in_admin(Request(scope, receive))
        except HTTPException:
            raise HTTPException(status_code=404, detail=NOT_FOUND_TEXT) from None
        raise ApiError(405, METHOD_NOT_ALLOWED_CODE, METHOD_NOT_ALLOWED_MESSAGE, headers={"Allow": ", ".join(methods)})


async def admin_not_found(request: Request) -> Response:
    """The catch-all's endpoint (what `AdminNotFoundRoute.handle` sends)."""
    return not_found_response(_route_path(request.scope))


def check_page_router(module: str, pages: Any) -> APIRouter:
    """Validate the dashboard pages router before it is included (raises `ApiMountError`).

    Every page route is a FastAPI route under `/admin/` that depends on `require_admin` (and, for POST, PUT, PATCH
    and DELETE, on `require_csrf`), and none claims the API, the gallery or the login surface.
    """
    if not isinstance(pages, APIRouter):
        raise ApiMountError(f"{module} must expose `router`, an APIRouter")
    for context in iter_route_contexts(pages.routes):
        path = str(context.path or "")
        if not path.startswith("/admin/") or any(
            path == prefix or path.startswith(prefix + "/") for prefix in RESERVED_PAGE_PREFIXES
        ):
            raise ApiMountError(f"{module}: the page path {path!r} is not a dashboard page path")
        check_route(context.original_route, path, set(context.methods or ()), module=module, route_class=False)
    return pages


def mount_development_gallery(app: Any) -> bool:
    """Add the component gallery to `app` when it runs in development, once per app. Returns whether it is there."""
    state = app.state
    if getattr(state, GALLERY_STATE, False):
        return True
    env = getattr(state, "env", None)
    if not getattr(env, "is_development", False):
        return False
    gallery = importlib.import_module(GALLERY_MODULE)  # imported only here: production never loads it
    mounted = bool(gallery.include_gallery(app, env))
    setattr(state, GALLERY_STATE, mounted)
    return mounted


@asynccontextmanager
async def admin_lifespan(app: Any) -> AsyncIterator[None]:
    """Router lifespan (FastAPI runs it inside the app's own): mount the development gallery, then serve."""
    if mount_development_gallery(app):
        log.info("admin_gallery_mounted", extra={"fields": {"path": "/admin/_gallery"}})
    yield


router = APIRouter(lifespan=admin_lifespan)
router.include_router(auth_router)  # /admin (login), /admin/enroll, /admin/invalidate/*, /admin/api/v1/auth/*
router.include_router(api_router)  # /admin/api/v1/<area>/..., /admin/api/v1/stream, /admin/api/v1/openapi.json

# ---- P11 include point: the dashboard pages (package `roxy/admin/pages/`, router `router`) --------------------------
# `roxy.admin.pages.router` holds `/admin/dashboard`, the shell's `/admin/ui/*` routes and every page of its registry
# (the built ones and "coming soon" for the rest). It is checked (guards, CSRF, paths) before it is included; a page
# module that exists but fails to import raises, as for the API areas.
_pages = optional_import(PAGES_MODULE)
if _pages is not None:
    router.include_router(check_page_router(PAGES_MODULE, getattr(_pages, "router", None)))
# ---- end of the P11 include point ------------------------------------------------------------------------------

# The catch-alls stay LAST (they also step aside for any route added later, but keeping them last keeps the order
# readable). The root one only ever answers methods the login page does not take; `admin_not_found` is the last.
router.add_api_route(
    ADMIN_ROOT_PATH,
    admin_not_found,
    methods=list(CATCH_ALL_METHODS),
    include_in_schema=False,
    name="admin_root_not_found",
    route_class_override=AdminNotFoundRoute,
)
router.add_api_route(
    ADMIN_CATCH_ALL_PATH,
    admin_not_found,
    methods=list(CATCH_ALL_METHODS),
    include_in_schema=False,
    name="admin_not_found",
    route_class_override=AdminNotFoundRoute,
)

__all__ = [
    "ADMIN_CATCH_ALL_PATH",
    "ADMIN_ROOT_PATH",
    "GALLERY_STATE",
    "METHOD_NOT_ALLOWED_CODE",
    "PAGES_MODULE",
    "RESERVED_PAGE_PREFIXES",
    "WRONG_METHOD_SCOPE",
    "AdminNotFoundRoute",
    "admin_lifespan",
    "admin_not_found",
    "check_page_router",
    "mount_development_gallery",
    "router",
]
