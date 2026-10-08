"""The admin entry router: every `/admin` route the application serves, included by `roxy/main.py`.

What this is
    `router`, an `APIRouter` that includes the admin sub-routers in a fixed order. Today that is the auth surface
    (`admin/auth/routes.py`: the login page `GET /admin`, enrollment, the kill-switch link and
    `/admin/api/v1/auth/*`). The dashboard pages and the rest of the admin API (P9, P11) add their routers here.
    LAST comes `AdminNotFoundRoute`, the catch-all for admin paths nothing else serves.

Why it exists
    `roxy/main.py` includes one router per area so the order of the whole application is visible in one tuple,
    with the proxy catch-all last. The admin area has several owners, so this module is the single place where
    their routers meet.
    The catch-all keeps v1's answer for an unknown admin path (plan 4.1 row 15, v1 `admin_not_found`): 404 with
    `"Not Found"` as a JSON string plus a newline, and never a probe. v1 added it because without it every typo
    and every stale bookmark fell through to the proxy route and showed up in the security log as an attack. The
    proxy route already refuses to match `/admin` paths, so without this route FastAPI's own 404 would answer,
    with another body and a probe record. Under `/admin/api/v1` the answer is the DESIGN.md section 13 error
    object instead (`{"error": {"code": "not_found", ...}}`), so the P9 API routers need nothing of their own.

How it works
    Plain `include_router` calls. Every included router guards its own routes with `require_admin` and
    `require_csrf` from `admin/auth/deps.py` (re-exported by `roxy/deps.py`); the security tests discover the
    routes from the application and check those guards. The catch-all needs no guard: it reveals nothing and
    does nothing.
    `AdminNotFoundRoute` matches `/admin/` plus anything, for every method, but steps aside whenever any other
    route of the application matches the request, even partially (a known path with another method keeps its
    405). So real admin routes always win, wherever they sit: earlier in this router, added to this router after
    the catch-all, or added to the app after `create_app` (tests and the development gallery do that). It checks
    by asking every route of the app's top router, once, with a scope flag that makes it step aside from its own
    question; that costs a few regular expression matches, and only for admin paths no earlier route claimed.
    Its answer is `core/errors.py: not_found_response`, the same bytes the `HTTPException` handler sends for a
    plain admin 404 (the network allowlist, D6), so a hidden page and a missing page look identical. It runs no
    error hook, so it is never recorded as a probe.

What to read next
    `roxy/admin/auth/routes.py` (the login surface), `roxy/admin/auth/deps.py` (the guards),
    `roxy/core/errors.py` (`not_found_response`), then `roxy/main.py`.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter
from fastapi.routing import APIRoute
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Match
from starlette.types import Receive, Scope, Send

from roxy.admin.auth.routes import router as auth_router
from roxy.core.errors import not_found_response

log = logging.getLogger("roxy.admin.router")

ADMIN_CATCH_ALL_PATH = "/admin/{rest:path}"
"""Every path below `/admin/` (`/admin` itself is the login page)."""

CATCH_ALL_METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
"""The methods the route declares. Any other method is answered the same way (see `matches`)."""

_ASKING_OTHERS = "roxy.admin_catch_all_asking"
"""Scope flag set while the catch-all asks the other routes, so it does not answer its own question."""


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


class AdminNotFoundRoute(APIRoute):
    """The admin catch-all: v1's 404 for an admin path no other route serves (see the module docstring)."""

    def matches(self, scope: Scope) -> tuple[Match, Scope]:
        if scope.get(_ASKING_OTHERS):
            return Match.NONE, {}
        match, child_scope = super().matches(scope)
        if match is Match.NONE:
            return match, child_scope
        if self.claimed_elsewhere(scope):
            return Match.NONE, {}
        return Match.FULL, child_scope  # every method: a PARTIAL (undeclared method) is still an unknown path

    @staticmethod
    def claimed_elsewhere(scope: Scope) -> bool:
        """True when any other route of the app matches this request, fully or for another method."""
        scope[_ASKING_OTHERS] = True
        try:
            return any(_match_of(route, scope) is not Match.NONE for route in _top_routes(scope))
        finally:
            scope.pop(_ASKING_OTHERS, None)

    async def handle(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Answered here for every method, without dependencies or a method check: there is nothing to resolve.
        await not_found_response(_route_path(scope))(scope, receive, send)


async def admin_not_found(request: Request) -> Response:
    """The catch-all's endpoint (what `AdminNotFoundRoute.handle` sends)."""
    return not_found_response(_route_path(request.scope))


router = APIRouter()
router.include_router(auth_router)
# P9 and P11 include their routers above this line. The catch-all stays LAST (it also steps aside for any route
# added later, but keeping it last keeps the order readable).
router.add_api_route(
    ADMIN_CATCH_ALL_PATH,
    admin_not_found,
    methods=list(CATCH_ALL_METHODS),
    include_in_schema=False,
    name="admin_not_found",
    route_class_override=AdminNotFoundRoute,
)

__all__ = ["ADMIN_CATCH_ALL_PATH", "AdminNotFoundRoute", "admin_not_found", "router"]
