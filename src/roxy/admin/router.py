"""The admin entry router: every `/admin` route the application serves, included by `roxy/main.py`.

What this is
    `router`, an `APIRouter` that includes the admin sub-routers in a fixed order. Today that is the auth surface
    (`admin/auth/routes.py`: the login page `GET /admin`, enrollment, the kill-switch link and
    `/admin/api/v1/auth/*`). The dashboard pages and the rest of the admin API (P9, P11) add their routers here.

Why it exists
    `roxy/main.py` includes one router per area so the order of the whole application is visible in one tuple,
    with the proxy catch-all last. The admin area has several owners, so this module is the single place where
    their routers meet. It deliberately defines no route of its own and no catch-all: a catch-all here would
    shadow admin routes added later (tests add some after `create_app`), and the proxy route already refuses to
    match `/admin` paths, so an unknown admin path gets the framework's plain 404 instead of the proxy pipeline.

How it works
    Plain `include_router` calls. Every included router guards its own routes with `require_admin` and
    `require_csrf` from `admin/auth/deps.py` (re-exported by `roxy/deps.py`); the security tests discover the
    routes from the application and check those guards.

What to read next
    `roxy/admin/auth/routes.py` (the login surface), `roxy/admin/auth/deps.py` (the guards), then `roxy/main.py`.
"""

from __future__ import annotations

from fastapi import APIRouter

from roxy.admin.auth.routes import router as auth_router

router = APIRouter()
router.include_router(auth_router)

__all__ = ["router"]
