"""Review round 3 (lens apisec): what the admin API mount checks accept as "the admin guard".

What this is
    Strict-xfail test for finding apisec-9. `roxy.admin.api.check_route` (used for every area router, the event
    stream and the P11 pages router) accepts a route when its dependency tree holds a callable named
    `require_admin_session` or `require_admin_fresh_mfa` from `roxy.admin.auth.deps`. Every instance made by
    `require_admin(...)` carries those names, including `require_admin("session", allow_bootstrap=True)`, the
    enrollment guard that admits a bootstrap session (password plus emailed code, before any authenticator is
    enrolled, D5). A route guarded that way passes the mount check and the route discovery test
    (`guard_scopes` reports it as `session`), so the checks cannot catch the one guard that must never appear
    outside the enrollment routes.

Why it exists
    DESIGN.md 13.1 makes the mount checks the gate that refuses to start an app with a weaker route, precisely so
    a mistake by one of many authors is caught at startup instead of in a review. Today no area uses the
    bootstrap guard; the check simply would not notice the day one does (a copy of an enrollment route's
    signature is enough), and the P11 pages are still to be written.

How it works
    A throwaway area router gets one route guarded by the bootstrap-permitting guard; `check_area_router` should
    refuse it with `ApiMountError`. A control proves the check does refuse a route with no guard at all.

What to read next
    `roxy/admin/api/__init__.py` (`check_route`, `_is_admin_guard`, `guard_scopes`), `roxy/admin/auth/deps.py`
    (`require_admin`, `ENROLL_PATHS`), `roxy/admin/auth/routes.py` (`AdminEnroll`).
"""

from __future__ import annotations

from typing import Annotated, Any

import pytest
from fastapi import Depends
from fastapi.routing import APIRoute

from roxy.admin.api import ApiMountError, check_area_router
from roxy.admin.api.common import area_router
from roxy.admin.auth.deps import AdminPrincipal, require_admin

BOOTSTRAP_OK = require_admin("session", allow_bootstrap=True)
"""Module level on purpose: FastAPI resolves the postponed annotations of a route against its module's globals."""
BootstrapAdmin = Annotated[AdminPrincipal, Depends(BOOTSTRAP_OK)]


def test_an_unguarded_route_is_refused() -> None:
    """Control (passes today)."""
    router = area_router("zzopen")

    @router.get("/x")
    async def x() -> dict[str, Any]:
        return {}

    with pytest.raises(ApiMountError, match="require_admin"):
        check_area_router("zzopen", router, seen=set())


@pytest.mark.xfail(
    strict=True,
    reason="finding apisec-9: the mount check accepts require_admin('session', allow_bootstrap=True) as the guard",
)
def test_a_bootstrap_session_guard_is_refused_outside_enrollment() -> None:
    router = area_router("zzboot")

    @router.get("/x")
    async def x(_admin: BootstrapAdmin) -> dict[str, Any]:
        return {}

    route = router.routes[0]
    assert isinstance(route, APIRoute)
    assert route.dependant.dependencies[0].call is BOOTSTRAP_OK  # the guard really is in the tree
    with pytest.raises(ApiMountError):
        check_area_router("zzboot", router, seen=set())
