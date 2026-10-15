"""Review round 3 (lens apisec): what the admin API mount checks accept as "the admin guard".

What this is
    Tests for finding apisec-9 (fixed; it was a strict xfail). `roxy.admin.api.check_route` (used for every area
    router, the event stream and the P11 pages router) accepted a route when its dependency tree held a callable
    named `require_admin_session` or `require_admin_fresh_mfa` from `roxy.admin.auth.deps`. Every instance made by
    `require_admin(...)` carries those names, including `require_admin("session", allow_bootstrap=True)`, the
    enrollment guard that admits a bootstrap session (password plus emailed code, before any authenticator is
    enrolled, D5). Now the checks read each guard's options (`guard_options`), refuse a guard that admits bootstrap
    sessions outside `deps.ENROLL_PATHS` (also when its options cannot be read: fail closed), and `guard_scopes`
    reports such a guard as `bootstrap` too, so the route discovery test sees it.

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

from roxy.admin.api import ApiMountError, admits_bootstrap, check_area_router, check_route, guard_options, guard_scopes
from roxy.admin.api.common import area_router
from roxy.admin.auth.deps import ENROLL_PATHS, AdminPrincipal, require_admin

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


def test_guard_options_and_scopes_tell_the_bootstrap_guard_apart() -> None:
    assert guard_options(BOOTSTRAP_OK) == {"scope": "session", "allow_bootstrap": True, "activity": "auto"}
    plain = require_admin("session", activity="never")
    assert guard_options(plain) == {"scope": "session", "allow_bootstrap": False, "activity": "never"}
    assert guard_options(len) == {}  # not an admin guard
    assert admits_bootstrap(BOOTSTRAP_OK) is True
    assert admits_bootstrap(plain) is False
    assert admits_bootstrap(require_admin("fresh_mfa")) is False
    router = area_router("zzscopes2")

    @router.get("/x")
    async def x(_admin: BootstrapAdmin) -> dict[str, Any]:
        return {}

    route = router.routes[0]
    assert isinstance(route, APIRoute)
    assert guard_scopes(route.dependant) == frozenset({"session", "bootstrap"})
    enroll_path = sorted(ENROLL_PATHS)[0]
    check_route(route, enroll_path, {"GET"}, module="test", route_class=True)  # the enrollment paths may use it


def test_a_guard_whose_options_cannot_be_read_counts_as_admitting_bootstrap() -> None:
    real = require_admin("session")

    async def require_admin_session(request: Any) -> Any:  # same name and module, but no options to read
        return await real(request)

    require_admin_session.__module__ = real.__module__
    assert guard_options(require_admin_session) == {}
    assert admits_bootstrap(require_admin_session) is True  # fail closed
    marked = require_admin("session")
    marked.allow_bootstrap = True  # type: ignore[attr-defined]  # an explicit attribute wins over the closure
    assert admits_bootstrap(marked) is True
