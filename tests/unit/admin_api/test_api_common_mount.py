"""Mounting the admin API areas (DESIGN.md section 13): missing modules are skipped, broken ones raise, and every
route must be guarded, use the API route class and keep to its own prefix."""

from __future__ import annotations

import sys
import types
from collections.abc import Iterator
from pathlib import Path
from typing import Annotated, Any

import pytest
from fastapi import APIRouter, Depends
from fastapi.routing import iter_route_contexts
from starlette.responses import PlainTextResponse

import roxy.deps
from roxy.admin.api import API_MODULES, SSE_MODULE, ApiMountError, build_api_router
from roxy.admin.api.common import AdminFreshMfa, AdminSession, CsrfChecked, TimeRange, area_router, time_range
from roxy.admin.auth.deps import require_admin

PACKAGE = "roxy.admin.api"


@pytest.fixture
def fake_modules() -> Iterator[dict[str, Any]]:
    """Place modules under `roxy.admin.api.*` in sys.modules (removed afterwards)."""
    placed: dict[str, Any] = {}

    def place(name: str, router: Any = None, *, full: str | None = None) -> str:
        module_name = full or f"{PACKAGE}.{name}"
        module = types.ModuleType(module_name)
        if router is not None:
            module.router = router  # type: ignore[attr-defined]
        sys.modules[module_name] = module
        placed[module_name] = module
        return name

    yield {"place": place}
    for module_name in placed:
        sys.modules.pop(module_name, None)


def guarded_area(area: str = "probe") -> APIRouter:
    router = area_router(area)

    @router.get("/read")
    async def read(_admin: AdminSession) -> dict[str, bool]:
        return {}

    @router.post("/write")
    async def write(_admin: AdminSession, _csrf: CsrfChecked) -> dict[str, bool]:
        return {}

    return router


def test_api_module_list_is_the_planned_one() -> None:
    assert API_MODULES == (
        "settings", "audit", "prefs", "data", "export", "export_llm", "system", "protection", "clients", "security",
        "overview", "traffic", "endpoints", "live", "cache", "upstream", "upstream_limits", "routing_rules", "egress",
        "rotator", "credential", "credential_allowlist", "lookup", "health", "recommendations",
    )  # fmt: skip
    assert SSE_MODULE == "roxy.admin.sse"


def test_missing_modules_are_skipped() -> None:
    router, mounted = build_api_router(("zz_not_written_yet", "zz_nor_this"), sse="roxy.admin.zz_no_stream")
    assert mounted == ()
    assert router.prefix == "/admin/api/v1"
    assert list(iter_route_contexts(router.routes)) == []


def test_a_module_that_fails_to_import_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    package = tmp_path / "zz_fake_api_pkg"
    package.mkdir()
    (package / "__init__.py").write_text('"""Fake package."""\n', encoding="utf-8")
    (package / "broken.py").write_text("import zz_roxy_dependency_that_does_not_exist  # noqa\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    try:
        with pytest.raises(ModuleNotFoundError) as caught:
            build_api_router(("broken",), package="zz_fake_api_pkg", sse=None)
        assert caught.value.name == "zz_roxy_dependency_that_does_not_exist"
        _, mounted = build_api_router(("absent",), package="zz_fake_api_pkg", sse=None)
        assert mounted == ()
    finally:
        for name in [n for n in sys.modules if n.startswith("zz_fake_api_pkg")]:
            sys.modules.pop(name, None)


def test_a_guarded_area_is_mounted_under_the_api_prefix(fake_modules: dict[str, Any]) -> None:
    name = fake_modules["place"]("zz_probe", guarded_area())
    router, mounted = build_api_router((name,), sse=None)
    assert mounted == (f"{PACKAGE}.zz_probe",)
    found = {(context.path, frozenset(context.methods or ())) for context in iter_route_contexts(router.routes)}
    assert found == {
        ("/admin/api/v1/probe/read", frozenset({"GET"})),
        ("/admin/api/v1/probe/write", frozenset({"POST"})),
    }


def test_module_must_expose_an_api_router_with_its_own_prefix(fake_modules: dict[str, Any]) -> None:
    place = fake_modules["place"]
    cases = {"zz_no_router": None, "zz_not_a_router": object(), "zz_no_prefix": APIRouter()}
    for name, router in cases.items():
        place(name, router)
    for name in ("zz_no_router", "zz_not_a_router", "zz_no_prefix"):
        with pytest.raises(ApiMountError):
            build_api_router((name,), sse=None)
    reserved = APIRouter(prefix="/auth")
    place("zz_reserved", reserved)
    with pytest.raises(ApiMountError, match="reserved"):
        build_api_router(("zz_reserved",), sse=None)
    place("zz_one", guarded_area("same"))
    place("zz_two", guarded_area("same"))
    with pytest.raises(ApiMountError, match="already uses"):
        build_api_router(("zz_one", "zz_two"), sse=None)


def test_area_routes_must_use_the_api_route_class(fake_modules: dict[str, Any]) -> None:
    plain = APIRouter(prefix="/plain")

    @plain.get("/read")
    async def read(_admin: AdminSession) -> dict[str, bool]:
        return {}

    fake_modules["place"]("zz_plain", plain)
    with pytest.raises(ApiMountError, match="AdminApiRoute"):
        build_api_router(("zz_plain",), sse=None)
    # The event stream is exempt from the route class rule (it has no body), not from the guards.
    fake_modules["place"]("", plain, full="roxy.admin.zz_stream")
    _, mounted = build_api_router((), sse="roxy.admin.zz_stream")
    assert mounted == ("roxy.admin.zz_stream",)


def test_every_route_needs_the_admin_guard(fake_modules: dict[str, Any]) -> None:
    router = area_router("open")

    @router.get("/read")
    async def read() -> dict[str, bool]:
        return {}

    fake_modules["place"]("zz_open", router)
    with pytest.raises(ApiMountError, match="require_admin"):
        build_api_router(("zz_open",), sse=None)


def test_state_changing_routes_need_csrf(fake_modules: dict[str, Any]) -> None:
    for method in ("post", "put", "patch", "delete"):
        router = area_router(f"nocsrf_{method}")
        getattr(router, method)("/change")(_change_without_csrf)
        fake_modules["place"](f"zz_nocsrf_{method}", router)
        with pytest.raises(ApiMountError, match="require_csrf"):
            build_api_router((f"zz_nocsrf_{method}",), sse=None)


async def _change_without_csrf(_admin: AdminSession) -> dict[str, bool]:
    return {}


def test_guards_are_found_in_every_accepted_form(fake_modules: dict[str, Any]) -> None:
    router = area_router("forms")

    @router.post("/fresh")
    async def fresh(_admin: AdminFreshMfa, _csrf: Annotated[None, Depends(roxy.deps.require_csrf)]) -> dict[str, bool]:
        return {}

    @router.get("/via-time-range")
    async def via_range(_tr: Annotated[TimeRange, Depends(time_range)]) -> dict[str, bool]:
        return {}  # the guard is a sub-dependency of time_range

    @router.delete("/decorator", dependencies=[Depends(require_admin("session")), Depends(roxy.deps.require_csrf)])
    async def decorator() -> dict[str, bool]:
        return {}

    fake_modules["place"]("zz_forms", router)
    _, mounted = build_api_router(("zz_forms",), sse=None)
    assert mounted == (f"{PACKAGE}.zz_forms",)


def test_nested_and_plain_routes_are_checked(fake_modules: dict[str, Any]) -> None:
    outer = area_router("outer")
    inner = APIRouter(prefix="/inner", route_class=outer.route_class)

    @inner.get("/open")
    async def open_route() -> dict[str, bool]:
        return {}

    outer.include_router(inner)
    fake_modules["place"]("zz_nested", outer)
    with pytest.raises(ApiMountError, match=r"/outer/inner/open"):
        build_api_router(("zz_nested",), sse=None)
    starlette = area_router("starlette")

    async def raw(request: Any) -> PlainTextResponse:
        return PlainTextResponse("x")

    starlette.add_route("/raw", raw)
    fake_modules["place"]("zz_starlette", starlette)
    with pytest.raises(ApiMountError, match="not a FastAPI route"):
        build_api_router(("zz_starlette",), sse=None)
