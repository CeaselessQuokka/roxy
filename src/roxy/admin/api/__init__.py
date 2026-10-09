"""The admin API package: `api_router` mounts every area module under `/admin/api/v1`, plus the OpenAPI document.

What this is
    `api_router`, an `APIRouter` with the prefix `/admin/api/v1` that includes one router per area module
    (`roxy.admin.api.<area>`, listed in `API_MODULES`), the event stream (`roxy.admin.sse`) and the admin-only
    OpenAPI document (`GET /admin/api/v1/openapi.json`), each area only once its module exists. `MOUNTED` names
    the modules that were included, in inclusion order. `build_api_router(...)` does the work (tests call it with
    their own module lists); `check_area_router(...)` and `check_route(...)` are the mount-time checks every area
    (and the dashboard pages, `roxy/admin/router.py`) passes; `openapi_document(routes)` builds the schema.

Why it exists
    Several specialists write the API areas at the same time. With this package the admin router
    (`roxy/admin/router.py`) includes one router, before its catch-all, and every area's routes are live in the
    real application the moment its module exists, with no edit to shared wiring. A module that is not written yet
    is skipped; a module that exists but fails to import raises, because starting without it would hide a bug.
    The mount-time check turns the DESIGN.md section 13 rules into errors at startup instead of findings in a
    review: every route is guarded by `require_admin`, every POST, PUT, PATCH and DELETE also by `require_csrf`,
    area routes use `common.AdminApiRoute` (so their errors have the section 13 shape and a malformed body is a
    400), and no area claims the API root, another area's prefix or the login surface (`/auth`).
    The schema is the contract between the API and its clients (the dashboard pages, scripts, an LLM reading the
    API), so it is served, but only to a signed-in admin: the public app has no `/openapi.json`, `/docs` or
    `/redoc` (`roxy/main.py`), because a public schema maps the admin surface for an attacker.

How it works
    * For each name, `roxy.lifespan.optional_import` imports `roxy.admin.api.<name>` (None only when that module
      itself is missing). The module must expose `router`, an `APIRouter` with a non-empty prefix of its own
      (`router = common.area_router("<area>")`). Every route under it, nested routers included, is inspected
      through FastAPI's route contexts: its dependency tree must contain the admin guard (`require_admin("session")`
      or `require_admin("fresh_mfa")`, found by the guard's function name in `roxy.admin.auth.deps`) and, for
      unsafe methods, `require_csrf` (from `roxy.admin.auth.deps` or its re-export in `roxy.deps`). A failed check
      raises `ApiMountError` naming the module, the route and the rule. The event stream module follows the same
      rules except the route class (a stream has no body to validate; it uses `area_router("stream")` anyway).
    * Nested prefixes: an area whose prefix lies under another area's (`/export/llm` under `/export`) is included
      before it, so the parent's path parameters (`/export/{dataset}`) never shadow it. Areas keep the
      `API_MODULES` order otherwise.
    * Lazy build: `api_router` and `MOUNTED` are built on first access (a module `__getattr__`, PEP 562), not while
      this package initializes. Every area module (and `roxy.admin.sse`) imports `roxy.admin.api.common`, which
      initializes this package first; building the router at that moment would mount the very module that is
      still half imported and refuse to start. `roxy.admin.router` asks for `api_router`, so the app builds it
      once, after every module can be imported, whatever was imported first.
    * OpenAPI: `GET /admin/api/v1/openapi.json` (guarded like every area route, never in its own schema) answers
      FastAPI's `get_openapi` over the app's routes under `/admin/api/v1` (the login surface, every area and the
      stream), built on a worker thread and kept on `app.state` until the app's admin API routes change.

What to read next
    `roxy/admin/api/common.py` (the shared layer every area uses), `roxy/admin/router.py` (where `api_router` is
    included, before the admin catch-all), then any area module.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator, Sequence
from typing import Any, Final

from fastapi import APIRouter, Request
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute, iter_route_contexts
from starlette.responses import Response

import roxy.deps
from roxy import __version__
from roxy.admin.api.common import API_PREFIX, RESERVED_PREFIXES, AdminApiRoute, AdminSession
from roxy.admin.auth import deps as auth_deps
from roxy.core.errors import is_admin_api_path
from roxy.lifespan import optional_import

API_PACKAGE: Final = "roxy.admin.api"
API_MODULES: Final[tuple[str, ...]] = (
    "settings",
    "audit",
    "prefs",
    "data",
    "export",
    "export_llm",
    "system",
    "protection",
    "clients",
    "security",
    "overview",
    "traffic",
    "endpoints",
    "live",
    "cache",
    "upstream",
    "upstream_limits",
    "routing_rules",
    "egress",
    "rotator",
    "credential",
    "credential_allowlist",
    "lookup",
    "health",
    "recommendations",
)
"""Area modules under `roxy.admin.api`, in mounting order. Each exposes `router = common.area_router("<area>")`."""

SSE_MODULE: Final = "roxy.admin.sse"
"""The event stream (plan 14.11), mounted under the same prefix when it exists (`router` with prefix `/stream`)."""

OPENAPI_PATH: Final = "/openapi.json"
OPENAPI_URL: Final = f"{API_PREFIX}{OPENAPI_PATH}"
OPENAPI_TITLE: Final = "Roxy admin API"
OPENAPI_DESCRIPTION: Final = (
    "The admin API behind the Roxy dashboard (DESIGN.md section 13). Every route needs a signed-in admin session "
    "(the `__Host-roxy_session` cookie); POST, PUT, PATCH and DELETE also need the session's `X-CSRF-Token` from "
    "Roxy's own origin; sensitive actions need a second factor entered within `admin_reauth_window_s` (403 "
    '`reauth_required` otherwise). Errors are `{"error": {"code", "message", "fields"}}`.'
)
OPENAPI_STATE: Final = "admin_api_openapi"
"""Where the built document is kept on `app.state` (with the route signature it was built from)."""

UNSAFE_METHODS: Final[frozenset[str]] = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_GUARD_MODULE: Final = auth_deps.__name__
_ADMIN_GUARD_NAMES: Final[frozenset[str]] = frozenset({"require_admin_session", "require_admin_fresh_mfa"})
_CSRF_GUARDS: Final[tuple[Any, ...]] = (auth_deps.require_csrf, roxy.deps.require_csrf)


class ApiMountError(TypeError):
    """An area module breaks a DESIGN.md section 13 mounting rule (the message names the module and the rule)."""


def _dependency_calls(dependant: Any) -> Iterator[Any]:
    """Every callable in a route's dependency tree (sub-dependencies included)."""
    for child in getattr(dependant, "dependencies", ()) or ():
        yield child.call
        yield from _dependency_calls(child)


def _is_admin_guard(call: Any) -> bool:
    return getattr(call, "__module__", None) == _GUARD_MODULE and getattr(call, "__name__", "") in _ADMIN_GUARD_NAMES


def guard_scopes(dependant: Any) -> frozenset[str]:
    """The admin guard scopes (`session`, `fresh_mfa`) in a dependency tree, and `csrf` when `require_csrf` is in it.

    The security route discovery test and the mount checks read routes the same way, through this function.
    """
    found: set[str] = set()
    for call in _dependency_calls(dependant):
        if _is_admin_guard(call):
            found.add(str(call.__name__).removeprefix("require_admin_"))
        elif call in _CSRF_GUARDS:
            found.add("csrf")
    return frozenset(found)


def check_route(route: Any, path: str, methods: set[str], *, module: str, route_class: bool) -> None:
    """Raise `ApiMountError` unless `route` is a guarded FastAPI route (see the module docstring)."""
    where = f"{module}: {sorted(methods)} {path}"
    if not isinstance(route, APIRoute):
        raise ApiMountError(f"{where} is not a FastAPI route, so its guards cannot be declared or checked")
    if route_class and not isinstance(route, AdminApiRoute):
        raise ApiMountError(f"{where} must use AdminApiRoute; build the router with common.area_router(...)")
    calls = list(_dependency_calls(route.dependant))
    if not any(_is_admin_guard(call) for call in calls):
        raise ApiMountError(f"{where} must depend on require_admin('session') or require_admin('fresh_mfa')")
    if methods & UNSAFE_METHODS and not any(call in _CSRF_GUARDS for call in calls):
        raise ApiMountError(f"{where} changes state and must also depend on require_csrf")


def check_area_router(module: str, router: Any, *, seen: set[str], route_class: bool = True) -> APIRouter:
    """Validate one module's `router` (type, prefix, every route) and return it."""
    if not isinstance(router, APIRouter):
        raise ApiMountError(f"{module} must expose `router`, an APIRouter")
    prefix = router.prefix
    if not prefix or not prefix.startswith("/") or prefix.endswith("/"):
        raise ApiMountError(f"{module}: the router needs a prefix of its own such as '/settings' (got {prefix!r})")
    if prefix in RESERVED_PREFIXES:
        raise ApiMountError(f"{module}: the prefix {prefix!r} is reserved for the login surface")
    if prefix in seen:
        raise ApiMountError(f"{module}: another API module already uses the prefix {prefix!r}")
    for context in iter_route_contexts(router.routes):
        check_route(
            context.original_route,
            str(context.path),
            set(context.methods or ()),
            module=module,
            route_class=route_class,
        )
    seen.add(prefix)
    return router


def _nested_first(areas: list[tuple[str, APIRouter]]) -> list[tuple[str, APIRouter]]:
    """Areas whose prefix has more segments first (a stable sort: same depth keeps the `API_MODULES` order)."""
    return sorted(areas, key=lambda area: -area[1].prefix.count("/"))


# ============================================================================================ OpenAPI


def admin_api_contexts(routes: Sequence[Any]) -> list[Any]:
    """The route contexts of `routes` under `/admin/api/v1` that belong in the schema (`include_in_schema`)."""
    return [
        context
        for context in iter_route_contexts(routes)
        if is_admin_api_path(str(context.path or "")) and getattr(context, "include_in_schema", True)
    ]


def _signature(contexts: Sequence[Any]) -> tuple[tuple[str, tuple[str, ...]], ...]:
    return tuple((str(context.path), tuple(sorted(context.methods or ()))) for context in contexts)


def openapi_document(routes: Sequence[Any]) -> dict[str, Any]:
    """The OpenAPI 3.1 document of the admin API among `routes` (blocking: pydantic builds every schema)."""
    contexts = admin_api_contexts(routes)
    tags = sorted({str(tag) for context in contexts for tag in (getattr(context, "tags", None) or ())})
    return get_openapi(
        title=OPENAPI_TITLE,
        version=__version__,
        description=OPENAPI_DESCRIPTION,
        routes=contexts,
        tags=[{"name": tag} for tag in tags],
    )


async def serve_openapi(request: Request, _admin: AdminSession) -> Response:
    """`GET /admin/api/v1/openapi.json`: the admin API schema, for a signed-in admin only."""
    state = request.app.state
    routes = request.app.router.routes
    signature = _signature(admin_api_contexts(routes))
    cached = getattr(state, OPENAPI_STATE, None)
    if isinstance(cached, tuple) and len(cached) == 2 and cached[0] == signature:
        document = cached[1]
    else:
        document = await asyncio.to_thread(openapi_document, routes)
        setattr(state, OPENAPI_STATE, (signature, document))
    return JSONResponse(document)


def _meta_router() -> APIRouter:
    """The routes this package itself serves under the API prefix (the schema)."""
    meta = APIRouter(route_class=AdminApiRoute)
    meta.add_api_route(
        OPENAPI_PATH,
        serve_openapi,
        methods=["GET"],
        include_in_schema=False,
        name="admin_api_openapi",
        response_model=None,
    )
    for context in iter_route_contexts(meta.routes):
        check_route(
            context.original_route, str(context.path), set(context.methods or ()), module=__name__, route_class=True
        )
    return meta


# ============================================================================================ mounting


def build_api_router(
    modules: Sequence[str] = API_MODULES,
    *,
    package: str = API_PACKAGE,
    sse: str | None = SSE_MODULE,
    meta: bool = False,
) -> tuple[APIRouter, tuple[str, ...]]:
    """An `APIRouter` at `/admin/api/v1` with every existing module's router, and the names that were mounted.

    `meta=True` also adds this package's own routes (the OpenAPI document); the app's `api_router` has them.
    """
    router = APIRouter(prefix=API_PREFIX)
    if meta:
        router.include_router(_meta_router())
    seen: set[str] = set()
    areas: list[tuple[str, APIRouter]] = []
    candidates = [(f"{package}.{name}", True) for name in modules]
    if sse:
        candidates.append((sse, False))  # a stream has no body to validate: exempt from the route class rule only
    for name, route_class in candidates:
        module = optional_import(name)
        if module is None:
            continue  # not written yet
        areas.append(
            (name, check_area_router(name, getattr(module, "router", None), seen=seen, route_class=route_class))
        )
    mounted: list[str] = []
    for name, area in _nested_first(areas):
        router.include_router(area)
        mounted.append(name)
    return router, tuple(mounted)


_BUILT: dict[str, Any] = {}
"""`api_router` and `MOUNTED` once built (see "Lazy build" in the module docstring)."""


def __getattr__(name: str) -> Any:
    """`api_router` and `MOUNTED`, built on first access (PEP 562)."""
    if name not in ("api_router", "MOUNTED"):
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    if not _BUILT:
        router, mounted = build_api_router(meta=True)
        _BUILT.update(api_router=router, MOUNTED=mounted)
    return _BUILT[name]


__all__ = [
    "API_MODULES",
    "API_PACKAGE",
    "MOUNTED",
    "OPENAPI_PATH",
    "OPENAPI_URL",
    "SSE_MODULE",
    "UNSAFE_METHODS",
    "ApiMountError",
    "admin_api_contexts",
    "api_router",
    "build_api_router",
    "check_area_router",
    "check_route",
    "guard_scopes",
    "openapi_document",
]
