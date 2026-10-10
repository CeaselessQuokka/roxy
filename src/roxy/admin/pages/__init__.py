"""The dashboard pages (P11): every `/admin/<page>` route, included at the P11 point of `roxy/admin/router.py`.

What this is
    `router` (built on first access) holds, in order: the shared routes of `core.py` (`/admin/dashboard`, the shell's
    `/admin/ui/*` endpoints), then for each of the 18 pages of `registry.PAGES` either the page module's own router
    (`roxy.admin.pages.<id>`, once its builder wrote it) or a "coming soon" route. Its lifespan
    (`dashboard_lifespan`) loads `docs/glossary.yml` at startup (a missing glossary fails the worker's startup and
    so the deploy health gate) and compiles the dashboard templates.
    Submodules: `registry` (pages, cards, the v1 section map), `kit` (`Page`, `PageView`, `table_view`), `shell`
    (the base layout's context), `inline` (inline settings), `texts` (glossary, caller texts, line diff), `fmt`
    (times), `core` (shared routes), `testing` (test harness; never imported by production code).

Why it exists
    `roxy/admin/router.py` includes this package's `router` at its marked include point and checks it with
    `check_page_router` (every route guarded by `require_admin`, unsafe ones by `require_csrf`, no reserved path).
    Building the router here, from the registry, means a builder adds a page by writing one module, and the
    sidebar, the palette and the tests learn about it from the registry, with no edit to shared files.

How it works
    `router` is built lazily (PEP 562 `__getattr__`), like `roxy.admin.api.api_router`, so importing a light
    submodule (`registry`, `texts`) never imports every page and every API module. A page module must expose
    `page` (a `kit.Page`) and `router` (`page.router`); a module that exists but fails to import raises at startup,
    because starting without it would hide a bug.
    Template warming (decision recorded in `.remake/p11_reports/core.md`): the lifespan compiles every template
    under `admin/` and `components/` (the gallery's excepted) on a thread at startup, so the first page an admin
    opens after a deploy does not pay for compiling the shell, and rendering never touches the disk.

What to read next
    `roxy/admin/pages/registry.py`, `roxy/admin/pages/kit.py`, `roxy/admin/pages/audit.py` (the reference page),
    `.remake/P11_CONTRACT.md`.
"""

from __future__ import annotations

import asyncio
import importlib
import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Final

log = logging.getLogger("roxy.admin.pages")

WARM_PREFIXES: Final[tuple[str, ...]] = ("admin/", "components/")
WARM_SKIP: Final[tuple[str, ...]] = ("admin/_gallery/",)
WARM_STATE: Final = "admin_templates_warmed"
"""`app.state` attribute: how many dashboard templates were compiled at startup and how long it took (ms)."""

_BUILT: dict[str, Any] = {}


def warm_dashboard_templates(templates: Any) -> tuple[int, float]:
    """Compile the dashboard's templates (blocking: call it on a thread). Returns (count, milliseconds)."""
    started = time.perf_counter()
    names = [n for n in templates.page_templates(WARM_PREFIXES) if not n.startswith(WARM_SKIP)]
    count = int(templates.warm(names))
    return count, (time.perf_counter() - started) * 1000


@asynccontextmanager
async def dashboard_lifespan(app: Any) -> AsyncIterator[None]:
    """Router lifespan: load the glossary (fail startup when it is missing) and warm the dashboard templates."""
    from roxy.admin.pages import shell
    from roxy.core.templating import Templates

    entries = await shell.load_glossary_into(app)
    templates = getattr(app.state, "templates", None)
    if isinstance(templates, Templates):
        count, ms = await asyncio.to_thread(warm_dashboard_templates, templates)
        setattr(app.state, WARM_STATE, {"templates": count, "ms": round(ms, 1)})
        log.info("dashboard_templates_warmed", extra={"fields": {"templates": count, "ms": round(ms, 1)}})
    log.info("dashboard_glossary_loaded", extra={"fields": {"terms": len(entries)}})
    yield


def build_router() -> Any:
    """The pages router (see the module docstring)."""
    from fastapi import APIRouter

    from roxy.admin.pages import core, registry

    router = APIRouter(lifespan=dashboard_lifespan)
    router.include_router(core.router)
    for spec in registry.PAGES:
        if registry.is_built(spec.id):
            module = importlib.import_module(spec.module)
            page_router = getattr(module, "router", None)
            if not isinstance(page_router, APIRouter):
                raise TypeError(f"{spec.module} must expose `router` (its `Page(...).router`)")
            router.include_router(page_router)
        else:
            router.include_router(core.coming_soon_router(spec))
    return router


def __getattr__(name: str) -> Any:
    """`router`, built on first access (PEP 562)."""
    if name != "router":
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    if "router" not in _BUILT:
        _BUILT["router"] = build_router()
    return _BUILT["router"]


__all__ = ["WARM_PREFIXES", "WARM_STATE", "build_router", "dashboard_lifespan", "router", "warm_dashboard_templates"]
