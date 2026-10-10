"""The dashboard's shared routes: `/admin/dashboard`, the "coming soon" pages and the shell's small endpoints.

What this is
    * `GET /admin/dashboard`: v1's dashboard URL (smoke check 173, `GET /admin/dashboard (logged in) -> 200`) and the
      address the login flow sends a signed-in admin to; it renders the Overview page itself (200, not a redirect).
    * `coming_soon_router(spec)`: `GET /admin/<id>` for a registered page whose module is not written yet: the shell
      with the page's purpose and the list of cards it will have, so the navigation works from the start.
    * `GET /admin/ui/setting/{key}?prefix=`: one inline setting control (API mode), re-rendered after a save or when
      the event stream says settings changed (`static/js/settings_api.js`).
    * `GET /admin/ui/palette?q=`: the command palette's server results (settings, recommendations, endpoints; at most
      20, every link a path under `/admin`).
    * `GET /admin/ui/status`: `{paused, throttle_all, signature}`, so an open page notices a pause or emergency
      limit switched elsewhere (`static/js/shell.js`).

Why it exists
    These routes belong to no single page. They are read-only (every change goes through the admin API) and
    guarded like every page route (`require_admin("session")`).

How it works
    Plain FastAPI routes on one `APIRouter`; `roxy.admin.pages.build_router` includes it before the pages.

What to read next
    `roxy/admin/pages/__init__.py`, `roxy/admin/pages/kit.py`, `static/js/palette.js`.
"""

from __future__ import annotations

import importlib
import json
import logging
from typing import Any, Final
from urllib.parse import quote, urlencode

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from roxy.admin.pages import inline, registry, shell
from roxy.admin.pages.kit import PageAdmin, page_session, templates_of
from roxy.admin.pages.registry import PageSpec
from roxy.config import catalog
from roxy.deps import get_ctx
from roxy.insights import read_recommendations
from roxy.metrics import queries

log = logging.getLogger("roxy.admin.pages")

DASHBOARD_PATH: Final = "/admin/dashboard"
COMING_SOON_TEMPLATE: Final = "admin/pages/_coming_soon.html"
SETTING_TEMPLATE: Final = "admin/pages/_setting.html"
MAX_PALETTE: Final = 20
PALETTE_MIN_CHARS: Final = 2
PALETTE_MAX_CHARS: Final = 100
PALETTE_ENDPOINT_WINDOW_S: Final = 86_400

router = APIRouter(dependencies=[Depends(page_session)])


async def render_coming_soon(request: Request, principal: Any, spec: PageSpec) -> HTMLResponse:
    """The shell with a plain "coming soon" body for a registered page that is not built yet."""
    built = await shell.build_shell(request, principal, spec)
    cards = [card for card in registry.cards_for(spec.id) if not card.fragment_only]
    context = {**built.context, "coming_cards": cards}
    return templates_of(request).render(request, COMING_SOON_TEMPLATE, context)


async def render_page(request: Request, principal: Any, page_id: str) -> HTMLResponse:
    """Render page `page_id`: its module's `page` when built, else the coming soon body."""
    spec = registry.page(page_id)
    if registry.is_built(page_id):
        module = importlib.import_module(spec.module)
        handle = getattr(module, "page", None)
        if handle is not None and hasattr(handle, "render"):
            response: HTMLResponse = await handle.render(request, principal)
            return response
    return await render_coming_soon(request, principal, spec)


def coming_soon_router(spec: PageSpec) -> APIRouter:
    """`GET /admin/<id>` for a page that is registered but not built yet."""
    pages = APIRouter(dependencies=[Depends(page_session)])

    async def coming_soon(request: Request, principal: PageAdmin) -> HTMLResponse:
        return await render_coming_soon(request, principal, spec)

    pages.add_api_route(
        spec.href, coming_soon, methods=["GET"], name=f"page_{spec.id}_coming_soon", include_in_schema=False
    )
    return pages


@router.get(DASHBOARD_PATH, include_in_schema=False)
async def dashboard(request: Request, principal: PageAdmin) -> HTMLResponse:
    """v1's dashboard address: the Overview page (200), where the login flow lands."""
    return await render_page(request, principal, "overview")


# ============================================================================================ inline settings


@router.get(f"{inline.SETTING_FRAGMENT_PATH}/{{key}}", include_in_schema=False)
async def setting_fragment(
    request: Request,
    principal: PageAdmin,
    key: str = Path(pattern=r"^[a-z][a-z0-9_]{0,79}$"),
    prefix: str = Query("set", max_length=48),
    saved: int = Query(0, ge=0, le=1),
) -> HTMLResponse:
    """One inline setting control, re-rendered from the live snapshot (after a save or a change elsewhere)."""
    spec = catalog.CATALOG.get(key)
    if spec is None:
        raise HTTPException(status_code=404, detail="Not Found")
    ctx = get_ctx(request)
    latest = await ctx.dbs.control.read(lambda conn: inline.read_latest(conn, [key]))
    tz = str(ctx.settings.get("ui_timezone") or "UTC")
    entry = inline.setting_entry(spec, ctx.settings.snapshot(), latest, tz=tz, prefix=prefix)
    html = templates_of(request).render_to_string(request, SETTING_TEMPLATE, {"entry": entry, "saved": bool(saved)})
    return HTMLResponse(html)


# ============================================================================================ palette


def _title_of(rec: dict[str, Any]) -> str:
    """A recommendation's title from its stored payload (bounded; the rule id when the payload is unreadable)."""
    try:
        payload = json.loads(rec.get("payload_json") or "{}")
    except (TypeError, ValueError):
        payload = {}
    title = payload.get("title") if isinstance(payload, dict) else None
    return str(title or rec.get("rule_id") or "Recommendation")[:160]


def setting_href(spec: Any) -> str:
    """Where the palette sends a setting: its first feature card on a built page, else the Settings page."""
    for anchor in spec.pages:
        page_id, _, card_id = anchor.partition("#")
        if registry.known(page_id) and page_id != "settings" and registry.is_built(page_id):
            card = registry.card(page_id, card_id)
            if card.fragment_only:
                continue
            return f"/admin/{page_id}#{card_id}"
    return f"/admin/settings?{urlencode({'key': spec.key})}"


@router.get("/admin/ui/palette", include_in_schema=False)
async def palette(
    request: Request, principal: PageAdmin, q: str = Query("", max_length=PALETTE_MAX_CHARS)
) -> JSONResponse:
    """Command palette results for `q`: settings, open recommendations and endpoints (at most 20)."""
    text = q.strip().lower()
    if len(text) < PALETTE_MIN_CHARS:
        return JSONResponse([])
    results: list[dict[str, str]] = []
    for spec in catalog.search(text)[:8]:
        results.append(
            {"group": "Settings", "label": spec.label, "hint": spec.key, "href": setting_href(spec), "icon": "sliders"}
        )
    ctx = get_ctx(request)
    now = int(ctx.clock.now())

    def read(conn: Any) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        recs, _total = read_recommendations.list_page(
            conn, read_recommendations.RecommendationFilter(states=("open",), q=text), limit=6
        )
        tz = str(ctx.settings.get("ui_timezone") or "UTC")
        window = queries.Window(now - PALETTE_ENDPOINT_WINDOW_S, now + 1, "hour", tz)
        endpoints = queries.endpoint_table_sync(
            conn, window, page=queries.Page(page=1, size=10, sort="requests", descending=True, search=text)
        )
        return recs, endpoints

    try:
        recs, endpoints = await ctx.dbs.metrics.read(read)
    except Exception:  # the palette degrades to pages and settings; it never fails the admin's search
        log.warning("palette_search_failed", exc_info=True)
        recs, endpoints = [], {}
    for rec in recs:
        title = _title_of(rec)
        results.append(
            {
                "group": "Recommendations",
                "label": title,
                "hint": f"{rec.get('severity', '')} {rec.get('rule_id', '')}".strip(),
                "href": f"/admin/recommendations?{urlencode({'rec': str(rec.get('id') or '')})}",
                "icon": "bulb",
            }
        )
    for row in (endpoints.get("rows") or [])[:6]:
        template = str(row.get("key") or "")[:300]
        results.append(
            {
                "group": "Endpoints",
                "label": template,
                "hint": f"{int(row.get('requests') or 0):,} requests in the last 24 hours",
                "href": f"/admin/endpoints?q={quote(template, safe='')}",
                "icon": "endpoints",
            }
        )
    return JSONResponse(results[:MAX_PALETTE])


@router.get("/admin/ui/status", include_in_schema=False)
async def status(request: Request, principal: PageAdmin) -> Response:
    """The pause and emergency-limit switches as a short signature (the shell checks it on `settings_changed`)."""
    return JSONResponse(await shell.status_signature(get_ctx(request)))


__all__ = ["DASHBOARD_PATH", "coming_soon_router", "render_coming_soon", "render_page", "router", "setting_href"]
