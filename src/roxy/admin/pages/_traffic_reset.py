"""Inline data resets of the Traffic, Endpoints and Live pages (plan 6.8 "inline on page / card").

What this is
    The "Reset these numbers" buttons next to the data they delete: Traffic > Requests (the `traffic` metric
    family), Traffic > Latency (`latency`), the Live page's tail (`live`: the live feed and the captured bodies) and
    one endpoint template's page (the `endpoint` scope). A button opens the drawer at `GET /admin/<page>/reset`,
    which shows the exact preview of the Data API (rows per table, the dates they cover, what stays, whether a
    snapshot is taken first, the phrase to type) and a form that posts the previewed reset to
    `POST /admin/api/v1/data/resets` with its digest, a reason and the typed phrase.

Why it exists
    v1 put a "Clear data" button on every section (dashboard.md 2.10; targets `requests`, `proxy_timings`,
    `endpoints`, `live`), and plan 6.8 keeps resets next to the data they affect, with a preview first, a reason
    for the audit log and, for a full family, the typed scope name. The preview is computed by the Data API's own
    functions (`admin/api/data.py build_plan`, `preview_plan`), which only read, so this page route changes nothing
    (P11 contract: page routes are read-only) and the drawer can never promise something the API would not do: the
    API runs only the scope whose digest the drawer shows.

How it works
    `add_reset_route(page, resolve)` adds `GET /admin/<page>/reset` to a page's router; `resolve(view)` names the
    reset from the query (`which=traffic|latency`, or an endpoint `template`). The drawer body is rendered as a
    fragment-only card (`kit.render_card`, so a bad parameter or a refused scope shows its message in place) from
    `templates/admin/pages/traffic/reset.html`. `reset_href(page_id, **params)` builds the button's drawer URL.

What to read next
    `roxy/admin/api/data.py` (`FAMILIES`, `build_plan`, `preview_plan`, `POST /data/resets`),
    `templates/admin/pages/traffic/reset.html`, `roxy/admin/pages/traffic.py`.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final
from urllib.parse import urlencode

from fastapi import Request
from fastapi.responses import HTMLResponse

from roxy.admin.api import common
from roxy.admin.api import data as data_api
from roxy.admin.pages.kit import CardDef, Page, PageAdmin, PageView, render_card
from roxy.admin.pages.registry import CardSpec

RESET_TEMPLATE: Final = "admin/pages/traffic/reset.html"
RESET_CARD: Final = CardSpec("reset", "Reset", "Preview and confirm a reset of these numbers.", fragment_only=True)
RESET_API: Final = f"{common.API_PREFIX}/data/resets"


@dataclass(frozen=True, slots=True)
class InlineReset:
    """One inline reset: the Data API scope it previews and runs, and the words the drawer shows around it."""

    key: str
    title: str
    lead: str
    body: Mapping[str, Any] = field(default_factory=dict)
    after: str = "The page reloads with the new numbers. A marker on every chart shows when the reset happened."


FAMILY_RESETS: Final[dict[str, InlineReset]] = {
    "traffic": InlineReset(
        "traffic",
        "Reset the traffic numbers",
        "Deletes the request counters behind every Traffic chart and table (and the endpoint, cache and upstream "
        "numbers recorded with the same requests), as v1's Clear data on Traffic, Requests and Status Codes did.",
        {"scope": "family", "families": ["traffic"]},
    ),
    "latency": InlineReset(
        "latency",
        "Reset the latency numbers",
        "Empties the latency and queue wait histograms; the request counts stay (v1's Clear data on Proxy Timings).",
        {"scope": "family", "families": ["latency"]},
    ),
    "live": InlineReset(
        "live",
        "Clear the live feed and the captures",
        "Deletes the live rows of the last 15 minutes and every captured request and response body (v1's Clear on "
        "Live Requests). Requests keep arriving and the list fills again at once.",
        {"scope": "family", "families": ["live"]},
        after="The page reloads. New requests appear in the list as they arrive.",
    ),
}
"""The plan 6.8 metric families these pages reset inline (`admin/api/data.py FAMILIES`: their cards are
`traffic#requests`, `traffic#latency` and `live#tail`)."""


def endpoint_reset(template: str) -> InlineReset:
    """The `endpoint` scope for one template: its rollups, 429 log rows, cooldowns, breakers and cache entries."""
    return InlineReset(
        "endpoint",
        "Reset this endpoint's numbers",
        "Deletes the counters of this one endpoint template, its Roblox 429 log rows, its cooldowns and breakers, "
        "and the cached answers it matches. Rules (blocks, limits, cache rules) and other endpoints stay.",
        {"scope": "endpoint", "template": template},
    )


def reset_href(page_id: str, **params: Any) -> str:
    """The drawer URL of an inline reset: `/admin/<page>/reset?<params>` (values None or "" left out)."""
    query = urlencode({k: v for k, v in params.items() if v not in (None, "")})
    return f"/admin/{page_id}/reset" + (f"?{query}" if query else "")


async def preview_context(view: PageView, reset: InlineReset) -> dict[str, Any]:
    """The drawer's context: the Data API's own preview of `reset` (nothing is deleted here)."""
    now = view.now
    body = data_api.ResetBody.model_validate(dict(reset.body))
    plan = data_api.build_plan(body, view.ctx, now)
    preview = await data_api.preview_plan(view.ctx, plan, now)
    tables = [dict(t) for t in preview.get("tables") or () if int(t.get("rows") or 0) > 0]
    return {
        "reset": reset,
        "preview": preview,
        "tables": tables,
        "families": list(reset.body.get("families") or ()),
        "template": reset.body.get("template"),
        "scope": reset.body.get("scope"),
        "phrase": preview.get("confirm_phrase") or "",
        "api_url": RESET_API,
        "nothing": int(preview.get("total_rows") or 0) == 0 and not preview.get("actions"),
    }


def add_reset_route(page: Page, resolve: Callable[[PageView], InlineReset]) -> None:
    """Add `GET /admin/<page>/reset` (the drawer body) to `page.router`; `resolve(view)` names the reset and may
    raise `common.ApiError` (shown in the drawer) for a parameter it cannot use."""

    async def render(view: PageView) -> dict[str, Any]:
        return await preview_context(view, resolve(view))

    card = CardDef(spec=RESET_CARD, render=render, template=RESET_TEMPLATE)

    @page.router.get("/reset", name=f"page_{page.id}_reset", include_in_schema=False)
    async def reset_drawer(request: Request, principal: PageAdmin) -> HTMLResponse:
        view = await page.view(request, principal)
        return HTMLResponse(await render_card(view, card))


def family_reset(view: PageView, allowed: tuple[str, ...]) -> InlineReset:
    """The family reset named by `?which=` (one of `allowed`), or a 404 the drawer shows."""
    which = view.param("which", max_chars=32)
    if which not in allowed or which not in FAMILY_RESETS:
        raise common.not_found(f"Choose what to reset: {', '.join(allowed)}.")
    return FAMILY_RESETS[which]


__all__ = [
    "FAMILY_RESETS",
    "RESET_API",
    "RESET_TEMPLATE",
    "InlineReset",
    "add_reset_route",
    "endpoint_reset",
    "family_reset",
    "preview_context",
    "reset_href",
]
