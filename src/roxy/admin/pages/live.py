"""The Live page (`/admin/live`, plan 14.1 Live row, 14.11; v1 "Live Requests", plan 14.1 row 8, parity rows 81, 82,
126 to 128).

What this is
    * `tail`: the real-time request list (`components/live_tail.html`, `static/js/live_tail.js`) fed by the event
      stream (`GET /admin/api/v1/stream?events=live,kpi`): every worker's requests as they finish, paused while the
      pointer is over it (or with Pause, or the P key), filtered by outcome, status, egress, cache state, client and
      endpoint (the filters also go to the server, which samples above 50 rows a second), keyboard navigable. The
      first screen is the newest rows already recorded: the stream URL carries `last_event_id` just below them, so
      the stream replays them and goes on live (no second request, no gap). A row opens the request drawer. The
      card's button clears the live feed and the captures (plan 6.8 family `live`, v1's Clear).
    * `capture`: what capture keeps (v1's "Capturing 12/250" chip and its window, row 82) and the live records'
      limits (15 minutes, at most 50 rows a second per worker, this worker's count of rows left out), with the
      capture settings inline.
    * `GET /admin/live/request?id=<request id>` (the drawer): one request's live record (row 126 fields), "why did
      this request wait?" (the Upstream API's own explainer), and its capture: request and response headers and
      bodies (redacted when they were captured), or why there is none: "never captured" (capture was off or the
      request was outside the sample) and "expired or evicted" are different messages (row 128).

Why it exists
    v1 polled a merged JSON list every few seconds, missed two outcomes in its filter and showed captures only from
    the worker that kept them (row 81, v1 bugs B16 and B17). v2 pushes every worker's rows over one stream and reads
    captures from the shared database, so any worker answers the drawer.

How it works
    `page = Page("live", stream_events=(..., "kpi"))`: the page-wide stream also carries `kpi`, which refreshes the
    capture card now and then. Filters in the address (`?outcome=refused&endpoint=games...`, the links from the
    Endpoints page) are checked with the Live API's own parser (`live_api.live_query`) and handed to the page
    script, which puts them in the tail's filter fields; `?request=<id>` opens that request's drawer on load. The
    drawer reads `live_api.detail_parts` (the same reads as `GET /live/{request_id}`) and the Upstream API's trace.
    Every field a caller chose (path, query, place, User-Agent, headers, bodies, upstream errors) is shown through
    `caller_text`; nothing from a row ever becomes markup or a link target.

What to read next
    `roxy/admin/api/live.py`, `roxy/admin/sse.py`, `static/js/live_tail.js`, `templates/admin/pages/live/*.html`,
    `static/js/pages/live.js`.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, Final
from urllib.parse import urlencode

from fastapi import Request
from fastapi.responses import HTMLResponse

from roxy.admin.api import common
from roxy.admin.api import live as live_api
from roxy.admin.api import upstream as upstream_api
from roxy.admin.pages import fmt
from roxy.admin.pages._traffic_reset import add_reset_route, family_reset, reset_href
from roxy.admin.pages.kit import CardDef, Page, PageAdmin, PageView, render_card
from roxy.admin.pages.registry import CardSpec
from roxy.admin.pages.shell import DEFAULT_STREAM_EVENTS
from roxy.admin.sse import LIVE_RATE
from roxy.core.reasons import ReasonCode
from roxy.metrics import read_dashboard
from roxy.metrics.capture import CAPTURE_EXPIRED_MESSAGE, CAPTURE_OFF_MESSAGE
from roxy.metrics.live import LIVE_EVENTS_PER_SECOND, LIVE_KEEP_S
from roxy.upstream.read_trace import REASON_TEXT

page = Page("live", stream_events=(*DEFAULT_STREAM_EVENTS, "kpi"))
router = page.router

SEED_ROWS: Final = 40
"""Rows the tail replays on load (the stream's rate gate lets 50 through at once; more would be sampled out)."""
FILTER_NAMES: Final[tuple[str, ...]] = ("outcome", "status", "egress", "cache", "client", "endpoint")
"""The tail's filter fields (`components/live_tail.html`); the address may name them (plan 14.2)."""
STREAM_EVENTS: Final = "live,kpi"
DETAIL_URL: Final = "/admin/live/request?id={id}"
MAX_BODY_CHARS: Final = 20_000
OUTCOME_WORDS: Final[dict[str, str]] = {
    "served_upstream": "Served by Roblox",
    "served_cache": "Served from the cache",
    "refused": "Refused by Roxy",
    "failed": "Failed",
}
SOURCE_WORDS: Final[dict[str, str]] = {
    "roblox": "Roblox (its answer, passed on as it came)",
    "relay": "Roblox (relayed: reshaped by Roxy)",
    "roxy": "Roxy (its own answer)",
    "cache": "Roxy's cache (Roblox never saw it)",
    "internal": "Roxy's own call",
}
EGRESS_WORDS: Final[dict[str, str]] = {
    "direct": "Direct (the server's own address)",
    "credential": "Credential (direct, with the Roblox account)",
    "rotator": "Rotator (DataImpulse)",
    "none": "None (Roblox was not called)",
}
REQUEST_CARD: Final = CardSpec("request", "Request", "One request: its record, its trace and its capture.", True)
REQUEST_TEMPLATE: Final = "admin/pages/live/request.html"


# ============================================================================================ helpers


def address_filters(view: PageView) -> tuple[dict[str, str], str | None]:
    """The tail's filters named in the address, checked with the Live API's parser (bad ones dropped, said so)."""
    values = {name: view.param(name, max_chars=read_dashboard.MAX_FILTER_TEXT) for name in FILTER_NAMES}
    wanted = {name: value for name, value in values.items() if value}
    if not wanted:
        return {}, None
    try:
        live_api.live_query(**wanted)
    except common.ApiError as error:
        bad = ", ".join(sorted(error.error_fields)) or "the filter"
        return {}, f"The live filter in the address was not valid ({bad}); every request is shown."
    return wanted, None


async def seed_after(view: PageView) -> int | None:
    """The event id just below the newest `SEED_ROWS` live rows (the stream replays what comes after it)."""
    pairs: list[tuple[int, dict[str, Any]]] = await view.ctx.dbs.metrics.read(
        lambda conn: read_dashboard.recent_live(conn, SEED_ROWS)
    )
    if not pairs:
        return None
    return max(0, min(int(event_id) for event_id, _row in pairs) - 1)


def pretty_body(text: Any) -> str:
    """A body as text: pretty JSON when it parses (v1 did the same), else as captured; bounded."""
    raw = str(text or "")
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return raw[:MAX_BODY_CHARS]
    if not isinstance(value, dict | list):
        return raw[:MAX_BODY_CHARS]
    return json.dumps(value, indent=2, ensure_ascii=False)[:MAX_BODY_CHARS]


def header_rows(headers: Any) -> list[tuple[str, str]]:
    if not isinstance(headers, Mapping):
        return []
    return [(str(name), str(value)) for name, value in headers.items()]


# ============================================================================================ the tail


@page.card("tail")
async def tail_card(view: PageView) -> dict[str, Any]:
    """The live tail: its stream URL (with the first screen's replay point) and the filters from the address."""
    filters, notice = address_filters(view)
    after = await seed_after(view)
    params: dict[str, Any] = {"events": STREAM_EVENTS}
    if after is not None:
        params["last_event_id"] = after
    return {
        "stream_url": f"{common.API_PREFIX}/stream?{urlencode(params)}",
        "detail_url": DETAIL_URL,
        "filters_json": json.dumps(filters, sort_keys=True),
        "notices": [notice] if notice else [],
        "keep_minutes": LIVE_KEEP_S // 60,
        "worker_rate": int(LIVE_EVENTS_PER_SECOND),
        "stream_rate": int(LIVE_RATE),
        "reset_href": reset_href("live", which="live"),
    }


# ============================================================================================ capture


@page.card("capture", refresh_on=("kpi",), refresh_min_s=30)
async def capture_card(view: PageView) -> dict[str, Any]:
    """What capture keeps now and the live records' limits (`live_api.state_answer`, the `GET /live/state` answer)."""
    state = await live_api.state_answer(view.ctx)
    capture = dict(state.get("capture") or {})
    live = dict(state.get("live") or {})
    oldest = capture.get("oldest_at")
    return {
        "capture": capture,
        "live": live,
        "oldest": view.time_cell(oldest) if oldest else None,
        "keep_minutes": LIVE_KEEP_S // 60,
    }


# ============================================================================================ the request drawer


async def request_context(view: PageView) -> dict[str, Any]:
    """One request for the drawer: its live record, its trace, and its capture or why there is none."""
    raw = view.param("id", max_chars=80)
    if not live_api.REQUEST_ID_RE.fullmatch(raw):
        raise common.not_found(
            "Open a request from the live list: that request id is not valid (1 to 64 letters, digits, - or _)."
        )
    request_id = live_api.checked_request_id(raw)
    found, row, window_s = await live_api.detail_parts(view.ctx, request_id)
    trace: dict[str, Any] | None = None
    trace_problem = None
    try:
        trace = await upstream_api.trace(view.request, view.principal, request_id)
    except common.ApiError as refused:
        trace_problem = refused.error_message
    record = dict(row or {})
    if not record and found:
        record = {
            "request_id": request_id,
            "at_ms": found.get("at_ms"),
            "method": found.get("method"),
            "url": found.get("url"),
            "query": found.get("query"),
            "ip": found.get("ip"),
            "place": found.get("place_id"),
            "user_agent": found.get("user_agent"),
            "status": found.get("status"),
            "upstream_status": found.get("upstream_status"),
            "outcome": found.get("outcome"),
            "reason": found.get("reason"),
            "egress": found.get("egress"),
        }
    missing = None
    if found is None:
        absent = live_api.missing_capture(row)
        missing = {"code": absent.error_code, "message": absent.error_message}
    at_ms = record.get("at_ms")
    reason = str(record.get("reason") or "")
    template = str(record.get("template") or "")
    return {
        "request_id": request_id,
        "record": record,
        "known": bool(row) or bool(found),
        "when": view.time_cell(at_ms / 1000 if isinstance(at_ms, int | float) else None),
        "outcome_words": OUTCOME_WORDS.get(str(record.get("outcome") or ""), str(record.get("outcome") or "")),
        "reason_text": REASON_TEXT.get(reason, "Roxy's protection refused it." if reason else ""),
        "reason_known": reason in {code.value for code in ReasonCode},
        "source_words": SOURCE_WORDS.get(str(record.get("source") or ""), str(record.get("source") or "")),
        "egress_words": EGRESS_WORDS.get(str(record.get("egress") or ""), str(record.get("egress") or "")),
        "took": record.get("duration_ms"),
        "trace": trace,
        "trace_problem": trace_problem,
        "capture": found,
        "request_headers": header_rows((found or {}).get("request_headers")),
        "response_headers": header_rows((found or {}).get("response_headers")),
        "request_body": pretty_body((found or {}).get("request_body")),
        "response_body": pretty_body((found or {}).get("response_body")),
        "missing": missing,
        "expired_message": CAPTURE_EXPIRED_MESSAGE,
        "off_message": CAPTURE_OFF_MESSAGE,
        "window_s": window_s,
        "endpoint_href": ("/admin/endpoints/template?" + urlencode({"template": template})) if template else "",
        "max_body_chars": MAX_BODY_CHARS,
        "ms": fmt.MISSING,
    }


_REQUEST_CARD = CardDef(spec=REQUEST_CARD, render=request_context, template=REQUEST_TEMPLATE)


@page.router.get("/request", name="page_live_request", include_in_schema=False)
async def request_drawer(request: Request, principal: PageAdmin) -> HTMLResponse:
    """The drawer body of one request (live tail rows and the Endpoints page's request tables open it)."""
    view = await page.view(request, principal)
    return HTMLResponse(await render_card(view, _REQUEST_CARD))


add_reset_route(page, lambda view: family_reset(view, ("live",)))


__all__ = ["page", "router"]
