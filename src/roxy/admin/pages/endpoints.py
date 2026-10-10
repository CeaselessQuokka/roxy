"""The Endpoints page (`/admin/endpoints`, plan 14.1 Endpoints row; v1 "Top Endpoints", plan 14.1 row 11, parity
rows 74 and 89).

What this is
    * `table` (the page's main table): every endpoint template of the range with v1's Top Endpoints columns
      (requests, methods as `GET:3 POST:1`, last request, last status, last caller, last place) and v2's numbers
      (trend against the comparison, upstream calls, hit ratio, Roblox 429s, failures, latency), searched, filtered
      by host and method, sorted and paged on the server, exported through the API. A row opens its drill-down.
    * `recent` (lazy): the latest requests of one endpoint (the busiest of the range unless another is chosen),
      v1's "Inspect": when, what, the answer, the cache, the time taken, the caller; a row opens the request on the
      Live page's drawer (trace and capture).
    * `detail` (fragment-only, the drawer): the drill-down of one template, the `GET /endpoints/detail` answer:
      totals with their change, requests by outcome and latency over time, its Roblox 429s, its cache rule and
      lifetime, who calls it, the concrete paths behind it, its recent requests, and every rule that applies.
    * `GET /admin/endpoints/template?template=<t>`: the same drill-down as a page of its own (plan 14.1 "drill-down
      page per template"), with the header menu's reset of that one endpoint (plan 6.8 "Single endpoint template").

Why it exists
    v1 showed lifetime counts in a three-level tree and five recent requests per template. v2 keeps the templating
    (placeholders such as `{universeId}`) and the concrete paths, adds trends and the numbers that matter for Roblox,
    and pages on the server so thousands of templates never ship to the browser (row 89). Plan P6: every number is
    the API's own answer (`endpoints_api.table_page`, `detail_answer`, `recent_answer`).

How it works
    `page = Page("endpoints")`. Templates, paths, places and User-Agents are caller text: they are shown through
    `caller_text`, and a template reaches a URL only URL-encoded in the query of a path this site serves (the
    drawer and the drill-down page), through `local_href`. Request ids are checked against the Live API's pattern
    before they go into a drawer URL.

What to read next
    `roxy/admin/api/endpoints.py`, `templates/admin/pages/endpoints/*.html`, `roxy/admin/pages/live.py` (the request
    drawer the recent rows open), `roxy/admin/pages/_traffic_reset.py`.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from typing import Any, Final
from urllib.parse import urlencode

from fastapi import Request
from fastapi.responses import HTMLResponse

from roxy.admin.api import common
from roxy.admin.api import endpoints as endpoints_api
from roxy.admin.api import live as live_api
from roxy.admin.pages import fmt, shell
from roxy.admin.pages._traffic_reset import add_reset_route, endpoint_reset, reset_href
from roxy.admin.pages.kit import (
    Page,
    PageAdmin,
    PageView,
    filter_chip,
    render_card,
    table_query,
    table_view,
    templates_of,
)
from roxy.deps import get_ctx
from roxy.metrics.catalog import METRICS

page = Page("endpoints")
router = page.router

TABLE_ID: Final = "endpoints-table"
SHOWN_COLUMNS: Final = (
    "key",
    "requests",
    "trend_pct",
    "upstream_calls",
    "hit_ratio",
    "roblox_429",
    "failed",
    "p95_ms",
    "methods",
    "last_request_ms",
    "last_status",
    "last_caller",
    "last_place",
    "previous_requests",
    "demand",
    "avoided_pct",
    "p50_ms",
    "p99_ms",
)
KEY_COLUMNS: Final = ("key", "requests", "roblox_429")
HIDDEN_COLUMNS: Final = ("previous_requests", "demand", "avoided_pct", "p50_ms", "p99_ms", "last_place")
METHODS: Final[tuple[str, ...]] = ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
RECENT_ROWS: Final = 25
CHOICES_MAX: Final = 10
DETAIL_TILES: Final[tuple[str, ...]] = (
    "requests",
    "upstream_calls",
    "avoided_pct",
    "hit_ratio",
    "roblox_429",
    "failed",
    "p95_ms",
    "status_5xx",
)
OUTCOME_WORDS: Final[dict[str, str]] = {
    "served_upstream": "Served by Roblox",
    "served_cache": "Served from the cache",
    "refused": "Refused",
    "failed": "Failed",
}
OUTCOME_SERIES: Final[dict[str, dict[str, Any]]] = {
    "requests:served_upstream": {"label": "Served by Roblox", "color": 1},
    "requests:served_cache": {"label": "Served from the cache", "color": 3},
    "requests:refused": {"label": "Refused by Roxy", "color": 4},
    "requests:failed": {"label": "Failed", "color": 8},
}
RULE_FAMILIES: Final[tuple[tuple[str, str, str], ...]] = (
    ("endpoint_block", "Endpoint block", "/admin/protection#endpoint-blocks"),
    ("endpoint_rule", "Endpoint rule (a rate limit)", "/admin/protection#endpoint-rules"),
    ("cache_rule", "Cache rule", "/admin/cache#rules"),
    ("routing_rule", "Routing rule", "/admin/upstream#routing"),
    ("credential_allowlist", "Credential allowlist", "/admin/credential#allowlist"),
)
"""Rule families of the drill-down: the answer's key, the words, and the card that manages them (DESIGN.md 9)."""
COMPARE_WORDS: Final[dict[str, str]] = {
    "previous": "the previous period",
    "week": "the same period last week",
    "month": "the same period last month",
    "year": "the same period last year",
}


# ============================================================================================ helpers


def status_tone(status: Any) -> str:
    code = int(status or 0) if isinstance(status, int | float) or str(status or "").isdigit() else 0
    if code >= 500:
        return "bad"
    if code >= 400:
        return "warn"
    if code >= 300 or code == 0:
        return "muted"
    return "ok"


def ms_text(value: Any) -> str:
    if not isinstance(value, int | float):
        return fmt.MISSING
    return f"{value:,.0f} ms" if value >= 10 else f"{value:,.1f} ms"


def pct_text(value: Any, *, ratio: bool = False) -> str:
    if not isinstance(value, int | float):
        return fmt.MISSING
    return f"{value * 100 if ratio else value:,.1f}%"


def methods_text(methods: Any) -> str:
    """v1's Methods column: `GET:3 POST:1`, busiest first (the API keeps that order)."""
    if not isinstance(methods, Mapping) or not methods:
        return ""
    return " ".join(f"{name}:{int(count)}" for name, count in methods.items())


def template_href(view: PageView, name: str) -> str:
    """The drill-down page of one template (the template URL-encoded in the query; the range kept)."""
    return "/admin/endpoints/template?" + urlencode({**view.time.params, "template": name})


def live_href(name: str) -> str:
    """The Live page filtered to one endpoint (its filter field takes the text; plan 14.1 Live filters)."""
    return "/admin/live?" + urlencode({"endpoint": name})


def request_drawer(request_id: Any) -> str | None:
    """The Live page's request drawer for one request id, or None for an id the Live API would refuse."""
    text = str(request_id or "")
    if not live_api.REQUEST_ID_RE.fullmatch(text):
        return None
    return "/admin/live/request?" + urlencode({"id": text})


def request_rows(view: PageView, rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Live rows as the request tables show them (texts ready; caller text stays raw for `caller_text`)."""
    out = []
    for row in rows:
        at_ms = row.get("at_ms")
        status = row.get("status")
        upstream = row.get("upstream_status")
        cache = str(row.get("cache") or "")
        out.append(
            {
                "request_id": str(row.get("request_id") or ""),
                "drawer": request_drawer(row.get("request_id")),
                "when": view.time_cell(at_ms / 1000 if isinstance(at_ms, int | float) else None),
                "method": str(row.get("method") or ""),
                "url": row.get("url") or row.get("template") or "",
                "query": row.get("query") or "",
                "status": status,
                "status_tone": status_tone(status),
                "upstream_status": upstream if upstream not in (None, status) else None,
                "outcome": OUTCOME_WORDS.get(str(row.get("outcome") or ""), str(row.get("outcome") or "")),
                "reason": str(row.get("reason") or ""),
                "cache": cache if cache and cache != "NA" else "",
                "took": ms_text(row.get("duration_ms")),
                "ip": str(row.get("ip") or ""),
                "place": row.get("place") or "",
                "user_agent": row.get("user_agent") or "",
            }
        )
    return out


def template_problem(error: common.ApiError) -> str:
    """What is wrong with a template from the address, in words (the API's field message)."""
    detail = "; ".join(error.error_fields.values()) or error.error_message
    return f"That endpoint template is not valid: {detail}"


def chosen_template(view: PageView) -> str:
    """The `template` of the address, checked like the API checks it; a missing or bad one is a message (404)."""
    raw = view.param("template", max_chars=endpoints_api.MAX_TEMPLATE_CHARS * 4)
    if not raw:
        raise common.not_found("Choose an endpoint from the table to see its details.")
    try:
        return endpoints_api.checked_template(raw)
    except common.ApiError as error:
        raise common.not_found(template_problem(error)) from None


def row_key(template: Any) -> str:
    """A row id for a template: a short hash (the template is caller text; it never becomes an id itself)."""
    return hashlib.sha256(str(template or "").encode("utf-8", "replace")).hexdigest()[:16]


def direction(key: str) -> common.GoodDirection:
    """Which way is better for a measure (the catalog's `better`), as the KPI tiles say it."""
    spec = METRICS.get(key)
    better = spec.better if spec else "neutral"
    return "up" if better == "higher" else ("down" if better == "lower" else "neutral")


def _choices(current: str | None, base: list[tuple[str, str]]) -> list[tuple[str, str]]:
    values = [value for value, _ in base]
    if current and current not in values:
        return [*base[:1], (current, current), *base[1:]]
    return base


# ============================================================================================ the table


@page.card("table")
async def table_card(view: PageView) -> dict[str, Any]:
    """Every endpoint template of the range (`endpoints_api.table_page`, the API's own function)."""
    spec = endpoints_api.TABLE_SPEC
    tq, notice = table_query(view, spec)
    host = view.state_param("host", max_chars=endpoints_api.MAX_HOST_CHARS)
    method = view.state_param("method", max_chars=12)
    try:
        filters = endpoints_api.table_filters(host or None, method or None)
    except common.ApiError as error:
        filters = {}
        problem = "; ".join(error.error_fields.values()) or error.error_message
        notice = f"The filters in the address were not valid ({problem}); every endpoint is shown."
        host = method = ""
    answer = await endpoints_api.table_page(view.ctx, view.tr, tq, filters)

    def cells(item: Mapping[str, Any]) -> dict[str, Any]:
        trend = item.get("trend_pct")
        previous = item.get("previous_requests")
        if isinstance(trend, int | float):
            trend_cell: Any = {"text": f"{'+' if trend > 0 else ''}{trend:,.1f}%"}
        elif previous == 0 and item.get("requests"):
            trend_cell = {"text": "New", "tone": "info"}
        else:
            trend_cell = None
        last_ms = item.get("last_request_ms")
        when = view.time_cell(last_ms / 1000 if isinstance(last_ms, int | float) else None)
        precision = str(item.get("last_request_precision") or "")
        if when is not None and precision and precision != "exact":
            when = {**when, "sub": f"{when.get('sub', '')}, to the {precision}".strip(", ")}
        status = item.get("last_status")
        return {
            "key": {"text": item.get("key"), "caller": True, "mono": True},
            "trend_pct": trend_cell,
            "avoided_pct": pct_text(item.get("avoided_pct")),
            "hit_ratio": pct_text(item.get("hit_ratio"), ratio=True),
            "p50_ms": ms_text(item.get("p50_ms")),
            "p95_ms": ms_text(item.get("p95_ms")),
            "p99_ms": ms_text(item.get("p99_ms")),
            "methods": {"text": methods_text(item.get("methods")), "caller": True, "mono": True}
            if item.get("methods")
            else None,
            "last_request_ms": when,
            "last_status": {"text": str(status), "tone": status_tone(status), "mono": True}
            if status is not None
            else None,
            "last_caller": {"text": item.get("last_caller"), "mono": True} if item.get("last_caller") else None,
            "last_place": {"text": item.get("last_place"), "caller": True} if item.get("last_place") else None,
        }

    hosts = sorted({str(h) for h in view.ctx.settings.list("allowed_roblox_hosts") if h})
    filter_list = [
        filter_chip("host", "Host", host, _choices(host or None, [("", "Any host"), *((h, h) for h in hosts)])),
        filter_chip(
            "method", "Method", method, _choices(method or None, [("", "Any method"), *((m, m) for m in METHODS)])
        ),
    ]
    table = table_view(
        view,
        TABLE_ID,
        spec,
        answer,
        src=view.fragment_url("table", part="table"),
        columns=SHOWN_COLUMNS,
        key_columns=KEY_COLUMNS,
        hidden=HIDDEN_COLUMNS,
        cells=cells,
        row_id=lambda item: "endpoint-" + row_key(item.get("key")),
        drawer=lambda item: view.fragment_url("detail", template=str(item.get("key") or "")),
        drawer_title=lambda item: "Endpoint " + str(item.get("key") or "")[:160],
        filters=filter_list,
        export_url=view.api_url("endpoints"),
        caption="Endpoint templates",
        empty={
            "title": "No endpoints in this range",
            "body": "An endpoint template appears here the first time a caller asks for it. Choose a longer range "
            "in the top bar, or clear the search and the filters.",
            "icon": "endpoints",
        },
        search_placeholder="Search endpoint templates",
        notice=notice,
    )
    compare = answer.get("compare") or {}
    if view.in_fragment and view.param("part", max_chars=8) == "table":
        return {"part": "table", "table": table}
    return {
        "part": "card",
        "table": table,
        "total": int(answer.get("total") or 0),
        "range_description": view.time.view.get("description"),
        "compare_words": COMPARE_WORDS.get(str(compare.get("mode") or "previous"), "the previous period"),
        "filtered": bool(filters or tq.q),
    }


# ============================================================================================ recent requests


@page.card("recent", lazy=True)
async def recent_card(view: PageView) -> dict[str, Any]:
    """The latest requests of one endpoint (`endpoints_api.recent_answer`); the busiest of the range by default."""
    busiest = await endpoints_api.table_page(
        view.ctx,
        view.tr,
        common.check_table_query(
            endpoints_api.TABLE_SPEC, page=1, page_size=CHOICES_MAX, sort="requests", order="desc", q=None
        ),
        {},
    )
    names = [str(item.get("key")) for item in busiest.get("items") or () if item.get("key")]
    wanted = view.param("template", max_chars=endpoints_api.MAX_TEMPLATE_CHARS * 4)
    chosen = wanted or (names[0] if names else "")
    notice = None
    rows: list[dict[str, Any]] = []
    if chosen:
        try:
            name = endpoints_api.checked_template(chosen)
        except common.ApiError as error:
            notice = f"{template_problem(error)} The busiest endpoint is shown instead."
            name = names[0] if names else ""
        chosen = name
        if name:
            answer = await endpoints_api.recent_answer(view.ctx, name, RECENT_ROWS)
            rows = request_rows(view, answer.get("items") or ())
    options = _choices(chosen or None, [(n, n) for n in names])
    return {
        "chosen": chosen,
        "options": options,
        "rows": rows,
        "notice": notice,
        "detail_href": template_href(view, chosen) if chosen else "",
        "live_href": live_href(chosen) if chosen else "",
    }


# ============================================================================================ the drill-down


@page.card("detail")
async def detail_card(view: PageView) -> dict[str, Any]:
    """One template's drill-down (`endpoints_api.detail_answer`), in the drawer or on its own page."""
    name = chosen_template(view)
    answer = await endpoints_api.detail_answer(view.ctx, view.tr, name)
    totals = answer.get("totals") or {}
    tiles = []
    for key in DETAIL_TILES:
        item = totals.get(key) or {}
        spec = METRICS.get(key)
        tile = common.kpi_tile(
            key,
            label=spec.label if spec else key,
            value=item.get("value"),
            unit=spec.unit if spec else "",
            delta=item.get("delta"),
            delta_pct=item.get("delta_pct"),
            good_direction=direction(key),
            help=spec.description if spec else "",
            notice=item.get("notice"),
        )
        tile["partial"] = bool(item.get("partial"))
        tiles.append(tile)
    compare = answer.get("compare") or {}
    rules = answer.get("rules") or {}
    targets = []
    for target in rules.get("targets") or ():
        found = []
        for key, words, href in RULE_FAMILIES:
            row = target.get(key)
            if row:
                found.append({"family": key, "words": words, "href": href, "row": row})
        targets.append(
            {
                "kind": target.get("kind"),
                "target": target.get("target"),
                "rules": found,
                "ignored": target.get("ignored_path"),
            }
        )
    limits = rules.get("upstream_limits") or {}
    cache = answer.get("cache") or {}
    callers = answer.get("top_callers") or {}
    in_page = view.request.url.path.endswith("/template")
    return {
        "name": name,
        "answer": answer,
        "tiles": tiles,
        "compare_words": COMPARE_WORDS.get(str(compare.get("mode") or "previous"), "the previous period"),
        "outcome_series": OUTCOME_SERIES,
        "u429": answer.get("upstream_429") or {},
        "u429_rows": [
            {
                **row,
                "when": view.time_cell(row.get("at_ms") / 1000 if isinstance(row.get("at_ms"), int | float) else None),
                "drawer": request_drawer(row.get("request_id")),
            }
            for row in (answer.get("upstream_429") or {}).get("recent") or ()
        ],
        "cache": cache,
        "range_callers": callers.get("range") or {},
        "recent_callers": callers.get("last_15_minutes") or {},
        "paths": [
            {
                **path,
                "when": view.time_cell(
                    path.get("last_at_ms") / 1000 if isinstance(path.get("last_at_ms"), int | float) else None
                ),
            }
            for path in answer.get("concrete_paths") or ()
        ],
        "rows": request_rows(view, answer.get("recent_requests") or ()),
        "targets": targets,
        "limits": [
            {"words": words, "row": limits.get(key)}
            for key, words in (("host", "Its host's bucket"), ("endpoint", "Its own bucket"))
            if limits.get(key)
        ],
        "notices": list(answer.get("notices") or ()),
        "in_page": in_page,
        "page_href": template_href(view, name),
        "live_href": live_href(name),
        "reset_href": reset_href("endpoints", template=name),
        "list_href": view.page_url(q=name),
    }


@page.router.get("/template", name="page_endpoints_template", include_in_schema=False)
async def template_page(request: Request, principal: PageAdmin) -> HTMLResponse:
    """The drill-down of one template as a page of its own (plan 14.1): the shell, then the `detail` card."""
    built = await shell.build_shell(request, principal, page.spec, stream_events=page.stream_events)
    view = PageView(
        request=request,
        principal=principal,
        ctx=get_ctx(request),
        page=page.spec,
        time=built.time,
        tz=built.tz,
        prefs=built.prefs,
        latest=built.facts.latest,
        shell=built,
    )
    card = page.card_def("detail")
    assert card is not None  # a registry card of this page (kit raises at import otherwise)
    html = await render_card(view, card)
    context = {
        **built.context,
        "page": {
            **built.context["page"],
            "title": "Endpoint detail",
            "purpose": "One endpoint template over the range: how much it is used, how it is answered, who calls it "
            "and which rules apply to it.",
        },
        "view": view,
        "cards": {"detail": html},
        "card_order": ["detail"],
        "page_assets": page.assets,
    }
    return templates_of(request).render(request, "admin/pages/endpoints/template.html", context)


def _endpoint_reset(view: PageView) -> Any:
    return endpoint_reset(chosen_template(view))


add_reset_route(page, _endpoint_reset)


__all__ = ["page", "router"]
