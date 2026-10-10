"""The page kit: how a dashboard page module declares its cards and gets its routes, guards and fragments.

What this is
    `Page(page_id)` is a page module's handle. `@page.card("log")` registers the renderer of one card (an async
    function that receives a `PageView` and returns the context of the card's template); `page.router` is the
    module's `router`, with the page at `GET /admin/<id>`, every card at `GET /admin/<id>/fragment/<card>` (HTMX
    refreshes, lazy cards, drawers) and any extra route the module adds with `@page.router.get(...)`. Every route
    of the router depends on `require_admin("session")` (`PageAdmin`); an unsafe one must also take `PageCsrf`.
    Helpers for card renderers: `table_view(...)` turns an admin API table answer into the `data_table` macro's
    context (server paging, sorting, search, filter chips, export through the API), `PageView.api_url(...)` and
    `PageView.fragment_url(...)` build URLs that keep the page's time range, `PageView.settings(card_id)` lists a
    card's inline settings.

Why it exists
    Seven builders write eighteen pages in parallel. The kit makes the safe way the easy way: a card renders the
    same template for the first paint and for every fragment (they cannot drift), every card gets its catalog
    settings and its help text from the registry, a card that fails shows an inline error instead of turning the
    page into a 500, the shell (top bar, banners, dialogs) is built once per page by `shell.build_shell`, and page
    routes stay read-only: every change goes through the admin API (forms and inline settings post JSON to it,
    `static/js/api_forms.js`, `static/js/settings_api.js`), so validation, risk rules, fresh second factors and the
    audit log have one implementation.

How it works
    * A page render builds the shell (one control.db and one metrics.db read, which also fetch the last change of
      every setting on the page), then renders every card that is not lazy, concurrently, each into its own
      template `admin/pages/<page>/<card>.html` (or `admin/pages/_card.html`, a settings-only card, when the module
      has no template for it). Lazy cards render a placeholder that loads its fragment when it scrolls into view.
      The page template is `admin/pages/<page>.html` when it exists (it extends `admin/_page.html` and lays the
      cards out from `cards`), else `admin/_page.html` puts them in a column.
    * A card renderer may raise `common.ApiError` (or a known service refusal): the card shows the error message
      in place. Any other exception is logged and the card says it failed; the rest of the page renders.
    * Page assets: `static/css/pages/<page>.css` and `static/js/pages/<page>.js` are linked when the files exist
      (checked once at import, so rendering never touches the disk).

What to read next
    `roxy/admin/pages/audit.py` (the reference page), `templates/admin/_page.html`, `templates/components/
    page_card.html`, `.remake/P11_CONTRACT.md`.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Annotated, Any, Final
from urllib.parse import parse_qsl, urlencode

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from markupsafe import Markup

from roxy.admin.api import common, prefs
from roxy.admin.api.common import API_PREFIX, Column, TableQuery, TableSpec
from roxy.admin.auth.deps import AdminPrincipal, require_admin, require_csrf
from roxy.admin.pages import fmt, inline, registry, shell
from roxy.admin.pages.registry import CardSpec, PageSpec
from roxy.core.templating import STATIC_DIR, TEMPLATES_DIR, Templates
from roxy.deps import get_ctx
from roxy.metrics import queries

log = logging.getLogger("roxy.admin.pages")

page_session = require_admin("session")
"""The guard of every page route (one instance, so FastAPI runs it once per request)."""

PageAdmin = Annotated[AdminPrincipal, Depends(page_session)]
PageFreshAdmin = Annotated[AdminPrincipal, Depends(require_admin("fresh_mfa"))]
PageCsrf = Annotated[None, Depends(require_csrf)]

CardRenderer = Callable[["PageView"], Awaitable[Mapping[str, Any] | None]]

PAGE_TEMPLATE_DIR: Final = "admin/pages"
DEFAULT_PAGE_TEMPLATE: Final = "admin/_page.html"
DEFAULT_CARD_TEMPLATE: Final = "admin/pages/_card.html"
ERROR_CARD_TEMPLATE: Final = "admin/pages/_card_error.html"
LAZY_CARD_TEMPLATE: Final = "admin/pages/_card_lazy.html"
MAX_FRAGMENT_PARAMS: Final = 32
DEFAULT_REFRESH_MIN_S: Final = 15

_KNOWN_ERRORS: Final = (common.ApiError,)


def templates_of(request: Request) -> Templates:
    found = getattr(request.app.state, "templates", None)
    if isinstance(found, Templates):
        return found
    raise RuntimeError("the app has no Templates (create_app sets app.state.templates)")


def _template_exists(name: str) -> bool:
    return (TEMPLATES_DIR / name).is_file()


def _static_exists(name: str) -> bool:
    return (STATIC_DIR / name).is_file()


# ============================================================================================ cards and views


@dataclass(frozen=True, slots=True)
class CardDef:
    """A card of a page module: its registry spec, its renderer and template, and how it loads."""

    spec: CardSpec
    render: CardRenderer | None
    template: str
    lazy: bool = False
    refresh_on: tuple[str, ...] = ()
    refresh_min_s: int = DEFAULT_REFRESH_MIN_S


@dataclass(slots=True)
class PageView:
    """What a card renderer receives: the request, the admin, the worker context, the page and its time range."""

    request: Request
    principal: AdminPrincipal
    ctx: Any
    page: PageSpec
    time: shell.PageTime
    tz: str
    prefs: dict[str, Any]
    latest: dict[str, dict[str, Any]]
    shell: shell.Shell | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def tr(self) -> common.TimeRange:
        """The resolved time range (the same object the API's `TimeRangeDep` builds)."""
        return self.time.tr

    @property
    def now(self) -> float:
        return float(self.ctx.clock.now())

    @property
    def query(self) -> Any:
        return self.request.query_params

    @property
    def in_fragment(self) -> bool:
        """True for a card's own fragment request (`/admin/<page>/fragment/<card>`), False for the page itself."""
        return "/fragment/" in self.request.url.path

    def param(self, name: str, default: str = "", *, max_chars: int = 200) -> str:
        """One query parameter, trimmed and bounded (never raises)."""
        value = self.request.query_params.get(name)
        return default if value is None else value.strip()[:max_chars]

    def state_param(self, name: str, default: str = "", *, address: bool = True, max_chars: int = 200) -> str:
        """A table's search or filter value. The page's main table (`address=True`) reads it on the page and in its
        fragment; any other table only in its own fragment requests, so a filter in the address bar (which belongs
        to the main table) never leaks into a second table on the same page."""
        if not address and not self.in_fragment:
            return default
        return self.param(name, default, max_chars=max_chars)

    def int_param(self, name: str, default: int, *, low: int = 1, high: int = 2**62) -> int:
        try:
            value = int(self.request.query_params.get(name, default))
        except (TypeError, ValueError):
            return default
        return min(max(value, low), high)

    def fragment_url(self, card_id: str, **params: Any) -> str:
        """`/admin/<page>/fragment/<card>?<time range>&<params>`."""
        query = self.time.query(**params)
        return f"/admin/{self.page.id}/fragment/{card_id}" + (f"?{query}" if query else "")

    def page_url(self, **params: Any) -> str:
        query = self.time.query(**params)
        return f"/admin/{self.page.id}" + (f"?{query}" if query else "")

    def api_url(self, path: str, *, time: bool = True, **params: Any) -> str:
        """`/admin/api/v1/<path>?<time range>&<params>` (the URL a chart or an export reads)."""
        values = {**(self.time.params if time else {}), **params}
        query = urlencode({k: v for k, v in values.items() if v is not None and v != ""})
        return f"{API_PREFIX}/{path.lstrip('/')}" + (f"?{query}" if query else "")

    def settings(self, card_id: str) -> list[dict[str, Any]]:
        """The inline settings of one card of this page (control contexts; see `inline.card_settings`)."""
        snapshot = self.ctx.settings.snapshot()
        return inline.card_settings(registry.anchor(self.page.id, card_id), snapshot, self.latest, tz=self.tz)

    def time_cell(self, ts: Any) -> dict[str, Any] | None:
        return fmt.time_cell(ts, self.tz, self.now)


def card_frame(view: PageView, cdef: CardDef) -> dict[str, Any]:
    """The `frame` every card template receives (`components/page_card.html page_card(frame)`)."""
    spec = cdef.spec
    return {
        "card": spec,
        "id": spec.id,
        "title": spec.title,
        "help": spec.help,
        "page_id": view.page.id,
        "anchor": registry.anchor(view.page.id, spec.id),
        "fragment_url": view.fragment_url(spec.id),
        "settings": view.settings(spec.id),
        "settings_open": spec.settings_open,
        "refresh_on": " ".join(cdef.refresh_on),
        "refresh_min_s": cdef.refresh_min_s,
        "lazy": cdef.lazy,
    }


def _base_context(view: PageView) -> dict[str, Any]:
    glossary = view.shell.context["glossary"] if view.shell else shell.glossary_of(view.request)
    return {"view": view, "glossary": glossary, "tz": view.tz, "now": view.now, "time": view.time.view}


async def render_card(view: PageView, cdef: CardDef) -> Markup:
    """One card's HTML (its renderer, then its template); an error renders in place of the card's body."""
    frame = card_frame(view, cdef)
    templates = templates_of(view.request)
    try:
        context = dict(await cdef.render(view) or {}) if cdef.render is not None else {}
        html = templates.render_to_string(
            view.request, cdef.template, {**_base_context(view), "frame": frame, **context}
        )
    except HTTPException as exc:
        parts = common.section13_parts(exc)
        message = parts[1] if parts else "This part of the page could not be loaded."
        html = _error_card(view, frame, message)
    except Exception as exc:  # a card must never take the whole page down (plan: no 500 for a page)
        mapped = common.service_error(exc)
        if mapped is None:
            log.exception("page_card_failed", extra={"fields": {"page": view.page.id, "card": cdef.spec.id}})
            message = "This part of the page failed to load. The error is in the server log; try again shortly."
        else:
            message = mapped.error_message
        html = _error_card(view, frame, message)
    return Markup(html)  # noqa: S704 (rendered by our own autoescaped templates, never by data)


def _error_card(view: PageView, frame: Mapping[str, Any], message: str) -> str:
    return templates_of(view.request).render_to_string(
        view.request, ERROR_CARD_TEMPLATE, {**_base_context(view), "frame": frame, "message": message}
    )


def lazy_card(view: PageView, cdef: CardDef) -> Markup:
    """The placeholder of a lazy card: it loads its fragment when it scrolls into view."""
    frame = card_frame(view, cdef)
    html = templates_of(view.request).render_to_string(view.request, LAZY_CARD_TEMPLATE, {"frame": frame})
    return Markup(html)  # noqa: S704 (rendered by our own autoescaped template)


# ============================================================================================ the page handle


class Page:
    """A dashboard page module's handle (see the module docstring)."""

    def __init__(
        self,
        page_id: str,
        *,
        stream_events: Sequence[str] = shell.DEFAULT_STREAM_EVENTS,
        default_range: str | None = None,
    ) -> None:
        self.spec = registry.page(page_id)
        self.id = page_id
        self.stream_events = tuple(stream_events)
        self.default_range = default_range
        """The range this page opens with when its URL names none (else the admin's `default_range` preference)."""
        self._cards: dict[str, CardDef] = {}
        own = f"{PAGE_TEMPLATE_DIR}/{page_id}.html"
        self.template = own if _template_exists(own) else DEFAULT_PAGE_TEMPLATE
        self.assets = {
            "css": f"css/pages/{page_id}.css" if _static_exists(f"css/pages/{page_id}.css") else None,
            "module": f"js/pages/{page_id}.js" if _static_exists(f"js/pages/{page_id}.js") else None,
        }
        self._router: APIRouter | None = None

    # ---- declaring cards

    def card(
        self,
        card_id: str,
        *,
        template: str | None = None,
        lazy: bool = False,
        refresh_on: Sequence[str] = (),
        refresh_min_s: int = DEFAULT_REFRESH_MIN_S,
    ) -> Callable[[CardRenderer], CardRenderer]:
        """Decorator: `@page.card("log")` registers the renderer of card `log` (a registry card of this page)."""
        spec = registry.card(self.id, card_id)  # KeyError for a card the registry does not know

        def register(render: CardRenderer) -> CardRenderer:
            self._cards[card_id] = CardDef(
                spec=spec,
                render=render,
                template=template or self._card_template(card_id),
                lazy=lazy,
                refresh_on=tuple(refresh_on),
                refresh_min_s=refresh_min_s,
            )
            return render

        return register

    def _card_template(self, card_id: str) -> str:
        own = f"{PAGE_TEMPLATE_DIR}/{self.id}/{card_id}.html"
        return own if _template_exists(own) else DEFAULT_CARD_TEMPLATE

    def cards(self) -> list[CardDef]:
        """Every registry card of this page in order: a registered renderer, or the settings-only default."""
        out: list[CardDef] = []
        for spec in registry.cards_for(self.id):
            found = self._cards.get(spec.id)
            out.append(found or CardDef(spec=spec, render=None, template=self._card_template(spec.id)))
        return out

    def card_def(self, card_id: str) -> CardDef | None:
        return next((c for c in self.cards() if c.spec.id == card_id), None)

    def missing_cards(self) -> list[str]:
        """Registry cards with neither a renderer nor a template nor settings (a builder's to-do list)."""
        missing = []
        for cdef in self.cards():
            has_settings = bool(registry.settings_for(registry.anchor(self.id, cdef.spec.id)))
            if cdef.render is None and cdef.template == DEFAULT_CARD_TEMPLATE and not has_settings:
                missing.append(cdef.spec.id)
        return missing

    # ---- rendering

    async def view(self, request: Request, principal: AdminPrincipal, *, card_ids: Sequence[str] = ()) -> PageView:
        """A `PageView` for a fragment request: the time range and preferences without the whole shell."""
        ctx = get_ctx(request)
        keys = sorted({spec.key for cid in card_ids for spec in registry.settings_for(registry.anchor(self.id, cid))})
        want_earliest = (request.query_params.get("range") or "") == "all"
        user_id = principal.user_id

        def control(conn: Any) -> tuple[Any, Any]:
            return prefs.read_rows(conn, user_id), inline.read_latest(conn, keys)

        rows, latest = await ctx.dbs.control.read(control)
        values = prefs.effective(rows, default_theme=prefs.default_theme_of(ctx.settings))
        default_range = self.default_range or str(values.get("default_range") or common.DEFAULT_RANGE)
        earliest = None
        if want_earliest or (default_range == "all" and not request.query_params.get("range")):
            earliest = await ctx.dbs.metrics.read(queries.earliest_data)
        time = shell.resolve_time(
            request.query_params,
            now=ctx.clock.now(),
            tz=str(ctx.settings.get("ui_timezone") or "UTC"),
            earliest=earliest,
            default_range=default_range,
            default_compare=str(values.get("compare") or "none"),
        )
        return PageView(
            request=request,
            principal=principal,
            ctx=ctx,
            page=self.spec,
            time=time,
            tz=shell.display_tz(ctx, values),
            prefs=values,
            latest=latest,
        )

    def page_setting_keys(self) -> list[str]:
        return sorted(
            {
                spec.key
                for cdef in self.cards()
                if not cdef.spec.fragment_only
                for spec in registry.settings_for(registry.anchor(self.id, cdef.spec.id))
            }
        )

    async def render(self, request: Request, principal: AdminPrincipal) -> HTMLResponse:
        """The whole page: the shell plus every card (lazy ones as placeholders)."""
        built = await shell.build_shell(
            request,
            principal,
            self.spec,
            stream_events=self.stream_events,
            extra_setting_keys=self.page_setting_keys(),
            default_range=self.default_range,
        )
        view = PageView(
            request=request,
            principal=principal,
            ctx=get_ctx(request),
            page=self.spec,
            time=built.time,
            tz=built.tz,
            prefs=built.prefs,
            latest=built.facts.latest,
            shell=built,
        )
        shown = [cdef for cdef in self.cards() if not cdef.spec.fragment_only]
        eager = [cdef for cdef in shown if not cdef.lazy]
        rendered = await asyncio.gather(*(render_card(view, cdef) for cdef in eager))
        cards: dict[str, Markup] = dict(zip((c.spec.id for c in eager), rendered, strict=True))
        for cdef in shown:
            if cdef.lazy:
                cards[cdef.spec.id] = lazy_card(view, cdef)
        context = {
            **built.context,
            "view": view,
            "cards": cards,
            "card_order": [cdef.spec.id for cdef in shown],
            "page_assets": self.assets,
        }
        return templates_of(request).render(request, self.template, context)

    async def fragment(self, request: Request, principal: AdminPrincipal, card_id: str) -> HTMLResponse:
        """One card for HTMX (`GET /admin/<page>/fragment/<card>`); 404 for a card this page does not have."""
        cdef = self.card_def(card_id)
        if cdef is None:
            raise HTTPException(status_code=404, detail="Not Found")
        if len(request.query_params) > MAX_FRAGMENT_PARAMS:
            raise HTTPException(status_code=404, detail="Not Found")
        view = await self.view(request, principal, card_ids=[card_id])
        return HTMLResponse(await render_card(view, cdef))

    # ---- routes

    @property
    def router(self) -> APIRouter:
        """The module's `router`: the page, its card fragments, and any route the module adds to it."""
        if self._router is None:
            router = APIRouter(prefix=f"/admin/{self.id}", dependencies=[Depends(page_session)])

            async def page_route(request: Request, principal: PageAdmin) -> HTMLResponse:
                return await self.render(request, principal)

            async def fragment_route(request: Request, card_id: str, principal: PageAdmin) -> HTMLResponse:
                return await self.fragment(request, principal, card_id)

            router.add_api_route("", page_route, methods=["GET"], name=f"page_{self.id}", include_in_schema=False)
            router.add_api_route(
                "/fragment/{card_id}",
                fragment_route,
                methods=["GET"],
                name=f"page_{self.id}_fragment",
                include_in_schema=False,
            )
            self._router = router
        return self._router


# ============================================================================================ tables


DEFAULT_SIZES: Final[tuple[int, ...]] = common.PAGE_SIZES


def table_query(view: PageView, spec: TableSpec, *, address: bool = True) -> tuple[TableQuery, str | None]:
    """The table's paging, sorting and search from the URL (`page`, `page_size`, `sort`, `order`, `q`, the admin
    API's names). The page's main table (`address=True`, one per page) reads them on the page and in its fragment
    and keeps them in the address bar; another table on the same page (`address=False`) reads them only in its own
    fragment requests and starts from its defaults on a full page load. An invalid value never fails the page: the
    defaults are used and the second value says what was wrong."""
    q = view.request.query_params
    reads = address or "/fragment/" in view.request.url.path

    def raw(name: str) -> str | None:
        value = q.get(name) if reads else None
        return None if value is None else value[:200]

    def number(name: str, default: int) -> int:
        try:
            return int(raw(name) or default)
        except ValueError:
            return -1

    try:
        tq = common.check_table_query(
            spec,
            page=number("page", 1),
            page_size=number("page_size", common.DEFAULT_PAGE_SIZE),
            sort=raw("sort"),
            order=raw("order"),
            q=raw("q"),
        )
        return tq, None
    except common.ApiError as error:
        details = "; ".join(error.error_fields.values()) or error.error_message
        tq = common.check_table_query(spec, page=1, page_size=common.DEFAULT_PAGE_SIZE, sort=None, order=None, q=None)
        return tq, f"The table settings in the address were not valid ({details}); the defaults are shown."


TIME_UNITS: Final = frozenset({"timestamp", "timestamp_ms"})
NUMERIC_UNITS: Final = frozenset({"count", "requests", "bytes", "seconds", "percent", "ratio", "ms", "calls", "rows"})


def is_time_column(column: Column) -> bool:
    """Epoch times: unit `timestamp` or `timestamp_ms` (DESIGN 13.1), or unit `s` on an `at`/`*_at` key (the
    audit and settings history tables label their epoch seconds that way)."""
    return column.unit in TIME_UNITS or (column.unit == "s" and (column.key == "at" or column.key.endswith("_at")))


def _numeric(column: Column) -> bool:
    return not is_time_column(column) and (column.unit in NUMERIC_UNITS or column.unit == "s")


def default_cell(column: Column, value: Any, view: PageView, *, caller: bool) -> Any:
    """How a value of `column` shows in a table by default (pages pass `cells=` to override any column)."""
    if value is None:
        return None
    if is_time_column(column):
        seconds = value / 1000 if column.unit == "timestamp_ms" and isinstance(value, int | float) else value
        return view.time_cell(seconds)
    if caller:
        return {"text": str(value), "caller": True}
    if isinstance(value, Mapping | list | tuple):
        return {"text": str(value), "mono": True}
    return value


def table_view(
    view: PageView,
    table_id: str,
    spec: TableSpec,
    answer: Mapping[str, Any],
    *,
    src: str,
    columns: Sequence[str] | None = None,
    labels: Mapping[str, str] | None = None,
    key_columns: Sequence[str] = (),
    hidden: Sequence[str] = (),
    cells: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
    row_id: Callable[[Mapping[str, Any]], str] | None = None,
    drawer: Callable[[Mapping[str, Any]], str | None] | None = None,
    drawer_title: Callable[[Mapping[str, Any]], str] | None = None,
    filters: Sequence[Mapping[str, Any]] = (),
    keep: Mapping[str, Any] | None = None,
    export_url: str | None = None,
    caption: str = "",
    empty: Mapping[str, Any] | None = None,
    search_placeholder: str = "Search",
    notice: str | None = None,
    address: bool = True,
) -> dict[str, Any]:
    """The `data_table` macro context for an admin API table answer (DESIGN.md 13 shape).

    `columns` picks and orders the API columns to show (default: all); `cells(item)` may return display cells for
    some keys (a dict `{"text", "href", "tone", "mono", "sub", "caller", "datetime"}` or a plain value), the rest use
    `default_cell`. `drawer(item)` is the fragment URL a row opens in the drawer and `drawer_title(item)` its
    heading (plain text; default: the first cell's text). Columns the answer lists in `caller_text` (or
    `Column(caller_text=True)`) are rendered by the caller-text macro, as plain text. `keep` holds page-level
    parameters (the time range) the table's requests carry; `export_url` is the API route (the macro adds
    `format=csv|json` and the current filters). `address` marks the page's main table (see `table_query`; pass the
    same value to both).
    """
    by_key = {column.key: column for column in spec.columns}
    chosen = [by_key[key] for key in (columns or [c.key for c in spec.columns]) if key in by_key]
    caller_keys = set(answer.get("caller_text") or ()) | set(spec.caller_text)
    names = dict(labels or {})
    column_ctx = [
        {
            "key": column.key,
            "label": names.get(column.key, column.label),
            "help": column.help,
            "num": _numeric(column) and column.unit not in ("timestamp", "timestamp_ms"),
            "sortable": column.sortable,
            "key_col": column.key in key_columns or (not key_columns and i < 2),
            "hidden": column.key in hidden,
            "mono": column.ip or column.key in ("request_id", "id"),
        }
        for i, column in enumerate(chosen)
    ]
    rows = []
    for index, item in enumerate(answer.get("items") or ()):
        custom = dict(cells(item)) if cells is not None else {}
        row_cells = {}
        for column in chosen:
            if column.key in custom:
                row_cells[column.key] = custom[column.key]
            else:
                row_cells[column.key] = default_cell(
                    column, item.get(column.key), view, caller=column.key in caller_keys
                )
        rows.append(
            {
                "id": row_id(item) if row_id else str(item.get("id", index)),
                "drawer": drawer(item) if drawer else None,
                "title": drawer_title(item) if drawer_title else None,
                "cells": row_cells,
            }
        )
    keep_values = {k: v for k, v in (keep if keep is not None else view.time.params).items() if v not in (None, "")}
    return {
        "id": table_id,
        "table_name": spec.name,
        "columns": column_ctx,
        "rows": rows,
        "src": _without(src, keep_values),
        "total": int(answer.get("total") or 0),
        "page": int(answer.get("page") or 1),
        "page_size": int(answer.get("page_size") or common.DEFAULT_PAGE_SIZE),
        "sort": answer.get("sort") or spec.default_sort,
        "order": answer.get("order") or spec.default_order,
        "q": (answer.get("q") or view.state_param("q", address=address)),
        "filters": [dict(f) for f in filters],
        "keep": keep_values,
        "export_url": export_url,
        "caption": caption,
        "empty": dict(empty) if empty else None,
        "sizes": DEFAULT_SIZES,
        "search_placeholder": search_placeholder,
        "notice": notice,
        "address": address,
        "defaults": {"page_size": common.DEFAULT_PAGE_SIZE, "sort": spec.default_sort, "order": spec.default_order},
    }


def _without(url: str, names: Mapping[str, Any]) -> str:
    """`url` without the query parameters in `names` (the state form sends them; twice would repeat them)."""
    path, _, query = url.partition("?")
    kept = [(k, v) for k, v in parse_qsl(query, keep_blank_values=True) if k not in names]
    return path + (f"?{urlencode(kept)}" if kept else "")


def filter_chip(name: str, label: str, value: str, options: Sequence[tuple[str, str]]) -> dict[str, Any]:
    """One filter select of a table (`options` as `(value, label)`; the first is usually `("", "All")`)."""
    return {"name": name, "label": label, "value": value, "options": [list(option) for option in options]}


__all__ = [
    "DEFAULT_CARD_TEMPLATE",
    "DEFAULT_PAGE_TEMPLATE",
    "CardDef",
    "Page",
    "PageAdmin",
    "PageCsrf",
    "PageFreshAdmin",
    "PageView",
    "card_frame",
    "default_cell",
    "filter_chip",
    "lazy_card",
    "page_session",
    "render_card",
    "table_query",
    "table_view",
    "templates_of",
]
