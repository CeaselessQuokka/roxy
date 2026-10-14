"""The Protection page (`/admin/protection`, plan 14.1, 10.9): who Roxy turns away and how, with every control.

What this is
    The largest dashboard page: twenty registry cards plus one card per spam detector, in six groups (the "On this
    page" list at the top links them):
      * Overview: `pipeline` (every check in order with its refusals in the range, plan 10.9, row 5) and
        `refusals` (v1 "Refusal Reasons" with the custom or default message split, rows 10, 72, 116; and the
        clients refused most, plan 10.9, read with the Clients page's own `client_table_answer`).
      * Limits: `throttle` (the per-IP limit, who is throttled now, the throttled history, the limiter reset; rows 6,
        26, 118), `ladder` (the ladder editor, rung hits, restore defaults and v1's repeat offender simulation; rows
        40, 76, 125), `strikes` (the strike board with forgive; row 41), `throttle-all` (the emergency limit and who
        it turned away since it was switched on, refused most first; rows 4, 135), `limits` and `places`.
      * Who: `bans` (countdowns, evidence, ban, lift, reset), `lists` (deny list and admin allowlist), `bypass`
        (bypass entries and "Bypass my IP"; rows 13, 113).
      * Rules: `ua-rules` (with the tester; row 44), `request-filters` (with the tester, presets and the attempts
        tab; rows 15, 18, 45), `endpoint-blocks` and `endpoint-rules` (each with its attempts tab; rows 12, 16, 17,
        43, 46, 75), `ignored-paths` (row 50).
      * Detectors: `spam` (master switches, decisions, the collateral preview and arm or disarm; plan 10.3),
        `spam-<detector>` (one card per detector, its settings), `bot` and `challenge` (plan 10.7, 10.8).
      * Tarpit: `tarpit` (state, the effective cap gauge, v1's four tiles, categories, hold lengths and who is held;
        rows 14, 47, 78, 123).

Why it exists
    Plan 10.9: "Protection page shows the pipeline diagram with per-check hit counts for the selected range, top
    refused clients, active bans with countdowns and evidence, strike board, tarpit gauge, detector timelines, and
    each check's settings inline." v1 spread this over fourteen dashboard sections; every number, table, action and
    setting of those sections lives here with the same meaning (plan 14.1 map, rows 4, 6, 10, 12 to 18, 26).

How it works
    Every card calls the same helper the admin API route calls (`roxy/admin/api/protection.py`: `pipeline_answer`,
    `bans_answer`, `attempts_answer`, ...), so the page and `GET /admin/api/v1/protection/...` can never disagree
    (DESIGN.md 13). Every change goes through that API: forms post JSON (`static/js/api_forms.js`), inline settings
    through the settings API, the ladder editor and the testers through `static/js/pages/protection.js`.
    Only the pipeline renders with the page; every other card is lazy (it loads as an HTMX fragment when scrolled
    into view), so the first paint stays small on the 1 GB server.
    One card fragment route serves three things, chosen by its query: the whole card (no parameter: the lazy load,
    a refresh after an action), one of the card's tables (`table=<key>`: the table's own search, sort, filter and
    paging request, answered with just that table so it swaps in place), and a row's details for the drawer
    (`detail=<id>`). A table reads its search, sort, filters and page only from its own requests (`address=False`):
    a page with seventeen tables has no single main table to keep in the address bar.
    Caller text (paths, User-Agents, rule needles and patterns, notes and messages an admin or a caller typed) is
    rendered only through `format.html caller_text`; links built from data only through `local_href`.

What to read next
    `roxy/admin/pages/_protection_views.py` (labels, the pipeline model, the repeat offender timeline, the tarpit
    tiles), `templates/admin/pages/protection.html` and `templates/admin/pages/protection/*.html`,
    `static/js/pages/protection.js`, `roxy/admin/api/protection.py`.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from typing import Any, Final, Literal, cast
from urllib.parse import urlencode

from roxy.abuse.read_bans import AUTO_DETECTORS
from roxy.abuse.throttle import decays_in, effective_strikes, ladder_from, load_strike_rows, rung_for
from roxy.admin.api import clients as clients_api
from roxy.admin.api import common
from roxy.admin.api import data as data_api
from roxy.admin.api import protection as prot
from roxy.admin.api.common import API_PREFIX, TableQuery, TableSpec
from roxy.admin.pages import _protection_views as pv
from roxy.admin.pages import shell
from roxy.admin.pages.clients import canonical_ip, client_href
from roxy.admin.pages.kit import Page, PageView, filter_chip, table_query, table_view
from roxy.admin.pages.texts import bypass_scope
from roxy.config.constants import MAX_THROTTLE_MULTIPLIER, MAX_THROTTLE_TIERS, TARPIT_CATEGORIES
from roxy.metrics import queries, read_producers

log = logging.getLogger("roxy.admin.pages")

page = Page("protection", stream_events=(*shell.DEFAULT_STREAM_EVENTS, "kpi"))
router = page.router

TABLE_PARAM: Final = "table"
DETAIL_PARAM: Final = "detail"
API: Final = API_PREFIX + "/protection"
DETECTORS: Final[tuple[str, ...]] = ("rate", "refused", "probe", "auth", "enum", "bust", "dist")
LIMIT_REASONS: Final[tuple[str, ...]] = (
    "flood",
    "body_too_large",
    "headers_too_large",
    "url_too_long",
    "method_not_allowed",
)
"""Refusals the Request limits card counts (the flood limit and the size and method limits of plan 9.12)."""
BAN_STATES: Final[tuple[str, ...]] = ("active", "expired", "all")
BAN_ORIGINS: Final[tuple[str, ...]] = ("any", "manual", "auto")
BAN_SUBJECTS: Final[tuple[str, ...]] = ("", "ip", "cidr", "place", "ua_hash")
SUBJECT_LABELS: Final[dict[str, str]] = {"ip": "Address", "cidr": "Network", "place": "Place", "ua_hash": "User-Agent"}
"""The words for a ban's subject type (the API's `ip`, `cidr`, `place`, `ua_hash`), as the Type filter says them."""
ORIGIN_LABELS: Final[dict[str, str]] = {"manual": "An admin", "auto": "A detector"}
"""Who made a ban (the API's `manual` or `auto`), as the "Made by" filter says it."""
SPAM_KINDS: Final[tuple[str, ...]] = ("all", "would_ban", "ban", "strike", "tarpit", "recommend")
TARPIT_WINDOWS: Final[tuple[tuple[str, int], ...]] = (("15m", 900), ("1h", 3600), ("24h", 86_400))
"""v1's "Last 15m", "Last hour" and "Last 24h" tarpit figures (now fleet-wide, from the hold statistics history)."""
TARPIT_HOUR_S: Final = 3600
TARPIT_BASELINE_MIN_S: Final = 86_400
"""The tarpit trend compares the last hour with the period just before it: the range's length, at least a day (v1
compared the hour with the lifetime gap; finding v1parity-10: the range alone made the 1 h trend compare the hour
with itself)."""
MAX_WORKER_ROWS: Final = 25
"""Rows of the per-worker tarpit tables shown ("why each hold happened", "callers held"), busiest first."""
MAX_DETAIL_CHARS: Final = 80
REFUSED_CLIENTS_SORT: Final = "refused"
REFUSED_CLIENTS_ROWS: Final = 10
"""The "Clients refused most" tab: the Clients page's address table, most refusals first, ten rows at first."""


# ============================================================================================ table plumbing


def default_query(spec: TableSpec) -> TableQuery:
    """A table's first page in its default order (what every table shows on a full card render)."""
    return common.check_table_query(spec, page=1, page_size=common.DEFAULT_PAGE_SIZE, sort=None, order=None, q=None)


def asked(view: PageView, key: str) -> bool:
    """True for a request of table `key` itself (its search, sort, filter or paging)."""
    return view.in_fragment and view.param(TABLE_PARAM, max_chars=40) == key


def query_for(view: PageView, spec: TableSpec, key: str) -> tuple[TableQuery, str | None]:
    """The table's paging, sorting and search: from its own request, else the defaults (never an error)."""
    if asked(view, key):
        return table_query(view, spec, address=False)
    return default_query(spec), None


def choice(view: PageView, key: str, name: str, choices: Sequence[str]) -> str:
    """A table filter's value from the table's own request; anything not in `choices` is the default (the first)."""
    if not asked(view, key):
        return choices[0]
    value = view.param(name, max_chars=40)
    return value if value in choices else choices[0]


def only_table(view: PageView, keys: Sequence[str]) -> str | None:
    """The one table a fragment request asks for (rendered alone, so it swaps in place), else None (the card)."""
    if not view.in_fragment:
        return None
    value = view.param(TABLE_PARAM, max_chars=40)
    return value if value in keys else None


def detail_of(view: PageView) -> str:
    """The row a drawer request names (`detail=<id>`), "" for a card or table request."""
    return view.param(DETAIL_PARAM, max_chars=MAX_DETAIL_CHARS) if view.in_fragment else ""


def table(
    view: PageView,
    card: str,
    key: str,
    spec: TableSpec,
    answer: Mapping[str, Any],
    *,
    export: str,
    **options: Any,
) -> dict[str, Any]:
    """`kit.table_view` for a table of this page: its own fragment (`table=<key>`), its export through the API
    route `export` (the macro adds the range, the search and the filters), and no address bar state.
    `searchable=False` hides the search box of a table whose read model has no search (the watch tables)."""
    searchable = bool(options.pop("searchable", True))
    context = table_view(
        view,
        f"prot-{key}",
        spec,
        answer,
        src=view.fragment_url(card, **{TABLE_PARAM: key}),
        export_url=f"{API}/{export}",
        address=False,
        **options,
    )
    context["searchable"] = searchable
    return context


def row_key(text: Any) -> str:
    """A short stable id for a row named by text (a path or a pattern): DOM ids must not carry caller text."""
    return hashlib.blake2s(str(text).encode("utf-8", "replace"), digest_size=6).hexdigest()


def covers(cidr: str, ip: str) -> bool:
    """True when the network `cidr` holds the address `ip` (the admin's own address, for the lockout warning)."""
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except (TypeError, ValueError):
        return False


def rule_hits_url(view: PageView, table_name: str, rule_id: Any) -> str:
    """The API series of one rule row's hits over the page's range (`GET /protection/rule-hits`)."""
    return view.api_url("protection/rule-hits", table=table_name, rule_id=str(rule_id))


def _caller(value: Any) -> dict[str, Any] | None:
    """A caller text cell (rendered by `format.html caller_text`), None for an empty value."""
    if value is None or value == "":
        return None
    return {"text": str(value), "caller": True}


def _mono(value: Any) -> dict[str, Any] | None:
    return None if value is None or value == "" else {"text": str(value), "mono": True}


def _span(seconds: Any, *, zero: str = "n/a") -> dict[str, Any] | None:
    if seconds is None:
        return None
    if not seconds:
        return {"text": zero, "tone": "muted"}
    return {"text": pv.span_words(seconds)}


def _hits_cells(view: PageView, item: Mapping[str, Any]) -> dict[str, Any]:
    return {"last_hit_at": view.time_cell(item.get("last_hit_at"))}


def _setting(view: PageView, key: str) -> Any:
    return view.ctx.settings.get(key)


def _find(rows: Sequence[Mapping[str, Any]], key: str, value: str) -> dict[str, Any] | None:
    for row in rows:
        if str(row.get(key)) == value:
            return dict(row)
    return None


def _not_found(what: str) -> common.ApiError:
    return common.not_found(f"No {what} has that id. It may have been removed; close this and refresh the card.")


CLEARS: Final[dict[str, dict[str, Any]]] = {
    "refusals": {
        "button": "Clear refusal records",
        "title": "Clear the refusal records?",
        "consequences": [
            "Every refusal record goes: each reason's last status and path, its clients, first and last seen and "
            "the message split start again from the next refusal (v1's Clear data on Refusal Reasons).",
            "The counts per reason stay: they are part of the traffic totals (the Data page resets those). The "
            "attempts tabs of the endpoint blocks, endpoint rules and request filters read these records, so they "
            "start again too. Rules, bans and lists stay.",
        ],
    },
    "throttled_clients": {
        "button": "Clear throttled clients",
        "title": "Clear the throttled clients list?",
        "consequences": [
            "The list of clients that became throttled starts again from the next throttle (v1's Clear data on "
            "Throttled IPs).",
            "Strikes and running penalties stay: forgive or reset a client for those.",
        ],
    },
    "throttle_rule_hits": {
        "button": "Clear stats",
        "title": "Clear the ladder and User-Agent rule statistics?",
        "consequences": [
            "The new strikes per rung and the User-Agent rules' allowed and refused counts start again from zero "
            "(v1's Clear stats on Throttle Rules).",
            "The ladder, the rules and every caller's strikes stay.",
        ],
    },
    "tarpit": {
        "button": "Clear stats",
        "title": "Clear the tarpit statistics?",
        "consequences": [
            "Holds, skips, hold lengths and the gaps between requests start again from zero, in every worker within "
            "a few seconds (v1's Clear stats on the Tarpit).",
            "The tarpit settings stay, and holds in progress finish normally.",
        ],
    },
    "endpoint_block_attempts": {
        "button": "Clear attempts",
        "title": "Clear the blocked endpoint attempts?",
        "consequences": [
            "The requests the endpoint blocks refused are forgotten (v1's Clear data on Blocked Endpoint Attempts).",
            "The blocks stay and keep refusing; the other attempts tabs stay.",
        ],
    },
    "endpoint_rule_attempts": {
        "button": "Clear attempts",
        "title": "Clear the rate-limited attempts?",
        "consequences": [
            "The requests the endpoint rules refused are forgotten (v1's Clear data on Rate-Limited Attempts).",
            "The rules stay and keep limiting; the other attempts tabs stay.",
        ],
    },
    "header_rule_attempts": {
        "button": "Clear attempts",
        "title": "Clear the header-blocked attempts?",
        "consequences": [
            "The requests the request filters refused are forgotten (v1's Clear data on Header-Blocked Attempts).",
            "The filters stay and keep refusing; the other attempts tabs stay.",
        ],
    },
}
"""v1's per-section clear buttons of this page's sections (v1 notes 2.10 and 4.3, 4.11), as plan 6.8 data resets of
the family each v1 target maps to (`admin/api/data.py V1_CLEAR_TARGETS`)."""


def clear_action(view: PageView, family: str) -> dict[str, Any]:
    """The dialog of one v1 clear button: `POST /admin/api/v1/data/resets` for the metric family `family`, with the
    preview digest and typed phrase of the Data API's own plan (`build_plan`, no I/O), so the dialog can run only the
    scope it shows. A plan that cannot be built leaves the digest empty and the dialog says so."""
    phrase = f"reset {family}"
    digest = None
    try:
        body = data_api.ResetBody.model_validate({"scope": "family", "families": [family]})
        plan = data_api.build_plan(body, view.ctx, view.ctx.clock.now())
        digest, phrase = plan.digest, plan.confirm_phrase or phrase
    except (common.ApiError, ValueError):
        log.warning("protection_clear_unavailable", extra={"fields": {"family": family}})
    return {
        "id": "dlg-prot-clear-" + family.replace("_", "-"),
        "family": family,
        "phrase": phrase,
        "digest": digest,
        "note": data_api.FAMILIES[family].note,
        "success": "Cleared. The reset is in the audit log and marked on the charts.",
        **CLEARS[family],
    }


# ============================================================================================ overview


@page.card("pipeline", refresh_on=("kpi",), refresh_min_s=60)
async def pipeline_card(view: PageView) -> dict[str, Any]:
    """Every check in order with its refusals in the range (`pipeline_answer`, the API's own function)."""
    answer = await prot.pipeline_answer(view.ctx, view.tr)
    return {"pipe": pv.pipeline_model(answer), "range_text": view.time.view.get("description") or ""}


@page.card("refusals", lazy=True)
async def refusals_card(view: PageView) -> dict[str, Any]:
    """v1 "Refusal Reasons" (`refusals_answer`): count, status, last path, clients, first and last seen, message;
    and the clients refused most in the range (plan 10.9 "top refused clients", the Clients page's own read)."""
    which = only_table(view, ("refusals", "clients"))
    tables: dict[str, Any] = {}
    if which in (None, "refusals"):
        tables["refusals"] = await _refusal_reasons_table(view)
    if which in (None, "clients"):
        tables["clients"] = await _refused_clients_table(view)
    context: dict[str, Any] = {"only": which, "tables": tables}
    if which is None:
        context["clear"] = clear_action(view, "refusals")
    return context


async def _refusal_reasons_table(view: PageView) -> dict[str, Any]:
    tq, notice = query_for(view, prot.REFUSALS_SPEC, "refusals")
    answer = await prot.refusals_answer(view.ctx, tq, view.tr)

    def cells(item: Mapping[str, Any]) -> dict[str, Any]:
        code = str(item.get("reason") or "")
        return {
            "reason": {"text": pv.reason_label(code), "sub": code},
            "message_source": pv.message_split(item.get("message_source")) or None,
        }

    return table(
        view,
        "refusals",
        "refusals",
        prot.REFUSALS_SPEC,
        answer,
        export="refusals",
        cells=cells,
        key_columns=("reason", "requests", "last_ms"),
        hidden=("unattributed", "first_ms"),
        row_id=lambda item: f"reason-{item.get('reason')}",
        caption="Refusal and failure reasons in this range",
        search_placeholder="Search reasons and paths",
        notice=notice,
        empty={
            "title": "Roxy refused nothing in this range",
            "body": "Every refusal and failure is counted here by its reason, with the message the caller got. "
            "Choose a longer range in the top bar to see older ones.",
            "icon": "shield",
            "tone": "good",
        },
    )


def _client_drawer(view: PageView, key: Any) -> str | None:
    """The Clients page's client view for an address (its drawer route), None for anything that is not one."""
    try:
        address = str(ipaddress.ip_address(str(key)))
    except ValueError:
        return None
    return "/admin/clients/client?" + urlencode({**view.time.params, "kind": "ip", "key": address})


async def _refused_clients_table(view: PageView) -> dict[str, Any]:
    """The addresses refused most in the range: the Clients page's address table (`client_table_answer`, the read
    of `GET /admin/api/v1/clients/ips`) sorted by refusals, so its numbers are the Clients page's numbers."""
    spec = clients_api.IP_SPEC
    if asked(view, "clients"):
        tq, notice = table_query(view, spec, address=False)
        if not view.param("sort", max_chars=40):
            tq = replace(tq, sort=REFUSED_CLIENTS_SORT, order="desc")
    else:
        tq = replace(default_query(spec), sort=REFUSED_CLIENTS_SORT, order="desc", page_size=REFUSED_CLIENTS_ROWS)
        notice = None
    answer = await clients_api.client_table_answer(view.ctx, spec, tq, view.tr, "ip")
    return table_view(
        view,
        "prot-clients",
        spec,
        answer,
        src=view.fragment_url("refusals", **{TABLE_PARAM: "clients"}),
        export_url=view.api_url("clients/ips"),
        address=False,
        columns=("key", "refused", "refused_pct", "requests", "top_endpoint", "last_seen", "bot_score"),
        key_columns=("key", "refused", "refused_pct"),
        hidden=("bot_score",),
        cells=lambda item: {
            "key": _mono(item.get("key")),
            "refused": {"text": f"{int(item.get('refused') or 0):,}", "tone": "warn" if item.get("refused") else None},
            "bot_score": None if item.get("bot_score") is None else {"text": f"{float(item['bot_score']):.0f}"},
        },
        row_id=lambda item: f"client-{row_key(item.get('key'))}",
        drawer=lambda item: _client_drawer(view, item.get("key")),
        drawer_title=lambda item: f"Address {item.get('key')}",
        caption="Addresses Roxy refused most in this range",
        search_placeholder="Search addresses",
        notice=notice,
        empty={
            "title": "No address called Roxy in this range",
            "body": "Every address is counted with its requests and refusals; the ones refused most come first. "
            "Choose a longer range in the top bar to look further back.",
            "icon": "users",
        },
    )


# ============================================================================================ limits


def _throttle_summary(view: PageView) -> dict[str, Any]:
    """The per-IP limit in plain words, from the live settings."""
    limit = int(_setting(view, "allowed_requests_per_minute"))
    window = int(_setting(view, "throttle_reset_duration"))
    mode = str(_setting(view, "throttle_window_mode"))
    if mode == "gcra":
        pacing = (
            f"smooth pacing: a burst of {limit:,}, then one more request every "
            f"{pv.number(round(window / max(1, limit), 2))} seconds"
        )
    else:
        pacing = f"a fixed window: the count starts again every {pv.span_words(window)}"
    return {
        "limit": limit,
        "window": window,
        "pacing": pacing,
        "cache_hits_count": bool(_setting(view, "throttle_count_cache_hits")),
        "escalation": bool(_setting(view, "throttle_escalation_enabled")),
        "strike_on_retry": bool(_setting(view, "throttle_strike_on_retry")),
    }


@page.card("throttle", lazy=True)
async def throttle_card(view: PageView) -> dict[str, Any]:
    """Who is throttled now (`throttle_watch_answer`), the throttled history (`throttled_history_answer`), the
    limiter reset preview (`limiter_reset_preview_answer`), and the per-IP limit in words."""
    which = only_table(view, ("watch", "history"))
    tables: dict[str, Any] = {}
    if which in (None, "watch"):
        tq, notice = query_for(view, prot.WATCH_SPEC, "watch")
        answer = await prot.throttle_watch_answer(view.ctx, tq)
        tables["watch"] = table(
            view,
            "throttle",
            "watch",
            prot.WATCH_SPEC,
            answer,
            export="throttle/watch",
            cells=lambda item: {
                "ip": _mono(item.get("ip")),
                "tier": {"text": f"Rung {item.get('tier')}"} if item.get("tier") else None,
                "time_left_s": _span(item.get("time_left_s")),
            },
            row_id=lambda item: f"watch-{item.get('ip')}",
            drawer=lambda item: view.fragment_url("strikes", **{DETAIL_PARAM: item["ip"]}),
            drawer_title=lambda item: f"Client {item.get('ip')}",
            caption="Clients serving a throttle penalty now",
            search_placeholder="Search clients",
            notice=notice,
            empty={
                "title": "Nobody is serving a throttle penalty right now",
                "body": "A client that goes over the per-IP limit is refused with 429 and waits out its penalty. "
                "This list shows each one while the wait runs, longest first.",
                "icon": "check-circle",
                "tone": "good",
            },
        )
    if which in (None, "history"):
        tq, notice = query_for(view, prot.THROTTLED_SPEC, "history")
        answer = await prot.throttled_history_answer(view.ctx, tq, view.tr)
        tables["history"] = table(
            view,
            "throttle",
            "history",
            prot.THROTTLED_SPEC,
            answer,
            export="throttle/history",
            cells=lambda item: {"ip": _mono(item.get("ip"))},
            row_id=lambda item: f"throttled-{item.get('ip')}",
            caption="Clients that became throttled in this range",
            search_placeholder="Search clients",
            notice=notice,
            empty={
                "title": "No client was throttled in this range",
                "body": "Every time a client goes over the per-IP limit it is counted here (v1's Throttled IPs). "
                "Choose a longer range to look further back.",
                "icon": "inbox",
            },
        )
    context: dict[str, Any] = {"only": which, "tables": tables}
    if which is None:
        context["summary"] = _throttle_summary(view)
        context["reset_all"] = await prot.limiter_reset_preview_answer(view.ctx, "all")
        context["clear"] = clear_action(view, "throttled_clients")
    return context


@page.card("ladder", lazy=True)
async def ladder_card(view: PageView) -> dict[str, Any]:
    """The ladder editor (`ladder_view`, with each rung's new strikes in the range) and v1's repeat offender
    simulation from the saved ladder and the live settings (`offender_timeline`)."""
    data = await prot.ladder_view(view.ctx, view.tr)
    rungs = list(data["rungs"])
    return {
        "ladder": data,
        "rungs": rungs,
        "timeline": pv.offender_timeline(
            rungs,
            base_s=int(data["window_s"]),
            escalation=bool(data["escalation_enabled"]),
            decay_s=int(data["decay_s"]),
        ),
        "max_rungs": MAX_THROTTLE_TIERS,
        "max_multiplier": MAX_THROTTLE_MULTIPLIER,
        "window_words": pv.span_words(data["window_s"]),
        "decay_words": pv.span_words(data["decay_s"]) if data["decay_s"] else "",
        "api": {"save": f"{API}/ladder", "reset": f"{API}/ladder/reset"},
        "clear": clear_action(view, "throttle_rule_hits"),
    }


async def _strike_detail(view: PageView, client: str) -> dict[str, Any]:
    """One client's strikes for the drawer, read with the abuse module's own `load_strike_rows` and computed with
    the strike board's formulas (`effective_strikes`, `rung_for`, `decays_in`)."""
    try:
        key = str(ipaddress.ip_network(client, strict=False)) if "/" in client else str(ipaddress.ip_address(client))
    except ValueError:
        raise common.not_found("That is not a client address or IPv6 network key.") from None
    ctx = view.ctx
    ladder = ladder_from(ctx.rules.snapshot.throttle_tiers)
    decay = int(_setting(view, "throttle_strike_decay_seconds"))
    now = int(ctx.clock.now())
    rows = await ctx.dbs.hot.read(lambda conn: load_strike_rows(conn, [key]))
    row = rows[key]
    strikes = effective_strikes(row.strikes, row.last_strike_at, now, decay)
    rung = rung_for(ladder, strikes)
    return {
        "client": key,
        "exists": row.exists,
        "strikes": strikes,
        "rung": rung.index,
        "rungs": len(ladder),
        "message": rung.message,
        "multiplier": rung.multiplier,
        "throttled": row.throttled_until > now,
        "reset_in": max(0, row.throttled_until - now),
        "last_strike": view.time_cell(row.last_strike_at or None),
        "decays_in": decays_in(row.strikes, row.last_strike_at, now, decay),
        "live_href": "/admin/live?" + urlencode({"client": key}),
        # An address opens its own client page; a network key (an IPv6 prefix) the address table searched for it
        # (`?ip=`, the Clients page's deep link; `q` would search the places table).
        "clients_href": client_href("ip", address)
        if (address := canonical_ip(key))
        else "/admin/clients?" + urlencode({"ip": key}),
        "api": {"forgive": f"{API}/strikes/forgive", "reset": f"{API}/limiter/reset"},
    }


@page.card("strikes", lazy=True)
async def strikes_card(view: PageView) -> dict[str, Any]:
    """The strike board (`strike_board_answer`), worst first, with forgive one and forgive everyone."""
    client = detail_of(view)
    if client:
        return {"detail": await _strike_detail(view, client)}
    tq, notice = query_for(view, prot.STRIKE_SPEC, "strikes")
    answer = await prot.strike_board_answer(view.ctx, tq)
    rungs = len(view.ctx.rules.snapshot.throttle_tiers)

    def cells(item: Mapping[str, Any]) -> dict[str, Any]:
        tier = int(item.get("tier") or 0)
        serving = bool(item.get("throttled"))
        return {
            "ip": _mono(item.get("ip")),
            "tier": {"text": f"{tier} of {rungs}", "tone": "bad" if rungs and tier >= rungs else None},
            "message": _caller(item.get("message")),
            "throttled": {"text": f"Serving {pv.span_words(item.get('reset_in'))}", "tone": "warn"}
            if serving
            else {"text": "Free to call", "tone": "muted"},
            "reset_in": _span(item.get("reset_in"), zero="none"),
            "decays_in": _span(item.get("decays_in"), zero="never"),
            "multiplier": {"text": f"{pv.number(item.get('multiplier'))} times"},
        }

    return {
        "only": only_table(view, ("strikes",)),
        "table": table(
            view,
            "strikes",
            "strikes",
            prot.STRIKE_SPEC,
            answer,
            export="strikes",
            columns=("ip", "strikes", "tier", "throttled", "decays_in", "last_strike_at", "multiplier", "message"),
            labels={"throttled": "Status"},
            key_columns=("ip", "strikes", "throttled"),
            hidden=("multiplier", "message"),
            cells=cells,
            row_id=lambda item: f"strike-{item.get('ip')}",
            drawer=lambda item: view.fragment_url("strikes", **{DETAIL_PARAM: item["ip"]}),
            drawer_title=lambda item: f"Client {item.get('ip')}",
            caption="Callers carrying strikes, worst first",
            search_placeholder="Search clients",
            notice=notice,
            empty={
                "title": "Nobody is carrying strikes right now",
                "body": "Each throttle a caller earns is a strike; strikes decide which rung of the ladder its next "
                "throttle uses, and they wear off with good behavior.",
                "icon": "check-circle",
                "tone": "good",
            },
        ),
        "api": {"forgive": f"{API}/strikes/forgive"},
    }


@page.card("throttle-all", lazy=True, refresh_on=("kpi",), refresh_min_s=15)
async def throttle_all_card(view: PageView) -> dict[str, Any]:
    """The emergency limit (`throttle_all_answer`) and who it turned away since it was switched on, refused most
    first (`throttle_all_watch_answer`, row 135 with v1's columns and rows: v1 listed the IPs with refusals)."""
    which = only_table(view, ("watch-all",))
    tq, notice = query_for(view, prot.WATCH_ALL_SPEC, "watch-all")
    state = await prot.throttle_all_answer(view.ctx)
    answer = await prot.throttle_all_watch_answer(view.ctx, tq)
    limit = int(_setting(view, "global_throttle_limit"))
    if state.get("enabled"):
        empty = {
            "title": "Nothing has been refused since the emergency limit was switched on",
            "body": "Every client Roxy turns away while the emergency limit is on is listed here, refused most "
            "first, with what it asks for and how fast, so you can judge when to switch it off.",
            "icon": "gauge",
            "tone": "good",
        }
    else:
        empty = {
            "title": "The emergency limit is off, so it refuses nobody",
            "body": "While the emergency limit is on, every client Roxy turns away is listed here with what it asks "
            "for and how fast, so you can judge when to switch it off.",
            "icon": "gauge",
        }

    def cells(item: Mapping[str, Any]) -> dict[str, Any]:
        rate = item.get("rate1")
        count = item.get("count")
        return {
            "ip": _mono(item.get("ip")),
            "limited": pv.yes_no(item.get("limited"), yes="Refused now", no="Within the limit"),
            # A client whose emergency window ended has none until its next request (it would be admitted).
            "count": {"text": "No window now", "tone": "muted"}
            if count is None
            else {"text": f"{int(count):,} of {limit:,}"},
            "reset_in_s": _span(item.get("reset_in_s"), zero="now"),
            "rate1": None
            if rate is None
            else {
                "text": f"{int(rate):,}/min",
                "sub": f"5 min: {int(item.get('rate5') or 0):,}; hour: {int(item.get('rate60') or 0):,}",
                "tone": "bad" if int(rate) >= 60 else ("warn" if int(rate) >= 10 else None),
            },
            "top_endpoint": _caller(item.get("top_endpoint")),
        }

    context: dict[str, Any] = {
        "only": which,
        "table": table(
            view,
            "throttle-all",
            "watch-all",
            prot.WATCH_ALL_SPEC,
            answer,
            export="throttle-all/watch",
            columns=(
                "ip",
                "refused",
                "requests",
                "rate1",
                "top_endpoint",
                "last_seen_ms",
                "limited",
                "count",
                "reset_in_s",
            ),
            key_columns=("ip", "refused", "rate1"),
            hidden=("count", "reset_in_s", "rate5", "rate60"),
            cells=cells,
            row_id=lambda item: f"watch-all-{item.get('ip')}",
            caption="Who the emergency limit turned away since it was switched on, refused most first",
            search_placeholder="Search clients",
            searchable=False,
            notice=notice,
            empty=empty,
        ),
    }
    if which is None:
        context["state"] = state
        context["since"] = view.time_cell(state.get("since"))
    return context


async def _reason_counts(view: PageView, reasons: Sequence[str]) -> list[dict[str, Any]]:
    """Refusals per reason in the range for `reasons`: the Refusal reasons card's `requests` and `last_ms` for them
    (`metrics/queries.py reason_counts`, which reads only those two numbers; the whole table read every event of
    the range four ways, seconds over 90 days, for each of these cards; plan 6.7)."""
    window = view.tr.window
    wanted = tuple(reasons)
    with common.service_errors():
        rows = await view.ctx.dbs.metrics.read(lambda conn: queries.reason_counts(conn, window, wanted))
    return [
        {
            "reason": reason,
            "label": pv.reason_label(reason),
            "requests": int((rows.get(reason) or {}).get("requests") or 0),
            "last": view.time_cell(((rows.get(reason) or {}).get("last_ms") or 0) / 1000 or None),
        }
        for reason in reasons
    ]


@page.card("limits", lazy=True)
async def limits_card(view: PageView) -> dict[str, Any]:
    """The flood limit and the request size limits, with their refusals in the range."""
    return {"counts": await _reason_counts(view, LIMIT_REASONS)}


@page.card("places", lazy=True)
async def places_card(view: PageView) -> dict[str, Any]:
    """Per-experience limits (D11) and their refusals in the range."""
    return {
        "counts": await _reason_counts(view, ("place_limit",)),
        "enabled": bool(_setting(view, "place_limit_enabled")),
        "per_minute": int(_setting(view, "place_limit_per_minute")),
    }


# ============================================================================================ who


def _ban_cells(view: PageView, item: Mapping[str, Any]) -> dict[str, Any]:
    evidence = item.get("evidence") or {}
    remaining = item.get("expires_in_s")
    subject_type = str(item.get("subject_type") or "")
    origin = str(item.get("origin") or "")
    return {
        "subject": _caller(item.get("subject")),
        "subject_type": {"text": SUBJECT_LABELS.get(subject_type, subject_type)},
        "origin": {"text": ORIGIN_LABELS.get(origin, origin), "sub": None},
        "active": pv.yes_no(item.get("active"), yes="In force", no="Expired"),
        "expires_in_s": {"text": "Permanent", "tone": "warn"} if item.get("permanent") else _span(remaining),
        "created_by": _caller(item.get("created_by")),
        "evidence": _caller(evidence.get("reason_text") or evidence.get("reason_code")),
        **_hits_cells(view, item),
    }


async def _ban_detail(view: PageView, raw: str) -> dict[str, Any]:
    if not raw.isdigit() or not 1 <= int(raw) <= common.MAX_ROW_ID:
        raise common.not_found("Choose a ban from the list; that ban number is not valid.")
    ban = await prot.ban_detail_answer(view.ctx, int(raw))
    events = [
        {**event, "when": view.time_cell((event.get("at_ms") or 0) / 1000 or None)}
        for event in ban.get("detector_events") or ()
    ]
    return {
        "ban": ban,
        "events": events,
        "created": view.time_cell(ban.get("created_at")),
        "expires": view.time_cell(ban.get("expires_at")),
        "last_hit": view.time_cell(ban.get("last_hit_at")),
        "remaining": pv.span_words(ban.get("expires_in_s")) if ban.get("expires_in_s") is not None else "",
        "chart_src": rule_hits_url(view, "bans", ban["id"]),
        "api": {"lift": f"{API}/bans/{int(ban['id'])}", "lift_subject": f"{API}/bans/lift"},
    }


@page.card("bans", lazy=True)
async def bans_card(view: PageView) -> dict[str, Any]:
    """Bans with countdowns and evidence (`bans_answer`), the ban form, the reset previews
    (`bans_reset_preview_answer`) and each ban's drawer (`ban_detail_answer`)."""
    raw = detail_of(view)
    if raw:
        return {"detail": await _ban_detail(view, raw)}
    state = choice(view, "bans", "state", BAN_STATES)
    origin = choice(view, "bans", "origin", BAN_ORIGINS)
    subject_type = choice(view, "bans", "subject_type", BAN_SUBJECTS)
    detector = choice(view, "bans", "detector", ("", *AUTO_DETECTORS))
    tq, notice = query_for(view, prot.BAN_SPEC, "bans")
    answer = await prot.bans_answer(
        view.ctx,
        tq,
        state=cast(Literal["active", "expired", "all"], state),
        origin=cast(Literal["any", "manual", "auto"], origin),
        detector=detector or None,
        subject_type=cast(Literal["ip", "cidr", "place", "ua_hash"] | None, subject_type or None),
    )
    filters = [
        filter_chip("state", "State", state, [("active", "In force"), ("expired", "Expired"), ("all", "All")]),
        filter_chip("origin", "Made by", origin, [("any", "Anyone"), ("manual", "An admin"), ("auto", "A detector")]),
        filter_chip(
            "subject_type",
            "Type",
            subject_type,
            [("", "Any type"), ("ip", "Address"), ("cidr", "Network"), ("place", "Place"), ("ua_hash", "User-Agent")],
        ),
        filter_chip("detector", "Detector", detector, [("", "Any detector"), *((d, d) for d in AUTO_DETECTORS)]),
    ]
    which = only_table(view, ("bans",))
    context: dict[str, Any] = {
        "only": which,
        "active_total": int(answer.get("active_total") or 0),
        "disguised": bool(answer.get("disguised")),
        "table": table(
            view,
            "bans",
            "bans",
            prot.BAN_SPEC,
            answer,
            export="bans",
            columns=(
                "subject",
                "subject_type",
                "active",
                "expires_in_s",
                "origin",
                "created_by",
                "hits",
                "last_hit_at",
                "created_at",
                "expires_at",
                "evidence",
                "id",
            ),
            key_columns=("subject", "active", "expires_in_s"),
            hidden=("created_at", "expires_at", "evidence", "id"),
            cells=lambda item: _ban_cells(view, item),
            row_id=lambda item: f"ban-{item.get('id')}",
            drawer=lambda item: view.fragment_url("bans", **{DETAIL_PARAM: item["id"]}),
            drawer_title=lambda item: f"Ban #{item.get('id')}",
            filters=filters,
            caption="Bans",
            search_placeholder="Search subjects",
            notice=notice,
            empty={
                "title": "No ban matches",
                "body": "Bans are made by hand (the Ban button above, or a client's page) or by a spam detector once "
                "it is armed. Try the State filter: expired bans stay listed until retention removes them.",
                "icon": "shield",
            },
        ),
    }
    if which is None:
        context["previews"] = {
            scope: await prot.bans_reset_preview_answer(view.ctx, scope) for scope in ("all", "auto", "expired")
        }
        context["detectors"] = AUTO_DETECTORS
        context["api"] = {"create": f"{API}/bans", "reset": f"{API}/bans/reset"}
    return context


def _access_cells(view: PageView, item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "cidr": _mono(item.get("cidr")),
        "note": _caller(item.get("note")),
        "active": pv.yes_no(item.get("active"), yes="Active", no="Expired"),
        "expires_in_s": {"text": "Never", "tone": "muted"}
        if item.get("expires_at") is None
        else _span(item.get("expires_in_s"), zero="expired"),
        "created_by": _caller(item.get("created_by")),
        **_hits_cells(view, item),
    }


def _access_table(
    view: PageView, card: str, key: str, kind: str, answer: Mapping[str, Any], **options: Any
) -> dict[str, Any]:
    return table(
        view,
        card,
        key,
        prot.ACCESS_SPEC,
        answer,
        export=f"access/{kind}",
        columns=(
            "cidr",
            "note",
            "active",
            "expires_in_s",
            "hits",
            "hits_total",
            "last_hit_at",
            "created_by",
            "created_at",
            "expires_at",
            "id",
        ),
        key_columns=("cidr", "active", "expires_in_s"),
        hidden=("hits_total", "created_at", "expires_at", "id"),
        cells=lambda item: _access_cells(view, item),
        row_id=lambda item: f"{kind}-{item.get('id')}",
        drawer=lambda item: view.fragment_url(card, **{DETAIL_PARAM: item["id"]}),
        drawer_title=lambda item: f"{item.get('cidr')}",
        search_placeholder="Search addresses and notes",
        **options,
    )


async def _access_detail(view: PageView, raw: str, kinds: Sequence[str]) -> dict[str, Any]:
    if not raw.isdigit():
        raise common.not_found("Choose an entry from the list; that entry number is not valid.")
    for kind in kinds:
        rows = await prot.access_rows(view.ctx, kind, view.tr)
        found = _find(rows, "id", raw)
        if found is not None:
            return {
                "entry": found,
                "kind": kind,
                "expires": view.time_cell(found.get("expires_at")),
                "created": view.time_cell(found.get("created_at")),
                "last_hit": view.time_cell(found.get("last_hit_at")),
                "remaining": pv.span_words(found.get("expires_in_s")) if found.get("expires_in_s") else "",
                "chart_src": rule_hits_url(view, "access", found["id"]) if kind != "allow_admin" else "",
                "delete_url": f"{API}/access/{kind}/{int(found['id'])}",
                "covers_you": covers(str(found.get("cidr")), view.principal.ip),
                "allowlist_on": bool(_setting(view, "admin_allowlist_enabled")),
            }
    raise _not_found("entry of this list")


@page.card("lists", lazy=True)
async def lists_card(view: PageView) -> dict[str, Any]:
    """The deny list and the admin allowlist (`access_answer`), each entry with its hits."""
    raw = detail_of(view)
    if raw:
        return {"detail": await _access_detail(view, raw, ("deny", "allow_admin"))}
    which = only_table(view, ("deny", "allow-admin"))
    tables: dict[str, Any] = {}
    allow_answer: Mapping[str, Any] = {}
    if which in (None, "deny"):
        tq, notice = query_for(view, prot.ACCESS_SPEC, "deny")
        answer = await prot.access_answer(view.ctx, "deny", tq, view.tr, view.principal.ip)
        tables["deny"] = _access_table(
            view,
            "lists",
            "deny",
            "deny",
            answer,
            caption="Deny list",
            notice=notice,
            empty={
                "title": "The deny list is empty",
                "body": "An address or network on the deny list is refused before any other check (403, or a "
                "disguised 429). Add one above; a temporary entry is usually better than a permanent one.",
                "icon": "shield",
            },
        )
    if which in (None, "allow-admin"):
        tq, notice = query_for(view, prot.ACCESS_SPEC, "allow-admin")
        allow_answer = await prot.access_answer(view.ctx, "allow_admin", tq, view.tr, view.principal.ip)
        tables["allow-admin"] = _access_table(
            view,
            "lists",
            "allow-admin",
            "allow_admin",
            allow_answer,
            caption="Admin allowlist",
            notice=notice,
            empty={
                "title": "The admin allowlist is empty",
                "body": "When the admin allowlist is switched on (Security > Admin access), only these networks "
                "can see /admin at all; everyone else gets a plain 404.",
                "icon": "lock",
            },
        )
    return {
        "only": which,
        "tables": tables,
        "your_ip": view.principal.ip,
        "allowlist_on": bool(_setting(view, "admin_allowlist_enabled")),
        "api": {"deny": f"{API}/access/deny", "allow_admin": f"{API}/access/allow_admin"},
    }


@page.card("bypass", lazy=True)
async def bypass_card(view: PageView) -> dict[str, Any]:
    """Bypass entries (`access_answer`) and "Bypass my IP" with the address Roxy resolved (`bypass_me_answer`)."""
    raw = detail_of(view)
    if raw:
        return {"detail": await _access_detail(view, raw, ("bypass",))}
    which = only_table(view, ("bypass",))
    tq, notice = query_for(view, prot.ACCESS_SPEC, "bypass")
    answer = await prot.access_answer(view.ctx, "bypass", tq, view.tr, view.principal.ip)
    context: dict[str, Any] = {
        "only": which,
        "table": _access_table(
            view,
            "bypass",
            "bypass",
            "bypass",
            answer,
            caption="Bypass entries",
            notice=notice,
            empty={
                "title": "No address bypasses the limits",
                "body": "Add your own address with Bypass my IP when you load-test the proxy. Entries expire after "
                "the default expiry unless you choose otherwise.",
                "icon": "inbox",
            },
        ),
    }
    if which is None:
        context["me"] = await prot.bypass_me_answer(view.ctx, view.principal.ip)
        context["api"] = {"me": f"{API}/access/bypass/me", "add": f"{API}/access/bypass"}
        context["scope"] = bypass_scope()  # from the checks' own flags (finding v1parity-9)
    return context


# ============================================================================================ rules


def _ua_cells(view: PageView, item: Mapping[str, Any]) -> dict[str, Any]:
    mode = str(item.get("mode") or "contains")
    return {
        "position": int(item.get("position") or 0) + 1,
        "needle": {
            "text": str(item.get("needle") or ""),
            "caller": True,
            "sub": " ".join(
                part
                for part in (
                    pv.MODE_LABELS.get(mode, mode) if mode != "contains" else "",
                    "" if item.get("enabled", True) else "off",
                )
                if part
            )
            or None,
        },
        "limit": {"text": pv.limit_text(item)},
        "scope": {"text": "shared" if item.get("scope") == "global" else "per IP"},
        "message": _caller(item.get("message")) or {"text": "default", "tone": "muted"},
        "note": _caller(item.get("note")),
        "enabled": pv.yes_no(item.get("enabled", True), yes="On", no="Off"),
        "refused": {
            "text": f"{int(item.get('allowed') or 0):,} / {int(item.get('refused') or 0):,}",
            "tone": "warn" if item.get("refused") else None,
        },
        **_hits_cells(view, item),
    }


async def _ua_detail(view: PageView, rule_id: str) -> dict[str, Any]:
    rows = sorted(await prot.ua_rule_rows(view.ctx, view.tr), key=lambda row: int(row.get("position") or 0))
    found = _find(rows, "id", rule_id)
    if found is None:
        raise _not_found("User-Agent rule")
    ids = [str(row["id"]) for row in rows]
    at = ids.index(rule_id)
    earlier = ids[:]
    later = ids[:]
    if at > 0:
        earlier[at - 1], earlier[at] = earlier[at], earlier[at - 1]
    if at < len(ids) - 1:
        later[at + 1], later[at] = later[at], later[at + 1]
    return {
        "rule": found,
        "kind": "ua",
        "limit_text": pv.limit_text(found),
        "position": at + 1,
        "count": len(ids),
        "earlier": "\n".join(earlier) if at > 0 else "",
        "later": "\n".join(later) if at < len(ids) - 1 else "",
        "last_hit": view.time_cell(found.get("last_hit_at")),
        "created": view.time_cell(found.get("created_at")),
        "chart_src": rule_hits_url(view, "ua-rules", found["id"]),
        "url": f"{API}/ua-rules/{found['id']}",
        "order_url": f"{API}/ua-rules/order",
    }


@page.card("ua-rules", lazy=True)
async def ua_rules_card(view: PageView) -> dict[str, Any]:
    """User-Agent rules in evaluation order (`ua_rules_answer`) with their allowed and refused counts, the rule form,
    the tester (`POST /ua-rules/test`, run by the page script) and each rule's drawer."""
    raw = detail_of(view)
    if raw:
        return {"detail": await _ua_detail(view, raw)}
    tq, notice = query_for(view, prot.UA_SPEC, "ua")
    answer = await prot.ua_rules_answer(view.ctx, tq, view.tr)
    items = answer.get("items") or ()
    return {
        "only": only_table(view, ("ua",)),
        "rules_enabled": bool(answer.get("rules_enabled")),
        "active": sum(1 for item in items if item.get("enabled", True)),
        "table": table(
            view,
            "ua-rules",
            "ua",
            prot.UA_SPEC,
            answer,
            export="ua-rules",
            columns=(
                "position",
                "needle",
                "limit",
                "scope",
                "message",
                "refused",
                "hits",
                "last_hit_at",
                "enabled",
                "note",
                "hits_total",
                "id",
            ),
            labels={"refused": "Allowed / refused", "needle": "Matches"},
            key_columns=("position", "needle", "limit"),
            hidden=("note", "hits_total", "id"),
            cells=lambda item: _ua_cells(view, item),
            row_id=lambda item: f"ua-{item.get('id')}",
            drawer=lambda item: view.fragment_url("ua-rules", **{DETAIL_PARAM: item["id"]}),
            drawer_title=lambda item: "User-Agent rule",
            caption="User-Agent rules, first match first",
            search_placeholder="Search rules",
            notice=notice,
            empty={
                "title": "No client rules; every caller uses the ordinary limits",
                "body": "A User-Agent rule gives one kind of client its own limit: a burst allowance or a minimum "
                "gap between requests. Add one above, and try it in the Tester tab first.",
                "icon": "inbox",
            },
        ),
        "api": {"create": f"{API}/ua-rules", "test": f"{API}/ua-rules/test"},
    }


def _rule_detail(
    view: PageView, rows: Sequence[Mapping[str, Any]], raw: str, *, kind: str, what: str
) -> dict[str, Any]:
    found = _find(rows, "id", raw)
    if found is None:
        raise _not_found(what)
    route = {"header": "header-rules", "block": "endpoint-blocks", "rule": "endpoint-rules"}[kind]
    return {
        "rule": found,
        "kind": kind,
        "describe": pv.header_rule_text(found) if kind == "header" else "",
        "last_hit": view.time_cell(found.get("last_hit_at")),
        "created": view.time_cell(found.get("created_at")),
        "chart_src": rule_hits_url(view, route, found["id"]),
        "url": f"{API}/{route}/{int(found['id'])}",
    }


def _attempts_table(
    view: PageView, card: str, reason: str, answer: Mapping[str, Any], **options: Any
) -> dict[str, Any]:
    route = {"endpoint_blocked": "endpoint-blocks", "endpoint_rule": "endpoint-rules", "header_rule": "header-rules"}
    spec = prot.ATTEMPT_SPECS[reason]
    headers = spec is prot.HEADER_ATTEMPT_SPEC

    def cells(item: Mapping[str, Any]) -> dict[str, Any]:
        refused_by = ", ".join(str(rule) for rule in item.get("refused_by") or ())
        found = {
            "path": {"text": str(item.get("path") or ""), "caller": True, "sub": None},
            "methods": _caller(", ".join(str(m) for m in item.get("methods") or ())),
            "refused_by": _caller(refused_by),
            "current_rule": _caller(item.get("current_rule")),
        }
        if headers:
            # v1's Last Header, Triggered By (`Header name` or `Header value`) and Matched Text (finding v1parity-5).
            field = str(item.get("last_field") or "")
            found["last_header"] = _caller(item.get("last_header"))
            found["last_field"] = {"text": pv.SCOPE_LABELS[field]} if field in ("key", "value") else None
            found["last_text"] = _caller(item.get("last_text"))
        return found

    if headers:
        # v1's column order: rule, blocked, unique IPs, then what matched, then the last path and attempt.
        options.setdefault(
            "columns",
            (
                "path",
                "attempts",
                "clients",
                "last_header",
                "last_field",
                "last_text",
                "refused_by",
                "methods",
                "last_ms",
                "unattributed",
                "current_rule",
            ),
        )
    return table(
        view,
        card,
        "attempts",
        spec,
        answer,
        export=f"{route[reason]}/attempts",
        key_columns=("path", "attempts", "last_header", "last_ms") if headers else ("path", "attempts", "last_ms"),
        # A request filter matches headers, not a path, so it has no "matching rule now".
        hidden=("unattributed", "current_rule") if headers else ("unattributed",),
        cells=cells,
        row_id=lambda item: f"attempt-{row_key(item.get('path'))}",
        search_placeholder="Search paths",
        **options,
    )


@page.card("request-filters", lazy=True)
async def request_filters_card(view: PageView) -> dict[str, Any]:
    """Request filters (`header_rules_answer`), their attempts tab (`attempts_answer`, row 18), the tester and its
    presets (`header_presets_answer`), and each filter's drawer."""
    raw = detail_of(view)
    if raw:
        rows = await prot.rule_table_rows(view.ctx, "rules_header", view.tr)
        return {"detail": _rule_detail(view, rows, raw, kind="header", what="request filter")}
    which = only_table(view, ("filters", "attempts"))
    tables: dict[str, Any] = {}
    if which in (None, "filters"):
        tq, notice = query_for(view, prot.HEADER_SPEC, "filters")
        answer = await prot.header_rules_answer(view.ctx, tq, view.tr)
        tables["filters"] = table(
            view,
            "request-filters",
            "filters",
            prot.HEADER_SPEC,
            answer,
            export="header-rules",
            columns=(
                "needle",
                "header",
                "scope",
                "mode",
                "message",
                "hits",
                "last_hit_at",
                "enabled",
                "note",
                "hits_total",
                "canonical_key",
                "id",
            ),
            key_columns=("needle", "header", "hits"),
            hidden=("note", "hits_total", "canonical_key", "id"),
            cells=lambda item: {
                "needle": _caller(item.get("needle")),
                "header": _caller(item.get("header")) or {"text": "(any)", "tone": "muted"},
                "scope": {"text": pv.SCOPE_LABELS.get(str(item.get("scope")), str(item.get("scope")))},
                "mode": {"text": pv.MODE_LABELS.get(str(item.get("mode")), str(item.get("mode")))},
                "message": _caller(item.get("message")) or {"text": "stealth 429", "tone": "muted"},
                "note": _caller(item.get("note")),
                "canonical_key": _caller(item.get("canonical_key")),
                "enabled": pv.yes_no(item.get("enabled", True), yes="On", no="Off"),
                **_hits_cells(view, item),
            },
            row_id=lambda item: f"filter-{item.get('id')}",
            drawer=lambda item: view.fragment_url("request-filters", **{DETAIL_PARAM: item["id"]}),
            drawer_title=lambda item: f"Request filter #{item.get('id')}",
            caption="Request filters, first match first",
            search_placeholder="Search filters",
            notice=notice,
            empty={
                "title": "No request filters",
                "body": "A request filter refuses requests whose headers contain a text you choose, usually with a "
                "normal-looking throttle answer so the client cannot tell. Try one in the Tester tab first.",
                "icon": "inbox",
            },
        )
    if which in (None, "attempts"):
        tq, notice = query_for(view, prot.HEADER_ATTEMPT_SPEC, "attempts")
        answer = await prot.attempts_answer(view.ctx, "header_rule", tq, view.tr)
        tables["attempts"] = _attempts_table(
            view,
            "request-filters",
            "header_rule",
            answer,
            caption="Requests a filter refused in this range",
            notice=notice,
            empty={
                "title": "No request was filtered in this range",
                "body": "Each path a request filter refused is listed here with how often, how many clients, which "
                "filter refused it and which header it matched, by name or by value (v1's Header-Blocked Attempts).",
                "icon": "inbox",
            },
        )
    context: dict[str, Any] = {"only": which, "tables": tables}
    if which is None:
        context["presets"] = await prot.header_presets_answer(view.ctx)
        context["api"] = {"create": f"{API}/header-rules", "test": f"{API}/header-rules/test"}
        context["clear"] = clear_action(view, "header_rule_attempts")
    return context


async def _pattern_card(
    view: PageView,
    *,
    card: str,
    main_key: str,
    spec: TableSpec,
    answer_of: Callable[..., Any],
    export: str,
    reason: str,
    table_name: str,
    columns: Sequence[str],
    cells: Callable[[Mapping[str, Any]], dict[str, Any]],
    detail_kind: str,
    what: str,
    empty_main: Mapping[str, Any],
    empty_attempts: Mapping[str, Any],
    attempts_caption: str,
    clear_family: str,
) -> dict[str, Any]:
    """The endpoint blocks and endpoint rules cards: the rule table, its attempts tab (with v1's clear button, the
    `clear_family` data reset) and each rule's drawer."""
    raw = detail_of(view)
    if raw:
        rows = await prot.rule_table_rows(view.ctx, table_name, view.tr)
        return {"detail": _rule_detail(view, rows, raw, kind=detail_kind, what=what)}
    which = only_table(view, (main_key, "attempts"))
    tables: dict[str, Any] = {}
    extra: Mapping[str, Any] = {}
    if which in (None, main_key):
        tq, notice = query_for(view, spec, main_key)
        answer = await answer_of(view.ctx, tq, view.tr)
        extra = answer
        tables[main_key] = table(
            view,
            card,
            main_key,
            spec,
            answer,
            export=export,
            columns=columns,
            key_columns=("pattern", "hits", "last_hit_at"),
            hidden=("note", "hits_total", "id", "created_at"),
            cells=cells,
            row_id=lambda item: f"{main_key}-{item.get('id')}",
            drawer=lambda item: view.fragment_url(card, **{DETAIL_PARAM: item["id"]}),
            drawer_title=lambda item: f"{what.capitalize()} #{item.get('id')}",
            caption=what.capitalize() + "s",
            search_placeholder="Search patterns",
            notice=notice,
            empty=empty_main,
        )
    if which in (None, "attempts"):
        tq, notice = query_for(view, prot.ATTEMPT_SPEC, "attempts")
        answer = await prot.attempts_answer(view.ctx, reason, tq, view.tr)
        tables["attempts"] = _attempts_table(
            view, card, reason, answer, caption=attempts_caption, notice=notice, empty=empty_attempts
        )
    context: dict[str, Any] = {"only": which, "tables": tables, "per_ip_allowance": extra.get("per_ip_allowance")}
    if which is None:
        context["clear"] = clear_action(view, clear_family)
    return context


def _pattern_cells(view: PageView, item: Mapping[str, Any]) -> dict[str, Any]:
    kind = str(item.get("type") or "glob")
    return {
        "pattern": _caller(item.get("pattern")),
        "type": {"text": pv.TYPE_LABELS.get(kind, kind)},
        "message": _caller(item.get("message")) or {"text": "default", "tone": "muted"},
        "note": _caller(item.get("note")),
        "enabled": pv.yes_no(item.get("enabled", True), yes="On", no="Off"),
        "scope": {"text": pv.RULE_SCOPE_LABELS.get(str(item.get("scope")), str(item.get("scope") or ""))},
        "period": {"text": pv.span_words(item.get("period"))} if item.get("period") else None,
        "created_at": view.time_cell(item.get("created_at")),
        **_hits_cells(view, item),
    }


@page.card("endpoint-blocks", lazy=True)
async def endpoint_blocks_card(view: PageView) -> dict[str, Any]:
    """Endpoint blocks (`endpoint_blocks_answer`) with the Attempts tab (`attempts_answer`, row 16)."""
    return await _pattern_card(
        view,
        card="endpoint-blocks",
        main_key="blocks",
        spec=prot.BLOCK_SPEC,
        answer_of=prot.endpoint_blocks_answer,
        export="endpoint-blocks",
        reason="endpoint_blocked",
        table_name="rules_endpoint_block",
        columns=(
            "pattern",
            "type",
            "message",
            "hits",
            "last_hit_at",
            "enabled",
            "note",
            "hits_total",
            "created_at",
            "id",
        ),
        cells=lambda item: _pattern_cells(view, item),
        detail_kind="block",
        what="endpoint block",
        empty_main={
            "title": "No endpoint is blocked",
            "body": "A block refuses every request to the endpoints its pattern names, for every caller, with 403 "
            "and its reply (or the default text).",
            "icon": "inbox",
        },
        empty_attempts={
            "title": "Nobody asked for a blocked endpoint in this range",
            "body": "Each blocked path is listed here with how often it was asked for, by how many clients, and the "
            "block that refused it (v1's Blocked Endpoint Attempts).",
            "icon": "inbox",
        },
        attempts_caption="Requests a block refused in this range",
        clear_family="endpoint_block_attempts",
    )


@page.card("endpoint-rules", lazy=True)
async def endpoint_rules_card(view: PageView) -> dict[str, Any]:
    """Endpoint rate rules (`endpoint_rules_answer`) with the Attempts tab (`attempts_answer`, row 17)."""
    return await _pattern_card(
        view,
        card="endpoint-rules",
        main_key="rules",
        spec=prot.ENDPOINT_RULE_SPEC,
        answer_of=prot.endpoint_rules_answer,
        export="endpoint-rules",
        reason="endpoint_rule",
        table_name="rules_endpoint_limit",
        columns=(
            "pattern",
            "limit",
            "period",
            "scope",
            "type",
            "message",
            "hits",
            "last_hit_at",
            "enabled",
            "note",
            "hits_total",
            "created_at",
            "id",
        ),
        cells=lambda item: _pattern_cells(view, item),
        detail_kind="rule",
        what="endpoint rule",
        empty_main={
            "title": "No endpoint rules",
            "body": "An endpoint rule gives one endpoint a stricter limit than the per-IP one (it can only be more "
            "restrictive). The most specific matching rule applies.",
            "icon": "inbox",
        },
        empty_attempts={
            "title": "No endpoint rule refused anything in this range",
            "body": "Each path an endpoint rule refused is listed here with the rule that refused it (v1's "
            "Rate-Limited Attempts).",
            "icon": "inbox",
        },
        attempts_caption="Requests an endpoint rule refused in this range",
        clear_family="endpoint_rule_attempts",
    )


@page.card("ignored-paths", lazy=True)
async def ignored_paths_card(view: PageView) -> dict[str, Any]:
    """Ignored paths (`ignored_paths_answer`): answered 404 at once, never logged as probes."""
    raw = detail_of(view)
    if raw:
        found = _find(await _all_ignored(view), "pattern", raw)
        if found is None:
            raise _not_found("ignored path")
        return {"detail": {"entry": found, "delete_url": f"{API}/ignored-paths"}}
    tq, notice = query_for(view, prot.IGNORED_SPEC, "ignored")
    answer = await prot.ignored_paths_answer(view.ctx, tq)
    return {
        "only": only_table(view, ("ignored",)),
        "table": table(
            view,
            "ignored-paths",
            "ignored",
            prot.IGNORED_SPEC,
            answer,
            export="ignored-paths",
            cells=lambda item: {"pattern": _caller(item.get("pattern")), "note": _caller(item.get("note"))},
            row_id=lambda item: f"ignored-{row_key(item.get('pattern'))}",
            drawer=lambda item: view.fragment_url("ignored-paths", **{DETAIL_PARAM: item["pattern"]}),
            drawer_title=lambda item: "Ignored path",
            caption="Ignored paths",
            search_placeholder="Search paths",
            notice=notice,
            empty={
                "title": "No ignored paths",
                "body": "An ignored path is answered 404 at once and never counted as a probe: useful for files "
                "browsers and tools ask every site for.",
                "icon": "inbox",
            },
        ),
        "api": {"create": f"{API}/ignored-paths"},
    }


async def _all_ignored(view: PageView) -> list[dict[str, Any]]:
    """Every ignored path (the drawer finds one by its pattern even past the first page)."""
    query = TableQuery(1, max(common.PAGE_SIZES), prot.IGNORED_SPEC.default_sort, "asc", "")
    answer = await prot.ignored_paths_answer(view.ctx, query)
    return [dict(item) for item in answer["items"]]


# ============================================================================================ detectors


ACTION_LABELS: Final[dict[str, str]] = {
    "ban": "Bans",
    "would_ban": "Would ban (dry run)",
    "strike": "Adds a strike",
    "tarpit": "Holds in the tarpit",
    "recommend": "Recommends only",
    "off": "Off",
}
DECISION_LABELS: Final[dict[str, str]] = {
    "spam_would_ban": "Would have banned",
    "spam_ban": "Banned",
    "spam_strike": "Strike",
    "spam_tarpit": "Tarpit",
    "spam_detected": "Recommendation",
}


def _detector_view(item: Mapping[str, Any]) -> dict[str, Any]:
    settings = item.get("settings") or {}
    decisions = item.get("decisions") or {}
    signal, default = pv.DETECTOR_SIGNALS.get(str(item.get("id")), ("", ""))
    return {
        **item,
        "signal": signal,
        "default": default,
        "action_label": ACTION_LABELS.get(str(item.get("effective_action")), str(item.get("effective_action"))),
        "threshold": f"{pv.number(settings.get('threshold'))} {item.get('unit') or ''}".strip(),
        "window": pv.span_words(settings.get("window_s")),
        "decisions_total": sum(int(v or 0) for v in decisions.values()),
        "decision_rows": [
            {"label": DECISION_LABELS.get(str(kind), str(kind)), "count": int(count or 0)}
            for kind, count in sorted(decisions.items())
        ],
    }


@page.card("spam", lazy=True)
async def spam_card(view: PageView) -> dict[str, Any]:
    """The spam detectors (`spam_answer`), their decisions (`spam_events_answer`), and the collateral preview the
    arm dialog shows (`collateral_answer`, plan 10.3)."""
    kind = choice(view, "decisions", "kind", SPAM_KINDS)
    detector = choice(view, "decisions", "detector", ("", *(f"SPAM-{d.upper()}" for d in DETECTORS)))
    tq, notice = query_for(view, prot.SPAM_EVENTS_SPEC, "decisions")
    answer = await prot.spam_events_answer(view.ctx, tq, view.tr, kind=kind, detector=detector or None)
    filters = [
        filter_chip(
            "kind",
            "Decision",
            kind,
            [
                ("all", "Any decision"),
                ("would_ban", "Would have banned"),
                ("ban", "Banned"),
                ("strike", "Strike"),
                ("tarpit", "Tarpit"),
                ("recommend", "Recommendation"),
            ],
        ),
        filter_chip(
            "detector", "Detector", detector, [("", "Any detector"), *((f"SPAM-{d.upper()}",) * 2 for d in DETECTORS)]
        ),
    ]
    which = only_table(view, ("decisions",))
    context: dict[str, Any] = {
        "only": which,
        "table": table(
            view,
            "spam",
            "decisions",
            prot.SPAM_EVENTS_SPEC,
            answer,
            export="spam/events",
            key_columns=("at_ms", "kind", "subject"),
            hidden=("value", "threshold", "window_s"),
            cells=lambda item: {
                "kind": {"text": DECISION_LABELS.get(str(item.get("kind")), str(item.get("kind") or ""))},
                "subject": _caller(item.get("subject")),
                "evidence": _caller(item.get("evidence")),
                "action": _caller(item.get("action")),
                "window_s": _span(item.get("window_s")),
            },
            row_id=lambda item: f"decision-{item.get('at_ms')}-{row_key(item.get('subject'))}",
            filters=filters,
            caption="Detector decisions in this range, newest first",
            searchable=False,
            notice=notice,
            empty={
                "title": "No detector decided anything in this range",
                "body": "While the detectors run in dry run, a ban they would have made is listed here as Would have "
                "banned, so you can check them before arming.",
                "icon": "inbox",
            },
        ),
    }
    if which is None:
        state = await prot.spam_answer(view.ctx, view.tr)
        context["state"] = state
        context["detectors"] = [_detector_view(item) for item in state.get("detectors") or ()]
        context["collateral"] = await prot.collateral_answer(view.ctx)
        context["api"] = {"arm": f"{API}/spam/arm", "disarm": f"{API}/spam/disarm"}
        # The detector timelines (plan 10.9): every detector's decisions per time bucket, read by the chart from
        # `GET /protection/spam/series` (the same events as the decisions table below, over the page's range).
        context["timeline_src"] = view.api_url("protection/spam/series")
    return context


def _make_detector_card(detector: str) -> None:
    card_id = f"spam-{detector}"

    async def render(view: PageView) -> dict[str, Any]:
        state = await prot.spam_answer(view.ctx, view.tr)
        found = next((item for item in state.get("detectors") or () if item.get("id") == detector), None)
        if found is None:
            raise common.not_found("This spam detector is not known.")
        return {
            "detector": _detector_view(found),
            "dry_run": bool(state.get("dry_run")),
            "master": bool(state.get("enabled")),
        }

    render.__name__ = f"spam_{detector}_card"
    page.card(card_id, template="admin/pages/protection/spam_detector.html", lazy=True)(render)


for _detector in DETECTORS:
    _make_detector_card(_detector)


@page.card("bot", lazy=True)
async def bot_card(view: PageView) -> dict[str, Any]:
    """Bot heuristics (`bot_answer`): the weights and what each signal measures, the thresholds, refusals."""
    answer = await prot.bot_answer(view.ctx, view.tr)
    weights = answer.get("weights") or {}
    total = sum(float(v or 0) for v in weights.values())
    signals = [
        {
            "name": name,
            "label": pv.BOT_SIGNAL_NOTES.get(name, (name, ""))[0],
            "how": pv.BOT_SIGNAL_NOTES.get(name, ("", ""))[1],
            "weight": float(weights.get(name) or 0),
            "share": round(float(weights.get(name) or 0) * 100.0 / total, 1) if total else 0.0,
        }
        for name in weights
    ]
    return {"bot": answer, "signals": signals, "total_weight": total}


@page.card("challenge", lazy=True)
async def challenge_card(view: PageView) -> dict[str, Any]:
    """The browser challenge (`bot_answer`'s challenge part): state, availability, refusals in the range."""
    answer = await prot.bot_answer(view.ctx, view.tr)
    return {"challenge": answer.get("challenge") or {}, "refused": (answer.get("refused") or {}).get("challenge", 0)}


# ============================================================================================ tarpit


@page.card("tarpit", lazy=True)
async def tarpit_card(view: PageView) -> dict[str, Any]:
    """The tarpit (`tarpit_answer`): switches, the effective cap and its gauge, v1's tiles over the fleet's hold
    statistics (the range, plus the last 15 minutes, hour and day), categories, hold lengths, who is held.

    The trend under "Time between requests" compares the last hour with the period that ends where that hour begins
    (`baseline`: as long as the range, at least a day), never with a window that holds the hour itself."""
    state = await prot.tarpit_answer(view.ctx, view.tr)
    now = int(view.ctx.clock.now())
    hour_start = now - TARPIT_HOUR_S
    baseline_s = max(TARPIT_BASELINE_MIN_S, int(view.tr.window.span))

    def windows(conn: Any) -> dict[str, Any]:
        found = {key: read_producers.tarpit_summary(conn, now - span, now + 60) for key, span in TARPIT_WINDOWS}
        found["baseline"] = read_producers.tarpit_summary(conn, hour_start - baseline_s, hour_start)
        return found

    with common.service_errors():
        recent = await view.ctx.dbs.metrics.read(windows)
    history = state.get("history") or {}
    labels = state.get("category_labels") or {}
    enabled_categories = set(state.get("categories") or ())
    by_category = history.get("by_category") or {}
    categories = [
        {
            "name": name,
            "label": labels.get(name, name),
            "note": pv.TARPIT_CATEGORY_NOTES.get(name, ""),
            "on": name in enabled_categories,
            "holds": int((by_category.get(name) or {}).get("holds") or 0),
            "skipped": int((by_category.get(name) or {}).get("skipped") or 0),
            "mean": (by_category.get(name) or {}).get("mean_hold_s"),
            "total": float((by_category.get(name) or {}).get("mean_hold_s") or 0)
            * int((by_category.get(name) or {}).get("holds") or 0),
        }
        for name in TARPIT_CATEGORIES
    ]
    stats = state.get("stats") or {}

    def worker_rows(table_name: str) -> list[dict[str, Any]]:
        rows = []
        for key, value in (stats.get(table_name) or {}).items():
            category, _, rule = str(key).partition("|") if table_name == "reasons" else ("", "", "")
            rows.append(
                {
                    "key": key,
                    "category": labels.get(category, category),
                    "rule": rule,
                    "held": int(value.get("held") or 0),
                    "skipped": int(value.get("skipped") or 0),
                    "total": float(value.get("total_held_s") or 0),
                    "last": view.time_cell(value.get("last_at") or None),
                }
            )
        rows.sort(key=lambda row: (row["held"] + row["skipped"], row["total"]), reverse=True)
        return rows[:MAX_WORKER_ROWS]

    tone, status = pv.tarpit_status(state)
    return {
        "tarpit": state,
        "status_tone": tone,
        "status": status,
        "tiles": pv.tarpit_tiles(history, recent, state),
        "categories": categories,
        "kinds": sorted((history.get("by_kind") or {}).items()),
        "histogram": pv.histogram_rows(history.get("hold_histogram") or ()),
        "reasons": worker_rows("reasons"),
        "ips": worker_rows("ips"),
        "span": pv.span_words,
        "clear": clear_action(view, "tarpit"),
    }


__all__ = ["page", "router"]
