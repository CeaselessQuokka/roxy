"""The Clients page (`/admin/clients`, plan 14.1 Clients row; v1 "Callers and Top Talkers", parity rows 73 and 92).

What this is
    The five registry cards, each rendered from the same helper its admin API route calls (`roxy/admin/api/
    clients.py`, plan P6):
      * `places`: every place (`Roblox-Id`) in the range with requests, refusals, rates over the last minute, five
        minutes and hour, the busiest endpoint, the addresses it came from, when it was last seen and whether a ban
        covers it (the page's main table, kept in the address bar), plus the place limit settings (`clients#places`).
      * `ips`: every address with the same numbers, its bot score (this worker's view, else the fleet's recorded
        score, labeled) and its ban and bypass state.
      * `lookup`: v1's "Identify an experience": a place or universe id to its name, owner and links.
      * `client-score`: what the bot score adds up, the weight of each signal now, how the fleet's recorded scores
        spread over the thresholds, and the bot settings (`clients#client-score`).
      * `activity`: what per-client activity is kept, for how long, and v1's "Clear data" for it (the `activity`
        reset family).
    The per-client view (plan 14.1 "per-client page with actions"): `GET /admin/clients/client?kind=&key=` is the
    body a table row opens in the drawer, and `GET /admin/clients/ip/{ip}` and `/admin/clients/place/{place}` are the
    same view as a page of its own (a link to share). It shows the client's totals and timeline for the range, its
    last hour, refusals by reason, ban, bypass, deny and strike state, bot score breakdown, peers, recent probes and
    requests, and the actions: ban, bypass, a rule (a deny list entry for an address, a `Roblox-Id` request filter
    for a place), identify (a place), and reset its activity.

Why it exists
    v1's busiest-callers tables kept 400 addresses and 200 places per worker in memory; v2 reads the client activity
    tables for any range on the server and puts the actions next to the numbers that justify them.

How it works
    `page = Page("clients")` from the kit. Page routes only read; every action posts JSON to the admin API
    (`form[data-api-form]`), which validates, audits and bumps `config_version`. Place ids and everything in a
    request row are caller text: shown with `format.html caller_text` only, never in an attribute that is
    interpreted; a place id that is not a number (a forged header) gets no drawer link and no actions, because the
    API's place routes take digits only. Heavy cards are lazy (plan 6.7 on the 1 GB server).

What to read next
    `roxy/admin/api/clients.py`, `templates/admin/pages/clients.html` and `templates/admin/pages/clients/*.html`,
    `static/js/pages/clients.js`, `roxy/admin/pages/cache.py` (the sibling page and its shared macros).
"""

from __future__ import annotations

import ipaddress
import logging
import re
from collections.abc import Mapping
from typing import Any, Final
from urllib.parse import quote, urlencode

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse

from roxy.abuse.bot import SIGNALS
from roxy.admin.api import clients as clients_api
from roxy.admin.api import common
from roxy.admin.api import data as data_api
from roxy.admin.api import lookup as lookup_api
from roxy.admin.pages import fmt, shell
from roxy.admin.pages.cache import reset_digest, row_key, table_only, table_state
from roxy.admin.pages.kit import Page, PageAdmin, PageView, table_query, table_view, templates_of
from roxy.config.catalog import CATALOG
from roxy.deps import get_ctx
from roxy.metrics import read_producers

log = logging.getLogger("roxy.admin.pages")

page = Page("clients")
router = page.router

PLACES_TABLE: Final = "client-places"
IPS_TABLE: Final = "client-ips"
PLACE_RE: Final = re.compile(clients_api.PLACE_PATTERN)
CLIENT_TEMPLATE: Final = "admin/pages/clients/client.html"
CLIENT_PAGE_TEMPLATE: Final = "admin/pages/clients/client_page.html"
CLIENT_ERROR_TEMPLATE: Final = "admin/pages/clients/client_error.html"
ACTIVITY_FAMILY: Final = "activity"
"""The plan 6.8 reset family of v1's "Clear data" on Callers and Top Talkers (`admin/api/data.py FAMILIES`)."""
SCORE_WINDOW_S: Final = 25 * 3600
"""Recorded bot scores of the last 25 hours (the window the API's tables and the recommendation rules read)."""
SCORE_LIMIT: Final = 5000
RECENT_ROWS: Final = 10
BAN_LENGTHS: Final[tuple[tuple[int, str], ...]] = (
    (60, "1 hour"),
    (1440, "1 day"),
    (10_080, "1 week"),
    (43_200, "30 days"),
)
RETENTION_KEYS: Final[tuple[str, ...]] = (
    "retention_client_minute_days",
    "retention_client_hour_days",
    "retention_client_day_days",
)
"""The retention settings of the client activity tables (shown with a link to their home, Data > Retention)."""
CAP_KEYS: Final[tuple[str, ...]] = ("activity_tracking", "max_ip_activity_records", "max_caller_records")
"""The record caps of the client activity tables (shown with a link to their home, Data > Record caps)."""
RATES: Final[tuple[str, ...]] = ("1", "5", "15", "60")
"""The trailing windows (minutes) of a client's last-hour rates (`metrics/activity.py client_detail`)."""
OUTCOME_WORDS: Final[dict[str, str]] = {
    "served_cache": "from the cache",
    "served_upstream": "from Roblox",
    "refused": "refused",
    "failed": "failed",
}


# ============================================================================================ helpers


def is_place_id(text: str) -> bool:
    """A place id the API's place routes accept (digits only; anything else is a forged header)."""
    return bool(PLACE_RE.fullmatch(text or ""))


def signal_label(name: str) -> str:
    """A bot score signal's name from its weight setting's catalog label ("Bot score weight: probe history" reads
    "Probe history"), so the signal tables use the catalog's words without repeating the prefix."""
    spec = CATALOG.get(f"bot_weight_{name}")
    label = spec.label if spec else name.replace("_", " ")
    head, sep, tail = label.partition(": ")
    text = tail if sep else head
    return text[:1].upper() + text[1:]


def canonical_ip(text: str) -> str | None:
    """The address in its canonical form, or None for anything that is not an IP address."""
    try:
        return str(ipaddress.ip_address((text or "").strip()))
    except ValueError:
        return None


def client_href(kind: str, key: str) -> str:
    """The client's own page (a path on this site; the key is checked before it goes into the path)."""
    return f"/admin/clients/{kind}/{quote(key, safe='')}"


def _drawer_src(view: PageView, kind: str, key: str) -> str:
    return "/admin/clients/client?" + urlencode({**view.time.params, "kind": kind, "key": key})


def _rate(value: Any) -> str:
    if not isinstance(value, int | float):
        return fmt.MISSING
    return f"{value:,.0f}" if float(value).is_integer() else f"{value:,.1f}"


def _common_cells(view: PageView, item: Mapping[str, Any]) -> dict[str, Any]:
    refused_pct = item.get("refused_pct")
    return {
        "refused_pct": {"text": f"{refused_pct:.1f}%"} if isinstance(refused_pct, int | float) else None,
        "rate1": _rate(item.get("rate1")),
        "rate5": _rate(item.get("rate5")),
        "rate60": _rate(item.get("rate60")),
        "top_endpoint": {"text": item.get("top_endpoint"), "caller": True, "mono": True, "limit": 120}
        if item.get("top_endpoint")
        else None,
        "banned": {"text": "banned", "tone": "bad"} if item.get("banned") else {"text": "no", "tone": "muted"},
    }


# ============================================================================================ places


@page.card("places")
async def places_card(view: PageView) -> dict[str, Any]:
    """Places (`Roblox-Id`) in the range: the page's main table (its state lives in the address bar)."""
    tq, notice = table_query(view, clients_api.PLACE_SPEC)
    answer = await clients_api.client_table_answer(view.ctx, clients_api.PLACE_SPEC, tq, view.tr, "place")

    def cells(item: Mapping[str, Any]) -> dict[str, Any]:
        key = str(item.get("key") or "")
        out = _common_cells(view, item)
        out["key"] = {"text": key, "caller": True, "mono": True, "limit": 64}
        if not is_place_id(key):
            out["key"]["sub"] = "not a number: a forged header"
        out["name"] = {"text": item.get("name"), "caller": True} if item.get("name") else {"text": "not looked up"}
        return out

    table = table_view(
        view,
        PLACES_TABLE,
        clients_api.PLACE_SPEC,
        answer,
        src=view.fragment_url("places"),
        columns=(
            "key",
            "name",
            "requests",
            "refused",
            "refused_pct",
            "rate1",
            "rate5",
            "rate60",
            "top_endpoint",
            "peers",
            "last_seen",
            "served",
            "bytes",
            "banned",
        ),
        key_columns=("key", "requests", "rate1"),
        hidden=("rate5", "rate60", "served", "bytes", "refused_pct"),
        cells=cells,
        row_id=lambda item: f"place-{row_key(item.get('key'))}",
        drawer=lambda item: _drawer_src(view, "place", str(item["key"])) if is_place_id(str(item.get("key"))) else None,
        drawer_title=lambda item: f"Place {item.get('key')}" if is_place_id(str(item.get("key"))) else "Place",
        export_url=view.api_url("clients/places"),
        caption="Places calling Roxy",
        empty={
            "title": "No places in this range",
            "body": "A place is counted when a request carries a Roblox-Id header, which Roblox game servers send "
            "on every HttpService call. Try a longer range in the top bar.",
            "icon": "users",
        },
        search_placeholder="Search place ids",
        notice=notice,
    )
    return {
        "table": table,
        "table_only": table_only(view, PLACES_TABLE),
        "card_src": view.fragment_url("places", **table_state(tq, clients_api.PLACE_SPEC)),
        "peers_basis": answer.get("peers_basis"),
    }


# ============================================================================================ addresses


@page.card("ips", lazy=True)
async def ips_card(view: PageView) -> dict[str, Any]:
    """Addresses in the range with rates, refusals, bot scores, ban and bypass state."""
    tq, notice = table_query(view, clients_api.IP_SPEC, address=False)
    answer = await clients_api.client_table_answer(view.ctx, clients_api.IP_SPEC, tq, view.tr, "ip")
    sources: dict[str, str] = {"this_worker": "this worker", "recorded": "recorded"}
    legit_max = int(view.ctx.settings.int("bot_score_legit_max"))
    abuse_min = int(view.ctx.settings.int("bot_score_abuse_min"))

    def cells(item: Mapping[str, Any]) -> dict[str, Any]:
        out = _common_cells(view, item)
        out["key"] = {"text": item.get("key"), "mono": True}
        score = item.get("bot_score")
        source = item.get("bot_score_source")
        if isinstance(score, int | float):
            # The bot settings' own thresholds, in words as well as color (plan 14.9).
            if score >= abuse_min:
                tone, words = "bad", "looks automated"
            elif score > legit_max:
                tone, words = "warn", "in between"
            else:
                tone, words = None, "looks legitimate"
            where = sources.get(str(source), "")
            out["bot_score"] = {"text": f"{score:.0f}", "tone": tone, "sub": f"{words} ({where})" if where else words}
        else:
            out["bot_score"] = {"text": fmt.MISSING, "tone": "muted", "sub": "no recent request"}
        out["bypassed"] = (
            {"text": "bypassed", "tone": "info"} if item.get("bypassed") else {"text": "no", "tone": "muted"}
        )
        return out

    table = table_view(
        view,
        IPS_TABLE,
        clients_api.IP_SPEC,
        answer,
        src=view.fragment_url("ips"),
        columns=(
            "key",
            "requests",
            "refused",
            "refused_pct",
            "rate1",
            "rate5",
            "rate60",
            "top_endpoint",
            "peers",
            "bot_score",
            "last_seen",
            "served",
            "bytes",
            "banned",
            "bypassed",
        ),
        key_columns=("key", "requests", "rate1"),
        hidden=("rate5", "rate60", "served", "bytes", "refused_pct"),
        cells=cells,
        row_id=lambda item: f"ip-{row_key(item.get('key'))}",
        drawer=lambda item: (
            _drawer_src(view, "ip", canonical_ip(str(item.get("key"))) or "")
            if canonical_ip(str(item.get("key")))
            else None
        ),
        drawer_title=lambda item: f"Address {item.get('key')}",
        export_url=view.api_url("clients/ips"),
        caption="Addresses calling Roxy",
        empty={
            "title": "No addresses in this range",
            "body": "Every request is counted under the address it came from (behind nginx). Try a longer range.",
            "icon": "users",
        },
        search_placeholder="Search addresses",
        notice=notice,
        address=False,
    )
    return {
        "table": table,
        "table_only": table_only(view, IPS_TABLE),
        "peers_basis": answer.get("peers_basis"),
        "sources": answer.get("bot_score_sources"),
    }


# ============================================================================================ lookup


@page.card("lookup")
async def lookup_card(view: PageView) -> dict[str, Any]:
    """v1's "Identify an experience" form (the answer is drawn by static/js/pages/clients.js from the API's JSON)."""
    return {
        "lookup_url": f"{common.API_PREFIX}/clients/lookup",
        "throwaway_note": lookup_api.THROWAWAY_NOTE,
        "prefill": view.param("lookup", max_chars=20) if is_place_id(view.param("lookup", max_chars=20)) else "",
    }


# ============================================================================================ bot score


@page.card("client-score", lazy=True)
async def client_score_card(view: PageView) -> dict[str, Any]:
    """What the bot score adds up, each signal's share now, and how recorded scores spread over the thresholds."""
    settings = view.ctx.settings
    weights = {name: float(settings.get(f"bot_weight_{name}")) for name in SIGNALS}
    total = sum(max(0.0, w) for w in weights.values())
    signals = []
    for name in SIGNALS:
        spec = CATALOG.get(f"bot_weight_{name}")
        weight = max(0.0, weights[name])
        signals.append(
            {
                "name": name,
                "label": signal_label(name),
                "weight": weight,
                "share": round(weight * 100.0 / total, 1) if total else 0.0,
            }
        )
    legit_max = int(settings.int("bot_score_legit_max"))
    abuse_min = int(settings.int("bot_score_abuse_min"))
    block = int(settings.int("bot_score_block_threshold"))
    since = int(view.now) - SCORE_WINDOW_S
    scores: dict[str, int] = await view.ctx.dbs.metrics.read(
        lambda conn: read_producers.client_scores(conn, since, limit=SCORE_LIMIT)
    )
    values = list(scores.values())
    return {
        "signals": signals,
        "total_weight": total,
        "legit_max": legit_max,
        "abuse_min": abuse_min,
        "block": block,
        "scored": len(values),
        "legit": sum(1 for v in values if v <= legit_max),
        "abusive": sum(1 for v in values if v >= abuse_min),
        "blocked_now": sum(1 for v in values if block and v >= block),
        "middle": sum(1 for v in values if legit_max < v < abuse_min),
    }


# ============================================================================================ activity


def activity_reset(ctx: Any) -> dict[str, Any]:
    """The "Clear client activity" dialog (v1 `Clear data` on Callers and Top Talkers, the `activity` family)."""
    family = data_api.FAMILIES[ACTIVITY_FAMILY]
    return {
        "id": "dlg-clients-reset-activity",
        "title": "Clear every client's activity?",
        "family": ACTIVITY_FAMILY,
        "phrase": f"reset {ACTIVITY_FAMILY}",
        "digest": reset_digest(ctx, scope="family", families=[ACTIVITY_FAMILY]),
        "consequences": [
            "The per-place and per-address activity rows (requests, refusals, rates, peers) are deleted, for places "
            "and addresses alike (v1 forgot the addresses).",
            "The recorded bot scores go too. Bans, bypass entries, rules and strikes stay.",
            "These tables start filling again with the next request; Traffic totals are not touched.",
        ],
        "note": family.note,
        "confirm_label": "Clear client activity",
        "success": "Client activity cleared.",
    }


@page.card("activity", lazy=True)
async def activity_card(view: PageView) -> dict[str, Any]:
    """What per-client activity Roxy keeps and for how long, and its reset."""
    settings = view.ctx.settings
    kept = []
    for key in (*RETENTION_KEYS, *CAP_KEYS):
        spec = CATALOG.get(key)
        if spec is None:
            continue
        home = next((a for a in spec.pages if not a.startswith("settings#")), spec.pages[0] if spec.pages else "")
        page_id, _, card_id = home.partition("#")
        value = settings.get(key)
        if spec.type.value == "bool":
            shown = "on" if value else "off"
        else:
            shown = f"{value:,}" if isinstance(value, int) else str(value)
            shown += f" {spec.unit}" if spec.unit else ""
        kept.append({"key": key, "label": spec.label, "shown": shown, "href": f"/admin/{page_id}#{card_id}"})
    return {"kept": kept, "reset": activity_reset(view.ctx)}


# ============================================================================================ the client view


def _series(answer: Mapping[str, Any]) -> dict[str, Any]:
    """The client's timeline as an API series answer (what static/js/charts.js draws)."""
    timeline = answer.get("timeline") or ()
    series = [
        {
            "key": key,
            "label": label,
            "unit": "requests",
            "points": [[point["t"], point.get(key, 0)] for point in timeline],
        }
        for key, label in (("requests", "Requests"), ("served", "Served"), ("refused", "Refused"))
    ]
    return {"range": answer.get("range"), "series": series, "compare": None, "annotations": [], "notices": []}


def client_reset(ctx: Any, kind: str, key: str) -> dict[str, Any]:
    """The "Reset this client" dialog (plan 6.8 scope `client`; bans stay)."""
    return {
        "id": "dlg-client-reset",
        "title": "Reset this client's activity?",
        "scope": "client",
        "client_type": kind,
        "client": key,
        "phrase": None,
        "digest": reset_digest(ctx, scope="client", client_type=kind, client=key),
        "consequences": [
            "Its activity rows, strikes, limiter state and events are deleted, so it starts with a full allowance.",
            "Bans, rules and settings stay; ban it or add a rule separately.",
        ],
        "confirm_label": "Reset this client",
        "success": "The client's activity was reset.",
    }


async def client_context(view: PageView, kind: str, key: str) -> dict[str, Any]:
    """The context of the client view (drawer or page): the API's own answer plus what the template needs."""
    ctx = view.ctx
    if kind == "ip":
        address = canonical_ip(key)
        if address is None:
            raise common.not_found("That is not an IP address.")
        answer = await clients_api.ip_view(ctx, view.tr, address)
        key = address
        api_base = f"{common.API_PREFIX}/clients/ips/{quote(address, safe='')}"
    elif kind == "place":
        if not is_place_id(key):
            raise common.not_found(
                "That place id is not a number, so it cannot be opened here. Roblox servers always send digits, so a "
                "place id like this one was forged by the caller."
            )
        answer = await clients_api.place_view(ctx, view.tr, key)
        api_base = f"{common.API_PREFIX}/clients/places/{key}"
    else:
        raise common.not_found("Choose a place or an address from the tables.")
    now = view.now
    recent = []
    for row in list(answer.get("recent_requests") or ())[:RECENT_ROWS]:
        at_ms = row.get("at_ms")
        recent.append(
            {
                **row,
                "when": fmt.time_cell(at_ms / 1000 if isinstance(at_ms, int | float) else None, view.tz, now),
                "outcome_words": OUTCOME_WORDS.get(str(row.get("outcome")), str(row.get("outcome") or "")),
                "target": (str(row.get("url") or "") + ("?" + str(row["query"]) if row.get("query") else ""))[:400],
            }
        )
    probes = [
        {**row, "when": fmt.time_cell(row["at_ms"] / 1000, view.tz, now) if row.get("at_ms") else None}
        for row in list(answer.get("recent_probes") or ())[:RECENT_ROWS]
    ]
    refusals = [
        {**row, "when": fmt.time_cell(row["last_ms"] / 1000, view.tz, now) if row.get("last_ms") else None}
        for row in answer.get("refusals") or ()
    ]
    peers = answer.get("peers") or {}
    peer_rows = [
        {
            **item,
            "when": view.time_cell(item.get("last_seen")),
            "href": client_href("place" if kind == "ip" else "ip", str(item["key"]))
            if (is_place_id(str(item["key"])) if kind == "ip" else canonical_ip(str(item["key"])))
            else "",
        }
        for item in peers.get("items") or ()
    ]
    bot = dict(answer.get("bot_score") or {})
    if bot.get("signals"):
        weights = bot.get("weights") or {}
        bot["rows"] = [
            {
                "name": name,
                "label": signal_label(name),
                "signal": float(bot["signals"].get(name) or 0.0),
                "weight": float(weights.get(name) or 0.0),
            }
            for name in SIGNALS
        ]
    history = [
        {**row, "when": fmt.local_time(row.get("bucket_start"), view.tz, seconds=False)}
        for row in bot.get("recorded_history") or ()
    ]
    ban = answer.get("ban")
    if ban:
        ban = {
            **ban,
            "until": fmt.local_time(ban.get("expires_at"), view.tz, seconds=False) if ban.get("expires_at") else None,
        }
    return {
        "kind": kind,
        "key": key,
        "client": answer,
        "chart": _series(answer),
        "recent": recent,
        "probes": probes,
        "refusals": refusals,
        "peers": {"total": peers.get("total") or 0, "rows": peer_rows, "basis": peers.get("basis")},
        "bot": bot,
        "history": history,
        "ban": ban,
        "lookup": answer.get("lookup"),
        "api_base": api_base,
        "page_href": client_href(kind, key),
        "drawer_src": _drawer_src(view, kind, key),
        "reset": client_reset(ctx, kind, key),
        "ban_lengths": BAN_LENGTHS,
        "bypass_hours": float(ctx.settings.get("bypass_default_expiry_h")),
        "range_label": view.time.view.get("label"),
        "rate_text": {name: _rate(((answer.get("last_hour") or {}).get("rates") or {}).get(name)) for name in RATES},
        "throwaway_note": lookup_api.THROWAWAY_NOTE,
        "audit_href": "/admin/audit?" + urlencode({"q": key}),
    }


async def _render_view(request: Request, principal: Any, kind: str, key: str, *, standalone: bool) -> HTMLResponse:
    """The client view as a drawer body, or (`standalone`) as a whole page inside the shell."""
    templates = templates_of(request)
    if standalone:
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
    else:
        view = await page.view(request, principal)
    base = {"view": view, "tz": view.tz, "now": view.now, "time": view.time.view, "standalone": standalone}
    try:
        context = await client_context(view, kind, key)
        template = CLIENT_TEMPLATE
    except Exception as exc:  # the view says what went wrong in place; it never turns into a 500
        mapped = exc if isinstance(exc, common.ApiError) else common.service_error(exc)
        if mapped is None:
            log.exception("client_view_failed", extra={"fields": {"kind": kind}})
            message = "This client failed to load. The error is in the server log; try again shortly."
        else:
            message = mapped.error_message
        context = {"error": message}
        template = CLIENT_ERROR_TEMPLATE
    if not standalone:
        return HTMLResponse(templates.render_to_string(request, template, {**base, **context}))
    assert view.shell is not None
    title = f"Place {key}" if kind == "place" else f"Address {key}"
    page_ctx = {
        **view.shell.context,
        **base,
        **context,
        "page": {
            "id": page.spec.id,
            "title": title if "error" not in context else "Client",
            "purpose": "One client's numbers for the selected range, its state, and the actions you can take on it.",
            "how_to_read": page.spec.how_to_read,
        },
        "body_template": template,
        "page_assets": page.assets,
    }
    return templates.render(request, CLIENT_PAGE_TEMPLATE, page_ctx)


@page.router.get("/client", include_in_schema=False)
async def client_drawer(request: Request, principal: PageAdmin) -> HTMLResponse:
    """One client in the drawer (`?kind=ip|place&key=`)."""
    kind = (request.query_params.get("kind") or "")[:8]
    key = (request.query_params.get("key") or "")[:64]
    return await _render_view(request, principal, kind, key, standalone=False)


@page.router.get("/ip/{ip}", include_in_schema=False)
async def ip_page(request: Request, principal: PageAdmin, ip: str) -> HTMLResponse:
    """One address as a page of its own (a shareable link); 404 for anything that is not an IP address."""
    address = canonical_ip(ip[:64])
    if address is None:
        raise HTTPException(status_code=404, detail="Not Found")
    return await _render_view(request, principal, "ip", address, standalone=True)


@page.router.get("/place/{place}", include_in_schema=False)
async def place_page(request: Request, principal: PageAdmin, place: str) -> HTMLResponse:
    """One place as a page of its own; 404 for anything that is not a place id (digits)."""
    if not is_place_id(place):
        raise HTTPException(status_code=404, detail="Not Found")
    return await _render_view(request, principal, "place", place, standalone=True)


__all__ = ["canonical_ip", "client_context", "client_href", "is_place_id", "page", "router"]
