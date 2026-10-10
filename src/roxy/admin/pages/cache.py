"""The Cache page (`/admin/cache`, plan 14.1 Cache row; v1 "Response Cache", parity rows 52 to 67).

What this is
    The ten registry cards of the page, each rendered from the same helper its admin API route calls
    (`roxy/admin/api/cache.py`, plan P6):
      * `stats`: the hit and avoided ratios with their comparison, v1's short-window hit ratios, the stored answers
        against their budgets, evictions, this worker's memory tier and the shared store's health (v1 tiles Hit
        Rate, Requests Roblox Never Saw, Stored Responses, Memory Tier), and "Clear stats" (the `cache_stats` reset
        family, v1 `Clear stats`).
      * `ratios`: hit ratio, avoided calls and the answers per cache state over time.
      * `settings` and `coalescing`: v1's "what happens to one request, using your current settings" explainer
        (plan 14.7, extended with the revalidation window and coalescing), v1's cache glossary, and the catalog
        settings the `pages` field places there (`cache#settings`, `cache#coalescing`).
      * `endpoints`: where the cache works, per endpoint template (hit ratio, TTL and rule, stale serves,
        revalidations, negative hits); a row opens its drawer with "write a rule" and "purge its answers".
      * `rules`: the cache rules with an add form, an edit and remove drawer per rule, and the TTL tuner's open
        suggestions (the cache family recommendations).
      * `ignored-params`: parameters left out of the cache key, v1's suggestion list and the key spread's suspects.
      * `spread`: v1's "Why isn't something being reused?" (the key spread diagnostic) with Ignore and Purge.
      * `browser`: the stored answers (search, sort, page; the page's main table, kept in the address bar), each
        opening the inspector drawer with Refresh and Purge; "Purge matching" removes exactly what the search
        lists (`scope: search`, v1 bug 4), plus Purge expired and Purge all.
      * `purge`: purge by host, rule, pattern (glob or regex), search text, expired, or everything.
    Three drawer routes serve the row details: `/admin/cache/drawer/entry?id=`, `/admin/cache/drawer/endpoint?
    template=` and `/admin/cache/drawer/rule?id=`.

Why it exists
    The cache is Roxy's strongest defense against Roblox rate limits (plan 2.5) and v1's Response Cache section was
    its most used part. Every control v1 had is kept (C3), with v1's browser bugs fixed by the API it calls.

How it works
    `page = Page("cache")` from the kit (`roxy/admin/pages/kit.py`): the route, the fragments, the guard, the shell,
    the inline settings. Page routes only read; every change posts JSON to the admin API (`form[data-api-form]`,
    `static/js/api_forms.js`), which validates, audits and purges. The statistics are read once per render even
    though two cards show them (`_stats`, a task shared by the cards of one render). Caller-chosen text (endpoint
    templates, cache keys, rule patterns and notes, stored bodies) is rendered only through `format.html
    caller_text` or inside `<code>`/`<pre>` as text. Heavy cards are lazy (plan 6.7 on the 1 GB server).

What to read next
    `roxy/admin/api/cache.py`, `templates/admin/pages/cache.html` and `templates/admin/pages/cache/*.html`,
    `static/js/pages/cache.js`, `roxy/admin/pages/kit.py`.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import Any, Final
from urllib.parse import quote, urlencode

from fastapi import Request
from fastapi.responses import HTMLResponse

from roxy.admin.api import cache as cache_api
from roxy.admin.api import common
from roxy.admin.api import data as data_api
from roxy.admin.pages import fmt
from roxy.admin.pages.kit import Page, PageAdmin, PageView, table_query, table_view, templates_of
from roxy.config.constants import DEFAULT_CACHE_RULE_TTL, MAX_CACHE_IGNORED_PARAMS
from roxy.config.insight_params import INSIGHT_RULES
from roxy.insights import read_recommendations
from roxy.insights.simulate import template_pattern
from roxy.metrics.catalog import METRICS

log = logging.getLogger("roxy.admin.pages")

page = Page("cache")
router = page.router

DRAWER_ERROR_TEMPLATE: Final = "admin/pages/cache/drawer_error.html"
BROWSER_TABLE: Final = "cache-browser"
ENDPOINTS_TABLE: Final = "cache-endpoints"
RULES_TABLE: Final = "cache-rules"
STATS_FAMILY: Final = "cache_stats"
"""The plan 6.8 reset family of v1's "Clear stats" (`admin/api/data.py FAMILIES`)."""
SPREAD_LIMIT: Final = 25
"""Endpoints the key spread lists (v1 asked for 25)."""
SUGGESTION_LIMIT: Final = 10
CACHE_RULE_IDS: Final[tuple[str, ...]] = tuple(rule for rule, spec in INSIGHT_RULES.items() if spec.family == "cache")
"""The recommendation rules of the cache family (the TTL tuner's suggestions among them)."""
MAX_TEMPLATE_CHARS: Final = 300
MAX_BODY_SHOWN: Final = 64 * 1024
"""Characters of a stored body the inspector shows (the API answer carries up to 256 KiB)."""
GLOSSARY_TERMS: Final[tuple[str, ...]] = ("hit", "miss", "ttl", "expired", "stale", "cache-entry", "evicted", "purge")
"""v1's "The words used on this page" (dashboard.md 9.4), now from docs/glossary.yml."""
STATE_TONES: Final[dict[str, str]] = {"fresh": "ok", "stale": "warn", "expired": "muted", "marker": "bad"}
STATE_WORDS: Final[dict[str, str]] = {
    "fresh": "fresh",
    "stale": "stale (still usable while Roblox fails)",
    "expired": "expired",
    "marker": "429 marker",
}
RULE_COLUMN_ORDER: Final[tuple[str, ...]] = (
    "pattern",
    "ttl",
    "type",
    "methods",
    "note",
    "enabled",
    "stale_ttl",
    "negative_ttl",
    "normalize_flags",
    "origin",
    "id",
    "created_at",
    "updated_at",
)
"""The rules table's columns, pattern first (the cell that opens the rule; a phone card leads with it)."""
RULE_ORIGINS: Final[dict[str, str]] = {"default": "shipped", "admin": "admin", "recommendation": "recommendation"}


# ============================================================================================ small helpers


def span_words(seconds: Any) -> str:
    """v1 `fmtSpan`: `N second(s)`, `N minute(s)` or `N minute(s) Ns`, `N hour(s)` or `N hour(s) Nm`."""
    try:
        s = max(0, int(seconds))
    except (TypeError, ValueError):
        return fmt.MISSING
    if s < 60:
        return f"{s} second{'' if s == 1 else 's'}"
    if s < 3600:
        m, rest = divmod(s, 60)
        return f"{m} minute{'' if m == 1 else 's'}" + (f" {rest}s" if rest else "")
    h, rest = divmod(s, 3600)
    m = rest // 60
    return f"{h} hour{'' if h == 1 else 's'}" + (f" {m}m" if m else "")


def _stats(view: PageView) -> asyncio.Future[dict[str, Any]]:
    """The statistics answer of this render, read once even when two cards show it (they render concurrently)."""
    task: asyncio.Future[dict[str, Any]] | None = view.extra.get("cache_stats")
    if task is None:
        task = asyncio.ensure_future(cache_api.stats_answer(view.ctx, view.tr))
        view.extra["cache_stats"] = task
    return task


def row_key(text: Any) -> str:
    """A short stable id for a row named by caller text (never the text itself in an attribute)."""
    return hashlib.sha256(str(text).encode("utf-8", "replace")).hexdigest()[:16]


def table_only(view: PageView, table_id: str) -> bool:
    """True for a table's own request (search, sort, page: htmx names the table in `HX-Target`): the card answers
    with the table alone, which replaces itself, instead of the whole card (which would nest inside the card)."""
    return view.in_fragment and view.request.headers.get("HX-Target") == table_id


def table_state(tq: common.TableQuery, spec: common.TableSpec) -> dict[str, Any]:
    """The table's non-default search, sort and size, for the card's own fragment URL: a refresh after an action
    keeps what the admin was looking at (the page number starts again at 1)."""
    state: dict[str, Any] = {}
    if tq.q:
        state["q"] = tq.q
    if tq.sort != spec.default_sort:
        state["sort"] = tq.sort
    if tq.order != spec.default_order:
        state["order"] = tq.order
    if tq.page_size != common.DEFAULT_PAGE_SIZE:
        state["page_size"] = tq.page_size
    return state


def reset_digest(ctx: Any, **scope: Any) -> str | None:
    """The preview digest of a data reset (`POST /data/resets` checks it): the same `build_plan` the data API runs,
    so the dialog can run the scope it shows. None when the scope cannot be built (the dialog then says so)."""
    try:
        body = data_api.ResetBody.model_validate(scope)
        return data_api.build_plan(body, ctx, ctx.clock.now()).digest
    except (common.ApiError, ValueError):
        return None


def stats_reset(ctx: Any) -> dict[str, Any]:
    """The "Clear stats" dialog of the statistics card (v1 `Clear stats`, the `cache_stats` family)."""
    family = data_api.FAMILIES[STATS_FAMILY]
    return {
        "id": "dlg-cache-reset-stats",
        "title": "Clear the cache statistics?",
        "family": STATS_FAMILY,
        "phrase": f"reset {STATS_FAMILY}",
        "digest": reset_digest(ctx, scope="family", families=[STATS_FAMILY]),
        "consequences": [
            "Hits, misses, stale and coalesced counts start again from zero, as v1's Clear stats did.",
            "The stored answers stay (use Purge for those); the requests stay in every Traffic total.",
            "A marker on the charts shows when it happened, and tiles over that time say their data was reset.",
        ],
        "note": family.note,
    }


def explainer(settings: Any) -> dict[str, Any]:
    """v1's "What happens to one request, using your current settings" (dashboard.md 7.1), from the saved settings,
    extended with the stale-while-revalidate window and coalescing (plan 14.7)."""
    enabled = bool(settings.bool("cache_enabled"))
    ttl = int(settings.int("cache_ttl_seconds"))
    stale = int(settings.int("cache_stale_seconds"))
    swr = int(settings.int("cache_swr_seconds"))
    coalesce = bool(settings.bool("cache_coalesce"))
    ttl_label = span_words(ttl)
    steps: list[dict[str, Any]] = []

    def step(at: str, *parts: Any) -> None:
        steps.append({"at": at, "parts": [p if isinstance(p, dict) else {"text": str(p)} for p in parts]})

    def strong(text: str) -> dict[str, str]:
        return {"strong": text}

    def badge(text: str, tone: str = "neutral") -> dict[str, str]:
        return {"badge": text, "tone": tone}

    if not enabled:
        step(
            "always",
            "Caching is switched off, so every request is forwarded to Roblox, including the ",
            strong("hundredth identical one"),
            ". Turn the response cache on in the settings below to change that.",
        )
    elif ttl <= 0:
        step(
            "always",
            '"Default cache lifetime" is 0, so nothing is saved by default and every request goes to Roblox. Only '
            "endpoints given their own cache rule are cached.",
        )
    else:
        first: list[Any] = [
            "Nobody has asked this before, so there is nothing to reuse: ",
            badge("MISS"),
            ". We ask Roblox once, pass the answer back, and keep a copy.",
        ]
        if coalesce:
            first += [
                " Callers asking the same question while that call is on its way wait for it and share its answer: ",
                badge("COALESCED", "info"),
                ". Roblox still hears one request.",
            ]
        step("0s", *first)
        step(
            f"up to {ttl_label}",
            "Everyone else asking the same question gets that copy: ",
            badge("HIT", "ok"),
            ". ",
            strong("Roblox hears nothing"),
            ", however many times they ask: one caller or ten thousand.",
        )
        step(
            ttl_label,
            "The copy is now ",
            strong("expired"),
            ". We stop treating it as current, but we do not throw it away yet.",
        )
        if swr > 0:
            step(
                f"{ttl_label} to {span_words(ttl + swr)}",
                "The next caller still gets the copy at once: ",
                badge("REVALIDATING", "info"),
                ", while Roxy asks Roblox for a fresh one in the background (one refresh for everyone). Nobody waits "
                "for Roblox here.",
            )
        after = span_words(ttl + swr) if swr > 0 else ttl_label
        if stale > 0:
            step(
                f"just after {after}",
                "The next person to ask sends us back to Roblox. If Roblox answers, we save the new copy and count a ",
                badge("MISS"),
                ". If Roblox refuses us (rate-limited, or down), we hand over the expired copy anyway: ",
                badge("STALE", "warn"),
                ". The caller gets a slightly old number instead of an error, and never knows anything went wrong.",
            )
            step(
                span_words(ttl + stale),
                f"That is {ttl_label} + {span_words(stale)}. The copy is now older than the stale serving window, so "
                "it is no longer used even as a fallback. From here on, a request that Roblox refuses becomes a real "
                "error for the caller.",
            )
        else:
            step(
                f"just after {after}",
                "The next person to ask sends us back to Roblox. If Roblox answers, we save the new copy and count a ",
                badge("MISS"),
                ". If Roblox refuses us, the caller gets the error, because ",
                strong('"Stale serving window" is 0'),
                ". Raising it would let them keep getting the last good answer instead.",
            )
    return {
        "steps": steps,
        "example": "games.roblox.com/v1/games/votes?universeIds=9967558039",
        "settings": {"enabled": enabled, "ttl": ttl, "stale": stale, "swr": swr, "coalesce": coalesce},
    }


# ============================================================================================ statistics


def _tile(answer: Mapping[str, Any], key: str) -> dict[str, Any] | None:
    return next((dict(t) for t in answer.get("tiles") or () if t.get("key") == key), None)


@page.card("stats")
async def stats_card(view: PageView) -> dict[str, Any]:
    """Hit and avoided ratios, short windows, size against the budgets, evictions, memory tier, disk health."""
    answer = await _stats(view)
    tiles = [dict(t) for t in answer["tiles"]]
    displays: dict[str, str] = {}
    hit = _tile(answer, "hit_ratio")
    if hit is not None and hit.get("value") is None and hit.get("partial"):
        # Plan 6.8 (finding parity-8): after a cache statistics reset the ratio has no lookups to divide by.
        displays["hit_ratio"] = "cleared by a reset"
    settings = answer.get("settings") or {}
    size = answer.get("size") or {}
    worker = answer.get("this_worker") or {}
    memory = worker.get("memory") or {}
    disk = answer.get("disk") or {}
    served = (_tile(answer, "served_cache") or {}).get("value")
    recent = [
        {"label": label, **(answer.get("recent_hit_ratio") or {}).get(name, {})}
        for name, label in (("5m", "Last 5 minutes"), ("1h", "Last hour"), ("24h", "Last 24 hours"))
    ]
    disk_problem = bool(size.get("disk_enabled")) and disk and not disk.get("OK", True)
    return {
        "tiles": tiles,
        "displays": displays,
        "settings": settings,
        "size": size,
        "evictions": answer.get("evictions") or {},
        "memory": memory,
        "flights": worker.get("stats") or {},
        "disk": disk,
        "disk_problem": disk_problem,
        "served": served,
        "recent": recent,
        "notices": list(answer.get("notices") or ()),
        "ttl_words": span_words(settings.get("ttl_s")),
        "reset": stats_reset(view.ctx),
        "states": answer.get("states") or {},
    }


def _split_series(answer: Mapping[str, Any], key: str) -> dict[str, Any]:
    """One series of a series answer (with its comparison), keeping the range, annotations and notices."""
    out = dict(answer)
    out["series"] = [s for s in answer.get("series") or () if s.get("key") == key]
    compare = answer.get("compare")
    if isinstance(compare, Mapping):
        out["compare"] = {**compare, "series": [s for s in compare.get("series") or () if s.get("key") == key]}
    return out


@page.card("ratios", lazy=True)
async def ratios_card(view: PageView) -> dict[str, Any]:
    """Hit ratio and avoided calls (embedded: they have different units, so two charts), states from the API."""
    answer = await cache_api.cache_series(view.ctx, view.tr, cache_api.RATIO_METRICS, {})
    return {
        "hit": _split_series(answer, "hit_ratio"),
        "avoided": _split_series(answer, "avoided_pct"),
        "states_src": view.api_url("cache/states"),
        "ratios_src": view.api_url("cache/ratios"),
        "help": {
            "hit": METRICS["hit_ratio"].description,
            "avoided": METRICS["avoided_pct"].description,
            "states": "; ".join(cache_api.STATE_LABELS.values()) + ".",
        },
    }


# ============================================================================================ settings


@page.card("settings", lazy=True)
async def settings_card(view: PageView) -> dict[str, Any]:
    """The explainer and the glossary (the template reads `glossary`) above the settings of `cache#settings`."""
    return {"explainer": explainer(view.ctx.settings), "terms": GLOSSARY_TERMS}


@page.card("coalescing", lazy=True)
async def coalescing_card(view: PageView) -> dict[str, Any]:
    """How many requests shared a fetch in the range, and this worker's single-flight counters."""
    answer = await _stats(view)
    cache = getattr(view.ctx, "cache", None)
    flights: dict[str, Any] = {}
    inflight = None
    if cache is not None:
        state = cache.state()
        flights = dict(state.get("Flights") or {})
        inflight = state.get("Inflight")
    return {
        "coalesced": (answer.get("states") or {}).get("cache_coalesced"),
        "enabled": bool(view.ctx.settings.bool("cache_coalesce")),
        "flights": flights,
        "inflight": inflight,
    }


# ============================================================================================ endpoints


@page.card("endpoints", lazy=True)
async def endpoints_card(view: PageView) -> dict[str, Any]:
    """Where the cache works, one row per endpoint template (v1 "Where the cache is working")."""
    tq, notice = table_query(view, cache_api.ENDPOINTS_SPEC, address=False)
    answer = await cache_api.endpoints_answer(view.ctx, view.tr, tq)

    def cells(item: Mapping[str, Any]) -> dict[str, Any]:
        rule = item.get("rule_id")
        requests = int(item.get("requests") or 0)
        ratio = item.get("hit_ratio")
        tone, words = None, None
        if isinstance(ratio, int | float) and requests >= 20:
            # v1's thresholds (dashboard.md 4.2), with words as well as color (plan 14.9).
            if ratio < 0.1:
                tone, words = "bad", "low for a busy endpoint"
            elif ratio >= 0.5:
                tone, words = "ok", "working well"
        ttl = item.get("ttl_s")
        return {
            "hit_ratio": {"text": f"{ratio * 100:.1f}%", "tone": tone, "sub": words}
            if isinstance(ratio, int | float)
            else None,
            "ttl_s": {"text": "never cached" if ttl == 0 else span_words(ttl), "tone": "warn" if ttl == 0 else None},
            "rule_id": {"text": f"#{rule}", "mono": True} if rule is not None else {"text": "default", "tone": "muted"},
        }

    table = table_view(
        view,
        ENDPOINTS_TABLE,
        cache_api.ENDPOINTS_SPEC,
        answer,
        src=view.fragment_url("endpoints"),
        key_columns=("key", "requests", "hit_ratio"),
        hidden=("cache_revalidating", "cache_coalesced", "cache_bytes_out", "upstream_calls"),
        cells=cells,
        row_id=lambda item: f"endpoint-{row_key(item.get('key'))}",
        drawer=lambda item: (
            "/admin/cache/drawer/endpoint?"
            + urlencode({**view.time.params, "template": str(item.get("key") or "")[:MAX_TEMPLATE_CHARS]})
        ),
        drawer_title=lambda item: "Endpoint",
        export_url=view.api_url("cache/endpoints"),
        caption="Where the cache is working",
        empty={
            "title": "No proxied requests in this range",
            "body": "Each endpoint callers ask for gets a row here once requests arrive. Try a longer range in the "
            "top bar.",
            "icon": "database",
        },
        search_placeholder="Search endpoints",
        notice=notice,
        address=False,
    )
    return {"table": table, "table_only": table_only(view, ENDPOINTS_TABLE)}


# ============================================================================================ rules


def _recommendation_rows(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for row in rows:
        try:
            payload = json.loads(row.get("payload_json") or "{}")
        except (TypeError, ValueError):
            payload = {}
        payload = payload if isinstance(payload, dict) else {}
        out.append(
            {
                "id": str(row.get("id") or ""),
                "rule_id": str(row.get("rule_id") or ""),
                "severity": str(row.get("severity") or "info"),
                "title": str(payload.get("title") or row.get("rule_id") or "Recommendation")[:300],
                "subject": str(payload.get("subject") or "")[:300],
                "href": "/admin/recommendations?" + urlencode({"rec": str(row.get("id") or "")}),
            }
        )
    return out


async def tuner_suggestions(ctx: Any) -> tuple[list[dict[str, Any]], int]:
    """Open recommendations of the cache family (the TTL tuner's lifetimes among them), most severe first."""
    wanted = read_recommendations.RecommendationFilter(states=("open",), rule_ids=CACHE_RULE_IDS)

    def read(conn: Any) -> tuple[list[dict[str, Any]], int]:
        return read_recommendations.list_page(conn, wanted, sort="severity", limit=SUGGESTION_LIMIT)

    try:
        rows, total = await ctx.dbs.metrics.read(read)
    except Exception:  # the suggestions degrade open, like the Overview's (plan P9); the rules still show
        return [], 0
    return _recommendation_rows(rows), int(total)


@page.card("rules", lazy=True)
async def rules_card(view: PageView) -> dict[str, Any]:
    """The cache rules (add, edit, remove), and the TTL tuner's open suggestions."""
    tq, notice = table_query(view, cache_api.RULES_SPEC, address=False)
    answer = await cache_api.rules_answer(view.ctx, tq)
    suggestions, suggestion_total = await tuner_suggestions(view.ctx)

    def cells(item: Mapping[str, Any]) -> dict[str, Any]:
        ttl = item.get("ttl")
        methods = item.get("methods") or []
        flags = item.get("normalize_flags") or []
        return {
            "id": {"text": f"#{item.get('id')}", "mono": True},
            "pattern": {"text": item.get("pattern"), "caller": True, "mono": True},
            "type": "Regex" if item.get("type") == "regex" else "Wildcard",
            "ttl": {"text": "never cache" if ttl == 0 else span_words(ttl), "tone": "warn" if ttl == 0 else None},
            "stale_ttl": span_words(item.get("stale_ttl")) if item.get("stale_ttl") else "none",
            "negative_ttl": span_words(item.get("negative_ttl")) if item.get("negative_ttl") else "none",
            "methods": ", ".join(str(m) for m in methods) or "GET",
            "normalize_flags": {"text": ", ".join(str(f) for f in flags), "caller": True} if flags else None,
            "note": {"text": item.get("note"), "caller": True} if item.get("note") else None,
            "enabled": {"text": "on", "tone": "ok"} if item.get("enabled") else {"text": "off", "tone": "muted"},
            "origin": RULE_ORIGINS.get(str(item.get("origin")), str(item.get("origin") or "")),
        }

    table = table_view(
        view,
        RULES_TABLE,
        cache_api.RULES_SPEC,
        answer,
        src=view.fragment_url("rules"),
        columns=RULE_COLUMN_ORDER,
        key_columns=("pattern", "ttl"),
        hidden=("stale_ttl", "negative_ttl", "normalize_flags", "origin", "created_at", "updated_at"),
        cells=cells,
        row_id=lambda item: f"cache-rule-{item.get('id')}",
        drawer=lambda item: "/admin/cache/drawer/rule?" + urlencode({"id": int(item.get("id") or 0)}),
        drawer_title=lambda item: f"Cache rule #{item.get('id')}",
        export_url=view.api_url("cache/rules", time=False),
        caption="Cache rules",
        empty={
            "title": "No cache rules",
            "body": "Every cacheable endpoint uses the default lifetime. Add a rule below to give one endpoint its own "
            "lifetime, or 0 to never cache it.",
            "icon": "database",
        },
        search_placeholder="Search patterns and notes",
        notice=notice,
        address=False,
    )
    return {
        "table": table,
        "table_only": table_only(view, RULES_TABLE),
        "default_ttl": answer.get("default_ttl_s"),
        "default_ttl_words": span_words(answer.get("default_ttl_s")),
        "new_rule_ttl": DEFAULT_CACHE_RULE_TTL,
        "suggestions": suggestions,
        "suggestion_total": suggestion_total,
        "tuner_on": bool(view.ctx.settings.bool("ttl_tuner_enabled")),
        "prefill": view.param("pattern", max_chars=common.MAX_SEARCH_CHARS) if view.in_fragment else "",
    }


# ============================================================================================ ignored parameters


@page.card("ignored-params", lazy=True)
async def ignored_params_card(view: PageView) -> dict[str, Any]:
    """Parameters left out of the cache key, with v1's suggestions and the key spread's suspects."""
    answer = await cache_api.ignored_params_answer(view.ctx)
    rows = []
    for item in answer.get("items") or ():
        name = str(item.get("name") or "")
        rows.append(
            {
                "name": name,
                "note": item.get("note") or "",
                "origin": RULE_ORIGINS.get(str(item.get("origin")), str(item.get("origin") or "")),
                "remove_url": f"{common.API_PREFIX}/cache/ignored-params/{_path_segment(name)}",
            }
        )
    return {
        "rows": rows,
        "total": answer.get("total") or 0,
        "cap": answer.get("cap") or MAX_CACHE_IGNORED_PARAMS,
        "suggestions": list(answer.get("suggestions") or ()),
        "suspects": list(answer.get("suspects") or ()),
    }


def _path_segment(name: str) -> str:
    """A parameter name as one URL path segment (percent-encoded; the API decodes it)."""
    return quote(name, safe="")


# ============================================================================================ key spread


@page.card("spread", lazy=True)
async def spread_card(view: PageView) -> dict[str, Any]:
    """v1's "Why isn't something being reused?": endpoints whose stored answers split on a changing parameter."""
    answer = await cache_api.spread_answer(view.ctx, SPREAD_LIMIT)
    groups = []
    for item in answer.get("items") or ():
        varying = list(item.get("varying") or ())[:4]
        groups.append(
            {
                **item,
                "varying": varying,
                "purge_pattern": str(item.get("path") or ""),
                "reused": int(item.get("hits") or 0) > 0,
            }
        )
    return {
        "groups": groups,
        "ignored": list(answer.get("ignored") or ()),
        "suggested": list(answer.get("suggested") or ()),
        "checked": fmt.local_time(view.now, view.tz),
    }


# ============================================================================================ browser


@page.card("browser")
async def browser_card(view: PageView) -> dict[str, Any]:
    """The stored answers: search, sort and page on the server (the page's main table), Purge matching."""
    tq, notice = table_query(view, cache_api.BROWSER_SPEC)
    answer = await cache_api.entries_answer(view.ctx, tq)

    def cells(item: Mapping[str, Any]) -> dict[str, Any]:
        state = str(item.get("state") or "")
        expires_in = int(item.get("expires_in_s") or 0)
        rule = item.get("rule_id")
        status = int(item.get("status") or 0)
        return {
            "key": {"text": item.get("key"), "caller": True, "mono": True, "limit": 160},
            "status": {"text": str(status), "tone": "ok" if 200 <= status < 300 else "warn", "mono": True},
            "state": {"text": STATE_WORDS.get(state, state), "tone": STATE_TONES.get(state)},
            "expires_at": {
                **(view.time_cell(item.get("expires_at")) or {"text": fmt.MISSING}),
                "sub": f"in {span_words(expires_in)}" if expires_in > 0 else "expired",
            },
            "rule_id": {"text": f"#{rule}", "mono": True} if rule is not None else {"text": "default", "tone": "muted"},
        }

    table = table_view(
        view,
        BROWSER_TABLE,
        cache_api.BROWSER_SPEC,
        answer,
        src=view.fragment_url("browser"),
        key_columns=("key", "hits", "state"),
        hidden=("last_hit_at", "rule_id"),
        cells=cells,
        row_id=lambda item: f"entry-{item.get('id')}",
        drawer=lambda item: "/admin/cache/drawer/entry?" + urlencode({"id": str(item.get("id") or "")}),
        drawer_title=lambda item: "Stored answer",
        caption="Stored answers",
        empty={
            "title": "No stored answer matches" if tq.q else "The cache is empty",
            "body": "Clear the search to see every stored answer."
            if tq.q
            else "Answers are stored as callers ask for cacheable endpoints; check the cache settings if this stays "
            "empty while traffic flows.",
            "icon": "database",
        },
        search_placeholder="Search stored answers",
        notice=notice,
    )
    return {
        "table": table,
        "table_only": table_only(view, BROWSER_TABLE),
        "card_src": view.fragment_url("browser", **table_state(tq, cache_api.BROWSER_SPEC)),
        "q": tq.q,
        "fresh": answer.get("fresh"),
        "total": answer.get("total"),
        "loaded": fmt.local_time(view.now, view.tz),
    }


# ============================================================================================ purge


@page.card("purge")
async def purge_card(view: PageView) -> dict[str, Any]:
    """Purge by host, rule, pattern, search, expired, or everything (the API audits each purge first)."""
    hosts = list(view.ctx.settings.get("allowed_roblox_hosts") or ())[:60]
    return {
        "scopes": [
            ("pattern", "Endpoint pattern"),
            ("host", "Host"),
            ("rule", "Cache rule id"),
            ("search", "Search text (as the browser matches it)"),
            ("expired", "Expired answers"),
        ],
        "hosts": [str(h) for h in hosts],
        "purge_url": f"{common.API_PREFIX}/cache/purge",
    }


# ============================================================================================ drawers

DrawerBuild = Callable[[PageView], Awaitable[dict[str, Any]]]


async def _render_drawer(request: Request, principal: Any, template: str, build: DrawerBuild) -> HTMLResponse:
    """Render a drawer body: `build(view)` returns its context; an API error shows its message in the drawer."""
    view = await page.view(request, principal)
    templates = templates_of(request)
    base = {"view": view, "tz": view.tz, "now": view.now, "time": view.time.view}
    try:
        context = await build(view)
    except Exception as exc:  # a drawer says what went wrong in place; it never turns into a 500
        mapped = exc if isinstance(exc, common.ApiError) else common.service_error(exc)
        if mapped is None:
            log.exception("cache_drawer_failed", extra={"fields": {"template": template}})
            message = "These details failed to load. The error is in the server log; try again shortly."
        else:
            details = "; ".join(str(text) for text in mapped.error_fields.values())
            message = f"{mapped.error_message} {details}".strip() if details else mapped.error_message
        context = {"error": message}
        template = DRAWER_ERROR_TEMPLATE
    return HTMLResponse(templates.render_to_string(request, template, {**base, **context}))


@page.router.get("/drawer/entry", include_in_schema=False)
async def entry_drawer(request: Request, principal: PageAdmin) -> HTMLResponse:
    """One stored answer: what it is, its lifetime and state, the body, and Refresh and Purge."""

    async def build(view: PageView) -> dict[str, Any]:
        entry_id = view.param("id", max_chars=64)
        found = await cache_api.entry_answer(view.ctx, entry_id)
        body = str(found.get("body") or "")
        pretty = body
        if "json" in str(found.get("content_type") or "").lower() or body[:1] in ("{", "["):
            try:
                pretty = json.dumps(json.loads(body), indent=2, ensure_ascii=False)
            except (TypeError, ValueError):
                pretty = body
        state = str(found.get("state") or "")
        refusal = None
        if found.get("negative") and int(found.get("status") or 0) == 429:
            refusal = "This row is a 429 marker, not an answer; it ends by itself when Roblox's cooldown does."
        elif str(found.get("auth_class") or "") == "cred":
            refusal = "Answers fetched with the credential are not refreshed from the dashboard (plan C1); purge it."
        return {
            "entry": found,
            "stored": view.time_cell(found.get("stored_at")),
            "expires": view.time_cell(found.get("expires_at")),
            "stale_until": view.time_cell(found.get("stale_until")),
            "last_hit": view.time_cell(found.get("last_hit_at")),
            "state_words": STATE_WORDS.get(state, state),
            "state_tone": STATE_TONES.get(state, "neutral"),
            "ttl_words": span_words(found.get("ttl")),
            "age_words": span_words(found.get("age_s")),
            "body_shown": pretty[:MAX_BODY_SHOWN],
            "body_cut": len(pretty) > MAX_BODY_SHOWN or bool(found.get("body_truncated")),
            "refresh_url": f"{common.API_PREFIX}/cache/entries/{found['id']}/refresh",
            "purge_url": f"{common.API_PREFIX}/cache/purge",
            "refresh_refusal": refusal,
        }

    return await _render_drawer(request, principal, "admin/pages/cache/drawer_entry.html", build)


@page.router.get("/drawer/endpoint", include_in_schema=False)
async def endpoint_drawer(request: Request, principal: PageAdmin) -> HTMLResponse:
    """One endpoint template: its numbers, the rule that applies, and "write a rule" and "purge its answers"."""

    async def build(view: PageView) -> dict[str, Any]:
        template = view.param("template", max_chars=MAX_TEMPLATE_CHARS)
        if not template:
            raise common.not_found("Choose an endpoint from the table.")
        tq = common.check_table_query(
            cache_api.ENDPOINTS_SPEC, page=1, page_size=10, sort=None, order=None, q=template[: common.MAX_SEARCH_CHARS]
        )
        answer = await cache_api.endpoints_answer(view.ctx, view.tr, tq)
        row = next((item for item in answer["items"] if str(item.get("key")) == template), None)
        rule = None
        if row is not None and row.get("rule_id") is not None:
            rule = await cache_api.rule_view(view.ctx, int(row["rule_id"]))
        pattern = template_pattern(template)
        return {
            "template": template,
            "row": row,
            "rule": rule,
            "pattern": pattern,
            "ttl_words": span_words((row or {}).get("ttl_s")),
            "new_rule_ttl": DEFAULT_CACHE_RULE_TTL,
            "rules_url": f"{common.API_PREFIX}/cache/rules",
            "purge_url": f"{common.API_PREFIX}/cache/purge",
            "endpoints_href": "/admin/endpoints?" + urlencode({"q": template}),
            "range_label": view.time.view.get("label"),
        }

    return await _render_drawer(request, principal, "admin/pages/cache/drawer_endpoint.html", build)


@page.router.get("/drawer/rule", include_in_schema=False)
async def rule_drawer(request: Request, principal: PageAdmin) -> HTMLResponse:
    """One cache rule: edit (PATCH) and remove (DELETE), both through the API, both purging what they affect."""

    async def build(view: PageView) -> dict[str, Any]:
        raw = view.param("id", max_chars=24)
        if not raw.isdigit() or not 1 <= int(raw) <= common.MAX_ROW_ID:
            raise common.not_found("Choose a rule from the table; that rule number is not valid.")
        rule = await cache_api.rule_view(view.ctx, int(raw))
        if rule is None:
            raise common.not_found("No cache rule has that id. It may have been removed.")
        return {
            "rule": rule,
            "rule_url": f"{common.API_PREFIX}/cache/rules/{int(rule['id'])}",
            "created": view.time_cell(rule.get("created_at")),
            "updated": view.time_cell(rule.get("updated_at")),
            "history_href": "/admin/audit?" + urlencode({"target": f"rules_cache:{int(rule['id'])}"}),
            "flags_text": "\n".join(str(f) for f in rule.get("normalize_flags") or ()),
        }

    return await _render_drawer(request, principal, "admin/pages/cache/drawer_rule.html", build)


__all__ = ["explainer", "page", "router", "span_words", "stats_reset"]
