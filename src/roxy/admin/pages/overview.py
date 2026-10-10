"""The Overview page (`/admin/overview`, also v1's `/admin/dashboard`; plan 14.1, 11.6, 13.1): Roxy at a glance.

What this is
    The first page an admin sees after signing in. Nine cards from the page registry, each the same numbers the
    Overview API answers (`roxy/admin/api/overview.py`), rendered on the server:
      * `status`: the status strip: proxy (running, paused, emergency limit), the credential's state (never its
        value), the rotator, the scheduler leader, the workers of this color and the running version.
      * `recommendations`: the three most severe open recommendations, read only (they open on the
        Recommendations page, where they are previewed and applied).
      * `kpis`: the plan 14.1 tiles (v1's eleven Overview tiles plus the plan 11.6 ones) with sparklines and the
        change against the comparison period; a tile whose data a reset touched shows its notice instead of a delta
        (plan 6.8).
      * `visitors`: human, crawler and unknown visitors, home and admin page visits, robots.txt and sitemap crawls.
      * `traffic`: caller requests against the calls Roxy made to Roblox, as a chart of the API series.
      * `outcomes`, `top-endpoints`, `top-places`: how requests ended and the busiest endpoint templates and
        experiences of the range (one read for the three cards).
      * `events`: recent notable events (bans, cooldowns, breakers, alerts, configuration changes) as a server-paged
        table, the page's main table, with CSV and JSON export through the API.
    The page header has the Check Proxy Health button (plan 13.1); it starts a run without the credential check
    and opens the run on the Health page (`static/js/pages/overview.js`).

Why it exists
    Plan 14.1 and 11.6: one page answers "is Roxy healthy, is Roblox still happy with it, and what needs me first".
    Plan P6: every number comes from the API's own builders (`build_status`, `build_kpis`, `build_visitors`,
    `build_breakdown`, `events_table`, `build_recommendations`), so the page and the API never disagree.

How it works
    `page = Page("overview")`, one `@page.card` renderer per registry card, each returning the context of
    `templates/admin/pages/overview/<card>.html`. Cards refresh themselves from the event stream (`kpi`,
    `recommendation`, `alert`, `settings_changed`) at most every 20 to 60 seconds, so an open Overview stays current
    without v1's polling. Caller-chosen text (endpoint templates, place ids, event details) is rendered by
    `format.html caller_text`; links built from data go through `local_href`.

What to read next
    `roxy/admin/api/overview.py`, `templates/admin/pages/overview.html`, `roxy/admin/pages/kit.py`,
    `roxy/admin/pages/health.py` (where the health button leads).
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, Final
from urllib.parse import quote, urlencode

from roxy.admin.api import overview as overview_api
from roxy.admin.pages import fmt
from roxy.admin.pages.kit import Page, PageView, table_query, table_view
from roxy.admin.pages.shell import COMPARE_LABELS
from roxy.storage.db import SharedStateUnavailable

log = logging.getLogger("roxy.admin.pages")

page = Page("overview", stream_events=("settings_changed", "recommendation", "alert", "kpi"))
router = page.router

EVENTS_TABLE_ID: Final = "overview-events"
EVENT_COLUMNS: Final = ("at_ms", "type", "severity", "reason", "endpoint_template", "detail")
EVENT_KEY_COLUMNS: Final = ("at_ms", "type", "severity")
MAX_DETAIL_CHARS: Final = 160

KPI_LINKS: Final[dict[str, str]] = {
    "requests": "/admin/traffic#requests",
    "requests_last_hour": "/admin/traffic#requests",
    "failures_last_hour": "/admin/upstream#failures",
    "avoided_pct": "/admin/cache#ratios",
    "avoided": "/admin/cache#ratios",
    "upstream_calls": "/admin/upstream#health",
    "roblox_429": "/admin/upstream#429-timeline",
    "roblox_429_per_10k": "/admin/upstream#429-timeline",
    "roxy_429": "/admin/protection#refusals",
    "status_5xx": "/admin/traffic#status",
    "roblox_5xx": "/admin/traffic#status",
    "status_2xx": "/admin/traffic#status",
    "status_4xx": "/admin/traffic#status",
    "p95_ms": "/admin/traffic#latency",
    "rotator_bytes_today": "/admin/egress#usage",
    "active_bans": "/admin/protection#bans",
    "service_uptime_s": "/admin/system#fleet",
    "served_cache": "/admin/cache#stats",
    "errors_hidden": "/admin/cache#stats",
}
"""Where each tile drills into (plan 14.5: "click to drill into the chart"); the page's time range goes along."""

VISITOR_LINKS: Final[dict[str, str]] = {
    "crawler_visitors": "/admin/security#crawls",
    "robots_crawls": "/admin/security#crawls",
    "sitemap_crawls": "/admin/security#crawls",
}

SEVERITY_TONES: Final[dict[str, str]] = {
    "critical": "bad",
    "error": "bad",
    "warn": "warn",
    "warning": "warn",
    "info": "info",
}
"""Event and recommendation severities as tones (the severity word is always shown beside the tone)."""

PROXY_STATES: Final[dict[str, tuple[str, str]]] = {
    "running": ("ok", "Running"),
    "paused": ("bad", "Paused"),
    "throttle_all": ("warn", "Emergency limit on"),
    "starting": ("info", "Starting"),
}
CREDENTIAL_STATES: Final[dict[str, tuple[str, str]]] = {
    "active": ("ok", "Working"),
    "unknown": ("info", "Not checked yet"),
    "cooling_down": ("warn", "Cooling down"),
    "rejected": ("bad", "Rejected by Roblox"),
    "unavailable": ("bad", "Unavailable"),
    "absent": ("neutral", "Not configured"),
    "disabled": ("neutral", "Switched off"),
    "not_built": ("neutral", "Not started"),
}
ROTATOR_REASONS: Final[dict[str, tuple[str, str]]] = {
    "rotator_not_configured": ("neutral", "Not configured"),
    "rotator_disabled": ("neutral", "Switched off"),
    "rotator_parked": ("warn", "Resting after errors"),
    "rotator_budget": ("warn", "Stopped by its budget"),
    "rotator_quota_hard_stop": ("warn", "Stopped by its quota"),
    "rotator_daily_cap": ("warn", "Daily cap reached"),
    "rotator_usage_unavailable": ("warn", "Usage unknown"),
    "invalid_url": ("bad", "URL not valid"),
    "encryption_key_missing": ("bad", "Key missing"),
    "ui_value_unreadable": ("bad", "Stored URL unreadable"),
    "not_built": ("neutral", "Not started"),
}
"""`RotatorPool.availability()` reasons in words (the reason code itself is Roxy's own vocabulary)."""


# ============================================================================================ helpers


def _href(path: str, view: PageView) -> str:
    """A link to another page that keeps this page's time range (`/admin/traffic?range=7d#requests`)."""
    base, _, anchor = path.partition("#")
    query = view.time.query()
    return base + (f"?{query}" if query else "") + (f"#{anchor}" if anchor else "")


def _iso_seconds(value: Any) -> float | None:
    """Epoch seconds of an ISO 8601 UTC text (`2026-10-10T12:00:00Z`, the recommendation payload's form)."""
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp()
    except ValueError:
        return None


def _seconds_text(value: Any) -> str:
    """`42 s`, `3 min 5 s`, `2 h 10 min` (a remaining time)."""
    if not isinstance(value, int | float) or value <= 0:
        return "0 s"
    total = int(round(value))
    if total < 60:
        return f"{total} s"
    if total < 3600:
        minutes, seconds = divmod(total, 60)
        return f"{minutes} min" + (f" {seconds} s" if seconds else "")
    hours, rest = divmod(total, 3600)
    return f"{hours} h" + (f" {rest // 60} min" if rest // 60 else "")


def compare_label(mode: Any) -> str:
    """`vs the previous period` (the tiles' delta words for the comparison in force)."""
    words = COMPARE_LABELS.get(str(mode or "previous")) or COMPARE_LABELS["previous"]
    return f"vs {words}"


# ============================================================================================ status


def status_items(status: Mapping[str, Any], view: PageView) -> list[dict[str, Any]]:
    """The status strip's items, each `{key, label, tone, state, detail, href}` (words always beside the tone)."""
    now = view.now
    proxy = status.get("proxy") or {}
    tone, words = PROXY_STATES.get(str(proxy.get("state")), ("info", "Unknown"))
    if proxy.get("state") == "paused":
        since = fmt.since_text(proxy.get("paused_since"), now, view.tz)
        drops = proxy.get("pause_drops")
        detail = f"Callers get the pause message{f' since {since}' if since else ''}."
        if isinstance(drops, int):
            detail += f" {drops:,} requests refused so far."
    elif proxy.get("state") == "throttle_all":
        since = fmt.since_text(proxy.get("throttle_all_since"), now, view.tz)
        drops = proxy.get("throttle_all_drops")
        detail = f"Every address is limited{f' since {since}' if since else ''}."
        if isinstance(drops, int):
            detail += f" {drops:,} requests refused so far."
    elif proxy.get("state") == "running":
        detail = "Serving callers normally."
    else:
        detail = "This worker is still starting; refresh in a moment."
    items = [
        {"key": "proxy", "label": "Proxy", "tone": tone, "state": words, "detail": detail, "href": None},
    ]

    credential = status.get("credential") or {}
    tone, words = CREDENTIAL_STATES.get(str(credential.get("status")), ("neutral", "Unknown"))
    remaining = credential.get("cooldown_remaining_s")
    if credential.get("status") == "cooling_down" and remaining:
        detail = f"Roblox rate-limited the account; calls resume in {_seconds_text(remaining)}."
    elif credential.get("problem"):
        detail = str(credential["problem"])
    elif credential.get("status") == "active":
        detail = "The one Roblox credential is usable (its value is never shown)."
    elif credential.get("status") == "absent":
        detail = "No credential is set; anonymous paths serve every caller."
    else:
        detail = "See the Credential page for its last probe."
    items.append(
        {
            "key": "credential",
            "label": "Credential",
            "tone": tone,
            "state": words,
            "detail": detail,
            "href": "/admin/credential#status",
        }
    )

    rotator = status.get("rotator") or {}
    if rotator.get("usable"):
        tone, words, detail = "ok", "Working", "Anonymous calls may use the DataImpulse rotator."
    else:
        reason = str(rotator.get("reason") or "")
        tone, words = ROTATOR_REASONS.get(reason, ("warn", "Not usable"))
        retry = rotator.get("retry_after_s")
        detail = "The direct path serves every call meanwhile."
        if isinstance(retry, int | float) and retry > 0:
            detail = f"Usable again in about {_seconds_text(retry)}; the direct path serves meanwhile."
        if not rotator.get("configured"):
            detail = "No rotator URL is configured; every call goes direct."
    items.append(
        {"key": "rotator", "label": "Rotator", "tone": tone, "state": words, "detail": detail, "href": "/admin/egress#rotator"}
    )

    lead = status.get("leader") or {}
    if lead.get("unavailable"):
        tone, words, detail = "warn", "Unknown", "The shared lease could not be read right now."
    elif lead.get("pid") is not None:
        mine = " (the worker serving this page)" if lead.get("this_worker") else ""
        tone, words = "ok", f"Worker {lead['pid']}"
        detail = f"Runs the scheduled jobs{mine}; epoch {lead.get('epoch')}."
    else:
        tone, words = "warn", "No leader"
        detail = "Scheduled jobs wait until a worker takes the lease (within about 15 s)."
    items.append(
        {"key": "leader", "label": "Leader", "tone": tone, "state": words, "detail": detail, "href": "/admin/system#leader"}
    )

    workers = status.get("workers") or {}
    fresh, expected = int(workers.get("fresh") or 0), int(workers.get("expected") or 0)
    tone = "ok" if fresh and fresh >= expected else ("warn" if fresh else "bad")
    color = str(workers.get("color") or "")
    detail = "Workers that sent a heartbeat in the last 30 seconds"
    detail += f" (color {color})." if color else "."
    items.append(
        {
            "key": "workers",
            "label": "Workers",
            "tone": tone,
            "state": f"{fresh} of {expected}" if expected else str(fresh),
            "detail": detail,
            "href": "/admin/system#fleet",
        }
    )

    version = status.get("version") or {}
    release = str(version.get("release") or "") or "Development build"
    items.append(
        {
            "key": "version",
            "label": "Version",
            "tone": "neutral",
            "state": release[:40],
            "detail": f"Configuration version {int(version.get('config_version') or 0):,}.",
            "href": "/admin/system#versions",
        }
    )
    return items


@page.card("status", refresh_on=("kpi", "settings_changed", "alert"), refresh_min_s=20)
async def status_card(view: PageView) -> dict[str, Any]:
    """The status strip (`build_status`, the API's own builder)."""
    status = await overview_api.build_status(view.ctx)
    return {"items": status_items(status, view)}


# ============================================================================================ recommendations


@page.card("recommendations", refresh_on=("recommendation",), refresh_min_s=10)
async def recommendations_card(view: PageView) -> dict[str, Any]:
    """The top three open recommendations (`build_recommendations`); read only, and degrading open (P9)."""
    notice = None
    try:
        found = await overview_api.build_recommendations(view.ctx)
    except (SharedStateUnavailable, sqlite3.Error) as exc:
        log.warning("overview_card_failed", extra={"fields": {"card": "recommendations", "error": str(exc)[:200]}})
        found = {"available": False, "items": [], "open": 0}
        notice = "The recommendations could not be read right now; try again shortly."
    items = []
    for item in found.get("items") or ():
        updated = _iso_seconds(item.get("updated_at"))
        rec_id = str(item.get("id") or "")
        items.append(
            {
                **item,
                "tone": SEVERITY_TONES.get(str(item.get("severity")), "neutral"),
                "age": fmt.ago(view.now - updated) if updated is not None else None,
                "href": f"/admin/recommendations?{urlencode({'rec': rec_id})}",
            }
        )
    return {
        "items": items,
        "open": int(found.get("open") or 0),
        "open_capped": bool(found.get("open_capped")),
        "available": bool(found.get("available")),
        "engine_on": bool(view.ctx.settings.bool("insights_enabled")),
        "interval_s": int(view.ctx.settings.int("insights_interval_s")),
        "notice": notice,
    }


# ============================================================================================ tiles


def display_tile(tile: Mapping[str, Any], href: str | None) -> dict[str, Any]:
    """A tile for `kpi_api`: a partial tile keeps its notice (shown instead of a delta, plan 6.8); any other notice
    is an explanation (a share, the v1 baseline) and is shown under the value, so the delta stays."""
    shown = dict(tile)
    note = None
    if not shown.get("partial"):
        note = shown.get("notice")
        shown["notice"] = None
    return {"tile": shown, "href": href, "note": note}


@page.card("kpis", refresh_on=("kpi",), refresh_min_s=60)
async def kpis_card(view: PageView) -> dict[str, Any]:
    """Every Overview tile (`build_kpis`), each linking to the page that explains it."""
    answer = await overview_api.build_kpis(view.ctx, view.tr)
    tiles = [
        display_tile(tile, _href(KPI_LINKS[tile["key"]], view) if tile["key"] in KPI_LINKS else None)
        for tile in answer["tiles"]
    ]
    return {
        "tiles": tiles,
        "compare_label": compare_label((answer.get("compare") or {}).get("mode")),
        "notices": list(answer.get("notices") or ()),
    }


@page.card("visitors")
async def visitors_card(view: PageView) -> dict[str, Any]:
    """The Visitors card (`build_visitors`, parity row 130)."""
    answer = await overview_api.build_visitors(view.ctx, view.tr)
    tiles = [
        display_tile(tile, _href(VISITOR_LINKS[tile["key"]], view) if tile["key"] in VISITOR_LINKS else None)
        for tile in answer["tiles"]
    ]
    return {"tiles": tiles, "compare_label": compare_label((answer.get("compare") or {}).get("mode"))}


# ============================================================================================ chart


@page.card("traffic")
async def traffic_card(view: PageView) -> dict[str, Any]:
    """Requests in against calls out: the chart reads `GET /overview/chart` (the API's series, notices included)."""
    return {
        "chart_src": view.api_url("overview/chart"),
        "range_label": str(view.time.view.get("label") or ""),
    }


# ============================================================================================ breakdown


async def _breakdown(view: PageView) -> dict[str, Any]:
    """`build_breakdown` once per page render: the outcome, endpoint and place cards share one read."""
    task = view.extra.get("breakdown")
    if task is None:
        task = asyncio.ensure_future(overview_api.build_breakdown(view.ctx, view.tr))
        view.extra["breakdown"] = task
    found: dict[str, Any] = await task
    return found


@page.card("outcomes")
async def outcomes_card(view: PageView) -> dict[str, Any]:
    """How requests ended in the range, with each outcome's share."""
    data = await _breakdown(view)
    outcomes = data["outcomes"]
    local = sum(int(item.get("answered_locally") or 0) for item in outcomes["items"])
    return {"total": int(outcomes["total"]), "items": outcomes["items"], "answered_locally": local}


def endpoint_href(template: Any) -> str:
    """The Endpoints page filtered to one template (its deep link, `?q=<template>`)."""
    return f"/admin/endpoints?q={quote(str(template)[:300], safe='')}"


@page.card("top-endpoints")
async def top_endpoints_card(view: PageView) -> dict[str, Any]:
    """The busiest endpoint templates of the range (caller-built text: shown as text)."""
    data = await _breakdown(view)
    rows = [{**row, "href": endpoint_href(row.get("key"))} for row in data["top_endpoints"]]
    return {"rows": rows, "all_href": _href("/admin/endpoints#table", view)}


@page.card("top-places")
async def top_places_card(view: PageView) -> dict[str, Any]:
    """The experiences (Roblox-Id) sending the most requests (the header is the caller's claim: shown as text)."""
    data = await _breakdown(view)
    return {"rows": data["top_places"], "all_href": _href("/admin/clients#places", view)}


# ============================================================================================ events


def _detail_text(detail: Any) -> str | None:
    if detail in (None, {}, []):
        return None
    try:
        return json.dumps(detail, sort_keys=True, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(detail)


@page.card("events")
async def events_card(view: PageView) -> dict[str, Any]:
    """Recent notable events (`events_table`, the API's own function): the page's main table."""
    tq, notice = table_query(view, overview_api.EVENTS_SPEC)
    answer = await overview_api.events_table(view.ctx, view.tr, tq)

    def cells(item: Mapping[str, Any]) -> dict[str, Any]:
        at_ms = item.get("at_ms")
        severity = str(item.get("severity") or "")
        detail = _detail_text(item.get("detail"))
        return {
            "at_ms": view.time_cell(at_ms / 1000) if isinstance(at_ms, int | float) else None,
            "type": {"text": item.get("type"), "mono": True},
            "severity": {"text": severity, "tone": SEVERITY_TONES.get(severity, "muted")} if severity else None,
            "reason": {"text": item.get("reason"), "mono": True} if item.get("reason") else None,
            "detail": {"text": detail, "caller": True, "limit": MAX_DETAIL_CHARS} if detail else None,
        }

    notices = [notice] if notice else []
    if answer.get("capped"):
        notices.append(
            "Only the newest events of this range are listed here; the Data page exports every event of the range."
        )
    table = table_view(
        view,
        EVENTS_TABLE_ID,
        overview_api.EVENTS_SPEC,
        answer,
        src=view.fragment_url("events"),
        columns=EVENT_COLUMNS,
        labels={"at_ms": "Time"},
        key_columns=EVENT_KEY_COLUMNS,
        cells=cells,
        row_id=lambda item: f"event-{item.get('id')}",
        drawer_title=lambda item: f"Event #{item.get('id')}",
        export_url=view.api_url("overview/events"),
        caption="Recent notable events",
        empty={
            "title": "No notable events in this range",
            "body": "Bans, Roblox cooldowns, open breakers, alerts and configuration changes are listed here as "
            "they happen. A quiet range is good news; choose a longer range in the top bar to look further back.",
            "icon": "flag",
            "tone": "good",
        },
        search_placeholder="Search events",
        notice=" ".join(notices) or None,
    )
    return {"table": table, "total": int(answer.get("total") or 0)}


__all__ = ["compare_label", "display_tile", "page", "router", "status_items"]
