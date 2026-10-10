"""The Egress page (`/admin/egress`, plan 14.1 and 8.5): bytes per egress path, the rotator's quota, health and exits.

What this is
    One card per registry card of page `egress` (DESIGN.md section 9 anchors):
      * `usage`: metered bytes and calls per egress (direct, credential and rotator byte totals) in the range, how
        the bytes are counted (on the wire or estimated, plan 8.3), and each egress's share of the calls over time.
      * `budget`: the plan 8.4 KPI tiles (used this cycle, projected, remaining, cost so far), the projection
        sentence with its 90 percent band, the daily bars of the cycle with the quota and an even pace, the hard
        stop and daily cap, and the provider's own figure (EGR-CALIBRATE input, `POST /egress/provider-report`).
      * `rotator`: v1's "Rotate (IP rotation)" health tile (state in words, calls, failures, timeouts, last success
        and error; parity row 34 "Egress > Rotator health"), the gateway URL masked (never the URL, plan 8.2, parity
        rows 30 and 33), replacing it (fresh second factor) and going back to the bootstrap value.
      * `exit-ips`: v1's Rotation Exit IPs (plan 14.1 row 36, parity row 32): this worker's recent exit addresses,
        masked to /24 (/48), "Verify rotation now", and an audited reveal.
      * `sessions`: session mode, open sessions on this worker, the fleet-wide park and failure streak, and the
        calls, 429s and failures per exit (a hash of a session, never an address).
      * `top-endpoints`: endpoints by metered bytes on one egress (the page's main table) and how many calls fell in
        each size slot.
      * `trips`: what the leak guard stopped (plan C2 item 4), and re-enabling an egress (fresh second factor and a
        reason).
    The `egress#rotator` and `egress#budget` settings (plan 15.6) are edited inline by the kit's settings block.

Why it exists
    Every rotator byte costs money and the plan has a monthly quota, a hard stop and a projection (8.4); the owner
    must see that the rotator works without the exit addresses being shown by default (privacy, row 32). Plan P6:
    every number comes from the function the admin API answers with (`roxy/admin/api/egress.py usage_answer`,
    `budget_answer`, `sessions_answer`, ...; `rotator.py state_view`; `upstream.py egress_cards_answer` for the
    rotator's call health). The page changes nothing itself: forms and buttons go to the admin API.

How it works
    `page = Page("egress")`; each `@page.card` returns the context of `templates/admin/pages/egress/<card>.html`.
    Settings-heavy cards are deferred (`_upstream_common.deferred`: they load as their own fragment right after the
    page). Bytes are decimal (1 GB = 10^9 bytes, the provider's unit). Endpoint templates are caller text.

What to read next
    `templates/admin/pages/egress.html`, `roxy/admin/api/egress.py`, `roxy/egress/read_state.py`,
    `static/js/pages/egress.js`.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, Final

from roxy.admin.api import common
from roxy.admin.api import egress as egress_api
from roxy.admin.api import rotator as rotator_api
from roxy.admin.api import upstream as upstream_api
from roxy.admin.pages._upstream_common import (
    DEFERRED,
    EGRESS_ABOUT,
    EGRESS_LABELS,
    decimal_bytes,
    deferred,
    egress_state,
    pct_text,
    precision_words,
    reason_words,
)
from roxy.admin.pages.kit import Page, PageView, filter_chip, table_query, table_view

page = Page("egress")
router = page.router

API: Final = common.API_PREFIX
EGRESS_OPTIONS: Final[tuple[tuple[str, str], ...]] = (
    ("rotator", "Rotator"),
    ("direct", "Direct"),
    ("credential", "Credential"),
)
METERING_WORDS: Final[dict[str, str]] = {
    "socket": "counted on the wire, below TLS (exact for the rotator, plan 8.3)",
    "estimate": "estimated from request and answer sizes plus a TLS allowance per connection (the fallback of "
    "plan 8.3)",
}
SOURCE_WORDS: Final[dict[str, str]] = {
    "ui": "set from this page",
    "bootstrap": "the systemd credential rotator_url",
    "test_override": "a development override",
}
MODE_WORDS: Final[dict[str, str]] = {
    "per_request": "a new exit for every call",
    "sticky": "one exit per session for a while",
    "sticky_until_429": "one exit per session until it gets a 429",
}
STOP_WORDS: Final[dict[str, str]] = {
    "rotator_quota_hard_stop": "the monthly hard stop was reached; only direct is used until the next cycle",
    "rotator_daily_cap": "the daily byte cap was reached; the rotator rests until midnight UTC",
}
SHARE_PREFIX: Final = "calls:"


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def _seconds_from_ms(value: Any) -> float | None:
    number = _number(value)
    return number / 1000 if number is not None else None


# ============================================================================================ usage


@page.card("usage")
async def usage_card(view: PageView) -> dict[str, Any]:
    """Bytes and calls per egress (`usage_answer`) and the calls per egress over time (`share_answer`)."""
    answer = await egress_api.usage_answer(view.ctx, view.tr)
    share = await egress_api.share_answer(view.ctx, view.tr)
    calls_only = {**share, "series": [s for s in share.get("series") or () if str(s["key"]).startswith(SHARE_PREFIX)]}
    total_calls = sum(int(item.get("calls") or 0) for item in answer["items"])
    items = []
    for item in answer["items"]:
        name = str(item["egress"])
        calls = int(item.get("calls") or 0)
        items.append(
            {
                **item,
                "label": EGRESS_LABELS.get(name, name),
                "about": EGRESS_ABOUT.get(name, ""),
                "bytes_text": decimal_bytes(item.get("bytes")),
                "per_call_text": decimal_bytes(item.get("bytes_per_call")),
                "share_text": pct_text(calls * 100.0 / total_calls) if total_calls else "n/a",
                "state": "On" if item.get("enabled") else "Off",
                "state_detail": None
                if item.get("enabled")
                else f"Not in use: {reason_words(item.get('disabled_reason'))}.",
                "tone": "ok" if item.get("enabled") else "neutral",
            }
        )
    mode = str(answer.get("metering_mode") or "")
    return {
        "items": items,
        "share": calls_only,
        "metering": METERING_WORDS.get(mode, mode or "n/a"),
        "estimate": mode == "estimate",
    }


# ============================================================================================ budget


def _daily_series(daily: Mapping[str, Any]) -> dict[str, Any]:
    """The `GET /egress/rotator/daily` answer as a series answer the chart component draws (same numbers)."""
    days: Sequence[Mapping[str, Any]] = daily.get("days") or ()
    starts = [int(day["start"]) for day in days]
    series = [
        common.series_entry(
            "bytes", "Bytes that day", "bytes", [[s, d["bytes"]] for s, d in zip(starts, days, strict=True)]
        ),
        common.series_entry(
            "cumulative",
            "Used so far",
            "bytes",
            [[s, d["cumulative_bytes"]] for s, d in zip(starts, days, strict=True)],
        ),
    ]
    if any(day.get("even_pace_bytes") is not None for day in days):
        series.append(
            common.series_entry(
                "even_pace",
                "Even pace to the quota",
                "bytes",
                [[s, d.get("even_pace_bytes")] for s, d in zip(starts, days, strict=True)],
            )
        )
    cycle = daily.get("cycle") or {}
    return {
        "range": {"from": cycle.get("start"), "to": cycle.get("end"), "granularity": "day", "tz": "UTC"},
        "series": series,
        "compare": None,
        "annotations": [],
        "notices": [],
    }


def _utc_day(ts: Any) -> str:
    """`Oct 1, 2026`: a billing cycle boundary, a UTC day (the provider's clock and the rotator's hard stop)."""
    number = _number(ts)
    if number is None:
        return "n/a"
    moment = datetime.fromtimestamp(number, UTC)
    return f"{moment:%b} {moment.day}, {moment.year}"


def _budget_tile(tile: Mapping[str, Any]) -> dict[str, Any]:
    """A budget KPI tile with its value in the provider's units: decimal bytes, and US dollars."""
    value = tile.get("value")
    if tile.get("unit") == "bytes":
        return {"tile": tile, "display": decimal_bytes(value) if value is not None else None}
    if tile.get("unit") == "usd":
        number = _number(value)
        shown = f"{number:,.2f} USD" if number is not None else None
        return {"tile": {**tile, "unit": ""}, "display": shown}
    return {"tile": tile, "display": None}


@page.card("budget")
async def budget_card(view: PageView) -> dict[str, Any]:
    """The plan 8.4 tiles and projection (`budget_answer`), the daily bars (`daily_answer`) and the provider's
    figure (`provider_view`): the API's own functions."""
    answer = await egress_api.budget_answer(view.ctx)
    daily = await egress_api.daily_answer(view.ctx)
    provider = await egress_api.provider_view(view.ctx)
    projection = answer.get("projection") or {}
    cycle = answer.get("cycle") or {}
    latest = provider.get("latest") or None
    band = None
    if projection.get("low_bytes") is not None and int(projection.get("high_bytes") or 0) > 0:
        band = f"{decimal_bytes(projection['low_bytes'])} to {decimal_bytes(projection['high_bytes'])}"
    days_left = _number(projection.get("days_left"))
    return {
        "tiles": [_budget_tile(tile) for tile in answer.get("tiles") or ()],
        "sentence": projection.get("sentence") or "",
        "band": band,
        "band_reason": projection.get("band_reason"),
        # The cycle ends at the start of the next one (exclusive): its last day is the day before.
        "cycle_text": f"{_utc_day(cycle.get('start'))} to {_utc_day((_number(cycle.get('end')) or 1) - 1)}",
        "days_left": f"{days_left:,.1f} days left" if days_left is not None else "",
        "today": decimal_bytes(cycle.get("today_bytes")),
        "quota": decimal_bytes(answer.get("quota_bytes")) if answer.get("quota_bytes") else None,
        "hard_stop": decimal_bytes(answer.get("hard_stop_bytes")) if answer.get("hard_stop_bytes") else None,
        "daily_cap": decimal_bytes(answer.get("daily_cap_bytes")) if answer.get("daily_cap_bytes") else None,
        "stopped": bool(answer.get("stopped")),
        "stop_words": STOP_WORDS.get(str(answer.get("stop_reason") or ""), reason_words(answer.get("stop_reason"))),
        "daily": _daily_series(daily),
        "has_days": any(int(day.get("bytes") or 0) for day in daily.get("days") or ()),
        "provider": provider,
        "provider_latest": latest,
        "provider_when": view.time_cell(latest.get("at")) if isinstance(latest, Mapping) else None,
        "provider_reported": decimal_bytes(latest.get("reported_bytes")) if isinstance(latest, Mapping) else None,
        "metered": decimal_bytes(provider.get("metered_bytes")),
        "diff": pct_text(provider.get("diff_pct")) if provider.get("diff_pct") is not None else None,
        "provider_url": f"{API}/egress/provider-report",
    }


# ============================================================================================ rotator


@page.card("rotator")
async def rotator_card(view: PageView) -> dict[str, Any]:
    """v1's Rotate tile and the gateway URL (masked): `rotator.state_view`, `sessions_answer` and the rotator's
    health card from `upstream.egress_cards_answer` (the API's own functions)."""
    if deferred(view):
        return DEFERRED
    state = await rotator_api.state_view(view.ctx)
    sessions = await egress_api.sessions_answer(view.ctx, view.tr)
    cards = await upstream_api.egress_cards_answer(view.ctx, view.tr)
    rotator: dict[str, Any] = next((item for item in cards["items"] if item.get("egress") == "rotator"), {})
    tone, words, detail = egress_state(rotator) if rotator else ("neutral", "n/a", "")
    if not state.get("configured"):
        tone, words, detail = "neutral", "Not configured", "No rotator URL is set, so every call goes direct."
    elif (sessions.get("health") or {}).get("parked"):
        tone, words, detail = "warn", "Parked", "Parked after a failure streak; it is tried again when the park ends."
    ui_value = state.get("ui_value") or None
    return {
        "state": state,
        "tone": tone,
        "words": words,
        "state_detail": detail,
        "rotator": rotator,
        "last_success": view.time_cell(rotator.get("last_success_at")),
        "last_success_precision": precision_words(rotator.get("last_success_precision")),
        "last_error_at": view.time_cell(rotator.get("last_error_at")),
        "source_words": SOURCE_WORDS.get(str(state.get("source") or ""), "none"),
        "ui_set": view.time_cell(ui_value.get("set_at")) if isinstance(ui_value, Mapping) else None,
        "ui_by": ui_value.get("set_by") if isinstance(ui_value, Mapping) else None,
        "mode_words": MODE_WORDS.get(str(state.get("mode") or ""), str(state.get("mode") or "")),
        "sessions": sessions,
        "url_api": f"{API}/rotator/url",
    }


# ============================================================================================ exit IPs and sessions


@page.card("exit-ips")
async def exit_ips_card(view: PageView) -> dict[str, Any]:
    """v1's Rotation Exit IPs: this worker's recent exits, masked (`exit_ips_view` over the pool, as the API's
    masked answer). The reveal is the API's audited route, asked by the page's script."""
    if deferred(view):
        return DEFERRED
    pool = egress_api.egress_of(view.ctx).rotator
    answer = egress_api.exit_ips_view(pool.recent_exit_ips(masked=True), masked=True)
    items = [
        {
            "ip": str(item.get("ip") or ""),
            "source": str(item.get("source") or ""),
            "when": view.time_cell(item.get("at")),
        }
        for item in answer["items"]
    ]
    return {
        "items": items,
        "note": answer["note"],
        "configured": bool(pool.configured()),
        "probe_url": f"{API}/egress/rotator/probe",
        "reveal_url": f"{API}/egress/exit-ips?reveal=true",
    }


@page.card("sessions")
async def sessions_card(view: PageView) -> dict[str, Any]:
    """Session mode, open sessions, the fleet-wide park and streak, and the calls per exit (`sessions_answer`)."""
    if deferred(view):
        return DEFERRED
    answer = await egress_api.sessions_answer(view.ctx, view.tr)
    health = answer.get("health") or {}
    exits = [
        {
            **item,
            "rate": pct_text(item.get("rate_429_pct")),
            "first": view.time_cell(item.get("first_seen")),
            "last": view.time_cell(item.get("last_seen")),
        }
        for item in answer.get("exits") or ()
    ]
    return {
        "answer": answer,
        "health": health,
        "parked_until": view.time_cell(_seconds_from_ms(health.get("parked_until_ms"))),
        "last_failure": view.time_cell(health.get("last_failure_at")),
        "mode_words": MODE_WORDS.get(str(answer.get("mode") or ""), str(answer.get("mode") or "")),
        "effective_words": MODE_WORDS.get(str(answer.get("effective_mode") or ""), str(answer.get("effective_mode"))),
        "unavailable": reason_words(answer.get("unavailable_reason")) if answer.get("unavailable_reason") else None,
        "exits": exits,
    }


# ============================================================================================ top endpoints


def _top_cells(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "template": {"text": item.get("template"), "caller": True, "mono": True},
        "bytes": decimal_bytes(item.get("bytes")),
        "bytes_per_call": decimal_bytes(item.get("bytes_per_call")),
        "bytes_in": decimal_bytes(item.get("bytes_in")),
        "bytes_out": decimal_bytes(item.get("bytes_out")),
        "share_pct": pct_text(item.get("share_pct")),
    }


@page.card("top-endpoints")
async def top_endpoints_card(view: PageView) -> dict[str, Any]:
    """Endpoints by metered bytes on one egress (`top_endpoint_rows`, the page's main table) and the bytes per
    call distribution (`bytes_per_request_answer`): the API's own functions."""
    tq, notice = table_query(view, egress_api.TOP_SPEC)
    chosen = view.state_param("egress", "rotator", max_chars=16)
    egress = chosen if chosen in egress_api.EGRESSES else "rotator"
    rows, total_bytes = await egress_api.top_endpoint_rows(view.ctx, view.tr, egress)
    answer = egress_api.top_endpoints_answer(rows, total_bytes, tq, view.tr, egress)
    table = table_view(
        view,
        "egress-top-endpoints",
        egress_api.TOP_SPEC,
        answer,
        src=view.fragment_url("top-endpoints"),
        key_columns=("template", "bytes", "share_pct"),
        hidden=("bytes_in", "bytes_out"),
        cells=_top_cells,
        row_id=lambda item: f"bytes-{item.get('template')}",
        drawer_title=lambda item: f"Endpoint {item.get('template')}",
        filters=[filter_chip("egress", "Egress", egress, EGRESS_OPTIONS)],
        export_url=f"{API}/egress/top-endpoints",
        caption="Endpoints by bytes",
        empty={
            "title": f"No {EGRESS_LABELS.get(egress, egress).lower()} bytes in this range",
            "body": "An endpoint appears here once a call through this egress is metered. The rotator is off by "
            "default (rotator_weight 0), so its list stays empty until it carries traffic.",
            "icon": "globe",
        },
        search_placeholder="Search endpoints",
        notice=notice,
    )
    histogram = await egress_api.bytes_per_request_answer(view.ctx, view.tr, egress)
    slots = [
        {
            "label": f"{decimal_bytes(slot['from_bytes'])} to {decimal_bytes(slot['to_bytes'])}"
            if slot.get("to_bytes") is not None
            else f"{decimal_bytes(slot['from_bytes'])} or more",
            "calls": int(slot.get("calls") or 0),
        }
        for slot in histogram.get("slots") or ()
    ]
    return {
        "table": table,
        "egress_label": EGRESS_LABELS.get(egress, egress),
        "total": decimal_bytes(total_bytes),
        "slots": slots,
        "slot_calls": int(histogram.get("calls") or 0),
        "basis": str(histogram.get("basis") or "").capitalize(),
    }


# ============================================================================================ leak guard


@page.card("trips")
async def trips_card(view: PageView) -> dict[str, Any]:
    """What the leak guard stopped (`trips_answer`) and this worker's guard counters, with the re-enable form."""
    answer = await egress_api.trips_answer(view.ctx)
    stats = egress_api.egress_of(view.ctx).stats().get("guard") or {}
    items = [
        {
            **item,
            "label": EGRESS_LABELS.get(str(item.get("egress")), str(item.get("egress"))),
            "since_cell": view.time_cell(item.get("since")),
            "enable_url": f"{API}/egress/{item.get('egress')}/enable",
        }
        for item in answer.get("items") or ()
        if item.get("egress") in ("direct", "rotator")
    ]
    guard = [
        {
            "label": EGRESS_LABELS.get(str(name), str(name)),
            "inspected": int(row.get("inspected") or 0),
            "leak_trips": int(row.get("leak_trips") or 0),
            "smuggling": int(row.get("smuggling_refusals") or 0),
        }
        for name, row in sorted(stats.items())
        if isinstance(row, Mapping)
    ]
    return {"items": items, "guard": guard, "runbook": answer.get("runbook") or ""}


__all__ = ["page", "router"]
