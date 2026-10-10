"""The Traffic page (`/admin/traffic`, plan 14.1 Traffic row, 14.2, 14.3; v1 sections Traffic, Requests, Status
Codes and Proxy Timings).

What this is
    Seven cards, each reading the same answer as its admin API route (`roxy/admin/api/traffic.py`):
      * `requests`: requests over time stacked by outcome (served by Roblox, from the cache, refused, failed) with
        the totals of the range above it; v1's "Traffic (Last 60 Minutes)" is this chart with the range "1h" (row 7).
        The card's reset button clears the traffic family (plan 6.8, v1's Clear data on these sections).
      * `bytes`: bytes between callers and Roxy and between Roxy and Roblox over time (plan 14.3 definitions), the
        range totals and the wire bytes per egress.
      * `verbs`: requests per HTTP method over time, the method mix, and the "Counts by Method" table (row 20).
      * `status`: v1's four tiles (429s and 5xx from Roblox and from Roxy, row 3), the "Who returned it?" verdict and
        table (rows 21, 68, 132), and status classes over time, or by who returned them.
      * `latency`: p50, p95 and p99 over time, or the p95 split per verb, egress, host or outcome (v1's split toggle,
        row 23 and parity row 131), with the split as a table; its reset button clears only the latency histograms.
      * `heatmap`: hour of day by weekday, a real table that doubles as the accessible alternative (plan 14.5).
      * `trends`: week over week, month over month and year over year tables with sparklines (plan 14.3).

Why it exists
    v1 drew the last 60 minutes and kept everything else as lifetime counters. v2 answers "when?" for every number
    over any range, compares periods, and keeps the source split that tells "Roblox is rate limiting Roxy" (act
    now) from "Roxy is rate limiting callers" (the system working). Plan P6: every number here comes from the
    API's own functions (`requests_answer`, `status_sources_answer`, ...), never from a second query.

How it works
    `page = Page("traffic")`. The requests card is part of the first paint, its series embedded in the page (no
    request after load); the other cards are lazy and load when scrolled into view, each with its series
    embedded in its fragment. A card's controls (the status view, the latency split, the heatmap measure) are
    small forms that ask the card's own fragment again with htmx. Tables are second tables of the page
    (`address=False`) and ask `?part=table` of their card, which answers the table alone. Caller text never
    reaches these cards except as escaped text (the hosts of the latency split are allowlisted names).

What to read next
    `roxy/admin/api/traffic.py`, `templates/admin/pages/traffic.html` and `traffic/*.html`,
    `roxy/admin/pages/_traffic_reset.py` (the inline resets), `roxy/metrics/queries.py` (`series`, `top_n`).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, Final

from roxy.admin.api import traffic as traffic_api
from roxy.admin.pages import fmt
from roxy.admin.pages._traffic_reset import add_reset_route, family_reset, reset_href
from roxy.admin.pages.kit import Page, PageView, table_query, table_view
from roxy.metrics.catalog import METRICS
from roxy.metrics.rollups import zone

page = Page("traffic")
router = page.router

OUTCOMES: Final[tuple[tuple[str, str, int], ...]] = (
    ("served_upstream", "Served by Roblox", 1),
    ("served_cache", "Served from the cache", 3),
    ("refused", "Refused by Roxy", 4),
    ("failed", "Failed", 8),
)
"""The outcome groups of the requests chart: key, words, series color slot (tokens `--series-N`)."""

SOURCE_COLORS: Final[dict[str, int]] = {"roblox": 1, "relay": 7, "roxy": 4, "cache": 3, "internal": 6}
STATUS_LABELS: Final[dict[str, tuple[str, int]]] = {
    "status_2xx": ("2xx answers", 6),
    "status_4xx": ("4xx answers", 4),
    "status_5xx": ("5xx answers", 8),
    "roxy_429": ("429s from Roxy", 2),
    "roblox_429": ("429s from Roblox", 5),
}
STATUS_VIEWS: Final[tuple[tuple[str, str], ...]] = (
    ("class", "By status class"),
    ("source", "By who returned it"),
)
LATENCY_SPLITS: Final[tuple[tuple[str, str], ...]] = (
    ("none", "No split: p50, p95 and p99"),
    ("method", "By verb (HTTP method)"),
    ("outcome", "By outcome (successes and failures)"),
    ("egress", "By egress path"),
    ("host", "By Roblox host"),
)
"""The latency card's split choices (row 131): v1's "Split successes / failures" is the outcome split."""

WEEKDAY_NAMES: Final[tuple[str, ...]] = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
EGRESS_WORDS: Final[dict[str, str]] = {
    "direct": "Direct (the server's own address)",
    "credential": "Credential (direct, with the Roblox account)",
    "rotator": "Rotator (DataImpulse, paid per byte)",
}
TILES: Final[tuple[tuple[str, str], ...]] = (
    ("roblox_429", "Roblox rate limiting Roxy"),
    ("roxy_429", "Roxy turning callers away"),
    ("roblox_5xx", "Roblox's own server errors"),
    ("roxy_5xx", "Roxy's own failures"),
)
"""v1's four "Who returned it?" tiles (dashboard.md 4.16) with their meta lines, in v1's order."""
VERDICT_TITLES: Final[dict[str, str]] = {
    "bad": "Roblox is rate limiting Roxy",
    "ok": "Only Roxy's own limits answered 429",
    "info": "No rate limiting in this range",
}
"""The heading of v1's verdict (the API's `verdict.text` is its body)."""


# ============================================================================================ helpers


def _series_sum(series: Mapping[str, Any]) -> float:
    return float(sum(v for _t, v in series.get("points") or () if isinstance(v, int | float)))


def group_totals(answer: Mapping[str, Any]) -> dict[str, float]:
    """`{group: total}` of a grouped series answer (`requests:served_cache` -> `served_cache`), summed from the
    chart's own points, so the numbers above a chart always add up to the chart."""
    out: dict[str, float] = {}
    for series in answer.get("series") or ():
        key = str(series.get("key") or "")
        out[key.partition(":")[2] or key] = _series_sum(series)
    return out


def share(part: float, whole: float) -> float | None:
    return round(part * 100.0 / whole, 1) if whole else None


def table_only(view: PageView) -> bool:
    """A table's own request (`?part=table` of the card's fragment): the card answers the table alone."""
    return view.in_fragment and view.param("part", max_chars=8) == "table"


def choice(view: PageView, name: str, options: Sequence[tuple[str, str]], default: str) -> str:
    """A card control's value from the query, or `default` when it is missing or not one of `options`."""
    value = view.param(name, max_chars=32)
    return value if value in {key for key, _label in options} else default


def status_tone(status: Any) -> str:
    """The tone of an HTTP status as the table shows it (words come with it: the code itself)."""
    code = int(status or 0)
    if code >= 500:
        return "bad"
    if code >= 400:
        return "warn"
    if code >= 300:
        return "muted"
    return "ok"


def ms_text(value: Any) -> str:
    if not isinstance(value, int | float):
        return fmt.MISSING
    return f"{value:,.0f} ms" if value >= 10 else f"{value:,.1f} ms"


def _day(ts: Any, tz: str) -> str:
    if not isinstance(ts, int | float) or ts <= 0:
        return fmt.MISSING
    moment = datetime.fromtimestamp(float(ts), zone(tz))
    return f"{moment.strftime('%b')} {moment.day}, {moment.year}"


# ============================================================================================ requests


@page.card("requests")
async def requests_card(view: PageView) -> dict[str, Any]:
    """Requests over time by outcome and the range totals (`traffic_api.requests_answer`)."""
    answer = await traffic_api.requests_answer(view.ctx, view.tr)
    totals = group_totals(answer)
    total = sum(totals.values())
    stats: list[dict[str, Any]] = [
        {
            "key": "requests",
            "label": "Requests",
            "value": total,
            "share": None,
            "help": METRICS["requests"].description,
        }
    ]
    for key, label, _slot in OUTCOMES:
        value = totals.get(key, 0.0)
        stats.append(
            {"key": key, "label": label, "value": value, "share": share(value, total), "help": METRICS[key].description}
        )
    words = ", ".join(f"{int(s['value']):,} {s['label'].lower()}" for s in stats[1:])
    summary = (
        f"Requests by outcome, {view.time.view['description']}: {int(total):,} requests in all ({words})."
        if total
        else f"No requests were recorded in this range ({view.time.view['description']})."
    )
    return {
        "answer": answer,
        "stats": stats,
        "summary": summary,
        "series_options": {f"requests:{key}": {"label": label, "color": slot} for key, label, slot in OUTCOMES},
        "reset_href": reset_href("traffic", which="traffic"),
        "last_hour_href": "/admin/traffic?range=1h",
        "range_label": view.time.view["label"],
    }


# ============================================================================================ bytes


@page.card("bytes", lazy=True)
async def bytes_card(view: PageView) -> dict[str, Any]:
    """Caller and upstream bytes over time, the range totals and the wire bytes per egress."""
    answer = await traffic_api.bytes_answer(view.ctx, view.tr)
    totals = [
        {
            "key": metric,
            "label": METRICS[metric].label,
            "value": (answer.get("totals") or {}).get(metric),
            "help": METRICS[metric].description,
        }
        for metric in traffic_api.BYTE_METRICS
    ]
    by_egress = [
        {"key": str(name), "label": EGRESS_WORDS.get(str(name), str(name)), "value": int(value or 0)}
        for name, value in sorted((answer.get("by_egress") or {}).items())
    ]
    empty = not any(isinstance(t["value"], int | float) and t["value"] > 0 for t in totals)
    return {"answer": answer, "totals": totals, "by_egress": by_egress, "empty": empty}


# ============================================================================================ verbs


VERB_KEY_COLUMNS: Final = ("key", "requests", "failed")
VERB_HIDDEN: Final = ("status_2xx", "status_4xx", "status_5xx")


@page.card("verbs", lazy=True)
async def verbs_card(view: PageView) -> dict[str, Any]:
    """Requests per method over time, the method mix and the counts by method (`traffic_api.dimension_table`)."""
    spec = traffic_api.VERBS_SPEC
    tq, notice = table_query(view, spec, address=False)
    found = await traffic_api.dimension_table(view.ctx, spec, "method", view.tr, tq)
    table = table_view(
        view,
        "traffic-verbs",
        spec,
        found,
        src=view.fragment_url("verbs", part="table"),
        key_columns=VERB_KEY_COLUMNS,
        hidden=VERB_HIDDEN,
        cells=lambda item: {"key": {"text": item.get("key"), "mono": True}, "p95_ms": ms_text(item.get("p95_ms"))},
        export_url=view.api_url("traffic/verbs/table"),
        caption="Counts by method",
        empty={
            "title": "No requests in this range",
            "body": "Each HTTP method callers use gets a row here as soon as Roxy handles a request with it.",
            "icon": "activity",
        },
        search_placeholder="Search methods",
        notice=notice,
        address=False,
    )
    if table_only(view):
        return {"part": "table", "table": table}
    answer = await traffic_api.verbs_answer(view.ctx, view.tr)
    totals = group_totals(answer)
    whole = sum(totals.values())
    mix = [
        {"method": name if name != "all" else "Any", "value": value, "share": share(value, whole) or 0.0}
        for name, value in sorted(totals.items(), key=lambda kv: (-kv[1], kv[0]))
        if value > 0
    ]
    items = list(found.get("items") or ())
    complete = int(found.get("total") or 0) <= len(items) and not tq.q
    outcome_split = None
    if complete and items:
        served = sum(int(i.get("served_upstream") or 0) + int(i.get("served_cache") or 0) for i in items)
        refused = sum(int(i.get("refused") or 0) for i in items)
        failed = sum(int(i.get("failed") or 0) for i in items)
        every = served + refused + failed
        outcome_split = [
            {"label": "Answered", "value": served, "share": share(served, every) or 0.0, "tone": "ok"},
            {"label": "Refused", "value": refused, "share": share(refused, every) or 0.0, "tone": "warn"},
            {"label": "Failed", "value": failed, "share": share(failed, every) or 0.0, "tone": "bad"},
        ]
    return {
        "part": "card",
        "table": table,
        "answer": answer,
        "mix": mix,
        "outcome_split": outcome_split,
        "series_options": {f"requests:{row['method']}": {"label": row["method"]} for row in mix},
    }


# ============================================================================================ status codes


SOURCE_COLUMNS: Final = ("source_label", "status", "requests", "source")


@page.card("status", lazy=True)
async def status_card(view: PageView) -> dict[str, Any]:
    """v1's Status Codes section: the four tiles, the verdict, "Who returned it?" and status over time."""
    spec = traffic_api.SOURCES_SPEC
    rows, totals = await traffic_api.status_source_rows(view.ctx, view.tr)
    tq, notice = table_query(view, spec, address=False)
    answer = traffic_api.status_sources_answer(view.tr, tq, rows, totals)
    table = table_view(
        view,
        "traffic-status-sources",
        spec,
        answer,
        src=view.fragment_url("status", part="table"),
        columns=SOURCE_COLUMNS,
        key_columns=("source_label", "status", "requests"),
        hidden=("source",),
        cells=lambda item: {
            "status": {"text": str(item.get("status")), "tone": status_tone(item.get("status")), "mono": True},
            "source": {"text": item.get("source"), "mono": True},
        },
        export_url=view.api_url("traffic/status/sources"),
        caption="Status codes by who returned them",
        empty={
            "title": "No status codes in this range",
            "body": "Every answer Roxy sends adds to a row here: who produced the status code, and which code.",
            "icon": "inbox",
        },
        search_placeholder="Search sources",
        notice=notice,
        address=False,
    )
    if table_only(view):
        return {"part": "table", "table": table}
    chosen = choice(view, "status_view", STATUS_VIEWS, "class")
    series = await traffic_api.status_answer(view.ctx, view.tr, chosen)
    if chosen == "source":
        options = {
            f"requests:{key}": {"label": item["label"], "color": SOURCE_COLORS.get(key, 1)}
            for key, item in (answer.get("sources") or {}).items()
        }
        kind, stack = "area", "source"
    else:
        options = {key: {"label": label, "color": slot} for key, (label, slot) in STATUS_LABELS.items()}
        kind, stack = "line", None
    tiles = []
    for key, meta in TILES:
        value = (answer.get("tiles") or {}).get(key)
        tone = None
        if key in ("roblox_429", "roxy_5xx") and isinstance(value, int | float):
            tone = "bad" if value > 0 else "ok"
        elif key == "roblox_5xx" and isinstance(value, int | float) and value > 0:
            tone = "warn"
        tiles.append(
            {
                "key": key,
                "label": METRICS[key].label,
                "value": value,
                "meta": meta,
                "help": METRICS[key].description,
                "tone": tone,
                "tone_label": {"bad": "Needs a look", "ok": "None in this range", "warn": "Seen in this range"}.get(
                    tone or ""
                ),
            }
        )
    verdict = dict(answer.get("verdict") or {})
    verdict["tone"] = {"muted": "info"}.get(str(verdict.get("tone")), str(verdict.get("tone") or "info"))
    verdict["title"] = VERDICT_TITLES.get(verdict["tone"], "Rate limiting in this range")
    return {
        "part": "card",
        "table": table,
        "tiles": tiles,
        "verdict": verdict,
        "sources": answer.get("sources") or {},
        "series": series,
        "series_options": options,
        "kind": kind,
        "stack": stack,
        "status_view": chosen,
        "views": STATUS_VIEWS,
    }


# ============================================================================================ latency


@page.card("latency", lazy=True)
async def latency_card(view: PageView) -> dict[str, Any]:
    """Latency percentiles over time, or split (v1's toggle), and the split as a table."""
    split = choice(view, "split", LATENCY_SPLITS, "none")
    by = split if split != "none" else "method"
    spec = traffic_api.SPLIT_SPEC
    tq, notice = table_query(view, spec, address=False)
    found = await traffic_api.dimension_table(view.ctx, spec, traffic_api.SPLITS[by], view.tr, tq)
    word = dict(LATENCY_SPLITS)[by].split("(")[0].strip().removeprefix("By ").strip()
    table = table_view(
        view,
        "traffic-latency-split",
        spec,
        found,
        src=view.fragment_url("latency", part="table", split=split),
        labels={"key": word[:1].upper() + word[1:]},
        key_columns=("key", "p95_ms", "requests"),
        cells=lambda item: {
            "key": {"text": item.get("key"), "mono": True},
            **{name: ms_text(item.get(name)) for name in ("p50_ms", "p95_ms", "p99_ms", "queue_wait_p95_ms")},
        },
        export_url=view.api_url("traffic/latency/split", by=by),
        caption=f"Latency by {word}",
        empty={
            "title": "No timed requests in this range",
            "body": "Every caller request Roxy answers is timed; the rows appear as soon as there is traffic.",
            "icon": "clock",
        },
        search_placeholder=f"Search by {word}",
        notice=notice,
        address=False,
    )
    if table_only(view):
        return {"part": "table", "table": table}
    series = await traffic_api.latency_answer(view.ctx, view.tr, split)
    return {
        "part": "card",
        "table": table,
        "series": series,
        "split": split,
        "splits": LATENCY_SPLITS,
        "by_word": word,
        "reset_href": reset_href("traffic", which="latency"),
    }


# ============================================================================================ heatmap


HEATMAP_CHOICES: Final[tuple[tuple[str, str], ...]] = tuple(
    (metric, METRICS[metric].label if metric in METRICS else metric) for metric in traffic_api.HEATMAP_METRICS
)


@page.card("heatmap", lazy=True)
async def heatmap_card(view: PageView) -> dict[str, Any]:
    """Hour of day by weekday for one measure (`traffic_api.heatmap_answer`), in `ui_timezone`."""
    metric = choice(view, "metric", HEATMAP_CHOICES, "requests")
    answer = await traffic_api.heatmap_answer(view.ctx, view.tr, metric)
    grid = answer.get("heatmap") or {}
    cells: list[list[int]] = [list(row) for row in grid.get("cells") or ()]
    days: list[int] = list(grid.get("days") or ())
    label = str(answer.get("label") or metric)
    unit = "calls" if METRICS.get(metric) and METRICS[metric].unit == "calls" else "requests"
    best = max(
        ((value, day, hour) for day, row in enumerate(cells) for hour, value in enumerate(row)), default=(0, 0, 0)
    )
    tz = str(grid.get("tz") or answer.get("range", {}).get("tz") or "UTC")
    if best[0] > 0:
        value, day, hour = best
        busiest = (
            f"The busiest hour was {WEEKDAY_NAMES[day]} {hour:02d}:00 to {(hour + 1) % 24:02d}:00 ({tz}), with "
            f"{value:,} {unit} added up over the range."
        )
    else:
        busiest = f"No {label.lower()} in this range, so every cell is empty."
    covered = ", ".join(
        f"{count} {WEEKDAY_NAMES[i]}{'' if count == 1 else 's'}" for i, count in enumerate(days) if count
    )
    return {
        "answer": answer,
        "rows": WEEKDAY_NAMES,
        "cols": [f"{hour:02d}" for hour in range(24)],
        "cells": cells or [[0] * 24 for _ in WEEKDAY_NAMES],
        "label": label,
        "unit": unit,
        "metric": metric,
        "choices": HEATMAP_CHOICES,
        "summary": f"{label} by weekday and hour of day, {tz} time. {busiest}",
        "covered": covered,
        "help": METRICS[metric].description if metric in METRICS else "",
    }


# ============================================================================================ trends


@page.card("trends", lazy=True)
async def trends_card(view: PageView) -> dict[str, Any]:
    """Week over week, month over month and year over year (`traffic_api.trends_answer`)."""
    answer = await traffic_api.trends_answer(view.ctx)
    tz = view.tz
    periods = []
    for period in answer.get("periods") or ():
        current, previous = period.get("range") or {}, period.get("previous_range") or {}
        rows = []
        for row in period.get("rows") or ():
            values = [float(v) if isinstance(v, int | float) else 0.0 for _t, v in row.get("sparkline") or ()]
            rows.append({**row, "spark": values, "help": METRICS[row["metric"]].description})
        periods.append(
            {
                "key": period.get("key"),
                "label": period.get("label"),
                "rows": rows,
                "notices": list(period.get("notices") or ()),
                "span": f"{_day(current.get('from'), tz)} to {_day(current.get('to'), tz)}",
                "before": f"{_day(previous.get('from'), tz)} to {_day(previous.get('to'), tz)}",
            }
        )
    return {"periods": periods}


# ============================================================================================ inline resets


add_reset_route(page, lambda view: family_reset(view, ("traffic", "latency")))


__all__ = ["page", "router"]
