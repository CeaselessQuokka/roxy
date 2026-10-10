"""The Upstream page (`/admin/upstream`, plan 14.1, 7.12): how Roblox answers Roxy, and the pacing that keeps it calm.

What this is
    One card per registry card of page `upstream` (DESIGN.md section 9 anchors):
      * `health`: one card per egress path (direct, rotator, credential) with v1's method health (failed count, last
        success, last error), the 429 and 5xx rates, latency percentiles and the egress bucket's fill gauge.
      * `429-timeline` and `latency`: Roblox 429s per endpoint over time, and p50, p95 and p99 latency (charts with a
        data table and an accessible summary; the series are embedded, so the chart needs no extra request).
      * `trace`: "Why did this request wait?" for one Roxy-Request-Id (plan 7.12, the 14.7 explainer).
      * `buckets`: the fill gauges of the global and egress buckets, every bucket's fill and rate (a drawer per
        bucket with its history chart and its rate override), the adaptive rate controller's changes, and the
        `upstream_limits` overrides with an add form.
      * `cooldowns`, `breakers`: what is paused now, with countdowns, and the "clear cooldowns and breakers" reset
        (v1 Service Health "routing state", parity row 34; buckets are never refilled).
      * `failures`: v1's Request Failures log (plan 14.1 row 24, parity row 72), the page's main table.
      * `hosts`: the same health per Roblox host, and the host allowlist settings.
      * `routing`: how a request picks its egress (plan 7.2), the routing rules (add, edit, delete) and a tester.
      * `retries` (v1 Retries, row 22: by status, by reason, CSRF retries, returned reasons), `challenges`,
        `internal-calls` (v1 Internal Requests, row 35), `queue` and `concurrency` (AIMD).
    Every catalog setting placed on these cards (`upstream#routing`, `#hosts`, `#buckets`, `#concurrency`,
    `#cooldowns`, `#breakers`, `#queue`, `#retries`) is edited inline by the kit's settings block.

Why it exists
    Plan 2.5 and 7: Roxy should almost never get a 429 from Roblox, and when it does the owner must see where, why
    and what Roxy did. Plan P6: every number comes from the same function the admin API answers with
    (`roxy/admin/api/upstream.py egress_cards_answer`, `host_rows`, `failure_rows`, ...; `routing_rules.py`,
    `upstream_limits.py`), so the page and the API can never disagree. The page changes nothing itself: forms
    post JSON to the admin API (CSRF, validation and the audit log there).

How it works
    `page = Page("upstream")`; each `@page.card` returns the context of `templates/admin/pages/upstream/<card>.html`.
    Cards heavy with settings or tables are lazy (they load when scrolled into view) to keep the first paint small
    on the 1 GB server. Three small page routes serve partials: `/admin/upstream/bucket?key=` (a bucket's drawer),
    `/admin/upstream/routing-rule?id=` (a routing rule's drawer) and `/admin/upstream/routing-test?target=` (the
    tester's answer). Text a caller chose (paths, endpoint templates, errors quoting them) is rendered with
    `format.html caller_text`; a bucket key in a form URL is one percent-encoded path segment (`quoted_key`).

What to read next
    `templates/admin/pages/upstream.html`, `roxy/admin/api/upstream.py`, `roxy/upstream/read_trace.py`,
    `roxy/admin/pages/_upstream_common.py`, `static/js/pages/upstream.js`.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Final
from urllib.parse import urlencode

from fastapi import Request
from fastapi.responses import HTMLResponse

from roxy.admin.api import common
from roxy.admin.api import routing_rules as routing_api
from roxy.admin.api import upstream as upstream_api
from roxy.admin.api import upstream_limits as limits_api
from roxy.admin.pages import shell
from roxy.admin.pages._upstream_common import (
    DEFERRED,
    EGRESS_ABOUT,
    EGRESS_LABELS,
    deferred,
    egress_state,
    fill_tone,
    gauge,
    ms_text,
    pct_text,
    per_min_text,
    precision_words,
    quoted_key,
    render_partial,
)
from roxy.admin.pages.kit import Page, PageAdmin, PageView, filter_chip, table_query, table_view
from roxy.metrics import queries
from roxy.metrics.catalog import METRICS

page = Page("upstream", stream_events=(*shell.DEFAULT_STREAM_EVENTS, "breaker", "cooldown"))
router = page.router

API: Final = common.API_PREFIX
EGRESS_OPTIONS: Final[tuple[tuple[str, str], ...]] = (
    ("", "Every egress"),
    ("direct", "Direct"),
    ("rotator", "Rotator"),
    ("credential", "Credential"),
)
MODE_WORDS: Final[dict[str, str]] = {
    "prefer_direct": "Prefer direct",
    "prefer_rotator": "Prefer the rotator",
    "direct_only": "Direct only",
    "rotator_only": "Rotator only",
}
BUCKET_ORDER: Final[tuple[str, ...]] = (
    "global",
    "egress:direct",
    "egress:rotator",
    "egress:credential",
    "egress:credential:probe",
)
"""The gauges at the top of the Buckets card: Roxy's own ceilings, in plan 7.3 order."""
BUCKET_LABELS: Final[dict[str, str]] = {
    "global": "Global (every call)",
    "egress:direct": "Direct",
    "egress:rotator": "Rotator",
    "egress:credential": "Credential",
    "egress:credential:probe": "Credential probes (reserved)",
}
BUCKET_SETTINGS: Final[dict[str, tuple[str, str]]] = {
    "global": ("global_bucket_per_min", "global_bucket_burst"),
    "egress:direct": ("direct_bucket_per_min", "direct_bucket_burst"),
    "egress:rotator": ("rotator_bucket_per_min", "rotator_bucket_burst"),
    "egress:credential": ("credential_bucket_per_min", "credential_bucket_burst"),
    "egress:credential:probe": ("credential_probe_reserved_per_min", "credential_bucket_burst"),
}
"""Where the rate of a bucket that `upstream_limits` cannot override comes from (the drawer names it)."""
MAX_CHANGES_SHOWN: Final = 25
SOURCE_WORDS: Final[dict[str, str]] = {
    "retry_after": "Roblox's Retry-After",
    "ratelimit_reset": "Roblox's rate limit headers",
    "breaker": "a circuit breaker",
    "default": "no Retry-After (the default)",
}
"""Why a cooldown lasts as long as it does (`upstream/cooldowns.py CooldownSource`)."""
CUT_FROM_WORDS: Final[dict[str, str]] = {
    "observed": "cut from the calls Roblox refused",
    "limit": "cut from the configured rate",
}
"""What an adaptive decrease started from (`upstream/adaptive.py` evidence `cut_from`)."""
MAX_TRACE_ID_CHARS: Final = 64
QUEUE_PRIORITIES: Final[tuple[tuple[int, str, str], ...]] = (
    (0, "A caller's request with no cached copy to fall back on", "queue_wait_interactive_ms"),
    (1, "A caller's request that can be answered from a stale cached copy instead", "queue_wait_stale_ms"),
    (2, "A background refresh of a cached answer (dropped first under pressure)", "queue_wait_background_ms"),
    (3, "An admin action (a lookup, a cache refresh)", "queue_wait_admin_ms"),
    (4, "Roxy's own probes and health checks", "queue_wait_internal_ms"),
)
"""Plan 7.8: who waits for a bucket slot, and the setting that bounds the wait."""


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def _seconds_from_ms(value: Any) -> float | None:
    number = _number(value)
    return number / 1000 if number is not None else None


def _join(parts: Sequence[str]) -> str:
    return ", ".join(part for part in parts if part)


# ============================================================================================ health


def _last_error(view: PageView, error: Any) -> dict[str, Any] | None:
    """v1's "last error" of an egress or host: when, why, the statuses, and the request (caller text)."""
    if not isinstance(error, Mapping):
        return None
    statuses = []
    if error.get("status") is not None:
        statuses.append(f"the caller got {error['status']}")
    if error.get("upstream_status") is not None:
        statuses.append(f"Roblox answered {error['upstream_status']}")
    return {
        "when": view.time_cell(_seconds_from_ms(error.get("at_ms"))),
        "reason": str(error.get("reason") or ""),
        "statuses": _join(statuses),
        "method": str(error.get("method") or ""),
        "template": error.get("template"),
        "path": error.get("path"),
        "error": error.get("error"),
    }


def _egress_card(view: PageView, item: Mapping[str, Any]) -> dict[str, Any]:
    name = str(item.get("egress") or "")
    label = EGRESS_LABELS.get(name, name)
    tone, words, state_detail = egress_state(item)
    bucket = item.get("bucket") or {}
    detail = f"{per_min_text(bucket.get('per_min'))}, burst {bucket.get('burst', 'n/a')}"
    if _number(bucket.get("next_free_in_ms")):
        detail += f"; the next call would wait {ms_text(bucket.get('next_free_in_ms'))}"
    return {
        "name": name,
        "label": label,
        "about": EGRESS_ABOUT.get(name, ""),
        "tone": tone,
        "words": words,
        "state_detail": state_detail,
        "item": item,
        "calls_per_min": f"{float(item.get('calls_per_min') or 0):,.2f}",
        "rate_429": pct_text(item.get("rate_429_pct")),
        "rate_5xx": pct_text(item.get("rate_5xx_pct")),
        "rate_failed": pct_text(item.get("rate_failed_pct")),
        "latency": " / ".join(ms_text(item.get(key)) for key in ("p50_ms", "p95_ms", "p99_ms")),
        "queue_p95": ms_text(item.get("queue_wait_p95_ms")),
        "gauge": gauge(f"{label} bucket fill", bucket.get("fill_pct"), detail=detail, key=f"egress:{name}"),
        "last_success": view.time_cell(item.get("last_success_at")),
        "last_success_precision": precision_words(item.get("last_success_precision")),
        "last_error_at": view.time_cell(item.get("last_error_at")),
        "last_error_precision": precision_words(item.get("last_error_precision")),
        "last_error": _last_error(view, item.get("last_error")),
    }


@page.card("health", refresh_on=("breaker", "cooldown"), refresh_min_s=15)
async def health_card(view: PageView) -> dict[str, Any]:
    """One health card per egress (`egress_cards_answer`, the API's own function)."""
    answer = await upstream_api.egress_cards_answer(view.ctx, view.tr)
    return {
        "egresses": [_egress_card(view, item) for item in answer["items"]],
        "range_label": view.time.view.get("description"),
    }


# ============================================================================================ charts


@page.card("429-timeline")
async def timeline_card(view: PageView) -> dict[str, Any]:
    """Roblox 429s per endpoint over the range (`timeline_429_answer`), embedded for the first paint."""
    answer = await upstream_api.timeline_429_answer(view.ctx, view.tr, top=10)
    totals = answer.get("totals") or {}
    counts = totals.get("by_endpoint") or {}
    by_endpoint = [{"template": template, "count": count} for template, count in counts.items()]
    spec = METRICS.get("roblox_429")
    return {
        "series": answer,
        "total": int(totals.get("total") or 0),
        "by_endpoint": by_endpoint,
        "help": spec.description if spec else "",
    }


@page.card("latency")
async def latency_card(view: PageView) -> dict[str, Any]:
    """p50, p95 and p99 latency and the p95 queue wait of requests that went to Roblox (`latency_answer`)."""
    if deferred(view):
        return DEFERRED
    answer = await upstream_api.latency_answer(view.ctx, view.tr)
    spec = METRICS.get("p95_ms")
    queue = METRICS.get("queue_wait_p95_ms")
    return {
        "series": answer,
        "help": " ".join(s.description for s in (spec, queue) if s is not None),
        "basis": str(answer.get("basis") or "").capitalize(),
    }


# ============================================================================================ trace


@page.card("trace")
async def trace_card(view: PageView) -> dict[str, Any]:
    """The "why did this request wait" explainer for `?request_id=` (`trace_answer`), or the empty lookup form."""
    raw = view.param("request_id", max_chars=MAX_TRACE_ID_CHARS)
    context: dict[str, Any] = {"request_id": raw, "answer": None, "error": None}
    if not raw:
        return context
    try:
        answer = await upstream_api.trace_answer(view.ctx, raw)
    except common.ApiError as exc:
        context["error"] = "; ".join(exc.error_fields.values()) or exc.error_message
        return context
    live = answer.get("live") if isinstance(answer.get("live"), Mapping) else None
    context["answer"] = answer
    context["live"] = live
    context["when"] = view.time_cell(_seconds_from_ms(live.get("at_ms"))) if live else None
    context["minted"] = view.time_cell(_seconds_from_ms(answer.get("minted_at_ms")))
    context["roblox_429s"] = [_trace_429(view, item) for item in answer.get("roblox_429s") or ()]
    context["prior_429s"] = [_trace_429(view, item) for item in answer.get("prior_429s") or ()]
    context["link"] = f"/admin/upstream?{urlencode({'request_id': answer.get('request_id') or ''})}#trace"
    return context


def _trace_429(view: PageView, item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "when": view.time_cell(_seconds_from_ms(item.get("at_ms"))),
        "template": item.get("endpoint_template"),
        "egress": EGRESS_LABELS.get(str(item.get("egress") or ""), str(item.get("egress") or "")),
        "retry_after_s": item.get("retry_after_s"),
    }


# ============================================================================================ buckets


def _bucket_cells(item: Mapping[str, Any]) -> dict[str, Any]:
    fill = item.get("fill_pct")
    peak = item.get("fill_pct_peak")
    return {
        "key": {"text": item.get("key"), "caller": True, "mono": True},
        "fill_pct": {"text": pct_text(fill), "tone": fill_tone(fill)} if fill is not None else None,
        "next_free_in_ms": ms_text(item.get("next_free_in_ms")) if item.get("next_free_in_ms") is not None else None,
        "per_min": per_min_text(item.get("per_min")),
        "fill_pct_peak": {"text": pct_text(peak), "tone": fill_tone(peak)} if peak is not None else None,
        "rejections": {"text": f"{int(item.get('rejections') or 0):,}", "tone": "bad"}
        if int(item.get("rejections") or 0)
        else 0,
    }


def _bucket_drawer(view: PageView, key: Any) -> str:
    return "/admin/upstream/bucket?" + urlencode({"key": str(key), **view.time.params})


def _limit_cells(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "bucket_key": {"text": item.get("bucket_key"), "caller": True, "mono": True},
        "per_min": per_min_text(item.get("per_min")),
        "default_per_min": per_min_text(item.get("default_per_min")),
        "note": {"text": item.get("note"), "caller": True} if item.get("note") else None,
    }


def _adaptive_changes(view: PageView, changes: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for item in list(changes)[:MAX_CHANGES_SHOWN]:
        evidence = item.get("evidence") or {}
        why = []
        if isinstance(evidence, Mapping):
            observed = _number(evidence.get("observed_calls"))
            if observed is not None:
                why.append(f"{observed:,.0f} calls went out in the minute before the 429")
            cut_from = CUT_FROM_WORDS.get(str(evidence.get("cut_from") or ""))
            if cut_from:
                why.append(cut_from)
        out.append(
            {
                "when": view.time_cell(_seconds_from_ms(item.get("at_ms"))),
                "direction": "Lowered" if item.get("direction") == "decrease" else "Raised",
                "tone": "warn" if item.get("direction") == "decrease" else "ok",
                "key": item.get("bucket_key"),
                "old": per_min_text(item.get("old_per_min")),
                "new": per_min_text(item.get("new_per_min")),
                "why": _join(why),
            }
        )
    return out


@page.card("buckets")
async def buckets_card(view: PageView) -> dict[str, Any]:
    """Fill gauges, every bucket (`bucket_rows`), the adaptive controller (`adaptive_answer`) and the overrides
    (`upstream_limits.limit_rows`): the API's own functions."""
    if deferred(view):
        return DEFERRED
    tq, notice = table_query(view, upstream_api.BUCKETS_SPEC, address=False)
    rows = await upstream_api.bucket_rows(view.ctx, view.tr)
    answer = upstream_api.buckets_answer(rows, tq, view.tr)
    by_key = {str(row["key"]): row for row in rows}
    gauges = []
    for key in BUCKET_ORDER:
        row = by_key.get(key)
        if row is None:
            continue
        detail = f"{per_min_text(row.get('per_min'))}, burst {row.get('burst', 'n/a')}"
        if int(row.get("rejections") or 0):
            detail += f"; {int(row['rejections']):,} reservations refused in this range"
        gauges.append(gauge(BUCKET_LABELS[key], row.get("fill_pct"), detail=detail, key=key))
    table = table_view(
        view,
        "upstream-buckets",
        upstream_api.BUCKETS_SPEC,
        answer,
        src=view.fragment_url("buckets"),
        key_columns=("key", "fill_pct", "per_min"),
        hidden=("next_free_in_ms", "burst", "attempts"),
        cells=_bucket_cells,
        row_id=lambda item: f"bucket-{item['key']}",
        drawer=lambda item: _bucket_drawer(view, item["key"]),
        drawer_title=lambda item: f"Bucket {item['key']}",
        export_url=f"{API}/upstream/buckets",
        caption="Buckets",
        empty={
            "title": "No bucket has been used yet",
            "body": "A bucket appears the first time a call to Roblox reserves a slot in it. Send traffic through "
            "the proxy and it fills in.",
            "icon": "gauge",
        },
        search_placeholder="Search buckets",
        notice=notice,
        address=False,
    )
    adaptive = await upstream_api.adaptive_answer(view.ctx, view.tr)
    limit_items = await limits_api.limit_rows(view.ctx)
    ltq, lnotice = table_query(view, limits_api.SPEC, address=False)
    limits = limits_api.limits_answer(view.ctx, limit_items, ltq)
    limits_table = table_view(
        view,
        "upstream-limits",
        limits_api.SPEC,
        limits,
        src=view.fragment_url("buckets"),
        columns=("bucket_key", "per_min", "burst", "default_per_min", "origin", "note", "updated_at", "updated_by"),
        key_columns=("bucket_key", "per_min", "origin"),
        hidden=("note", "updated_by"),
        cells=_limit_cells,
        row_id=lambda item: f"limit-{item['bucket_key']}",
        drawer=lambda item: _bucket_drawer(view, item["bucket_key"]),
        drawer_title=lambda item: f"Bucket {item['bucket_key']}",
        export_url=f"{API}/upstream-limits",
        caption="Rate overrides",
        empty={
            "title": "No rate overrides",
            "body": "Every host and endpoint bucket runs at its default rate. An override appears when you add one, "
            "when a recommendation is applied, or when the adaptive controller lowers an endpoint after a 429.",
            "icon": "sliders",
        },
        search_placeholder="Search overrides",
        notice=lnotice,
        address=False,
    )
    held = len(adaptive.get("rates") or ())
    defaults = limits.get("defaults") or {}
    host = defaults.get("host") or {}
    endpoint = defaults.get("endpoint") or {}
    return {
        "gauges": gauges,
        "table": table,
        "limits_table": limits_table,
        "adaptive": adaptive,
        "changes": _adaptive_changes(view, adaptive.get("changes") or ()),
        "held_text": "no rate" if not held else f"{held} rate" + ("s" if held != 1 else ""),
        "host_default": f"{per_min_text(host.get('per_min'))} (burst {host.get('burst', 'n/a')})",
        "endpoint_default": f"{per_min_text(endpoint.get('per_min'))} (burst {endpoint.get('burst', 'n/a')})",
        "limits_url": f"{API}/upstream-limits",
    }


@page.router.get("/bucket", include_in_schema=False)
async def bucket_drawer(request: Request, principal: PageAdmin) -> HTMLResponse:
    """One bucket in the drawer: its history chart, its rate and where it comes from, and its override form."""

    async def build(view: PageView) -> dict[str, Any]:
        key = view.param("key", max_chars=upstream_api.MAX_KEY_CHARS)
        if not key:
            raise common.not_found("Choose a bucket from the table.")
        history = await upstream_api.bucket_history_answer(view.ctx, view.tr, key)
        describe = history.get("describe") or {}
        rows = await upstream_api.bucket_rows(view.ctx, view.tr)
        row = next((item for item in rows if item.get("key") == key), None)
        overridable = describe.get("kind") in ("host", "endpoint")
        override = None
        if overridable:
            override = next((item for item in await limits_api.limit_rows(view.ctx) if item["bucket_key"] == key), None)
        return {
            "key": key,
            "describe": describe,
            "row": row,
            "history": history,
            "gauge": gauge("Fill now", (row or {}).get("fill_pct")),
            "overridable": overridable,
            "override": override,
            "settings_keys": BUCKET_SETTINGS.get(key),
            "patch_url": f"{API}/upstream-limits/{quoted_key(key)}",
            "create_url": f"{API}/upstream-limits",
            "fill_help": (METRICS["bucket_fill_peak_pct"].description if "bucket_fill_peak_pct" in METRICS else ""),
        }

    return await render_partial(page, request, principal, "admin/pages/upstream/_bucket.html", build)


# ============================================================================================ concurrency, queue


@page.card("concurrency")
async def concurrency_card(view: PageView) -> dict[str, Any]:
    """Adaptive concurrency (AIMD, plan 7.4, Tier 3): its switch and each key's limit and calls in flight."""
    if deferred(view):
        return DEFERRED
    answer = await upstream_api.aimd_answer(view.ctx)
    items = [
        {**item, "changed": view.time_cell(item.get("last_change_at"))} for item in answer.get("items") or ()
    ]
    return {"aimd": answer, "items": items}


@page.card("queue")
async def queue_card(view: PageView) -> dict[str, Any]:
    """The five wait classes of plan 7.8 with the live value of the setting that bounds each one."""
    if deferred(view):
        return DEFERRED
    settings = view.ctx.settings
    rows = [
        {"priority": priority, "who": who, "key": key, "value": ms_text(settings.get(key))}
        for priority, who, key in QUEUE_PRIORITIES
    ]
    return {
        "priorities": rows,
        "queue_max": settings.get("queue_max_length"),
        "deadline_s": settings.get("request_deadline_s"),
    }


# ============================================================================================ cooldowns, breakers


def _source_words(source: Any) -> str:
    text = str(source or "")
    return SOURCE_WORDS.get(text, text.replace("_", " ") or "n/a")


def _countdown(ends_at_ms: Any, now_ms: Any) -> dict[str, Any] | None:
    ends = _number(ends_at_ms)
    now = _number(now_ms)
    if ends is None or now is None:
        return None
    remaining = max(0.0, (ends - now) / 1000)
    return {"ends_at_ms": int(ends), "now_ms": int(now), "remaining_s": round(remaining, 1)}


@page.card("cooldowns", refresh_on=("cooldown",), refresh_min_s=5)
async def cooldowns_card(view: PageView) -> dict[str, Any]:
    """Every open cooldown with its source and a countdown (`cooldowns_answer`), and the reset button."""
    if deferred(view):
        return DEFERRED
    answer = await upstream_api.cooldowns_answer(view.ctx)
    now_ms = answer.get("now_ms")
    items = [
        {
            **item,
            "egress_label": EGRESS_LABELS.get(str(item.get("egress") or ""), "Every egress"),
            "source_words": _source_words(item.get("source")),
            "countdown": _countdown(item.get("ends_at_ms"), now_ms),
            "set": view.time_cell(item.get("set_at")),
        }
        for item in answer.get("items") or ()
    ]
    local = [
        {
            **item,
            "source_words": _source_words(item.get("source")),
            "countdown": _countdown(item.get("ends_at_ms"), now_ms),
        }
        for item in answer.get("local") or ()
    ]
    return {"items": items, "local": local, "local_note": answer.get("local_note")}


@page.card("breakers", refresh_on=("breaker",), refresh_min_s=5)
async def breakers_card(view: PageView) -> dict[str, Any]:
    """Breakers that are open, half-open or counting failures (`breakers_answer`), and the reset button."""
    if deferred(view):
        return DEFERRED
    answer = await upstream_api.breakers_answer(view.ctx)
    now_ms = answer.get("now_ms")
    items = []
    for item in answer.get("items") or ():
        state = str(item.get("state") or "")
        tone = {"open": "bad", "half_open": "warn"}.get(state, "neutral")
        words = {"open": "Open: no calls", "half_open": "Half-open: one test call"}.get(state, "Counting failures")
        items.append(
            {
                **item,
                "tone": tone,
                "words": words,
                "egress_label": EGRESS_LABELS.get(str(item.get("egress") or ""), "Every egress"),
                "countdown": _countdown(item.get("reopens_at_ms"), now_ms) if item.get("reopens_at_ms") else None,
            }
        )
    return {"items": items}


# ============================================================================================ failures, hosts


def _failure_cells(item: Mapping[str, Any]) -> dict[str, Any]:
    egress = item.get("egress")
    return {
        "egress": EGRESS_LABELS.get(str(egress), str(egress)) if egress else {"text": "Folded", "tone": "muted"},
        "reason": {"text": item.get("reason"), "mono": True},
    }


@page.card("failures")
async def failures_card(view: PageView) -> dict[str, Any]:
    """v1's Request Failures log (`failure_rows`, the API's own function): the page's main table."""
    tq, notice = table_query(view, upstream_api.FAILURES_SPEC)
    chosen = view.state_param("egress", max_chars=16)
    egress = chosen if chosen in upstream_api.EGRESSES else None
    rows, capped = await upstream_api.failure_rows(view.ctx, view.tr, egress)
    answer = upstream_api.failures_answer(rows, capped, tq, view.tr, egress)
    table = table_view(
        view,
        "upstream-failures",
        upstream_api.FAILURES_SPEC,
        answer,
        src=view.fragment_url("failures"),
        key_columns=("reason", "count", "last_ms"),
        hidden=("folded", "first_ms", "last_method", "last_template"),
        cells=_failure_cells,
        row_id=lambda item: f"failure-{item.get('egress')}-{item.get('reason')}-{item.get('upstream_status')}",
        drawer_title=lambda item: f"Failures: {item.get('reason')}",
        filters=[filter_chip("egress", "Egress", egress or "", EGRESS_OPTIONS)],
        export_url=f"{API}/upstream/failures",
        caption="Request failures",
        empty={
            "title": "No failed requests in this range",
            "body": "Every request that went to Roblox got an answer. Failures (Roblox 5xx after the retries, "
            "timeouts, connection errors) are listed here as they happen.",
            "tone": "good",
        },
        search_placeholder="Search failures",
        notice=notice,
    )
    total = sum(int(row.get("count") or 0) for row in rows)
    return {"table": table, "total": total, "capped": capped}


def _error_summary(error: Any) -> dict[str, Any] | None:
    if not isinstance(error, Mapping):
        return None
    parts = [str(error.get("reason") or "")]
    if error.get("upstream_status") is not None:
        parts.append(f"Roblox {error['upstream_status']}")
    if error.get("path"):
        parts.append(f"{error.get('method') or ''} {error['path']}".strip())
    if error.get("error"):
        parts.append(str(error["error"]))
    return {"text": _join(parts), "caller": True, "limit": 160}


def _host_cells(item: Mapping[str, Any]) -> dict[str, Any]:
    fill = item.get("bucket_fill_pct")
    return {
        "host": {"text": item.get("host"), "caller": True, "mono": True},
        "calls_per_min": f"{float(item.get('calls_per_min') or 0):,.2f}",
        "rate_429_pct": {"text": pct_text(item.get("rate_429_pct")), "tone": "bad"}
        if int(item.get("roblox_429") or 0)
        else pct_text(item.get("rate_429_pct")),
        "rate_5xx_pct": pct_text(item.get("rate_5xx_pct")),
        "p50_ms": ms_text(item.get("p50_ms")),
        "p95_ms": ms_text(item.get("p95_ms")),
        "p99_ms": ms_text(item.get("p99_ms")),
        "bucket_fill_pct": {"text": pct_text(fill), "tone": fill_tone(fill)},
        "per_min": per_min_text(item.get("per_min")),
        "last_error": _error_summary(item.get("last_error")),
    }


@page.card("hosts")
async def hosts_card(view: PageView) -> dict[str, Any]:
    """Per Roblox host health (`host_rows`) and the host allowlist (the card's settings)."""
    if deferred(view):
        return DEFERRED
    tq, notice = table_query(view, upstream_api.HOSTS_SPEC, address=False)
    rows = await upstream_api.host_rows(view.ctx, view.tr)
    answer = upstream_api.hosts_answer(rows, tq, view.tr)
    table = table_view(
        view,
        "upstream-hosts",
        upstream_api.HOSTS_SPEC,
        answer,
        src=view.fragment_url("hosts"),
        key_columns=("host", "calls", "rate_429_pct"),
        hidden=(
            "calls_per_min",
            "roblox_5xx",
            "timeouts",
            "failed",
            "p50_ms",
            "p99_ms",
            "per_min",
            "last_error_at",
            "last_error",
        ),
        cells=_host_cells,
        row_id=lambda item: f"host-{item['host']}",
        drawer_title=lambda item: f"Host {item['host']}",
        export_url=f"{API}/upstream/hosts",
        caption="Roblox hosts",
        empty={
            "title": "No calls to Roblox in this range",
            "body": "A host appears here once Roxy calls it for a caller or for itself. Try a longer range.",
        },
        search_placeholder="Search hosts",
        notice=notice,
        address=False,
    )
    settings = view.ctx.settings
    allowed = settings.get("allowed_roblox_hosts") or ()
    return {"table": table, "strict": bool(settings.get("strict_host_allowlist")), "allowed": list(allowed)}


# ============================================================================================ routing


def _rule_cells(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": {"text": f"#{item['id']}", "mono": True},
        "pattern": {"text": item.get("pattern"), "caller": True, "mono": True},
        "mode": MODE_WORDS.get(str(item.get("mode")), str(item.get("mode"))),
        "enabled": {"text": "On", "tone": "ok"} if item.get("enabled") else {"text": "Off", "tone": "muted"},
        "note": {"text": item.get("note"), "caller": True} if item.get("note") else None,
    }


@page.card("routing")
async def routing_card(view: PageView) -> dict[str, Any]:
    """How an attempt picks its egress (plan 7.2, the live settings) and the routing rules (`rule_rows`)."""
    if deferred(view):
        return DEFERRED
    tq, notice = table_query(view, routing_api.SPEC, address=False)
    rows = await routing_api.rule_rows(view.ctx)
    answer = routing_api.rules_answer(rows, tq)
    table = table_view(
        view,
        "routing-rules",
        routing_api.SPEC,
        answer,
        src=view.fragment_url("routing"),
        columns=("id", "pattern", "type", "mode", "enabled", "note", "updated_at", "created_by"),
        key_columns=("id", "pattern", "mode"),
        hidden=("type", "updated_at", "created_by"),
        cells=_rule_cells,
        row_id=lambda item: f"routing-{item['id']}",
        drawer=lambda item: "/admin/upstream/routing-rule?" + urlencode({"id": item["id"]}),
        drawer_title=lambda item: f"Routing rule #{item['id']}",
        export_url=f"{API}/routing-rules",
        caption="Routing rules",
        empty={
            "title": "No routing rules",
            "body": "Every endpoint follows the weights above. Add a rule to keep a fragile endpoint off the "
            "rotator, or to move one the server address keeps getting 429s on to it.",
            "icon": "upstream",
        },
        search_placeholder="Search rules",
        notice=notice,
        address=False,
    )
    settings = view.ctx.settings
    return {
        "table": table,
        "modes": [(mode, MODE_WORDS[mode]) for mode in routing_api.MODES],
        "create_url": f"{API}/routing-rules",
        "summary": {
            "direct_enabled": bool(settings.get("direct_enabled")),
            "rotator_enabled": bool(settings.get("rotator_enabled")),
            "direct_weight": settings.get("direct_weight"),
            "rotator_weight": settings.get("rotator_weight"),
            "shift_pct": settings.get("direct_shift_threshold_pct"),
            "fallback_on_429": bool(settings.get("fallback_on_429")),
            "attempts": settings.get("upstream_max_attempts"),
        },
    }


@page.router.get("/routing-rule", include_in_schema=False)
async def routing_rule_drawer(request: Request, principal: PageAdmin) -> HTMLResponse:
    """One routing rule in the drawer: its fields, the edit form (PATCH) and the delete dialog (DELETE)."""

    async def build(view: PageView) -> dict[str, Any]:
        raw = view.param("id", max_chars=24)
        if not raw.isdigit() or not 1 <= int(raw) <= common.MAX_ROW_ID:
            raise common.not_found("Choose a rule from the table; that rule number is not valid.")
        rule_id = int(raw)
        found = next((item for item in await routing_api.rule_rows(view.ctx) if item["id"] == rule_id), None)
        if found is None:
            raise common.not_found("No routing rule has that id. It may have been deleted.")
        return {
            "rule": found,
            "mode_words": MODE_WORDS.get(str(found.get("mode")), str(found.get("mode"))),
            "modes": [(mode, MODE_WORDS[mode]) for mode in routing_api.MODES],
            "url": f"{API}/routing-rules/{rule_id}",
            "created": view.time_cell(found.get("created_at")),
            "updated": view.time_cell(found.get("updated_at")),
        }

    return await render_partial(page, request, principal, "admin/pages/upstream/_routing_rule.html", build)


@page.router.get("/routing-test", include_in_schema=False)
async def routing_test(request: Request, principal: PageAdmin) -> HTMLResponse:
    """The routing tester's answer (`routing_rules.target_answer`, the API's own function)."""

    async def build(view: PageView) -> dict[str, Any]:
        target = view.param("target", max_chars=routing_api.MAX_TARGET_CHARS)
        if not target:
            raise common.validation_error({"target": "Give a host and path such as games.roblox.com/v1/games."})
        answer = routing_api.target_answer(view.ctx, target)
        rule = answer.get("rule")
        return {
            "answer": answer,
            "mode_words": MODE_WORDS.get(str(answer.get("mode")), "") if rule else "",
        }

    return await render_partial(page, request, principal, "admin/pages/upstream/_routing_test.html", build)


# ============================================================================================ retries and the rest


KIND_WORDS: Final[dict[str, str]] = {
    "first": "First calls",
    "retry_5xx": "Retries after a 5xx, a timeout or a connection error",
    "csrf_retry": "Repeats with a fresh CSRF token",
    "fallback_429": "Retries on another egress after a 429",
    "redirect": "Redirect hops followed",
}
"""The attempt kinds of `upstream_attempt_minute` (`metrics/recorder.py record_attempts`) in plain words."""

RETURNED_LABELS: Final[dict[str, str]] = {
    "roxy": "Roxy's own failure text (Roblox failed or could not be reached)",
    "roblox": "Roblox's own answer, passed on",
    "custom": "A refusal with your custom message",
    "default": "A refusal with the default message",
    "unknown": "Not recorded (older or folded rows)",
}
"""v1's "Returned Reasons" (row 22, parity row 116): whose words a refused or failed caller got."""


@page.card("retries")
async def retries_card(view: PageView) -> dict[str, Any]:
    """Retries by status, reason and egress, CSRF retries and attempt kinds (`retries_answer`), plus v1's
    returned reasons from the refusal reasons read model (`metrics/queries.py refusal_reasons`, row 116)."""
    if deferred(view):
        return DEFERRED
    answer = await upstream_api.retries_answer(view.ctx, view.tr)
    window = view.tr.window
    reasons = await view.ctx.dbs.metrics.read(lambda conn: queries.refusal_reasons(conn, window))
    returned: dict[str, int] = {}
    for row in reasons:
        for source, count in (row.get("message_source") or {}).items():
            returned[str(source)] = returned.get(str(source), 0) + int(count or 0)
    returned_rows = [
        {"source": source, "label": RETURNED_LABELS.get(source, source), "count": count}
        for source, count in sorted(returned.items(), key=lambda pair: -pair[1])
    ]

    def ordered(mapping: Any) -> list[tuple[str, int]]:
        pairs = [(str(k), int(v or 0)) for k, v in (mapping or {}).items()]
        return sorted(pairs, key=lambda pair: -pair[1])

    kinds = {str(k): int(v or 0) for k, v in (answer.get("attempt_kinds") or {}).items()}
    return {
        "answer": answer,
        "by_status": ordered(answer.get("by_status")),
        "by_reason": ordered(answer.get("by_reason")),
        "by_egress": [(EGRESS_LABELS.get(k, k), v) for k, v in ordered(answer.get("by_egress"))],
        "kinds": [(KIND_WORDS.get(kind, kind), count) for kind, count in ordered(kinds)],
        "retry_5xx": kinds.get("retry_5xx", 0),
        "fallback_429": kinds.get("fallback_429", 0),
        "returned": returned_rows,
    }


def _challenge_cells(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "egress": EGRESS_LABELS.get(str(item.get("egress")), str(item.get("egress"))),
        "template": {"text": item.get("template"), "caller": True, "mono": True},
        "challenges": {"text": f"{int(item.get('challenges') or 0):,}", "tone": "bad"}
        if int(item.get("challenges") or 0)
        else 0,
        "html_bodies": {"text": f"{int(item.get('html_bodies') or 0):,}", "tone": "warn"}
        if int(item.get("html_bodies") or 0)
        else 0,
    }


@page.card("challenges")
async def challenges_card(view: PageView) -> dict[str, Any]:
    """Answers that were a bot challenge or an HTML page (`challenge_rows`, the API's own function)."""
    if deferred(view):
        return DEFERRED
    tq, notice = table_query(view, upstream_api.CHALLENGES_SPEC, address=False)
    rows = await upstream_api.challenge_rows(view.ctx, view.tr)
    flagged = [row for row in rows if int(row.get("challenges") or 0) or int(row.get("html_bodies") or 0)]
    answer = upstream_api.challenges_answer(rows, tq, view.tr)
    table = table_view(
        view,
        "upstream-challenges",
        upstream_api.CHALLENGES_SPEC,
        answer,
        src=view.fragment_url("challenges"),
        key_columns=("template", "challenges", "html_bodies"),
        cells=_challenge_cells,
        row_id=lambda item: f"challenge-{item.get('egress')}-{item.get('template')}",
        drawer_title=lambda item: f"Endpoint {item.get('template')}",
        export_url=f"{API}/upstream/challenges",
        caption="Challenge and HTML answers",
        empty={
            "title": "No calls to Roblox in this range",
            "body": "Calls appear here per endpoint once Roxy calls Roblox; the flagged ones are at the top.",
        },
        search_placeholder="Search endpoints",
        notice=notice,
        address=False,
    )
    return {"table": table, "flagged": len(flagged)}


@page.card("internal-calls")
async def internal_calls_card(view: PageView) -> dict[str, Any]:
    """Roxy's own calls (v1 Internal Requests, rows 28 and 29): `internal_calls_answer`, the API's own function."""
    if deferred(view):
        return DEFERRED
    answer = await upstream_api.internal_calls_answer(view.ctx, view.tr)
    health = {
        "ok": ("ok", "OK"),
        "failing": ("bad", "Failing"),
        "not_called": ("neutral", "Not called yet"),
    }
    items = []
    for item in answer.get("items") or ():
        tone, words = health.get(str(item.get("health")), ("neutral", str(item.get("health"))))
        items.append(
            {
                **item,
                "count": int(item.get("count") or 0),
                "failed": int(item.get("failed") or 0),
                "tone": tone,
                "words": words,
                "mean": ms_text(item.get("mean_ms")),
                "last": view.time_cell(_seconds_from_ms(item.get("last_ms"))),
                "last_error_when": view.time_cell(_seconds_from_ms(item.get("last_error_ms"))),
            }
        )
    order = {"not_called": 0, "failing": 1, "ok": 2}
    items.sort(key=lambda item: (order.get(str(item.get("health")), 3), str(item.get("purpose"))))
    return {"items": items, "note": answer.get("note") or ""}


__all__ = ["page", "router"]
