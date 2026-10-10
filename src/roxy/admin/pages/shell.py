"""The shell context: everything `templates/admin/base.html` needs, built once per page render.

What this is
    `build_shell(request, principal, spec, ...)` returns the context of the admin shell (the base layout contract in
    `admin/base.html`): the signed-in admin, the masked CSRF token, session timings, theme and density from the
    admin's preferences, the time range and comparison from the URL, the live service state for the banners and
    the top bar (with the caller texts), the recommendations bell, the URLs the shell's scripts call, the glossary,
    the inline settings of the top bar dialogs and the preferences dialog, the environment name and the version.
    `resolve_time(...)` turns the URL's `range`, `from`, `to`, `granularity` and `compare` into the same `TimeRange`
    the admin API builds (`admin/api/common.build_time_range`, the `TimeRangeDep` rules).

Why it exists
    Plan 14.1 and 14.2 put the same top bar on every page (time range, comparison, live indicator, palette,
    recommendations bell, Health, Pause and Emergency Limit, user menu), and plan P6 asks for one source of truth
    per number. So the shell reads the same state the API reads (the pause and throttle-all rows, the refusal
    counts since they began, the recommendation facets, the admin's stored preferences) through the same read
    models, in as few reads as possible: one control.db read and one metrics.db read per page.

How it works
    * Time: the URL wins, then the admin's stored `default_range` and `compare` preferences, then `24h` and no
      comparison. An invalid value never fails the page: the default range is used and `time.notice` says what was
      wrong (a page must never answer 500 or 422 for a bad link).
    * Status: `PauseState` and `ThrottleAllState` from control.db `service_state`, refusals since each began from
      `metrics.queries.drops_since`, and the caller texts from `texts.caller_texts` with the live
      `pause_message_default` (P11_INPUTS "Shell and shared", finding spec-3).
    * Bell: open and critical counts from `insights.read_recommendations.facets` (the same rows the
      Recommendations API counts).
    * Stream: the page-wide SSE URL asks only for the event kinds the page wants (`stream_events`).

What to read next
    `templates/admin/base.html` (the contract), `roxy/admin/pages/kit.py` (which calls `build_shell`),
    `roxy/admin/pages/inline.py` (the dialog settings).
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final
from urllib.parse import urlencode

from fastapi import Request

from roxy import __version__
from roxy.abuse.pause import STATE_KEY as PAUSE_KEY
from roxy.abuse.pause import PauseState
from roxy.abuse.state import read_state_value
from roxy.abuse.throttle_all import STATE_KEY as THROTTLE_ALL_KEY
from roxy.abuse.throttle_all import ThrottleAllState
from roxy.admin.api import common, prefs
from roxy.admin.api.common import API_PREFIX, DEFAULT_RANGE, RangeParams, TimeRange
from roxy.admin.auth.deps import AdminPrincipal, masked_csrf
from roxy.admin.pages import fmt, inline, registry
from roxy.admin.pages.texts import GlossaryEntry, caller_texts, load_glossary
from roxy.deps import get_ctx
from roxy.insights import read_recommendations
from roxy.metrics import queries

GLOSSARY_STATE: Final = "admin_glossary"
"""`app.state` attribute holding the glossary loaded at startup (`roxy.admin.pages.dashboard_lifespan`)."""

DEFAULT_STREAM_EVENTS: Final[tuple[str, ...]] = ("settings_changed", "recommendation", "alert")
"""What the page-wide stream asks for unless a page wants more (plan 14.11; `admin/sse.py EVENT_KINDS`)."""

TOPBAR_SETTING_ANCHORS: Final[dict[str, str]] = {
    "pause": "topbar#pause",
    "throttle_all": "topbar#throttle-all",
    "preferences": "user-menu#preferences",
}
"""The non-page homes of DESIGN.md section 9: the top bar dialogs and the user menu's preferences dialog."""

COMPARE_LABELS: Final[dict[str, str]] = {
    "none": "",
    "previous": "the previous period",
    "week": "the same period last week",
    "month": "the same period last month",
    "year": "the same period last year",
}
RANGE_LABELS: Final[dict[str, str]] = {
    "live": "Last 15 minutes",
    "1h": "Last hour",
    "6h": "Last 6 hours",
    "24h": "Last 24 hours",
    "7d": "Last 7 days",
    "30d": "Last 30 days",
    "90d": "Last 90 days",
    "1y": "Last year",
    "all": "All time",
    "custom": "Custom range",
}
TIME_PARAMS: Final[tuple[str, ...]] = ("range", "from", "to", "granularity", "compare")
MAX_PARAM_CHARS: Final = common.MAX_TIME_TEXT


# ============================================================================================ time


@dataclass(frozen=True, slots=True)
class PageTime:
    """The time range of a page: the resolved `TimeRange`, what the top bar shows, and the URL parameters that
    carry it to fragments and API calls (only the ones that differ from the defaults)."""

    tr: TimeRange
    view: dict[str, Any]
    params: dict[str, str] = field(default_factory=dict)
    notice: str | None = None

    def query(self, **extra: Any) -> str:
        """`range=7d&compare=previous&...` plus `extra` (values None or "" left out)."""
        values: dict[str, Any] = {**self.params, **extra}
        return urlencode({k: v for k, v in values.items() if v is not None and v != ""})


def _raw(query: Mapping[str, str], name: str) -> str | None:
    value = query.get(name)
    if value is None:
        return None
    return value.strip()[:MAX_PARAM_CHARS] or None


def resolve_time(
    query: Mapping[str, str],
    *,
    now: float,
    tz: str,
    earliest: float | None = None,
    default_range: str = DEFAULT_RANGE,
    default_compare: str = "none",
) -> PageTime:
    """The page's time range from its URL (see the module docstring); never raises for a bad value."""
    params = RangeParams(
        range=_raw(query, "range") or default_range,
        start=_raw(query, "from"),
        end=_raw(query, "to"),
        granularity=_raw(query, "granularity") or "auto",
        compare=_raw(query, "compare") or default_compare,
    )
    notice = None
    try:
        tr = common.build_time_range(params, now=now, tz=tz, earliest=earliest)
    except common.ApiError as error:
        details = "; ".join(f"{name}: {message}" for name, message in error.error_fields.items())
        notice = (
            f"The time range in the address was not valid ({details or error.error_message}), so the last 24 "
            "hours are shown."
        )
        params = RangeParams()
        tr = common.build_time_range(params, now=now, tz=tz, earliest=earliest)
    used: dict[str, str] = {}
    if params.range != DEFAULT_RANGE or _raw(query, "range"):
        used["range"] = params.range
    if params.range == "custom":
        used["from"] = params.start or ""
        used["to"] = params.end or ""
    if params.granularity != "auto":
        used["granularity"] = params.granularity
    if params.compare != "none":
        used["compare"] = params.compare
    label = RANGE_LABELS.get(params.range, params.range)
    if params.range == "custom":
        start = fmt.local_time(tr.window.start, tz, seconds=False)
        label = f"{start} to {fmt.local_time(tr.window.end, tz, seconds=False)}"
    compare_text = COMPARE_LABELS.get(params.compare or "none", "")
    view = {
        "range": params.range,
        "compare": params.compare or "none",
        "from": params.start or "",
        "to": params.end or "",
        "granularity": params.granularity,
        "label": label,
        "compare_label": compare_text,
        "description": f"{label}, compared with {compare_text}" if compare_text else label,
        "notice": notice,
        "tz": tz,
    }
    return PageTime(tr=tr, view=view, params=used, notice=notice)


# ============================================================================================ reads


@dataclass(slots=True)
class ShellFacts:
    """What one page render reads for the shell (two database reads)."""

    pause: PauseState
    throttle_all: ThrottleAllState
    pref_rows: dict[str, tuple[Any, int]]
    latest: dict[str, dict[str, Any]]
    facets: list[dict[str, Any]]
    pause_drops: int | None = None
    throttle_drops: int | None = None
    earliest: float | None = None


def shell_setting_keys() -> list[str]:
    return sorted({spec.key for anchor in TOPBAR_SETTING_ANCHORS.values() for spec in registry.settings_for(anchor)})


async def read_facts(
    ctx: Any, user_id: int, *, extra_keys: Sequence[str] = (), want_earliest: bool = False
) -> ShellFacts:
    """The shell's control.db and metrics.db facts (one read each); `extra_keys` adds settings whose last change
    the page's cards show (so a page with inline settings does not need a read of its own)."""
    keys = [*shell_setting_keys(), *extra_keys]

    def control(conn: Any) -> tuple[Any, Any, dict[str, tuple[Any, int]], dict[str, dict[str, Any]]]:
        return (
            read_state_value(conn, PAUSE_KEY),
            read_state_value(conn, THROTTLE_ALL_KEY),
            prefs.read_rows(conn, user_id),
            inline.read_latest(conn, keys),
        )

    raw_pause, raw_throttle, pref_rows, latest = await ctx.dbs.control.read(control)
    pause = PauseState.from_json(raw_pause)
    throttle_all = ThrottleAllState.from_json(raw_throttle)
    now = ctx.clock.now()
    pause_since = pause.active_since(now)
    throttle_since = throttle_all.since if throttle_all.enabled else 0.0

    def metrics(conn: Any) -> tuple[list[dict[str, Any]], int | None, int | None, float | None]:
        rows = read_recommendations.facets(conn)
        p = queries.drops_since(conn, "paused", pause_since, now) if pause_since > 0 else None
        t = queries.drops_since(conn, "throttle_all", throttle_since, now) if throttle_since > 0 else None
        e = queries.earliest_data(conn) if want_earliest else None
        return rows, p, t, e

    facets, pause_drops, throttle_drops, earliest = await ctx.dbs.metrics.read(metrics)
    return ShellFacts(pause, throttle_all, pref_rows, latest, facets, pause_drops, throttle_drops, earliest)


def bell_counts(facets: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    """Open and critical recommendation counts for the bell (the API's `_counts` over the same facet rows)."""
    open_count = sum(int(row["count"]) for row in facets if row.get("state") == "open")
    critical = sum(
        int(row["count"]) for row in facets if row.get("state") == "open" and row.get("severity") == "critical"
    )
    return {"open": open_count, "critical": critical}


# ============================================================================================ the context


def stream_url(events: Sequence[str]) -> str:
    wanted = ",".join(dict.fromkeys(events))
    return f"{API_PREFIX}/stream?{urlencode({'events': wanted})}" if wanted else ""


def shell_urls(events: Sequence[str]) -> dict[str, Any]:
    """The URLs the shell's scripts and dialogs call (base.html contract `urls`)."""
    return {
        "pause": f"{API_PREFIX}/protection/pause",
        "throttle_all": f"{API_PREFIX}/protection/throttle-all",
        "stream": stream_url(events),
        "palette": "/admin/ui/palette",
        "status": "/admin/ui/status",
        "health_run": f"{API_PREFIX}/health/runs",
        "health_page": "/admin/health",
        "llm_export": {
            "copy": f"{API_PREFIX}/export/llm?format=text",
            "download": f"{API_PREFIX}/export/llm?download=true",
            "schema": f"{API_PREFIX}/export/llm/schema",
        },
        "logout": f"{API_PREFIX}/auth/logout",
        "prefs": f"{API_PREFIX}/prefs",
        "reauth": f"{API_PREFIX}/auth/reauth",
        "session": f"{API_PREFIX}/auth/session",
    }


def status_view(ctx: Any, facts: ShellFacts, *, tz: str) -> dict[str, Any]:
    """The `status` context of banners.html, topbar.html and control_dialogs.html."""
    settings = ctx.settings
    now = ctx.clock.now()
    pause, throttle_all = facts.pause, facts.throttle_all
    paused = pause.active(now)
    since = pause.active_since(now) if paused else 0.0
    limit_since = throttle_all.since if throttle_all.enabled else 0.0
    return {
        "paused": paused,
        "paused_since": fmt.since_text(since, now, tz),
        "paused_since_iso": fmt.iso(since),
        "pause_reason": pause.reason,
        "pause_drops": facts.pause_drops or 0,
        "scheduled": pause.scheduled_start is not None and pause.scheduled_end is not None,
        "throttle_all": throttle_all.enabled,
        "throttle_all_since": fmt.since_text(limit_since, now, tz),
        "throttle_all_since_iso": fmt.iso(limit_since),
        "throttle_limit": int(settings.int("global_throttle_limit")),
        "throttle_period": int(settings.int("global_throttle_period")),
        "throttle_reason": throttle_all.reason,
        "throttle_drops": facts.throttle_drops or 0,
        "signature": f"p{int(paused)}t{int(throttle_all.enabled)}",
        **caller_texts(pause, throttle_all, now=now, pause_message_default=settings.get("pause_message_default")),
    }


def glossary_of(request: Request) -> dict[str, GlossaryEntry]:
    """The glossary loaded at startup (`GLOSSARY_STATE`), or loaded now in an app whose lifespan did not run."""
    loaded = getattr(request.app.state, GLOSSARY_STATE, None)
    if isinstance(loaded, dict):
        return loaded
    return load_glossary()


def display_tz(ctx: Any, pref_values: Mapping[str, Any]) -> str:
    """The zone times are shown in: the admin's own `timezone` preference, else the `ui_timezone` setting."""
    chosen = str(pref_values.get("timezone") or "")
    return chosen or str(ctx.settings.get("ui_timezone") or "UTC")


@dataclass(slots=True)
class Shell:
    """A built shell: the template context plus the parts page routes reuse (time, preferences, facts)."""

    context: dict[str, Any]
    time: PageTime
    prefs: dict[str, Any]
    facts: ShellFacts
    tz: str


async def build_shell(
    request: Request,
    principal: AdminPrincipal,
    spec: registry.PageSpec,
    *,
    stream_events: Sequence[str] = DEFAULT_STREAM_EVENTS,
    extra_setting_keys: Sequence[str] = (),
    default_range: str | None = None,
) -> Shell:
    """The base.html context for `spec` (see the module docstring). `default_range` overrides the admin's preference
    for a page that opens with another range when its URL names none (the Audit page shows the whole log)."""
    ctx = get_ctx(request)
    query = request.query_params
    want_earliest = (query.get("range") or "") == "all"
    facts = await read_facts(ctx, principal.user_id, extra_keys=extra_setting_keys, want_earliest=want_earliest)
    settings = ctx.settings
    pref_values = prefs.effective(facts.pref_rows, default_theme=prefs.default_theme_of(settings))
    opening_range = default_range or str(pref_values.get("default_range") or DEFAULT_RANGE)
    if not want_earliest and opening_range == "all" and not query.get("range"):
        facts.earliest = await ctx.dbs.metrics.read(queries.earliest_data)
    window_tz = str(settings.get("ui_timezone") or "UTC")
    time = resolve_time(
        query,
        now=ctx.clock.now(),
        tz=window_tz,
        earliest=facts.earliest,
        default_range=opening_range,
        default_compare=str(pref_values.get("compare") or "none"),
    )
    tz = display_tz(ctx, pref_values)
    snapshot = settings.snapshot()
    dialog_settings = {
        name: inline.card_settings(anchor, snapshot, facts.latest, tz=tz, prefix=f"set-{name.replace('_', '-')}")
        for name, anchor in TOPBAR_SETTING_ANCHORS.items()
    }
    context: dict[str, Any] = {
        "page": {
            "id": spec.id,
            "title": spec.title,
            "purpose": spec.purpose,
            "how_to_read": spec.how_to_read,
        },
        "admin": {"username": principal.username},
        "csrf_token": masked_csrf(request) or "",
        "session": {
            "heartbeat_s": int(settings.int("admin_heartbeat_interval_s")),
            "activity_window_s": int(settings.int("admin_activity_window_s")),
            "heartbeat_url": f"{API_PREFIX}/auth/heartbeat",
            "login_url": "/admin",
        },
        "theme": pref_values.get("theme") or "dark",
        "density": pref_values.get("density") or "comfortable",
        "prefs": pref_values,
        "time": time.view,
        "status": status_view(ctx, facts, tz=tz),
        "recs": bell_counts(facts.facets),
        "urls": shell_urls(stream_events),
        "glossary": glossary_of(request),
        "dialog_settings": dialog_settings,
        "env_name": str(getattr(ctx.env, "env", "production")),
        "version": __version__,
        "tz": tz,
        "now": ctx.clock.now(),
    }
    return Shell(context=context, time=time, prefs=pref_values, facts=facts, tz=tz)


async def status_signature(ctx: Any) -> dict[str, Any]:
    """`{paused, throttle_all, signature}` for `GET /admin/ui/status` (the shell's change check)."""

    def control(conn: Any) -> tuple[Any, Any]:
        return read_state_value(conn, PAUSE_KEY), read_state_value(conn, THROTTLE_ALL_KEY)

    raw_pause, raw_throttle = await ctx.dbs.control.read(control)
    paused = PauseState.from_json(raw_pause).active(ctx.clock.now())
    limited = ThrottleAllState.from_json(raw_throttle).enabled
    return {"paused": paused, "throttle_all": limited, "signature": f"p{int(paused)}t{int(limited)}"}


async def load_glossary_into(app: Any) -> dict[str, GlossaryEntry]:
    """Load the glossary on a thread and keep it on `app.state` (raises FileNotFoundError when it is missing)."""
    entries = await asyncio.to_thread(load_glossary)
    setattr(app.state, GLOSSARY_STATE, entries)
    return entries


__all__ = [
    "COMPARE_LABELS",
    "DEFAULT_STREAM_EVENTS",
    "GLOSSARY_STATE",
    "RANGE_LABELS",
    "TIME_PARAMS",
    "TOPBAR_SETTING_ANCHORS",
    "PageTime",
    "Shell",
    "ShellFacts",
    "bell_counts",
    "build_shell",
    "display_tz",
    "glossary_of",
    "load_glossary_into",
    "read_facts",
    "resolve_time",
    "shell_setting_keys",
    "shell_urls",
    "status_signature",
    "status_view",
    "stream_url",
]
