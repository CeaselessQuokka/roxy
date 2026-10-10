"""The System page (`/admin/system`, plan 14.1; parity rows 3, 16, 72, 84, 85, 121, 122): workers, the leader, jobs,
the metrics pipeline, persistence, the error log, versions, the environment and the forced flush.

What this is
    One card per registry card, each reading the same function its `GET /admin/api/v1/system/...` route calls:
      * `fleet`: the worker fleet of parity row 84 (both colors during a deploy, Expected against Count per color,
        service and host uptime, the time since the last deploy switch, fleet memory, tarpit connection use) and the
        workers table (`workers`, the v1 Workers card with its hints) with "Reset request counts" (row 122).
      * `leader`: who leads (the hot.db lease), its epoch, and this worker's view.
      * `jobs`: every scheduled job with its last run, and the WAL checkpoint durations.
      * `metrics-pipeline`: this worker's metrics queue, drops and flushes, every worker's drops in the last hour, the
        database writers; plus the catalog settings placed here.
      * `persistence`: database and WAL files with each writer's health (row 85), 30 days of disk growth as a chart
        with its data table, and the largest tables.
      * `errors`: the error log (v1 Error Log, rows 16 and 72; the page's main table: search, source filter, sorting
        and paging in the address bar); a row opens its traceback in the drawer.
      * `alerts`: which alert channels are configured (credential names only), plus the alert settings.
      * `versions`, `environment`: what runs, and the non-secret startup facts.
      * `flush`: the forced flush (row 121, v1's "Refresh" with `?flush=1`).

Why it exists
    v1's Service Health and Error Log sections live here (plan 14.1 map rows 3, 31, 34, 37). Plan P6: every number is
    the API's own (`roxy/admin/api/system.py`), labeled with where it comes from (fleet-wide from shared state, or
    "this worker"). Health checks link to `/admin/system#workers`, `#storage`, `#jobs` and `#errors`; each lands on
    the element of that name.

How it works
    Cards render concurrently; the heavier ones are lazy. The two actions post to the admin API: "Reset request
    counts" through a confirm dialog (`POST /system/workers/reset-counts`), the flush through a form
    (`POST /system/flush`). The workers table is a second table on the page (`address=False`); the errors table is
    the main one. A table's own request (htmx names the table as its target) gets only the table back, so its swap
    never nests a card. Text a caller may have chosen (error signatures, details, tracebacks, where an error was
    raised) is rendered by `format.html caller_text`.

What to read next
    `roxy/admin/api/system.py`, `templates/admin/pages/system.html`, `roxy/scheduler/read_fleet.py`.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any, Final

from roxy.admin.api import common
from roxy.admin.api import system as system_api
from roxy.admin.pages.kit import Page, PageView, filter_chip, table_query, table_view

page = Page("system")
router = page.router

WORKERS_TABLE_ID: Final = "workers"
"""The workers table's element id: health checks link to `/admin/system#workers`."""
ERRORS_TABLE_ID: Final = "error-log"
WORKER_COLUMNS: Final = (
    "pid",
    "color",
    "is_leader",
    "fresh",
    "uptime_s",
    "rss_bytes",
    "requests",
    "proxied",
    "loop_lag_ms_p99",
    "open_connections",
    "inflight_upstream",
    "max_requests",
    "counters_reset_at",
    "last_seen",
    "version",
    "is_this_worker",
)
WORKER_KEYS: Final = ("pid", "color", "uptime_s", "rss_bytes")
WORKER_HIDDEN: Final = ("max_requests", "counters_reset_at", "version", "is_this_worker", "inflight_upstream")
ERROR_COLUMNS: Final = ("signature", "count", "source", "last_seen", "first_seen", "module_line", "last_detail")
ERROR_KEYS: Final = ("signature", "count", "last_seen")
ERROR_HIDDEN: Final = ("first_seen", "module_line")
SOURCE_TONES: Final[dict[str, str]] = {"roblox": "warn", "internal": "info"}
"""v1's source badges: Roblox warn, Internal muted (info here), anything else (Roxy's own) bad."""
MAX_TABLE_SIZES: Final = 15
CHANNEL_CREDENTIALS: Final[dict[str, tuple[str, ...]]] = {
    "email": ("smtp_password", "alert_emails"),
    "webhook": ("alert_webhook_url",),
}
"""The systemd credentials each alert channel needs (plan 9.8; names only, never a value)."""


# ============================================================================================ formatting


def duration_text(seconds: Any) -> str:
    """`5400` -> `1h 30m` (the rules of `format.html duration`)."""
    if not isinstance(seconds, int | float):
        return "n/a"
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m" + (f" {s % 60}s" if s % 60 else "")
    if s < 86_400:
        return f"{s // 3600}h" + (f" {(s % 3600) // 60}m" if (s % 3600) // 60 else "")
    return f"{s // 86_400}d" + (f" {(s % 86_400) // 3600}h" if (s % 86_400) // 3600 else "")


def bytes_text(value: Any) -> str:
    """`67108864` -> `64.0 MiB` (the rules of `format.html bytes`: binary units, one decimal)."""
    if not isinstance(value, int | float):
        return "n/a"
    if value < 1024:
        return f"{value:,.0f} B"
    for unit, size in (("KiB", 1024), ("MiB", 1024**2), ("GiB", 1024**3)):
        if value < size * 1024:
            return f"{value / size:.1f} {unit}"
    return f"{value / 1024**4:.1f} TiB"


def stable_id(text: Any) -> str:
    """A short id for a row from its text (the same in every worker, unlike `hash()`)."""
    return hashlib.sha256(str(text).encode("utf-8", "replace")).hexdigest()[:12]


def _is_table_request(view: PageView, table_id: str) -> bool:
    """True when htmx asks for one table of a card (its own sort, page or filter request), not the whole card."""
    return view.in_fragment and view.request.headers.get("HX-Target") == table_id


# ============================================================================================ fleet


def _worker_cells(view: PageView) -> Any:
    def cells(item: Mapping[str, Any]) -> dict[str, Any]:
        lag = item.get("loop_lag_ms_p99")
        return {
            "pid": {
                "text": str(item.get("pid")),
                "mono": True,
                "sub": "serving you" if item.get("is_this_worker") else None,
            },
            "color": item.get("color") or None,
            "is_this_worker": "Yes" if item.get("is_this_worker") else "No",
            "is_leader": {"text": "Leader", "tone": "info"} if item.get("is_leader") else "No",
            "fresh": {"text": "Fresh", "tone": "ok"} if item.get("fresh") else {"text": "Stale", "tone": "bad"},
            "uptime_s": duration_text(item.get("uptime_s")) if item.get("uptime_s") is not None else None,
            "rss_bytes": bytes_text(item.get("rss_bytes")) if item.get("rss_bytes") is not None else None,
            "loop_lag_ms_p99": f"{float(lag):,.1f} ms" if isinstance(lag, int | float) else None,
            "counters_reset_at": view.time_cell(item.get("counters_reset_at")),
            "last_seen": view.time_cell(item.get("last_seen")),
            "version": {"text": item.get("version"), "mono": True} if item.get("version") else None,
        }

    return cells


def fleet_facts(data: Mapping[str, Any]) -> dict[str, Any]:
    """The fleet header from a `fleet` answer: this color, the other colors, totals and warnings in plain words."""
    colors = list(data.get("colors") or [])
    mine = next((c for c in colors if c.get("is_this_color")), colors[0] if colors else None)
    warnings = []
    for color in colors:
        if color.get("short"):
            warnings.append(
                f"The {color['color']} color runs {color['count']} of the {color['expected']} workers it should; "
                "a worker that stopped is restarted by gunicorn, so a lasting shortfall needs a look at the journal."
            )
        if color.get("stale"):
            warnings.append(
                f"{color['stale']} {color['color']} worker rows are stale (no heartbeat for 20 s): a stopped or frozen "
                "worker. A stale row disappears once the heartbeat table is pruned."
            )
    return {
        "mine": mine,
        "colors": colors,
        "deploying": bool(data.get("deploying")),
        "warnings": warnings,
    }


@page.card("fleet")
async def fleet_card(view: PageView) -> dict[str, Any]:
    """The fleet header and the workers table (`fleet` and `workers_table`, the API's own functions)."""
    data = await system_api.fleet(view.ctx)
    tq, notice = table_query(view, system_api.WORKERS_TABLE, address=False)
    answer = system_api.workers_table(data, tq)
    table = table_view(
        view,
        WORKERS_TABLE_ID,
        system_api.WORKERS_TABLE,
        answer,
        src=view.fragment_url("fleet"),
        columns=WORKER_COLUMNS,
        key_columns=WORKER_KEYS,
        hidden=WORKER_HIDDEN,
        cells=_worker_cells(view),
        row_id=lambda item: f"worker-{item.get('pid')}-{item.get('color')}",
        export_url=view.api_url("system/workers", time=False),
        caption="Workers",
        empty={
            "title": "No workers have reported in yet",
            "body": "Each worker writes a heartbeat every few seconds; the first one appears within 5 seconds of "
            "starting.",
            "icon": "server",
        },
        search_placeholder="Search by pid, color or version",
        notice=notice,
        address=False,
    )
    max_requests = next((w.get("max_requests") for w in data.get("workers") or () if w.get("max_requests")), None)
    return {
        "table": table,
        "table_only": _is_table_request(view, WORKERS_TABLE_ID),
        "fleet": data,
        "facts": fleet_facts(data),
        "max_requests": max_requests,
        "reset_url": f"{common.API_PREFIX}/system/workers/reset-counts",
    }


# ============================================================================================ leader, jobs


@page.card("leader")
async def leader_card(view: PageView) -> dict[str, Any]:
    """Who leads, from the hot.db lease (`leader_state`)."""
    state = await system_api.leader_state(view.ctx)
    mine = state["this_worker"]
    return {
        "state": state,
        "holder_is_me": state.get("holder") == mine.get("worker_id"),
        "since": view.time_cell(mine.get("since")),
    }


@page.card("jobs", lazy=True)
async def jobs_card(view: PageView) -> dict[str, Any]:
    """Every scheduled job and the checkpoint durations (`jobs_view`)."""
    answer = await system_api.jobs_view(view.ctx)
    rows = []
    for job in answer["jobs"]:
        last = job.get("last_finished_at") or job.get("last_started_at")
        rows.append({**job, "last": view.time_cell(last), "every": duration_text(job.get("interval_s"))})
    checkpoints = [
        {"name": name, **item, "finished": view.time_cell(item.get("last_finished_at"))}
        for name, item in (answer.get("checkpoints") or {}).items()
    ]
    return {"answer": answer, "jobs": rows, "checkpoints": checkpoints}


# ============================================================================================ pipeline, persistence


@page.card("metrics-pipeline", lazy=True)
async def pipeline_card(view: PageView) -> dict[str, Any]:
    """This worker's metrics queue and drops, the fleet's drops, the database writers (`pipeline_view`)."""
    answer = await system_api.pipeline_view(view.ctx)
    recorder = answer.get("recorder") or {}
    batch = recorder.get("batch") or {}
    drops = answer.get("fleet_drops_last_hour") or {}
    dropped = int(drops.get("dropped") or 0) + int(drops.get("history_dropped") or 0)
    return {
        "answer": answer,
        "recorder": recorder,
        "batch": batch,
        "last_flush": view.time_cell(batch.get("last_flush_at")),
        "drops": drops,
        "fleet_dropped": dropped,
        "databases": answer.get("databases") or [],
    }


def growth_series(growth: list[Mapping[str, Any]] | None, tz: str) -> dict[str, Any] | None:
    """The disk samples as an admin API series answer (`components/chart.html series_chart(series=...)`)."""
    if not growth:
        return None
    first, last = int(growth[0]["at"]), int(growth[-1]["at"])
    return {
        "range": {"from": first, "to": last, "granularity": "hour", "tz": tz},
        "series": [
            {
                "key": "storage_bytes",
                "label": "Roxy's storage",
                "unit": "bytes",
                "points": [[int(s["at"]), int(s.get("total_bytes") or 0)] for s in growth],
            },
            {
                "key": "free_bytes",
                "label": "Free disk",
                "unit": "bytes",
                "points": [[int(s["at"]), int(s.get("free_bytes") or 0)] for s in growth],
            },
        ],
        "compare": None,
        "annotations": [],
        "notices": [],
    }


@page.card("persistence", lazy=True)
async def persistence_card(view: PageView) -> dict[str, Any]:
    """Database files, writer health, disk growth and the largest tables (`persistence_view`)."""
    answer = await system_api.persistence_view(view.ctx)
    databases = answer.get("databases") or []
    problems = [db["db"] for db in databases if int(db.get("write_errors") or 0) or int(db.get("unavailable") or 0)]
    tables = (answer.get("table_sizes") or {}).get("tables") or {}
    largest = sorted(tables.items(), key=lambda item: int(item[1] or 0), reverse=True)[:MAX_TABLE_SIZES]
    sampled = (answer.get("table_sizes") or {}).get("at")
    return {
        "answer": answer,
        "databases": databases,
        "problems": problems,
        "series": growth_series(answer.get("growth"), view.tz),
        "largest": largest,
        "tables_count": len(tables),
        "tables_sampled": view.time_cell(sampled),
    }


# ============================================================================================ errors


def _error_cells(view: PageView) -> Any:
    def cells(item: Mapping[str, Any]) -> dict[str, Any]:
        source = str(item.get("source") or "roxy")
        return {
            "signature": {"text": item.get("signature"), "caller": True, "mono": True},
            "source": {"text": source.capitalize(), "tone": SOURCE_TONES.get(source.lower(), "bad")},
            "first_seen": view.time_cell(item.get("first_seen")),
            "last_seen": view.time_cell(item.get("last_seen")),
            "module_line": {"text": item.get("module_line"), "caller": True, "mono": True}
            if item.get("module_line")
            else None,
            "last_detail": {"text": item.get("last_detail"), "caller": True} if item.get("last_detail") else None,
        }

    return cells


@page.card("errors")
async def errors_card(view: PageView) -> dict[str, Any]:
    """The error log (`errors_answer`), or one signature in detail for the drawer (`error_detail_view`)."""
    signature = view.param("signature", max_chars=300) if view.in_fragment else ""
    if signature:
        found = await system_api.error_detail_view(view.ctx, signature)
        if found is None:
            raise common.not_found("No error has that signature now; a data reset of the errors may have cleared it.")
        hourly = found.get("hourly") or []
        return {
            "detail": found,
            "first": view.time_cell(found.get("first_seen")),
            "last": view.time_cell(found.get("last_seen")),
            "hourly": [{"at": view.time_cell(at), "count": count} for at, count in hourly],
            "hourly_values": [count for _at, count in hourly],
        }
    tq, notice = table_query(view, system_api.ERRORS_TABLE)
    source = view.state_param("source", max_chars=64) or None
    answer = await system_api.errors_answer(view.ctx, tq, source=source)
    sources = [str(s) for s in answer.get("sources") or ()]
    options = [("", "Any source"), *((s, s.capitalize()) for s in sources)]
    if source and source not in sources:
        options.insert(1, (source, source))
    table = table_view(
        view,
        ERRORS_TABLE_ID,
        system_api.ERRORS_TABLE,
        answer,
        src=view.fragment_url("errors"),
        columns=ERROR_COLUMNS,
        key_columns=ERROR_KEYS,
        hidden=ERROR_HIDDEN,
        cells=_error_cells(view),
        row_id=lambda item: f"error-{stable_id(item.get('signature'))}",
        drawer=lambda item: view.fragment_url("errors", signature=item.get("signature")),
        drawer_title=lambda item: "Error details",
        filters=[filter_chip("source", "Source", source or "", options)],
        export_url=view.api_url("system/errors", time=False),
        caption="Error log",
        empty={
            "title": "No errors match the filter" if (tq.q or source) else "No errors recorded",
            "body": "Clear the search or the source filter to see every error."
            if (tq.q or source)
            else "Errors appear here when a request or a job fails inside Roxy, grouped by signature with how often "
            "each happened. Nothing is dropped as more come in.",
            "icon": "check-circle" if not (tq.q or source) else "inbox",
            "tone": "good" if not (tq.q or source) else "neutral",
        },
        search_placeholder="Search errors",
        notice=notice,
    )
    return {
        "table": table,
        "table_only": _is_table_request(view, ERRORS_TABLE_ID),
        "total": answer["total"],
        "filtered": bool(tq.q or source),
    }


# ============================================================================================ alerts, versions, env


@page.card("alerts", lazy=True)
async def alerts_card(view: PageView) -> dict[str, Any]:
    """Which alert channels have their credentials (names only, `environment_view`), beside the alert settings."""
    environment = await system_api.environment_view(view.ctx)
    present = environment.get("credentials_present") or {}
    channels = [
        {
            "name": name,
            "configured": all(bool(present.get(credential)) for credential in credentials),
            "credentials": credentials,
        }
        for name, credentials in CHANNEL_CREDENTIALS.items()
    ]
    webhook_on = bool(view.ctx.settings.get("alert_webhook_enabled"))
    return {"channels": channels, "webhook_on": webhook_on}


@page.card("versions", lazy=True)
async def versions_card(view: PageView) -> dict[str, Any]:
    """What runs (`versions_view`): the release, Python, SQLite, libraries, catalog and schema versions."""
    answer = await system_api.versions_view(view.ctx)
    schema = [
        {"db": name, "version": version, "required": answer["schema_required"].get(name)}
        for name, version in (answer.get("schema") or {}).items()
    ]
    return {"answer": answer, "schema": schema, "mixed": len(answer.get("fleet_versions") or {}) > 1}


@page.card("environment", lazy=True)
async def environment_card(view: PageView) -> dict[str, Any]:
    """The non-secret startup facts and which credentials exist, by name (`environment_view`)."""
    return {"env": await system_api.environment_view(view.ctx)}


@page.card("flush")
async def flush_card(view: PageView) -> dict[str, Any]:
    """The forced flush form (`POST /system/flush`)."""
    interval = view.ctx.settings.get("metrics_flush_interval_ms")
    return {"flush_url": f"{common.API_PREFIX}/system/flush", "interval_ms": interval}


__all__ = ["bytes_text", "duration_text", "fleet_facts", "growth_series", "page", "router", "stable_id"]
