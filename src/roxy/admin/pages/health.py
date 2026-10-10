"""The Health page (`/admin/health`, plan 14.1, 13.1 to 13.3): run Check Proxy Health, watch it, compare runs.

What this is
    Four cards from the page registry:
      * `run`: the Run button (with the choice to include the credential check, which spends one call on the Roblox
        account and so needs a fresh second factor, plan 13.3), and the run view: the newest run (or the one named by
        `?run=<id>`) as a checklist in plan 13.2 order, each check with its status in words, measured value,
        threshold, explanation, detail (H-CLOCK's queue wait and call time among them), the fix link, "Apply fix"
        when a recommendation is linked, and "Copy for LLM"; while a run is running the checks still to come show
        as waiting and the card follows the run live over the event stream (static/js/pages/health.js). Under it:
        what changed since the run before, a "compare with" choice (`?with=<id>`) for any earlier run, and the
        exports (JSON, the printable report, the whole run for an LLM).
      * `checks`: the catalog: every check, what it measures, how it is judged and where its fix is.
      * `history`: every run (the page's main table) with filters, export and a link to open each one.
      * `schedule`: automatic runs (the `health#schedule` catalog settings, placed below the body) with the last and
        the next scheduled run.

Why it exists
    Plan 13.1: one click runs every check, results stream in, runs are stored, compared and exported; plan 14.8: the
    owner runs it from a phone. Page routes only read: the Run button posts to `POST /admin/api/v1/health/runs` and
    the exports are the API's (audited) downloads. Plan P6: every card reads through the Health API's own functions
    (`run_answer`, `latest_run_id`, `compare_answer`, `runs_table`, `run_filters`, `checks_catalog`).

How it works
    `page = Page("health", default_range="all")`: the history opens on every run; another range filters runs by
    their start. The run card's renderer reads one run (results, linked recommendations and the comparison) and, for
    a running run, the planned check list (`health.checks.expand`, the runner's own plan) to show what is still to
    come. Check explanations and values are Roxy's own words, but a value can quote an address or a host, and fix
    links go through `local_href`.

What to read next
    `roxy/admin/api/health.py`, `roxy/health/store.py`, `roxy/health/checks.py`, `templates/admin/pages/health/*.html`,
    `static/js/pages/health.js`.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final
from urllib.parse import urlencode

from roxy.admin.api import common
from roxy.admin.api import health as health_api
from roxy.admin.api.common import API_PREFIX, TableQuery
from roxy.admin.pages import fmt
from roxy.admin.pages.kit import Page, PageView, filter_chip, table_query, table_view
from roxy.health import checks
from roxy.health import store as health_store
from roxy.health.model import TRIGGERS

page = Page("health", stream_events=("settings_changed", "recommendation", "alert", "health"), default_range="all")
router = page.router

PAGE_PATH: Final = "/admin/health"
HISTORY_TABLE_ID: Final = "health-history"
RUN_EXPORT: Final = f"{API_PREFIX}/health/runs/{{run_id}}/export"
MAX_COMPARE_CHOICES: Final = 25
MAX_DETAIL_ITEMS: Final = 24

STATUS_WORDS: Final[dict[str, tuple[str, str, str]]] = {
    "pass": ("ok", "Pass", "check-circle"),
    "warn": ("warn", "Warn", "alert-triangle"),
    "fail": ("bad", "Fail", "alert-octagon"),
    "n/a": ("neutral", "n/a", "minus"),
    "pending": ("info", "Waiting", "clock"),
}
"""A check status as (tone, words, icon): words and an icon beside every color (plan 14.9)."""
STATE_WORDS: Final[dict[str, str]] = {
    "running": "Running",
    "finished": "Finished",
    "interrupted": "Interrupted (its worker stopped)",
}
TRIGGER_WORDS: Final[dict[str, str]] = {
    "manual": "Started by an admin",
    "schedule": "Scheduled",
    "deploy": "After a deploy",
    "cli": "From the command line",
}
CHANGE_WORDS: Final[dict[str, tuple[str, str]]] = {
    "worse": ("bad", "Worse"),
    "better": ("ok", "Better"),
    "same": ("neutral", "Same"),
    "value_changed": ("info", "Value changed"),
    "new": ("info", "New check"),
    "missing": ("neutral", "Not in this run"),
}
HISTORY_COLUMNS: Final = (
    "id",
    "started_at",
    "worst",
    "trigger",
    "state",
    "passed",
    "warned",
    "failed",
    "not_applicable",
    "critical",
    "duration_s",
    "finished_at",
    "actor",
    "version",
)


# ============================================================================================ helpers


def run_href(run_id: Any, **params: Any) -> str:
    query = urlencode({"run": str(run_id), **{k: str(v) for k, v in params.items() if v is not None}})
    return f"{PAGE_PATH}?{query}#run"


def export_url(run_id: int, fmt_name: str, *, focus: str | None = None) -> str:
    params = {"format": fmt_name, **({"focus": focus} if focus else {})}
    return RUN_EXPORT.format(run_id=int(run_id)) + "?" + urlencode(params)


def status_view(status: Any) -> dict[str, str]:
    tone, words, icon = STATUS_WORDS.get(str(status), ("neutral", str(status or "n/a"), "minus"))
    return {"tone": tone, "words": words, "icon": icon, "raw": str(status or "")}


def duration_text(seconds: Any) -> str | None:
    if not isinstance(seconds, int | float) or seconds < 0:
        return None
    total = int(seconds)
    if total < 60:
        return f"{total} s"
    minutes, rest = divmod(total, 60)
    return f"{minutes} min {rest} s" if rest else f"{minutes} min"


def detail_items(detail: Any) -> list[tuple[str, str]]:
    """A result's `detail` as label and value pairs (`queue_wait_ms` reads "Queue wait ms")."""
    if not isinstance(detail, Mapping):
        return []
    items: list[tuple[str, str]] = []
    for key, value in list(detail.items())[:MAX_DETAIL_ITEMS]:
        label = str(key).replace("_", " ").strip().capitalize()
        if isinstance(value, bool):
            text = "yes" if value else "no"
        elif isinstance(value, float):
            text = f"{value:,.3g}" if abs(value) < 1000 else f"{value:,.0f}"
        elif isinstance(value, int):
            text = f"{value:,}"
        elif isinstance(value, str):
            text = value
        else:
            text = str(value)
        items.append((label, text[:300]))
    return items


def result_row(result: Mapping[str, Any], run_id: int | None) -> dict[str, Any]:
    """One checklist row for the template."""
    check_id = str(result.get("check_id") or "")
    status = str(result.get("status") or "")
    rec = result.get("recommendation")
    apply_fix = None
    if isinstance(rec, Mapping) and rec.get("id"):
        apply_fix = {
            "href": f"/admin/recommendations?{urlencode({'rec': str(rec['id'])})}",
            "title": str(rec.get("title") or ""),
            "rule_id": str(rec.get("rule_id") or ""),
        }
    found = checks.spec_for(check_id)
    spec = found[0] if found else None
    return {
        "check_id": check_id,
        "title": str(result.get("title") or (spec.title if spec else check_id)),
        "status": status_view(status),
        "critical": bool(result.get("critical")),
        "value": str(result.get("value") or ""),
        "threshold": str(result.get("threshold") or ""),
        "explanation": str(result.get("explanation") or (spec.explanation if spec else "")),
        "fix_link": str(result.get("fix_link") or ""),
        "fix_label": str(result.get("fix_label") or (spec.fix_label if spec else "") or "How to fix"),
        "apply_fix": apply_fix,
        "detail": detail_items(result.get("detail")),
        "duration_ms": result.get("duration_ms"),
        "llm": export_url(run_id, "llm", focus=check_id) if run_id is not None and status in ("warn", "fail") else None,
        "pending": False,
    }


def pending_rows(ctx: Any, run: Mapping[str, Any], done: set[str]) -> list[dict[str, Any]]:
    """The checks a running run has not finished yet, from the runner's own plan (`checks.expand`)."""
    options = run.get("options") or {}
    wanted = [str(c) for c in options.get("checks") or () if isinstance(c, str)]
    try:
        planned = checks.expand(ctx, wanted)
    except Exception:  # the plan reads only settings; a surprise here must not fail the page
        return []
    rows = []
    for spec, params in planned:
        check_id = spec.instance_id(params)
        if check_id in done:
            continue
        rows.append(
            {
                "check_id": check_id,
                "title": spec.title,
                "status": status_view("pending"),
                "critical": False,
                "value": "",
                "threshold": spec.thresholds,
                "explanation": spec.explanation,
                "fix_link": "",
                "fix_label": "",
                "apply_fix": None,
                "detail": [],
                "duration_ms": None,
                "llm": None,
                "pending": True,
            }
        )
    return rows


def run_view(ctx: Any, run: Mapping[str, Any], view: PageView) -> dict[str, Any]:
    """One run for the template: its facts, its checklist in plan 13.2 order and what changed since the run before."""
    run_id = int(run["id"])
    rows = [result_row(result, run_id) for result in run.get("results") or ()]
    state = str(run.get("state") or "")
    pending = pending_rows(ctx, run, {row["check_id"] for row in rows}) if state == "running" else []
    ordered = sorted([*rows, *pending], key=lambda row: checks.sort_key(row["check_id"]))
    summary = run.get("summary") or {}
    worst = summary.get("worst")
    comparison = run.get("comparison") or None
    options = run.get("options") or {}
    return {
        "id": run_id,
        "state": state,
        "state_words": STATE_WORDS.get(state, state),
        "trigger": TRIGGER_WORDS.get(str(run.get("trigger")), str(run.get("trigger") or "")),
        "actor": str(run.get("actor") or ""),
        "version": str(run.get("version") or ""),
        "started": fmt.time_cell(run.get("started_at"), view.tz, view.now),
        "finished": fmt.time_cell(run.get("finished_at"), view.tz, view.now),
        "duration": duration_text(run.get("duration_s")),
        "worst": status_view(worst) if worst else None,
        "counts": {
            "pass": int(summary.get("pass") or 0),
            "warn": int(summary.get("warn") or 0),
            "fail": int(summary.get("fail") or 0),
            "n/a": int(summary.get("n/a") or 0),
            "critical": int(summary.get("critical") or 0),
        },
        "done": len(rows),
        "planned": len(rows) + len(pending),
        "rows": ordered,
        "credential": bool(options.get("include_credential", True)),
        "comparison": comparison,
        "exports": {
            "json": export_url(run_id, "json"),
            "html": export_url(run_id, "html"),
            "llm": export_url(run_id, "llm"),
        },
    }


def comparison_rows(found: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for change in found.get("changes") or ():
        if not isinstance(change, Mapping):
            continue
        tone, words = CHANGE_WORDS.get(str(change.get("change")), ("neutral", str(change.get("change"))))
        before = change.get("before") or {}
        after = change.get("after") or {}
        spec = checks.spec_for(str(change.get("check_id") or ""))
        rows.append(
            {
                "check_id": str(change.get("check_id") or ""),
                "title": spec[0].title if spec else str(change.get("check_id") or ""),
                "tone": tone,
                "words": words,
                "change": str(change.get("change") or ""),
                "before": status_view(before.get("status")) if before else None,
                "before_value": str(before.get("value") or "") if before else "",
                "after": status_view(after.get("status")) if after else None,
                "after_value": str(after.get("value") or "") if after else "",
            }
        )
    order = {"worse": 0, "new": 1, "value_changed": 2, "better": 3, "missing": 4, "same": 5}
    return sorted(rows, key=lambda row: (order.get(row["change"], 9), checks.sort_key(row["check_id"])))


# ============================================================================================ the run card


@page.card("run")
async def run_card(view: PageView) -> dict[str, Any]:
    """The Run button and the run view (`run_answer`, `latest_run_id`, `compare_answer`: the API's own functions)."""
    ctx = view.ctx
    notices: list[str] = []
    raw = view.param("run", max_chars=20)
    run_id: int | None = None
    pinned = False
    if raw:
        if raw.isdigit() and 1 <= int(raw) <= common.MAX_ROW_ID:
            run_id, pinned = int(raw), True
        else:
            notices.append("That run number is not valid; the newest run is shown.")
    if run_id is None:
        run_id = await health_api.latest_run_id(ctx)
    run = None
    if run_id is not None:
        try:
            run = await health_api.run_answer(ctx, run_id)
        except common.ApiError:
            notices.append(f"No health run has the number {run_id}; it may have been pruned. The newest run is shown.")
            pinned = False
            latest = await health_api.latest_run_id(ctx)
            run = await health_api.run_answer(ctx, latest) if latest is not None else None
    shown = run_view(ctx, run, view) if run is not None else None
    compare = None
    choices: list[dict[str, Any]] = []
    if shown is not None:
        listing = await health_api.runs_table(
            ctx, health_store.RunFilter(), TableQuery(page=1, page_size=MAX_COMPARE_CHOICES, sort="started_at")
        )
        choices = [
            {
                "id": int(item["id"]),
                "label": f"Run {item['id']}, {fmt.local_time(item.get('started_at'), view.tz, seconds=False)}"
                f" ({STATUS_WORDS.get(str(item.get('worst')), ('', str(item.get('worst') or 'running'), ''))[1]})",
            }
            for item in listing["items"]
            if int(item["id"]) != shown["id"]
        ]
        other_raw = view.param("with", max_chars=20)
        if other_raw:
            if other_raw.isdigit() and 1 <= int(other_raw) <= common.MAX_ROW_ID:
                try:
                    found = await health_api.compare_answer(ctx, shown["id"], int(other_raw))
                    compare = {
                        "other": int(other_raw),
                        "rows": comparison_rows(found),
                        "new_failures": list(found.get("new_failures") or ()),
                        "fixed": list(found.get("fixed") or ()),
                        "counts": dict(found.get("counts") or {}),
                    }
                except common.ApiError as error:
                    notices.append(error.error_message)
            else:
                notices.append("That run to compare with is not valid.")
    return {
        "run": shown,
        "pinned": pinned,
        "compare": compare,
        "choices": choices,
        "notices": notices,
        "run_url": f"{API_PREFIX}/health/runs",
        "reauth_window_min": max(1, int(ctx.settings.int("admin_reauth_window_s")) // 60),
        "page_path": PAGE_PATH,
    }


# ============================================================================================ the catalog


@page.card("checks", lazy=True)
async def checks_card(view: PageView) -> dict[str, Any]:
    """Every check of plan 13.2 (`checks_catalog`, the API's own function)."""
    catalog = health_api.checks_catalog()
    hosts = [str(h) for h in (view.ctx.settings.get("allowed_roblox_hosts") or ())]
    return {"items": catalog["items"], "hosts": len(hosts)}


# ============================================================================================ history


@page.card("history")
async def history_card(view: PageView) -> dict[str, Any]:
    """Every run, newest first (`runs_table`), the page's main table."""
    tq, table_notice = table_query(view, health_api.RUNS_TABLE)
    trigger = view.state_param("trigger", max_chars=16)
    worst = view.state_param("worst", max_chars=8)
    whole = view.time.view.get("range") == "all"
    start = None if whole else str(int(view.tr.window.start))
    end = None if whole else str(int(view.tr.window.end))
    notices = [table_notice] if table_notice else []
    tz = str(view.ctx.settings.get("ui_timezone") or "UTC")
    try:
        filters = health_api.run_filters(trigger or None, worst or None, None, None, start, end, tz)
    except common.ApiError as error:
        details = "; ".join(error.error_fields.values()) or error.error_message
        notices.append(f"The filters in the address were not valid ({details}); every run is shown.")
        trigger = worst = ""
        filters = health_api.run_filters(None, None, None, None, start, end, tz)
    answer = await health_api.runs_table(view.ctx, filters, tq)

    def cells(item: Mapping[str, Any]) -> dict[str, Any]:
        worst_view = status_view(item.get("worst")) if item.get("worst") else None
        state = str(item.get("state") or "")
        return {
            "id": {"text": f"Run {item.get('id')}", "href": run_href(item.get("id"))},
            "worst": {"text": worst_view["words"], "tone": worst_view["tone"]} if worst_view else None,
            "trigger": TRIGGER_WORDS.get(str(item.get("trigger")), item.get("trigger")),
            "state": {"text": STATE_WORDS.get(state, state), "tone": "info" if state == "running" else None},
            "duration_s": duration_text(item.get("duration_s")),
            "actor": {"text": item.get("actor"), "caller": True, "limit": 80} if item.get("actor") else None,
            "version": {"text": item.get("version"), "mono": True} if item.get("version") else None,
        }

    bounds = {} if whole else {"from": start, "to": end}
    table = table_view(
        view,
        HISTORY_TABLE_ID,
        health_api.RUNS_TABLE,
        answer,
        src=view.fragment_url("history"),
        columns=HISTORY_COLUMNS,
        key_columns=("id", "started_at", "worst"),
        hidden=("finished_at", "actor", "version", "critical", "not_applicable"),
        cells=cells,
        row_id=lambda item: f"run-{item.get('id')}",
        filters=[
            filter_chip(
                "trigger", "Trigger", trigger, [("", "Any trigger"), *((t, TRIGGER_WORDS.get(t, t)) for t in TRIGGERS)]
            ),
            filter_chip(
                "worst",
                "Worst result",
                worst,
                [("", "Any result"), *((s, STATUS_WORDS[s][1]) for s in health_api.STATUSES)],
            ),
        ],
        export_url=view.api_url("health/runs", time=False, **bounds),
        caption="Health runs",
        empty={
            "title": "No health run yet" if whole else "No health run in this range",
            "body": "Press Run a health check above; every run is kept here so you can compare it with later ones. "
            "Scheduled runs appear here too.",
            "icon": "heart",
        },
        search_placeholder="Search runs",
        notice=" ".join(notices) or None,
    )
    return {"table": table, "whole": whole, "range_label": view.time.view.get("label")}


# ============================================================================================ schedule


@page.card("schedule", lazy=True)
async def schedule_card(view: PageView) -> dict[str, Any]:
    """Automatic runs: the settings (placed by the catalog), the last scheduled run and the next one."""
    settings = view.ctx.settings
    interval_h = float(settings.float("health_auto_interval_h"))
    now = view.now

    def read(conn: Any) -> tuple[int | None, list[Any]]:
        return health_store.last_started_at(conn, "schedule"), health_store.read_job_status(conn, now - 86_400)

    last, jobs = await view.ctx.dbs.metrics.read(read)
    job = next((row for row in jobs if row.name == "health_scheduled_run"), None)
    next_at = None
    if interval_h > 0:
        next_at = (last + interval_h * 3600) if last else None
    return {
        "enabled": interval_h > 0,
        "interval_h": interval_h,
        "include_credential": bool(settings.bool("health_auto_include_credential")),
        "last": fmt.since_text(last, now, view.tz) if last else None,
        "next": fmt.local_time(max(next_at, now), view.tz, seconds=False) if next_at else None,
        "job_seen": job is not None,
    }


__all__ = ["comparison_rows", "detail_items", "page", "result_row", "router", "run_view", "status_view"]
