"""Health API (`/admin/api/v1/health`): start a Check Proxy Health run, list and read runs, compare, export.

What this is
    The routes behind the Check Proxy Health button and the Health page (plan 13.1):
      * `POST /runs` starts a run (all checks, or the `checks` named) and answers 202 with its id at once; the
        results stream through the event stream (`health_run_started`, `health_result`, `health_run_finished`).
        A run that includes the credential check needs a fresh second factor (it spends a call on the account).
      * `GET /runs` lists runs (filters: trigger, worst status, a check and its status, a time span; paging and
        sorting; `format=csv` or `format=json` downloads the list, audited).
      * `GET /runs/latest` and `GET /runs/{run_id}`: one run with every result in 13.2 order, the "Apply fix"
        recommendation of each failing check, and what changed since the run before.
      * `GET /runs/{run_id}/compare?with=<id>`: check-by-check differences (default: the run before).
      * `GET /runs/{run_id}/export?format=json|html|llm`: the JSON report, the printable HTML page, or the
        "Copy run for LLM" text (the 12.5 instruction block plus the run, outside text under `untrusted`;
        `focus=<check id>` for a row's button). Every export is audited.
      * `GET /checks`: the catalog (id, title, what it measures, thresholds, fix link), for the checklist the page
        draws before results arrive.

Why it exists
    DESIGN.md section 13: one thin module per area, built on `admin/api/common.py`; the read models live next to the
    data (`roxy/health/store.py`) and the run engine in `roxy/health/runner.py`, so this module only parses, calls
    and shapes the answer.

How it works
    Every route depends on the `session` guard; the POST also on `require_csrf`, and it calls the `fresh_mfa`
    guard itself when the planned checks include H-CRED-AUTH (`ReauthRequired`, 403 `reauth_required`, until the
    admin re-enters a code). Bodies are `ApiBody` models (unknown fields refused, strings bounded). A second run
    while one is running anywhere in the fleet is 409 `run_in_progress` with the running run's id in the
    `Roxy-Health-Run` header (the page follows that run instead). Starting a run writes a `health.run` audit row;
    exports write `export.download`.

What to read next
    `roxy/health/runner.py`, `roxy/health/store.py`, `roxy/health/report.py`, `roxy/admin/api/common.py`.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
from typing import Annotated, Any, Final

from fastapi import Depends, Query, Request
from pydantic import Field, StringConstraints
from starlette.responses import Response

from roxy.admin.api import common
from roxy.admin.api.common import (
    AdminSession,
    ApiBody,
    Column,
    CsrfChecked,
    ExportFormatDep,
    TableQuery,
    TableSpec,
    table_params,
)
from roxy.config import audit
from roxy.core.errors import JSON_TYPE
from roxy.deps import get_ctx
from roxy.health import checks, report, store
from roxy.health.model import TRIGGERS, RunOptions, Status
from roxy.health.runner import NoChecks, RunBusy, audit_run, runner_for

log = logging.getLogger("roxy.admin.api.health")

router = common.area_router("health")

MAX_CHECKS_PER_RUN: Final = 200
STATUSES: Final = tuple(status.value for status in Status)
LLM_TYPE: Final = "text/plain; charset=utf-8"
HTML_TYPE: Final = "text/html; charset=utf-8"

RUNS_TABLE: Final = TableSpec(
    name="health_runs",
    columns=(
        Column("id", "Run", "The run number."),
        Column("started_at", "Started", "When the run started (Unix seconds).", "s"),
        Column("finished_at", "Finished", "When the run finished (empty while it runs).", "s"),
        Column("duration_s", "Duration", "How long the run took.", "s", sortable=False),
        Column("trigger", "Trigger", "manual, schedule, deploy or cli.", sortable=False),
        Column("state", "State", "running, finished or interrupted.", sortable=False),
        Column("worst", "Worst", "The worst status of any check in the run.", sortable=False),
        Column("passed", "Pass", "Checks that passed.", sortable=False),
        Column("warned", "Warn", "Checks that warned.", sortable=False),
        Column("failed", "Fail", "Checks that failed.", sortable=False),
        Column("not_applicable", "n/a", "Checks that did not apply here or were skipped.", sortable=False),
        Column(
            "critical",
            "Critical",
            "Results flagged critical (an account switch, a leak guard that let a request through).",
            sortable=False,
        ),
        Column("actor", "Started by", "Who started the run.", sortable=False),
        Column("version", "Version", "The release that ran it.", sortable=False),
    ),
    default_sort="started_at",
)

CheckId = Annotated[str, StringConstraints(min_length=1, max_length=120, strip_whitespace=True)]


class StartRunBody(ApiBody):
    """`POST /health/runs`: which checks to run (empty: all) and whether the credential check may call Roblox."""

    checks: list[CheckId] = Field(default_factory=list, max_length=MAX_CHECKS_PER_RUN)
    include_credential: bool = True


def _known(ids: list[str], field: str) -> None:
    unknown = [check_id for check_id in ids if not checks.known_check_id(check_id)]
    if unknown:
        raise common.validation_error({field: f"Unknown check id: {unknown[0][:120]}."}, code="unknown_check")


def _run_item(run: dict[str, Any]) -> dict[str, Any]:
    summary = run.get("summary") or {}
    return {
        **{k: v for k, v in run.items() if k not in ("summary", "options")},
        "worst": summary.get("worst"),
        "passed": summary.get("pass", 0),
        "warned": summary.get("warn", 0),
        "failed": summary.get("fail", 0),
        "not_applicable": summary.get("n/a", 0),
        "critical": summary.get("critical", 0),
        "summary": summary,
        "options": run.get("options") or {},
    }


def _filters(
    trigger: str | None,
    worst: str | None,
    check: str | None,
    check_status: str | None,
    start: str | None,
    end: str | None,
    tz: str,
) -> store.RunFilter:
    fields: dict[str, str] = {}
    if trigger is not None and trigger not in TRIGGERS:
        fields["trigger"] = f"Choose one of: {', '.join(TRIGGERS)}."
    if worst is not None and worst not in STATUSES:
        fields["worst"] = f"Choose one of: {', '.join(STATUSES)}."
    if check_status is not None and check_status not in STATUSES:
        fields["check_status"] = f"Choose one of: {', '.join(STATUSES)}."
    if check is not None and not checks.known_check_id(check):
        fields["check"] = "Unknown check id."
    since = until = None
    for name, raw in (("from", start), ("to", end)):
        if raw is None:
            continue
        try:
            value = int(common.parse_instant(raw, tz=tz))
        except ValueError as exc:
            fields[name] = str(exc)
            continue
        if name == "from":
            since = value
        else:
            until = value
    if fields:
        raise common.validation_error(fields, "The run filter is not valid.", code="invalid_filter")
    return store.RunFilter(
        trigger=trigger, worst=worst, since=since, until=until, check_id=check, check_status=check_status
    )


# ------------------------------------------------------------------------------------------------- routes


def checks_catalog() -> dict[str, Any]:
    """The 13.2 catalog in table order (`GET /health/checks` and the Health page's Checks card)."""
    return {
        "items": [
            {
                "id": spec.id,
                "title": spec.title,
                "measures": spec.measures,
                "thresholds": spec.thresholds,
                "fix_link": spec.fix_link,
                "fix_label": spec.fix_label,
                "explanation": spec.explanation,
                "kind": spec.kind.value,
                "uses_credential": spec.uses_credential,
                "per_host": bool(spec.placeholder),
            }
            for spec in checks.SPECS
        ],
        "events": list(store.EVENT_TYPES),
    }


@router.get("/checks")
async def list_checks(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """The 13.2 catalog in table order, with what each check measures and how it is judged."""
    get_ctx(request)
    return checks_catalog()


@router.post("/runs", status_code=202)
async def start_run(request: Request, body: StartRunBody, admin: AdminSession, _csrf: CsrfChecked) -> dict[str, Any]:
    """Start a run in the background (plan 13.1): 202 with its id; results stream as each check finishes."""
    ctx = get_ctx(request)
    _known(list(body.checks), "checks")
    options = RunOptions(checks=tuple(body.checks), include_credential=body.include_credential, admin_ip=admin.ip)
    runner = runner_for(ctx)
    try:
        planned = runner.plan(options)
    except NoChecks:
        raise common.validation_error({"checks": "No check matches these ids."}, code="unknown_check") from None
    uses_credential = body.include_credential and any(spec.uses_credential for spec, _ in planned)
    if uses_credential:
        # 13.3: the credential check spends a call on the Roblox account; that needs a fresh second factor.
        admin = await common.admin_fresh_mfa(request)
    try:
        run_id = await runner.start_run(trigger="manual", actor=f"admin:{admin.username}", options=options)
    except RunBusy as busy:
        headers = {"Roxy-Health-Run": str(busy.running_run_id)} if busy.running_run_id else None
        running = f" (run {busy.running_run_id})" if busy.running_run_id else ""
        raise common.ApiError(
            409, "run_in_progress", f"A health run is already running{running}; follow it instead.", headers=headers
        ) from None
    try:
        await audit_run(ctx, common.actor_for(admin), run_id, options, common.request_id_of(request))
    except Exception as exc:  # the run is recorded in health_runs with its actor either way
        log.warning("health_run_audit_failed", extra={"fields": {"run_id": run_id, "error": str(exc)[:200]}})
    return {
        "run_id": run_id,
        "state": "running",
        "checks": len(planned),
        "include_credential": uses_credential,
        "events": list(store.EVENT_TYPES),
        "links": {"run": f"{common.API_PREFIX}/health/runs/{run_id}"},
    }


@router.get("/runs", response_model=None)
async def list_runs(
    request: Request,
    admin: AdminSession,
    tq: Annotated[TableQuery, Depends(table_params(RUNS_TABLE))],
    fmt: ExportFormatDep,
    trigger: Annotated[str | None, Query(max_length=16)] = None,
    worst: Annotated[str | None, Query(max_length=8)] = None,
    check: Annotated[str | None, Query(max_length=120)] = None,
    check_status: Annotated[str | None, Query(max_length=8)] = None,
    from_: Annotated[str | None, Query(alias="from", max_length=common.MAX_TIME_TEXT)] = None,
    to: Annotated[str | None, Query(max_length=common.MAX_TIME_TEXT)] = None,
) -> Any:
    """Runs newest first (filters, paging, sorting); `format=csv|json` downloads them (audited)."""
    ctx = get_ctx(request)
    tz = str(ctx.settings.get("ui_timezone") or "UTC")
    filters = _filters(trigger, worst, check, check_status, from_, to, tz)
    if fmt is not None:
        read = _runs_reader(ctx, filters, tq)

        async def fetch(page: int, size: int) -> tuple[list[dict[str, Any]], int]:
            rows, total = await ctx.dbs.metrics.read(read(page, size))
            return [_run_item(r) for r in rows], total

        applied = {k: v for k, v in dataclasses.asdict(filters).items() if v is not None}
        return await common.export_pages(request, admin, RUNS_TABLE, fetch, fmt, tq=tq, filters=applied)
    return await runs_table(ctx, filters, tq)


def _runs_reader(ctx: Any, filters: store.RunFilter, tq: TableQuery) -> Any:
    now = float(ctx.clock.now())

    def read(page: int, size: int) -> Any:
        return lambda conn: store.list_runs(
            conn, filters, page=page, page_size=size, sort=tq.sort, descending=tq.descending, now=now
        )

    return read


async def runs_table(ctx: Any, filters: store.RunFilter, tq: TableQuery) -> dict[str, Any]:
    """One page of the run history (`GET /health/runs` and the Health page's History card)."""
    read = _runs_reader(ctx, filters, tq)
    with common.service_errors():
        rows, total = await ctx.dbs.metrics.read(read(tq.page, tq.page_size))
    return common.table_answer(RUNS_TABLE, tq, [_run_item(r) for r in rows], total)


run_filters = _filters
"""`run_filters(trigger, worst, check, check_status, start, end, tz) -> store.RunFilter` (422 when invalid)."""


async def run_answer(ctx: Any, run_id: int) -> dict[str, Any]:
    """One run as `GET /health/runs/{id}` answers it (404 when no run has that id)."""
    return _shape_run(await _run_detail(ctx, run_id))


async def latest_run_id(ctx: Any) -> int | None:
    """The newest run's id (running or finished), or None before the first run."""
    with common.service_errors():
        found = await ctx.dbs.metrics.read(lambda conn: store.latest_run_id(conn, finished=False))
    return None if found is None else int(found)


async def compare_answer(ctx: Any, run_id: int, other: int | None) -> dict[str, Any]:
    """What changed between run `run_id` and `other` (default: the run before), as `GET .../compare` answers."""
    now = float(ctx.clock.now())
    with common.service_errors():
        found = await ctx.dbs.metrics.read(lambda conn: store.compare_runs(conn, run_id, other, now=now))
    if found is None:
        raise common.not_found("No health run has that id.")
    if other is not None and found.get("previous") is None:
        raise common.not_found("No health run has the id given in with.")
    result: dict[str, Any] = found
    return result


async def _run_detail(ctx: Any, run_id: int) -> dict[str, Any]:
    now = float(ctx.clock.now())

    def read(conn: Any) -> dict[str, Any] | None:
        run = store.get_run(conn, run_id, now=now)
        if run is None:
            return None
        ids = [r["check_id"] for r in run["results"] if r["status"] in (Status.FAIL, Status.WARN)]
        run["recommendations"] = store.linked_recommendations(conn, ids, checks.RECOMMENDATION_RULES)
        run["comparison"] = store.compare_runs(conn, run_id, None, now=now)
        return run

    with common.service_errors():
        found = await ctx.dbs.metrics.read(read)
    if found is None:
        raise common.not_found("No health run has that id.")
    detail: dict[str, Any] = found
    return detail


def _shape_run(run: dict[str, Any]) -> dict[str, Any]:
    links = run.pop("recommendations", {})
    comparison = run.pop("comparison", None)
    results = []
    for item in report.sorted_results(run.get("results") or []):
        entry = dict(item)
        found = checks.spec_for(str(entry["check_id"]))
        if found is not None:
            entry["title"] = found[0].title
            entry["fix_label"] = found[0].fix_label
        entry["recommendation"] = links.get(entry["check_id"])
        results.append(entry)
    run["results"] = results
    run["comparison"] = (
        None
        if comparison is None
        else {
            "previous_run_id": (comparison.get("previous") or {}).get("id"),
            "new_failures": comparison.get("new_failures", []),
            "fixed": comparison.get("fixed", []),
            "counts": comparison.get("counts", {}),
        }
    )
    return run


@router.get("/runs/latest")
async def latest_run(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """The newest run (running or finished), as `GET /runs/{id}` answers it."""
    ctx = get_ctx(request)
    run_id = await latest_run_id(ctx)
    if run_id is None:
        raise common.not_found("No health run has been made yet.")
    return await run_answer(ctx, run_id)


@router.get("/runs/{run_id}")
async def get_run(request: Request, run_id: common.RowId, _admin: AdminSession) -> dict[str, Any]:
    """One run: every result in 13.2 order, each failing check's open recommendation, and the change summary."""
    return await run_answer(get_ctx(request), run_id)


@router.get("/runs/{run_id}/compare")
async def compare_runs(
    request: Request,
    run_id: common.RowId,
    _admin: AdminSession,
    with_: Annotated[int | None, Query(alias="with", ge=1, le=common.MAX_ROW_ID)] = None,
) -> dict[str, Any]:
    """What changed between this run and `with` (default: the run before it), check by check."""
    return await compare_answer(get_ctx(request), run_id, with_)


@router.get("/runs/{run_id}/export", response_model=None)
async def export_run(
    request: Request,
    run_id: common.RowId,
    admin: AdminSession,
    format_: Annotated[str, Query(alias="format", max_length=8)] = "json",
    focus: Annotated[str | None, Query(max_length=120)] = None,
) -> Response:
    """The JSON report, the printable HTML page, or the "Copy run for LLM" text of one run (audited)."""
    ctx = get_ctx(request)
    if format_ not in ("json", "html", "llm"):
        raise common.validation_error({"format": "Choose json, html or llm."}, code="invalid_format")
    if focus is not None and not checks.known_check_id(focus):
        raise common.validation_error({"focus": "Unknown check id."}, code="unknown_check")
    run = await _run_detail(ctx, run_id)
    links = run.pop("recommendations", {})
    comparison = run.pop("comparison", None)
    now = float(ctx.clock.now())
    if format_ == "json":
        document = report.json_report(run, comparison=comparison, recommendations=links, generated_at=now)
        content = json.dumps(document, indent=2, ensure_ascii=False).encode("utf-8")
        media_type, filename = JSON_TYPE, f"roxy_health_run_{run_id}.json"
    elif format_ == "html":
        nonce = getattr(request.state, "csp_nonce", None)
        page = await asyncio.to_thread(report.html_report, run, generated_at=now, nonce=nonce)
        content, media_type, filename = page.encode("utf-8"), HTML_TYPE, f"roxy_health_run_{run_id}.html"
    else:
        text = report.llm_copy(run, focus=focus, comparison=comparison)
        content, media_type, filename = text.encode("utf-8"), LLM_TYPE, ""
    actor = common.actor_for(admin)
    request_id = common.request_id_of(request)
    details = {"format": format_, "run_id": run_id, "focus": focus, "bytes": len(content)}

    def write(conn: Any) -> int:
        return audit.record(
            conn,
            actor,
            common.EXPORT_AUDIT_ACTION,
            f"health_run:{run_id}",
            None,
            details,
            None,
            request_id,
            at=int(now),
        )

    with common.service_errors():
        await ctx.dbs.control.write(write)
    response = Response(content=content, media_type=media_type)
    if filename:
        response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    response.headers["Cache-Control"] = common.NO_STORE
    return response


__all__ = [
    "RUNS_TABLE",
    "STATUSES",
    "StartRunBody",
    "checks_catalog",
    "compare_answer",
    "latest_run_id",
    "router",
    "run_answer",
    "run_filters",
    "runs_table",
]
