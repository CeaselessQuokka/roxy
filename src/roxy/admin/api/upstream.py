"""Upstream API (`/admin/api/v1/upstream`): how Roxy's calls to Roblox are paced, refused and retried (plan 7.12).

What this is
    The routes behind the Upstream page (plan 14.1):
      * `GET /egress`: one health card per egress (direct, rotator, credential): calls per minute, the Roblox 429
        and 5xx rates, failed requests, timeouts, p50/p95/p99 latency, v1's method health (when it last worked,
        when it last failed and what that failure was; parity row 71), challenge and HTML answers, the egress
        bucket's fill, its active cooldowns and open breakers.
      * `GET /hosts`: the same per Roblox host, as a section 13 table (export too).
      * `GET /failures`: v1's "Request Failures" log (plan 14.1 row 24, parity row 72): failed requests grouped by
        egress, reason and Roblox's status, with first and last seen and the latest one's details (export too).
      * `GET /challenges`: answers that were a challenge or an HTML block page, by egress and endpoint.
      * `GET /429-timeline`: Roblox 429s per time bucket for the endpoints with the most 429s, plus the rest.
      * `GET /latency`: p50, p95 and p99 latency (and the p95 queue wait) of requests that went to Roblox.
      * `GET /buckets` and `GET /buckets/history?key=`: every bucket's fill gauge, next free slot and configured
        rate, with its reservations, refusals and peak fill over the range; one bucket over time.
      * `GET /adaptive`: the adaptive rate controller's changes (plan 7.3) and the rates it set.
      * `GET /aimd`: the Tier 3 concurrency limits and calls in flight (plan 7.4), when `aimd_enabled` is on.
      * `GET /cooldowns` and `GET /breakers`: what is cooling down or open, with the end time for a countdown.
      * `POST /reset`: clear every cooldown and breaker. Buckets are never refilled (parity row 34, v1 bug B21).
      * `GET /retries`: retries by status, reason and egress (row 117), CSRF retries, calls by attempt kind.
      * `GET /internal-calls`: Roxy's own calls (rows 28, 29) with their health.
      * `GET /trace/{request_id}`: "Why did this request wait?" for one `Roxy-Request-Id`.

Why it exists
    Plan 2.5 and 7: Roxy should almost never get a 429 from Roblox, and when it does, the admin must see where, why,
    and what Roxy did about it. Every number comes from one read model (`metrics/queries.py`,
    `metrics/read_upstream.py`, `metrics/read_history.py`, the `UpstreamService` snapshots), so the page, the
    recommendations and the LLM export agree (DESIGN.md section 13, P6).

How it works
    Every route depends on the session guard; `POST /reset` also on the CSRF guard, needs a reason, and writes an
    audit row (`upstream.reset_state`, with the exact counts cleared) and a chart marker. Time-ranged reads take
    the section 13 range parameters. Live state (buckets, cooldowns, breakers, AIMD) is read from hot.db, so every
    worker shows the same; a cooldown this worker could not share during a hot.db outage is listed as `local`.
    Fields holding text a caller chose (paths, endpoint templates, errors quoting them) are named in the answer's
    `caller_text` list, so the page shows them as plain text.

What to read next
    `roxy/upstream/service.py`, `roxy/upstream/read_trace.py` (the explainer), `roxy/metrics/read_upstream.py`.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from typing import Annotated, Any, Final, Literal

from fastapi import Depends, Path, Query, Request
from pydantic import Field

from roxy.admin.api import common
from roxy.admin.api.common import (
    AdminSession,
    ApiBody,
    Column,
    CsrfChecked,
    ExportFormatDep,
    TableQuery,
    TableSpec,
    TimeRange,
    TimeRangeDep,
    table_params,
)
from roxy.config import audit
from roxy.config.constants import MAX_REASON_LENGTH
from roxy.core.reasons import Egress
from roxy.deps import get_ctx
from roxy.metrics import capture, queries, read_history, read_upstream
from roxy.storage.db import SharedStateUnavailable
from roxy.upstream import aimd, read_state, read_trace
from roxy.upstream.buckets import BucketDefaults
from roxy.upstream.internal import INTERNAL_NOTE, internal_endpoints

log = logging.getLogger("roxy.admin.api.upstream")

router = common.area_router("upstream")

EGRESSES: Final = (Egress.DIRECT.value, Egress.ROTATOR.value, Egress.CREDENTIAL.value)
MAX_BUCKETS: Final = 500
MAX_COOLDOWNS: Final = 1000
MAX_BREAKERS: Final = 500
MAX_HOSTS: Final = 250
MAX_CHANGES: Final = 200
MAX_KEY_CHARS: Final = 300
RESET_ACTION: Final = "upstream.reset_state"
TRACE_BEFORE_MS: Final = 5_000
TRACE_SLACK_S: Final = 30
_REQUEST_ID = re.compile(r"[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{26}")

EgressName = Literal["direct", "rotator", "credential"]

HOSTS_SPEC: Final = TableSpec(
    name="upstream_hosts",
    columns=(
        Column("host", "Host", "The Roblox service (host name)."),
        Column("calls", "Calls", "Upstream calls to this host in the range, Roxy's own calls included.", "count"),
        Column("calls_per_min", "Calls per minute", "Calls divided by the minutes of the range so far.", "per_min"),
        Column("roblox_429", "Roblox 429s", "Answers where Roblox said 429 (every one is logged).", "count"),
        Column("rate_429_pct", "429 rate", "Roblox 429s per 100 calls.", "pct"),
        Column("roblox_5xx", "Roblox 5xx", "Requests that ended with a 5xx Roblox sent.", "count"),
        Column("rate_5xx_pct", "5xx rate", "Roblox 5xx per 100 requests that went to this host.", "pct"),
        Column("timeouts", "Timeouts", "Requests that ended because Roblox did not answer in time.", "count"),
        Column("failed", "Failed", "Requests to this host Roxy could not answer (any failure reason).", "count"),
        Column("p50_ms", "p50", "Median latency of requests to this host (queue wait included).", "ms"),
        Column("p95_ms", "p95", "95th percentile latency.", "ms"),
        Column("p99_ms", "p99", "99th percentile latency.", "ms"),
        Column("bucket_fill_pct", "Bucket fill", "How much of the host bucket's burst is in use now.", "pct"),
        Column("per_min", "Rate limit", "The host bucket's configured rate.", "per_min"),
        Column(
            "last_success_at",
            "Last success",
            "Start of the newest minute (or hour, see last_success_precision) with a request Roblox answered, over "
            "everything kept, not only the range.",
            "timestamp",
            sortable=False,
        ),
        Column(
            "last_error_at",
            "Last error",
            "Start of the newest minute (or hour) with a failed request, over everything kept.",
            "timestamp",
            sortable=False,
        ),
        Column(
            "last_error",
            "Last error detail",
            "The newest recorded failure: time, reason, statuses, endpoint and error (path and error are caller text).",
            sortable=False,
            caller_text=True,
        ),
    ),
    default_sort="calls",
)

CARD_CALLER_TEXT: Final = ("last_error.template", "last_error.path", "last_error.error")
"""Fields of the cards and host rows holding text a caller chose (a path, or an error quoting it): the page shows
them as plain text, never as markup."""

FAILURES_SPEC: Final = TableSpec(
    name="upstream_failures",
    columns=(
        Column("egress", "Egress", "The path the failed request took (empty: folded rows, which keep no egress)."),
        Column("reason", "Reason", "Why it failed (upstream_5xx, upstream_timeout, upstream_connect, ...)."),
        Column("upstream_status", "Roblox status", "What Roblox answered on the last call (empty: no answer)."),
        Column("count", "Count", "Failed requests in this group in the range.", "count"),
        Column(
            "folded",
            "Folded",
            "Of these, requests the recorder folded over its event budget (they keep no egress, path or error).",
            "count",
        ),
        Column("first_ms", "First seen", "The first failure of this group in the range.", "timestamp_ms"),
        Column("last_ms", "Last seen", "The latest failure of this group in the range.", "timestamp_ms"),
        Column("last_status", "Last status", "What the caller got on the latest failure.", sortable=False),
        Column("last_method", "Last method", "The HTTP method of the latest failure.", sortable=False),
        Column(
            "last_template",
            "Last endpoint",
            "The endpoint template of the latest failure.",
            sortable=False,
            caller_text=True,
        ),
        Column(
            "last_path",
            "Last path",
            "The path of the latest failure (caller text, redacted).",
            sortable=False,
            caller_text=True,
        ),
        Column(
            "last_error",
            "Last detail",
            "Roblox's status line or the connection error of the latest failure (redacted).",
            sortable=False,
            caller_text=True,
        ),
    ),
    default_sort="count",
)
FAILURES_CALLER_TEXT: Final = ("last_template", "last_path", "last_error")

CHALLENGES_SPEC: Final = TableSpec(
    name="upstream_challenges",
    columns=(
        Column("egress", "Egress", "The path the calls took."),
        Column("template", "Endpoint", "The endpoint template (caller text).", caller_text=True),
        Column("calls", "Calls", "Upstream calls to this endpoint through this egress in the range.", "count"),
        Column("challenges", "Challenges", "Answers carrying a challenge (rblx-challenge-*, cf-mitigated).", "count"),
        Column("html_bodies", "HTML pages", "HTML answers on a JSON endpoint: a block or error page.", "count"),
        Column(
            "last_at", "Last flagged", "Start of the newest minute with a flagged answer.", "timestamp", sortable=False
        ),
    ),
    default_sort="challenges",
)

BUCKETS_SPEC: Final = TableSpec(
    name="upstream_buckets",
    columns=(
        Column("key", "Bucket", "global, egress:<egress>, host:<host> or endpoint:<template>."),
        Column("kind", "Kind", "global, egress, host or endpoint."),
        Column("fill_pct", "Fill", "How much of the burst is in use now (100 means the next call waits).", "pct"),
        Column("next_free_in_ms", "Next free slot", "How long the next call would wait now.", "ms"),
        Column("per_min", "Rate", "The configured rate (setting or override).", "per_min"),
        Column("burst", "Burst", "The configured burst.", "count"),
        Column("origin", "Rate from", "setting, or the override's origin (admin, recommendation, adaptive)."),
        Column("attempts", "Reservations", "Reservations that reached this bucket in the range.", "count"),
        Column("rejections", "Refused", "Reservations refused because this bucket's wait was too long.", "count"),
        Column("fill_pct_peak", "Peak fill", "The fullest the bucket was in any minute of the range.", "pct"),
    ),
    default_sort="fill_pct",
)


def _need(value: Any, what: str) -> Any:
    """The running service, or 503 while the worker is still starting (C7: never a 500)."""
    if value is None:
        raise common.unavailable(f"The {what} is not running yet; try again shortly.")
    return value


def _elapsed_minutes(tr: TimeRange, now: float) -> float:
    """Minutes of the range that have happened (a range ends in the open bucket), at least one."""
    return max(1.0, (min(float(tr.window.end), now) - tr.window.start) / 60.0)


def _rate(part: Any, whole: Any) -> float | None:
    if not isinstance(part, int | float) or not isinstance(whole, int | float) or whole <= 0:
        return None
    return round(part * 100.0 / whole, 2)


def _calls(row: Mapping[str, Any]) -> int:
    return int(row.get("upstream_calls") or 0) + int(row.get("internal_calls") or 0)


def _health(row: Mapping[str, Any], minutes: float) -> dict[str, Any]:
    """The numbers of one egress or host card (P6: unknown stays None)."""
    calls = _calls(row)
    requests = int(row.get("requests") or 0)
    return {
        "requests": requests,
        "calls": calls,
        "internal_calls": int(row.get("internal_calls") or 0),
        "calls_per_min": round(calls / minutes, 2),
        "failed": int(row.get("failed") or 0),
        "rate_failed_pct": _rate(int(row.get("failed") or 0), requests),
        "roblox_429": row.get("roblox_429"),
        "rate_429_pct": _rate(row.get("roblox_429"), calls),
        "roblox_5xx": int(row.get("roblox_5xx") or 0),
        "rate_5xx_pct": _rate(row.get("roblox_5xx"), requests),
        "timeouts": int(row.get("timeouts") or 0),
        "p50_ms": row.get("p50_ms"),
        "p95_ms": row.get("p95_ms"),
        "p99_ms": row.get("p99_ms"),
        "queue_wait_p95_ms": row.get("queue_wait_p95_ms"),
    }


def _method_health(
    name: str,
    successes: Mapping[str, Mapping[str, Any]],
    failures: Mapping[str, Mapping[str, Any]],
    errors: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """v1's method health for one egress or host (parity row 71): when it last worked and what failed last.

    `last_success_at` and `last_error_at` are the start of the newest rollup bucket with a success or a failure,
    over everything kept (not only the range), with the level that answered (`*_precision`: minute while minutes are
    kept); `last_error` is the newest recorded failure event (exact `at_ms`, reason, statuses, endpoint, error).
    None means "none kept" (P6), never "never happened".
    """
    success = successes.get(name) or {}
    failure = failures.get(name) or {}
    return {
        "last_success_at": success.get("at"),
        "last_success_precision": success.get("precision"),
        "last_error_at": failure.get("at"),
        "last_error_precision": failure.get("precision"),
        "last_error": dict(errors[name]) if name in errors else None,
    }


def _bucket_view(state: Any, configured: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "key": state.key,
        "fill_pct": round(state.fill * 100.0, 1),
        "next_free_in_ms": round(state.next_free_in_ms, 1),
        "per_min": configured.get("per_min"),
        "burst": configured.get("burst"),
        "origin": configured.get("origin"),
        "stored_per_min": round(state.per_min, 3),
    }


# ------------------------------------------------------------------------------------------- health cards


@router.get("/egress")
async def egress_cards(request: Request, _admin: AdminSession, tr: TimeRangeDep) -> dict[str, Any]:
    """One health card per egress: traffic and failure rates over the range, v1's method health (failed count,
    last success, last error), challenge and HTML answers, plus its live bucket and state."""
    ctx = get_ctx(request)
    upstream = _need(ctx.upstream, "upstream service")
    egress = _need(ctx.egress, "egress layer")
    window = tr.window
    page = queries.Page(size=10, sort="upstream_calls")

    def read(conn: Any) -> dict[str, Any]:
        return {
            "top": queries.top_n_sync(conn, window, "egress", page=page),
            "successes": read_upstream.last_outcome_at(conn, "egress", "served_upstream"),
            "failures": read_upstream.last_outcome_at(conn, "egress", "failed"),
            "errors": read_upstream.last_failure_events(conn, "egress"),
            "flagged": read_upstream.challenge_counts(conn, window.start, window.end),
        }

    data = await ctx.dbs.metrics.read(read)
    rows = {str(row.get("key")): row for row in data["top"]["rows"]}
    flagged = {str(row["egress"]): row for row in data["flagged"]}
    defaults = BucketDefaults.from_settings(ctx.settings)
    limits = ctx.rules.snapshot
    with common.service_errors():
        buckets = {state.key: state for state in await upstream.bucket_snapshot(MAX_BUCKETS)}
        cooling = await upstream.cooldown_snapshot(MAX_COOLDOWNS)
        open_breakers = await upstream.breaker_snapshot(MAX_BREAKERS)
    minutes = _elapsed_minutes(tr, ctx.clock.now())
    cards = []
    for name in EGRESSES:
        value = Egress(name)
        enabled, why = egress.is_enabled(value)
        key = f"egress:{name}"
        configured = read_state.configured_limit(key, defaults, limits)
        state = buckets.get(key)
        cards.append(
            {
                "egress": name,
                "enabled": bool(enabled),
                "disabled_reason": why or None,
                "leak_guard_tripped": egress.tripped(value) if value is not Egress.CREDENTIAL else False,
                **_health(rows.get(name, {}), minutes),
                **_method_health(name, data["successes"], data["failures"], data["errors"]),
                "challenges": int(flagged.get(name, {}).get("challenges") or 0),
                "html_bodies": int(flagged.get(name, {}).get("html_bodies") or 0),
                "bucket": _bucket_view(state, configured)
                if state is not None
                else {"key": key, "fill_pct": 0.0, "next_free_in_ms": 0.0, **configured, "stored_per_min": None},
                "cooldowns": sum(1 for row in cooling if read_state.describe_key(row.key)["egress"] == name),
                "breakers_open": sum(
                    1
                    for row in open_breakers
                    if row.get("state") == "open" and read_state.describe_key(str(row.get("key")))["egress"] == name
                ),
            }
        )
    return {
        "range": tr.info(),
        "items": cards,
        "caller_text": list(CARD_CALLER_TEXT),
        "settings_card": "upstream#routing",
    }


@router.get("/hosts")
async def host_table(
    request: Request,
    admin: AdminSession,
    tr: TimeRangeDep,
    tq: Annotated[TableQuery, Depends(table_params(HOSTS_SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    """One row per Roblox host: calls, 429 and 5xx rates, latency percentiles, its bucket's fill and rate."""
    ctx = get_ctx(request)
    upstream = _need(ctx.upstream, "upstream service")
    window = tr.window
    page = queries.Page(size=MAX_HOSTS, sort="upstream_calls")

    def read(conn: Any) -> dict[str, Any]:
        return {
            "top": queries.top_n_sync(conn, window, "host", page=page),
            "successes": read_upstream.last_outcome_at(conn, "host", "served_upstream"),
            "failures": read_upstream.last_outcome_at(conn, "host", "failed"),
            "errors": read_upstream.last_failure_events(conn, "host"),
        }

    data = await ctx.dbs.metrics.read(read)
    defaults = BucketDefaults.from_settings(ctx.settings)
    limits = ctx.rules.snapshot
    with common.service_errors():
        buckets = {state.key: state for state in await upstream.bucket_snapshot(MAX_BUCKETS)}
    minutes = _elapsed_minutes(tr, ctx.clock.now())
    rows: list[dict[str, Any]] = []
    for row in data["top"]["rows"]:
        host = str(row.get("key"))
        key = f"host:{host}"
        state = buckets.get(key)
        rows.append(
            {
                "host": host,
                **_health(row, minutes),
                **_method_health(host, data["successes"], data["failures"], data["errors"]),
                "bucket_fill_pct": round(state.fill * 100.0, 1) if state is not None else 0.0,
                "per_min": read_state.configured_limit(key, defaults, limits)["per_min"],
            }
        )
    if fmt is not None:
        whole = common.TableQuery(1, common.MAX_EXPORT_ROWS, tq.sort, tq.order, tq.q)
        items, total = common.page_rows(rows, whole, search_keys=("host",))
        return await common.export_table(request, admin, HOSTS_SPEC, items, fmt, total=total, tq=tq, tr=tr)
    items, total = common.page_rows(rows, tq, search_keys=("host",))
    answer = common.table_answer(HOSTS_SPEC, tq, items, total) | {
        "range": tr.info(),
    }
    return common.add_caller_text(answer, list(CARD_CALLER_TEXT))


# --------------------------------------------------------------------------------------- failures and pages


@router.get("/failures")
async def failure_table(
    request: Request,
    admin: AdminSession,
    tr: TimeRangeDep,
    tq: Annotated[TableQuery, Depends(table_params(FAILURES_SPEC))],
    fmt: ExportFormatDep,
    egress: EgressName | None = None,
) -> Any:
    """Upstream > Failures (v1 "Request Failures", plan 14.1 row 24, parity row 72): failed requests in the range
    grouped by egress, reason and Roblox's status, with first and last seen and the latest one's status, endpoint,
    path and error. Searchable, sortable, exportable (`format=csv|json`)."""
    ctx = get_ctx(request)
    start_ms, end_ms = tr.window.start * 1000, tr.window.end * 1000
    with common.service_errors():
        found = await ctx.dbs.metrics.read(lambda conn: read_upstream.failure_log(conn, start_ms, end_ms))
    rows = [row for row in found if egress is None or row["egress"] == egress]
    search_keys = ("egress", "reason", "last_template", "last_path", "last_error")
    if fmt is not None:
        whole = common.TableQuery(1, common.MAX_EXPORT_ROWS, tq.sort, tq.order, tq.q)
        items, total = common.page_rows(rows, whole, search_keys=search_keys)
        return await common.export_table(
            request, admin, FAILURES_SPEC, items, fmt, total=total, tq=tq, tr=tr, filters={"egress": egress}
        )
    items, total = common.page_rows(rows, tq, search_keys=search_keys)
    answer = common.table_answer(FAILURES_SPEC, tq, items, total) | {
        "range": tr.info(),
        "filters": {"egress": egress},
        "capped": len(found) >= read_upstream.MAX_FAILURE_GROUPS,
    }
    return common.add_caller_text(answer, list(FAILURES_CALLER_TEXT))


@router.get("/challenges")
async def challenge_table(
    request: Request,
    admin: AdminSession,
    tr: TimeRangeDep,
    tq: Annotated[TableQuery, Depends(table_params(CHALLENGES_SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    """Calls Roblox answered with a challenge or an HTML page (a block page) in the range, by egress and endpoint
    (`upstream/pages.py`; the evidence UP-CHALLENGE reads), most flagged first. Exportable."""
    ctx = get_ctx(request)
    start, end = tr.window.start, tr.window.end
    with common.service_errors():
        found = await ctx.dbs.metrics.read(
            lambda conn: read_upstream.challenge_counts(conn, start, end, by_template=True)
        )
    if fmt is not None:
        whole = common.TableQuery(1, common.MAX_EXPORT_ROWS, tq.sort, tq.order, tq.q)
        items, total = common.page_rows(found, whole, search_keys=("egress", "template"))
        return await common.export_table(request, admin, CHALLENGES_SPEC, items, fmt, total=total, tq=tq, tr=tr)
    items, total = common.page_rows(found, tq, search_keys=("egress", "template"))
    answer = common.table_answer(CHALLENGES_SPEC, tq, items, total) | {
        "range": tr.info(),
        "basis": "per call, from the minute history of upstream attempts (upstream_attempt_minute)",
    }
    return common.add_caller_text(answer, ["template"])


# ------------------------------------------------------------------------------------------------- charts


async def _annotations(ctx: Any, tr: TimeRange) -> tuple[list[dict[str, Any]], list[str]]:
    start, end = tr.window.start, tr.window.end

    def read(conn: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        return queries.chart_annotations(conn, start, end), queries.reset_annotations(conn, start, end)

    marks, resets = await ctx.dbs.metrics.read(read)
    tz = str(ctx.settings.get("ui_timezone") or "UTC")
    return common.annotation_entries(marks), common.reset_notices(resets, tz=tz)


@router.get("/429-timeline")
async def timeline_429(
    request: Request,
    _admin: AdminSession,
    tr: TimeRangeDep,
    top: Annotated[int, Query(ge=1, le=read_upstream.MAX_SERIES)] = 10,
    egress: EgressName | None = None,
) -> dict[str, Any]:
    """Roblox 429s per time bucket, one series per endpoint with the most 429s (and `other`), by egress if given."""
    ctx = get_ctx(request)
    window = tr.window
    data = await ctx.dbs.metrics.read(
        lambda conn: read_upstream.roblox_429_timeline(conn, window, top=top, egress=egress)
    )
    buckets = data["buckets"]
    series = [
        common.series_entry(f"roblox_429:{template}", template, "count", list(zip(buckets, values, strict=True)))
        for template, values in data["series"].items()
    ]
    if any(data["other"]):
        series.append(
            common.series_entry(
                "roblox_429:other", "Other endpoints", "count", list(zip(buckets, data["other"], strict=True))
            )
        )
    compare_series = None
    if tr.compare_window is not None:
        other_window = tr.compare_window
        previous = await ctx.dbs.metrics.read(
            lambda conn: read_upstream.roblox_429_timeline(conn, other_window, top=1, egress=egress)
        )
        compare_series = [
            common.series_entry(
                "roblox_429:total",
                "All endpoints",
                "count",
                list(zip(previous["buckets"], previous["all"], strict=True)),
            )
        ]
    annotations, notices = await _annotations(ctx, tr)
    answer = common.series_answer(tr, series, compare_series=compare_series, annotations=annotations, notices=notices)
    answer["totals"] = {"total": data["total"], "by_endpoint": data["totals"]}
    return answer


@router.get("/latency")
async def latency(
    request: Request, _admin: AdminSession, tr: TimeRangeDep, egress: EgressName | None = None
) -> dict[str, Any]:
    """p50, p95 and p99 latency of requests that went to Roblox (served or failed), queue wait included."""
    ctx = get_ctx(request)
    metrics = ["p50_ms", "p95_ms", "p99_ms", "queue_wait_p95_ms"]
    filters: dict[str, Any] = {"outcome": ["served_upstream", "failed"]}
    if egress:
        filters["egress"] = egress
    window = tr.window
    data = await queries.series(ctx.dbs.metrics, window, metrics=metrics, filters=filters)
    series = [entry for metric in metrics for entry in common.series_from_read_model(data, metric, unit="ms")]
    compare_series = None
    if tr.compare_window is not None:
        other = await queries.series(ctx.dbs.metrics, tr.compare_window, metrics=metrics, filters=filters)
        compare_series = [
            entry for metric in metrics for entry in common.series_from_read_model(other, metric, unit="ms")
        ]
    annotations, notices = await _annotations(ctx, tr)
    answer = common.series_answer(tr, series, compare_series=compare_series, annotations=annotations, notices=notices)
    answer["basis"] = "caller latency of requests that went to Roblox: queue wait plus every attempt"
    return answer


# ------------------------------------------------------------------------------------------------ buckets


@router.get("/buckets")
async def bucket_table(
    request: Request,
    admin: AdminSession,
    tr: TimeRangeDep,
    tq: Annotated[TableQuery, Depends(table_params(BUCKETS_SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    """Every bucket: fill gauge and next free slot now, configured rate, and reservations, refusals and peak fill
    over the range. Buckets are never refilled by hand (parity row 34)."""
    ctx = get_ctx(request)
    upstream = _need(ctx.upstream, "upstream service")
    start, end = tr.window.start, tr.window.end
    with common.service_errors():
        states = await upstream.bucket_snapshot(MAX_BUCKETS)
    summary = await ctx.dbs.metrics.read(lambda conn: read_history.bucket_summary(conn, start, end))
    defaults = BucketDefaults.from_settings(ctx.settings)
    limits = ctx.rules.snapshot
    rows: dict[str, dict[str, Any]] = {}
    for state in states:
        rows[state.key] = _bucket_view(state, read_state.configured_limit(state.key, defaults, limits))
    for key in summary:
        if key not in rows and len(rows) < MAX_BUCKETS * 4:
            rows[key] = {
                "key": key,
                "fill_pct": None,
                "next_free_in_ms": None,
                **read_state.configured_limit(key, defaults, limits),
                "stored_per_min": None,
            }
    for key, row in rows.items():
        found = summary.get(key) or {}
        row["kind"] = read_state.describe_key(key)["kind"]
        row["attempts"] = int(found.get("attempts") or 0)
        row["rejections"] = int(found.get("rejections") or 0)
        row["fill_pct_peak"] = found.get("fill_pct_peak")
    items_all = list(rows.values())
    if fmt is not None:
        whole = common.TableQuery(1, common.MAX_EXPORT_ROWS, tq.sort, tq.order, tq.q)
        items, total = common.page_rows(items_all, whole, search_keys=("key",))
        return await common.export_table(request, admin, BUCKETS_SPEC, items, fmt, total=total, tq=tq, tr=tr)
    items, total = common.page_rows(items_all, tq, search_keys=("key",))
    return common.table_answer(BUCKETS_SPEC, tq, items, total) | {
        "range": tr.info(),
        "refills": "never: a reset clears cooldowns and breakers only (parity row 34)",
        "settings_card": "upstream#buckets",
    }


@router.get("/buckets/history")
async def bucket_history(
    request: Request,
    _admin: AdminSession,
    tr: TimeRangeDep,
    key: Annotated[str, Query(min_length=1, max_length=MAX_KEY_CHARS)],
) -> dict[str, Any]:
    """One bucket over time: reservations, refusals and peak fill per chart bucket (`bucket_minute`)."""
    ctx = get_ctx(request)
    window = tr.window
    data = await ctx.dbs.metrics.read(lambda conn: read_upstream.bucket_series(conn, key, window))
    starts = data["buckets"]
    series = [
        common.series_entry("attempts", "Reservations", "count", list(zip(starts, data["attempts"], strict=True))),
        common.series_entry("rejections", "Refused", "count", list(zip(starts, data["rejections"], strict=True))),
        common.series_entry("fill_pct_peak", "Peak fill", "pct", list(zip(starts, data["fill_pct_peak"], strict=True))),
    ]
    annotations, notices = await _annotations(ctx, tr)
    answer = common.series_answer(tr, series, annotations=annotations, notices=notices)
    answer["key"] = key
    answer["describe"] = read_state.describe_key(key)
    return answer


# -------------------------------------------------------------------------------------- adaptive and AIMD


@router.get("/adaptive")
async def adaptive(request: Request, _admin: AdminSession, tr: TimeRangeDep) -> dict[str, Any]:
    """The adaptive rate controller (plan 7.3): its settings, the rates it holds now, and its changes in the range."""
    ctx = get_ctx(request)
    settings = ctx.settings
    start_ms, end_ms = tr.window.start * 1000, tr.window.end * 1000
    events = await ctx.dbs.metrics.read(
        lambda conn: read_upstream.recent_events(
            conn, ("adaptive_rate_decrease", "adaptive_rate_increase"), start_ms, end_ms, limit=MAX_CHANGES
        )
    )
    changes = [
        {
            "at_ms": item["at_ms"],
            "direction": "decrease" if item["type"] == "adaptive_rate_decrease" else "increase",
            "bucket_key": item["detail"].get("bucket_key"),
            "old_per_min": item["detail"].get("old_per_min"),
            "new_per_min": item["detail"].get("new_per_min"),
            "evidence": item["detail"].get("evidence") or {},
        }
        for item in events
    ]
    snapshot = ctx.rules.snapshot
    held = [
        {"bucket_key": row.bucket_key, "per_min": row.per_min, "burst": row.burst, "updated_at": row.updated_at}
        for row in snapshot.upstream_limits.values()
        if row.origin == "adaptive"
    ][:MAX_CHANGES]
    policy = {
        key: settings.get(key)
        for key in (
            "adaptive_rate_enabled",
            "adaptive_decrease_pct",
            "adaptive_increase_pct",
            "adaptive_probe_after_h",
            "adaptive_min_per_min",
            "adaptive_max_per_min",
        )
    }
    return {
        "range": tr.info(),
        "enabled": bool(settings.get("adaptive_rate_enabled")),
        "settings": policy,
        "rates": held,
        "changes": changes,
        "changes_truncated": len(changes) >= MAX_CHANGES,
        "settings_card": "upstream#buckets",
    }


@router.get("/aimd")
async def aimd_state(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """Adaptive concurrency (plan 7.4, Tier 3): each host and egress key's limit and calls in flight now."""
    ctx = get_ctx(request)
    policy = aimd.AimdPolicy.from_settings(ctx.settings)
    with common.service_errors():
        rows = await ctx.dbs.hot.read(read_state.aimd_rows)
    return {
        "enabled": policy.enabled,
        "settings": {
            "aimd_initial": policy.initial,
            "aimd_min": policy.minimum,
            "aimd_max": policy.maximum,
            "aimd_increase_after": policy.increase_after,
            "aimd_decrease_factor": policy.decrease_factor,
        },
        "items": rows,
        "history": None,
        "history_note": "The limit and in-flight counts are kept as a current value only; there is no history table.",
        "settings_card": "upstream#concurrency",
    }


# ---------------------------------------------------------------------------------- cooldowns and breakers


@router.get("/cooldowns")
async def cooldown_list(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """Every active cooldown with its source and end time (the page counts down from `ends_at_ms`)."""
    ctx = get_ctx(request)
    upstream = _need(ctx.upstream, "upstream service")
    with common.service_errors():
        rows = await upstream.cooldown_snapshot(MAX_COOLDOWNS)
    now_ms = int(ctx.clock.now_ms())
    items = [
        {
            "key": row.key,
            **read_state.describe_key(row.key),
            "source": row.source,
            "ends_at_ms": row.until_ms,
            "remaining_s": round(row.remaining_s(now_ms), 1),
            "set_at": row.set_at,
            "hits": row.hits,
        }
        for row in rows
    ]
    local = [
        {"key": row.key, **read_state.describe_key(row.key), "source": row.source, "ends_at_ms": row.until_ms}
        for row in upstream.local_cooldowns.pending(now_ms)
    ][:MAX_COOLDOWNS]
    return {
        "now_ms": now_ms,
        "items": items,
        "local": local,
        "local_note": "Cooldowns this worker opened while hot.db could not be written; shared once it can be.",
        "settings_card": "upstream#cooldowns",
    }


@router.get("/breakers")
async def breaker_list(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """Breakers that are open, half-open or counting failures (plan 7.10), with when an open one may probe again."""
    ctx = get_ctx(request)
    upstream = _need(ctx.upstream, "upstream service")
    with common.service_errors():
        rows = await upstream.breaker_snapshot(MAX_BREAKERS)
    now_ms = int(ctx.clock.now_ms())
    items = []
    for row in rows:
        reopens = float(row.get("reopens_in_s") or 0.0)
        items.append(
            {
                **row,
                **read_state.describe_key(str(row.get("key"))),
                "reopens_at_ms": now_ms + int(reopens * 1000) if reopens > 0 else None,
            }
        )
    return {"now_ms": now_ms, "items": items, "settings_card": "upstream#breakers"}


class ResetBody(ApiBody):
    """`POST /upstream/reset`: why (required; it goes in the audit row)."""

    reason: Annotated[str, Field(max_length=MAX_REASON_LENGTH)]


@router.post("/reset")
async def reset_state(request: Request, admin: AdminSession, _csrf: CsrfChecked, body: ResetBody) -> dict[str, Any]:
    """Clear every cooldown and breaker, fleet-wide (plan 6.8 "Upstream state"). Buckets are never refilled.

    The audit row (`upstream.reset_state`) records the exact counts; a chart marker (kind `config_change`, because
    no metric data is deleted, so KPIs get no partial-data notice) links to it.
    """
    reason = common.require_reason(body.reason, required=True)
    ctx = get_ctx(request)
    upstream = _need(ctx.upstream, "upstream service")
    with common.service_errors():
        counts = await upstream.reset_state()
    now = int(ctx.clock.now())
    actor = common.actor_for(admin)
    request_id = common.request_id_of(request)
    after = {"cooldowns_cleared": counts.get("cooldowns", 0), "breakers_cleared": counts.get("breakers", 0)}
    warnings: list[str] = []
    audit_id: int | None = None
    try:
        audit_id = await ctx.dbs.control.write(
            lambda conn: audit.record(
                conn, actor, RESET_ACTION, "upstream_state", None, after, reason, request_id, at=now
            )
        )
    except SharedStateUnavailable:
        log.error("upstream_reset_audit_failed", extra={"fields": after})
        warnings.append("The reset was applied, but control.db was busy and its audit row could not be written.")
    label = f"Upstream state reset: {after['cooldowns_cleared']} cooldowns, {after['breakers_cleared']} breakers"
    try:
        await ctx.dbs.metrics.write(
            lambda conn: read_upstream.insert_annotation(conn, now, "config_change", label, audit_id)
        )
    except SharedStateUnavailable:
        warnings.append("The chart marker could not be written (metrics.db busy).")
    return {"cleared": after, "buckets": "unchanged", "audit_id": audit_id, "warnings": warnings}


# --------------------------------------------------------------------------------- retries and internal calls


@router.get("/retries")
async def retries(request: Request, _admin: AdminSession, tr: TimeRangeDep) -> dict[str, Any]:
    """Retries by status, reason and egress (parity row 117), CSRF retries, and upstream calls by attempt kind."""
    ctx = get_ctx(request)
    window = tr.window

    def read(conn: Any) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        return queries.retry_stats(conn, window), read_upstream.attempt_kind_totals(conn, window.start, window.end)

    stats, kinds = await ctx.dbs.metrics.read(read)
    by_kind: dict[str, int] = {}
    for row in kinds:
        by_kind[row["kind"]] = by_kind.get(row["kind"], 0) + int(row["calls"])
    return {
        "range": tr.info(),
        **stats,
        "csrf_retries": int(stats["by_reason"].get("CSRF token refresh", 0)),
        "attempt_kinds": by_kind,
        "attempt_kinds_by_egress": kinds,
        "settings_card": "upstream#retries",
    }


def _internal_health(item: Mapping[str, Any]) -> str:
    if not item.get("count"):
        return "not_called"
    last_error = item.get("last_error_ms") or 0
    if item.get("failed") and last_error >= int(item.get("last_ms") or 0):
        return "failing"
    return "ok"


@router.get("/internal-calls")
async def internal_calls(request: Request, _admin: AdminSession, tr: TimeRangeDep) -> dict[str, Any]:
    """Roxy's own upstream calls (probes, lookups, health checks): the list, counts, failures and health."""
    ctx = get_ctx(request)
    window = tr.window
    stats = await ctx.dbs.metrics.read(lambda conn: queries.internal_calls(conn, window))
    by_purpose = {str(row["purpose"]): row for row in stats}
    listed = internal_endpoints(
        str(ctx.settings.get("credential_probe_url")), str(getattr(ctx.env, "rotator_ip_echo_url", "") or "")
    )
    items = []
    for entry in listed:
        found = by_purpose.pop(entry["Purpose"], {})
        item = {"purpose": entry["Purpose"], "url": entry["URL"], "what": entry["What"], **dict(found)}
        item.setdefault("count", 0)
        items.append(item)
    for purpose, found in by_purpose.items():
        items.append({"purpose": purpose, "url": None, "what": None, **dict(found)})
    for item in items:
        item["purpose"] = str(item["purpose"])
        item["health"] = _internal_health(item)
    return {"range": tr.info(), "note": INTERNAL_NOTE, "items": items}


# ------------------------------------------------------------------------------------------------ trace


def _flagged_calls(conn: Any, template: str, egress: str, minute: int) -> dict[str, int]:
    """Calls to `template` through `egress` in the minute starting at `minute`, and how many of them Roblox
    answered with a challenge or an HTML page (`read_history.attempt_rows`, one indexed minute)."""
    rows = read_history.attempt_rows(conn, minute, minute + 60, template)
    mine = [row for row in rows if not egress or row.get("egress") == egress]
    return {
        "calls": sum(int(row["count"]) for row in mine),
        "challenges": sum(int(row["count"]) for row in mine if row.get("challenge")),
        "html_bodies": sum(int(row["count"]) for row in mine if row.get("html_body")),
    }


@router.get("/trace/{request_id}")
async def trace(
    request: Request,
    _admin: AdminSession,
    request_id: Annotated[str, Path(min_length=1, max_length=64)],
) -> dict[str, Any]:
    """What happened to one request and why it waited (plan 7.12), from what Roxy keeps across every worker."""
    clean = request_id.strip().upper()
    minted = read_upstream.ulid_time_ms(clean)
    if minted is None or not _REQUEST_ID.fullmatch(clean):
        raise common.validation_error(
            {"request_id": "A request id is the 26 character Roxy-Request-Id value."}, code="invalid_request_id"
        )
    ctx = get_ctx(request)
    settings = ctx.settings
    deadline_s = int(settings.get("request_deadline_s"))
    start_ms = minted - TRACE_BEFORE_MS
    end_ms = minted + (deadline_s + TRACE_SLACK_S) * 1000
    lookback_ms = int(float(settings.get("cooldown_max_s")) * 1000)
    ttl_s = int(settings.get("capture_ttl_seconds"))
    now = ctx.clock.now()

    def read(conn: Any) -> read_trace.WaitFacts:
        row = read_upstream.live_row(conn, clean, start_ms, end_ms)
        own_429s = read_upstream.request_429_rows(conn, clean, start_ms, end_ms)
        prior: list[dict[str, Any]] = []
        buckets: dict[str, dict[str, Any]] = {}
        flagged: dict[str, int] = {}
        if row is not None:
            at_ms = int(row.get("at_ms") or minted)
            template = str(row.get("template") or "")
            if template:
                prior = read_upstream.recent_429s_for(conn, template, at_ms, lookback_ms)
            minute = (min(at_ms, minted + deadline_s * 1000) // 1000) // 60 * 60
            buckets = read_history.bucket_summary(conn, minute, minute + 60, read_trace.request_bucket_keys(row))
            if template:
                flagged = _flagged_calls(conn, template, str(row.get("egress") or ""), minute)
        captured = capture.get_capture(conn, clean, now, ttl_s) is not None
        return read_trace.WaitFacts(
            request_id=clean,
            minted_at_ms=minted,
            live=row,
            roblox_429s=own_429s,
            prior_429s=prior,
            buckets=buckets,
            queue_budget_ms=float(settings.get("queue_wait_interactive_ms")),
            capture_available=captured,
            flagged_calls=flagged,
        )

    facts = await ctx.dbs.metrics.read(read)
    explanation = read_trace.explain_wait(facts)
    return {"request_id": clean, "minted_at_ms": minted, "live": facts.live, **explanation}


__all__ = ["BUCKETS_SPEC", "CHALLENGES_SPEC", "FAILURES_SPEC", "HOSTS_SPEC", "router"]
