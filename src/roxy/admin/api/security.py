"""The Security page API (`/admin/api/v1/security`): logins, probes, crawls, fingerprints, CSP reports, sessions,
trusted devices, passkeys and recovery codes.

What this is
    The routes behind plan 14.1 "Security", in the DESIGN.md section 13 shapes:
      * Event logs, paged on the server and exportable (parity rows 80, 97): admin logins and failed logins
        (`result` filter), probes and exploit attempts, the probe summary by signature, crawls by client.
      * Request fingerprints (rows 79, 134): header names with their value statistics, one header's values,
        User-Agents, the blocked variants (headers and User-Agents of requests a request filter refused), and the
        ignored headers (values not recorded) with add and remove.
      * CSP violation reports (plan 9.2), grouped by what was blocked.
      * The admin's own sessions (list, revoke one, revoke the others, sign out everywhere), trusted devices (list,
        revoke one or all), passkeys (list; rename and delete with a fresh second factor) and recovery codes
        (status; regenerate with a fresh second factor).

Why it exists
    The auth package already answers these account actions on `/admin/api/v1/auth/*` in v1's shapes for the login
    pages; the dashboard's Security page reads everything here in one convention (section 13 tables and errors) next
    to the security event logs. Both surfaces call the same auth functions, so there is one implementation of each
    action (the session and device functions of `admin/auth/sessions.py` and `trusted_devices.py`, the recovery code
    and passkey functions of `admin/auth/enrollment.py`), each writing its audit row in the same transaction.

How it works
    - Logs read `metrics/security_events.py ring` and `summary_by_*`; fingerprints and CSP reports read
      `metrics/read_security.py`. Stored values are scrubbed or hashed at write time, so nothing here can reveal a
      secret.
    - An ignored header is a row of the `ignored_value_headers` rule table (rules service: validation, audit,
      `config_version`); adding one also deletes the values already stored for it (`metrics/fingerprints.py
      clear_values`, v1 "No longer recording values"). Removing it starts recording again.
    - `AuthError` refusals of the auth functions (a busy hasher, shared state down) become section 13 errors with
      the same status. Passkey rename has no auth function yet: it is one control.db transaction here (update the
      name, audit row), and the report asks for it to move into `admin/auth/enrollment.py`.
    - Regenerated recovery codes are the one secret this API returns: shown once, never stored in clear, never
      logged, and answered with `Cache-Control: no-store` like every admin answer.

What to read next
    `roxy/metrics/security_events.py`, `roxy/metrics/read_security.py`, `roxy/admin/auth/enrollment.py`, then
    `roxy/admin/api/protection.py`.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import replace
from typing import Annotated, Any, Final, Literal

from fastapi import Depends, Path, Query, Request
from pydantic import Field
from starlette.responses import JSONResponse, Response

from roxy.admin.api.common import (
    AdminFreshMfa,
    AdminSession,
    ApiBody,
    ApiError,
    Column,
    CsrfChecked,
    ExportFormat,
    ExportFormatDep,
    TableQuery,
    TableSpec,
    TimeRange,
    TimeRangeDep,
    actor_for,
    area_router,
    collect_pages,
    export_table,
    not_found,
    page_rows,
    request_id_of,
    run_mutation,
    service_errors,
    table_answer,
    table_params,
    validation_error,
)
from roxy.admin.api.protection import audit_reason
from roxy.admin.auth import enrollment, sessions, trusted_devices, webauthn
from roxy.admin.auth.deps import STATE_SESSION, AdminPrincipal, get_auth, request_info
from roxy.admin.auth.events import audit_auth
from roxy.admin.auth.flow import AuthError
from roxy.admin.auth.responses import clear_session_cookie
from roxy.config.constants import MAX_REASON_LENGTH
from roxy.deps import get_ctx
from roxy.metrics import read_security, security_events
from roxy.metrics.fingerprints import clear_values
from roxy.rules.service import RuleChange, RulesService

router = area_router("security")

MAX_SUMMARY_ROWS: Final = 1000
"""Grouped summaries read at most this many groups (plan P9); the table pages through them."""
_AUTH_CODES: Final[dict[int, str]] = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    409: "conflict",
    429: "rate_limited",
    503: "unavailable",
}


# =============================================================================================== helpers


def auth_error(error: AuthError) -> ApiError:
    """An auth refusal (v1-shaped body) as a section 13 error with the same status and headers."""
    status = error.status if 400 <= error.status <= 599 else 500
    body = error.body if isinstance(error.body, str) else "The request was refused."
    return ApiError(status, _AUTH_CODES.get(status, "bad_request"), body, headers=error.headers or None)


async def _auth_call[T](call: Awaitable[T]) -> T:
    try:
        return await call
    except AuthError as error:
        raise auth_error(error) from None


def _session_record(request: Request) -> sessions.SessionRecord:
    record = getattr(request.state, STATE_SESSION, None)
    if not isinstance(record, sessions.SessionRecord):  # pragma: no cover - the guard always ran first
        raise not_found()
    return record


Fetch = Callable[[int, int], Awaitable[tuple[Sequence[Any], int]]]


async def _paged(
    request: Request,
    admin: AdminPrincipal,
    spec: TableSpec,
    tq: TableQuery,
    fmt: ExportFormat | None,
    fetch: Fetch,
    *,
    tr: TimeRange | None = None,
    filters: dict[str, Any] | None = None,
) -> Any:
    with service_errors():
        if fmt is not None:
            rows, total = await collect_pages(fetch)
            return await export_table(request, admin, spec, rows, fmt, total=total, tq=tq, tr=tr, filters=filters)
        items, total = await fetch(tq.page, tq.page_size)
    answer = table_answer(spec, tq, items, total)
    if tr is not None:
        answer["range"] = tr.info()
    return answer


async def _listed(
    request: Request,
    admin: AdminPrincipal,
    spec: TableSpec,
    tq: TableQuery,
    fmt: ExportFormat | None,
    rows: Sequence[dict[str, Any]],
    *,
    search_keys: Sequence[str],
    tr: TimeRange | None = None,
) -> Any:
    if fmt is not None:
        everything, total = page_rows(rows, replace(tq, page=1, page_size=max(1, len(rows))), search_keys=search_keys)
        return await export_table(request, admin, spec, everything, fmt, total=total, tq=tq, tr=tr)
    items, total = page_rows(rows, tq, search_keys=search_keys)
    answer = table_answer(spec, tq, items, total)
    if tr is not None:
        answer["range"] = tr.info()
    return answer


def _only_newest_first(tq: TableQuery) -> None:
    if tq.order != "desc":
        raise validation_error({"order": "This log is listed newest first only."}, code="invalid_table_query")


# =============================================================================================== logins, probes, crawls


LOGIN_SPEC: Final = TableSpec(
    name="admin_logins",
    columns=(
        Column("at_ms", "When", "When the attempt happened (newest first).", "timestamp_ms"),
        Column("ip", "IP", "Where the attempt came from.", ip=True, sortable=False),
        Column("successful", "Successful", "Whether the admin got in.", sortable=False),
        Column("username", "Username", "The account named (failed attempts may name any).", sortable=False),
        Column("method", "Method", "The step or factor used.", sortable=False),
        Column("reason", "Result", "success or failure.", sortable=False),
    ),
    default_sort="at_ms",
)  # fmt: skip
PROBE_SPEC: Final = TableSpec(
    name="probes",
    columns=(
        Column("at_ms", "When", "When the probe arrived (newest first).", "timestamp_ms"),
        Column("ip", "IP", "Who sent it.", ip=True, sortable=False),
        Column("reason", "Signature", "The probe signature (v1 reason, without the probed URL).", sortable=False),
        Column("target", "Target", "What was probed (redacted).", sortable=False),
        Column("path", "Path", "The path asked for (redacted).", sortable=False),
        Column("user_agent", "User-Agent", "Its User-Agent.", sortable=False),
        Column("count", "Count", "1, or the number of probes folded into this row over the event budget.", "count",
               sortable=False),
    ),
    default_sort="at_ms",
)  # fmt: skip
SUMMARY_SPEC: Final = TableSpec(
    name="probe_summary",
    columns=(
        Column("reason", "Signature", "The probe signature."),
        Column("count", "Count", "Probes with this signature in the range.", "count"),
        Column("first_ms", "First seen", "The first one in the range.", "timestamp_ms"),
        Column("last_ms", "Last seen", "The latest one.", "timestamp_ms"),
    ),
    default_sort="count",
)
CRAWL_SPEC: Final = TableSpec(
    name="crawls",
    columns=(
        Column("ip", "IP", "Who fetched robots.txt or sitemap.xml.", ip=True),
        Column("count", "Count", "Fetches in the range.", "count"),
        Column("last_ms", "Last fetch", "The latest one.", "timestamp_ms"),
    ),
    default_sort="count",
)


def _ring_fetch(
    request: Request, event_type: str, tr: TimeRange, *, ip: str | None = None, reason: str | None = None
) -> Fetch:
    ctx = get_ctx(request)

    async def fetch(page: int, size: int) -> tuple[Sequence[Any], int]:
        data = await ctx.dbs.metrics.read(
            lambda conn: security_events.ring(
                conn, event_type, since_ms=tr.window.start * 1000, until_ms=tr.window.end * 1000, ip=ip,
                reason=reason, limit=size, offset=(page - 1) * size,
            )
        )  # fmt: skip
        return data["items"], int(data["total"])

    return fetch


@router.get("/logins")
async def logins(
    request: Request,
    admin: AdminSession,
    tr: TimeRangeDep,
    tq: Annotated[TableQuery, Depends(table_params(LOGIN_SPEC))],
    fmt: ExportFormatDep,
    result: Annotated[Literal["all", "success", "failure"], Query()] = "all",
    ip: Annotated[str | None, Query(max_length=64)] = None,
) -> Any:
    """Admin login attempts, newest first; `result=failure` is the failed logins list (rows 80, 97)."""
    _only_newest_first(tq)
    reason = None if result == "all" else result
    fetch = _ring_fetch(request, security_events.LOGIN, tr, ip=ip or None, reason=reason)
    return await _paged(request, admin, LOGIN_SPEC, tq, fmt, fetch, tr=tr, filters={"result": result, "ip": ip})


@router.get("/probes")
async def probes(
    request: Request,
    admin: AdminSession,
    tr: TimeRangeDep,
    tq: Annotated[TableQuery, Depends(table_params(PROBE_SPEC))],
    fmt: ExportFormatDep,
    ip: Annotated[str | None, Query(max_length=64)] = None,
    signature: Annotated[str | None, Query(max_length=200)] = None,
) -> Any:
    """Probe and exploit attempts, newest first (v1 "Exploit / Probe Attempts", row 80)."""
    _only_newest_first(tq)
    fetch = _ring_fetch(request, security_events.PROBE, tr, ip=ip or None, reason=signature or None)
    return await _paged(request, admin, PROBE_SPEC, tq, fmt, fetch, tr=tr, filters={"ip": ip, "signature": signature})


@router.get("/probes/summary")
async def probe_summary(
    request: Request,
    admin: AdminSession,
    tr: TimeRangeDep,
    tq: Annotated[TableQuery, Depends(table_params(SUMMARY_SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    """Probes grouped by signature in the range (v1 "Exploit / Probe Summary"; v1 bug B19 fixed by signatures)."""
    ctx = get_ctx(request)
    start, end = tr.window.start * 1000, tr.window.end * 1000
    with service_errors():
        rows = await ctx.dbs.metrics.read(
            lambda conn: security_events.summary_by_reason(conn, security_events.PROBE, start, end, MAX_SUMMARY_ROWS)
        )
    return await _listed(request, admin, SUMMARY_SPEC, tq, fmt, rows, search_keys=("reason",), tr=tr)


@router.get("/crawls")
async def crawls(
    request: Request,
    admin: AdminSession,
    tr: TimeRangeDep,
    tq: Annotated[TableQuery, Depends(table_params(CRAWL_SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    """robots.txt and sitemap fetches by client in the range (v1 "Crawler Activity", row 80)."""
    ctx = get_ctx(request)
    start, end = tr.window.start * 1000, tr.window.end * 1000
    with service_errors():
        rows = await ctx.dbs.metrics.read(
            lambda conn: security_events.summary_by_ip(conn, security_events.CRAWL, start, end, MAX_SUMMARY_ROWS)
        )
    return await _listed(request, admin, CRAWL_SPEC, tq, fmt, rows, search_keys=("ip",), tr=tr)


# =============================================================================================== fingerprints


HEADER_SPEC: Final = TableSpec(
    name="fingerprint_headers",
    columns=(
        Column("name", "Header name", "Lowercase; a secret-shaped name is shown as fp:<hash>."),
        Column("count", "Count", "Requests that carried it.", "count"),
        Column("value_count", "Values", "Distinct values stored (capped per header).", "count"),
        Column("unique_ratio", "Unique ratio", "Stored values per request that carried one (1 means always new).",
               "ratio", sortable=False),
        Column("values_ignored", "Values ignored", "Its values are not recorded (an ignored header).",
               sortable=False),
        Column("high_cardinality", "High cardinality", "90% or more of its values were new (consider ignoring).",
               sortable=False),
        Column("first_seen", "First seen", "First request that carried it.", "timestamp"),
        Column("last_seen", "Last seen", "Latest request that carried it.", "timestamp"),
    ),
    default_sort="count",
)  # fmt: skip
VALUE_SPEC: Final = TableSpec(
    name="fingerprint_values",
    columns=(
        Column("value", "Value", "Scrubbed; sensitive values are stored as fp:<hash>."),
        Column("count", "Count", "Requests that carried it.", "count"),
        Column("first_seen", "First seen", "First request that carried it.", "timestamp", sortable=False),
        Column("last_seen", "Last seen", "Latest request that carried it.", "timestamp"),
    ),
    default_sort="count",
)  # fmt: skip
UA_SPEC: Final = TableSpec(
    name="fingerprint_user_agents",
    columns=(
        Column("user_agent", "User-Agent", "As sent (scrubbed); (none) for requests without one."),
        Column("count", "Count", "Requests that sent it.", "count"),
        Column("first_seen", "First seen", "First request.", "timestamp"),
        Column("last_seen", "Last seen", "Latest request.", "timestamp"),
    ),
    default_sort="count",
)
IGNORED_SPEC: Final = TableSpec(
    name="ignored_headers",
    columns=(
        Column("name", "Header", "Values of this header are not recorded (its count still is)."),
        Column("why", "Why", "Detected automatically, a default, or added by an admin.", sortable=False),
        Column("note", "Detail", "The note (an automatic entry says how unique its values were).", sortable=False),
    ),
    default_sort="name",
    default_order="asc",
)  # fmt: skip


def _ignored(ctx: Any) -> frozenset[str]:
    names: frozenset[str] = ctx.rules.snapshot.ignored_value_headers
    return names


@router.get("/fingerprints/headers")
async def fingerprint_headers(
    request: Request,
    admin: AdminSession,
    tq: Annotated[TableQuery, Depends(table_params(HEADER_SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    """Header names callers send, with how many distinct values each carried (row 79)."""
    ctx = get_ctx(request)
    ignored = _ignored(ctx)

    async def fetch(page: int, size: int) -> tuple[Sequence[Any], int]:
        data = await ctx.dbs.metrics.read(
            lambda conn: read_security.header_names(
                conn, ignored=ignored, search=tq.q, sort=tq.sort, descending=tq.descending, limit=size,
                offset=(page - 1) * size,
            )
        )  # fmt: skip
        return data["rows"], int(data["total"])

    return await _paged(request, admin, HEADER_SPEC, tq, fmt, fetch)


@router.get("/fingerprints/headers/{name}/values")
async def fingerprint_values(
    request: Request,
    admin: AdminSession,
    name: Annotated[str, Path(min_length=1, max_length=120)],
    tq: Annotated[TableQuery, Depends(table_params(VALUE_SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    """One header's stored values, most frequent first (the v1 drill-down)."""
    ctx = get_ctx(request)
    key = name.lower()

    async def fetch(page: int, size: int) -> tuple[Sequence[Any], int]:
        data = await ctx.dbs.metrics.read(
            lambda conn: read_security.header_values(
                conn, key, sort=tq.sort, descending=tq.descending, limit=size, offset=(page - 1) * size
            )
        )
        return data["rows"], int(data["total"])

    answer = await _paged(request, admin, VALUE_SPEC, tq, fmt, fetch, filters={"name": key})
    if isinstance(answer, dict):
        answer["name"] = key
        answer["values_ignored"] = key in _ignored(ctx)
    return answer


@router.get("/fingerprints/user-agents")
async def fingerprint_user_agents(
    request: Request,
    admin: AdminSession,
    tq: Annotated[TableQuery, Depends(table_params(UA_SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    """User-Agents callers send (row 79)."""
    ctx = get_ctx(request)

    async def fetch(page: int, size: int) -> tuple[Sequence[Any], int]:
        data = await ctx.dbs.metrics.read(
            lambda conn: read_security.user_agents(
                conn, search=tq.q, sort=tq.sort, descending=tq.descending, limit=size, offset=(page - 1) * size
            )
        )
        return data["rows"], int(data["total"])

    return await _paged(request, admin, UA_SPEC, tq, fmt, fetch)


@router.get("/fingerprints/blocked")
async def fingerprint_blocked(request: Request, _admin: AdminSession, tr: TimeRangeDep) -> dict[str, Any]:
    """Header names and User-Agents of requests a request filter refused in the range (row 134, Blocked tab)."""
    ctx = get_ctx(request)
    start, end = tr.window.start * 1000, tr.window.end * 1000
    with service_errors():
        data = await ctx.dbs.metrics.read(lambda conn: read_security.blocked_fingerprints(conn, start, end))
    return {"range": tr.info(), **data}


@router.get("/fingerprints/ignored")
async def fingerprint_ignored(
    request: Request,
    admin: AdminSession,
    tq: Annotated[TableQuery, Depends(table_params(IGNORED_SPEC))],
    fmt: ExportFormatDep,
) -> Any:
    """Headers whose values are not recorded: detected automatically, a shipped default, or added by an admin."""
    ctx = get_ctx(request)
    with service_errors():
        stored = await _rules(ctx).list_rows("ignored_value_headers")
    rows = []
    for row in stored:
        note = str(row.get("note") or "")
        why = "Detected automatically" if row.get("auto") else ("Default" if note == "default" else "Added by an admin")
        rows.append({"name": row["name"], "why": why, "note": note, "auto": bool(row.get("auto"))})
    return await _listed(request, admin, IGNORED_SPEC, tq, fmt, rows, search_keys=("name", "note"))


def _rules(ctx: Any) -> RulesService:
    return RulesService(ctx.dbs.control, clock=ctx.clock, store=ctx.rules)


def _change(change: RuleChange) -> dict[str, Any]:
    return {
        "action": change.action,
        "key": change.key,
        "changed": change.changed,
        "item": change.after,
        "config_version": change.config_version,
        "audit_id": change.audit_id,
    }


class IgnoreBody(ApiBody):
    """Stop recording the values of one header (its count is still kept)."""

    name: str = Field(min_length=1, max_length=480)
    note: str = Field("", max_length=MAX_REASON_LENGTH)
    reason: str | None = Field(None, max_length=MAX_REASON_LENGTH)


@router.post("/fingerprints/ignored")
async def fingerprint_ignore(
    request: Request, admin: AdminSession, _csrf: CsrfChecked, body: IgnoreBody
) -> dict[str, Any]:
    """Ignore a header's values (rule table `ignored_value_headers`) and delete the values already stored."""
    ctx = get_ctx(request)
    row = {"name": body.name, "note": body.note}
    change = await run_mutation(
        _rules(ctx).create(
            "ignored_value_headers", row, actor_for(admin), audit_reason(body.reason), request_id=request_id_of(request)
        )
    )
    name = str(change.key)
    with service_errors():
        removed: int = await ctx.dbs.metrics.write(lambda conn: clear_values(conn, name), busy_timeout_ms=2000)
    answer = _change(change)
    answer["values_removed"] = removed
    return answer


@router.delete("/fingerprints/ignored/{name}")
async def fingerprint_unignore(
    request: Request,
    admin: AdminSession,
    _csrf: CsrfChecked,
    name: Annotated[str, Path(min_length=1, max_length=120)],
    reason: Annotated[str | None, Query(max_length=MAX_REASON_LENGTH)] = None,
) -> dict[str, Any]:
    """Record a header's values again."""
    ctx = get_ctx(request)
    change = await run_mutation(
        _rules(ctx).delete(
            "ignored_value_headers", name.lower(), actor_for(admin), audit_reason(reason),
            request_id=request_id_of(request),
        )
    )  # fmt: skip
    return _change(change)


# =============================================================================================== CSP reports


CSP_SPEC: Final = TableSpec(
    name="csp_reports",
    columns=(
        Column("directive", "Directive", "The CSP directive that refused something.", sortable=False),
        Column("blocked", "Blocked", "What the browser refused to load or run.", sortable=False),
        Column("document", "Page", "The page it happened on.", sortable=False),
        Column("source", "Source file", "The file that tried.", sortable=False),
        Column("disposition", "Disposition", "enforce or report.", sortable=False),
        Column("count", "Count", "Reports in the range.", "count"),
        Column("last_ms", "Last seen", "The latest report.", "timestamp_ms"),
    ),
    default_sort="count",
)


@router.get("/csp-reports")
async def csp_reports(
    request: Request,
    admin: AdminSession,
    tr: TimeRangeDep,
    tq: Annotated[TableQuery, Depends(table_params(CSP_SPEC))],
    fmt: ExportFormatDep,
    directive: Annotated[str | None, Query(max_length=64, pattern=r"^[a-z-]+$")] = None,
) -> Any:
    """Content-Security-Policy violation reports in the range, grouped by what was blocked (plan 9.2)."""
    ctx = get_ctx(request)
    start, end = tr.window.start * 1000, tr.window.end * 1000

    async def fetch(page: int, size: int) -> tuple[Sequence[Any], int]:
        data = await ctx.dbs.metrics.read(
            lambda conn: read_security.csp_reports(
                conn, start, end, directive=directive or "", sort=tq.sort, descending=tq.descending, limit=size,
                offset=(page - 1) * size,
            )
        )  # fmt: skip
        return data["rows"], int(data["total"])

    return await _paged(request, admin, CSP_SPEC, tq, fmt, fetch, tr=tr, filters={"directive": directive})


# =============================================================================================== sessions


@router.get("/sessions")
async def session_list(request: Request, admin: AdminSession) -> dict[str, Any]:
    """The admin's unexpired sessions, newest first (`current` marks this browser)."""
    auth = get_auth(request)
    now = int(auth.clock.now())
    rows = await _auth_call(auth.control_read(lambda conn: sessions.list_for_user(conn, admin.user_id, now)))
    current = sessions.public_id(admin.session_id)
    items = [
        {
            "id": row["Id"],
            "created_at": row["CreatedAt"],
            "last_seen_at": row["LastSeenAt"],
            "expires_at": row["ExpiresAt"],
            "ip": row["IP"],
            "user_agent": row["UserAgent"],
            "mfa_level": row["MfaLevel"],
            "current": row["Id"] == current,
        }
        for row in rows
    ]
    return {"items": items, "total": len(items), "current": current}


async def _revoke_sessions(request: Request, admin: AdminPrincipal, mode: str, short_id: str | None) -> Response:
    """Revoke sessions with the auth package's functions and its audit row, in one control.db transaction."""
    auth = get_auth(request)
    info = request_info(request)
    now = int(auth.clock.now())
    actions = {
        "one": "auth.session_revoked",
        "others": "auth.sessions_revoked_others",
        "all": "auth.sessions_revoked_all",
    }

    def write(conn: sqlite3.Connection) -> int:
        if mode == "one":
            count = 1 if sessions.revoke_public(conn, admin.user_id, short_id or "") else 0
        elif mode == "others":
            count = sessions.revoke_user(conn, admin.user_id, keep=admin.session_id)
        else:
            count, _epoch = sessions.revoke_all(conn, now)
        if count:
            audit_auth(
                conn, actions[mode], user_id=admin.user_id, username=admin.username, ip=info.ip,
                request_id=info.request_id, after={"sessions_ended": count, "session": short_id}, at=now,
            )  # fmt: skip
        return count

    count = await _auth_call(auth.control_write(write))
    if mode == "one" and count == 0:
        raise not_found("No session of yours has that id.")
    signed_out = mode == "all" or (mode == "one" and short_id == sessions.public_id(admin.session_id))
    response = JSONResponse({"revoked": count, "signed_out": signed_out})
    if signed_out:
        clear_session_cookie(response)
    return response


@router.post("/sessions/{session_id}/revoke")
async def session_revoke(
    request: Request,
    admin: AdminSession,
    _csrf: CsrfChecked,
    session_id: Annotated[str, Path(pattern=r"^[0-9a-f]{16}$")],
) -> Response:
    """End one of your sessions (this browser's too, which signs it out)."""
    return await _revoke_sessions(request, admin, "one", session_id)


@router.post("/sessions/revoke-others")
async def session_revoke_others(request: Request, admin: AdminSession, _csrf: CsrfChecked) -> Response:
    """End every other session of yours."""
    return await _revoke_sessions(request, admin, "others", None)


@router.post("/sessions/revoke-all")
async def session_revoke_all(request: Request, admin: AdminSession, _csrf: CsrfChecked) -> Response:
    """Sign out everywhere (the epoch kill switch from the dashboard), this browser included."""
    return await _revoke_sessions(request, admin, "all", None)


# =============================================================================================== trusted devices


@router.get("/trusted-devices")
async def trusted_list(request: Request, admin: AdminSession) -> dict[str, Any]:
    """Trusted devices (row 100): name, browser family, last use; `this_device` marks this browser."""
    auth = get_auth(request)
    now = int(auth.clock.now())
    rows = await _auth_call(auth.control_read(lambda conn: trusted_devices.list_for_user(conn, admin.user_id, now)))
    this_device = None
    cookie = request.cookies.get(trusted_devices.TRUSTED_COOKIE)
    if cookie:
        try:
            found = await auth.control_read(lambda conn: trusted_devices.find_valid(conn, cookie, admin.ua, now))
            this_device = found.id if found is not None and found.user_id == admin.user_id else None
        except AuthError:
            this_device = None
    items = [
        {
            "id": row["Id"],
            "name": row["Name"],
            "family": row["Family"],
            "created_at": row["CreatedAt"],
            "last_used_at": row["LastUsedAt"],
            "expires_at": row["ExpiresAt"],
            "this_device": row["Id"] == this_device,
        }
        for row in rows
    ]
    return {
        "items": items,
        "total": len(items),
        "enabled": bool(auth.settings.bool("admin_trusted_devices_enabled")),
        "this_device": this_device,
    }


async def _revoke_trusted(request: Request, admin: AdminPrincipal, device_id: int | None) -> int:
    auth = get_auth(request)
    info = request_info(request)
    now = int(auth.clock.now())

    def write(conn: sqlite3.Connection) -> int:
        if device_id is None:
            count = trusted_devices.revoke_all(conn, admin.user_id)
        else:
            count = 1 if trusted_devices.revoke(conn, admin.user_id, device_id) else 0
        if count:
            audit_auth(
                conn,
                "auth.trusted_devices_revoked_all" if device_id is None else "auth.trusted_device_revoked",
                user_id=admin.user_id, username=admin.username, ip=info.ip, request_id=info.request_id,
                after={"revoked": count, "device_id": device_id}, at=now,
            )  # fmt: skip
        return count

    count: int = await _auth_call(auth.control_write(write))
    return count


@router.post("/trusted-devices/{device_id}/revoke")
async def trusted_revoke(
    request: Request, admin: AdminSession, _csrf: CsrfChecked, device_id: Annotated[int, Path(ge=1, le=2**62)]
) -> dict[str, Any]:
    """Revoke one trusted device (it needs the full second factor next time)."""
    if await _revoke_trusted(request, admin, device_id) == 0:
        raise not_found("No trusted device of yours has that id.")
    return {"revoked": 1}


@router.post("/trusted-devices/revoke-all")
async def trusted_revoke_all(request: Request, admin: AdminSession, _csrf: CsrfChecked) -> Response:
    """Revoke every trusted device, this browser's included (its cookie is cleared too)."""
    count = await _revoke_trusted(request, admin, None)
    response = JSONResponse({"revoked": count})
    response.delete_cookie(trusted_devices.TRUSTED_COOKIE, path="/", secure=True, httponly=True, samesite="strict")
    return response


# =============================================================================================== passkeys


class PasskeyRename(ApiBody):
    name: str = Field(min_length=1, max_length=webauthn.MAX_NAME)


@router.get("/passkeys")
async def passkey_list(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """Your passkeys (never the key material)."""
    record = _session_record(request)
    items = await _auth_call(enrollment.passkey_list(get_auth(request), record))
    keys = [
        {"id": item["Id"], "name": item["Name"], "created_at": item["CreatedAt"], "last_used_at": item["LastUsedAt"]}
        for item in items
    ]
    return {"items": keys, "total": len(keys), "max": webauthn.MAX_PASSKEYS_PER_USER}


@router.patch("/passkeys/{passkey_id}")
async def passkey_rename(
    request: Request,
    admin: AdminFreshMfa,
    _csrf: CsrfChecked,
    passkey_id: Annotated[int, Path(ge=1, le=2**62)],
    body: PasskeyRename,
) -> dict[str, Any]:
    """Rename a passkey (fresh second factor). One transaction: the new name and its audit row."""
    auth = get_auth(request)
    info = request_info(request)
    now = int(auth.clock.now())
    clean = " ".join(body.name.split())[: webauthn.MAX_NAME]
    if not clean:
        raise validation_error({"name": "Give the passkey a name."})

    def write(conn: sqlite3.Connection) -> str | None:
        row = conn.execute(
            "SELECT name FROM admin_passkeys WHERE id = ? AND user_id = ?", (passkey_id, admin.user_id)
        ).fetchone()
        if row is None:
            return None
        before = str(row[0] or "")
        if before != clean:
            conn.execute("UPDATE admin_passkeys SET name = ? WHERE id = ? AND user_id = ?", (clean, passkey_id,
                                                                                            admin.user_id))  # fmt: skip
            audit_auth(
                conn, "auth.passkey_renamed", user_id=admin.user_id, username=admin.username, ip=info.ip,
                request_id=info.request_id, before={"passkey_id": passkey_id, "name": before},
                after={"passkey_id": passkey_id, "name": clean}, at=now,
            )  # fmt: skip
        return before

    before = await _auth_call(auth.control_write(write))
    if before is None:
        raise not_found("No passkey of yours has that id.")
    return {"id": passkey_id, "name": clean, "changed": before != clean}


@router.delete("/passkeys/{passkey_id}")
async def passkey_delete(
    request: Request,
    _admin: AdminFreshMfa,
    _csrf: CsrfChecked,
    passkey_id: Annotated[int, Path(ge=1, le=2**62)],
) -> dict[str, Any]:
    """Delete a passkey (fresh second factor)."""
    record = _session_record(request)
    removed = await _auth_call(enrollment.passkey_delete(get_auth(request), request_info(request), record, passkey_id))
    if not removed:
        raise not_found("No passkey of yours has that id.")
    return {"removed": True}


# =============================================================================================== recovery codes


@router.get("/recovery-codes")
async def recovery_status(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """How many recovery codes you have left (never the codes)."""
    record = _session_record(request)
    status = await _auth_call(enrollment.recovery_status(get_auth(request), record))
    return {"total": status["Total"], "remaining": status["Remaining"]}


@router.post("/recovery-codes/regenerate")
async def recovery_regenerate(request: Request, _admin: AdminFreshMfa, _csrf: CsrfChecked) -> dict[str, Any]:
    """Replace every recovery code (fresh second factor). The new codes are shown once, here, and never again."""
    record = _session_record(request)
    codes = await _auth_call(enrollment.regenerate_recovery(get_auth(request), request_info(request), record))
    return {"codes": codes, "total": len(codes), "note": "Store these now; they are not shown again."}


__all__ = ["auth_error", "router"]
