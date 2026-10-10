"""Admin API: the Live page (`/admin/api/v1/live`, plan 14.1 Live row, parity rows 81, 82, 126 to 128).

What this is
    * `GET /live`: the live tail as a query: the newest requests of every worker (the last 15 minutes), filtered by
      outcome, reason, status (codes or classes), egress, cache state, client, endpoint and free text, newest
      first, with a `before` cursor to read further back. When the table holds no more matching rows and the first
      page still has room, it also brings this worker's own recent rows the table did not get (above 50 rows per
      second a worker writes only a sample).
    * `GET /live/state`: the capture window and caps (v1's "Capturing 12/250" chip) and the live row limits.
    * `GET /live/{request_id}`: the full detail of one request: its capture (request and response headers and
      bodies, redacted) and its live row. When the capture has aged out or was evicted the answer is 404 with v1's
      exact text, "That capture has expired or was evicted." (row 128); when the request was never captured
      (capture off, or a served request outside the sample) it is 404 `not_captured` with v1's "capture was off"
      text.

Why it exists
    v1 polled a merged JSON list every few seconds, missed two outcomes in its filter and showed captures only from
    the worker that buffered them (row 81, v1 bugs B16 and B17). v2 writes every request as an `events` row any
    worker can read; the event stream (`roxy/admin/sse.py`) pushes new rows as they happen, and this module answers
    the first screen, the filters and the click on a row.

How it works
    Rows come from `metrics/read_dashboard.py recent_live` (by event id, so a cursor never skips a row) and are
    filtered with `LiveQuery`, the same filter the event stream applies. At most `MAX_SCAN` rows are read per call
    (plan P9); when the filter matched fewer than asked, `next_before` lets the page read further back. Captures
    come from `metrics/capture.py get_capture`, which already redacted every header, the query and both bodies
    when the capture was made.

What to read next
    `roxy/admin/sse.py` (the stream), `roxy/metrics/live.py` (the rows), `roxy/metrics/capture.py`.
"""

from __future__ import annotations

import re
import sqlite3
from typing import Annotated, Any, Final

from fastapi import Path, Query, Request

from roxy.admin.api.common import MAX_ROW_ID, AdminSession, ApiError, area_router, validation_error
from roxy.deps import get_ctx
from roxy.metrics import read_dashboard
from roxy.metrics.capture import CAPTURE_EXPIRED_MESSAGE, CAPTURE_OFF_MESSAGE, CapturePolicy, capture_state, get_capture
from roxy.metrics.live import LIVE_EVENTS_PER_SECOND, LIVE_KEEP_S

router = area_router("live")

DEFAULT_LIMIT: Final = 100
MAX_LIMIT: Final = 500
MAX_SCAN: Final = read_dashboard.MAX_LIVE_ROWS
"""Live rows read per request at most, whatever the filter (plan P9)."""
REQUEST_ID_RE: Final = re.compile(r"[A-Za-z0-9_-]{1,64}")
CAPTURE_EXPIRED_CODE: Final = "capture_expired"
NOT_CAPTURED_CODE: Final = "not_captured"


def _query(
    outcome: str | None,
    reason: str | None,
    status: str | None,
    egress: str | None,
    cache: str | None,
    client: str | None,
    endpoint: str | None,
    q: str | None,
) -> read_dashboard.LiveQuery:
    query, problems = read_dashboard.parse_live_query(
        outcome=outcome, reason=reason, status=status, egress=egress, cache=cache, client=client, endpoint=endpoint, q=q
    )
    if problems:
        raise validation_error(problems, "The live filter is not valid.")
    return query


Text = Annotated[str | None, Query(max_length=read_dashboard.MAX_FILTER_TEXT * 4)]


@router.get("")
async def live_rows(
    request: Request,
    _admin: AdminSession,
    outcome: Text = None,
    reason: Text = None,
    status: Text = None,
    egress: Text = None,
    cache: Text = None,
    client: Text = None,
    endpoint: Text = None,
    q: Text = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
    before: Annotated[int | None, Query(ge=1, le=MAX_ROW_ID)] = None,
) -> dict[str, Any]:
    """The newest matching requests of every worker, newest first (see the module docstring)."""
    query = _query(outcome, reason, status, egress, cache, client, endpoint, q)
    ctx = get_ctx(request)
    pairs = await ctx.dbs.metrics.read(lambda conn: read_dashboard.recent_live(conn, MAX_SCAN, before))
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    next_before: int | None = None
    full = False
    for event_id, row in pairs:
        next_before = event_id  # the smallest id looked at so far: the next page reads below it
        if not query.matches(row):
            continue
        seen.add(str(row.get("request_id") or ""))
        items.append({**row, "event_id": event_id})
        if len(items) >= limit:
            full = True
            break
    exhausted = not full and len(pairs) < MAX_SCAN  # every older row was looked at
    local_added = 0
    recorder = getattr(ctx, "recorder", None)
    if before is None and recorder is not None and exhausted:
        # Every live row in the table was looked at and the page still has room: add this worker's own recent rows
        # the table does not hold (sampled out above 50 a second, or not flushed yet). They carry no event id; the
        # page is not full, so no table row is pushed off it and `next_before` stays exact.
        stored = {str(row.get("request_id") or "") for _id, row in pairs}
        oldest_ms = ctx.clock.now_ms() - LIVE_KEEP_S * 1000
        for row in recorder.live.snapshot(None, limit=MAX_LIMIT):
            if len(items) >= limit:
                break
            rid = str(row.get("request_id") or "")
            if rid in stored or rid in seen or int(row.get("at_ms") or 0) < oldest_ms or not query.matches(row):
                continue
            items.append({**row, "event_id": None})
            seen.add(rid)
            local_added += 1
        items.sort(key=lambda item: (int(item.get("at_ms") or 0), int(item.get("event_id") or 0)), reverse=True)
    return {
        "items": items,
        "total": len(items),
        "next_before": None if exhausted else next_before,
        "filters": query.describe(),
        "from_this_worker": local_added,
        "limits": {"keep_s": LIVE_KEEP_S, "rows_per_second_per_worker": LIVE_EVENTS_PER_SECOND},
    }


def _policy(ctx: Any) -> CapturePolicy:
    return CapturePolicy.from_settings(ctx.settings.get)


@router.get("/state")
async def live_state(request: Request, _admin: AdminSession) -> dict[str, Any]:
    """The capture window, counts and caps (v1 `capture.get_state`, row 82) and the live row limits."""
    ctx = get_ctx(request)
    policy = _policy(ctx)
    now = ctx.clock.now()
    state = await ctx.dbs.metrics.read(lambda conn: capture_state(conn, policy, now))
    recorder = getattr(ctx, "recorder", None)
    return {
        "capture": state,
        "live": {
            "keep_s": LIVE_KEEP_S,
            "rows_per_second_per_worker": LIVE_EVENTS_PER_SECOND,
            "ring_size": recorder.live.size if recorder is not None else 0,
            "sampled_out_by_this_worker": int(getattr(recorder, "live_sampled_out", 0) or 0),
        },
    }


@router.get("/{request_id}")
async def live_detail(
    request: Request,
    _admin: AdminSession,
    request_id: Annotated[str, Path(max_length=256)],
) -> dict[str, Any]:
    """One request's capture and live row; 404 with v1's expired text once the capture is gone (row 128)."""
    if not REQUEST_ID_RE.fullmatch(request_id):
        raise validation_error({"request_id": "A request id is 1 to 64 letters, digits, '-' or '_'."})
    ctx = get_ctx(request)
    policy = _policy(ctx)
    now = ctx.clock.now()
    now_ms = ctx.clock.now_ms()

    def read(conn: sqlite3.Connection) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        found = get_capture(conn, request_id, now, policy.ttl_s)
        row = read_dashboard.live_row(
            conn, request_id, since_ms=now_ms - (LIVE_KEEP_S + 120) * 1000, until_ms=now_ms + 120_000
        )
        return found, row

    found, row = await ctx.dbs.metrics.read(read)
    recorder = getattr(ctx, "recorder", None)
    if found is None and row is None and recorder is not None:
        for entry in recorder.live.snapshot(None, limit=recorder.live.size or 1):
            if entry.get("request_id") == request_id:
                row = entry
                break
    if found is None:
        if row is not None and not row.get("capture_id"):
            raise ApiError(404, NOT_CAPTURED_CODE, CAPTURE_OFF_MESSAGE)
        raise ApiError(404, CAPTURE_EXPIRED_CODE, CAPTURE_EXPIRED_MESSAGE)
    return {
        "request_id": request_id,
        "capture": found,
        "live": row,
        "capture_window_s": policy.ttl_s,
    }


__all__ = ["CAPTURE_EXPIRED_CODE", "NOT_CAPTURED_CODE", "router"]
