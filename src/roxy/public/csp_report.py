"""POST /csp-report: where browsers send Content Security Policy violation reports (plan 9.2).

What this is
    `router` with one route, `POST /csp-report`, named in every page's policy (`report-uri /csp-report`) and in
    the `Reporting-Endpoints` header (`report-to csp-endpoint`). Also the pure helpers it is built from, so tests
    can call them directly: `extract_reports` (both report formats to one small dict), `report_signature` and
    `admit_sample` (the fleet-wide hourly budget and its per-client and per-report shares in hot.db).

Why it exists
    A violation report means one of two things: a template bug (a script or style without the nonce, which the
    browser just blocked for a real visitor) or someone trying to inject markup. Either is worth seeing. The
    endpoint is public and unauthenticated by design: browsers send reports without cookies, so an `/admin` route
    would reject them (and the admin allowlist would hide them). That makes it an open door, so it is narrow:
    only the two report content types, at most 8 KiB per body (nginx also limits it to 1 request per second per
    IP with a burst of 5, zone `cspreport`, plan 17.2), and at most 100 stored reports per hour across all
    workers, so a flood of fake reports cannot fill the events table. A first-come budget alone could be spent by
    one client in seconds, right before an attack it would then hide, so each client network and each distinct
    report only gets a small share of the hour.

How it works
    1. Content type: `application/csp-report` (the older `report-uri` format, one JSON object under
       "csp-report") or `application/reports+json` (the Reporting API, a JSON list of reports, of which only
       `csp-violation` entries are used). Anything else is 415.
    2. Size: a declared `Content-Length` over 8 KiB is refused at once (413); otherwise the body is read in
       chunks and refused as soon as it passes 8 KiB, so it is never buffered beyond that.
    3. Parsing keeps only a few fields, each cut to `MAX_FIELD_CHARS`: the page path (no query string, secrets
       masked), the blocked resource reduced to a keyword or `scheme://host`, the directive, the disposition, the
       source file path, line and column, and the HTTP status. The script sample and the policy text are dropped:
       a sample can contain whatever text a visitor typed, and the policy only repeats a nonce. Identical reports
       in one body count once (`report_signature`, a hash of the kept fields).
    4. Sampling: ONE request stores at most ONE report. `admit_sample` checks, in one short hot.db write
       transaction, three fixed windows per clock hour in the `limiter` table: the fleet budget
       (`csp_report:sample`, `SAMPLE_PER_HOUR`), the sender's share (`csp_report:ip:<limit key>`, the IPv4 address
       or the IPv6 network of `ipv6_limit_prefix` bits, `SOURCE_PER_HOUR`) and the report's share
       (`csp_report:sig:<signature>`, `SIGNATURE_PER_HOUR`, so a template bug every visitor hits cannot crowd out
       a rarer report). The first report of the body whose share is not used up takes the slot, and all three
       counters move together, so the limits hold with any number of workers (plan C6). Rows are written only
       for a stored report, so a capped flood writes nothing and the rows stay bounded (3 per stored report at
       most). Each row's `tat_ms` is the end of its window, which keeps the retention job from pruning it while
       the window is open. Once a worker sees the fleet budget spent it stops asking the database until the next
       hour. If hot.db is busy the report is dropped: losing a report is fine, slowing the proxy's hot database is
       not.
    5. Storage: `ctx.recorder.record_event("csp_report", "info", None, detail, aggregate=True)`. Aggregated events
       are summed per minute (identical reports in one minute become one `events` row with a count) and queued at
       the recorder's aggregated-event priority, below every individual event such as a ban or a credential
       change, so the batch writer drops them first under pressure (plan 9.2 "low-priority"). A structured log line
       stands in while there is no recorder.
    A well-formed report always gets 204 No Content, stored or not, so the answer reveals nothing about the
    budget. Malformed requests get a plain 4xx and are logged as probes by the shared error handler.

What to read next
    `roxy/core/security_headers.py` (the policy that produces these reports), `roxy/storage/retention.py`
    (`prune_limiter`), then `roxy/metrics/recorder.py` (`record_event` and the batch priorities).
"""

from __future__ import annotations

import hashlib
import inspect
import json
import logging
import sqlite3
import time
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

from roxy.core.client_ip import limit_key
from roxy.core.redact import masked_url, redact_path
from roxy.core.scope import setting_int
from roxy.core.security_headers import CSP_REPORT_PATH

log = logging.getLogger("roxy.public.csp_report")

router = APIRouter()

CONTENT_TYPE_CSP_REPORT: Final = "application/csp-report"
CONTENT_TYPE_REPORTS_JSON: Final = "application/reports+json"
ACCEPTED_CONTENT_TYPES: Final = frozenset({CONTENT_TYPE_CSP_REPORT, CONTENT_TYPE_REPORTS_JSON})

MAX_REPORT_BYTES: Final = 8 * 1024
"""Largest accepted body (plan 9.2). A real report is well under 2 KiB."""
SAMPLE_PER_HOUR: Final = 100
"""Reports stored per clock hour across the whole fleet (plan 9.2 "sampled (max 100 per hour)")."""
SOURCE_PER_HOUR: Final = 5
"""Reports one client network (its per-IP limit key) may have stored per clock hour. A visitor's browser sends a
handful of reports at most; 5 means at least 20 networks are needed to spend the fleet budget."""
SIGNATURE_PER_HOUR: Final = 10
"""Times one identical report (same page path, directive, blocked resource, source and line) may be stored per
clock hour. A template bug seen by every visitor shows up 10 times, and leaves 90 slots for everything else."""
SAMPLE_WINDOW_S: Final = 3600
SAMPLE_BUCKET_KEY: Final = "csp_report:sample"
"""Row in hot.db `limiter`; the prefix keeps it apart from the abuse limiters' keys."""
SOURCE_KEY_PREFIX: Final = "csp_report:ip:"
SIGNATURE_KEY_PREFIX: Final = "csp_report:sig:"
SAMPLE_BUSY_TIMEOUT_MS: Final = 50
"""How long the sampling write may wait for hot.db's lock before the report is dropped (never the proxy's time)."""
MAX_REPORTS_PER_BODY: Final = 10
"""A Reporting API body may batch several reports; more than this in one body are ignored (bounded work)."""
MAX_FIELD_CHARS: Final = 256

EVENT_TYPE: Final = "csp_report"
EVENT_SEVERITY: Final = "info"

# Keywords browsers put in blocked-uri / blockedURL instead of a URL. Kept as they are.
_BLOCKED_KEYWORDS: Final = frozenset({"inline", "eval", "wasm-eval", "self", "data", "blob", "trusted-types-sink"})


def media_type(content_type: str) -> str:
    """`Application/CSP-Report; charset=utf-8` -> `application/csp-report`."""
    return content_type.split(";", 1)[0].strip().lower()


def _cut(value: Any) -> str:
    return str(value)[:MAX_FIELD_CHARS] if value is not None else ""


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip()[:9])
    return None


def page_path(url: Any) -> str:
    """The path of a page URL with the query and fragment removed and secret segments masked.

    The path is cut to twice the stored length BEFORE it is redacted, so an anonymous report pays a bounded amount
    of scrubbing whatever it sends (review finding public-4). Safe: whatever survives the final cut lies inside the
    redacted prefix, with room for a whole 24 character credential window around it.
    """
    if not isinstance(url, str) or not url:
        return ""
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    return _cut(redact_path((parts.path or "/")[: 2 * MAX_FIELD_CHARS]))


def blocked_resource(value: Any) -> str:
    """A keyword (`inline`, `eval`, ...) as is, a URL reduced to `scheme://host[:port]`, anything else empty."""
    if not isinstance(value, str) or not value:
        return ""
    text = value.strip()
    if text.lower() in _BLOCKED_KEYWORDS:
        return text.lower()
    try:
        parts = urlsplit(masked_url(text))
    except ValueError:
        return ""
    if parts.scheme in ("http", "https", "ws", "wss") and parts.netloc:
        return _cut(f"{parts.scheme}://{parts.netloc}")
    # data:, blob:, chrome-extension: and similar: the scheme says enough (an extension id could single out a
    # visitor, so it is not kept).
    return _cut(parts.scheme)


def _directive(value: Any) -> str:
    """The directive name only (`script-src-elem`), never the policy values that may follow it."""
    if not isinstance(value, str):
        return ""
    name = value.strip().split(" ", 1)[0].lower()
    return name[:64] if all(char.isalnum() or char == "-" for char in name) else ""


def _normalize(fields: dict[str, Any], *, kebab: bool) -> dict[str, Any]:
    """One report, from either format, as the small dict that is stored."""

    def pick(kebab_name: str, camel_name: str) -> Any:
        return fields.get(kebab_name if kebab else camel_name)

    directive = _directive(pick("effective-directive", "effectiveDirective")) or _directive(
        fields.get("violated-directive")
    )
    disposition = _cut(pick("disposition", "disposition")).lower()
    return {
        "document": page_path(pick("document-uri", "documentURL")),
        "blocked": blocked_resource(pick("blocked-uri", "blockedURL")),
        "directive": directive,
        "disposition": disposition if disposition in ("enforce", "report") else "",
        "source": page_path(pick("source-file", "sourceFile")),
        "line": _int_or_none(pick("line-number", "lineNumber")),
        "column": _int_or_none(pick("column-number", "columnNumber")),
        "status": _int_or_none(pick("status-code", "statusCode")),
    }


def extract_reports(document: Any, content_type: str) -> list[dict[str, Any]]:
    """Every usable report in a parsed body, normalized; an empty list when there is none."""
    if content_type == CONTENT_TYPE_CSP_REPORT:
        body = document.get("csp-report") if isinstance(document, dict) else None
        return [_normalize(body, kebab=True)] if isinstance(body, dict) else []
    if content_type == CONTENT_TYPE_REPORTS_JSON and isinstance(document, list):
        reports: list[dict[str, Any]] = []
        for item in document[:MAX_REPORTS_PER_BODY]:
            if isinstance(item, dict) and item.get("type") == "csp-violation" and isinstance(item.get("body"), dict):
                reports.append(_normalize(item["body"], kebab=False))
        return reports
    return []


def report_signature(report: dict[str, Any]) -> str:
    """A short name for a report's content: equal reports get equal signatures (sha256 of the kept fields)."""
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()[:16]


class Admission(StrEnum):
    """What `admit_sample` decided for one request."""

    STORED = "stored"
    BUDGET_SPENT = "budget_spent"  # the fleet's budget for this hour is used up
    SOURCE_CAPPED = "source_capped"  # this client network used its share of the hour
    SIGNATURE_CAPPED = "signature_capped"  # every report in the body was already stored often enough this hour


@dataclass(frozen=True, slots=True)
class AdmitResult:
    """`admission`, the start of the fleet budget's window, and which report (index into `signatures`) was
    admitted, or None."""

    admission: Admission
    window: int
    index: int | None


def _window_count(conn: sqlite3.Connection, key: str, window: int) -> tuple[int, int]:
    """(window start, count) of one fixed window row. A row already in a LATER window is used as it is: another
    worker's clock was a little ahead and opened the next hour first (clocks on one box differ by at most a step;
    plan notes on the WSL clock)."""
    row = conn.execute("SELECT window_start, count FROM limiter WHERE bucket_key = ?", (key,)).fetchone()
    if row is not None and int(row[0]) >= window:
        return int(row[0]), int(row[1])
    return window, 0


def _save_window(conn: sqlite3.Connection, key: str, window: int, count: int, now_s: float, window_s: int) -> None:
    conn.execute(
        "INSERT INTO limiter (bucket_key, tat_ms, window_start, count, updated_at) VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT (bucket_key) DO UPDATE SET tat_ms = excluded.tat_ms, window_start = excluded.window_start, "
        "count = excluded.count, updated_at = excluded.updated_at",
        # tat_ms = end of the window: retention only prunes limiter rows whose tat_ms has passed.
        (key, (window + window_s) * 1000, window, count, int(now_s)),
    )


def admit_sample(
    conn: sqlite3.Connection,
    now_s: float,
    *,
    source: str,
    signatures: Sequence[str],
    cap: int = SAMPLE_PER_HOUR,
    source_cap: int = SOURCE_PER_HOUR,
    signature_cap: int = SIGNATURE_PER_HOUR,
    window_s: int = SAMPLE_WINDOW_S,
) -> AdmitResult:
    """Take one slot of this hour's report budget for ONE of `signatures` (the distinct reports of one request).

    Run inside one hot.db write transaction. Checks the fleet budget, then the sender's share, then each report's
    share in body order; the first report with share left is admitted and all three counters are incremented.
    Nothing is written when nothing is admitted, so refused floods leave no rows behind.
    """
    window = int(now_s // window_s) * window_s
    budget_window, used = _window_count(conn, SAMPLE_BUCKET_KEY, window)
    if used >= cap:
        return AdmitResult(Admission.BUDGET_SPENT, budget_window, None)
    source_key = SOURCE_KEY_PREFIX + source
    source_window, source_used = _window_count(conn, source_key, window)
    if source_used >= source_cap:
        return AdmitResult(Admission.SOURCE_CAPPED, budget_window, None)
    for index, signature in enumerate(signatures):
        signature_key = SIGNATURE_KEY_PREFIX + signature
        signature_window, signature_used = _window_count(conn, signature_key, window)
        if signature_used >= signature_cap:
            continue
        _save_window(conn, SAMPLE_BUCKET_KEY, budget_window, used + 1, now_s, window_s)
        _save_window(conn, source_key, source_window, source_used + 1, now_s, window_s)
        _save_window(conn, signature_key, signature_window, signature_used + 1, now_s, window_s)
        return AdmitResult(Admission.STORED, budget_window, index)
    return AdmitResult(Admission.SIGNATURE_CAPPED, budget_window, None)


class ReportSampler:
    """Per-app front end to `admit_sample`: remembers a spent hour so the database is not asked again."""

    def __init__(self) -> None:
        self.spent_window: int | None = None  # start of an hour whose fleet budget is known to be used up
        self._local_window = -1
        self._local_count = 0

    def _local_admit(self, now_s: float, workers: int) -> int | None:
        """Fallback without databases (a bare test app): a per-process budget of cap / workers, first report."""
        window = int(now_s // SAMPLE_WINDOW_S) * SAMPLE_WINDOW_S
        if window != self._local_window:
            self._local_window, self._local_count = window, 0
        if self._local_count >= max(1, SAMPLE_PER_HOUR // max(1, workers)):
            return None
        self._local_count += 1
        return 0

    async def admit(self, ctx: Any, now_s: float, source: str, signatures: Sequence[str]) -> int | None:
        """The index of the report to store, or None when none may be stored (never raises)."""
        window = int(now_s // SAMPLE_WINDOW_S) * SAMPLE_WINDOW_S
        if not signatures or (self.spent_window is not None and window <= self.spent_window):
            return None
        hot = getattr(getattr(ctx, "dbs", None), "hot", None)
        if hot is None:
            workers = int(getattr(getattr(ctx, "env", None), "workers", 1) or 1)
            return self._local_admit(now_s, workers)
        try:
            result: AdmitResult = await hot.write(
                lambda conn: admit_sample(conn, now_s, source=source, signatures=signatures),
                busy_timeout_ms=SAMPLE_BUSY_TIMEOUT_MS,
            )
        except Exception:
            log.debug("csp_report_sample_unavailable", exc_info=True)
            return None  # hot.db busy or unavailable: drop this report rather than wait
        if result.admission is Admission.BUDGET_SPENT:
            self.spent_window = result.window  # a capped sender or report is not a spent hour
        return result.index


def sampler_for(request: Request) -> ReportSampler:
    """The sampler stored on this app (created on first use)."""
    sampler = getattr(request.app.state, "csp_report_sampler", None)
    if not isinstance(sampler, ReportSampler):
        sampler = ReportSampler()
        request.app.state.csp_report_sampler = sampler
    return sampler


_store_warned = False


async def store_report(ctx: Any, report: dict[str, Any]) -> None:
    """Hand one report to the metrics recorder as a low-priority event (or log it while there is none).

    `aggregate=True` puts it in the recorder's per-minute sums: identical reports in one minute share a row (with
    a count), and those rows are queued below every individual event, so a full queue drops them first.
    """
    global _store_warned
    recorder = getattr(ctx, "recorder", None)
    record_event = getattr(recorder, "record_event", None) if recorder is not None else None
    if record_event is None:
        log.info("csp_report", extra={"fields": report})
        return
    try:
        result = record_event(EVENT_TYPE, EVENT_SEVERITY, None, report, aggregate=True)
        if inspect.isawaitable(result):
            await result
    except Exception:
        if not _store_warned:
            _store_warned = True
            log.warning("csp_report_store_failed", exc_info=True)


def _source_key(request: Request) -> str:
    """The sender's per-IP limit key: the IPv4 address, or its IPv6 network of `ipv6_limit_prefix` bits."""
    ip = getattr(request.state, "client_ip", None)
    if not isinstance(ip, str) or not ip:
        ip = request.client.host if request.client else "unknown"
    return limit_key(ip, setting_int(request.scope, "ipv6_limit_prefix", 64))


async def read_capped_body(request: Request, limit: int = MAX_REPORT_BYTES) -> bytes:
    """The request body, or 413 as soon as it is known to be larger than `limit` (never buffered beyond it)."""
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > limit:
                raise HTTPException(status_code=413, detail="Payload Too Large")
        except ValueError:
            raise HTTPException(status_code=400, detail="Bad Request") from None
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise HTTPException(status_code=413, detail="Payload Too Large")
        chunks.append(chunk)
    return b"".join(chunks)


@router.post(CSP_REPORT_PATH, status_code=204, include_in_schema=False)
async def csp_report(request: Request) -> Response:
    """Accept, sample and store CSP violation reports. Unauthenticated by design (plan 9.2, 19.7)."""
    kind = media_type(request.headers.get("content-type", ""))
    if kind not in ACCEPTED_CONTENT_TYPES:
        raise HTTPException(status_code=415, detail="Unsupported Media Type")
    body = await read_capped_body(request)
    try:
        document = json.loads(body)
    except (ValueError, RecursionError):  # UnicodeDecodeError is a ValueError; deep nesting is RecursionError
        raise HTTPException(status_code=400, detail="Bad Request") from None
    reports = extract_reports(document, kind)
    if not reports:
        raise HTTPException(status_code=400, detail="Bad Request")
    distinct: dict[str, dict[str, Any]] = {}
    for report in reports:
        distinct.setdefault(report_signature(report), report)  # identical reports in one body count once
    signatures = list(distinct)
    ctx = getattr(request.app.state, "ctx", None)
    clock = getattr(ctx, "clock", None)
    now_s = clock.now() if clock is not None else time.time()
    index = await sampler_for(request).admit(ctx, now_s, _source_key(request), signatures)
    if index is not None:  # one request, at most one stored report
        detail = dict(distinct[signatures[index]])
        if len(signatures) > 1:
            detail["others_in_body"] = len(signatures) - 1  # the rest of the batch is counted, not stored
        await store_report(ctx, detail)
    return Response(status_code=204)
