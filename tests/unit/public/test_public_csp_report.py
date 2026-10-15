"""CSP report parsing, the fleet-wide hourly sample budget and its fair shares, and where reports are stored (9.2).

What this is
    Unit tests for `roxy.public.csp_report`: `extract_reports` (both report formats), the field sanitizing
    helpers, `report_signature`, `admit_sample` against a real hot.db, the per-app `ReportSampler`, and
    `store_report` against the real metrics recorder.

Why it exists
    The endpoint is public and unauthenticated, so what it keeps must be small and harmless (no query strings,
    no masked secrets, no script samples), its storage budget must hold across workers (plan C6) and survive
    the retention job (which prunes idle `limiter` rows), and no single client or single repeated report may
    spend the whole hour's budget (review finding 2). Stored reports must be the events the batch writer drops
    before bans and credential events (plan 9.2 "low-priority", review finding 6).

How it works
    Parsed documents go through the helpers directly; the sampling SQL runs on the `dbs` fixture's hot.db, and
    `storage.retention.prune_limiter` is run against it to prove the rows outlive a pruning pass. The recorder
    test builds a real `MetricsRecorder` on the same temporary databases.

What to read next
    `roxy/public/csp_report.py`, then `roxy/storage/retention.py` (`prune_limiter`) and
    `roxy/metrics/recorder.py` (`record_event` with `aggregate=True`).
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

import pytest

from roxy.config import catalog
from roxy.core.clock import FakeClock
from roxy.public.csp_report import (
    CONTENT_TYPE_CSP_REPORT,
    CONTENT_TYPE_REPORTS_JSON,
    EVENT_TYPE,
    MAX_REPORTS_PER_BODY,
    SAMPLE_BUCKET_KEY,
    SAMPLE_PER_HOUR,
    SIGNATURE_PER_HOUR,
    SOURCE_PER_HOUR,
    Admission,
    AdmitResult,
    ReportSampler,
    admit_sample,
    blocked_resource,
    extract_reports,
    media_type,
    page_path,
    report_signature,
    store_report,
)

NOW = 1_760_000_400.0 + 100  # 100 s into a clock hour (1_760_000_400 is a multiple of 3600)
WINDOW = int(NOW // 3600) * 3600

LEGACY = {
    "csp-report": {
        "document-uri": "https://roxytheproxy.com/admin/invalidate/SECRETTOKEN123456?x=1#frag",
        "referrer": "https://elsewhere.example/?q=private",
        "violated-directive": "script-src-elem",
        "effective-directive": "script-src-elem",
        "original-policy": "default-src 'none'; script-src 'nonce-abc' 'strict-dynamic'",
        "disposition": "enforce",
        "blocked-uri": "https://evil.example:8443/x.js?token=1",
        "line-number": 12,
        "column-number": "7",
        "source-file": "https://roxytheproxy.com/static/public/site.abc.js?v=1",
        "status-code": 200,
        "script-sample": "alert(document.cookie)",
    }
}

REPORTING_API = [
    {
        "type": "csp-violation",
        "age": 10,
        "url": "https://roxytheproxy.com/docs",
        "user_agent": "Mozilla/5.0",
        "body": {
            "documentURL": "https://roxytheproxy.com/docs?secret=1",
            "blockedURL": "inline",
            "effectiveDirective": "style-src-attr",
            "originalPolicy": "default-src 'none'",
            "disposition": "report",
            "sample": "color: red",
            "lineNumber": 3,
            "columnNumber": 9,
            "statusCode": 200,
        },
    },
    {"type": "deprecation", "body": {"id": "x"}},
]


def test_media_type() -> None:
    assert media_type("Application/CSP-Report; charset=utf-8") == CONTENT_TYPE_CSP_REPORT
    assert media_type("application/reports+json") == CONTENT_TYPE_REPORTS_JSON
    assert media_type("") == ""


def test_extract_legacy_report_keeps_only_safe_fields() -> None:
    [report] = extract_reports(LEGACY, CONTENT_TYPE_CSP_REPORT)
    assert report == {
        "document": "/admin/invalidate/[redacted]",
        "blocked": "https://evil.example:8443",
        "directive": "script-src-elem",
        "disposition": "enforce",
        "source": "/static/public/site.abc.js",
        "line": 12,
        "column": 7,
        "status": 200,
    }
    flat = repr(report)
    for leaked in ("SECRETTOKEN", "q=private", "nonce-abc", "document.cookie", "token=1", "frag"):
        assert leaked not in flat


def test_extract_reporting_api_uses_only_csp_violations() -> None:
    reports = extract_reports(REPORTING_API, CONTENT_TYPE_REPORTS_JSON)
    assert reports == [
        {
            "document": "/docs",
            "blocked": "inline",
            "directive": "style-src-attr",
            "disposition": "report",
            "source": "",
            "line": 3,
            "column": 9,
            "status": 200,
        }
    ]
    many = [REPORTING_API[0]] * (MAX_REPORTS_PER_BODY + 5)
    assert len(extract_reports(many, CONTENT_TYPE_REPORTS_JSON)) == MAX_REPORTS_PER_BODY


@pytest.mark.parametrize(
    "document",
    [None, [], {}, {"csp-report": "x"}, {"csp-report": [1]}, "text", 5],
)
def test_extract_rejects_unusable_legacy_documents(document: Any) -> None:
    assert extract_reports(document, CONTENT_TYPE_CSP_REPORT) == []


def test_extract_rejects_mismatched_shapes() -> None:
    assert extract_reports(LEGACY, CONTENT_TYPE_REPORTS_JSON) == []
    assert extract_reports(REPORTING_API, CONTENT_TYPE_CSP_REPORT) == []
    assert extract_reports([{"type": "csp-violation", "body": "x"}], CONTENT_TYPE_REPORTS_JSON) == []


def test_field_helpers() -> None:
    assert page_path("https://roxytheproxy.com/a/b?c=d") == "/a/b"
    assert page_path("not a url") == "not a url"
    assert page_path(5) == ""
    assert blocked_resource("eval") == "eval"
    assert blocked_resource("data:text/html;base64,AAAA") == "data"
    assert blocked_resource("https://user:pass@cdn.example/x") == "https://cdn.example"
    assert blocked_resource("chrome-extension://abcdef/x.js") == "chrome-extension"
    assert blocked_resource("not a url") == ""
    assert blocked_resource("") == ""
    assert blocked_resource(None) == ""
    long = "https://example.com/" + "a" * 5000
    assert len(page_path(long)) <= 256


def test_page_path_scrubs_a_bounded_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    """Review finding public-4 (defense in depth): an anonymous report's path is cut to twice the stored length
    BEFORE it is scrubbed, so a document-uri full of `%0A` costs a bounded amount of redaction work."""
    from roxy.public import csp_report

    seen: list[int] = []
    real = csp_report.redact_path

    def counting(text: str) -> str:
        seen.append(len(text))
        return real(text)

    monkeypatch.setattr(csp_report, "redact_path", counting)
    assert page_path("https://roxytheproxy.com/" + "%0A" * 2700).startswith("/")
    assert seen == [2 * csp_report.MAX_FIELD_CHARS]


def test_report_signature_names_identical_reports_alike() -> None:
    [first] = extract_reports(LEGACY, CONTENT_TYPE_CSP_REPORT)
    [again] = extract_reports(json.loads(json.dumps(LEGACY)), CONTENT_TYPE_CSP_REPORT)
    other = dict(first, line=13)
    assert report_signature(first) == report_signature(again)
    assert report_signature(first) != report_signature(other)
    assert len(report_signature(first)) == 16


# --- the hourly budget and its shares ------------------------------------------------------------------------------


def _admit(dbs: Any, now: float, source: str, signatures: Sequence[str]) -> AdmitResult:
    result: AdmitResult = dbs.hot.write_sync(lambda conn: admit_sample(conn, now, source=source, signatures=signatures))
    return result


def _fresh(dbs: Any, now: float, i: int) -> AdmitResult:
    """One report from a client and with a content nobody used before (only the global budget applies)."""
    return _admit(dbs, now, f"10.0.{i // 200}.{i % 200}", [f"sig{i:013d}"])


def _limiter_rows(dbs: Any) -> dict[str, tuple[int, int, int]]:
    rows = dbs.hot.read_sync(lambda conn: conn.execute("SELECT bucket_key, window_start, count, tat_ms FROM limiter"))
    return {str(row[0]): (int(row[1]), int(row[2]), int(row[3])) for row in rows}


def test_admit_sample_caps_each_hour(dbs: Any) -> None:
    results = [_fresh(dbs, NOW + i, i) for i in range(SAMPLE_PER_HOUR + 5)]
    assert [r.admission for r in results].count(Admission.STORED) == SAMPLE_PER_HOUR
    assert all(r.admission is Admission.BUDGET_SPENT for r in results[SAMPLE_PER_HOUR:])
    assert {r.window for r in results} == {WINDOW}
    # The next clock hour has a fresh budget.
    assert _fresh(dbs, WINDOW + 3600 + 1, 999) == AdmitResult(Admission.STORED, WINDOW + 3600, 0)
    assert _limiter_rows(dbs)[SAMPLE_BUCKET_KEY] == (WINDOW + 3600, 1, (WINDOW + 7200) * 1000)


def test_one_client_gets_only_its_share_of_the_hour(dbs: Any) -> None:
    """Review finding 2: one IP sent 10 bodies of 10 reports and used all 100 slots."""
    results = [_admit(dbs, NOW + i, "203.0.113.9", [f"sig{i:013d}"]) for i in range(SAMPLE_PER_HOUR)]
    stored = [r for r in results if r.admission is Admission.STORED]
    assert len(stored) == SOURCE_PER_HOUR
    assert all(r.admission is Admission.SOURCE_CAPPED for r in results[SOURCE_PER_HOUR:])
    # Everyone else still has the rest of the hour.
    assert _admit(dbs, NOW + 200, "198.51.100.7", ["genuine0000000"]).admission is Admission.STORED
    assert _limiter_rows(dbs)[SAMPLE_BUCKET_KEY][1] == SOURCE_PER_HOUR + 1


def test_one_identical_report_gets_only_its_share_of_the_hour(dbs: Any) -> None:
    """A template bug seen by every visitor must not crowd out a different report (an injection attempt)."""
    results = [_admit(dbs, NOW + i, f"10.1.0.{i}", ["samebug0000000"]) for i in range(SIGNATURE_PER_HOUR + 5)]
    assert [r.admission for r in results].count(Admission.STORED) == SIGNATURE_PER_HOUR
    assert all(r.admission is Admission.SIGNATURE_CAPPED for r in results[SIGNATURE_PER_HOUR:])
    assert _admit(dbs, NOW + 100, "10.1.1.1", ["different00000"]).admission is Admission.STORED


def test_the_first_report_with_share_left_is_the_one_stored(dbs: Any) -> None:
    for i in range(SIGNATURE_PER_HOUR):
        _admit(dbs, NOW + i, f"10.2.0.{i}", ["samebug0000000"])
    result = _admit(dbs, NOW + 50, "10.2.1.1", ["samebug0000000", "newreport00000", "another0000000"])
    assert result == AdmitResult(Admission.STORED, WINDOW, 1)


def test_capped_requests_write_nothing(dbs: Any) -> None:
    """Rows are written only for stored reports, so at most 3 rows per stored report exist per hour (plan P9)."""
    for i in range(SOURCE_PER_HOUR):
        _admit(dbs, NOW + i, "203.0.113.9", [f"sig{i:013d}"])
    before = _limiter_rows(dbs)
    for i in range(50):
        assert _admit(dbs, NOW + 10 + i, "203.0.113.9", [f"more{i:012d}"]).admission is Admission.SOURCE_CAPPED
    assert _limiter_rows(dbs) == before
    assert len(before) == 1 + 1 + SOURCE_PER_HOUR  # the budget, the source, one row per distinct report


def test_admit_sample_tolerates_a_clock_slightly_behind(dbs: Any) -> None:
    assert _fresh(dbs, WINDOW + 3600 + 1, 1).window == WINDOW + 3600  # a worker already in the next hour
    assert _fresh(dbs, WINDOW + 3599.5, 2).window == WINDOW + 3600  # this worker is 0.5 s behind: same window
    assert _limiter_rows(dbs)[SAMPLE_BUCKET_KEY][1] == 2


def test_retention_keeps_the_budget_rows_while_their_hour_is_open(dbs: Any) -> None:
    from roxy.storage import retention

    for i in range(SAMPLE_PER_HOUR):
        _fresh(dbs, NOW + i, i)
    for i in range(SOURCE_PER_HOUR):
        _admit(dbs, NOW, "203.0.113.9", [f"x{i:015d}"])
    policy = retention.RetentionPolicy()
    later = NOW + 1800  # far beyond stale_ip_duration (60 s), still inside the hour
    dbs.hot.write_sync(lambda conn: retention.prune_limiter(conn, later, policy, 10_000))
    assert _fresh(dbs, later, 5000).admission is Admission.BUDGET_SPENT  # the rows survived
    dbs.hot.write_sync(lambda conn: retention.prune_limiter(conn, WINDOW + 3600 + 120, policy, 10_000))
    assert _limiter_rows(dbs) == {}  # once the hour is over the rows may go


class _Ctx:
    def __init__(self, dbs: Any) -> None:
        self.dbs = dbs


async def test_sampler_stops_asking_the_database_once_the_hour_is_spent(dbs: Any) -> None:
    sampler = ReportSampler()
    ctx = _Ctx(dbs)
    admitted = [await sampler.admit(ctx, NOW + i, f"10.3.0.{i}", [f"s{i:015d}"]) for i in range(SAMPLE_PER_HOUR + 1)]
    assert sum(index == 0 for index in admitted) == SAMPLE_PER_HOUR
    assert admitted[-1] is None
    assert sampler.spent_window == WINDOW

    class Exploding:
        async def write(self, *args: Any, **kwargs: Any) -> Any:
            raise AssertionError("the spent hour must not reach the database")

    class Dbs:
        hot = Exploding()

    assert await sampler.admit(_Ctx(Dbs()), NOW + 500, "10.3.1.1", ["late"]) is None
    assert await sampler.admit(ctx, WINDOW + 3600 + 5, "10.3.1.1", ["late"]) == 0  # next hour: asks again


async def test_a_capped_client_does_not_mark_the_hour_spent(dbs: Any) -> None:
    sampler = ReportSampler()
    ctx = _Ctx(dbs)
    for i in range(SOURCE_PER_HOUR + 3):
        await sampler.admit(ctx, NOW + i, "203.0.113.9", [f"s{i:015d}"])
    assert sampler.spent_window is None
    assert await sampler.admit(ctx, NOW + 20, "198.51.100.7", ["genuine"]) == 0


async def test_sampler_drops_reports_when_hot_db_is_unavailable() -> None:
    class Busy:
        async def write(self, *args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("database is locked")

    class Dbs:
        hot = Busy()

    sampler = ReportSampler()
    assert await sampler.admit(_Ctx(Dbs()), NOW, "10.0.0.1", ["x"]) is None
    assert sampler.spent_window is None  # a busy database is not a spent budget


async def test_sampler_without_databases_uses_a_per_worker_share() -> None:
    class Env:
        workers = 4

    class NoDbCtx:
        dbs = None
        env = Env()

    sampler = ReportSampler()
    admitted = [await sampler.admit(NoDbCtx(), NOW + i, f"10.4.0.{i}", ["x"]) for i in range(SAMPLE_PER_HOUR)]
    assert sum(index == 0 for index in admitted) == SAMPLE_PER_HOUR // 4


# --- where stored reports go (review finding 6) ------------------------------------------------------------------


class _Settings:
    """What `MetricsRecorder` reads from the runtime settings: `get(key)` and a `version`."""

    version = 1

    def __init__(self) -> None:
        self.values = catalog.defaults()

    def get(self, key: str) -> Any:
        return self.values[key]


class _RecorderCtx:
    def __init__(self, recorder: Any) -> None:
        self.recorder = recorder


async def test_reports_are_low_priority_events_and_duplicates_share_a_row(dbs: Any) -> None:
    from roxy.metrics.recorder import KIND_AGG_EVENTS, KIND_EVENTS, PRIORITIES, MetricsRecorder

    clock = FakeClock(start=NOW)
    recorder = MetricsRecorder(dbs, _Settings(), clock)
    [report] = extract_reports(LEGACY, CONTENT_TYPE_CSP_REPORT)
    for _ in range(3):
        await store_report(_RecorderCtx(recorder), report)
    # Not in the queue of individual events (priority 60, shared with bans and credential events) ...
    assert recorder.batch.stats()["kinds"][KIND_EVENTS]["queued"] == 0
    # ... but in the per-minute sums, whose rows the batch writer drops before any individual event.
    assert PRIORITIES[KIND_AGG_EVENTS] < PRIORITIES[KIND_EVENTS]
    clock.advance(60)
    await recorder.flush()
    rows = dbs.metrics.read_sync(
        lambda conn: conn.execute("SELECT severity, detail_json FROM events WHERE type = ?", (EVENT_TYPE,)).fetchall()
    )
    assert len(rows) == 1  # three identical reports in one minute: one row
    severity, detail_json = rows[0]
    detail = json.loads(detail_json)
    assert severity == "info"
    assert detail["count"] == 3
    assert detail["document"] == report["document"]
