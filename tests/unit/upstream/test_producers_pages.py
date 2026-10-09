"""Challenge and HTML-body detection in the upstream exchange, recorded per attempt for UP-CHALLENGE.

Covers the wave 3b producers lane, item 4: `upstream/pages.py classify_page` (a Roblox challenge header or a CDN
challenge, an HTML document where the endpoint answers JSON), the flags on the call's trace record, and the
`challenge` and `html_body` columns of `upstream_attempt_minute` that the recorder fills from the trace. Also the
per-call rotator exit (insights_core request 8): each call keeps the exit it used.
"""

from __future__ import annotations

from typing import Any

import pytest
from upstream_fakes import FakeEgress, FakeSettings, answer, make_ctx, make_service, request

from roxy.core.reasons import Egress
from roxy.metrics import read_history
from roxy.metrics.recorder import MetricsRecorder
from roxy.upstream.pages import NO_FLAGS, PageFlags, classify_page, expects_json, is_challenge, is_html
from roxy.upstream.queue import Priority
from roxy.upstream.trace import Trace, short_hash

API = "games.roblox.com"
HTML = b"<!DOCTYPE html>\n<html><head><title>Access denied</title></head><body>blocked</body></html>"


@pytest.mark.parametrize(
    ("host", "status", "headers", "body", "accept", "expected"),
    [
        (API, 200, {"content-type": "application/json"}, b'{"data":[]}', "", NO_FLAGS),
        (API, 403, {"rblx-challenge-id": "x1", "rblx-challenge-type": "captcha"}, b"{}", "", PageFlags(True, False)),
        (API, 403, {"cf-mitigated": "challenge", "content-type": "text/html"}, HTML, "", PageFlags(True, True)),
        (API, 200, {"content-type": "text/html; charset=utf-8"}, HTML, "", PageFlags(False, True)),
        (API, 503, {}, b"   \n<html><body>maintenance</body></html>", "", PageFlags(False, True)),
        (API, 200, {"content-type": "application/json"}, HTML, "", NO_FLAGS),  # the content type says JSON
        ("www.roblox.com", 200, {"content-type": "text/html"}, HTML, "", NO_FLAGS),  # a web page host
        ("www.roblox.com", 200, {"content-type": "text/html"}, HTML, "application/json", PageFlags(False, True)),
        (API, 302, {"content-type": "text/html", "location": "/x"}, HTML, "", NO_FLAGS),  # a redirect is no page
        (API, 304, {"rblx-challenge-id": "x"}, b"", "", NO_FLAGS),
        (API, 200, {"content-type": "text/html"}, b"", "", NO_FLAGS),  # nothing to judge
        (API, 200, {}, b"plain text answer", "", NO_FLAGS),
    ],
)
def test_classify_page(
    host: str, status: int, headers: dict[str, str], body: bytes, accept: str, expected: PageFlags
) -> None:
    assert classify_page(host, status, headers, body, accept=accept) == expected


def test_helpers_and_bounds() -> None:
    assert is_challenge({"rblx-challenge-metadata": "e30="})
    assert not is_challenge({"cf-mitigated": "block"})
    assert expects_json("thumbnails.roblox.com")
    assert not expects_json("WWW.roblox.com.")
    assert is_html({}, b"<HTML lang=en>")
    huge = b" " * 10_000 + b"<html>"
    assert not is_html({}, huge)  # only the first bytes are looked at: an HTML page starts at once
    assert classify_page(API, "not a status", {}, b"", accept="") == NO_FLAGS  # type: ignore[arg-type]
    assert not NO_FLAGS.any
    assert PageFlags(challenge=True).any


def attempts(dbs: Any, clock: Any) -> list[dict[str, Any]]:
    now = int(clock.now())
    return dbs.metrics.read_sync(lambda conn: read_history.attempt_rows(conn, now - 3600, now + 60))


async def test_each_rotator_call_keeps_the_exit_it_used(dbs: Any, clock: Any) -> None:
    recorder = MetricsRecorder(dbs, FakeSettings(), clock, worker_id="w1")
    trace = Trace(egress_identity="rotator:" + short_hash("session-b"))
    trace.start_attempt("rotator")
    trace.record_call(egress="rotator", kind="retry_5xx", status=503, duration_ms=5, exit_id=short_hash("session-a"))
    trace.start_attempt("rotator")
    trace.record_call(egress="rotator", kind="success", status=200, duration_ms=5, exit_id=short_hash("session-b"))
    trace.start_attempt("direct")
    trace.record_call(egress="direct", kind="success", status=200, duration_ms=5)
    recorder.record_attempts("games.roblox.com/v1/games", trace)
    recorder.close()
    exits = {(row["egress"], row["status"]): row["exit_id"] for row in attempts(dbs, clock)}
    assert exits == {
        ("rotator", 503): short_hash("session-a"),  # the first exit, not the trace's last one
        ("rotator", 200): short_hash("session-b"),
        ("direct", 200): "",
    }


async def test_flags_reach_the_trace_and_the_attempt_rows(dbs: Any, clock: Any) -> None:
    pages = iter(
        [
            answer(200, HTML, {"content-type": "text/html; charset=utf-8"}),
            answer(403, b'{"errors":[{"code":0}]}', {"rblx-challenge-id": "abc", "rblx-challenge-type": "captcha"}),
            answer(200, b'{"data":[]}'),
        ]
    )
    egress = FakeEgress(lambda _egress, _out: next(pages))
    settings = FakeSettings(rotator_enabled=0)
    recorder = MetricsRecorder(dbs, settings, clock, worker_id="w1")
    ctx = make_ctx(dbs, clock, egress, settings=settings, recorder=recorder)
    service = make_service(ctx)
    results = []
    for n in range(3):
        req = request(service, query=[("universeIds", str(n))], template="games.roblox.com/v1/games")
        results.append(await service.fetch(req, priority=Priority.INTERACTIVE, stale_available=False))
    flags = [(r.trace.calls[-1].challenge, r.trace.calls[-1].html_body) for r in results]
    assert flags == [(False, True), (True, False), (False, False)]
    assert results[0].trace.to_dict()["Calls"][-1]["HtmlBody"] is True
    recorder.close()
    rows = attempts(dbs, clock)
    marked = sorted((row["status"], row["challenge"], row["html_body"], row["count"]) for row in rows)
    assert marked == [(200, False, False, 1), (200, False, True, 1), (403, True, False, 1)]
    assert {row["egress"] for row in rows} == {Egress.DIRECT.value}
    assert {row["endpoint_template"] for row in rows} == {"games.roblox.com/v1/games"}
