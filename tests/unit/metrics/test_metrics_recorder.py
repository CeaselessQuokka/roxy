"""The recorder: aggregation by (minute, dims), bounded dimensions, events, drops, never raising (plan 6.3)."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest

from roxy.core.clock import FakeClock
from roxy.core.reasons import CacheState, Egress, Outcome, ReasonCode, Source
from roxy.metrics import histograms
from roxy.metrics.recorder import (
    EVENT_BURST,
    KIND_LIVE,
    KIND_SAMPLES,
    MetricsRecorder,
    OutcomeEvent,
    dims_hash,
)
from roxy.metrics.templating import OTHER

Rows = Callable[..., list[tuple[Any, ...]]]


async def test_same_minute_and_dims_make_one_row(
    recorder: MetricsRecorder, make_event: Callable[..., OutcomeEvent], metrics_rows: Rows, fake_clock: FakeClock
) -> None:
    fake_clock.set(1_760_000_080.0)  # 40 s into the minute that starts at 1_760_000_040
    for latency in (3.0, 40.0, 400.0):
        recorder.record_outcome(make_event(latency_ms=latency))
    fake_clock.advance(30)  # next minute
    recorder.record_outcome(make_event())
    await recorder.flush()
    rows = metrics_rows(
        "SELECT bucket_start, requests, upstream_calls, caller_bytes_out, latency_hist "
        "FROM rollup_minute ORDER BY bucket_start"
    )
    assert [(r[0], r[1], r[2], r[3]) for r in rows] == [(1_760_000_040, 3, 3, 1500), (1_760_000_100, 1, 1, 500)]
    hist = histograms.decode(rows[0][4])
    assert sum(hist) == 3
    assert hist[histograms.bucket_index(400.0)] == 1


async def test_dims_row_holds_every_dimension(
    recorder: MetricsRecorder, make_event: Callable[..., OutcomeEvent], metrics_rows: Rows
) -> None:
    recorder.record_outcome(make_event())
    await recorder.flush()
    (row,) = metrics_rows("SELECT * FROM dims")
    assert row[1:] == (
        "games.roblox.com/v1/games/{gameId}/votes",
        1,
        "games.roblox.com",
        "GET",
        "direct",
        "served_upstream",
        "upstream_ok",
        200,
        "roblox",
        "MISS",
        "anon",
    )
    assert row[0] == dims_hash(row[1:])


async def test_dimensions_are_bounded(
    recorder: MetricsRecorder, make_event: Callable[..., OutcomeEvent], metrics_rows: Rows
) -> None:
    recorder.record_outcome(make_event(status=418, method="BREW"))
    recorder.record_outcome(make_event(host="evil.example", endpoint_template="evil.example/a/b"))
    recorder.templates.limit = 1
    recorder.record_outcome(make_event(endpoint_template="games.roblox.com/v1/other"))
    await recorder.flush()
    rows = metrics_rows("SELECT endpoint_template, host, method, status FROM dims ORDER BY status, host")
    assert ("games.roblox.com/v1/games/{gameId}/votes", "games.roblox.com", "OTHER", 0) in rows
    assert (OTHER, OTHER, "GET", 200) in rows  # not a Roblox host: never its own dimension value
    assert (OTHER, "games.roblox.com", "GET", 200) in rows  # template vocabulary full


async def test_client_rows_and_activity_switch(
    recorder: MetricsRecorder,
    make_event: Callable[..., OutcomeEvent],
    metrics_rows: Rows,
    settings: Any,
    presets: dict[str, Any],
) -> None:
    recorder.record_outcome(make_event(client_ip="::ffff:203.0.113.9"))
    recorder.record_outcome(make_event(client_ip="203.0.113.9", **presets["refused"]))
    recorder.record_outcome(make_event(place_id=None, client_ip=""))
    await recorder.flush()
    rows = metrics_rows(
        "SELECT client_type, client_key, requests, refused, served, bytes, top_endpoint IS NULL FROM client_minute "
        "ORDER BY client_type, client_key"
    )
    # The pair row keeps which IP called as which place (v1's peer columns, finding parity-7), with no endpoint.
    assert rows == [
        ("ip", "203.0.113.9", 2, 1, 1, 1000, 0),
        ("pair", "203.0.113.9|12345", 2, 1, 1, 1000, 1),
        ("place", "12345", 2, 1, 1, 1000, 0),
    ]
    settings.set(activity_tracking=0)
    recorder.record_outcome(make_event(client_ip="198.51.100.1"))
    await recorder.flush()
    assert metrics_rows("SELECT count(*) FROM client_minute WHERE client_key = '198.51.100.1'") == [(0,)]


async def test_refusal_events_are_budgeted_but_counts_stay_exact(
    recorder: MetricsRecorder, make_event: Callable[..., OutcomeEvent], metrics_rows: Rows, presets: dict[str, Any]
) -> None:
    n = int(EVENT_BURST) + 25
    for _ in range(n):
        recorder.record_outcome(make_event(message_source="custom", **presets["refused"]))
    recorder.close()
    individual = metrics_rows(
        "SELECT count(*) FROM events WHERE type = 'refusal' AND detail_json NOT LIKE '%aggregated%'"
    )
    total = metrics_rows(
        "SELECT sum(coalesce(json_extract(detail_json, '$.count'), 1)) FROM events WHERE type = 'refusal'"
    )
    assert individual == [(int(EVENT_BURST),)]
    assert total == [(n,)]
    sources = metrics_rows(
        "SELECT DISTINCT json_extract(detail_json, '$.message_source') FROM events WHERE type = 'refusal'"
    )
    assert sources == [("custom",)]
    assert metrics_rows("SELECT sum(requests) FROM rollup_minute") == [(n,)]


async def test_aggregated_events_wait_for_their_minute_to_close(
    recorder: MetricsRecorder, metrics_rows: Rows, fake_clock: FakeClock
) -> None:
    fake_clock.set(1_760_000_100.0)
    for _ in range(5):
        recorder.record_event("ua_rule_hit", "info", "r1", {"allowed": True}, aggregate=True)
    await recorder.flush()
    assert metrics_rows("SELECT count(*) FROM events WHERE type = 'ua_rule_hit'") == [(0,)]
    fake_clock.advance(60)
    await recorder.flush()
    rows = metrics_rows("SELECT at_ms, reason_code, detail_json FROM events WHERE type = 'ua_rule_hit'")
    assert len(rows) == 1
    assert rows[0][0] == 1_760_000_100_000 // 60_000 * 60_000
    assert json.loads(rows[0][2]) == {"allowed": True, "count": 5}


async def test_upstream_429_internal_background_and_egress(recorder: MetricsRecorder, metrics_rows: Rows) -> None:
    recorder.record_upstream_429(
        endpoint_template="games.roblox.com/v1/games/{gameId}/votes",
        host="games.roblox.com",
        egress=Egress.ROTATOR,
        retry_after_s=7,
        ratelimit_headers={"X-RateLimit-Remaining": "0", "Retry-After": "7", "Set-Cookie": "nope"},
        request_id="R1",
    )
    recorder.record_internal_call(
        "token_validate",
        ok=False,
        status=503,
        duration_ms=12.5,
        endpoint_template="a.roblox.com/v1/x",
        host="a.roblox.com",
        error="boom",
    )
    recorder.record_background_fetch(
        endpoint_template="games.roblox.com/v1/x",
        host="games.roblox.com",
        calls=2,
        bytes_in=10,
        bytes_out=5,
        status=200,
    )
    recorder.record_egress_usage("rotator", req_bytes=100, resp_bytes=900, overhead_bytes=6000)
    recorder.record_egress_usage("rotator", req_bytes=1, resp_bytes=2)
    recorder.close()
    (row,) = metrics_rows("SELECT egress, retry_after_s, ratelimit_headers_json, request_id FROM upstream_429")
    assert row[0] == "rotator"
    assert json.loads(row[2]) == {"retry-after": "7", "x-ratelimit-remaining": "0"}
    internal = metrics_rows(
        "SELECT r.requests, r.upstream_calls, r.errors, d.reason_code, d.status FROM rollup_minute r "
        "JOIN dims d USING (dim_hash) WHERE d.source = 'internal'"
    )
    assert internal == [(0, 1, 1, "upstream_5xx", 503)]
    background = metrics_rows(
        "SELECT r.requests, r.upstream_calls, d.cache_state FROM rollup_minute r "
        "JOIN dims d USING (dim_hash) WHERE d.reason_code = 'cache_revalidating'"
    )
    assert background == [(0, 2, "REVALIDATING")]
    assert metrics_rows("SELECT requests, req_bytes, resp_bytes, overhead_bytes FROM egress_usage") == [
        (2, 101, 902, 6000)
    ]
    (event,) = metrics_rows("SELECT reason_code, detail_json FROM events WHERE type = 'internal_call'")
    assert event[0] == "token_validate"
    assert json.loads(event[1])["error"] == "boom"


async def test_errors_are_upserted_and_redacted(recorder: MetricsRecorder, metrics_rows: Rows) -> None:
    recorder.record_error("ValueError: bad", detail="password=hunter22 here", module_line="roxy/x.py:10")
    recorder.record_error("ValueError: bad", detail="")
    await recorder.flush()
    recorder.record_error("ValueError: bad", traceback="Traceback\n token=abcdefgh123456")
    await recorder.flush()
    (row,) = metrics_rows("SELECT count, last_detail, module_line, traceback_redacted FROM errors")
    assert row[0] == 3
    assert "hunter22" not in row[1]
    assert row[2] == "roxy/x.py:10"
    assert "abcdefgh123456" not in row[3]


async def test_queue_overflow_drops_lowest_priority_first(
    dbs: Any, settings_factory: Callable[..., Any], fake_clock: FakeClock, make_event: Callable[..., OutcomeEvent]
) -> None:
    rec = MetricsRecorder(dbs, settings_factory(metrics_queue_max=10), fake_clock)
    for i in range(20):
        rec.record_outcome(make_event(request_id=f"r{i}"))
    stats = rec.batch.stats()
    assert stats["queued"] <= 10
    assert rec.batch.dropped >= 30  # 20 live rows and 20 samples competed for 10 slots
    assert stats["kinds"][KIND_LIVE]["dropped"] > 0
    assert stats["kinds"][KIND_SAMPLES]["queued"] == 10  # samples outrank live rows
    await rec.flush()
    # Rollups are not queued items: every request is still counted.
    assert dbs.metrics.read_sync(lambda c: c.execute("SELECT sum(requests) FROM rollup_minute").fetchone()[0]) == 20


def test_record_outcome_never_raises(recorder: MetricsRecorder, make_event: Callable[..., OutcomeEvent]) -> None:
    bad = make_event()
    bad.at_ms = "not a number"  # type: ignore[assignment]
    assert recorder.record_outcome(bad) == ""
    assert recorder.record_errors == 1
    recorder.record_fingerprint(None, None)  # type: ignore[arg-type]
    assert recorder.record_errors == 2


async def test_close_writes_the_open_minute(
    recorder: MetricsRecorder, make_event: Callable[..., OutcomeEvent], metrics_rows: Rows
) -> None:
    recorder.record_outcome(make_event())
    recorder.record_visit("home", "Mozilla/5.0")
    recorder.close()
    assert metrics_rows("SELECT sum(requests) FROM rollup_minute") == [(1,)]
    assert metrics_rows("SELECT count(*) FROM events WHERE type = 'visit'") == [(1,)]


async def test_live_ring_and_live_rows(
    recorder: MetricsRecorder, make_event: Callable[..., OutcomeEvent], metrics_rows: Rows, settings: Any
) -> None:
    recorder.record_outcome(make_event(path="games.roblox.com/v1/games/1/votes", query="a=1&token=secret123"))
    await recorder.flush()
    assert len(recorder.live) == 1
    (detail,) = metrics_rows("SELECT detail_json FROM events WHERE type = 'live'")
    entry = json.loads(detail[0])
    assert entry["query"] == "a=1&token=[redacted]"
    settings.set(live_tail_buffer=0)
    recorder.record_outcome(make_event())
    assert len(recorder.live) == 0


async def test_capture_through_record_outcome(
    recorder: MetricsRecorder, make_event: Callable[..., OutcomeEvent], metrics_rows: Rows, presets: dict[str, Any]
) -> None:
    from roxy.metrics.capture import CaptureInput

    ev = make_event(request_id="REQ1", **presets["refused"])
    cap = CaptureInput(
        request_id="REQ1",
        at_ms=ev.at_ms,
        method="GET",
        url="games.roblox.com/v1/x",
        request_headers={"Cookie": "a=b"},
        request_body=b'{"password": "pw12345678"}',
    )
    assert recorder.record_outcome(ev, capture=cap) == "REQ1"
    await recorder.flush()
    assert metrics_rows("SELECT request_id, outcome FROM captures") == [("REQ1", "refused")]
    (live,) = metrics_rows("SELECT json_extract(detail_json, '$.capture_id') FROM events WHERE type = 'live'")
    assert live == ("REQ1",)


async def test_capture_errors_never_fail_the_request(
    recorder: MetricsRecorder,
    make_event: Callable[..., OutcomeEvent],
    monkeypatch: pytest.MonkeyPatch,
    presets: dict[str, Any],
    metrics_rows: Rows,
) -> None:
    import roxy.metrics.recorder as mod
    from roxy.metrics.capture import CaptureInput

    def broken(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(mod, "make_row", broken)
    ev = make_event(**presets["refused"])
    # The capture is accepted at once (its id goes to the Live row); building it fails on the encoder thread.
    assert recorder.record_outcome(ev, capture=CaptureInput(request_id="X", at_ms=ev.at_ms)) == "X"
    await recorder.flush()
    assert recorder.capture_errors == 1
    assert recorder.record_errors == 0
    assert recorder.stats()["capture_errors"] == 1
    assert metrics_rows("SELECT count(*) FROM captures") == [(0,)]
    assert metrics_rows("SELECT sum(requests) FROM rollup_minute") == [(1,)]  # the request itself was counted
    # A failure before the capture is queued (on the caller's thread) returns no capture id at all.
    monkeypatch.setattr(mod, "trim_input", broken)
    assert recorder.record_outcome(make_event(**presets["refused"]), capture=CaptureInput("Y", ev.at_ms)) == ""
    assert recorder.capture_errors == 2
    assert recorder.record_errors == 0


async def test_samples_only_for_proxied_requests(
    dbs: Any,
    settings_factory: Callable[..., Any],
    fake_clock: FakeClock,
    make_event: Callable[..., OutcomeEvent],
    presets: dict[str, Any],
) -> None:
    key = b"k" * 32
    rec = MetricsRecorder(dbs, settings_factory(), fake_clock, ip_hash_key=key)
    rec.record_outcome(make_event(cache_key_id="a" * 24, body_hash="b" * 16))
    rec.record_outcome(make_event(**presets["refused"]))
    rec.record_outcome(make_event(outcome=Outcome.FAILED, reason=ReasonCode.UPSTREAM_5XX, status=503))
    await rec.flush()
    rows = dbs.metrics.read_sync(
        lambda c: [tuple(r) for r in c.execute("SELECT key_id, client_hash, body_hash FROM request_samples")]
    )
    assert len(rows) == 2
    assert ("a" * 24, rows[0][1], "b" * 16) in rows
    client_hash = rows[0][1]
    assert client_hash is not None
    assert len(client_hash) == 16
    assert "203.0.113" not in client_hash


async def test_limiter_refusals_are_refusal_samples_bounded_per_minute(
    dbs: Any,
    settings_factory: Callable[..., Any],
    fake_clock: FakeClock,
    make_event: Callable[..., OutcomeEvent],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Review round 4 (findings LOGICFIX-5 and LOGICFIX-6): a refusal by the per-IP throttle or a later check is a
    refusal sample with its client hash and rate; an earlier refusal (flood, a ban) is not; a worker keeps at most
    `MAX_REFUSAL_SAMPLES_PER_MINUTE` a minute; request samples carry the rate they were taken at."""
    from roxy.metrics import recorder as recorder_module

    monkeypatch.setattr(recorder_module, "MAX_REFUSAL_SAMPLES_PER_MINUTE", 3)
    rec = MetricsRecorder(dbs, settings_factory(), fake_clock, ip_hash_key=b"k" * 32)
    refused = {"outcome": Outcome.REFUSED, "status": 429, "source": Source.ROXY, "cache_state": CacheState.NA}
    rec.record_outcome(make_event(**refused, reason=ReasonCode.FLOOD))  # before the per-IP limiter: not kept
    rec.record_outcome(make_event(**refused, reason=ReasonCode.BANNED))
    for _ in range(4):
        rec.record_outcome(make_event(**refused, reason=ReasonCode.THROTTLE))
    rec.record_outcome(make_event(**refused, reason=ReasonCode.ENDPOINT_RULE))
    rec.record_outcome(make_event(cache_key_id="a" * 24))
    await rec.flush()
    rows = dbs.metrics.read_sync(
        lambda c: [tuple(r) for r in c.execute("SELECT reason, client_hash, sample_pct FROM refusal_samples")]
    )
    assert [row[0] for row in rows] == ["throttle", "throttle", "throttle"]  # 3 a minute; the rest are counted
    assert all(row[1] and len(row[1]) == 16 and row[2] == 100.0 for row in rows)
    assert rec.stats()["refusal_samples_capped"] == 2
    fake_clock.advance(60)  # a new minute: room again
    rec.record_outcome(make_event(**refused, reason=ReasonCode.ENDPOINT_RULE))
    await rec.flush()
    assert dbs.metrics.read_sync(lambda c: c.execute("SELECT count(*) FROM refusal_samples").fetchone()[0]) == 4
    rates = dbs.metrics.read_sync(lambda c: [r[0] for r in c.execute("SELECT sample_pct FROM request_samples")])
    assert rates == [100.0]


async def test_fingerprints_flow_and_blocked_variant(
    recorder: MetricsRecorder, metrics_rows: Rows, fake_clock: FakeClock
) -> None:
    pairs = [("User-Agent", "Roblox/WinInet"), ("Roblox-Id", "123"), ("Cookie", "a=b"), ("X-Thing", "v")]
    recorder.record_fingerprint(pairs, "Roblox/WinInet")
    recorder.record_fingerprint(pairs, "Roblox/WinInet")
    recorder.record_fingerprint([("X-Evil", "1")], "BadBot/1", blocked=True)
    fake_clock.advance(61)
    await recorder.flush()
    assert metrics_rows("SELECT name, count FROM fingerprint_headers ORDER BY name") == [
        ("cookie", 2),
        ("roblox-id", 2),
        ("user-agent", 2),
        ("x-thing", 2),
    ]
    cookie = metrics_rows("SELECT value FROM fingerprint_values WHERE name = 'cookie'")
    assert cookie[0][0].startswith("fp:")
    blocked = metrics_rows("SELECT type, reason_code FROM events WHERE type LIKE 'blocked%' ORDER BY type")
    assert blocked == [("blocked_header", "x-evil"), ("blocked_user_agent", None)]


async def test_visits_and_security_helpers(recorder: MetricsRecorder, metrics_rows: Rows) -> None:
    recorder.record_visit("home", "")
    recorder.record_admin_visit_discount()
    recorder.record_probe("198.51.100.7", 'Invalid URL: "evil.example/x?.ROBLOSECURITY=abc"', "curl/8")
    recorder.record_login("198.51.100.8", False, username="owner")
    recorder.record_crawl("198.51.100.9", "robots.txt", "Googlebot")
    recorder.record_throttled("198.51.100.10", tier=2, strikes=4)
    recorder.close()
    probes = metrics_rows("SELECT reason_code, detail_json FROM events WHERE type = 'probe'")
    assert probes[0][0] == "Invalid URL"
    assert "abc" not in probes[0][1]
    assert metrics_rows("SELECT count(*) FROM events WHERE type IN ('login', 'crawl', 'throttled')") == [(3,)]
    counts = metrics_rows(
        "SELECT json_extract(detail_json, '$.page'), json_extract(detail_json, '$.count') "
        "FROM events WHERE type = 'visit' ORDER BY 1"
    )
    assert counts == [("admin", -1), ("home", None)]


def test_stats_shape(recorder: MetricsRecorder) -> None:
    stats = recorder.stats()
    for key in ("metrics_dropped", "capture_errors", "record_errors", "dims_last_minute", "templates_known", "batch"):
        assert key in stats


async def test_vocabulary_refresh_keeps_the_busiest(
    recorder: MetricsRecorder, make_event: Callable[..., OutcomeEvent]
) -> None:
    for _ in range(3):
        recorder.record_outcome(make_event(endpoint_template="games.roblox.com/busy"))
    recorder.record_outcome(make_event(endpoint_template="games.roblox.com/quiet"))
    await recorder.flush()
    recorder.templates.limit = 1
    await recorder.refresh_vocabulary()
    assert "games.roblox.com/busy" in recorder.templates
    assert "games.roblox.com/quiet" not in recorder.templates


def test_dims_hash_is_stable_and_signed_64_bit() -> None:
    dims = ("t", 1, "h", "GET", "direct", "served_upstream", "upstream_ok", 200, "roblox", "MISS", "anon")
    value = dims_hash(dims)
    assert value == dims_hash(tuple(dims))
    assert -(2**63) <= value < 2**63
    assert dims_hash((*dims[:-1], "cred")) != value


def test_cache_state_and_source_strings(make_event: Callable[..., OutcomeEvent]) -> None:
    ev = make_event(cache_state=CacheState.NA, source=Source.ROXY)
    assert str(ev.cache_state) == "n/a"


# --- shapes other packages call with (upstream service, egress accounting, proxy, core error hooks) -------------


async def test_shapes_used_by_other_packages(
    recorder: MetricsRecorder, make_event: Callable[..., OutcomeEvent], metrics_rows: Rows
) -> None:
    from dataclasses import dataclass

    @dataclass(frozen=True)
    class Usage:  # the attribute names of egress/accounting.py EgressUsage
        at_ms: int
        egress: Egress
        req_bytes: int
        resp_bytes: int
        overhead_bytes: int
        requests: int = 1

    recorder.record_egress_usage(Usage(1_760_000_000_000, Egress.ROTATOR, 10, 20, 30))
    recorder.record_internal_call(
        purpose="credential_probe",
        ok=True,
        status=200,
        elapsed_ms=12.0,
        endpoint="https://accountinformation.roblox.com/v1/birthdate",
        error="",
        egress="credential",
    )
    recorder.record_upstream_429(
        at_ms=1_760_000_000_000,
        endpoint_template="games.roblox.com/v1/x",
        host="games.roblox.com",
        egress="direct",
        retry_after_s=None,
        ratelimit_headers={"limit": 10.0, "remaining": 0.0, "reset_s": None},
        request_id="R",
    )
    recorder.record_outcome(
        make_event(
            host="",
            endpoint_template="(not_roblox)",
            outcome=Outcome.REFUSED,
            reason=ReasonCode.NOT_ROBLOX,
            status=404,
            source=Source.ROXY,
        )
    )
    recorder.close()
    assert metrics_rows("SELECT egress, req_bytes, resp_bytes, overhead_bytes FROM egress_usage") == [
        ("rotator", 10, 20, 30)
    ]
    internal = metrics_rows("SELECT d.host, d.endpoint_template, d.egress FROM dims d WHERE d.source = 'internal'")
    assert internal == [("accountinformation.roblox.com", "accountinformation.roblox.com/v1/birthdate", "credential")]
    (limits,) = metrics_rows("SELECT ratelimit_headers_json FROM upstream_429")[0]
    assert json.loads(limits) == {"limit": 10.0, "remaining": 0.0, "reset_s": None}
    problem = metrics_rows("SELECT endpoint_template, host FROM dims WHERE reason_code = 'not_roblox'")
    assert problem == [("(not_roblox)", OTHER)]


async def test_core_error_hooks_record_probes_and_errors(recorder: MetricsRecorder, metrics_rows: Rows) -> None:
    from roxy.core.errors import ErrorEvent, ErrorHooks
    from roxy.metrics.security_events import install_error_hooks

    hooks = ErrorHooks()
    install_error_hooks(hooks, lambda: recorder)
    hooks.client_error[0](ErrorEvent(404, None, "", "R1", "198.51.100.3", "GET", "/wp-login.php", "curl/8"))
    try:
        raise ValueError("bad thing")
    except ValueError as exc:
        hooks.server_error[0](ErrorEvent(500, None, "", "R2", "198.51.100.4", "POST", "/x", "UA", exc))
    recorder.close()
    probe = metrics_rows("SELECT reason_code, json_extract(detail_json, '$.target') FROM events WHERE type = 'probe'")
    assert probe == [("HTTP 404 via GET", "/wp-login.php")]
    (error,) = metrics_rows("SELECT signature, module_line, last_detail, traceback_redacted FROM errors")
    assert error[0] == "ValueError: bad thing"
    assert error[1].startswith("test_metrics_recorder.py:")
    assert "POST /x" in error[2]
    assert "bad thing" in error[3]


async def test_new_public_pages_are_counted_apart(recorder: MetricsRecorder, metrics_rows: Rows) -> None:
    recorder.record_visit("docs", "Mozilla/5.0")
    recorder.record_visit("status", "Mozilla/5.0")
    recorder.close()
    pages = metrics_rows("SELECT json_extract(detail_json, '$.page') FROM events WHERE type = 'visit' ORDER BY 1")
    assert pages == [("docs",), ("status",)]


def test_build_recorder_from_an_app_context(dbs: Any, settings: Any, fake_clock: FakeClock) -> None:
    from types import SimpleNamespace

    from roxy.metrics.recorder import build_recorder

    ctx = SimpleNamespace(
        dbs=dbs, settings=settings, clock=fake_clock, worker_id="host:1:abcd", ip_hash_key=None, rules=None
    )
    rec = build_recorder(ctx)
    assert rec.worker_id == "host:1:abcd"
    assert rec.clock is fake_clock
    assert "metrics.rollups" in rec.batch.kinds()
