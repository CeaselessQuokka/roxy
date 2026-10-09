"""Reviewer finding spec-7: a local OPTIONS answer is not "Served from Roblox" (principle P6, honest numbers).

What this is
    A metrics test that records one ordinary upstream answer and one OPTIONS answer exactly as the proxy router
    builds it (`respond.options_rendered` plus `router.build_outcome_event`), then reads the totals the Overview
    tiles use.

Why it exists
    Plan 4.1 row 1 answers OPTIONS locally (204, never upstream), and the router records it with outcome
    `served_upstream` and reason `options_local` (CHANGES.md: "the closest value of the closed enum"). The `demand`
    measure leaves `options_local` out, but the `served_upstream` measure does not, and its catalog text says
    "Requests answered with a fresh response from Roblox". Every CORS preflight or OPTIONS probe therefore added to
    "Served from Roblox" although nothing was sent to Roblox, which P6 forbids ("Metrics never flatter"). The metrics
    unit scenario modeled the same OPTIONS answer as `served_cache`, so the producer and the read model disagreed.
    Fixed: the `served_upstream` measure leaves `options_local` out (like `demand`), the scenario in
    `test_metrics_queries.py` records what the router records, and a local OPTIONS answer is no request sample.

How it works
    The recorder from `tests/unit/metrics/conftest.py` on temp databases and the fake clock.

What to read next
    `roxy/metrics/queries.py` (`MEASURES`), `roxy/metrics/catalog.py` (`served_upstream`), `roxy/proxy/respond.py`
    (`options_rendered`).
"""

from __future__ import annotations

from typing import Any

from roxy.core.clock import FakeClock
from roxy.core.reasons import ReasonCode
from roxy.metrics import queries as q
from roxy.metrics.recorder import MetricsRecorder
from roxy.proxy import respond
from roxy.proxy.context import ProxyRequest
from roxy.proxy.router import build_outcome_event


def _options_event(clock: FakeClock) -> Any:
    req = ProxyRequest(
        request_id="01RRSPECOPTIONS00000000000",
        received_ms=clock.now_ms(),
        deadline_at=10**9,
        client_ip="203.0.113.9",
        limit_key="203.0.113.9",
        method="OPTIONS",
        host="games.roblox.com",
        path="/v1/games",
        query=[],
        prettyprint=False,
        body=b"",
        content_type=None,
        headers={},
        header_names_in_order=[],
        user_agent="Mozilla/5.0",
        place_id=None,
        is_browser=True,
        template="games.roblox.com/v1/games",
        target="games.roblox.com/v1/games",
    )
    return build_outcome_event(req, respond.options_rendered(req), None, bytes_out=0)


def _totals(recorder: MetricsRecorder, clock: FakeClock) -> dict[str, Any]:
    window = q.resolve_window("1h", now=clock.now())
    totals: dict[str, Any] = recorder.dbs.metrics.read_sync(lambda c: q.totals_sync(c, window))
    return totals


def test_spec_7_control_options_is_not_demand(
    recorder: MetricsRecorder, make_event: Any, fake_clock: FakeClock
) -> None:
    """Control (passes today): the OPTIONS record is what the router writes, and demand already leaves it out."""
    event = _options_event(fake_clock)
    assert (event.reason, event.upstream_calls, event.status) == (ReasonCode.OPTIONS_LOCAL, 0, 204)
    recorder.record_outcome(make_event())
    recorder.record_outcome(event)
    recorder.close()
    totals = _totals(recorder, fake_clock)
    assert (totals["requests"], totals["demand"], totals["upstream_calls"]) == (2, 1, 1)


def test_spec_7_local_options_is_not_served_from_roblox(
    recorder: MetricsRecorder, make_event: Any, fake_clock: FakeClock
) -> None:
    recorder.record_outcome(make_event())  # one real answer from Roblox
    recorder.record_outcome(_options_event(fake_clock))  # answered by Roxy itself, nothing sent upstream
    recorder.close()
    totals = _totals(recorder, fake_clock)
    assert (totals["served_upstream"], totals["served_cache"], totals["requests"]) == (1, 0, 2)
    samples = recorder.dbs.metrics.read_sync(lambda c: c.execute("SELECT method FROM request_samples").fetchall())
    assert [row[0] for row in samples] == ["GET"]  # the OPTIONS answer never reached the cache or Roblox
