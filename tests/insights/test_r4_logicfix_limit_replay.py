"""Review round 4, lens logicfix: the per-IP limit dry run (THROTTLE-TUNE) over the samples production records.

What this is
    An adversarial test of the insights-14 fix (`simulate._limit_replays`: `allowed_requests_per_minute` per
    `throttle_reset_duration`, the production `gcra`). The fixer's test inserts a sample for EVERY request a client
    sent; production samples only requests that reached the cache or Roblox (`metrics/samples.py
    SAMPLED_OUTCOMES`: refusals are never sampled). THROTTLE-TUNE proposes a higher limit exactly when clients were
    refused, so its dry run replayed a stream from which every refused request was missing: the replay of the
    proposed limit refused nothing while the limiter would still refuse part of the real stream. This was a strict
    xfail for finding LOGICFIX-5; the recorder now keeps refusal samples (metrics.db schema 7 `refusal_samples`: the
    per-IP throttle and every check after it, at the same rate), and the limit replays add them to the stream.

Why it exists
    Plan 19.10 row 11: "dry-run estimates within 10% of a replayed ground truth"; plan 11.3: the preview tells the
    admin what a change does before Apply. A "0 refused" preview for a limit that still refuses a third of the
    client's requests (53 of 160 here) misleads the admin into thinking the change ends the refusals.

How it works
    The real app (`create_app`, its lifespan, respx playing Roblox): one game server sends 20 requests per 50 s for
    400 s against the default limit (10 per 50 s), escalation off so only the GCRA refuses. The proxy
    records its samples; the worker's `InsightsEngine.dry_run` previews THROTTLE-TUNE's change (10 -> 12). The
    ground truth is the production `abuse.limiter.gcra` at 12 per 50 s over every request the client SENT.

What to read next
    `roxy/insights/simulate.py` (`_limit_replays`, `limit_replay`), `roxy/metrics/samples.py` (`should_sample`),
    `roxy/insights/rules/abuse.py` (THROTTLE-TUNE).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx

from roxy.abuse.limiter import LimiterRow, gcra
from roxy.config.audit import Actor
from roxy.config.settings_service import SettingsService
from roxy.core.clock import FakeClock
from roxy.insights.models import ProposedChange, Recommendation
from roxy.main import create_app

ADMIN = Actor("admin", "r4-logicfix")
GAMES = "games.roblox.com"
CLIENT = "203.0.113.9"
PER_WINDOW = 20  # requests the client sends per `throttle_reset_duration`
WINDOWS = 8


async def test_r4_logicfix_per_ip_dry_run_over_production_samples(
    env: Any, credentials_dir: Path, respx_mock: Any
) -> None:
    for name in ("smtp_password", "alert_webhook_url"):
        (credentials_dir / name).unlink(missing_ok=True)  # alerts go to the log only
    clock = FakeClock()
    app = create_app(env, clock=clock)
    lifespan = app.router.lifespan_context(app)
    await lifespan.__aenter__()
    try:
        ctx = app.state.ctx
        settings = SettingsService(ctx.dbs.control, runtime=ctx.settings, clock=clock)
        await settings.update(
            {
                "tarpit_enabled": 0,
                "rotator_enabled": 0,
                "request_sample_pct": 100,
                "throttle_escalation_enabled": 0,  # only the GCRA refuses (no penalty ladder)
                "throttle_strike_on_retry": 0,
            },
            ADMIN,
            "r4 limit replay setup",
        )
        await ctx.settings.reload()
        limit = int(ctx.settings.int("allowed_requests_per_minute"))
        window_s = int(ctx.settings.int("throttle_reset_duration"))
        assert (limit, window_s) == (10, 50)  # the defaults the fixer's test uses too
        respx_mock.route(host=GAMES, path="/v1/games").mock(return_value=httpx.Response(200, json={"data": []}))
        sent_ms: list[int] = []
        statuses: list[int] = []
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 50000))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
            for n in range(PER_WINDOW * WINDOWS):
                sent_ms.append(int(clock.now() * 1000))
                response = await http.get(
                    f"/{GAMES}/v1/games?universeIds={n + 1}",
                    headers={"User-Agent": "Roblox/Linux", "X-Forwarded-For": CLIENT},
                )
                statuses.append(response.status_code)
                await ctx.cache.settle()
                clock.advance(window_s / PER_WINDOW)
        refused_today = statuses.count(429)
        assert refused_today > 0, statuses  # the precondition: today's limit refuses part of the stream
        assert set(statuses) == {200, 429}, statuses
        await ctx.recorder.flush()
        sampled = ctx.dbs.metrics.read_sync(lambda c: c.execute("SELECT count(*) FROM request_samples").fetchone()[0])
        assert sampled == statuses.count(200)  # refusals are never request samples (metrics/samples.py)
        refused_rows = ctx.dbs.metrics.read_sync(
            lambda c: c.execute("SELECT count(*), min(reason), max(reason) FROM refusal_samples").fetchone()
        )
        assert tuple(refused_rows) == (refused_today, "throttle", "throttle")  # each refusal is a refusal sample
        # THROTTLE-TUNE's change: 10 -> 12 per window.
        change = ProposedChange("setting", key="allowed_requests_per_minute", current=limit, proposed=12)
        rec = Recommendation(rule_id="THROTTLE-TUNE", family="abuse", subject="per-ip", title="t", changes=[change])
        report = await ctx.insights.dry_run(rec)
        # Ground truth: the production limiter at the proposed limit over every request the client sent.
        row, truth = LimiterRow("client"), 0
        for at in sent_ms:
            decision = gcra(row, 12, window_s, at)
            if decision.admitted:
                row = decision.row
            else:
                truth += 1
        assert truth > 0
        assert report.refused_requests is not None
        assert abs(report.refused_requests - truth) <= 0.10 * truth, (
            f"the dry run of 10 -> 12 per {window_s} s says {report.refused_requests} refused requests; the limiter "
            f"would refuse {truth} of the {len(sent_ms)} the client sent ({refused_today} refused today were never "
            f"sampled, so the replay never saw them)"
        )
    finally:
        await lifespan.__aexit__(None, None, None)
