"""Review round 4, lens logicfix: the 11.3 cache replay against the real cache, on failures that carry no status.

What this is
    An adversarial test of the insights-6 fix (`simulate.stored_as`, `cache_replay`). The fix judges a sample by its
    `upstream_status`, but reads a sample WITHOUT one as storable content. Production records exactly that for every
    request Roblox never answered (a connect error or a timeout: `upstream_status` NULL, `cache_state` MISS), and
    the cache keeps nothing for those (`cache/policy.py store_decision`: no upstream status is a failure). So the
    replay of an outage episode still counted the next requests of those keys as cache hits that never happen. This
    was a strict xfail for finding LOGICFIX-4; `stored_as` now reads a sample without a status as content only when
    the cache served it (a hit state) or it carries the hash of a body fetched from Roblox.

Why it exists
    Plan 19.10 row 11: "dry-run estimates within 10% of a replayed ground truth"; UP-TIMEOUT and UP-5XX propose cache
    lifetimes exactly for endpoints in this state, and their impact text comes from this replay. The samples hold
    what is needed to tell the two cases apart: a cache serve has a hit state (HIT, STALE, ...), a failure a MISS.

How it works
    The real app (`create_app`, its lifespan, respx playing Roblox, the cache on at its defaults). Ten keys are asked
    three times, 10 s apart; for four of them every call of the first request fails to connect (the caller gets a
    5xx), afterwards Roblox answers. The ground truth is what the real cache did: the requests it answered without
    calling Roblox (`cache_state` HIT). The replay runs over the very `request_samples` rows the proxy recorded, with
    the lifetime the cache used.

What to read next
    `roxy/insights/simulate.py` (`stored_as`, `cache_replay`), `roxy/cache/policy.py` (`store_decision`),
    `tests/insights/test_r3_insights_simulate.py` (the 5xx form of the same check).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx

from roxy.config.audit import Actor
from roxy.config.settings_service import SettingsService
from roxy.core.clock import FakeClock
from roxy.insights import simulate
from roxy.main import create_app

ADMIN = Actor("admin", "r4-logicfix")
GAMES = "games.roblox.com"
TEMPLATE = "games.roblox.com/v1/games/votes"
KEYS = 10
FAILING = 4


async def test_r4_logicfix_replay_of_failed_requests_matches_the_real_cache(
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
            {"tarpit_enabled": 0, "rotator_enabled": 0, "request_sample_pct": 100}, ADMIN, "r4 replay setup"
        )
        down: set[str] = set()

        def roblox(request: httpx.Request) -> httpx.Response:
            universe = request.url.params.get("universeIds", "")
            if universe in down:
                raise httpx.ConnectError("connection refused", request=request)
            return httpx.Response(200, json={"data": [{"id": int(universe), "upVotes": 1}]})

        respx_mock.route(host=GAMES, path="/v1/games/votes").mock(side_effect=roblox)
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 50000))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
            for key in range(KEYS):
                for step in range(3):
                    universe = str(1000 + key)
                    if key < FAILING and step == 0:
                        down.add(universe)  # Roblox cannot be reached for this key's first request
                    else:
                        down.discard(universe)
                    response = await http.get(
                        f"/{GAMES}/v1/games/votes?universeIds={universe}",
                        headers={"User-Agent": "Roblox/Linux", "X-Forwarded-For": f"203.0.113.{key * 3 + step + 1}"},
                    )
                    failed_first = key < FAILING and step == 0
                    assert (response.status_code >= 500) == failed_first, (key, step, response.status_code)
                    await ctx.cache.settle()
                    clock.advance(10)
        await ctx.recorder.flush()
        samples = ctx.dbs.metrics.read_sync(
            lambda c: [
                dict(r)
                for r in c.execute(
                    "SELECT id, at_ms, key_id, endpoint_template, method, upstream_status, cache_state, body_hash, "
                    "egress FROM request_samples WHERE endpoint_template = ? ORDER BY id",
                    (TEMPLATE,),
                )
            ]
        )
        assert len(samples) == KEYS * 3
        failures = [s for s in samples if s["upstream_status"] is None and s["cache_state"] == "MISS"]
        assert len(failures) == FAILING, samples[:4]  # what production records for a request Roblox never answered
        truth_avoided = sum(1 for s in samples if s["cache_state"] in ("HIT", "STALE", "REVALIDATING", "COALESCED"))
        assert truth_avoided == FAILING * 1 + (KEYS - FAILING) * 2  # the real cache: 16 answered without Roblox
        ttl_s = int(ctx.settings.int("cache_ttl_seconds"))
        assert ttl_s > 20  # the three requests of a key fall inside one lifetime
        replay = simulate.cache_replay(samples, ttl_s=ttl_s, swr_s=0)
        error = abs(replay.avoided_calls - truth_avoided) / truth_avoided
        assert error <= 0.10, (
            f"replay {replay.avoided_calls} avoided calls over the production samples, the real cache avoided "
            f"{truth_avoided} ({error:.0%} off): the {FAILING} failed first requests were replayed as stored content"
        )
    finally:
        await lifespan.__aexit__(None, None, None)
