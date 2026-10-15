"""Ingress re-review (rr), peek race lens: a decision made on "this is a fresh cache hit" must hold when it is served.

What this is
    End-to-end probes through the real middleware stack, the real proxy route, the real `AbusePipeline` and a real
    `CacheService` (over the test's hot.db and cache.db) for the two settings that let the abuse verdict depend on
    the cache peek (`router.peek_before_verdict`): `cache_serve_throttled` = 1 (a throttled caller is answered from
    a fresh entry) and `throttle_count_cache_hits` = 0 (a fresh hit is neither counted nor refused).

Why it exists
    In both modes the abuse layer lets a request through (or answers it) BECAUSE the peek saw a fresh entry. The
    router then calls `CacheService.serve(req, peek)`, which used to check freshness again against a later clock
    and, when the entry expired in between, fetched from Roblox. The window is the abuse verdict itself: one hot.db
    write with a 500 ms budget (`pipeline.TX_BUSY_TIMEOUT_MS`). A caller that kept requesting a hot key near its
    expiry got upstream calls while it was over its per-IP limit (finding INGRESS-3, fixed: `serve` now serves the
    entry the peek found fresh, the one the decision was made on).

How it works
    The verdict is wrapped so that the shared fake clock moves `VERDICT_S` (0.4 s, inside the 500 ms budget) while
    the pipeline decides, starting 0.2 s before the entry expires. The first request is a normal MISS that spends
    the caller's whole allowance (1 request per day); the second request is the over-limit caller. `FakeUpstream`
    counts every upstream call. Correct behavior: the second request is answered from the peeked entry (`HIT`,
    the first answer's body); it never makes an upstream call.

What to read next
    `roxy/proxy/router.py` (`ProxyFlow._handle`, `refuse`), `roxy/cache/service.py` (`serve`), and
    `tests/security/test_ingress_refusal_order.py` (the static-filter half of the same feature).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from ingress_support import CLIENT_IP, CatalogSettings, make_proxy_app, proxy_request, raw_asgi_request

from roxy.abuse.pipeline import AbusePipeline
from roxy.cache.service import CacheService
from roxy.cache.testing import FakeSettings, FakeUpstream, StaticRules, rules_snapshot
from roxy.core.clock import FakeClock
from roxy.rules.store import RulesSnapshot

VERDICT_S = 0.4
"""How long the abuse verdict takes in this probe (the abuse transaction's budget is 500 ms)."""
BEFORE_EXPIRY_S = 0.2
"""How long before the entry's expiry the over-limit request arrives."""
TARGET = b"/games.roblox.com/v1/games"
QUERY = b"universeIds=1"


class SlowVerdict:
    """The real pipeline, with the clock moving while it decides (a busy hot.db, still inside its budget)."""

    def __init__(self, pipeline: AbusePipeline, clock: FakeClock) -> None:
        self.pipeline = pipeline
        self.clock = clock
        self.tarpit = pipeline.tarpit

    async def evaluate(self, req: Any) -> Any:
        verdict = await self.pipeline.evaluate(req)
        self.clock.advance(VERDICT_S)
        return verdict


def headers() -> list[tuple[bytes, bytes]]:
    # The same caller headers `ingress_support.proxy_request` uses, so the probe's peek builds the same cache key.
    return [
        (b"host", b"testserver"),
        (b"x-forwarded-for", CLIENT_IP.encode()),
        (b"user-agent", b"Roblox/Linux"),
        (b"accept", b"*/*"),
    ]


@pytest.mark.parametrize(
    "mode",
    [{"cache_serve_throttled": 1}, {"throttle_count_cache_hits": 0}],
    ids=["cache_serve_throttled", "hits_not_counted"],
)
async def test_an_over_limit_caller_never_reaches_roblox_through_an_entry_that_expires_during_the_verdict(
    dbs: Any, mode: dict[str, int]
) -> None:
    clock = FakeClock()
    settings = CatalogSettings(
        {"tarpit_enabled": 0, "allowed_requests_per_minute": 1, "throttle_reset_duration": 86_400, **mode}
    )
    pipeline = AbusePipeline(
        settings=settings,
        rules=RulesSnapshot.empty(),
        hot_db=dbs.hot,
        control_db=dbs.control,
        clock=clock,
        monotonic=clock.monotonic,
    )
    upstream = FakeUpstream()
    cache = CacheService(
        dbs=dbs,
        settings=FakeSettings(),
        rules=StaticRules(rules_snapshot()),
        clock=clock,
        upstream=upstream,
        worker_id="rr-ingress",
    )
    ctx = SimpleNamespace(
        settings=settings, clock=clock, abuse=SlowVerdict(pipeline, clock), cache=cache, upstream=None, recorder=None
    )
    app = make_proxy_app(ctx)

    first, first_headers, first_body, _ = await raw_asgi_request(app, TARGET, query=QUERY, headers=headers())
    assert first == 200
    assert first_headers.get(b"roxy-cache") == b"MISS"
    await cache.settle()
    assert upstream.count == 1

    peek = await cache.peek(proxy_request(TARGET, QUERY))
    assert peek.fresh is not None, "the probe needs a fresh entry to race against"
    clock.advance(peek.fresh.expires_at - clock.now() - BEFORE_EXPIRY_S)  # the entry has 0.2 s left

    status, response_headers, body, _ = await raw_asgi_request(app, TARGET, query=QUERY, headers=headers())
    await cache.settle()
    assert upstream.count == 1, (
        f"an over-limit caller made upstream call #{upstream.count} (status {status}, "
        f"Roxy-Cache {response_headers.get(b'roxy-cache')!r})"
    )
    assert clock.now() >= peek.fresh.expires_at  # the entry really expired while the verdict ran
    # Served from the entry the decision was made on (plan row 60 in one mode, an uncounted hit in the other).
    assert (status, response_headers.get(b"roxy-cache"), body) == (200, b"HIT", first_body)


async def test_control_an_entry_that_stays_fresh_is_served_without_an_upstream_call(dbs: Any) -> None:
    """Control for the probe above: the same over-limit request with a fast verdict is served from the cache."""
    clock = FakeClock()
    settings = CatalogSettings(
        {
            "tarpit_enabled": 0,
            "allowed_requests_per_minute": 1,
            "throttle_reset_duration": 86_400,
            "cache_serve_throttled": 1,
        }
    )
    pipeline = AbusePipeline(
        settings=settings, rules=RulesSnapshot.empty(), hot_db=dbs.hot, control_db=dbs.control, clock=clock
    )
    upstream = FakeUpstream()
    cache = CacheService(
        dbs=dbs,
        settings=FakeSettings(),
        rules=StaticRules(rules_snapshot()),
        clock=clock,
        upstream=upstream,
        worker_id="rr-ingress",
    )
    ctx = SimpleNamespace(settings=settings, clock=clock, abuse=pipeline, cache=cache, upstream=None, recorder=None)
    app = make_proxy_app(ctx)
    assert (await raw_asgi_request(app, TARGET, query=QUERY, headers=headers()))[0] == 200
    await cache.settle()
    status, response_headers, _body, _ = await raw_asgi_request(app, TARGET, query=QUERY, headers=headers())
    assert status == 200
    assert response_headers.get(b"roxy-cache") == b"HIT"
    assert upstream.count == 1
