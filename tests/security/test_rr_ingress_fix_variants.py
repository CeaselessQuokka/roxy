"""Ingress re-review (rr), fix verification: variants of fix pass 1's ingress findings that the original tests miss.

What this is
    Regression probes, one or more per ingress finding closed by fix pass 1 (`.remake/wave2_reports/
    fix1_integrate.md`, findings table), each attacking the fix from a side its own test does not cover: the
    spam row cap with many clients instead of one, the credential-answer rule across workers instead of inside
    one, the request regex budget across all three phases of an ALLOWED request, and the public `/internal` guard
    with other methods and spellings. Every probe here passes today: the fixes hold against these variants.

Why it exists
    A fix that only closes the exact repro of its finding tends to leave a neighbor open. These probes pin the
    neighbors, so a later change that reopens one fails here with a precise name.

How it works
    Real components over the test's databases (`dbs`): `SpamDetectors` with its caps shrunk by monkeypatch, two
    `CacheService` instances sharing hot.db and cache.db (two workers), the real proxy route with the real
    `CacheService` and `AbusePipeline` plus a fake upstream that matches the credential allowlist the way
    `upstream/service.py` does, and a Starlette app with the public `/internal` guard before the proxy route.

What to read next
    `tests/security/test_ingress_exhaustion.py`, `test_ingress_cache_poisoning.py`, `test_ingress_redos.py`, then
    the `test_rr_ingress_*.py` probes that file new findings.
"""

from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace
from typing import Any

import pytest
from ingress_support import CLIENT_IP, CatalogSettings, make_proxy_app, proxy_request, raw_asgi_request
from starlette.applications import Starlette

from roxy.abuse import spam as spam_module
from roxy.abuse.pipeline import AbusePipeline
from roxy.abuse.spam import SpamDetectors
from roxy.cache.service import CacheService
from roxy.cache.testing import FakeSettings, FakeUpstream, StaticRules, ok, rules_snapshot
from roxy.core.client_ip import parse_cidrs
from roxy.core.clock import FakeClock
from roxy.core.middleware import build_middleware
from roxy.core.reasons import AuthClass, CacheState
from roxy.internal_app import PublicInternalNotFound
from roxy.proxy.router import router as proxy_router
from roxy.rules.match import REGEX_REQUEST_BUDGET_S, regex_budget, regex_timeouts_total
from roxy.rules.models import CacheRuleRow, CredentialAllowlistRow
from roxy.rules.store import RulesSnapshot

# --- spam_windows: the fleet-wide row cap holds with many clients, not only the per-client fold -----------------------


async def test_many_clients_cannot_grow_spam_windows_past_the_row_cap(
    dbs: Any, fake_clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fix pass 1 (spam_windows unbounded) was tested with one client. Many clients (an IPv6 /48 has 65,536 /64
    limit keys) each stay under their own fold quota, so only `MAX_SPAM_ROWS` and its eviction bound the table."""
    monkeypatch.setattr(spam_module, "MAX_SPAM_ROWS", 300)
    monkeypatch.setattr(spam_module, "EVICT_BATCH", 20)
    spam = SpamDetectors(CatalogSettings(), dbs.hot, fake_clock)
    for _minute in range(3):
        for client in range(150):
            for n in range(6):
                spam.observe(
                    limit_key=f"2001:db8:{client:x}::/64",
                    place_id=f"{client}{n}",
                    template=f"games.roblox.com/v1/x{n}",
                    path=f"/v1/games/{n}",
                    query=[],
                    user_agent=f"Roblox/WinInet {n}",
                    refused=True,
                    probe=False,
                    auth=False,
                    game_server=False,
                    bypass=False,
                )
        await spam.flush()
        fake_clock.advance(60)
        rows = dbs.hot.read_sync(lambda conn: conn.execute("SELECT count(*) FROM spam_windows").fetchone()[0])
        assert rows <= 300 + spam_module.MAX_ACTIVE_FLAGS, rows
        counters = dbs.hot.read_sync(
            lambda conn: conn.execute("SELECT count(*) FROM spam_windows WHERE subject NOT LIKE 'flag|%'").fetchone()[0]
        )
        assert counters <= 300, f"{counters} counter rows over a cap of 300"
    assert spam.evicted > 0


# --- F2 across workers: a credential answer for an anonymous key never reaches a follower in another worker -----------


async def test_a_follower_in_another_worker_never_receives_a_credential_answer_for_an_anonymous_key(dbs: Any) -> None:
    """Fix pass 1 (F2) was tested with a follower in the owner's own worker (shared Python objects). Here the
    follower runs in a second `CacheService` (another worker) and can only learn the owner's answer through the
    hot.db lease row or a cache.db handoff row."""
    gate = asyncio.Event()
    clock = FakeClock()

    def respond(req: Any, n: int) -> Any:
        if n == 1:
            return ok('{"robux":"' + "secret" * 4000 + '"}', auth_class=AuthClass.CRED)  # big: a handoff row
        return ok('{"robux":"public"}')

    upstream = FakeUpstream(respond, gate=gate)
    workers = [
        CacheService(
            dbs=dbs,
            settings=FakeSettings(),
            rules=StaticRules(rules_snapshot()),
            clock=clock,
            upstream=upstream,
            worker_id=name,
        )
        for name in ("w1", "w2")
    ]

    async def call(service: CacheService) -> Any:
        req = proxy_request(b"/economy.roblox.com/v1/user/currency")
        return await service.serve(req, await service.peek(req))

    owner = asyncio.create_task(call(workers[0]))
    await asyncio.wait_for(upstream.started.wait(), timeout=5)
    follower = asyncio.create_task(call(workers[1]))
    await asyncio.sleep(0.2)  # the follower is polling the owner's lease row
    gate.set()
    first, other = await asyncio.gather(owner, follower)
    for service in workers:
        await service.settle()
    assert b"secret" in first.body
    assert b"secret" not in other.body
    assert other.cache_state is CacheState.MISS  # its own anonymous call, not a coalesced copy
    assert upstream.count == 2
    assert workers[0].stats.handoffs == 0  # the private answer never went into a handoff row either
    later = await call(workers[1])
    assert b"secret" not in later.body


# --- the request regex budget across peek, abuse and upstream for an ALLOWED request ---------------------------------

SLOW = r"x+x+x+y"
"""A stored v1 shape (the validator refuses it for new rules; the migrator stores v1 rules unjudged)."""
TARGET_TEXT = "x" * (4096 - len("/games.roblox.com/") - 64)


class AllowlistMatchingUpstream(FakeUpstream):
    """A fake upstream that matches the credential allowlist the way `upstream/service.py _run` does (inside a
    nested `regex_budget()`, which keeps the request's), then answers."""

    def __init__(self, rules: RulesSnapshot) -> None:
        super().__init__()
        self.rules = rules

    async def fetch(self, req: Any, **kwargs: Any) -> Any:
        with regex_budget():
            self.rules.credential_rule_for(f"{req.host}{req.path}", "GET")
        return await super().fetch(req, **kwargs)


async def test_an_allowed_request_spends_one_regex_budget_across_peek_and_upstream(dbs: Any) -> None:
    """Fix pass 1 (ReDoS: cache peek outside the budget) was tested with a refused caller. An allowed caller runs
    the cache policy (slow stored cache rules, enough to spend the whole budget) and then the upstream allowlist
    match (slow stored rows) in the cache's own nested `regex_budget()`. Sharing one budget, the request costs
    about one budget; two separate budgets would cost at least two (0.4 s), which the bound below excludes."""
    clock = FakeClock()
    cache_rules = tuple(CacheRuleRow(id=i, pattern=SLOW + "(?:q)?" * i, type="regex", ttl=60) for i in range(1, 9))
    allowlist = tuple(
        CredentialAllowlistRow(id=i, pattern=SLOW + "(?:w)?" * i, type="regex", methods=("GET",), cache_private=True)
        for i in range(1, 9)
    )
    upstream = AllowlistMatchingUpstream(RulesSnapshot(version=1, loaded_at=0.0, credential_allowlist=allowlist))
    settings = CatalogSettings({"tarpit_enabled": 0})
    pipeline = AbusePipeline(
        settings=settings, rules=RulesSnapshot.empty(), hot_db=dbs.hot, control_db=dbs.control, clock=clock
    )
    cache = CacheService(
        dbs=dbs,
        settings=FakeSettings(),
        rules=StaticRules(RulesSnapshot(version=1, loaded_at=0.0, cache_rules=cache_rules)),
        clock=clock,
        upstream=upstream,
        worker_id="rr-budget",
    )
    ctx = SimpleNamespace(settings=settings, clock=clock, abuse=pipeline, cache=cache, upstream=None, recorder=None)
    app = make_proxy_app(ctx)
    raw = b"/games.roblox.com/" + TARGET_TEXT.encode()
    headers = [(b"host", b"testserver"), (b"x-forwarded-for", CLIENT_IP.encode())]
    before = regex_timeouts_total()
    started = time.perf_counter()
    status, _headers, _body, _ = await raw_asgi_request(app, raw, headers=headers)
    elapsed = time.perf_counter() - started
    await cache.settle()
    assert status == 200
    assert upstream.count == 1  # the upstream phase really ran
    assert regex_timeouts_total() > before  # and the slow rules really ran into their limit
    assert elapsed < REGEX_REQUEST_BUDGET_S + 0.12, f"one request spent {elapsed * 1000:.0f} ms"


# --- /internal on the public app: every method and spelling the server hands over -----------------------------------


@pytest.fixture
def internal_guard_app() -> Starlette:
    ctx = SimpleNamespace(
        settings=CatalogSettings(), clock=FakeClock(), abuse=None, cache=None, upstream=None, recorder=None
    )
    app = Starlette(
        routes=[PublicInternalNotFound(), *proxy_router.routes],
        middleware=build_middleware(trusted_cidrs=parse_cidrs("127.0.0.1/32"), hops=1),
    )
    app.state.ctx = ctx
    return app


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS", "POST", "DELETE", "PATCH"])
@pytest.mark.parametrize(
    "raw_path",
    [b"/internal", b"/internal/", b"/internal/version", b"/%69nternal/version", b"/internal%2Fversion"],
    ids=["bare", "slash", "version", "encoded_letter", "encoded_slash"],
)
async def test_internal_paths_are_an_instant_plain_404_for_every_method(
    internal_guard_app: Starlette, method: str, raw_path: bytes
) -> None:
    """Fix pass 1 (/internal on the public port) was tested with GET. The server decodes `%69` and `%2F` into
    `scope["path"]`, which is what the guard reads; every method gets the same 404, never a proxy answer."""
    status, headers, body, _ = await raw_asgi_request(internal_guard_app, raw_path, method=method)
    assert status == 404
    assert b"roxy-refusal" not in headers
    if method != "HEAD":
        assert body == b'"Not Found"\n'
