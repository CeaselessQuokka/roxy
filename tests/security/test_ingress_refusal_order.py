"""Ingress review, refusal order and bypass lens: which refusal wins when several apply, and what bypass skips.

What this is
    Pairwise probes of the abuse pipeline order against v1 (`.remake/v1notes/pipeline.md` section 4.2 and 4.6,
    plan 4.1 rows 5 to 7, DESIGN 11.1 step 4): for each pair of checks that both refuse one request, the earlier
    check's refusal must be the answer. Plus the bypass contract (skips throttle-all, per-IP, UA rules, endpoint
    rules and the tarpit; never pause, bans, filters, smuggling or blocks), and two end-to-end properties through
    the real proxy route: a bypass caller is never held by the tarpit, and a request a filter refuses is never
    answered with content.

Why it exists
    The order decides what an abuser learns and what an admin control means. A refusal that wins too early can
    unmask a disguised rule; one that wins too late lets a caller past a control (for example being served while a
    header filter should refuse them).

How it works
    The pipeline tests build a real `AbusePipeline` over the test's hot.db with a `RulesSnapshot` made directly
    from row models, and real `ProxyRequest` objects from raw paths. End-to-end tests run the real middleware stack
    and proxy route (`ingress_support.make_proxy_app`) with a tarpit sleep that records instead of sleeping.

What to read next
    `roxy/abuse/checks/__init__.py` (the order), `roxy/proxy/router.py` (`refuse`, `tarpit_plan`).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from ingress_support import CLIENT_IP, CatalogSettings, make_proxy_app, proxy_request, raw_asgi_request

from roxy.abuse import pause, throttle_all
from roxy.abuse.pipeline import AbusePipeline
from roxy.abuse.verdict import Allow, Refuse
from roxy.config.audit import Actor
from roxy.core.clock import FakeClock
from roxy.core.reasons import CacheState, Outcome, ReasonCode, Source
from roxy.proxy import respond
from roxy.rules.models import (
    AccessListRow,
    BanRow,
    EndpointBlockRow,
    EndpointLimitRow,
    HeaderRuleRow,
    IgnoredPathRow,
    UserAgentRuleRow,
)
from roxy.rules.store import AccessLists, BanIndex, RulesSnapshot

ADMIN = Actor("admin", "owner", None)
TOKEN = ("x-roblox-token", "")
XENO = ("xeno-fingerprint", "4f3a91c0")


def rules(**families: Any) -> RulesSnapshot:
    return RulesSnapshot(version=1, loaded_at=0.0, **families)


BAN = BanRow(id=1, subject_type="ip", subject=CLIENT_IP, reason_code="admin", created_at=0, created_by="admin:owner")
BYPASS = AccessListRow(id=1, kind="bypass", cidr=CLIENT_IP)
DENY = AccessListRow(id=2, kind="deny", cidr="203.0.113.0/24")
HEADER_RULE = HeaderRuleRow(id=1, canonical_key="|either|contains|xeno", scope="either", mode="contains", needle="xeno")
BLOCK = EndpointBlockRow(id=1, pattern="games.roblox.com/v1/blocked", type="glob")
ENDPOINT_RULE = EndpointLimitRow(id=1, pattern="games.roblox.com", type="glob", scope="ip", limit=1, period=60)
UA_RULE = UserAgentRuleRow(id="ua1", needle="tool", mode="contains", kind="burst", limit=1, period=60)
IGNORED = IgnoredPathRow(pattern="favicon.ico")


def pipeline_for(dbs: Any, clock: FakeClock, snapshot: RulesSnapshot, **overrides: Any) -> AbusePipeline:
    return AbusePipeline(
        settings=CatalogSettings({"tarpit_enabled": 0, "allowed_requests_per_minute": 1000, **overrides}),
        rules=snapshot,
        hot_db=dbs.hot,
        control_db=dbs.control,
        clock=clock,
    )


def req(path: bytes = b"/games.roblox.com/v1/games", *extra: tuple[str, str], ua: str = "Roblox/Linux") -> Any:
    return proxy_request(path, headers=[("user-agent", ua), ("accept", "*/*"), *extra])


async def reason_of(pipeline: AbusePipeline, request: Any) -> ReasonCode | None:
    verdict = await pipeline.evaluate(request)
    return verdict.reason if isinstance(verdict, Refuse) else None


# --- pairwise order (v1 pipeline.md 4.2) ------------------------------------------------------------------------------


async def test_pause_beats_a_ban(dbs: Any, fake_clock: FakeClock) -> None:
    await pause.set_pause(dbs.control, fake_clock, ADMIN, paused=True)
    pipeline = pipeline_for(dbs, fake_clock, rules(bans=BanIndex([BAN])))
    pipeline.switches.reload_sync()
    assert await reason_of(pipeline, req()) is ReasonCode.PAUSED


async def test_a_ban_beats_the_per_ip_throttle(dbs: Any, fake_clock: FakeClock) -> None:
    pipeline = pipeline_for(dbs, fake_clock, rules(), allowed_requests_per_minute=1)
    assert await reason_of(pipeline, req()) is None
    assert await reason_of(pipeline, req()) is ReasonCode.THROTTLE
    pipeline.rules = rules(bans=BanIndex([BAN]))
    assert await reason_of(pipeline, req()) is ReasonCode.BANNED


async def test_throttle_all_beats_the_per_ip_throttle(dbs: Any, fake_clock: FakeClock) -> None:
    await throttle_all.set_throttle_all(dbs.control, fake_clock, ADMIN, enabled=True)
    pipeline = pipeline_for(dbs, fake_clock, rules(), allowed_requests_per_minute=1)
    pipeline.switches.reload_sync()
    assert await reason_of(pipeline, req()) is None
    assert await reason_of(pipeline, req()) is ReasonCode.THROTTLE_ALL  # v1 step 3 before step 4


async def test_per_ip_throttle_beats_a_ua_rule(dbs: Any, fake_clock: FakeClock) -> None:
    pipeline = pipeline_for(dbs, fake_clock, rules(ua_rules=(UA_RULE,)), allowed_requests_per_minute=1)
    assert await reason_of(pipeline, req(ua="tool/1")) is None
    assert await reason_of(pipeline, req(ua="tool/1")) is ReasonCode.THROTTLE  # v1 step 4 before step 5


async def test_ua_rule_beats_ignored_path(dbs: Any, fake_clock: FakeClock) -> None:
    pipeline = pipeline_for(dbs, fake_clock, rules(ua_rules=(UA_RULE,), ignored_path_rows=(IGNORED,)))
    assert await reason_of(pipeline, req(ua="tool/1")) is None
    assert await reason_of(pipeline, req(b"/favicon.ico", ua="tool/1")) is ReasonCode.USER_AGENT_RULE


async def test_ignored_path_beats_not_roblox(dbs: Any, fake_clock: FakeClock) -> None:
    pipeline = pipeline_for(dbs, fake_clock, rules(ignored_path_rows=(IGNORED,)))
    assert await reason_of(pipeline, req(b"/favicon.ico")) is ReasonCode.IGNORED_PATH


async def test_unsafe_url_beats_auth_smuggling(dbs: Any, fake_clock: FakeClock) -> None:
    pipeline = pipeline_for(dbs, fake_clock, rules())
    assert await reason_of(pipeline, req(b"/games.roblox.com/%3Cx%3E", TOKEN)) is ReasonCode.UNSAFE_URL


async def test_not_roblox_beats_auth_smuggling(dbs: Any, fake_clock: FakeClock) -> None:
    pipeline = pipeline_for(dbs, fake_clock, rules())
    assert await reason_of(pipeline, req(b"/evil.example/x", TOKEN)) is ReasonCode.NOT_ROBLOX


async def test_auth_smuggling_beats_a_header_filter(dbs: Any, fake_clock: FakeClock) -> None:
    pipeline = pipeline_for(dbs, fake_clock, rules(header_rules=(HEADER_RULE,)))
    assert await reason_of(pipeline, req(b"/games.roblox.com/v1/games", TOKEN, XENO)) is ReasonCode.AUTH_SMUGGLING


async def test_header_filter_beats_an_endpoint_block(dbs: Any, fake_clock: FakeClock) -> None:
    pipeline = pipeline_for(dbs, fake_clock, rules(header_rules=(HEADER_RULE,), endpoint_blocks=(BLOCK,)))
    assert await reason_of(pipeline, req(b"/games.roblox.com/v1/blocked", XENO)) is ReasonCode.HEADER_RULE


async def test_endpoint_block_beats_an_endpoint_rule(dbs: Any, fake_clock: FakeClock) -> None:
    pipeline = pipeline_for(dbs, fake_clock, rules(endpoint_blocks=(BLOCK,), endpoint_limits=(ENDPOINT_RULE,)))
    assert await reason_of(pipeline, req()) is None  # spends the endpoint rule's one request
    assert await reason_of(pipeline, req()) is ReasonCode.ENDPOINT_RULE
    assert await reason_of(pipeline, req(b"/games.roblox.com/v1/blocked")) is ReasonCode.ENDPOINT_BLOCKED


# --- bypass (v1 pipeline.md 4.6) --------------------------------------------------------------------------------------


async def test_bypass_skips_rate_controls(dbs: Any, fake_clock: FakeClock) -> None:
    await throttle_all.set_throttle_all(dbs.control, fake_clock, ADMIN, enabled=True)
    snapshot = rules(access=AccessLists.build([BYPASS]), ua_rules=(UA_RULE,), endpoint_limits=(ENDPOINT_RULE,))
    pipeline = pipeline_for(dbs, fake_clock, snapshot, allowed_requests_per_minute=1, flood_limit_per_minute=1)
    pipeline.switches.reload_sync()
    for _ in range(5):
        assert isinstance(await pipeline.evaluate(req(ua="tool/1")), Allow)


@pytest.mark.parametrize(
    ("snapshot_kwargs", "request_args", "expected"),
    [
        ({"header_rules": (HEADER_RULE,)}, (b"/games.roblox.com/v1/games", XENO), ReasonCode.HEADER_RULE),
        ({"endpoint_blocks": (BLOCK,)}, (b"/games.roblox.com/v1/blocked",), ReasonCode.ENDPOINT_BLOCKED),
        ({}, (b"/games.roblox.com/v1/games", TOKEN), ReasonCode.AUTH_SMUGGLING),
        ({}, (b"/evil.example/x",), ReasonCode.NOT_ROBLOX),
        ({"ignored_path_rows": (IGNORED,)}, (b"/favicon.ico",), ReasonCode.IGNORED_PATH),
        ({"bans": BanIndex([BAN])}, (b"/games.roblox.com/v1/games",), ReasonCode.BANNED),
    ],
    ids=["header_rule", "block", "auth_smuggling", "not_roblox", "ignored_path", "ban"],
)
async def test_bypass_never_skips_filters(
    dbs: Any, fake_clock: FakeClock, snapshot_kwargs: dict[str, Any], request_args: tuple[Any, ...], expected: Any
) -> None:
    pipeline = pipeline_for(dbs, fake_clock, rules(access=AccessLists.build([BYPASS]), **snapshot_kwargs))
    assert await reason_of(pipeline, req(*request_args)) is expected


# --- end to end: the tarpit never holds a bypass caller ---------------------------------------------------------------


class RecordingSleep:
    def __init__(self) -> None:
        self.calls: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


def proxy_app(dbs: Any, clock: FakeClock, snapshot: RulesSnapshot, cache: Any = None, **overrides: Any) -> Any:
    settings = CatalogSettings({"tarpit_enabled": 1, **overrides})
    sleep = RecordingSleep()
    pipeline = AbusePipeline(
        settings=settings,
        rules=snapshot,
        hot_db=dbs.hot,
        control_db=dbs.control,
        clock=clock,
        tarpit_sleep=sleep,
        monotonic=clock.monotonic,
    )
    ctx = SimpleNamespace(settings=settings, clock=clock, abuse=pipeline, cache=cache, upstream=None, recorder=None)
    return make_proxy_app(ctx), sleep


def headers(*extra: tuple[bytes, bytes]) -> list[tuple[bytes, bytes]]:
    return [(b"host", b"testserver"), (b"x-forwarded-for", CLIENT_IP.encode()), *extra]


@pytest.mark.parametrize(
    ("snapshot_kwargs", "path", "extra"),
    [
        ({}, b"/evil.example/wp-login.php", ()),
        ({"header_rules": (HEADER_RULE,)}, b"/games.roblox.com/v1/games", ((b"xeno-fingerprint", b"1"),)),
        ({}, b"/games.roblox.com/v1/games", ((b"x-roblox-token", b""),)),
    ],
    ids=["probe", "header_rule", "auth_smuggling"],
)
async def test_bypass_caller_refused_by_a_filter_is_never_held(
    dbs: Any, fake_clock: FakeClock, snapshot_kwargs: dict[str, Any], path: bytes, extra: tuple[Any, ...]
) -> None:
    app, sleep = proxy_app(dbs, fake_clock, rules(access=AccessLists.build([BYPASS]), **snapshot_kwargs))
    status, _, _, _ = await raw_asgi_request(app, path, headers=headers(*extra))
    assert status in (400, 404, 429)
    assert sleep.calls == []


@pytest.mark.xfail(
    strict=True,
    reason=(
        "ingress finding: bans and the deny list (position 20) refuse before the bypass marker (position 30) "
        "runs, so req.bypass stays False and the router tarpits a bypass caller (tarpit_on_ban defaults to 1), "
        "against plan 10.6 and DESIGN 11.1 (bypass never held)"
    ),
)
@pytest.mark.parametrize("subject", ["ban", "deny_list"])
async def test_bypass_caller_refused_by_a_ban_is_never_held(dbs: Any, fake_clock: FakeClock, subject: str) -> None:
    entries = [BYPASS, DENY] if subject == "deny_list" else [BYPASS]
    bans = BanIndex([BAN]) if subject == "ban" else BanIndex()
    app, sleep = proxy_app(dbs, fake_clock, rules(access=AccessLists.build(entries), bans=bans))
    status, _, _, _ = await raw_asgi_request(app, b"/games.roblox.com/v1/games", headers=headers())
    assert status == 429  # the disguised ban or deny refusal
    assert sleep.calls == [], f"a bypass caller was held for {sleep.calls} s"


# --- end to end: a filtered request is never answered with content ---------------------------------------------------


class FreshCache:
    """A cache that reports a fresh entry for every key and serves it (what `cache_serve_throttled` uses)."""

    def __init__(self) -> None:
        self.served: list[Any] = []

    async def peek(self, req: Any) -> Any:
        return SimpleNamespace(key=SimpleNamespace(id="k", body_hash=None), fresh=object())

    async def serve(self, req: Any, peek: Any) -> Any:
        self.served.append(req)
        return respond.ProxyResult(
            reason=ReasonCode.CACHE_HIT,
            status=200,
            body=b'{"cached":true}',
            content_type="application/json",
            cache_state=CacheState.HIT,
            outcome=Outcome.SERVED_CACHE,
            source=Source.CACHE,
        )


@pytest.mark.xfail(
    strict=True,
    reason=(
        "ingress finding: with cache_serve_throttled on, a per-IP throttle refusal (position 70) carries "
        "allow_fresh_cache_serve and wins before the header filter, auth smuggling and endpoint block checks, so "
        "the router serves cached content to a request one of those filters refuses (v1 step 4a had the same flaw)"
    ),
)
@pytest.mark.parametrize(
    ("snapshot_kwargs", "path", "extra"),
    [
        ({"header_rules": (HEADER_RULE,)}, b"/games.roblox.com/v1/games", ((b"xeno-fingerprint", b"1"),)),
        ({"endpoint_blocks": (BLOCK,)}, b"/games.roblox.com/v1/blocked", ()),
        ({}, b"/games.roblox.com/v1/games", ((b"x-roblox-token", b""),)),
    ],
    ids=["header_rule", "endpoint_block", "auth_smuggling"],
)
async def test_a_throttled_request_a_filter_refuses_is_never_served_from_cache(
    dbs: Any, fake_clock: FakeClock, snapshot_kwargs: dict[str, Any], path: bytes, extra: tuple[Any, ...]
) -> None:
    cache = FreshCache()
    app, _sleep = proxy_app(
        dbs,
        fake_clock,
        rules(**snapshot_kwargs),
        cache=cache,
        tarpit_enabled=0,
        cache_serve_throttled=1,
        allowed_requests_per_minute=1,
    )
    first, _, _, _ = await raw_asgi_request(app, b"/games.roblox.com/v1/other", headers=headers())
    assert first == 200  # spends the per-IP allowance
    status, _, body, _ = await raw_asgi_request(app, path, headers=headers(*extra))
    assert b"cached" not in body, f"a filtered request got cached content ({status})"
