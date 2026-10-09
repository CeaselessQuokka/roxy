"""Ingress review, regex denial of service lens: what an admin pattern can cost per caller request (plan 9.9).

What this is
    Probes for `rules/match.py` (the write-time validator, the per-match timeout, the per-request budget, the
    fail-closed rule) and for where requests pay for pattern matching: the abuse pipeline, the cache policy run
    by `CacheService.peek`, and the proxy route as a whole.

Why it exists
    Admins write regular expressions (endpoint blocks and rate rules, cache rules, the credential allowlist, User-
    Agent and header rules); callers choose the text they run on (a path of up to `max_url_length` characters, a
    User-Agent or any header of up to `max_header_bytes`). A pattern that backtracks badly lets one caller freeze a
    worker's event loop. The validator, the 50 ms per-match timeout and the 200 ms per-request budget are the three
    defenses; these probes check each and fail when a request can cost more than the budget.

How it works
    The slow probes (`ACCEPTED_BUT_SLOW`) were accepted by the validator when this review ran; the write-time cost
    model (`rules/regex_cost.py`) now refuses every one of them, which a test below pins. They still matter at run
    time, because imported v1 patterns are stored without being judged again (CHANGES.md), so the budget tests build
    such rows directly, as the migrator does. Time is measured with `time.perf_counter`; the bounds are several
    times wider than what a correct implementation needs, so the probes do not flake on a slow machine, and a
    broken bound misses them by a lot.

What to read next
    `roxy/rules/match.py`, then `test_ingress_refusal_order.py`.
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any

import pytest
from ingress_support import CLIENT_IP, CatalogSettings, make_proxy_app, proxy_request, raw_asgi_request

from roxy.abuse.pipeline import AbusePipeline
from roxy.cache.policy import CacheSettings, request_policy
from roxy.cache.service import CacheService
from roxy.cache.testing import FakeSettings, FakeUpstream, StaticRules
from roxy.core.clock import FakeClock
from roxy.core.reasons import AuthClass, ReasonCode
from roxy.rules import match
from roxy.rules.match import (
    REGEX_REQUEST_BUDGET_S,
    PatternValidationError,
    compile_pattern,
    normalize_target,
    regex_timeouts_total,
    text_matches,
    validate_pattern,
    validate_regex,
)
from roxy.rules.models import BanRow, CacheRuleRow, CredentialAllowlistRow, EndpointBlockRow, HeaderRuleRow
from roxy.rules.store import BanIndex, RulesSnapshot

MAX_TARGET = 4096 - len("/games.roblox.com/")
"""The longest path a caller can send under the default `max_url_length` (4096)."""

# --- the validator refuses the classic exponential shapes ----------------------------------------------------------

CATASTROPHIC = [
    r"(a+)+",
    r"(a*)*b",
    r"(a|a)*",
    r"(a|aa)+",
    r"^(a|ab)*c",
    r"(\w+\s?)+$",
    r"^(([a-z])+.)+[A-Z]([a-z])+$",
    r"(a{1,10}){1,10}",
    r"(\d+,)+x",
    r"(.*a){20}",
    r"(?:x+x+)+y",
    r"((ab)+c)+",
    r"(.*,){5}",
    r"a" * 501,
    "a\nb",
]


@pytest.mark.parametrize("pattern", CATASTROPHIC)
def test_validator_refuses_catastrophic_shapes(pattern: str) -> None:
    with pytest.raises(PatternValidationError):
        validate_regex(pattern)


@pytest.mark.parametrize("glob", ["games.roblox.com/*a*b*c", "games.roblox.com/" + "*/" * 17 + "x", "a" * 501])
def test_validator_refuses_slow_globs(glob: str) -> None:
    with pytest.raises(PatternValidationError):
        validate_pattern(glob, "glob")


# --- what the validator used to admit ------------------------------------------------------------------------------

# Patterns the earlier validator accepted, paired with a caller-controlled target that makes them fail slowly. The
# cost model now refuses each one for new rules (checked below); they stand in for stored v1 rules.
ACCEPTED_BUT_SLOW: list[tuple[str, str]] = [
    (r"x+x+x+y", "x" * MAX_TARGET),
    (r"\w+\d+\w+x", "x" * MAX_TARGET),
    (r"[a-z]+[0-9]+[a-z]+x", "x" * MAX_TARGET),
    (r".*.*.*x", "1," * (MAX_TARGET // 2)),
    (r"a.*a.*a.*b", "a" * MAX_TARGET),
    # A realistic admin cache or block rule ("any v1 icon endpoint"), slow on a path of repeated `v1/` segments.
    (r".*/v1/.*/.*icons", "v1/" * (MAX_TARGET // 3)),
]


LONG_TARGET = 8192 - len("user-agent")
"""The longest User-Agent a caller can send under the default `max_header_bytes` (8 KiB per header line), and about
the longest path under the catalog maximum of `max_url_length`: what the cost model sizes inputs at (INGRESS-2)."""

# Patterns the validator still accepts that come closest to its cost budget (`rules/regex_cost.py`), each with its
# slowest known caller input of `LONG_TARGET` characters. They must stay accepted (the budget is not "refuse
# everything") and fast. The four near-budget patterns of fix pass 1 (`users/\d+/.*friends`, `catalog.*search`,
# `^\w+\W`, `^Mozilla/5\.0 \(.*\) AppleWebKit/.*Chrome/\d+`) took 10 to 20 ms on 8 KiB once inputs were sized
# honestly, and are refused now (tests/unit/rules/test_regex_cost.py REFUSED).
NEAR_BUDGET: list[tuple[str, str]] = [
    (r"\d{1,3}\d{1,3}x", "1" * LONG_TARGET),
    (r"[a-z]{3,8}\d{2,4}x", "a" * LONG_TARGET),
    (r"x{1,100}y", "x" * LONG_TARGET),
    ("[a-z]?" * 6 + "[0-9]", "a" * LONG_TARGET),
    (r"^catalog.*search", "catalog" * (LONG_TARGET // 7) + "searc"),
]


@pytest.mark.parametrize(
    ("pattern", "target"), ACCEPTED_BUT_SLOW + NEAR_BUDGET, ids=[p for p, _ in ACCEPTED_BUT_SLOW + NEAR_BUDGET]
)
def test_accepted_patterns_never_need_the_timeout(pattern: str, target: str) -> None:
    """Either the validator refuses the pattern, or a worst-case caller input finishes well inside the timeout
    (under half of it, as a path and as a header value). Finding fixed by the write-time cost model: every
    ACCEPTED_BUT_SLOW probe is now refused, while the NEAR_BUDGET patterns stay accepted."""
    try:
        validate_regex(pattern)
    except PatternValidationError:
        assert (pattern, target) not in NEAR_BUDGET, f"{pattern!r} should stay accepted"
        return  # refused at write time: the property holds
    compiled = compile_pattern(pattern, "regex")
    before = regex_timeouts_total()
    checks = (
        lambda: compiled.matches(normalize_target("games.roblox.com/" + target)),
        lambda: text_matches("regex", pattern, target),
    )
    for run in checks:
        started = time.perf_counter()
        run()
        elapsed = time.perf_counter() - started
        assert elapsed < match.REGEX_MATCH_TIMEOUT_S / 2, f"{pattern!r} took {elapsed * 1000:.0f} ms"
    assert regex_timeouts_total() == before, f"{pattern!r} hit the per-match timeout"


def test_every_slow_probe_pattern_is_refused_by_the_validator() -> None:
    """The probes model stored v1 rules: an admin can no longer store any of them (ingress finding fixed)."""
    for pattern, _ in ACCEPTED_BUT_SLOW:
        with pytest.raises(PatternValidationError):
            validate_regex(pattern)


# --- fail closed: a timed-out match never lets a caller past a refusing rule, never grants anything --------------


def _slow_snapshot(**families: Any) -> RulesSnapshot:
    return RulesSnapshot(version=1, loaded_at=0.0, **families)


def test_timed_out_block_regex_refuses() -> None:
    pattern, target = ACCEPTED_BUT_SLOW[0]
    snapshot = _slow_snapshot(endpoint_blocks=(EndpointBlockRow(id=1, pattern=pattern, type="regex"),))
    assert snapshot.endpoint_block_for("games.roblox.com/" + target) is not None


def test_timed_out_header_and_ua_regexes_refuse() -> None:
    pattern, target = ACCEPTED_BUT_SLOW[0]
    assert text_matches("regex", pattern, target, on_timeout=True)


def test_timed_out_credential_allowlist_regex_never_grants_the_credential() -> None:
    pattern, target = ACCEPTED_BUT_SLOW[0]
    snapshot = _slow_snapshot(
        credential_allowlist=(
            CredentialAllowlistRow(id=1, pattern=pattern, type="regex", methods=("GET",), cache_private=False),
        )
    )
    assert snapshot.credential_rule_for("games.roblox.com/" + target, "GET") is None
    cs = CacheSettings.read(FakeSettings())
    assert request_policy("GET", "games.roblox.com/" + target, {}, cs, snapshot).auth_class is AuthClass.ANON


# --- the per-request budget -------------------------------------------------------------------------------------------


def _distinct(pattern: str, index: int, filler: str = "z") -> str:
    """An equally slow variant of `pattern` (an optional literal appended). Not validated: like the probe itself it
    stands in for a stored v1 rule, which the validator never judges again."""
    return pattern + f"(?:{filler})?" * index


def _slow_header_rules(count: int) -> tuple[HeaderRuleRow, ...]:
    pattern = ACCEPTED_BUT_SLOW[0][0]
    return tuple(
        HeaderRuleRow(id=i, canonical_key=f"k{i}", scope="value", mode="regex", needle=_distinct(pattern, i))
        for i in range(1, count + 1)
    )


def _slow_cache_rules(count: int) -> tuple[CacheRuleRow, ...]:
    pattern = ACCEPTED_BUT_SLOW[0][0]
    return tuple(
        CacheRuleRow(id=i, pattern=_distinct(pattern, i, "q"), type="regex", ttl=60) for i in range(1, count + 1)
    )


async def test_abuse_pipeline_regex_time_is_capped_by_the_budget(dbs: Any) -> None:
    """Inside `AbusePipeline.evaluate`, every pattern match shares one `regex_budget()` (plan 9.9), and refusing
    rules stop at their first timed-out match (fail closed), so a crafted request costs at most the budget."""
    pattern, target = ACCEPTED_BUT_SLOW[0]
    rules = _slow_snapshot(
        header_rules=_slow_header_rules(8),
        endpoint_blocks=tuple(
            EndpointBlockRow(id=i, pattern=_distinct(pattern, i, "b"), type="regex") for i in range(1, 9)
        ),
    )
    pipeline = AbusePipeline(
        settings=CatalogSettings({"tarpit_enabled": 0}),
        rules=rules,
        hot_db=dbs.hot,
        control_db=dbs.control,
        clock=FakeClock(),
    )
    req = proxy_request(
        b"/games.roblox.com/" + target.encode(), headers=[("user-agent", target), ("x-pad", target), ("x-b", target)]
    )
    started = time.perf_counter()
    await pipeline.evaluate(req)
    elapsed = time.perf_counter() - started
    assert elapsed < REGEX_REQUEST_BUDGET_S + 0.25, f"abuse evaluation took {elapsed * 1000:.0f} ms"


@pytest.mark.parametrize("early_peek", [False, True], ids=["defaults_peek_after_allow", "hits_not_counted"])
async def test_a_banned_caller_cannot_spend_more_regex_time_than_the_budget(dbs: Any, early_peek: bool) -> None:
    """End to end through the real route: a banned client sends a crafted path. The 16 stored slow cache rules
    (built directly, as the migrator stores v1 patterns without judging them again) would cost 16 x the per-match
    timeout. With the catalog defaults no abuse check reads the cache, so the router peeks only after an Allow and
    the banned caller runs none of them. When an admin stops counting cache hits the peek must run before the
    verdict; then `CacheService.peek` matches the rules under the router's one request `regex_budget` (fixed
    ingress finding), so the request still costs at most the budget."""
    slow, target = r"x+x+x+y", "x" * MAX_TARGET
    cache_rules = tuple(CacheRuleRow(id=i, pattern=slow + "(?:q)?" * i, type="regex", ttl=60) for i in range(1, 17))
    clock = FakeClock()
    ban = BanRow(
        id=1, subject_type="ip", subject=CLIENT_IP, reason_code="admin", created_at=0, created_by="admin:owner"
    )
    overrides: dict[str, Any] = {"tarpit_enabled": 0}
    if early_peek:
        overrides["throttle_count_cache_hits"] = 0
    settings = CatalogSettings(overrides)
    pipeline = AbusePipeline(
        settings=settings,
        rules=_slow_snapshot(bans=BanIndex([ban])),
        hot_db=dbs.hot,
        control_db=dbs.control,
        clock=clock,
    )
    cache = CacheService(
        dbs=dbs,
        settings=FakeSettings(),
        rules=StaticRules(_slow_snapshot(cache_rules=cache_rules)),
        clock=clock,
        upstream=FakeUpstream(),
        worker_id="ingress",
    )
    ctx = SimpleNamespace(settings=settings, clock=clock, abuse=pipeline, cache=cache, upstream=None, recorder=None)
    app = make_proxy_app(ctx)
    raw = b"/games.roblox.com/" + target.encode()
    headers = [(b"host", b"testserver"), (b"x-forwarded-for", CLIENT_IP.encode())]
    timeouts_before = regex_timeouts_total()
    started = time.perf_counter()
    status, response_headers, _body, _ = await raw_asgi_request(app, raw, headers=headers)
    elapsed = time.perf_counter() - started
    assert status == 429
    assert response_headers.get(b"roxy-refusal") == b"throttle"  # the disguised ban
    assert pipeline.stats.refusals.get("bans") == 1
    if early_peek:
        # The slow rules really ran into their limit (not a vacuous pass), and the budget still capped them.
        assert regex_timeouts_total() > timeouts_before
        assert elapsed < REGEX_REQUEST_BUDGET_S + 0.25, f"a banned request cost {elapsed * 1000:.0f} ms of regex time"
    else:
        assert regex_timeouts_total() == timeouts_before, "a refused caller ran the cache rules"
        assert elapsed < REGEX_REQUEST_BUDGET_S + 0.25, f"a banned request cost {elapsed * 1000:.0f} ms"


STORED_SLOW_REGEX = r"x+x+x+y"
"""A slow header filter that can exist even under a strict validator: imported v1 patterns are not judged again
(CHANGES.md), so the rows are built directly, as the migrator stores them."""


def _stored_slow_header_rules(count: int) -> tuple[HeaderRuleRow, ...]:
    return tuple(
        HeaderRuleRow(id=i, canonical_key=f"k{i}", scope="value", mode="regex", needle=STORED_SLOW_REGEX + "(?:z)?" * i)
        for i in range(1, count + 1)
    )


@pytest.mark.parametrize("limit", ["flood", "per_ip"])
async def test_a_flood_refused_caller_runs_no_slow_regex(dbs: Any, limit: str) -> None:
    """v1 refused a throttled caller before any regex: a caller already over the flood limit (or the per-IP limit)
    must not make Roxy run an admin regex again on every request (the abuse pipeline runs the cheap limiters first
    while regex rules exist, `roxy/abuse/pipeline.py` step 2)."""
    target = "x" * MAX_TARGET
    overrides = {"flood_limit_per_minute": 1} if limit == "flood" else {"allowed_requests_per_minute": 1}
    pipeline = AbusePipeline(
        settings=CatalogSettings({"tarpit_enabled": 0, **overrides}),
        rules=_slow_snapshot(header_rules=_stored_slow_header_rules(4)),
        hot_db=dbs.hot,
        control_db=dbs.control,
        clock=FakeClock(),
    )
    first = await pipeline.evaluate(proxy_request(b"/games.roblox.com/v1/games"))  # the one request allowed
    assert getattr(first, "reason", None) is None
    crafted = proxy_request(b"/games.roblox.com/v1/games", headers=[("user-agent", "Roblox/Linux"), ("x-pad", target)])
    before = regex_timeouts_total()
    started = time.perf_counter()
    verdict = await pipeline.evaluate(crafted)
    elapsed = time.perf_counter() - started
    expected = ReasonCode.FLOOD if limit == "flood" else ReasonCode.THROTTLE
    assert getattr(verdict, "reason", None) is expected
    assert regex_timeouts_total() == before, f"a refused request still ran slow regexes ({elapsed * 1000:.0f} ms)"
    assert pipeline.stats.pattern_checks_skipped == 1
    # The same crafted request from a client that is NOT over a limit still meets the filters (fail closed).
    other = proxy_request(
        b"/games.roblox.com/v1/games",
        headers=[("user-agent", "Roblox/Linux"), ("x-pad", target)],
        client_ip="198.51.100.20",
    )
    assert getattr(await pipeline.evaluate(other), "reason", None) is ReasonCode.HEADER_RULE


def test_budget_is_per_request_not_shared() -> None:
    """The budget is a context variable: one request spending it never shortens another request's budget."""
    pattern, target = ACCEPTED_BUT_SLOW[0]
    compiled = compile_pattern(pattern, "regex")
    with match.regex_budget(0.06):
        compiled.matches(target)
        compiled.matches(target)  # budget now spent
        assert compiled.matches(target, on_timeout=True)  # answered as a timeout at once
    fast = compile_pattern("games", "regex")
    with match.regex_budget(0.06):
        assert fast.matches("games.roblox.com/v1")
