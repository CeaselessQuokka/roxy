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
    Patterns are first passed through the real validator (a probe only uses patterns the dashboard would accept).
    Time is measured with `time.perf_counter`; the bounds are several times wider than what a correct
    implementation needs, so the probes do not flake on a slow machine, and a broken bound misses them by a lot.

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


# --- what the validator still admits ---------------------------------------------------------------------------------

# Patterns the validator accepts (checked below) paired with a caller-controlled target that makes them fail slowly.
ACCEPTED_BUT_SLOW: list[tuple[str, str]] = [
    (r"x+x+x+y", "x" * MAX_TARGET),
    (r"\w+\d+\w+x", "x" * MAX_TARGET),
    (r"[a-z]+[0-9]+[a-z]+x", "x" * MAX_TARGET),
    (r".*.*.*x", "1," * (MAX_TARGET // 2)),
    (r"a.*a.*a.*b", "a" * MAX_TARGET),
    # A realistic admin cache or block rule ("any v1 icon endpoint"), slow on a path of repeated `v1/` segments.
    (r".*/v1/.*/.*icons", "v1/" * (MAX_TARGET // 3)),
]


@pytest.mark.xfail(
    strict=True,
    reason=(
        "ingress finding: rules/match.py validate_regex admits polynomial shapes (three open-ended repeats, "
        "MAX_UNBOUNDED_REPEATS = 3) that run into the 50 ms per-match timeout on a 4 KB caller path or header"
    ),
)
@pytest.mark.parametrize(("pattern", "target"), ACCEPTED_BUT_SLOW, ids=[p for p, _ in ACCEPTED_BUT_SLOW])
def test_accepted_patterns_never_need_the_timeout(pattern: str, target: str) -> None:
    """Either the validator refuses the pattern, or a worst-case caller input finishes well inside the timeout."""
    try:
        validate_regex(pattern)
    except PatternValidationError:
        return  # refused at write time: the property holds
    compiled = compile_pattern(pattern, "regex")
    before = regex_timeouts_total()
    started = time.perf_counter()
    compiled.matches(normalize_target("games.roblox.com/" + target))
    text_matches("regex", pattern, target)
    elapsed = time.perf_counter() - started
    assert regex_timeouts_total() == before, f"{pattern!r} hit the per-match timeout ({elapsed * 1000:.0f} ms)"


def test_every_slow_probe_pattern_is_accepted_by_the_validator() -> None:
    """Keeps the probe above honest: it only uses patterns an admin can actually store today."""
    for pattern, _ in ACCEPTED_BUT_SLOW:
        assert validate_regex(pattern) == pattern


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
    """An equally slow variant of `pattern` (an optional literal appended), still accepted by the validator."""
    variant = pattern + f"(?:{filler})?" * index
    validate_regex(variant)
    return variant


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


@pytest.mark.xfail(
    strict=True,
    reason=(
        "ingress finding: cache rule (and credential allowlist, routing) matches run outside any regex_budget; "
        "CacheService.peek runs them before the abuse verdict, so each stored slow regex costs the full "
        "per-match timeout on every request, even for a banned caller"
    ),
)
async def test_a_banned_caller_cannot_spend_more_regex_time_than_the_budget(dbs: Any) -> None:
    """End to end through the real route: a banned client sends a crafted path; the cache peek runs first."""
    _pattern, target = ACCEPTED_BUT_SLOW[0]
    clock = FakeClock()
    ban = BanRow(
        id=1, subject_type="ip", subject=CLIENT_IP, reason_code="admin", created_at=0, created_by="admin:owner"
    )
    settings = CatalogSettings({"tarpit_enabled": 0})
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
        rules=StaticRules(_slow_snapshot(cache_rules=_slow_cache_rules(16))),
        clock=clock,
        upstream=FakeUpstream(),
        worker_id="ingress",
    )
    ctx = SimpleNamespace(settings=settings, clock=clock, abuse=pipeline, cache=cache, upstream=None, recorder=None)
    app = make_proxy_app(ctx)
    raw = b"/games.roblox.com/" + target.encode()
    headers = [(b"host", b"testserver"), (b"x-forwarded-for", CLIENT_IP.encode())]
    started = time.perf_counter()
    status, response_headers, _body, _ = await raw_asgi_request(app, raw, headers=headers)
    elapsed = time.perf_counter() - started
    assert status == 429
    assert response_headers.get(b"roxy-refusal") == b"throttle"  # the disguised ban
    assert pipeline.stats.refusals.get("bans") == 1
    assert elapsed < REGEX_REQUEST_BUDGET_S + 0.25, f"a banned request cost {elapsed * 1000:.0f} ms of regex time"


@pytest.mark.xfail(
    strict=True,
    reason=(
        "ingress finding: the abuse pipeline prepares every check (User-Agent, header, block and endpoint "
        "regexes) before the single hot.db transaction, so a caller already over the flood or per-IP limit "
        "still runs every slow regex on every request (v1 refused a throttled caller before any regex)"
    ),
)
async def test_a_flood_refused_caller_runs_no_slow_regex(dbs: Any) -> None:
    _pattern, target = ACCEPTED_BUT_SLOW[0]
    pipeline = AbusePipeline(
        settings=CatalogSettings({"tarpit_enabled": 0, "flood_limit_per_minute": 1}),
        rules=_slow_snapshot(header_rules=_slow_header_rules(4)),
        hot_db=dbs.hot,
        control_db=dbs.control,
        clock=FakeClock(),
    )
    await pipeline.evaluate(proxy_request(b"/games.roblox.com/v1/games"))  # the one request of this minute
    crafted = proxy_request(b"/games.roblox.com/v1/games", headers=[("user-agent", "Roblox/Linux"), ("x-pad", target)])
    before = regex_timeouts_total()
    started = time.perf_counter()
    verdict = await pipeline.evaluate(crafted)
    elapsed = time.perf_counter() - started
    assert getattr(verdict, "reason", None) is ReasonCode.FLOOD
    assert regex_timeouts_total() == before, f"a flood-refused request still ran slow regexes ({elapsed * 1000:.0f} ms)"


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
