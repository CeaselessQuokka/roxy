"""Cache policy (plan 4.4 rows 55, 56, 57, 61; plan 7.6, 7.7; 15.3 D; v1 bugs B3, B4)."""

from __future__ import annotations

import pytest

from roxy.cache.policy import (
    CacheSettings,
    StoreKind,
    is_csrf_challenge,
    marker_ttl,
    post_allowed,
    request_policy,
    select_rule,
    store_decision,
    wants_fresh,
)
from roxy.cache.testing import FakeResult, FakeSettings, failure, ok, roblox_429, roblox_error, rules_snapshot
from roxy.core.reasons import AuthClass, ReasonCode


def _cs(**overrides: object) -> CacheSettings:
    return CacheSettings.read(FakeSettings(overrides))


def test_settings_read_defaults() -> None:
    cs = _cs()
    assert cs.enabled
    assert cs.disk_enabled
    assert cs.coalesce
    assert cs.compress
    assert (cs.ttl_s, cs.error_ttl_s, cs.swr_s, cs.stale_s) == (120, 60, 60, 600)
    assert cs.owner_deadline_s == pytest.approx(36.0)  # plan 5.2: 4 + 15 x 2 + 2
    assert cs.follower_wait_s == pytest.approx(36.0)  # cache_coalesce_wait_ms 0 means the owner deadline
    assert _cs(cache_coalesce_wait_ms=1500).follower_wait_s == pytest.approx(1.5)
    assert cs.shared_tier_on
    assert not _cs(cache_max_entries=0).shared_tier_on


def test_disabled_cache_is_off() -> None:
    policy = request_policy("GET", "games.roblox.com/v1/games", {}, _cs(cache_enabled=0), rules_snapshot())
    assert not policy.cacheable
    assert policy.off_reason == "disabled"


@pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE"])
def test_write_methods_are_never_cached(method: str) -> None:
    policy = request_policy(method, "games.roblox.com/v1/games", {}, _cs(cache_post_requests="all"), rules_snapshot())
    assert not policy.cacheable
    assert policy.off_reason == "method"


def test_get_and_head_are_cacheable_with_default_lifetimes() -> None:
    for method in ("GET", "HEAD"):
        policy = request_policy(method, "games.roblox.com/v1/x", {}, _cs(), rules_snapshot())
        assert policy.cacheable
        assert policy.coalesce
        assert (policy.ttl_s, policy.negative_ttl_s, policy.swr_s, policy.stale_s) == (120, 60, 60, 600)
        assert policy.stale_window_s == 600
        assert policy.auth_class is AuthClass.ANON


def test_post_modes() -> None:
    rules = rules_snapshot()
    batch = "users.roblox.com/v1/users"  # on the built-in allowlist (plan 15.5)
    other = "users.roblox.com/v1/something"
    assert request_policy("POST", batch, {}, _cs(), rules).cacheable
    assert not request_policy("POST", other, {}, _cs(), rules).cacheable
    assert not request_policy("POST", batch, {}, _cs(cache_post_requests="off"), rules).cacheable
    assert request_policy("POST", other, {}, _cs(cache_post_requests="all"), rules).cacheable
    with_rule = rules_snapshot(cache_rules=[{"pattern": other, "ttl": 30, "methods": ["POST"]}])
    policy = request_policy("POST", other, {}, _cs(), with_rule)
    assert policy.cacheable
    assert policy.ttl_s == 30
    assert post_allowed(batch, None, "allowlist")


def test_a_post_off_by_cache_post_requests_keeps_its_identity() -> None:
    """Finding insights-7: a POST that only `cache_post_requests` keeps OFF is marked `key_when_off` (with the rule
    the cache would use), so `CacheService.peek` still builds its key for request samples. Nothing else that is OFF
    gets one: the cache switched off, another method, a `cache_private` credential endpoint."""
    batch, other, third = "users.roblox.com/v1/users", "users.roblox.com/v1/something", "users.roblox.com/v1/third"
    rule_rows = [{"pattern": other, "ttl": 30, "methods": ["GET", "POST"], "normalize_flags": ["casefold_path"]}]
    rules = rules_snapshot(cache_rules=rule_rows)
    for target, mode in ((batch, "off"), (other, "off"), (third, "allowlist")):
        policy = request_policy("POST", target, {}, _cs(cache_post_requests=mode), rules)
        assert not policy.cacheable
        assert policy.off_reason == "method"
        assert policy.key_when_off
    with_rule = request_policy("POST", other, {}, _cs(cache_post_requests="off"), rules)
    assert with_rule.rule is not None
    assert with_rule.rule.ttl == 30  # its normalization flags shape the key exactly as for a cached request
    assert not request_policy("POST", batch, {}, _cs(), rules).key_when_off  # cacheable: the ordinary key
    assert not request_policy("POST", other, {}, _cs(), rules).key_when_off
    assert not request_policy("PUT", batch, {}, _cs(cache_post_requests="all"), rules).key_when_off
    assert not request_policy("POST", batch, {}, _cs(cache_enabled=0, cache_post_requests="off"), rules).key_when_off
    private = rules_snapshot(
        credential_allowlist=[{"pattern": batch, "methods": ["POST"], "cache_private": 1}], cache_rules=rule_rows
    )
    assert not request_policy("POST", batch, {}, _cs(cache_post_requests="off"), private).key_when_off
    # An OFF policy never stores, whatever rule it carries.
    off = request_policy("POST", other, {}, _cs(cache_post_requests="off"), rules)
    assert store_decision(ok(), off, _cs()).kind is StoreKind.NONE


def test_rule_selection_respects_methods_and_default_switch() -> None:
    rules = rules_snapshot(
        cache_rules=[
            {"pattern": "games.roblox.com/v1/games/*/votes", "ttl": 50},
            {"pattern": "games.roblox.com/v1/games/1/votes", "ttl": 99, "methods": ["POST"]},
            {"pattern": "games.roblox.com/v1/games", "ttl": 7, "origin": "default"},
        ]
    )
    rule = select_rule(rules, "games.roblox.com/v1/games/1/votes", "GET", True)
    assert rule is not None
    assert rule.ttl == 50
    shipped = select_rule(rules, "games.roblox.com/v1/games", "GET", True)
    assert shipped is not None
    assert shipped.ttl == 7
    assert select_rule(rules, "games.roblox.com/v1/games", "GET", False) is None


def test_rule_lifetimes() -> None:
    rules = rules_snapshot(
        cache_rules=[
            {"pattern": "presence.roblox.com/v1/presence/users", "ttl": 15, "stale_ttl": 15, "negative_ttl": 5},
            {"pattern": "games.roblox.com/v1/never", "ttl": 0, "negative_ttl": 30},
        ]
    )
    presence = request_policy("GET", "presence.roblox.com/v1/presence/users", {}, _cs(), rules)
    assert (presence.ttl_s, presence.swr_s, presence.negative_ttl_s) == (15, 15, 5)
    never = request_policy("GET", "games.roblox.com/v1/never", {}, _cs(), rules)
    assert never.cacheable  # still MISS, like v1 (a key is built)
    assert never.ttl_s == 0
    assert never.negative_ttl_s == 0
    assert not never.coalesce  # nothing would be stored, so nobody waits for an owner


def test_credential_allowlist_sets_auth_class_and_private_is_off() -> None:
    rules = rules_snapshot(
        credential_allowlist=[
            {"pattern": "users.roblox.com/v1/users/authenticated", "methods": ["GET"], "cache_private": 1},
            {"pattern": "economy.roblox.com/v1/user/currency", "methods": ["GET"], "cache_private": 0},
        ]
    )
    private = request_policy("GET", "users.roblox.com/v1/users/authenticated", {}, _cs(), rules)
    assert not private.cacheable
    assert private.private
    assert private.auth_class is AuthClass.CRED
    assert private.off_reason == "private_credential"
    shared = request_policy("GET", "economy.roblox.com/v1/user/currency", {}, _cs(), rules)
    assert shared.cacheable
    assert shared.auth_class is AuthClass.CRED


def test_caller_no_cache_only_when_respected() -> None:
    headers = {"cache-control": "No-Cache"}
    assert not wants_fresh(headers, False)
    assert wants_fresh(headers, True)
    assert wants_fresh({"cache-control": "no-store"}, True)
    assert not wants_fresh({"pragma": "no-cache"}, True)  # v1 ignores Pragma
    policy = request_policy("GET", "games.roblox.com/x", headers, _cs(cache_respect_no_cache=1), rules_snapshot())
    assert policy.bypass_lookup


def _policy(**overrides: object):
    return request_policy("GET", "games.roblox.com/v1/x", {}, _cs(**overrides), rules_snapshot())


def test_store_2xx_all_cacheable_v1_b4_fixed() -> None:
    for status in (200, 201, 204):
        decision = store_decision(ok(status=status), _policy(), _cs())
        assert decision.kind is StoreKind.ENTRY
        assert decision.ttl_s == 120


def test_store_skips_zero_lifetime_and_oversize() -> None:
    zero = store_decision(ok(), _policy(cache_ttl_seconds=0), _cs(cache_ttl_seconds=0))
    assert zero.kind is StoreKind.NONE
    assert zero.skipped
    assert zero.why == "ttl_zero"
    big = store_decision(ok(b"x" * 11), _policy(), _cs(cache_max_body=10))
    assert big.kind is StoreKind.NONE
    assert big.why == "too_large"
    nothing = store_decision(ok(b"x"), _policy(), _cs(cache_max_body=0))
    assert nothing.kind is StoreKind.NONE  # 0 caches nothing (v1 B11 decided)


@pytest.mark.parametrize("status", [400, 404, 410])
def test_definitive_errors_are_negative_entries(status: int) -> None:
    decision = store_decision(roblox_error(status), _policy(), _cs())
    assert decision.kind is StoreKind.NEGATIVE
    assert decision.ttl_s == 60


def test_403_only_when_not_a_csrf_challenge() -> None:
    permission = roblox_error(403, b'{"errors":[{"message":"You do not have permission"}]}')
    assert store_decision(permission, _policy(), _cs()).kind is StoreKind.NEGATIVE
    csrf_header = roblox_error(403, headers={"x-csrf-token": "abc"})
    assert store_decision(csrf_header, _policy(), _cs()).kind is StoreKind.NONE
    csrf_body = roblox_error(403, b'{"errors":[{"code":0,"message":"Token Validation Failed"}]}')
    assert is_csrf_challenge({}, csrf_body.body)
    assert store_decision(csrf_body, _policy(), _cs()).why == "csrf_challenge"


def test_other_4xx_not_cached_even_under_a_rule_v1_b3_fixed() -> None:
    rules = rules_snapshot(cache_rules=[{"pattern": "games.roblox.com/v1/x", "ttl": 600}])
    policy = request_policy("GET", "games.roblox.com/v1/x", {}, _cs(), rules)
    for status in (401, 405, 409, 422):
        assert store_decision(roblox_error(status), policy, _cs()).kind is StoreKind.NONE


def test_error_ttl_zero_skips() -> None:
    decision = store_decision(roblox_error(404), _policy(cache_error_ttl_seconds=0), _cs(cache_error_ttl_seconds=0))
    assert decision.kind is StoreKind.NONE
    assert decision.skipped


def test_429_becomes_a_marker_until_the_cooldown_ends() -> None:
    decision = store_decision(roblox_429(45), _policy(), _cs())
    assert decision.kind is StoreKind.MARKER
    assert decision.ttl_s == 45
    off = store_decision(roblox_429(45), _policy(cache_negative_429=0), _cs(cache_negative_429=0))
    assert off.kind is StoreKind.NONE
    assert marker_ttl(roblox_429(5000), _cs()) == 600  # clamped to cooldown_max_s
    bare = FakeResult(status=429, upstream_status=429, reason=ReasonCode.UPSTREAM_COOLDOWN)
    assert marker_ttl(bare, _cs()) == 30  # no Retry-After: cooldown_default_s


def test_failures_are_never_content() -> None:
    for result in (failure(), failure(ReasonCode.UPSTREAM_TIMEOUT, 504), failure(ReasonCode.UPSTREAM_BUSY, 429)):
        assert store_decision(result, _policy(), _cs()).kind is StoreKind.NONE


def test_credential_answer_never_stored_under_an_anonymous_key() -> None:
    decision = store_decision(ok(auth_class=AuthClass.CRED), _policy(), _cs())
    assert decision.kind is StoreKind.NONE
    assert decision.why == "auth_class_mismatch"


def test_upstream_hints_are_honored() -> None:
    """DESIGN 11.3 hints: `cacheable` for 2xx content, `negative_ttl_s` set for negative-cacheable 4xx."""
    assert store_decision(ok(cacheable=False), _policy(), _cs()).why == "upstream_veto"
    not_negative = roblox_error(404, negative_ttl_s=None)
    assert store_decision(not_negative, _policy(), _cs()).why == "upstream_veto"
    hinted = roblox_error(404, negative_ttl_s=0)  # the hint says "negative-cacheable"; the lifetime is ours
    assert store_decision(hinted, _policy(), _cs()).ttl_s == 60
    assert roblox_error(422).negative_ttl_s is None  # the fake mirrors upstream/status.py


def test_rule_negative_ttl_applies_even_when_the_global_error_ttl_is_zero() -> None:
    rules = rules_snapshot(cache_rules=[{"pattern": "games.roblox.com/v1/x", "ttl": 60, "negative_ttl": 20}])
    cs = _cs(cache_error_ttl_seconds=0)
    policy = request_policy("GET", "games.roblox.com/v1/x", {}, cs, rules)
    decision = store_decision(roblox_error(404, negative_ttl_s=0), policy, cs)
    assert decision.kind is StoreKind.NEGATIVE
    assert decision.ttl_s == 20
