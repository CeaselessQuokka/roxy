"""Reason code tests: the enums hold exactly the DESIGN.md section 6 values."""

from __future__ import annotations

import pytest

from roxy.core.reasons import (
    FAILURE_REASONS,
    REFUSAL_REASONS,
    SERVED_REASONS,
    AuthClass,
    CacheState,
    Egress,
    Outcome,
    ReasonCategory,
    ReasonCode,
    Source,
)

DESIGN_REFUSALS = (
    "paused, banned, deny_list, flood, spam, throttle_all, throttle, place_limit, user_agent_rule, ignored_path, "
    "unsafe_url, not_roblox, host_not_allowed, auth_smuggling, header_rule, endpoint_blocked, endpoint_rule, "
    "body_too_large, headers_too_large, url_too_long, method_not_allowed, challenge, bot_score"
)
DESIGN_FAILURES = (
    "upstream_cooldown, upstream_busy, queue_overflow, upstream_5xx, upstream_timeout, upstream_connect, deadline, "
    "coalesce_timeout, egress_disabled, credential_unavailable, degraded, leak_blocked, internal_error"
)
DESIGN_SERVED = (
    "upstream_ok, upstream_4xx, cache_hit, cache_revalidating, cache_stale_cooldown, cache_stale_error, "
    "cache_coalesced, cache_negative, throttled_cache, options_local"
)


def words(text: str) -> set[str]:
    return {item.strip() for item in text.split(",")}


def test_reason_codes_are_exactly_design_section_6() -> None:
    assert {c.value for c in REFUSAL_REASONS} == words(DESIGN_REFUSALS)
    assert {c.value for c in FAILURE_REASONS} == words(DESIGN_FAILURES)
    assert {c.value for c in SERVED_REASONS} == words(DESIGN_SERVED)
    assert len(ReasonCode) == len(words(DESIGN_REFUSALS) | words(DESIGN_FAILURES) | words(DESIGN_SERVED))


def test_reason_code_is_a_string_and_has_a_category() -> None:
    assert ReasonCode.DEADLINE == "deadline"
    assert ReasonCode.DEADLINE.category is ReasonCategory.FAILURE
    assert ReasonCode.FLOOD.is_refusal
    assert ReasonCode.CACHE_HIT.is_served
    assert ReasonCode("url_too_long") is ReasonCode.URL_TOO_LONG


def test_other_enums() -> None:
    assert {o.value for o in Outcome} == {"served_upstream", "served_cache", "refused", "failed"}
    assert {e.value for e in Egress} == {"none", "direct", "credential", "rotator"}
    assert {s.value for s in Source} == {"roblox", "roxy", "relay", "internal", "cache"}
    assert {a.value for a in AuthClass} == {"anon", "cred"}


def test_cache_state_header_text() -> None:
    assert [str(s) for s in CacheState] == ["HIT", "REVALIDATING", "STALE", "COALESCED", "MISS", "OFF", "n/a"]
    assert CacheState.NA.header_text == "n/a"
    assert CacheState("NA") is CacheState.NA
    assert CacheState("hit") is CacheState.HIT
    with pytest.raises(ValueError):
        CacheState("WARM")
