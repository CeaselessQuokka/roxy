"""Routing decisions (plan 7.2), including the plan 19.5 item 6 property test: never the credential unless allowed."""

from __future__ import annotations

import random

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from roxy.core.reasons import AuthClass, Egress, ReasonCode
from roxy.upstream.routing import (
    CredentialRule,
    EgressAvailability,
    RouteRequest,
    credential_eligible,
    decide,
    shifted_weights,
)

DIRECT = EgressAvailability(Egress.DIRECT)
ROTATOR = EgressAvailability(Egress.ROTATOR)
CRED = EgressAvailability(Egress.CREDENTIAL)
ALL = {Egress.DIRECT: DIRECT, Egress.ROTATOR: ROTATOR, Egress.CREDENTIAL: CRED}
RULE = CredentialRule(1, cache_private=True, identical_anonymous=False)


def test_default_is_direct_and_rotator_weight_zero_never_wins() -> None:
    rng = random.Random(1)
    for _ in range(500):
        decision = decide(RouteRequest(method="GET"), ALL, rng)
        assert decision.egress is Egress.DIRECT
        assert decision.candidates == (Egress.DIRECT, Egress.ROTATOR)
        assert decision.auth_class is AuthClass.ANON


def test_weights_split_traffic() -> None:
    rng = random.Random(2)
    picks = [
        decide(RouteRequest(method="GET", direct_weight=50, rotator_weight=50), ALL, rng).egress for _ in range(2000)
    ]
    share = picks.count(Egress.ROTATOR) / len(picks)
    assert 0.45 < share < 0.55


def test_both_weights_zero_is_a_fair_draw() -> None:
    rng = random.Random(3)
    picks = [
        decide(RouteRequest(method="GET", direct_weight=0, rotator_weight=0), ALL, rng).egress for _ in range(2000)
    ]
    assert 0.45 < picks.count(Egress.DIRECT) / len(picks) < 0.55


@pytest.mark.parametrize(
    ("fill", "expected"),
    [(0.0, (100, 0)), (0.8, (100, 0)), (0.9, (50, 50)), (1.0, (0, 100))],
)
def test_direct_shift_toward_rotator(fill: float, expected: tuple[float, float]) -> None:
    direct, rotator = shifted_weights(100, 0, fill, 80, rotator_ok=True)
    assert (direct, rotator) == pytest.approx(expected)


def test_no_shift_without_rotator_or_at_threshold_100() -> None:
    assert shifted_weights(100, 0, 1.0, 80, rotator_ok=False) == (100, 0)
    assert shifted_weights(100, 0, 1.0, 100, rotator_ok=True) == (100, 0)


def test_shift_uses_direct_fill() -> None:
    states = dict(ALL) | {Egress.DIRECT: EgressAvailability(Egress.DIRECT, fill=1.0)}
    picks = {decide(RouteRequest(method="GET"), states, random.Random(i)).egress for i in range(50)}
    assert picks == {Egress.ROTATOR}  # a full direct bucket shifted the whole weight


def test_cooling_direct_hands_over_to_rotator() -> None:
    states = dict(ALL) | {
        Egress.DIRECT: EgressAvailability(Egress.DIRECT, cooldown_s=30, cooldown_source="retry_after")
    }
    decision = decide(RouteRequest(method="GET"), states)
    assert decision.egress is Egress.ROTATOR
    assert decision.candidates == (Egress.ROTATOR,)


def test_cooldown_is_never_waited_out() -> None:
    states = {
        Egress.DIRECT: EgressAvailability(Egress.DIRECT, cooldown_s=0.5, cooldown_source="retry_after"),
        Egress.ROTATOR: EgressAvailability(Egress.ROTATOR, enabled=False),
    }
    decision = decide(RouteRequest(method="GET", max_wait_s=4), states)
    assert decision.egress is None
    assert decision.reason is ReasonCode.UPSTREAM_COOLDOWN
    assert decision.retry_after_s == 0.5
    assert decision.cooldown_source == "retry_after"


def test_bucket_wait_within_budget_is_fine() -> None:
    states = dict(ALL) | {Egress.DIRECT: EgressAvailability(Egress.DIRECT, bucket_wait_s=3)}
    assert decide(RouteRequest(method="GET", max_wait_s=4), states).egress is Egress.DIRECT


def test_busy_beyond_budget_reports_soonest() -> None:
    states = {
        Egress.DIRECT: EgressAvailability(Egress.DIRECT, bucket_wait_s=9),
        Egress.ROTATOR: EgressAvailability(Egress.ROTATOR, cooldown_s=20),
    }
    decision = decide(RouteRequest(method="GET", max_wait_s=4), states)
    assert (decision.reason, decision.retry_after_s) == (ReasonCode.UPSTREAM_BUSY, 9)


def test_open_breaker_reports_cooldown() -> None:
    states = {
        Egress.DIRECT: EgressAvailability(Egress.DIRECT, breaker_wait_s=12),
        Egress.ROTATOR: EgressAvailability(Egress.ROTATOR, enabled=False),
    }
    decision = decide(RouteRequest(method="GET"), states)
    assert (decision.reason, decision.retry_after_s, decision.cooldown_source) == (
        ReasonCode.UPSTREAM_COOLDOWN,
        12,
        "breaker",
    )


def test_everything_disabled() -> None:
    states = {e: EgressAvailability(e, enabled=False) for e in Egress if e is not Egress.NONE}
    decision = decide(RouteRequest(method="GET"), states)
    assert (decision.reason, decision.retry_after_s) == (ReasonCode.EGRESS_DISABLED, 60)


@pytest.mark.parametrize(
    ("mode", "direct", "expected"),
    [
        ("direct_only", DIRECT, (Egress.DIRECT,)),
        ("rotator_only", DIRECT, (Egress.ROTATOR,)),
        ("prefer_rotator", DIRECT, (Egress.ROTATOR, Egress.DIRECT)),
        ("prefer_direct", DIRECT, (Egress.DIRECT, Egress.ROTATOR)),
        ("prefer_direct", EgressAvailability(Egress.DIRECT, cooldown_s=5), (Egress.ROTATOR,)),
    ],
)
def test_routing_rules(mode: str, direct: EgressAvailability, expected: tuple[Egress, ...]) -> None:
    states = {Egress.DIRECT: direct, Egress.ROTATOR: ROTATOR}
    decision = decide(RouteRequest(method="GET", routing_mode=mode), states)
    assert decision.candidates == expected


def test_direct_only_never_spills_to_rotator() -> None:
    states = {Egress.DIRECT: EgressAvailability(Egress.DIRECT, cooldown_s=10), Egress.ROTATOR: ROTATOR}
    decision = decide(RouteRequest(method="GET", routing_mode="direct_only"), states)
    assert decision.egress is None
    assert decision.reason is ReasonCode.UPSTREAM_COOLDOWN


# --- the credential (plan 7.2 step 1, D1, 6.9) -----------------------------------------------------------------------


def test_allowlisted_get_uses_the_credential() -> None:
    decision = decide(RouteRequest(method="GET", credential_rule=RULE, credential_usable=True), ALL)
    assert decision.egress is Egress.CREDENTIAL
    assert decision.auth_class is AuthClass.CRED
    assert decision.candidates == (Egress.CREDENTIAL,)  # never an anonymous fallback candidate


@pytest.mark.parametrize("method", ["POST", "PATCH", "PUT", "DELETE", "OPTIONS"])
def test_allowlisted_write_never_uses_the_credential(method: str) -> None:
    route = RouteRequest(method=method, credential_rule=RULE, credential_usable=True)
    assert credential_eligible(route) is False
    assert decide(route, ALL).egress is Egress.DIRECT


def test_unusable_credential_never_falls_back_anonymous() -> None:
    decision = decide(RouteRequest(method="GET", credential_rule=RULE, credential_usable=False), ALL)
    assert decision.egress is None
    assert decision.reason is ReasonCode.CREDENTIAL_UNAVAILABLE


def test_credential_cooldown_retry_after() -> None:
    states = dict(ALL) | {
        Egress.CREDENTIAL: EgressAvailability(Egress.CREDENTIAL, cooldown_s=42, cooldown_source="default")
    }
    decision = decide(RouteRequest(method="GET", credential_rule=RULE, credential_usable=True), states)
    assert (decision.reason, decision.retry_after_s) == (ReasonCode.CREDENTIAL_UNAVAILABLE, 42)


def test_credential_bucket_busy() -> None:
    states = dict(ALL) | {Egress.CREDENTIAL: EgressAvailability(Egress.CREDENTIAL, bucket_wait_s=30)}
    decision = decide(RouteRequest(method="GET", credential_rule=RULE, credential_usable=True, max_wait_s=4), states)
    assert (decision.reason, decision.retry_after_s) == (ReasonCode.UPSTREAM_BUSY, 30)


def test_identical_anonymous_may_go_anonymous() -> None:
    rule = CredentialRule(1, cache_private=False, identical_anonymous=True)
    decision = decide(RouteRequest(method="GET", credential_rule=rule, credential_usable=False), ALL)
    assert decision.egress is Egress.DIRECT


def test_excluded_credential_is_unavailable_not_anonymous() -> None:
    route = RouteRequest(
        method="GET", credential_rule=RULE, credential_usable=True, exclude=frozenset({Egress.CREDENTIAL})
    )
    decision = decide(route, ALL)
    assert decision.egress is None
    assert decision.reason is ReasonCode.CREDENTIAL_UNAVAILABLE


availability = st.builds(
    EgressAvailability,
    egress=st.sampled_from([Egress.DIRECT, Egress.ROTATOR, Egress.CREDENTIAL]),
    enabled=st.booleans(),
    cooldown_s=st.sampled_from([0.0, 0.0, 5.0]),
    breaker_wait_s=st.sampled_from([0.0, 0.0, 3.0]),
    bucket_wait_s=st.sampled_from([0.0, 1.0, 10.0]),
    fill=st.floats(min_value=0, max_value=1),
)


@given(
    method=st.sampled_from(["GET", "HEAD", "POST", "PATCH", "PUT", "DELETE", "get", "OPTIONS"]),
    allowlisted=st.booleans(),
    usable=st.booleans(),
    identical=st.booleans(),
    mode=st.sampled_from([None, "prefer_direct", "prefer_rotator", "direct_only", "rotator_only", "bogus"]),
    weights=st.tuples(st.integers(0, 1000), st.integers(0, 1000)),
    exclude=st.sets(st.sampled_from([Egress.DIRECT, Egress.ROTATOR, Egress.CREDENTIAL])),
    states=st.lists(availability, min_size=0, max_size=3),
    seed=st.integers(0, 10_000),
)
@settings(max_examples=600, deadline=None)
def test_routing_never_selects_credential_for_non_allowlisted(
    method: str,
    allowlisted: bool,
    usable: bool,
    identical: bool,
    mode: str | None,
    weights: tuple[int, int],
    exclude: set[Egress],
    states: list[EgressAvailability],
    seed: int,
) -> None:
    """Plan 19.5 item 6: whatever the states say, the credential is chosen only for an allowlisted GET or HEAD
    while it is usable and not excluded; and an allowlisted endpoint never silently goes anonymous instead."""
    rule = CredentialRule(1, cache_private=True, identical_anonymous=identical) if allowlisted else None
    route = RouteRequest(
        method=method,
        credential_rule=rule,
        credential_usable=usable,
        routing_mode=mode,
        direct_weight=weights[0],
        rotator_weight=weights[1],
        exclude=frozenset(exclude),
    )
    by_egress = {state.egress: state for state in states}
    decision = decide(route, by_egress, random.Random(seed))
    chosen = [decision.egress, *decision.candidates]
    if Egress.CREDENTIAL in chosen:
        assert allowlisted
        assert method.upper() in ("GET", "HEAD")
        assert usable
        assert Egress.CREDENTIAL not in exclude
        assert decision.candidates == (Egress.CREDENTIAL,)
    if allowlisted and method.upper() in ("GET", "HEAD") and not identical:
        assert decision.egress in (None, Egress.CREDENTIAL)  # no anonymous substitute (plan 6.9)
    for egress in decision.candidates:
        assert egress not in exclude
