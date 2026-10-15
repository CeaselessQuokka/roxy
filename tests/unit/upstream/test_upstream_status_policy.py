"""Status classification and the plan 7.9 outcome policy table, row by row."""

from __future__ import annotations

import httpx
import pytest
from upstream_fakes import (
    AuthSmugglingBlocked,
    CredentialLeakBlocked,
    EgressDisabled,
    UpstreamConnectError,
    UpstreamTimeout,
)

from roxy.core.reasons import ReasonCode
from roxy.upstream.status import (
    POLICY_TABLE,
    AttemptKind,
    RetryRule,
    SideEffect,
    classify_exception,
    classify_response,
    failure_reason_text,
    has_csrf_token,
    is_negative_cacheable,
)

CSRF = {"X-CSRF-TOKEN": "abc"}


@pytest.mark.parametrize(
    ("status", "headers", "retried", "kind"),
    [
        (200, {}, False, AttemptKind.SUCCESS),
        (201, {}, False, AttemptKind.SUCCESS),
        (204, {}, False, AttemptKind.SUCCESS),
        (206, {}, False, AttemptKind.SUCCESS),
        (299, {}, False, AttemptKind.SUCCESS),
        (304, {}, False, AttemptKind.NOT_MODIFIED),
        (301, {}, False, AttemptKind.REDIRECT),
        (302, {}, False, AttemptKind.REDIRECT),
        (307, {}, False, AttemptKind.REDIRECT),
        (403, CSRF, False, AttemptKind.CSRF_CHALLENGE),
        (403, CSRF, True, AttemptKind.DEFINITIVE),
        (403, {"x-csrf-token": "  "}, False, AttemptKind.DEFINITIVE),
        (403, {}, False, AttemptKind.DEFINITIVE),
        (400, {}, False, AttemptKind.DEFINITIVE),
        (401, {}, False, AttemptKind.DEFINITIVE),
        (404, {}, False, AttemptKind.DEFINITIVE),
        (410, {}, False, AttemptKind.DEFINITIVE),
        (422, {}, False, AttemptKind.DEFINITIVE),
        (429, {}, False, AttemptKind.RATE_LIMITED),
        (429, CSRF, False, AttemptKind.RATE_LIMITED),
        (500, {}, False, AttemptKind.SERVER_ERROR),
        (502, {}, False, AttemptKind.SERVER_ERROR),
        (503, {}, False, AttemptKind.SERVER_ERROR),
        (504, {}, False, AttemptKind.SERVER_ERROR),
        (599, {}, False, AttemptKind.SERVER_ERROR),
    ],
)
def test_classify_response(status: int, headers: dict[str, str], retried: bool, kind: AttemptKind) -> None:
    assert classify_response(status, headers, csrf_retried=retried) is kind


@pytest.mark.parametrize(
    ("exc", "kind"),
    [
        (CredentialLeakBlocked("x"), AttemptKind.LEAK_BLOCKED),
        (AuthSmugglingBlocked("x"), AttemptKind.SMUGGLING_BLOCKED),
        (EgressDisabled("x"), AttemptKind.EGRESS_DISABLED),
        (UpstreamTimeout("x"), AttemptKind.TIMEOUT),
        (UpstreamConnectError("x"), AttemptKind.CONNECT_ERROR),
        (httpx.ReadTimeout("x"), AttemptKind.TIMEOUT),
        (httpx.ConnectTimeout("x"), AttemptKind.TIMEOUT),
        (httpx.ConnectError("x"), AttemptKind.CONNECT_ERROR),
        (httpx.RemoteProtocolError("x"), AttemptKind.CONNECT_ERROR),
        (ValueError("bug"), None),
    ],
)
def test_classify_exception(exc: BaseException, kind: AttemptKind | None) -> None:
    assert classify_exception(exc) is kind


def test_subclass_of_a_contract_exception_is_recognized() -> None:
    class CredentialUnavailable(EgressDisabled):
        pass

    assert classify_exception(CredentialUnavailable("x")) is AttemptKind.EGRESS_DISABLED


def test_egress_package_exceptions_are_recognized() -> None:
    errors = pytest.importorskip("roxy.egress.errors")
    from roxy.core.reasons import Egress

    assert classify_exception(errors.UpstreamTimeout(Egress.DIRECT, "t")) is AttemptKind.TIMEOUT
    assert classify_exception(errors.CredentialUnavailable("cooling_down")) is AttemptKind.EGRESS_DISABLED
    assert classify_exception(errors.TargetNotAllowed(Egress.DIRECT, "x")) is AttemptKind.TARGET_REFUSED


S = SideEffect
# Plan 7.9, one row per outcome: (kind, retry rule, side effects that must be present, reason if it ends there).
ROWS = [
    (AttemptKind.SUCCESS, RetryRule.NONE, {S.RECORD_SUCCESS, S.AIMD_SUCCESS}, ReasonCode.UPSTREAM_OK),
    (AttemptKind.NOT_MODIFIED, RetryRule.NONE, {S.REFRESH_TTL}, ReasonCode.UPSTREAM_OK),
    (AttemptKind.REDIRECT, RetryRule.FOLLOW_REDIRECT, set(), ReasonCode.UPSTREAM_OK),
    (AttemptKind.CSRF_CHALLENGE, RetryRule.CSRF_ONCE_SAME_EGRESS, set(), ReasonCode.UPSTREAM_4XX),
    (
        AttemptKind.DEFINITIVE,
        RetryRule.NONE,
        {S.NEGATIVE_CACHE, S.CREDENTIAL_REJECT_CHECK},
        ReasonCode.UPSTREAM_4XX,
    ),
    (
        AttemptKind.RATE_LIMITED,
        RetryRule.OPTIONAL_OTHER_ANONYMOUS,
        {S.COOLDOWN, S.ROTATE_SESSION, S.BREAKER_FAILURE, S.ADAPTIVE_DECREASE, S.LOG_429},
        ReasonCode.UPSTREAM_COOLDOWN,
    ),
    (AttemptKind.SERVER_ERROR, RetryRule.BACKOFF, {S.BREAKER_FAILURE}, ReasonCode.UPSTREAM_5XX),
    (
        AttemptKind.TIMEOUT,
        RetryRule.BACKOFF,
        {S.BREAKER_FAILURE, S.ROTATOR_HEALTH_FAILURE},
        ReasonCode.UPSTREAM_TIMEOUT,
    ),
    (
        AttemptKind.CONNECT_ERROR,
        RetryRule.BACKOFF,
        {S.BREAKER_FAILURE, S.ROTATOR_HEALTH_FAILURE},
        ReasonCode.UPSTREAM_CONNECT,
    ),
    (AttemptKind.LEAK_BLOCKED, RetryRule.NONE, {S.CRITICAL_ALERT, S.DISABLE_EGRESS}, ReasonCode.LEAK_BLOCKED),
    (AttemptKind.SMUGGLING_BLOCKED, RetryRule.NONE, {S.COUNT_SMUGGLING}, ReasonCode.AUTH_SMUGGLING),
    (AttemptKind.EGRESS_DISABLED, RetryRule.REROUTE, set(), ReasonCode.EGRESS_DISABLED),
    (AttemptKind.TARGET_REFUSED, RetryRule.NONE, set(), ReasonCode.HOST_NOT_ALLOWED),
]


@pytest.mark.parametrize(("kind", "retry", "effects", "reason"), ROWS, ids=[row[0].value for row in ROWS])
def test_outcome_policy_row(kind: AttemptKind, retry: RetryRule, effects: set[SideEffect], reason: ReasonCode) -> None:
    policy = POLICY_TABLE[kind]
    assert policy.retry is retry
    assert effects <= policy.side_effects
    assert policy.reason is reason


def test_every_kind_has_a_row() -> None:
    assert set(POLICY_TABLE) == set(AttemptKind)
    assert {row[0] for row in ROWS} == set(AttemptKind)


def test_only_rate_limits_and_errors_count_against_breakers_and_rotator_health() -> None:
    failing = {AttemptKind.RATE_LIMITED, AttemptKind.SERVER_ERROR, AttemptKind.TIMEOUT, AttemptKind.CONNECT_ERROR}
    assert {kind for kind, policy in POLICY_TABLE.items() if policy.breaker_failure} == failing
    assert {kind for kind, policy in POLICY_TABLE.items() if policy.rotator_health_failure} == failing


def test_nothing_sent_for_guard_and_disabled() -> None:
    unsent = {kind for kind, policy in POLICY_TABLE.items() if not policy.sent}
    assert unsent == {
        AttemptKind.LEAK_BLOCKED,
        AttemptKind.SMUGGLING_BLOCKED,
        AttemptKind.EGRESS_DISABLED,
        AttemptKind.TARGET_REFUSED,
    }


def test_no_rule_retries_onto_another_egress_immediately_on_429() -> None:
    assert POLICY_TABLE[AttemptKind.RATE_LIMITED].retry is not RetryRule.BACKOFF


@pytest.mark.parametrize(
    ("status", "headers", "negative"),
    [
        (400, {}, True),
        (404, {}, True),
        (410, {}, True),
        (403, {}, True),
        (403, CSRF, False),
        (401, {}, False),
        (422, {}, False),
    ],
)
def test_negative_caching(status: int, headers: dict[str, str], negative: bool) -> None:
    assert is_negative_cacheable(status, headers) is negative


@pytest.mark.parametrize(
    ("status", "text"),
    [
        (429, "Rate limited (429)"),
        (500, "Upstream error (500)"),
        (503, "Upstream error (503)"),
        (403, "Forbidden (403)"),
        (404, "Not found (404)"),
        (400, "Client error (400)"),
        (418, "Client error (418)"),
        (302, "HTTP 302"),
    ],
)
def test_v1_failure_labels(status: int, text: str) -> None:
    assert failure_reason_text(status) == text


def test_csrf_header_any_case() -> None:
    assert has_csrf_token({"X-Csrf-Token": "a"})
    assert not has_csrf_token({"x-csrf-token": ""})
    assert not has_csrf_token({})
