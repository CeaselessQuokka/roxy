"""The CSRF token cache, the trace (row 37), and the Tier 3 AIMD limiter."""

from __future__ import annotations

from typing import Any

import pytest
from upstream_fakes import FakeSettings, read_rows

from roxy.core.reasons import Egress
from roxy.upstream import aimd, csrf
from roxy.upstream.trace import MAX_ATTEMPT_RECORDS, Trace

NOW_S = 1_760_000_000.0

# --- CSRF -------------------------------------------------------------------------------------------------------------


def test_identity_and_methods() -> None:
    assert csrf.egress_identity(Egress.DIRECT) == "direct"
    assert csrf.egress_identity(Egress.CREDENTIAL, "ignored") == "credential"
    assert csrf.egress_identity(Egress.ROTATOR, "abc") == "rotator:abc"
    assert csrf.egress_identity(Egress.ROTATOR) == "rotator"
    assert [m for m in ("GET", "HEAD", "POST", "put", "PATCH", "DELETE") if csrf.needs_token(m)] == [
        "POST",
        "put",
        "PATCH",
        "DELETE",
    ]


@pytest.mark.parametrize(
    ("headers", "token"),
    [
        ({"x-csrf-token": "abcDEF123"}, "abcDEF123"),
        ({"X-CSRF-TOKEN": " tok "}, "tok"),
        ({"x-csrf-token": "has space"}, None),
        ({"x-csrf-token": "x" * 300}, None),
        ({}, None),
    ],
)
def test_token_from(headers: dict[str, str], token: str | None) -> None:
    assert csrf.token_from(headers) == token


def test_cache_store_read_expire(dbs: Any) -> None:
    dbs.hot.write_sync(lambda c: csrf.store_token(c, "direct", "t1", 600, NOW_S))
    assert dbs.hot.read_sync(lambda c: csrf.read_token(c, "direct", NOW_S + 599)) == "t1"
    assert dbs.hot.read_sync(lambda c: csrf.read_token(c, "direct", NOW_S + 600)) is None
    assert dbs.hot.read_sync(lambda c: csrf.read_token(c, "credential", NOW_S)) is None  # identities never mix
    dbs.hot.write_sync(lambda c: csrf.forget_token(c, "direct"))
    assert dbs.hot.read_sync(lambda c: csrf.read_token(c, "direct", NOW_S)) is None


def test_cache_disabled_with_zero_ttl(dbs: Any) -> None:
    dbs.hot.write_sync(lambda c: csrf.store_token(c, "direct", "t1", 0, NOW_S))
    assert read_rows(dbs.hot, "SELECT * FROM csrf_cache") == []


def test_cache_is_bounded(dbs: Any) -> None:
    def fill(conn: Any) -> None:
        for i in range(csrf.MAX_CACHED_TOKENS + 40):
            csrf.store_token(conn, f"rotator:s{i}", f"t{i}", 600 + i, NOW_S)

    dbs.hot.write_sync(fill)
    count = read_rows(dbs.hot, "SELECT count(*) FROM csrf_cache")[0][0]
    assert count == csrf.MAX_CACHED_TOKENS
    assert dbs.hot.read_sync(lambda c: csrf.read_token(c, "rotator:s0", NOW_S)) is None  # the soonest to expire went
    last = csrf.MAX_CACHED_TOKENS + 39
    assert dbs.hot.read_sync(lambda c: csrf.read_token(c, f"rotator:s{last}", NOW_S)) == f"t{last}"


def test_expired_rows_are_pruned_on_store(dbs: Any) -> None:
    dbs.hot.write_sync(lambda c: csrf.store_token(c, "old", "t", 10, NOW_S))
    dbs.hot.write_sync(lambda c: csrf.store_token(c, "new", "t", 600, NOW_S + 100))
    assert [row[0] for row in read_rows(dbs.hot, "SELECT egress_identity FROM csrf_cache")] == ["new"]


# --- the trace --------------------------------------------------------------------------------------------------------


def test_trace_v1_fields_and_redaction() -> None:
    trace = Trace(request_id="r1")
    trace.start_attempt("direct")
    trace.record_call(egress="direct", kind="timeout", status=None, duration_ms=15000, error="ReadTimeout: slow")
    assert trace.upstream_error == "ReadTimeout: slow"
    trace.start_attempt("rotator")
    trace.record_call(
        egress="rotator",
        kind="success",
        status=200,
        duration_ms=120.4,
        headers={"set-cookie": ".ROBLOSECURITY=secret", "x-csrf-token": "tok", "content-type": "application/json"},
    )
    data = trace.to_dict()
    assert data["Attempts"] == 2
    assert data["Methods"] == ["direct", "rotator"]
    assert data["Method"] == "rotator"
    assert data["UpstreamStatus"] == 200
    assert data["UpstreamError"] == ""
    assert data["Duration"] == pytest.approx(0.12)
    assert data["UpstreamHeaders"]["set-cookie"] == "[redacted]"
    assert data["UpstreamHeaders"]["x-csrf-token"] == "[redacted]"
    assert data["UpstreamHeaders"]["content-type"] == "application/json"
    for key in ("QueueWaitMs", "CooldownSource", "BucketKey", "EgressIdentity", "CacheDecision", "Retries", "Outcome"):
        assert key in data
    assert [call["Kind"] for call in data["Calls"]] == ["timeout", "success"]


def test_trace_counts_csrf_retries_and_is_bounded() -> None:
    trace = Trace()
    trace.start_attempt("direct")
    for _ in range(MAX_ATTEMPT_RECORDS + 5):
        trace.record_call(egress="direct", kind="csrf_challenge", status=403, duration_ms=1, csrf_retry=True)
    assert trace.retries == MAX_ATTEMPT_RECORDS + 5
    assert len(trace.calls) == MAX_ATTEMPT_RECORDS


# --- AIMD (Tier 3, off by default) ------------------------------------------------------------------------------------


def test_aimd_off_by_default() -> None:
    policy = aimd.AimdPolicy.from_settings(FakeSettings())
    assert policy.enabled is False
    assert (policy.initial, policy.minimum, policy.maximum, policy.increase_after, policy.decrease_factor) == (
        8,
        1,
        32,
        50,
        0.5,
    )


def test_aimd_limit_arithmetic() -> None:
    policy = aimd.AimdPolicy(enabled=True)
    limit = 8.0
    for _ in range(50):
        limit = aimd.next_limit(limit, True, policy)
    assert limit == pytest.approx(9.0)  # +1 after 50 successes
    assert aimd.next_limit(9.0, False, policy) == 4.5
    assert aimd.next_limit(1.5, False, policy) == 1.0  # floor
    assert aimd.next_limit(32.0, True, policy) == 32.0  # ceiling


def test_aimd_slots_across_holders(dbs: Any) -> None:
    policy = aimd.AimdPolicy(enabled=True, initial=2)
    key = aimd.aimd_key("games.roblox.com", Egress.DIRECT)
    now_ms = int(NOW_S * 1000)
    first = dbs.hot.write_sync(lambda c: aimd.acquire(c, key, "w1:1", policy, now_ms))
    second = dbs.hot.write_sync(lambda c: aimd.acquire(c, key, "w2:1", policy, now_ms))
    third = dbs.hot.write_sync(lambda c: aimd.acquire(c, key, "w1:2", policy, now_ms))
    assert first
    assert second
    assert third is None
    assert read_rows(dbs.hot, "SELECT inflight FROM aimd WHERE key = ?", (key,)) == [(2,)]
    limit = dbs.hot.write_sync(lambda c: aimd.release(c, key, first, "w1:1", False, policy, now_ms))
    assert limit == 1.0
    assert dbs.hot.write_sync(lambda c: aimd.acquire(c, key, "w1:3", policy, now_ms)) is None  # limit 1, one in flight
    assert dbs.hot.write_sync(lambda c: aimd.acquire(c, key, "w1:4", policy, now_ms + 21_000)) is not None  # expiry
