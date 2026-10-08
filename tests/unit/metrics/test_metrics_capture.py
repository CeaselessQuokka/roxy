"""Capture: broader redaction than v1, sampling, byte limits, caps, TTL, expired lookups (rows 82, 127, 128)."""

from __future__ import annotations

import json
import random
from typing import Any

import pytest

from roxy.core.redact import TOKEN_PREFIX
from roxy.metrics.capture import (
    CAPTURE_EXPIRED_MESSAGE,
    CaptureInput,
    CapturePolicy,
    build_record,
    capture_state,
    decode_record,
    encode_record,
    get_capture,
    make_row,
    truncate_body,
    write_captures,
)

NOW = 1_760_000_000


def _input(**fields: Any) -> CaptureInput:
    base: dict[str, Any] = {
        "request_id": "REQ",
        "at_ms": NOW * 1000,
        "method": "POST",
        "url": "users.roblox.com/v1/usernames/users",
        "query": "",
        "ip": "203.0.113.5",
        "outcome": "refused",
        "status": 429,
    }
    base.update(fields)
    return CaptureInput(**base)


def test_v1_expired_message_is_exact() -> None:
    assert CAPTURE_EXPIRED_MESSAGE == "That capture has expired or was evicted."


def test_headers_query_url_and_bodies_are_redacted() -> None:
    cookie = TOKEN_PREFIX + "ABCDEF0123456789" * 8
    record = build_record(
        _input(
            url="x.roblox.com/admin/invalidate/sometokenvalue123",
            query="userIds=1&access_token=abc12345&api_key=k" + "9" * 10,
            user_agent="Bot/1 password=hunter22",
            request_headers={
                "Cookie": f".ROBLOSECURITY={cookie}",
                "Authorization": "Bearer xyz",
                "X-Api-Key": "open-cloud-key-123456",
                "X-CSRF-TOKEN": "csrf123",
                "Content-Type": "application/json",
            },
            request_body=json.dumps({"usernames": ["builderman"], "password": "pw12345678", "note": cookie}).encode(),
            response_headers=[("Set-Cookie", "rbx=1"), ("Content-Type", "application/json")],
            response_body='{"data": [{"id": 156, "name": "builderman"}], "session_id": "s3cr3tsess"}',
        ),
        CapturePolicy(),
    )
    text = json.dumps(record)
    for secret in (
        "ABCDEF0123456789",
        "xyz",
        "open-cloud-key",
        "csrf123",
        "abc12345",
        "hunter22",
        "pw12345678",
        "s3cr3tsess",
        "sometokenvalue123",
        "rbx=1",
        "9999999999",
    ):
        assert secret not in text, secret
    assert record["request_headers"]["Content-Type"] == "application/json"
    assert "builderman" in record["request_body"]
    assert "builderman" in record["response_body"]
    assert record["query"].startswith("userIds=1&")


def test_bodies_are_cut_in_bytes_and_zero_keeps_none() -> None:
    assert truncate_body("é" * 10, 5) == ("éé�", True, 20)
    assert truncate_body(b"abc", 0) == ("", True, 3)
    assert truncate_body(None, 10) == ("", False, 0)
    assert truncate_body("short", 100) == ("short", False, 5)


@pytest.mark.parametrize(
    ("policy", "active"),
    [
        (CapturePolicy(), True),
        (CapturePolicy(enabled=False), False),
        (CapturePolicy(max_records=0), False),
        (CapturePolicy(max_bytes=0), False),
        (CapturePolicy(ttl_s=0), False),
    ],
)
def test_policy_is_off_when_any_cap_is_zero(policy: CapturePolicy, active: bool) -> None:
    assert policy.active is active
    assert policy.wants("refused") is active


def test_refusals_always_served_sampled() -> None:
    policy = CapturePolicy(sample_served_pct=20)
    rng = random.Random(1)
    served = sum(policy.wants("served_upstream", rng.random) for _ in range(5000))
    assert 800 < served < 1200
    assert all(policy.wants(outcome) for outcome in ("refused", "failed"))
    assert CapturePolicy(sample_served_pct=0).wants("served_cache") is False
    assert CapturePolicy(sample_served_pct=100).wants("served_cache") is True


def test_policy_from_settings() -> None:
    values = {
        "capture_enabled": 1,
        "capture_max_records": 5,
        "capture_max_bytes": 1000,
        "capture_max_body": 10,
        "capture_ttl_seconds": 60,
        "capture_sample_served_pct": 50,
    }
    policy = CapturePolicy.from_settings(values.__getitem__)
    assert policy == CapturePolicy(True, 5, 1000, 10, 60, 50.0)
    nothing: dict[str, Any] = {}
    assert CapturePolicy.from_settings(nothing.__getitem__) == CapturePolicy()


def test_encode_round_trip_is_compressed() -> None:
    record = build_record(_input(response_body="x" * 10_000), CapturePolicy(max_body=16_384))
    blob = encode_record(record)
    assert len(blob) < 1000
    assert decode_record(blob) == record


def test_write_enforces_count_bytes_and_ttl(dbs: Any) -> None:
    policy = CapturePolicy(max_records=3, ttl_s=900)
    rows = [make_row(_input(request_id=f"R{i}", at_ms=(NOW + i) * 1000), policy) for i in range(5)]
    dbs.metrics.write_sync(lambda conn: write_captures(conn, rows, policy, NOW + 10))
    ids = dbs.metrics.read_sync(lambda c: [r[0] for r in c.execute("SELECT request_id FROM captures ORDER BY id")])
    assert ids == ["R2", "R3", "R4"]
    size = len(rows[0].blob)
    small = CapturePolicy(max_records=100, max_bytes=size * 2, ttl_s=900)
    dbs.metrics.write_sync(lambda conn: write_captures(conn, [make_row(_input(request_id="R9"), small)], small, NOW))
    ids = dbs.metrics.read_sync(lambda c: [r[0] for r in c.execute("SELECT request_id FROM captures ORDER BY id")])
    assert len(ids) <= 2
    assert ids[-1] == "R9"
    short = CapturePolicy(ttl_s=5)
    dbs.metrics.write_sync(lambda conn: write_captures(conn, [], short, NOW + 3600))
    assert dbs.metrics.read_sync(lambda c: c.execute("SELECT count(*) FROM captures").fetchone()[0]) == 0


def test_get_capture_and_expiry(dbs: Any) -> None:
    policy = CapturePolicy(ttl_s=900)
    row = make_row(_input(request_id="LOOK"), policy)
    dbs.metrics.write_sync(lambda conn: write_captures(conn, [row], policy, NOW))
    found = dbs.metrics.read_sync(lambda c: get_capture(c, "LOOK", NOW + 10, 900))
    assert found is not None
    assert found["request_id"] == "LOOK"
    assert dbs.metrics.read_sync(lambda c: get_capture(c, "LOOK", NOW + 901, 900)) is None  # aged out, not swept
    assert dbs.metrics.read_sync(lambda c: get_capture(c, "MISSING", NOW, 900)) is None
    assert dbs.metrics.read_sync(lambda c: get_capture(c, "", NOW, 900)) is None
    state = dbs.metrics.read_sync(lambda c: capture_state(c, policy, NOW + 60))
    assert state["count"] == 1
    assert state["window_s"] == 60
