"""Tests for `roxy.config.audit` (DESIGN.md section 5; plan 6.2, 9.7): audit rows and secret masking."""

from __future__ import annotations

import base64
import json
import secrets
import sqlite3
from collections.abc import Iterator
from typing import Any

import pytest

from roxy.config import audit
from roxy.config.audit import SYSTEM_ACTOR, Actor, AuditSecretError, is_secret_target, scrub, secret_summary
from roxy.config.constants import MAX_AUDIT_JSON_BYTES
from roxy.core.redact import MASK, TOKEN_PREFIX, SecretRegistry

KEY = b"0123456789abcdef0123456789abcdef"


@pytest.fixture
def registered_secret() -> Iterator[str]:
    value = "fake-registered-" + secrets.token_hex(12)
    SecretRegistry.register("test_audit_secret", value)
    yield value
    SecretRegistry.unregister("test_audit_secret")


def _all_text(dbs: Any) -> str:
    """Every cell of every table in control.db, as one string (for "the value appears nowhere" checks)."""

    def dump(conn: sqlite3.Connection) -> str:
        parts: list[str] = []
        tables = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
        for table in tables:
            for row in conn.execute(f'SELECT * FROM "{table}"'):
                parts.extend(str(cell) for cell in tuple(row))
        return "\n".join(parts)

    return str(dbs.control.read_sync(dump))


def test_record_writes_one_row(dbs: Any) -> None:
    actor = Actor("admin", "owner", "198.51.100.4")
    row_id = dbs.control.write_sync(
        lambda conn: audit.record(
            conn, actor, "rule.create", "rules_cache:7", None, {"ttl": 300}, "why not", "req1", at=1234
        )
    )
    row = dbs.control.read_sync(lambda conn: conn.execute("SELECT * FROM audit_log WHERE id = ?", (row_id,)).fetchone())
    assert dict(row) == {
        "id": row_id,
        "at": 1234,
        "actor": "admin:owner",
        "actor_ip": "198.51.100.4",
        "action": "rule.create",
        "target": "rules_cache:7",
        "before_json": None,
        "after_json": '{"ttl":300}',
        "reason": "why not",
        "request_id": "req1",
    }


def test_actor_validation_and_labels() -> None:
    assert Actor("admin", "owner").label == "admin:owner"
    assert Actor("system").label == "system"
    assert SYSTEM_ACTOR.label == "system:roxy"
    assert Actor.system("auto:spam_rate").label == "system:auto:spam_rate"
    with pytest.raises(ValueError):
        Actor("hacker", "x")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        Actor("admin", "x" * 65)
    with pytest.raises(ValueError):
        Actor("admin", "line\nbreak")


def test_secret_targets_are_recognized() -> None:
    for target in ("credential", "rotator_url", "admin_user:3:totp_secret", "recovery_codes:owner", "smtp_password"):
        assert is_secret_target(target), target
    for target in ("setting:cache_enabled", "rules_cache:3", None, "", "credential_allowlist:4"):
        assert not is_secret_target(target), target


def test_secret_replace_stores_only_fingerprint_and_masked(dbs: Any) -> None:
    old = TOKEN_PREFIX + "FAKEOLDCREDENTIAL" + secrets.token_hex(40).upper()
    new = TOKEN_PREFIX + "FAKENEWCREDENTIAL" + secrets.token_hex(40).upper()
    dbs.control.write_sync(
        lambda conn: audit.record(
            conn,
            Actor("admin", "owner"),
            "credential.replace",
            "credential",
            secret_summary(old, KEY, credential=True),
            secret_summary(new, KEY, credential=True),
            "rotated by Roblox",
            None,
        )
    )
    row = dbs.control.read_sync(lambda conn: conn.execute("SELECT before_json, after_json FROM audit_log").fetchone())
    before, after = json.loads(row[0]), json.loads(row[1])
    assert set(before) == set(after) == {"fingerprint", "masked"}
    assert after["masked"] == "…" + new[-6:]
    assert before["fingerprint"] != after["fingerprint"]
    text = _all_text(dbs)
    assert old[-40:] not in text
    assert new[-40:] not in text


def test_secret_target_refuses_raw_values_before_writing(dbs: Any) -> None:
    raw = "fake-smtp-" + secrets.token_hex(10)
    for before, after in ((None, raw), (raw, None), ({"masked": "x"}, None), ({"fingerprint": "f", "masked": 3}, None)):
        with pytest.raises(AuditSecretError):
            dbs.control.write_sync(
                lambda conn, b=before, a=after: audit.record(
                    conn, SYSTEM_ACTOR, "smtp.replace", "smtp_password", b, a, None, None
                )
            )
    assert dbs.control.read_sync(lambda conn: conn.execute("SELECT count(*) FROM audit_log").fetchone()[0]) == 0
    assert raw not in _all_text(dbs)


def test_forced_secret_and_extra_keys_dropped(dbs: Any) -> None:
    summary = {"fingerprint": "abcd", "masked": "…tail", "value": "leak"}
    dbs.control.write_sync(
        lambda conn: audit.record(conn, SYSTEM_ACTOR, "x.change", "thing", None, summary, None, None, secret=True)
    )
    after = dbs.control.read_sync(lambda conn: conn.execute("SELECT after_json FROM audit_log").fetchone()[0])
    assert json.loads(after) == {"fingerprint": "abcd", "masked": "…tail"}


def test_secret_summary_for_urls() -> None:
    summary = secret_summary("http://fakeuser:fakepass@127.0.0.1:9", KEY, url=True)
    assert summary is not None
    assert summary["masked"] == "http://127.0.0.1:9"
    assert len(summary["fingerprint"]) == 16
    assert secret_summary(None, KEY) is None


def test_scrub_masks_secret_keys_and_registered_values(registered_secret: str) -> None:
    value = {
        "password": "hunter2",
        "nested": {"api_token": "abc", "note": f"pasted {registered_secret} by mistake"},
        "list": [{"session_id": "s"}, "plain"],
        "cookie_line": f"Cookie: .ROBLOSECURITY={TOKEN_PREFIX}FAKE",
        "raw": b"\x00\x01",
        "n": 5,
    }
    cleaned = scrub(value)
    assert cleaned["password"] == MASK
    assert cleaned["nested"]["api_token"] == MASK
    assert registered_secret not in cleaned["nested"]["note"]
    assert cleaned["list"][0]["session_id"] == MASK
    assert TOKEN_PREFIX not in cleaned["cookie_line"]
    assert cleaned["raw"] == "<2 bytes>"
    assert cleaned["n"] == 5


def test_non_secret_values_are_scrubbed_when_written(dbs: Any, registered_secret: str) -> None:
    dbs.control.write_sync(
        lambda conn: audit.record(
            conn,
            SYSTEM_ACTOR,
            "rule.update",
            "rules_header:1",
            {"needle": "x"},
            {"needle": registered_secret, "password": "p"},
            f"reason mentions {registered_secret}",
            None,
        )
    )
    assert registered_secret not in _all_text(dbs)


def test_large_values_are_bounded(dbs: Any) -> None:
    big = {"items": ["x" * 100] * (MAX_AUDIT_JSON_BYTES // 50)}
    dbs.control.write_sync(lambda conn: audit.record(conn, SYSTEM_ACTOR, "bulk.import", "bulk", None, big, None, None))
    after = dbs.control.read_sync(lambda conn: conn.execute("SELECT after_json FROM audit_log").fetchone()[0])
    assert len(after.encode()) < 4096
    assert json.loads(after)["truncated"] is True


def test_bad_action_or_target_is_refused(dbs: Any) -> None:
    with pytest.raises(ValueError):
        dbs.control.write_sync(
            lambda conn: audit.record(conn, SYSTEM_ACTOR, "Bad Action!", None, None, None, None, None)
        )
    with pytest.raises(ValueError):
        dbs.control.write_sync(lambda conn: audit.record(conn, SYSTEM_ACTOR, "ok", "t" * 300, None, None, None, None))


def test_audit_log_is_append_only(dbs: Any) -> None:
    dbs.control.write_sync(lambda conn: audit.record(conn, SYSTEM_ACTOR, "x.y", "t", None, None, None, None))
    with pytest.raises(sqlite3.DatabaseError):
        dbs.control.write_sync(lambda conn: conn.execute("UPDATE audit_log SET reason = 'edited'"))
    with pytest.raises(sqlite3.DatabaseError):
        dbs.control.write_sync(lambda conn: conn.execute("DELETE FROM audit_log"))


def test_secret_summaries_show_no_part_of_other_secrets() -> None:
    """Security review L7: only the Roblox credential keeps its v1 tail label; URLs keep scheme and host."""
    password = "correct horse battery staple"
    totp = base64.b32encode(secrets.token_bytes(10)).decode()
    for value in (password, totp):
        summary = secret_summary(value, KEY)
        assert summary is not None
        assert summary["masked"] == "[redacted]"
        assert value[-4:] not in summary["masked"]
    hook = "https://hooks.example.invalid/services/T000/B000/FAKEsecretPATHtoken"
    summary = secret_summary(hook, KEY, url=True)
    assert summary is not None
    assert summary["masked"] == "https://hooks.example.invalid"
    assert secret_summary("http://[::1]:8080/x/secret", KEY, url=True)["masked"] == "http://[::1]:8080"  # type: ignore[index]
    assert secret_summary("not a url", KEY, url=True)["masked"] == "[redacted]"  # type: ignore[index]
