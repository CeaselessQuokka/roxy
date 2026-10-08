"""The credential manager: one slot, sources and precedence, fleet-wide state, probes and admin actions.

What this is
    Unit tests for `roxy.egress.credential.CredentialManager` over real (temporary) control.db and hot.db.

Why it exists
    Plan C1 and C7, parity rows 25 to 27: exactly one credential; the UI value wins and supersedes the bootstrap
    value; replacement reaches every worker at once; a 429 opens a fleet-wide cooldown and is never "expired";
    exactly one probe runs at a time; an account switch needs a confirmation; shared state that cannot be read
    means the credential is not used; a rotated cookie from Roblox is never stored.

How it works
    Two managers over the same databases stand in for two workers. Probes use a fake fetch that returns a chosen
    `EgressResponse`; alerts go to a recording notifier. No network.

What to read next
    `src/roxy/egress/credential.py`.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

import httpx
import pytest

from roxy.config.audit import Actor
from roxy.core.clock import SYSTEM_CLOCK, FakeClock
from roxy.core.reasons import Egress
from roxy.core.redact import TOKEN_PREFIX
from roxy.egress.credential import (
    CredentialManager,
    CredentialStateError,
    CredentialValueError,
    retry_after_seconds,
)
from roxy.egress.crypto import load_encryption_key
from roxy.egress.errors import CredentialUnavailable, TargetNotAllowed
from roxy.egress.events import EventSink
from roxy.egress.models import EgressResponse
from roxy.storage.db import SharedStateUnavailable

ADMIN = Actor("admin", "owner", "127.0.0.1")
NEW_VALUE = TOKEN_PREFIX + "REPLACEMENTVALUE" + "AB12" * 60


class Notifier:
    def __init__(self) -> None:
        self.alerts: list[Any] = []

    def send(self, alert: Any) -> None:
        self.alerts.append(alert)

    def subjects(self) -> list[str]:
        return [alert.subject for alert in self.alerts]


def manager(
    env: Any,
    dbs: Any,
    settings: Any,
    notifier: Notifier | None = None,
    *,
    worker: str = "w1",
    key_dir: Path | None = None,
    loopback: bool = False,
    clock: Any = SYSTEM_CLOCK,
) -> CredentialManager:
    events = EventSink(lambda: notifier, lambda: None)
    return CredentialManager(
        credentials_dir=env.credentials_dir,
        dbs=dbs,
        settings=settings,
        clock=clock,
        worker_id=worker,
        encryption_key=load_encryption_key(key_dir or env.credentials_dir),
        events=events,
        allow_loopback_target=loopback,
    )


def response(status: int, body: bytes = b"", headers: dict[str, str] | None = None) -> EgressResponse:
    return EgressResponse(
        status=status,
        headers=httpx.Headers(headers or {}),
        body=body,
        elapsed_ms=1.0,
        bytes_out=0,
        bytes_in=0,
        egress=Egress.CREDENTIAL,
        session_id=None,
        http_version="HTTP/1.1",
    )


def fetch_returning(*answers: EgressResponse) -> Any:
    queue = list(answers)
    calls: list[str] = []

    async def fetch(url: str) -> EgressResponse:
        calls.append(url)
        return queue.pop(0)

    fetch.calls = calls  # type: ignore[attr-defined]
    return fetch


def audit_rows(dbs: Any) -> list[dict[str, Any]]:
    return dbs.control.read_sync(
        lambda conn: [dict(row) for row in conn.execute("SELECT * FROM audit_log ORDER BY id").fetchall()]
    )


def version(dbs: Any) -> int:
    return dbs.control.read_sync(
        lambda conn: int(
            json.loads(
                conn.execute("SELECT value_json FROM service_state WHERE key = 'credential_version'").fetchone()[0]
            )
        )
    )


async def make_active(m: CredentialManager, account: int = 123) -> None:
    result = await m.probe("admin_check", fetch=fetch_returning(response(200, json.dumps({"id": account}).encode())))
    assert result.outcome == "ok", result


async def test_bootstrap_is_loaded_once_and_described(env: Any, dbs: Any, settings: Any, secret: str) -> None:
    m = manager(env, dbs, settings)
    await m.start()
    status = m.status()
    assert status.present
    assert status.source == "bootstrap"
    assert status.status == "unknown"
    assert status.masked == "…" + secret[-6:]
    assert status.fingerprint == m.fingerprint_of(secret)
    assert not m.available()
    assert m.probe_allowed()
    rows = audit_rows(dbs)
    assert [row["action"] for row in rows] == ["credential.bootstrap_loaded"]
    assert secret[-40:] not in json.dumps(rows)
    # A second worker starting on the same file changes nothing.
    await manager(env, dbs, settings, worker="w2").start()
    assert len(audit_rows(dbs)) == 1


async def test_multiline_bootstrap_keeps_only_the_first_line(
    env: Any, dbs: Any, settings: Any, caplog: pytest.LogCaptureFixture
) -> None:
    first = TOKEN_PREFIX + "FIRSTVALUE" + "CD34" * 50
    second = TOKEN_PREFIX + "SECONDVALUE" + "EF56" * 50
    (env.credentials_dir / "roblox_credential").write_text(f"\n{first}\n{second}\n", encoding="utf-8")
    m = manager(env, dbs, settings)
    with caplog.at_level(logging.WARNING, logger="roxy.egress.credential"):
        await m.start()
    assert m.status().fingerprint == m.fingerprint_of(first)
    assert any(record.msg == "credential_bootstrap_extra_lines_discarded" for record in caplog.records)
    assert m.leak_matcher().matches(first.encode())
    assert not m.leak_matcher().matches(second.encode())


async def test_replace_is_encrypted_audited_and_reaches_other_workers(
    env: Any, dbs: Any, settings: Any, secret: str
) -> None:
    worker_a, worker_b = manager(env, dbs, settings), manager(env, dbs, settings, worker="w2")
    await worker_a.start()
    await worker_b.start()
    before = version(dbs)
    status = await worker_a.replace(NEW_VALUE, ADMIN, reason="rotated by hand")
    assert status.source == "ui"
    assert status.fingerprint == worker_a.fingerprint_of(NEW_VALUE)
    assert status.status == "unknown"
    assert status.bootstrap_superseded
    assert version(dbs) == before + 1
    stored = dbs.control.read_sync(
        lambda conn: bytes(conn.execute("SELECT ciphertext FROM credential_store").fetchone()[0])
    )
    assert NEW_VALUE.encode()[-30:] not in stored
    replace_row = audit_rows(dbs)[-1]
    assert replace_row["action"] == "credential.replace"
    assert replace_row["actor"] == "admin:owner"
    assert set(json.loads(replace_row["after_json"])) == {"fingerprint", "masked"}
    assert NEW_VALUE[-30:] not in json.dumps(replace_row)
    assert secret[-30:] not in json.dumps(replace_row)
    await worker_b.refresh()
    assert worker_b.status().fingerprint == worker_a.fingerprint_of(NEW_VALUE)
    assert worker_b.leak_matcher().matches(NEW_VALUE.encode())
    assert worker_b.leak_matcher().matches(secret.encode())  # the old value stays watched for leaks


async def test_replace_accepts_one_string_only(env: Any, dbs: Any, settings: Any) -> None:
    m = manager(env, dbs, settings)
    await m.start()
    for bad in ([NEW_VALUE], (NEW_VALUE,), {NEW_VALUE}):
        with pytest.raises(TypeError):
            await m.replace(bad, ADMIN)  # type: ignore[arg-type]
    for bad_text in (NEW_VALUE + "\n" + NEW_VALUE, "short", NEW_VALUE + " x", NEW_VALUE + ";x"):
        with pytest.raises(CredentialValueError):
            await m.replace(bad_text, ADMIN)


async def test_replace_needs_the_encryption_key(env: Any, dbs: Any, settings: Any) -> None:
    (env.credentials_dir / "credential_encryption_key").unlink()
    m = manager(env, dbs, settings)
    await m.start()
    with pytest.raises(CredentialStateError):
        await m.replace(NEW_VALUE, ADMIN)


async def test_delete_ui_value_goes_back_to_the_bootstrap_value(env: Any, dbs: Any, settings: Any, secret: str) -> None:
    m = manager(env, dbs, settings)
    await m.start()
    await m.replace(NEW_VALUE, ADMIN)
    with pytest.raises(CredentialStateError):
        await manager(env, dbs, settings, worker="w9").confirm_account(ADMIN)
    status = await m.delete_ui_value(ADMIN, reason="back to the file")
    assert status.source == "bootstrap"
    assert status.fingerprint == m.fingerprint_of(secret)
    assert not status.bootstrap_superseded
    assert status.status == "unknown"
    with pytest.raises(CredentialStateError):
        await m.delete_ui_value(ADMIN)


async def test_cooldown_is_fleet_wide_and_never_shortened(env: Any, dbs: Any, settings: Any) -> None:
    clock = FakeClock(1_760_000_000.0)  # shared by both "workers"; WSL's wall clock may step back (AGENT_BRIEF)
    worker_a = manager(env, dbs, settings, clock=clock)
    worker_b = manager(env, dbs, settings, worker="w2", clock=clock)
    await worker_a.start()
    await worker_b.start()
    await make_active(worker_a)
    await worker_b.refresh()
    assert worker_b.available()
    remaining = await worker_a.set_cooldown(30, "retry_after")
    assert remaining == 30
    await worker_a.set_cooldown(5, "default")
    assert worker_a.cooldown_remaining() == 30
    await worker_b.refresh()
    assert worker_b.status().status == "cooling_down"
    assert not worker_b.available()
    request = httpx.Request("GET", "https://users.roblox.com/v1/users/authenticated")
    with pytest.raises(CredentialUnavailable) as raised:
        await worker_b.authorize(request, logical_url=request.url, probe=True)
    assert raised.value.why == "cooling_down"
    assert raised.value.retry_after_s == 30
    clock.advance(30.5)
    await worker_b.refresh()
    assert worker_b.available()  # the cooldown ended on its own; status was never "expired"
    with pytest.raises(ValueError):
        await worker_a.set_cooldown(10, "made_up")


async def test_authorize_attaches_the_cookie_only_to_listed_https_hosts(
    env: Any, dbs: Any, settings: Any, secret: str
) -> None:
    m = manager(env, dbs, settings)
    await m.start()
    await make_active(m)
    good = httpx.Request("GET", "https://users.roblox.com/v1/users/authenticated")
    await m.authorize(good, logical_url=good.url, probe=False)
    assert good.headers["Cookie"] == f".ROBLOSECURITY={secret}"
    for url in ("http://users.roblox.com/v1/x", "https://unlisted.roblox.com/v1/x", "https://users.roblox.com:8443/"):
        request = httpx.Request("GET", url)
        with pytest.raises(TargetNotAllowed):
            await m.authorize(request, logical_url=request.url, probe=False)
        assert "cookie" not in request.headers
    elsewhere = httpx.Request("GET", "https://evil.example/v1/x")
    with pytest.raises(TargetNotAllowed):
        await m.authorize(elsewhere, logical_url=good.url, probe=False)
    loopback = httpx.Request("GET", "http://127.0.0.1:9/v1/users/authenticated")
    with pytest.raises(TargetNotAllowed):  # only with the development override
        await m.authorize(loopback, logical_url=good.url, probe=False)
    test_mode = manager(env, dbs, settings, worker="w2", loopback=True)
    await test_mode.start()
    await test_mode.authorize(loopback, logical_url=good.url, probe=False)
    assert loopback.headers["Cookie"].endswith(secret[-10:])


async def test_unknown_status_allows_probes_but_not_traffic(env: Any, dbs: Any, settings: Any) -> None:
    m = manager(env, dbs, settings)
    await m.start()
    request = httpx.Request("GET", "https://users.roblox.com/v1/users/authenticated")
    with pytest.raises(CredentialUnavailable) as raised:
        await m.authorize(request, logical_url=request.url, probe=False)
    assert raised.value.why == "not_confirmed"
    await m.authorize(request, logical_url=request.url, probe=True)
    settings.set("credential_enabled", 0)
    with pytest.raises(CredentialUnavailable):
        await m.authorize(request, logical_url=request.url, probe=True)
    assert (await m.probe("admin_check", fetch=fetch_returning())).outcome == "disabled"


async def test_probe_outcomes(env: Any, dbs: Any, settings: Any) -> None:
    notifier = Notifier()
    m = manager(env, dbs, settings, notifier)
    await m.start()
    ok = await m.probe("admin_check", fetch=fetch_returning(response(200, b'{"id": 123, "name": "x"}')))
    assert ok.ok
    assert ok.account_match
    assert m.status().status == "active"
    first_account = m.status().account_id_fingerprint
    assert first_account is not None

    switched = await m.probe("admin_check", fetch=fetch_returning(response(200, b'{"id": 456}')))
    assert switched.outcome == "account_mismatch"
    assert m.status().status == "rejected"
    assert notifier.subjects()[-1] == "Token Expired"
    confirmed = await m.confirm_account(ADMIN, reason="typed the C1 warning")
    assert confirmed.status == "active"
    assert confirmed.account_id_fingerprint != first_account

    limited = await m.probe("liveness", fetch=fetch_returning(response(429, headers={"Retry-After": "120"})))
    assert limited.outcome == "rate_limited"
    assert limited.retry_after_s == 120
    status = m.status()
    assert status.status == "cooling_down"
    assert status.last_probe_result == {
        "kind": "liveness",
        "result": "rate_limited",
        "status": 429,
    }
    blocked = fetch_returning()
    assert (await m.probe("admin_check", fetch=blocked)).outcome == "cooling_down"
    assert blocked.calls == []


async def test_probe_401_rejects_and_liveness_then_stops(env: Any, dbs: Any, settings: Any) -> None:
    notifier = Notifier()
    m = manager(env, dbs, settings, notifier)
    await m.start()
    result = await m.probe("liveness", fetch=fetch_returning(response(401)))
    assert result.outcome == "rejected"
    assert m.status().status == "rejected"
    assert "Token Expired" in notifier.subjects()
    skipped = fetch_returning()
    assert (await m.probe("liveness", fetch=skipped)).outcome == "skipped_rejected"
    assert skipped.calls == []
    actions = [row["action"] for row in audit_rows(dbs)]
    assert "credential.status" in actions
    await m.mark_rejected("confirmed by upstream")
    assert m.status().status == "rejected"


async def test_one_probe_at_a_time_fleet_wide(env: Any, dbs: Any, settings: Any) -> None:
    worker_a, worker_b = manager(env, dbs, settings), manager(env, dbs, settings, worker="w2")
    await worker_a.start()
    await worker_b.start()
    gate = asyncio.Event()

    async def slow(url: str) -> EgressResponse:
        await gate.wait()
        return response(200, b'{"id": 1}')

    first = asyncio.create_task(worker_a.probe("admin_check", fetch=slow))
    await asyncio.sleep(0.2)
    second = await worker_b.probe("admin_check", fetch=slow)
    same_worker = await worker_a.probe("admin_check", fetch=slow)
    assert second.outcome == "busy"
    assert same_worker.outcome == "busy"
    gate.set()
    assert (await first).outcome == "ok"
    assert (await worker_b.probe("admin_check", fetch=fetch_returning(response(200, b'{"id": 1}')))).outcome == "ok"


async def test_unreadable_shared_state_means_no_credential(
    env: Any, dbs: Any, settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    m = manager(env, dbs, settings)
    await m.start()
    await make_active(m)

    async def broken(fn: Any) -> Any:
        raise SharedStateUnavailable("hot", "database is locked")

    monkeypatch.setattr(dbs.hot, "read", broken)
    request = httpx.Request("GET", "https://users.roblox.com/v1/users/authenticated")
    with pytest.raises(CredentialUnavailable) as raised:
        await m.authorize(request, logical_url=request.url, probe=False)
    assert raised.value.why == "degraded"
    assert "cookie" not in request.headers
    assert not m.available()
    assert m.status().status == "unavailable"
    assert (await m.probe("admin_check", fetch=fetch_returning())).outcome == "degraded"


async def test_rotated_cookie_is_never_stored(env: Any, dbs: Any, settings: Any, secret: str) -> None:
    notifier = Notifier()
    m = manager(env, dbs, settings, notifier)
    await m.start()
    before_version = version(dbs)
    rotated = "ROTATEDVALUE" + "9F" * 120
    await m.observe_set_cookie(
        [f".ROBLOSECURITY={rotated}; domain=.roblox.com; path=/; secure; HttpOnly", "other=1"],
        endpoint="users.roblox.com/v1/users/authenticated",
    )
    assert notifier.subjects() == ["Roxy: Roblox sent a new credential cookie"]
    assert m.status().fingerprint == m.fingerprint_of(secret)
    assert version(dbs) == before_version
    assert dbs.control.read_sync(lambda conn: conn.execute("SELECT count(*) FROM credential_store").fetchone()[0]) == 0
    row = audit_rows(dbs)[-1]
    assert row["action"] == "credential.rotation_seen"
    assert rotated[-20:] not in json.dumps(row)
    assert m.leak_matcher().matches(rotated.encode())
    await m.observe_set_cookie([f".ROBLOSECURITY={secret}; path=/"], endpoint="users.roblox.com/x")
    assert len(notifier.alerts) == 1  # the same cookie again is not a rotation


async def test_ui_value_without_key_is_never_replaced_by_the_bootstrap(
    env: Any, dbs: Any, settings: Any, tmp_path: Path
) -> None:
    m = manager(env, dbs, settings)
    await m.start()
    await m.replace(NEW_VALUE, ADMIN)
    empty = tmp_path / "nokey"
    empty.mkdir()
    keyless = manager(env, dbs, settings, worker="w2", key_dir=empty)
    await keyless.start()
    status = keyless.status()
    assert not status.present
    assert status.problem == "encryption_key_missing"
    assert status.status == "unavailable"


async def test_changed_bootstrap_file_keeps_the_account_for_comparison(env: Any, dbs: Any, settings: Any) -> None:
    m = manager(env, dbs, settings)
    await m.start()
    await make_active(m, account=777)
    account = m.status().account_id_fingerprint
    other = TOKEN_PREFIX + "OTHERFILEVALUE" + "77" * 100
    (env.credentials_dir / "roblox_credential").write_text(other, encoding="utf-8")
    restarted = manager(env, dbs, settings, worker="w3")
    await restarted.start()
    status = restarted.status()
    assert status.fingerprint == restarted.fingerprint_of(other)
    assert status.status == "unknown"
    assert status.account_id_fingerprint == account
    assert audit_rows(dbs)[-1]["action"] == "credential.bootstrap_changed"
    mismatch = await restarted.probe("admin_check", fetch=fetch_returning(response(200, b'{"id": 778}')))
    assert mismatch.outcome == "account_mismatch"


def test_retry_after_parsing() -> None:
    assert retry_after_seconds("120", 1000.0) == 120.0
    assert retry_after_seconds("Wed, 21 Oct 2015 07:28:00 GMT", 1445412400.0) == 80.0
    assert retry_after_seconds("garbage", 0.0) is None
    assert retry_after_seconds(None, 0.0) is None
    assert retry_after_seconds("Wed, 21 Oct 2015 07:28:00 GMT", 1445412500.0) == 0.0
