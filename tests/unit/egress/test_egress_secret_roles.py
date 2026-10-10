"""Secret registration by role: a credential or gateway URL that can be used again stays redacted (finding W2H-1).

What this is
    Unit tests for how `CredentialManager` and `RotatorPool` register their values with `SecretRegistry`: the
    bootstrap value, the value in use, and values offered from the dashboard each have registry names of their own
    (`credential.BOOTSTRAP_SECRET_NAME`, `IN_USE_SECRET_NAME`, `CREDENTIAL_SECRET_NAME`;
    `rotator.BOOTSTRAP_SECRET_NAMES`, `IN_USE_SECRET_NAMES`, `OFFERED_SECRET_NAMES`).

Why it exists
    `SecretRegistry` keeps 3 values per name, newest first, and every redaction point (the log filter, audit reasons,
    outcome records, Live rows, captures, events, the LLM export) knows only registered values. Before the fix the
    bootstrap value shared its name with every value pasted later, so three pastes pushed it out, and going back to it
    (`delete_ui_value`, `revert_to_bootstrap`) left the secret in use unredacted: the audit reason of that very action
    was stored in clear. The rule pinned here: any value that is in use, or can become the one in use again, stays
    registered while it can be used, on every path (replace N times, refused pastes, revert, restart).

How it works
    Real (temporary) control.db and hot.db; `SecretRegistry` is cleared before and after each test by the package
    conftest, and cleared again in the middle of a test to stand in for a worker restart (it is process wide). A
    value is "known" when `redact_text` turns it into `[redacted]`; the credential is checked by its secret part
    only (what follows the public warning), so no shape rule can find it and only the registry can. A failing
    control.db write is a monkeypatched `Database.write` raising `SharedStateUnavailable` (C7).

What to read next
    `src/roxy/egress/credential.py` (`start`, `_use`, `replace`, `delete_ui_value`), `src/roxy/egress/rotator.py`
    (`start`, `_set_url`, `replace_url`, `revert_to_bootstrap`), `src/roxy/core/redact.py` (`SecretRegistry`).
"""

from __future__ import annotations

import secrets
from typing import Any

import pytest

from roxy.config.audit import Actor
from roxy.core.clock import SYSTEM_CLOCK
from roxy.core.redact import CREDENTIAL_SECRET_NAME, TOKEN_PREFIX, SecretRegistry, redact_text
from roxy.egress.credential import BOOTSTRAP_SECRET_NAME, IN_USE_SECRET_NAME, CredentialManager
from roxy.egress.crypto import load_encryption_key
from roxy.egress.events import EventSink
from roxy.egress.rotator import (
    BOOTSTRAP_SECRET_NAMES,
    IN_USE_SECRET_NAMES,
    OFFERED_SECRET_NAMES,
    RotatorPool,
    parse_proxy_url,
)
from roxy.storage.db import SharedStateUnavailable

ADMIN = Actor("admin", "owner", "127.0.0.1")
REPLACES = 5  # more than the 3 values the registry keeps per name


def credential_manager(env: Any, dbs: Any, settings: Any) -> CredentialManager:
    return CredentialManager(
        credentials_dir=env.credentials_dir,
        dbs=dbs,
        settings=settings,
        clock=SYSTEM_CLOCK,
        worker_id="w1",
        encryption_key=load_encryption_key(env.credentials_dir),
        events=EventSink(lambda: None, lambda: None),
    )


def rotator_pool(env: Any, dbs: Any, settings: Any) -> RotatorPool:
    class Client:
        async def aclose(self) -> None:
            return None

    return RotatorPool(
        credentials_dir=env.credentials_dir,
        dbs=dbs,
        settings=settings,
        clock=SYSTEM_CLOCK,
        echo_url="http://127.0.0.1:9/ip",
        encryption_key=load_encryption_key(env.credentials_dir),
        client_factory=lambda url, session_id, keepalive: Client(),
        events=EventSink(lambda: None, lambda: None),
    )


def pasted_value(tag: str) -> str:
    return TOKEN_PREFIX + f"PASTED{tag}" + secrets.token_hex(64).upper()


def secret_part(value: str) -> str:
    """What follows the public warning: only the registry can find it (no shape rule matches a bare hex run)."""
    return value.removeprefix(TOKEN_PREFIX)


def known(text: str) -> bool:
    """True when `redact_text` hides `text` completely (the registry knows it)."""
    return redact_text(f"x {text} y") == "x [redacted] y"


def password_of(url: str) -> str:
    return parse_proxy_url(url).password


def gateway_url(tag: str) -> str:
    return f"http://user{tag}:pw{tag}{secrets.token_hex(10)}@127.0.0.1:9"


def audit_reasons(dbs: Any, action: str) -> list[str]:
    return dbs.control.read_sync(
        lambda conn: [
            str(row[0] or "")
            for row in conn.execute("SELECT reason FROM audit_log WHERE action = ? ORDER BY id", (action,)).fetchall()
        ]
    )


def failing_control_writes(dbs: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Every control.db write fails as a locked database does after its budget (C7)."""

    async def refuse(*args: Any, **kwargs: Any) -> Any:
        raise SharedStateUnavailable("control", "database is locked")

    monkeypatch.setattr(dbs.control, "write", refuse)


# --- the credential -------------------------------------------------------------------------------------------------


async def test_the_bootstrap_credential_is_registered_under_its_own_name(
    env: Any, dbs: Any, settings: Any, secret: str
) -> None:
    manager = credential_manager(env, dbs, settings)
    await manager.start()
    assert {BOOTSTRAP_SECRET_NAME, IN_USE_SECRET_NAME} <= set(SecretRegistry.names())
    assert manager.status().source == "bootstrap"
    assert known(secret_part(secret))


async def test_replacing_many_times_then_deleting_the_ui_value_keeps_the_bootstrap_redacted(
    env: Any, dbs: Any, settings: Any, secret: str
) -> None:
    """Replace N times (every value in use stays known while it is in use), then go back to the bootstrap file with a
    reason that repeats its secret part: the reason is stored redacted and the value in use is still known."""
    manager = credential_manager(env, dbs, settings)
    await manager.start()
    for attempt in range(REPLACES):
        value = pasted_value(str(attempt))
        await manager.replace(value, ADMIN, reason=f"attempt {attempt} {secret_part(value)}")
        assert manager.status().source == "ui"
        assert known(secret_part(value)), attempt  # the value in use
        assert known(secret_part(secret)), attempt  # the superseded bootstrap value can come back
    await manager.delete_ui_value(ADMIN, reason=f"back to the file {secret_part(secret)}")
    assert manager.status().source == "bootstrap"
    assert known(secret_part(secret))
    reasons = audit_reasons(dbs, "credential.delete_ui_value")
    assert len(reasons) == 1
    assert secret_part(secret)[:24].lower() not in reasons[0].lower()
    assert "[redacted]" in reasons[0]
    for reason in audit_reasons(dbs, "credential.replace"):
        assert "PASTED" not in reason  # each replace reason repeated its own value, registered before the write


async def test_refused_pastes_never_push_the_value_in_use_out(
    env: Any, dbs: Any, settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A UI value is in use; then several pastes are registered but never stored (control.db is locked). The value
    in use must stay known: it is registered under the in use name, which offered values never touch."""
    manager = credential_manager(env, dbs, settings)
    await manager.start()
    in_use = pasted_value("INUSE")
    await manager.replace(in_use, ADMIN, reason="the real one")
    with monkeypatch.context() as patch:
        failing_control_writes(dbs, patch)
        for attempt in range(REPLACES):
            with pytest.raises(SharedStateUnavailable):
                await manager.replace(pasted_value(f"REFUSED{attempt}"), ADMIN, reason="refused")
    assert manager.status().source == "ui"
    assert manager.status().fingerprint == manager.fingerprint_of(in_use)
    assert known(secret_part(in_use))


async def test_a_restart_registers_the_bootstrap_and_the_ui_value_in_use(
    env: Any, dbs: Any, settings: Any, secret: str
) -> None:
    """A worker that starts while a UI value is stored knows both values: the UI value (in use) and the superseded
    bootstrap value (it can come back through `delete_ui_value`); deleting then keeps the reason redacted."""
    first = credential_manager(env, dbs, settings)
    await first.start()
    ui_value = pasted_value("STORED")
    await first.replace(ui_value, ADMIN, reason="stored before the restart")
    SecretRegistry.clear()  # a new process: nothing registered yet
    assert not known(secret_part(ui_value))
    restarted = credential_manager(env, dbs, settings)
    await restarted.start()
    assert restarted.status().source == "ui"
    assert known(secret_part(ui_value))
    assert known(secret_part(secret))
    await restarted.delete_ui_value(ADMIN, reason=f"back to {secret_part(secret)}")
    assert restarted.status().source == "bootstrap"
    reasons = audit_reasons(dbs, "credential.delete_ui_value")
    assert len(reasons) == 1
    assert secret_part(secret)[:24].lower() not in reasons[0].lower()
    SecretRegistry.clear()  # and a restart after the delete: the bootstrap value is in use and known at once
    again = credential_manager(env, dbs, settings)
    await again.start()
    assert again.status().source == "bootstrap"
    assert known(secret_part(secret))


async def test_offered_values_keep_their_own_name(env: Any, dbs: Any, settings: Any, secret: str) -> None:
    """The three roles are separate names, so the registry's per name bound applies to each role on its own."""
    manager = credential_manager(env, dbs, settings)
    await manager.start()
    await manager.replace(pasted_value("ROLE"), ADMIN, reason="role check")
    assert {CREDENTIAL_SECRET_NAME, BOOTSTRAP_SECRET_NAME, IN_USE_SECRET_NAME} <= set(SecretRegistry.names())


# --- the rotator gateway URL ----------------------------------------------------------------------------------------


async def test_the_bootstrap_gateway_is_registered_under_its_own_names(
    env: Any, dbs: Any, settings: Any, fake_secrets: dict[str, str]
) -> None:
    pool = rotator_pool(env, dbs, settings)
    await pool.start()
    assert set(BOOTSTRAP_SECRET_NAMES) | set(IN_USE_SECRET_NAMES) <= set(SecretRegistry.names())
    assert pool.url_source() == "bootstrap"
    assert known(password_of(fake_secrets["rotator_url"]))


async def test_trying_many_gateways_then_reverting_keeps_the_bootstrap_password_redacted(
    env: Any, dbs: Any, settings: Any, fake_secrets: dict[str, str]
) -> None:
    pool = rotator_pool(env, dbs, settings)
    await pool.start()
    bootstrap_password = password_of(fake_secrets["rotator_url"])
    for attempt in range(REPLACES):
        url = gateway_url(str(attempt))
        await pool.replace_url(url, ADMIN, reason=f"attempt {attempt} {password_of(url)}")
        assert pool.url_source() == "ui"
        assert known(password_of(url)), attempt  # the password in use
        assert known(bootstrap_password), attempt  # the bootstrap password can come back
    await pool.revert_to_bootstrap(ADMIN, reason=f"back to the file, password {bootstrap_password}")
    assert pool.url_source() == "bootstrap"
    assert known(bootstrap_password)
    reasons = audit_reasons(dbs, "rotator.revert_to_bootstrap")
    assert len(reasons) == 1
    assert bootstrap_password not in reasons[0]
    assert all("pw" not in reason for reason in audit_reasons(dbs, "rotator.replace_url"))


async def test_refused_gateways_never_push_the_url_in_use_out(
    env: Any, dbs: Any, settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    pool = rotator_pool(env, dbs, settings)
    await pool.start()
    in_use = gateway_url("inuse")
    await pool.replace_url(in_use, ADMIN, reason="the real one")
    with monkeypatch.context() as patch:
        failing_control_writes(dbs, patch)
        for attempt in range(REPLACES):
            with pytest.raises(SharedStateUnavailable):
                await pool.replace_url(gateway_url(f"refused{attempt}"), ADMIN, reason="refused")
    assert pool.url_source() == "ui"
    assert known(password_of(in_use))
    assert known(in_use)


async def test_a_restart_registers_the_bootstrap_gateway_and_the_ui_url_in_use(
    env: Any, dbs: Any, settings: Any, fake_secrets: dict[str, str]
) -> None:
    first = rotator_pool(env, dbs, settings)
    await first.start()
    ui_url = gateway_url("stored")
    await first.replace_url(ui_url, ADMIN, reason="stored before the restart")
    SecretRegistry.clear()  # a new process
    restarted = rotator_pool(env, dbs, settings)
    await restarted.start()
    assert restarted.url_source() == "ui"
    bootstrap_password = password_of(fake_secrets["rotator_url"])
    assert known(password_of(ui_url))
    assert known(bootstrap_password)
    await restarted.revert_to_bootstrap(ADMIN, reason=f"password {bootstrap_password}")
    assert restarted.url_source() == "bootstrap"
    reasons = audit_reasons(dbs, "rotator.revert_to_bootstrap")
    assert len(reasons) == 1
    assert bootstrap_password not in reasons[0]


def test_role_names_are_distinct() -> None:
    names = [
        CREDENTIAL_SECRET_NAME,
        BOOTSTRAP_SECRET_NAME,
        IN_USE_SECRET_NAME,
        *OFFERED_SECRET_NAMES,
        *BOOTSTRAP_SECRET_NAMES,
        *IN_USE_SECRET_NAMES,
    ]
    assert len(set(names)) == len(names)
