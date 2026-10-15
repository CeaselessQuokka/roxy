"""Tests for `roxy.config.secret_text` and where the settings layer uses it (review finding constraints-1).

A credential pasted into a setting is refused by the catalog (every writer and every reload), the settings history
keeps a scrubbed reason, and the history read model and the settings export scrub what they show. Ordinary help
texts (the catalog defaults, texts that name the cookie or use words such as "session:") are never refused.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest

from roxy.config import catalog, read_settings
from roxy.config.audit import Actor
from roxy.config.runtime import load_runtime_settings
from roxy.config.secret_text import (
    PASTE_REFUSED_MESSAGE,
    holds_secret,
    scrub_secrets,
    value_holds_secret,
)
from roxy.config.settings_service import SettingsService, SettingsUpdateError
from roxy.core.clock import FakeClock
from roxy.core.redact import CREDENTIAL_SECRET_NAME, TOKEN_PREFIX, SecretRegistry

ADMIN = Actor("admin", "owner", "203.0.113.9")
SECRET_PART = "FAKETESTCREDENTIAL" + "A1B2C3D4E5F60718" * 12
CREDENTIAL = TOKEN_PREFIX + SECRET_PART
PIECE = SECRET_PART[-40:]  # what an owner might paste: 40 characters of the cookie, no warning text
RUN = PIECE[-24:]


@pytest.fixture(autouse=True)
def registered() -> Iterator[None]:
    """The credential registered as the credential manager does at start (substring windows on)."""
    SecretRegistry.clear()
    SecretRegistry.register(CREDENTIAL_SECRET_NAME, CREDENTIAL)
    SecretRegistry.register("smtp_password", "fake-smtp-password-1234")
    yield
    SecretRegistry.clear()


def _string_defaults() -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for key, spec in catalog.CATALOG.items():
        values = spec.default if isinstance(spec.default, list | tuple) else [spec.default]
        found.extend((key, value) for value in values if isinstance(value, str))
    return found


# --------------------------------------------------------------------------------------------- holds_secret


@pytest.mark.parametrize(
    "text",
    [
        "Back soon " + PIECE,
        "Back soon " + RUN,
        "Back soon " + RUN.lower(),  # the windows ignore ASCII case (the credential is hex)
        CREDENTIAL,
        "x " + TOKEN_PREFIX + "anything",  # the public warning text marks a pasted cookie of any account
        "cookie: .ROBLOSECURITY=" + "9F" * 20,
        "Back soon " + "".join(f"%{ord(char):02X}" for char in PIECE),  # every character percent-encoded
        "mail me: fake-smtp-password-1234",  # any registered value, not only the credential
    ],
    ids=["piece", "run", "run_lowercase", "whole", "token_marker", "cookie_assignment", "encoded", "registered"],
)
def test_a_pasted_secret_is_found(text: str) -> None:
    assert holds_secret(text)
    assert value_holds_secret(["ok", text])
    assert value_holds_secret({"note": text})


@pytest.mark.parametrize(
    "text",
    [
        "",
        "Back soon " + RUN[:-1],  # 23 characters of the credential are not a leak (plan 9.15 sets 24)
        "Roxy never forwards a .ROBLOSECURITY=... cookie from a caller.",  # names the cookie, holds no value
        "Your session: 10 minutes; token=refresh in the browser",  # log shapes are not secrets in a help text
        "100% of requests",
    ],
    ids=["empty", "23_chars", "cookie_named", "secret_shaped_words", "percent_sign"],
)
def test_ordinary_text_is_not_a_secret(text: str) -> None:
    assert not holds_secret(text)


def test_no_catalog_default_is_taken_for_a_secret() -> None:
    assert [key for key, value in _string_defaults() if holds_secret(value)] == []


def test_scrub_secrets_changes_only_texts_that_hold_one() -> None:
    plain = ["Service down for maintenance.", "Your session: 10 minutes"]
    assert scrub_secrets(plain) == plain
    assert scrub_secrets(7) == 7
    scrubbed = scrub_secrets({"value": "Back soon " + PIECE, "overridden": True})
    assert RUN not in json.dumps(scrubbed)
    assert scrubbed["value"].startswith("Back soon ")
    assert scrubbed["overridden"] is True


def test_with_nothing_registered_only_the_cookie_shapes_count() -> None:
    SecretRegistry.clear()
    assert not holds_secret("Back soon " + PIECE)
    assert holds_secret(TOKEN_PREFIX + SECRET_PART)


# ------------------------------------------------------------------------------------------------ the catalog


@pytest.mark.parametrize(
    ("key", "raw"),
    [
        ("pause_message_default", "Back soon " + PIECE),
        ("site_bug_bounty_text", "Write to us. " + CREDENTIAL),
        # A list item, refused before the host check (whose message quotes 60 characters of the item).
        ("allowed_roblox_hosts", ["games.roblox.com", PIECE.lower() + ".roblox.com"]),
        ("direct_user_agent", "Mozilla/5.0 " + PIECE),
    ],
)
def test_the_catalog_refuses_a_setting_that_holds_a_secret(key: str, raw: Any) -> None:
    with pytest.raises(catalog.SettingValidationError) as refused:
        catalog.validate_value(key, raw)
    assert refused.value.message == PASTE_REFUSED_MESSAGE
    assert RUN not in str(refused.value)  # the refusal never repeats the value


def test_the_catalog_still_takes_ordinary_text() -> None:
    assert catalog.validate_value("pause_message_default", "Back soon, about 10 minutes") == (
        "Back soon, about 10 minutes"
    )


# ----------------------------------------------------------------------------------------- the settings service


async def test_a_change_holding_a_secret_writes_nothing(dbs: Any, fake_clock: FakeClock) -> None:
    runtime = await load_runtime_settings(dbs, fake_clock)
    service = SettingsService(dbs.control, runtime=runtime, clock=fake_clock)
    with pytest.raises(SettingsUpdateError) as refused:
        await service.update({"pause_message_default": "Back soon " + PIECE}, ADMIN, "pasted in the wrong box")
    assert refused.value.errors == {"pause_message_default": PASTE_REFUSED_MESSAGE}
    stored = dbs.control.read_sync(
        lambda conn: [tuple(row) for row in conn.execute("SELECT * FROM settings_history").fetchall()]
    )
    assert stored == []


async def test_the_history_reason_is_scrubbed_like_the_audit_reason(dbs: Any, fake_clock: FakeClock) -> None:
    runtime = await load_runtime_settings(dbs, fake_clock)
    service = SettingsService(dbs.control, runtime=runtime, clock=fake_clock)
    await service.update({"allowed_requests_per_minute": 20}, ADMIN, "new cookie " + PIECE)
    reasons = dbs.control.read_sync(
        lambda conn: [str(row[0]) for row in conn.execute("SELECT reason FROM settings_history").fetchall()]
    )
    assert len(reasons) == 1
    assert reasons[0].startswith("new cookie ")
    assert RUN not in reasons[0]


def _write_raw(dbs: Any, sql: str, params: tuple[Any, ...]) -> None:
    dbs.control.write_sync(lambda conn: conn.execute(sql, params))


async def test_a_stored_override_holding_a_secret_is_not_served(dbs: Any, fake_clock: FakeClock) -> None:
    """A value written before the registry knew the secret (or before this screening) is dropped at load, like any
    other invalid override: callers get the catalog default, and the export does not carry it."""
    _write_raw(
        dbs,
        "INSERT INTO settings (key, value_json, updated_at, updated_by) VALUES (?, ?, ?, ?)",
        ("pause_message_default", json.dumps("Back soon " + PIECE), 1, "admin:owner"),
    )
    runtime = await load_runtime_settings(dbs, fake_clock)
    assert "pause_message_default" in runtime.snapshot().invalid
    assert RUN not in str(runtime.get("pause_message_default"))
    exported = await SettingsService(dbs.control, runtime=runtime, clock=fake_clock).export_overrides()
    assert RUN not in json.dumps(exported)


def test_the_history_read_model_scrubs_old_rows() -> None:
    row = (
        7,
        "pause_message_default",
        json.dumps("Back soon " + PIECE),
        json.dumps("Back"),
        1,
        "admin:o",
        PIECE,
        "admin",
    )
    shown = read_settings.history_row(row)
    assert RUN not in json.dumps(shown)
    assert shown["old"].startswith("Back soon ")
    assert shown["new"] == "Back"
    plain = read_settings.history_row((8, "allowed_requests_per_minute", "10", "20", 1, "admin:o", "Busy", "admin"))
    assert (plain["old"], plain["new"], plain["reason"]) == (10, 20, "Busy")
