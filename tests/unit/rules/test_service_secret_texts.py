"""Rule texts holding a secret Roxy keeps are refused when written, never dropped when stored rows reload (review
finding constraints-1: a rule message reaches every refused caller; `config/secret_text.py`)."""

from __future__ import annotations

import time
from collections.abc import Iterator
from typing import Any

import pytest

from roxy.config.audit import Actor
from roxy.config.secret_text import PASTE_REFUSED_MESSAGE
from roxy.core.clock import FakeClock
from roxy.core.redact import CREDENTIAL_SECRET_NAME, TOKEN_PREFIX, SecretRegistry
from roxy.rules.service import RulesService, RuleValidationError
from roxy.rules.store import build_rules_snapshot

ADMIN = Actor("admin", "owner", "203.0.113.9")
SECRET = "FAKETESTCREDENTIAL" + "0A1B2C3D4E5F6789" * 10
PIECE = SECRET[-40:]


@pytest.fixture(autouse=True)
def registered() -> Iterator[None]:
    SecretRegistry.clear()
    SecretRegistry.register(CREDENTIAL_SECRET_NAME, TOKEN_PREFIX + SECRET)
    yield
    SecretRegistry.clear()


@pytest.fixture
def service(dbs: Any, fake_clock: FakeClock) -> RulesService:
    return RulesService(dbs.control, clock=fake_clock)


async def test_a_rule_message_holding_the_credential_is_refused(service: RulesService) -> None:
    with pytest.raises(RuleValidationError) as caught:
        await service.create("rules_endpoint_block", {"pattern": "a.roblox.com", "message": "Blocked " + PIECE}, ADMIN)
    assert caught.value.errors == [{"field": "message", "message": PASTE_REFUSED_MESSAGE}]
    assert PIECE[-24:] not in str(caught.value)


async def test_a_ladder_rung_holding_the_credential_is_refused(service: RulesService) -> None:
    with pytest.raises(RuleValidationError) as caught:
        await service.replace_throttle_tiers([{"multiplier": 1, "message": "Slow down " + PIECE}], ADMIN, "paste")
    assert caught.value.errors == [{"field": "tiers.1.message", "message": f"Rung 1: {PASTE_REFUSED_MESSAGE}"}]


def test_a_stored_rule_is_never_dropped_for_its_text(dbs: Any) -> None:
    """A block written before the registry knew the value still blocks after a reload."""
    dbs.control.write_sync(
        lambda conn: conn.execute(
            "INSERT INTO rules_endpoint_block (pattern, type, message, created_at, created_by) VALUES (?, ?, ?, ?, ?)",
            ("a.roblox.com", "glob", "Blocked " + PIECE, 1, "admin:owner"),
        )
    )
    snapshot = dbs.control.read_sync(lambda conn: build_rules_snapshot(conn, time.time()))
    assert [row.pattern for row in snapshot.endpoint_blocks] == ["a.roblox.com"]
