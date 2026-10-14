"""Pause, schedule and throttle-all reasons holding a secret Roxy keeps are refused (review finding constraints-1):
the reason is every caller's 503 or 429 body."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from roxy.abuse.messages import checked_state_reason
from roxy.config.secret_text import PASTE_REFUSED_MESSAGE
from roxy.core.redact import CREDENTIAL_SECRET_NAME, TOKEN_PREFIX, SecretRegistry

SECRET = "FAKETESTCREDENTIAL" + "0A1B2C3D4E5F6789" * 10


@pytest.fixture(autouse=True)
def registered() -> Iterator[None]:
    SecretRegistry.clear()
    SecretRegistry.register(CREDENTIAL_SECRET_NAME, TOKEN_PREFIX + SECRET)
    yield
    SecretRegistry.clear()


@pytest.mark.parametrize("pasted", [SECRET[-40:], TOKEN_PREFIX + "anything", ".ROBLOSECURITY=" + "9F" * 20])
def test_a_reason_holding_a_secret_is_refused(pasted: str) -> None:
    with pytest.raises(ValueError, match="The reason") as caught:
        checked_state_reason("Maintenance " + pasted)
    assert PASTE_REFUSED_MESSAGE in str(caught.value)
    assert SECRET[-24:] not in str(caught.value)


def test_an_ordinary_reason_is_kept() -> None:
    assert checked_state_reason("  Maintenance until 18:00 UTC  ") == "Maintenance until 18:00 UTC"
