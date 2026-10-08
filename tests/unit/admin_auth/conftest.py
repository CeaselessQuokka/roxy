"""Fixtures for the admin auth unit tests: a running app with the auth routes, a fast hasher and recorded mail.

`harness` starts `create_app(env, clock=fake_clock)` with its lifespan (temp databases, fake credentials from the
root conftest), includes the auth router, swaps in a cheap argon2 hasher and a notifier whose mail transport only
records messages. See `roxy/admin/auth/testing.py` for the helpers (`login`, `post`, `next_code`, ...).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from roxy.admin.auth.testing import AuthHarness, auth_harness
from roxy.core.clock import FakeClock


@pytest.fixture
async def harness(env: Any, fake_clock: FakeClock, credentials_dir: Path) -> AsyncIterator[AuthHarness]:
    async with auth_harness(env, clock=fake_clock, credentials_dir=credentials_dir) as running:
        yield running
