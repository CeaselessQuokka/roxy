"""Fixtures of the insights tests: the fixture harness closes the states it keeps loaded when a module ends.

What this is
    One autouse module fixture: `insights.harness` keeps up to `MAX_LOADED` fixture states loaded (their databases
    open) so the cases and variants of one fixture file share one load; they are closed when the module ends.

Why it exists
    The root conftest's database thread guard (`tests/db_threads.py`, finding G8) fails a module that leaves a
    database open. The harness used to close its states only when the process exited, so their database threads
    outlived every module that loaded them.

How it works
    `harness._close_all()` after the module's last test (module fixtures are torn down before the root guard runs).

What to read next
    `tests/insights/harness.py` (`loaded`, `MAX_LOADED`), `tests/conftest.py` (the guard).
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from insights import harness


@pytest.fixture(autouse=True, scope="module")
def _close_loaded_fixtures() -> Iterator[None]:
    yield
    harness._close_all()
