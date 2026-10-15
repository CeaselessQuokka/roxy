"""Fixtures for the deploy tests (tests/deploy): the deploy.sh sandbox and the script loader.

What this is
    Two fixtures: `sandbox`, a fresh `DeploySandbox` (a fake server with stub commands and the deploy scripts in
    /opt/roxy), and `load_tool`, which imports a deploy/tools script (the root wrappers have no .py name).

Why it exists
    pytest finds fixtures in conftest.py; the helpers themselves live in `deploy_sandbox.py`, a plain module the test
    files import by name, because test directories here are not packages (no __init__.py), so `from conftest
    import ...` would be ambiguous across the suite.

How it works
    Each fixture builds its objects under pytest's per-test temporary directory; nothing outside it is touched.

What to read next
    `tests/deploy/deploy_sandbox.py`, then `tests/deploy/test_deploy_sh.py`.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

import pytest
from deploy_sandbox import DEPLOY, DeploySandbox, load_script


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Everything under tests/deploy needs Linux (bash, flock, POSIX modes)."""
    if sys.platform != "win32":
        return
    skip = pytest.mark.skip(reason="the deploy runs on Linux")
    for item in items:
        if "tests/deploy" in str(item.fspath).replace("\\", "/"):
            item.add_marker(skip)


@pytest.fixture
def sandbox(tmp_path: Path) -> DeploySandbox:
    """A fake server with the repository's deploy scripts installed in /opt/roxy."""
    box = DeploySandbox(tmp_path)
    box.install_deploy_script()
    return box


@pytest.fixture
def load_tool() -> Callable[[str], ModuleType]:
    """Load a deploy/tools script as a module: `load_tool("roxy-nginx-apply")`."""

    def load(name: str) -> ModuleType:
        return load_script(DEPLOY / "tools" / name)

    return load
