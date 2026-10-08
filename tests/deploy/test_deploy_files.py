"""House rules for the deploy files: teaching headers, comments on every setting, style, modes, shellcheck.

What this is
    Repository-level checks over deploy/**, scripts/smoke_remote.py, scripts/build_static.py and tests/deploy:
    every Python file opens with the four-part teaching docstring (plan P7) and every shell script with the same
    four parts as a comment, every env example line has its reason, nothing has an em or en dash or a British
    spelling (plan C5, scripts/check_style.py), files have Unix line endings, the programs are executable, and
    shellcheck finds nothing in the shell scripts.

Why it exists
    Deploy files are read by the owner at 3 a.m. during an incident; the reason for each line has to be next to it.
    A lost executable bit or a CRLF line ending breaks a deploy in ways that only show on the server.

How it works
    Plain file reads. shellcheck comes from PATH or the no-root unpack location (~/.local/p13tools); the test is
    skipped with the reason when it is absent.

What to read next
    deploy/README.md.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

import pytest
from deploy_sandbox import DEPLOY, REPO, find_tool

pytestmark = [pytest.mark.deploy]

SECTIONS = ("What this is", "Why it exists", "How it works", "What to read next")
PYTHON_FILES = [
    DEPLOY / "gunicorn.conf.py",
    DEPLOY / "prestart.py",
    DEPLOY / "tools" / "alert_on_failure.py",
    DEPLOY / "tools" / "roxy-audit.py",
    DEPLOY / "tools" / "roxy-nginx-apply",
    DEPLOY / "tools" / "roxy-switch-color",
    REPO / "scripts" / "smoke_remote.py",
    REPO / "scripts" / "build_static.py",
    *sorted((REPO / "tests" / "deploy").glob("*.py")),
]
SHELL_FILES = [
    DEPLOY / "deploy.sh",
    DEPLOY / "deploy_rollback.sh",
    DEPLOY / "install-system.sh",
    DEPLOY / "tools" / "backup.sh",
]
EXECUTABLES = [*SHELL_FILES, *(DEPLOY / "tools").iterdir()]


@pytest.mark.parametrize("path", PYTHON_FILES, ids=lambda p: str(p.relative_to(REPO)))
def test_python_files_have_the_teaching_docstring(path: Path) -> None:
    docstring = ast.get_docstring(ast.parse(path.read_text(encoding="utf-8"))) or ""
    assert [s for s in SECTIONS if s not in docstring] == []


@pytest.mark.parametrize("path", SHELL_FILES, ids=lambda p: p.name)
def test_shell_scripts_have_the_teaching_header(path: Path) -> None:
    header = "\n".join(line for line in path.read_text().splitlines()[:60] if line.startswith("#"))
    assert [s for s in SECTIONS if s not in header] == []
    assert path.read_text().startswith("#!/bin/bash\n")


@pytest.mark.parametrize("path", sorted((DEPLOY / "env").glob("*.example")), ids=lambda p: p.name)
def test_every_env_setting_has_its_reason(path: Path) -> None:
    lines = path.read_text().splitlines()
    for index, line in enumerate(lines):
        if line and not line.startswith("#"):
            assert "=" in line, f"{path.name}: {line} has no comment above it"
            assert lines[index - 1].startswith("#"), f"{path.name}: {line} has no comment above it"


def test_no_secrets_in_env_examples() -> None:
    for path in (DEPLOY / "env").glob("*.example"):
        text = path.read_text().lower()
        for marker in ("password=", "roblosecurity=", "token=", "secret=", "_key="):
            assert marker not in text, f"{path.name} must not carry {marker} (secrets are credentials, plan 9.8)"


def all_deploy_files() -> list[Path]:
    files = [p for p in DEPLOY.rglob("*") if p.is_file() and "__pycache__" not in p.parts]
    return [
        *files,
        REPO / "scripts" / "smoke_remote.py",
        REPO / "scripts" / "build_static.py",
        *(p for p in (REPO / "tests" / "deploy").glob("*.py")),
    ]


def test_unix_line_endings_and_trailing_newline() -> None:
    for path in all_deploy_files():
        data = path.read_bytes()
        assert b"\r\n" not in data, f"{path} has CRLF line endings"
        assert data.endswith(b"\n"), f"{path} lacks a final newline"


def test_programs_are_executable() -> None:
    for path in EXECUTABLES:
        if path.is_file():
            assert os.access(path, os.X_OK), f"{path} must be executable (chmod 0755)"


def test_style_check_passes() -> None:
    """Plan C5: no em or en dash and US spelling, with the repository's own checker."""
    paths = [str(p) for p in all_deploy_files()]
    result = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "check_style.py"), *paths], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_shellcheck() -> None:
    """Plan 19.9: shellcheck the deploy scripts (v1's backtick bug is the kind of mistake it finds)."""
    shellcheck = find_tool("shellcheck")
    if shellcheck is None:
        pytest.skip("shellcheck is not installed (apt-get download shellcheck; dpkg -x into ~/.local/p13tools)")
    result = subprocess.run(
        [shellcheck, "--severity=style", *map(str, SHELL_FILES)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stdout


@pytest.mark.parametrize("path", SHELL_FILES, ids=lambda p: p.name)
def test_shell_syntax(path: Path) -> None:
    assert subprocess.run(["bash", "-n", str(path)], check=False).returncode == 0


def test_deploy_log_strings_keep_the_c5_replacements() -> None:
    """Plan C5 exceptions table: the v1 deploy messages, with the dash replaced exactly as listed."""
    text = (DEPLOY / "deploy.sh").read_text()
    for line in (
        "Clone is missing $required; refusing to deploy it.",
        "Dependencies changed (or no usable environment); rebuilding.",
        "Dependencies unchanged; keeping the existing environment.",
        "Previous build restored. The site should be back up; nothing was upgraded.",
        "Site successfully deployed.",
    ):
        assert line in text
