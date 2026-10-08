"""The thin script `scripts/migrate_from_v1.py` (plan 18.3): runs from a checkout, dry run end to end."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from v1_migration_helpers import tree_snapshot

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "migrate_from_v1.py"


def _env() -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if not key.startswith("ROXY_")}
    env.pop("CREDENTIALS_DIRECTORY", None)
    return env


def test_script_help() -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"], capture_output=True, text=True, timeout=60, env=_env(), check=False
    )
    assert result.returncode == 0
    flags = ("--v1-root", "--state-dir", "--credentials-out", "--dry-run", "--report", "--import-admin-password")
    for flag in (*flags, "--v1-state-file", "--v1-data-file", "ROXY_ROTATE_PROXY"):
        assert flag in result.stdout


def test_script_dry_run(v1: Any, ws: Any) -> None:
    v1.small_tree(ws.v1).write()
    before = tree_snapshot(ws.v1)
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--v1-root",
            str(ws.v1),
            "--state-dir",
            str(ws.state),
            "--credentials-out",
            str(ws.credentials),
            "--report",
            str(ws.report),
            "--dry-run",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        env=_env(),
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "dry_run_would_change" in result.stdout
    assert not ws.state.exists()
    assert not ws.credentials.exists()
    assert tree_snapshot(ws.v1) == before
    data = json.loads(ws.report.with_name(ws.report.name + ".json").read_text(encoding="utf-8"))
    assert data["dry_run"] is True
    assert data["counts"]["imported"] > 10
