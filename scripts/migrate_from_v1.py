#!/usr/bin/env python3
"""Migrate a Roxy v1 `/etc/roxy` tree into Roxy v2 (REMAKE_PLAN.md 18.3).

What this is
    The command the owner runs during cutover (MIGRATION.md), first with `--dry-run`:
    `python scripts/migrate_from_v1.py --v1-root /etc/roxy --state-dir /var/lib/roxy --credentials-out
    /etc/roxy/credentials --report /root/roxy-migration --dry-run`.

Why it exists
    The logic lives in the importable package `roxy.migration` so it can be tested; this file only makes `src/`
    importable when run from a checkout and calls `roxy.migration.cli.main`.

How it works
    It inserts `<repo>/src` at the front of `sys.path` when the package is not installed, then exits with the
    status `main` returns (0 success, 1 a step failed, 2 bad arguments).

What to read next
    `src/roxy/migration/cli.py` (the arguments) and `src/roxy/migration/runner.py` (the steps).
"""

from __future__ import annotations

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from roxy.migration.cli import main  # noqa: E402 (imported after the path tweak on purpose)

if __name__ == "__main__":
    raise SystemExit(main())
