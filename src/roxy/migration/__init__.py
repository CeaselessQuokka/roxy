"""The v1 to v2 data migration: everything `scripts/migrate_from_v1.py` does, as an importable package.

What this is
    The one-time importer that reads a copy of the v1 `/etc/roxy` tree (files.txt, roxy_state.json,
    roxy_data.json, the token, credential, email and rotator files) and writes what v2 keeps into the v2
    databases and into a directory of bootstrap credential files (plan 18.3). It never changes a v1 file.

Why it exists
    The owner moves from v1 to v2 once, during a short maintenance window (MIGRATION.md). Settings, rules, the
    ladder, bypass entries, pause messages and the lifetime statistics must arrive intact, every admin-written
    text must follow plan C5, exactly one Roblox credential may survive (plan C1), and nothing secret may leak
    into the report. A plain script would be hard to test, so the logic lives here and the script is a thin
    wrapper around `roxy.migration.cli.main`.

How it works
    `v1_tree` reads the v1 files (read only, bounded, never outside `--v1-root`). `v1_settings`, `rules_import`,
    `hosts`, `admin_import`, `secrets_out` and `stats_import` each plan and apply one part of plan 18.3 through
    the existing services (settings service with source `import`, the rules registry helpers, audit rows and
    `config_version` bumps). `text` rewrites em and en dashes (plan C5). `ledger` remembers what earlier runs
    placed, so a rerun after the cutover never puts back what the owner changed or deleted in v2. `runner` puts it
    together, including the dry run (the same code against throwaway copies) and the refusals (an output path that
    is the v1 root, a v1 root without v1 files), and `report` renders the JSON and Markdown report.

What to read next
    `roxy/migration/runner.py` (the order of the steps), then `roxy/migration/v1_tree.py` (what is read) and
    `roxy/migration/report.py` (what the owner sees).
"""

from __future__ import annotations

__all__: list[str] = []
