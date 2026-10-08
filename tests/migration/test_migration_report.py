"""The report files and the report's warnings (plan 18.3): safe to write anywhere, and every high risk is listed.

What this is
    Tests for `report.write_report` (temporary file handling) and for warnings the plan asks the report to carry.

Why it exists
    Review findings 7 and 15. The owner may write the report into a shared directory such as /tmp while running
    as root, so the writer must never follow a link another user planted; and the plan's "high-risk warning in
    the report" for cached POST requests must be a warning, not only a note in the settings table.

How it works
    A planted symbolic link at every name the writer could use, then a check that the link targets are unchanged;
    a v1 tree with `cache_post_requests` 1, then a check of `report.warnings`.

What to read next
    `src/roxy/migration/report.py` (`_write_private`) and `src/roxy/migration/runner.py` (`_import_settings`).
"""

from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Any

from roxy.migration.report import MigrationReport, write_report


def test_report_writer_never_follows_a_planted_symlink(tmp_path: Path) -> None:
    shared = tmp_path / "shared"  # stands for a world-writable directory such as /tmp
    shared.mkdir()
    victims = {}
    for name in (".migration.json.tmp", ".migration.md.tmp", "migration.json"):
        victim = tmp_path / f"victim-{name.strip('.')}"
        victim.write_text("important=1\n", encoding="utf-8")
        victim.chmod(0o644)
        (shared / name).symlink_to(victim)  # planted by another local user
        victims[name] = victim
    report = MigrationReport(dry_run=True, started_at=0, v1_root="x", state_dir="y", credentials_out=None)
    json_path, markdown_path = write_report(report, shared / "migration")
    for victim in victims.values():
        assert victim.read_text(encoding="utf-8") == "important=1\n", victim.name
        assert stat.S_IMODE(victim.stat().st_mode) == 0o644, victim.name
    for path in (json_path, markdown_path):
        assert not path.is_symlink()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert json.loads(json_path.read_text(encoding="utf-8"))["dry_run"] is True
    leftovers = sorted(p.name for p in shared.iterdir() if p.name.endswith(".tmp") and not p.is_symlink())
    assert leftovers == []


async def test_migration_cache_post_high_risk_is_a_warning(v1: Any, ws: Any, migrate: Any) -> None:
    builder = v1.V1TreeBuilder(ws.v1)
    v1.set_setting(builder.runtime, "cache_post_requests", 1)
    builder.write()
    report = await migrate()
    assert any("HIGH RISK" in w and "cache_post_requests" in w for w in report.warnings), report.warnings
    again = await migrate()  # still true on a rerun: v2 still caches every POST because of the import
    assert any("HIGH RISK" in w for w in again.warnings)


async def test_migration_cache_post_off_gives_no_warning(v1: Any, ws: Any, migrate: Any) -> None:
    v1.V1TreeBuilder(ws.v1).write()
    report = await migrate()
    assert not any("HIGH RISK" in w for w in report.warnings)
