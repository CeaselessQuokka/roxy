"""Reading v1 files the way v1 did (plan 19.6): a corrupt roxy_data.json, the legacy Runtime blob, files.txt, and
the guarantee that no v1 file is ever changed, renamed or added to."""

from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Any

import pytest
from v1_migration_helpers import rows, run_cli, tree_snapshot

from roxy.migration.runner import Options, run_migration
from roxy.migration.v1_tree import V1ReadError, read_v1_tree


async def test_migration_corrupt_roxy_data_json(v1: Any, ws: Any, migrate: Any) -> None:
    """A corrupt data file is reported, never renamed (v1 renamed it to .corrupt-<time>); rules still import."""
    builder = v1.small_tree(ws.v1)
    builder.corrupt_data = True
    builder.write()
    before = tree_snapshot(ws.v1)
    report = await migrate()
    assert tree_snapshot(ws.v1) == before
    assert not list(ws.v1.glob("roxy_data.json.corrupt-*"))
    assert any("roxy_data.json: not valid JSON" in error for error in report.errors)
    assert report.status == "completed_with_errors"
    assert report.statistics["detail"].startswith("no v1 statistics")
    metrics = ws.state / "metrics.db"
    assert rows(metrics, "SELECT count(*) FROM legacy_totals")[0][0] == 0
    control = ws.state / "control.db"
    assert rows(control, "SELECT count(*) FROM rules_endpoint_block")[0][0] == 2  # roxy_state.json still imported
    assert report.hosts["status"] == "skipped"  # no statistics, so no hosts seen


async def test_migration_corrupt_data_falls_back_to_bak(v1: Any, ws: Any, migrate: Any) -> None:
    """v1 storage.load_data read roxy_data.json.bak when the data file was broken; so does the migrator."""
    builder = v1.small_tree(ws.v1)
    builder.corrupt_data = True
    builder.data_backup = True
    builder.write()
    before = tree_snapshot(ws.v1)
    report = await migrate()
    assert tree_snapshot(ws.v1) == before
    assert report.sources["statistics"] == "roxy_data.json.bak"
    totals = {
        r["key"]: json.loads(r["value_json"]) for r in rows(ws.state / "metrics.db", "SELECT * FROM legacy_totals")
    }
    assert totals["v1.roblox_429_total"]["value"] == 579


async def test_migration_legacy_runtime_blob(v1: Any, ws: Any, migrate: Any) -> None:
    """Before the state/data split, v1 kept its control plane under `Runtime` in roxy_data.json; v1 loaded it
    when roxy_state.json had none, and so does the migrator."""
    builder = v1.small_tree(ws.v1)
    builder.legacy_runtime = builder.runtime
    builder.write_state = False
    builder.write()
    report = await migrate()
    assert "legacy Runtime blob" in report.sources["control_plane"]
    control = ws.state / "control.db"
    assert rows(control, "SELECT count(*) FROM rules_endpoint_block")[0][0] == 2
    assert [r["id"] for r in rows(control, "SELECT id FROM rules_user_agent ORDER BY position")] == [
        "a1b2c3d4",
        "0f0f0f0f",
    ]


async def test_migration_legacy_runtime_ignored_when_state_has_one(v1: Any, ws: Any, migrate: Any) -> None:
    builder = v1.small_tree(ws.v1)
    old = v1.default_runtime()
    old["EndpointBlocks"] = {"legacy.roblox.com/old": {"Note": "", "Message": "", "Type": "glob"}}
    builder.legacy_runtime = old
    builder.write()
    report = await migrate()
    assert report.sources["control_plane"] == "roxy_state.json"
    assert report.sources["legacy_runtime_ignored"] is True
    patterns = [r["pattern"] for r in rows(ws.state / "control.db", "SELECT pattern FROM rules_endpoint_block")]
    assert "legacy.roblox.com/old" not in patterns


async def test_migration_corrupt_state_uses_legacy_runtime(v1: Any, ws: Any, migrate: Any) -> None:
    """v1 treated an unreadable roxy_state.json as empty and fell back to the legacy blob (bug B4)."""
    builder = v1.small_tree(ws.v1)
    builder.legacy_runtime = builder.runtime
    builder.write()
    (ws.v1 / "roxy_state.json").write_text("{broken", encoding="utf-8")
    before = tree_snapshot(ws.v1)
    report = await migrate()
    assert tree_snapshot(ws.v1) == before
    assert "legacy Runtime blob" in report.sources["control_plane"]
    assert any("roxy_state.json: not valid JSON" in warning for warning in report.warnings)


async def test_migration_never_changes_v1_files(v1: Any, ws: Any, migrate: Any) -> None:
    """Hash every v1 file (and mode) before and after a real run, a rerun and a dry run (plan 18.3)."""
    builder = v1.small_tree(ws.v1, token_count=2)
    builder.write()
    before = tree_snapshot(ws.v1)
    await migrate(dry_run=True)
    await migrate(admin=True)
    await migrate(admin=True)
    after = tree_snapshot(ws.v1)
    assert after == before  # same files, same bytes, same modes, nothing added (no .lock, .bak or .corrupt)


def test_files_listing_outside_root_is_never_followed(v1: Any, ws: Any, tmp_path: Path) -> None:
    """An absolute path in files.txt is re-rooted inside --v1-root, so a copied tree can never make the migrator
    read the live /etc/roxy (or anything else outside the root)."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "auth_tokens.txt").write_text(v1.fake_token(), encoding="utf-8")
    builder = v1.V1TreeBuilder(ws.v1)
    builder.files_listing = [
        "admin_credentials.txt",
        "app_password.txt",
        str(outside / "auth_tokens.txt"),
        "../outside/emails.txt",
    ]
    builder.write()
    tree = read_v1_tree(ws.v1)
    assert tree.secrets.tokens == builder.secrets.tokens  # read from the root, not from `outside`
    assert any("outside the v1 root" in warning for warning in tree.warnings)
    assert any("emails" in error and "outside the v1 root" in error for error in tree.errors)
    assert tree.secrets.email_to is None


def test_unreadable_root_is_refused(tmp_path: Path) -> None:
    with pytest.raises(V1ReadError):
        read_v1_tree(tmp_path / "missing")


def test_conventional_names_without_files_txt(v1: Any, ws: Any) -> None:
    builder = v1.V1TreeBuilder(ws.v1)
    builder.write()
    (ws.v1 / "files.txt").unlink()
    tree = read_v1_tree(ws.v1)
    assert tree.secrets.tokens == builder.secrets.tokens
    assert tree.secrets.admin_username == builder.secrets.username
    assert any("files.txt is missing" in warning for warning in tree.warnings)


async def test_migration_refuses_a_root_without_v1_data(ws: Any, migrate: Any) -> None:
    """A wrong --v1-root (no state, no data, no secret file) is refused and nothing is written, so a later run on
    the right root is not told "already imported" (review finding 5)."""
    ws.v1.mkdir(parents=True)
    (ws.v1 / "unrelated.txt").write_text("not a roxy tree\n", encoding="utf-8")
    (ws.v1 / "files.txt").write_text("a\nb\nc\nd\n", encoding="utf-8")
    report = await migrate()
    assert report.status == "refused"
    assert any("holds none of the v1 files" in error for error in report.errors)
    assert not ws.state.exists()
    assert not ws.credentials.exists()


@pytest.mark.usefixtures("restore_logging")
def test_cli_refuses_a_root_without_v1_data(ws: Any) -> None:
    ws.v1.mkdir(parents=True)
    status, stdout, _logs = run_cli(ws)
    assert status == 2
    assert "holds none of the v1 files" in stdout
    assert not ws.state.exists()
    assert not ws.report.with_name(ws.report.name + ".json").exists()


@pytest.mark.parametrize("which", ["state_dir", "credentials_out"])
async def test_migration_refuses_an_output_directory_that_is_the_v1_root(
    v1: Any, ws: Any, fake_clock: Any, which: str
) -> None:
    """`--credentials-out /etc/roxy` (a slip for /etc/roxy/credentials) would chmod the live v1 directory to 0700
    and add files to it; `--state-dir /etc/roxy` would add databases. Both are refused (review finding 11)."""
    v1.V1TreeBuilder(ws.v1).write()
    ws.v1.chmod(0o755)
    before = tree_snapshot(ws.v1)
    paths = {"state_dir": ws.state, "credentials_out": ws.credentials, which: ws.v1}
    options = Options(ws.v1, paths["state_dir"], paths["credentials_out"])
    report = await run_migration(options, clock=fake_clock)
    assert report.status == "refused"
    assert any(f"--{which.replace('_', '-')}" in error and "v1 root" in error for error in report.errors)
    assert tree_snapshot(ws.v1) == before
    assert stat.S_IMODE(ws.v1.stat().st_mode) == 0o755
    assert not ws.state.exists()
    assert not ws.credentials.exists()


@pytest.mark.usefixtures("restore_logging")
def test_cli_refuses_a_report_inside_the_v1_root(v1: Any, ws: Any) -> None:
    """`--report /etc/roxy/roxy_state.json` would replace the v1 state file with the report; any report path
    inside the v1 root is refused before anything runs."""
    v1.V1TreeBuilder(ws.v1).write()
    before = tree_snapshot(ws.v1)
    status, stdout, _logs = run_cli(ws, report=ws.v1 / "roxy_state.json")
    assert status == 2
    assert "--report" in stdout
    assert "v1 root" in stdout
    assert tree_snapshot(ws.v1) == before
    assert not ws.state.exists()


async def test_migration_reads_the_state_and_data_files_v1_was_told_to_use(v1: Any, ws: Any, migrate: Any) -> None:
    """v1 honored ROXY_STATE_FILE and ROXY_DATA_FILE; `--v1-state-file` and `--v1-data-file` name those files
    inside --v1-root (an absolute path is read by its file name inside the root), and the `.bak` fallback follows
    the data file (review finding 13)."""
    builder = v1.small_tree(ws.v1)
    builder.write()
    (ws.v1 / "roxy_state.json").rename(ws.v1 / "state-prod.json")
    (ws.v1 / "roxy_data.json").rename(ws.v1 / "data-prod.json")
    report = await migrate(state_file="/etc/roxy/state-prod.json", data_file="data-prod.json")
    assert report.errors == []
    assert report.sources["control_plane"] == "state-prod.json"
    assert report.sources["statistics"] == "data-prod.json"
    assert any("--v1-state-file" in warning and "outside the v1 root" in warning for warning in report.warnings)
    assert rows(ws.state / "control.db", "SELECT count(*) FROM rules_endpoint_block")[0][0] == 2
    totals = rows(ws.state / "metrics.db", "SELECT value_json FROM legacy_totals WHERE key = 'v1.roblox_429_total'")
    assert json.loads(totals[0][0])["value"] == 579
