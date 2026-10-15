"""Back up now: roxy-backup-request.path and the request handling in deploy/tools/backup.sh (plan 14.1, 17.5).

What this is
    Tests of the path unit (what it watches, what it starts, every directive commented, `systemd-analyze verify`),
    of install-system.sh enabling it, and of backup.sh answering a request: a requested run makes a set and records
    `last_request` in backup.json, the request file is consumed first thing whatever happens next, a request
    within the minimum gap after a good backup is skipped, a request before the first deploy is answered without
    a backup, and a request file that is a link or a directory is removed without following anything. The last
    test goes end to end: `scripts/ctl.py backup-now` writes the request and backup.sh answers it.

Why it exists
    The service runs as the unprivileged roxy user and may not start units (plan 9.14), so "back up now" from the
    dashboard or the CLI can only leave a file for systemd to notice. That file is written by the roxy user and
    read and removed by a root job, so the root side must never follow a link the roxy user planted, must not loop
    (PathExists= fires again while the file exists) and must not let a flood of requests keep the box busy.

How it works
    backup.sh runs for real against migrated temporary databases, with zstd from PATH or ~/.local/p13tools (tests
    that make a set skip without it). The request file path and the minimum gap are environment overrides
    (ROXY_BACKUP_REQUEST, ROXY_BACKUP_MIN_GAP_S); the status file lives outside the state directory as in
    test_deploy_backup.py. The unit is parsed as text; `systemd-analyze verify` runs in a private root.

What to read next
    deploy/systemd/roxy-backup-request.path, deploy/tools/backup.sh, scripts/ctl.py (`backup-now`).
"""

from __future__ import annotations

import io
import json
import os
import shutil
import sqlite3
import subprocess
from pathlib import Path

import pytest
from deploy_sandbox import DEPLOY, REPO, find_tool, load_script

pytestmark = [pytest.mark.deploy]

SCRIPT = DEPLOY / "tools" / "backup.sh"
UNIT = DEPLOY / "systemd" / "roxy-backup-request.path"
STATE_DIR_IN_UNITS = "/var/lib/roxy"


def directives(path: Path) -> list[tuple[str, str, str, bool]]:
    """(section, key, value, has a comment line directly above) for every directive line."""
    rows: list[tuple[str, str, str, bool]] = []
    section = previous = ""
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
        elif line and not line.startswith(("#", ";")) and "=" in line:
            key, _, value = line.partition("=")
            rows.append((section, key.strip(), value.strip(), previous.startswith("#")))
        previous = line
    return rows


# ------------------------------------------------------------------------------------------------- the unit


def test_request_path_unit_watches_the_request_file() -> None:
    rows = directives(UNIT)
    found = {(section, key): value for section, key, value, _ in rows}
    assert found[("Path", "PathExists")] == f"{STATE_DIR_IN_UNITS}/backup-request"
    assert found[("Path", "Unit")] == "roxy-backup.service"
    assert found[("Install", "WantedBy")] == "paths.target"
    assert [key for _, key, _, commented in rows if not commented] == [], "every directive has its reason"
    service = (DEPLOY / "systemd" / "roxy-backup.service").read_text()
    assert "ReadWritePaths=/var/backups/roxy -/var/lib/roxy" in service, "backup.sh may remove the request file"


def test_every_side_names_the_same_request_file(tmp_path: Path) -> None:
    ctl = load_script(REPO / "scripts" / "ctl.py", "roxy_ctl_for_deploy_tests")
    watched = next(value for _, key, value, _ in directives(UNIT) if key == "PathExists")
    assert Path(watched).name == ctl.BACKUP_REQUEST_NAME
    assert 'REQUEST_FILE="${ROXY_BACKUP_REQUEST:-$STATE_DIR/backup-request}"' in SCRIPT.read_text()


def test_install_enables_the_request_path() -> None:
    text = (DEPLOY / "install-system.sh").read_text()
    enable = text[text.index("systemctl enable --now") :].split("\n\n")[0]
    assert "roxy-backup-request.path" in enable


def test_systemd_analyze_verify_accepts_the_request_path(tmp_path: Path) -> None:
    analyze = shutil.which("systemd-analyze")
    if analyze is None or not Path("/usr/lib/systemd/system").is_dir():
        pytest.skip("systemd-analyze is not available")
    root = tmp_path / "root"
    shutil.copytree("/usr/lib/systemd/system", root / "usr" / "lib" / "systemd" / "system", symlinks=True)
    target = root / "etc" / "systemd" / "system"
    target.mkdir(parents=True)
    for unit in (DEPLOY / "systemd").iterdir():
        if unit.suffix in {".service", ".timer", ".path"}:
            shutil.copy(unit, target / unit.name)
    for executable in ("/usr/local/lib/roxy/backup.sh", "/usr/bin/python3"):
        stand_in = root / executable.lstrip("/")
        stand_in.parent.mkdir(parents=True, exist_ok=True)
        stand_in.write_text("#!/bin/sh\n")
        stand_in.chmod(0o755)
    result = subprocess.run(
        [analyze, "verify", f"--root={root}", "--man=no", "roxy-backup-request.path", "roxy-backup.service"],
        capture_output=True,
        text=True,
        cwd=root,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert (result.stdout + result.stderr).strip() == ""


# ------------------------------------------------------------------------------------------------- backup.sh


@pytest.fixture
def zstd() -> str:
    found = find_tool("zstd")
    if found is None:
        pytest.skip("zstd is not installed (apt-get download zstd; dpkg -x into ~/.local/p13tools)")
    return found


@pytest.fixture
def state(tmp_path: Path) -> Path:
    from roxy.storage.migrate import migrate_paths

    directory = tmp_path / "state"
    directory.mkdir()
    migrate_paths({name: directory / f"{name}.db" for name in ("control", "hot", "metrics", "cache")})
    return directory


def run_backup(tmp_path: Path, state: Path, zstd: str | None, **extra: str) -> subprocess.CompletedProcess[str]:
    path = f"{Path(zstd).parent}:/usr/bin:/bin" if zstd else "/usr/bin:/bin"
    env = {
        "PATH": path,
        "ROXY_STATE_DIR": str(state),
        "ROXY_BACKUP_DIR": str(tmp_path / "backups"),
        "ROXY_BACKUP_STATUS": str(tmp_path / "status" / "backup.json"),
        "ROXY_ZSTD": zstd or "zstd-missing",
        "ROXY_BACKUP_AGE_RECIPIENTS": str(tmp_path / "no-recipients"),
        "ROXY_BACKUP_DATE": "2026-10-07",
        "ROXY_DEPLOYED_VERSION_FILE": str(tmp_path / "no-deploy-yet"),
    }
    env.update(extra)
    return subprocess.run(["bash", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=120, check=False)


def status_of(tmp_path: Path) -> dict[str, object]:
    return dict(json.loads((tmp_path / "status" / "backup.json").read_text()))


def write_request(state: Path, by: str = "cli:opsadmin") -> Path:
    request = state / "backup-request"
    request.write_text(json.dumps({"requested_at": "2026-10-07T10:00:00Z", "by": by, "audit_id": 7}))
    return request


def test_a_requested_backup_runs_and_consumes_the_request(tmp_path: Path, state: Path, zstd: str) -> None:
    request = write_request(state)
    result = run_backup(tmp_path, state, zstd)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not request.exists(), "consumed, so PathExists= does not start the backup again"
    status = status_of(tmp_path)
    last = status["last_request"]
    assert isinstance(last, dict)
    assert last["outcome"] == "ran"
    assert last["by"] == "cli:opsadmin"
    assert last["requested_at"] == "2026-10-07T10:00:00Z"
    assert "last_success" in status
    assert (tmp_path / "backups" / "2026-10-07" / "control.db.zst").is_file()


def test_a_nightly_run_records_no_request(tmp_path: Path, state: Path, zstd: str) -> None:
    assert run_backup(tmp_path, state, zstd).returncode == 0
    assert "last_request" not in status_of(tmp_path)


def test_a_request_soon_after_a_good_backup_is_skipped(tmp_path: Path, state: Path, zstd: str) -> None:
    assert run_backup(tmp_path, state, zstd).returncode == 0
    request = write_request(state)
    result = run_backup(tmp_path, state, zstd, ROXY_BACKUP_DATE="2026-10-08")
    assert result.returncode == 0, result.stdout + result.stderr
    assert not request.exists()
    assert status_of(tmp_path)["last_request"]["outcome"] == "skipped_recent"  # type: ignore[index]
    assert not (tmp_path / "backups" / "2026-10-08").exists(), "no second set within the gap"
    write_request(state)
    result = run_backup(tmp_path, state, zstd, ROXY_BACKUP_DATE="2026-10-08", ROXY_BACKUP_MIN_GAP_S="0")
    assert result.returncode == 0, result.stdout + result.stderr
    assert status_of(tmp_path)["last_request"]["outcome"] == "ran"  # type: ignore[index]
    assert (tmp_path / "backups" / "2026-10-08").is_dir()


def test_a_request_before_the_first_deploy_is_answered_without_a_backup(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    request = write_request(state)
    result = run_backup(tmp_path, state, None)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not request.exists()
    assert status_of(tmp_path)["last_request"]["outcome"] == "skipped_no_database"  # type: ignore[index]


def test_the_request_text_is_sanitized_and_bounded(tmp_path: Path, state: Path, zstd: str) -> None:
    request = state / "backup-request"
    request.write_text(json.dumps({"by": "cli:op$(reboot)`id`\n" + "x" * 5000, "requested_at": "<script>"}))
    result = run_backup(tmp_path, state, zstd)
    assert result.returncode == 0, result.stdout + result.stderr
    last = status_of(tmp_path)["last_request"]
    assert isinstance(last, dict)
    assert last["by"] == "unknown", "a body over 4 KiB is not JSON once cut; nothing from it is kept"
    request.write_text(json.dumps({"by": "cli:op$(reboot)`id`", "requested_at": "<script>"}))
    assert run_backup(tmp_path, state, zstd, ROXY_BACKUP_MIN_GAP_S="0").returncode == 0
    last = status_of(tmp_path)["last_request"]
    assert isinstance(last, dict)
    assert last["by"] == "cli:opreboot" + "id"
    assert last["requested_at"] == ""


def test_a_request_link_is_removed_never_followed(tmp_path: Path, state: Path, zstd: str) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me")
    (state / "backup-request").symlink_to(victim)
    result = run_backup(tmp_path, state, zstd)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not (state / "backup-request").is_symlink()
    assert victim.read_text() == "keep me"
    assert status_of(tmp_path)["last_request"]["by"] == "unknown"  # type: ignore[index]


def test_a_request_directory_is_removed_without_following_links(tmp_path: Path, state: Path, zstd: str) -> None:
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "precious.txt").write_text("keep me")
    request = state / "backup-request"
    request.mkdir()
    (request / "link").symlink_to(victim)
    result = run_backup(tmp_path, state, zstd)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not request.exists()
    assert (victim / "precious.txt").read_text() == "keep me"


def test_ctl_backup_now_end_to_end(tmp_path: Path, state: Path, zstd: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """The CLI writes the request (as the roxy user would) and backup.sh answers it (as root would)."""
    conn = sqlite3.connect(state / "control.db")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.close()
    monkeypatch.setenv("SUDO_USER", "opsadmin")
    ctl = load_script(REPO / "scripts" / "ctl.py", "roxy_ctl_for_deploy_tests")
    out = io.StringIO()
    status = ctl.main(
        ["--state-dir", str(state), "--env-dir", str(tmp_path / "no-env"), "backup-now", "--reason", "drill"], out=out
    )
    assert status == 0, out.getvalue()
    assert (state / "backup-request").is_file()
    result = run_backup(tmp_path, state, zstd)
    assert result.returncode == 0, result.stdout + result.stderr
    last = status_of(tmp_path)["last_request"]
    assert isinstance(last, dict)
    assert (last["by"], last["outcome"]) == ("cli:opsadmin", "ran")
    assert not (state / "backup-request").exists()
    assert os.access(SCRIPT, os.X_OK)
