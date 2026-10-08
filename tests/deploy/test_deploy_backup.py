"""deploy/tools/backup.sh: consistent copies, checks, zstd, optional age and rclone, retention (plan 17.1, 17.5).

What this is
    Runs the real backup script against migrated temporary databases: the set it writes (files, checksums,
    modes), the integrity of every restored copy, hot.db only on request, age encryption when a recipients file
    exists, 14 daily plus 8 weekly retention over a simulated two months, the monthly restore test, the rclone
    push with a stub, and the failure path (status recorded, no half-written set).

Why it exists
    A backup that was never restored is a hope, not a backup. These tests restore every copy they make.

How it works
    zstd and age come from PATH or the no-root unpack location (~/.local/p13tools, `apt-get download` plus
    `dpkg -x`); tests needing them skip with the reason when absent. ROXY_BACKUP_DATE lets a test make one set per
    simulated day. Ownership changes (root:roxy on the status file) are best effort and ignored when unprivileged.
    The status file lives in a directory inside the roxy user's state directory, so the tests also plant what that
    user could (links where root is about to write) and check that root never follows them. Here the test user
    plays both root and roxy, which is enough: following a link does not depend on who planted it.

What to read next
    deploy/tools/backup.sh, deploy/systemd/roxy-backup.service.
"""

from __future__ import annotations

import datetime
import json
import os
import sqlite3
import stat
import subprocess
from pathlib import Path

import pytest
from deploy_sandbox import DEPLOY, find_tool, write_exec

pytestmark = [pytest.mark.deploy]

SCRIPT = DEPLOY / "tools" / "backup.sh"


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
    conn = sqlite3.connect(directory / "control.db")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("INSERT INTO service_state (key, value_json, updated_at) VALUES ('backup_test', '\"marker\"', 1)")
    conn.commit()
    conn.close()
    return directory


def run_backup(tmp_path: Path, state: Path, zstd: str, **extra: str) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": f"{Path(zstd).parent}:/usr/bin:/bin",
        "ROXY_STATE_DIR": str(state),
        "ROXY_BACKUP_DIR": str(tmp_path / "backups"),
        "ROXY_BACKUP_STATUS": str(tmp_path / "status" / "backup.json"),
        "ROXY_ZSTD": zstd,
        "ROXY_BACKUP_AGE_RECIPIENTS": str(tmp_path / "no-recipients"),
        "ROXY_BACKUP_DATE": "2026-10-07",
        "ROXY_DEPLOYED_VERSION_FILE": str(tmp_path / "no-deploy-yet"),
    }
    env.update(extra)
    return subprocess.run(["bash", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=120, check=False)


def restore(zstd: str, compressed: Path, target: Path) -> sqlite3.Connection:
    subprocess.run([zstd, "-q", "-d", str(compressed), "-o", str(target)], check=True)
    conn = sqlite3.connect(target)
    assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    return conn


def test_nightly_set(tmp_path: Path, state: Path, zstd: str) -> None:
    result = run_backup(tmp_path, state, zstd)
    assert result.returncode == 0, result.stdout + result.stderr
    backups = tmp_path / "backups"
    day = backups / "2026-10-07"
    assert sorted(p.name for p in day.iterdir()) == ["SHA256SUMS", "control.db.zst", "metrics.db.zst"]
    assert stat.S_IMODE(backups.stat().st_mode) == 0o700
    assert stat.S_IMODE(day.stat().st_mode) == 0o700
    for path in day.iterdir():
        assert stat.S_IMODE(path.stat().st_mode) & 0o077 == 0, f"{path.name} must be private to root"
    check = subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=day, capture_output=True, text=True, check=False)
    assert check.returncode == 0, check.stdout
    conn = restore(zstd, day / "control.db.zst", tmp_path / "control-restored.db")
    assert conn.execute("SELECT value_json FROM service_state WHERE key = 'backup_test'").fetchone()[0] == '"marker"'
    conn.close()
    restore(zstd, day / "metrics.db.zst", tmp_path / "metrics-restored.db").close()
    assert not list(backups.glob(".tmp-*")), "no work directory left behind"
    status = json.loads((tmp_path / "status" / "backup.json").read_text())
    assert status["last_success"]["date"] == "2026-10-07"
    assert set(status["last_success"]["set"]["files"]) == {"SHA256SUMS", "control.db.zst", "metrics.db.zst"}
    assert status["restore_test"]["ok"] is True, "the first run restores its own set"
    assert stat.S_IMODE((tmp_path / "status" / "backup.json").stat().st_mode) == 0o640


def test_cache_db_is_never_backed_up_and_hot_db_only_on_request(tmp_path: Path, state: Path, zstd: str) -> None:
    assert run_backup(tmp_path, state, zstd).returncode == 0
    names = {p.name for p in (tmp_path / "backups" / "2026-10-07").iterdir()}
    assert "cache.db.zst" not in names
    assert "hot.db.zst" not in names
    assert run_backup(tmp_path, state, zstd, ROXY_BACKUP_HOT="1", ROXY_BACKUP_DATE="2026-10-08").returncode == 0
    names = {p.name for p in (tmp_path / "backups" / "2026-10-08").iterdir()}
    assert "hot.db.zst" in names
    assert "cache.db.zst" not in names


def test_same_day_rerun_replaces_the_set(tmp_path: Path, state: Path, zstd: str) -> None:
    assert run_backup(tmp_path, state, zstd).returncode == 0
    assert run_backup(tmp_path, state, zstd).returncode == 0
    assert sorted(p.name for p in (tmp_path / "backups").iterdir()) == ["2026-10-07"]


def test_retention_keeps_14_daily_and_8_weekly(tmp_path: Path, state: Path, zstd: str) -> None:
    start = datetime.date(2026, 8, 1)
    days = [start + datetime.timedelta(days=i) for i in range(70)]
    backups = tmp_path / "backups"
    for day in days[:-1]:  # fast setup: empty sets with the right names
        (backups / day.isoformat()).mkdir(parents=True)
    assert run_backup(tmp_path, state, zstd, ROXY_BACKUP_DATE=days[-1].isoformat()).returncode == 0
    kept = sorted(p.name for p in backups.iterdir())
    names = sorted((d.isoformat() for d in days), reverse=True)
    expected = set(names[:14])
    weeks: dict[tuple[int, int], str] = {}
    for name in names:
        weeks.setdefault(datetime.date.fromisoformat(name).isocalendar()[:2], name)
    expected |= {weeks[week] for week in sorted(weeks, reverse=True)[:8]}
    assert kept == sorted(expected)
    assert len(kept) < 14 + 8 + 1


def test_age_encryption_round_trip(tmp_path: Path, state: Path, zstd: str) -> None:
    age, keygen = find_tool("age"), find_tool("age-keygen")
    if age is None or keygen is None:
        pytest.skip("age is not installed")
    identity = tmp_path / "identity.txt"
    subprocess.run([keygen, "-o", str(identity)], check=True, capture_output=True)
    public = next(line.split(": ")[1] for line in identity.read_text().splitlines() if "public key" in line)
    recipients = tmp_path / "recipients"
    recipients.write_text(public + "\n")
    result = run_backup(
        tmp_path,
        state,
        zstd,
        ROXY_AGE=age,
        ROXY_BACKUP_AGE_RECIPIENTS=str(recipients),
        PATH=f"{Path(age).parent}:/usr/bin:/bin",
    )
    assert result.returncode == 0, result.stderr
    day = tmp_path / "backups" / "2026-10-07"
    assert sorted(p.name for p in day.iterdir()) == ["SHA256SUMS", "control.db.zst.age", "metrics.db.zst.age"]
    decrypted = tmp_path / "control.db.zst"
    subprocess.run([age, "-d", "-i", str(identity), "-o", str(decrypted), str(day / "control.db.zst.age")], check=True)
    restore(zstd, decrypted, tmp_path / "control.db").close()
    status = json.loads((tmp_path / "status" / "backup.json").read_text())
    assert status["restore_test"]["ok"] is None, "an encrypted set is drilled by hand with the escrowed key"


def test_restore_test_runs_monthly(tmp_path: Path, state: Path, zstd: str) -> None:
    assert run_backup(tmp_path, state, zstd).returncode == 0
    first = json.loads((tmp_path / "status" / "backup.json").read_text())["restore_test"]
    assert run_backup(tmp_path, state, zstd, ROXY_BACKUP_DATE="2026-10-08").returncode == 0
    second = json.loads((tmp_path / "status" / "backup.json").read_text())["restore_test"]
    assert second == first, "not due again until 28 days have passed"


def test_rclone_push(tmp_path: Path, state: Path, zstd: str) -> None:
    log = tmp_path / "rclone.log"
    rclone = write_exec(tmp_path / "bin" / "rclone", f'#!/bin/bash\necho "$*" >>{log}\n')
    creds = tmp_path / "creds"
    creds.mkdir()
    (creds / "rclone_config").write_text("[offsite]\ntype = local\n")
    result = run_backup(
        tmp_path, state, zstd, ROXY_RCLONE=str(rclone), ROXY_BACKUP_REMOTE="offsite", CREDENTIALS_DIRECTORY=str(creds)
    )
    assert result.returncode == 0, result.stderr
    assert log.read_text().strip() == (
        f"--config {creds}/rclone_config copy {tmp_path}/backups/2026-10-07 offsite:roxy-backups/2026-10-07"
    )
    status = json.loads((tmp_path / "status" / "backup.json").read_text())
    assert status["last_success"]["set"]["remote"] == "offsite"


@pytest.mark.parametrize("remote", ["evil:path", "a b", "../x"])
def test_rclone_remote_must_be_a_name(tmp_path: Path, state: Path, zstd: str, remote: str) -> None:
    creds = tmp_path / "creds"
    creds.mkdir()
    (creds / "rclone_config").write_text("[x]\n")
    rclone = write_exec(tmp_path / "bin" / "rclone", "#!/bin/bash\nexit 0\n")
    result = run_backup(
        tmp_path, state, zstd, ROXY_RCLONE=str(rclone), ROXY_BACKUP_REMOTE=remote, CREDENTIALS_DIRECTORY=str(creds)
    )
    assert result.returncode != 0


def test_failure_is_recorded_and_leaves_no_partial_set(tmp_path: Path, state: Path, zstd: str) -> None:
    (state / "metrics.db").unlink()
    result = run_backup(tmp_path, state, zstd)
    assert result.returncode != 0
    assert "FAILED at step copy metrics.db" in result.stdout
    backups = tmp_path / "backups"
    assert not (backups / "2026-10-07").exists()
    assert not list(backups.glob(".tmp-*"))
    status = json.loads((tmp_path / "status" / "backup.json").read_text())
    assert status["last_failure"]["step"] == "copy metrics.db"


def test_corrupt_database_fails_the_integrity_check(tmp_path: Path, state: Path, zstd: str) -> None:
    path = state / "metrics.db"
    data = bytearray(path.read_bytes())
    for offset in range(4096, min(len(data), 4096 * 3)):
        data[offset] = 0xFF  # trash the first pages after the header
    path.write_bytes(bytes(data))
    result = run_backup(tmp_path, state, zstd)
    assert result.returncode != 0
    assert not (tmp_path / "backups" / "2026-10-07").exists()


def mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def earlier_backup(tmp_path: Path) -> Path:
    """A file of an earlier backup set (root-only in production): what a planted link would aim at."""
    victim = tmp_path / "backups" / "2026-10-06" / "control.db.zst"
    victim.parent.mkdir(parents=True)
    victim.write_bytes(b"PRECIOUS-BACKUP-BYTES")
    victim.chmod(0o600)
    return victim


def test_status_write_never_follows_a_planted_link(tmp_path: Path, state: Path, zstd: str) -> None:
    """The roxy user owns /var/lib/roxy, the root backup writes /var/lib/roxy/audit/backup.json: links planted at
    the temporary name or at the status file itself must never be followed (they would overwrite a backup)."""
    victim = earlier_backup(tmp_path)
    audit = state / "audit"
    audit.mkdir()
    for name in ("backup.json.tmp", ".backup.json.tmp", "backup.json"):
        (audit / name).symlink_to(victim)
    result = run_backup(tmp_path, state, zstd, ROXY_BACKUP_STATUS=str(audit / "backup.json"))
    assert result.returncode == 0, result.stdout + result.stderr
    assert victim.read_bytes() == b"PRECIOUS-BACKUP-BYTES"
    assert mode(victim) == 0o600
    status = audit / "backup.json"
    assert not status.is_symlink()
    assert json.loads(status.read_text())["last_success"]["date"] == "2026-10-07"
    assert mode(status) == 0o640


def test_status_directory_planted_as_a_link_is_moved_aside(tmp_path: Path, state: Path, zstd: str) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "keep.txt").write_text("x")
    (state / "audit").symlink_to(elsewhere)
    result = run_backup(tmp_path, state, zstd, ROXY_BACKUP_STATUS=str(state / "audit" / "backup.json"))
    assert result.returncode == 0, result.stdout + result.stderr
    assert [p.name for p in elsewhere.iterdir()] == ["keep.txt"], "nothing was written through the link"
    assert (state / "audit").is_dir()
    assert not (state / "audit").is_symlink()
    assert (state / "audit" / "backup.json").is_file()
    assert len(list(state.glob("audit.untrusted-*"))) == 1, "the link is kept aside for the owner to look at"


def test_status_directory_is_readable_by_the_service_group(tmp_path: Path, state: Path, zstd: str) -> None:
    """The app (user roxy, group roxy) reads backup.json for H-BACKUP: the directory root creates under its umask
    0077 must still be 0750 (root:roxy on the server), the file 0640."""
    result = run_backup(tmp_path, state, zstd, ROXY_BACKUP_STATUS=str(state / "audit" / "backup.json"))
    assert result.returncode == 0, result.stdout + result.stderr
    assert mode(state / "audit") == 0o750
    assert mode(state / "audit" / "backup.json") == 0o640


def test_nothing_to_back_up_before_the_first_deploy(tmp_path: Path, zstd: str) -> None:
    """The timer runs from install time; before any color has started there are no databases. That is not a
    failure (no false "backup failed" alert), but once a deploy has been recorded, missing databases are."""
    empty = tmp_path / "state"
    empty.mkdir()
    result = run_backup(tmp_path, empty, zstd)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "nothing to back up yet" in result.stdout
    assert not (tmp_path / "status" / "backup.json").exists()
    assert run_backup(tmp_path, tmp_path / "no-state-dir", zstd).returncode == 0
    deployed = tmp_path / "deployed_version"
    deployed.write_text("a" * 40 + "\n")
    result = run_backup(tmp_path, empty, zstd, ROXY_DEPLOYED_VERSION_FILE=str(deployed))
    assert result.returncode != 0
    assert "FAILED at step copy control.db" in result.stdout


def test_backup_never_touches_the_source_files(tmp_path: Path, state: Path, zstd: str) -> None:
    before = {p.name: p.read_bytes() for p in state.glob("*.db")}
    assert run_backup(tmp_path, state, zstd).returncode == 0
    after = {p.name: p.read_bytes() for p in state.glob("*.db")}
    assert before == after
    assert os.access(SCRIPT, os.X_OK)
