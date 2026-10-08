"""deploy/tools/roxy-audit.py: the metadata-only permission audit behind H-SECRETS-PERMS (plan 17.1, 17.3).

What this is
    Builds the expected server layout under a temporary root (owners are the test user, standing in for root, roxy
    and roxy-deploy), runs the audit, and checks its findings, the exposure score parsing, and the report file.

Why it exists
    The audit runs as root every 6 hours; its promise is that it reads metadata only and that a weakened permission
    shows up as a finding the app can display. A credential value must never appear in the report.

How it works
    `Layout` takes the root directory and the account names, so the expectations table is checked against the
    temporary tree. A stub systemd-analyze prints the exposure line the real one prints. The report is written
    into a directory the roxy user owns on the server, so the write tests plant what that user could (links at the
    temporary name, at perms.json, or in place of the report directory) and check root never follows them; the
    test user plays both parts, which is enough, since following a link does not depend on who planted it.

What to read next
    deploy/tools/roxy-audit.py.
"""

from __future__ import annotations

import dataclasses
import grp
import json
import os
import pwd
import stat
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from deploy_sandbox import DEPLOY, load_script, write_exec

pytestmark = [pytest.mark.deploy]

SECRET = "fake-secret-value-that-must-never-be-read-0123456789"


@pytest.fixture(scope="module")
def audit() -> ModuleType:
    return load_script(DEPLOY / "tools" / "roxy-audit.py", "roxy_audit_for_tests")


def build_tree(root: Path) -> None:
    def make(path: str, mode: int, content: str | None = None) -> None:
        target = root / path.lstrip("/")
        if content is None:
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        target.chmod(mode)

    make("/etc/roxy", 0o750)
    make("/etc/roxy/credentials", 0o700)
    make("/etc/roxy/credentials/roblox_credential", 0o600, SECRET)
    make("/etc/roxy/credentials/alert_webhook_url", 0o600, "")
    for name in ("roxy.env", "blue.env", "green.env"):
        make(f"/etc/roxy/{name}", 0o640, "ROXY_ENV=production\n")
    make("/var/lib/roxy", 0o750)
    make("/var/lib/roxy/audit", 0o750)
    make("/var/lib/roxy/control.db", 0o640, "db")
    make("/var/lib/roxy/control.db-wal", 0o640, "wal")
    make("/var/backups/roxy", 0o700)
    for name in ("roxy-nginx-apply", "roxy-switch-color"):
        make(f"/usr/local/sbin/{name}", 0o755, "#!/bin/sh\n")
    make("/usr/local/lib/roxy", 0o755)
    make("/usr/local/lib/roxy/backup.sh", 0o755, "#!/bin/sh\n")
    make("/etc/sudoers.d/roxy-deploy", 0o440, "# rules\n")
    make("/opt/roxy/releases", 0o755)
    (root / "etc" / "roxy").chmod(0o750)


@pytest.fixture
def layout(tmp_path: Path, audit: ModuleType) -> object:
    me = pwd.getpwuid(os.getuid()).pw_name
    group = grp.getgrgid(os.getgid()).gr_name
    root = tmp_path / "root"
    build_tree(root)
    analyze = write_exec(
        tmp_path / "bin" / "systemd-analyze",
        """
        #!/bin/bash
        echo "  NAME   DESCRIPTION   EXPOSURE"
        case "$3" in
          roxy@blue.service) echo "-> Overall exposure level for roxy@blue.service: 1.2 OK :-)" ;;
          *) echo "-> Overall exposure level for $3: 5.6 MEDIUM :-|" ;;
        esac
    """,
    )
    return audit.Layout(
        root=root,
        output=tmp_path / "out" / "perms.json",
        report_group=group,
        service_user=me,
        service_group=group,
        admin_user=me,
        admin_group=group,
        deploy_user=me,
        systemd_analyze=(str(analyze),),
    )


def findings_with_problems(report: dict[str, Any]) -> dict[str, list[str]]:
    return {f["path"]: f["problems"] for f in report["findings"] if f["problems"]}


def test_correct_layout_has_no_findings(audit: ModuleType, layout: object) -> None:
    report = audit.run_audit(layout, with_scores=False)
    assert findings_with_problems(report) == {}
    assert report["ok"] is True
    paths = {f["path"] for f in report["findings"]}
    assert "/etc/roxy/credentials/roblox_credential" in paths
    assert "/var/lib/roxy/control.db-wal" in paths


def test_weakened_permissions_are_reported(audit: ModuleType, layout: object) -> None:
    root = layout.root  # type: ignore[attr-defined]
    (root / "etc/roxy/credentials/roblox_credential").chmod(0o644)
    (root / "var/lib/roxy/control.db").chmod(0o644)
    (root / "etc/roxy/roxy.env").chmod(0o666)
    (root / "etc/sudoers.d/roxy-deploy").unlink()
    (root / "usr/local/lib/roxy/backup.sh").chmod(0o777)
    problems = findings_with_problems(audit.run_audit(layout, with_scores=False))
    assert "mode is 0644, expected 0600" in problems["/etc/roxy/credentials/roblox_credential"]
    assert any("0004" in p for p in problems["/var/lib/roxy/control.db"])
    assert problems["/etc/sudoers.d/roxy-deploy"] == ["missing"]
    assert "/etc/roxy/roxy.env" in problems
    assert "/usr/local/lib/roxy/backup.sh" in problems


def test_symlinks_are_findings(audit: ModuleType, layout: object, tmp_path: Path) -> None:
    root = layout.root  # type: ignore[attr-defined]
    credential = root / "etc/roxy/credentials/roblox_credential"
    credential.unlink()
    (tmp_path / "elsewhere").write_text("x")
    credential.symlink_to(tmp_path / "elsewhere")
    problems = findings_with_problems(audit.run_audit(layout, with_scores=False))
    assert "is a symlink" in problems["/etc/roxy/credentials/roblox_credential"]


def test_metadata_only(audit: ModuleType, layout: object) -> None:
    """An unreadable secret is still audited (lstat needs no read permission), and no value reaches the report."""
    root = layout.root  # type: ignore[attr-defined]
    (root / "etc/roxy/credentials/roblox_credential").chmod(0o000)
    report = audit.run_audit(layout, with_scores=False)
    audit.write_report(layout, report)
    text = layout.output.read_text()  # type: ignore[attr-defined]
    assert SECRET not in text
    entry = next(f for f in report["findings"] if f["path"] == "/etc/roxy/credentials/roblox_credential")
    assert entry["empty"] is False
    assert "size" not in entry
    empty = next(f for f in report["findings"] if f["path"] == "/etc/roxy/credentials/alert_webhook_url")
    assert empty["empty"] is True


def test_exposure_scores_and_report_file(audit: ModuleType, layout: object, capsys: pytest.CaptureFixture[str]) -> None:
    assert audit.main([], layout=layout) == 0
    report = json.loads(layout.output.read_text())  # type: ignore[attr-defined]
    assert report["exposure"]["roxy@blue.service"] == {"score": 1.2, "rating": "OK", "ok": True}
    assert report["exposure"]["roxy@green.service"]["ok"] is False
    assert report["ok"] is False
    assert report["schema"] == "roxy.perms/1"
    assert stat.S_IMODE(layout.output.stat().st_mode) == 0o640  # type: ignore[attr-defined]
    assert "problem(s)" in capsys.readouterr().out


def test_report_directory_is_audited(audit: ModuleType, layout: object) -> None:
    root = layout.root  # type: ignore[attr-defined]
    (root / "var/lib/roxy/audit").chmod(0o700)
    problems = findings_with_problems(audit.run_audit(layout, with_scores=False))
    assert "mode is 0700, expected 0750" in problems["/var/lib/roxy/audit"]


# ------------------------------------------------------------------- writing the report (root, in roxy's tree)


def with_output(layout: object, output: Path) -> object:
    return dataclasses.replace(layout, output=output)  # type: ignore[type-var]


def mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def test_report_never_follows_a_planted_link(audit: ModuleType, layout: object, tmp_path: Path) -> None:
    """roxy-audit runs as root and writes into /var/lib/roxy, which the roxy user owns: a link planted at the
    temporary name or at perms.json itself must never be followed."""
    victim = tmp_path / "victim.db.zst"
    victim.write_bytes(b"PRECIOUS")
    victim.chmod(0o600)
    report_dir = tmp_path / "state" / "audit"
    report_dir.mkdir(parents=True)
    for name in (".perms.json.tmp", "perms.json.tmp", "perms.json"):
        (report_dir / name).symlink_to(victim)
    assert audit.write_report(with_output(layout, report_dir / "perms.json"), {"schema": "roxy.perms/1"}) is True
    assert victim.read_bytes() == b"PRECIOUS"
    assert mode(victim) == 0o600
    report = report_dir / "perms.json"
    assert not report.is_symlink()
    assert json.loads(report.read_text()) == {"schema": "roxy.perms/1"}


def test_report_directory_is_readable_by_the_service_group(audit: ModuleType, layout: object, tmp_path: Path) -> None:
    """Under the unit's UMask=0077 a plain mkdir makes the directory 0700 and the app (group roxy) could never read
    perms.json; the directory gets 0750 and the file 0640 explicitly."""
    state = tmp_path / "state"
    state.mkdir()
    old = os.umask(0o077)
    try:
        assert audit.write_report(with_output(layout, state / "audit" / "perms.json"), {"schema": "x"}) is True
    finally:
        os.umask(old)
    assert mode(state / "audit") == 0o750
    assert mode(state / "audit" / "perms.json") == 0o640


@pytest.mark.parametrize("kind", ["link", "writable"])
def test_untrusted_report_directory_is_moved_aside(
    audit: ModuleType, layout: object, tmp_path: Path, kind: str
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    planted = tmp_path / "planted"
    planted.mkdir()
    (planted / "keep").write_text("x")
    if kind == "link":
        (state / "audit").symlink_to(planted)
    else:
        (state / "audit").mkdir()
        (state / "audit").chmod(0o777)  # anyone could swap files in it
        (state / "audit" / "keep").write_text("x")
    assert audit.write_report(with_output(layout, state / "audit" / "perms.json"), {"schema": "x"}) is True
    assert [p.name for p in planted.iterdir()] == ["keep"]
    assert not (state / "audit").is_symlink()
    assert sorted(p.name for p in (state / "audit").iterdir()) == ["perms.json"]
    assert mode(state / "audit") == 0o750
    assert len(list(state.glob("audit.untrusted-*"))) == 1


def test_report_is_skipped_while_the_state_directory_is_missing(
    audit: ModuleType, layout: object, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Before the first color has started there is no /var/lib/roxy (the unit's ReadWritePaths entry is optional):
    the audit still runs, and says why no report was written, instead of failing."""
    missing = tmp_path / "missing-state"
    assert audit.main(["--no-scores"], layout=with_output(layout, missing / "audit" / "perms.json")) == 0
    assert not missing.exists()
    assert "no report written" in capsys.readouterr().out


def test_audit_script_is_standard_library_only() -> None:
    text = (DEPLOY / "tools" / "roxy-audit.py").read_text()
    assert text.startswith("#!/usr/bin/python3 -I\n")
    assert "read_text" not in text.split("def write_report")[0], "no file contents are read before the report"
