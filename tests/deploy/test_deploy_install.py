"""deploy/install-system.sh: the root setup installs every piece with the modes roxy-audit.py expects.

What this is
    Runs the install script with `--prefix` (no accounts, no owner changes, no systemctl) into a temporary root
    and checks what it installed: units, tools, wrappers, sudo rules, env files and directories with their modes,
    that local configuration is never overwritten, that no secret is written, and that a second run changes
    nothing. Also: an /etc/roxy that Roxy v1 still owns is left exactly as it is, and the sudo rules are checked by
    visudo in the form they are installed.

Why it exists
    The install script is the only way root-owned files reach the server (deploy.sh cannot write them, plan 9.14),
    so a wrong mode here would be a wrong mode in production. It also runs on the live v1 server during the
    cutover, where taking /etc/roxy away from v1's account would stop v1 (it writes its state there).

How it works
    `bash deploy/install-system.sh --prefix <tmp>`; then plain stat calls. In a --prefix install the test user
    owns everything, so `ROXY_INSTALL_UID` names some other uid to make an existing /etc/roxy look like v1's, and
    `ROXY_SETFACL` and a `visudo` early on PATH are stubs that record their arguments.

What to read next
    deploy/install-system.sh, deploy/tools/roxy-audit.py (the same expectations, audited on the server).
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest
from deploy_sandbox import DEPLOY, write_exec

pytestmark = [pytest.mark.deploy]

# Stands in for v1's account (ubuntu) in a --prefix install, where the test user owns every file.
OTHER_UID = str(os.getuid() + 1)


def install(prefix: Path, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(DEPLOY / "install-system.sh"), "--prefix", str(prefix), *args],
        capture_output=True,
        text=True,
        timeout=60,
        env={**os.environ, **(env or {})},
        check=False,
    )


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_install_layout(tmp_path: Path) -> None:
    result = install(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    expected_dirs = {
        "opt/roxy": 0o755,
        "opt/roxy/releases": 0o755,
        "var/lib/roxy-deploy": 0o755,
        "etc/roxy": 0o750,
        "etc/roxy/credentials": 0o700,
        "var/backups/roxy": 0o700,
        "usr/local/lib/roxy": 0o755,
    }
    for directory, wanted in expected_dirs.items():
        assert mode(tmp_path / directory) == wanted, directory
    for unit in (DEPLOY / "systemd").iterdir():
        if unit.suffix in {".service", ".timer", ".path"}:
            installed = tmp_path / "etc/systemd/system" / unit.name
            assert installed.read_bytes() == unit.read_bytes()
            assert mode(installed) == 0o644
    assert (tmp_path / "etc/systemd/journald.conf.d/roxy.conf").is_file()
    for tool in ("alert_on_failure.py", "backup.sh", "roxy-audit.py"):
        assert mode(tmp_path / "usr/local/lib/roxy" / tool) == 0o755
    for wrapper in ("roxy-nginx-apply", "roxy-switch-color"):
        assert mode(tmp_path / "usr/local/sbin" / wrapper) == 0o755
    sudoers = tmp_path / "etc/sudoers.d/roxy-deploy"
    assert mode(sudoers) == 0o440
    for name in ("roxy.env", "blue.env", "green.env"):
        assert mode(tmp_path / "etc/roxy" / name) == 0o640
    assert mode(tmp_path / "opt/roxy/deploy.sh") == 0o755
    for optional in ("alert_webhook_url", "rotator_url", "rclone_config"):
        path = tmp_path / "etc/roxy/credentials" / optional
        assert path.stat().st_size == 0
        assert mode(path) == 0o600
    assert "still missing in /etc/roxy/credentials" in result.stdout
    assert "roblox_credential" in result.stdout
    assert not (tmp_path / "etc/roxy/credentials/roblox_credential").exists(), "no secret is ever written"
    assert not list(tmp_path.glob("tmp-*")), "no temporary file is left behind"


def test_install_keeps_local_configuration_and_is_idempotent(tmp_path: Path) -> None:
    assert install(tmp_path).returncode == 0
    env = tmp_path / "etc/roxy/roxy.env"
    env.write_text("ROXY_WORKERS=1\n")
    secret = tmp_path / "etc/roxy/credentials/alert_webhook_url"
    secret.write_text("configured")
    second = install(tmp_path)
    assert second.returncode == 0, second.stderr
    assert env.read_text() == "ROXY_WORKERS=1\n"
    assert secret.read_text() == "configured"
    assert "keeping the existing /etc/roxy/roxy.env" in second.stdout


def test_install_sets_the_deploy_user_in_the_sudo_rules(tmp_path: Path) -> None:
    assert install(tmp_path, "--deploy-user", "shipper").returncode == 0
    text = (tmp_path / "etc/sudoers.d/roxy-deploy").read_text()
    assert "User_Alias ROXY_DEPLOYERS = shipper" in text


def test_install_refuses_bad_arguments(tmp_path: Path) -> None:
    result = subprocess.run(
        ["bash", str(DEPLOY / "install-system.sh"), "--bogus"], capture_output=True, text=True, check=False
    )
    assert result.returncode == 2


def test_install_creates_the_state_directory(tmp_path: Path) -> None:
    """The root jobs (audit, backup) run from the moment the timers are enabled, before any color has started:
    /var/lib/roxy must exist for their sandbox (ReadWritePaths). Their report directory audit/ inside it is made by
    the jobs themselves, without following links (tests in test_deploy_audit.py and test_deploy_backup.py)."""
    assert install(tmp_path).returncode == 0
    assert mode(tmp_path / "var/lib/roxy") == 0o750
    assert not (tmp_path / "var/lib/roxy/audit").exists()


def test_install_never_changes_a_directory_through_a_symlink(tmp_path: Path) -> None:
    """The deploy user owns /opt/roxy, so it could replace /opt/roxy/releases with a link to a root directory;
    chmod and chown as root through that link would give the directory away (plan 9.14: no path to root)."""
    prefix = tmp_path / "root"
    victim = tmp_path / "victim"
    victim.mkdir()
    victim.chmod(0o700)
    (prefix / "opt" / "roxy").mkdir(parents=True)
    (prefix / "opt" / "roxy" / "releases").symlink_to(victim)
    result = install(prefix)
    assert result.returncode != 0
    assert "is a symlink" in result.stderr
    assert mode(victim) == 0o700


# --------------------------------------------------------------------------------- beside Roxy v1 (cutover)


def v1_etc(prefix: Path) -> Path:
    """/etc/roxy as v1 has it: owned by its account (here: OTHER_UID), mode 0700, its state files 0600."""
    etc = prefix / "etc" / "roxy"
    etc.mkdir(parents=True)
    data = etc / "roxy_data.json"
    data.write_text("{}\n")
    data.chmod(0o600)
    etc.chmod(0o700)
    return etc


def setfacl_stub(tmp_path: Path) -> tuple[Path, Path]:
    log = tmp_path / "setfacl.log"
    stub = write_exec(tmp_path / "stubs" / "setfacl", f'#!/bin/bash\necho "$*" >>"{log}"\n')
    return stub, log


def test_install_leaves_a_v1_etc_directory_alone(tmp_path: Path) -> None:
    """v1 (user ubuntu, mode 0700) keeps writing its state to /etc/roxy until the cutover: its owner and mode stay,
    and only the deploy user gets permission to pass through (an ACL entry), to read the v2 env files."""
    prefix = tmp_path / "root"
    etc = v1_etc(prefix)
    stub, log = setfacl_stub(tmp_path)
    result = install(prefix, env={"ROXY_INSTALL_UID": OTHER_UID, "ROXY_SETFACL": str(stub)})
    assert result.returncode == 0, result.stdout + result.stderr
    assert mode(etc) == 0o700, "v1's directory keeps its mode (and, on the server, its owner)"
    assert (etc / "roxy_data.json").read_text() == "{}\n"
    assert mode(etc / "roxy_data.json") == 0o600
    assert log.read_text().split() == ["-m", "u:roxy-deploy:x", str(etc)]
    assert "Roxy v1" in result.stdout
    assert "--take-over-etc" in result.stdout
    for name in ("roxy.env", "blue.env", "green.env"):
        assert mode(etc / name) == 0o640
    assert mode(etc / "credentials") == 0o700


def test_install_beside_v1_needs_setfacl_and_changes_nothing_without_it(tmp_path: Path) -> None:
    prefix = tmp_path / "root"
    etc = v1_etc(prefix)
    result = install(prefix, env={"ROXY_INSTALL_UID": OTHER_UID})
    assert result.returncode == 1
    assert "apt install acl" in result.stderr
    assert mode(etc) == 0o700
    assert [p.name for p in etc.iterdir()] == ["roxy_data.json"], "nothing was installed"
    assert not (prefix / "etc" / "systemd").exists()


def test_take_over_etc_after_v1_is_retired(tmp_path: Path) -> None:
    prefix = tmp_path / "root"
    etc = v1_etc(prefix)
    stub, log = setfacl_stub(tmp_path)
    result = install(prefix, "--take-over-etc", env={"ROXY_INSTALL_UID": OTHER_UID, "ROXY_SETFACL": str(stub)})
    assert result.returncode == 0, result.stdout + result.stderr
    assert mode(etc) == 0o750
    assert log.read_text().split() == ["-b", str(etc)], "the cutover ACL entry is removed"


# ------------------------------------------------------------------------------------------- sudo rules


@pytest.mark.parametrize("name", ["roxy deploy", "evil/x", "a&b", "x\nALL ALL=(ALL) NOPASSWD: ALL", "Root"])
def test_install_refuses_an_unsafe_deploy_user_name(tmp_path: Path, name: str) -> None:
    """A name with spaces or sudoers syntax would install rules visudo rejects (and a broken sudoers file stops
    sudo for everyone) or rules for someone else."""
    result = install(tmp_path, "--deploy-user", name)
    assert result.returncode != 0
    assert not (tmp_path / "etc" / "sudoers.d" / "roxy-deploy").exists()


def test_rendered_sudo_rules_are_checked_before_they_are_installed(tmp_path: Path) -> None:
    """visudo checks the file that is installed (with the deploy user filled in), not only the template."""
    log = tmp_path / "visudo.log"
    stubs = tmp_path / "stubs"
    write_exec(
        stubs / "visudo",
        f"""
        #!/bin/bash
        file="${{@: -1}}"
        grep '^User_Alias' "$file" >>"{log}"
        if grep -q '= shipper$' "$file"; then exit 1; fi
        exit 0
        """,
    )
    prefix = tmp_path / "root"
    result = install(prefix, "--deploy-user", "shipper", env={"PATH": f"{stubs}:{os.environ['PATH']}"})
    assert result.returncode != 0
    assert "User_Alias ROXY_DEPLOYERS = shipper" in log.read_text()
    sudoers = prefix / "etc" / "sudoers.d"
    assert not (sudoers / "roxy-deploy").exists()
    assert not sudoers.exists() or list(sudoers.iterdir()) == []
