"""systemd units: every plan 17.1 directive with its reason, a clean `systemd-analyze verify`, an exposure score of
2.0 or lower, and the app actually running under the unit's sandbox (plan 17.1, 19.10 row 17).

What this is
    Static checks of deploy/systemd/* (directives and values, a comment above every directive, the DESIGN.md
    section 0 memory numbers, no root unit running code from the deploy-owned /opt/roxy), `systemd-analyze verify`
    in a private root, `systemd-analyze security --offline` for roxy@.service, and a runtime test that boots the real
    app with gunicorn under the unit's seccomp-based settings (MemoryDenyWriteExecute, SystemCallFilter, ...) with
    `systemd-run --user`.

Why it exists
    A unit file fails quietly: a misspelled key is a warning in the journal, and a too-strict filter is a crash at
    the first request. Plan 17.1 asks to verify MemoryDenyWriteExecute against uvloop and zstandard in tests rather
    than hope. And the ownership rule matters for security: a root unit must never execute a file the deploy user
    can replace (plan 9.14), so root tools live in /usr/local, not in /opt/roxy.

How it works
    Units are parsed as lists of (section, key, value) with comments tracked. `systemd-analyze verify --root` runs
    against a temporary root holding a copy of the system's units and stand-in executables. The runtime test parses
    the sandbox properties out of roxy@.service and passes them to systemd-run, adding PrivateUsers and
    PrivateNetwork so the app has loopback only. Tests skip with a reason when systemd-analyze or a user manager is
    not available.

What to read next
    deploy/systemd/roxy@.service, then deploy/README.md.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from deploy_sandbox import DEPLOY, REPO, load_script

pytestmark = [pytest.mark.deploy]

UNITS = DEPLOY / "systemd"
UNIT_FILES = sorted(p for p in UNITS.iterdir() if p.suffix in {".service", ".timer", ".path"})


def parse_unit(path: Path) -> list[tuple[str, str, str, bool]]:
    """(section, key, value, has_comment_above) for every directive line."""
    rows: list[tuple[str, str, str, bool]] = []
    section = ""
    previous = ""
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
        elif line and not line.startswith(("#", ";")) and "=" in line:
            key, _, value = line.partition("=")
            rows.append((section, key.strip(), value.strip(), previous.startswith("#")))
        previous = line
    return rows


def values(path: Path, key: str, section: str | None = None) -> list[str]:
    return [v for s, k, v, _ in parse_unit(path) if k == key and (section is None or s == section)]


def one(path: Path, key: str) -> str:
    found = values(path, key)
    assert len(found) == 1, f"{path.name}: {key} appears {len(found)} times"
    return found[0]


@pytest.mark.parametrize("path", UNIT_FILES, ids=lambda p: p.name)
def test_every_directive_has_its_reason(path: Path) -> None:
    """Plan 17.1 and 18.1 item 8: a comment line directly above every directive (systemd has no end-of-line
    comments; a `#` after a value would become part of the value)."""
    missing = [f"{key}={value}" for _, key, value, commented in parse_unit(path) if not commented]
    assert missing == []
    for _, key, value, _ in parse_unit(path):
        assert "#" not in value, f"{key}: a '#' inside a value is not a comment in systemd"


ROXY = UNITS / "roxy@.service"

EXPECTED_17_1 = {
    "Description": "Roxy (%i)",
    "StartLimitIntervalSec": "300",
    "StartLimitBurst": "5",
    "OnFailure": "roxy-alert@%n.service",
    "Type": "notify",
    "NotifyAccess": "main",
    "User": "roxy",
    "Group": "roxy",
    "WorkingDirectory": "/opt/roxy/releases/current-%i",
    "ExecStart": "/opt/roxy/releases/current-%i/.venv/bin/gunicorn -c deploy/gunicorn.conf.py roxy.asgi:app",
    "ExecReload": "/bin/kill -HUP $MAINPID",
    "KillMode": "mixed",
    "KillSignal": "SIGTERM",
    "TimeoutStopSec": "45",
    "Restart": "on-failure",
    "RestartSec": "3",
    "StateDirectory": "roxy",
    "StateDirectoryMode": "0750",
    "LogsDirectory": "roxy",
    "RuntimeDirectory": "roxy-%i",
    "RuntimeDirectoryMode": "0750",
    "UMask": "0027",
    "MemoryAccounting": "yes",
    "MemoryHigh": "320M",  # DESIGN.md section 0 (909 MB server), not the plan's 650M
    "MemoryMax": "420M",  # DESIGN.md section 0, not the plan's 800M
    "TasksMax": "256",
    "LimitNOFILE": "65536",
    "NoNewPrivileges": "yes",
    "PrivateTmp": "yes",
    "PrivateDevices": "yes",
    "ProtectSystem": "strict",
    "ProtectHome": "yes",
    "ReadWritePaths": "/var/lib/roxy",
    "ProtectKernelTunables": "yes",
    "ProtectKernelModules": "yes",
    "ProtectKernelLogs": "yes",
    "ProtectControlGroups": "yes",
    "ProtectClock": "yes",
    "ProtectHostname": "yes",
    "ProtectProc": "invisible",
    "ProcSubset": "pid",
    "RestrictAddressFamilies": "AF_INET AF_INET6 AF_UNIX",
    "RestrictNamespaces": "yes",
    "RestrictRealtime": "yes",
    "RestrictSUIDSGID": "yes",
    "LockPersonality": "yes",
    "RemoveIPC": "yes",
    "MemoryDenyWriteExecute": "yes",
    "SystemCallArchitectures": "native",
    "CapabilityBoundingSet": "",
    "AmbientCapabilities": "",
    "SyslogIdentifier": "roxy-%i",
}


@pytest.mark.parametrize(("key", "expected"), sorted(EXPECTED_17_1.items()))
def test_roxy_unit_has_the_plan_17_1_directive(key: str, expected: str) -> None:
    assert one(ROXY, key) == expected


def test_roxy_unit_lists_and_order() -> None:
    assert values(ROXY, "After") == ["network-online.target"]
    assert values(ROXY, "Wants") == ["network-online.target"]
    assert values(ROXY, "EnvironmentFile") == ["/etc/roxy/roxy.env", "/etc/roxy/%i.env", "-/etc/roxy/nginx-hints.env"]
    assert values(ROXY, "SystemCallFilter") == ["@system-service", "~@privileged @resources", "@chown"]
    assert values(ROXY, "SystemCallErrorNumber") == ["EPERM"]
    credentials = [value.split(":", 1)[0] for value in values(ROXY, "LoadCredential")]
    assert credentials == [
        "roblox_credential",
        "rotator_url",
        "smtp_password",
        "alert_emails",
        "alert_webhook_url",
        "credential_encryption_key",
        "totp_encryption_key",
        "ip_hash_key",
    ]
    for value in values(ROXY, "LoadCredential"):
        name, source = value.split(":", 1)
        assert source == f"/etc/roxy/credentials/{name}"
    assert values(ROXY, "Environment") == [], "no Environment=ROXY_BIND=...${PORT}: systemd does not expand it (17.1)"
    assert values(ROXY, "IPAddressDeny") == []
    assert values(ROXY, "IPAddressAllow") == []
    assert values(ROXY, "ExecStartPre") == [
        "/opt/roxy/releases/current-%i/.venv/bin/python /opt/roxy/releases/current-%i/deploy/prestart.py"
    ]
    assert "[Install]" not in ROXY.read_text().splitlines(), "colors are never enabled; roxy-boot.service does it"


def test_stop_timeout_outlives_gunicorns_graceful_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """v1 had TimeoutStopSec=20 against graceful_timeout=30 (plan 2.4); now systemd waits longer than gunicorn."""
    conf = load_script(DEPLOY / "gunicorn.conf.py", "gunicorn_conf_for_unit_tests")
    assert int(one(ROXY, "TimeoutStopSec")) > conf.graceful_timeout


def test_memory_numbers_fit_the_909_mb_server() -> None:
    """DESIGN.md section 0: two colors overlap during a deploy; at their soft limits they must leave room for nginx
    and the operating system on 909 MB without swap."""

    def megabytes(text: str) -> int:
        return int(text.removesuffix("M"))

    high, hard = megabytes(one(ROXY, "MemoryHigh")), megabytes(one(ROXY, "MemoryMax"))
    assert high < hard
    assert 2 * high + 200 < 909, "two colors at MemoryHigh plus about 200 MB for nginx and the OS"


def test_ports_and_sockets_agree_across_files() -> None:
    for color, port in (("blue", 8001), ("green", 8002)):
        env = (DEPLOY / "env" / f"{color}.env.example").read_text()
        assert f"ROXY_BIND=127.0.0.1:{port}" in env
        assert f"ROXY_INTERNAL_SOCKET=/run/roxy-{color}/internal.sock" in env  # inside RuntimeDirectory=roxy-%i
        assert f"server 127.0.0.1:{port};" in (DEPLOY / "nginx" / f"roxy-upstream-{color}.conf").read_text()


def test_alert_unit() -> None:
    unit = UNITS / "roxy-alert@.service"
    assert one(unit, "Type") == "oneshot"
    assert one(unit, "ExecStart") == "/usr/bin/python3 -I /usr/local/lib/roxy/alert_on_failure.py %i"
    assert [v.split(":")[0] for v in values(unit, "LoadCredential")] == [
        "smtp_password",
        "alert_emails",
        "alert_webhook_url",
    ]
    assert one(unit, "StateDirectory") == "roxy-alert"
    assert values(unit, "OnFailure") == [], "an alert about the alert unit could loop"
    assert one(unit, "DynamicUser") == "yes"


def test_timers_and_paths() -> None:
    backup_timer = UNITS / "roxy-backup.timer"
    assert one(backup_timer, "OnCalendar") == "*-*-* 03:30:00"
    assert one(backup_timer, "RandomizedDelaySec") == "15m"
    assert one(backup_timer, "Persistent") == "true"
    assert one(UNITS / "roxy-audit.timer", "OnUnitInactiveSec") == "6h"
    deploy_sh = (DEPLOY / "deploy.sh").read_text()
    audit_path = one(UNITS / "roxy-audit.path", "PathChanged")
    assert audit_path == "/var/lib/roxy-deploy/deployed_version"
    assert '"$DEPLOY_STATE_DIR/deployed_version"' in deploy_sh
    assert "/var/lib/roxy-deploy" in deploy_sh
    alert_path = UNITS / "roxy-deploy-alert.path"
    assert one(alert_path, "PathChanged") == "/var/lib/roxy-deploy/last_failure.json"
    assert one(alert_path, "Unit") == "roxy-alert@deploy-failure.service"
    assert '"$DEPLOY_STATE_DIR/last_failure.json"' in deploy_sh
    alert_script = (DEPLOY / "tools" / "alert_on_failure.py").read_text()
    assert 'DEPLOY_FAILURE_INSTANCE = "deploy-failure"' in alert_script


def test_root_units_never_run_code_the_deploy_user_owns() -> None:
    """Plan 9.14: the deploy user owns /opt/roxy (releases, deploy.sh). A root unit executing anything there would
    hand the deploy user root, so root units run only files under /usr."""
    for path in UNIT_FILES:
        if path.suffix != ".service":
            continue
        user = (values(path, "User") or ["root"])[0]
        if user != "root" or values(path, "DynamicUser"):
            continue
        for key in ("ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecReload"):
            for command in values(path, key):
                program = command.lstrip("-@!+:").split()[0]
                assert program.startswith("/usr/"), f"{path.name} {key} runs {program} as root"
                for arg in command.split()[1:]:
                    assert not arg.startswith("/opt/"), f"{path.name} {key} passes {arg} to a root program"


@pytest.mark.parametrize("name", ["roxy-backup.service", "roxy-audit.service"])
def test_root_jobs_start_before_the_state_directory_exists(name: str) -> None:
    """Their timers run from install time, but /var/lib/roxy may not exist yet (a color creates it on its first
    start). A missing ReadWritePaths= entry fails the unit with status 226 and an OnFailure alert, so the state
    directory is optional ("-") for these jobs (install-system.sh also creates it)."""
    paths = " ".join(values(UNITS / name, "ReadWritePaths")).split()
    assert "-/var/lib/roxy" in paths
    assert "/var/lib/roxy" not in paths


def test_journald_drop_in() -> None:
    text = (UNITS / "journald-roxy.conf").read_text()
    assert "SystemMaxUse=2G" in text
    assert "MaxRetentionSec=30day" in text


# ------------------------------------------------------------------------------------ systemd-analyze


def analyze_root(tmp_path: Path) -> Path:
    """A private root: the system's own units, ours in /etc/systemd/system, stand-ins for every executable."""
    root = tmp_path / "root"
    shutil.copytree("/usr/lib/systemd/system", root / "usr" / "lib" / "systemd" / "system", symlinks=True)
    target = root / "etc" / "systemd" / "system"
    target.mkdir(parents=True)
    for path in UNIT_FILES:
        shutil.copy(path, target / path.name)
    for executable in (
        "/opt/roxy/releases/current-blue/.venv/bin/python",
        "/opt/roxy/releases/current-blue/.venv/bin/gunicorn",
        "/opt/roxy/releases/current-green/.venv/bin/python",
        "/opt/roxy/releases/current-green/.venv/bin/gunicorn",
        "/usr/local/lib/roxy/backup.sh",
        "/usr/local/sbin/roxy-switch-color",
        "/usr/bin/python3",
        "/bin/kill",
    ):
        stand_in = root / executable.lstrip("/")
        stand_in.parent.mkdir(parents=True, exist_ok=True)
        stand_in.write_text("#!/bin/sh\n")
        stand_in.chmod(0o755)
    return root


@pytest.fixture
def systemd_analyze() -> str:
    found = shutil.which("systemd-analyze")
    if found is None or not Path("/usr/lib/systemd/system").is_dir():
        pytest.skip("systemd-analyze is not available")
    return found


INSTANCES = [
    "roxy@blue.service",
    "roxy@green.service",
    "roxy-alert@roxy@blue.service.service",
    "roxy-backup.service",
    "roxy-backup.timer",
    "roxy-audit.service",
    "roxy-audit.timer",
    "roxy-audit.path",
    "roxy-deploy-alert.path",
    "roxy-boot.service",
]


def test_systemd_analyze_verify(systemd_analyze: str, tmp_path: Path) -> None:
    root = analyze_root(tmp_path)
    result = subprocess.run(
        [systemd_analyze, "verify", f"--root={root}", "--man=no", *INSTANCES],
        capture_output=True,
        text=True,
        cwd=root,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "", result.stdout + result.stderr
    assert result.stderr.strip() == "", result.stdout + result.stderr


def test_systemd_analyze_verify_catches_mistakes(systemd_analyze: str, tmp_path: Path) -> None:
    """Control: the same check reports a misspelled directive, so a clean result above means something."""
    root = analyze_root(tmp_path)
    unit = root / "etc" / "systemd" / "system" / "roxy@.service"
    unit.write_text(unit.read_text().replace("NoNewPrivileges=yes", "NoNewPrivilege=yes"))
    result = subprocess.run(
        [systemd_analyze, "verify", f"--root={root}", "--man=no", "roxy@blue.service"],
        capture_output=True,
        text=True,
        cwd=root,
        check=False,
    )
    assert "NoNewPrivilege" in result.stdout + result.stderr


def test_exposure_score_is_ok(systemd_analyze: str, tmp_path: Path) -> None:
    """Plan 17.1 target: `systemd-analyze security roxy@blue` 2.0 or lower ("OK")."""
    root = analyze_root(tmp_path)
    result = subprocess.run(
        [systemd_analyze, "security", "--offline=yes", f"--root={root}", "--no-pager", "roxy@blue.service"],
        capture_output=True,
        text=True,
        check=False,
    )
    match = re.search(r"Overall exposure level for roxy@blue\.service:\s*([0-9.]+)", result.stdout)
    assert match is not None, result.stdout + result.stderr
    assert float(match.group(1)) <= 2.0, result.stdout


# ------------------------------------------------------------------------------- the app under the sandbox

SECCOMP_KEYS = (
    "MemoryDenyWriteExecute",
    "SystemCallFilter",
    "SystemCallErrorNumber",
    "SystemCallArchitectures",
    "RestrictAddressFamilies",
    "NoNewPrivileges",
    "LockPersonality",
    "RestrictRealtime",
    "RestrictSUIDSGID",
    "RestrictNamespaces",
    "UMask",
)


def sandbox_properties() -> list[str]:
    """The roxy@.service settings a user manager can apply, read from the unit itself (so the test follows it),
    plus PrivateUsers and PrivateNetwork: inside, the app has loopback only and reaches no real system."""
    props = []
    for _, key, value, _ in parse_unit(ROXY):
        if key in SECCOMP_KEYS:
            props += ["-p", f"{key}={value}"]
    return [*props, "-p", "PrivateUsers=yes", "-p", "PrivateNetwork=yes"]


@pytest.fixture
def systemd_run() -> str:
    found = shutil.which("systemd-run")
    if found is None:
        pytest.skip("systemd-run is not available")
    probe = subprocess.run(
        [found, "--user", "--wait", "--collect", "--quiet", "-p", "PrivateUsers=yes", "/bin/true"],
        capture_output=True,
        check=False,
        timeout=60,
    )
    if probe.returncode != 0:
        pytest.skip("no usable systemd user manager here")
    return found


def test_libraries_work_under_memory_deny_write_execute(systemd_run: str) -> None:
    """Plan 17.1: verify MemoryDenyWriteExecute with uvloop, zstandard (and argon2-cffi, cryptography, ctypes
    callbacks); the control shows the filter is really active (a writable and executable mapping is refused)."""
    code = (
        "import asyncio, ctypes, mmap, json, uvloop, zstandard, argon2, regex\n"
        "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
        "out = {}\n"
        "out['argon2'] = argon2.PasswordHasher(time_cost=1, memory_cost=1024).hash('x').startswith('$argon2id')\n"
        "packed = zstandard.ZstdCompressor().compress(b'a' * 99)\n"
        "out['zstd'] = zstandard.ZstdDecompressor().decompress(packed) == b'a' * 99\n"
        "key = AESGCM.generate_key(bit_length=256)\n"
        "out['aesgcm'] = AESGCM(key).decrypt(b'0' * 12, AESGCM(key).encrypt(b'0' * 12, b'x', None), None) == b'x'\n"
        "async def main():\n    await asyncio.sleep(0)\n    return True\n"
        "out['uvloop'] = uvloop.run(main())\n"
        "out['regex'] = regex.match(r'(a+)+$', 'aaa', timeout=1) is not None\n"
        "out['ctypes'] = ctypes.CFUNCTYPE(ctypes.c_int)(lambda: 7)() == 7\n"
        "try:\n    mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)\n"
        "    out['wx_blocked'] = False\nexcept OSError:\n    out['wx_blocked'] = True\n"
        "print(json.dumps(out))\n"
    )
    result = subprocess.run(
        [
            systemd_run,
            "--user",
            "--wait",
            "--collect",
            "--quiet",
            "--pipe",
            *sandbox_properties(),
            str(REPO / ".venv" / "bin" / "python"),
            "-c",
            code,
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    out: dict[str, Any] = json.loads(result.stdout.strip().splitlines()[-1])
    assert out == {
        "argon2": True,
        "zstd": True,
        "aesgcm": True,
        "uvloop": True,
        "regex": True,
        "ctypes": True,
        "wx_blocked": True,
    }


@pytest.mark.multiprocess
def test_app_boots_under_the_unit_sandbox(systemd_run: str, tmp_path: Path, credentials_dir: Path) -> None:
    """The whole app (prestart, gunicorn, two uvicorn workers with uvloop and httptools) under the unit's
    sandbox settings: ready on the internal socket, internal endpoints 404 on TCP, clean stop."""
    work = tmp_path / "work"
    work.mkdir()
    credentials = tmp_path / "creds"
    shutil.copytree(credentials_dir, credentials)
    for path in [credentials, *credentials.iterdir()]:
        path.chmod(0o755 if path.is_dir() else 0o644)  # readable from inside the private user namespace
    result = subprocess.run(
        [
            systemd_run,
            "--user",
            "--wait",
            "--collect",
            "--quiet",
            "--pipe",
            *sandbox_properties(),
            f"--working-directory={REPO}",
            str(REPO / ".venv" / "bin" / "python"),
            str(Path(__file__).parent / "gunicorn_live_driver.py"),
            "sockets",
            str(work),
            str(credentials),
        ],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-3000:]
    out = json.loads(result.stdout.strip().splitlines()[-1])
    assert out["ready"] is True, out["log_tail"]
    assert out["internal_socket_mode"] == "0660"
    assert out["tcp_internal_version"] == 404
    assert out["stop_code"] == 0, out["log_tail"]
    assert "Traceback" not in out["log_tail"]
    assert os.path.exists(work / "state" / "control.db")
