#!/usr/bin/python3 -I
"""roxy-audit.py: the root permission audit that feeds health check H-SECRETS-PERMS (plan 17.1).

What this is
    Installed as /usr/local/lib/roxy/roxy-audit.py and run as root by roxy-audit.service (every 6 hours, and after
    each deploy through roxy-audit.path). It checks the owner, group and mode of every security-relevant path on
    the server, records the `systemd-analyze security` exposure score of both Roxy colors, and writes the result to
    /var/lib/roxy/audit/perms.json (0640 root:roxy), where the app's System page and health check read it.

Why it exists
    The app runs unprivileged and sandboxed (ProtectSystem=strict, no capabilities), so it cannot see whether
    /etc/roxy/credentials is still 0700 or whether someone made a backup world-readable. Root can, but root code
    should be small and boring: this script reads only METADATA (lstat and directory listings), never a file's
    contents, so it can run as root every few hours without ever touching a secret. The report holds file names,
    modes and owners, and whether a credential file is empty (empty means "not configured"), never sizes or
    contents.

How it works
    A table of expectations (path, kind, owner, group, the exact mode or the bits that must be clear) is checked
    with lstat. A symlink where a file is expected is a finding (a link can point anywhere). Globs cover the
    credential files and the database files with their -wal and -shm companions. The exposure scores come from
    `systemd-analyze security --no-pager roxy@blue.service` (the line "Overall exposure level"); the plan's target
    is 2.0 or lower.
    Writing the report is the one place root writes into a tree another account controls: /var/lib/roxy belongs
    to the roxy user, who could plant a link where root is about to write (and so make root overwrite any file).
    So the report directory audit/ is root's own (root:roxy 0750, which the roxy user can read but not change),
    opened with O_NOFOLLOW relative to its parent and accepted only when this process owns it and nobody else can
    write to it; anything else found under that name is renamed aside (a rename moves a link, never its target)
    and a fresh directory is made. The report goes to a new random name (O_CREAT | O_EXCL | O_NOFOLLOW), gets its
    mode and group through the open file, and is renamed over perms.json. Before the first color has started the
    state directory may not exist; then no report is written (the unit's ReadWritePaths entry is optional).
    All paths come from a `Layout`, and owners are names looked up at run time, so tests audit a temporary tree
    with their own user.

What to read next
    deploy/systemd/roxy-audit.service, deploy/README.md (the expected layout, plan 17.3), then the H-SECRETS-PERMS
    health check in src/roxy/health.
"""

from __future__ import annotations

import argparse
import contextlib
import grp
import json
import os
import pwd
import re
import secrets
import stat
import subprocess
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def say(text: str) -> None:
    """One line on stdout (the journal or the deploy log). A function, not print, so output is explicit."""
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


def warn(text: str) -> None:
    """One line on stderr."""
    sys.stderr.write(text + "\n")
    sys.stderr.flush()


EXPOSURE_RE = re.compile(r"Overall exposure level for (\S+):\s*([0-9.]+)\s+(\w+)")
EXPOSURE_TARGET = 2.0


@dataclass(frozen=True)
class Expect:
    """What one path must look like. `mode` is exact; `forbidden` lists bits that must be clear."""

    path: str
    kind: str  # "file", "dir" or "any"
    owner: str | None = None
    group: str | None = None
    mode: int | None = None
    forbidden: int = 0o002
    required: bool = True
    note: str = ""


@dataclass(frozen=True)
class Layout:
    """The paths to audit and the account names, production values by default."""

    root: Path = Path("/")
    output: Path = Path("/var/lib/roxy/audit/perms.json")
    report_group: str = "roxy"
    service_user: str = "roxy"
    service_group: str = "roxy"
    admin_user: str = "root"
    admin_group: str = "root"
    deploy_user: str = "roxy-deploy"
    units: tuple[str, ...] = ("roxy@blue.service", "roxy@green.service")
    systemd_analyze: tuple[str, ...] = ("systemd-analyze",)
    extra: tuple[Expect, ...] = field(default_factory=tuple)

    def expectations(self) -> list[Expect]:
        r, s, sg = self.admin_user, self.service_user, self.service_group
        return [
            Expect("/etc/roxy", "dir", r, sg, forbidden=0o022, note="config directory"),
            Expect("/etc/roxy/credentials", "dir", r, None, 0o700, note="systemd credential sources (plan 9.8)"),
            Expect("/etc/roxy/credentials/*", "file", r, None, 0o600, note="one secret per file"),
            Expect("/etc/roxy/roxy.env", "file", r, sg, 0o640, note="shared non-secret config"),
            Expect("/etc/roxy/blue.env", "file", r, sg, 0o640, note="blue color config"),
            Expect("/etc/roxy/green.env", "file", r, sg, 0o640, note="green color config"),
            Expect("/etc/roxy/nginx-hints.env", "file", r, None, forbidden=0o022, required=False),
            Expect("/var/lib/roxy", "dir", s, sg, 0o750, note="state directory (StateDirectoryMode)"),
            # Not required: this audit creates it when it writes its first report, after these checks ran.
            Expect("/var/lib/roxy/audit", "dir", r, sg, 0o750, required=False, note="root's report directory"),
            Expect("/var/lib/roxy/*.db", "file", s, sg, forbidden=0o027, note="databases"),
            Expect("/var/lib/roxy/*.db-wal", "file", s, sg, forbidden=0o027, required=False),
            Expect("/var/lib/roxy/*.db-shm", "file", s, sg, forbidden=0o027, required=False),
            Expect("/var/lib/roxy/snapshots", "dir", s, sg, forbidden=0o027, required=False),
            Expect("/var/backups/roxy", "dir", r, None, 0o700, required=False, note="backups (plan 17.3)"),
            Expect("/usr/local/sbin/roxy-nginx-apply", "file", r, r, 0o755, note="root wrapper (plan 9.14)"),
            Expect("/usr/local/sbin/roxy-switch-color", "file", r, r, 0o755, note="root wrapper (plan 9.14)"),
            Expect("/usr/local/lib/roxy", "dir", r, r, 0o755, note="root-run tools"),
            Expect("/usr/local/lib/roxy/*", "file", r, r, 0o755, note="root-run tools"),
            Expect("/etc/sudoers.d/roxy-deploy", "file", r, r, 0o440, note="deploy sudo rules"),
            Expect("/etc/nginx/roxy-upstream-blue.conf", "file", r, None, forbidden=0o022, required=False),
            Expect("/etc/nginx/roxy-upstream-green.conf", "file", r, None, forbidden=0o022, required=False),
            Expect("/opt/roxy/releases", "dir", self.deploy_user, None, forbidden=0o022, required=False),
            *self.extra,
        ]


def name_of_uid(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def name_of_gid(gid: int) -> str:
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def check_path(path: Path, expect: Expect) -> dict[str, Any]:
    """One finding for one path: what it is, what was expected, and the problems (empty list = fine)."""
    entry: dict[str, Any] = {"path": str(path), "expected": describe(expect), "problems": []}
    try:
        info = path.lstat()
    except FileNotFoundError:
        entry["exists"] = False
        if expect.required:
            entry["problems"].append("missing")
        return entry
    except PermissionError:
        entry["exists"] = None
        entry["problems"].append("cannot read metadata (run as root)")
        return entry
    entry["exists"] = True
    mode = stat.S_IMODE(info.st_mode)
    owner, group = name_of_uid(info.st_uid), name_of_gid(info.st_gid)
    entry.update({"mode": f"{mode:04o}", "owner": owner, "group": group})
    problems: list[str] = entry["problems"]
    if stat.S_ISLNK(info.st_mode):
        problems.append("is a symlink")
    elif expect.kind == "file" and not stat.S_ISREG(info.st_mode):
        problems.append("is not a regular file")
    elif expect.kind == "dir" and not stat.S_ISDIR(info.st_mode):
        problems.append("is not a directory")
    if expect.owner is not None and owner != expect.owner:
        problems.append(f"owner is {owner}, expected {expect.owner}")
    if expect.group is not None and group != expect.group:
        problems.append(f"group is {group}, expected {expect.group}")
    if expect.mode is not None and mode != expect.mode:
        problems.append(f"mode is {mode:04o}, expected {expect.mode:04o}")
    if mode & expect.forbidden:
        problems.append(f"mode {mode:04o} grants bits {mode & expect.forbidden:04o} that must be clear")
    if expect.path.startswith("/etc/roxy/credentials/") and stat.S_ISREG(info.st_mode):
        entry["empty"] = info.st_size == 0  # empty means "not configured"; the size itself is never recorded
    return entry


def describe(expect: Expect) -> str:
    parts = [expect.kind]
    if expect.owner:
        parts.append(f"owner {expect.owner}")
    if expect.group:
        parts.append(f"group {expect.group}")
    if expect.mode is not None:
        parts.append(f"mode {expect.mode:04o}")
    elif expect.forbidden:
        parts.append(f"no {expect.forbidden:04o} bits")
    return ", ".join(parts)


def audit_paths(layout: Layout) -> list[dict[str, Any]]:
    """Check every expectation; globs expand to every match (a glob with no match is a finding when required)."""
    findings: list[dict[str, Any]] = []
    for expect in layout.expectations():
        relative = expect.path.lstrip("/")
        if any(ch in relative for ch in "*?["):
            matches = sorted(layout.root.glob(relative))
            if not matches:
                entry: dict[str, Any] = {
                    "path": expect.path,
                    "expected": describe(expect),
                    "exists": False,
                    "problems": [],
                }
                if expect.required:
                    entry["problems"].append("no matching files")
                findings.append(entry)
            for match in matches:
                found = check_path(match, expect)
                found["path"] = "/" + str(match.relative_to(layout.root))
                findings.append(found)
        else:
            found = check_path(layout.root / relative, expect)
            found["path"] = expect.path
            findings.append(found)
    for finding in findings:
        finding["ok"] = not finding["problems"]
    return findings


def exposure_scores(layout: Layout) -> dict[str, Any]:
    """`systemd-analyze security` per unit: {unit: {"score": float, "rating": str, "ok": bool}} or an error."""
    scores: dict[str, Any] = {}
    for unit in layout.units:
        try:
            result = subprocess.run(  # noqa: S603
                [*layout.systemd_analyze, "security", "--no-pager", unit],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            scores[unit] = {"error": str(exc)}
            continue
        match = EXPOSURE_RE.search(result.stdout + result.stderr)
        if match is None:
            scores[unit] = {"error": (result.stderr.strip() or "no exposure line")[:300]}
            continue
        score = float(match.group(2))
        scores[unit] = {"score": score, "rating": match.group(3), "ok": score <= EXPOSURE_TARGET}
    return scores


REPORT_DIR_MODE = 0o750
REPORT_FILE_MODE = 0o640


def give_group(fd: int, group: str) -> None:
    """chown the open file or directory to `group`, keeping its owner. Tests run unprivileged (no such group, or
    no right to chown); production runs as root with CAP_CHOWN."""
    with contextlib.suppress(KeyError, PermissionError):
        os.fchown(fd, -1, grp.getgrnam(group).gr_gid)


def trusted_dir(fd: int) -> bool:
    """A real directory that this process owns and that nobody else can write to (so nobody can plant in it)."""
    info = os.fstat(fd)
    return stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o022


def open_report_dir(directory: Path, group: str) -> int | None:
    """Open (or make) the report directory without following a link, and return its descriptor; None when its
    parent (the state directory) does not exist yet. Whatever else sits under that name is renamed aside."""
    try:
        parent = os.open(directory.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    try:
        for _attempt in range(3):
            try:
                fd = os.open(directory.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            except FileNotFoundError:
                os.mkdir(directory.name, 0o700, dir_fd=parent)
                continue
            except OSError:  # a link (ELOOP) or not a directory (ENOTDIR): never followed, moved aside below
                fd = -1
            if fd >= 0 and trusted_dir(fd):
                os.fchmod(fd, REPORT_DIR_MODE)
                give_group(fd, group)
                return fd
            if fd >= 0:
                os.close(fd)
            aside = f"{directory.name}.untrusted-{time.strftime('%Y%m%dT%H%M%S')}-{secrets.token_hex(3)}"
            os.rename(directory.name, aside, src_dir_fd=parent, dst_dir_fd=parent)
            warn(f"roxy-audit: {directory} was not a directory only root controls; moved it to {aside}")
        raise OSError(f"cannot make a trusted report directory at {directory}")
    finally:
        os.close(parent)


def write_report(layout: Layout, report: dict[str, Any]) -> bool:
    """Write perms.json atomically, 0640, group roxy (when that group exists), never through a link. Returns False
    when the state directory does not exist yet (nothing is written)."""
    output = layout.output
    directory = open_report_dir(output.parent, layout.report_group)
    if directory is None:
        return False
    try:
        tmp = f".{output.name}.{secrets.token_hex(8)}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(tmp, flags, 0o600, dir_fd=directory)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write((json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8"))
                handle.flush()
                os.fchmod(handle.fileno(), REPORT_FILE_MODE)
                give_group(handle.fileno(), layout.report_group)
                os.fsync(handle.fileno())
            # rename() replaces whatever is at perms.json (a planted link included) without following it.
            os.replace(tmp, output.name, src_dir_fd=directory, dst_dir_fd=directory)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp, dir_fd=directory)
            raise
    finally:
        os.close(directory)
    return True


def run_audit(layout: Layout, *, with_scores: bool = True) -> dict[str, Any]:
    findings = audit_paths(layout)
    scores = exposure_scores(layout) if with_scores else {}
    problems = sum(1 for finding in findings if not finding["ok"])
    score_problems = sum(1 for value in scores.values() if not value.get("ok", False))
    return {
        "schema": "roxy.perms/1",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "ok": problems == 0 and score_problems == 0,
        "problem_count": problems,
        "findings": findings,
        "exposure": scores,
        "exposure_target": EXPOSURE_TARGET,
    }


def main(argv: Sequence[str] | None = None, layout: Layout | None = None) -> int:
    parser = argparse.ArgumentParser(prog="roxy-audit.py", description="Audit Roxy file permissions (metadata only).")
    parser.add_argument("--no-scores", action="store_true", help="skip systemd-analyze security")
    parser.add_argument("--print", action="store_true", help="also print the report")
    args = parser.parse_args(argv)
    layout = layout or Layout()
    report = run_audit(layout, with_scores=not args.no_scores)
    written = write_report(layout, report)
    if args.print:
        say(json.dumps(report, indent=2, sort_keys=True))
    if written:
        say(f"roxy-audit: {report['problem_count']} problem(s); report in {layout.output}")
    else:
        # Before the first deploy has started a color: nothing reads a report yet, and this is not a failure.
        say(
            f"roxy-audit: {report['problem_count']} problem(s); {layout.output.parent.parent} does not exist yet "
            "(no color has started), so no report written"
        )
    return 0  # findings are data for the app; only a crash (unexpected exception) fails the unit


if __name__ == "__main__":
    sys.exit(main())
