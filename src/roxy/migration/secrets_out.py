"""Writing the bootstrap credential files (plan 9.8) from the v1 secret files: one credential, never a list.

What this is
    `write_credential_files(out_dir, secrets, report)` writes the systemd credential source files v2 loads with
    `LoadCredential=`: `roblox_credential`, `rotator_url`, `smtp_password`, `alert_emails`, and generates
    `credential_encryption_key`, `totp_encryption_key` and `ip_hash_key` when they do not exist yet.

Why it exists
    Plan 9.8 makes every secret a systemd credential file under `/etc/roxy/credentials/` (directory 0700, files
    0600), never an environment variable. Plan C1: exactly one Roblox credential; v1's token file was a list, so
    only its first non-empty line is kept, and the report and a log line say how many lines were discarded, each
    shown masked (an ellipsis and the last 6 characters, the v1 dashboard label). An existing file is never
    overwritten, because replacing the credential must be a deliberate act (C1), and regenerating a key would make
    every value encrypted with the old key unreadable. For the same reasons a file an earlier run wrote and the
    owner removed since (the C1 runbook removes the bootstrap cookie after a UI replacement) is never written again.

How it works
    Each file is written to a temporary name in the same directory with `O_CREAT | O_EXCL` and mode 0600,
    flushed with fsync, then linked into place with `os.link`, which fails instead of replacing a file that
    appeared meanwhile. A run killed between those two steps leaves the temporary file, which holds the secret, so
    every run first deletes temporary files with the names this module uses. The directory is created (or
    tightened) to 0700, and an existing file readable by others is set to 0600. Keys are 32 random bytes from
    `secrets`, written as 64 hex characters (the form `core/iphash.py decode_key_material` reads). Values are
    compared with what is already there, so a rerun reports "already present" and writes nothing.

What to read next
    `roxy/core/iphash.py` (how a key file is read) and REMAKE_PLAN.md sections 3 (C1) and 9.8.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import secrets
import stat
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlsplit

from roxy.core.iphash import decode_key_material
from roxy.core.redact import MASK, TOKEN_PREFIX, mask_token
from roxy.migration.report import MigrationReport
from roxy.migration.v1_tree import V1Secrets

log = logging.getLogger(__name__)

DIR_MODE: Final = 0o700
FILE_MODE: Final = 0o600
VALUE_NAMES: Final[tuple[str, ...]] = ("roblox_credential", "rotator_url", "smtp_password", "alert_emails")
KEY_NAMES: Final[tuple[str, ...]] = ("credential_encryption_key", "totp_encryption_key", "ip_hash_key")
KEY_BYTES: Final = 32
MIN_KEY_BYTES: Final = 16
_TEMPORARY = re.compile(r"\.(?:" + "|".join(map(re.escape, (*VALUE_NAMES, *KEY_NAMES))) + r")\.[0-9a-f]{8}\.tmp")
"""The temporary names `_write_new` uses: `.<file name>.<8 hex characters>.tmp`."""

WRITTEN: Final = "written"
GENERATED: Final = "generated"
PRESENT: Final = "already_present"
KEPT_DIFFERENT: Final = "kept_existing_different"
REMOVED_AFTER_IMPORT: Final = "removed_after_import"
NO_SOURCE: Final = "no_source"
HANDLED: Final = frozenset({WRITTEN, GENERATED, PRESENT, KEPT_DIFFERENT, REMOVED_AFTER_IMPORT})
"""Statuses that put the file name in the import ledger (a later run never writes that name again)."""


def masked_email(address: str | None) -> str:
    """`o***@example.invalid`: enough for the owner to recognize the address, not enough to harvest it."""
    if not address or "@" not in address:
        return MASK if address else ""
    local, _, domain = address.partition("@")
    return f"{local[:1]}***@{domain}"


def masked_host(url: str | None) -> str:
    """Scheme, host and port of a proxy URL (the user name, password and path are dropped)."""
    if not url:
        return ""
    try:
        parts = urlsplit(url.strip())
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return MASK
    if not parts.scheme or not host:
        return MASK
    return f"{parts.scheme}://{host}{f':{port}' if port is not None else ''}"


def _secure_dir(path: Path, report: MigrationReport) -> None:
    if not path.exists():
        path.mkdir(parents=True, mode=DIR_MODE)
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode != DIR_MODE:
            path.chmod(DIR_MODE)
            if mode & 0o077:
                report.warn(f"the credentials directory was mode {mode:o}; it is now {DIR_MODE:o}")
    except OSError as exc:
        report.error(f"could not set the credentials directory to mode {DIR_MODE:o} ({type(exc).__name__})")


def _remove_stale_temporaries(out_dir: Path, report: MigrationReport) -> None:
    """Delete temporary files a killed run left (they hold a secret; review finding 8). Only this module's own
    temporary names are touched, and a link is removed itself, never followed."""
    removed: list[str] = []
    try:
        with os.scandir(out_dir) as entries:
            stale = [entry for entry in entries if _TEMPORARY.fullmatch(entry.name)]
    except OSError:
        return
    for entry in stale:
        if entry.is_dir(follow_symlinks=False):
            continue
        try:
            os.unlink(entry.path)
            removed.append(entry.name)
        except FileNotFoundError:
            continue
        except OSError as exc:
            report.error(f"could not remove the temporary file {entry.name} ({type(exc).__name__}); remove it by hand")
    if removed:
        report.changed(len(removed))
        report.warn(
            f"removed {len(removed)} temporary file(s) left in the credentials directory by an interrupted run: "
            + ", ".join(sorted(removed))
        )


def _tighten(path: Path, report: MigrationReport) -> None:
    """An existing credential file readable by the group or others is set to 0600, with a warning (finding 10)."""
    try:
        info = path.lstat()
    except OSError:
        return
    if stat.S_ISLNK(info.st_mode):
        report.warn(f"{path.name} is a symbolic link; its mode was not checked. Make it a regular file, mode 600")
        return
    mode = stat.S_IMODE(info.st_mode)
    if not mode & 0o077:
        return
    try:
        os.chmod(path, FILE_MODE)
    except OSError as exc:
        report.error(f"{path.name} is mode {mode:o} and could not be set to {FILE_MODE:o} ({type(exc).__name__})")
        return
    report.warn(f"{path.name} was mode {mode:o}; it is now {FILE_MODE:o}")


def _write_new(path: Path, content: str) -> bool:
    """Create `path` with `content` (mode 0600) unless it exists. Returns False when it already existed."""
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, FILE_MODE)
    try:
        try:
            os.fchmod(fd, FILE_MODE)  # the umask can only remove bits; set the mode exactly anyway
            data = memoryview(content.encode("utf-8"))
            while data:  # os.write may write less than asked
                data = data[os.write(fd, data) :]
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.link(temporary, path)  # atomic and never replaces an existing file
        except FileExistsError:
            return False
        return True
    finally:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()


def _existing(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except (OSError, UnicodeDecodeError):
        return "\0unreadable"


def _place(path: Path, content: str, report: MigrationReport) -> str:
    """Write one value file, or say why not."""
    current = _existing(path)
    if current is not None:
        _tighten(path, report)
        return PRESENT if current.strip() == content.strip() else KEPT_DIFFERENT
    if not _write_new(path, content):
        return PRESENT if (_existing(path) or "").strip() == content.strip() else KEPT_DIFFERENT
    report.changed()
    return WRITTEN


def _removed_after_import(path: Path, previously: frozenset[str]) -> bool:
    """True when an earlier run wrote this file and it is gone now (a dangling link counts as present)."""
    return path.name in previously and not os.path.lexists(path)


def _removed_item(name: str, report: MigrationReport) -> dict[str, Any]:
    if name == "roblox_credential":
        why = "the C1 runbook removes the bootstrap cookie after a UI replacement, so it is not written again"
    elif name in KEY_NAMES:
        why = (
            "not generated again: a new key cannot read what the old one encrypted. Restore it from a backup, or "
            "create one by hand if nothing was encrypted with it"
        )
        report.warn(f"{name} was generated by an earlier run and is missing now; v2 needs it (see the report)")
    else:
        why = "not written again; restore it by hand if v2 should use it"
    return {
        "name": name,
        "status": REMOVED_AFTER_IMPORT,
        "detail": f"written by an earlier run and removed since; {why}",
    }


def _log_discarded(count: int, masked: list[str]) -> None:
    # Plan C1: "logs (masked) that others were discarded" (review finding 12). Only the v1 dashboard label
    # (an ellipsis and the last 6 characters) leaves the token file.
    log.warning("v1_credentials_discarded", extra={"fields": {"count": count, "masked": masked}})


def write_credential_files(
    out_dir: Path, v1: V1Secrets, report: MigrationReport, *, previously: frozenset[str] = frozenset()
) -> set[str]:
    """Write every credential file plan 9.8 lists that the v1 tree can provide, plus the three keys.

    `previously` names the files an earlier run handled in this directory (the import ledger): one of them that is
    missing now was removed on purpose and is reported, not written again. Returns the names this run handled.
    """
    _secure_dir(out_dir, report)
    _remove_stale_temporaries(out_dir, report)
    items: list[dict[str, Any]] = []

    def place(name: str, content: str, detail: str) -> dict[str, Any]:
        path = out_dir / name
        if _removed_after_import(path, previously):
            return _removed_item(name, report)
        return {"name": name, "status": _place(path, content, report), "detail": detail}

    # The Roblox credential (C1): the first non-empty line only.
    if v1.tokens:
        first = v1.tokens[0]
        discarded = [mask_token(line) for line in v1.tokens[1:]]
        detail = f"the first non-empty line of the token file ({mask_token(first)})"
        if discarded:
            detail += f"; {len(discarded)} more line(s) discarded (plan C1: one credential only): " + ", ".join(
                discarded
            )
            report.warn(
                f"the v1 token file had {len(v1.tokens)} credentials; only the first was kept (plan C1). Discarded: "
                + ", ".join(discarded)
            )
            _log_discarded(len(discarded), discarded)
        if not first.startswith(TOKEN_PREFIX):
            report.warn("the kept credential does not start with Roblox's warning prefix; check it is a cookie value")
        item = place("roblox_credential", first, detail)
        item.update(masked=mask_token(first), discarded_lines=len(discarded), discarded_masked=discarded)
    else:
        item = {"name": "roblox_credential", "status": NO_SOURCE, "detail": "the v1 token file is missing or empty"}
        report.warn("no Roblox credential was found in the v1 token file")
    items.append(item)

    # The rotator URL (from rotate_proxy.txt, or from ROXY_ROTATE_PROXY as v1 read it first).
    if v1.rotator_url:
        source = v1.rotator_source or "rotate_proxy.txt"
        items.append(place("rotator_url", v1.rotator_url, f"from {source} ({masked_host(v1.rotator_url)})"))
    else:
        items.append(
            {
                "name": "rotator_url",
                "status": NO_SOURCE,
                "detail": "no rotate_proxy.txt and no ROXY_ROTATE_PROXY (rotation was off in v1)",
            }
        )

    # The SMTP app password.
    if v1.app_password:
        items.append(place("smtp_password", v1.app_password, "from the app password file"))
    else:
        items.append(
            {"name": "smtp_password", "status": NO_SOURCE, "detail": "the app password file is missing or empty"}
        )

    # Alert addresses: `to:` and `from:` lines (plan 9.8).
    if v1.email_to:
        lines = [f"to: {v1.email_to}"]
        if v1.email_from:
            lines.append(f"from: {v1.email_from}")
        else:
            report.warn("the v1 emails file has no second line (the sender); alert_emails has a recipient only")
        detail = f"to {masked_email(v1.email_to)}, from {masked_email(v1.email_from) or 'n/a'}"
        items.append(place("alert_emails", "\n".join(lines) + "\n", detail))
    else:
        items.append({"name": "alert_emails", "status": NO_SOURCE, "detail": "the v1 emails file is missing or empty"})

    # Keys: generated only when absent; an existing key is never replaced.
    for name in KEY_NAMES:
        path = out_dir / name
        if _removed_after_import(path, previously):
            items.append(_removed_item(name, report))
            continue
        current = _existing(path)
        if current is not None:
            _tighten(path, report)
            usable = len(decode_key_material(current.encode("utf-8", "replace"))) >= MIN_KEY_BYTES
            status = PRESENT if usable else KEPT_DIFFERENT
            detail = "kept the existing key" if usable else "an existing file is not a usable key; it was not replaced"
            if not usable:
                report.warn(f"{name} exists but is not a usable 32 byte key; fix it by hand")
            items.append({"name": name, "status": status, "detail": detail})
            continue
        if _write_new(path, secrets.token_hex(KEY_BYTES)):
            report.changed()
            items.append({"name": name, "status": GENERATED, "detail": "32 random bytes, written as 64 hex characters"})
        else:
            items.append({"name": name, "status": PRESENT, "detail": "appeared while the migrator ran; kept"})

    for entry in items:
        if entry["status"] == KEPT_DIFFERENT and entry["name"] not in KEY_NAMES:
            entry["detail"] = entry.get("detail", "") + "; a different file already exists and was not replaced"
            why = (
                " (plan C1: replacing the credential is a deliberate act)"
                if entry["name"] == "roblox_credential"
                else ""
            )
            report.warn(f"{entry['name']} already exists with a different value; it was not replaced{why}")
    _fsync_dir(out_dir)
    report.credentials.extend(items)
    return {entry["name"] for entry in items if entry["status"] in HANDLED}


def _fsync_dir(path: Path) -> None:
    with contextlib.suppress(OSError):
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


__all__ = ["KEY_NAMES", "VALUE_NAMES", "masked_email", "masked_host", "write_credential_files"]
