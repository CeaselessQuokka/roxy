"""Reading a v1 `/etc/roxy` tree: the control plane, the statistics and the secret files, read only.

What this is
    `read_v1_tree(root)` returns a `V1Tree`: the v1 `Runtime` blob (settings, rules, pause state), the
    `Diagnostics` statistics, the secret values from the files named in `files.txt`, and one `inputs` line per
    file for the report. `V1Secrets.secret_values()` lists every secret read, for the report scrubber.
    `V1Tree.has_v1_files` says whether the root holds any v1 file at all (a wrong `--v1-root` holds none).

Why it exists
    Plan 18.3 and the v1 notes (settings.md sections 8, 9 and 13). The migrator must see exactly what v1 saw,
    including v1's fallbacks: a missing or broken `roxy_state.json` made v1 load the legacy `Runtime` blob from
    `roxy_data.json`, and a broken data file made it read `roxy_data.json.bak`. It must also never change a v1
    file (v1 renamed a corrupt data file to `.corrupt-<time>`; the migrator only reads), never read outside the
    given root (an absolute path in files.txt is re-rooted by its file name, so a copied tree can never make the
    migrator read the live `/etc/roxy`), and never load an unbounded file into memory (plan P9).

How it works
    Every read goes through `_read_bytes`, which refuses paths that resolve outside the root (symlinks included)
    and files over a size limit. JSON is parsed with the standard library; a parse failure is a report line, never
    an exception. Secret files are decoded as UTF-8 and split the way v1 split them (`auth.py`): the admin file
    into username, password, HMAC key and session secret; the token file into its non-empty lines; the emails
    file into the recipient and the sender. Secret values never appear in `inputs`, only counts.

    The v1 path variables (plan 15.3 L): v1 read the rotator URL from `ROXY_ROTATE_PROXY` before any file, and the
    file from `ROXY_ROTATE_PROXY_FILE`; both are read from the migrator's environment, as v1 did. The URL holds a
    password, so it is never a command line argument. `ROXY_STATE_FILE` and `ROXY_DATA_FILE` come as the explicit
    `--v1-state-file` and `--v1-data-file` arguments instead: a developer shell often has them set for a sandbox,
    and silently reading another data file would be a bad surprise. Every path named this way is read inside the
    root: an absolute path outside it is read by its file name inside the root, like a files.txt line.

What to read next
    `roxy/migration/runner.py` (how the tree is used) and `.remake/v1notes/settings.md` section 13.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

MAX_JSON_BYTES: Final = 64 * 1024 * 1024  # v1 quarantined data files over 24 MiB; leave room, stay bounded
MAX_SECRET_FILE_BYTES: Final = 1024 * 1024
MAX_LISTING_BYTES: Final = 64 * 1024

SECRET_ROLES: Final[tuple[str, ...]] = ("admin_credentials", "app_password", "tokens", "emails")
CONVENTIONAL_NAMES: Final[dict[str, str]] = {
    "admin_credentials": "admin_credentials.txt",
    "app_password": "app_password.txt",
    "tokens": "auth_tokens.txt",
    "emails": "emails.txt",
}
STATE_FILE: Final = "roxy_state.json"
DATA_FILE: Final = "roxy_data.json"
ROTATOR_FILE: Final = "rotate_proxy.txt"
ROTATOR_ENV: Final = "ROXY_ROTATE_PROXY"
ROTATOR_FILE_ENV: Final = "ROXY_ROTATE_PROXY_FILE"
V1_FILE_ROLES: Final = frozenset({"state", "data", "data_backup", "rotator_url", *SECRET_ROLES})
"""Inputs that are v1 files; a root where none of them exists is not a v1 tree."""
RUNTIME_STATE_FILES: Final[tuple[str, ...]] = (
    "roxy_routing.json",
    "roxy_throttle.json",
    "roxy_coord.json",
    "roxy_tarpit.json",
    "roxy_workers.json",
    "roxy_capture.json",
)
"""v1's per-worker coordination files: live counters and leases, disposable, never migrated."""


class V1ReadError(Exception):
    """A file could not be read safely; the message is safe to show (it never holds file contents)."""


@dataclass
class V1Secrets:
    """The secret values of the v1 tree. Never logged, never put in the report (only counts and masks)."""

    admin_username: str | None = None
    admin_password: str | None = None
    admin_line_count: int = 0
    hmac_key: str | None = None
    session_secret: str | None = None
    app_password: str | None = None
    tokens: list[str] = field(default_factory=list)
    rotator_url: str | None = None
    rotator_source: str = ""  # where the URL came from, for the report (a file name or the variable)
    other_rotator_urls: list[str] = field(default_factory=list)  # read but not used (the variable won)
    email_to: str | None = None
    email_from: str | None = None

    def _rotator_urls(self) -> list[str]:
        return [url for url in (self.rotator_url, *self.other_rotator_urls) if url]

    def secret_values(self) -> list[str]:
        """Every secret value read (for the report scrubber); the username and addresses are not secrets."""
        values = [self.admin_password, self.hmac_key, self.session_secret, self.app_password]
        values += self.tokens
        for url in self._rotator_urls():
            values += [url, *_userinfo_secrets(url)]
        return [value for value in values if value]

    def piece_values(self) -> list[str]:
        """The secrets whose pieces are secret too (not the whole proxy URL: its scheme and host are not secret)."""
        values = [self.admin_password, self.hmac_key, self.session_secret, self.app_password]
        values += [_userinfo_secrets(url)[-1] for url in self._rotator_urls() if _userinfo_secrets(url)]
        return [value for value in values if value]


def _userinfo_secrets(url: str) -> list[str]:
    """`user:password` and `password` of a proxy URL (empty when it has no user part)."""
    if "@" not in url:
        return []
    userinfo = url.split("://", 1)[-1].rsplit("@", 1)[0]
    return [userinfo, *userinfo.split(":", 1)[1:]]


@dataclass
class V1Tree:
    """What the migrator knows about one v1 tree after reading it."""

    root: Path
    inputs: list[dict[str, Any]] = field(default_factory=list)
    runtime: dict[str, Any] = field(default_factory=dict)
    runtime_source: str = "none"
    legacy_runtime_ignored: bool = False
    diagnostics: dict[str, Any] = field(default_factory=dict)
    statistics_source: str = "none"
    data_bytes: int = 0
    secrets: V1Secrets = field(default_factory=V1Secrets)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    runtime_files: list[str] = field(default_factory=list)
    cache_files: int = 0
    content_hashes: dict[str, str] = field(default_factory=dict)  # non-secret files only

    @property
    def has_v1_files(self) -> bool:
        """Whether any v1 state, data or secret file exists under the root (an environment variable alone does not
        count). A root without one is the wrong directory, not a v1 install that never saved anything: v1 could
        not even start without its four secret files."""
        return any(entry.get("found") and entry.get("role") in V1_FILE_ROLES for entry in self.inputs)


def _inside(root: Path, path: Path) -> bool:
    try:
        return path.resolve().is_relative_to(root.resolve())
    except (OSError, RuntimeError):
        return False


def _read_bytes(root: Path, path: Path, limit: int) -> bytes | None:
    """The bytes of `path`, or None when it does not exist. Raises V1ReadError when reading would be unsafe."""
    if not _inside(root, path):
        raise V1ReadError(f"{path.name} resolves outside the v1 root; it was not read")
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise V1ReadError(f"{path.name} could not be read ({type(exc).__name__})") from None
    if not path.is_file():
        raise V1ReadError(f"{path.name} is not a regular file")
    if size > limit:
        raise V1ReadError(f"{path.name} is larger than {limit} bytes; it was not read")
    try:
        # O_NOFOLLOW is not needed: the resolved path was checked above, and the file is only read.
        with path.open("rb") as handle:
            return handle.read(limit + 1)[:limit]
    except OSError as exc:
        raise V1ReadError(f"{path.name} could not be read ({type(exc).__name__})") from None


def _relative(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _load_json(tree: V1Tree, role: str, path: Path) -> tuple[Any, str | None]:
    """(parsed JSON or None, problem text or None). Records an `inputs` line either way."""
    entry: dict[str, Any] = {"role": role, "path": _relative(tree.root, path), "found": False}
    tree.inputs.append(entry)
    try:
        raw = _read_bytes(tree.root, path, MAX_JSON_BYTES)
    except V1ReadError as exc:
        entry["detail"] = str(exc)
        return None, str(exc)
    if raw is None:
        entry["detail"] = "missing"
        return None, "missing"
    entry["found"] = True
    entry["bytes"] = len(raw)
    digest = hashlib.sha256(raw).hexdigest()
    entry["sha256"] = digest
    tree.content_hashes[entry["path"]] = digest
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        problem = f"not valid JSON ({type(exc).__name__})"
        entry["detail"] = problem
        return None, problem
    entry["detail"] = "read"
    return data, None


def _read_listing(tree: V1Tree) -> list[str]:
    path = tree.root / "files.txt"
    entry: dict[str, Any] = {"role": "files_listing", "path": "files.txt", "found": False}
    tree.inputs.append(entry)
    try:
        raw = _read_bytes(tree.root, path, MAX_LISTING_BYTES)
    except V1ReadError as exc:
        entry["detail"] = str(exc)
        tree.warnings.append(f"files.txt: {exc}; using the conventional file names")
        return []
    if raw is None:
        entry["detail"] = "missing; the conventional file names were used"
        tree.warnings.append("files.txt is missing; using the conventional file names (auth_tokens.txt and so on)")
        return []
    entry["found"] = True
    lines = raw.decode("utf-8", "replace").strip().splitlines()  # v1 auth.py: read().strip().splitlines()
    entry["detail"] = f"{len(lines)} file name(s)"
    if len(lines) < len(SECRET_ROLES):
        tree.warnings.append(
            f"files.txt lists {len(lines)} file(s); v1 needed 4. The missing ones use the conventional names."
        )
    return lines


def _rerooted(tree: V1Tree, value: str, source: str) -> Path:
    """The file a v1 path setting (`source`: a files.txt line, a variable, an argument) names, inside the root.

    A relative path is taken under the root (and still refused by `_read_bytes` if `..` leads out of it). An
    absolute path outside the root is read by its file name inside the root, so a copied tree, or a value copied
    from the v1 service, can never make the migrator read the live `/etc/roxy`.
    """
    listed = Path(value)
    if not listed.is_absolute():
        return tree.root / value
    if _inside(tree.root, listed):
        return listed
    tree.warnings.append(
        f"{source} names an absolute path outside the v1 root; read {listed.name} from the v1 root instead (the "
        "migrator never reads outside --v1-root)"
    )
    return tree.root / listed.name


def _resolve_listed(tree: V1Tree, role: str, line: str | None) -> Path:
    """Where the file for `role` is: the files.txt line (inside the root), or the conventional name."""
    if line is None or not line.strip():
        return tree.root / CONVENTIONAL_NAMES[role]
    if Path(line).is_absolute():
        return _rerooted(tree, line, f"files.txt (the {role} line)")
    candidate = tree.root / line
    if not candidate.exists() and (tree.root / line.strip()).exists():
        candidate = tree.root / line.strip()  # v1 kept spaces in file names (bug B29); accept the trimmed name
    return candidate


def _read_secret(tree: V1Tree, role: str, path: Path) -> str | None:
    entry: dict[str, Any] = {"role": role, "path": _relative(tree.root, path), "found": False}
    tree.inputs.append(entry)
    try:
        raw = _read_bytes(tree.root, path, MAX_SECRET_FILE_BYTES)
    except V1ReadError as exc:
        entry["detail"] = str(exc)
        tree.errors.append(f"{role}: {exc}")
        return None
    if raw is None:
        entry["detail"] = "missing"
        return None
    entry["found"] = True
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        entry["detail"] = "not UTF-8 text; not used"
        tree.errors.append(f"{role}: the file is not UTF-8 text; it was not used")
        return None
    entry["detail"] = f"{len([line for line in text.splitlines() if line.strip()])} non-empty line(s)"
    return text


def _read_rotator(tree: V1Tree, environ: Mapping[str, str]) -> None:
    """The rotator URL the way v1 auth.read_rotate_proxy found it: `ROXY_ROTATE_PROXY` when it is not blank, else
    the file (`ROXY_ROTATE_PROXY_FILE`, default rotate_proxy.txt), stripped (review finding 13)."""
    secrets = tree.secrets
    file_setting = (environ.get(ROTATOR_FILE_ENV) or "").strip()
    path = _rerooted(tree, file_setting, ROTATOR_FILE_ENV) if file_setting else tree.root / ROTATOR_FILE
    text = _read_secret(tree, "rotator_url", path)
    from_file = (text or "").strip()
    from_variable = (environ.get(ROTATOR_ENV) or "").strip()
    if from_variable:
        tree.inputs.append(
            {
                "role": "rotator_url_variable",
                "path": f"environment variable {ROTATOR_ENV}",
                "found": True,
                "detail": "set; v1 used it before any file, and so does the import",
            }
        )
        secrets.rotator_url = from_variable
        secrets.rotator_source = f"the {ROTATOR_ENV} environment variable"
        if from_file and from_file != from_variable:
            secrets.other_rotator_urls.append(from_file)  # still a secret: the scrubber must know it
            tree.warnings.append(
                f"{path.name} holds a different URL than {ROTATOR_ENV}; v1 used the variable, and so does the import"
            )
    elif from_file:
        secrets.rotator_url = from_file
        secrets.rotator_source = _relative(tree.root, path)
    elif text is None:
        tree.warnings.append(
            f"no rotator URL was found ({path.name} is missing and {ROTATOR_ENV} is not set); if v1 rotated through a "
            f"proxy, run the migrator with {ROTATOR_ENV} set as the v1 service had it, or write the rotator_url "
            "credential by hand"
        )


def _read_secrets(tree: V1Tree, environ: Mapping[str, str]) -> None:
    lines = _read_listing(tree)
    secrets = tree.secrets
    for index, role in enumerate(SECRET_ROLES):
        path = _resolve_listed(tree, role, lines[index] if index < len(lines) else None)
        text = _read_secret(tree, role, path)
        if text is None:
            continue
        if role == "admin_credentials":
            parts = text.strip().splitlines()  # v1 auth.read_admin_credentials: lines are not stripped
            secrets.admin_line_count = len(parts)
            secrets.admin_username = parts[0] if parts else None
            secrets.admin_password = parts[1] if len(parts) > 1 else None
            secrets.hmac_key = parts[2] if len(parts) > 2 else None
            secrets.session_secret = parts[3] if len(parts) > 3 else None
            if len(parts) < 4:
                tree.warnings.append(f"the admin credentials file has {len(parts)} line(s); v1 needed 4")
        elif role == "app_password":
            secrets.app_password = text.strip() or None
        elif role == "tokens":
            secrets.tokens = [line.strip() for line in text.splitlines() if line.strip()]
        elif role == "emails":
            parts = [part.strip() for part in text.strip().splitlines()]
            secrets.email_to = parts[0] if parts and parts[0] else None
            secrets.email_from = parts[1] if len(parts) > 1 and parts[1] else None
    _read_rotator(tree, environ)


def _read_control_and_stats(tree: V1Tree, state_path: Path, data_path: Path) -> None:
    state_name, data_name = _relative(tree.root, state_path), _relative(tree.root, data_path)
    backup_path = data_path.with_name(data_path.name + ".bak")
    backup_name = _relative(tree.root, backup_path)
    state, state_problem = _load_json(tree, "state", state_path)
    data, data_problem = _load_json(tree, "data", data_path)
    data_source = data_name
    if data_problem is not None and data_problem != "missing":
        tree.errors.append(f"{data_name}: {data_problem}; trying {backup_name} as v1 did")
    if data is None:
        backup, backup_problem = _load_json(tree, "data_backup", backup_path)
        if backup is not None:
            data, data_source = backup, backup_name
            tree.warnings.append(f"statistics and any legacy Runtime blob were read from {backup_name}")
        elif backup_problem not in (None, "missing"):
            tree.errors.append(f"{backup_name}: {backup_problem}")
    if not isinstance(data, dict):
        if data is not None:
            tree.errors.append(f"{data_source}: the top level is not an object; statistics skipped")
        data = {}
    else:
        tree.data_bytes = next((i.get("bytes", 0) for i in tree.inputs if i["role"] in ("data", "data_backup")), 0)

    diagnostics = data.get("Diagnostics")
    if isinstance(diagnostics, dict) and diagnostics:
        tree.diagnostics = diagnostics
        tree.statistics_source = data_source
    else:
        tree.statistics_source = "none (no Diagnostics in the data file)"

    if state_problem is not None and state_problem != "missing":
        tree.warnings.append(f"{state_name}: {state_problem}; v1 treated it as empty")
    state_blob = state.get("Runtime") if isinstance(state, dict) else None
    legacy = data.get("Runtime")
    if state_blob:
        # v1 runtime._load_from_disk: a truthy Runtime in the state file wins; the legacy key is ignored.
        if isinstance(state_blob, dict):
            tree.runtime = state_blob
            tree.runtime_source = state_name
        else:
            tree.runtime_source = f"{state_name} (its Runtime is not an object, so v1 used its defaults)"
            tree.warnings.append(
                f"{state_name}: Runtime is not an object; v1 used its defaults, and so does the import"
            )
        if isinstance(legacy, dict) and legacy:
            tree.legacy_runtime_ignored = True
    elif isinstance(legacy, dict) and legacy:
        tree.runtime = legacy
        tree.runtime_source = f"{data_source} (legacy Runtime blob, used because {state_name} has none)"
    else:
        tree.runtime_source = "none (no Runtime anywhere, so v1 ran on its defaults)"


def _note_runtime_files(tree: V1Tree) -> None:
    for name in RUNTIME_STATE_FILES:
        if (tree.root / name).exists():
            tree.runtime_files.append(name)
    cache_dir = tree.root / "cache"
    if cache_dir.is_dir() and _inside(tree.root, cache_dir):
        try:
            tree.cache_files = sum(1 for entry in os.scandir(cache_dir) if entry.is_file())
        except OSError:
            tree.cache_files = 0


def read_v1_tree(
    root: Path | str,
    *,
    state_file: str | None = None,
    data_file: str | None = None,
    environ: Mapping[str, str] | None = None,
) -> V1Tree:
    """Read everything the migrator needs from the v1 tree at `root`, without writing anything.

    `state_file` and `data_file` are the v1 `ROXY_STATE_FILE` and `ROXY_DATA_FILE` values (the `--v1-state-file`
    and `--v1-data-file` arguments), read inside the root; `environ` is where `ROXY_ROTATE_PROXY` and
    `ROXY_ROTATE_PROXY_FILE` are looked up (the process environment when None).
    """
    base = Path(root)
    if not base.is_dir():
        raise V1ReadError(f"the v1 root {str(base)[:200]!r} is not a directory")
    tree = V1Tree(root=base)
    state_path = _rerooted(tree, state_file, "--v1-state-file") if state_file else base / STATE_FILE
    data_path = _rerooted(tree, data_file, "--v1-data-file") if data_file else base / DATA_FILE
    _read_control_and_stats(tree, state_path, data_path)
    _read_secrets(tree, os.environ if environ is None else environ)
    _note_runtime_files(tree)
    return tree


__all__ = [
    "CONVENTIONAL_NAMES",
    "DATA_FILE",
    "MAX_JSON_BYTES",
    "ROTATOR_ENV",
    "ROTATOR_FILE_ENV",
    "RUNTIME_STATE_FILES",
    "SECRET_ROLES",
    "STATE_FILE",
    "V1ReadError",
    "V1Secrets",
    "V1Tree",
    "read_v1_tree",
]
