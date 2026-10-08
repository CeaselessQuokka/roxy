"""Command line for the v1 migrator: `python scripts/migrate_from_v1.py --v1-root ... --state-dir ...`.

What this is
    `main(argv)` parses the arguments of plan 18.3 (`--v1-root`, `--state-dir`, `--credentials-out`, `--dry-run`,
    `--report`, `--import-admin-password`, plus `--v1-state-file` and `--v1-data-file` for a v1 that was told to
    use other file names), runs `runner.run_migration`, writes the JSON and Markdown report, and prints a short
    summary. Exit status 0 on success, 1 when a step reported an error, 2 on bad arguments, an unreadable v1 root,
    or a refused run (an output path inside the v1 root, or a v1 root without v1 files; nothing is written then,
    not even the report).

Why it exists
    MIGRATION.md tells the owner to run this twice: with `--dry-run` first (nothing is written to the state or
    credentials directory), then for real. Keeping the parsing here and the logic in the package makes every
    part testable without a subprocess, while `scripts/migrate_from_v1.py` stays a two-line wrapper.

How it works
    Logging goes through `core.logging.configure_logging` (JSON lines on stderr with the redaction filter), and
    every secret read from the v1 tree is registered with `SecretRegistry` before any step runs, so even an
    unexpected log line cannot print one. The summary on stdout holds counts and paths only. The v1 rotator URL
    may come from the `ROXY_ROTATE_PROXY` environment variable, as it did for v1 (a URL with a password must never
    be a command line argument, which other users can read in the process list).

What to read next
    `roxy/migration/runner.py`, then MIGRATION.md (the cutover steps that call this tool).
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import IO, Final

from roxy.core.logging import configure_logging
from roxy.core.redact import SecretRegistry
from roxy.migration.report import REFUSED, report_paths, write_report
from roxy.migration.runner import Options, read_tree, resolves_inside, run_migration
from roxy.migration.v1_tree import ROTATOR_ENV, ROTATOR_FILE_ENV, V1ReadError

DEFAULT_REPORT: Final = Path("roxy-v1-migration-report")
_MAX_REGISTERED_TOKENS: Final = 16


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scripts/migrate_from_v1.py",
        description=(
            "Import a Roxy v1 /etc/roxy tree into the v2 databases and write the bootstrap credential files "
            "(REMAKE_PLAN.md 18.3). v1 files are only read, never changed. Safe to run again: a rerun adds only "
            "v1 items no earlier run placed."
        ),
        epilog=(
            f"If the v1 service set {ROTATOR_ENV} (the rotator URL) or {ROTATOR_FILE_ENV}, run this with the same "
            "variable set, as v1 had it; the URL holds a password, so there is no argument for it."
        ),
    )
    parser.add_argument("--v1-root", required=True, type=Path, help="the v1 directory (a copy of /etc/roxy)")
    parser.add_argument("--state-dir", required=True, type=Path, help="the v2 state directory (control.db and so on)")
    parser.add_argument(
        "--credentials-out",
        type=Path,
        help="where to write the bootstrap credential files (directory 0700, files 0600), for example "
        "/etc/roxy/credentials",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="run every step against private copies and write only the report",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=DEFAULT_REPORT,
        help="report path, outside the v1 root; PATH.json and PATH.md are written (default: %(default)s)",
    )
    parser.add_argument(
        "--import-admin-password",
        action="store_true",
        help="hash the v1 admin password with argon2id and create the v2 admin (TOTP enrollment at first login)",
    )
    parser.add_argument(
        "--v1-state-file",
        help="the ROXY_STATE_FILE value of the v1 service, if it set one (default roxy_state.json); read inside "
        "--v1-root, an absolute path by its file name",
    )
    parser.add_argument(
        "--v1-data-file",
        help="the ROXY_DATA_FILE value of the v1 service, if it set one (default roxy_data.json); read inside "
        "--v1-root, an absolute path by its file name",
    )
    parser.add_argument("--log-level", default="info", help="log level for stderr (default: %(default)s)")
    return parser


def register_secrets(options: Options) -> None:
    """Register every secret in the v1 tree with the log redaction registry (values, never names of files)."""
    try:
        secrets = read_tree(options).secrets
    except V1ReadError:
        return
    named = {
        "v1_admin_password": secrets.admin_password,
        "v1_hmac_key": secrets.hmac_key,
        "v1_session_secret": secrets.session_secret,
        "v1_app_password": secrets.app_password,
        "v1_rotator_url": secrets.rotator_url,
    }
    for index, url in enumerate(secrets.other_rotator_urls):
        named[f"v1_other_rotator_url_{index}"] = url
    for name, value in named.items():
        SecretRegistry.register(name, value)
    for index, token in enumerate(secrets.tokens[:_MAX_REGISTERED_TOKENS]):
        SecretRegistry.register(f"v1_credential_{index}", token, match_substrings=True)


def _report_refusal(report_path: Path, v1_root: Path) -> str | None:
    """Why `--report` may not be used: a report file inside the v1 root (`--report /etc/roxy/roxy_state.json`
    would replace the v1 state file; review finding 11)."""
    for path in report_paths(report_path):
        if resolves_inside(path, v1_root):
            return (
                f"--report {str(report_path)!r} would write {path.name} inside the v1 root; the migrator never "
                "writes into the v1 root. Write the report somewhere else"
            )
    return None


def main(argv: Sequence[str] | None = None, *, out: IO[str] | None = None, log_stream: IO[str] | None = None) -> int:
    """Run the migrator from the command line. See the module docstring for the exit statuses."""
    stdout = out or sys.stdout
    args = build_parser().parse_args(argv)
    try:
        configure_logging(args.log_level, stream=log_stream)
    except ValueError as exc:
        stdout.write(f"error: {exc}\n")
        return 2
    options = Options(
        v1_root=args.v1_root,
        state_dir=args.state_dir,
        credentials_out=args.credentials_out,
        dry_run=args.dry_run,
        import_admin_password=args.import_admin_password,
        v1_state_file=args.v1_state_file,
        v1_data_file=args.v1_data_file,
    )
    if not options.v1_root.is_dir():
        stdout.write(f"error: --v1-root {str(options.v1_root)!r} is not a directory\n")
        return 2
    refusal = _report_refusal(args.report, options.v1_root)
    if refusal is not None:
        stdout.write(f"error: {refusal}\n")
        return 2
    register_secrets(options)
    try:
        report = asyncio.run(run_migration(options))
    except V1ReadError as exc:
        stdout.write(f"error: {exc}\n")
        return 2
    if report.status == REFUSED:
        stdout.writelines(f"error: {message}\n" for message in report.errors)
        return 2
    json_path, markdown_path = write_report(report, args.report)
    counts = ", ".join(f"{key} {value}" for key, value in report.counts().items()) or "nothing"
    dry = " (dry run: none were really written)" if report.dry_run else ""
    stdout.write(
        f"Roxy v1 migration: {report.status}\n"
        f"  items: {counts}\n"
        f"  rows and files written: {report.changes}{dry}\n"
        f"  warnings: {len(report.warnings)}, errors: {len(report.errors)}\n"
        f"  report: {json_path} and {markdown_path}\n"
    )
    return 1 if report.errors else 0


__all__ = ["build_parser", "main", "register_secrets"]
