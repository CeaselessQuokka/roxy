#!/usr/bin/env python3
"""Create or reset a Roxy admin account from the server console, with TOTP enrollment shown as a terminal QR code.

What this is
    `python scripts/create_admin.py --username owner` creates an admin: it asks for a password twice (checked
    against the policy: at least 14 characters, not a common password), makes a new authenticator (TOTP) secret,
    draws its QR code in the terminal, asks for the first 6-digit code to confirm the phone has it, and prints 10
    recovery codes once. `--reset-mfa` gives an existing admin a new authenticator and new recovery codes and
    removes their passkeys, trusted devices and sessions (for a lost phone). `--reset-password` sets a new
    password and ends every session of that admin.

Why it exists
    Plan 9.5: the first admin is created on the server console, so there is never a "first visitor becomes admin"
    window on the public internet. The console is also the way back in when the owner has lost both the phone
    and the recovery codes, or has locked /admin away with the network allowlist.

How it works
    It uses the same code as the server (`roxy.admin.auth.users`, `passwords`, `totp`, `recovery_codes`), so an
    account made here is checked by exactly the rules the login uses. The TOTP secret is encrypted with the
    `totp_encryption_key` credential (`$CREDENTIALS_DIRECTORY`, `ROXY_CREDENTIALS_DIR`, or `--credentials-dir`).
    It refuses to run against a control.db whose schema is older than this release needs (it never migrates).
    Every change is one control.db transaction with an audit row (actor `cli:create_admin`). Secrets are printed
    only to this terminal, never logged.

What to read next
    `src/roxy/admin/auth/users.py`, then `src/roxy/admin/auth/totp.py`.
"""

from __future__ import annotations

import argparse
import getpass
import sqlite3
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, TextIO

_SRC = Path(__file__).resolve().parent.parent / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))  # run from a checkout without installing the package

from roxy.admin.auth import recovery_codes, totp, users  # noqa: E402 (after the path fix above)
from roxy.admin.auth.events import audit_auth  # noqa: E402
from roxy.admin.auth.passwords import PasswordHasher, check_password_policy  # noqa: E402

PASSWORD_TRIES = 3
CODE_TRIES = 3


class CliError(Exception):
    """A problem the operator can fix; printed without a traceback, exit status 1."""


def _open(state_dir: str | None) -> Any:
    from roxy.storage.db import open_databases
    from roxy.storage.migrate import check_schema

    if state_dir:
        env: Any = {"ROXY_STATE_DIR": state_dir}
        credentials_hint = None
    else:
        from roxy.config.env import EnvSettings

        env = EnvSettings()
        credentials_hint = env.credentials_dir
    dbs = open_databases(env)
    check_schema(dbs, names=["control"])
    return dbs, credentials_hint


def _ask_password(username: str, ask: Callable[[str], str], out: TextIO) -> str:
    for _ in range(PASSWORD_TRIES):
        first = ask("New password: ")
        problems = check_password_policy(first, username)
        if problems:
            for problem in problems:
                out.write(f"  {problem}\n")
            continue
        if ask("Repeat the password: ") != first:
            out.write("  The two passwords differ.\n")
            continue
        return first
    raise CliError("no acceptable password entered")


def _enroll_totp(username: str, read: Callable[[str], str], out: TextIO, verify: bool) -> str:
    secret = totp.new_secret()
    uri = totp.provisioning_uri(secret, username)
    out.write("\nScan this QR code with your authenticator app:\n\n")
    out.write(totp.qr_terminal(uri))
    grouped = " ".join(secret[i : i + 4] for i in range(0, len(secret), 4))
    out.write(f"\nOr enter this key by hand: {grouped}\n")
    if not verify:
        return secret
    for _ in range(CODE_TRIES):
        code = read("Enter the 6-digit code your app shows now: ").strip()
        if totp.match_step(secret, code, time.time()) is not None:
            out.write("  Authenticator confirmed.\n")
            return secret
        out.write("  That code does not match. Check the phone's clock and try the newest code.\n")
    raise CliError("the authenticator was not confirmed; nothing was changed")


def main(
    argv: Sequence[str] | None = None,
    *,
    out: TextIO | None = None,
    read: Callable[[str], str] = input,
    ask_secret: Callable[[str], str] = getpass.getpass,
    hasher: PasswordHasher | None = None,
) -> int:
    out = out or sys.stdout
    parser = argparse.ArgumentParser(
        prog="create_admin.py",
        description="Create or reset a Roxy admin account (run on the server console).",
    )
    parser.add_argument("--username", required=True, help="admin username (letters, digits, _ . @ -)")
    parser.add_argument("--email", help="address for emailed codes (optional)")
    parser.add_argument(
        "--reset-mfa",
        action="store_true",
        help="new authenticator and recovery codes; removes passkeys, trusted devices and sessions",
    )
    parser.add_argument("--reset-password", action="store_true", help="set a new password and end all sessions")
    parser.add_argument("--state-dir", help="directory holding control.db (default: ROXY_STATE_DIR)")
    parser.add_argument(
        "--credentials-dir",
        help="directory holding totp_encryption_key (default: $CREDENTIALS_DIRECTORY or ROXY_CREDENTIALS_DIR)",
    )
    parser.add_argument("--no-verify", action="store_true", help="do not ask for a first code to confirm the app")
    args = parser.parse_args(argv)
    try:
        return _run(args, out=out, read=read, ask_secret=ask_secret, hasher=hasher or PasswordHasher())
    except CliError as exc:
        out.write(f"error: {exc}\n")
        return 1


def _run(
    args: argparse.Namespace,
    *,
    out: TextIO,
    read: Callable[[str], str],
    ask_secret: Callable[[str], str],
    hasher: PasswordHasher,
) -> int:
    from roxy.config.audit import Actor

    if not users.valid_username(args.username):
        raise CliError("usernames are 1 to 64 letters, digits, '_', '.', '@' or '-'")
    try:
        dbs, credentials_hint = _open(args.state_dir)
    except Exception as exc:  # schema too old, unreadable files: say what, not a traceback
        raise CliError(str(exc)) from exc
    try:
        credentials = Path(args.credentials_dir) if args.credentials_dir else credentials_hint
        if credentials is None:
            import os

            raw = os.environ.get("CREDENTIALS_DIRECTORY") or os.environ.get("ROXY_CREDENTIALS_DIR")
            credentials = Path(raw) if raw else None
        cipher = totp.load_cipher(credentials)
        existing = dbs.control.read_sync(lambda conn: users.get_by_username(conn, args.username))
        creating = existing is None
        if creating and (args.reset_mfa or args.reset_password):
            raise CliError(f"there is no admin named {args.username!r}")
        if not creating and not (args.reset_mfa or args.reset_password):
            raise CliError(f"{args.username!r} already exists; use --reset-mfa or --reset-password")
        new_totp = creating or args.reset_mfa
        if new_totp and cipher is None:
            raise CliError("the totp_encryption_key credential was not found (set --credentials-dir)")

        password_hash = None
        if creating or args.reset_password:
            password_hash = hasher.hash_sync(_ask_password(args.username, ask_secret, out))
        secret = _enroll_totp(args.username, read, out, not args.no_verify) if new_totp else None
        codes = recovery_codes.generate() if new_totp else []
        entries = recovery_codes.hash_codes_sync(hasher, codes) if codes else []
        actor = Actor("cli", "create_admin")
        now = int(time.time())

        def write(conn: sqlite3.Connection) -> int:
            if creating:
                assert password_hash is not None
                user_id = users.insert_user(
                    conn, username=args.username, password_hash=password_hash, now=now, email=args.email
                )
                action, reason = "auth.user_created", "admin created on the server console"
            else:
                assert existing is not None
                user_id = existing.id
                action, reason = "auth.user_reset", "admin reset on the server console"
                if args.email:
                    conn.execute("UPDATE admin_users SET email = ? WHERE id = ?", (args.email, user_id))
            removed: dict[str, int] = {}
            if args.reset_mfa:
                removed = users.reset_mfa(conn, user_id)
            if password_hash is not None and not creating:
                users.set_password_hash(conn, user_id, password_hash)
                removed["sessions"] = (
                    removed.get("sessions", 0)
                    + conn.execute("DELETE FROM admin_sessions WHERE user_id = ?", (user_id,)).rowcount
                )
            if secret is not None and cipher is not None:
                users.store_totp(
                    conn, user_id, cipher.encrypt(secret, totp.user_context(user_id)), recovery_codes.dumps(entries)
                )
            audit_auth(
                conn,
                action,
                user_id=user_id,
                username=actor.name,
                ip=None,
                request_id=None,
                reason=reason,
                after={
                    "password_set": password_hash is not None,
                    "authenticator_enrolled": secret is not None,
                    "recovery_codes": len(codes),
                    "removed": removed,
                },
                at=now,
                actor_kind="cli",
            )
            return user_id

        user_id = dbs.control.write_sync(write)
    finally:
        dbs.close_all_sync()
    out.write(f"\nAdmin {args.username!r} (id {user_id}) is ready.\n")
    if codes:
        out.write("\nRecovery codes (each works once; store them somewhere safe now, they are not shown again):\n")
        for code in codes:
            out.write(f"  {code}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
