#!/usr/bin/env python3
"""Email the admin that a systemd unit failed, with the tail of its log.

Invoked by roxy-alert@.service, which roxy.service names in OnFailure=.

This exists because the application cannot report its own death. When the
kernel OOM-killer sends SIGKILL there is no exception to catch, no handler
runs, and the in-app error email never fires -- so a crash looks exactly like
silence. systemd is outside that blast radius and can still speak.

Deliberately dependency-free (stdlib + the app's own credential files) so it
keeps working even when the app itself will not start.
"""

import os
import smtplib
import socket
import subprocess
import sys
from email.message import EmailMessage

ROXY_FILE_ROOT = os.environ.get("ROXY_FILE_ROOT", "/etc/roxy/")
LOG_LINES = 60


def _paths() -> list[str]:
    with open(os.path.join(ROXY_FILE_ROOT, "files.txt")) as file:
        return [os.path.join(ROXY_FILE_ROOT, line) for line in file.read().strip().splitlines()]


def _read(path: str) -> str:
    with open(path) as file:
        return file.read().strip()


def _journal(unit: str) -> str:
    try:
        return subprocess.run(
            ["journalctl", "-u", unit, "-n", str(LOG_LINES), "--no-pager", "--output=short-iso"],
            capture_output=True,
            text=True,
            timeout=20,
        ).stdout
    except Exception as error:
        return f"(could not read the journal: {error})"


def _status(unit: str) -> str:
    try:
        return subprocess.run(
            ["systemctl", "status", unit, "--no-pager", "--lines=0"],
            capture_output=True,
            text=True,
            timeout=20,
        ).stdout
    except Exception as error:
        return f"(could not read the unit status: {error})"


def main() -> int:
    unit = sys.argv[1] if len(sys.argv) > 1 else "roxy.service"
    paths = _paths()
    app_password = _read(paths[1])
    emails = _read(paths[3]).splitlines()
    to_address, from_address = emails[0], emails[1]

    body = (
        f"{unit} entered a failed state on {socket.gethostname()}.\n\n"
        "Roxy cannot send this itself: a process killed by the kernel (out of "
        "memory) or by a signal raises no Python exception, so the in-app error "
        "email never fires.\n\n"
        "Worth checking first:\n"
        "  systemctl status roxy.service\n"
        "  journalctl -u roxy.service -n 200 --no-pager\n"
        "  sudo dmesg -T | grep -i -A4 'out of memory'\n"
        "  ls -lh /etc/roxy/roxy_data.json\n\n"
        f"--- systemctl status ---\n{_status(unit)}\n"
        f"--- last {LOG_LINES} log lines ---\n{_journal(unit)}"
    )

    message = EmailMessage()
    message["To"] = to_address
    message["From"] = from_address
    message["Subject"] = f"Roxy DOWN: {unit} failed on {socket.gethostname()}"
    message.set_content(body)

    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=20) as smtp:
        smtp.login(from_address, app_password)
        smtp.send_message(message)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:  # Never let the alert unit itself fail loudly.
        print(f"alert_on_failure: {type(error).__name__}: {error}", file=sys.stderr)
        sys.exit(0)
