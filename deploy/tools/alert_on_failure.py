#!/usr/bin/python3 -I
"""Alert the admin that a systemd unit failed, or that a deploy failed (the roxy-alert@.service program).

What this is
    `alert_on_failure.py <unit>` emails "Roxy DOWN: <unit> failed on <host>" with the unit's status, restart count
    and its last 60 journal lines (redacted), and posts the same alert to the optional webhook. With the instance
    name `deploy-failure` it reads the record deploy.sh wrote (/var/lib/roxy-deploy/last_failure.json) and sends
    "Roxy: deploy <short sha> failed at step <n>" instead (plan 17.7). Installed as
    /usr/local/lib/roxy/alert_on_failure.py and run by roxy-alert@.service with the SYSTEM Python 3, standard
    library only.

Why it exists
    A worker killed by the kernel (out of memory) or by a signal raises no Python exception, so the app's own error
    email never fires; systemd's OnFailure= is the only layer that sees it. v1 had this script too, with four
    problems plan 17.1 fixes (v1 notes, sections 9 and 10):
    - it ran on the app's virtual environment, which the deploy rebuilt, so a broken release also broke alerts.
      Now: /usr/bin/python3, no third-party imports.
    - it read secrets from positional lines of files.txt. Now: named systemd credentials (smtp_password,
      alert_emails, alert_webhook_url) from $CREDENTIALS_DIRECTORY.
    - it mailed 60 raw journal lines (query strings, cookies, tokens). Now: every line is redacted first.
    - it sent one email per failure with no limit (a crash loop on systemd 254+ means one email every 3 s), and
      exited 0 when sending failed. Now: one email per unit per 10 minutes with a count of the suppressed ones
      (a stamp file per unit in $STATE_DIRECTORY), and a non-zero exit when any channel fails, so the alert
      unit itself shows in `systemctl --failed`.
    The subject `Roxy DOWN: <unit> failed on <host>` is kept exactly, because owners filter mail on it.

How it works
    1. Rate limit: read the unit's stamp; inside 10 minutes of the last sent alert, count it as suppressed and
       exit 0. 2. Collect `systemctl status`, `systemctl show` (restart count, result) and `journalctl` output.
    3. Redact: credential markers and cookies, auth headers (plain and JSON or dict form), URL passwords and query
       strings, password-like key=value pairs, the kill-switch token path, long opaque strings, and the exact
       values of the secrets this script read. 4. Send over Gmail SMTP SSL 465 (to the main address, from the alt
       address, as v1) and, when configured, POST JSON to the webhook. 5. Update the stamp when any channel
       delivered.
    Settings come from systemd's environment ($CREDENTIALS_DIRECTORY, $STATE_DIRECTORY); ROXY_ALERT_SMTP_HOST,
    ROXY_ALERT_SMTP_PORT, ROXY_ALERT_SMTP_SSL and ROXY_ALERT_DEPLOY_FILE exist for tests and unusual relays.

What to read next
    deploy/systemd/roxy-alert@.service (its sandbox and credentials), deploy/systemd/roxy-deploy-alert.path, then
    src/roxy/notify (the app's own alerts, plan 17.7).
"""

from __future__ import annotations

import json
import os
import re
import smtplib
import socket
import ssl
import subprocess
import sys
import time
import urllib.request
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from email.message import EmailMessage
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


LOG_LINES = 60
RATE_LIMIT_S = 600
NETWORK_TIMEOUT_S = 20
WEBHOOK_CONTENT_LIMIT = 1900
DEPLOY_FAILURE_INSTANCE = "deploy-failure"
REDACTED = "[redacted]"

# ------------------------------------------------------------------------------------------------ redaction

_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    # The Roblox cookie warning prefix and whatever follows it (a credential value).
    (re.compile(r"_\|WARNING:-DO-NOT-SHARE-THIS[^\s\"';,]*"), "[redacted credential]"),
    # The cookie by name, in a header or a URL.
    (re.compile(r"(?i)(\.ROBLOSECURITY\s*=\s*)[^;\s\"',]*"), rf"\1{REDACTED}"),
    # Secret-bearing headers logged as JSON or a Python dict ({"authorization": "Bearer ..."}): a quote sits between
    # the name and the colon. The quoted value (or, unquoted, the value up to the next comma or brace) is replaced,
    # so the rest of the line stays readable. Runs before the plain form below, which needs no quote there.
    (
        re.compile(
            r"(?i)\b(cookie|set-cookie|authorization|proxy-authorization|x-csrf-token|x-api-key)"
            r"([\"']\s*:\s*)(\"(?:[^\"\\\r\n]|\\.)*\"|'(?:[^'\\\r\n]|\\.)*'|[^,}\r\n]*)"
        ),
        rf"\1\2{REDACTED}",
    ),
    # Secret-bearing headers, whole value.
    (
        re.compile(
            r"(?i)\b(cookie|set-cookie|authorization|proxy-authorization|x-csrf-token|x-api-key)(\s*[:=]\s*)[^\r\n]*"
        ),
        rf"\1\2{REDACTED}",
    ),
    # user:password@ in any URL (the rotator URL carries its password like this).
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@"), rf"\1{REDACTED}@"),
    # The one-time kill-switch token in /admin/invalidate/<token>.
    (re.compile(r"(/admin/invalidate/)[^\s\"'?#]+"), rf"\1{REDACTED}"),
    # Query strings after a URL or path (callers put ids and sometimes secrets there).
    (re.compile(r"(?<=[A-Za-z0-9/._-])\?[^\s\"'<>]+"), f"?{REDACTED}"),
    # password=..., token: ..., "api_key": "..." and similar pairs, in key=value text and in JSON log lines.
    (
        re.compile(
            r"(?i)\b([\w-]*(?:passw(?:or)?d|pass|secret|token|api[_-]?key|totp|otp|recovery)[\w-]*)"
            r"(\"?\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;&\"'}]+)"
        ),
        rf"\1\2{REDACTED}",
    ),
    # Long opaque strings (session ids, keys, cookie bodies). A 40 character commit id stays readable, and so do
    # long URL paths (the class has no "/" or ".").
    (re.compile(r"[A-Za-z0-9+=_-]{48,}"), REDACTED),
)


def redact(text: str, secrets: Iterable[str] = ()) -> str:
    """Remove everything that looks like a secret, and the exact secret values this script knows."""
    for value in secrets:
        value = value.strip()
        if len(value) >= 6:
            text = text.replace(value, REDACTED)
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


# -------------------------------------------------------------------------------------------------- settings


@dataclass(frozen=True)
class Settings:
    """Where things are. From systemd's environment in production; tests build their own."""

    credentials_dir: Path
    state_dir: Path
    deploy_failure_file: Path
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 465
    smtp_ssl: bool = True
    hostname: str = ""

    @classmethod
    def from_environ(cls, environ: Mapping[str, str]) -> Settings:
        return cls(
            credentials_dir=Path(environ.get("CREDENTIALS_DIRECTORY", "/run/credentials/roxy-alert")),
            state_dir=Path(environ.get("STATE_DIRECTORY", "/var/lib/roxy-alert").split(":")[0]),
            deploy_failure_file=Path(environ.get("ROXY_ALERT_DEPLOY_FILE", "/var/lib/roxy-deploy/last_failure.json")),
            smtp_host=environ.get("ROXY_ALERT_SMTP_HOST", "smtp.gmail.com"),
            smtp_port=int(environ.get("ROXY_ALERT_SMTP_PORT", "465")),
            smtp_ssl=environ.get("ROXY_ALERT_SMTP_SSL", "1") != "0",
            hostname=socket.gethostname(),
        )


def read_credential(settings: Settings, name: str) -> str:
    """One systemd credential's text, stripped; empty when the file is missing or empty (not configured)."""
    try:
        return (settings.credentials_dir / name).read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def parse_addresses(text: str) -> tuple[str, str]:
    """(to, from) from the alert_emails credential: `to:` and `from:` lines (plan 9.8), or v1's two plain lines
    (main address first, alt address second). A single address is used for both."""
    to_addr = from_addr = ""
    plain: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition(":")
        if sep and key.strip().lower() == "to":
            to_addr = value.strip()
        elif sep and key.strip().lower() == "from":
            from_addr = value.strip()
        else:
            plain.append(line)
    if not to_addr and plain:
        to_addr = plain[0]
    if not from_addr:
        from_addr = plain[1] if len(plain) > 1 else to_addr
    return to_addr, from_addr


# -------------------------------------------------------------------------------------------- rate limiting


def stamp_path(settings: Settings, key: str) -> Path:
    """The stamp file for one alert key (unit names contain '@' and '.', which are fine in file names)."""
    return settings.state_dir / (re.sub(r"[^A-Za-z0-9@._-]", "_", key)[:200] + ".json")


def load_stamp(settings: Settings, key: str) -> dict[str, float]:
    """{"last_sent": seconds, "suppressed": count}; a missing or damaged stamp means "never sent"."""
    try:
        data = json.loads(stamp_path(settings, key).read_text(encoding="utf-8"))
        return {"last_sent": float(data.get("last_sent", 0.0)), "suppressed": float(data.get("suppressed", 0))}
    except (OSError, ValueError, TypeError, AttributeError):
        return {"last_sent": 0.0, "suppressed": 0.0}


def save_stamp(settings: Settings, key: str, stamp: Mapping[str, float]) -> None:
    """Write the stamp atomically (a crash never leaves half a file)."""
    path = stamp_path(settings, key)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps({"last_sent": stamp["last_sent"], "suppressed": int(stamp["suppressed"])}), "utf-8")
    os.replace(tmp, path)


# ----------------------------------------------------------------------------------------- what to report


def run_text(cmd: Sequence[str]) -> str:
    """A command's stdout (or its error) as text; never raises (the alert must still go out)."""
    try:
        result = subprocess.run(  # noqa: S603
            list(cmd), capture_output=True, text=True, timeout=NETWORK_TIMEOUT_S, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return f"(could not run {cmd[0]}: {exc})"
    output = result.stdout.strip()
    if not output and result.stderr.strip():
        output = f"({result.stderr.strip()})"
    return output


def unit_facts(unit: str) -> dict[str, str]:
    """Restart count and result from `systemctl show` (empty strings when unavailable)."""
    facts = {"NRestarts": "", "Result": "", "ExecMainStatus": ""}
    text = run_text(["systemctl", "show", unit, "-p", "NRestarts", "-p", "Result", "-p", "ExecMainStatus"])
    for line in text.splitlines():
        key, _, value = line.partition("=")
        if key in facts:
            facts[key] = value.strip()
    return facts


@dataclass
class Alert:
    """One message for every channel."""

    subject: str
    body: str
    fields: dict[str, Any]


def unit_alert(unit: str, host: str, *, suppressed: int, secrets: Sequence[str], now: float) -> Alert:
    """The "Roxy DOWN" alert for a failed unit (subject kept from v1)."""
    status = redact(run_text(["systemctl", "status", unit, "--no-pager", "--lines=0"]), secrets)
    facts = unit_facts(unit)
    journal = redact(
        run_text(["journalctl", "-u", unit, "-n", str(LOG_LINES), "--no-pager", "--output=short-iso"]), secrets
    )
    when = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(now))
    lines = [
        f"{unit} entered a failed state on {host}.",
        "",
        "Roxy cannot send this itself: a process killed by the kernel (out of memory) or by a signal raises no "
        "Python exception, so the in-app error email never fires.",
        "",
        f"When: {when}",
        f"Restarts so far: {facts['NRestarts'] or 'unknown'}",
        f"Result: {facts['Result'] or 'unknown'} (exit status {facts['ExecMainStatus'] or 'unknown'})",
    ]
    if suppressed:
        lines.append(f"Suppressed since last alert: {suppressed}")
    lines += [
        "",
        "Worth checking first:",
        "  systemctl status roxy@blue.service roxy@green.service",
        f"  journalctl -u {unit} -n 200 --no-pager",
        "  sudo dmesg -T | grep -i -A4 'out of memory'",
        "  ls -lh /var/lib/roxy",
        "",
        "--- systemctl status ---",
        status,
        f"--- last {LOG_LINES} log lines (redacted) ---",
        journal,
    ]
    return Alert(
        subject=f"Roxy DOWN: {unit} failed on {host}",
        body="\n".join(lines) + "\n",
        fields={
            "unit": unit,
            "host": host,
            "when": when,
            "restarts": facts["NRestarts"],
            "result": facts["Result"],
            "suppressed": suppressed,
        },
    )


def deploy_alert(record: Mapping[str, Any], host: str, *, suppressed: int, secrets: Sequence[str]) -> Alert:
    """The "deploy failed" alert from deploy.sh's failure record (plan 17.7)."""
    sha = str(record.get("sha", "unknown"))
    short = sha[:12] if re.fullmatch(r"[0-9a-f]{7,40}", sha) else "unknown"
    step = str(record.get("step", "?"))
    step = step if step.isdigit() else "?"
    error = redact(str(record.get("error", "")), secrets)[:2000]
    rollback = redact(str(record.get("rollback", "")), secrets)[:500]
    when = redact(str(record.get("at", "")), secrets)[:40]
    lines = [
        f"The deploy of {short} failed at step {step} on {host}.",
        "",
        f"What happened: {error or 'see the deploy log'}",
        f"When: {when}",
        f"Rollback: {rollback or 'unknown'}",
    ]
    if suppressed:
        lines.append(f"Suppressed since last alert: {suppressed}")
    lines += [
        "",
        "What to do:",
        "  Read the GitHub Action log of this deploy (the step and the failing command are there).",
        "  systemctl status roxy@blue.service roxy@green.service",
        "  /opt/roxy/deploy_rollback.sh   (only if the site is not serving the previous release)",
    ]
    return Alert(
        subject=f"Roxy: deploy {short} failed at step {step}",
        body="\n".join(lines) + "\n",
        fields={"sha": short, "step": step, "error": error, "rollback": rollback, "host": host},
    )


# ------------------------------------------------------------------------------------------------- sending


def send_email(settings: Settings, alert: Alert, *, to_addr: str, from_addr: str, password: str) -> None:
    """Gmail SMTP over SSL (465), logging in as the sender, as v1 did. Raises on any failure."""
    message = EmailMessage()
    message["To"] = to_addr
    message["From"] = from_addr
    message["Subject"] = alert.subject
    message.set_content(alert.body)
    if settings.smtp_ssl:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(
            settings.smtp_host, settings.smtp_port, timeout=NETWORK_TIMEOUT_S, context=context
        ) as smtp:
            smtp.login(from_addr, password)
            smtp.send_message(message)
    else:  # tests and local relays only (ROXY_ALERT_SMTP_SSL=0)
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=NETWORK_TIMEOUT_S) as smtp:
            if password:
                smtp.login(from_addr, password)
            smtp.send_message(message)


def send_webhook(url: str, alert: Alert) -> None:
    """POST the alert as JSON. `content` is the text chat webhooks (Discord) display; the rest is structured."""
    content = f"{alert.subject}\n{alert.body}"
    if len(content) > WEBHOOK_CONTENT_LIMIT:
        content = content[: WEBHOOK_CONTENT_LIMIT - 3] + "..."
    payload = {"content": content, "subject": alert.subject, "severity": "critical", "fields": alert.fields}
    if not url.startswith(("https://", "http://")):
        raise ValueError("the webhook URL must be http or https")
    request = urllib.request.Request(  # noqa: S310 (scheme checked above)
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "roxy-alert"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=NETWORK_TIMEOUT_S) as response:  # noqa: S310
        if not 200 <= response.status < 300:
            raise RuntimeError(f"webhook answered {response.status}")


# ---------------------------------------------------------------------------------------------------- main


def main(argv: Sequence[str] | None = None, *, settings: Settings | None = None, now: float | None = None) -> int:
    """Exit status: 0 sent (or suppressed by the rate limit), 1 a channel failed, 2 nothing could be sent."""
    args = list(sys.argv[1:] if argv is None else argv)
    unit = args[0] if args else "unknown.service"
    settings = settings or Settings.from_environ(os.environ)
    now = time.time() if now is None else now
    host = settings.hostname or socket.gethostname()

    password = read_credential(settings, "smtp_password")
    to_addr, from_addr = parse_addresses(read_credential(settings, "alert_emails"))
    webhook = read_credential(settings, "alert_webhook_url")
    secrets = [value for value in (password, webhook) if value]

    record: dict[str, Any] = {}
    key = unit
    if unit == DEPLOY_FAILURE_INSTANCE:
        try:
            loaded = json.loads(settings.deploy_failure_file.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            warn(f"alert_on_failure: cannot read {settings.deploy_failure_file}: {exc}")
            return 2
        record = loaded if isinstance(loaded, dict) else {}
        key = f"deploy-{str(record.get('sha', 'unknown'))[:40]}"

    stamp = load_stamp(settings, key)
    if stamp["last_sent"] > 0 and 0 <= now - stamp["last_sent"] < RATE_LIMIT_S:
        stamp["suppressed"] += 1
        save_stamp(settings, key, stamp)
        say(f"alert_on_failure: {key} alerted {int(now - stamp['last_sent'])} s ago; suppressed")
        return 0
    suppressed = int(stamp["suppressed"])

    if unit == DEPLOY_FAILURE_INSTANCE:
        alert = deploy_alert(record, host, suppressed=suppressed, secrets=secrets)
    else:
        alert = unit_alert(unit, host, suppressed=suppressed, secrets=secrets, now=now)

    delivered = 0
    errors: list[str] = []
    if to_addr and password:
        try:
            send_email(settings, alert, to_addr=to_addr, from_addr=from_addr, password=password)
            delivered += 1
        except (OSError, smtplib.SMTPException, ssl.SSLError) as exc:
            errors.append(f"email: {type(exc).__name__}: {redact(str(exc), secrets)}")
    else:
        errors.append("email: smtp_password or alert_emails credential is missing")
    if webhook:
        try:
            send_webhook(webhook, alert)
            delivered += 1
        except (OSError, ValueError, RuntimeError) as exc:
            errors.append(f"webhook: {type(exc).__name__}: {redact(str(exc), secrets)}")

    if delivered:
        save_stamp(settings, key, {"last_sent": now, "suppressed": 0})
    for error in errors:
        warn(f"alert_on_failure: {error}")
    if not delivered:
        return 2 if not (to_addr and password) and not webhook else 1
    say(f"alert_on_failure: sent {alert.subject!r} ({delivered} channel(s))")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
