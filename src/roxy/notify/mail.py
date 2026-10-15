"""The email channel: Gmail SMTP over SSL (port 465) with aiosmtplib, as v1, but never on a request's path.

What this is
    `MailConfig` (who receives, who sends, the app password), `load_mail_config(credentials_dir)`, and
    `MailSender.send(subject, body, to=None)`.

Why it exists
    Alerts and login codes reach the owner by email (plan 17.7; v1 `mail.py`). v1 used blocking `smtplib` inside
    request threads. aiosmtplib speaks SMTP on the event loop without blocking it, and every send has a hard
    timeout (`SMTP_TIMEOUT_S`, 15 s) so a hung mail server can only ever delay a background task.

How it works
    - Secrets come from systemd credentials (plan 9.8), never the environment: `smtp_password` (the Gmail app
      password) and `alert_emails`, one address per line with `to:` and `from:` prefixes. A file in v1's format
      (main address on line 1, sender address on line 2, no prefixes) is read the same way; with a single
      address it is both recipient and sender.
    - The password is registered with the log redaction filter (`SecretRegistry`) the moment it is read, and is
      held as a `SecretStr`, whose repr never shows it.
    - Headers cannot be injected: CR and LF in a subject become spaces before the message is built.
    - The TLS context is aiosmtplib's own default (the system CA store, hostname checked) with the key log switched
      off: CPython's `ssl.create_default_context` copies the `SSLKEYLOGFILE` environment variable into the context,
      and a debugging leftover in the service environment would write the session keys that protect the app
      password to a file (review finding cred-6, plan C2 item 2: environment settings are ignored). It is built on a
      thread, because loading the CA store reads files.
    - `transport` can be replaced (tests pass a function that records messages); nothing in a test ever opens a
      connection to a mail server (plan 19.12).

What to read next
    `roxy/notify/notifier.py` (the only caller), then `roxy/notify/webhook.py`.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path

import aiosmtplib
from pydantic import SecretStr

from roxy.config.constants import SMTP_TIMEOUT_S
from roxy.core.redact import SecretRegistry

log = logging.getLogger("roxy.notify.mail")

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465  # implicit TLS ("SMTP over SSL"), as v1
PASSWORD_CREDENTIAL = "smtp_password"  # noqa: S105 (a credential file NAME, not a secret)
EMAILS_CREDENTIAL = "alert_emails"
MAX_SUBJECT = 200
MAX_BODY = 64 * 1024

Transport = Callable[[EmailMessage, "MailConfig"], Awaitable[None]]


class MailError(RuntimeError):
    """The message could not be handed to the mail server."""


@dataclass(frozen=True, slots=True)
class MailConfig:
    to_addr: str
    from_addr: str
    password: SecretStr
    host: str = SMTP_HOST
    port: int = SMTP_PORT


def parse_alert_emails(text: str) -> tuple[str | None, str | None]:
    """(to, from) from the `alert_emails` credential (prefixed lines, or v1's two plain lines)."""
    to_addr: str | None = None
    from_addr: str | None = None
    plain: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lowered = line.lower()
        if lowered.startswith("to:"):
            to_addr = to_addr or line[3:].strip()
        elif lowered.startswith("from:"):
            from_addr = from_addr or line[5:].strip()
        else:
            plain.append(line)
    to_addr = to_addr or (plain[0] if plain else None)
    from_addr = from_addr or (plain[1] if len(plain) > 1 else to_addr)
    return to_addr or None, from_addr or None


def _read(credentials_dir: Path, name: str) -> str | None:
    try:
        return (credentials_dir / name).read_text(encoding="utf-8").strip()
    except OSError:
        return None


def load_mail_config(credentials_dir: Path | None) -> MailConfig | None:
    """The mail configuration, or None when either credential is missing (alerts then go to the log only)."""
    if credentials_dir is None:
        return None
    emails = _read(credentials_dir, EMAILS_CREDENTIAL)
    password = _read(credentials_dir, PASSWORD_CREDENTIAL)
    if not emails or not password:
        return None
    to_addr, from_addr = parse_alert_emails(emails)
    if not to_addr or not from_addr:
        return None
    SecretRegistry.register(PASSWORD_CREDENTIAL, password)  # scrubbed from every log line from now on
    return MailConfig(to_addr=to_addr, from_addr=from_addr, password=SecretStr(password))


def smtp_tls_context() -> ssl.SSLContext:
    """aiosmtplib's default client context (system CA store, certificates and hostname checked), never logging keys.

    `ssl.create_default_context` takes `SSLKEYLOGFILE` from the environment by itself; `None` switches it off.
    """
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.keylog_filename = None  # type: ignore[assignment]  # None turns key logging off (CPython docs)
    return context


async def smtp_transport(message: EmailMessage, config: MailConfig) -> None:
    """Send through the real SMTP server (implicit TLS, login, send, quit), bounded by `SMTP_TIMEOUT_S`."""
    context = await asyncio.to_thread(smtp_tls_context)  # loading the CA store reads files: never on the loop
    await aiosmtplib.send(
        message,
        hostname=config.host,
        port=config.port,
        use_tls=True,
        tls_context=context,
        username=config.from_addr,
        password=config.password.get_secret_value(),
        timeout=SMTP_TIMEOUT_S,
    )


def _header_safe(text: str) -> str:
    return " ".join(text.replace("\r", " ").replace("\n", " ").split())[:MAX_SUBJECT]


class MailSender:
    """Builds and sends one plain text email per call."""

    def __init__(self, config: MailConfig, *, transport: Transport | None = None) -> None:
        self.config = config
        self._transport = transport or smtp_transport

    def build(self, subject: str, body: str, *, to: str | None = None) -> EmailMessage:
        message = EmailMessage()
        message["To"] = _header_safe(to or self.config.to_addr)
        message["From"] = _header_safe(self.config.from_addr)
        message["Subject"] = _header_safe(subject)
        message.set_content(body[:MAX_BODY])
        return message

    async def send(self, subject: str, body: str, *, to: str | None = None) -> None:
        """Send one message. Raises `MailError` (never the library's own exception) on failure."""
        message = self.build(subject, body, to=to)
        try:
            await self._transport(message, self.config)
        except Exception as exc:
            log.warning("mail_send_failed", extra={"fields": {"error": type(exc).__name__}})
            raise MailError(type(exc).__name__) from exc
