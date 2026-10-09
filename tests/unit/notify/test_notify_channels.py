"""The two channels: mail configuration and message building (no SMTP connection is ever made), and the webhook
(mocked with respx on a loopback URL). Plan 9.8, 17.7, 19.12."""

from __future__ import annotations

import ssl
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from roxy.admin.auth.testing import RecordingTransport
from roxy.core.redact import SecretRegistry, redact_text
from roxy.notify import mail as mail_module
from roxy.notify.mail import MailError, MailSender, load_mail_config, parse_alert_emails
from roxy.notify.webhook import WebhookError, WebhookSender, acceptable_url, load_webhook_url


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("to: a@example.invalid\nfrom: b@example.invalid\n", ("a@example.invalid", "b@example.invalid")),
        ("a@example.invalid\nb@example.invalid\n", ("a@example.invalid", "b@example.invalid")),  # v1 file format
        ("a@example.invalid", ("a@example.invalid", "a@example.invalid")),
        ("from: b@example.invalid\nTo: a@example.invalid", ("a@example.invalid", "b@example.invalid")),
        ("# comment\n\n", (None, None)),
    ],
)
def test_parse_alert_emails(text: str, expected: tuple[str | None, str | None]) -> None:
    assert parse_alert_emails(text) == expected


def test_load_mail_config_registers_the_password(credentials_dir: Path, fake_secrets: dict[str, str]) -> None:
    config = load_mail_config(credentials_dir)
    assert config is not None
    assert config.to_addr == config.from_addr == "owner@example.invalid"
    assert fake_secrets["smtp_password"] not in repr(config)
    assert redact_text(f"login with {fake_secrets['smtp_password']}") == "login with [redacted]"
    SecretRegistry.unregister("smtp_password")


def test_missing_credentials_mean_no_mail(tmp_path: Path) -> None:
    assert load_mail_config(None) is None
    assert load_mail_config(tmp_path) is None


async def test_message_building_and_failure_wrapping(credentials_dir: Path) -> None:
    config = load_mail_config(credentials_dir)
    assert config is not None
    transport = RecordingTransport()
    sender = MailSender(config, transport=transport)
    await sender.send("Subject\r\nBcc: x@example.invalid", "body text", to="someone@example.invalid")
    message = transport.messages[0]
    assert message["Subject"] == "Subject Bcc: x@example.invalid"
    assert message["To"] == "someone@example.invalid"
    assert message["From"] == "owner@example.invalid"
    assert message.get_content().strip() == "body text"
    transport.fail = True
    with pytest.raises(MailError):
        await sender.send("s", "b")
    SecretRegistry.unregister("smtp_password")


def test_acceptable_webhook_urls() -> None:
    assert acceptable_url("https://discord.example/api/webhooks/1/abc")
    assert acceptable_url("http://127.0.0.1:9/hook")
    assert acceptable_url("http://localhost/hook")
    assert not acceptable_url("http://hooks.example/abc")
    assert not acceptable_url("ftp://hooks.example/abc")
    assert not acceptable_url("not a url")


def test_load_webhook_url(credentials_dir: Path, fake_secrets: dict[str, str], tmp_path: Path) -> None:
    url = load_webhook_url(credentials_dir)
    assert url == fake_secrets["alert_webhook_url"]
    assert "fake-webhook" not in redact_text(f"posting to {url}")
    SecretRegistry.unregister("alert_webhook_url")
    (tmp_path / "alert_webhook_url").write_text("http://hooks.example/plain-http")
    assert load_webhook_url(tmp_path) is None
    SecretRegistry.unregister("alert_webhook_url")


async def test_webhook_posts_json_and_reports_failures() -> None:
    url = "http://127.0.0.1:9/fake-webhook/abc"
    sender = WebhookSender(url)
    with respx.mock(assert_all_called=True) as router:
        route = router.post(url).mock(return_value=httpx.Response(204))
        await sender.send({"content": "hi"})
        assert route.calls[0].request.headers["content-type"] == "application/json"
        router.post(url).mock(return_value=httpx.Response(500))
        with pytest.raises(WebhookError):
            await sender.send({"content": "hi"})
        router.post(url).mock(side_effect=httpx.ConnectError("refused"))
        with pytest.raises(WebhookError):
            await sender.send({"content": "hi"})
    assert "abc" not in repr(sender)
    await sender.aclose()


async def test_alert_channels_never_log_tls_keys(
    monkeypatch: pytest.MonkeyPatch, credentials_dir: Path, tmp_path: Path
) -> None:
    """Review finding cred-6, notify side: `SSLKEYLOGFILE` in the environment never reaches a channel's TLS context.

    CPython's `ssl.create_default_context` copies the variable into `keylog_filename` by itself, so both channels
    build their own context: the mail session protects the app password, the webhook session the URL's token.
    """
    monkeypatch.setenv("SSLKEYLOGFILE", str(tmp_path / "keys.log"))
    assert ssl.create_default_context().keylog_filename == str(tmp_path / "keys.log")  # the premise

    assert mail_module.smtp_tls_context().keylog_filename is None
    assert mail_module.smtp_tls_context().verify_mode == ssl.CERT_REQUIRED
    sent: dict[str, Any] = {}

    async def fake_send(message: Any, **kwargs: Any) -> None:
        sent.update(kwargs)

    monkeypatch.setattr(mail_module.aiosmtplib, "send", fake_send)  # nothing ever connects to a mail server
    config = load_mail_config(credentials_dir)
    assert config is not None
    await mail_module.smtp_transport(MailSender(config).build("s", "b"), config)
    assert isinstance(sent["tls_context"], ssl.SSLContext)
    assert sent["tls_context"].keylog_filename is None
    assert sent["tls_context"].check_hostname
    SecretRegistry.unregister("smtp_password")

    sender = WebhookSender("http://127.0.0.1:9/fake-webhook/abc")
    pool_context = sender._client._transport._pool._ssl_context  # type: ignore[attr-defined]  # httpx internals
    assert pool_context.keylog_filename is None
    assert pool_context.verify_mode == ssl.CERT_REQUIRED
    await sender.aclose()
