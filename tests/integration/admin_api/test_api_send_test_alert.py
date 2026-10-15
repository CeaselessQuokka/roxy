"""Send test alert: `POST /admin/api/v1/system/alerts/test`, the Settings > Alerts button (plan 13.2 H-ALERTS).

What this is
    Integration tests of the route behind the Settings > Alerts card's "Send test alert" button: one real alert
    through every configured channel, audited first, one a minute, and words for why nothing was sent.

Why it exists
    The final review found that the H-ALERTS finding and the `alert_webhook_enabled` notes sent the owner to this
    button while no route, template or script had it (findings brain-11 and docs_a-8). Plan 13.2 asks for it: a
    webhook provider that cannot be tested without posting is checked only by posting one real message.

How it works
    The admin API fixtures run the real app (`tests/integration/admin_api/conftest.py`), whose notifier starts with
    no channel (the fixture removes the mail and webhook credentials). A test puts a `MailSender` over a recording
    transport on the running notifier, so the alert is rendered and "sent" without SMTP. The fake clock never
    moves, so a second click inside the minute meets the alert's cooldown.

What to read next
    `src/roxy/admin/api/system.py` (`send_test_alert`), `src/roxy/notify/alerts.py` (`test_alert`),
    `src/roxy/templates/admin/pages/settings/alerts.html`.
"""

from __future__ import annotations

from email.message import EmailMessage
from typing import Any

from pydantic import SecretStr

from roxy.notify.mail import MailConfig, MailSender

MAIL = MailConfig("owner@example.invalid", "alerts@example.invalid", SecretStr("not-a-real-password"))


class RecordingTransport:
    """A mail transport that keeps the messages (no SMTP)."""

    def __init__(self) -> None:
        self.messages: list[EmailMessage] = []

    async def __call__(self, message: EmailMessage, config: Any) -> None:
        self.messages.append(message)


async def _audit_actions(api_app: Any) -> list[str]:
    return await api_app.ctx.dbs.control.read(
        lambda conn: [str(row[0]) for row in conn.execute("SELECT action FROM audit_log WHERE action = 'alerts.test'")]
    )


async def test_the_button_sends_one_real_alert_once_a_minute_and_audits_each_click(
    api: Any, api_app: Any, api_json: Any
) -> None:
    transport = RecordingTransport()
    api_app.ctx.alerts.mail = MailSender(MAIL, transport=transport)
    body = api_json(await api.post("system/alerts/test", json={"reason": "check the channels"}))
    assert body["sent"] == ["email"]
    assert body["message"] == "Test alert sent by email."
    assert body["warnings"] == []
    tests = [message for message in transport.messages if str(message["Subject"]) == "Roxy: test alert"]
    assert len(tests) == 1  # (the sign-in's own login alert may reach the new transport too)
    # Below alert_min_severity (warn by default) an info alert is dropped: the test goes out at the lowest level the
    # filter lets through, so the owner always gets it.
    again = api_json(await api.post("system/alerts/test", json={"reason": "once more"}))
    assert (again["sent"], again["skipped"]) == ([], "deduped")
    assert again["message"] == "The test alert was not sent."
    assert "less than a minute ago" in again["warnings"][0]
    assert len([message for message in transport.messages if str(message["Subject"]) == "Roxy: test alert"]) == 1
    assert await _audit_actions(api_app) == ["alerts.test", "alerts.test"]


async def test_with_no_channel_the_answer_says_why_nothing_went_out(api: Any, api_app: Any, api_json: Any) -> None:
    api_app.ctx.alerts.mail = None
    api_app.ctx.alerts.webhook = None
    body = api_json(await api.post("system/alerts/test", json={"reason": ""}))
    assert (body["sent"], body["skipped"]) == ([], "no_channel")
    assert body["warnings"][0].startswith("No alert channel is configured")


async def test_the_card_has_the_button_and_the_route_is_guarded(anon_api: Any, api: Any) -> None:
    card = (await api.http.get("/admin/settings/fragment/alerts", headers={"HX-Request": "true"})).text
    assert "Send test alert" in card
    assert "/admin/api/v1/system/alerts/test" in card
    assert (await anon_api.post("system/alerts/test", json={})).status_code == 401
    assert (await api.post("system/alerts/test", json={}, csrf=False)).status_code == 403
